use crate::core::model::addr::ThinFileOffset;
use crate::insn::{BranchTarget, Insn, InsnKind};

use crate::analysis::report::disassembly::{
    DirectTarget, DisassemblyRecord, DisassemblyStatus, InstructionKind,
};
use crate::analysis::report::{
    CanonicalUuid, ContainerKind, ContentHash, HexBytes, ImageIdentity, ReportSliceIdentity,
};

use super::metadata::Metadata;
use super::selection::{RegionExtent, RegionPlan, SelectedSlice};
use super::sink::{DisassemblySink, RegionHeader, RegionSummary, SliceHeader, SliceSummary};
use super::{DecodeMode, DisassemblyError, DisassemblyRequest, WorkStats};

// The streaming decode threads the selected slice, request, resolved plans,
// mutable metadata, container identity, the event sink, and the optional
// work-stats observer through one pass; splitting them would fragment the single
// decode path without removing any argument.
#[allow(clippy::too_many_arguments)]
pub(crate) fn decode_slice(
    slice: &SelectedSlice<'_, '_>,
    request: &DisassemblyRequest,
    plans: Vec<RegionPlan>,
    metadata: &mut Metadata,
    container_hash: ContentHash,
    container_kind: ContainerKind,
    sink: &mut dyn DisassemblySink,
    mut observer: Option<&mut WorkStats>,
) -> Result<(), DisassemblyError> {
    let image_hash = if container_kind == ContainerKind::Thin {
        container_hash
    } else {
        ContentHash::new(crate::analysis::report::sha256_hex(slice.macho.bytes()))
            .expect("SHA-256 is canonical lowercase hexadecimal")
    };
    let uuid = slice
        .macho
        .uuid()
        .map(crate::core::format_uuid)
        .map(CanonicalUuid::new)
        .transpose()
        .map_err(|error| {
            DisassemblyError::new(
                "analysis.disassembly.report.invalid",
                format!("invalid image UUID: {error}"),
            )
        })?;
    let identity = ReportSliceIdentity {
        image: ImageIdentity {
            content_sha256: image_hash,
            byte_len: slice.macho.file_size() as u64,
            container: container_kind,
            slice_index: slice.index,
            architecture: slice.architecture,
            uuid,
        },
    };

    sink.slice_start(SliceHeader {
        identity,
        container_offset: slice.container_offset,
        slice_size: slice.macho.file_size() as u64,
    })?;

    let mut remaining = request.max_decoded_bytes_per_slice.get() as u64;
    let mut decoded_bytes = 0u64;
    let mut decoded_bytes_truncated = false;
    let mut has_gap = false;
    for plan in plans {
        let decoded = decode_region(slice, request, &plan, &mut remaining, metadata, sink)?;
        decoded_bytes = decoded_bytes
            .checked_add(decoded.decoded_bytes)
            .ok_or_else(|| {
                DisassemblyError::new(
                    "analysis.disassembly.report.invalid",
                    "decoded byte count overflows",
                )
            })?;
        decoded_bytes_truncated |= decoded.truncated;
        has_gap |= decoded.has_gap;
        if let Some(stats) = observer.as_deref_mut() {
            stats.decode_attempts += decoded.decode_attempts;
            stats.decoder_input_bytes += decoded.decoder_input_bytes;
            stats.unexamined_lookahead_bytes += decoded.unexamined_lookahead_bytes;
            stats.decode_eligible_bytes += decoded.decode_eligible_bytes;
            stats.examined_bytes += decoded.decoded_bytes;
            stats.raw_bytes_retained += decoded.decoded_bytes;
            stats.records_retained += decoded.records_count;
        }
    }
    let partial =
        has_gap || decoded_bytes_truncated || metadata.truncated || !metadata.issues.is_empty();
    sink.slice_end(
        SliceSummary {
            status: if partial {
                DisassemblyStatus::Partial
            } else {
                DisassemblyStatus::Complete
            },
            decoded_bytes,
            decoded_bytes_truncated,
            symbol_ranges_truncated: metadata.truncated,
        },
        &metadata.issues,
    )?;
    Ok(())
}

struct DecodedRegion {
    decoded_bytes: u64,
    truncated: bool,
    has_gap: bool,
    decode_attempts: u64,
    decoder_input_bytes: u64,
    unexamined_lookahead_bytes: u64,
    decode_eligible_bytes: u64,
    records_count: u64,
}

#[derive(Debug, Default)]
struct DecodeWork {
    decode_attempts: u64,
    decoder_input_bytes: u64,
    unexamined_lookahead_bytes: u64,
    pending_recovery_probe_va: Option<u64>,
}

impl DecodeWork {
    fn charge_probe(&mut self, input_len: usize) {
        self.decode_attempts += 1;
        self.decoder_input_bytes += input_len as u64;
    }

    fn charge_unexamined_since(&mut self, attempts_before: u64) {
        self.unexamined_lookahead_bytes += self.decode_attempts - attempts_before;
    }

    fn retain_recovery_probe(&mut self, va: u64) {
        debug_assert!(self.pending_recovery_probe_va.is_none());
        self.pending_recovery_probe_va = Some(va);
        self.unexamined_lookahead_bytes += 1;
    }

    fn cover_pending_probe(&mut self, va: u64) {
        if self.pending_recovery_probe_va == Some(va) {
            self.pending_recovery_probe_va = None;
            self.unexamined_lookahead_bytes -= 1;
        }
    }
}

fn decode_region(
    slice: &SelectedSlice<'_, '_>,
    request: &DisassemblyRequest,
    plan: &RegionPlan,
    remaining: &mut u64,
    metadata: &Metadata,
    sink: &mut dyn DisassemblySink,
) -> Result<DecodedRegion, DisassemblyError> {
    let start_delta = plan.start.checked_sub(plan.section_start).ok_or_else(|| {
        DisassemblyError::new(
            "analysis.disassembly.address.unmapped",
            "selected range precedes its section",
        )
    })?;
    let natural_len = plan.section_end.checked_sub(plan.start).ok_or_else(|| {
        DisassemblyError::new(
            "analysis.disassembly.address.unmapped",
            "selected range exceeds its section",
        )
    })?;
    let natural_offset = plan
        .section_file_offset
        .checked_add(start_delta)
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.address.unmapped",
                "selected file offset overflows",
            )
        })?;
    let natural_bytes = slice
        .macho
        .read_bytes_at(
            ThinFileOffset(natural_offset),
            usize::try_from(natural_len).map_err(|_| {
                DisassemblyError::new(
                    "analysis.disassembly.address.unmapped",
                    "selected section is too large for this host",
                )
            })?,
        )
        .map_err(|error| {
            DisassemblyError::new(
                "analysis.disassembly.address.unmapped",
                format!("failed to read selected bytes: {error}"),
            )
        })?;

    let byte_end = match plan.extent {
        RegionExtent::Bytes(end) => Some(end),
        RegionExtent::Instructions(_) => None,
    };
    let requested_count = match plan.extent {
        RegionExtent::Instructions(count) => Some(count),
        RegionExtent::Bytes(_) => None,
    };
    sink.region_start(RegionHeader {
        segment: plan.segment.clone(),
        section: plan.section.clone(),
        selection_source: plan.selection_source,
        range_source: plan.range_source,
        end_source: plan.end_source,
        start_va: plan.start,
        requested_end_va: byte_end,
        requested_instruction_count: requested_count,
        instruction_flags: plan.flags,
    })?;
    let mut cursor = plan.start;
    let mut records_count = 0u64;
    let mut instruction_count = 0u64;
    let mut has_gap = false;
    let mut truncated = false;
    let max_instruction_len = if slice.arch.is_arm64() { 4 } else { 15 };
    let decode_eligible_bytes = match plan.extent {
        RegionExtent::Bytes(end) => {
            let requested = end.checked_sub(plan.start).ok_or_else(|| {
                DisassemblyError::new(
                    "analysis.disassembly.address.unmapped",
                    "selected byte range precedes its start",
                )
            })?;
            let available_tail = plan.section_end.checked_sub(end).ok_or_else(|| {
                DisassemblyError::new(
                    "analysis.disassembly.address.unmapped",
                    "selected byte range exceeds its section",
                )
            })?;
            requested
                .checked_add(available_tail.min((max_instruction_len - 1) as u64))
                .ok_or_else(|| {
                    DisassemblyError::new(
                        "analysis.disassembly.report.invalid",
                        "decode-eligible byte count overflows",
                    )
                })?
        }
        RegionExtent::Instructions(_) => natural_len,
    };
    let mut work = DecodeWork::default();
    let mut disassembler = crate::insn::Disassembler::new(slice.arch);

    loop {
        if byte_end.is_some_and(|end| cursor >= end)
            || requested_count.is_some_and(|count| instruction_count >= count)
        {
            break;
        }
        if *remaining == 0 {
            truncated = true;
            break;
        }
        if cursor >= plan.section_end {
            if requested_count.is_some_and(|count| instruction_count < count) {
                return Err(DisassemblyError::new(
                    "analysis.disassembly.count.unsatisfied",
                    format!(
                        "section end reached after {instruction_count} of {} requested instructions",
                        requested_count.expect("count extent")
                    ),
                ));
            }
            break;
        }
        let relative =
            usize::try_from(cursor - plan.start).expect("slice-backed offset fits usize");
        let tail = &natural_bytes[relative..];
        let attempts_before = work.decode_attempts;
        match decode_for_display_at(
            tail,
            cursor,
            &mut disassembler,
            max_instruction_len,
            &mut work,
        ) {
            Ok(decoded) => {
                let instruction = decoded.instruction;
                let len = instruction.len as u64;
                let instruction_end = cursor.checked_add(len).ok_or_else(|| {
                    DisassemblyError::new(
                        "analysis.disassembly.address.unmapped",
                        "instruction VA overflows",
                    )
                })?;
                if let Some(end) = byte_end.filter(|end| instruction_end > *end) {
                    let selected_len = end - cursor;
                    if *remaining < selected_len {
                        work.charge_unexamined_since(attempts_before);
                        truncated = true;
                        break;
                    }
                    if request.mode == DecodeMode::Strict {
                        return Err(DisassemblyError::new(
                            "analysis.disassembly.selection.partial_instruction",
                            format!("selection ends inside a valid instruction at {cursor:#x}"),
                        ));
                    }
                    let bytes = &tail[..selected_len as usize];
                    work.cover_pending_probe(cursor);
                    emit_record(
                        sink,
                        metadata,
                        gap_record(
                            slice,
                            plan,
                            cursor,
                            bytes,
                            "analysis.disassembly.selection.partial_instruction",
                            "selection ends inside a valid instruction",
                        )?,
                    )?;
                    records_count += 1;
                    *remaining -= selected_len;
                    cursor = end;
                    has_gap = true;
                    break;
                }
                if *remaining < len {
                    work.charge_unexamined_since(attempts_before);
                    truncated = true;
                    break;
                }
                let bytes = &tail[..instruction.len];
                work.cover_pending_probe(cursor);
                emit_record(
                    sink,
                    metadata,
                    instruction_record(
                        slice,
                        plan,
                        cursor,
                        bytes,
                        decoded.text,
                        &instruction,
                        metadata,
                    )?,
                )?;
                records_count += 1;
                *remaining -= len;
                cursor = instruction_end;
                instruction_count += 1;
            }
            Err(error) => {
                if request.mode == DecodeMode::Strict {
                    return Err(DisassemblyError::new(
                        crate::insn::DecodeError::CODE,
                        format!("invalid instruction at {cursor:#x}: {error}"),
                    ));
                }
                let mut gap_len = if slice.arch.is_arm64() {
                    tail.len().min(4) as u64
                } else {
                    1
                };
                if let Some(end) = byte_end {
                    gap_len = gap_len.min(end - cursor);
                }
                if !slice.arch.is_arm64() {
                    let extended = extend_x86_gap(tail, cursor, byte_end, *remaining, &mut work);
                    gap_len = extended.length;
                    if gap_len <= *remaining {
                        if let Some(va) = extended.next_valid_va {
                            work.retain_recovery_probe(va);
                        }
                    }
                }
                if gap_len == 0 || *remaining < gap_len {
                    work.charge_unexamined_since(attempts_before);
                    truncated = true;
                    break;
                }
                work.cover_pending_probe(cursor);
                emit_record(
                    sink,
                    metadata,
                    gap_record(
                        slice,
                        plan,
                        cursor,
                        &tail[..gap_len as usize],
                        crate::insn::DecodeError::CODE,
                        &error.to_string(),
                    )?,
                )?;
                records_count += 1;
                *remaining -= gap_len;
                cursor += gap_len;
                has_gap = true;
            }
        }
    }

    if !truncated {
        if let Some(end) = byte_end {
            if cursor < end {
                return Err(DisassemblyError::new(
                    "analysis.disassembly.address.unmapped",
                    "selected byte range could not be fully examined",
                ));
            }
        }
    }
    let labels_end = cursor;
    let labels = metadata.labels_between(plan.start, labels_end);
    let decoded_bytes = cursor - plan.start;
    sink.region_end(
        RegionSummary {
            emitted_instruction_count: instruction_count,
            examined_end_va: cursor,
            next_unexamined_va: truncated.then_some(cursor),
        },
        &labels,
    )?;
    Ok(DecodedRegion {
        decoded_bytes,
        truncated,
        has_gap,
        decode_attempts: work.decode_attempts,
        decoder_input_bytes: work.decoder_input_bytes,
        unexamined_lookahead_bytes: work.unexamined_lookahead_bytes,
        decode_eligible_bytes,
        records_count,
    })
}

/// Emit one record to the sink with the labels whose VA equals the record VA.
fn emit_record(
    sink: &mut dyn DisassemblySink,
    metadata: &Metadata,
    record: DisassemblyRecord,
) -> Result<(), DisassemblyError> {
    let labels = metadata.labels_at(record.va());
    sink.record(&record, &labels)
}

struct ExtendedGap {
    length: u64,
    next_valid_va: Option<u64>,
}

fn extend_x86_gap(
    tail: &[u8],
    va: u64,
    byte_end: Option<u64>,
    budget: u64,
    work: &mut DecodeWork,
) -> ExtendedGap {
    let selected_len = byte_end
        .map(|end| end - va)
        .unwrap_or(tail.len() as u64)
        .min(tail.len() as u64)
        // Inspect one byte beyond the remaining accounting budget. If that
        // byte is also invalid, the recovery unit crosses the boundary and
        // the caller must leave the entire unit unexamined.
        .min(budget.saturating_add(1));
    let mut length = 1u64;
    while length < selected_len {
        let offset = length as usize;
        if decode_at(
            &tail[offset..],
            va + length,
            crate::insn::Arch::X86_64,
            work,
        )
        .is_ok()
        {
            return ExtendedGap {
                length,
                next_valid_va: Some(va + length),
            };
        }
        length += 1;
    }
    ExtendedGap {
        length,
        next_valid_va: None,
    }
}

fn decode_at(
    tail: &[u8],
    va: u64,
    arch: crate::insn::Arch,
    work: &mut DecodeWork,
) -> Result<Insn, crate::insn::DecodeError> {
    let max_instruction_len = if arch.is_arm64() { 4 } else { 15 };
    let window_len = tail.len().min(max_instruction_len);
    work.charge_probe(window_len);
    crate::insn::decode_one(&tail[..window_len], va, arch)
}

fn decode_for_display_at(
    tail: &[u8],
    va: u64,
    disassembler: &mut crate::insn::Disassembler,
    max_instruction_len: usize,
    work: &mut DecodeWork,
) -> Result<crate::insn::DisassembledInsn, crate::insn::DecodeError> {
    let window_len = tail.len().min(max_instruction_len);
    work.charge_probe(window_len);
    disassembler.decode_one(&tail[..window_len], va)
}

fn instruction_record(
    slice: &SelectedSlice<'_, '_>,
    plan: &RegionPlan,
    va: u64,
    bytes: &[u8],
    text: String,
    instruction: &Insn,
    metadata: &Metadata,
) -> Result<DisassemblyRecord, DisassemblyError> {
    let thin_file_offset = thin_offset(plan, va)?;
    let container_file_offset = slice
        .container_offset
        .checked_add(thin_file_offset)
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.report.invalid",
                "container instruction offset overflows",
            )
        })?;
    let direct_target = direct_target(instruction, va, metadata);
    Ok(DisassemblyRecord::Instruction {
        va,
        thin_file_offset,
        container_file_offset,
        size: bytes.len() as u64,
        bytes: HexBytes::from_bytes(bytes),
        text,
        kind: instruction_kind(&instruction.kind),
        direct_target,
    })
}

fn gap_record(
    slice: &SelectedSlice<'_, '_>,
    plan: &RegionPlan,
    va: u64,
    bytes: &[u8],
    code: &str,
    message: &str,
) -> Result<DisassemblyRecord, DisassemblyError> {
    let thin_file_offset = thin_offset(plan, va)?;
    let container_file_offset = slice
        .container_offset
        .checked_add(thin_file_offset)
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.report.invalid",
                "container gap offset overflows",
            )
        })?;
    Ok(DisassemblyRecord::Gap {
        va,
        thin_file_offset,
        container_file_offset,
        bytes: HexBytes::from_bytes(bytes),
        code: code.to_owned(),
        message: message.to_owned(),
    })
}

fn thin_offset(plan: &RegionPlan, va: u64) -> Result<u64, DisassemblyError> {
    plan.section_file_offset
        .checked_add(va.checked_sub(plan.section_start).ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.report.invalid",
                "record VA precedes its section",
            )
        })?)
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.report.invalid",
                "record file offset overflows",
            )
        })
}

fn instruction_kind(kind: &InsnKind) -> InstructionKind {
    match kind {
        InsnKind::Branch(_) => InstructionKind::Branch,
        InsnKind::Call(_) => InstructionKind::Call,
        InsnKind::CondBranch(_) => InstructionKind::ConditionalBranch,
        InsnKind::Return => InstructionKind::Return,
        InsnKind::Nop => InstructionKind::Nop,
        InsnKind::PcRelative(_) => InstructionKind::PcRelative,
        InsnKind::Other => InstructionKind::Other,
        _ => InstructionKind::Other,
    }
}

fn direct_target(instruction: &Insn, va: u64, metadata: &Metadata) -> Option<DirectTarget> {
    let displacement = match &instruction.kind {
        InsnKind::Branch(info) | InsnKind::Call(info) | InsnKind::CondBranch(info) => {
            match info.target {
                BranchTarget::Direct(displacement) => displacement,
                _ => return None,
            }
        }
        _ => return None,
    };
    let target = va.checked_add_signed(displacement)?;
    let resolved = metadata.target_owner(target).and_then(|symbol| {
        if !metadata.issues.is_empty() {
            return None;
        }
        // When the presentation index is truncated, an omitted owner may lie
        // between a retained start and the target. Exact-start annotations are
        // still provable; non-zero offsets stay symbolic-free.
        if metadata.truncated && symbol.va != target {
            return None;
        }
        Some(symbol)
    });
    Some(match resolved {
        Some(symbol) => DirectTarget {
            va: target,
            raw_symbol: Some(symbol.raw_name.clone()),
            display_symbol: Some(symbol.display_name.clone()),
            source: Some(symbol.source),
            offset: Some(target - symbol.va),
        },
        None => DirectTarget {
            va: target,
            raw_symbol: None,
            display_symbol: None,
            source: None,
            offset: None,
        },
    })
}
