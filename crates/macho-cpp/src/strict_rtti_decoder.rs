//! Bounded Itanium RTTI decoding and pointer-fixup reconstruction.

use std::collections::BTreeMap;

use macho_core::model::addr::{ThinFileOffset, Va};
use macho_core::model::load_command::LoadCommand;
use macho_core::model::macho_file::MachoFile;
use macho_core::model::symbol::{Symbol, SymbolTable};
use macho_dyld::FixupKind;

use super::*;
use crate::{Error, Result};

#[derive(Clone, Debug, Eq, PartialEq)]
struct PointerFixup {
    encoding: StrictPointerEncoding,
    authentication: StrictPointerAuthentication,
    target: StrictPointerTarget,
}

pub(crate) struct StrictDecoder<'a, 'data> {
    pub(crate) macho: &'a MachoFile<'data>,
    limits: StrictRttiLimits,
    pub(crate) pointer_size: u64,
    fixups: BTreeMap<u64, PointerFixup>,
    pub(crate) symbols_by_va: BTreeMap<u64, String>,
    pub(crate) observations: Vec<StrictRttiObservation>,
    base_count: u64,
    evidence_bytes: u64,
}

impl<'a, 'data> StrictDecoder<'a, 'data> {
    pub(crate) fn new(macho: &'a MachoFile<'data>, limits: StrictRttiLimits) -> Result<Self> {
        Ok(Self {
            macho,
            limits,
            pointer_size: if macho.is_64bit() { 8 } else { 4 },
            fixups: build_pointer_fixups(macho)?,
            symbols_by_va: BTreeMap::new(),
            observations: Vec::new(),
            base_count: 0,
            evidence_bytes: 0,
        })
    }

    pub(crate) fn observe(
        &mut self,
        symbol: &str,
        field: impl Into<String>,
        va: u64,
        length: u64,
        kind: StrictRttiObservationKind,
    ) -> Result<u64> {
        let file_offset = self.macho.address_map().va_to_thin_offset(Va(va))?.0;
        self.evidence_bytes = self
            .evidence_bytes
            .checked_add(length)
            .ok_or_else(|| Error::format("strict RTTI evidence byte count overflows"))?;
        if self.evidence_bytes > self.limits.max_evidence_bytes {
            self.evidence_bytes -= length;
            return Err(Error::format("strict RTTI evidence byte limit exceeded"));
        }
        let ordinal = u64::try_from(self.observations.len())
            .map_err(|_| Error::format("strict RTTI observation count exceeds UInt64"))?;
        self.observations.push(StrictRttiObservation {
            ordinal,
            symbol: symbol.to_owned(),
            field: field.into(),
            va,
            file_offset,
            length,
            kind,
        });
        Ok(ordinal)
    }

    pub(crate) fn pointer(
        &mut self,
        symbol: &str,
        field: impl Into<String>,
        va: u64,
    ) -> Result<StrictPointerObservation> {
        let field = field.into();
        let file_offset = self.macho.address_map().va_to_thin_offset(Va(va))?.0;
        let raw_value = self.peek_word(va)?;
        let observation_ordinal = self.observe(
            symbol,
            field,
            va,
            self.pointer_size,
            StrictRttiObservationKind::Pointer,
        )?;
        let (encoding, authentication, target) =
            self.pointer_value(file_offset, raw_value, u64::MAX)?;
        Ok(StrictPointerObservation {
            observation_ordinal,
            raw_value,
            width: self.pointer_size as u8,
            encoding,
            authentication,
            target,
        })
    }

    fn type_name_pointer(
        &mut self,
        symbol: &str,
        va: u64,
    ) -> Result<(StrictPointerObservation, bool)> {
        let file_offset = self.macho.address_map().va_to_thin_offset(Va(va))?.0;
        let raw_value = self.peek_word(va)?;
        let shift = u32::try_from(self.pointer_size * 8 - 1)
            .map_err(|_| Error::format("strict RTTI type-name tag width is invalid"))?;
        let tag = 1_u64
            .checked_shl(shift)
            .ok_or_else(|| Error::format("strict RTTI type-name tag width is invalid"))?;
        let observation_ordinal = self.observe(
            symbol,
            "type_name",
            va,
            self.pointer_size,
            StrictRttiObservationKind::Pointer,
        )?;
        let (encoding, authentication, target) =
            self.pointer_value(file_offset, raw_value, !tag)?;
        Ok((
            StrictPointerObservation {
                observation_ordinal,
                raw_value,
                width: self.pointer_size as u8,
                encoding,
                authentication,
                target,
            },
            raw_value & tag != 0,
        ))
    }

    pub(crate) fn peek_word(&self, va: u64) -> Result<u64> {
        let bytes = self
            .macho
            .read_bytes_at_va(Va(va), self.pointer_size as usize)?;
        if self.pointer_size == 8 {
            Ok(self.macho.endian().read_u64(
                bytes.try_into().map_err(|_| {
                    Error::format("strict RTTI pointer read returned the wrong width")
                })?,
            ))
        } else {
            Ok(u64::from(self.macho.endian().read_u32(
                bytes.try_into().map_err(|_| {
                    Error::format("strict RTTI pointer read returned the wrong width")
                })?,
            )))
        }
    }

    pub(crate) fn peek_pointer_target(&self, va: u64) -> Result<StrictPointerTarget> {
        let file_offset = self.macho.address_map().va_to_thin_offset(Va(va))?.0;
        let raw_value = self.peek_word(va)?;
        self.pointer_value(file_offset, raw_value, u64::MAX)
            .map(|(_, _, target)| target)
    }

    fn pointer_value(
        &self,
        file_offset: u64,
        raw_value: u64,
        local_address_mask: u64,
    ) -> Result<(
        StrictPointerEncoding,
        StrictPointerAuthentication,
        StrictPointerTarget,
    )> {
        let fixup = self.fixups.get(&file_offset).cloned();
        let (encoding, authentication, target) = fixup.map_or_else(
            || {
                let target = if raw_value == 0 {
                    StrictPointerTarget::Null
                } else {
                    StrictPointerTarget::Local { va: raw_value }
                };
                (
                    StrictPointerEncoding::Direct,
                    StrictPointerAuthentication::NotApplicable,
                    target,
                )
            },
            |value| (value.encoding, value.authentication, value.target),
        );
        let target = match target {
            StrictPointerTarget::Local { va } => StrictPointerTarget::Local {
                va: va & local_address_mask,
            },
            value => value,
        };
        if let StrictPointerTarget::Local { va: target } = target {
            if target != 0
                && self
                    .macho
                    .address_map()
                    .va_to_thin_offset(Va(target))
                    .is_err()
            {
                return Err(Error::address(format!(
                    "strict RTTI pointer targets unmapped VA {target:#x}"
                )));
            }
        }
        Ok((encoding, authentication, target))
    }

    fn integer_u32(&mut self, symbol: &str, field: impl Into<String>, va: u64) -> Result<u32> {
        let bytes = self.macho.read_bytes_at_va(Va(va), 4)?;
        let value = self.macho.endian().read_u32(
            bytes
                .try_into()
                .map_err(|_| Error::format("strict RTTI u32 read returned the wrong width"))?,
        );
        self.observe(symbol, field, va, 4, StrictRttiObservationKind::Integer)?;
        Ok(value)
    }

    pub(crate) fn integer_word(
        &mut self,
        symbol: &str,
        field: impl Into<String>,
        va: u64,
    ) -> Result<u64> {
        if self.pointer_size == 8 {
            let bytes = self.macho.read_bytes_at_va(Va(va), 8)?;
            let value =
                self.macho.endian().read_u64(bytes.try_into().map_err(|_| {
                    Error::format("strict RTTI word read returned the wrong width")
                })?);
            self.observe(symbol, field, va, 8, StrictRttiObservationKind::Integer)?;
            Ok(value)
        } else {
            self.integer_u32(symbol, field, va).map(u64::from)
        }
    }

    fn type_name(&mut self, symbol: &str, pointer: &StrictPointerObservation) -> Result<String> {
        let StrictPointerTarget::Local { va } = pointer.target else {
            return Err(Error::address("strict RTTI type-name pointer is not local"));
        };
        if va == 0 {
            return Err(Error::address("strict RTTI type-name pointer is null"));
        }
        let offset = self.macho.address_map().va_to_thin_offset(Va(va))?.0;
        let start = usize::try_from(offset)
            .map_err(|_| Error::format("strict RTTI type-name offset exceeds usize"))?;
        let maximum = usize::try_from(self.limits.max_name_bytes)
            .map_err(|_| Error::format("strict RTTI name limit exceeds usize"))?;
        let available = self
            .macho
            .bytes()
            .get(start..)
            .ok_or_else(|| Error::bounds(offset, 1, self.macho.bytes().len() as u64))?;
        let bounded = &available[..available.len().min(maximum.saturating_add(1))];
        let length = bounded
            .iter()
            .position(|byte| *byte == 0)
            .ok_or_else(|| Error::format("strict RTTI type name is unterminated or oversized"))?;
        if length == 0 {
            return Err(Error::format("strict RTTI type name is empty"));
        }
        let value = std::str::from_utf8(&bounded[..length])
            .map_err(|_| Error::format("strict RTTI type name is not UTF-8"))?;
        self.observe(
            symbol,
            "type_name_bytes",
            va,
            u64::try_from(length + 1)
                .map_err(|_| Error::format("strict RTTI type-name length exceeds UInt64"))?,
            StrictRttiObservationKind::TypeName,
        )?;
        Ok(value.to_owned())
    }

    fn family(&self, pointer: &StrictPointerObservation) -> Result<ItaniumTypeInfoFamily> {
        let name = match &pointer.target {
            StrictPointerTarget::Local { va } => {
                let (symbol_va, name) = self
                    .symbols_by_va
                    .range(..=*va)
                    .next_back()
                    .ok_or_else(|| Error::format("RTTI runtime vtable target lacks a symbol"))?;
                let maximum_delta = self
                    .pointer_size
                    .checked_mul(2)
                    .ok_or_else(|| Error::format("RTTI vtable address-point bound overflows"))?;
                if va
                    .checked_sub(*symbol_va)
                    .is_none_or(|delta| delta > maximum_delta)
                {
                    return Err(Error::format(
                        "RTTI runtime vtable target is not an exact ABI address point",
                    ));
                }
                name.as_str()
            }
            StrictPointerTarget::External { symbol, .. } => symbol.as_str(),
            StrictPointerTarget::Null => {
                return Err(Error::format("RTTI runtime vtable pointer is null"));
            }
        };
        classify_family(name)
            .ok_or_else(|| Error::unsupported(format!("unsupported RTTI runtime family {name}")))
    }

    fn decode(&mut self, symbol: &Symbol<'_>) -> Result<ItaniumTypeInfoRecord> {
        let ptr = self.pointer_size;
        let runtime_vtable = self.pointer(symbol.name, "runtime_vtable", symbol.value)?;
        let family = self.family(&runtime_vtable)?;
        let (type_name_pointer, type_name_non_unique) =
            self.type_name_pointer(symbol.name, checked_add(symbol.value, ptr)?)?;
        let type_name = self.type_name(symbol.name, &type_name_pointer)?;
        let mut class_flags = 0;
        let mut bases = Vec::new();
        let mut pointee = None;
        match family {
            ItaniumTypeInfoFamily::SingleInheritanceClass => {
                let base = self.pointer(
                    symbol.name,
                    "base[0].typeinfo",
                    checked_add(
                        symbol.value,
                        ptr.checked_mul(2)
                            .ok_or_else(|| Error::format("RTTI field offset overflows"))?,
                    )?,
                )?;
                bases.push(ItaniumBaseRecord {
                    ordinal: 0,
                    typeinfo: base,
                    offset_flags: 0x2,
                    signed_offset: 0,
                    is_virtual: false,
                    is_public: true,
                });
                self.base_count = self
                    .base_count
                    .checked_add(1)
                    .ok_or_else(|| Error::format("RTTI base count overflows"))?;
            }
            ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass => {
                let header = checked_add(
                    symbol.value,
                    ptr.checked_mul(2)
                        .ok_or_else(|| Error::format("RTTI field offset overflows"))?,
                )?;
                class_flags = self.integer_u32(symbol.name, "vmi.flags", header)?;
                let count = u64::from(self.integer_u32(
                    symbol.name,
                    "vmi.base_count",
                    checked_add(header, 4)?,
                )?);
                self.base_count = self
                    .base_count
                    .checked_add(count)
                    .ok_or_else(|| Error::format("RTTI base count overflows"))?;
                if self.base_count > self.limits.max_bases {
                    return Err(Error::format("strict RTTI base limit exceeded"));
                }
                let entry_size = ptr
                    .checked_mul(2)
                    .ok_or_else(|| Error::format("RTTI base entry size overflows"))?;
                let start = checked_add(header, 8)?;
                for ordinal in 0..count {
                    let entry = checked_add(
                        start,
                        ordinal
                            .checked_mul(entry_size)
                            .ok_or_else(|| Error::format("RTTI base table offset overflows"))?,
                    )?;
                    let typeinfo =
                        self.pointer(symbol.name, format!("base[{ordinal}].typeinfo"), entry)?;
                    let offset_flags = self.integer_word(
                        symbol.name,
                        format!("base[{ordinal}].offset_flags"),
                        checked_add(entry, ptr)?,
                    )?;
                    bases.push(ItaniumBaseRecord {
                        ordinal,
                        typeinfo,
                        offset_flags,
                        signed_offset: (offset_flags as i64) >> 8,
                        is_virtual: offset_flags & 1 != 0,
                        is_public: offset_flags & 2 != 0,
                    });
                }
            }
            ItaniumTypeInfoFamily::Pointer | ItaniumTypeInfoFamily::PointerToMember => {
                let flags_va = checked_add(
                    symbol.value,
                    ptr.checked_mul(2)
                        .ok_or_else(|| Error::format("RTTI field offset overflows"))?,
                )?;
                let flags = self.integer_u32(symbol.name, "pbase.flags", flags_va)?;
                let pointee_va = align_up(checked_add(flags_va, 4)?, ptr)?;
                let pointee_pointer = self.pointer(symbol.name, "pbase.pointee", pointee_va)?;
                let member_of = if family == ItaniumTypeInfoFamily::PointerToMember {
                    Some(self.pointer(
                        symbol.name,
                        "pointer_to_member.context",
                        checked_add(pointee_va, ptr)?,
                    )?)
                } else {
                    None
                };
                pointee = Some(ItaniumPointeeRecord {
                    flags,
                    pointee: pointee_pointer,
                    member_of,
                });
            }
            _ => {}
        }
        if self.base_count > self.limits.max_bases {
            return Err(Error::format("strict RTTI base limit exceeded"));
        }
        let file_offset = self
            .macho
            .address_map()
            .va_to_thin_offset(Va(symbol.value))?
            .0;
        Ok(ItaniumTypeInfoRecord {
            symbol: symbol.name.to_owned(),
            va: symbol.value,
            file_offset,
            family,
            type_name,
            type_name_non_unique,
            runtime_vtable,
            type_name_pointer,
            class_flags,
            bases,
            pointee,
            weak_definition: symbol.is_weak_def(),
        })
    }
}

/// Decode one selected thin Mach-O into strict Itanium RTTI leaf records.
pub fn decode_strict_rtti(
    macho: &MachoFile<'_>,
    limits: StrictRttiLimits,
) -> Result<StrictRttiBatch> {
    limits.validate()?;
    let input_bytes = u64::try_from(macho.bytes().len())
        .map_err(|_| Error::format("strict RTTI input length exceeds UInt64"))?;
    if input_bytes > limits.max_input_bytes {
        return preflight_limit_batch("input_bytes", limits);
    }
    let symtab = macho.ext::<SymbolTable<'_>>()?;
    let symbol_count = u64::try_from(symtab.symbols().len())
        .map_err(|_| Error::format("strict RTTI symbol count exceeds UInt64"))?;
    if symbol_count > limits.max_symbols {
        return preflight_limit_batch("symbol_registry", limits);
    }
    let mut candidates = symtab
        .symbols()
        .iter()
        .filter(|symbol| is_typeinfo_symbol(symbol.name))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.name
            .cmp(right.name)
            .then_with(|| left.value.cmp(&right.value))
            .then_with(|| left.index.cmp(&right.index))
    });
    let attempted = u64::try_from(candidates.len())
        .map_err(|_| Error::format("strict RTTI candidate count exceeds UInt64"))?;
    if attempted == 0 {
        let batch = StrictRttiBatch {
            outcome: StrictRttiOutcome::Absent,
            records: Vec::new(),
            observations: Vec::new(),
            gaps: Vec::new(),
            conservation: StrictRttiConservation {
                attempted: 0,
                included: 0,
                unknown: 0,
                excluded: 0,
            },
        };
        batch.validate(limits)?;
        return Ok(batch);
    }
    if attempted > limits.max_records {
        let batch = StrictRttiBatch {
            outcome: StrictRttiOutcome::Rejected,
            records: Vec::new(),
            observations: Vec::new(),
            gaps: vec![StrictRttiGap {
                symbol: None,
                field: "candidate_registry".into(),
                code: StrictRttiGapCode::StructuralLimitExceeded,
                source_code: None,
            }],
            conservation: StrictRttiConservation {
                attempted,
                included: 0,
                unknown: 0,
                excluded: attempted,
            },
        };
        batch.validate(limits)?;
        return Ok(batch);
    }

    let mut decoder = StrictDecoder::new(macho, limits)?;
    decoder.symbols_by_va = symtab
        .symbols()
        .iter()
        .filter(|symbol| symbol.is_defined() && symbol.value != 0)
        .map(|symbol| (symbol.value, symbol.name.to_owned()))
        .collect();
    let mut records = Vec::new();
    let mut gaps = Vec::new();
    let mut included = 0_u64;
    let mut unknown = 0_u64;
    for symbol in candidates {
        if symbol.is_undefined() {
            records.push(StrictRttiRecord::ExternalTypeInfo {
                symbol: symbol.name.to_owned(),
                library_ordinal: i32::from(symbol.library_ordinal() as i8),
                weak: symbol.is_weak_ref(),
            });
            included += 1;
            continue;
        }
        if !symbol.is_defined() || symbol.value == 0 {
            gaps.push(StrictRttiGap {
                symbol: Some(symbol.name.to_owned()),
                field: "symbol".into(),
                code: StrictRttiGapCode::RecordMalformed,
                source_code: None,
            });
            unknown += 1;
            continue;
        }
        match decoder.decode(symbol) {
            Ok(record) => {
                records.push(StrictRttiRecord::TypeInfo {
                    record: Box::new(record),
                });
                included += 1;
            }
            Err(error) => {
                let code = match error.kind {
                    crate::CppErrorKind::Unsupported => StrictRttiGapCode::FamilyUnsupported,
                    crate::CppErrorKind::InvalidAddress => StrictRttiGapCode::PointerUnresolved,
                    crate::CppErrorKind::OutOfBounds | crate::CppErrorKind::InvalidFormat => {
                        if error.message().contains("type name") {
                            StrictRttiGapCode::TypeNameInvalid
                        } else if error.message().contains("limit") {
                            StrictRttiGapCode::StructuralLimitExceeded
                        } else {
                            StrictRttiGapCode::RecordMalformed
                        }
                    }
                    _ => StrictRttiGapCode::RecordMalformed,
                };
                gaps.push(StrictRttiGap {
                    symbol: Some(symbol.name.to_owned()),
                    field: "typeinfo".into(),
                    code,
                    source_code: Some(error.code().to_owned()),
                });
                unknown += 1;
            }
        }
    }
    let outcome = if gaps.is_empty() {
        StrictRttiOutcome::Complete
    } else {
        StrictRttiOutcome::Rejected
    };
    let batch = StrictRttiBatch {
        outcome,
        records,
        observations: decoder.observations,
        gaps,
        conservation: StrictRttiConservation {
            attempted,
            included,
            unknown,
            excluded: 0,
        },
    };
    batch.validate(limits)?;
    Ok(batch)
}

fn preflight_limit_batch(field: &str, limits: StrictRttiLimits) -> Result<StrictRttiBatch> {
    let batch = StrictRttiBatch {
        outcome: StrictRttiOutcome::Rejected,
        records: Vec::new(),
        observations: Vec::new(),
        gaps: vec![StrictRttiGap {
            symbol: None,
            field: field.to_owned(),
            code: StrictRttiGapCode::StructuralLimitExceeded,
            source_code: None,
        }],
        conservation: StrictRttiConservation {
            attempted: 0,
            included: 0,
            unknown: 0,
            excluded: 0,
        },
    };
    batch.validate(limits)?;
    Ok(batch)
}

/// Decode strict Itanium RTTI from a borrowed thin-image byte source.
pub fn decode_strict_rtti_from_source<S>(
    source: &S,
    limits: StrictRttiLimits,
) -> Result<StrictRttiBatch>
where
    S: AsRef<[u8]> + ?Sized,
{
    let macho = crate::parse_source(source)?;
    decode_strict_rtti(&macho, limits)
}

fn build_pointer_fixups(macho: &MachoFile<'_>) -> Result<BTreeMap<u64, PointerFixup>> {
    let mut values = BTreeMap::new();
    let has_chained = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::DyldChainedFixups(_)));
    if has_chained && !cfg!(feature = "fixups") {
        return Err(Error::unsupported(
            "strict RTTI image uses chained fixups but the fixups feature is disabled",
        ));
    }
    if has_chained {
        let chained = macho_dyld::parse_chained_fixups(macho)?;
        for fixup in &chained.fixups {
            let segment = macho
                .segments()
                .get(fixup.segment_index)
                .ok_or_else(|| Error::format("chained RTTI fixup has an invalid segment index"))?;
            let file_offset = segment
                .file_offset()
                .0
                .checked_add(fixup.segment_offset)
                .ok_or_else(|| Error::format("chained RTTI fixup file offset overflows"))?;
            let value = match &fixup.kind {
                FixupKind::Rebase { target } => PointerFixup {
                    encoding: StrictPointerEncoding::ChainedRebase,
                    authentication: StrictPointerAuthentication::NotApplicable,
                    target: local_rebase_target(macho, *target)?,
                },
                FixupKind::AuthRebase {
                    target,
                    diversity,
                    key,
                    addr_div,
                } => PointerFixup {
                    encoding: StrictPointerEncoding::ChainedRebase,
                    authentication: StrictPointerAuthentication::Authenticated {
                        key: *key,
                        diversity: *diversity,
                        address_diversity: *addr_div,
                    },
                    target: local_rebase_target(macho, *target)?,
                },
                FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                    let import = chained.imports.get(*import_index as usize).ok_or_else(|| {
                        Error::format("chained RTTI bind has an invalid import index")
                    })?;
                    let authentication = match &fixup.kind {
                        FixupKind::AuthBind {
                            diversity,
                            key,
                            addr_div,
                            ..
                        } => StrictPointerAuthentication::Authenticated {
                            key: *key,
                            diversity: *diversity,
                            address_diversity: *addr_div,
                        },
                        _ => StrictPointerAuthentication::NotApplicable,
                    };
                    PointerFixup {
                        encoding: StrictPointerEncoding::ChainedBind {
                            addend: import.addend,
                            weak: import.weak,
                        },
                        authentication,
                        target: StrictPointerTarget::External {
                            symbol: import.name.to_owned(),
                            library_ordinal: import.lib_ordinal,
                        },
                    }
                }
                _ => {
                    return Err(Error::unsupported(
                        "unknown chained-fixup kind in strict RTTI field map",
                    ));
                }
            };
            if values.insert(file_offset, value).is_some() {
                return Err(Error::format("duplicate chained RTTI fixup location"));
            }
        }
        return Ok(values);
    }

    let has_legacy = macho.load_commands().iter().any(|command| {
        matches!(
            command.kind(),
            LoadCommand::DyldInfo(_) | LoadCommand::DyldInfoOnly(_)
        )
    });
    if has_legacy && !cfg!(feature = "fixups") {
        return Err(Error::unsupported(
            "strict RTTI image uses legacy fixups but the fixups feature is disabled",
        ));
    }
    if !has_legacy {
        return Ok(values);
    }
    let mut local_symbols = BTreeMap::<&str, Option<u64>>::new();
    for symbol in macho.ext::<SymbolTable<'_>>()?.symbols() {
        if !symbol.is_defined() || symbol.value == 0 {
            continue;
        }
        local_symbols
            .entry(symbol.name)
            .and_modify(|value| {
                if *value != Some(symbol.value) {
                    *value = None;
                }
            })
            .or_insert(Some(symbol.value));
    }
    let (regular, weak, lazy) = macho_dyld::parse_bind_entries(macho)?;
    for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let segment = macho
            .segments()
            .get(bind.segment_index)
            .ok_or_else(|| Error::format("legacy RTTI bind has an invalid segment index"))?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(bind.segment_offset)
            .ok_or_else(|| Error::format("legacy RTTI bind file offset overflows"))?;
        let value = PointerFixup {
            encoding: StrictPointerEncoding::LegacyBind {
                addend: bind.addend,
                weak: bind.weak,
                lazy: bind.lazy,
            },
            authentication: StrictPointerAuthentication::NotApplicable,
            target: if bind.lib_ordinal == 0 {
                local_symbols
                    .get(bind.symbol_name)
                    .and_then(|value| *value)
                    .map_or_else(
                        || StrictPointerTarget::External {
                            symbol: bind.symbol_name.to_owned(),
                            library_ordinal: 0,
                        },
                        |va| StrictPointerTarget::Local { va },
                    )
            } else {
                StrictPointerTarget::External {
                    symbol: bind.symbol_name.to_owned(),
                    library_ordinal: bind
                        .lib_ordinal
                        .clamp(i64::from(i32::MIN), i64::from(i32::MAX))
                        as i32,
                }
            },
        };
        if values.insert(file_offset, value).is_some() {
            return Err(Error::format("duplicate legacy RTTI bind location"));
        }
    }
    for rebase in macho_dyld::parse_rebase_entries(macho)? {
        let segment = macho
            .segments()
            .get(rebase.segment_index)
            .ok_or_else(|| Error::format("legacy RTTI rebase has an invalid segment index"))?;
        let file_offset = segment
            .file_offset()
            .0
            .checked_add(rebase.segment_offset)
            .ok_or_else(|| Error::format("legacy RTTI rebase file offset overflows"))?;
        let va = macho
            .address_map()
            .thin_offset_to_va(ThinFileOffset(file_offset))?;
        let raw = read_raw_pointer(macho, va)?;
        let value = PointerFixup {
            encoding: StrictPointerEncoding::LegacyRebase,
            authentication: StrictPointerAuthentication::NotApplicable,
            target: if raw == 0 {
                StrictPointerTarget::Null
            } else {
                StrictPointerTarget::Local { va: raw }
            },
        };
        if let Some(existing) = values.get(&file_offset) {
            // A legacy lazy pointer is initially rebased to dyld's stub helper
            // and later overwritten by the lazy bind. Both opcode streams
            // therefore own the same storage. The eventual bind is the
            // semantic target; all other cross-stream collisions are corrupt.
            if matches!(
                existing.encoding,
                StrictPointerEncoding::LegacyBind { lazy: true, .. }
            ) || existing.target == value.target
            {
                continue;
            }
            return Err(Error::format(format!(
                "conflicting legacy RTTI fixup at file offset {file_offset:#x}: {existing:?} versus {value:?}"
            )));
        }
        values.insert(file_offset, value);
    }
    Ok(values)
}

fn local_rebase_target(macho: &MachoFile<'_>, target: u64) -> Result<StrictPointerTarget> {
    let va = macho
        .image_base()
        .0
        .checked_add(target)
        .ok_or_else(|| Error::format("chained RTTI rebase target overflows"))?;
    Ok(if va == 0 {
        StrictPointerTarget::Null
    } else {
        StrictPointerTarget::Local { va }
    })
}

fn read_raw_pointer(macho: &MachoFile<'_>, va: Va) -> Result<u64> {
    let width = if macho.is_64bit() { 8 } else { 4 };
    let bytes = macho.read_bytes_at_va(va, width)?;
    if width == 8 {
        Ok(macho.endian().read_u64(
            bytes
                .try_into()
                .map_err(|_| Error::format("RTTI pointer read returned the wrong width"))?,
        ))
    } else {
        Ok(u64::from(
            macho.endian().read_u32(
                bytes
                    .try_into()
                    .map_err(|_| Error::format("RTTI pointer read returned the wrong width"))?,
            ),
        ))
    }
}

pub(super) fn is_typeinfo_symbol(name: &str) -> bool {
    name.starts_with("__ZTI") || name.starts_with("_ZTI")
}

fn classify_family(name: &str) -> Option<ItaniumTypeInfoFamily> {
    [
        (
            "__fundamental_type_info",
            ItaniumTypeInfoFamily::Fundamental,
        ),
        ("__array_type_info", ItaniumTypeInfoFamily::Array),
        ("__function_type_info", ItaniumTypeInfoFamily::Function),
        ("__enum_type_info", ItaniumTypeInfoFamily::Enum),
        (
            "__si_class_type_info",
            ItaniumTypeInfoFamily::SingleInheritanceClass,
        ),
        (
            "__vmi_class_type_info",
            ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass,
        ),
        ("__class_type_info", ItaniumTypeInfoFamily::Class),
        ("__pointer_type_info", ItaniumTypeInfoFamily::Pointer),
        (
            "__pointer_to_member_type_info",
            ItaniumTypeInfoFamily::PointerToMember,
        ),
        ("__qualified_type_info", ItaniumTypeInfoFamily::Qualified),
    ]
    .into_iter()
    .find_map(|(needle, family)| name.contains(needle).then_some(family))
}

pub(crate) fn checked_add(left: u64, right: u64) -> Result<u64> {
    left.checked_add(right)
        .ok_or_else(|| Error::format("strict RTTI address arithmetic overflows"))
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let mask = alignment
        .checked_sub(1)
        .ok_or_else(|| Error::format("strict RTTI alignment is zero"))?;
    value
        .checked_add(mask)
        .map(|candidate| candidate & !mask)
        .ok_or_else(|| Error::format("strict RTTI alignment overflows"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admitted_itanium_family_registry_is_exact() {
        for (symbol, expected) in [
            (
                "__ZTVN10__cxxabiv123__fundamental_type_infoE",
                ItaniumTypeInfoFamily::Fundamental,
            ),
            (
                "__ZTVN10__cxxabiv117__array_type_infoE",
                ItaniumTypeInfoFamily::Array,
            ),
            (
                "__ZTVN10__cxxabiv120__function_type_infoE",
                ItaniumTypeInfoFamily::Function,
            ),
            (
                "__ZTVN10__cxxabiv116__enum_type_infoE",
                ItaniumTypeInfoFamily::Enum,
            ),
            (
                "__ZTVN10__cxxabiv117__class_type_infoE",
                ItaniumTypeInfoFamily::Class,
            ),
            (
                "__ZTVN10__cxxabiv120__si_class_type_infoE",
                ItaniumTypeInfoFamily::SingleInheritanceClass,
            ),
            (
                "__ZTVN10__cxxabiv121__vmi_class_type_infoE",
                ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass,
            ),
            (
                "__ZTVN10__cxxabiv119__pointer_type_infoE",
                ItaniumTypeInfoFamily::Pointer,
            ),
            (
                "__ZTVN10__cxxabiv129__pointer_to_member_type_infoE",
                ItaniumTypeInfoFamily::PointerToMember,
            ),
            (
                "__ZTVN10__cxxabiv121__qualified_type_infoE",
                ItaniumTypeInfoFamily::Qualified,
            ),
        ] {
            assert_eq!(classify_family(symbol), Some(expected));
        }
        assert_eq!(classify_family("__ZTV7Mystery"), None);
    }
}
