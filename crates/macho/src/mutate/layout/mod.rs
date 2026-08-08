mod encoder;

use crate::mutate::format::io::Endian;
use crate::mutate::model::header::Bitness;
use crate::mutate::model::load_command::LoadCommand;
use crate::mutate::model::macho_file::MachoFile;
use crate::mutate::model::segment::Segment;
use crate::mutate::section::{EditableSegment, SectionContent};
use crate::mutate::{Error, Result};

pub(crate) use encoder::encode_edited_load_command;
pub use encoder::encode_load_command;

/// Build the final binary bytes from the editor's state.
pub fn build_binary(
    original: &MachoFile<'_>,
    commands: &[(LoadCommand, Vec<u8>)],
    segments: &[Segment],
) -> Result<Vec<u8>> {
    let segments = segments
        .iter()
        .cloned()
        .map(EditableSegment::from)
        .collect::<Vec<_>>();
    build_edited_binary(original, commands, &segments)
}

pub(crate) fn build_edited_binary(
    original: &MachoFile<'_>,
    commands: &[(LoadCommand, Vec<u8>)],
    segments: &[EditableSegment<'_>],
) -> Result<Vec<u8>> {
    validate_added_section_ownership(original, commands, segments)?;

    let endian = original.endian();
    let header_size = original.bitness().header_size();
    let original_header_end = header_size
        .checked_add(original.header().load_commands_size() as usize)
        .ok_or_else(|| Error::invalid("original load-command range overflow"))?;
    if original_header_end > original.bytes().len() {
        return Err(Error::invalid(
            "original load-command range exceeds the input",
        ));
    }

    let new_sizeofcmds = commands.iter().try_fold(0usize, |total, (_, bytes)| {
        total
            .checked_add(bytes.len())
            .ok_or_else(|| Error::invalid("encoded load-command size overflow"))
    })?;
    let new_sizeofcmds_u32 = u32::try_from(new_sizeofcmds)
        .map_err(|_| Error::invalid("encoded load commands exceed Mach-O's u32 size field"))?;
    let new_header_end = header_size
        .checked_add(new_sizeofcmds)
        .ok_or_else(|| Error::invalid("new load-command range overflow"))?;
    let payload_start = first_occupied_offset(original, original_header_end);
    if new_header_end > payload_start {
        return Err(Error::unsupported(format!(
            "insufficient load-command slack: commands end at {new_header_end:#x}, but existing payload begins at {payload_start:#x}; relocating existing payload is unsupported"
        )));
    }

    let ncmds = u32::try_from(commands.len())
        .map_err(|_| Error::invalid("load-command count exceeds Mach-O's u32 field"))?;
    let mut header_bytes = original.bytes()[..header_size].to_vec();
    write_u32_at(&mut header_bytes, endian, 16, ncmds);
    write_u32_at(&mut header_bytes, endian, 20, new_sizeofcmds_u32);

    let mut output = Vec::with_capacity(original.bytes().len());
    output.extend_from_slice(&header_bytes);
    for (_, encoded) in commands {
        output.extend_from_slice(encoded);
    }
    output.resize(payload_start, 0);
    output.extend_from_slice(&original.bytes()[payload_start..]);

    for section in segments.iter().flat_map(|segment| &segment.added_sections) {
        let SectionContent::FileBacked(bytes) = section.request.content() else {
            continue;
        };
        let start = usize::try_from(section.file_offset)
            .map_err(|_| Error::invalid("new section offset cannot be represented on this host"))?;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| Error::invalid("new section payload range overflow"))?;
        if output.len() < end {
            output.resize(end, 0);
        }
        output[start..end].copy_from_slice(bytes);
    }

    Ok(output)
}

#[derive(Debug)]
struct ProtectedFileRange {
    start: u64,
    end: u64,
    owner: String,
}

/// Prove that bytes written for added sections do not already belong to a
/// modeled file-backed structure. Zero bytes are not evidence of free space:
/// an `LC_NOTE`, symbol table, relocation table, or another command-owned blob
/// may legitimately contain only zeroes. This check belongs at final build so
/// it is independent of the order in which editor operations were staged.
fn validate_added_section_ownership(
    original: &MachoFile<'_>,
    commands: &[(LoadCommand, Vec<u8>)],
    segments: &[EditableSegment<'_>],
) -> Result<()> {
    fn add_range(
        ranges: &mut Vec<ProtectedFileRange>,
        start: u64,
        count: u64,
        stride: u64,
        owner: impl Into<String>,
    ) -> Result<()> {
        if count == 0 || stride == 0 {
            return Ok(());
        }
        let size = count
            .checked_mul(stride)
            .ok_or_else(|| Error::invalid("modeled file range size overflow"))?;
        let end = start
            .checked_add(size)
            .ok_or_else(|| Error::invalid("modeled file range end overflow"))?;
        ranges.push(ProtectedFileRange {
            start,
            end,
            owner: owner.into(),
        });
        Ok(())
    }

    let mut ranges = Vec::new();
    for segment in original.segments() {
        add_range(
            &mut ranges,
            segment.file_offset().0,
            segment.file_size(),
            1,
            format!("segment {}", segment.name()),
        )?;
        for section in segment.sections() {
            add_range(
                &mut ranges,
                section.relocation_offset().0,
                u64::from(section.relocation_count()),
                8,
                format!(
                    "relocations for section {},{}",
                    segment.name(),
                    section.section_name()
                ),
            )?;
        }
    }

    let symbol_size = match original.bitness() {
        Bitness::Bits32 => 12,
        Bitness::Bits64 => 16,
    };
    let module_size = match original.bitness() {
        Bitness::Bits32 => 52,
        Bitness::Bits64 => 56,
    };
    let input_len = u64::try_from(original.bytes().len())
        .map_err(|_| Error::invalid("input length exceeds u64"))?;
    let mut has_unknown_command = false;

    for (command, _) in commands {
        match command {
            LoadCommand::Symtab(data) => {
                add_range(
                    &mut ranges,
                    data.sym_offset.into(),
                    data.nsyms.into(),
                    symbol_size,
                    "LC_SYMTAB symbols",
                )?;
                add_range(
                    &mut ranges,
                    data.str_offset.into(),
                    data.str_size.into(),
                    1,
                    "LC_SYMTAB strings",
                )?;
            }
            LoadCommand::Dysymtab(data) => {
                for (offset, count, stride, owner) in [
                    (data.tocoff, data.ntoc, 8, "LC_DYSYMTAB table of contents"),
                    (
                        data.modtaboff,
                        data.nmodtab,
                        module_size,
                        "LC_DYSYMTAB modules",
                    ),
                    (
                        data.extrefsymoff,
                        data.nextrefsyms,
                        4,
                        "LC_DYSYMTAB external references",
                    ),
                    (
                        data.indirectsymoff,
                        data.nindirectsyms,
                        4,
                        "LC_DYSYMTAB indirect symbols",
                    ),
                    (
                        data.extreloff,
                        data.nextrel,
                        8,
                        "LC_DYSYMTAB external relocations",
                    ),
                    (
                        data.locreloff,
                        data.nlocrel,
                        8,
                        "LC_DYSYMTAB local relocations",
                    ),
                ] {
                    add_range(&mut ranges, offset.into(), count.into(), stride, owner)?;
                }
            }
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
                for (offset, size, owner) in [
                    (data.rebase_off, data.rebase_size, "LC_DYLD_INFO rebases"),
                    (data.bind_off, data.bind_size, "LC_DYLD_INFO bindings"),
                    (
                        data.weak_bind_off,
                        data.weak_bind_size,
                        "LC_DYLD_INFO weak bindings",
                    ),
                    (
                        data.lazy_bind_off,
                        data.lazy_bind_size,
                        "LC_DYLD_INFO lazy bindings",
                    ),
                    (data.export_off, data.export_size, "LC_DYLD_INFO exports"),
                ] {
                    add_range(&mut ranges, offset.into(), size.into(), 1, owner)?;
                }
            }
            LoadCommand::CodeSignature(data)
            | LoadCommand::SegmentSplitInfo(data)
            | LoadCommand::FunctionStarts(data)
            | LoadCommand::DataInCode(data)
            | LoadCommand::DylibCodeSignDrs(data)
            | LoadCommand::LinkerOptimizationHint(data)
            | LoadCommand::DyldExportsTrie(data)
            | LoadCommand::DyldChainedFixups(data)
            | LoadCommand::AtomInfo(data)
            | LoadCommand::FunctionVariants(data)
            | LoadCommand::FunctionVariantFixups(data) => add_range(
                &mut ranges,
                data.data_offset.into(),
                data.data_size.into(),
                1,
                command.name(),
            )?,
            LoadCommand::EncryptionInfo(data) | LoadCommand::EncryptionInfo64(data) => add_range(
                &mut ranges,
                data.crypt_offset.into(),
                data.crypt_size.into(),
                1,
                command.name(),
            )?,
            LoadCommand::TwolevelHints(data) => add_range(
                &mut ranges,
                data.offset.into(),
                data.nhints.into(),
                4,
                "LC_TWOLEVEL_HINTS",
            )?,
            LoadCommand::Note(data) => add_range(
                &mut ranges,
                data.offset,
                data.size,
                1,
                format!("LC_NOTE {}", data.data_owner),
            )?,
            LoadCommand::FilesetEntry(data) => {
                // A fileset command gives the nested image's start, not its
                // length. Conservatively protect it through the original EOF.
                if data.file_offset < input_len {
                    add_range(
                        &mut ranges,
                        data.file_offset,
                        input_len - data.file_offset,
                        1,
                        format!("LC_FILESET_ENTRY {}", data.entry_id),
                    )?;
                }
            }
            LoadCommand::Unknown(_) => has_unknown_command = true,
            _ => {}
        }
    }

    for section in segments.iter().flat_map(|segment| &segment.added_sections) {
        let SectionContent::FileBacked(bytes) = section.request.content() else {
            continue;
        };
        let write_end =
            section
                .file_offset
                .checked_add(u64::try_from(bytes.len()).map_err(|_| {
                    Error::invalid("new section length cannot be represented as u64")
                })?)
                .ok_or_else(|| Error::invalid("new section payload range overflow"))?
                .min(input_len);
        if write_end <= section.file_offset {
            continue;
        }
        if has_unknown_command {
            return Err(Error::unsupported(format!(
                "cannot place section {},{} in existing file bytes while an unknown load command may own file ranges",
                section.request.segment_name(),
                section.request.section_name()
            )));
        }
        if let Some(protected) = ranges
            .iter()
            .find(|protected| protected.start < write_end && section.file_offset < protected.end)
        {
            return Err(Error::unsupported(format!(
                "cannot place section {},{} in {:#x}..{write_end:#x}: the range overlaps {} at {:#x}..{:#x}",
                section.request.segment_name(),
                section.request.section_name(),
                section.file_offset,
                protected.owner,
                protected.start,
                protected.end
            )));
        }
    }

    Ok(())
}

/// Return the first byte that is known to be payload rather than command slack.
///
/// Mach-O has no explicit load-command capacity field. We therefore combine
/// modeled file-offset metadata with the first non-zero padding byte and only
/// permit command growth before the earliest result. Existing payload is never
/// shifted: doing so would also require rewriting symbol values, fixups, and
/// other address-bearing data that this crate does not yet model.
fn first_occupied_offset(macho: &MachoFile<'_>, header_end: usize) -> usize {
    fn consider(first: &mut usize, input_len: usize, header_end: usize, offset: u64, size: u64) {
        if size == 0 || offset < header_end as u64 {
            return;
        }
        if let Ok(offset) = usize::try_from(offset) {
            *first = (*first).min(offset.min(input_len));
        }
    }

    let input_len = macho.bytes().len();
    let mut first = input_len;

    for segment in macho.segments() {
        let mut has_file_section = false;
        for section in segment.sections() {
            if !section.section_type().is_zerofill() && section.size() > 0 {
                has_file_section = true;
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    section.offset().0,
                    section.size(),
                );
            }
            if section.relocation_count() > 0 {
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    section.relocation_offset().0,
                    u64::from(section.relocation_count()),
                );
            }
        }
        if segment.file_offset().0 > 0 {
            consider(
                &mut first,
                input_len,
                header_end,
                segment.file_offset().0,
                segment.file_size(),
            );
        } else if segment.file_size() > header_end as u64 && !has_file_section {
            // A file-backed segment without sections gives us no proof that any
            // byte following the commands is padding.
            first = first.min(header_end);
        }
    }

    for command in macho.load_commands() {
        match command.kind() {
            LoadCommand::Symtab(data) => {
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    data.sym_offset.into(),
                    data.nsyms.into(),
                );
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    data.str_offset.into(),
                    data.str_size.into(),
                );
            }
            LoadCommand::Dysymtab(data) => {
                for (offset, count) in [
                    (data.tocoff, data.ntoc),
                    (data.modtaboff, data.nmodtab),
                    (data.extrefsymoff, data.nextrefsyms),
                    (data.indirectsymoff, data.nindirectsyms),
                    (data.extreloff, data.nextrel),
                    (data.locreloff, data.nlocrel),
                ] {
                    consider(
                        &mut first,
                        input_len,
                        header_end,
                        offset.into(),
                        count.into(),
                    );
                }
            }
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => {
                for (offset, size) in [
                    (data.rebase_off, data.rebase_size),
                    (data.bind_off, data.bind_size),
                    (data.weak_bind_off, data.weak_bind_size),
                    (data.lazy_bind_off, data.lazy_bind_size),
                    (data.export_off, data.export_size),
                ] {
                    consider(
                        &mut first,
                        input_len,
                        header_end,
                        offset.into(),
                        size.into(),
                    );
                }
            }
            LoadCommand::CodeSignature(data)
            | LoadCommand::SegmentSplitInfo(data)
            | LoadCommand::FunctionStarts(data)
            | LoadCommand::DataInCode(data)
            | LoadCommand::DylibCodeSignDrs(data)
            | LoadCommand::LinkerOptimizationHint(data)
            | LoadCommand::DyldExportsTrie(data)
            | LoadCommand::DyldChainedFixups(data)
            | LoadCommand::AtomInfo(data)
            | LoadCommand::FunctionVariants(data)
            | LoadCommand::FunctionVariantFixups(data) => {
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    data.data_offset.into(),
                    data.data_size.into(),
                );
            }
            LoadCommand::EncryptionInfo(data) | LoadCommand::EncryptionInfo64(data) => {
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    data.crypt_offset.into(),
                    data.crypt_size.into(),
                );
            }
            LoadCommand::TwolevelHints(data) => {
                consider(
                    &mut first,
                    input_len,
                    header_end,
                    data.offset.into(),
                    data.nhints.into(),
                );
            }
            LoadCommand::Note(data) => {
                consider(&mut first, input_len, header_end, data.offset, data.size)
            }
            LoadCommand::FilesetEntry(data) => {
                consider(&mut first, input_len, header_end, data.file_offset, 1)
            }
            LoadCommand::Main(data) => {
                consider(&mut first, input_len, header_end, data.entry_offset, 1)
            }
            LoadCommand::Unknown(_) => {
                // An unknown command may carry file offsets we cannot identify
                // or rewrite, so none of the existing slack is proven safe.
                first = first.min(header_end);
            }
            _ => {}
        }
    }

    if let Some(relative) = macho.bytes()[header_end..first]
        .iter()
        .position(|byte| *byte != 0)
    {
        first = header_end + relative;
    }
    first
}

fn write_u32_at(buf: &mut [u8], endian: Endian, offset: usize, val: u32) {
    let encoded = endian.encode_u32(val).to_ne_bytes();
    buf[offset..offset + 4].copy_from_slice(&encoded);
}
