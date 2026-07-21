mod encoder;

use crate::format::io::Endian;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::model::segment::Segment;
use crate::section::{EditableSegment, SectionContent};
use crate::{Error, Result};

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
        return Err(Error::invalid(format!(
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
