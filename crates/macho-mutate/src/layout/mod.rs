mod encoder;

use crate::Result;
use crate::format::io::Endian;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::model::segment::Segment;
use crate::section::{EditableSegment, SectionContent};

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
    segments: &[EditableSegment],
) -> Result<Vec<u8>> {
    let endian = original.endian();
    let bitness = original.bitness();
    let header_size = bitness.header_size();

    // Compute new sizeofcmds
    let new_sizeofcmds: usize = commands.iter().map(|(_, bytes)| bytes.len()).sum();

    // Find the original first segment data offset
    let original_data_start = find_first_data_offset(original);
    let page_size = infer_page_size(original);

    // New data start: header + commands, aligned to page boundary
    let new_data_start = align_up(header_size + new_sizeofcmds, page_size);

    // Delta: how much segment data shifts
    let delta = new_data_start as i64 - original_data_start as i64;

    // Build the header
    let mut output = Vec::with_capacity(
        original
            .bytes()
            .len()
            .saturating_add(delta.unsigned_abs() as usize),
    );

    // Write header
    let mut header_bytes = original.bytes()[..header_size].to_vec();
    // Update ncmds
    let ncmds = commands.len() as u32;
    write_u32_at(&mut header_bytes, endian, 16, ncmds); // ncmds at offset 16
    write_u32_at(&mut header_bytes, endian, 20, new_sizeofcmds as u32); // sizeofcmds at offset 20
    output.extend_from_slice(&header_bytes);

    // Write all encoded commands (with delta-adjusted offsets)
    for (lc, encoded) in commands {
        let mut adjusted = encoded.clone();
        apply_delta_to_command(lc, &mut adjusted, endian, delta)?;
        output.extend_from_slice(&adjusted);
    }

    // Pad to new_data_start
    while output.len() < new_data_start {
        output.push(0);
    }

    // Copy original segment data (everything after the original command region)
    if original_data_start < original.bytes().len() {
        output.extend_from_slice(&original.bytes()[original_data_start..]);
    }

    for section in segments.iter().flat_map(|segment| &segment.added_sections) {
        let SectionContent::FileBacked(bytes) = section.request.content() else {
            continue;
        };
        let adjusted_offset = add_signed(section.file_offset, delta)?;
        let start = usize::try_from(adjusted_offset).map_err(|_| {
            crate::Error::invalid("new section offset cannot be represented on this host")
        })?;
        let end = start
            .checked_add(bytes.len())
            .ok_or_else(|| crate::Error::invalid("new section payload range overflow"))?;
        if output.len() < end {
            output.resize(end, 0);
        }
        output[start..end].copy_from_slice(bytes);
    }

    Ok(output)
}

fn add_signed(value: u64, delta: i64) -> Result<u64> {
    let adjusted = i128::from(value) + i128::from(delta);
    u64::try_from(adjusted).map_err(|_| crate::Error::invalid("adjusted section offset overflow"))
}

fn find_first_data_offset(macho: &MachoFile<'_>) -> usize {
    // Find the smallest non-zero file offset among segments with file data.
    // This is where segment content begins in the file. For executables,
    // __TEXT starts at offset 0 (overlapping header+commands), so the actual
    // content beyond the header starts at the page-aligned offset after commands.
    // For __DATA_CONST at e.g. 0x4000, that's the first distinct data region.
    //
    // The key insight: we want the offset where the header+commands region ENDS
    // and segment data that we need to preserve BEGINS. For __TEXT at offset 0,
    // the header and commands are already part of __TEXT, so we need to find
    // where the content AFTER the commands starts. That's the page-aligned
    // boundary after header + sizeofcmds.
    let header_end = macho.bitness().header_size() + macho.header().load_commands_size() as usize;
    let page_size = infer_page_size(macho);
    align_up(header_end, page_size)
}

fn infer_page_size(macho: &MachoFile<'_>) -> usize {
    for seg in macho.segments() {
        if seg.file_size() > 0 && seg.file_offset().0 > 0 {
            let off = seg.file_offset().0 as usize;
            if off % 0x4000 == 0 {
                return 0x4000;
            }
            if off % 0x1000 == 0 {
                return 0x1000;
            }
        }
    }
    0x1000 // default
}

fn align_up(val: usize, align: usize) -> usize {
    (val + align - 1) & !(align - 1)
}

fn write_u32_at(buf: &mut [u8], endian: Endian, offset: usize, val: u32) {
    let encoded = endian.encode_u32(val).to_ne_bytes();
    buf[offset..offset + 4].copy_from_slice(&encoded);
}

/// Adjust file offset fields within an encoded command by a delta.
fn apply_delta_to_command(
    lc: &LoadCommand,
    encoded: &mut [u8],
    endian: Endian,
    delta: i64,
) -> Result<()> {
    match lc {
        LoadCommand::Segment64(_) => {
            // Layout: cmd(4)+cmdsize(4)+segname(16)+vmaddr(8)+vmsize(8)+fileoff(8)+...
            // fileoff is at byte offset 40, nsects at 64
            adjust_u64(encoded, endian, 40, delta); // fileoff
            let nsects = read_u32(encoded, endian, 64) as usize;
            for i in 0..nsects {
                let base = 72 + i * 80;
                let sect_offset = read_u32(encoded, endian, base + 48);
                if sect_offset > 0 {
                    adjust_u32(encoded, endian, base + 48, delta);
                }
                let reloff = read_u32(encoded, endian, base + 56);
                if reloff > 0 {
                    adjust_u32(encoded, endian, base + 56, delta);
                }
            }
        }
        LoadCommand::Segment32(_) => {
            // Layout: cmd(4)+cmdsize(4)+segname(16)+vmaddr(4)+vmsize(4)+fileoff(4)+...
            // fileoff is at byte offset 32, nsects at 48
            adjust_u32(encoded, endian, 32, delta); // fileoff
            let nsects = read_u32(encoded, endian, 48) as usize;
            for i in 0..nsects {
                let base = 56 + i * 68;
                let sect_offset = read_u32(encoded, endian, base + 40);
                if sect_offset > 0 {
                    adjust_u32(encoded, endian, base + 40, delta);
                }
                let reloff = read_u32(encoded, endian, base + 44);
                if reloff > 0 {
                    adjust_u32(encoded, endian, base + 44, delta);
                }
            }
        }
        LoadCommand::Symtab(_) => {
            adjust_u32(encoded, endian, 8, delta); // symoff
            adjust_u32(encoded, endian, 16, delta); // stroff
        }
        LoadCommand::Dysymtab(_) => {
            adjust_u32(encoded, endian, 32, delta); // tocoff
            adjust_u32(encoded, endian, 40, delta); // modtaboff
            adjust_u32(encoded, endian, 48, delta); // extrefsymoff
            adjust_u32(encoded, endian, 56, delta); // indirectsymoff
            adjust_u32(encoded, endian, 64, delta); // extreloff
            adjust_u32(encoded, endian, 72, delta); // locreloff
        }
        LoadCommand::DyldInfo(_) | LoadCommand::DyldInfoOnly(_) => {
            adjust_u32(encoded, endian, 8, delta); // rebase_off
            adjust_u32(encoded, endian, 16, delta); // bind_off
            adjust_u32(encoded, endian, 24, delta); // weak_bind_off
            adjust_u32(encoded, endian, 32, delta); // lazy_bind_off
            adjust_u32(encoded, endian, 40, delta); // export_off
        }
        LoadCommand::Main(_) => {
            adjust_u64(encoded, endian, 8, delta); // entryoff
        }
        LoadCommand::CodeSignature(_)
        | LoadCommand::SegmentSplitInfo(_)
        | LoadCommand::FunctionStarts(_)
        | LoadCommand::DataInCode(_)
        | LoadCommand::DylibCodeSignDrs(_)
        | LoadCommand::LinkerOptimizationHint(_)
        | LoadCommand::DyldExportsTrie(_)
        | LoadCommand::DyldChainedFixups(_)
        | LoadCommand::AtomInfo(_)
        | LoadCommand::FunctionVariants(_)
        | LoadCommand::FunctionVariantFixups(_) => {
            adjust_u32(encoded, endian, 8, delta); // dataoff
        }
        LoadCommand::EncryptionInfo(_) => {
            adjust_u32(encoded, endian, 8, delta); // cryptoff
        }
        LoadCommand::EncryptionInfo64(_) => {
            adjust_u32(encoded, endian, 8, delta); // cryptoff
        }
        LoadCommand::TwolevelHints(_) => {
            adjust_u32(encoded, endian, 8, delta); // offset
        }
        LoadCommand::Note(_) => {
            adjust_u64(encoded, endian, 24, delta); // offset
        }
        LoadCommand::FilesetEntry(_) => {
            adjust_u64(encoded, endian, 16, delta); // fileoff
        }
        // Commands with no file offsets to adjust
        _ => {}
    }
    Ok(())
}

fn read_u32(buf: &[u8], endian: Endian, offset: usize) -> u32 {
    if offset + 4 > buf.len() {
        return 0;
    }
    endian.interpret_u32(u32::from_ne_bytes(
        buf[offset..offset + 4].try_into().unwrap(),
    ))
}

fn adjust_u32(buf: &mut [u8], endian: Endian, offset: usize, delta: i64) {
    if offset + 4 > buf.len() {
        return;
    }
    let val = read_u32(buf, endian, offset);
    if val == 0 {
        return;
    } // don't adjust zero offsets
    let new_val = (val as i64 + delta) as u32;
    write_u32_at(buf, endian, offset, new_val);
}

fn adjust_u64(buf: &mut [u8], endian: Endian, offset: usize, delta: i64) {
    if offset + 8 > buf.len() {
        return;
    }
    let val = endian.interpret_u64(u64::from_ne_bytes(
        buf[offset..offset + 8].try_into().unwrap(),
    ));
    if val == 0 {
        return;
    }
    let new_val = (val as i64 + delta) as u64;
    let encoded = endian.encode_u64(new_val).to_ne_bytes();
    buf[offset..offset + 8].copy_from_slice(&encoded);
}
