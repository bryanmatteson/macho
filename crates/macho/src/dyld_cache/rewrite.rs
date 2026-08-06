use super::*;
use crate::dyld_cache::family::*;
use crate::dyld_cache::materialize::*;

pub(super) fn rebuild_symbol_blobs(
    family: &DyldCacheFamily<'_>,
    bytes: &[u8],
    commands: &[(u32, usize, usize)],
    linkedit: &RawCacheSegment,
    bitness: crate::core::model::Bitness,
    endian: crate::core::format::io::Endian,
) -> Result<Vec<(u64, Vec<u8>)>> {
    use crate::core::format::constants::LC_SYMTAB;
    use crate::core::model::Bitness;

    let symtabs = commands
        .iter()
        .filter(|(command, _, _)| *command == LC_SYMTAB)
        .collect::<Vec<_>>();
    if symtabs.len() > 1 {
        return Err(Error::unsupported(
            "multiple LC_SYMTAB commands are not supported for cache reconstruction",
        ));
    }
    let Some((_, command_offset, _)) = symtabs.first().copied() else {
        return Ok(Vec::new());
    };
    let symoff = u64::from(read_macho_u32(
        bytes,
        command_offset + 8,
        endian,
        "symbol table offset",
    )?);
    let nsyms = u64::from(read_macho_u32(
        bytes,
        command_offset + 12,
        endian,
        "symbol count",
    )?);
    let stroff = u64::from(read_macho_u32(
        bytes,
        command_offset + 16,
        endian,
        "string table offset",
    )?);
    let strsize = u64::from(read_macho_u32(
        bytes,
        command_offset + 20,
        endian,
        "string table size",
    )?);
    if nsyms == 0 {
        return Ok(Vec::new());
    }
    if symoff == 0 || stroff == 0 || strsize == 0 {
        return Err(Error::format(
            "nonempty LC_SYMTAB has an absent symbol or string table",
        ));
    }
    let entry_size = if bitness == Bitness::Bits64 { 16 } else { 12 };
    let symbol_size = nsyms
        .checked_mul(entry_size)
        .ok_or_else(|| Error::address("symbol table size overflows"))?;
    validate_old_linkedit_range(linkedit, symoff, symbol_size, "symbol table")?;
    validate_old_linkedit_range(linkedit, stroff, strsize, "string table")?;
    let symbol_va = linkedit
        .vmaddr
        .checked_add(symoff - linkedit.old_fileoff)
        .ok_or_else(|| Error::address("symbol table VA overflows"))?;
    let symbol_end = symbol_va
        .checked_add(symbol_size)
        .ok_or_else(|| Error::address("symbol table VA extent overflows"))?;
    let mut nlists = family.read_va_exact(symbol_va..symbol_end)?;
    let string_base_va = linkedit
        .vmaddr
        .checked_add(stroff - linkedit.old_fileoff)
        .ok_or_else(|| Error::address("string table VA overflows"))?;
    let mut string_pool = vec![0_u8];
    let mut indexes = BTreeMap::<Vec<u8>, u32>::new();
    indexes.insert(Vec::new(), 0);
    for index in 0..nsyms as usize {
        let entry_offset = index * entry_size as usize;
        let old_index = read_macho_u32(&nlists, entry_offset, endian, "nlist string index")?;
        let new_index = if old_index == 0 {
            0
        } else {
            let old_index = u64::from(old_index);
            if old_index >= strsize {
                return Err(Error::format(format!(
                    "nlist[{index}] string index {old_index:#x} exceeds shared string table size {strsize:#x}"
                )));
            }
            let name_va = string_base_va
                .checked_add(old_index)
                .ok_or_else(|| Error::address("symbol name VA overflows"))?;
            let name = family.read_c_string_va(name_va, strsize - old_index, "symbol name")?;
            if let Some(existing) = indexes.get(&name) {
                *existing
            } else {
                let new_index = u32::try_from(string_pool.len())
                    .map_err(|_| Error::unsupported("rebuilt string table exceeds u32"))?;
                string_pool.extend_from_slice(&name);
                string_pool.push(0);
                indexes.insert(name, new_index);
                new_index
            }
        };
        write_macho_u32(&mut nlists, entry_offset, new_index, endian)?;
    }
    Ok(vec![(symoff, nlists), (stroff, string_pool)])
}

fn validate_old_linkedit_range(
    linkedit: &RawCacheSegment,
    offset: u64,
    size: u64,
    subject: &str,
) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::address(format!("{subject} extent overflows")))?;
    let linkedit_end = linkedit
        .old_fileoff
        .checked_add(linkedit.filesize)
        .ok_or_else(|| Error::address("source __LINKEDIT extent overflows"))?;
    if offset < linkedit.old_fileoff || end > linkedit_end {
        return Err(Error::unsupported(format!(
            "{subject} range {offset:#x}..{end:#x} lies outside source __LINKEDIT {:#x}..{linkedit_end:#x}",
            linkedit.old_fileoff
        )));
    }
    Ok(())
}

pub(super) fn patch_segment_and_sections(
    bytes: &mut [u8],
    segment: &RawCacheSegment,
    linkedit: Option<&LinkeditLayout>,
    endian: crate::core::format::io::Endian,
) -> Result<()> {
    if segment.is_64 {
        write_macho_u64(
            bytes,
            segment.command_offset + 40,
            segment.new_fileoff,
            endian,
        )?;
        write_macho_u64(
            bytes,
            segment.command_offset + 48,
            segment.new_filesize,
            endian,
        )?;
    } else {
        let new = u32::try_from(segment.new_fileoff)
            .map_err(|_| Error::unsupported("32-bit segment file offset exceeds u32"))?;
        let new_size = u32::try_from(segment.new_filesize)
            .map_err(|_| Error::unsupported("32-bit segment file size exceeds u32"))?;
        write_macho_u32(bytes, segment.command_offset + 32, new, endian)?;
        write_macho_u32(bytes, segment.command_offset + 36, new_size, endian)?;
    }
    for section in &segment.sections {
        let offset_field = section.command_offset + if segment.is_64 { 48 } else { 40 };
        let relocation_field = section.command_offset + if segment.is_64 { 56 } else { 48 };
        if section.old_offset != 0 {
            let new = if segment.name == "__LINKEDIT" {
                let old =
                    segment
                        .old_fileoff
                        .checked_add(section.address.checked_sub(segment.vmaddr).ok_or_else(
                            || Error::format("__LINKEDIT section precedes its segment"),
                        )?)
                        .ok_or_else(|| Error::address("__LINKEDIT section offset overflows"))?;
                u32::try_from(translate_linkedit_u64(old, linkedit)?)
                    .map_err(|_| Error::unsupported("section file offset exceeds u32"))?
            } else {
                let delta = section.address.checked_sub(segment.vmaddr).ok_or_else(|| {
                    Error::format(format!("section in {} precedes its segment", segment.name))
                })?;
                if delta >= segment.filesize {
                    return Err(Error::unsupported(format!(
                        "file-backed section in {} lies outside reconstructed segment bytes",
                        segment.name
                    )));
                }
                segment
                    .new_fileoff
                    .checked_add(delta)
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or_else(|| Error::unsupported("section file offset exceeds u32"))?
            };
            write_macho_u32(bytes, offset_field, new, endian)?;
        }
        if section.old_relocation_offset != 0 {
            if section.relocation_count == 0 {
                write_macho_u32(bytes, relocation_field, 0, endian)?;
            } else {
                let new = translate_linkedit_u32(section.old_relocation_offset, linkedit)?;
                write_macho_u32(bytes, relocation_field, new, endian)?;
            }
        }
    }
    Ok(())
}

pub(super) fn patch_file_offsets_for_command(
    bytes: &mut [u8],
    command: u32,
    offset: usize,
    linkedit: Option<&LinkeditLayout>,
    segments: &[RawCacheSegment],
    endian: crate::core::format::io::Endian,
) -> Result<()> {
    use crate::core::format::constants::*;

    let patch_u32 = |bytes: &mut [u8], field: usize| -> Result<()> {
        let old = read_macho_u32(bytes, offset + field, endian, "load-command file offset")?;
        let new = translate_linkedit_u32(old, linkedit)?;
        write_macho_u32(bytes, offset + field, new, endian)
    };
    let patch_sized_u32 =
        |bytes: &mut [u8], offset_field: usize, size_field: usize| -> Result<()> {
            let size = read_macho_u32(bytes, offset + size_field, endian, "load-command size")?;
            if size == 0 {
                write_macho_u32(bytes, offset + offset_field, 0, endian)
            } else {
                patch_u32(bytes, offset_field)
            }
        };
    match command {
        LC_SYMTAB => {
            let old_stroff = read_macho_u32(bytes, offset + 16, endian, "string table offset")?;
            let nsyms = read_macho_u32(bytes, offset + 12, endian, "symbol count")?;
            if nsyms == 0 {
                write_macho_u32(bytes, offset + 8, 0, endian)?;
                write_macho_u32(bytes, offset + 16, 0, endian)?;
                write_macho_u32(bytes, offset + 20, 0, endian)?;
            } else {
                patch_sized_u32(bytes, 8, 12)?;
                patch_sized_u32(bytes, 16, 20)?;
                let rebuilt_size = linkedit
                    .and_then(|layout| {
                        layout
                            .synthetic_blobs
                            .iter()
                            .find(|blob| blob.old_anchor == u64::from(old_stroff))
                    })
                    .map(|blob| u32::try_from(blob.bytes.len()))
                    .transpose()
                    .map_err(|_| Error::unsupported("rebuilt string table exceeds u32"))?
                    .ok_or_else(|| Error::format("rebuilt string table metadata is absent"))?;
                write_macho_u32(bytes, offset + 20, rebuilt_size, endian)?;
            }
        }
        LC_DYSYMTAB => {
            for (offset_field, count_field) in
                [(32, 36), (40, 44), (48, 52), (56, 60), (64, 68), (72, 76)]
            {
                patch_sized_u32(bytes, offset_field, count_field)?;
            }
        }
        LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
            for (offset_field, size_field) in [(8, 12), (16, 20), (24, 28), (32, 36), (40, 44)] {
                patch_sized_u32(bytes, offset_field, size_field)?;
            }
        }
        LC_CODE_SIGNATURE => {
            write_macho_u32(bytes, offset + 8, 0, endian)?;
            write_macho_u32(bytes, offset + 12, 0, endian)?;
        }
        LC_SEGMENT_SPLIT_INFO
        | LC_FUNCTION_STARTS
        | LC_DATA_IN_CODE
        | LC_DYLIB_CODE_SIGN_DRS
        | LC_LINKER_OPTIMIZATION_HINT
        | LC_DYLD_EXPORTS_TRIE
        | LC_DYLD_CHAINED_FIXUPS
        | LC_ATOM_INFO
        | LC_FUNCTION_VARIANTS
        | LC_FUNCTION_VARIANT_FIXUPS => patch_sized_u32(bytes, 8, 12)?,
        LC_TWOLEVEL_HINTS => patch_sized_u32(bytes, 8, 12)?,
        LC_MAIN => {
            let old = read_macho_u64(bytes, offset + 8, endian, "entry-point file offset")?;
            let text = segments
                .iter()
                .find(|segment| segment.name == "__TEXT")
                .ok_or_else(|| Error::unsupported("LC_MAIN image has no __TEXT segment"))?;
            let old_end = text
                .old_fileoff
                .checked_add(text.filesize)
                .ok_or_else(|| Error::address("source __TEXT file extent overflows"))?;
            if old < text.old_fileoff || old >= old_end {
                return Err(Error::unsupported(format!(
                    "LC_MAIN entry offset {old:#x} lies outside source __TEXT {:#x}..{old_end:#x}",
                    text.old_fileoff
                )));
            }
            let new = text
                .new_fileoff
                .checked_add(old - text.old_fileoff)
                .ok_or_else(|| Error::address("rewritten LC_MAIN entry offset overflows"))?;
            write_macho_u64(bytes, offset + 8, new, endian)?;
        }
        LC_ENCRYPTION_INFO | LC_ENCRYPTION_INFO_64 => {
            let crypt_size = read_macho_u32(bytes, offset + 12, endian, "encryption size")?;
            if crypt_size != 0 {
                return Err(Error::unsupported(
                    "encrypted cache images are not supported for standalone reconstruction",
                ));
            }
            write_macho_u32(bytes, offset + 8, 0, endian)?;
        }
        LC_NOTE => {
            let old = read_macho_u64(bytes, offset + 24, endian, "note file offset")?;
            let size = read_macho_u64(bytes, offset + 32, endian, "note size")?;
            let new = if size == 0 {
                0
            } else {
                translate_linkedit_u64(old, linkedit)?
            };
            write_macho_u64(bytes, offset + 24, new, endian)?;
        }
        LC_FILESET_ENTRY => {
            return Err(Error::unsupported(
                "LC_FILESET_ENTRY cache images require fileset-aware reconstruction",
            ));
        }
        _ => {}
    }
    Ok(())
}

fn translate_linkedit_u32(old: u32, linkedit: Option<&LinkeditLayout>) -> Result<u32> {
    u32::try_from(translate_linkedit_u64(u64::from(old), linkedit)?)
        .map_err(|_| Error::unsupported("rewritten linkedit offset exceeds u32"))
}

fn translate_linkedit_u64(old: u64, linkedit: Option<&LinkeditLayout>) -> Result<u64> {
    if old == 0 {
        return Ok(0);
    }
    let linkedit = linkedit.ok_or_else(|| {
        Error::unsupported("nonzero linkedit file reference without a __LINKEDIT segment")
    })?;
    if let Some(blob) = linkedit
        .synthetic_blobs
        .iter()
        .find(|blob| blob.old_anchor == old)
    {
        return linkedit
            .new_fileoff
            .checked_add(blob.new_relative_start)
            .ok_or_else(|| Error::address("rewritten synthetic linkedit offset overflows"));
    }
    let range = linkedit
        .ranges
        .iter()
        .find(|range| old >= range.old.start && old < range.old.end)
        .ok_or_else(|| {
            Error::unsupported(format!(
                "linkedit file reference {old:#x} is not in a retained image metadata range"
            ))
        })?;
    linkedit
        .new_fileoff
        .checked_add(range.new_relative_start)
        .and_then(|base| base.checked_add(old - range.old.start))
        .ok_or_else(|| Error::address("rewritten linkedit offset overflows"))
}

pub(super) fn align_up(value: u64, alignment: u64) -> Result<u64> {
    let mask = alignment - 1;
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or_else(|| Error::address("reconstructed file alignment overflows"))
}

pub(super) fn read_macho_u32(
    bytes: &[u8],
    offset: usize,
    endian: crate::core::format::io::Endian,
    subject: &str,
) -> Result<u32> {
    let value: [u8; 4] = bytes
        .get(offset..offset.saturating_add(4))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| Error::format(format!("{subject} is truncated")))?;
    Ok(endian.read_u32(value))
}

pub(super) fn read_macho_u64(
    bytes: &[u8],
    offset: usize,
    endian: crate::core::format::io::Endian,
    subject: &str,
) -> Result<u64> {
    let value: [u8; 8] = bytes
        .get(offset..offset.saturating_add(8))
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| Error::format(format!("{subject} is truncated")))?;
    Ok(endian.read_u64(value))
}

pub(super) fn write_macho_u32(
    bytes: &mut [u8],
    offset: usize,
    value: u32,
    endian: crate::core::format::io::Endian,
) -> Result<()> {
    let encoded = match endian {
        crate::core::format::io::Endian::Little => value.to_le_bytes(),
        crate::core::format::io::Endian::Big => value.to_be_bytes(),
    };
    bytes
        .get_mut(offset..offset.saturating_add(4))
        .ok_or_else(|| Error::format("rewritten u32 field is out of bounds"))?
        .copy_from_slice(&encoded);
    Ok(())
}

fn write_macho_u64(
    bytes: &mut [u8],
    offset: usize,
    value: u64,
    endian: crate::core::format::io::Endian,
) -> Result<()> {
    let encoded = match endian {
        crate::core::format::io::Endian::Little => value.to_le_bytes(),
        crate::core::format::io::Endian::Big => value.to_be_bytes(),
    };
    bytes
        .get_mut(offset..offset.saturating_add(8))
        .ok_or_else(|| Error::format("rewritten u64 field is out of bounds"))?
        .copy_from_slice(&encoded);
    Ok(())
}
