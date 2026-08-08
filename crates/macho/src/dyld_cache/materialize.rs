use super::*;
use crate::dyld_cache::family::*;
use crate::dyld_cache::rewrite::*;

#[derive(Debug)]
pub(super) struct CacheMaterializedImage {
    pub(super) bytes: Vec<u8>,
    pub(super) mappings: Vec<CacheMaterializedMapping>,
    pub(super) synthetic_padding: Vec<Range<u64>>,
}

#[derive(Debug)]
pub(super) struct CacheMaterializedMapping {
    pub(super) file: Range<u64>,
    pub(super) rva: Range<u64>,
}

#[derive(Debug, Clone)]
pub(super) struct RawCacheSegment {
    pub(super) command_offset: usize,
    pub(super) is_64: bool,
    pub(super) name: String,
    pub(super) vmaddr: u64,
    pub(super) vmsize: u64,
    pub(super) old_fileoff: u64,
    pub(super) filesize: u64,
    pub(super) new_fileoff: u64,
    pub(super) new_filesize: u64,
    pub(super) sections: Vec<RawCacheSection>,
}

#[derive(Debug, Clone)]
pub(super) struct RawCacheSection {
    pub(super) command_offset: usize,
    pub(super) address: u64,
    pub(super) old_offset: u32,
    pub(super) old_relocation_offset: u32,
    pub(super) relocation_count: u32,
}

#[derive(Debug, Clone)]
pub(super) struct LinkeditLayout {
    pub(super) old_fileoff: u64,
    pub(super) old_vmaddr: u64,
    pub(super) new_fileoff: u64,
    pub(super) new_filesize: u64,
    pub(super) ranges: Vec<LinkeditRange>,
    pub(super) synthetic_blobs: Vec<SyntheticLinkeditBlob>,
}

#[derive(Debug, Clone)]
pub(super) struct LinkeditRange {
    pub(super) old: Range<u64>,
    pub(super) new_relative_start: u64,
}

#[derive(Debug, Clone)]
pub(super) struct SyntheticLinkeditBlob {
    pub(super) old_anchor: u64,
    pub(super) new_relative_start: u64,
    pub(super) bytes: Vec<u8>,
}

pub(super) fn materialize_cache_image(
    family: &DyldCacheFamily<'_>,
    image_address: u64,
    limits: MaterializationLimits,
) -> Result<CacheMaterializedImage> {
    use crate::core::format::constants::{LC_SEGMENT, LC_SEGMENT_64};
    use crate::core::model::{Bitness, MagicNumber};

    let prefix_end = image_address
        .checked_add(32)
        .ok_or_else(|| Error::address("Mach-O header extent overflows"))?;
    let prefix = family.read_va_exact(image_address..prefix_end)?;
    let magic_bytes: [u8; 4] = prefix[0..4]
        .try_into()
        .expect("prefix has a checked 32-byte extent");
    let magic = MagicNumber::from_u32(u32::from_ne_bytes(magic_bytes)).map_err(Error::from)?;
    let endian = magic.endian();
    let bitness = magic.bitness();
    let header_size = bitness.header_size();
    let ncmds = read_macho_u32(&prefix, 16, endian, "Mach-O command count")?;
    let sizeofcmds = u64::from(read_macho_u32(
        &prefix,
        20,
        endian,
        "Mach-O load-command bytes",
    )?);
    if ncmds > limits.max_load_commands {
        return Err(Error::unsupported(format!(
            "Mach-O command count {ncmds} exceeds {}",
            limits.max_load_commands
        )));
    }
    if sizeofcmds > limits.max_load_command_bytes {
        return Err(Error::unsupported(format!(
            "Mach-O load-command bytes {sizeofcmds} exceed {}",
            limits.max_load_command_bytes
        )));
    }
    let commands_end = (header_size as u64)
        .checked_add(sizeofcmds)
        .ok_or_else(|| Error::address("Mach-O load-command extent overflows"))?;
    let header_end = image_address
        .checked_add(commands_end)
        .ok_or_else(|| Error::address("Mach-O mapped header extent overflows"))?;
    let header_and_commands = family.read_va_exact(image_address..header_end)?;
    let commands_end_usize = usize::try_from(commands_end)
        .map_err(|_| Error::unsupported("Mach-O load commands exceed host limits"))?;

    let mut cursor = header_size;
    let mut commands = Vec::with_capacity(ncmds as usize);
    let mut segments = Vec::new();
    for index in 0..ncmds {
        let command = read_macho_u32(&header_and_commands, cursor, endian, "load command")?;
        let command_size = usize::try_from(read_macho_u32(
            &header_and_commands,
            cursor
                .checked_add(4)
                .ok_or_else(|| Error::address("load-command offset overflows"))?,
            endian,
            "load-command size",
        )?)
        .map_err(|_| Error::unsupported("load-command size exceeds host limits"))?;
        let command_end = cursor
            .checked_add(command_size)
            .ok_or_else(|| Error::address("load-command extent overflows"))?;
        if command_size < 8 || command_end > commands_end_usize {
            return Err(Error::format(format!(
                "Mach-O load command {index} is truncated"
            )));
        }
        commands.push((command, cursor, command_size));
        match (command, bitness) {
            (LC_SEGMENT_64, Bitness::Bits64) => segments.push(parse_cache_segment(
                &header_and_commands,
                cursor,
                command_size,
                true,
                endian,
            )?),
            (LC_SEGMENT, Bitness::Bits32) => segments.push(parse_cache_segment(
                &header_and_commands,
                cursor,
                command_size,
                false,
                endian,
            )?),
            (LC_SEGMENT_64, _) | (LC_SEGMENT, _) => {
                return Err(Error::unsupported(
                    "Mach-O segment command does not match header bitness",
                ));
            }
            _ => {}
        }
        cursor = command_end;
    }
    if cursor != commands_end_usize || segments.is_empty() {
        return Err(Error::format(
            "Mach-O load commands or file-backed segments are incomplete",
        ));
    }

    let header_segment = segments
        .iter()
        .position(|segment| {
            segment.filesize != 0
                && image_address >= segment.vmaddr
                && image_address < segment.vmaddr.saturating_add(segment.filesize)
        })
        .ok_or_else(|| Error::unsupported("cache image header is not in a file-backed segment"))?;
    if segments[header_segment].vmaddr != image_address {
        return Err(Error::unsupported(
            "cache image header does not begin at its containing segment VM address",
        ));
    }
    if segments[header_segment].filesize < commands_end {
        return Err(Error::bounds(
            segments[header_segment].vmaddr,
            commands_end,
            segments[header_segment].filesize,
        ));
    }

    let linkedit_index = segments
        .iter()
        .position(|segment| segment.name == "__LINKEDIT");
    let mut linkedit_layout = match linkedit_index {
        Some(index) => Some(build_linkedit_layout(
            family,
            &header_and_commands,
            &commands,
            &segments[index],
            &segments,
            bitness,
            endian,
        )?),
        None => None,
    };
    if let Some(index) = linkedit_index {
        segments[index].new_filesize = linkedit_layout
            .as_ref()
            .expect("layout exists for indexed __LINKEDIT")
            .new_filesize;
    }

    let mut layout_order = Vec::with_capacity(segments.len());
    layout_order.push(header_segment);
    layout_order.extend((0..segments.len()).filter(|index| *index != header_segment));
    let mut file_end = 0_u64;
    let mut synthetic_padding = Vec::new();
    for index in layout_order {
        let segment = &mut segments[index];
        if segment.new_filesize == 0 {
            segment.new_fileoff = 0;
            continue;
        }
        let new_fileoff = if file_end == 0 {
            0
        } else {
            align_up(file_end, 0x4000)?
        };
        if file_end < new_fileoff {
            synthetic_padding.push(file_end..new_fileoff);
        }
        let new_end = new_fileoff
            .checked_add(segment.new_filesize)
            .ok_or_else(|| Error::address("reconstructed segment extent overflows"))?;
        if new_end > limits.max_file_bytes {
            return Err(Error::unsupported(format!(
                "reconstructed Mach-O length {new_end} exceeds {}",
                limits.max_file_bytes
            )));
        }
        segment.new_fileoff = new_fileoff;
        if segment.name == "__LINKEDIT"
            && let Some(layout) = linkedit_layout.as_mut()
        {
            layout.new_fileoff = new_fileoff;
        }
        file_end = new_end;
    }
    if file_end == 0 {
        return Err(Error::format(
            "cache image has no file-backed segment bytes",
        ));
    }
    let mut bytes = vec![
        0_u8;
        usize::try_from(file_end).map_err(|_| Error::unsupported(
            "reconstructed Mach-O exceeds host limits"
        ))?
    ];
    let mut mappings = Vec::new();
    for segment in &segments {
        if segment.new_filesize == 0 {
            continue;
        }
        if segment.new_filesize > segment.vmsize {
            return Err(Error::format(format!(
                "segment {} file size exceeds VM size",
                segment.name
            )));
        }
        if segment.name == "__LINKEDIT" {
            let layout = linkedit_layout
                .as_ref()
                .expect("file-backed __LINKEDIT has a layout");
            for range in &layout.ranges {
                let source_start = layout
                    .old_vmaddr
                    .checked_add(range.old.start - layout.old_fileoff)
                    .ok_or_else(|| Error::address("__LINKEDIT source VA overflows"))?;
                let source_end = source_start
                    .checked_add(range.old.end - range.old.start)
                    .ok_or_else(|| Error::address("__LINKEDIT source extent overflows"))?;
                let source = family.read_va_exact(source_start..source_end)?;
                let destination_start = layout
                    .new_fileoff
                    .checked_add(range.new_relative_start)
                    .ok_or_else(|| Error::address("compacted __LINKEDIT offset overflows"))?;
                let destination_end = destination_start
                    .checked_add(source.len() as u64)
                    .ok_or_else(|| Error::address("compacted __LINKEDIT extent overflows"))?;
                bytes[destination_start as usize..destination_end as usize]
                    .copy_from_slice(&source);
                mappings.push(CacheMaterializedMapping {
                    file: destination_start..destination_end,
                    rva: (source_start - image_address)..(source_end - image_address),
                });
            }
            for blob in &layout.synthetic_blobs {
                let destination_start = layout
                    .new_fileoff
                    .checked_add(blob.new_relative_start)
                    .ok_or_else(|| Error::address("synthetic linkedit offset overflows"))?;
                let destination_end = destination_start
                    .checked_add(blob.bytes.len() as u64)
                    .ok_or_else(|| Error::address("synthetic linkedit extent overflows"))?;
                bytes[destination_start as usize..destination_end as usize]
                    .copy_from_slice(&blob.bytes);
            }
        } else {
            let source_end = segment
                .vmaddr
                .checked_add(segment.filesize)
                .ok_or_else(|| Error::address("cache segment source extent overflows"))?;
            let source = family.read_va_exact(segment.vmaddr..source_end)?;
            let destination_end = segment
                .new_fileoff
                .checked_add(segment.filesize)
                .ok_or_else(|| Error::address("reconstructed segment extent overflows"))?;
            let destination = bytes
                .get_mut(segment.new_fileoff as usize..destination_end as usize)
                .ok_or_else(|| Error::bounds(segment.new_fileoff, segment.filesize, file_end))?;
            destination.copy_from_slice(&source);
            let rva_start = segment
                .vmaddr
                .checked_sub(image_address)
                .ok_or_else(|| Error::unsupported("file-backed segment precedes image header"))?;
            let rva_end = rva_start
                .checked_add(segment.filesize)
                .ok_or_else(|| Error::address("segment RVA extent overflows"))?;
            mappings.push(CacheMaterializedMapping {
                file: segment.new_fileoff..destination_end,
                rva: rva_start..rva_end,
            });
        }
    }

    // A standalone reconstruction is not resident in dyld's cache.
    let flags = read_macho_u32(&bytes, 24, endian, "Mach-O flags")? & !0x8000_0000;
    write_macho_u32(&mut bytes, 24, flags, endian)?;

    for segment in &segments {
        patch_segment_and_sections(&mut bytes, segment, linkedit_layout.as_ref(), endian)?;
    }
    for (command, offset, _) in commands {
        patch_file_offsets_for_command(
            &mut bytes,
            command,
            offset,
            linkedit_layout.as_ref(),
            &segments,
            endian,
        )?;
    }

    // The rewritten file must pass the same strict parser used by downstream
    // CLI and library workflows before it can escape this crate.
    crate::core::format::parse(&bytes).map_err(Error::from)?;
    Ok(CacheMaterializedImage {
        bytes,
        mappings,
        synthetic_padding,
    })
}

fn parse_cache_segment(
    bytes: &[u8],
    offset: usize,
    command_size: usize,
    is_64: bool,
    endian: crate::core::format::io::Endian,
) -> Result<RawCacheSegment> {
    let minimum = if is_64 { 72 } else { 56 };
    if command_size < minimum {
        return Err(Error::format("Mach-O segment command is truncated"));
    }
    let name = read_fixed_c_string(bytes, offset + 8, 16, "segment name")?;
    let (vmaddr, vmsize, fileoff, filesize, nsects, section_size) = if is_64 {
        (
            read_macho_u64(bytes, offset + 24, endian, "segment VM address")?,
            read_macho_u64(bytes, offset + 32, endian, "segment VM size")?,
            read_macho_u64(bytes, offset + 40, endian, "segment file offset")?,
            read_macho_u64(bytes, offset + 48, endian, "segment file size")?,
            read_macho_u32(bytes, offset + 64, endian, "segment section count")?,
            80_usize,
        )
    } else {
        (
            u64::from(read_macho_u32(
                bytes,
                offset + 24,
                endian,
                "segment VM address",
            )?),
            u64::from(read_macho_u32(
                bytes,
                offset + 28,
                endian,
                "segment VM size",
            )?),
            u64::from(read_macho_u32(
                bytes,
                offset + 32,
                endian,
                "segment file offset",
            )?),
            u64::from(read_macho_u32(
                bytes,
                offset + 36,
                endian,
                "segment file size",
            )?),
            read_macho_u32(bytes, offset + 48, endian, "segment section count")?,
            68_usize,
        )
    };
    let section_bytes = usize::try_from(nsects)
        .ok()
        .and_then(|count| count.checked_mul(section_size))
        .ok_or_else(|| Error::format("segment section table size overflows"))?;
    if minimum
        .checked_add(section_bytes)
        .is_none_or(|required| required > command_size)
    {
        return Err(Error::format("Mach-O segment section table is truncated"));
    }
    let mut sections = Vec::with_capacity(nsects as usize);
    for index in 0..nsects as usize {
        let section_offset = offset + minimum + index * section_size;
        let (address, old_offset, old_relocation_offset, relocation_count) = if is_64 {
            (
                read_macho_u64(bytes, section_offset + 32, endian, "section address")?,
                read_macho_u32(bytes, section_offset + 48, endian, "section file offset")?,
                read_macho_u32(
                    bytes,
                    section_offset + 56,
                    endian,
                    "section relocation offset",
                )?,
                read_macho_u32(
                    bytes,
                    section_offset + 60,
                    endian,
                    "section relocation count",
                )?,
            )
        } else {
            (
                u64::from(read_macho_u32(
                    bytes,
                    section_offset + 32,
                    endian,
                    "section address",
                )?),
                read_macho_u32(bytes, section_offset + 40, endian, "section file offset")?,
                read_macho_u32(
                    bytes,
                    section_offset + 48,
                    endian,
                    "section relocation offset",
                )?,
                read_macho_u32(
                    bytes,
                    section_offset + 52,
                    endian,
                    "section relocation count",
                )?,
            )
        };
        sections.push(RawCacheSection {
            command_offset: section_offset,
            address,
            old_offset,
            old_relocation_offset,
            relocation_count,
        });
    }
    Ok(RawCacheSegment {
        command_offset: offset,
        is_64,
        name,
        vmaddr,
        vmsize,
        old_fileoff: fileoff,
        filesize,
        new_fileoff: 0,
        new_filesize: filesize,
        sections,
    })
}

fn build_linkedit_layout(
    family: &DyldCacheFamily<'_>,
    bytes: &[u8],
    commands: &[(u32, usize, usize)],
    linkedit: &RawCacheSegment,
    segments: &[RawCacheSegment],
    bitness: crate::core::model::Bitness,
    endian: crate::core::format::io::Endian,
) -> Result<LinkeditLayout> {
    use crate::core::format::constants::*;
    use crate::core::model::Bitness;

    let rebuilt_symbols = rebuild_symbol_blobs(family, bytes, commands, linkedit, bitness, endian)?;
    let mut requested = Vec::<Range<u64>>::new();
    let mut retain = |offset: u64, size: u64, subject: &str| -> Result<()> {
        if size == 0 {
            return Ok(());
        }
        if offset == 0 {
            return Err(Error::format(format!(
                "{subject} has nonzero size with a zero file offset"
            )));
        }
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
        requested.push(offset..end);
        Ok(())
    };

    for segment in segments {
        for section in &segment.sections {
            retain(
                u64::from(section.old_relocation_offset),
                u64::from(section.relocation_count)
                    .checked_mul(8)
                    .ok_or_else(|| Error::address("section relocation table size overflows"))?,
                "section relocation table",
            )?;
        }
    }
    for &(command, offset, _) in commands {
        let u32_at =
            |field, subject| read_macho_u32(bytes, offset + field, endian, subject).map(u64::from);
        match command {
            LC_SYMSEG => retain(
                u32_at(8, "obsolete symbol segment offset")?,
                u32_at(12, "obsolete symbol segment size")?,
                "obsolete symbol segment",
            )?,
            LC_SYMTAB => {
                // Per-image nlists and their referenced strings are rebuilt
                // below; the shared cache string pool is never copied whole.
            }
            LC_DYSYMTAB => {
                let module_size = if bitness == Bitness::Bits64 { 56 } else { 52 };
                for (offset_field, count_field, stride, subject) in [
                    (32, 36, 8, "table of contents"),
                    (40, 44, module_size, "module table"),
                    (48, 52, 4, "external reference table"),
                    (56, 60, 4, "indirect symbol table"),
                    (64, 68, 8, "external relocation table"),
                    (72, 76, 8, "local relocation table"),
                ] {
                    retain(
                        u32_at(offset_field, subject)?,
                        u32_at(count_field, subject)?
                            .checked_mul(stride)
                            .ok_or_else(|| Error::address(format!("{subject} size overflows")))?,
                        subject,
                    )?;
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                for (offset_field, size_field, subject) in [
                    (8, 12, "dyld rebase stream"),
                    (16, 20, "dyld bind stream"),
                    (24, 28, "dyld weak-bind stream"),
                    (32, 36, "dyld lazy-bind stream"),
                    (40, 44, "dyld export stream"),
                ] {
                    retain(
                        u32_at(offset_field, subject)?,
                        u32_at(size_field, subject)?,
                        subject,
                    )?;
                }
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
            | LC_FUNCTION_VARIANT_FIXUPS => retain(
                u32_at(8, "linkedit data offset")?,
                u32_at(12, "linkedit data size")?,
                "linkedit data",
            )?,
            LC_CODE_SIGNATURE => {
                // A cache/member signature is not transferable to the rewritten image.
            }
            LC_TWOLEVEL_HINTS => retain(
                u32_at(8, "two-level hints offset")?,
                u32_at(12, "two-level hints count")?
                    .checked_mul(4)
                    .ok_or_else(|| Error::address("two-level hints size overflows"))?,
                "two-level hints",
            )?,
            LC_NOTE => retain(
                read_macho_u64(bytes, offset + 24, endian, "note file offset")?,
                read_macho_u64(bytes, offset + 32, endian, "note size")?,
                "note data",
            )?,
            _ => {}
        }
    }

    requested.sort_by_key(|range| range.start);
    let mut merged = Vec::<Range<u64>>::new();
    for range in requested {
        if let Some(last) = merged.last_mut()
            && range.start <= last.end
        {
            last.end = last.end.max(range.end);
        } else {
            merged.push(range);
        }
    }
    let mut new_length = 0_u64;
    let mut ranges = Vec::with_capacity(merged.len());
    for old in merged {
        let start = align_up(new_length, 8)?;
        new_length = start
            .checked_add(old.end - old.start)
            .ok_or_else(|| Error::address("compacted __LINKEDIT extent overflows"))?;
        ranges.push(LinkeditRange {
            old,
            new_relative_start: start,
        });
    }
    let mut synthetic_blobs = Vec::with_capacity(rebuilt_symbols.len());
    for (old_anchor, blob) in rebuilt_symbols {
        let start = align_up(new_length, 8)?;
        new_length = start
            .checked_add(blob.len() as u64)
            .ok_or_else(|| Error::address("rebuilt symbol metadata extent overflows"))?;
        synthetic_blobs.push(SyntheticLinkeditBlob {
            old_anchor,
            new_relative_start: start,
            bytes: blob,
        });
    }
    Ok(LinkeditLayout {
        old_fileoff: linkedit.old_fileoff,
        old_vmaddr: linkedit.vmaddr,
        new_fileoff: 0,
        new_filesize: new_length,
        ranges,
        synthetic_blobs,
    })
}
