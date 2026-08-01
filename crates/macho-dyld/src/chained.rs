use crate::dyld::types::{ChainedImport, ChainedImportRecord, Fixup, FixupKind};
use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::io::endian::Endian;
use crate::format::io::pod::{
    self, RawChainedFixupsHeader, RawChainedImport, RawChainedImportAddend,
    RawChainedImportAddend64,
};
use crate::model::addr::ThinFileOffset;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;

/// Parsed chained fixup data from LC_DYLD_CHAINED_FIXUPS.
#[derive(Debug)]
pub struct ChainedFixups<'data> {
    /// The imports field.
    pub imports: Vec<ChainedImport<'data>>,
    /// The fixups field.
    pub fixups: Vec<Fixup>,
}

/// Import-table encoding used by `LC_DYLD_CHAINED_FIXUPS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainedImportFormat {
    /// Four-byte import without an addend.
    Import,
    /// Eight-byte import with a signed 32-bit addend.
    ImportAddend,
    /// Sixteen-byte import with signed 64-bit addend and wide library ordinal.
    ImportAddend64,
}

/// Authoritative parsed chained-import table, independent of chain walking.
#[derive(Debug)]
pub struct ChainedImports<'data> {
    /// On-disk import encoding.
    pub format: ChainedImportFormat,
    /// Imports in exact table order.
    pub imports: Vec<ChainedImport<'data>>,
}

/// Result of exact-name lookup in the authoritative chained-import table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainedImportLookup {
    /// The selected image has no chained-fixup command.
    Absent,
    /// Chained imports exist, but none has the requested name.
    NotFound,
    /// Exactly one table row has the requested name.
    Unique(ChainedImportRecord),
    /// More than one table row has the requested name, retained in ordinal order.
    Ambiguous(Vec<ChainedImportRecord>),
}

/// Performs parse_chained_fixups.
pub fn parse_chained_fixups<'data>(macho: &MachoFile<'data>) -> Result<ChainedFixups<'data>> {
    let linkedit =
        unique_chained_command(macho)?.ok_or_else(|| Error::format("no LC_DYLD_CHAINED_FIXUPS"))?;

    let data_off = linkedit.data_offset as usize;
    let data_size = linkedit.data_size as usize;
    let fixup_data = macho.read_bytes_at(ThinFileOffset(data_off as u64), data_size)?;

    let endian = macho.endian();
    let header: RawChainedFixupsHeader = pod::read_pod(fixup_data, 0)?;
    let starts_offset = endian.interpret_u32(header.starts_offset) as usize;
    validate_chained_header(&header, endian)?;
    let imports = parse_import_table(fixup_data, endian, &header)?.imports;
    let fixups = walk_all_chains(macho, fixup_data, endian, starts_offset)?;

    Ok(ChainedFixups { imports, fixups })
}

/// Parse only the authoritative chained-import table without walking pointer chains.
pub fn parse_chained_imports<'data>(
    macho: &MachoFile<'data>,
) -> Result<Option<ChainedImports<'data>>> {
    let Some(linkedit) = unique_chained_command(macho)? else {
        return Ok(None);
    };
    let fixup_data = macho.read_bytes_at(
        ThinFileOffset(u64::from(linkedit.data_offset)),
        linkedit.data_size as usize,
    )?;
    let endian = macho.endian();
    let header: RawChainedFixupsHeader = pod::read_pod(fixup_data, 0)?;
    validate_chained_header(&header, endian)?;
    parse_import_table(fixup_data, endian, &header).map(Some)
}

/// Look up an exact symbol name in the already-validated chained import model.
pub fn lookup_chained_import(macho: &MachoFile<'_>, name: &str) -> Result<ChainedImportLookup> {
    let Some(parsed) = parse_chained_imports(macho)? else {
        return Ok(ChainedImportLookup::Absent);
    };
    let matches = parsed
        .imports
        .iter()
        .enumerate()
        .filter(|(_, import)| import.name == name)
        .map(|(ordinal, import)| import_record(ordinal, import))
        .collect::<Result<Vec<_>>>()?;
    Ok(match matches.as_slice() {
        [] => ChainedImportLookup::NotFound,
        [record] => ChainedImportLookup::Unique(record.clone()),
        _ => ChainedImportLookup::Ambiguous(matches),
    })
}

fn unique_chained_command<'image>(
    macho: &'image MachoFile<'_>,
) -> Result<Option<&'image crate::model::load_command::LinkeditData>> {
    let mut commands = macho
        .load_commands()
        .iter()
        .filter_map(|command| match command.kind() {
            LoadCommand::DyldChainedFixups(data) => Some(data),
            _ => None,
        });
    let first = commands.next();
    if commands.next().is_some() {
        return Err(Error::format("duplicate LC_DYLD_CHAINED_FIXUPS commands"));
    }
    Ok(first)
}

fn validate_chained_header(header: &RawChainedFixupsHeader, endian: Endian) -> Result<()> {
    let version = endian.interpret_u32(header.fixups_version);
    if version != 0 {
        return Err(Error::unsupported(format!(
            "unsupported chained-fixups version {version}"
        )));
    }
    let symbols_format = endian.interpret_u32(header.symbols_format);
    if symbols_format != 0 {
        return Err(Error::unsupported(format!(
            "unsupported chained-symbol format {symbols_format}"
        )));
    }
    Ok(())
}

fn parse_import_table<'data>(
    fixup_data: &'data [u8],
    endian: Endian,
    header: &RawChainedFixupsHeader,
) -> Result<ChainedImports<'data>> {
    let imports_offset = endian.interpret_u32(header.imports_offset) as usize;
    let symbols_offset = endian.interpret_u32(header.symbols_offset) as usize;
    if symbols_offset > fixup_data.len() {
        return Err(Error::bounds(
            symbols_offset as u64,
            0,
            fixup_data.len() as u64,
        ));
    }
    let imports_count = endian.interpret_u32(header.imports_count) as usize;
    let raw_format = endian.interpret_u32(header.imports_format);
    let format = match raw_format {
        DYLD_CHAINED_IMPORT => ChainedImportFormat::Import,
        DYLD_CHAINED_IMPORT_ADDEND => ChainedImportFormat::ImportAddend,
        DYLD_CHAINED_IMPORT_ADDEND64 => ChainedImportFormat::ImportAddend64,
        _ => {
            return Err(Error::unsupported(format!(
                "unknown chained import format {raw_format}"
            )));
        }
    };
    let imports = parse_imports(
        fixup_data,
        endian,
        imports_offset,
        imports_count,
        raw_format,
        &fixup_data[symbols_offset..],
    )?;
    Ok(ChainedImports { format, imports })
}

fn import_record(ordinal: usize, import: &ChainedImport<'_>) -> Result<ChainedImportRecord> {
    Ok(ChainedImportRecord {
        ordinal: u32::try_from(ordinal)
            .map_err(|_| Error::format("chained import ordinal exceeds u32"))?,
        name: import.name.to_owned(),
        library_ordinal: import.lib_ordinal,
        weak: import.weak,
        addend: import.addend,
    })
}

fn parse_imports<'data>(
    fixup_data: &'data [u8],
    endian: Endian,
    imports_offset: usize,
    imports_count: usize,
    imports_format: u32,
    symbols_data: &'data [u8],
) -> Result<Vec<ChainedImport<'data>>> {
    let cap = imports_count.min(1_000_000);
    let mut imports = Vec::with_capacity(cap);

    for i in 0..imports_count {
        let entry_offset = |width: usize| {
            i.checked_mul(width)
                .and_then(|delta| imports_offset.checked_add(delta))
                .ok_or_else(|| Error::format("chained import table offset overflows"))
        };
        match imports_format {
            DYLD_CHAINED_IMPORT => {
                let raw: RawChainedImport = pod::read_pod(fixup_data, entry_offset(4)?)?;
                let packed = endian.interpret_u32(raw.packed);
                let lib_ordinal = (packed & 0xFF) as i8 as i32;
                let weak = (packed >> 8) & 1 != 0;
                let name_offset = (packed >> 9) & 0x7FFFFF;
                let name = read_fixup_string(symbols_data, name_offset as usize)?;
                imports.push(ChainedImport {
                    name,
                    lib_ordinal,
                    weak,
                    addend: 0,
                });
            }
            DYLD_CHAINED_IMPORT_ADDEND => {
                let raw: RawChainedImportAddend = pod::read_pod(fixup_data, entry_offset(8)?)?;
                let packed = endian.interpret_u32(raw.packed);
                let lib_ordinal = (packed & 0xFF) as i8 as i32;
                let weak = (packed >> 8) & 1 != 0;
                let name_offset = (packed >> 9) & 0x7FFFFF;
                let name = read_fixup_string(symbols_data, name_offset as usize)?;
                let addend = endian.interpret_i32(raw.addend) as i64;
                imports.push(ChainedImport {
                    name,
                    lib_ordinal,
                    weak,
                    addend,
                });
            }
            DYLD_CHAINED_IMPORT_ADDEND64 => {
                // RawChainedImportAddend64 is 16 bytes (u64 packed + u64 addend)
                let entry_size = size_of::<RawChainedImportAddend64>();
                let raw: RawChainedImportAddend64 =
                    pod::read_pod(fixup_data, entry_offset(entry_size)?)?;
                let packed = endian.interpret_u64(raw.packed);
                let lib_ordinal = (packed & 0xFFFF) as i16 as i32;
                let weak = (packed >> 16) & 1 != 0;
                let name_offset = (packed >> 32) as u32;
                let name = read_fixup_string(symbols_data, name_offset as usize)?;
                let addend = endian.interpret_u64(raw.addend) as i64;
                imports.push(ChainedImport {
                    name,
                    lib_ordinal,
                    weak,
                    addend,
                });
            }
            _ => {
                return Err(Error::unsupported(format!(
                    "unknown chained import format {imports_format}"
                )));
            }
        }
    }

    Ok(imports)
}

fn read_fixup_string(symbols_data: &[u8], offset: usize) -> Result<&str> {
    if offset >= symbols_data.len() {
        return Err(Error::bounds(offset as u64, 1, symbols_data.len() as u64));
    }
    let slice = &symbols_data[offset..];
    let end = slice
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Error::format(format!("unterminated fixup symbol at {offset}")))?;
    std::str::from_utf8(&slice[..end])
        .map_err(|e| Error::format(format!("invalid UTF-8 in fixup symbol at {offset}: {e}")))
}

fn walk_all_chains(
    macho: &MachoFile<'_>,
    fixup_data: &[u8],
    endian: Endian,
    starts_offset: usize,
) -> Result<Vec<Fixup>> {
    let table_header_end = starts_offset
        .checked_add(4)
        .ok_or_else(|| Error::format("chained starts offset overflows"))?;
    if table_header_end > fixup_data.len() {
        return Err(Error::format("chained starts truncated"));
    }

    let seg_count = endian.interpret_u32(pod::read_pod::<u32>(fixup_data, starts_offset)?) as usize;
    let table_end = table_header_end
        .checked_add(
            seg_count
                .checked_mul(4)
                .ok_or_else(|| Error::format("chained starts table size overflows"))?,
        )
        .ok_or_else(|| Error::format("chained starts table range overflows"))?;
    if table_end > fixup_data.len() {
        return Err(Error::format("chained starts table is truncated"));
    }
    let mut fixups = Vec::new();

    for seg_idx in 0..seg_count {
        let info_off_pos = table_header_end + seg_idx * 4;
        let seg_info_offset =
            endian.interpret_u32(pod::read_pod::<u32>(fixup_data, info_off_pos)?) as usize;
        if seg_info_offset == 0 {
            continue;
        }

        let seg_starts_base = starts_offset
            .checked_add(seg_info_offset)
            .ok_or_else(|| Error::format("segment starts offset overflows"))?;
        let fixed_end = seg_starts_base
            .checked_add(22)
            .ok_or_else(|| Error::format("segment starts header overflows"))?;
        if fixed_end > fixup_data.len() {
            return Err(Error::format(format!(
                "segment {seg_idx} starts header is truncated"
            )));
        }

        let size =
            endian.interpret_u32(pod::read_pod::<u32>(fixup_data, seg_starts_base)?) as usize;
        let page_size_raw =
            endian.interpret_u16(pod::read_pod::<u16>(fixup_data, seg_starts_base + 4)?);
        let pointer_format =
            endian.interpret_u16(pod::read_pod::<u16>(fixup_data, seg_starts_base + 6)?);
        if !is_supported_pointer_format(pointer_format) {
            return Err(Error::unsupported(format!(
                "unsupported chained pointer format {pointer_format}"
            )));
        }
        let segment_offset =
            endian.interpret_u64(pod::read_pod::<u64>(fixup_data, seg_starts_base + 8)?);
        let _max_valid_pointer =
            endian.interpret_u32(pod::read_pod::<u32>(fixup_data, seg_starts_base + 16)?);
        let page_count =
            endian.interpret_u16(pod::read_pod::<u16>(fixup_data, seg_starts_base + 20)?) as usize;
        let page_size = page_size_raw as u64;
        if page_size == 0 {
            return Err(Error::format(format!(
                "segment {seg_idx} chained page size is zero"
            )));
        }
        let page_table_size = page_count
            .checked_mul(2)
            .ok_or_else(|| Error::format("chained page-start table size overflows"))?;
        let required_size = 22usize
            .checked_add(page_table_size)
            .ok_or_else(|| Error::format("chained segment starts size overflows"))?;
        if size < required_size {
            return Err(Error::format(format!(
                "segment {seg_idx} chained starts size {size} is smaller than {required_size}"
            )));
        }
        let declared_end = seg_starts_base
            .checked_add(size)
            .ok_or_else(|| Error::format("chained segment starts range overflows"))?;
        if declared_end > fixup_data.len() {
            return Err(Error::format(format!(
                "segment {seg_idx} chained starts are truncated"
            )));
        }

        let image_base = macho.image_base().0;
        let segment = macho.segments().get(seg_idx).ok_or_else(|| {
            Error::format(format!("chained starts reference absent segment {seg_idx}"))
        })?;
        let expected_va = image_base
            .checked_add(segment_offset)
            .ok_or_else(|| Error::address("chained segment address overflows"))?;
        if expected_va != segment.vm_addr().0 {
            return Err(Error::format(format!(
                "segment {seg_idx} chained offset maps to {expected_va:#x}, expected {:#x}",
                segment.vm_addr().0
            )));
        }
        let seg_file_offset = segment.file_offset().0;

        let stride = stride_for_format(pointer_format);
        let file_data = macho.bytes();

        for page_idx in 0..page_count {
            let page_start_pos = fixed_end + page_idx * 2;
            let page_start =
                endian.interpret_u16(pod::read_pod::<u16>(fixup_data, page_start_pos)?);

            if page_start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            if page_start & DYLD_CHAINED_PTR_START_MULTI != 0 {
                return Err(Error::unsupported(format!(
                    "segment {seg_idx} page {page_idx} uses unsupported multi-start chains"
                )));
            }
            if u64::from(page_start) >= page_size {
                return Err(Error::format(format!(
                    "segment {seg_idx} page {page_idx} chain start exceeds its page"
                )));
            }

            let page_delta = (page_idx as u64)
                .checked_mul(page_size)
                .ok_or_else(|| Error::address("chained page offset overflows"))?;
            let page_file_offset = seg_file_offset
                .checked_add(page_delta)
                .ok_or_else(|| Error::address("chained page file offset overflows"))?;
            let page_end = page_file_offset
                .checked_add(page_size)
                .ok_or_else(|| Error::address("chained page end overflows"))?;
            let segment_file_end = segment
                .file_offset()
                .0
                .checked_add(segment.file_size())
                .ok_or_else(|| Error::address("segment file range overflows"))?;
            if page_end > segment_file_end {
                return Err(Error::format(format!(
                    "segment {seg_idx} page {page_idx} exceeds file-backed segment bytes"
                )));
            }
            let mut chain_offset = page_file_offset
                .checked_add(u64::from(page_start))
                .ok_or_else(|| Error::address("chained pointer offset overflows"))?;

            loop {
                let read_size = if is_32bit_format(pointer_format) {
                    4
                } else {
                    8
                };
                let read_end = chain_offset
                    .checked_add(read_size as u64)
                    .ok_or_else(|| Error::address("chained pointer read range overflows"))?;
                if read_end > page_end || read_end > file_data.len() as u64 {
                    return Err(Error::bounds(
                        chain_offset,
                        read_size as u64,
                        file_data.len() as u64,
                    ));
                }
                let chain_offset_usize = usize::try_from(chain_offset)
                    .map_err(|_| Error::address("chained pointer offset exceeds host"))?;

                let raw_val = if read_size == 4 {
                    endian.interpret_u32(pod::read_pod::<u32>(file_data, chain_offset_usize)?)
                        as u64
                } else {
                    endian.interpret_u64(pod::read_pod::<u64>(file_data, chain_offset_usize)?)
                };

                let (fixup_kind, next) = decode_chain_entry(raw_val, pointer_format)?;
                fixups.push(Fixup {
                    segment_index: seg_idx,
                    segment_offset: chain_offset - seg_file_offset,
                    pointer_format,
                    kind: fixup_kind,
                });

                if next == 0 {
                    break;
                }
                let advance = u64::from(next)
                    .checked_mul(stride)
                    .ok_or_else(|| Error::address("chained pointer advance overflows"))?;
                chain_offset = chain_offset
                    .checked_add(advance)
                    .ok_or_else(|| Error::address("chained pointer offset overflows"))?;
            }
        }
    }

    Ok(fixups)
}

fn is_32bit_format(format: u16) -> bool {
    matches!(
        format,
        DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE | DYLD_CHAINED_PTR_32_FIRMWARE
    )
}

fn is_supported_pointer_format(format: u16) -> bool {
    matches!(
        format,
        DYLD_CHAINED_PTR_ARM64E
            | DYLD_CHAINED_PTR_ARM64E_USERLAND
            | DYLD_CHAINED_PTR_ARM64E_USERLAND24
            | DYLD_CHAINED_PTR_64
            | DYLD_CHAINED_PTR_64_OFFSET
    )
}

fn stride_for_format(format: u16) -> u64 {
    match format {
        DYLD_CHAINED_PTR_ARM64E
        | DYLD_CHAINED_PTR_ARM64E_USERLAND
        | DYLD_CHAINED_PTR_ARM64E_USERLAND24 => 8,
        DYLD_CHAINED_PTR_64
        | DYLD_CHAINED_PTR_64_OFFSET
        | DYLD_CHAINED_PTR_ARM64E_KERNEL
        | DYLD_CHAINED_PTR_64_KERNEL_CACHE
        | DYLD_CHAINED_PTR_ARM64E_FIRMWARE => 4,
        DYLD_CHAINED_PTR_32 | DYLD_CHAINED_PTR_32_CACHE | DYLD_CHAINED_PTR_32_FIRMWARE => 4,
        DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE => 1,
        _ => 4,
    }
}

fn decode_chain_entry(raw: u64, format: u16) -> Result<(FixupKind, u16)> {
    match format {
        DYLD_CHAINED_PTR_ARM64E | DYLD_CHAINED_PTR_ARM64E_USERLAND => {
            // Layout: target:43, high8:8, next:11, bind:1, auth:1
            let bind = (raw >> 62) & 1 != 0;
            let auth = (raw >> 63) & 1 != 0;
            let next = ((raw >> 51) & 0x7FF) as u16; // bits 51-61

            if auth && bind {
                // auth_bind: ordinal:16, zero:16, diversity:16, addrDiv:1, key:2, next:11, bind:1, auth:1
                let ordinal = (raw & 0xFFFF) as u32;
                let diversity = ((raw >> 32) & 0xFFFF) as u16;
                let addr_div = (raw >> 48) & 1 != 0;
                let key = ((raw >> 49) & 0x3) as u8;
                Ok((
                    FixupKind::AuthBind {
                        import_index: ordinal,
                        diversity,
                        key,
                        addr_div,
                    },
                    next,
                ))
            } else if auth {
                // auth_rebase: target:32, diversity:16, addrDiv:1, key:2, next:11, bind:1, auth:1
                let target = raw & 0xFFFF_FFFF;
                let diversity = ((raw >> 32) & 0xFFFF) as u16;
                let addr_div = (raw >> 48) & 1 != 0;
                let key = ((raw >> 49) & 0x3) as u8;
                Ok((
                    FixupKind::AuthRebase {
                        target,
                        diversity,
                        key,
                        addr_div,
                    },
                    next,
                ))
            } else if bind {
                // bind: ordinal:16, zero:16, addend:19, next:11, bind:1, auth:1
                let ordinal = (raw & 0xFFFF) as u32;
                let raw19 = ((raw >> 32) & 0x7FFFF) as u32;
                // Sign-extend 19-bit value
                let addend = if raw19 & 0x40000 != 0 {
                    (raw19 | 0xFFF80000) as i32 as i64
                } else {
                    raw19 as i64
                };
                Ok((
                    FixupKind::Bind {
                        import_index: ordinal,
                        addend,
                    },
                    next,
                ))
            } else {
                // rebase: target:43, high8:8, next:11, bind:1, auth:1
                let target = raw & 0x7FF_FFFF_FFFF; // 43 bits
                let high8 = ((raw >> 43) & 0xFF) << 56;
                Ok((
                    FixupKind::Rebase {
                        target: target | high8,
                    },
                    next,
                ))
            }
        }
        DYLD_CHAINED_PTR_ARM64E_USERLAND24 => {
            // Same bit layout as ARM64E but ordinal is 24 bits for bind
            let bind = (raw >> 62) & 1 != 0;
            let auth = (raw >> 63) & 1 != 0;
            let next = ((raw >> 51) & 0x7FF) as u16; // bits 51-61

            if auth && bind {
                let ordinal = (raw & 0xFFFFFF) as u32; // 24 bits
                let diversity = ((raw >> 32) & 0xFFFF) as u16;
                let addr_div = (raw >> 48) & 1 != 0;
                let key = ((raw >> 49) & 0x3) as u8;
                Ok((
                    FixupKind::AuthBind {
                        import_index: ordinal,
                        diversity,
                        key,
                        addr_div,
                    },
                    next,
                ))
            } else if auth {
                let target = raw & 0xFFFF_FFFF;
                let diversity = ((raw >> 32) & 0xFFFF) as u16;
                let addr_div = (raw >> 48) & 1 != 0;
                let key = ((raw >> 49) & 0x3) as u8;
                Ok((
                    FixupKind::AuthRebase {
                        target,
                        diversity,
                        key,
                        addr_div,
                    },
                    next,
                ))
            } else if bind {
                let ordinal = (raw & 0xFFFFFF) as u32;
                let addend = ((raw >> 24) & 0xFF) as u8 as i8 as i64;
                Ok((
                    FixupKind::Bind {
                        import_index: ordinal,
                        addend,
                    },
                    next,
                ))
            } else {
                let target = raw & 0x7FF_FFFF_FFFF;
                let high8 = ((raw >> 43) & 0xFF) << 56;
                Ok((
                    FixupKind::Rebase {
                        target: target | high8,
                    },
                    next,
                ))
            }
        }
        DYLD_CHAINED_PTR_64 | DYLD_CHAINED_PTR_64_OFFSET => {
            // Layout: target:36, high8:8, reserved:7, next:12, bind:1
            let bind = (raw >> 63) & 1 != 0;
            let next = ((raw >> 51) & 0xFFF) as u16; // bits 51-62

            if bind {
                let ordinal = (raw & 0xFFFFFF) as u32;
                let addend = ((raw >> 24) & 0xFF) as u8 as i8 as i64;
                Ok((
                    FixupKind::Bind {
                        import_index: ordinal,
                        addend,
                    },
                    next,
                ))
            } else {
                let target = raw & 0xF_FFFF_FFFF; // 36 bits
                let high8 = ((raw >> 36) & 0xFF) << 56;
                Ok((
                    FixupKind::Rebase {
                        target: target | high8,
                    },
                    next,
                ))
            }
        }
        _ => Err(Error::unsupported(format!(
            "unsupported chained pointer format {format}"
        ))),
    }
}
