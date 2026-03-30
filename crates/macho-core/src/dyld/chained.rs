use crate::addr::{ThinFileOffset, Va};
use crate::constants::*;
use crate::dyld::types::{ChainedImport, Fixup, FixupKind};
use crate::error::{Error, Result};
use crate::io::endian::Endian;
use crate::io::pod::{
    self, RawChainedFixupsHeader, RawChainedImport, RawChainedImportAddend,
    RawChainedImportAddend64,
};
use crate::model::load_command::LoadCommand;
use crate::model::mach::MachFile;

/// Parsed chained fixup data from LC_DYLD_CHAINED_FIXUPS.
#[derive(Debug)]
pub struct ChainedFixups<'data> {
    pub imports: Vec<ChainedImport<'data>>,
    pub fixups: Vec<Fixup>,
}

pub fn parse_chained_fixups<'data>(mach: &MachFile<'data>) -> Result<ChainedFixups<'data>> {
    let linkedit = mach
        .find_load_command(|lc| matches!(lc, LoadCommand::DyldChainedFixups(_)))
        .and_then(|lc| lc.kind.as_linkedit_data())
        .ok_or_else(|| Error::Format("no LC_DYLD_CHAINED_FIXUPS".into()))?;

    let data_off = linkedit.data_offset as usize;
    let data_size = linkedit.data_size as usize;
    let fixup_data = mach.read_bytes_at(ThinFileOffset(data_off as u64), data_size)?;

    let endian = mach.endian();
    let header: RawChainedFixupsHeader = pod::read_pod(fixup_data, 0)?;
    let starts_offset = endian.interpret_u32(header.starts_offset) as usize;
    let imports_offset = endian.interpret_u32(header.imports_offset) as usize;
    let symbols_offset = endian.interpret_u32(header.symbols_offset) as usize;
    let imports_count = endian.interpret_u32(header.imports_count) as usize;
    let imports_format = endian.interpret_u32(header.imports_format);

    let symbols_data = if symbols_offset < fixup_data.len() {
        &fixup_data[symbols_offset..]
    } else {
        &[]
    };

    let imports = parse_imports(
        fixup_data,
        endian,
        imports_offset,
        imports_count,
        imports_format,
        symbols_data,
    )?;
    let fixups = walk_all_chains(mach, fixup_data, endian, starts_offset)?;

    Ok(ChainedFixups { imports, fixups })
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
        match imports_format {
            DYLD_CHAINED_IMPORT => {
                let raw: RawChainedImport = pod::read_pod(fixup_data, imports_offset + i * 4)?;
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
                let raw: RawChainedImportAddend =
                    pod::read_pod(fixup_data, imports_offset + i * 8)?;
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
                    pod::read_pod(fixup_data, imports_offset + i * entry_size)?;
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
                return Err(Error::Unsupported(format!(
                    "unknown chained import format {imports_format}"
                )));
            }
        }
    }

    Ok(imports)
}

fn read_fixup_string(symbols_data: &[u8], offset: usize) -> Result<&str> {
    if offset >= symbols_data.len() {
        return Err(Error::Bounds {
            offset: offset as u64,
            needed: 1,
            available: symbols_data.len() as u64,
        });
    }
    let slice = &symbols_data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end])
        .map_err(|e| Error::Format(format!("invalid UTF-8 in fixup symbol at {offset}: {e}")))
}

fn walk_all_chains(
    mach: &MachFile<'_>,
    fixup_data: &[u8],
    endian: Endian,
    starts_offset: usize,
) -> Result<Vec<Fixup>> {
    if starts_offset + 4 > fixup_data.len() {
        return Err(Error::Format("chained starts truncated".into()));
    }

    let seg_count = endian.interpret_u32(pod::read_pod::<u32>(fixup_data, starts_offset)?) as usize;
    let mut fixups = Vec::new();

    for seg_idx in 0..seg_count {
        let info_off_pos = starts_offset + 4 + seg_idx * 4;
        if info_off_pos + 4 > fixup_data.len() {
            break;
        }
        let seg_info_offset =
            endian.interpret_u32(pod::read_pod::<u32>(fixup_data, info_off_pos)?) as usize;
        if seg_info_offset == 0 {
            continue;
        }

        let seg_starts_base = starts_offset + seg_info_offset;
        if seg_starts_base + 22 > fixup_data.len() {
            continue;
        }

        let _size = endian.interpret_u32(pod::read_pod::<u32>(fixup_data, seg_starts_base)?);
        let page_size_raw =
            endian.interpret_u16(pod::read_pod::<u16>(fixup_data, seg_starts_base + 4)?);
        let pointer_format =
            endian.interpret_u16(pod::read_pod::<u16>(fixup_data, seg_starts_base + 6)?);
        let segment_offset =
            endian.interpret_u64(pod::read_pod::<u64>(fixup_data, seg_starts_base + 8)?);
        let _max_valid_pointer =
            endian.interpret_u32(pod::read_pod::<u32>(fixup_data, seg_starts_base + 16)?);
        let page_count =
            endian.interpret_u16(pod::read_pod::<u16>(fixup_data, seg_starts_base + 20)?) as usize;
        let page_size = page_size_raw as u64;

        // segment_offset is the VM offset from image base to the start of the
        // segment. Convert to an absolute VA, then translate to file offset.
        let image_base = mach.image_base().0;
        let seg_va = Va(image_base + segment_offset);
        let seg_file_offset = match mach.address_map().va_to_thin_offset(seg_va) {
            Ok(off) => off.0,
            Err(_) => continue, // segment not mapped
        };

        let stride = stride_for_format(pointer_format);
        let file_data = mach.bytes();

        for page_idx in 0..page_count {
            let page_start_pos = seg_starts_base + 22 + page_idx * 2;
            if page_start_pos + 2 > fixup_data.len() {
                break;
            }
            let page_start =
                endian.interpret_u16(pod::read_pod::<u16>(fixup_data, page_start_pos)?);

            if page_start == DYLD_CHAINED_PTR_START_NONE {
                continue;
            }
            if page_start & DYLD_CHAINED_PTR_START_MULTI != 0 {
                // Multi-start pages have an overflow table. Skip for now —
                // these are rare and only occur on pages with many chains.
                continue;
            }

            let page_file_offset = seg_file_offset + page_idx as u64 * page_size;
            let mut chain_offset = page_file_offset + page_start as u64;

            loop {
                let read_size = if is_32bit_format(pointer_format) {
                    4
                } else {
                    8
                };
                if chain_offset as usize + read_size > file_data.len() {
                    break;
                }

                let raw_val = if read_size == 4 {
                    endian.interpret_u32(pod::read_pod::<u32>(file_data, chain_offset as usize)?)
                        as u64
                } else {
                    endian.interpret_u64(pod::read_pod::<u64>(file_data, chain_offset as usize)?)
                };

                let (fixup_kind, next) = decode_chain_entry(raw_val, pointer_format)?;
                fixups.push(Fixup {
                    segment_index: seg_idx,
                    segment_offset: chain_offset - seg_file_offset,
                    kind: fixup_kind,
                });

                if next == 0 {
                    break;
                }
                chain_offset += next as u64 * stride;
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
                let addend = ((raw >> 24) & 0xFF) as i64;
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
                let addend = ((raw >> 24) & 0xFF) as i64;
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
        _ => Ok((FixupKind::Rebase { target: raw }, 0)),
    }
}
