use crate::constants::*;
use crate::dyld::types::BindEntry;
use crate::dyld::uleb::LebReader;
use crate::error::{Error, Result};
use crate::model::load_command::LoadCommand;
use crate::model::mach::MachFile;

/// Parse bind entries from LC_DYLD_INFO/LC_DYLD_INFO_ONLY.
/// Returns (regular binds, weak binds, lazy binds).
pub fn parse_bind_entries<'data>(
    mach: &MachFile<'data>,
) -> Result<(
    Vec<BindEntry<'data>>,
    Vec<BindEntry<'data>>,
    Vec<BindEntry<'data>>,
)> {
    let (bind_data, weak_data, lazy_data) = find_bind_data(mach)?;

    let regular = if bind_data.is_empty() {
        Vec::new()
    } else {
        interpret_bind_opcodes(bind_data, mach, false)?
    };

    let weak = if weak_data.is_empty() {
        Vec::new()
    } else {
        interpret_bind_opcodes(weak_data, mach, false)?
    };

    let lazy = if lazy_data.is_empty() {
        Vec::new()
    } else {
        interpret_bind_opcodes(lazy_data, mach, true)?
    };

    Ok((regular, weak, lazy))
}

fn find_bind_data<'data>(
    mach: &MachFile<'data>,
) -> Result<(&'data [u8], &'data [u8], &'data [u8])> {
    for lc in mach.load_commands() {
        match &lc.kind {
            LoadCommand::DyldInfo(d) | LoadCommand::DyldInfoOnly(d) => {
                let bind = if d.bind_size > 0 {
                    mach.read_bytes_at(
                        crate::addr::ThinFileOffset(d.bind_off as u64),
                        d.bind_size as usize,
                    )?
                } else {
                    &[]
                };
                let weak = if d.weak_bind_size > 0 {
                    mach.read_bytes_at(
                        crate::addr::ThinFileOffset(d.weak_bind_off as u64),
                        d.weak_bind_size as usize,
                    )?
                } else {
                    &[]
                };
                let lazy = if d.lazy_bind_size > 0 {
                    mach.read_bytes_at(
                        crate::addr::ThinFileOffset(d.lazy_bind_off as u64),
                        d.lazy_bind_size as usize,
                    )?
                } else {
                    &[]
                };
                return Ok((bind, weak, lazy));
            }
            _ => {}
        }
    }
    Ok((&[], &[], &[]))
}

fn interpret_bind_opcodes<'data>(
    data: &'data [u8],
    mach: &MachFile<'data>,
    lazy: bool,
) -> Result<Vec<BindEntry<'data>>> {
    let pointer_size = if mach.is_64bit() { 8u64 } else { 4u64 };
    let mut reader = LebReader::new(data);
    let mut entries = Vec::new();

    let mut bind_type: u8 = BIND_TYPE_POINTER;
    let mut segment_index: usize = 0;
    let mut segment_offset: u64 = 0;
    let mut symbol_name: &str = "";
    let mut symbol_flags: u8 = 0;
    let mut lib_ordinal: i64 = 0;
    let mut addend: i64 = 0;

    loop {
        if reader.is_empty() {
            break;
        }
        let byte = reader.read_u8()?;
        let opcode = byte & BIND_OPCODE_MASK;
        let imm = byte & BIND_IMMEDIATE_MASK;

        match opcode {
            BIND_OPCODE_DONE => {
                if lazy {
                    // In lazy binds, DONE separates entries but doesn't end the stream
                    continue;
                }
                break;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                lib_ordinal = imm as i64;
            }
            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                lib_ordinal = reader.read_uleb128()? as i64;
            }
            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if imm == 0 {
                    lib_ordinal = 0;
                } else {
                    // Sign extend the 4-bit immediate
                    lib_ordinal = (0xF0 | imm) as i8 as i64;
                }
            }
            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                symbol_flags = imm;
                symbol_name = reader.read_string()?;
            }
            BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = imm;
            }
            BIND_OPCODE_SET_ADDEND_SLEB => {
                addend = reader.read_sleb128()?;
            }
            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment_index = imm as usize;
                segment_offset = reader.read_uleb128()?;
            }
            BIND_OPCODE_ADD_ADDR_ULEB => {
                segment_offset += reader.read_uleb128()?;
            }
            BIND_OPCODE_DO_BIND => {
                entries.push(BindEntry {
                    segment_index,
                    segment_offset,
                    bind_type,
                    symbol_name,
                    lib_ordinal,
                    addend,
                    weak: symbol_flags & 0x01 != 0,
                    lazy,
                });
                segment_offset += pointer_size;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                entries.push(BindEntry {
                    segment_index,
                    segment_offset,
                    bind_type,
                    symbol_name,
                    lib_ordinal,
                    addend,
                    weak: symbol_flags & 0x01 != 0,
                    lazy,
                });
                let skip = reader.read_uleb128()?;
                segment_offset += pointer_size + skip;
            }
            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                entries.push(BindEntry {
                    segment_index,
                    segment_offset,
                    bind_type,
                    symbol_name,
                    lib_ordinal,
                    addend,
                    weak: symbol_flags & 0x01 != 0,
                    lazy,
                });
                segment_offset += pointer_size + imm as u64 * pointer_size;
            }
            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let count = reader.read_uleb128()?;
                let skip = reader.read_uleb128()?;
                for _ in 0..count {
                    entries.push(BindEntry {
                        segment_index,
                        segment_offset,
                        bind_type,
                        symbol_name,
                        lib_ordinal,
                        addend,
                        weak: symbol_flags & 0x01 != 0,
                        lazy,
                    });
                    segment_offset += pointer_size + skip;
                }
            }
            BIND_OPCODE_THREADED => {
                // Threaded bind is used with chained fixups in newer binaries.
                // The subopcode is in the immediate field.
                match imm {
                    BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE => {
                        let _count = reader.read_uleb128()?;
                        // Sets the ordinal table size — handled by chained fixups
                    }
                    BIND_SUBOPCODE_THREADED_APPLY => {
                        // Apply threaded binds — handled by chained fixups
                    }
                    _ => {
                        return Err(Error::Format(format!(
                            "unknown bind threaded subopcode {imm:#x}"
                        )));
                    }
                }
            }
            _ => {
                return Err(Error::Format(format!("unknown bind opcode {byte:#x}")));
            }
        }

        if entries.len() > 10_000_000 {
            return Err(Error::Format("bind entry count exceeds limit".into()));
        }
    }

    Ok(entries)
}
