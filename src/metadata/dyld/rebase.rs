use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::metadata::dyld::types::RebaseEntry;
use crate::metadata::dyld::uleb::LebReader;
use crate::model::load_command::LoadCommand;
use crate::model::mach_file::MachFile;

/// Parse rebase entries from LC_DYLD_INFO/LC_DYLD_INFO_ONLY rebase data.
pub fn parse_rebase_entries(mach: &MachFile<'_>) -> Result<Vec<RebaseEntry>> {
    let rebase_data = find_rebase_data(mach)?;
    if rebase_data.is_empty() {
        return Ok(Vec::new());
    }
    interpret_rebase_opcodes(rebase_data, mach)
}

fn find_rebase_data<'data>(mach: &MachFile<'data>) -> Result<&'data [u8]> {
    for lc in mach.load_commands() {
        match &lc.kind {
            LoadCommand::DyldInfo(d) | LoadCommand::DyldInfoOnly(d) => {
                if d.rebase_size > 0 {
                    return mach.read_bytes_at(
                        crate::model::addr::ThinFileOffset(d.rebase_off as u64),
                        d.rebase_size as usize,
                    );
                }
            }
            _ => {}
        }
    }
    Ok(&[])
}

fn interpret_rebase_opcodes(data: &[u8], mach: &MachFile<'_>) -> Result<Vec<RebaseEntry>> {
    let pointer_size = if mach.is_64bit() { 8u64 } else { 4u64 };
    let mut reader = LebReader::new(data);
    let mut entries = Vec::new();

    let mut rebase_type: u8 = REBASE_TYPE_POINTER;
    let mut segment_index: usize = 0;
    let mut segment_offset: u64 = 0;

    loop {
        if reader.is_empty() {
            break;
        }
        let byte = reader.read_u8()?;
        let opcode = byte & REBASE_OPCODE_MASK;
        let imm = byte & REBASE_IMMEDIATE_MASK;

        match opcode {
            REBASE_OPCODE_DONE => break,
            REBASE_OPCODE_SET_TYPE_IMM => {
                rebase_type = imm;
            }
            REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment_index = imm as usize;
                segment_offset = reader.read_uleb128()?;
            }
            REBASE_OPCODE_ADD_ADDR_ULEB => {
                segment_offset += reader.read_uleb128()?;
            }
            REBASE_OPCODE_ADD_ADDR_IMM_SCALED => {
                segment_offset += imm as u64 * pointer_size;
            }
            REBASE_OPCODE_DO_REBASE_IMM_TIMES => {
                for _ in 0..imm {
                    entries.push(RebaseEntry {
                        segment_index,
                        segment_offset,
                        rebase_type,
                    });
                    segment_offset += pointer_size;
                }
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES => {
                let count = reader.read_uleb128()?;
                for _ in 0..count {
                    entries.push(RebaseEntry {
                        segment_index,
                        segment_offset,
                        rebase_type,
                    });
                    segment_offset += pointer_size;
                }
            }
            REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB => {
                entries.push(RebaseEntry {
                    segment_index,
                    segment_offset,
                    rebase_type,
                });
                let skip = reader.read_uleb128()?;
                segment_offset += pointer_size + skip;
            }
            REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING => {
                let count = reader.read_uleb128()?;
                let skip = reader.read_uleb128()?;
                for _ in 0..count {
                    entries.push(RebaseEntry {
                        segment_index,
                        segment_offset,
                        rebase_type,
                    });
                    segment_offset += pointer_size + skip;
                }
            }
            _ => {
                return Err(Error::Format(format!("unknown rebase opcode {byte:#x}")));
            }
        }

        if entries.len() > 10_000_000 {
            return Err(Error::Format("rebase entry count exceeds limit".into()));
        }
    }

    Ok(entries)
}
