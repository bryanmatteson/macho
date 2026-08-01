//! Strict, bounded decoding of `LC_FUNCTION_STARTS`.

use macho_core::MachoFile;
use macho_core::model::addr::{ThinFileOffset, Va};
use macho_core::model::load_command::{LinkeditData, LoadCommand};

use crate::error::{Error, Result};
use crate::uleb::LebReader;

/// One function start with exact encoded-source provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionStart {
    /// Unslid virtual address of the function.
    pub address: Va,
    /// Delta from the preceding start, or from the image base for the first row.
    pub delta: u64,
    /// Thin-file offset of this row's ULEB encoding.
    pub encoded_offset: ThinFileOffset,
    /// Length of this row's ULEB encoding.
    pub encoded_size: u8,
}

/// Continuation coordinate for a bounded function-start inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionStartContinuation {
    /// First function start not retained in the bounded result.
    pub next: FunctionStart,
    /// Number of decoded starts, including the retained prefix and continuation row.
    pub decoded_count: u64,
}

/// Strict function-start evidence state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionStartsOutcome {
    /// The selected image has no `LC_FUNCTION_STARTS` command.
    Absent,
    /// The complete terminated stream fit within the requested bound.
    Complete(Vec<FunctionStart>),
    /// A deterministic prefix was retained and the next source coordinate is provided.
    Truncated {
        /// Retained prefix.
        starts: Vec<FunctionStart>,
        /// Exact next row.
        continuation: FunctionStartContinuation,
    },
}

/// Decode one selected image's function starts, rejecting malformed streams.
///
/// `limit` is the maximum retained row count and must be positive. A rejected
/// result is returned as [`crate::DyldError`]; absence and truncation are data
/// states rather than errors.
pub fn decode_function_starts(macho: &MachoFile<'_>, limit: u64) -> Result<FunctionStartsOutcome> {
    if limit == 0 {
        return Err(Error::format(
            "function-start inventory limit must be positive",
        ));
    }
    let Some(command) = unique_command(macho)? else {
        return Ok(FunctionStartsOutcome::Absent);
    };
    let data = macho.read_bytes_at(
        ThinFileOffset(u64::from(command.data_offset)),
        command.data_size as usize,
    )?;
    if data.is_empty() {
        return Err(Error::format(
            "LC_FUNCTION_STARTS stream has no terminating zero",
        ));
    }

    let mut reader = LebReader::new(data);
    let mut relative = 0_u64;
    let mut starts = Vec::new();
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    loop {
        if reader.is_empty() {
            return Err(Error::format(
                "LC_FUNCTION_STARTS stream has no terminating zero",
            ));
        }
        let encoded_start = reader.pos();
        let delta = reader.read_uleb128()?;
        let encoded_end = reader.pos();
        if delta == 0 {
            if data[encoded_end..].iter().any(|byte| *byte != 0) {
                return Err(Error::format(
                    "LC_FUNCTION_STARTS has nonzero bytes after its terminator",
                ));
            }
            return Ok(FunctionStartsOutcome::Complete(starts));
        }
        relative = relative
            .checked_add(delta)
            .ok_or_else(|| Error::address("function-start delta accumulation overflows"))?;
        let address = macho
            .image_base()
            .0
            .checked_add(relative)
            .map(Va)
            .ok_or_else(|| Error::address("function-start address overflows"))?;
        let encoded_offset = u64::from(command.data_offset)
            .checked_add(encoded_start as u64)
            .map(ThinFileOffset)
            .ok_or_else(|| Error::address("function-start source offset overflows"))?;
        let encoded_size = u8::try_from(encoded_end - encoded_start)
            .map_err(|_| Error::format("function-start ULEB width exceeds u8"))?;
        let row = FunctionStart {
            address,
            delta,
            encoded_offset,
            encoded_size,
        };
        if starts.len() == limit {
            return Ok(FunctionStartsOutcome::Truncated {
                starts,
                continuation: FunctionStartContinuation {
                    next: row,
                    decoded_count: limit as u64 + 1,
                },
            });
        }
        starts.push(row);
    }
}

fn unique_command<'image>(macho: &'image MachoFile<'_>) -> Result<Option<&'image LinkeditData>> {
    let mut commands = macho
        .load_commands()
        .iter()
        .filter_map(|command| match command.kind() {
            LoadCommand::FunctionStarts(data) => Some(data),
            _ => None,
        });
    let first = commands.next();
    if commands.next().is_some() {
        return Err(Error::format("duplicate LC_FUNCTION_STARTS commands"));
    }
    Ok(first)
}
