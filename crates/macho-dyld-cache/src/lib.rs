#![deny(missing_docs)]
//! Offline dyld shared-cache family parsing and Mach-O reconstruction.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Range;

use macho_core::MaterializationLimits;
use serde::Serialize;

pub use macho_core::format;

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{DyldCacheError, DyldCacheErrorKind, Result};

mod completeness;
mod family;
mod materialize;
mod parse;
mod rewrite;

pub use family::*;
pub use parse::*;

fn read_u32_le(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::bounds(offset as u64, 4, data.len() as u64))?;
    if end > data.len() {
        return Err(Error::bounds(offset as u64, 4, data.len() as u64));
    }
    let bytes: [u8; 4] = data[offset..end]
        .try_into()
        .expect("slice length guaranteed by bounds check");
    Ok(u32::from_le_bytes(bytes))
}

fn read_u64_le(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::bounds(offset as u64, 8, data.len() as u64))?;
    if end > data.len() {
        return Err(Error::bounds(offset as u64, 8, data.len() as u64));
    }
    let bytes: [u8; 8] = data[offset..end]
        .try_into()
        .expect("slice length guaranteed by bounds check");
    Ok(u64::from_le_bytes(bytes))
}

fn read_uuid(data: &[u8], offset: usize) -> Result<[u8; 16]> {
    data.get(offset..offset.saturating_add(16))
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| Error::bounds(offset as u64, 16, data.len() as u64))
}

fn read_fixed_c_string(data: &[u8], offset: usize, size: usize, subject: &str) -> Result<String> {
    let bytes = data
        .get(offset..offset.saturating_add(size))
        .ok_or_else(|| Error::bounds(offset as u64, size as u64, data.len() as u64))?;
    let end = bytes
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(bytes.len());
    let value = std::str::from_utf8(&bytes[..end])
        .map_err(|_| Error::format(format!("{subject} is not UTF-8")))?;
    Ok(value.to_owned())
}

fn format_uuid(uuid: [u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15]
    )
}

fn read_c_string(data: &[u8], offset: usize, subject: &str) -> Result<String> {
    const MAX_CACHE_PATH_BYTES: usize = 4096;
    let remaining = data
        .get(offset..)
        .ok_or_else(|| Error::bounds(offset as u64, 1, data.len() as u64))?;
    let bounded = &remaining[..remaining.len().min(MAX_CACHE_PATH_BYTES)];
    let length = bounded.iter().position(|byte| *byte == 0).ok_or_else(|| {
        Error::format(format!(
            "{subject} at {offset:#x} is not NUL-terminated within {} bytes",
            bounded.len()
        ))
    })?;
    let path = std::str::from_utf8(&bounded[..length])
        .map_err(|_| Error::format(format!("{subject} at {offset:#x} is not UTF-8")))?;
    if path.is_empty() || !path.starts_with('/') {
        return Err(Error::format(format!(
            "{subject} at {offset:#x} is not a nonempty absolute install path"
        )));
    }
    Ok(path.to_owned())
}

#[cfg(test)]
mod tests;
