use crate::core::error::{ContextFrame, Error, Result};
use crate::core::format::ParseLimits;
use crate::core::format::io::endian::Endian;
use crate::core::format::io::pod::{self, RawFatArch32, RawFatArch64, RawFatHeader};
use crate::core::format::macho::parse_macho_file_with_limits;
use crate::core::model::addr::FatFileOffset;
use crate::core::model::container::{FatArch, FatBinary};
use crate::core::model::header::{ArchSpec, FatHeader, FatMagic};
use crate::core::model::header::{CpuSubtype, CpuType};

/// Performs parse_fat_binary.
pub fn parse_fat_binary(data: &[u8]) -> Result<FatBinary<'_>> {
    parse_fat_binary_with_limits(data, &ParseLimits::default())
}

pub(crate) fn parse_fat_binary_with_limits<'data>(
    data: &'data [u8],
    limits: &ParseLimits,
) -> Result<FatBinary<'data>> {
    if data.len() < 8 {
        return Err(Error::format("file too small for fat header"));
    }

    // Fat headers are always big-endian per spec
    let endian = Endian::Big;

    let raw_header: RawFatHeader = pod::read_pod(data, 0)?;
    let magic_val = endian.interpret_u32(raw_header.magic);
    let magic = FatMagic::from_u32(magic_val)?;
    let nfat_arch = endian.interpret_u32(raw_header.nfat_arch);

    if nfat_arch == 0 {
        return Err(Error::format("fat binary has zero architectures"));
    }
    if nfat_arch as usize > limits.max_fat_arches {
        return Err(Error::limit(format!(
            "fat binary claims {nfat_arch} architectures, exceeding max_fat_arches={}",
            limits.max_fat_arches
        )));
    }

    let header = FatHeader::new(magic, nfat_arch);
    let mut arches = Vec::with_capacity(nfat_arch as usize);

    if magic.is_64bit() {
        let arch_size = size_of::<RawFatArch64>();
        for i in 0..nfat_arch as usize {
            let arch_off = 8usize
                .checked_add(i.checked_mul(arch_size).ok_or_else(|| {
                    Error::format(format!("fat arch {i}: index * stride overflows usize"))
                })?)
                .ok_or_else(|| {
                    Error::format(format!("fat arch {i}: header offset overflows usize"))
                })?;
            let raw: RawFatArch64 = pod::read_pod(data, arch_off)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;
            let offset = endian.interpret_u64(raw.offset);
            let size = endian.interpret_u64(raw.size);
            let align = endian.interpret_u32(raw.align);

            validate_arch_bounds(data.len(), offset, size, i)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;
            let (start, end) = arch_bounds_as_usize(offset, size, i)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;
            let slice = &data[start..end];
            let macho = parse_macho_file_with_limits(slice, limits)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;

            arches.push(
                FatArch::try_new(
                    ArchSpec {
                        cpu_type: CpuType(endian.interpret_i32(raw.cputype)),
                        cpu_subtype: CpuSubtype(endian.interpret_i32(raw.cpusubtype)),
                    },
                    FatFileOffset(offset),
                    size,
                    align,
                    endian.interpret_u32(raw.reserved),
                    macho,
                    data.len(),
                )
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?,
            );
        }
    } else {
        let arch_size = size_of::<RawFatArch32>();
        for i in 0..nfat_arch as usize {
            let arch_off = 8usize
                .checked_add(i.checked_mul(arch_size).ok_or_else(|| {
                    Error::format(format!("fat arch {i}: index * stride overflows usize"))
                })?)
                .ok_or_else(|| {
                    Error::format(format!("fat arch {i}: header offset overflows usize"))
                })?;
            let raw: RawFatArch32 = pod::read_pod(data, arch_off)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;
            let offset = endian.interpret_u32(raw.offset) as u64;
            let size = endian.interpret_u32(raw.size) as u64;
            let align = endian.interpret_u32(raw.align);

            validate_arch_bounds(data.len(), offset, size, i)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;
            let (start, end) = arch_bounds_as_usize(offset, size, i)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;
            let slice = &data[start..end];
            let macho = parse_macho_file_with_limits(slice, limits)
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?;

            arches.push(
                FatArch::try_new(
                    ArchSpec {
                        cpu_type: CpuType(endian.interpret_i32(raw.cputype)),
                        cpu_subtype: CpuSubtype(endian.interpret_i32(raw.cpusubtype)),
                    },
                    FatFileOffset(offset),
                    size,
                    align,
                    0,
                    macho,
                    data.len(),
                )
                .map_err(|error| error.with_context(ContextFrame::FatArchitecture { index: i }))?,
            );
        }
    }

    FatBinary::try_new(header, arches, data)
}

fn validate_arch_bounds(file_len: usize, offset: u64, size: u64, index: usize) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::format(format!("fat arch {index}: offset + size overflows")))?;
    if end > file_len as u64 {
        return Err(Error::format(format!(
            "fat arch {index}: slice {offset:#x}..{end:#x} exceeds file size {file_len:#x}"
        )));
    }
    Ok(())
}

/// Convert validated `u64` slice bounds into `usize` for indexing.
///
/// `validate_arch_bounds` has already proven `offset + size <= file_len as u64`
/// and that `file_len <= usize::MAX`, so both fit in `usize` on any target where
/// the file was mapped into memory. The explicit conversion guards against
/// cross-compiling to a 32-bit target where a valid-looking 64-bit fat offset
/// would otherwise truncate during a raw `as usize` cast.
fn arch_bounds_as_usize(offset: u64, size: u64, index: usize) -> Result<(usize, usize)> {
    let start = usize::try_from(offset).map_err(|_| {
        Error::format(format!(
            "fat arch {index}: offset {offset:#x} exceeds addressable memory"
        ))
    })?;
    let end_u64 = offset
        .checked_add(size)
        .ok_or_else(|| Error::format(format!("fat arch {index}: offset + size overflows")))?;
    let end = usize::try_from(end_u64).map_err(|_| {
        Error::format(format!(
            "fat arch {index}: end {end_u64:#x} exceeds addressable memory"
        ))
    })?;
    Ok((start, end))
}
