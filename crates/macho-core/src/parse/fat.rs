use crate::addr::FatFileOffset;
use crate::error::{Error, Result};
use crate::io::endian::Endian;
use crate::io::pod::{self, RawFatArch32, RawFatArch64, RawFatHeader};
use crate::model::container::{FatArch, FatBinary};
use crate::model::fat::{ArchSpec, FatHeader, FatMagic};
use crate::model::header::{CpuSubtype, CpuType};
use crate::parse::mach::parse_mach_file;

pub fn parse_fat_binary(data: &[u8]) -> Result<FatBinary<'_>> {
    if data.len() < 8 {
        return Err(Error::Format("file too small for fat header".into()));
    }

    // Fat headers are always big-endian per spec
    let endian = Endian::Big;

    let raw_header: RawFatHeader = pod::read_pod(data, 0)?;
    let magic_val = endian.interpret_u32(raw_header.magic);
    let magic = FatMagic::from_u32(magic_val)?;
    let nfat_arch = endian.interpret_u32(raw_header.nfat_arch);

    if nfat_arch == 0 {
        return Err(Error::Format("fat binary has zero architectures".into()));
    }
    if nfat_arch > 256 {
        return Err(Error::Format(format!(
            "fat binary claims {nfat_arch} architectures, which is unreasonably large"
        )));
    }

    let header = FatHeader { magic, nfat_arch };
    let mut arches = Vec::with_capacity(nfat_arch as usize);

    if magic.is_64bit() {
        let arch_size = size_of::<RawFatArch64>();
        for i in 0..nfat_arch as usize {
            let raw: RawFatArch64 = pod::read_pod(data, 8 + i * arch_size)?;
            let offset = endian.interpret_u64(raw.offset);
            let size = endian.interpret_u64(raw.size);
            let align = endian.interpret_u32(raw.align);

            validate_arch_bounds(data.len(), offset, size, i)?;
            let slice = &data[offset as usize..(offset + size) as usize];
            let mach = parse_mach_file(slice)?;

            arches.push(FatArch {
                spec: ArchSpec {
                    cpu_type: CpuType(endian.interpret_i32(raw.cputype)),
                    cpu_subtype: CpuSubtype(endian.interpret_i32(raw.cpusubtype)),
                },
                fat_offset: FatFileOffset(offset),
                size,
                align,
                mach,
            });
        }
    } else {
        let arch_size = size_of::<RawFatArch32>();
        for i in 0..nfat_arch as usize {
            let raw: RawFatArch32 = pod::read_pod(data, 8 + i * arch_size)?;
            let offset = endian.interpret_u32(raw.offset) as u64;
            let size = endian.interpret_u32(raw.size) as u64;
            let align = endian.interpret_u32(raw.align);

            validate_arch_bounds(data.len(), offset, size, i)?;
            let slice = &data[offset as usize..(offset + size) as usize];
            let mach = parse_mach_file(slice)?;

            arches.push(FatArch {
                spec: ArchSpec {
                    cpu_type: CpuType(endian.interpret_i32(raw.cputype)),
                    cpu_subtype: CpuSubtype(endian.interpret_i32(raw.cpusubtype)),
                },
                fat_offset: FatFileOffset(offset),
                size,
                align,
                mach,
            });
        }
    }

    Ok(FatBinary { header, arches })
}

fn validate_arch_bounds(file_len: usize, offset: u64, size: u64, index: usize) -> Result<()> {
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::Format(format!("fat arch {index}: offset + size overflows")))?;
    if end > file_len as u64 {
        return Err(Error::Format(format!(
            "fat arch {index}: slice {offset:#x}..{end:#x} exceeds file size {file_len:#x}"
        )));
    }
    Ok(())
}
