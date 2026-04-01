use crate::error::{Error, Result};
use crate::format::constants::MachoHeaderFlags;
use crate::format::io::pod::{self, RawMachHeader32, RawMachHeader64};
use crate::format::load_commands::parse_load_commands;
use crate::model::header::*;
use crate::model::macho_file::MachoFile;

pub fn parse_macho_file(data: &[u8]) -> Result<MachoFile<'_>> {
    if data.len() < 4 {
        return Err(Error::Format("file too small for Mach-O magic".into()));
    }

    let magic_val = u32::from_ne_bytes(data[0..4].try_into().unwrap());
    let magic = MagicNumber::from_u32(magic_val)?;
    let endian = magic.endian();
    let bitness = magic.bitness();

    let header = match bitness {
        Bitness::Bits32 => {
            let raw: RawMachHeader32 = pod::read_pod(data, 0)?;
            MachoHeader {
                magic,
                cpu_type: CpuType(endian.interpret_i32(raw.cputype)),
                cpu_subtype: CpuSubtype(endian.interpret_i32(raw.cpusubtype)),
                file_type: FileType::from_u32(endian.interpret_u32(raw.filetype)),
                ncmds: endian.interpret_u32(raw.ncmds),
                sizeofcmds: endian.interpret_u32(raw.sizeofcmds),
                flags: MachoHeaderFlags::from_bits_truncate(endian.interpret_u32(raw.flags)),
                reserved: 0,
            }
        }
        Bitness::Bits64 => {
            let raw: RawMachHeader64 = pod::read_pod(data, 0)?;
            MachoHeader {
                magic,
                cpu_type: CpuType(endian.interpret_i32(raw.cputype)),
                cpu_subtype: CpuSubtype(endian.interpret_i32(raw.cpusubtype)),
                file_type: FileType::from_u32(endian.interpret_u32(raw.filetype)),
                ncmds: endian.interpret_u32(raw.ncmds),
                sizeofcmds: endian.interpret_u32(raw.sizeofcmds),
                flags: MachoHeaderFlags::from_bits_truncate(endian.interpret_u32(raw.flags)),
                reserved: endian.interpret_u32(raw.reserved),
            }
        }
    };

    let lc_offset = bitness.header_size();
    let (load_commands, segments) = parse_load_commands(
        data,
        endian,
        bitness,
        lc_offset,
        header.ncmds,
        header.sizeofcmds,
    )?;

    Ok(MachoFile::new(
        data,
        header,
        load_commands,
        segments,
        endian,
        bitness,
    ))
}
