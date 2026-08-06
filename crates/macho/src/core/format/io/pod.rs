use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::core::error::{Error, Result};

mod objc;

pub use objc::*;

/// Read a zerocopy-compatible struct from `data` at `offset`.
/// Returns a copy (not a reference) to handle unaligned data.
pub fn read_pod<T>(data: &[u8], offset: usize) -> Result<T>
where
    T: FromBytes + KnownLayout + Immutable + Copy,
{
    let size = size_of::<T>();
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::bounds(offset as u64, size as u64, data.len() as u64))?;
    if end > data.len() {
        return Err(Error::bounds(offset as u64, size as u64, data.len() as u64));
    }
    T::read_from_bytes(&data[offset..end]).map_err(|e| {
        Error::format(format!(
            "failed to read {} at offset {offset:#x}: {e}",
            std::any::type_name::<T>()
        ))
    })
}

// Raw on-disk structures. All fields are in file byte order and must be
// interpreted through an `Endian` context. Every struct uses #[repr(C)]
// for predictable layout and derives zerocopy traits for safe parsing.

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawMachHeader32 type.
pub struct RawMachHeader32 {
    /// The magic field.
    pub magic: u32,
    /// The cputype field.
    pub cputype: i32,
    /// The cpusubtype field.
    pub cpusubtype: i32,
    /// The filetype field.
    pub filetype: u32,
    /// The ncmds field.
    pub ncmds: u32,
    /// The sizeofcmds field.
    pub sizeofcmds: u32,
    /// The flags field.
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawMachHeader64 type.
pub struct RawMachHeader64 {
    /// The magic field.
    pub magic: u32,
    /// The cputype field.
    pub cputype: i32,
    /// The cpusubtype field.
    pub cpusubtype: i32,
    /// The filetype field.
    pub filetype: u32,
    /// The ncmds field.
    pub ncmds: u32,
    /// The sizeofcmds field.
    pub sizeofcmds: u32,
    /// The flags field.
    pub flags: u32,
    /// The reserved field.
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawFatHeader type.
pub struct RawFatHeader {
    /// The magic field.
    pub magic: u32,
    /// The nfat_arch field.
    pub nfat_arch: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawFatArch32 type.
pub struct RawFatArch32 {
    /// The cputype field.
    pub cputype: i32,
    /// The cpusubtype field.
    pub cpusubtype: i32,
    /// The offset field.
    pub offset: u32,
    /// The size field.
    pub size: u32,
    /// The align field.
    pub align: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawFatArch64 type.
pub struct RawFatArch64 {
    /// The cputype field.
    pub cputype: i32,
    /// The cpusubtype field.
    pub cpusubtype: i32,
    /// The offset field.
    pub offset: u64,
    /// The size field.
    pub size: u64,
    /// The align field.
    pub align: u32,
    /// The reserved field.
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawLoadCommand type.
pub struct RawLoadCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawSegmentCommand32 type.
pub struct RawSegmentCommand32 {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The segname field.
    pub segname: [u8; 16],
    /// The vmaddr field.
    pub vmaddr: u32,
    /// The vmsize field.
    pub vmsize: u32,
    /// The fileoff field.
    pub fileoff: u32,
    /// The filesize field.
    pub filesize: u32,
    /// The maxprot field.
    pub maxprot: i32,
    /// The initprot field.
    pub initprot: i32,
    /// The nsects field.
    pub nsects: u32,
    /// The flags field.
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawSegmentCommand64 type.
pub struct RawSegmentCommand64 {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The segname field.
    pub segname: [u8; 16],
    /// The vmaddr field.
    pub vmaddr: u64,
    /// The vmsize field.
    pub vmsize: u64,
    /// The fileoff field.
    pub fileoff: u64,
    /// The filesize field.
    pub filesize: u64,
    /// The maxprot field.
    pub maxprot: i32,
    /// The initprot field.
    pub initprot: i32,
    /// The nsects field.
    pub nsects: u32,
    /// The flags field.
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawSection32 type.
pub struct RawSection32 {
    /// The sectname field.
    pub sectname: [u8; 16],
    /// The segname field.
    pub segname: [u8; 16],
    /// The addr field.
    pub addr: u32,
    /// The size field.
    pub size: u32,
    /// The offset field.
    pub offset: u32,
    /// The align field.
    pub align: u32,
    /// The reloff field.
    pub reloff: u32,
    /// The nreloc field.
    pub nreloc: u32,
    /// The flags field.
    pub flags: u32,
    /// The reserved1 field.
    pub reserved1: u32,
    /// The reserved2 field.
    pub reserved2: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawSection64 type.
pub struct RawSection64 {
    /// The sectname field.
    pub sectname: [u8; 16],
    /// The segname field.
    pub segname: [u8; 16],
    /// The addr field.
    pub addr: u64,
    /// The size field.
    pub size: u64,
    /// The offset field.
    pub offset: u32,
    /// The align field.
    pub align: u32,
    /// The reloff field.
    pub reloff: u32,
    /// The nreloc field.
    pub nreloc: u32,
    /// The flags field.
    pub flags: u32,
    /// The reserved1 field.
    pub reserved1: u32,
    /// The reserved2 field.
    pub reserved2: u32,
    /// The reserved3 field.
    pub reserved3: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawSymtabCommand type.
pub struct RawSymtabCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The symoff field.
    pub symoff: u32,
    /// The nsyms field.
    pub nsyms: u32,
    /// The stroff field.
    pub stroff: u32,
    /// The strsize field.
    pub strsize: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawDysymtabCommand type.
pub struct RawDysymtabCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The ilocalsym field.
    pub ilocalsym: u32,
    /// The nlocalsym field.
    pub nlocalsym: u32,
    /// The iextdefsym field.
    pub iextdefsym: u32,
    /// The nextdefsym field.
    pub nextdefsym: u32,
    /// The iundefsym field.
    pub iundefsym: u32,
    /// The nundefsym field.
    pub nundefsym: u32,
    /// The tocoff field.
    pub tocoff: u32,
    /// The ntoc field.
    pub ntoc: u32,
    /// The modtaboff field.
    pub modtaboff: u32,
    /// The nmodtab field.
    pub nmodtab: u32,
    /// The extrefsymoff field.
    pub extrefsymoff: u32,
    /// The nextrefsyms field.
    pub nextrefsyms: u32,
    /// The indirectsymoff field.
    pub indirectsymoff: u32,
    /// The nindirectsyms field.
    pub nindirectsyms: u32,
    /// The extreloff field.
    pub extreloff: u32,
    /// The nextrel field.
    pub nextrel: u32,
    /// The locreloff field.
    pub locreloff: u32,
    /// The nlocrel field.
    pub nlocrel: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawDylibCommand type.
pub struct RawDylibCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The name_offset field.
    pub name_offset: u32,
    /// The timestamp field.
    pub timestamp: u32,
    /// The current_version field.
    pub current_version: u32,
    /// The compatibility_version field.
    pub compatibility_version: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawUuidCommand type.
pub struct RawUuidCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The uuid field.
    pub uuid: [u8; 16],
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawBuildVersionCommand type.
pub struct RawBuildVersionCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The platform field.
    pub platform: u32,
    /// The minos field.
    pub minos: u32,
    /// The sdk field.
    pub sdk: u32,
    /// The ntools field.
    pub ntools: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawBuildToolVersion type.
pub struct RawBuildToolVersion {
    /// The tool field.
    pub tool: u32,
    /// The version field.
    pub version: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawEntryPointCommand type.
pub struct RawEntryPointCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The entryoff field.
    pub entryoff: u64,
    /// The stacksize field.
    pub stacksize: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawSourceVersionCommand type.
pub struct RawSourceVersionCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The version field.
    pub version: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawLinkeditDataCommand type.
pub struct RawLinkeditDataCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The dataoff field.
    pub dataoff: u32,
    /// The datasize field.
    pub datasize: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawDyldInfoCommand type.
pub struct RawDyldInfoCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The rebase_off field.
    pub rebase_off: u32,
    /// The rebase_size field.
    pub rebase_size: u32,
    /// The bind_off field.
    pub bind_off: u32,
    /// The bind_size field.
    pub bind_size: u32,
    /// The weak_bind_off field.
    pub weak_bind_off: u32,
    /// The weak_bind_size field.
    pub weak_bind_size: u32,
    /// The lazy_bind_off field.
    pub lazy_bind_off: u32,
    /// The lazy_bind_size field.
    pub lazy_bind_size: u32,
    /// The export_off field.
    pub export_off: u32,
    /// The export_size field.
    pub export_size: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawEncryptionInfoCommand type.
pub struct RawEncryptionInfoCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The cryptoff field.
    pub cryptoff: u32,
    /// The cryptsize field.
    pub cryptsize: u32,
    /// The cryptid field.
    pub cryptid: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawEncryptionInfoCommand64 type.
pub struct RawEncryptionInfoCommand64 {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The cryptoff field.
    pub cryptoff: u32,
    /// The cryptsize field.
    pub cryptsize: u32,
    /// The cryptid field.
    pub cryptid: u32,
    /// The pad field.
    pub pad: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawVersionMinCommand type.
pub struct RawVersionMinCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The version field.
    pub version: u32,
    /// The sdk field.
    pub sdk: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawNoteCommand type.
pub struct RawNoteCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The data_owner field.
    pub data_owner: [u8; 16],
    /// The offset field.
    pub offset: u64,
    /// The size field.
    pub size: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawFilesetEntryCommand type.
pub struct RawFilesetEntryCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The vmaddr field.
    pub vmaddr: u64,
    /// The fileoff field.
    pub fileoff: u64,
    /// The entry_id_offset field.
    pub entry_id_offset: u32,
    /// The reserved field.
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawStringCommand type.
pub struct RawStringCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The string_offset field.
    pub string_offset: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawLinkerOptionCommand type.
pub struct RawLinkerOptionCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The count field.
    pub count: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawPrebindCksumCommand type.
pub struct RawPrebindCksumCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The cksum field.
    pub cksum: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawTwolevelHintsCommand type.
pub struct RawTwolevelHintsCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The offset field.
    pub offset: u32,
    /// The nhints field.
    pub nhints: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawRoutinesCommand type.
pub struct RawRoutinesCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The init_address field.
    pub init_address: u32,
    /// The init_module field.
    pub init_module: u32,
    /// The reserved1 field.
    pub reserved1: u32,
    /// The reserved2 field.
    pub reserved2: u32,
    /// The reserved3 field.
    pub reserved3: u32,
    /// The reserved4 field.
    pub reserved4: u32,
    /// The reserved5 field.
    pub reserved5: u32,
    /// The reserved6 field.
    pub reserved6: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawRoutinesCommand64 type.
pub struct RawRoutinesCommand64 {
    /// The cmd field.
    pub cmd: u32,
    /// The cmdsize field.
    pub cmdsize: u32,
    /// The init_address field.
    pub init_address: u64,
    /// The init_module field.
    pub init_module: u64,
    /// The reserved1 field.
    pub reserved1: u64,
    /// The reserved2 field.
    pub reserved2: u64,
    /// The reserved3 field.
    pub reserved3: u64,
    /// The reserved4 field.
    pub reserved4: u64,
    /// The reserved5 field.
    pub reserved5: u64,
    /// The reserved6 field.
    pub reserved6: u64,
}

// Symbol table entries (nlist)

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawNlist32 type.
pub struct RawNlist32 {
    /// The n_strx field.
    pub n_strx: u32,
    /// The n_type field.
    pub n_type: u8,
    /// The n_sect field.
    pub n_sect: u8,
    /// The n_desc field.
    pub n_desc: i16,
    /// The n_value field.
    pub n_value: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawNlist64 type.
pub struct RawNlist64 {
    /// The n_strx field.
    pub n_strx: u32,
    /// The n_type field.
    pub n_type: u8,
    /// The n_sect field.
    pub n_sect: u8,
    /// The n_desc field.
    pub n_desc: u16,
    /// The n_value field.
    pub n_value: u64,
}

// Relocation entries

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawRelocationInfo type.
pub struct RawRelocationInfo {
    /// The r_address field.
    pub r_address: i32,
    /// The r_symbolnum_and_flags field.
    pub r_symbolnum_and_flags: u32,
}

// Chained fixup structures

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawChainedFixupsHeader type.
pub struct RawChainedFixupsHeader {
    /// The fixups_version field.
    pub fixups_version: u32,
    /// The starts_offset field.
    pub starts_offset: u32,
    /// The imports_offset field.
    pub imports_offset: u32,
    /// The symbols_offset field.
    pub symbols_offset: u32,
    /// The imports_count field.
    pub imports_count: u32,
    /// The imports_format field.
    pub imports_format: u32,
    /// The symbols_format field.
    pub symbols_format: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawChainedImport type.
pub struct RawChainedImport {
    /// The packed field.
    pub packed: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawChainedImportAddend type.
pub struct RawChainedImportAddend {
    /// The packed field.
    pub packed: u32,
    /// The addend field.
    pub addend: i32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
/// The RawChainedImportAddend64 type.
pub struct RawChainedImportAddend64 {
    /// The packed field.
    pub packed: u64,
    /// The addend field.
    pub addend: u64,
}

/// Write a zerocopy-compatible struct into `buf` at `offset`.
pub fn write_pod<T>(buf: &mut [u8], offset: usize, value: &T) -> Result<()>
where
    T: IntoBytes + Immutable + KnownLayout,
{
    let size = size_of::<T>();
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::bounds(offset as u64, size as u64, buf.len() as u64))?;
    if end > buf.len() {
        return Err(Error::bounds(offset as u64, size as u64, buf.len() as u64));
    }
    buf[offset..end].copy_from_slice(value.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_pod_valid() {
        let data = 0xDEADBEEFu32.to_le_bytes();
        let val: u32 = read_pod(&data, 0).unwrap();
        assert_eq!(val, 0xDEADBEEF);
    }

    #[test]
    fn read_pod_truncated() {
        let data = [0u8; 2];
        let result: Result<u32> = read_pod(&data, 0);
        assert!(result.is_err());
    }

    #[test]
    fn read_pod_offset_overflow() {
        let data = [0u8; 8];
        let result: Result<u32> = read_pod(&data, usize::MAX);
        assert!(result.is_err());
    }

    #[test]
    fn raw_header_size() {
        assert_eq!(size_of::<RawMachHeader32>(), 28);
        assert_eq!(size_of::<RawMachHeader64>(), 32);
    }

    #[test]
    fn raw_segment_size() {
        assert_eq!(size_of::<RawSegmentCommand32>(), 56);
        assert_eq!(size_of::<RawSegmentCommand64>(), 72);
    }

    #[test]
    fn raw_section_size() {
        assert_eq!(size_of::<RawSection32>(), 68);
        assert_eq!(size_of::<RawSection64>(), 80);
    }

    #[test]
    fn raw_nlist_size() {
        assert_eq!(size_of::<RawNlist32>(), 12);
        assert_eq!(size_of::<RawNlist64>(), 16);
    }

    #[test]
    fn raw_relocation_size() {
        assert_eq!(size_of::<RawRelocationInfo>(), 8);
    }

    #[test]
    fn raw_chained_fixup_sizes() {
        assert_eq!(size_of::<RawChainedFixupsHeader>(), 28);
        assert_eq!(size_of::<RawChainedImport>(), 4);
        assert_eq!(size_of::<RawChainedImportAddend>(), 8);
        assert_eq!(size_of::<RawChainedImportAddend64>(), 16);
    }

    #[test]
    fn write_pod_round_trip() {
        let mut buf = [0u8; 16];
        let val: u32 = 0xCAFEBABE;
        write_pod(&mut buf, 4, &val).unwrap();
        let read_back: u32 = read_pod(&buf, 4).unwrap();
        assert_eq!(read_back, val);
    }

    #[test]
    fn write_pod_bounds() {
        let mut buf = [0u8; 4];
        let val: u64 = 0;
        assert!(write_pod(&mut buf, 0, &val).is_err());
    }
}
