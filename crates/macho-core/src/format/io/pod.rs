use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use crate::error::{Error, Result};

/// Read a zerocopy-compatible struct from `data` at `offset`.
/// Returns a copy (not a reference) to handle unaligned data.
pub fn read_pod<T>(data: &[u8], offset: usize) -> Result<T>
where
    T: FromBytes + KnownLayout + Immutable + Copy,
{
    let size = size_of::<T>();
    let end = offset.checked_add(size).ok_or(Error::Bounds {
        offset: offset as u64,
        needed: size as u64,
        available: data.len() as u64,
    })?;
    if end > data.len() {
        return Err(Error::Bounds {
            offset: offset as u64,
            needed: size as u64,
            available: data.len() as u64,
        });
    }
    T::read_from_bytes(&data[offset..end]).map_err(|e| {
        Error::Format(format!(
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
pub struct RawMachHeader32 {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawMachHeader64 {
    pub magic: u32,
    pub cputype: i32,
    pub cpusubtype: i32,
    pub filetype: u32,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawFatHeader {
    pub magic: u32,
    pub nfat_arch: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawFatArch32 {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u32,
    pub size: u32,
    pub align: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawFatArch64 {
    pub cputype: i32,
    pub cpusubtype: i32,
    pub offset: u64,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawLoadCommand {
    pub cmd: u32,
    pub cmdsize: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawSegmentCommand32 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u32,
    pub vmsize: u32,
    pub fileoff: u32,
    pub filesize: u32,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawSegmentCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub segname: [u8; 16],
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub maxprot: i32,
    pub initprot: i32,
    pub nsects: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawSection32 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u32,
    pub size: u32,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawSection64 {
    pub sectname: [u8; 16],
    pub segname: [u8; 16],
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub align: u32,
    pub reloff: u32,
    pub nreloc: u32,
    pub flags: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawSymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub symoff: u32,
    pub nsyms: u32,
    pub stroff: u32,
    pub strsize: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawDysymtabCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawDylibCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub name_offset: u32,
    pub timestamp: u32,
    pub current_version: u32,
    pub compatibility_version: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawUuidCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub uuid: [u8; 16],
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawBuildVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub platform: u32,
    pub minos: u32,
    pub sdk: u32,
    pub ntools: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawBuildToolVersion {
    pub tool: u32,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawEntryPointCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub entryoff: u64,
    pub stacksize: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawSourceVersionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawLinkeditDataCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub dataoff: u32,
    pub datasize: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawDyldInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawEncryptionInfoCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawEncryptionInfoCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cryptoff: u32,
    pub cryptsize: u32,
    pub cryptid: u32,
    pub pad: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawVersionMinCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub version: u32,
    pub sdk: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawNoteCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub data_owner: [u8; 16],
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawFilesetEntryCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub vmaddr: u64,
    pub fileoff: u64,
    pub entry_id_offset: u32,
    pub reserved: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawStringCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub string_offset: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawLinkerOptionCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawPrebindCksumCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub cksum: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawTwolevelHintsCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub offset: u32,
    pub nhints: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawRoutinesCommand {
    pub cmd: u32,
    pub cmdsize: u32,
    pub init_address: u32,
    pub init_module: u32,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
    pub reserved4: u32,
    pub reserved5: u32,
    pub reserved6: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawRoutinesCommand64 {
    pub cmd: u32,
    pub cmdsize: u32,
    pub init_address: u64,
    pub init_module: u64,
    pub reserved1: u64,
    pub reserved2: u64,
    pub reserved3: u64,
    pub reserved4: u64,
    pub reserved5: u64,
    pub reserved6: u64,
}

// Symbol table entries (nlist)

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawNlist32 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: i16,
    pub n_value: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawNlist64 {
    pub n_strx: u32,
    pub n_type: u8,
    pub n_sect: u8,
    pub n_desc: u16,
    pub n_value: u64,
}

// Relocation entries

#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawRelocationInfo {
    pub r_address: i32,
    pub r_symbolnum_and_flags: u32,
}

// Chained fixup structures

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawChainedFixupsHeader {
    pub fixups_version: u32,
    pub starts_offset: u32,
    pub imports_offset: u32,
    pub symbols_offset: u32,
    pub imports_count: u32,
    pub imports_format: u32,
    pub symbols_format: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawChainedImport {
    pub packed: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawChainedImportAddend {
    pub packed: u32,
    pub addend: i32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawChainedImportAddend64 {
    pub packed: u64,
    pub addend: u64,
}

/// Write a zerocopy-compatible struct into `buf` at `offset`.
pub fn write_pod<T>(buf: &mut [u8], offset: usize, value: &T) -> Result<()>
where
    T: IntoBytes + Immutable + KnownLayout,
{
    let size = size_of::<T>();
    let end = offset.checked_add(size).ok_or(Error::Bounds {
        offset: offset as u64,
        needed: size as u64,
        available: buf.len() as u64,
    })?;
    if end > buf.len() {
        return Err(Error::Bounds {
            offset: offset as u64,
            needed: size as u64,
            available: buf.len() as u64,
        });
    }
    buf[offset..end].copy_from_slice(value.as_bytes());
    Ok(())
}

// ObjC runtime structures (64-bit)

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawObjCClass64 {
    pub isa: u64,
    pub superclass: u64,
    pub cache: u64,
    pub vtable: u64,
    pub data: u64, // pointer to class_ro_t (bit 0 = swift flag in some ABIs)
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawClassRoT64 {
    pub flags: u32,
    pub instance_start: u32,
    pub instance_size: u32,
    pub reserved: u32,
    pub ivar_layout: u64,
    pub name: u64,
    pub base_methods: u64,
    pub base_protocols: u64,
    pub ivars: u64,
    pub weak_ivar_layout: u64,
    pub base_properties: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawMethodListHeader {
    pub entsize_and_flags: u32,
    pub count: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawMethodT {
    pub name: u64,
    pub types: u64,
    pub imp: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawRelativeMethodT {
    pub name_offset: i32,
    pub types_offset: i32,
    pub imp_offset: i32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawIvarT64 {
    pub offset_ptr: u64,
    pub name: u64,
    pub type_encoding: u64,
    pub alignment: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawPropertyT {
    pub name: u64,
    pub attributes: u64,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawProtocolT64 {
    pub isa: u64,
    pub name: u64,
    pub protocols: u64,
    pub instance_methods: u64,
    pub class_methods: u64,
    pub optional_instance_methods: u64,
    pub optional_class_methods: u64,
    pub instance_properties: u64,
    pub size: u32,
    pub flags: u32,
}

#[derive(Debug, Clone, Copy, FromBytes, Immutable, KnownLayout)]
#[repr(C)]
pub struct RawCategoryT64 {
    pub name: u64,
    pub cls: u64,
    pub instance_methods: u64,
    pub class_methods: u64,
    pub protocols: u64,
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
