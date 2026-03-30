use std::io::Write;

use zerocopy::{Immutable, IntoBytes, KnownLayout};

use crate::addr::map::{AddressMap, MappingEntry};
use crate::addr::types::{Rva, ThinFileOffset, Va};
use crate::error::{Error, Result};
use crate::io::endian::Endian;
use crate::io::pod;
use crate::model::header::{Bitness, MachHeader};
use crate::model::load_command::ParsedLoadCommand;
use crate::model::mach::MachFile;
use crate::model::segment::Segment;
use crate::parse::mach::parse_mach_file;

/// An owned, mutable Mach-O image suitable for in-place patching.
///
/// Holds a `Vec<u8>` of the file bytes plus a snapshot of parsed metadata
/// (header, segments, load commands, address map). The metadata snapshot stays
/// valid as long as writes are purely in-place — modifying existing data bytes
/// without changing structural layout. To get a fresh read-only view after
/// writes, call [`as_mach_file()`](Self::as_mach_file).
pub struct OwnedMachFile {
    bytes: Vec<u8>,
    header: MachHeader,
    load_commands: Vec<ParsedLoadCommand>,
    segments: Vec<Segment>,
    endian: Endian,
    bitness: Bitness,
    address_map: AddressMap,
    image_base: Va,
}

impl OwnedMachFile {
    /// Create from a parsed `MachFile` by copying its bytes and metadata.
    pub fn from_mach_file(mach: &MachFile<'_>) -> Self {
        let entries: Vec<MappingEntry> = mach
            .segments()
            .iter()
            .map(|seg| MappingEntry {
                file_offset: seg.file_offset,
                file_size: seg.file_size,
                vm_addr: seg.vm_addr,
                vm_size: seg.vm_size,
            })
            .collect();

        Self {
            bytes: mach.bytes().to_vec(),
            header: mach.header().clone(),
            load_commands: mach.load_commands().to_vec(),
            segments: mach.segments().to_vec(),
            endian: mach.endian(),
            bitness: mach.bitness(),
            address_map: AddressMap::new(entries),
            image_base: mach.image_base(),
        }
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn header(&self) -> &MachHeader {
        &self.header
    }

    pub fn load_commands(&self) -> &[ParsedLoadCommand] {
        &self.load_commands
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn bitness(&self) -> Bitness {
        self.bitness
    }

    pub fn address_map(&self) -> &AddressMap {
        &self.address_map
    }

    pub fn image_base(&self) -> Va {
        self.image_base
    }

    // Write methods

    pub fn write_bytes_at(&mut self, offset: ThinFileOffset, data: &[u8]) -> Result<()> {
        let start = offset.as_usize();
        let end = start.checked_add(data.len()).ok_or(Error::Bounds {
            offset: offset.0,
            needed: data.len() as u64,
            available: self.bytes.len() as u64,
        })?;
        if end > self.bytes.len() {
            return Err(Error::Bounds {
                offset: offset.0,
                needed: data.len() as u64,
                available: self.bytes.len() as u64,
            });
        }
        self.bytes[start..end].copy_from_slice(data);
        Ok(())
    }

    pub fn write_bytes_at_va(&mut self, va: Va, data: &[u8]) -> Result<()> {
        let offset = self.address_map.va_to_thin_offset(va)?;
        self.write_bytes_at(offset, data)
    }

    pub fn write_bytes_at_rva(&mut self, rva: Rva, data: &[u8]) -> Result<()> {
        let va = AddressMap::rva_to_va(rva, self.image_base);
        self.write_bytes_at_va(va, data)
    }

    pub fn write_pod_at<T>(&mut self, offset: ThinFileOffset, value: &T) -> Result<()>
    where
        T: IntoBytes + Immutable + KnownLayout,
    {
        pod::write_pod(&mut self.bytes, offset.as_usize(), value)
    }

    /// Re-parse the owned bytes as a fresh read-only `MachFile`.
    pub fn as_mach_file(&self) -> Result<MachFile<'_>> {
        parse_mach_file(&self.bytes)
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    pub fn save_to<W: Write>(&self, mut writer: W) -> std::io::Result<()> {
        writer.write_all(&self.bytes)
    }
}

impl std::fmt::Debug for OwnedMachFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedMachFile")
            .field("size", &self.bytes.len())
            .field("endian", &self.endian)
            .field("bitness", &self.bitness)
            .finish()
    }
}

/// An owned, mutable fat binary container.
pub struct OwnedFatBinary {
    /// Full container bytes (header + arch table + padding + all arch slices).
    container_bytes: Vec<u8>,
    /// Per-arch owned copies with their offsets within the container.
    arches: Vec<OwnedFatArch>,
}

pub struct OwnedFatArch {
    /// Offset of this arch's slice within the fat container.
    pub offset: usize,
    /// Size of this arch's slice.
    pub size: usize,
    /// The owned mutable image for this arch.
    pub mach: OwnedMachFile,
}

impl OwnedFatBinary {
    /// Create from a parsed fat binary and the full container bytes.
    pub fn from_fat(fat: &crate::model::container::FatBinary<'_>, full_data: &[u8]) -> Self {
        let arches = fat
            .arches()
            .iter()
            .map(|arch| OwnedFatArch {
                offset: arch.fat_offset.0 as usize,
                size: arch.size as usize,
                mach: OwnedMachFile::from_mach_file(&arch.mach),
            })
            .collect();

        Self {
            container_bytes: full_data.to_vec(),
            arches,
        }
    }

    pub fn arches(&self) -> &[OwnedFatArch] {
        &self.arches
    }

    pub fn arch(&self, index: usize) -> Option<&OwnedMachFile> {
        self.arches.get(index).map(|a| &a.mach)
    }

    pub fn arch_mut(&mut self, index: usize) -> Option<&mut OwnedMachFile> {
        self.arches.get_mut(index).map(|a| &mut a.mach)
    }

    /// Sync modified arch bytes back into the container and return the bytes.
    pub fn into_bytes(mut self) -> Vec<u8> {
        self.sync_arches();
        self.container_bytes
    }

    pub fn save_to<W: Write>(&mut self, mut writer: W) -> std::io::Result<()> {
        self.sync_arches();
        writer.write_all(&self.container_bytes)
    }

    fn sync_arches(&mut self) {
        for arch in &self.arches {
            let end = arch.offset + arch.size;
            if end <= self.container_bytes.len() && arch.mach.bytes().len() == arch.size {
                self.container_bytes[arch.offset..end].copy_from_slice(arch.mach.bytes());
            }
        }
    }
}

impl std::fmt::Debug for OwnedFatBinary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnedFatBinary")
            .field("container_size", &self.container_bytes.len())
            .field("num_arches", &self.arches.len())
            .finish()
    }
}

// Convenience constructor on MachFile
impl MachFile<'_> {
    pub fn to_owned_mach(&self) -> OwnedMachFile {
        OwnedMachFile::from_mach_file(self)
    }
}
