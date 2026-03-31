use std::io::Write;

use zerocopy::{Immutable, IntoBytes, KnownLayout};

use crate::addr::map::{AddressMap, MappingEntry};
use crate::addr::types::{Rva, ThinFileOffset, Va};
use crate::error::{Error, Result};
use crate::io::endian::Endian;
use crate::io::pod;
use crate::model::fat::FatMagic;
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
        Self {
            bytes: mach.bytes().to_vec(),
            header: mach.header().clone(),
            load_commands: mach.load_commands().to_vec(),
            segments: mach.segments().to_vec(),
            endian: mach.endian(),
            bitness: mach.bitness(),
            address_map: AddressMap::new(mapping_entries(mach.segments())),
            image_base: mach.image_base(),
        }
    }

    /// Create from owned Mach-O bytes by parsing and snapshotting metadata.
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let parsed = parse_mach_file(&bytes)?;
        let header = parsed.header().clone();
        let load_commands = parsed.load_commands().to_vec();
        let segments = parsed.segments().to_vec();
        let endian = parsed.endian();
        let bitness = parsed.bitness();
        let image_base = parsed.image_base();
        let address_map = AddressMap::new(mapping_entries(&segments));

        Ok(Self {
            bytes,
            header,
            load_commands,
            segments,
            endian,
            bitness,
            address_map,
            image_base,
        })
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
    magic: FatMagic,
    /// Per-arch owned copies with their offsets within the container.
    arches: Vec<OwnedFatArch>,
}

pub struct OwnedFatArch {
    /// Architecture spec from the fat arch table.
    pub spec: crate::model::fat::ArchSpec,
    /// Offset of this arch's slice within the fat container.
    pub offset: usize,
    /// Size of this arch's slice.
    pub size: usize,
    /// Alignment exponent from the fat arch table (`2^align` bytes).
    pub align: u32,
    /// Reserved field from `fat_arch_64`.
    pub reserved: u32,
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
                spec: arch.spec,
                offset: arch.fat_offset.0 as usize,
                size: arch.size as usize,
                align: arch.align,
                reserved: arch.reserved,
                mach: OwnedMachFile::from_mach_file(&arch.mach),
            })
            .collect();

        Self {
            container_bytes: full_data.to_vec(),
            magic: fat.header.magic,
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

    pub fn replace_arch(&mut self, index: usize, bytes: Vec<u8>) -> Result<()> {
        let arch_count = self.arches.len();
        let mach = OwnedMachFile::from_bytes(bytes)?;
        let arch = self.arches.get_mut(index).ok_or_else(|| {
            Error::Format(format!(
                "fat arch index {index} out of range (have {arch_count})",
            ))
        })?;
        arch.size = mach.bytes().len();
        arch.mach = mach;
        Ok(())
    }

    /// Serialize the current fat container, rebuilding offsets if any slice changed size.
    pub fn try_into_bytes(mut self) -> Result<Vec<u8>> {
        self.rebuild_in_place()?;
        Ok(self.container_bytes)
    }

    /// Serialize the current fat container, rebuilding offsets if any slice changed size.
    ///
    /// Panics only if the current in-memory state cannot be re-encoded as a valid fat binary.
    pub fn into_bytes(self) -> Vec<u8> {
        self.try_into_bytes()
            .expect("OwnedFatBinary::into_bytes failed to rebuild fat container")
    }

    pub fn save_to<W: Write>(&mut self, mut writer: W) -> std::io::Result<()> {
        self.rebuild_in_place()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
        writer.write_all(&self.container_bytes)
    }

    pub fn rebuild_bytes(&self) -> Result<Vec<u8>> {
        let (out, _) = self.build_rebuilt_container()?;
        Ok(out)
    }

    fn rebuild_in_place(&mut self) -> Result<()> {
        let (rebuilt, layouts) = self.build_rebuilt_container()?;
        for (arch, (offset, size)) in self.arches.iter_mut().zip(layouts) {
            arch.offset = offset;
            arch.size = size;
        }
        self.container_bytes = rebuilt;
        Ok(())
    }

    fn build_rebuilt_container(&self) -> Result<(Vec<u8>, Vec<(usize, usize)>)> {
        let arch_entry_size = match self.magic {
            FatMagic::Fat32 => 20usize,
            FatMagic::Fat64 => 32usize,
        };
        let header_size = 8usize
            .checked_add(
                arch_entry_size
                    .checked_mul(self.arches.len())
                    .ok_or_else(|| Error::Format("fat arch table size overflow".into()))?,
            )
            .ok_or_else(|| Error::Format("fat header size overflow".into()))?;

        let layouts = self.arches.iter().try_fold(
            (Vec::with_capacity(self.arches.len()), header_size),
            |(mut layouts, cursor), arch| {
                let align_bytes = fat_align_bytes(arch.align)?;
                let offset = align_up(cursor, align_bytes);
                let size = arch.mach.bytes().len();
                let end = offset
                    .checked_add(size)
                    .ok_or_else(|| Error::Format("fat arch offset overflow".into()))?;
                layouts.push((arch, offset, size));
                Ok::<_, Error>((layouts, end))
            },
        )?;
        let (layouts, total_size) = layouts;

        let mut out = vec![0; total_size];
        write_fat_header(&mut out, self.magic, self.arches.len() as u32);
        let mut offsets = Vec::with_capacity(self.arches.len());

        for (index, (arch, offset, size)) in layouts.iter().enumerate() {
            write_fat_arch_entry(
                &mut out,
                self.magic,
                index,
                arch,
                u64::try_from(*offset)
                    .map_err(|_| Error::Format("fat arch offset exceeds u64".into()))?,
            )?;

            let end = *offset + *size;
            out[*offset..end].copy_from_slice(arch.mach.bytes());
            offsets.push((*offset, *size));
        }

        Ok((out, offsets))
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

fn mapping_entries(segments: &[Segment]) -> Vec<MappingEntry> {
    segments
        .iter()
        .map(|seg| MappingEntry {
            file_offset: seg.file_offset,
            file_size: seg.file_size,
            vm_addr: seg.vm_addr,
            vm_size: seg.vm_size,
        })
        .collect()
}

fn fat_align_bytes(align: u32) -> Result<usize> {
    1usize
        .checked_shl(align)
        .ok_or_else(|| Error::Format(format!("fat arch alignment 2^{align} is too large")))
}

fn align_up(value: usize, align: usize) -> usize {
    if align <= 1 {
        value
    } else {
        value.div_ceil(align) * align
    }
}

fn write_fat_header(out: &mut [u8], magic: FatMagic, nfat_arch: u32) {
    let magic = match magic {
        FatMagic::Fat32 => crate::constants::FAT_MAGIC,
        FatMagic::Fat64 => crate::constants::FAT_MAGIC_64,
    };

    out[0..4].copy_from_slice(&magic.to_be_bytes());
    out[4..8].copy_from_slice(&nfat_arch.to_be_bytes());
}

fn write_fat_arch_entry(
    out: &mut [u8],
    magic: FatMagic,
    index: usize,
    arch: &OwnedFatArch,
    offset: u64,
) -> Result<()> {
    let base = match magic {
        FatMagic::Fat32 => 8 + index * 20,
        FatMagic::Fat64 => 8 + index * 32,
    };

    out[base..base + 4].copy_from_slice(&arch.spec.cpu_type.0.to_be_bytes());
    out[base + 4..base + 8].copy_from_slice(&arch.spec.cpu_subtype.0.to_be_bytes());

    match magic {
        FatMagic::Fat32 => {
            let offset = u32::try_from(offset)
                .map_err(|_| Error::Format("fat32 arch offset exceeds u32".into()))?;
            let size = u32::try_from(arch.mach.bytes().len())
                .map_err(|_| Error::Format("fat32 arch size exceeds u32".into()))?;
            out[base + 8..base + 12].copy_from_slice(&offset.to_be_bytes());
            out[base + 12..base + 16].copy_from_slice(&size.to_be_bytes());
            out[base + 16..base + 20].copy_from_slice(&arch.align.to_be_bytes());
        }
        FatMagic::Fat64 => {
            out[base + 8..base + 16].copy_from_slice(&offset.to_be_bytes());
            out[base + 16..base + 24]
                .copy_from_slice(&(arch.mach.bytes().len() as u64).to_be_bytes());
            out[base + 24..base + 28].copy_from_slice(&arch.align.to_be_bytes());
            out[base + 28..base + 32].copy_from_slice(&arch.reserved.to_be_bytes());
        }
    }

    Ok(())
}
