use crate::addr::{FatFileOffset, ThinFileOffset};
use crate::error::{Error, Result};
use crate::model::fat::{ArchSpec, FatHeader};
use crate::model::header::{CpuSubtype, CpuType};
use crate::model::mach::MachFile;

#[derive(Debug)]
pub struct FatArch<'data> {
    pub spec: ArchSpec,
    pub fat_offset: FatFileOffset,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
    pub mach: MachFile<'data>,
}

impl FatArch<'_> {
    /// Translate a thin-image-relative offset to a fat-container-relative offset.
    pub fn thin_to_fat_offset(&self, thin: ThinFileOffset) -> FatFileOffset {
        FatFileOffset(self.fat_offset.0 + thin.0)
    }

    /// Translate a fat-container-relative offset to a thin-image-relative offset.
    pub fn fat_to_thin_offset(&self, fat: FatFileOffset) -> Result<ThinFileOffset> {
        let rel = fat.0.wrapping_sub(self.fat_offset.0);
        if rel >= self.size {
            return Err(Error::Address(format!(
                "fat offset {fat} is outside arch slice at {:#x}..{:#x}",
                self.fat_offset.0,
                self.fat_offset.0 + self.size,
            )));
        }
        Ok(ThinFileOffset(rel))
    }
}

pub struct FatBinary<'data> {
    pub header: FatHeader,
    pub arches: Vec<FatArch<'data>>,
}

impl<'data> FatBinary<'data> {
    pub fn arches(&self) -> &[FatArch<'data>] {
        &self.arches
    }

    /// Find an arch by CPU type only (returns first match).
    pub fn find_arch(&self, cpu_type: CpuType) -> Option<&FatArch<'data>> {
        self.arches.iter().find(|a| a.spec.cpu_type == cpu_type)
    }

    /// Find an arch by exact CPU type and masked subtype.
    pub fn find_arch_spec(
        &self,
        cpu_type: CpuType,
        cpu_subtype: CpuSubtype,
    ) -> Option<&FatArch<'data>> {
        self.arches.iter().find(|a| {
            a.spec.cpu_type == cpu_type && a.spec.cpu_subtype.masked() == cpu_subtype.masked()
        })
    }
}

impl std::fmt::Debug for FatBinary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FatBinary")
            .field("header", &self.header)
            .field(
                "arches",
                &self
                    .arches
                    .iter()
                    .map(|a| a.spec.name())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

pub enum MachContainer<'data> {
    Thin(MachFile<'data>),
    Fat(FatBinary<'data>),
}

impl<'data> MachContainer<'data> {
    pub fn is_thin(&self) -> bool {
        matches!(self, Self::Thin(_))
    }

    pub fn is_fat(&self) -> bool {
        matches!(self, Self::Fat(_))
    }

    pub fn mach_files(&self) -> Vec<&MachFile<'data>> {
        match self {
            Self::Thin(mach) => vec![mach],
            Self::Fat(fat) => fat.arches.iter().map(|a| &a.mach).collect(),
        }
    }

    /// Returns the first (or only) MachFile. Panics only if a fat binary has
    /// zero arches, which `parse_fat_binary` rejects, so this is safe for all
    /// parsed containers.
    pub fn first_mach(&self) -> &MachFile<'data> {
        match self {
            Self::Thin(mach) => mach,
            Self::Fat(fat) => &fat.arches[0].mach,
        }
    }

    pub fn find_arch(&self, cpu_type: CpuType) -> Option<&MachFile<'data>> {
        match self {
            Self::Thin(mach) => {
                if mach.header().cpu_type == cpu_type {
                    Some(mach)
                } else {
                    None
                }
            }
            Self::Fat(fat) => fat.find_arch(cpu_type).map(|a| &a.mach),
        }
    }
}

impl std::fmt::Debug for MachContainer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Thin(mach) => f.debug_tuple("Thin").field(mach).finish(),
            Self::Fat(fat) => f.debug_tuple("Fat").field(fat).finish(),
        }
    }
}
