use crate::error::{Error, Result};
use crate::model::addr::{FatFileOffset, ThinFileOffset};
use crate::model::header::{ArchSpec, FatHeader};
use crate::model::header::{CpuSubtype, CpuType};
use crate::model::macho_file::MachoFile;

#[derive(Debug)]
pub struct FatArch<'data> {
    pub spec: ArchSpec,
    pub fat_offset: FatFileOffset,
    pub size: u64,
    pub align: u32,
    pub reserved: u32,
    pub macho: MachoFile<'data>,
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
}

pub enum MachoContainer<'data> {
    Thin(MachoFile<'data>),
    Fat(FatBinary<'data>),
}

impl<'data> MachoContainer<'data> {
    pub fn is_thin(&self) -> bool {
        matches!(self, Self::Thin(_))
    }

    pub fn is_fat(&self) -> bool {
        matches!(self, Self::Fat(_))
    }

    pub fn macho_files(&self) -> Vec<&MachoFile<'data>> {
        match self {
            Self::Thin(macho) => vec![macho],
            Self::Fat(fat) => fat.arches.iter().map(|a| &a.macho).collect(),
        }
    }

    /// Returns the first (or only) MachFile.
    ///
    /// Panics only if a fat binary has zero arches, which `parse_fat_binary` rejects,
    /// so this is safe for parsed containers.
    pub fn first_mach(&self) -> &MachoFile<'data> {
        match self {
            Self::Thin(macho) => macho,
            Self::Fat(fat) => &fat.arches[0].macho,
        }
    }

    pub fn find_arch<'a>(&'a self, cpu_type: CpuType) -> Option<&'a MachoFile<'data>> {
        match self {
            Self::Thin(macho) => {
                if macho.header().cpu_type == cpu_type {
                    Some(macho)
                } else {
                    None
                }
            }
            Self::Fat(fat) => fat.find_arch(cpu_type).map(|a| &a.macho),
        }
    }

    /// Find an arch by CPU type and masked subtype.
    pub fn find_arch_spec<'a>(
        &'a self,
        cpu_type: CpuType,
        cpu_subtype: CpuSubtype,
    ) -> Option<&'a MachoFile<'data>> {
        match self {
            Self::Thin(macho) => {
                if macho.header().cpu_type == cpu_type
                    && macho.header().cpu_subtype.masked() == cpu_subtype.masked()
                {
                    Some(macho)
                } else {
                    None
                }
            }
            Self::Fat(fat) => fat
                .arches
                .iter()
                .find(|a| {
                    a.spec.cpu_type == cpu_type
                        && a.spec.cpu_subtype.masked() == cpu_subtype.masked()
                })
                .map(|a| &a.macho),
        }
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

impl std::fmt::Debug for MachoContainer<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Thin(macho) => f.debug_tuple("Thin").field(macho).finish(),
            Self::Fat(fat) => f.debug_tuple("Fat").field(fat).finish(),
        }
    }
}

impl<'data> FatBinary<'data> {
    pub fn find_arch<'a>(&'a self, cpu_type: CpuType) -> Option<&'a FatArch<'data>> {
        self.arches.iter().find(|a| a.spec.cpu_type == cpu_type)
    }

    pub fn find_arch_spec<'a>(
        &'a self,
        cpu_type: CpuType,
        cpu_subtype: CpuSubtype,
    ) -> Option<&'a FatArch<'data>> {
        self.arches.iter().find(|a| {
            a.spec.cpu_type == cpu_type && a.spec.cpu_subtype.masked() == cpu_subtype.masked()
        })
    }
}
