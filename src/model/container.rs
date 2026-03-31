use crate::addr::{FatFileOffset, ThinFileOffset};
use crate::analysis::snapshot::{ContainerFormat, ContainerSnapshot, SliceSnapshot};
use crate::container_analysis::parity;
use crate::container_analysis::resolve;
use crate::container_analysis::{ContainerReport, FilesetReport};
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

    pub fn snapshot(&self) -> ContainerSnapshot {
        ContainerSnapshot {
            format: ContainerFormat::Fat,
            slices: self
                .arches
                .iter()
                .map(|arch| {
                    let mut snap = SliceSnapshot::from_mach(&arch.mach);
                    snap.arch = arch.spec.name();
                    snap
                })
                .collect(),
        }
    }

    pub fn container_report(&self) -> ContainerReport {
        ContainerReport::from_snapshot(&self.snapshot())
    }

    pub fn parity_report(&self) -> Option<parity::ArchParityReport> {
        let snapshot = self.snapshot();
        if snapshot.slices.len() > 1 {
            Some(parity::compute_parity(&snapshot.slices))
        } else {
            None
        }
    }

    pub fn fileset_report(&self) -> Option<FilesetReport> {
        self.container_report().fileset
    }

    pub fn resolve_cross_image(&self) -> resolve::CrossImageResolution {
        resolve::resolve_cross_image(&self.snapshot())
    }

    pub fn common_exports(&self) -> Vec<String> {
        resolve::common_exports(&self.snapshot())
    }

    pub fn divergent_exports(&self) -> Vec<resolve::ExportOwnership> {
        resolve::divergent_exports(&self.snapshot())
    }

    pub fn common_imports(&self) -> Vec<String> {
        resolve::common_imports(&self.snapshot())
    }

    pub fn all_signed(&self) -> bool {
        resolve::all_signed(&self.snapshot())
    }

    pub fn diff_slices(&self, old_arch: &str, new_arch: &str) -> Option<crate::diff::DiffReport> {
        resolve::diff_slices(&self.snapshot(), old_arch, new_arch)
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

    pub fn snapshot(&self) -> ContainerSnapshot {
        match self {
            Self::Thin(_) => ContainerSnapshot::from_container(self),
            Self::Fat(fat) => fat.snapshot(),
        }
    }

    pub fn container_report(&self) -> ContainerReport {
        ContainerReport::from_container(self)
    }

    pub fn parity_report(&self) -> Option<parity::ArchParityReport> {
        match self {
            Self::Thin(_) => None,
            Self::Fat(fat) => fat.parity_report(),
        }
    }

    pub fn fileset_report(&self) -> Option<FilesetReport> {
        self.container_report().fileset
    }

    pub fn resolve_cross_image(&self) -> resolve::CrossImageResolution {
        resolve::resolve_cross_image(&self.snapshot())
    }

    pub fn common_exports(&self) -> Vec<String> {
        resolve::common_exports(&self.snapshot())
    }

    pub fn divergent_exports(&self) -> Vec<resolve::ExportOwnership> {
        resolve::divergent_exports(&self.snapshot())
    }

    pub fn common_imports(&self) -> Vec<String> {
        resolve::common_imports(&self.snapshot())
    }

    pub fn all_signed(&self) -> bool {
        resolve::all_signed(&self.snapshot())
    }

    pub fn diff_slices(&self, old_arch: &str, new_arch: &str) -> Option<crate::diff::DiffReport> {
        resolve::diff_slices(&self.snapshot(), old_arch, new_arch)
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
