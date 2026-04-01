use crate::analysis::container::{
    ContainerReport, FilesetEntryInspection, FilesetMemberReport, FilesetReport,
};
use crate::analysis::diff::DiffReport;
use crate::analysis::snapshot::{ContainerFormat, ContainerSnapshot};
use crate::format::parse;
use crate::model::container::{FatBinary, MachContainer};
use crate::model::load_command::LoadCommand;
use crate::model::mach_file::MachFile;

impl<'data> FatBinary<'data> {
    pub fn snapshot(&self) -> ContainerSnapshot {
        ContainerSnapshot {
            format: ContainerFormat::Fat,
            slices: self
                .arches
                .iter()
                .map(|arch| {
                    let mut snap = crate::analysis::snapshot::SliceSnapshot::from_mach(&arch.mach);
                    snap.arch = arch.spec.name();
                    snap
                })
                .collect(),
        }
    }

    pub fn container_report(&self) -> ContainerReport {
        ContainerReport::from_snapshot(&self.snapshot())
    }

    pub fn parity_report(&self) -> Option<crate::analysis::container::parity::ArchParityReport> {
        self.parity_report_with_domains(crate::analysis::container::parity::all_domains())
    }

    pub fn parity_report_with_domains(
        &self,
        domains: &[crate::analysis::container::parity::ParityDomain],
    ) -> Option<crate::analysis::container::parity::ArchParityReport> {
        if self.snapshot().slices.len() > 1 {
            Some(
                crate::analysis::container::parity::compute_parity_with_domains(
                    &self.snapshot().slices,
                    domains,
                ),
            )
        } else {
            None
        }
    }

    pub fn check_parity(
        &self,
        domains: &[crate::analysis::container::parity::ParityDomain],
    ) -> Option<crate::analysis::container::parity::ArchParityReport> {
        self.parity_report_with_domains(domains)
    }

    pub fn fileset_report(&self) -> Option<FilesetReport> {
        ContainerReport::from_snapshot(&self.snapshot()).fileset
    }

    pub fn resolve_cross_image(&self) -> crate::analysis::container::resolve::CrossImageResolution {
        crate::analysis::container::resolve::resolve_cross_image(&self.snapshot())
    }

    pub fn common_exports(&self) -> Vec<String> {
        crate::analysis::container::resolve::common_exports(&self.snapshot())
    }

    pub fn divergent_exports(&self) -> Vec<crate::analysis::container::resolve::ExportOwnership> {
        crate::analysis::container::resolve::divergent_exports(&self.snapshot())
    }

    pub fn common_imports(&self) -> Vec<String> {
        crate::analysis::container::resolve::common_imports(&self.snapshot())
    }

    pub fn all_signed(&self) -> bool {
        crate::analysis::container::resolve::all_signed(&self.snapshot())
    }

    pub fn diff_slices(&self, old_arch: &str, new_arch: &str) -> Option<DiffReport> {
        crate::analysis::container::resolve::diff_slices(&self.snapshot(), old_arch, new_arch)
    }

    pub fn inspect_fileset_entry(&self, entry_id: &str) -> Vec<FilesetEntryInspection> {
        self.arches
            .iter()
            .flat_map(|arch| {
                let arch_name = arch.spec.name();
                inspect_fileset_entry_in_mach(&arch.mach, &arch_name, entry_id)
            })
            .collect()
    }
}

impl<'data> MachContainer<'data> {
    pub fn snapshot(&self) -> crate::analysis::snapshot::ContainerSnapshot {
        match self {
            Self::Thin(mach) => {
                let format = if mach.header().file_type.name() == "MH_FILESET" {
                    ContainerFormat::Fileset
                } else {
                    ContainerFormat::Thin
                };
                ContainerSnapshot {
                    format,
                    slices: vec![crate::analysis::snapshot::SliceSnapshot::from_mach(mach)],
                }
            }
            Self::Fat(fat) => fat.snapshot(),
        }
    }

    pub fn container_report(&self) -> ContainerReport {
        ContainerReport::from_container(self)
    }

    pub fn parity_report(&self) -> Option<crate::analysis::container::parity::ArchParityReport> {
        self.parity_report_with_domains(crate::analysis::container::parity::all_domains())
    }

    pub fn parity_report_with_domains(
        &self,
        domains: &[crate::analysis::container::parity::ParityDomain],
    ) -> Option<crate::analysis::container::parity::ArchParityReport> {
        match self {
            Self::Thin(_) => None,
            Self::Fat(fat) => fat.parity_report_with_domains(domains),
        }
    }

    pub fn check_parity(
        &self,
        domains: &[crate::analysis::container::parity::ParityDomain],
    ) -> Option<crate::analysis::container::parity::ArchParityReport> {
        self.parity_report_with_domains(domains)
    }

    pub fn fileset_report(&self) -> Option<FilesetReport> {
        self.container_report().fileset
    }

    pub fn resolve_cross_image(&self) -> crate::analysis::container::resolve::CrossImageResolution {
        crate::analysis::container::resolve::resolve_cross_image(&self.snapshot())
    }

    pub fn common_exports(&self) -> Vec<String> {
        crate::analysis::container::resolve::common_exports(&self.snapshot())
    }

    pub fn divergent_exports(&self) -> Vec<crate::analysis::container::resolve::ExportOwnership> {
        crate::analysis::container::resolve::divergent_exports(&self.snapshot())
    }

    pub fn common_imports(&self) -> Vec<String> {
        crate::analysis::container::resolve::common_imports(&self.snapshot())
    }

    pub fn all_signed(&self) -> bool {
        crate::analysis::container::resolve::all_signed(&self.snapshot())
    }

    pub fn diff_slices(&self, old_arch: &str, new_arch: &str) -> Option<DiffReport> {
        crate::analysis::container::resolve::diff_slices(&self.snapshot(), old_arch, new_arch)
    }

    pub fn inspect_fileset_entry(&self, entry_id: &str) -> Vec<FilesetEntryInspection> {
        match self {
            Self::Thin(mach) => {
                let arch = mach.header().cpu_type.name().to_string();
                inspect_fileset_entry_in_mach(mach, &arch, entry_id)
            }
            Self::Fat(fat) => fat.inspect_fileset_entry(entry_id),
        }
    }
}

fn inspect_fileset_entry_in_mach(
    mach: &MachFile<'_>,
    arch: &str,
    entry_id: &str,
) -> Vec<FilesetEntryInspection> {
    let mut inspections = Vec::new();

    for data in mach.load_commands().iter().filter_map(|lc| match &lc.kind {
        LoadCommand::FilesetEntry(data) if data.entry_id == entry_id => Some(data),
        _ => None,
    }) {
        let (member, parse_error) = inspect_fileset_member(mach, data.file_offset);
        inspections.push(FilesetEntryInspection {
            arch: arch.to_string(),
            entry_id: data.entry_id.clone(),
            vm_addr: data.vm_addr,
            file_offset: data.file_offset,
            member,
            parse_error,
        });
    }

    inspections
}

fn inspect_fileset_member(
    mach: &MachFile<'_>,
    file_offset: u64,
) -> (Option<FilesetMemberReport>, Option<String>) {
    let Ok(offset) = usize::try_from(file_offset) else {
        return (
            None,
            Some(format!("member offset {file_offset:#x} is too large")),
        );
    };

    if offset >= mach.bytes().len() {
        return (
            None,
            Some(format!(
                "member offset {file_offset:#x} is outside image bounds ({:#x} bytes)",
                mach.bytes().len()
            )),
        );
    }

    match parse(&mach.bytes()[offset..]) {
        Ok(member) => {
            let member_mach = member.first_mach();
            (
                Some(FilesetMemberReport {
                    file_type: member_mach.header().file_type.name().to_string(),
                    cpu: member_mach.header().cpu_type.to_string(),
                    load_commands: member_mach.load_commands().len(),
                    segments: member_mach.segments().len(),
                }),
                None,
            )
        }
        Err(err) => (None, Some(err.to_string())),
    }
}
