pub mod parity;
pub mod resolve;

use serde::Serialize;

use crate::analysis::snapshot::{ContainerFormat, ContainerSnapshot};
use crate::model::container::MachContainer;
use crate::model::load_command::LoadCommand;

#[derive(Debug, Clone, Serialize)]
pub struct ContainerReport {
    pub format: ContainerFormat,
    pub arches: Vec<String>,
    pub parity: Option<parity::ArchParityReport>,
    pub fileset: Option<FilesetReport>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesetReport {
    pub entries: Vec<FilesetEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesetEntry {
    pub arch: String,
    pub entry_id: String,
    pub vm_addr: u64,
    pub file_offset: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesetMemberReport {
    pub file_type: String,
    pub cpu: String,
    pub load_commands: usize,
    pub segments: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FilesetEntryInspection {
    pub arch: String,
    pub entry_id: String,
    pub vm_addr: u64,
    pub file_offset: u64,
    pub member: Option<FilesetMemberReport>,
    pub parse_error: Option<String>,
}

impl ContainerReport {
    pub fn from_container(container: &MachContainer<'_>) -> Self {
        Self::from_container_with_domains(container, parity::all_domains())
    }

    pub fn from_container_with_domains(
        container: &MachContainer<'_>,
        domains: &[parity::ParityDomain],
    ) -> Self {
        let snapshot = ContainerSnapshot::from_container(container);
        Self::from_snapshot_with_domains(&snapshot, domains)
    }

    pub fn from_snapshot(snap: &ContainerSnapshot) -> Self {
        Self::from_snapshot_with_domains(snap, parity::all_domains())
    }

    pub fn from_snapshot_with_domains(
        snap: &ContainerSnapshot,
        domains: &[parity::ParityDomain],
    ) -> Self {
        let arches: Vec<String> = snap.slices.iter().map(|s| s.arch.clone()).collect();

        let parity = if snap.slices.len() > 1 {
            Some(parity::compute_parity_with_domains(&snap.slices, domains))
        } else {
            None
        };

        let fileset = extract_fileset(snap);

        Self {
            format: snap.format,
            arches,
            parity,
            fileset,
        }
    }
}

pub fn inspect_fileset_entry(
    container: &MachContainer<'_>,
    entry_id: &str,
) -> Vec<FilesetEntryInspection> {
    match container {
        MachContainer::Thin(mach) => {
            let arch = mach.header().cpu_type.name().to_string();
            inspect_fileset_entry_in_mach(mach, &arch, entry_id)
        }
        MachContainer::Fat(fat) => fat
            .arches()
            .iter()
            .flat_map(|arch| {
                let arch_name = arch.spec.name();
                inspect_fileset_entry_in_mach(&arch.mach, &arch_name, entry_id)
            })
            .collect(),
    }
}

fn extract_fileset(snap: &ContainerSnapshot) -> Option<FilesetReport> {
    let mut entries = Vec::new();

    for slice in &snap.slices {
        if slice.header.file_type != "MH_FILESET" {
            continue;
        }

        entries.extend(
            slice
                .load_commands
                .iter()
                .filter_map(|lc| lc.fileset_entry.as_ref())
                .map(|entry| FilesetEntry {
                    arch: slice.arch.clone(),
                    entry_id: entry.entry_id.clone(),
                    vm_addr: entry.vm_addr,
                    file_offset: entry.file_offset,
                }),
        );
    }

    if entries.is_empty() {
        None
    } else {
        Some(FilesetReport { entries })
    }
}

pub(crate) fn inspect_fileset_entry_in_mach(
    mach: &crate::model::mach::MachFile<'_>,
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
    mach: &crate::model::mach::MachFile<'_>,
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

    match crate::parse::parse(&mach.bytes()[offset..]) {
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
