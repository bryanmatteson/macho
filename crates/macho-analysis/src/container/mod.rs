pub mod ext;
pub mod parity;
pub mod resolve;

use serde::Serialize;

use crate::snapshot::ContainerSnapshot;

#[derive(Debug, Clone, Serialize)]
pub struct ContainerReport {
    pub format: crate::snapshot::ContainerFormat,
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
    pub fn from_container(container: &crate::model::container::MachoContainer<'_>) -> Self {
        Self::from_container_with_domains(container, parity::all_domains())
    }

    pub fn from_container_with_domains(
        container: &crate::model::container::MachoContainer<'_>,
        domains: &[parity::ParityDomain],
    ) -> Self {
        let snapshot = crate::snapshot::ContainerSnapshot::from_container(container);
        Self::from_snapshot_with_domains(&snapshot, domains)
    }

    pub fn from_snapshot(snapshot: &ContainerSnapshot) -> Self {
        Self::from_snapshot_with_domains(snapshot, parity::all_domains())
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
