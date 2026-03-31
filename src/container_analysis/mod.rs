pub mod parity;
pub mod resolve;

use serde::Serialize;

use crate::analysis::snapshot::ContainerSnapshot;

#[derive(Debug, Clone, Serialize)]
pub struct ContainerReport {
    pub format: String,
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

impl ContainerReport {
    pub fn from_snapshot(snap: &ContainerSnapshot) -> Self {
        let arches: Vec<String> = snap.slices.iter().map(|s| s.arch.clone()).collect();

        let parity = if snap.slices.len() > 1 {
            Some(parity::compute_parity(&snap.slices))
        } else {
            None
        };

        let fileset = extract_fileset(snap);

        Self {
            format: snap.format.to_string(),
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
