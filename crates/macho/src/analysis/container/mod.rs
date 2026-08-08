/// The ext module.
pub mod ext;

use serde::Serialize;
use std::collections::BTreeMap;

use crate::analysis::{AnalysisDomain, DomainState, SnapshotDocument};

/// Selective schema-v1 container report.
#[derive(Debug, Clone, Serialize)]
pub struct ContainerDocumentReport {
    /// The format field.
    pub format: String,
    /// The arches field.
    pub arches: Vec<String>,
    /// The parity field.
    pub parity: DocumentParityReport,
    /// The fileset field.
    pub fileset: Option<FilesetReport>,
    /// The resolution_inputs field.
    pub resolution_inputs: Option<BTreeMap<String, BTreeMap<AnalysisDomain, serde_json::Value>>>,
}

/// Selected domains and only their actual divergences.
#[derive(Debug, Clone, Serialize)]
pub struct DocumentParityReport {
    /// The domains field.
    pub domains: Vec<AnalysisDomain>,
    /// The divergences field.
    pub divergences: Vec<DomainParity>,
}

/// Per-domain parity state computed only from selected domain results.
#[derive(Debug, Clone, Serialize)]
pub struct DomainParity {
    /// The domain field.
    pub domain: AnalysisDomain,
    /// The equal field.
    pub equal: bool,
    /// The per_arch field.
    pub per_arch: BTreeMap<String, serde_json::Value>,
}

impl ContainerDocumentReport {
    /// Performs from_document.
    pub fn from_document(
        document: &SnapshotDocument,
        domains: &[AnalysisDomain],
        include_resolution_inputs: bool,
    ) -> Self {
        let mut parity = Vec::new();
        for domain in domains {
            let per_arch = document
                .slices
                .iter()
                .map(|slice| {
                    (
                        slice.identity.arch.clone(),
                        serde_json::to_value(&slice.domains[domain])
                            .expect("domain state is serializable"),
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let mut values = per_arch.values();
            let first = values.next();
            let equal = first.is_none_or(|first| values.all(|value| value == first));
            parity.push(DomainParity {
                domain: *domain,
                equal,
                per_arch,
            });
        }
        let divergences = parity
            .iter()
            .filter(|domain| !domain.equal)
            .cloned()
            .collect();
        let fileset = fileset_from_document(document);
        let resolution_inputs = include_resolution_inputs.then(|| {
            document
                .slices
                .iter()
                .map(|slice| {
                    let values = [AnalysisDomain::Imports, AnalysisDomain::Exports]
                        .into_iter()
                        .filter_map(|domain| match &slice.domains[&domain] {
                            DomainState::NotRequested => None,
                            state => Some((
                                domain,
                                serde_json::to_value(state).expect("domain state is serializable"),
                            )),
                        })
                        .collect();
                    (slice.identity.arch.clone(), values)
                })
                .collect()
        });
        Self {
            format: if fileset.is_some() {
                "Fileset".to_owned()
            } else {
                document.container.format.clone()
            },
            arches: document
                .slices
                .iter()
                .map(|slice| slice.identity.arch.clone())
                .collect(),
            parity: DocumentParityReport {
                domains: domains.to_vec(),
                divergences,
            },
            fileset,
            resolution_inputs,
        }
    }
}

fn fileset_from_document(document: &SnapshotDocument) -> Option<FilesetReport> {
    let mut entries = Vec::new();
    for slice in &document.slices {
        let DomainState::Complete {
            value: crate::analysis::DomainPayload::LoadCommands(value),
            ..
        } = &slice.domains[&AnalysisDomain::LoadCommands]
        else {
            continue;
        };
        let Some(commands) = value.as_array() else {
            continue;
        };
        for command in commands {
            let Some(entry) = command
                .get("fileset_entry")
                .filter(|entry| !entry.is_null())
            else {
                continue;
            };
            entries.push(FilesetEntry {
                arch: slice.identity.arch.clone(),
                entry_id: entry["entry_id"].as_str().unwrap_or_default().to_owned(),
                vm_addr: entry["vm_addr"].as_u64().unwrap_or_default(),
                file_offset: entry["file_offset"].as_u64().unwrap_or_default(),
            });
        }
    }
    (!entries.is_empty()).then_some(FilesetReport { entries })
}

#[derive(Debug, Clone, Serialize)]
/// The FilesetReport type.
pub struct FilesetReport {
    /// The entries field.
    pub entries: Vec<FilesetEntry>,
}

#[derive(Debug, Clone, Serialize)]
/// The FilesetEntry type.
pub struct FilesetEntry {
    /// The arch field.
    pub arch: String,
    /// The entry_id field.
    pub entry_id: String,
    /// The vm_addr field.
    pub vm_addr: u64,
    /// The file_offset field.
    pub file_offset: u64,
}

#[derive(Debug, Clone, Serialize)]
/// The FilesetMemberReport type.
pub struct FilesetMemberReport {
    /// The file_type field.
    pub file_type: String,
    /// The cpu field.
    pub cpu: String,
    /// The load_commands field.
    pub load_commands: usize,
    /// The segments field.
    pub segments: usize,
}

#[derive(Debug, Clone, Serialize)]
/// The FilesetEntryInspection type.
pub struct FilesetEntryInspection {
    /// The arch field.
    pub arch: String,
    /// The entry_id field.
    pub entry_id: String,
    /// The vm_addr field.
    pub vm_addr: u64,
    /// The file_offset field.
    pub file_offset: u64,
    /// The member field.
    pub member: Option<FilesetMemberReport>,
    /// The parse_error field.
    pub parse_error: Option<String>,
}
