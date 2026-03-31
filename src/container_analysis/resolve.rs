use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::analysis::snapshot::ContainerSnapshot;

#[derive(Debug, Clone, Serialize)]
pub struct CrossImageResolution {
    pub export_ownership: Vec<ExportOwnership>,
    pub import_divergence: Vec<ImportDivergence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExportOwnership {
    pub symbol: String,
    pub arches: Vec<String>,
}

/// An import that is present in some arches but not all.
#[derive(Debug, Clone, Serialize)]
pub struct ImportDivergence {
    pub symbol: String,
    pub present_in: Vec<String>,
    pub absent_from: Vec<String>,
}

pub fn resolve_cross_image(snap: &ContainerSnapshot) -> CrossImageResolution {
    let all_arch_names: Vec<&str> = snap.slices.iter().map(|s| s.arch.as_str()).collect();
    let total_arches = snap.slices.len();

    let mut export_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut import_map: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for slice in &snap.slices {
        for export in &slice.exports {
            export_map
                .entry(export.name.clone())
                .or_default()
                .insert(slice.arch.clone());
        }
        for import in &slice.imports {
            import_map
                .entry(import.name.clone())
                .or_default()
                .insert(slice.arch.clone());
        }
    }

    // Exports present in some but not all arches
    let export_ownership: Vec<ExportOwnership> = export_map
        .into_iter()
        .filter(|(_, arches)| arches.len() < total_arches)
        .map(|(symbol, arches)| ExportOwnership {
            symbol,
            arches: arches.into_iter().collect(),
        })
        .collect();

    // Imports divergent across arches (present in some but not all)
    let import_divergence: Vec<ImportDivergence> = import_map
        .into_iter()
        .filter(|(_, arches)| arches.len() < total_arches)
        .map(|(symbol, present)| {
            let absent: Vec<String> = all_arch_names
                .iter()
                .filter(|a| !present.contains(**a))
                .map(|a| a.to_string())
                .collect();
            ImportDivergence {
                symbol,
                present_in: present.into_iter().collect(),
                absent_from: absent,
            }
        })
        .collect();

    CrossImageResolution {
        export_ownership,
        import_divergence,
    }
}
