use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::diff::DiffReport;
use crate::diff::diff_slice_snapshots;
use crate::snapshot::ContainerSnapshot;
use crate::snapshot::ExportSnapshot;
use crate::snapshot::SliceSnapshot;
use crate::symbols::imports::ImportRecord;

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

pub fn slice_by_arch<'a>(snap: &'a ContainerSnapshot, arch: &str) -> Option<&'a SliceSnapshot> {
    snap.slices
        .iter()
        .find(|slice| slice.arch.eq_ignore_ascii_case(arch))
}

pub fn common_exports(snap: &ContainerSnapshot) -> Vec<String> {
    common_export_names(snap)
}

pub fn common_imports(snap: &ContainerSnapshot) -> Vec<String> {
    common_import_names(snap)
}

pub fn divergent_exports(snap: &ContainerSnapshot) -> Vec<ExportOwnership> {
    resolve_cross_image(snap).export_ownership
}

pub fn all_signed(snap: &ContainerSnapshot) -> bool {
    snap.slices.iter().all(|slice| slice.codesign.is_some())
}

pub fn diff_slices(snap: &ContainerSnapshot, old_arch: &str, new_arch: &str) -> Option<DiffReport> {
    let old = slice_by_arch(snap, old_arch)?;
    let new = slice_by_arch(snap, new_arch)?;

    Some(diff_slice_snapshots(old, new))
}

fn common_export_names(snap: &ContainerSnapshot) -> Vec<String> {
    let mut iter = snap.slices.iter();
    let Some(first) = iter.next() else {
        return Vec::new();
    };

    let mut common: BTreeSet<ExportSnapshot> = first.exports.iter().cloned().collect();
    for slice in iter {
        let exports: BTreeSet<ExportSnapshot> = slice.exports.iter().cloned().collect();
        common = common.intersection(&exports).cloned().collect();
    }

    common.into_iter().map(|export| export.name).collect()
}

fn common_import_names(snap: &ContainerSnapshot) -> Vec<String> {
    let mut iter = snap.slices.iter();
    let Some(first) = iter.next() else {
        return Vec::new();
    };

    let mut common: BTreeSet<ImportRecord> = first.imports.iter().cloned().collect();
    for slice in iter {
        let imports: BTreeSet<ImportRecord> = slice.imports.iter().cloned().collect();
        common = common.intersection(&imports).cloned().collect();
    }

    common.into_iter().map(|import| import.name).collect()
}
