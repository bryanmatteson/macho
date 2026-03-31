use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use crate::analysis::snapshot::SliceSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ParityDomain {
    Exports,
    Imports,
    Segments,
    Codesign,
    Objc,
}

impl std::fmt::Display for ParityDomain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Exports => write!(f, "exports"),
            Self::Imports => write!(f, "imports"),
            Self::Segments => write!(f, "segments"),
            Self::Codesign => write!(f, "codesign"),
            Self::Objc => write!(f, "objc"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ArchParityReport {
    pub arches: Vec<String>,
    pub domains: Vec<ParityDomain>,
    pub divergences: Vec<ParityDivergence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ParityDivergence {
    pub domain: ParityDomain,
    pub description: String,
    pub per_arch: BTreeMap<String, String>,
}

pub fn compute_parity(slices: &[SliceSnapshot]) -> ArchParityReport {
    compute_parity_with_domains(slices, all_domains())
}

pub fn check_parity(slices: &[SliceSnapshot], domains: &[ParityDomain]) -> ArchParityReport {
    compute_parity_with_domains(slices, domains)
}

pub fn compute_parity_with_domains(
    slices: &[SliceSnapshot],
    domains: &[ParityDomain],
) -> ArchParityReport {
    let arches: Vec<String> = slices.iter().map(|s| s.arch.clone()).collect();
    let domains = normalized_domains(domains);
    let mut divergences = Vec::new();

    for domain in &domains {
        match domain {
            ParityDomain::Exports => check_export_parity(slices, &mut divergences),
            ParityDomain::Imports => check_import_parity(slices, &mut divergences),
            ParityDomain::Segments => check_segment_parity(slices, &mut divergences),
            ParityDomain::Codesign => check_codesign_parity(slices, &mut divergences),
            ParityDomain::Objc => check_objc_class_parity(slices, &mut divergences),
        }
    }

    ArchParityReport {
        arches,
        domains,
        divergences,
    }
}

pub fn all_domains() -> &'static [ParityDomain] {
    &[
        ParityDomain::Exports,
        ParityDomain::Imports,
        ParityDomain::Segments,
        ParityDomain::Codesign,
        ParityDomain::Objc,
    ]
}

fn normalized_domains(domains: &[ParityDomain]) -> Vec<ParityDomain> {
    let mut normalized = if domains.is_empty() {
        all_domains().to_vec()
    } else {
        domains.to_vec()
    };
    normalized.sort();
    normalized.dedup();
    normalized
}

fn check_export_parity(slices: &[SliceSnapshot], divs: &mut Vec<ParityDivergence>) {
    let sets: Vec<BTreeSet<&str>> = slices
        .iter()
        .map(|s| s.exports.iter().map(|e| e.name.as_str()).collect())
        .collect();

    let all: BTreeSet<&str> = sets.iter().flat_map(|s| s.iter().copied()).collect();

    for name in &all {
        let present_in: Vec<&str> = slices
            .iter()
            .zip(sets.iter())
            .filter(|(_, set)| set.contains(name))
            .map(|(s, _)| s.arch.as_str())
            .collect();

        if present_in.len() != slices.len() {
            let mut per_arch = BTreeMap::new();
            for (s, set) in slices.iter().zip(sets.iter()) {
                per_arch.insert(
                    s.arch.clone(),
                    if set.contains(name) {
                        "present".into()
                    } else {
                        "absent".into()
                    },
                );
            }
            divs.push(ParityDivergence {
                domain: ParityDomain::Exports,
                description: format!("export {name} not present in all arches"),
                per_arch,
            });
        }
    }

    for name in &all {
        let per_arch: BTreeMap<String, String> = slices
            .iter()
            .filter_map(|slice| {
                slice
                    .exports
                    .iter()
                    .find(|export| export.name == *name)
                    .map(|export| (slice.arch.clone(), describe_export(export)))
            })
            .collect();

        if per_arch.len() < 2 {
            continue;
        }

        let variants: BTreeSet<&str> = per_arch.values().map(|value| value.as_str()).collect();
        if variants.len() > 1 {
            divs.push(ParityDivergence {
                domain: ParityDomain::Exports,
                description: format!("export {name} differs across arches"),
                per_arch,
            });
        }
    }
}

fn check_import_parity(slices: &[SliceSnapshot], divs: &mut Vec<ParityDivergence>) {
    let sets: Vec<BTreeSet<&str>> = slices
        .iter()
        .map(|s| s.imports.iter().map(|i| i.name.as_str()).collect())
        .collect();

    let all: BTreeSet<&str> = sets.iter().flat_map(|s| s.iter().copied()).collect();

    for name in &all {
        let present_in: Vec<&str> = slices
            .iter()
            .zip(sets.iter())
            .filter(|(_, set)| set.contains(name))
            .map(|(s, _)| s.arch.as_str())
            .collect();

        if present_in.len() != slices.len() {
            let mut per_arch = BTreeMap::new();
            for (s, set) in slices.iter().zip(sets.iter()) {
                per_arch.insert(
                    s.arch.clone(),
                    if set.contains(name) {
                        "present".into()
                    } else {
                        "absent".into()
                    },
                );
            }
            divs.push(ParityDivergence {
                domain: ParityDomain::Imports,
                description: format!("import {name} not present in all arches"),
                per_arch,
            });
        }
    }

    for name in &all {
        let per_arch: BTreeMap<String, String> = slices
            .iter()
            .filter_map(|slice| {
                let variants: Vec<String> = slice
                    .imports
                    .iter()
                    .filter(|import| import.name == *name)
                    .map(describe_import)
                    .collect();
                (!variants.is_empty()).then(|| (slice.arch.clone(), variants.join(", ")))
            })
            .collect();

        if per_arch.len() < 2 {
            continue;
        }

        let variants: BTreeSet<&str> = per_arch.values().map(|value| value.as_str()).collect();
        if variants.len() > 1 {
            divs.push(ParityDivergence {
                domain: ParityDomain::Imports,
                description: format!("import {name} differs across arches"),
                per_arch,
            });
        }
    }
}

fn check_segment_parity(slices: &[SliceSnapshot], divs: &mut Vec<ParityDivergence>) {
    let sets: Vec<BTreeSet<&str>> = slices
        .iter()
        .map(|s| s.segments.iter().map(|seg| seg.name.as_str()).collect())
        .collect();

    let all: BTreeSet<&str> = sets.iter().flat_map(|s| s.iter().copied()).collect();

    for name in &all {
        let present: Vec<bool> = sets.iter().map(|s| s.contains(name)).collect();
        if present.iter().any(|p| !p) {
            let mut per_arch = BTreeMap::new();
            for (s, p) in slices.iter().zip(present.iter()) {
                per_arch.insert(
                    s.arch.clone(),
                    if *p {
                        "present".into()
                    } else {
                        "absent".into()
                    },
                );
            }
            divs.push(ParityDivergence {
                domain: ParityDomain::Segments,
                description: format!("segment {name} not present in all arches"),
                per_arch,
            });
        }
    }

    // Check protection parity for shared segments
    for name in &all {
        let prots: Vec<Option<(&str, &str)>> = slices
            .iter()
            .map(|s| {
                s.segments
                    .iter()
                    .find(|seg| seg.name == *name)
                    .map(|seg| (seg.init_prot.as_str(), seg.max_prot.as_str()))
            })
            .collect();

        let first = prots.iter().flatten().next();
        if let Some(first_prot) = first {
            if prots
                .iter()
                .any(|p| matches!(p, Some(v) if v != first_prot))
            {
                let mut per_arch = BTreeMap::new();
                for (s, p) in slices.iter().zip(prots.iter()) {
                    if let Some((init, max)) = p {
                        per_arch.insert(s.arch.clone(), format!("init={init} max={max}"));
                    }
                }
                divs.push(ParityDivergence {
                    domain: ParityDomain::Segments,
                    description: format!("segment {name} has different protections across arches"),
                    per_arch,
                });
            }
        }
    }
}

fn check_codesign_parity(slices: &[SliceSnapshot], divs: &mut Vec<ParityDivergence>) {
    push_codesign_divergence(
        slices,
        divs,
        "signing status differs across arches",
        |slice| {
            if slice.codesign.is_some() {
                "signed".to_string()
            } else {
                "unsigned".to_string()
            }
        },
    );
    push_codesign_divergence(
        slices,
        divs,
        "code signature identifier differs across arches",
        |slice| {
            slice
                .codesign
                .as_ref()
                .and_then(|cs| cs.identifier.clone())
                .unwrap_or_else(|| "none".to_string())
        },
    );
    push_codesign_divergence(
        slices,
        divs,
        "code signature team ID differs across arches",
        |slice| {
            slice
                .codesign
                .as_ref()
                .and_then(|cs| cs.team_id.clone())
                .unwrap_or_else(|| "none".to_string())
        },
    );
    push_codesign_divergence(
        slices,
        divs,
        "code signature hash type differs across arches",
        |slice| {
            slice
                .codesign
                .as_ref()
                .map(|cs| cs.hash_type.clone())
                .unwrap_or_else(|| "none".to_string())
        },
    );
    push_codesign_divergence(
        slices,
        divs,
        "entitlement keys differ across arches",
        |slice| {
            slice
                .codesign
                .as_ref()
                .map(|cs| {
                    if cs.entitlement_keys.is_empty() {
                        "none".to_string()
                    } else {
                        cs.entitlement_keys.join(", ")
                    }
                })
                .unwrap_or_else(|| "none".to_string())
        },
    );
    push_codesign_divergence(
        slices,
        divs,
        "DER entitlements fingerprint differs across arches",
        |slice| {
            slice
                .codesign
                .as_ref()
                .and_then(|cs| cs.entitlements_der_fingerprint.clone())
                .unwrap_or_else(|| "none".to_string())
        },
    );
}

fn push_codesign_divergence<F>(
    slices: &[SliceSnapshot],
    divs: &mut Vec<ParityDivergence>,
    description: &str,
    mut value_for: F,
) where
    F: FnMut(&SliceSnapshot) -> String,
{
    let per_arch: BTreeMap<String, String> = slices
        .iter()
        .map(|slice| (slice.arch.clone(), value_for(slice)))
        .collect();
    let unique: BTreeSet<&str> = per_arch.values().map(String::as_str).collect();
    if unique.len() > 1 {
        divs.push(ParityDivergence {
            domain: ParityDomain::Codesign,
            description: description.into(),
            per_arch,
        });
    }
}

fn check_objc_class_parity(slices: &[SliceSnapshot], divs: &mut Vec<ParityDivergence>) {
    let sets: Vec<BTreeSet<&str>> = slices
        .iter()
        .map(|s| s.objc.classes.iter().map(|c| c.name.as_str()).collect())
        .collect();

    let all: BTreeSet<&str> = sets.iter().flat_map(|s| s.iter().copied()).collect();

    for name in &all {
        let present: Vec<bool> = sets.iter().map(|s| s.contains(name)).collect();
        if present.iter().any(|p| !p) {
            let mut per_arch = BTreeMap::new();
            for (s, p) in slices.iter().zip(present.iter()) {
                per_arch.insert(
                    s.arch.clone(),
                    if *p {
                        "present".into()
                    } else {
                        "absent".into()
                    },
                );
            }
            divs.push(ParityDivergence {
                domain: ParityDomain::Objc,
                description: format!("ObjC class {name} not present in all arches"),
                per_arch,
            });
        }
    }
}

fn describe_export(export: &crate::analysis::snapshot::ExportSnapshot) -> String {
    let kind = match &export.kind {
        crate::analysis::snapshot::ExportKindSnapshot::Regular { address } => {
            format!("regular@{address:#x}")
        }
        crate::analysis::snapshot::ExportKindSnapshot::ThreadLocal { address } => {
            format!("thread_local@{address:#x}")
        }
        crate::analysis::snapshot::ExportKindSnapshot::Absolute { address } => {
            format!("absolute@{address:#x}")
        }
        crate::analysis::snapshot::ExportKindSnapshot::Reexport { ordinal, name } => format!(
            "reexport ordinal={ordinal} name={}",
            name.as_deref().unwrap_or("<none>")
        ),
        crate::analysis::snapshot::ExportKindSnapshot::StubAndResolver {
            stub_offset,
            resolver_offset,
        } => format!("stub={stub_offset:#x} resolver={resolver_offset:#x}"),
    };
    format!("{kind} weak={}", export.weak)
}

fn describe_import(import: &crate::analysis::snapshot::ImportSnapshot) -> String {
    format!("ordinal={} weak={}", import.lib_ordinal, import.weak)
}
