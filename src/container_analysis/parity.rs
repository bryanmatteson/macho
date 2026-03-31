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
    let signed: Vec<bool> = slices.iter().map(|s| s.codesign.is_some()).collect();
    if signed.iter().any(|s| *s) && signed.iter().any(|s| !s) {
        let mut per_arch = BTreeMap::new();
        for (s, sig) in slices.iter().zip(signed.iter()) {
            per_arch.insert(
                s.arch.clone(),
                if *sig {
                    "signed".into()
                } else {
                    "unsigned".into()
                },
            );
        }
        divs.push(ParityDivergence {
            domain: ParityDomain::Codesign,
            description: "signing status differs across arches".into(),
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
