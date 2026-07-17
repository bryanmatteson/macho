//! Schema-v2 document comparison.

use std::collections::{BTreeMap, BTreeSet};

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::{AnalysisDomain, AnalysisIssue, DomainPayload, DomainState, SnapshotDocument};

use super::*;

/// Compare only the selected schema-v2 domains.
pub fn diff_documents(
    old: &SnapshotDocument,
    new: &SnapshotDocument,
    selected: &BTreeSet<AnalysisDomain>,
) -> DiffReport {
    let mut findings = Vec::new();
    diff_container_identity(&old.container, &new.container, &mut findings);

    let old_slices = old
        .slices
        .iter()
        .map(|slice| (slice.identity.arch.as_str(), slice))
        .collect::<BTreeMap<_, _>>();
    let new_slices = new
        .slices
        .iter()
        .map(|slice| (slice.identity.arch.as_str(), slice))
        .collect::<BTreeMap<_, _>>();

    for arch in old_slices
        .keys()
        .chain(new_slices.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        let Some(old_slice) = old_slices.get(arch) else {
            findings.push(slice_presence(arch, "added", ChangeSeverity::Info));
            continue;
        };
        let Some(new_slice) = new_slices.get(arch) else {
            findings.push(slice_presence(arch, "removed", ChangeSeverity::Breaking));
            continue;
        };

        for domain in selected {
            let old_state = &old_slice.domains[domain];
            let new_state = &new_slice.domains[domain];
            if old_state == new_state {
                continue;
            }
            let arch = Some(arch.to_owned());
            match (old_state, new_state) {
                (
                    DomainState::Complete {
                        value: old_value,
                        issues: old_issues,
                    },
                    DomainState::Complete {
                        value: new_value,
                        issues: new_issues,
                    },
                ) => {
                    let before = findings.len();
                    if let Err(error) =
                        diff_complete_values(*domain, old_value, new_value, &arch, &mut findings)
                    {
                        findings.push(DiffFinding {
                            domain: DiffDomain::Analysis,
                            severity: ChangeSeverity::Warning,
                            arch: arch.clone(),
                            message: format!(
                                "could not compare {} payloads: {error}",
                                domain.as_str()
                            ),
                        });
                    }
                    diff_issues(*domain, old_issues, new_issues, &arch, &mut findings);
                    if findings.len() == before {
                        findings.push(DiffFinding {
                            domain: report_domain(*domain),
                            severity: ChangeSeverity::Warning,
                            arch,
                            message: format!("{} analysis changed", domain.as_str()),
                        });
                    }
                }
                _ => findings.push(DiffFinding {
                    domain: report_domain(*domain),
                    severity: state_change_severity(old_state, new_state),
                    arch,
                    message: format!(
                        "{} state changed: {} -> {}",
                        domain.as_str(),
                        state_name(old_state),
                        state_name(new_state)
                    ),
                }),
            }
        }
    }

    DiffReport { findings }
}

fn diff_complete_values(
    domain: AnalysisDomain,
    old: &DomainPayload,
    new: &DomainPayload,
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) -> Result<(), serde_json::Error> {
    let old = payload_value(old);
    let new = payload_value(new);
    match domain {
        AnalysisDomain::Header => diff_headers(&decode(old)?, &decode(new)?, arch, findings),
        AnalysisDomain::LoadCommands => diff_load_commands(
            &decode::<Vec<LoadCommandSnapshot>>(old)?,
            &decode::<Vec<LoadCommandSnapshot>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Segments => diff_segments(
            &decode::<Vec<SegmentSnapshot>>(old)?,
            &decode::<Vec<SegmentSnapshot>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Symbols => diff_symbols(
            &decode::<Vec<SymbolSnapshot>>(old)?,
            &decode::<Vec<SymbolSnapshot>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Exports => diff_exports(
            &decode::<Vec<ExportSnapshot>>(old)?,
            &decode::<Vec<ExportSnapshot>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Imports => diff_imports(
            &decode::<Vec<ImportRecord>>(old)?,
            &decode::<Vec<ImportRecord>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Fixups => diff_fixups(
            &decode::<Vec<FixupSnapshot>>(old)?,
            &decode::<Vec<FixupSnapshot>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Objc => diff_objc(&decode(old)?, &decode(new)?, arch, findings),
        AnalysisDomain::Codesign => {
            let old: Option<CodesignSnapshot> = decode(old)?;
            let new: Option<CodesignSnapshot> = decode(new)?;
            diff_codesign(old.as_ref(), new.as_ref(), arch, findings);
        }
        _ => {}
    }
    Ok(())
}

fn decode<T: DeserializeOwned>(value: &Value) -> Result<T, serde_json::Error> {
    serde_json::from_value(value.clone())
}

fn payload_value(payload: &DomainPayload) -> &Value {
    match payload {
        DomainPayload::Container(value)
        | DomainPayload::Header(value)
        | DomainPayload::LoadCommands(value)
        | DomainPayload::Segments(value)
        | DomainPayload::Relocations(value)
        | DomainPayload::Symbols(value)
        | DomainPayload::Exports(value)
        | DomainPayload::Imports(value)
        | DomainPayload::Fixups(value)
        | DomainPayload::Codesign(value)
        | DomainPayload::Objc(value)
        | DomainPayload::Swift(value)
        | DomainPayload::Dwarf(value)
        | DomainPayload::Vtables(value)
        | DomainPayload::Strings(value)
        | DomainPayload::Ranges(value)
        | DomainPayload::Xrefs(value)
        | DomainPayload::Dependencies(value)
        | DomainPayload::Audit(value)
        | DomainPayload::CHeaders(value)
        | DomainPayload::CppHeaders(value)
        | DomainPayload::ObjcHeaders(value) => value,
    }
}

fn diff_issues(
    domain: AnalysisDomain,
    old: &[AnalysisIssue],
    new: &[AnalysisIssue],
    arch: &Option<String>,
    findings: &mut Vec<DiffFinding>,
) {
    let old = old
        .iter()
        .map(|issue| (&issue.code, &issue.message))
        .collect::<BTreeSet<_>>();
    let new = new
        .iter()
        .map(|issue| (&issue.code, &issue.message))
        .collect::<BTreeSet<_>>();
    for (code, message) in new.difference(&old) {
        findings.push(DiffFinding {
            domain: DiffDomain::Analysis,
            severity: ChangeSeverity::Warning,
            arch: arch.clone(),
            message: format!("new {} issue {code}: {message}", domain.as_str()),
        });
    }
    for (code, message) in old.difference(&new) {
        findings.push(DiffFinding {
            domain: DiffDomain::Analysis,
            severity: ChangeSeverity::Info,
            arch: arch.clone(),
            message: format!("resolved {} issue {code}: {message}", domain.as_str()),
        });
    }
}

fn slice_presence(arch: &str, change: &str, severity: ChangeSeverity) -> DiffFinding {
    DiffFinding {
        domain: DiffDomain::Container,
        severity,
        arch: Some(arch.to_owned()),
        message: format!("architecture slice {change}"),
    }
}

fn state_change_severity<T>(old: &DomainState<T>, new: &DomainState<T>) -> ChangeSeverity {
    if matches!(old, DomainState::Complete { .. }) && matches!(new, DomainState::Complete { .. }) {
        ChangeSeverity::Warning
    } else {
        ChangeSeverity::Breaking
    }
}

fn state_name<T>(state: &DomainState<T>) -> &'static str {
    match state {
        DomainState::NotRequested => "not_requested",
        DomainState::Complete { .. } => "complete",
        DomainState::Unsupported { .. } => "unsupported",
        DomainState::Failed { .. } => "failed",
    }
}

fn report_domain(domain: AnalysisDomain) -> DiffDomain {
    match domain {
        AnalysisDomain::Container => DiffDomain::Container,
        AnalysisDomain::Header => DiffDomain::Header,
        AnalysisDomain::LoadCommands => DiffDomain::LoadCommands,
        AnalysisDomain::Segments => DiffDomain::Segments,
        AnalysisDomain::Symbols => DiffDomain::Symbols,
        AnalysisDomain::Exports => DiffDomain::Exports,
        AnalysisDomain::Imports => DiffDomain::Imports,
        AnalysisDomain::Fixups => DiffDomain::Fixups,
        AnalysisDomain::Codesign => DiffDomain::Codesign,
        AnalysisDomain::Objc => DiffDomain::ObjC,
        _ => DiffDomain::Analysis,
    }
}
