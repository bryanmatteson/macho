//! Schema-v3 document comparison.

use std::collections::{BTreeMap, BTreeSet};

use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::analysis::{
    AnalysisDomain, AnalysisIssue, DomainPayload, DomainState, SnapshotDocument,
};

use super::*;

/// Compare only the selected schema-v3 domains.
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
                    let handled = match diff_complete_values(
                        *domain,
                        old_value,
                        new_value,
                        &arch,
                        &mut findings,
                    ) {
                        Ok(handled) => handled,
                        Err(error) => {
                            findings.push(DiffFinding {
                                domain: DiffDomain::Analysis,
                                severity: ChangeSeverity::Warning,
                                arch: arch.clone(),
                                message: format!(
                                    "could not compare {} payloads: {error}",
                                    domain.as_str()
                                ),
                            });
                            true
                        }
                    };
                    diff_issues(*domain, old_issues, new_issues, &arch, &mut findings);
                    if !handled && findings.len() == before {
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
                        "{} evidence state changed: {} -> {}",
                        domain.as_str(),
                        state_description(old_state),
                        state_description(new_state)
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
) -> Result<bool, serde_json::Error> {
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
        AnalysisDomain::Relocations => diff_relocations(
            &decode::<Vec<RelocationSectionSnapshot>>(old)?,
            &decode::<Vec<RelocationSectionSnapshot>>(new)?,
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
        AnalysisDomain::Objc => {
            diff_objc_payload(old, new, arch, findings)?;
        }
        AnalysisDomain::Codesign => {
            let old: Option<CodesignSnapshot> = decode(old)?;
            let new: Option<CodesignSnapshot> = decode(new)?;
            diff_codesign(old.as_ref(), new.as_ref(), arch, findings);
        }
        AnalysisDomain::Swift => {
            diff_swift(&decode(old)?, &decode(new)?, arch, findings)?;
        }
        AnalysisDomain::Strings => diff_strings(
            &decode::<Vec<crate::analysis::strings::FoundString>>(old)?,
            &decode::<Vec<crate::analysis::strings::FoundString>>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Ranges => {
            diff_ranges(
                &decode::<Vec<crate::analysis::xref::ranges::RangeEntry>>(old)?,
                &decode::<Vec<crate::analysis::xref::ranges::RangeEntry>>(new)?,
                arch,
                findings,
            )?;
        }
        AnalysisDomain::Xrefs => {
            diff_xrefs(
                &decode::<Vec<crate::analysis::xref::refs::Xref>>(old)?,
                &decode::<Vec<crate::analysis::xref::refs::Xref>>(new)?,
                arch,
                findings,
            )?;
        }
        AnalysisDomain::Dependencies => diff_dependencies(
            &decode::<DependencySnapshot>(old)?,
            &decode::<DependencySnapshot>(new)?,
            arch,
            findings,
        ),
        AnalysisDomain::Audit => {
            diff_audit(&decode(old)?, &decode(new)?, arch, findings)?;
        }
        AnalysisDomain::CSurface => diff_recovery_surface(
            &decode(old)?,
            &decode(new)?,
            DiffDomain::CSurface,
            arch,
            findings,
        )?,
        AnalysisDomain::CppSurface => diff_recovery_surface(
            &decode(old)?,
            &decode(new)?,
            DiffDomain::CppSurface,
            arch,
            findings,
        )?,
        AnalysisDomain::ObjcHeaders => {
            diff_objc_headers(&decode(old)?, &decode(new)?, arch, findings)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
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
        | DomainPayload::CSurface(value)
        | DomainPayload::CppSurface(value)
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
    match (old, new) {
        (DomainState::Complete { .. }, DomainState::Failed { .. })
        | (DomainState::Complete { .. }, DomainState::Unsupported { .. }) => {
            ChangeSeverity::Breaking
        }
        (DomainState::Failed { .. }, DomainState::Complete { .. })
        | (DomainState::Unsupported { .. }, DomainState::Complete { .. }) => ChangeSeverity::Info,
        _ => ChangeSeverity::Warning,
    }
}

fn state_description<T>(state: &DomainState<T>) -> String {
    match state {
        DomainState::NotRequested => "not_requested".to_owned(),
        DomainState::Complete { .. } => "complete".to_owned(),
        DomainState::Unsupported { reason } => {
            format!("unsupported ({}: {})", reason.code, reason.message)
        }
        DomainState::Failed { error, .. } => {
            format!("failed ({}: {})", error.code, error.message)
        }
    }
}

fn report_domain(domain: AnalysisDomain) -> DiffDomain {
    match domain {
        AnalysisDomain::Container => DiffDomain::Container,
        AnalysisDomain::Header => DiffDomain::Header,
        AnalysisDomain::LoadCommands => DiffDomain::LoadCommands,
        AnalysisDomain::Segments => DiffDomain::Segments,
        AnalysisDomain::Relocations => DiffDomain::Relocations,
        AnalysisDomain::Symbols => DiffDomain::Symbols,
        AnalysisDomain::Exports => DiffDomain::Exports,
        AnalysisDomain::Imports => DiffDomain::Imports,
        AnalysisDomain::Fixups => DiffDomain::Fixups,
        AnalysisDomain::Codesign => DiffDomain::Codesign,
        AnalysisDomain::Objc => DiffDomain::ObjC,
        AnalysisDomain::Swift => DiffDomain::Swift,
        AnalysisDomain::Strings => DiffDomain::Strings,
        AnalysisDomain::Ranges => DiffDomain::Ranges,
        AnalysisDomain::Xrefs => DiffDomain::Xrefs,
        AnalysisDomain::Dependencies => DiffDomain::Dependencies,
        AnalysisDomain::Audit => DiffDomain::Audit,
        AnalysisDomain::CSurface => DiffDomain::CSurface,
        AnalysisDomain::CppSurface => DiffDomain::CppSurface,
        AnalysisDomain::ObjcHeaders => DiffDomain::ObjCHeaders,
        _ => DiffDomain::Analysis,
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::analysis::{
        AnalysisFailure, ContainerIdentity, SliceIdentity, SliceSnapshot, UnsupportedReason,
    };

    fn document(domain: AnalysisDomain, state: DomainState<DomainPayload>) -> SnapshotDocument {
        let mut domains = AnalysisDomain::ALL
            .iter()
            .copied()
            .map(|domain| (domain, DomainState::NotRequested))
            .collect::<BTreeMap<_, _>>();
        domains.insert(domain, state);
        SnapshotDocument {
            schema_version: 3,
            container: ContainerIdentity {
                format: "thin".to_owned(),
                slice_count: 1,
            },
            slices: vec![SliceSnapshot {
                identity: SliceIdentity {
                    index: 0,
                    arch: "arm64".to_owned(),
                },
                domains,
            }],
        }
    }

    fn complete(payload: DomainPayload) -> DomainState<DomainPayload> {
        DomainState::Complete {
            value: payload,
            issues: Vec::new(),
        }
    }

    #[test]
    fn string_diff_uses_content_multisets_without_order_or_address_churn() {
        let a = json!({"value":"alpha", "va":0x1000, "file_offset":0x10});
        let b = json!({"value":"beta", "va":0x1010, "file_offset":0x20});
        let moved_a = json!({"value":"alpha", "va":0x9000, "file_offset":0x90});
        let moved_b = json!({"value":"beta", "va":0x9010, "file_offset":0xa0});
        let old = document(
            AnalysisDomain::Strings,
            complete(DomainPayload::Strings(json!([a, b]))),
        );
        let reordered = document(
            AnalysisDomain::Strings,
            complete(DomainPayload::Strings(json!([moved_b, moved_a]))),
        );
        let selected = BTreeSet::from([AnalysisDomain::Strings]);

        let reordered_report = diff_documents(&old, &reordered, &selected);
        assert!(
            reordered_report.findings.is_empty(),
            "{:?}",
            reordered_report.findings
        );

        let changed = document(
            AnalysisDomain::Strings,
            complete(DomainPayload::Strings(json!([
                {"value":"alpha", "va":0x1000, "file_offset":0x10},
                {"value":"gamma", "va":0x1020, "file_offset":0x30}
            ]))),
        );
        let report = diff_documents(&old, &changed, &selected);
        assert!(report.findings.iter().any(|finding| {
            finding.domain == DiffDomain::Strings && finding.message.contains("removed 1 string")
        }));
        assert!(report.findings.iter().any(|finding| {
            finding.domain == DiffDomain::Strings && finding.message.contains("added 1 string")
        }));
    }

    #[test]
    fn xref_diff_uses_relationships_and_internal_deltas() {
        let old = document(
            AnalysisDomain::Xrefs,
            complete(DomainPayload::Xrefs(json!([
                {"source":0x1000, "target":{"type":"internal", "va":0x1100}, "kind":"direct_branch"},
                {"source":0x1200, "target":{"type":"import", "name":"_open", "ordinal":1}, "kind":"stub"}
            ]))),
        );
        let moved_and_reordered = document(
            AnalysisDomain::Xrefs,
            complete(DomainPayload::Xrefs(json!([
                {"source":0x9200, "target":{"type":"import", "name":"_open", "ordinal":1}, "kind":"stub"},
                {"source":0x9000, "target":{"type":"internal", "va":0x9100}, "kind":"direct_branch"}
            ]))),
        );
        let selected = BTreeSet::from([AnalysisDomain::Xrefs]);
        let moved_report = diff_documents(&old, &moved_and_reordered, &selected);
        assert!(
            moved_report.findings.is_empty(),
            "{:?}",
            moved_report.findings
        );
    }

    #[test]
    fn range_diff_ignores_order_and_classifies_moves_vs_semantic_changes() {
        let main = |start: u64, end: u64, source: &str| {
            json!({
                "start":start, "end":end,
                "entity":{"kind":"symbol", "name":"_main", "external":true},
                "source":source, "is_alt_entry":false
            })
        };
        let helper = json!({
            "start":0x1200, "end":0x1220,
            "entity":{"kind":"symbol", "name":"_helper", "external":false},
            "source":"nlist", "is_alt_entry":false
        });
        let old = document(
            AnalysisDomain::Ranges,
            complete(DomainPayload::Ranges(json!([
                main(0x1000, 0x1040, "nlist"),
                helper
            ]))),
        );
        let reordered = document(
            AnalysisDomain::Ranges,
            complete(DomainPayload::Ranges(json!([
                helper,
                main(0x1000, 0x1040, "nlist")
            ]))),
        );
        let selected = BTreeSet::from([AnalysisDomain::Ranges]);
        assert!(
            diff_documents(&old, &reordered, &selected)
                .findings
                .is_empty()
        );

        let moved = document(
            AnalysisDomain::Ranges,
            complete(DomainPayload::Ranges(json!([
                main(0x9000, 0x9040, "nlist"),
                helper
            ]))),
        );
        let report = diff_documents(&old, &moved, &selected);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].domain, DiffDomain::Ranges);
        assert_eq!(report.findings[0].severity, ChangeSeverity::Info);

        let resized = document(
            AnalysisDomain::Ranges,
            complete(DomainPayload::Ranges(json!([
                main(0x9000, 0x9060, "inferred"),
                helper
            ]))),
        );
        let report = diff_documents(&old, &resized, &selected);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].domain, DiffDomain::Ranges);
        assert_eq!(report.findings[0].severity, ChangeSeverity::Warning);
        assert!(report.findings[0].message.contains("inferred"));
    }

    #[test]
    fn audit_same_rule_change_is_structured_and_deterministic() {
        let old = document(
            AnalysisDomain::Audit,
            complete(DomainPayload::Audit(json!({
                "arch":"arm64",
                "findings":[{"rule_id":"CS003", "severity":"warning", "title":"Weak hash", "body":"SHA-1", "evidence":[], "remediation":"re-sign"}]
            }))),
        );
        let new = document(
            AnalysisDomain::Audit,
            complete(DomainPayload::Audit(json!({
                "arch":"arm64",
                "findings":[{"rule_id":"CS003", "severity":"critical", "title":"Invalid signature", "body":"verification failed", "evidence":["slot 0"], "remediation":"sign with a trusted identity"}]
            }))),
        );
        let selected = BTreeSet::from([AnalysisDomain::Audit]);
        let first = diff_documents(&old, &new, &selected);
        let second = diff_documents(&old, &new, &selected);
        assert_eq!(first, second);
        assert_eq!(first.findings.len(), 1);
        assert_eq!(first.findings[0].domain, DiffDomain::Audit);
        assert_eq!(first.findings[0].severity, ChangeSeverity::Breaking);
        assert!(first.findings[0].message.contains("CS003"));
        assert!(first.findings[0].message.contains("changed"));
    }

    #[test]
    fn duplicate_audit_rules_cancel_exact_matches_before_pairing() {
        let finding = |title: &str| {
            json!({
                "rule_id":"LP001", "severity":"warning", "title":title,
                "body":format!("{title} body"), "evidence":[], "remediation":null
            })
        };
        let old = document(
            AnalysisDomain::Audit,
            complete(DomainPayload::Audit(json!({
                "arch":"arm64", "findings":[finding("Zulu"), finding("Mike")]
            }))),
        );
        let new = document(
            AnalysisDomain::Audit,
            complete(DomainPayload::Audit(json!({
                "arch":"arm64",
                "findings":[finding("Zulu"), finding("Alpha"), finding("Mike")]
            }))),
        );
        let reordered_new = document(
            AnalysisDomain::Audit,
            complete(DomainPayload::Audit(json!({
                "arch":"arm64",
                "findings":[finding("Mike"), finding("Zulu"), finding("Alpha")]
            }))),
        );
        let selected = BTreeSet::from([AnalysisDomain::Audit]);
        let report = diff_documents(&old, &new, &selected);
        let reordered = diff_documents(&old, &reordered_new, &selected);
        assert_eq!(report, reordered);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].domain, DiffDomain::Audit);
        assert!(
            report.findings[0]
                .message
                .contains("new audit finding LP001")
        );
        assert!(report.findings[0].message.contains("Alpha"));
    }

    #[test]
    fn relocation_and_dependency_changes_keep_their_structured_domains() {
        let old_relocations = document(
            AnalysisDomain::Relocations,
            complete(DomainPayload::Relocations(json!([
                {"segment":"__TEXT", "section":"__text", "count":2}
            ]))),
        );
        let new_relocations = document(
            AnalysisDomain::Relocations,
            complete(DomainPayload::Relocations(json!([
                {"segment":"__TEXT", "section":"__text", "count":5}
            ]))),
        );
        let report = diff_documents(
            &old_relocations,
            &new_relocations,
            &BTreeSet::from([AnalysisDomain::Relocations]),
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].domain, DiffDomain::Relocations);
        assert!(report.findings[0].message.contains("2 -> 5"));

        let old_dependencies = document(
            AnalysisDomain::Dependencies,
            complete(DomainPayload::Dependencies(json!({
                "install_name":"@rpath/libOld.dylib", "dylib_count":2,
                "import_count":4, "export_count":1
            }))),
        );
        let new_dependencies = document(
            AnalysisDomain::Dependencies,
            complete(DomainPayload::Dependencies(json!({
                "install_name":"@rpath/libNew.dylib", "dylib_count":3,
                "import_count":4, "export_count":1
            }))),
        );
        let report = diff_documents(
            &old_dependencies,
            &new_dependencies,
            &BTreeSet::from([AnalysisDomain::Dependencies]),
        );
        assert_eq!(report.findings.len(), 2);
        assert!(
            report
                .findings
                .iter()
                .all(|finding| finding.domain == DiffDomain::Dependencies)
        );
        assert!(report.findings.iter().any(|finding| {
            finding.severity == ChangeSeverity::Breaking && finding.message.contains("install name")
        }));
    }

    #[test]
    fn evidence_state_transitions_are_not_empty_domain_diffs() {
        let unsupported = document(
            AnalysisDomain::Xrefs,
            DomainState::Unsupported {
                reason: UnsupportedReason {
                    code: "analysis.capability.unsupported".to_owned(),
                    message: "architecture is unsupported".to_owned(),
                },
            },
        );
        let failed = document(
            AnalysisDomain::Xrefs,
            DomainState::Failed {
                error: AnalysisFailure {
                    code: "analysis.parse.failed".to_owned(),
                    message: "truncated instruction".to_owned(),
                },
                issues: Vec::new(),
            },
        );
        let selected = BTreeSet::from([AnalysisDomain::Xrefs]);
        let report = diff_documents(&unsupported, &failed, &selected);
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].domain, DiffDomain::Xrefs);
        assert_eq!(report.findings[0].severity, ChangeSeverity::Warning);
        assert!(report.findings[0].message.contains("unsupported"));
        assert!(report.findings[0].message.contains("failed"));
        assert!(report.findings[0].message.contains("truncated instruction"));
    }
}
