use super::*;
use std::sync::Mutex;

struct PanicOutside(BTreeSet<AnalysisDomain>);

impl DomainObserver for PanicOutside {
    fn before_domain(&self, domain: AnalysisDomain) -> Result<()> {
        assert!(
            self.0.contains(&domain),
            "excluded runner {domain:?} executed"
        );
        Ok(())
    }
}

#[derive(Default)]
struct CountingObserver(Mutex<BTreeMap<AnalysisDomain, usize>>);

impl DomainObserver for CountingObserver {
    fn before_domain(&self, domain: AnalysisDomain) -> Result<()> {
        *self.0.lock().unwrap().entry(domain).or_default() += 1;
        Ok(())
    }
}

struct FailingObserver(AnalysisDomain);

impl DomainObserver for FailingObserver {
    fn before_domain(&self, domain: AnalysisDomain) -> Result<()> {
        if domain == self.0 {
            Err(AnalysisError::new(
                domain,
                AnalysisErrorKind::Validation,
                "injected runner failure",
            ))
        } else {
            Ok(())
        }
    }
}

#[test]
fn excluded_domains_are_not_executed() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let document = Analyzer
        .run_with_observer(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header]),
            &PanicOutside(BTreeSet::from([AnalysisDomain::Header])),
        )
        .unwrap();
    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Header],
        DomainState::Complete { .. }
    ));
    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Objc],
        DomainState::NotRequested
    ));
}

#[test]
fn selected_fat_slice_is_the_document_slice_count() {
    let bytes = macho_test_support::disassembly_fat();
    let container = crate::core::parse(&bytes).unwrap();
    let document = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["x86_64".to_owned()]),
        )
        .unwrap();

    assert_eq!(document.container.format, "fat");
    assert_eq!(document.container.slice_count, 1);
    assert_eq!(document.slices.len(), 1);
    assert_eq!(document.slices[0].identity.index, 0);
    assert_eq!(document.slices[0].identity.arch, "x86_64");
    document.validate().unwrap();
}

#[test]
fn family_selector_retains_qualified_siblings_with_distinct_identities() {
    let bytes = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::disassembly_arm64(),
        ),
        (
            macho_test_support::CPU_TYPE_ARM64,
            macho_test_support::CPU_SUBTYPE_ARM64E,
            macho_test_support::disassembly_arm64e(),
        ),
    ]);
    let container = crate::core::parse(&bytes).unwrap();

    let family = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["arm64".to_owned()]),
        )
        .unwrap();
    assert_eq!(family.container.slice_count, 2);
    assert_eq!(
        family
            .slices
            .iter()
            .map(|slice| slice.identity.arch.as_str())
            .collect::<Vec<_>>(),
        ["arm64", "arm64e"]
    );

    let qualified = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["arm64e".to_owned()]),
        )
        .unwrap();
    assert_eq!(qualified.container.slice_count, 1);
    assert_eq!(qualified.slices[0].identity.arch, "arm64e");
}

#[test]
fn every_requested_architecture_selector_must_match() {
    let bytes = macho_test_support::disassembly_fat();
    let container = crate::core::parse(&bytes).unwrap();
    let error = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header])
                .with_slices(["arm64e".to_owned(), "not_present".to_owned()]),
        )
        .unwrap_err();
    assert!(
        error
            .message()
            .contains("no architecture matching 'not_present'")
    );
}

#[test]
fn x86_64_family_siblings_have_distinct_observable_identities() {
    let bytes = macho_test_support::disassembly_fat_x86_subtypes();
    let container = crate::core::parse(&bytes).unwrap();
    let family = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["x86_64".to_owned()]),
        )
        .unwrap();
    assert_eq!(
        family
            .slices
            .iter()
            .map(|slice| slice.identity.arch.as_str())
            .collect::<Vec<_>>(),
        ["x86_64", "x86_64h"]
    );

    let qualified = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["x86_64h".to_owned()]),
        )
        .unwrap();
    assert_eq!(qualified.slices.len(), 1);
    assert_eq!(qualified.slices[0].identity.arch, "x86_64h");
}

#[test]
fn diff_exclusion_is_applied_before_dependency_execution() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let compiled = crate::analysis::planner::DiffPlan::default()
        .exclude(AnalysisDomain::Symbols)
        .compile();
    let resolved = resolve_domains(&compiled);
    assert!(!resolved.contains(&AnalysisDomain::Symbols));
    Analyzer
        .run_with_observer(&container, &compiled, &PanicOutside(resolved))
        .unwrap();
}

#[test]
fn dependency_closure_executes_each_domain_once() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let observer = CountingObserver::default();
    let document = Analyzer
        .run_with_observer(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Segments]),
            &observer,
        )
        .unwrap();
    for domain in [
        AnalysisDomain::Header,
        AnalysisDomain::LoadCommands,
        AnalysisDomain::Segments,
    ] {
        assert!(matches!(
            document.slices[0].domains[&domain],
            DomainState::Complete { .. }
        ));
    }
    assert_eq!(
        *observer.0.lock().unwrap(),
        BTreeMap::from([
            (AnalysisDomain::Header, 1),
            (AnalysisDomain::LoadCommands, 1),
            (AnalysisDomain::Segments, 1),
        ])
    );
}

#[test]
fn injected_runner_failure_has_failed_state() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let document = Analyzer
        .run_with_observer(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Symbols]),
            &FailingObserver(AnalysisDomain::Symbols),
        )
        .unwrap();
    assert!(matches!(
        document.slices[0].domains[&AnalysisDomain::Symbols],
        DomainState::Failed { .. }
    ));
}

#[test]
fn all_four_domain_states_are_distinct_and_serialize_explicitly() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let complete_and_unrequested = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Strings]))
        .unwrap();
    let complete = &complete_and_unrequested.slices[0].domains[&AnalysisDomain::Strings];
    assert!(matches!(
        complete,
        DomainState::Complete {
            value: DomainPayload::Strings(value),
            ..
        } if value.as_array().is_some_and(Vec::is_empty)
    ));
    let not_requested = &complete_and_unrequested.slices[0].domains[&AnalysisDomain::ObjcHeaders];
    assert!(matches!(not_requested, DomainState::NotRequested));

    let unsupported_bytes = macho_test_support::thin64_unknown_cpu(2);
    let unsupported_container = crate::core::parse(&unsupported_bytes).unwrap();
    let unsupported_document = Analyzer
        .run(
            &unsupported_container,
            &AnalysisPlan::new([AnalysisDomain::Xrefs]),
        )
        .unwrap();
    let unsupported = &unsupported_document.slices[0].domains[&AnalysisDomain::Xrefs];
    assert!(matches!(unsupported, DomainState::Unsupported { .. }));

    let failed_document = Analyzer
        .run_with_observer(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Symbols]),
            &FailingObserver(AnalysisDomain::Symbols),
        )
        .unwrap();
    let failed = &failed_document.slices[0].domains[&AnalysisDomain::Symbols];
    assert!(matches!(failed, DomainState::Failed { .. }));

    assert_eq!(serde_json::to_value(complete).unwrap()["state"], "complete");
    assert_eq!(
        serde_json::to_value(not_requested).unwrap()["state"],
        "not_requested"
    );
    assert_eq!(
        serde_json::to_value(unsupported).unwrap()["state"],
        "unsupported"
    );
    assert_eq!(serde_json::to_value(failed).unwrap()["state"], "failed");
}

#[test]
fn collection_and_decode_limits_truncate_without_failing_the_domain() {
    let bytes =
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_entry",
            external: true,
            defined: true,
        }]);
    let container = crate::core::parse(&bytes).unwrap();
    let limits = AnalysisLimits {
        max_ranges_per_slice: 0,
        max_decoded_bytes_per_slice: 0,
        ..AnalysisLimits::default()
    };
    let document = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Ranges, AnalysisDomain::Xrefs]).with_limits(limits),
        )
        .unwrap();
    for domain in [AnalysisDomain::Ranges, AnalysisDomain::Xrefs] {
        match &document.slices[0].domains[&domain] {
            DomainState::Complete { issues, .. } => assert!(
                issues
                    .iter()
                    .any(|issue| issue.code == "analysis.limit.truncated"),
                "{domain:?} did not record truncation"
            ),
            state => panic!("{domain:?} should remain complete, got {state:?}"),
        }
    }
}

#[test]
fn issue_limit_bounds_advisory_failure_propagation() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let document = Analyzer
        .run_with_observer(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Imports]).with_limits(AnalysisLimits {
                max_issues_per_domain: 0,
                ..AnalysisLimits::default()
            }),
            &FailingObserver(AnalysisDomain::Symbols),
        )
        .unwrap();
    match &document.slices[0].domains[&AnalysisDomain::Imports] {
        DomainState::Complete { issues, .. } => {
            assert_eq!(issues.len(), 1);
            assert_eq!(issues[0].code, "analysis.limit.truncated");
        }
        state => panic!("imports should run after advisory failure, got {state:?}"),
    }
}

#[test]
fn rejects_unversioned_and_mismatched_snapshots() {
    assert!(SnapshotDocument::from_json("{}").is_err());
    let mut document = SnapshotDocument {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        container: ContainerIdentity {
            format: "thin".into(),
            slice_count: 1,
        },
        slices: vec![SliceSnapshot {
            identity: SliceIdentity {
                index: 0,
                arch: "arm64".into(),
            },
            domains: AnalysisDomain::ALL
                .iter()
                .copied()
                .map(|domain| (domain, DomainState::NotRequested))
                .collect(),
        }],
    };
    document.slices[0].domains.insert(
        AnalysisDomain::Header,
        DomainState::Complete {
            value: DomainPayload::Segments(json!([])),
            issues: vec![],
        },
    );
    assert!(document.validate().is_err());
}

#[test]
fn typed_reports_preserve_state_and_schema_v1_wire_shape() {
    let bytes =
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_typed_entry",
            external: true,
            defined: true,
        }]);
    let container = crate::core::parse(&bytes).unwrap();
    let document = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([
                AnalysisDomain::Header,
                AnalysisDomain::Symbols,
                AnalysisDomain::Xrefs,
            ]),
        )
        .unwrap();
    let before = serde_json::to_string(&document).unwrap();
    let slice = &document.slices[0];

    let header = slice.report(domain_reports::HEADER).unwrap();
    assert!(matches!(
        header,
        DomainState::Complete { value, .. } if value.cpu_type == "x86_64"
    ));
    let symbols = slice.report(domain_reports::SYMBOLS).unwrap();
    assert!(matches!(
        symbols,
        DomainState::Complete { value, .. }
            if value.iter().any(|symbol| symbol.name == "_typed_entry")
    ));
    let xrefs = slice.report(domain_reports::XREFS).unwrap();
    assert!(matches!(xrefs, DomainState::Complete { .. }));
    assert!(matches!(
        slice.report(domain_reports::OBJC).unwrap(),
        DomainState::NotRequested
    ));

    // Typed reads are a projection over the existing payload and cannot alter
    // schema-v1 serialization.
    let after = serde_json::to_string(&document).unwrap();
    assert_eq!(after, before);
    let wire: Value = serde_json::from_str(&before).unwrap();
    let header_wire = &wire["slices"][0]["domains"]["header"]["value"];
    assert_eq!(
        header_wire,
        &json!({
            "kind": "header",
            "report_schema": 1,
            "report": {
                "cpu_type": "x86_64",
                "cpu_subtype": "all",
                "file_type": "MH_EXECUTE",
                "flags": [],
                "ncmds": 2,
                "uuid": null,
                "platform": null
            }
        })
    );

    let round_tripped = SnapshotDocument::from_json(&before).unwrap();
    assert_eq!(serde_json::to_string(&round_tripped).unwrap(), before);
    assert!(matches!(
        round_tripped.slices[0]
            .report(domain_reports::SYMBOLS)
            .unwrap(),
        DomainState::Complete { value, .. }
            if value.iter().any(|symbol| symbol.name == "_typed_entry")
    ));
}

#[test]
fn typed_payload_rejects_a_cross_domain_key_before_deserialization() {
    let payload = DomainPayload::Header(json!([]));
    let error = payload.decode(domain_reports::SYMBOLS).unwrap_err();
    assert_eq!(error.kind, AnalysisErrorKind::DomainTypeMismatch);
    assert_eq!(error.domain, AnalysisDomain::Header);
    assert_eq!(error.code(), "analysis.domain.type_mismatch");
    assert!(error.message().contains("header payload"));
    assert!(error.message().contains("symbols report key"));
}

#[test]
fn typed_reports_preserve_unsupported_and_failed_details() {
    let unsupported_bytes = macho_test_support::thin64_unknown_cpu(2);
    let unsupported_container = crate::core::parse(&unsupported_bytes).unwrap();
    let unsupported = Analyzer
        .run(
            &unsupported_container,
            &AnalysisPlan::new([AnalysisDomain::Xrefs]),
        )
        .unwrap();
    match unsupported.slices[0].report(domain_reports::XREFS).unwrap() {
        DomainState::Unsupported { reason } => {
            assert_eq!(reason.code, "analysis.capability.unsupported");
            assert!(reason.message.contains("does not support architecture"));
        }
        state => panic!("expected typed unsupported state, got {state:?}"),
    }

    let bytes = macho_test_support::thin64_arm64(2);
    let container = crate::core::parse(&bytes).unwrap();
    let failed = Analyzer
        .run_with_observer(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Symbols]),
            &FailingObserver(AnalysisDomain::Symbols),
        )
        .unwrap();
    match failed.slices[0].report(domain_reports::SYMBOLS).unwrap() {
        DomainState::Failed { error, issues } => {
            assert_eq!(error.code, "analysis.validation.failed");
            assert_eq!(error.message, "injected runner failure");
            assert!(issues.is_empty());
        }
        state => panic!("expected typed failed state, got {state:?}"),
    }
}

#[test]
fn xref_domain_preserves_recovery_partiality_reasons() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = crate::core::parse(&bytes).unwrap();
    let document = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([AnalysisDomain::Xrefs]).with_limits(AnalysisLimits {
                max_decoded_bytes_per_slice: 1,
                ..AnalysisLimits::default()
            }),
        )
        .unwrap();
    match &document.slices[0].domains[&AnalysisDomain::Xrefs] {
        DomainState::Complete { issues, .. } => assert!(
            issues.iter().any(|issue| issue.code.starts_with("xrefs.")),
            "xref completeness reasons must survive the analyzer adapter: {issues:?}"
        ),
        state => panic!("xref domain should execute with explicit issues, got {state:?}"),
    }
}
