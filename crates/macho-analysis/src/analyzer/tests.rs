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
    let container = macho_core::parse(&bytes).unwrap();
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
fn diff_exclusion_is_applied_before_dependency_execution() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho_core::parse(&bytes).unwrap();
    let compiled = crate::planner::DiffPlan::default()
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
    let container = macho_core::parse(&bytes).unwrap();
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
    let container = macho_core::parse(&bytes).unwrap();
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
    let container = macho_core::parse(&bytes).unwrap();
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
    let unsupported_container = macho_core::parse(&unsupported_bytes).unwrap();
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
    let container = macho_core::parse(&bytes).unwrap();
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
    let container = macho_core::parse(&bytes).unwrap();
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
