use std::collections::{BTreeMap, BTreeSet};
use std::sync::Mutex;

use macho::analysis::analyzer::DomainObserver;
use macho::analysis::audit::{AuditInput, AuditReport, AuditSeverity, audit_slice};
use macho::analysis::snapshot::{CodesignSnapshot, HeaderSnapshot};
use macho::analysis::{
    AnalysisDomain, AnalysisError, Analyzer, AuditPlan, DomainPayload, DomainState,
};

#[derive(Default)]
struct Counter(Mutex<BTreeMap<AnalysisDomain, usize>>);

impl DomainObserver for Counter {
    fn before_domain(&self, domain: AnalysisDomain) -> Result<(), AnalysisError> {
        *self
            .0
            .lock()
            .expect("counter lock")
            .entry(domain)
            .or_default() += 1;
        Ok(())
    }
}

#[test]
fn disabled_audit_rules_do_not_expand_or_execute_their_domains() {
    let mut plan = AuditPlan::default();
    for spec in AuditPlan::rule_specs() {
        if spec.id != "MEM002" {
            plan = plan.excluding_rule(spec.id);
        }
    }
    let compiled = plan.compile();
    assert_eq!(
        compiled.domains(),
        &BTreeSet::from([AnalysisDomain::Header, AnalysisDomain::Audit])
    );

    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse");
    let counter = Counter::default();
    let document = Analyzer
        .run_with_observer(&container, &compiled, &counter)
        .expect("audit");
    assert_eq!(
        *counter.0.lock().expect("counter lock"),
        BTreeMap::from([(AnalysisDomain::Header, 1), (AnalysisDomain::Audit, 1)])
    );

    let DomainState::Complete {
        value: DomainPayload::Audit(value),
        ..
    } = &document.slices[0].domains[&AnalysisDomain::Audit]
    else {
        panic!("audit did not complete")
    };
    let report: AuditReport = serde_json::from_value(value.clone()).expect("audit report");
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule_id == "MEM002")
    );
}

fn codesign_snapshot(hash_type: &str, team_id: Option<&str>) -> CodesignSnapshot {
    CodesignSnapshot {
        identifier: Some("com.example.fixture".into()),
        team_id: team_id.map(str::to_owned),
        hash_type: hash_type.into(),
        has_entitlements: false,
        entitlements_xml: None,
        entitlement_keys: Vec::new(),
        has_der_entitlements: false,
        entitlements_der_fingerprint: None,
        has_cms_signature: true,
        n_code_slots: 1,
        code_limit: 4_096,
    }
}

fn command_from_remediation(remediation: &str) -> &str {
    let start = remediation
        .find('`')
        .expect("command remediation starts a code span")
        + 1;
    let end = remediation[start..]
        .find('`')
        .map(|offset| start + offset)
        .expect("command remediation ends a code span");
    &remediation[start..end]
}

fn assert_remediation_command_is_live(remediation: &str) {
    let command = command_from_remediation(remediation);
    macho_cli::commands::parse_only(command.split_whitespace()).unwrap_or_else(|error| {
        panic!("audit remediation is rejected by the CLI: {command}: {error}")
    });
}

#[test]
fn code_signing_remediations_use_live_safe_cli_commands() {
    let unsigned = audit_slice(&AuditInput {
        arch: "arm64".into(),
        header: Some(HeaderSnapshot {
            cpu_type: "arm64".into(),
            cpu_subtype: "all".into(),
            file_type: "MH_EXECUTE".into(),
            flags: Vec::new(),
            ncmds: 0,
            uuid: None,
            platform: None,
        }),
        load_commands: Some(Vec::new()),
        segments: None,
        codesign: None,
        analysis_issues: Vec::new(),
        enabled_rules: BTreeSet::from(["CS001".into()]),
    });
    let weak = audit_slice(&AuditInput {
        arch: "arm64".into(),
        header: None,
        load_commands: None,
        segments: None,
        codesign: Some(codesign_snapshot("SHA-1", Some("TEAMID"))),
        analysis_issues: Vec::new(),
        enabled_rules: BTreeSet::from(["CS003".into()]),
    });

    for finding in unsigned.findings.iter().chain(&weak.findings) {
        let remediation = finding
            .remediation
            .as_deref()
            .expect("actionable signing finding has remediation");
        assert_remediation_command_is_live(remediation);
        assert!(
            remediation.contains("--output"),
            "remediation must preserve the original by default"
        );
        assert!(!remediation.contains("--in-place"));
        assert!(!remediation.contains("--digest-algorithm"));
    }
    assert!(
        weak.findings[0]
            .remediation
            .as_deref()
            .expect("CS003 remediation")
            .contains("includes a SHA-256 CodeDirectory")
    );
}

#[test]
fn missing_team_id_is_context_not_an_automatic_repair() {
    let report = audit_slice(&AuditInput {
        arch: "arm64e".into(),
        header: None,
        load_commands: None,
        segments: None,
        codesign: Some(codesign_snapshot("SHA-256", None)),
        analysis_issues: Vec::new(),
        enabled_rules: BTreeSet::from(["CS004".into()]),
    });

    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].severity, AuditSeverity::Info);
    assert!(report.findings[0].remediation.is_none());
    assert!(report.findings[0].body.contains("Distribution context"));
}
