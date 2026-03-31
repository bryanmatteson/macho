use macho::analysis::snapshot::{
    AnalysisIssueSnapshot, ContainerFormat, ContainerSnapshot, DiagnosticSnapshot, HeaderSnapshot,
    ObjCSnapshot, SliceSnapshot,
};
use macho::diff::{ChangeSeverity, DiffDomain, diff_containers};

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

fn synthetic_snapshot() -> ContainerSnapshot {
    ContainerSnapshot {
        format: ContainerFormat::Thin,
        slices: vec![SliceSnapshot {
            arch: "arm64".into(),
            header: HeaderSnapshot {
                cpu_type: "arm64".into(),
                cpu_subtype: "all".into(),
                file_type: "MH_EXECUTE".into(),
                flags: Vec::new(),
                ncmds: 0,
                uuid: None,
                platform: None,
            },
            load_commands: Vec::new(),
            segments: Vec::new(),
            symbols: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            objc: ObjCSnapshot {
                classes: Vec::new(),
                categories: Vec::new(),
                protocols: Vec::new(),
            },
            codesign: None,
            analysis_issues: Vec::new(),
            diagnostics: Vec::new(),
        }],
    }
}

#[test]
fn diff_identical_binary_has_no_findings() {
    let snap = snapshot_for("/usr/bin/true");
    let report = diff_containers(&snap, &snap);
    assert!(
        report.findings.is_empty(),
        "diffing a binary against itself should produce no findings, got: {:?}",
        report
            .findings
            .iter()
            .map(|f| &f.message)
            .collect::<Vec<_>>()
    );
}

#[test]
fn diff_different_binaries_has_findings() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    assert!(!report.findings.is_empty());
}

#[test]
fn diff_true_vs_false_detects_identifier_change() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let codesign_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.domain == DiffDomain::Codesign)
        .collect();

    assert!(
        !codesign_findings.is_empty(),
        "should detect codesign differences"
    );

    assert!(
        codesign_findings
            .iter()
            .any(|f| f.message.contains("identifier changed"))
    );
}

#[test]
fn diff_true_vs_false_has_uuid_change() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let uuid_findings: Vec<_> = report
        .findings
        .iter()
        .filter(|f| f.message.contains("UUID changed"))
        .collect();

    assert!(
        !uuid_findings.is_empty(),
        "should detect UUID change between true and false"
    );
}

#[test]
fn diff_filter_domain() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let codesign_only = report.filter_domain(DiffDomain::Codesign);
    for f in &codesign_only {
        assert_eq!(f.domain, DiffDomain::Codesign);
    }
}

#[test]
fn diff_filter_severity() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);

    let warnings = report.filter_severity(ChangeSeverity::Warning);
    for f in &warnings {
        assert!(f.severity >= ChangeSeverity::Warning);
    }
}

#[test]
fn diff_max_severity() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    assert!(report.max_severity().is_some());
}

#[test]
fn diff_has_breaking_returns_false_for_true_vs_false() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    // true and false are nearly identical — no breaking changes expected
    assert!(!report.has_breaking());
}

#[test]
fn diff_report_serializes_to_json() {
    let old = snapshot_for("/usr/bin/true");
    let new = snapshot_for("/usr/bin/false");
    let report = diff_containers(&old, &new);
    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed["findings"].is_array());
}

#[test]
fn diff_severity_ordering() {
    assert!(ChangeSeverity::Info < ChangeSeverity::Warning);
    assert!(ChangeSeverity::Warning < ChangeSeverity::Breaking);
}

#[test]
fn diff_domain_ordering() {
    assert!(DiffDomain::Container < DiffDomain::Header);
    assert!(DiffDomain::Header < DiffDomain::Exports);
}

#[test]
fn diff_validation_detects_message_changes_for_same_code() {
    let mut old = synthetic_snapshot();
    old.slices[0].diagnostics.push(DiagnosticSnapshot {
        severity: "error".into(),
        code: "E010".into(),
        message: "string table truncated".into(),
        spans: Vec::new(),
    });

    let mut new = synthetic_snapshot();
    new.slices[0].diagnostics.push(DiagnosticSnapshot {
        severity: "warning".into(),
        code: "E010".into(),
        message: "string table overlaps __LINKEDIT".into(),
        spans: Vec::new(),
    });

    let report = diff_containers(&old, &new);
    let validation: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Validation)
        .collect();

    assert_eq!(
        validation.len(),
        2,
        "expected add/remove pair: {validation:?}"
    );
    assert!(
        validation.iter().any(|finding| {
            finding
                .message
                .contains("new validation finding E010: string table overlaps __LINKEDIT")
        }),
        "missing added finding: {validation:?}"
    );
    assert!(
        validation.iter().any(|finding| {
            finding
                .message
                .contains("validation finding E010 resolved: string table truncated")
        }),
        "missing resolved finding: {validation:?}"
    );
}

#[test]
fn diff_reports_analysis_issue_changes() {
    let mut old = synthetic_snapshot();
    old.slices[0].analysis_issues.push(AnalysisIssueSnapshot {
        component: "codesign".into(),
        message: "failed to parse code signature: truncated superblob".into(),
    });

    let new = synthetic_snapshot();
    let report = diff_containers(&old, &new);

    let analysis: Vec<_> = report
        .findings
        .iter()
        .filter(|finding| finding.domain == DiffDomain::Analysis)
        .collect();

    assert_eq!(
        analysis.len(),
        1,
        "expected one resolved issue: {analysis:?}"
    );
    assert!(
        analysis[0]
            .message
            .contains("analysis issue resolved in codesign"),
        "unexpected finding: {:?}",
        analysis[0]
    );
}
