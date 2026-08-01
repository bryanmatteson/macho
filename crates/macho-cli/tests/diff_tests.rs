use std::collections::BTreeSet;

use macho::analysis::diff::{ChangeSeverity, DiffDomain, diff_documents};
use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer};

mod support;
use support::{run_cli, temp_file_path, write_macho_fixture};

#[test]
fn v3_diff_preserves_detailed_header_comparison() {
    let old_bytes = macho_test_support::thin64_arm64(2);
    let new_bytes = macho_test_support::thin64_arm64(6);
    let old_container = macho::parse(&old_bytes).expect("parse old");
    let new_container = macho::parse(&new_bytes).expect("parse new");
    let plan = AnalysisPlan::new([AnalysisDomain::Header]);
    let old = Analyzer.run(&old_container, &plan).expect("analyze old");
    let new = Analyzer.run(&new_container, &plan).expect("analyze new");
    let selected = BTreeSet::from([AnalysisDomain::Header]);

    let report = diff_documents(&old, &new, &selected);
    assert!(report.findings.iter().any(|finding| {
        finding.domain == DiffDomain::Header
            && finding.severity == ChangeSeverity::Breaking
            && finding.message.contains("file type changed")
    }));
}

#[test]
fn unselected_domains_cannot_create_findings() {
    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse");
    let document = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Header]))
        .expect("analyze");
    let report = diff_documents(&document, &document, &BTreeSet::new());
    assert!(report.findings.is_empty());
}

#[test]
fn cli_diff_reports_semantic_string_changes_from_snapshots() {
    use macho::analysis::{DomainPayload, DomainState};

    let bytes = macho_test_support::thin64_arm64(2);
    let container = macho::parse(&bytes).expect("parse");
    let mut old = Analyzer
        .run(&container, &AnalysisPlan::new([AnalysisDomain::Strings]))
        .expect("analyze old");
    let mut new = old.clone();
    old.slices[0].domains.insert(
        AnalysisDomain::Strings,
        DomainState::Complete {
            value: DomainPayload::Strings(serde_json::json!([
                {"value":"legacy endpoint", "va":4096, "file_offset":16}
            ])),
            issues: Vec::new(),
        },
    );
    new.slices[0].domains.insert(
        AnalysisDomain::Strings,
        DomainState::Complete {
            value: DomainPayload::Strings(serde_json::json!([
                {"value":"production endpoint", "va":8192, "file_offset":32}
            ])),
            issues: Vec::new(),
        },
    );
    let old = write_macho_fixture(
        &serde_json::to_vec(&old).expect("serialize old snapshot"),
        "diff-old-snapshot",
        false,
    );
    let new = write_macho_fixture(
        &serde_json::to_vec(&new).expect("serialize new snapshot"),
        "diff-new-snapshot",
        false,
    );

    let output = run_cli([
        "diff",
        old.path().to_str().expect("old path"),
        new.path().to_str().expect("new path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    let findings = report["data"]["findings"]
        .as_array()
        .or_else(|| report["findings"].as_array())
        .unwrap_or_else(|| panic!("findings in {report}"));
    assert_eq!(findings.len(), 2);
    assert!(
        findings
            .iter()
            .all(|finding| finding["domain"] == "strings")
    );
    assert!(findings.iter().any(|finding| {
        finding["message"]
            .as_str()
            .is_some_and(|message| message.contains("legacy endpoint"))
    }));
    assert!(findings.iter().any(|finding| {
        finding["message"]
            .as_str()
            .is_some_and(|message| message.contains("production endpoint"))
    }));
}

#[test]
fn cli_diff_accepts_the_json_envelope_emitted_by_cli_snapshot() {
    let input = write_macho_fixture(
        &macho_test_support::thin64_arm64(2),
        "diff-cli-snapshot-input",
        false,
    );
    let snapshot = run_cli([
        "snapshot",
        input.path().to_str().expect("input path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        snapshot.status.success(),
        "{}",
        String::from_utf8_lossy(&snapshot.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&snapshot.stdout).expect("snapshot envelope");
    assert_eq!(envelope["command"], "snapshot");
    assert_eq!(envelope["data"]["schema_version"], 3);

    let snapshot_path = temp_file_path("diff-cli-snapshot-envelope");
    std::fs::write(&snapshot_path, &snapshot.stdout).expect("write snapshot envelope");
    let diff = run_cli([
        "diff",
        snapshot_path.to_str().expect("snapshot path"),
        snapshot_path.to_str().expect("snapshot path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    let _ = std::fs::remove_file(snapshot_path);
    assert!(
        diff.status.success(),
        "{}",
        String::from_utf8_lossy(&diff.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&diff.stdout).expect("diff envelope");
    assert_eq!(report["data"]["findings"], serde_json::json!([]));
}

#[test]
fn cli_diff_applies_architecture_selection_to_snapshot_inputs() {
    let fat = macho_test_support::fat32(&[
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
    let input = write_macho_fixture(&fat, "diff-snapshot-arch-input", false);
    let generated = run_cli([
        "snapshot",
        input.path().to_str().expect("input path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(generated.status.success());
    let old_path = temp_file_path("diff-snapshot-arch-old");
    let new_path = temp_file_path("diff-snapshot-arch-new");
    std::fs::write(&old_path, &generated.stdout).expect("write old snapshot");

    let mut changed: serde_json::Value =
        serde_json::from_slice(&generated.stdout).expect("snapshot envelope");
    let ordinary = changed["data"]["slices"]
        .as_array_mut()
        .expect("snapshot slices")
        .iter_mut()
        .find(|slice| slice["identity"]["arch"] == "arm64")
        .expect("ordinary arm64 slice");
    ordinary["domains"]["header"]["value"]["report"]["file_type"] = serde_json::json!("MH_DYLIB");
    std::fs::write(
        &new_path,
        serde_json::to_vec(&changed).expect("serialize changed snapshot"),
    )
    .expect("write new snapshot");

    let selected = run_cli([
        "diff",
        old_path.to_str().expect("old path"),
        new_path.to_str().expect("new path"),
        "--arch",
        "arm64e",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    let _ = std::fs::remove_file(old_path);
    let _ = std::fs::remove_file(new_path);
    assert!(
        selected.status.success(),
        "{}",
        String::from_utf8_lossy(&selected.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&selected.stdout).expect("selected diff envelope");
    assert_eq!(report["data"]["findings"], serde_json::json!([]));
}
