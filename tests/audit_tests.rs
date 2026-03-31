use macho::analysis::snapshot::{
    CodesignSnapshot, ContainerFormat, ContainerSnapshot, FixupSnapshot, HeaderSnapshot,
    LoadCommandSnapshot, ObjCSnapshot, SegmentSnapshot, SliceSnapshot,
};
use macho::audit::{AuditSeverity, audit_slice, audit_snapshot};
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn macho_bin() -> &'static str {
    env!("CARGO_BIN_EXE_macho")
}

fn temp_file_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time went backwards")
        .as_nanos();
    std::env::temp_dir().join(format!("macho-{name}-{nanos}.bin"))
}

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

fn synthetic_audit_snapshot() -> ContainerSnapshot {
    fn slice(arch: &str, signed: bool, pie: bool) -> SliceSnapshot {
        SliceSnapshot {
            arch: arch.into(),
            header: HeaderSnapshot {
                cpu_type: arch.into(),
                cpu_subtype: "all".into(),
                file_type: "MH_EXECUTE".into(),
                flags: if pie { vec!["PIE".into()] } else { Vec::new() },
                ncmds: 0,
                uuid: None,
                platform: None,
            },
            load_commands: Vec::new(),
            segments: vec![SegmentSnapshot {
                name: "__TEXT".into(),
                vm_addr: 0x1000_0000,
                vm_size: 0x1000,
                file_offset: 0,
                file_size: 0x1000,
                max_prot: "r-x".into(),
                init_prot: "r-x".into(),
                sections: Vec::new(),
            }],
            symbols: Vec::new(),
            exports: Vec::new(),
            imports: Vec::new(),
            fixups: Vec::<FixupSnapshot>::new(),
            objc: ObjCSnapshot {
                classes: Vec::new(),
                categories: Vec::new(),
                protocols: Vec::new(),
            },
            codesign: signed.then_some(CodesignSnapshot {
                identifier: Some(format!("com.example.{arch}")),
                team_id: Some("TEAMID".into()),
                hash_type: "sha256".into(),
                has_entitlements: true,
                entitlements_xml: None,
                entitlement_keys: Vec::new(),
                has_der_entitlements: true,
                entitlements_der_fingerprint: None,
                has_cms_signature: true,
                n_code_slots: 0,
                code_limit: 0,
            }),
            analysis_issues: Vec::new(),
            diagnostics: Vec::new(),
        }
    }

    ContainerSnapshot {
        format: ContainerFormat::Fat,
        slices: vec![slice("arm64", true, true), slice("x86_64", false, false)],
    }
}

fn malformed_codesign_binary() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const MH_EXECUTE: u32 = 2;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_CODE_SIGNATURE: u32 = 0x1D;

    let code_sig_offset = 32u32 + 72 + 16;
    let code_sig_size = 8u32;
    let total_size = code_sig_offset + code_sig_size;

    let mut data = Vec::new();
    data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    data.extend_from_slice(&(CPU_TYPE_ARM64 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&MH_EXECUTE.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&88u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    data.extend_from_slice(&segname);
    data.extend_from_slice(&0x1000_0000u64.to_le_bytes());
    data.extend_from_slice(&0x1000u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&(total_size as u64).to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    data.extend_from_slice(&16u32.to_le_bytes());
    data.extend_from_slice(&code_sig_offset.to_le_bytes());
    data.extend_from_slice(&code_sig_size.to_le_bytes());
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 1, 2, 3]);

    data
}

fn malformed_codesign_snapshot() -> ContainerSnapshot {
    let data = malformed_codesign_binary();
    let container = macho::parse(&data).expect("parse malformed codesign binary");
    ContainerSnapshot::from_container(&container)
}

fn dylib_path_snapshot(command: &str, path: &str) -> SliceSnapshot {
    SliceSnapshot {
        arch: "arm64".into(),
        header: HeaderSnapshot {
            cpu_type: "arm64".into(),
            cpu_subtype: "all".into(),
            file_type: "MH_EXECUTE".into(),
            flags: vec!["PIE".into()],
            ncmds: 1,
            uuid: None,
            platform: None,
        },
        load_commands: vec![LoadCommandSnapshot {
            name: command.into(),
            summary: path.into(),
            fileset_entry: None,
        }],
        segments: vec![
            SegmentSnapshot {
                name: "__PAGEZERO".into(),
                vm_addr: 0,
                vm_size: 0x1000,
                file_offset: 0,
                file_size: 0,
                max_prot: "---".into(),
                init_prot: "---".into(),
                sections: Vec::new(),
            },
            SegmentSnapshot {
                name: "__TEXT".into(),
                vm_addr: 0x1000_0000,
                vm_size: 0x1000,
                file_offset: 0,
                file_size: 0x1000,
                max_prot: "r-x".into(),
                init_prot: "r-x".into(),
                sections: Vec::new(),
            },
        ],
        symbols: Vec::new(),
        exports: Vec::new(),
        imports: Vec::new(),
        fixups: Vec::<FixupSnapshot>::new(),
        objc: ObjCSnapshot {
            classes: Vec::new(),
            categories: Vec::new(),
            protocols: Vec::new(),
        },
        codesign: None,
        analysis_issues: Vec::new(),
        diagnostics: Vec::new(),
    }
}

fn write_malformed_codesign_fixture() -> PathBuf {
    let path = temp_file_path("audit-fixture");
    let data = malformed_codesign_binary();
    std::fs::write(&path, data).expect("write malformed binary");
    path
}

fn write_relative_malformed_codesign_fixture() -> (PathBuf, PathBuf) {
    let cwd = std::env::current_dir().expect("current dir");
    let path = cwd
        .join("target")
        .join("audit-fixtures")
        .join(format!("audit relative {}.bin", std::process::id()));
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture dir");
    }
    std::fs::write(&path, malformed_codesign_binary()).expect("write malformed binary");
    let relative = path
        .strip_prefix(&cwd)
        .expect("relative path")
        .to_path_buf();
    (path, relative)
}

#[test]
fn audit_system_binary_no_critical() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let report = audit_slice(slice);
        let critical: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.severity == AuditSeverity::Critical)
            .collect();
        assert!(
            critical.is_empty(),
            "system binary should have no critical findings, got: {:?}",
            critical.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
    }
}

#[test]
fn audit_findings_have_rule_ids() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let report = audit_slice(slice);
        for finding in &report.findings {
            assert!(
                !finding.rule_id.is_empty(),
                "every finding must have a rule_id"
            );
            assert!(!finding.title.is_empty(), "every finding must have a title");
        }
    }
}

#[test]
fn audit_system_binary_detects_no_team_id() {
    // Apple system binaries are Apple-signed (no team ID)
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let report = audit_slice(slice);
        let cs004: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "CS004")
            .collect();
        // CS004 = missing team ID (Apple system binaries have CMS but no team ID)
        assert!(
            !cs004.is_empty(),
            "expected CS004 (missing team ID) for Apple system binary"
        );
    }
}

#[test]
fn audit_system_binary_pie_present() {
    // System executables should have PIE
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let report = audit_slice(slice);
        let mem002: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "MEM002")
            .collect();
        assert!(mem002.is_empty(), "system binary should have PIE flag set");
    }
}

#[test]
fn audit_system_binary_no_wx() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let report = audit_slice(slice);
        let mem001: Vec<_> = report
            .findings
            .iter()
            .filter(|f| f.rule_id == "MEM001")
            .collect();
        assert!(
            mem001.is_empty(),
            "system binary should have no W+X segments"
        );
    }
}

#[test]
fn audit_findings_sorted_by_severity() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let report = audit_slice(slice);
        for window in report.findings.windows(2) {
            assert!(
                window[0].severity >= window[1].severity,
                "findings should be sorted by severity (descending)"
            );
        }
    }
}

#[test]
fn audit_severity_ordering() {
    assert!(AuditSeverity::Info < AuditSeverity::Warning);
    assert!(AuditSeverity::Warning < AuditSeverity::Error);
    assert!(AuditSeverity::Error < AuditSeverity::Critical);
}

#[test]
fn audit_max_severity() {
    let snap = snapshot_for("/usr/bin/true");
    let slice = &snap.slices[0];
    let report = audit_slice(slice);
    if !report.findings.is_empty() {
        assert!(report.max_severity().is_some());
    }
}

#[test]
fn audit_finding_serializes_to_json() {
    let snap = snapshot_for("/usr/bin/true");
    let slice = &snap.slices[0];
    let report = audit_slice(slice);
    let json = serde_json::to_string(&report.findings).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed.is_array());
}

#[test]
fn audit_reports_unreadable_code_signature_instead_of_unsigned() {
    let snap = malformed_codesign_snapshot();
    let slice = &snap.slices[0];
    let report = audit_slice(slice);

    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CS000"),
        "expected CS000 for unreadable signature, got: {:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, &finding.title))
            .collect::<Vec<_>>()
    );
    assert!(
        report
            .findings
            .iter()
            .all(|finding| finding.rule_id != "CS001"),
        "malformed signature should not be reported as unsigned"
    );
}

#[test]
fn audit_json_cli_filters_and_serializes_lowercase_severity() {
    let path = write_malformed_codesign_fixture();

    let output = Command::new(macho_bin())
        .args([
            "audit",
            "--json",
            "--min-severity",
            "error",
            path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run macho audit --json");

    let _ = std::fs::remove_file(&path);

    assert!(output.status.success(), "audit command failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let slices = payload.as_array().expect("top-level array");
    assert_eq!(slices.len(), 1);

    let findings = slices[0]["findings"].as_array().expect("findings array");
    assert!(
        !findings.is_empty(),
        "expected at least one finding in JSON output"
    );

    for finding in findings {
        let severity = finding["severity"].as_str().expect("severity string");
        assert!(
            matches!(severity, "error" | "critical"),
            "min-severity filtering should remove warnings/info, got {severity}"
        );
        assert!(
            !finding["rule_id"]
                .as_str()
                .expect("rule_id string")
                .is_empty()
        );
    }
}

#[test]
fn audit_sarif_cli_emits_machine_readable_document() {
    let path = write_malformed_codesign_fixture();

    let output = Command::new(macho_bin())
        .args([
            "audit",
            "--sarif",
            "--min-severity",
            "error",
            path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run macho audit --sarif");

    let _ = std::fs::remove_file(&path);

    assert!(output.status.success(), "audit command failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(sarif["runs"][0]["tool"]["driver"]["name"], "macho audit");

    let rules = sarif["runs"][0]["tool"]["driver"]["rules"]
        .as_array()
        .expect("rules array");
    assert!(
        !rules.is_empty(),
        "expected at least one SARIF rule descriptor"
    );

    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("results array");
    assert!(
        !results.is_empty(),
        "expected SARIF results for malformed binary"
    );

    for result in results {
        assert_eq!(result["level"], "error");
        assert!(result["ruleId"].is_string());
        assert!(result["message"]["text"].is_string());
        assert!(
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                .as_str()
                .expect("uri string")
                .starts_with("file://")
        );
    }
}

#[test]
fn audit_fail_on_exits_nonzero_after_emitting_json_output() {
    let path = write_malformed_codesign_fixture();

    let output = Command::new(macho_bin())
        .args([
            "audit",
            "--json",
            "--fail-on",
            "error",
            path.to_str().expect("utf8 path"),
        ])
        .output()
        .expect("run macho audit --json --fail-on");

    let _ = std::fs::remove_file(&path);

    assert!(
        !output.status.success(),
        "audit command should fail when threshold is met"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let payload: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert!(
        payload.as_array().is_some(),
        "stdout should still contain the JSON report"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("audit findings reached fail threshold"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn audit_sarif_cli_encodes_file_uri() {
    let path = temp_file_path("audit sarif uri");
    std::fs::write(&path, malformed_codesign_binary()).expect("write malformed binary");

    let output = Command::new(macho_bin())
        .args(["audit", "--sarif", path.to_str().expect("utf8 path")])
        .output()
        .expect("run macho audit --sarif");

    let _ = std::fs::remove_file(&path);

    assert!(output.status.success(), "audit command failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    let uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .expect("uri string");
    let message = sarif["runs"][0]["results"][0]["message"]["text"]
        .as_str()
        .expect("message text");

    assert!(
        uri.starts_with("file:///"),
        "expected file URI for absolute path, got {uri}"
    );
    assert!(
        !uri.contains(' '),
        "SARIF URI must be percent-encoded, got {uri}"
    );
    assert!(
        uri.contains("%20"),
        "expected spaces to be percent-encoded in SARIF URI, got {uri}"
    );
    assert!(
        message.contains("Evidence:"),
        "expected SARIF message to preserve finding evidence, got {message}"
    );
}

#[test]
fn audit_fail_on_invalid_severity_fails_before_printing_output() {
    let output = Command::new(macho_bin())
        .args([
            "audit",
            "--json",
            "--fail-on",
            "definitely_not_real",
            "/usr/bin/true",
        ])
        .output()
        .expect("run macho audit with invalid fail-on");

    assert!(
        !output.status.success(),
        "audit command should fail for invalid severity"
    );

    assert!(
        String::from_utf8_lossy(&output.stdout).is_empty(),
        "command should not emit output before validating fail-on"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown severity: definitely_not_real"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn audit_sarif_cli_canonicalizes_relative_input_paths() {
    let (abs, rel) = write_relative_malformed_codesign_fixture();

    let output = Command::new(macho_bin())
        .args(["audit", "--sarif", rel.to_str().expect("utf8 path")])
        .output()
        .expect("run macho audit --sarif on relative path");

    let _ = std::fs::remove_file(&abs);

    assert!(output.status.success(), "audit command failed");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let sarif: serde_json::Value = serde_json::from_str(&stdout).expect("valid SARIF JSON");
    let uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
        ["artifactLocation"]["uri"]
        .as_str()
        .expect("uri string");

    assert!(
        uri.starts_with("file:///"),
        "expected canonical absolute file URI, got {uri}"
    );
    assert!(
        uri.contains("audit-fixtures"),
        "expected canonicalized file URI to include the relative fixture path, got {uri}"
    );
}

#[test]
fn audit_snapshot_reports_cross_arch_security_drift() {
    let reports = audit_snapshot(&synthetic_audit_snapshot());
    let container_report = reports
        .iter()
        .find(|report| report.arch == "container")
        .expect("expected container-level audit report");

    assert!(
        container_report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "CTR002"),
        "expected cross-arch drift finding: {:?}",
        container_report.findings
    );
    assert!(
        container_report.findings[0]
            .evidence
            .iter()
            .any(|evidence| evidence.contains("code signature differs")),
        "expected code-signature drift evidence: {:?}",
        container_report.findings[0].evidence
    );
}

#[test]
fn audit_flags_absolute_reexport_dylib_paths() {
    let report = audit_slice(&dylib_path_snapshot(
        "LC_REEXPORT_DYLIB",
        "/opt/acme/libWidget.dylib",
    ));

    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.rule_id == "LP003"),
        "expected LP003 for reexport dylib path, got: {:?}",
        report
            .findings
            .iter()
            .map(|finding| (&finding.rule_id, &finding.title))
            .collect::<Vec<_>>()
    );
}
