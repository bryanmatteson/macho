use macho::analysis::snapshot::ContainerSnapshot;
use macho::audit::{AuditSeverity, audit_slice};

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

fn malformed_codesign_snapshot() -> ContainerSnapshot {
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

    let container = macho::parse(&data).expect("parse malformed codesign binary");
    ContainerSnapshot::from_container(&container)
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
