pub mod rules;

use serde::Serialize;
use std::fmt;

use crate::analysis::snapshot::ContainerSnapshot;
use crate::analysis::snapshot::SliceSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AuditSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl fmt::Display for AuditSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Error => write!(f, "error"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct AuditContext<'a> {
    pub slice: &'a SliceSnapshot,
}

impl<'a> AuditContext<'a> {
    pub fn new(slice: &'a SliceSnapshot) -> Self {
        Self { slice }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub rule_id: &'static str,
    pub severity: AuditSeverity,
    pub title: String,
    pub body: String,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
}

pub type RulePack = Vec<Box<dyn AuditRule>>;

pub trait AuditRule {
    fn id(&self) -> &'static str;
    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>);
}

#[derive(Debug, Clone, Serialize)]
pub struct AuditReport {
    pub arch: String,
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    pub fn max_severity(&self) -> Option<AuditSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

pub fn audit_slice(slice: &SliceSnapshot) -> AuditReport {
    let mut findings = Vec::new();
    let _context = AuditContext::new(slice);
    let rule_set: RulePack = rules::all_rules();

    for rule in &rule_set {
        rule.run(slice, &mut findings);
    }

    findings.sort_by(compare_findings);

    AuditReport {
        arch: slice.arch.clone(),
        findings,
    }
}

pub fn audit_snapshot(snapshot: &ContainerSnapshot) -> Vec<AuditReport> {
    let mut reports: Vec<AuditReport> = snapshot.slices.iter().map(audit_slice).collect();
    if let Some(container_report) = audit_container(snapshot) {
        reports.push(container_report);
    }
    reports
}

fn audit_container(snapshot: &ContainerSnapshot) -> Option<AuditReport> {
    if snapshot.slices.len() < 2 {
        return None;
    }

    let mut findings = Vec::new();
    let first = &snapshot.slices[0];
    let baseline = SecurityPosture::from_slice(first);

    for slice in &snapshot.slices[1..] {
        let posture = SecurityPosture::from_slice(slice);
        let mut evidence = Vec::new();

        collect_drift(
            &mut evidence,
            "code signature",
            baseline.signed,
            posture.signed,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_drift(
            &mut evidence,
            "entitlements",
            baseline.has_entitlements,
            posture.has_entitlements,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_drift(
            &mut evidence,
            "CMS signature",
            baseline.has_cms_signature,
            posture.has_cms_signature,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_drift(
            &mut evidence,
            "team ID",
            baseline.has_team_id,
            posture.has_team_id,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_drift(
            &mut evidence,
            "PIE",
            baseline.has_pie,
            posture.has_pie,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_drift(
            &mut evidence,
            "__PAGEZERO",
            baseline.has_pagezero,
            posture.has_pagezero,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_drift(
            &mut evidence,
            "stack execution allowance",
            baseline.allows_stack_execution,
            posture.allows_stack_execution,
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_option_drift(
            &mut evidence,
            "identifier",
            baseline.identifier.as_deref(),
            posture.identifier.as_deref(),
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_option_drift(
            &mut evidence,
            "hash type",
            baseline.hash_type.as_deref(),
            posture.hash_type.as_deref(),
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_option_drift(
            &mut evidence,
            "DER entitlements fingerprint",
            baseline.der_fingerprint.as_deref(),
            posture.der_fingerprint.as_deref(),
            first.arch.as_str(),
            slice.arch.as_str(),
        );
        collect_set_drift(
            &mut evidence,
            "entitlement keys",
            &baseline.entitlement_keys,
            &posture.entitlement_keys,
            first.arch.as_str(),
            slice.arch.as_str(),
        );

        if !evidence.is_empty() {
            findings.push(AuditFinding {
                rule_id: "CTR002",
                severity: AuditSeverity::Warning,
                title: "security posture differs across architectures".into(),
                body: "Security-relevant metadata should stay aligned across slices in a multi-arch container. Divergence can hide regressions that only affect one architecture.".into(),
                evidence,
                remediation: Some(
                    "Rebuild all slices with the same signing, entitlement, and hardening settings".into(),
                ),
            });
        }
    }

    if findings.is_empty() {
        None
    } else {
        findings.sort_by(compare_findings);
        Some(AuditReport {
            arch: "container".into(),
            findings,
        })
    }
}

#[derive(Debug, Clone)]
struct SecurityPosture {
    signed: bool,
    identifier: Option<String>,
    has_entitlements: bool,
    entitlement_keys: Vec<String>,
    der_fingerprint: Option<String>,
    has_cms_signature: bool,
    has_team_id: bool,
    hash_type: Option<String>,
    has_pie: bool,
    has_pagezero: bool,
    allows_stack_execution: bool,
}

impl SecurityPosture {
    fn from_slice(slice: &SliceSnapshot) -> Self {
        let codesign = slice.codesign.as_ref();
        Self {
            signed: codesign.is_some(),
            identifier: codesign.and_then(|cs| cs.identifier.clone()),
            has_entitlements: codesign.map(|cs| cs.has_entitlements).unwrap_or(false),
            entitlement_keys: codesign
                .map(|cs| cs.entitlement_keys.clone())
                .unwrap_or_default(),
            der_fingerprint: codesign.and_then(|cs| cs.entitlements_der_fingerprint.clone()),
            has_cms_signature: codesign.map(|cs| cs.has_cms_signature).unwrap_or(false),
            has_team_id: codesign.and_then(|cs| cs.team_id.as_ref()).is_some(),
            hash_type: codesign.map(|cs| cs.hash_type.clone()),
            has_pie: slice.header.flags.iter().any(|flag| flag == "PIE"),
            has_pagezero: slice
                .segments
                .iter()
                .any(|segment| segment.name == "__PAGEZERO" && segment.vm_size > 0),
            allows_stack_execution: slice
                .header
                .flags
                .iter()
                .any(|flag| flag == "ALLOW_STACK_EXECUTION"),
        }
    }
}

fn collect_drift(
    evidence: &mut Vec<String>,
    label: &str,
    left: bool,
    right: bool,
    left_arch: &str,
    right_arch: &str,
) {
    if left != right {
        evidence.push(format!(
            "{label} differs: {left_arch}={left}, {right_arch}={right}"
        ));
    }
}

fn collect_option_drift(
    evidence: &mut Vec<String>,
    label: &str,
    left: Option<&str>,
    right: Option<&str>,
    left_arch: &str,
    right_arch: &str,
) {
    if left != right {
        evidence.push(format!(
            "{label} differs: {left_arch}={}, {right_arch}={}",
            left.unwrap_or("none"),
            right.unwrap_or("none")
        ));
    }
}

fn collect_set_drift(
    evidence: &mut Vec<String>,
    label: &str,
    left: &[String],
    right: &[String],
    left_arch: &str,
    right_arch: &str,
) {
    if left != right {
        let left = if left.is_empty() {
            "none".to_string()
        } else {
            left.join(", ")
        };
        let right = if right.is_empty() {
            "none".to_string()
        } else {
            right.join(", ")
        };
        evidence.push(format!(
            "{label} differs: {left_arch}=[{left}], {right_arch}=[{right}]"
        ));
    }
}

fn compare_findings(a: &AuditFinding, b: &AuditFinding) -> std::cmp::Ordering {
    b.severity
        .cmp(&a.severity)
        .then_with(|| a.rule_id.cmp(b.rule_id))
        .then_with(|| a.title.cmp(&b.title))
        .then_with(|| a.body.cmp(&b.body))
        .then_with(|| a.evidence.cmp(&b.evidence))
        .then_with(|| a.remediation.cmp(&b.remediation))
}
