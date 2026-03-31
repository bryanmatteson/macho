pub mod rules;

use serde::Serialize;
use std::fmt;

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

fn compare_findings(a: &AuditFinding, b: &AuditFinding) -> std::cmp::Ordering {
    b.severity
        .cmp(&a.severity)
        .then_with(|| a.rule_id.cmp(b.rule_id))
        .then_with(|| a.title.cmp(&b.title))
        .then_with(|| a.body.cmp(&b.body))
        .then_with(|| a.evidence.cmp(&b.evidence))
        .then_with(|| a.remediation.cmp(&b.remediation))
}
