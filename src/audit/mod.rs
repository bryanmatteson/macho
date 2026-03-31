pub mod rules;

use serde::Serialize;
use std::fmt;

use crate::analysis::snapshot::SliceSnapshot;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
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

#[derive(Debug, Clone, Serialize)]
pub struct AuditFinding {
    pub rule_id: &'static str,
    pub severity: AuditSeverity,
    pub title: String,
    pub body: String,
    pub evidence: Vec<String>,
    pub remediation: Option<String>,
}

pub trait AuditRule {
    fn id(&self) -> &'static str;
    fn run(&self, slice: &SliceSnapshot, findings: &mut Vec<AuditFinding>);
}

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
    let rule_set: Vec<Box<dyn AuditRule>> = rules::all_rules();

    for rule in &rule_set {
        rule.run(slice, &mut findings);
    }

    findings.sort_by(|a, b| b.severity.cmp(&a.severity));

    AuditReport {
        arch: slice.arch.clone(),
        findings,
    }
}
