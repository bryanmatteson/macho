/// The rules module.
pub mod rules;

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

use crate::analysis::AnalysisIssue;
use crate::analysis::snapshot::{
    CodesignSnapshot, HeaderSnapshot, LoadCommandSnapshot, SegmentSnapshot,
};

/// Minimal owned domain input consumed by audit rules.
#[derive(Debug, Clone)]
pub struct AuditInput {
    /// Selected architecture name.
    pub arch: String,
    /// Parsed header facts.
    pub header: Option<HeaderSnapshot>,
    /// Parsed load-command facts.
    pub load_commands: Option<Vec<LoadCommandSnapshot>>,
    /// Parsed segment facts.
    pub segments: Option<Vec<SegmentSnapshot>>,
    /// Parsed code-signing facts, if present.
    pub codesign: Option<CodesignSnapshot>,
    /// Problems encountered while collecting advisory audit facts.
    pub analysis_issues: Vec<AnalysisIssue>,
    /// Stable IDs of rules selected by the compiled audit plan.
    pub enabled_rules: BTreeSet<String>,
}

impl AuditInput {
    /// Header facts when at least one enabled rule requested them.
    pub fn header(&self) -> Option<&HeaderSnapshot> {
        self.header.as_ref()
    }

    /// Load-command facts requested by the enabled rule set.
    pub fn load_commands(&self) -> &[LoadCommandSnapshot] {
        self.load_commands.as_deref().unwrap_or_default()
    }

    /// Segment facts requested by the enabled rule set.
    pub fn segments(&self) -> &[SegmentSnapshot] {
        self.segments.as_deref().unwrap_or_default()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
/// The AuditSeverity type.
#[non_exhaustive]
pub enum AuditSeverity {
    /// The Info variant.
    Info,
    /// The Warning variant.
    Warning,
    /// The Error variant.
    Error,
    /// The Critical variant.
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
/// The AuditContext type.
pub struct AuditContext<'a> {
    /// The slice field.
    pub slice: &'a AuditInput,
}

impl<'a> AuditContext<'a> {
    /// Performs new.
    pub fn new(slice: &'a AuditInput) -> Self {
        Self { slice }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The AuditFinding type.
pub struct AuditFinding {
    /// The rule_id field.
    pub rule_id: String,
    /// The severity field.
    pub severity: AuditSeverity,
    /// The title field.
    pub title: String,
    /// The body field.
    pub body: String,
    /// The evidence field.
    pub evidence: Vec<String>,
    /// The remediation field.
    pub remediation: Option<String>,
}

/// The RulePack type.
pub type RulePack = Vec<Box<dyn AuditRule>>;

/// The AuditRule type.
pub trait AuditRule {
    /// Performs id.
    fn id(&self) -> &'static str;
    /// Performs run.
    fn run(&self, slice: &AuditInput, findings: &mut Vec<AuditFinding>);
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The AuditReport type.
pub struct AuditReport {
    /// The arch field.
    pub arch: String,
    /// The findings field.
    pub findings: Vec<AuditFinding>,
}

impl AuditReport {
    /// Performs max_severity.
    pub fn max_severity(&self) -> Option<AuditSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// Performs audit_slice.
pub fn audit_slice(slice: &AuditInput) -> AuditReport {
    let mut findings = Vec::new();
    let _context = AuditContext::new(slice);
    let rule_set: RulePack = rules::all_rules();

    for rule in &rule_set {
        if !slice.enabled_rules.contains(rule.id()) {
            continue;
        }
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
        .then_with(|| a.rule_id.cmp(&b.rule_id))
        .then_with(|| a.title.cmp(&b.title))
        .then_with(|| a.body.cmp(&b.body))
        .then_with(|| a.evidence.cmp(&b.evidence))
        .then_with(|| a.remediation.cmp(&b.remediation))
}
