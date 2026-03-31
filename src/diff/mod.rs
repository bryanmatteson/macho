mod compare;

pub use compare::{diff_containers, diff_slice_snapshots};

use serde::Serialize;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum ChangeSeverity {
    Info,
    Warning,
    Breaking,
}

impl fmt::Display for ChangeSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "info"),
            Self::Warning => write!(f, "warning"),
            Self::Breaking => write!(f, "breaking"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub enum DiffDomain {
    Container,
    Header,
    LoadCommands,
    Segments,
    Symbols,
    Exports,
    Imports,
    Fixups,
    ObjC,
    Codesign,
    Analysis,
    Validation,
}

impl fmt::Display for DiffDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Container => write!(f, "container"),
            Self::Header => write!(f, "header"),
            Self::LoadCommands => write!(f, "load-commands"),
            Self::Segments => write!(f, "segments"),
            Self::Symbols => write!(f, "symbols"),
            Self::Exports => write!(f, "exports"),
            Self::Imports => write!(f, "imports"),
            Self::Fixups => write!(f, "fixups"),
            Self::ObjC => write!(f, "objc"),
            Self::Codesign => write!(f, "codesign"),
            Self::Analysis => write!(f, "analysis"),
            Self::Validation => write!(f, "validation"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffFinding {
    pub domain: DiffDomain,
    pub severity: ChangeSeverity,
    pub arch: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffReport {
    pub findings: Vec<DiffFinding>,
}

impl DiffReport {
    pub fn max_severity(&self) -> Option<ChangeSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    pub fn has_breaking(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == ChangeSeverity::Breaking)
    }

    pub fn filter_domain(&self, domain: DiffDomain) -> Vec<&DiffFinding> {
        self.findings
            .iter()
            .filter(|f| f.domain == domain)
            .collect()
    }

    pub fn filter_severity(&self, min: ChangeSeverity) -> Vec<&DiffFinding> {
        self.findings.iter().filter(|f| f.severity >= min).collect()
    }

    pub fn print_text(&self) {
        if self.findings.is_empty() {
            println!("No differences found.");
            return;
        }

        let mut grouped: std::collections::BTreeMap<
            ChangeSeverity,
            std::collections::BTreeMap<DiffDomain, Vec<&DiffFinding>>,
        > = std::collections::BTreeMap::new();
        for finding in &self.findings {
            grouped
                .entry(finding.severity)
                .or_default()
                .entry(finding.domain)
                .or_default()
                .push(finding);
        }

        for severity in [
            ChangeSeverity::Breaking,
            ChangeSeverity::Warning,
            ChangeSeverity::Info,
        ] {
            let Some(domains) = grouped.get(&severity) else {
                continue;
            };
            println!("[{severity}]");
            for (domain, findings) in domains {
                println!("  {domain}");
                for f in findings {
                    let arch = f.arch.as_deref().unwrap_or("*");
                    println!("    [{arch}] {}", f.message);
                }
            }
            println!();
        }

        let breaking = self
            .findings
            .iter()
            .filter(|f| f.severity == ChangeSeverity::Breaking)
            .count();
        let warning = self
            .findings
            .iter()
            .filter(|f| f.severity == ChangeSeverity::Warning)
            .count();
        let info = self
            .findings
            .iter()
            .filter(|f| f.severity == ChangeSeverity::Info)
            .count();
        println!(
            "\n{} finding(s): {} breaking, {} warning, {} info",
            self.findings.len(),
            breaking,
            warning,
            info
        );
    }
}
