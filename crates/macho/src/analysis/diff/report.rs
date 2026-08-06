use serde::Serialize;
use std::fmt::{self, Write as _};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
/// The ChangeSeverity type.
#[non_exhaustive]
pub enum ChangeSeverity {
    #[serde(rename = "info")]
    /// The Info variant.
    Info,
    #[serde(rename = "warning")]
    /// The Warning variant.
    Warning,
    #[serde(rename = "breaking")]
    /// The Breaking variant.
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
/// The DiffDomain type.
#[non_exhaustive]
pub enum DiffDomain {
    #[serde(rename = "container")]
    /// The Container variant.
    Container,
    #[serde(rename = "header")]
    /// The Header variant.
    Header,
    #[serde(rename = "load_commands")]
    /// The LoadCommands variant.
    LoadCommands,
    #[serde(rename = "segments")]
    /// The Segments variant.
    Segments,
    #[serde(rename = "symbols")]
    /// The Symbols variant.
    Symbols,
    #[serde(rename = "exports")]
    /// The Exports variant.
    Exports,
    #[serde(rename = "imports")]
    /// The Imports variant.
    Imports,
    #[serde(rename = "fixups")]
    /// The Fixups variant.
    Fixups,
    #[serde(rename = "relocations")]
    /// Relocation-table changes.
    Relocations,
    #[serde(rename = "strings")]
    /// Extracted string-surface changes.
    Strings,
    #[serde(rename = "ranges")]
    /// Recovered code-ownership range changes.
    Ranges,
    #[serde(rename = "xrefs")]
    /// Cross-reference relationship changes.
    Xrefs,
    #[serde(rename = "dependencies")]
    /// Dynamic-link dependency-surface changes.
    Dependencies,
    #[serde(rename = "audit")]
    /// Security audit finding changes.
    Audit,
    #[serde(rename = "swift")]
    /// Recovered Swift surface changes.
    Swift,
    #[serde(rename = "c_surface")]
    /// Recovered C ABI surface changes.
    CSurface,
    #[serde(rename = "cpp_surface")]
    /// Recovered C++ surface changes.
    CppSurface,
    #[serde(rename = "objc_headers")]
    /// Recovered Objective-C header changes.
    ObjCHeaders,
    #[serde(rename = "objc")]
    /// The ObjC variant.
    ObjC,
    #[serde(rename = "codesign")]
    /// The Codesign variant.
    Codesign,
    #[serde(rename = "analysis")]
    /// The Analysis variant.
    Analysis,
    #[serde(rename = "validation")]
    /// The Validation variant.
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
            Self::Relocations => write!(f, "relocations"),
            Self::Strings => write!(f, "strings"),
            Self::Ranges => write!(f, "ranges"),
            Self::Xrefs => write!(f, "xrefs"),
            Self::Dependencies => write!(f, "dependencies"),
            Self::Audit => write!(f, "audit"),
            Self::Swift => write!(f, "swift"),
            Self::CSurface => write!(f, "c-surface"),
            Self::CppSurface => write!(f, "cpp-surface"),
            Self::ObjCHeaders => write!(f, "objc-headers"),
            Self::ObjC => write!(f, "objc"),
            Self::Codesign => write!(f, "codesign"),
            Self::Analysis => write!(f, "analysis"),
            Self::Validation => write!(f, "validation"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The DiffFinding type.
pub struct DiffFinding {
    /// The domain field.
    pub domain: DiffDomain,
    /// The severity field.
    pub severity: ChangeSeverity,
    /// The arch field.
    pub arch: Option<String>,
    /// The message field.
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The DiffReport type.
pub struct DiffReport {
    /// The findings field.
    pub findings: Vec<DiffFinding>,
}

impl DiffReport {
    /// Performs max_severity.
    pub fn max_severity(&self) -> Option<ChangeSeverity> {
        self.findings.iter().map(|f| f.severity).max()
    }

    /// Performs has_breaking.
    pub fn has_breaking(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.severity == ChangeSeverity::Breaking)
    }

    /// Performs filter_domain.
    pub fn filter_domain(&self, domain: DiffDomain) -> Vec<&DiffFinding> {
        self.findings
            .iter()
            .filter(|f| f.domain == domain)
            .collect()
    }

    /// Performs filter_severity.
    pub fn filter_severity(&self, min: ChangeSeverity) -> Vec<&DiffFinding> {
        self.findings.iter().filter(|f| f.severity >= min).collect()
    }

    /// Performs render_text.
    pub fn render_text(&self) -> String {
        let mut output = String::new();
        if self.findings.is_empty() {
            output.push_str("No differences found.\n");
            return output;
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
            let _ = writeln!(output, "[{severity}]");
            for (domain, findings) in domains {
                let _ = writeln!(output, "  {domain}");
                for f in findings {
                    let arch = f.arch.as_deref().unwrap_or("*");
                    let _ = writeln!(output, "    [{arch}] {}", f.message);
                }
            }
            output.push('\n');
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
        let _ = writeln!(
            output,
            "\n{} finding(s): {} breaking, {} warning, {} info",
            self.findings.len(),
            breaking,
            warning,
            info
        );
        output
    }
}
