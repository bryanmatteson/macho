use anyhow::Result;
use macho::audit::{AuditReport, AuditSeverity};
use serde::Serialize;
use std::collections::BTreeSet;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Serialize)]
pub(crate) struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
pub(crate) struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
pub(crate) struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
pub(crate) struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRuleDescriptor>,
}

#[derive(Serialize)]
pub(crate) struct SarifRuleDescriptor {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Serialize)]
pub(crate) struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
pub(crate) struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
pub(crate) struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
pub(crate) struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
pub(crate) struct SarifMessage {
    text: String,
}

pub fn render(path: &Path, reports: &[AuditReport]) -> Result<String> {
    let uri = file_uri(path);

    let mut seen_rules = BTreeSet::new();
    let mut rule_descs = Vec::new();
    let mut results = Vec::new();

    for report in reports {
        for finding in &report.findings {
            if seen_rules.insert(finding.rule_id) {
                rule_descs.push(SarifRuleDescriptor {
                    id: finding.rule_id.to_string(),
                    short_description: SarifMessage {
                        text: finding.title.clone(),
                    },
                });
            }

            results.push(SarifResult {
                rule_id: finding.rule_id.to_string(),
                level: match finding.severity {
                    AuditSeverity::Info => "note",
                    AuditSeverity::Warning => "warning",
                    AuditSeverity::Error | AuditSeverity::Critical => "error",
                },
                message: SarifMessage {
                    text: format!("[{}] {}", report.arch, finding.title),
                },
                locations: vec![SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation { uri: uri.clone() },
                    },
                }],
            });
        }
    }

    let report = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "macho audit",
                    version: env!("CARGO_PKG_VERSION"),
                    rules: rule_descs,
                },
            },
            results,
        }],
    };

    Ok(serde_json::to_string_pretty(&report)?)
}

fn file_uri(path: &Path) -> String {
    let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let encoded = percent_encode_path(path_bytes(&resolved));

    if resolved.is_absolute() {
        format!("file://{encoded}")
    } else {
        encoded
    }
}

#[cfg(unix)]
fn path_bytes(path: &Path) -> &[u8] {
    path.as_os_str().as_bytes()
}

#[cfg(not(unix))]
fn path_bytes(path: &Path) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

fn percent_encode_path(input: impl AsRef<[u8]>) -> String {
    let input = input.as_ref();
    let mut out = String::with_capacity(input.len());
    for &byte in input {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' | b'/' | b':' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}
