use anyhow::{Context, Result};
use macho::analysis::snapshot::ContainerSnapshot;
use macho::audit::{AuditFinding, AuditSeverity, audit_slice};
use serde::Serialize;
use std::path::{Path, PathBuf};
use std::process;

use crate::commands::common::filter_snapshot_by_arch;

#[derive(clap::Args)]
pub struct AuditArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long, conflicts_with = "sarif")]
    json: bool,
    /// Output as SARIF
    #[arg(long, conflicts_with = "json")]
    sarif: bool,
    /// Minimum severity to display (info, warning, error, critical)
    #[arg(long, default_value = "info")]
    min_severity: String,
    /// Exit with failure if findings reach this severity
    #[arg(long)]
    fail_on: Option<String>,
}

pub fn run(args: AuditArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    let mut snapshot = ContainerSnapshot::from_container(&container);
    if let Some(ref filter) = args.arch {
        filter_snapshot_by_arch(&mut snapshot, filter, Path::new(&args.path))?;
    }

    let min_sev = parse_severity(&args.min_severity)?;

    let mut all_findings: Vec<(String, Vec<AuditFinding>)> = Vec::new();
    for slice in &snapshot.slices {
        let report = audit_slice(slice);
        let filtered: Vec<AuditFinding> = report
            .findings
            .into_iter()
            .filter(|f| f.severity >= min_sev)
            .collect();
        if !filtered.is_empty() {
            all_findings.push((slice.arch.clone(), filtered));
        }
    }

    if args.sarif {
        print_sarif(&args.path, &all_findings)?;
    } else if args.json {
        print_json(&all_findings)?;
    } else {
        print_text(&all_findings);
    }

    if let Some(ref threshold) = args.fail_on {
        let fail_sev = parse_severity(threshold)?;
        let any_match = all_findings
            .iter()
            .flat_map(|(_, findings)| findings)
            .any(|f| f.severity >= fail_sev);
        if any_match {
            process::exit(1);
        }
    }

    Ok(())
}

fn parse_severity(s: &str) -> Result<AuditSeverity> {
    match s {
        "info" => Ok(AuditSeverity::Info),
        "warning" => Ok(AuditSeverity::Warning),
        "error" => Ok(AuditSeverity::Error),
        "critical" => Ok(AuditSeverity::Critical),
        other => anyhow::bail!("unknown severity: {other} (use info, warning, error, or critical)"),
    }
}

fn print_text(all: &[(String, Vec<AuditFinding>)]) {
    let total: usize = all.iter().map(|(_, f)| f.len()).sum();
    if total == 0 {
        println!("No audit findings.");
        return;
    }

    for (arch, findings) in all {
        for f in findings {
            println!("[{:>8}] [{arch}] {}: {}", f.severity, f.rule_id, f.title);
            if !f.evidence.is_empty() {
                for e in &f.evidence {
                    println!("           evidence: {e}");
                }
            }
            if let Some(ref rem) = f.remediation {
                println!("           fix: {rem}");
            }
        }
    }

    let counts = count_severities(all);
    println!(
        "\n{total} finding(s): {} critical, {} error, {} warning, {} info",
        counts.0, counts.1, counts.2, counts.3
    );
}

fn print_json(all: &[(String, Vec<AuditFinding>)]) -> Result<()> {
    let mut map = serde_json::Map::new();
    for (arch, findings) in all {
        map.insert(arch.clone(), serde_json::to_value(findings)?);
    }
    if map.len() == 1 {
        let (_, val) = map.into_iter().next().unwrap();
        println!("{}", serde_json::to_string_pretty(&val)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&map)?);
    }
    Ok(())
}

#[derive(Serialize)]
struct SarifReport {
    #[serde(rename = "$schema")]
    schema: &'static str,
    version: &'static str,
    runs: Vec<SarifRun>,
}

#[derive(Serialize)]
struct SarifRun {
    tool: SarifTool,
    results: Vec<SarifResult>,
}

#[derive(Serialize)]
struct SarifTool {
    driver: SarifDriver,
}

#[derive(Serialize)]
struct SarifDriver {
    name: &'static str,
    version: &'static str,
    rules: Vec<SarifRuleDescriptor>,
}

#[derive(Serialize)]
struct SarifRuleDescriptor {
    id: String,
    #[serde(rename = "shortDescription")]
    short_description: SarifMessage,
}

#[derive(Serialize)]
struct SarifResult {
    #[serde(rename = "ruleId")]
    rule_id: String,
    level: &'static str,
    message: SarifMessage,
    locations: Vec<SarifLocation>,
}

#[derive(Serialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    artifact_location: SarifArtifactLocation,
}

#[derive(Serialize)]
struct SarifArtifactLocation {
    uri: String,
}

#[derive(Serialize)]
struct SarifMessage {
    text: String,
}

fn print_sarif(path: &Path, all: &[(String, Vec<AuditFinding>)]) -> Result<()> {
    let raw_path = path.display().to_string();
    let uri = if raw_path.starts_with('/') {
        format!("file://{raw_path}")
    } else {
        raw_path
    };
    let mut seen_rules = std::collections::BTreeSet::new();
    let mut rule_descs = Vec::new();
    let mut results = Vec::new();

    for (arch, findings) in all {
        for f in findings {
            if seen_rules.insert(f.rule_id) {
                rule_descs.push(SarifRuleDescriptor {
                    id: f.rule_id.to_string(),
                    short_description: SarifMessage {
                        text: f.title.clone(),
                    },
                });
            }
            results.push(SarifResult {
                rule_id: f.rule_id.to_string(),
                level: match f.severity {
                    AuditSeverity::Info => "note",
                    AuditSeverity::Warning => "warning",
                    AuditSeverity::Error | AuditSeverity::Critical => "error",
                },
                message: SarifMessage {
                    text: format!("[{arch}] {}", f.title),
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

    let json = serde_json::to_string_pretty(&report)?;
    println!("{json}");
    Ok(())
}

fn count_severities(all: &[(String, Vec<AuditFinding>)]) -> (usize, usize, usize, usize) {
    let mut crit = 0;
    let mut err = 0;
    let mut warn = 0;
    let mut info = 0;
    for (_, findings) in all {
        for f in findings {
            match f.severity {
                AuditSeverity::Critical => crit += 1,
                AuditSeverity::Error => err += 1,
                AuditSeverity::Warning => warn += 1,
                AuditSeverity::Info => info += 1,
            }
        }
    }
    (crit, err, warn, info)
}
