use anyhow::{Context, Result};
use macho::analysis::snapshot::ContainerSnapshot;
use macho::audit::{AuditFinding, AuditReport, AuditSeverity, audit_slice};
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::commands::common::filter_snapshot_by_arch;
use crate::output::sarif;

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
    let fail_sev = args.fail_on.as_deref().map(parse_severity).transpose()?;

    let raw_reports: Vec<AuditReport> = snapshot.slices.iter().map(audit_slice).collect();
    let mut reports = raw_reports.clone();
    for report in &mut reports {
        report.findings.retain(|f| f.severity >= min_sev);
    }

    if args.sarif {
        println!("{}", sarif::render(&args.path, &reports)?);
    } else if args.json {
        print_json(&reports)?;
    } else {
        print_text(&reports);
    }

    if let Some(fail_sev) = fail_sev {
        let any_match = raw_reports
            .iter()
            .flat_map(|report| &report.findings)
            .any(|f| f.severity >= fail_sev);
        if any_match {
            anyhow::bail!(
                "audit findings reached fail threshold {fail_sev}; use --min-severity to filter output or choose a higher --fail-on value"
            );
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

fn print_text(reports: &[AuditReport]) {
    let total: usize = reports.iter().map(|report| report.findings.len()).sum();
    if total == 0 {
        println!("No audit findings.");
        return;
    }

    let mut first_arch = true;
    for report in reports {
        if report.findings.is_empty() {
            continue;
        }

        if !first_arch {
            println!();
        }
        first_arch = false;

        println!("{}", report.arch);
        let mut current_severity: Option<AuditSeverity> = None;
        for f in &report.findings {
            if current_severity != Some(f.severity) {
                if current_severity.is_some() {
                    println!();
                }
                current_severity = Some(f.severity);
                println!("  {}:", f.severity);
            }

            println!("    {}: {}", f.rule_id, f.title);
            println!("      {}", f.body);
            for e in &f.evidence {
                println!("      evidence: {e}");
            }
            if let Some(ref rem) = f.remediation {
                println!("      fix: {rem}");
            }
        }
    }

    let counts = count_severities(reports);
    println!(
        "\n{total} finding(s): {} critical, {} error, {} warning, {} info",
        counts.0, counts.1, counts.2, counts.3
    );
}

#[derive(Serialize)]
struct AuditJsonSlice<'a> {
    arch: &'a str,
    findings: &'a [AuditFinding],
}

fn print_json(reports: &[AuditReport]) -> Result<()> {
    let payload: Vec<AuditJsonSlice<'_>> = reports
        .iter()
        .map(|report| AuditJsonSlice {
            arch: &report.arch,
            findings: &report.findings,
        })
        .collect();
    println!("{}", serde_json::to_string_pretty(&payload)?);
    Ok(())
}

fn count_severities(reports: &[AuditReport]) -> (usize, usize, usize, usize) {
    let mut crit = 0;
    let mut err = 0;
    let mut warn = 0;
    let mut info = 0;
    for report in reports {
        for f in &report.findings {
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
