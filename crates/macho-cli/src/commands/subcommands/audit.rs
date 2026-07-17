use crate::analysis::audit::{AuditFinding, AuditReport, AuditSeverity};
use crate::analysis::{AnalysisDomain, Analyzer, AuditPlan, DomainPayload, DomainState};
use crate::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;

use crate::commands::output::sarif;
use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, PolicyFailure, usage_message};

#[derive(clap::Args)]
/// The AuditArgs type.
pub struct AuditArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Minimum severity to display (info, warning, error, critical)
    #[arg(long, default_value = "info")]
    min_severity: String,
    /// Exit with failure if findings reach this severity
    #[arg(long)]
    fail_on: Option<String>,
}

/// Performs run.
pub fn run(args: AuditArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    let audit_plan = AuditPlan::default().with_limits((&args.limits).into());
    let audit_plan = if let Some(ref arch) = args.selection.arch {
        audit_plan.with_slices([arch.clone()])
    } else {
        audit_plan
    };
    let plan = audit_plan.compile();
    let document = Analyzer.run(&container, &plan)?;

    let min_sev = parse_severity(&args.min_severity)?;
    let fail_sev = args.fail_on.as_deref().map(parse_severity).transpose()?;

    let raw_reports = reports_from_document(&document)?;
    let mut reports = raw_reports.clone();
    for report in &mut reports {
        report.findings.retain(|f| f.severity >= min_sev);
    }

    if format == OutputFormat::Sarif {
        let _ = writeln!(out, "{}", sarif::render(&args.input.path, &reports)?);
    } else if format == OutputFormat::Json {
        print_json(&reports, out)?;
    } else {
        print_text(&reports, out);
    }

    if let Some(fail_sev) = fail_sev {
        let any_match = raw_reports
            .iter()
            .flat_map(|report| &report.findings)
            .any(|f| f.severity >= fail_sev);
        if any_match {
            return Err(PolicyFailure(format!(
                "audit findings reached fail threshold {fail_sev}; use --min-severity to filter output or choose a higher --fail-on value"
            ))
            .into());
        }
    }

    Ok(())
}

fn reports_from_document(document: &crate::analysis::SnapshotDocument) -> Result<Vec<AuditReport>> {
    document
        .slices
        .iter()
        .map(|slice| match &slice.domains[&AnalysisDomain::Audit] {
            DomainState::Complete {
                value: DomainPayload::Audit(value),
                ..
            } => serde_json::from_value(value.clone()).map_err(Into::into),
            DomainState::Unsupported { reason } => Ok(capability_report(
                &slice.identity.arch,
                "AUDIT_UNSUPPORTED",
                &reason.message,
            )),
            DomainState::Failed { error, .. } => Ok(capability_report(
                &slice.identity.arch,
                "AUDIT_FAILED",
                &error.message,
            )),
            DomainState::NotRequested => Ok(capability_report(
                &slice.identity.arch,
                "AUDIT_NOT_REQUESTED",
                "audit domain was not requested",
            )),
            DomainState::Complete { .. } => {
                anyhow::bail!("audit domain carried a mismatched payload")
            }
            _ => anyhow::bail!("audit domain carried an unknown state"),
        })
        .collect()
}

fn capability_report(arch: &str, rule_id: &str, message: &str) -> AuditReport {
    AuditReport {
        arch: arch.to_owned(),
        findings: vec![AuditFinding {
            rule_id: rule_id.to_owned(),
            severity: AuditSeverity::Error,
            title: "Audit analysis unavailable".to_owned(),
            body: message.to_owned(),
            evidence: vec![message.to_owned()],
            remediation: None,
        }],
    }
}

fn parse_severity(s: &str) -> Result<AuditSeverity> {
    match s {
        "info" => Ok(AuditSeverity::Info),
        "warning" => Ok(AuditSeverity::Warning),
        "error" => Ok(AuditSeverity::Error),
        "critical" => Ok(AuditSeverity::Critical),
        other => Err(usage_message(format!(
            "unknown severity: {other} (use info, warning, error, or critical)"
        ))),
    }
}

fn print_text(reports: &[AuditReport], out: &mut dyn Write) {
    let total: usize = reports.iter().map(|report| report.findings.len()).sum();
    if total == 0 {
        let _ = writeln!(out, "No audit findings.");
        return;
    }

    let mut first_arch = true;
    for report in reports {
        if report.findings.is_empty() {
            continue;
        }

        if !first_arch {
            let _ = writeln!(out,);
        }
        first_arch = false;

        let _ = writeln!(out, "{}", report.arch);
        let mut current_severity: Option<AuditSeverity> = None;
        for f in &report.findings {
            if current_severity != Some(f.severity) {
                if current_severity.is_some() {
                    let _ = writeln!(out,);
                }
                current_severity = Some(f.severity);
                let _ = writeln!(out, "  {}:", f.severity);
            }

            let _ = writeln!(out, "    {}: {}", f.rule_id, f.title);
            let _ = writeln!(out, "      {}", f.body);
            for e in &f.evidence {
                let _ = writeln!(out, "      evidence: {e}");
            }
            if let Some(ref rem) = f.remediation {
                let _ = writeln!(out, "      fix: {rem}");
            }
        }
    }

    let counts = count_severities(reports);
    let _ = writeln!(
        out,
        "\n{total} finding(s): {} critical, {} error, {} warning, {} info",
        counts.0, counts.1, counts.2, counts.3
    );
}

#[derive(Serialize)]
struct AuditJsonSlice<'a> {
    arch: &'a str,
    findings: &'a [AuditFinding],
}

fn print_json(reports: &[AuditReport], out: &mut dyn Write) -> Result<()> {
    let payload: Vec<AuditJsonSlice<'_>> = reports
        .iter()
        .map(|report| AuditJsonSlice {
            arch: &report.arch,
            findings: &report.findings,
        })
        .collect();
    let _ = writeln!(out, "{}", serde_json::to_string_pretty(&payload)?);
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
                _ => warn += 1,
            }
        }
    }
    (crit, err, warn, info)
}
