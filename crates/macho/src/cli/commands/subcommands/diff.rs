use crate::cli::analysis::diff::{ChangeSeverity, diff_documents};
use crate::cli::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DiffPlan, SnapshotDocument};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::cli::commands::args::{AnalysisLimitArgs, ArchitectureArgs};
use crate::cli::commands::subcommands::common::read_input;
use crate::cli::commands::{OutputFormat, PolicyFailure, usage_message};

#[derive(clap::Args)]
/// Compare binary structure, link behavior, security posture, references, and
/// recovered C, C++, Objective-C, and Swift surfaces. Findings are attributed
/// to their architecture and semantic domain; reordered evidence alone is not
/// a change.
pub struct DiffArgs {
    /// Path to the old (baseline) Mach-O binary
    old: PathBuf,
    /// Path to the new Mach-O binary
    new: PathBuf,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Exit with failure if findings reach this severity (info, warning, breaking)
    #[arg(long)]
    fail_on: Option<String>,
    /// Ignore code-signing differences
    #[arg(long)]
    ignore_codesign: bool,
    /// Ignore ObjC differences
    #[arg(long)]
    ignore_objc: bool,
    /// Ignore symbol differences
    #[arg(long)]
    ignore_symbols: bool,
}

/// Performs run.
pub fn run(args: DiffArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mut diff_plan = DiffPlan::default();
    if args.ignore_codesign {
        diff_plan = diff_plan.exclude(AnalysisDomain::Codesign);
    }
    if args.ignore_objc {
        diff_plan = diff_plan
            .exclude(AnalysisDomain::Objc)
            .exclude(AnalysisDomain::ObjcHeaders);
    }
    if args.ignore_symbols {
        diff_plan = diff_plan.exclude(AnalysisDomain::Symbols);
    }
    if let Some(ref arch) = args.selection.arch {
        diff_plan = diff_plan.with_slices([arch.clone()]);
    }
    diff_plan = diff_plan.with_limits((&args.limits).into());
    let analysis_plan = diff_plan.compile();
    let selector = args.selection.arch.as_deref();
    let old_snap = load_document(&args.old, &analysis_plan, selector)?;
    let new_snap = load_document(&args.new, &analysis_plan, selector)?;
    let report = diff_documents(&old_snap, &new_snap, diff_plan.selected_domains());

    if format == OutputFormat::Json {
        crate::cli::commands::output::json::write_pretty(out, &report)?;
    } else {
        write!(out, "{}", report.render_text())?;
    }

    // Exit code based on --fail-on
    if let Some(ref threshold) = args.fail_on {
        let min_severity = match threshold.as_str() {
            "info" => ChangeSeverity::Info,
            "warning" => ChangeSeverity::Warning,
            "breaking" => ChangeSeverity::Breaking,
            other => {
                return Err(usage_message(format!(
                    "unknown severity: {other} (use info, warning, or breaking)"
                )));
            }
        };
        if report.findings.iter().any(|f| f.severity >= min_severity) {
            out.flush()?;
            return Err(
                PolicyFailure(format!("diff findings reached fail threshold {threshold}")).into(),
            );
        }
    }

    Ok(())
}

fn load_document(
    path: &Path,
    plan: &AnalysisPlan,
    selector: Option<&str>,
) -> Result<SnapshotDocument> {
    let bytes = read_input(path)?;
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("snapshot {} is not UTF-8", path.display()))?;
        let value: serde_json::Value = serde_json::from_str(text).map_err(|error| {
            crate::cli::commands::input_message(format!(
                "invalid snapshot JSON in {}: {error}",
                path.display()
            ))
        })?;
        let snapshot = if value.get("command").is_some() || value.get("ok").is_some() {
            let envelope_version = value.get("schema_version").and_then(|value| value.as_u64());
            let command = value.get("command").and_then(|value| value.as_str());
            let ok = value.get("ok").and_then(|value| value.as_bool());
            if envelope_version != Some(1) || command != Some("snapshot") || ok != Some(true) {
                return Err(crate::cli::commands::input_message(format!(
                    "{} is not a successful macho snapshot JSON envelope",
                    path.display()
                )));
            }
            value.get("data").cloned().ok_or_else(|| {
                crate::cli::commands::input_message(format!(
                    "snapshot envelope {} has no data payload",
                    path.display()
                ))
            })?
        } else {
            value
        };
        let snapshot = serde_json::to_string(&snapshot)
            .context("failed to normalize snapshot JSON payload")?;
        let snapshot = SnapshotDocument::from_json(&snapshot)?;
        return select_snapshot_slices(snapshot, selector);
    }
    let container =
        crate::parse(&bytes).with_context(|| format!("failed to parse {}", path.display()))?;
    Analyzer.run(&container, plan).map_err(Into::into)
}

fn select_snapshot_slices(
    mut snapshot: SnapshotDocument,
    selector: Option<&str>,
) -> Result<SnapshotDocument> {
    let Some(selector) = selector else {
        return Ok(snapshot);
    };
    snapshot
        .slices
        .retain(|slice| snapshot_arch_matches(&slice.identity.arch, selector));
    if snapshot.slices.is_empty() {
        return Err(crate::cli::commands::input_message(format!(
            "no architecture matching '{selector}' found in snapshot"
        )));
    }
    snapshot.container.slice_count = snapshot.slices.len();
    snapshot.validate()?;
    Ok(snapshot)
}

fn snapshot_arch_matches(arch: &str, selector: &str) -> bool {
    arch.eq_ignore_ascii_case(selector)
        || (selector.eq_ignore_ascii_case("arm64") && arch.eq_ignore_ascii_case("arm64e"))
        || (selector.eq_ignore_ascii_case("x86_64") && arch.eq_ignore_ascii_case("x86_64h"))
}
