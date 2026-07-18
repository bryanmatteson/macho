use crate::analysis::diff::{ChangeSeverity, diff_documents};
use crate::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DiffPlan, SnapshotDocument};
use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::args::{AnalysisLimitArgs, ArchitectureArgs};
use crate::commands::subcommands::common::read_input;
use crate::commands::{OutputFormat, PolicyFailure, usage_message};

#[derive(clap::Args)]
/// The DiffArgs type.
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
        diff_plan = diff_plan.exclude(AnalysisDomain::Objc);
    }
    if args.ignore_symbols {
        diff_plan = diff_plan.exclude(AnalysisDomain::Symbols);
    }
    if let Some(ref arch) = args.selection.arch {
        diff_plan = diff_plan.with_slices([arch.clone()]);
    }
    diff_plan = diff_plan.with_limits((&args.limits).into());
    let analysis_plan = diff_plan.compile();
    let old_snap = load_document(&args.old, &analysis_plan)?;
    let new_snap = load_document(&args.new, &analysis_plan)?;
    let report = diff_documents(&old_snap, &new_snap, diff_plan.selected_domains());

    if format == OutputFormat::Json {
        crate::commands::output::json::write_pretty(out, &report)?;
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

fn load_document(path: &Path, plan: &AnalysisPlan) -> Result<SnapshotDocument> {
    let bytes = read_input(path)?;
    if bytes
        .iter()
        .copied()
        .find(|byte| !byte.is_ascii_whitespace())
        == Some(b'{')
    {
        let text = std::str::from_utf8(&bytes)
            .with_context(|| format!("snapshot {} is not UTF-8", path.display()))?;
        return SnapshotDocument::from_json(text).map_err(Into::into);
    }
    let container =
        macho::parse(&bytes).with_context(|| format!("failed to parse {}", path.display()))?;
    Analyzer.run(&container, plan).map_err(Into::into)
}
