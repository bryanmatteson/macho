use crate::analysis::{AnalysisPlan, Analyzer};
use crate::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::map_input;
use anyhow::{Context, Result};
use std::io::Write;

#[derive(clap::Args)]
/// The SnapshotArgs type.
pub struct SnapshotArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
}

/// Performs run.
pub fn run(args: SnapshotArgs, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    let plan = if let Some(arch) = args.selection.arch {
        AnalysisPlan::all().with_slices([arch])
    } else {
        AnalysisPlan::all()
    }
    .with_limits((&args.limits).into());
    let snapshot = Analyzer.run(&container, &plan)?;

    crate::commands::output::json::write_pretty(out, &snapshot)?;
    Ok(())
}
