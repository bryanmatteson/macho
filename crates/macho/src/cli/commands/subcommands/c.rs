use std::io::Write;

use crate::analysis::report::RecoveryLanguage;
use anyhow::Result;

use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::commands::output::Options as OutputOptions;
use crate::cli::commands::subcommands::recovery::RecoveryArgs;

#[derive(clap::Args)]
/// Evidence-first C-compatible ABI recovery arguments.
pub struct CArgs {
    /// Path to the Mach-O binary.
    #[command(flatten)]
    input: InputArgs,
    /// Optional architecture selection.
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Shared recovery plan.
    #[command(flatten)]
    recovery: RecoveryArgs,
}

/// Runs C-compatible recovery.
pub fn run(args: CArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    super::recovery::run(
        args.input,
        args.selection,
        args.recovery,
        RecoveryLanguage::CAbi,
        output,
        out,
    )
}
