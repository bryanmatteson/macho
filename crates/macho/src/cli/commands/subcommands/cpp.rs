use std::io::Write;

use crate::analysis::report::RecoveryLanguage;
use anyhow::Result;

use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::commands::output::Options as OutputOptions;
use crate::cli::commands::subcommands::recovery::RecoveryArgs;

#[derive(clap::Args)]
/// Evidence-first C++ recovery arguments.
pub struct CppArgs {
    /// Path to the Mach-O binary.
    #[command(flatten)]
    input: InputArgs,
    /// Optional architecture selection.
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Shared recovery plan.
    #[command(flatten)]
    recovery: RecoveryArgs,
    /// Compatibility alias for an exact class-name selection.
    #[arg(long, name = "class")]
    class_filter: Option<String>,
}

/// Runs C++ recovery.
pub fn run(mut args: CppArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    if let Some(class) = args.class_filter.take() {
        args.recovery.names.push(class);
    }
    super::recovery::run(
        args.input,
        args.selection,
        args.recovery,
        RecoveryLanguage::Cpp,
        output,
        out,
    )
}
