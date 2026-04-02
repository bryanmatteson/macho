use anyhow::Result;
use clap::ValueEnum;
use std::path::PathBuf;

use super::inspect::{InspectArgs, InspectScope};

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum InfoScope {
    Header,
    Segments,
    Sections,
    #[value(name = "load-commands")]
    LoadCommands,
}

#[derive(clap::Args)]
pub struct InfoArgs {
    /// Path to Mach-O binary
    path: PathBuf,

    /// Show only a specific structural scope
    #[arg(value_enum)]
    scope: Option<InfoScope>,

    /// Filter to a specific architecture (e.g., arm64, x86_64, arm64e)
    #[arg(long)]
    arch: Option<String>,

    /// Show validation diagnostics
    #[arg(long)]
    validate: bool,
}

pub fn run(args: InfoArgs) -> Result<()> {
    let scope = match args.scope {
        None => InspectScope::Full,
        Some(InfoScope::Header) => InspectScope::Header,
        Some(InfoScope::Segments) => InspectScope::Segments,
        Some(InfoScope::Sections) => InspectScope::Sections,
        Some(InfoScope::LoadCommands) => InspectScope::LoadCommands,
    };
    let inspect_args = InspectArgs::new(args.path, args.arch, args.validate);
    super::inspect::run_scoped(inspect_args, scope)
}
