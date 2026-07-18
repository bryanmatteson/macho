use anyhow::Result;
use clap::ValueEnum;
use std::io::Write;

use super::inspect::{InspectArgs, InspectScope};
use crate::analysis::{AnalysisDomain, AnalysisPlan, Analyzer};
use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::read_input;
use crate::commands::{CliWarning, OutputFormat};

#[derive(Debug, Clone, Copy, ValueEnum)]
/// The InfoScope type.
#[non_exhaustive]
pub enum InfoScope {
    /// The Header variant.
    Header,
    /// The Segments variant.
    Segments,
    /// The Sections variant.
    Sections,
    #[value(name = "load-commands")]
    /// The LoadCommands variant.
    LoadCommands,
}

#[derive(clap::Args)]
/// The InfoArgs type.
pub struct InfoArgs {
    #[command(flatten)]
    input: InputArgs,

    /// Show only a specific structural scope
    #[arg(value_enum)]
    scope: Option<InfoScope>,

    #[command(flatten)]
    selection: ArchitectureArgs,

    /// Show validation diagnostics
    #[arg(long)]
    validate: bool,
}

/// Performs run.
pub(crate) fn run(
    args: InfoArgs,
    output: crate::commands::output::Options,
    out: &mut dyn Write,
    warnings: &mut Vec<CliWarning>,
) -> Result<()> {
    let format = output.format();
    let scope = match args.scope {
        None => InspectScope::Full,
        Some(InfoScope::Header) => InspectScope::Header,
        Some(InfoScope::Segments) => InspectScope::Segments,
        Some(InfoScope::Sections) => InspectScope::Sections,
        Some(InfoScope::LoadCommands) => InspectScope::LoadCommands,
    };
    if format == OutputFormat::Json {
        let bytes = read_input(&args.input.path)?;
        let options = macho::core::ParseOptions {
            mode: macho::core::ParseMode::Forensic,
            limits: macho::core::ParseLimits::default(),
        };
        let outcome = macho::parse_with_options(&bytes, &options)?;
        warnings.extend(outcome.diagnostics.iter().map(|diagnostic| CliWarning {
            code: diagnostic.code.0.to_owned(),
            message: diagnostic.message.clone(),
        }));
        let domains = match scope {
            InspectScope::Full => vec![
                AnalysisDomain::Header,
                AnalysisDomain::LoadCommands,
                AnalysisDomain::Segments,
            ],
            InspectScope::Header => vec![AnalysisDomain::Header],
            InspectScope::LoadCommands => vec![AnalysisDomain::LoadCommands],
            InspectScope::Segments | InspectScope::Sections => vec![AnalysisDomain::Segments],
        };
        let mut plan = AnalysisPlan::new(domains);
        if let Some(arch) = args.selection.arch {
            plan = plan.with_slices([arch]);
        }
        let document = Analyzer.run(&outcome.container, &plan)?;
        crate::commands::output::json::write_pretty(out, &document)?;
        return Ok(());
    }
    let inspect_args = InspectArgs::new(args.input.path, args.selection.arch, args.validate);
    super::inspect::run_scoped(inspect_args, scope, output.style(), out, warnings)
}
