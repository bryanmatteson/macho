use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::metadata::dyld::chained::parse_chained_fixups;
use crate::cli::model::macho_file::MachoFile;
use crate::cli::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::io::Write;

use crate::cli::analysis::{AnalysisDomain, AnalysisLimits};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::cli::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The ImportsArgs type.
pub struct ImportsArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Demangle Rust and C++ symbol names when possible
    #[arg(long)]
    demangle: bool,
}

/// Performs run.
pub fn run(args: ImportsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = crate::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    if format == OutputFormat::Json {
        return write_selected_json(
            analyze_selected_domain(
                &container,
                args.selection.arch.as_deref(),
                AnalysisDomain::Imports,
                AnalysisLimits::default(),
                true,
            )?,
            out,
        );
    }

    for_each_selected_mach(
        &container,
        args.selection.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                let _ = writeln!(out, "=== {arch_name} ===");
            }
            print_imports(macho, &args, out);
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_imports(macho: &MachoFile<'_>, args: &ImportsArgs, out: &mut dyn Write) {
    match parse_chained_fixups(macho) {
        Ok(fixups) => {
            let mut demangler = SymbolDemangler::new(args.demangle);
            demangler.precompute(fixups.imports.iter().map(|import| import.name));

            for (i, imp) in fixups.imports.iter().enumerate() {
                let weak = if imp.weak { " [weak]" } else { "" };
                let _ = writeln!(
                    out,
                    "  [{i:>4}] ordinal={:<4} {}{}",
                    imp.lib_ordinal,
                    demangler.format(imp.name),
                    weak
                );
            }
            let _ = writeln!(
                out,
                "({} imports, {} fixups)",
                fixups.imports.len(),
                fixups.fixups.len()
            );
        }
        Err(e) => {
            let _ = writeln!(out, "No chained fixups: {e}");
        }
    }
}
