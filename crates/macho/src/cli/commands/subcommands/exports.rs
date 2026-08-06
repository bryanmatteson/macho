use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::metadata::dyld::exports::parse_exports;
use crate::cli::metadata::dyld::types::ExportKind;
use crate::cli::model::macho_file::MachoFile;
use crate::cli::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::io::Write;

use crate::cli::analysis::{AnalysisDomain, AnalysisLimits};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::cli::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The ExportsArgs type.
pub struct ExportsArgs {
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
pub fn run(args: ExportsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = crate::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    if format == OutputFormat::Json {
        return write_selected_json(
            analyze_selected_domain(
                &container,
                args.selection.arch.as_deref(),
                AnalysisDomain::Exports,
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
            print_exports(macho, &args, out);
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_exports(macho: &MachoFile<'_>, args: &ExportsArgs, out: &mut dyn Write) {
    match parse_exports(macho) {
        Ok(exports) => {
            let mut demangler = SymbolDemangler::new(args.demangle);
            demangler.precompute(exports.iter().map(|export| export.name.as_str()));
            demangler.precompute(exports.iter().filter_map(|export| match &export.kind {
                ExportKind::Reexport {
                    name: Some(name), ..
                } => Some(name.as_str()),
                _ => None,
            }));

            for e in &exports {
                match &e.kind {
                    ExportKind::Regular { address } => {
                        let _ = writeln!(out, "  {:#018x} {}", address, demangler.format(&e.name));
                    }
                    ExportKind::ThreadLocal { address } => {
                        let _ = writeln!(
                            out,
                            "  {:#018x} [tlv] {}",
                            address,
                            demangler.format(&e.name)
                        );
                    }
                    ExportKind::Absolute { address } => {
                        let _ = writeln!(
                            out,
                            "  {:#018x} [abs] {}",
                            address,
                            demangler.format(&e.name)
                        );
                    }
                    ExportKind::Reexport { ordinal, name } => {
                        let _ = write!(
                            out,
                            "  [reexport ord={ordinal}] {}",
                            demangler.format(&e.name)
                        );
                        if let Some(name) = name {
                            let _ = write!(out, " -> {}", demangler.format(name));
                        }
                        let _ = writeln!(out,);
                    }
                    ExportKind::StubAndResolver {
                        stub_offset,
                        resolver_offset,
                    } => {
                        let _ = writeln!(
                            out,
                            "  [stub={stub_offset:#x} resolver={resolver_offset:#x}] {}",
                            demangler.format(&e.name)
                        );
                    }
                    _ => {
                        let _ = writeln!(out, "  [unknown] {}", demangler.format(&e.name));
                    }
                }
            }
            let _ = writeln!(out, "({} exports)", exports.len());
        }
        Err(e) => {
            let _ = writeln!(out, "No exports: {e}");
        }
    }
}
