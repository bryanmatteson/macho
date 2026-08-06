use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::model::macho_file::MachoFile;
use crate::cli::model::symbol::SymbolTable;
use crate::cli::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::io::Write;

use crate::cli::analysis::{AnalysisDomain, AnalysisLimits};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::cli::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The SymbolsArgs type.
pub struct SymbolsArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,

    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,

    /// Show only external symbols
    #[arg(long)]
    external: bool,

    /// Show only undefined symbols
    #[arg(long, name = "undefined", conflicts_with = "defined")]
    undefined_only: bool,

    /// Show only defined symbols
    #[arg(long, name = "defined", conflicts_with = "undefined")]
    defined_only: bool,

    /// Sort by address
    #[arg(long)]
    sort_address: bool,

    /// Demangle Rust and C++ symbol names when possible
    #[arg(long)]
    demangle: bool,
}

/// Performs run.
pub fn run(args: SymbolsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;

    let container = crate::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    if format == OutputFormat::Json {
        let mut values = analyze_selected_domain(
            &container,
            args.selection.arch.as_deref(),
            AnalysisDomain::Symbols,
            AnalysisLimits::default(),
            true,
        )?;
        for (_, value) in &mut values {
            if let Some(symbols) = value.as_array_mut() {
                symbols.retain(|symbol| {
                    (!args.external
                        || symbol.get("external").and_then(serde_json::Value::as_bool)
                            == Some(true))
                        && (!args.undefined_only
                            || symbol.get("undefined").and_then(serde_json::Value::as_bool)
                                == Some(true))
                        && (!args.defined_only
                            || symbol.get("undefined").and_then(serde_json::Value::as_bool)
                                == Some(false))
                });
                if args.sort_address {
                    symbols.sort_by_key(|symbol| {
                        symbol
                            .get("value")
                            .and_then(serde_json::Value::as_u64)
                            .unwrap_or_default()
                    });
                }
            }
        }
        return write_selected_json(values, out);
    }

    for_each_selected_mach(
        &container,
        args.selection.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                let _ = writeln!(out, "=== {arch_name} ===");
            }
            print_symbols(macho, &args, out);
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;

    Ok(())
}

fn print_symbols(macho: &MachoFile<'_>, args: &SymbolsArgs, out: &mut dyn Write) {
    let symtab = match macho.ext::<SymbolTable<'_>>() {
        Ok(st) => st,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("no LC_SYMTAB") {
                let _ = writeln!(out, "No symbol table (binary has no LC_SYMTAB).");
            } else {
                let _ = writeln!(out, "Failed to parse symbol table: {msg}");
            }
            return;
        }
    };

    if symtab.is_empty() {
        let _ = writeln!(out, "Symbol table is empty (0 symbols).");
        return;
    }

    let _ = writeln!(
        out,
        "{:>6}  {:>18}  {:>5}  {:>4}  {:>4}  NAME",
        "INDEX", "VALUE", "TYPE", "EXT", "SECT"
    );

    let mut symbols: Vec<_> = symtab.symbols().iter().collect();
    let mut demangler = SymbolDemangler::new(args.demangle);

    demangler.precompute(symbols.iter().map(|sym| sym.name));

    if args.sort_address {
        symbols.sort_by_key(|s| s.value);
    }

    for sym in &symbols {
        if args.external && !sym.external {
            continue;
        }
        if args.undefined_only && !sym.is_undefined() {
            continue;
        }
        if args.defined_only && !sym.is_defined() {
            continue;
        }

        let ext_str = if sym.external {
            "ext"
        } else if sym.private_external {
            "pext"
        } else {
            ""
        };

        let _ = writeln!(
            out,
            "{:>6}  {:#018x}  {:>5}  {:>4}  {:>4}  {}",
            sym.index,
            sym.value,
            sym.sym_type.name(),
            ext_str,
            sym.section_index,
            demangler.format(sym.name),
        );
    }

    let _ = writeln!(out, "({} symbols total)", symtab.len());
}
