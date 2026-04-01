use crate::format::parse_symbol_table;
use crate::model::mach_file::MachFile;
use crate::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct SymbolsArgs {
    /// Path to Mach-O binary
    path: PathBuf,

    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,

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

pub fn run(args: SymbolsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |mach, arch_name, show_header| {
            if show_header {
                println!("=== {arch_name} ===");
            }
            print_symbols(mach, &args);
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;

    Ok(())
}

fn print_symbols(mach: &MachFile<'_>, args: &SymbolsArgs) {
    let symtab = match parse_symbol_table(mach) {
        Ok(st) => st,
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("no LC_SYMTAB") {
                println!("No symbol table (binary has no LC_SYMTAB).");
            } else {
                println!("Failed to parse symbol table: {msg}");
            }
            return;
        }
    };

    if symtab.is_empty() {
        println!("Symbol table is empty (0 symbols).");
        return;
    }

    println!(
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

        println!(
            "{:>6}  {:#018x}  {:>5}  {:>4}  {:>4}  {}",
            sym.index,
            sym.value,
            sym.sym_type.name(),
            ext_str,
            sym.section_index,
            demangler.format(sym.name),
        );
    }

    println!("({} symbols total)", symtab.len());
}
