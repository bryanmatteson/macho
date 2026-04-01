use crate::metadata::dyld::chained::parse_chained_fixups;
use crate::model::mach_file::MachFile;
use crate::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct ImportsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    /// Demangle Rust and C++ symbol names when possible
    #[arg(long)]
    demangle: bool,
}

pub fn run(args: ImportsArgs) -> Result<()> {
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
            print_imports(mach, &args);
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_imports(mach: &MachFile<'_>, args: &ImportsArgs) {
    match parse_chained_fixups(mach) {
        Ok(fixups) => {
            let mut demangler = SymbolDemangler::new(args.demangle);
            demangler.precompute(fixups.imports.iter().map(|import| import.name));

            for (i, imp) in fixups.imports.iter().enumerate() {
                let weak = if imp.weak { " [weak]" } else { "" };
                println!(
                    "  [{i:>4}] ordinal={:<4} {}{}",
                    imp.lib_ordinal,
                    demangler.format(imp.name),
                    weak
                );
            }
            println!(
                "({} imports, {} fixups)",
                fixups.imports.len(),
                fixups.fixups.len()
            );
        }
        Err(e) => println!("No chained fixups: {e}"),
    }
}
