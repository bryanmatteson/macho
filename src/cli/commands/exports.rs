use crate::metadata::dyld::exports::parse_exports;
use crate::metadata::dyld::types::ExportKind;
use crate::model::macho_file::MachoFile;
use crate::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct ExportsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    /// Demangle Rust and C++ symbol names when possible
    #[arg(long)]
    demangle: bool,
}

pub fn run(args: ExportsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                println!("=== {arch_name} ===");
            }
            print_exports(macho, &args);
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_exports(macho: &MachoFile<'_>, args: &ExportsArgs) {
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
                        println!("  {:#018x} {}", address, demangler.format(&e.name));
                    }
                    ExportKind::ThreadLocal { address } => {
                        println!("  {:#018x} [tlv] {}", address, demangler.format(&e.name));
                    }
                    ExportKind::Absolute { address } => {
                        println!("  {:#018x} [abs] {}", address, demangler.format(&e.name));
                    }
                    ExportKind::Reexport { ordinal, name } => {
                        print!("  [reexport ord={ordinal}] {}", demangler.format(&e.name));
                        if let Some(name) = name {
                            print!(" -> {}", demangler.format(name));
                        }
                        println!();
                    }
                    ExportKind::StubAndResolver {
                        stub_offset,
                        resolver_offset,
                    } => {
                        println!(
                            "  [stub={stub_offset:#x} resolver={resolver_offset:#x}] {}",
                            demangler.format(&e.name)
                        );
                    }
                }
            }
            println!("({} exports)", exports.len());
        }
        Err(e) => println!("No exports: {e}"),
    }
}
