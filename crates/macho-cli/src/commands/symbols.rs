use anyhow::{Context, Result};
use macho_core::ext::MachExt;
use macho_core::model::container::MachContainer;
use macho_core::model::mach::MachFile;
use macho_core::model::symbol::SymbolTable;
use std::path::PathBuf;

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
}

pub fn run(args: SymbolsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    let container = macho_core::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachContainer::Thin(mach) => {
            print_symbols(mach, &args);
        }
        MachContainer::Fat(fat) => {
            for (i, arch) in fat.arches().iter().enumerate() {
                let arch_name = arch.spec.name();
                if let Some(ref filter) = args.arch {
                    if !arch_name.eq_ignore_ascii_case(filter) {
                        continue;
                    }
                }
                if fat.arches().len() > 1 {
                    println!("=== {arch_name} ===");
                }
                print_symbols(&arch.mach, &args);
                if i + 1 < fat.arches().len() {
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn print_symbols(mach: &MachFile<'_>, args: &SymbolsArgs) {
    let symtab = match SymbolTable::parse(mach) {
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
            sym.name,
        );
    }

    println!("({} symbols total)", symtab.len());
}
