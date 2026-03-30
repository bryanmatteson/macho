use anyhow::{Context, Result};
use macho::dyld::chained::parse_chained_fixups;
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ImportsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
}

pub fn run(args: ImportsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachContainer::Thin(mach) => print_imports(mach),
        MachContainer::Fat(fat) => {
            for arch in fat.arches() {
                let name = arch.spec.name();
                if let Some(ref f) = args.arch {
                    if !name.eq_ignore_ascii_case(f) {
                        continue;
                    }
                }
                if fat.arches().len() > 1 {
                    println!("=== {name} ===");
                }
                print_imports(&arch.mach);
                println!();
            }
        }
    }
    Ok(())
}

fn print_imports(mach: &MachFile<'_>) {
    match parse_chained_fixups(mach) {
        Ok(fixups) => {
            for (i, imp) in fixups.imports.iter().enumerate() {
                let weak = if imp.weak { " [weak]" } else { "" };
                println!(
                    "  [{i:>4}] ordinal={:<4} {}{}",
                    imp.lib_ordinal, imp.name, weak
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
