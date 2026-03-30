use anyhow::{Context, Result};
use macho::dyld::exports::parse_exports;
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ExportsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
}

pub fn run(args: ExportsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachContainer::Thin(mach) => print_exports(mach),
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
                print_exports(&arch.mach);
                println!();
            }
        }
    }
    Ok(())
}

fn print_exports(mach: &MachFile<'_>) {
    match parse_exports(mach) {
        Ok(exports) => {
            for e in &exports {
                println!("  {e}");
            }
            println!("({} exports)", exports.len());
        }
        Err(e) => println!("No exports: {e}"),
    }
}
