use anyhow::{Context, Result};
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use macho::parse::relocations::relocations_for_section;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct RelocationsArgs {
    /// Path to Mach-O binary
    path: PathBuf,

    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,

    /// Filter to a specific section (e.g., __DATA,__la_symbol_ptr)
    #[arg(long)]
    section: Option<String>,
}

pub fn run(args: RelocationsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };

    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachContainer::Thin(mach) => {
            print_relocations(mach, &args)?;
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
                print_relocations(&arch.mach, &args)?;
                if i + 1 < fat.arches().len() {
                    println!();
                }
            }
        }
    }

    Ok(())
}

fn print_relocations(mach: &MachFile<'_>, args: &RelocationsArgs) -> Result<()> {
    let mut total = 0usize;

    for seg in mach.segments() {
        for sect in &seg.sections {
            if sect.nreloc == 0 {
                continue;
            }

            let seg_name = sect.segment_name.as_str_lossy();
            let sect_name = sect.section_name.as_str_lossy();

            if let Some(ref filter) = args.section {
                let full_name = format!("{seg_name},{sect_name}");
                if !full_name.eq_ignore_ascii_case(filter) {
                    continue;
                }
            }

            let relocs = relocations_for_section(mach, sect).with_context(|| {
                format!("failed to parse relocations for {seg_name},{sect_name}")
            })?;

            println!(
                "Section {},{} ({} relocation{}):",
                seg_name,
                sect_name,
                relocs.len(),
                if relocs.len() == 1 { "" } else { "s" }
            );

            for reloc in &relocs {
                println!("  {reloc}");
            }

            total += relocs.len();
        }
    }

    if total == 0 {
        println!("No relocations found.");
    } else {
        println!("\n{total} relocation(s) total.");
    }

    Ok(())
}
