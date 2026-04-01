use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;

use crate::commands::subcommands::common::for_each_selected_mach;
use crate::model::addr::ThinFileOffset;
use crate::model::macho_file::MachoFile;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(Debug, Clone, Serialize)]
struct DwarfSectionEntry {
    segment: String,
    section: String,
    offset: u64,
    size: u64,
}

#[derive(clap::Args)]
pub struct ViewDwarfArgs {
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    json: bool,
}

#[derive(clap::Args)]
pub struct ExtractDwarfArgs {
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    section: Option<String>,
    #[arg(long)]
    output_dir: PathBuf,
}

pub fn run_view(args: ViewDwarfArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |macho, arch_name, _| {
            result.insert(
                arch_name.to_string(),
                serde_json::to_value(dwarf_sections(macho))?,
            );
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                println!("=== {arch_name} ===");
            }
            let sections = dwarf_sections(macho);
            if sections.is_empty() {
                println!("No DWARF sections found.");
            } else {
                println!("DWARF sections: {}", sections.len());
                for section in sections {
                    println!(
                        "  {},{}  off={:#x} size={:#x}",
                        section.segment, section.section, section.offset, section.size
                    );
                }
            }
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;

    Ok(())
}

pub fn run_extract(args: ExtractDwarfArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    std::fs::create_dir_all(&args.output_dir).with_context(|| {
        format!(
            "failed to create output directory {}",
            args.output_dir.display()
        )
    })?;

    let mut wrote = 0usize;
    for_each_selected_mach(&container, args.arch.as_deref(), |macho, arch_name, _| {
        for section in dwarf_sections(macho) {
            if let Some(filter) = args.section.as_deref() {
                if section.section != filter && section.section.trim_start_matches('_') != filter {
                    continue;
                }
            }
            let bytes =
                macho.read_bytes_at(ThinFileOffset(section.offset), section.size as usize)?;
            let path = args.output_dir.join(format!(
                "{}-{}.bin",
                arch_name,
                section.section.trim_start_matches('_')
            ));
            std::fs::write(&path, bytes)
                .with_context(|| format!("failed to write {}", path.display()))?;
            wrote += 1;
        }
        Ok(())
    })?;

    if wrote == 0 {
        anyhow::bail!("no DWARF sections matched the requested filters");
    }

    println!(
        "Extracted {wrote} DWARF section{} to {}",
        if wrote == 1 { "" } else { "s" },
        args.output_dir.display()
    );
    Ok(())
}

fn dwarf_sections(macho: &MachoFile<'_>) -> Vec<DwarfSectionEntry> {
    macho
        .all_sections()
        .filter(|section| {
            section.segment_name == "__DWARF"
                || section.section_name.as_str_lossy().starts_with("__debug")
        })
        .filter(|section| !section.section_type.is_zerofill())
        .map(|section| DwarfSectionEntry {
            segment: section.segment_name.to_string(),
            section: section.section_name.to_string(),
            offset: section.offset.0,
            size: section.size,
        })
        .collect()
}
