use crate::commands::args::{ArchitectureArgs, InputArgs};
use anyhow::{Context, Result};
use serde::Serialize;
use std::io::Write;
use std::path::{Path, PathBuf};

use super::common::{for_each_selected_mach, map_input};
use crate::commands::OutputFormat;
use crate::commands::input_message;
use crate::model::addr::ThinFileOffset;
use crate::model::macho_file::MachoFile;

#[derive(Debug, Clone, Serialize)]
struct DwarfSectionEntry {
    segment: String,
    section: String,
    offset: u64,
    size: u64,
}

/// View or extract DWARF debug sections.
///
/// By default, lists DWARF sections found in the binary.
/// When `--output-dir` is provided, extracts the raw section data to disk.
#[derive(clap::Args)]
pub struct DwarfArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,

    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,

    /// Filter to a specific DWARF section name (extract mode only)
    #[arg(long)]
    section: Option<String>,

    /// Extract DWARF sections to this directory (enables extract mode)
    #[arg(long)]
    output_dir: Option<PathBuf>,
}

/// Performs run.
pub fn run(args: DwarfArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    if let Some(output_dir) = args.output_dir {
        run_extract(
            &args.input.path,
            args.selection.arch.as_deref(),
            args.section.as_deref(),
            &output_dir,
            out,
        )
    } else {
        run_view(
            &args.input.path,
            args.selection.arch.as_deref(),
            format == OutputFormat::Json,
            out,
        )
    }
}

fn run_view(path: &Path, arch: Option<&str>, json: bool, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |macho, arch_name, _| {
            result.insert(
                arch_name.to_string(),
                serde_json::to_value(dwarf_sections(macho))?,
            );
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&val)?);
        } else {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(&container, arch, |macho, arch_name, show_header| {
        if show_header {
            let _ = writeln!(out, "=== {arch_name} ===");
        }
        let sections = dwarf_sections(macho);
        if sections.is_empty() {
            let _ = writeln!(out, "No DWARF sections found.");
        } else {
            let _ = writeln!(out, "DWARF sections: {}", sections.len());
            for section in sections {
                let _ = writeln!(
                    out,
                    "  {},{}  off={:#x} size={:#x}",
                    section.segment, section.section, section.offset, section.size
                );
            }
        }
        if show_header {
            let _ = writeln!(out,);
        }
        Ok(())
    })?;

    Ok(())
}

fn run_extract(
    path: &Path,
    arch: Option<&str>,
    section_filter: Option<&str>,
    output_dir: &PathBuf,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("failed to create output directory {}", output_dir.display()))?;

    let mut wrote = 0usize;
    for_each_selected_mach(&container, arch, |macho, arch_name, _| {
        for section in dwarf_sections(macho) {
            if let Some(filter) = section_filter {
                if section.section != filter && section.section.trim_start_matches('_') != filter {
                    continue;
                }
            }
            let bytes =
                macho.read_bytes_at(ThinFileOffset(section.offset), section.size as usize)?;
            let out_path = output_dir.join(format!(
                "{}-{}.bin",
                arch_name,
                section.section.trim_start_matches('_')
            ));
            std::fs::write(&out_path, bytes)
                .with_context(|| format!("failed to write {}", out_path.display()))?;
            wrote += 1;
        }
        Ok(())
    })?;

    if wrote == 0 {
        return Err(input_message(
            "no DWARF sections matched the requested filters",
        ));
    }

    let _ = writeln!(
        out,
        "Extracted {wrote} DWARF section{} to {}",
        if wrote == 1 { "" } else { "s" },
        output_dir.display()
    );
    Ok(())
}

fn dwarf_sections(macho: &MachoFile<'_>) -> Vec<DwarfSectionEntry> {
    macho
        .all_sections()
        .filter(|section| {
            section.segment_name() == "__DWARF"
                || section.section_name().as_str_lossy().starts_with("__debug")
        })
        .filter(|section| !section.section_type().is_zerofill())
        .map(|section| DwarfSectionEntry {
            segment: section.segment_name().to_string(),
            section: section.section_name().to_string(),
            offset: section.offset().0,
            size: section.size(),
        })
        .collect()
}
