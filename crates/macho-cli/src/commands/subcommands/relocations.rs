use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::format::relocations::relocations_for_section;
use crate::model::macho_file::MachoFile;
use anyhow::{Context, Result};
use std::io::Write;

use crate::analysis::{AnalysisDomain, AnalysisLimits};
use crate::commands::OutputFormat;
use crate::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The RelocationsArgs type.
pub struct RelocationsArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,

    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,

    /// Filter to a specific section (e.g., __DATA,__la_symbol_ptr)
    #[arg(long)]
    section: Option<String>,
}

/// Performs run.
pub fn run(args: RelocationsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;

    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    if format == OutputFormat::Json {
        let mut values = analyze_selected_domain(
            &container,
            args.selection.arch.as_deref(),
            AnalysisDomain::Relocations,
            AnalysisLimits::default(),
            true,
        )?;
        if let Some(section) = &args.section {
            let (segment, section_name) = section.split_once(',').unwrap_or(("", section));
            for (_, value) in &mut values {
                if let Some(sections) = value.as_array_mut() {
                    sections.retain(|item| {
                        item.get("section").and_then(serde_json::Value::as_str)
                            == Some(section_name)
                            && (segment.is_empty()
                                || item.get("segment").and_then(serde_json::Value::as_str)
                                    == Some(segment))
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
            print_relocations(macho, &args, out)?;
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;

    Ok(())
}

fn print_relocations(
    macho: &MachoFile<'_>,
    args: &RelocationsArgs,
    out: &mut dyn Write,
) -> Result<()> {
    let mut total = 0usize;

    for seg in macho.segments() {
        for sect in seg.sections() {
            if sect.relocation_count() == 0 {
                continue;
            }

            let seg_name = sect.segment_name().as_str_lossy();
            let sect_name = sect.section_name().as_str_lossy();

            if let Some(ref filter) = args.section {
                let full_name = format!("{seg_name},{sect_name}");
                if !full_name.eq_ignore_ascii_case(filter) {
                    continue;
                }
            }

            let relocs = relocations_for_section(macho, sect).with_context(|| {
                format!("failed to parse relocations for {seg_name},{sect_name}")
            })?;

            let _ = writeln!(
                out,
                "Section {},{} ({} relocation{}):",
                seg_name,
                sect_name,
                relocs.len(),
                if relocs.len() == 1 { "" } else { "s" }
            );

            for reloc in &relocs {
                let _ = writeln!(out, "  {reloc}");
            }

            total += relocs.len();
        }
    }

    if total == 0 {
        let _ = writeln!(out, "No relocations found.");
    } else {
        let _ = writeln!(out, "\n{total} relocation(s) total.");
    }

    Ok(())
}
