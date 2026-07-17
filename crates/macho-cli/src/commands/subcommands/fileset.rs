use crate::analysis::container::ContainerDocumentReport;
use crate::analysis::container::ext::MachoContainerExt;
use crate::analysis::{AnalysisDomain, Analyzer, ContainerPlan};
use crate::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, input_message};
use anyhow::{Context, Result};
use std::collections::BTreeMap;
use std::io::Write;

#[derive(clap::Args)]
/// The FilesetArgs type.
pub struct FilesetArgs {
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    #[command(subcommand)]
    action: FilesetAction,
}

#[derive(clap::Subcommand)]
enum FilesetAction {
    /// List fileset entries in the binary
    List {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
    },
    /// Inspect a specific fileset entry by ID
    Inspect {
        #[command(flatten)]
        input: InputArgs,
        /// The entry_id to inspect
        entry_id: String,
        #[command(flatten)]
        selection: ArchitectureArgs,
    },
}

/// Performs run.
pub fn run(args: FilesetArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let limits = (&args.limits).into();
    match args.action {
        FilesetAction::List { input, selection } => {
            run_list(&input.path, selection.arch.as_deref(), limits, format, out)
        }
        FilesetAction::Inspect {
            input,
            entry_id,
            selection,
        } => run_inspect(
            &input.path,
            &entry_id,
            selection.arch.as_deref(),
            format,
            out,
        ),
    }
}

fn run_list(
    path: &std::path::Path,
    arch: Option<&str>,
    limits: crate::analysis::AnalysisLimits,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    let plan = ContainerPlan::new([AnalysisDomain::LoadCommands]).with_limits(limits);
    let document = Analyzer.run(&container, &plan.compile())?;
    let report =
        ContainerDocumentReport::from_document(&document, &[AnalysisDomain::LoadCommands], false);

    let mut found = false;
    let mut selected_entries = Vec::new();
    if let Some(fileset) = report.fileset.as_ref() {
        let mut entries_by_arch: BTreeMap<&str, Vec<_>> = BTreeMap::new();
        for entry in &fileset.entries {
            if let Some(filter) = arch {
                if !entry.arch.eq_ignore_ascii_case(filter) {
                    continue;
                }
            }
            entries_by_arch
                .entry(entry.arch.as_str())
                .or_default()
                .push(entry);
            selected_entries.push(entry);
        }

        if format == OutputFormat::Json {
            writeln!(
                out,
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({
                    "action": "list",
                    "entries": selected_entries,
                }))?
            )?;
            return Ok(());
        }

        for (arch_name, entries) in entries_by_arch {
            found = true;
            let _ = writeln!(out, "[{}] {} fileset entries:", arch_name, entries.len());
            for entry in entries {
                let _ = writeln!(
                    out,
                    "  {} vm={:#x} fileoff={:#x}",
                    entry.entry_id, entry.vm_addr, entry.file_offset
                );
            }
        }
    }

    if format == OutputFormat::Json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "action": "list",
                "entries": selected_entries,
            }))?
        )?;
        return Ok(());
    }

    if !found {
        if let Some(filter) = arch {
            if report.fileset.is_some() {
                let _ = writeln!(out, "No fileset entries matched architecture '{filter}'.");
            } else {
                let _ = writeln!(out, "No fileset entries found (binary is not MH_FILESET).");
            }
        } else {
            let _ = writeln!(out, "No fileset entries found (binary is not MH_FILESET).");
        }
    }

    Ok(())
}

fn run_inspect(
    path: &std::path::Path,
    entry_id: &str,
    arch: Option<&str>,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    let all_matches = container.inspect_fileset_entry(entry_id);
    let matches: Vec<_> = all_matches
        .iter()
        .filter(|inspection| arch.is_none_or(|filter| inspection.arch.eq_ignore_ascii_case(filter)))
        .collect();

    if matches.is_empty() {
        if let Some(filter) = arch
            && !all_matches.is_empty()
        {
            return Err(input_message(format!(
                "Fileset entry '{entry_id}' not found for architecture '{filter}'"
            )));
        } else {
            return Err(input_message(format!(
                "Fileset entry '{entry_id}' not found"
            )));
        }
    }

    if format == OutputFormat::Json {
        writeln!(
            out,
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "action": "inspect",
                "entry_id": entry_id,
                "matches": matches,
            }))?
        )?;
        return Ok(());
    }

    let show_headers = matches.len() > 1;
    for (index, inspection) in matches.iter().enumerate() {
        if show_headers {
            if index > 0 {
                let _ = writeln!(out,);
            }
            let _ = writeln!(out, "=== {} ===", inspection.arch);
        }

        let _ = writeln!(out, "Fileset Entry: {}", inspection.entry_id);
        let _ = writeln!(out, "  VM address:   {:#x}", inspection.vm_addr);
        let _ = writeln!(out, "  File offset:  {:#x}", inspection.file_offset);
        if let Some(member) = &inspection.member {
            let _ = writeln!(out, "  File type:    {}", member.file_type);
            let _ = writeln!(out, "  CPU:          {}", member.cpu);
            let _ = writeln!(out, "  Load cmds:    {}", member.load_commands);
            let _ = writeln!(out, "  Segments:     {}", member.segments);
        } else if let Some(err) = &inspection.parse_error {
            let _ = writeln!(out, "  (could not parse member as Mach-O: {err})");
        }
    }
    Ok(())
}
