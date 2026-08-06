use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::metadata::dyld::chained::parse_chained_fixups;
use crate::cli::metadata::dyld::types::FixupKind;
use crate::cli::model::macho_file::MachoFile;
use crate::cli::symbols::demangle::SymbolDemangler;
use anyhow::{Context, Result};
use std::io::Write;

use crate::cli::analysis::{AnalysisDomain, AnalysisLimits};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::cli::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The FixupsArgs type.
pub struct FixupsArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Show only bind fixups
    #[arg(long, conflicts_with = "rebases_only")]
    binds_only: bool,
    /// Show only rebase fixups
    #[arg(long, conflicts_with = "binds_only")]
    rebases_only: bool,
    /// Demangle Rust and C++ symbol names when possible
    #[arg(long)]
    demangle: bool,
}

/// Performs run.
pub fn run(args: FixupsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = crate::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    if format == OutputFormat::Json {
        let mut values = analyze_selected_domain(
            &container,
            args.selection.arch.as_deref(),
            AnalysisDomain::Fixups,
            AnalysisLimits::default(),
            true,
        )?;
        for (_, value) in &mut values {
            if let Some(fixups) = value.as_array_mut() {
                fixups.retain(|fixup| {
                    let kind = fixup
                        .get("kind")
                        .and_then(serde_json::Value::as_object)
                        .and_then(|kind| kind.get("kind"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default();
                    (!args.binds_only || kind.contains("bind"))
                        && (!args.rebases_only || kind.contains("rebase"))
                });
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
            print_fixups(macho, &args, out);
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_fixups(macho: &MachoFile<'_>, args: &FixupsArgs, out: &mut dyn Write) {
    match parse_chained_fixups(macho) {
        Ok(fixups) => {
            let mut bind_count = 0usize;
            let mut rebase_count = 0usize;
            let mut demangler = SymbolDemangler::new(args.demangle);

            demangler.precompute(fixups.imports.iter().map(|import| import.name));

            for f in &fixups.fixups {
                let is_bind = matches!(f.kind, FixupKind::Bind { .. } | FixupKind::AuthBind { .. });
                let is_rebase = !is_bind;

                if args.binds_only && !is_bind {
                    continue;
                }
                if args.rebases_only && !is_rebase {
                    continue;
                }

                if is_bind {
                    bind_count += 1;
                } else {
                    rebase_count += 1;
                }

                let kind_str = match &f.kind {
                    FixupKind::Rebase { target } => format!("rebase  -> {target:#x}"),
                    FixupKind::Bind {
                        import_index,
                        addend,
                    } => {
                        let name = fixups
                            .imports
                            .get(*import_index as usize)
                            .map(|i| i.name)
                            .unwrap_or("?");
                        let name = demangler.format(name);
                        if *addend != 0 {
                            format!("bind    -> {name} + {addend}")
                        } else {
                            format!("bind    -> {name}")
                        }
                    }
                    FixupKind::AuthRebase {
                        target,
                        key,
                        diversity,
                        ..
                    } => {
                        format!("auth-rb -> {target:#x} key={key} div={diversity}")
                    }
                    FixupKind::AuthBind {
                        import_index,
                        key,
                        diversity,
                        ..
                    } => {
                        let name = fixups
                            .imports
                            .get(*import_index as usize)
                            .map(|i| i.name)
                            .unwrap_or("?");
                        let name = demangler.format(name);
                        format!("auth-bd -> {name} key={key} div={diversity}")
                    }
                    _ => "unknown".to_owned(),
                };

                let _ = writeln!(
                    out,
                    "  seg[{}]+{:#010x}  {kind_str}",
                    f.segment_index, f.segment_offset,
                );
            }

            let _ = writeln!(out, "({bind_count} binds, {rebase_count} rebases)");
        }
        Err(e) => {
            let _ = writeln!(out, "No chained fixups: {e}");
        }
    }
}
