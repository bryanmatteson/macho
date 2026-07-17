use crate::analysis::reconstruct::cpp::{CppImageIndex, CppReconstructionPlan, reconstruct};
use crate::commands::OutputFormat;
use crate::commands::args::{ArchitectureArgs, InputArgs};
use anyhow::{Context, Result};
use std::io::Write;

use crate::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The CppArgs type.
pub struct CppArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Render a recovered header
    #[arg(long)]
    headers: bool,
    /// Filter to a specific class name
    #[arg(long, name = "class")]
    class_filter: Option<String>,
}

/// Performs run.
pub fn run(args: CppArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let plan = CppReconstructionPlan {
        class_filter: args.class_filter.clone(),
        render_header: args.headers,
    };

    if format == OutputFormat::Json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |macho, arch_name, _| {
                let report = reconstruct(macho, &plan)?;
                result.insert(arch_name.to_string(), serde_json::to_value(report)?);
                Ok(())
            },
        )?;
        if result.len() == 1 {
            let (_, value) = result.into_iter().next().unwrap();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&value)?);
        } else {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(
        &container,
        args.selection.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                let _ = writeln!(out, "=== {arch_name} ===");
            }

            if args.headers {
                let report = reconstruct(macho, &plan)?;
                let _ = writeln!(out, "{}", report.header.unwrap_or_default());
            } else {
                let report = reconstruct(macho, &plan)?;
                print_cpp_summary(&report.index, out);
            }

            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;

    Ok(())
}

fn print_cpp_summary(index: &CppImageIndex, out: &mut dyn Write) {
    let _ = writeln!(
        out,
        "C++ recovery: {} classes, {} typeinfos, {} free functions, {} symbols",
        index.classes.len(),
        index.typeinfos.len(),
        index.free_functions.len(),
        index.symbols.len(),
    );

    for class in index.classes.values() {
        let _ = writeln!(
            out,
            "  {}: {} bases, {} methods, {} vtables",
            class.name,
            class.bases.len(),
            class.methods.len(),
            class.vtables.len(),
        );
    }
}
