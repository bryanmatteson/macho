use crate::commands::args::{ArchitectureArgs, InputArgs};
use std::io::Write;
use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::adapters::validate_c_header;
use crate::analysis::reconstruct::c::{
    CReconstructionPlan, HeaderSource, InMemoryHeaderCorrelator, analyze_headers, render_header,
};
use crate::commands::subcommands::common::{for_each_selected_mach, map_input, read_input_string};
use crate::commands::{OutputFormat, input_result};

#[derive(clap::Args)]
/// The CArgs type.
pub struct CArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,

    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,

    /// Correlate declarations against headers under this root
    #[arg(long)]
    header_root: Option<PathBuf>,

    /// Validate the rendered header with clang syntax checking
    #[arg(long)]
    validate: bool,
}

/// Performs run.
pub fn run(args: CArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let correlator = args
        .header_root
        .as_deref()
        .map(load_header_sources)
        .transpose()?
        .map(InMemoryHeaderCorrelator::new);
    let plan = CReconstructionPlan {
        correlator: correlator
            .as_ref()
            .map(|value| value as &dyn crate::analysis::reconstruct::c::HeaderCorrelator),
    };

    if format == OutputFormat::Json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |macho, arch_name, _| {
                let analysis = analyze_headers(macho, &plan)?;
                result.insert(arch_name.to_string(), serde_json::to_value(analysis)?);
                Ok(())
            },
        )?;
        if result.len() == 1 {
            let (_, value) = result.into_iter().next().expect("one value");
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
            let analysis = analyze_headers(macho, &plan)?;
            let header = render_header(&analysis);
            if args.validate {
                validate_c_header(&header)?;
            }
            let _ = writeln!(out, "{header}");
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;

    Ok(())
}

fn load_header_sources(root: &std::path::Path) -> Result<Vec<HeaderSource>> {
    let mut sources = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = input_result(
            std::fs::read_dir(&directory),
            format!("failed to read {}", directory.display()),
        )?;
        for entry in entries {
            let path = input_result(
                entry,
                format!("failed to read an entry under {}", directory.display()),
            )?
            .path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|extension| extension.to_str()) == Some("h") {
                let contents = read_input_string(&path)?;
                sources.push(HeaderSource {
                    path: path.display().to_string(),
                    contents,
                });
            }
        }
    }
    Ok(sources)
}
