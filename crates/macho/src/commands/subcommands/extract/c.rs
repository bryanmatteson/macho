use std::path::PathBuf;

use anyhow::{Context, Result};

use crate::analysis::reconstruct::c::{
    CAnalysisOptions, analyze_headers, render_header, validate_header_syntax,
};
use crate::commands::subcommands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct CArgs {
    /// Path to Mach-O binary
    path: PathBuf,

    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,

    /// Output as JSON
    #[arg(long)]
    json: bool,

    /// Correlate declarations against headers under this root
    #[arg(long)]
    header_root: Option<PathBuf>,

    /// Validate the rendered header with clang syntax checking
    #[arg(long)]
    validate: bool,
}

pub fn run(args: CArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |macho, arch_name, _| {
            let analysis = analyze_headers(
                macho,
                &CAnalysisOptions {
                    header_root: args.header_root.clone(),
                },
            )?;
            result.insert(arch_name.to_string(), serde_json::to_value(analysis)?);
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, value) = result.into_iter().next().expect("one value");
            crate::outln!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            crate::outln!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                crate::outln!("=== {arch_name} ===");
            }
            let analysis = analyze_headers(
                macho,
                &CAnalysisOptions {
                    header_root: args.header_root.clone(),
                },
            )?;
            let header = render_header(&analysis);
            if args.validate {
                validate_header_syntax(&header)?;
            }
            crate::outln!("{header}");
            if show_header {
                crate::outln!();
            }
            Ok(())
        },
    )?;

    Ok(())
}
