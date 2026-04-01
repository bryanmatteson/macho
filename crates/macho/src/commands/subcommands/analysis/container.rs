use crate::analysis::container::ext::MachoContainerExt;
use crate::analysis::container::parity::ParityDomain;
use crate::analysis::container::{ContainerReport, resolve};
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::commands::subcommands::common::filter_snapshot_by_arch;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(clap::Args)]
pub struct ContainerArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Show cross-image symbol resolution
    #[arg(long)]
    resolve: bool,
    /// Limit parity checks to a specific domain (repeatable: exports, imports, segments, codesign, objc)
    #[arg(long = "parity-domain")]
    parity_domains: Vec<String>,
}

pub fn run(args: ContainerArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    let mut snapshot = container.snapshot();
    if let Some(ref filter) = args.arch {
        filter_snapshot_by_arch(&mut snapshot, filter, &args.path)?;
    }
    let parity_domains = parse_parity_domains(&args.parity_domains)?;
    let report = ContainerReport::from_snapshot_with_domains(&snapshot, &parity_domains);

    if args.json {
        if args.resolve {
            let resolution = resolve::resolve_cross_image(&snapshot);
            let combined = serde_json::json!({
                "container": report,
                "resolution": resolution,
            });
            println!("{}", serde_json::to_string_pretty(&combined)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        return Ok(());
    }

    // Text output
    println!("Container: {}", report.format);
    println!("Architectures: {}", report.arches.join(", "));

    if let Some(ref parity) = report.parity {
        println!(
            "Parity domains: {}",
            parity
                .domains
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if parity.divergences.is_empty() {
            println!("\nParity: all arches in agreement");
        } else {
            println!("\nParity divergences ({}):", parity.divergences.len());
            for div in &parity.divergences {
                println!("  [{}] {}", div.domain, div.description);
                for (arch, status) in &div.per_arch {
                    println!("    {arch}: {status}");
                }
            }
        }
    }

    if let Some(ref fileset) = report.fileset {
        println!("\nFileset entries ({}):", fileset.entries.len());
        for entry in &fileset.entries {
            println!(
                "  [{}] {} vm={:#x} fileoff={:#x}",
                entry.arch, entry.entry_id, entry.vm_addr, entry.file_offset
            );
        }
    }

    if args.resolve {
        let resolution = resolve::resolve_cross_image(&snapshot);
        if !resolution.export_ownership.is_empty() {
            println!(
                "\nArch-specific exports ({}):",
                resolution.export_ownership.len()
            );
            for eo in &resolution.export_ownership {
                println!("  {} -> {}", eo.symbol, eo.arches.join(", "));
            }
        }
        if !resolution.import_divergence.is_empty() {
            println!(
                "\nDivergent imports ({}):",
                resolution.import_divergence.len()
            );
            for div in &resolution.import_divergence {
                println!(
                    "  {} — present in: {}, absent from: {}",
                    div.symbol,
                    div.present_in.join(", "),
                    div.absent_from.join(", ")
                );
            }
        }
    }

    Ok(())
}

fn parse_parity_domains(raw: &[String]) -> Result<Vec<ParityDomain>> {
    raw.iter()
        .map(|domain| match domain.as_str() {
            "exports" => Ok(ParityDomain::Exports),
            "imports" => Ok(ParityDomain::Imports),
            "segments" => Ok(ParityDomain::Segments),
            "codesign" => Ok(ParityDomain::Codesign),
            "objc" => Ok(ParityDomain::Objc),
            other => anyhow::bail!(
                "unknown parity domain: {other} (use exports, imports, segments, codesign, or objc)"
            ),
        })
        .collect()
}
