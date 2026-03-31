use anyhow::{Context, Result};
use macho::analysis::snapshot::ContainerSnapshot;
use macho::diff::{ChangeSeverity, DiffDomain, diff_containers};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::commands::common::filter_snapshot_by_arch;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(clap::Args)]
pub struct DiffArgs {
    /// Path to the old (baseline) Mach-O binary
    old: PathBuf,
    /// Path to the new Mach-O binary
    new: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Exit with failure if findings reach this severity (info, warning, breaking)
    #[arg(long)]
    fail_on: Option<String>,
    /// Ignore code-signing differences
    #[arg(long)]
    ignore_codesign: bool,
    /// Ignore ObjC differences
    #[arg(long)]
    ignore_objc: bool,
    /// Ignore symbol differences
    #[arg(long)]
    ignore_symbols: bool,
}

pub fn run(args: DiffArgs) -> Result<()> {
    let old_snap = load_snapshot(&args.old, args.arch.as_deref())?;
    let new_snap = load_snapshot(&args.new, args.arch.as_deref())?;

    let mut report = diff_containers(&old_snap, &new_snap);

    // Apply ignore filters
    report.findings.retain(|f| {
        if args.ignore_codesign && f.domain == DiffDomain::Codesign {
            return false;
        }
        if args.ignore_objc && f.domain == DiffDomain::ObjC {
            return false;
        }
        if args.ignore_symbols && f.domain == DiffDomain::Symbols {
            return false;
        }
        true
    });

    if args.json {
        let json = serde_json::to_string_pretty(&report)?;
        println!("{json}");
    } else {
        report.print_text();
    }

    // Exit code based on --fail-on
    if let Some(ref threshold) = args.fail_on {
        let min_severity = match threshold.as_str() {
            "info" => ChangeSeverity::Info,
            "warning" => ChangeSeverity::Warning,
            "breaking" => ChangeSeverity::Breaking,
            other => anyhow::bail!("unknown severity: {other} (use info, warning, or breaking)"),
        };
        if report.findings.iter().any(|f| f.severity >= min_severity) {
            std::io::stdout().flush()?;
            anyhow::bail!("diff findings reached fail threshold {threshold}");
        }
    }

    Ok(())
}

fn load_snapshot(path: &Path, arch_filter: Option<&str>) -> Result<ContainerSnapshot> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    let mut snapshot = ContainerSnapshot::from_container(&container);

    if let Some(filter) = arch_filter {
        filter_snapshot_by_arch(&mut snapshot, filter, path)?;
    }

    Ok(snapshot)
}
