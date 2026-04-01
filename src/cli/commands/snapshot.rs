use crate::analysis::snapshot::ContainerSnapshot;
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::commands::common::filter_snapshot_by_arch;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(clap::Args)]
pub struct SnapshotArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
}

pub fn run(args: SnapshotArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    let mut snapshot = ContainerSnapshot::from_container(&container);

    if let Some(ref filter) = args.arch {
        filter_snapshot_by_arch(&mut snapshot, filter, &args.path)?;
    }

    let json = serde_json::to_string_pretty(&snapshot)?;
    println!("{json}");
    Ok(())
}
