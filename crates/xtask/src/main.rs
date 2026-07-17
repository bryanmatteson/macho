mod architecture;
mod docs;
mod release;
mod verify;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "cargo xtask")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Enforce workspace dependency direction and source ownership.
    Architecture,
    /// Generate or check README/help/diagnostic documentation.
    Docs {
        /// Check committed files without modifying them.
        #[arg(long)]
        check: bool,
    },
    /// Check workspace, CLI, changelog, lockfile, and exact-tag versions.
    Release {
        /// Check release authorities without modifying them.
        #[arg(long)]
        check: bool,
    },
    /// Run the complete Plan 15 verification gate in contract order.
    Verify,
}

fn main() -> Result<()> {
    let root = workspace_root()?;
    match Args::parse().command {
        Command::Architecture => architecture::check(&root),
        Command::Docs { check } => {
            anyhow::ensure!(
                check,
                "docs requires --check; generation is intentionally explicit"
            );
            docs::check(&root)
        }
        Command::Release { check } => {
            anyhow::ensure!(check, "release requires --check");
            release::check(&root)
        }
        Command::Verify => verify::run(&root),
    }
}

fn workspace_root() -> Result<std::path::PathBuf> {
    let manifest = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    Ok(manifest
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or_else(|| anyhow::anyhow!("xtask manifest is not under <workspace>/crates/xtask"))?
        .to_path_buf())
}
