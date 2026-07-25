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
    /// Check workspace, package, CLI, changelog, lockfile, and tag authorities.
    Release {
        /// Check release authorities without modifying them.
        #[arg(long)]
        check: bool,
        /// Require clean version-bearing inputs and an exact matching release tag.
        #[arg(long, requires = "check")]
        require_tag: bool,
    },
    /// Run the stable verification gate in contract order.
    Verify,
    /// Build every fuzz target with a nightly Rust toolchain.
    VerifyFuzz,
}

fn main() -> Result<()> {
    let root = workspace_root()?;
    match Args::parse().command {
        Command::Architecture => architecture::check(&root),
        Command::Docs { check } => {
            anyhow::ensure!(check, "docs requires --check; generation is explicit");
            docs::check(&root)
        }
        Command::Release { check, require_tag } => {
            anyhow::ensure!(check, "release requires --check");
            release::check(&root, require_tag)
        }
        Command::Verify => verify::run(&root),
        Command::VerifyFuzz => verify::run_fuzz(&root),
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
