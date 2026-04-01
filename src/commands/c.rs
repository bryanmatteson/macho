use anyhow::Result;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct CArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Render a recovered header
    #[arg(long)]
    headers: bool,
    /// Output as JSON
    #[arg(long)]
    json: bool,
}

pub fn run(args: CArgs) -> Result<()> {
    let mode = if args.json {
        "JSON"
    } else if args.headers {
        "header"
    } else {
        "summary"
    };
    let arch_hint = args
        .arch
        .as_deref()
        .map(|arch| format!(" for arch {arch}"))
        .unwrap_or_default();

    Err(anyhow::anyhow!(
        "C declaration recovery is not implemented yet ({mode} mode requested for {}{arch_hint})",
        args.path.display()
    ))
}
