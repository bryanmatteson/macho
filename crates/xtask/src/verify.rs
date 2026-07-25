use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};

pub fn run(root: &Path) -> Result<()> {
    super::architecture::check(root)?;
    super::docs::check(root)?;
    super::release::check(root, false)?;
    for command in [
        &["fmt", "--all", "--", "--check"][..],
        &["check", "--workspace", "--all-targets", "--all-features"][..],
        &[
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ][..],
        &["doc", "--workspace", "--all-features", "--no-deps"][..],
        &["test", "--workspace", "--all-features"][..],
        &["bench", "--workspace", "--all-features", "--no-run"][..],
    ] {
        run_command(root, "cargo", command, command.first() == Some(&"doc"))?;
    }
    println!("verify: ok");
    Ok(())
}

pub fn run_fuzz(root: &Path) -> Result<()> {
    run_command(root, "cargo", &["fuzz", "build"], false)?;
    println!("verify-fuzz: ok");
    Ok(())
}

fn run_command(root: &Path, program: &str, args: &[&str], rustdoc_warnings: bool) -> Result<()> {
    println!("+ {program} {}", args.join(" "));
    let mut command = Command::new(program);
    command.args(args).current_dir(root);
    if rustdoc_warnings {
        command.env("RUSTDOCFLAGS", "-D warnings");
    }
    let status = command
        .status()
        .with_context(|| format!("run {program} {}", args.join(" ")))?;
    if status.success() {
        Ok(())
    } else {
        bail!("command failed: {program} {}", args.join(" "))
    }
}
