use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail};
use cargo_metadata::MetadataCommand;

pub fn check(root: &Path) -> Result<()> {
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .context("cargo metadata failed")?;
    let workspace_versions: BTreeSet<_> = metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
        .map(|package| package.version.to_string())
        .collect();
    if workspace_versions.len() != 1 {
        bail!("workspace packages have divergent versions: {workspace_versions:?}");
    }
    let version = workspace_versions
        .iter()
        .next()
        .context("workspace has no packages")?;
    if macho_cli::version() != version {
        bail!(
            "CLI version {} differs from workspace version {version}",
            macho_cli::version()
        );
    }
    let changelog = fs::read_to_string(root.join("CHANGELOG.md")).context("read CHANGELOG.md")?;
    if !changelog
        .lines()
        .any(|line| line.trim() == format!("## {version}"))
    {
        bail!("CHANGELOG.md has no `## {version}` heading");
    }
    check_lockfile(root, version)?;
    check_clean_exact_tag(root, version)?;
    println!("release: ok ({version})");
    Ok(())
}

fn check_lockfile(root: &Path, version: &str) -> Result<()> {
    let lock = fs::read_to_string(root.join("Cargo.lock")).context("read Cargo.lock")?;
    for name in [
        "macho-core",
        "macho-insn",
        "macho-dyld",
        "macho-demangle",
        "macho-symbols",
        "macho-codesign",
        "macho-dwarf",
        "macho-objc",
        "macho-swift",
        "macho-cpp",
        "macho-analysis",
        "macho-mutate",
        "macho-patch",
        "macho-dyld-cache",
        "macho-header-infer",
        "macho-workflow",
        "macho",
        "macho-cli",
        "macho-test-support",
        "xtask",
    ] {
        let package = format!("name = \"{name}\"\nversion = \"{version}\"");
        if !lock.contains(&package) {
            bail!("Cargo.lock does not contain {name} at workspace version {version}");
        }
    }
    Ok(())
}

fn check_clean_exact_tag(root: &Path, version: &str) -> Result<()> {
    let paths = ["Cargo.toml", "Cargo.lock", "CHANGELOG.md", "crates"];
    let status = Command::new("git")
        .arg("diff")
        .arg("--quiet")
        .arg("HEAD")
        .arg("--")
        .args(paths)
        .current_dir(root)
        .status()
        .context("run git diff for version-bearing files")?;
    if !status.success() {
        return Ok(());
    }
    let output = Command::new("git")
        .args(["describe", "--tags", "--exact-match", "HEAD"])
        .current_dir(root)
        .output()
        .context("query exact tag")?;
    if output.status.success() {
        let tag = String::from_utf8(output.stdout)?.trim().to_string();
        validate_tag(&tag, version)?;
    }
    Ok(())
}

fn validate_tag(tag: &str, version: &str) -> Result<()> {
    let expected = format!("v{version}");
    if tag == expected {
        Ok(())
    } else {
        bail!("exact tag {tag} differs from workspace version {expected}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matching_tag_is_accepted() {
        validate_tag("v0.2.0", "0.2.0").unwrap();
    }

    #[test]
    fn mismatched_tag_is_rejected() {
        assert!(validate_tag("v0.1.3", "0.2.0").is_err());
    }
}
