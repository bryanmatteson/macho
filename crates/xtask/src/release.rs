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
    check_license_contract(root, &metadata)?;
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

fn check_license_contract(root: &Path, metadata: &cargo_metadata::Metadata) -> Result<()> {
    anyhow::ensure!(root.join("LICENSE").is_file(), "root LICENSE is absent");
    for package in metadata
        .packages
        .iter()
        .filter(|package| metadata.workspace_members.contains(&package.id))
    {
        validate_license_declaration(
            &package.name,
            package.license.as_deref(),
            package.license_file.is_some(),
        )?;
    }
    Ok(())
}

fn validate_license_declaration(
    package: &str,
    license: Option<&str>,
    has_license_file: bool,
) -> Result<()> {
    if license != Some("Apache-2.0") {
        bail!("workspace package {package} license is not Apache-2.0");
    }
    if has_license_file {
        bail!("workspace package {package} declares redundant license-file");
    }
    Ok(())
}

fn check_lockfile(root: &Path, version: &str) -> Result<()> {
    check_lockfile_packages(
        &root.join("Cargo.lock"),
        version,
        &[
            "macho-core",
            "macho-insn",
            "macho-dyld",
            "macho-evidence",
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
        ],
    )?;
    check_lockfile_packages(
        &root.join("fuzz/Cargo.lock"),
        version,
        &[
            "macho-codesign",
            "macho-core",
            "macho-dyld",
            "macho-dyld-cache",
            "macho-insn",
            "macho-mutate",
        ],
    )
}

fn check_lockfile_packages(path: &Path, version: &str, names: &[&str]) -> Result<()> {
    let lock = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    for name in names {
        let package = format!("name = \"{name}\"\nversion = \"{version}\"");
        if !lock.contains(&package) {
            bail!(
                "{} does not contain {name} at workspace version {version}",
                path.display()
            );
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

    #[test]
    fn non_apache_license_is_rejected() {
        assert!(validate_license_declaration("fixture", Some("MIT"), true).is_err());
    }

    #[test]
    fn redundant_license_file_is_rejected() {
        assert!(validate_license_declaration("fixture", Some("Apache-2.0"), true).is_err());
    }

    #[test]
    fn stale_auxiliary_lockfile_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let lock = temporary.path().join("Cargo.lock");
        fs::write(
            &lock,
            "[[package]]\nname = \"macho-core\"\nversion = \"0.2.0\"\n",
        )
        .unwrap();
        assert!(check_lockfile_packages(&lock, "0.4.0", &["macho-core"]).is_err());
    }
}
