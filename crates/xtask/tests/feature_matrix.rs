use std::path::PathBuf;
use std::process::Command;

use cargo_metadata::MetadataCommand;

#[test]
fn every_declared_feature_compiles_independently() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("xtask crate is under <workspace>/crates")
        .to_path_buf();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let metadata = MetadataCommand::new()
        .manifest_path(root.join("Cargo.toml"))
        .no_deps()
        .exec()
        .expect("resolve workspace feature metadata");
    let product = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "macho")
        .expect("workspace has a macho package");

    assert!(
        Command::new(&cargo)
            .current_dir(&root)
            .args([
                "check",
                "--locked",
                "-p",
                "macho",
                "--lib",
                "--no-default-features",
            ])
            .status()
            .expect("run empty feature compile check")
            .success(),
        "empty feature composition failed to compile"
    );
    assert!(
        Command::new(&cargo)
            .current_dir(&root)
            .args(["check", "--locked", "-p", "macho", "--lib"])
            .status()
            .expect("run default feature compile check")
            .success(),
        "default feature composition failed to compile"
    );
    for feature in product
        .features
        .keys()
        .filter(|name| name.as_str() != "default")
    {
        assert!(
            Command::new(&cargo)
                .current_dir(&root)
                .args([
                    "check",
                    "--locked",
                    "-p",
                    "macho",
                    "--lib",
                    "--no-default-features",
                    "--features",
                    feature,
                ])
                .status()
                .expect("run feature compile check")
                .success(),
            "declared feature {feature} failed to compile independently"
        );
    }
    assert!(
        Command::new(cargo)
            .current_dir(root)
            .args([
                "check",
                "--locked",
                "-p",
                "macho",
                "--no-default-features",
                "--features",
                "cli",
                "--bin",
                "macho",
            ])
            .status()
            .expect("run CLI binary compile check")
            .success(),
        "CLI feature failed to compile the shipped binary"
    );
}
