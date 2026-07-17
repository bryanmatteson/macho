use std::path::PathBuf;
use std::process::Command;

#[test]
fn every_facade_feature_combination_compiles() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("xtask crate is under <workspace>/crates")
        .to_path_buf();
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let combinations = [
        ("no-default", None),
        ("metadata", Some("metadata")),
        ("analysis", Some("analysis")),
        ("mutation", Some("mutation")),
        ("workflow", Some("workflow")),
        ("dyld-cache", Some("dyld-cache")),
        ("header-infer", Some("header-infer")),
        ("full", Some("full")),
    ];
    for (name, feature) in combinations {
        let mut command = Command::new(&cargo);
        command
            .current_dir(&root)
            .args(["check", "-p", "macho", "--lib", "--no-default-features"]);
        if let Some(feature) = feature {
            command.args(["--features", feature]);
        }
        assert!(
            command
                .status()
                .expect("run feature compile check")
                .success(),
            "facade feature combination {name} failed to compile"
        );
    }
    assert!(
        Command::new(cargo)
            .current_dir(root)
            .args(["check", "-p", "macho", "--lib"])
            .status()
            .expect("run default feature compile check")
            .success(),
        "default facade features failed to compile"
    );
}
