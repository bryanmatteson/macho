use std::path::PathBuf;

struct FixtureGuard(PathBuf);

impl Drop for FixtureGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

#[test]
fn documented_cli_examples_execute_against_shared_fixture() {
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/cmd/fixture.macho");
    std::fs::write(&fixture, macho_test_support::thin64_arm64(2)).expect("write fixture");
    let _guard = FixtureGuard(fixture);

    let cases = trycmd::TestCases::new();
    cases.register_bin("macho", PathBuf::from(env!("CARGO_BIN_EXE_macho")));
    cases.case("tests/cmd/readme.trycmd");
    cases.run();
}

#[test]
fn onboarding_distinguishes_installation_msrv_and_machine_output_contracts() {
    let readme = include_str!("../../../README.md");

    assert!(readme.contains("cargo add macho-lib --rename macho"));
    assert!(readme.contains("cargo install macho-cli"));
    assert!(!readme.contains("cargo install macho-lib"));
    assert!(readme.contains("libraries declare Rust 1.85"));
    assert!(readme.contains("CLI requires Rust 1.88"));
    assert!(readme.contains("disassemble --format json"));
    assert!(readme.contains("newline-delimited JSON"));
    assert!(readme.contains("header-infer export"));
    assert!(readme.contains("intentionally require text mode"));
    assert!(!readme.contains("Complete header reconstruction"));
    assert!(!readme.contains("reconstructed the complete declaration"));

    let mut root = macho_cli::clap_command();
    let root_help = root.render_long_help().to_string();
    assert!(root_help.contains("JSON report or command-documented NDJSON stream"));
    let disassemble_help = root
        .find_subcommand_mut("disassemble")
        .expect("live disassemble command")
        .render_long_help()
        .to_string();
    assert!(disassemble_help.contains("newline-delimited JSON, not a single document"));
}
