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
