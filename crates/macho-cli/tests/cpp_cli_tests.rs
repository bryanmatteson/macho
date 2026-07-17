mod support;

fn cpp_fixture() -> Vec<u8> {
    macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "__ZN4DemoC1Ev",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "__ZN4DemoD1Ev",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "__ZNK4Demo3runEi",
            external: true,
            defined: true,
        },
    ])
}

#[test]
fn cpp_cli_json_emits_recovered_classes() {
    let path = support::temp_file_path("cpp-cli-json");
    std::fs::write(&path, cpp_fixture()).expect("write fixture");
    let output = support::run_cli(["cpp", path.to_str().unwrap(), "--format", "json"]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    assert!(envelope["data"]["index"]["classes"]["Demo"].is_object());
}

#[test]
fn cpp_cli_headers_emit_class_declaration() {
    let path = support::temp_file_path("cpp-cli-headers");
    std::fs::write(&path, cpp_fixture()).expect("write fixture");
    let output = support::run_cli(["cpp", path.to_str().unwrap(), "--headers"]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("class Demo"));
    assert!(stdout.contains("run"));
}
