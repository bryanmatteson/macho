#![cfg(feature = "cli")]

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
fn cpp_cli_json_emits_conservative_canonical_recovery() {
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
    let data = &envelope["data"];
    assert_eq!(data["schema_version"], 2);
    assert_eq!(data["language"], "cpp");
    let slice = &data["slices"][0];
    assert_eq!(slice["observations"].as_array().map(Vec::len), Some(3));
    assert_eq!(slice["entities"].as_array().map(Vec::len), Some(4));
    assert!(
        slice["observations"]
            .as_array()
            .unwrap()
            .iter()
            .all(|item| item["disposition"]["kind"] == "included")
    );
}

#[test]
fn cpp_cli_header_emits_only_the_positive_anchor_class_forward() {
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
    assert!(stdout.contains("class Demo;"), "{stdout}");
    assert!(!stdout.contains("Demo::run"), "{stdout}");
}

#[test]
fn cpp_abi_execution_is_bounded_to_the_exact_selected_entity() {
    let path = support::temp_file_path("cpp-cli-abi-selection");
    std::fs::write(&path, cpp_fixture()).expect("write fixture");
    let output = support::run_cli([
        "cpp",
        path.to_str().unwrap(),
        "--analysis",
        "abi",
        "--name",
        "*run*",
        "--format",
        "json",
    ]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let envelope: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("JSON envelope");
    let slice = &envelope["data"]["slices"][0];
    let selected = slice["resolved_plan"]["selected_entity_ids"]
        .as_array()
        .expect("selected entity IDs");
    assert_eq!(selected.len(), 1);
    let abi_execution = slice["executions"]
        .as_array()
        .expect("execution ledger")
        .iter()
        .find(|execution| execution["collector"] == "abi_body")
        .expect("ABI execution record");
    assert_eq!(
        abi_execution["target_entity_ids"]
            .as_array()
            .expect("ABI target entity IDs"),
        selected
    );
    assert_eq!(abi_execution["counts"]["selected_targets"], 1);
    for entity in slice["entities"].as_array().expect("entities") {
        if entity["id"] != selected[0] {
            assert!(
                entity["evidence"]
                    .as_array()
                    .expect("entity evidence")
                    .iter()
                    .all(|evidence| evidence["collector"] != "abi_body")
            );
        }
    }
}
