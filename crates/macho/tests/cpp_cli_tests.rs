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
fn cpp_cli_header_preserves_proven_namespace_ownership() {
    let path = support::temp_file_path("cpp-cli-namespace");
    std::fs::write(
        &path,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "__ZN4Tool3runEi",
            external: true,
            defined: true,
        }]),
    )
    .expect("write fixture");
    let headers = tempfile::tempdir().expect("header root");
    std::fs::write(
        headers.path().join("tool.hpp"),
        "namespace Tool { int run(int value); }\n",
    )
    .expect("write header");
    let root = format!("headers={}", headers.path().display());
    let output = support::run_cli([
        "cpp",
        path.to_str().unwrap(),
        "--headers",
        "--header-root",
        &root,
    ]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("namespace Tool {"), "{stdout}");
    assert!(stdout.contains("int run(int value);"), "{stdout}");
}

#[test]
fn cpp_cli_header_projects_a_correlated_public_class_member() {
    let path = support::temp_file_path("cpp-cli-class-member");
    std::fs::write(&path, cpp_fixture()).expect("write fixture");
    let headers = tempfile::tempdir().expect("header root");
    std::fs::write(
        headers.path().join("demo.hpp"),
        "class Demo { public: int run(int value) const; };\n",
    )
    .expect("write header");
    let root = format!("headers={}", headers.path().display());
    let output = support::run_cli([
        "cpp",
        path.to_str().unwrap(),
        "--headers",
        "--header-root",
        &root,
    ]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("class Demo {"), "{stdout}");
    assert!(stdout.contains("public:"), "{stdout}");
    assert!(stdout.contains("int run(int value) const;"), "{stdout}");
    assert!(!stdout.contains("Demo::run"), "{stdout}");
}

#[test]
fn cpp_cli_header_preserves_a_correlated_struct_owner() {
    let path = support::temp_file_path("cpp-cli-struct-member");
    std::fs::write(
        &path,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "__ZN4Demo3runEi",
            external: true,
            defined: true,
        }]),
    )
    .expect("write fixture");
    let headers = tempfile::tempdir().expect("header root");
    std::fs::write(
        headers.path().join("demo.hpp"),
        "struct Demo { int run(int value); };\n",
    )
    .expect("write header");
    let root = format!("headers={}", headers.path().display());
    let output = support::run_cli([
        "cpp",
        path.to_str().unwrap(),
        "--headers",
        "--header-root",
        &root,
    ]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("struct Demo {"), "{stdout}");
    assert!(stdout.contains("public:"), "{stdout}");
    assert!(stdout.contains("int run(int value);"), "{stdout}");
    assert!(!stdout.contains("class Demo"), "{stdout}");
}

#[test]
fn cpp_cli_header_preserves_a_typed_namespace_class_owner_chain() {
    let path = support::temp_file_path("cpp-cli-nested-class-member");
    std::fs::write(
        &path,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "__ZNK4Tool4Demo3runEi",
            external: true,
            defined: true,
        }]),
    )
    .expect("write fixture");
    let headers = tempfile::tempdir().expect("header root");
    std::fs::write(
        headers.path().join("demo.hpp"),
        "namespace Tool { class Demo { public: int run(int value) const; }; }\n",
    )
    .expect("write header");
    let root = format!("headers={}", headers.path().display());
    let output = support::run_cli([
        "cpp",
        path.to_str().unwrap(),
        "--headers",
        "--header-root",
        &root,
    ]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("namespace Tool {"), "{stdout}");
    assert!(stdout.contains("class Demo {"), "{stdout}");
    assert!(stdout.contains("public:"), "{stdout}");
    assert!(stdout.contains("int run(int value) const;"), "{stdout}");
}

#[test]
fn cpp_cli_header_does_not_correlate_a_same_leaf_from_the_wrong_namespace() {
    let path = support::temp_file_path("cpp-cli-wrong-namespace");
    std::fs::write(
        &path,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "__ZN4Tool3runEi",
            external: true,
            defined: true,
        }]),
    )
    .expect("write fixture");
    let headers = tempfile::tempdir().expect("header root");
    std::fs::write(
        headers.path().join("other.hpp"),
        "namespace Other { int run(int value); }\n",
    )
    .expect("write header");
    let root = format!("headers={}", headers.path().display());
    let output = support::run_cli([
        "cpp",
        path.to_str().unwrap(),
        "--headers",
        "--header-root",
        &root,
    ]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("owner/unproven_owner: 1"), "{stdout}");
    assert!(!stdout.contains("namespace Other"), "{stdout}");
}

#[test]
fn cpp_cli_empty_header_reports_one_exact_blocker_per_source_entity() {
    let path = support::temp_file_path("cpp-cli-qualified-type");
    std::fs::write(
        &path,
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "__ZTIN4Demo6WidgetE",
            external: true,
            defined: true,
        }]),
    )
    .expect("write fixture");
    let output = support::run_cli(["cpp", path.to_str().unwrap(), "--headers"]);
    let _ = std::fs::remove_file(path);
    assert!(
        output.status.success(),
        "cpp CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("selected source entities: 1"), "{stdout}");
    assert!(stdout.contains("exact projection blockers: 1"), "{stdout}");
    assert!(stdout.contains("owner/unproven_owner: 1"), "{stdout}");
    assert!(
        stdout.contains("header-infer export --all-header-gaps"),
        "{stdout}"
    );
    assert!(!stdout.contains("layout_fields"), "{stdout}");
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
