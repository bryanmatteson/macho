#![cfg(feature = "cli")]

mod support;

use support::{run_cli, temp_file_path};

fn arm64_sibling_fixture() -> Vec<u8> {
    macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::disassembly_arm64(),
        ),
        (
            macho_test_support::CPU_TYPE_ARM64,
            macho_test_support::CPU_SUBTYPE_ARM64E,
            macho_test_support::disassembly_arm64e(),
        ),
    ])
}

#[test]
fn analysis_domain_commands_accept_arch_on_fat_input() {
    let path = temp_file_path("analysis-arch-selection");
    std::fs::write(&path, macho_test_support::disassembly_fat()).expect("write fat fixture");
    let path = path.to_str().expect("UTF-8 fixture path");

    for command in ["xrefs", "strings", "ranges", "vtables"] {
        let output = run_cli([command, path, "--arch", "x86_64", "--color", "never"]);
        assert!(
            output.status.success(),
            "{command} --arch x86_64 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    std::fs::remove_file(path).expect("remove fat fixture");
}

#[test]
fn analysis_domain_commands_preserve_family_siblings_without_json_key_collision() {
    let path = temp_file_path("analysis-arch-siblings");
    std::fs::write(&path, arm64_sibling_fixture()).expect("write fat fixture");
    let path = path.to_str().expect("UTF-8 fixture path");

    for command in [
        "symbols",
        "imports",
        "exports",
        "fixups",
        "codesign",
        "relocations",
        "xrefs",
        "strings",
        "ranges",
        "vtables",
    ] {
        let family = run_cli([
            command, path, "--arch", "arm64", "--format", "json", "--color", "never",
        ]);
        assert!(
            family.status.success(),
            "{command} --arch arm64 failed: {}",
            String::from_utf8_lossy(&family.stderr)
        );
        let family: serde_json::Value =
            serde_json::from_slice(&family.stdout).expect("valid family JSON");
        let family = family["data"].as_object().unwrap_or_else(|| {
            panic!("{command} broad family output must be keyed by distinct slice identities")
        });
        assert_eq!(
            family.keys().map(String::as_str).collect::<Vec<_>>(),
            ["arm64", "arm64e"],
            "{command} must expose both selected siblings"
        );

        let qualified = run_cli([
            command, path, "--arch", "arm64e", "--format", "json", "--color", "never",
        ]);
        assert!(
            qualified.status.success(),
            "{command} --arch arm64e failed: {}",
            String::from_utf8_lossy(&qualified.stderr)
        );
        let qualified: serde_json::Value =
            serde_json::from_slice(&qualified.stdout).expect("valid qualified JSON");
        assert_eq!(
            qualified["data"], family["arm64e"],
            "{command} qualified selection must unwrap exactly the arm64e value"
        );

        let missing = run_cli([
            command,
            path,
            "--arch",
            "definitely_not_real",
            "--format",
            "json",
            "--color",
            "never",
        ]);
        assert!(
            !missing.status.success(),
            "{command} silently accepted an unmatched selector"
        );
        assert!(
            String::from_utf8_lossy(&missing.stderr)
                .contains("no architecture matching 'definitely_not_real' found"),
            "unexpected {command} unmatched-selector diagnostic: {}",
            String::from_utf8_lossy(&missing.stderr)
        );
    }

    for command in ["snapshot", "info"] {
        let output = run_cli([
            command, path, "--arch", "arm64", "--format", "json", "--color", "never",
        ]);
        assert!(
            output.status.success(),
            "{command} --arch arm64 failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let envelope: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid document JSON");
        let slices = envelope["data"]["slices"]
            .as_array()
            .expect("analysis document slices");
        assert_eq!(
            slices
                .iter()
                .map(|slice| slice["identity"]["arch"].as_str().expect("slice arch"))
                .collect::<Vec<_>>(),
            ["arm64", "arm64e"],
            "{command} must expose both qualified identities"
        );
    }

    let container = run_cli([
        "container",
        path,
        "--arch",
        "arm64",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(container.status.success());
    let container: serde_json::Value =
        serde_json::from_slice(&container.stdout).expect("valid container JSON");
    assert_eq!(
        container["data"]["arches"],
        serde_json::json!(["arm64", "arm64e"])
    );

    let deps = run_cli([
        "deps", path, "--arch", "arm64", "--format", "json", "--color", "never",
    ]);
    assert!(
        deps.status.success(),
        "deps --arch arm64 failed: {}",
        String::from_utf8_lossy(&deps.stderr)
    );
    let deps: serde_json::Value =
        serde_json::from_slice(&deps.stdout).expect("one valid dependency JSON document");
    assert_eq!(
        deps["data"]
            .as_object()
            .expect("per-slice dependency values")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["arm64", "arm64e"]
    );

    let audit = run_cli([
        "audit", path, "--arch", "arm64", "--format", "json", "--color", "never",
    ]);
    assert!(
        audit.status.success(),
        "audit --arch arm64 failed: {}",
        String::from_utf8_lossy(&audit.stderr)
    );
    let audit: serde_json::Value = serde_json::from_slice(&audit.stdout).expect("valid audit JSON");
    assert_eq!(
        audit["data"]
            .as_array()
            .expect("audit reports")
            .iter()
            .map(|report| report["arch"].as_str().expect("audit arch"))
            .collect::<Vec<_>>(),
        ["arm64", "arm64e"]
    );

    let disassembly = run_cli([
        "disassemble",
        path,
        "--arch",
        "arm64",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        disassembly.status.success(),
        "disassemble --arch arm64 failed: {}",
        String::from_utf8_lossy(&disassembly.stderr)
    );
    let mut disassembly_slices = disassembly
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("valid NDJSON line"))
        .map(|line| line["architecture"]["cpu_subtype"].as_i64().unwrap())
        .collect::<Vec<_>>();
    disassembly_slices.dedup();
    assert_eq!(
        disassembly_slices,
        [0, i64::from(macho_test_support::CPU_SUBTYPE_ARM64E)]
    );

    std::fs::remove_file(path).expect("remove fat fixture");
}

#[test]
fn x86_64h_is_a_distinct_json_identity_and_qualified_selector() {
    let path = temp_file_path("analysis-x86-arch-siblings");
    std::fs::write(&path, macho_test_support::disassembly_fat_x86_subtypes())
        .expect("write x86 fat fixture");
    let path = path.to_str().expect("UTF-8 fixture path");

    let family = run_cli([
        "symbols", path, "--arch", "x86_64", "--format", "json", "--color", "never",
    ]);
    assert!(family.status.success());
    let family: serde_json::Value =
        serde_json::from_slice(&family.stdout).expect("valid family JSON");
    let family = family["data"].as_object().expect("per-architecture map");
    assert_eq!(
        family.keys().map(String::as_str).collect::<Vec<_>>(),
        ["x86_64", "x86_64h"]
    );

    let qualified = run_cli([
        "symbols", path, "--arch", "x86_64h", "--format", "json", "--color", "never",
    ]);
    assert!(qualified.status.success());
    let qualified: serde_json::Value =
        serde_json::from_slice(&qualified.stdout).expect("valid qualified JSON");
    assert_eq!(qualified["data"], family["x86_64h"]);

    std::fs::remove_file(path).expect("remove x86 fat fixture");
}

#[test]
fn family_subset_provenance_lists_only_the_resolved_exact_architectures() {
    let path = temp_file_path("analysis-three-arch-family-subset");
    let bytes = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_X86_64,
            3,
            macho_test_support::disassembly_x86_64(),
        ),
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::disassembly_arm64(),
        ),
        (
            macho_test_support::CPU_TYPE_ARM64,
            macho_test_support::CPU_SUBTYPE_ARM64E,
            macho_test_support::disassembly_arm64e(),
        ),
    ]);
    std::fs::write(&path, bytes).expect("write three-architecture fixture");
    let path = path.to_str().expect("UTF-8 fixture path");
    let expected = serde_json::json!({
        "kind": "many",
        "architectures": [
            {"cpu_type": i64::from(macho_test_support::CPU_TYPE_ARM64), "cpu_subtype": 0},
            {
                "cpu_type": i64::from(macho_test_support::CPU_TYPE_ARM64),
                "cpu_subtype": i64::from(macho_test_support::CPU_SUBTYPE_ARM64E)
            }
        ]
    });

    for command in ["c", "cpp"] {
        let output = run_cli([
            command, path, "--arch", "arm64", "--format", "json", "--color", "never",
        ]);
        assert!(
            output.status.success(),
            "{command} family recovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let output: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("valid recovery JSON");
        assert_eq!(output["data"]["schema_version"], 2);
        assert_eq!(output["data"]["request"]["architectures"], expected);
        assert_eq!(output["data"]["slices"].as_array().map(Vec::len), Some(2));
    }

    let output = run_cli([
        "disassemble",
        path,
        "--arch",
        "arm64",
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        output.status.success(),
        "family disassembly failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut architectures = output
        .stdout
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<serde_json::Value>(line).expect("valid NDJSON line"))
        .map(|line| {
            assert_eq!(line["schema_version"], 1);
            assert!(line.get("event").is_none());
            (
                line["architecture"]["cpu_type"].as_i64().unwrap(),
                line["architecture"]["cpu_subtype"].as_i64().unwrap(),
            )
        })
        .collect::<Vec<_>>();
    architectures.dedup();
    assert_eq!(
        architectures,
        [
            (i64::from(macho_test_support::CPU_TYPE_ARM64), 0),
            (
                i64::from(macho_test_support::CPU_TYPE_ARM64),
                i64::from(macho_test_support::CPU_SUBTYPE_ARM64E),
            ),
        ]
    );

    std::fs::remove_file(path).expect("remove three-architecture fixture");
}
