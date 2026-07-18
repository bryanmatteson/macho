mod support;

use std::path::{Path, PathBuf};

use support::{run_cli, temp_file_path};

struct Fixture {
    object: PathBuf,
    recovery: PathBuf,
    bundle: PathBuf,
    response: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        Self::new_for_field("owner")
    }

    fn new_for_field(field: &str) -> Self {
        let object = temp_file_path("header-infer-object");
        let recovery = temp_file_path("header-infer-recovery");
        let bundle = temp_file_path("header-infer-bundle");
        let response = temp_file_path("header-infer-response");
        std::fs::write(
            &object,
            macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
                name: "_demo_add",
                external: true,
                defined: true,
            }]),
        )
        .expect("write Mach-O object");
        let output = run_cli(["c", "--format", "json", object.to_str().expect("utf8")]);
        assert!(
            output.status.success(),
            "C recovery failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        std::fs::write(&recovery, &output.stdout).expect("write recovery envelope");
        let recovery_json: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("recovery JSON");
        let gap = recovery_json["data"]["slices"][0]["entities"][0]["gaps"]
            .as_array()
            .expect("gaps")
            .iter()
            .find(|gap| gap["field"] == field)
            .and_then(|gap| gap["id"].as_str())
            .expect("gap ID")
            .to_owned();
        let export = run_cli([
            "header-infer",
            "export",
            recovery.to_str().expect("utf8"),
            "--arch",
            "x86_64",
            "--gap",
            &gap,
            "--output",
            bundle.to_str().expect("utf8"),
        ]);
        assert!(
            export.status.success(),
            "bundle export failed: {}",
            String::from_utf8_lossy(&export.stderr)
        );
        assert!(export.stdout.is_empty());
        let bundle_json: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&bundle).expect("bundle bytes"))
                .expect("bundle JSON");
        std::fs::write(
            &response,
            serde_json::to_vec(&serde_json::json!({
                "schema_version": 1,
                "bundle_digest": bundle_json["bundle_digest"],
                "hypotheses": [],
                "unresolved_gap_ids": [gap],
            }))
            .expect("response JSON"),
        )
        .expect("write response");
        Self {
            object,
            recovery,
            bundle,
            response,
        }
    }
}

#[test]
fn typed_declaration_fragment_is_rendered_reparsed_and_accepted() {
    let fixture = Fixture::new_for_field("return_type");
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.bundle).expect("bundle"))
            .expect("bundle JSON");
    let entity = bundle["targets"][0]["entity_id"]
        .as_str()
        .expect("entity ID");
    let gap = bundle["targets"][0]["gap_ids"][0].as_str().expect("gap ID");
    let evidence = bundle["evidence"][0]["evidence_id"]
        .as_str()
        .expect("evidence ID");
    write_json(
        &fixture.response,
        &serde_json::json!({
            "schema_version": 1,
            "bundle_digest": bundle["bundle_digest"],
            "hypotheses": [{
                "id": "1".repeat(64),
                "entity_id": entity,
                "gap_id": gap,
                "operation": {
                    "kind": "propose_declaration_fragment",
                    "fragment": {
                        "kind": "function",
                        "id": entity,
                        "owner": null,
                        "name": "demo_add",
                        "signature": {
                            "kind": "function",
                            "return_type": {"kind": "builtin", "name": "int"},
                            "parameters": [],
                            "parameter_state": "known",
                            "variadic": false,
                            "calling_convention": "c",
                            "qualifiers": {
                                "const": false,
                                "volatile": false,
                                "reference": null,
                                "noexcept": null
                            }
                        },
                        "storage": "none",
                        "linkage": "c"
                    }
                },
                "support": [{"kind": "evidence", "evidence_id": evidence}]
            }],
            "unresolved_gap_ids": []
        }),
    );
    let output = run_cli([
        "header-infer",
        "validate",
        fixture.bundle.to_str().expect("utf8"),
        fixture.response.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "validation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report");
    assert_eq!(report["data"]["results"][0]["disposition"], "accepted");
    assert!(
        report["data"]["projected_header"]["source"]
            .as_str()
            .is_some_and(|source| source.contains("int demo_add(void);"))
    );
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for path in [&self.object, &self.recovery, &self.bundle, &self.response] {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[test]
fn offline_bundle_prompt_validate_and_apply_flow() {
    let fixture = Fixture::new();
    let check = run_cli([
        "header-infer",
        "check-bundle",
        fixture.bundle.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(check.status.success());
    let check_json: serde_json::Value = serde_json::from_slice(&check.stdout).expect("check JSON");
    assert_eq!(check_json["data"]["valid"], true);

    let first = run_cli([
        "header-infer",
        "prompt",
        fixture.bundle.to_str().expect("utf8"),
    ]);
    let second = run_cli([
        "header-infer",
        "prompt",
        fixture.bundle.to_str().expect("utf8"),
    ]);
    assert!(first.status.success());
    assert_eq!(first.stdout, second.stdout);
    assert!(String::from_utf8_lossy(&first.stdout).contains("ModelResponse schema version 1"));

    let validation = run_cli([
        "header-infer",
        "validate",
        fixture.bundle.to_str().expect("utf8"),
        fixture.response.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(
        validation.status.success(),
        "validation failed: {}",
        String::from_utf8_lossy(&validation.stderr)
    );
    let report: serde_json::Value =
        serde_json::from_slice(&validation.stdout).expect("report envelope");
    assert_eq!(report["data"]["results"], serde_json::json!([]));
    assert_eq!(
        report["data"]["unresolved_gap_ids"]
            .as_array()
            .map(Vec::len),
        Some(1)
    );

    let header = temp_file_path("header-infer-header");
    let sidecar = temp_file_path("header-infer-sidecar");
    let apply = run_cli([
        "header-infer",
        "apply",
        fixture.bundle.to_str().expect("utf8"),
        fixture.response.to_str().expect("utf8"),
        "--header-out",
        header.to_str().expect("utf8"),
        "--sidecar-out",
        sidecar.to_str().expect("utf8"),
    ]);
    assert!(apply.status.success());
    assert!(apply.stdout.is_empty());
    assert!(
        std::fs::read_to_string(&header)
            .expect("header")
            .contains("no declarations accepted")
    );
    let persisted: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&sidecar).expect("sidecar")).expect("sidecar JSON");
    assert_eq!(persisted["schema_version"], 1);
    let _ = std::fs::remove_file(header);
    let _ = std::fs::remove_file(sidecar);
}

#[test]
fn stale_digest_and_unknown_keys_are_execution_failures() {
    let fixture = Fixture::new();
    let bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.bundle).expect("bundle"))
            .expect("bundle JSON");
    let gap = bundle["targets"][0]["gap_ids"][0].as_str().expect("gap");
    let invalid = temp_file_path("header-infer-invalid-response");
    std::fs::write(
        &invalid,
        serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "bundle_digest": "0".repeat(64),
            "hypotheses": [],
            "unresolved_gap_ids": [gap],
            "confidence": 0.9,
        }))
        .expect("invalid response JSON"),
    )
    .expect("write invalid response");
    let output = run_cli([
        "header-infer",
        "validate",
        fixture.bundle.to_str().expect("utf8"),
        invalid.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let error: serde_json::Value = serde_json::from_slice(&output.stderr).expect("error envelope");
    assert_eq!(error["ok"], false);
    let _ = std::fs::remove_file(invalid);
}

#[test]
fn fixed_artifact_commands_reject_json_and_forced_color() {
    let fixture = Fixture::new();
    for arguments in [
        vec![
            "header-infer",
            "prompt",
            fixture.bundle.to_str().expect("utf8"),
            "--format",
            "json",
        ],
        vec![
            "header-infer",
            "apply",
            fixture.bundle.to_str().expect("utf8"),
            fixture.response.to_str().expect("utf8"),
            "--color",
            "always",
        ],
    ] {
        let output = run_cli(arguments);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn malformed_bundle_digest_is_rejected_before_prompt() {
    let fixture = Fixture::new();
    let invalid = temp_file_path("header-infer-invalid-bundle");
    let mut bundle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&fixture.bundle).expect("bundle"))
            .expect("bundle JSON");
    bundle["bundle_digest"] = serde_json::Value::String("0".repeat(64));
    write_json(&invalid, &bundle);
    let output = run_cli(["header-infer", "prompt", invalid.to_str().expect("utf8")]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let _ = std::fs::remove_file(invalid);
}

fn write_json(path: &Path, value: &serde_json::Value) {
    std::fs::write(path, serde_json::to_vec(value).expect("JSON bytes")).expect("write JSON")
}
