mod support;

use std::collections::BTreeMap;

use macho::analysis::reconstruct::{
    ConfidenceSummary, EntityKind, EvidenceBundle, EvidenceEntity, EvidenceFact, EvidenceSource,
    EvidenceSourceKind, EvidenceStrength, HeaderInferenceModel, HeaderInferenceSession,
    HeaderLanguage, HeaderUnit, InferenceOptions, InferredDeclaration, InferredUnresolved,
    ModelOutput, PromptSet, ValidationTarget, ValidationTargetKind, build_prompt, validate_bundle,
};
use macho_cli::adapters::XcrunClangValidator;
use support::{run_cli, temp_file_path};

fn sample_bundle(language: HeaderLanguage) -> EvidenceBundle {
    EvidenceBundle {
        schema_version: EvidenceBundle::CURRENT_SCHEMA_VERSION,
        header_unit: HeaderUnit {
            id: "unit.demo".into(),
            name: "demo.h".into(),
            language,
            target_abi: "apple-macho".into(),
            target_triple: Some("arm64-apple-darwin".into()),
            module: Some("Demo".into()),
            summary: Some("Demo inference bundle".into()),
            prompt_hints: vec!["Prefer exact fact spellings when available".into()],
        },
        entities: vec![EvidenceEntity {
            id: "entity.widget".into(),
            kind: match language {
                HeaderLanguage::C => EntityKind::Function,
                HeaderLanguage::Cpp | HeaderLanguage::Mixed => EntityKind::Class,
                _ => EntityKind::Class,
            },
            language,
            display_name: match language {
                HeaderLanguage::C => "demo_add".into(),
                HeaderLanguage::Cpp | HeaderLanguage::Mixed => "Widget".into(),
                _ => "Widget".into(),
            },
            required: true,
            canonical_decl: Some(match language {
                HeaderLanguage::C => "int demo_add(int lhs, int rhs);".into(),
                HeaderLanguage::Cpp | HeaderLanguage::Mixed => {
                    "class Widget { public: int value() const; };".into()
                }
                _ => "class Widget { public: int value() const; };".into(),
            }),
            preferred_spelling: None,
            mangled_name: None,
            dependencies: Vec::new(),
            exact_fact_ids: vec!["fact.primary".into()],
            evidence: vec![EvidenceFact {
                id: "fact.primary".into(),
                summary: "Primary declaration recovered deterministically".into(),
                strength: EvidenceStrength::Exact,
                confidence: Some(0.97),
                source: EvidenceSource {
                    kind: EvidenceSourceKind::Manual,
                    label: "test fixture".into(),
                    image: None,
                    path: None,
                    line: None,
                    address: Some(0x1000),
                    note: None,
                },
                payload: serde_json::Value::Null,
            }],
            payload: serde_json::Value::Null,
        }],
        unresolved: vec![macho::analysis::reconstruct::UnresolvedGap {
            id: "gap.ret".into(),
            entity_id: "entity.widget".into(),
            summary: "Return type alias may be source-specific".into(),
            suggested_fallback: Some("Use canonical integer spelling".into()),
        }],
        validation_targets: vec![ValidationTarget {
            kind: ValidationTargetKind::Syntax,
            label: "clang syntax".into(),
            expected: serde_json::Value::Null,
        }],
        notes: vec!["bundle note".into()],
        metadata: BTreeMap::from([(String::from("owner"), String::from("tests"))]),
    }
}

fn valid_output(language: HeaderLanguage) -> ModelOutput {
    ModelOutput {
        header_name: "demo.h".into(),
        declarations: vec![InferredDeclaration {
            entity_id: Some("entity.widget".into()),
            label: "primary".into(),
            code: match language {
                HeaderLanguage::C => "int demo_add(int lhs, int rhs);".into(),
                HeaderLanguage::Cpp | HeaderLanguage::Mixed => {
                    "class Widget {\npublic:\n    int value() const;\n};".into()
                }
                _ => "class Widget {\npublic:\n    int value() const;\n};".into(),
            },
            confidence: Some(0.95),
            rationale: vec!["exact deterministic evidence".into()],
            references: vec!["fact.primary".into()],
        }],
        dependencies: vec!["entity.widget".into()],
        unresolved: vec![InferredUnresolved {
            entity_id: "entity.widget".into(),
            reason: "typedef alias unresolved".into(),
            fallback: Some("emit canonical spelling".into()),
        }],
        confidence_summary: Some(ConfidenceSummary {
            overall: Some(0.94),
            highlights: vec!["syntax-safe".into()],
        }),
        notes: vec!["generated for testing".into()],
    }
}

#[derive(Debug)]
struct SequenceModel {
    responses: std::sync::Mutex<Vec<String>>,
}

impl SequenceModel {
    fn new(responses: Vec<String>) -> Self {
        Self {
            responses: std::sync::Mutex::new(responses),
        }
    }
}

impl HeaderInferenceModel for SequenceModel {
    fn infer(&self, _prompt: &PromptSet) -> macho::analysis::Result<String> {
        let mut guard = self.responses.lock().expect("lock");
        if guard.is_empty() {
            return Err(macho::analysis::AnalysisError::validation(
                "no more responses",
            ));
        }
        Ok(guard.remove(0))
    }
}

#[test]
fn prompt_includes_evidence_and_contract() {
    let prompt = build_prompt(&sample_bundle(HeaderLanguage::Cpp)).expect("prompt");
    assert!(prompt.system.contains("Return JSON only"));
    assert!(prompt.user.contains("Evidence bundle:"));
    assert!(prompt.user.contains("header_name"));
}

#[test]
fn session_apply_generates_valid_sidecar_for_c() {
    let session = HeaderInferenceSession::new(sample_bundle(HeaderLanguage::C));
    let clang = XcrunClangValidator;
    let sidecar = session
        .apply(valid_output(HeaderLanguage::C), &[&clang])
        .expect("apply");

    assert!(
        sidecar.valid,
        "expected valid sidecar: {:?}",
        sidecar.validation
    );
    assert!(sidecar.generated_header.contains("#pragma once"));
    assert!(sidecar.generated_header.contains("int demo_add"));
    assert!(sidecar.repair_prompt.is_none());
}

#[test]
fn session_reports_unknown_entity_and_repair_prompt() {
    let session = HeaderInferenceSession::new(sample_bundle(HeaderLanguage::C));
    let clang = XcrunClangValidator;
    let mut output = valid_output(HeaderLanguage::C);
    output.declarations[0].entity_id = Some("entity.missing".into());

    let sidecar = session.apply(output, &[&clang]).expect("apply");
    assert!(!sidecar.valid);
    assert!(
        sidecar
            .validation
            .issues
            .iter()
            .any(|issue| issue.code == "HI001")
    );
    assert!(sidecar.repair_prompt.is_some());
}

#[test]
fn model_output_roundtrip_from_json() {
    let session = HeaderInferenceSession::new(sample_bundle(HeaderLanguage::Cpp));
    let json = serde_json::to_string_pretty(&valid_output(HeaderLanguage::Cpp)).expect("json");
    let parsed = session.parse_model_output(&json).expect("parse");
    assert_eq!(parsed.header_name, "demo.h");
    assert_eq!(parsed.declarations.len(), 1);
}

#[test]
fn invalid_bundle_is_reported() {
    let mut bundle = sample_bundle(HeaderLanguage::C);
    bundle.schema_version = 99;
    bundle.entities[0]
        .dependencies
        .push("entity.missing".into());
    let report = validate_bundle(&bundle);
    assert!(!report.valid);
    assert!(report.issues.iter().any(|issue| issue.code == "HB001"));
    assert!(report.issues.iter().any(|issue| issue.code == "HB009"));
}

#[test]
fn session_rejects_invalid_bundle() {
    let mut bundle = sample_bundle(HeaderLanguage::C);
    bundle.header_unit.target_abi.clear();
    let session = HeaderInferenceSession::new(bundle);
    let err = session.prompt().expect_err("bundle should be rejected");
    assert!(err.to_string().contains("invalid evidence bundle"));
}

#[test]
fn repair_loop_recovers_from_invalid_json() {
    let session = HeaderInferenceSession::new(sample_bundle(HeaderLanguage::C));
    let clang = XcrunClangValidator;
    let model = SequenceModel::new(vec![
        String::from("{not valid json"),
        serde_json::to_string_pretty(&valid_output(HeaderLanguage::C)).expect("response json"),
    ]);

    let run = session
        .run_with_model(&model, &[&clang], InferenceOptions { max_attempts: 3 })
        .expect("run");

    assert!(run.success);
    assert_eq!(run.attempts.len(), 2);
    assert!(run.attempts[0].parse_error.is_some());
    assert!(run.sidecar.as_ref().expect("sidecar").valid);
}

#[test]
fn failed_repair_loop_keeps_latest_invalid_sidecar() {
    let session = HeaderInferenceSession::new(sample_bundle(HeaderLanguage::C));
    let clang = XcrunClangValidator;
    let mut invalid = valid_output(HeaderLanguage::C);
    invalid.declarations[0].entity_id = Some("entity.missing".into());
    let model = SequenceModel::new(vec![
        serde_json::to_string_pretty(&invalid).expect("response json"),
    ]);

    let run = session
        .run_with_model(&model, &[&clang], InferenceOptions { max_attempts: 1 })
        .expect("run");

    assert!(!run.success);
    let sidecar = run
        .sidecar
        .expect("latest invalid sidecar should be preserved");
    assert!(!sidecar.valid);
    assert!(
        sidecar
            .validation
            .issues
            .iter()
            .any(|issue| issue.code == "HI001")
    );
}

#[test]
fn cli_prompt_and_apply_flow() {
    let bundle_path = temp_file_path("header-infer-bundle");
    let response_path = temp_file_path("header-infer-response");
    let header_path = temp_file_path("header-infer-header");
    let sidecar_path = temp_file_path("header-infer-sidecar");

    std::fs::write(
        &bundle_path,
        serde_json::to_vec_pretty(&sample_bundle(HeaderLanguage::C)).expect("bundle json"),
    )
    .expect("write bundle");
    std::fs::write(
        &response_path,
        serde_json::to_vec_pretty(&valid_output(HeaderLanguage::C)).expect("response json"),
    )
    .expect("write response");

    let prompt = run_cli([
        "header-infer",
        "check-bundle",
        bundle_path.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(
        prompt.status.success(),
        "check-bundle stderr: {}",
        String::from_utf8_lossy(&prompt.stderr)
    );
    let report_json: serde_json::Value =
        serde_json::from_slice(&prompt.stdout).expect("valid check bundle json");
    assert_eq!(report_json["data"]["valid"], true);

    let prompt = run_cli([
        "header-infer",
        "prompt",
        bundle_path.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(
        prompt.status.success(),
        "prompt stderr: {}",
        String::from_utf8_lossy(&prompt.stderr)
    );
    let prompt_envelope: serde_json::Value =
        serde_json::from_slice(&prompt.stdout).expect("valid prompt envelope");
    let prompt_json: PromptSet =
        serde_json::from_value(prompt_envelope["data"].clone()).expect("valid prompt json");
    assert!(prompt_json.user.contains("Evidence bundle"));

    let apply = run_cli([
        "header-infer",
        "apply",
        bundle_path.to_str().expect("utf8"),
        response_path.to_str().expect("utf8"),
        "--header-out",
        header_path.to_str().expect("utf8"),
        "--sidecar-out",
        sidecar_path.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(
        apply.status.success(),
        "apply stderr: {}",
        String::from_utf8_lossy(&apply.stderr)
    );
    let apply_envelope: serde_json::Value =
        serde_json::from_slice(&apply.stdout).expect("valid sidecar envelope");
    let sidecar: macho::analysis::reconstruct::SidecarOutput =
        serde_json::from_value(apply_envelope["data"].clone()).expect("valid sidecar json");
    assert!(sidecar.valid);

    let header_text = std::fs::read_to_string(&header_path).expect("header");
    assert!(header_text.contains("demo_add"));
    let persisted_sidecar = std::fs::read_to_string(&sidecar_path).expect("sidecar");
    assert!(persisted_sidecar.contains("\"valid\": true"));

    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(response_path);
    let _ = std::fs::remove_file(header_path);
    let _ = std::fs::remove_file(sidecar_path);
}

#[test]
fn cli_check_bundle_fails_for_invalid_bundle() {
    let bundle_path = temp_file_path("header-infer-invalid-bundle");
    let mut bundle = sample_bundle(HeaderLanguage::C);
    bundle.header_unit.target_abi.clear();
    std::fs::write(
        &bundle_path,
        serde_json::to_vec_pretty(&bundle).expect("bundle json"),
    )
    .expect("write bundle");

    let output = run_cli([
        "header-infer",
        "check-bundle",
        bundle_path.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let report_json: serde_json::Value =
        serde_json::from_slice(&output.stderr).expect("valid error envelope");
    assert_eq!(report_json["ok"], false);

    let _ = std::fs::remove_file(bundle_path);
}

#[test]
fn cli_validate_fails_for_invalid_model_output() {
    let bundle_path = temp_file_path("header-infer-bundle-invalid-model");
    let response_path = temp_file_path("header-infer-response-invalid-model");

    let mut output = valid_output(HeaderLanguage::C);
    output.declarations[0].entity_id = Some("entity.missing".into());

    std::fs::write(
        &bundle_path,
        serde_json::to_vec_pretty(&sample_bundle(HeaderLanguage::C)).expect("bundle json"),
    )
    .expect("write bundle");
    std::fs::write(
        &response_path,
        serde_json::to_vec_pretty(&output).expect("response json"),
    )
    .expect("write response");

    let result = run_cli([
        "header-infer",
        "validate",
        bundle_path.to_str().expect("utf8"),
        response_path.to_str().expect("utf8"),
        "--format",
        "json",
    ]);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    let report_json: serde_json::Value =
        serde_json::from_slice(&result.stderr).expect("valid validation error envelope");
    assert_eq!(report_json["ok"], false);

    let _ = std::fs::remove_file(bundle_path);
    let _ = std::fs::remove_file(response_path);
}
