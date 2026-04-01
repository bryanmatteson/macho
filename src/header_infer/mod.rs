pub mod prompt;
pub mod schema;
pub mod validate;

use serde::{Deserialize, Serialize};

pub use prompt::build_parse_repair_prompt;
pub use prompt::{PromptSet, build_prompt, build_repair_prompt};
pub use schema::{
    BundleValidationIssue, BundleValidationReport, EntityKind, EvidenceBundle, EvidenceEntity,
    EvidenceFact, EvidenceSource, EvidenceSourceKind, EvidenceStrength, HeaderEvidenceProvider,
    HeaderLanguage, HeaderUnit, UnresolvedGap, ValidationTarget, ValidationTargetKind,
    validate_bundle,
};
pub use validate::{
    ClangSyntaxValidator, EntityCoverageValidator, ModelOutputValidator, OutputContractValidator,
    ValidationIssue, ValidationReport, ValidationSeverity, validate_output,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfidenceSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub overall: Option<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub highlights: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredDeclaration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    pub label: String,
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rationale: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferredUnresolved {
    pub entity_id: String,
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelOutput {
    pub header_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub declarations: Vec<InferredDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unresolved: Vec<InferredUnresolved>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_summary: Option<ConfidenceSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SidecarOutput {
    pub schema_version: u32,
    pub header_unit_id: String,
    pub header_name: String,
    pub valid: bool,
    pub generated_header: String,
    pub model_output: ModelOutput,
    pub validation: ValidationReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<PromptSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repair_prompt: Option<PromptSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceAttempt {
    pub prompt: PromptSet,
    pub raw_response: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parsed_output: Option<ModelOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub validation: Option<ValidationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InferenceRun {
    pub success: bool,
    pub attempts: Vec<InferenceAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sidecar: Option<SidecarOutput>,
}

#[derive(Debug, Clone, Copy)]
pub struct InferenceOptions {
    pub max_attempts: usize,
}

impl Default for InferenceOptions {
    fn default() -> Self {
        Self { max_attempts: 2 }
    }
}

pub trait HeaderInferenceModel {
    fn infer(&self, prompt: &PromptSet) -> crate::Result<String>;
}

#[derive(Debug, Clone)]
pub struct HeaderInferenceSession {
    bundle: EvidenceBundle,
}

impl HeaderInferenceSession {
    pub fn new(bundle: EvidenceBundle) -> Self {
        Self { bundle }
    }

    pub fn bundle(&self) -> &EvidenceBundle {
        &self.bundle
    }

    pub fn validate_bundle(&self) -> crate::Result<()> {
        let report = validate_bundle(&self.bundle);
        if report.valid {
            return Ok(());
        }
        let joined = report
            .issues
            .iter()
            .map(|issue| format!("{}: {}", issue.code, issue.message))
            .collect::<Vec<_>>()
            .join("; ");
        Err(crate::Error::Validation(format!(
            "invalid evidence bundle: {joined}"
        )))
    }

    pub fn prompt(&self) -> crate::Result<PromptSet> {
        self.validate_bundle()?;
        build_prompt(&self.bundle)
    }

    pub fn parse_model_output(&self, json: &str) -> crate::Result<ModelOutput> {
        serde_json::from_str(json)
            .map_err(|err| crate::Error::Validation(format!("parse model output JSON: {err}")))
    }

    pub fn validate(
        &self,
        output: &ModelOutput,
        validators: &[&dyn ModelOutputValidator],
    ) -> crate::Result<ValidationReport> {
        self.validate_bundle()?;
        validate_output(&self.bundle, output, validators)
    }

    pub fn apply(
        &self,
        output: ModelOutput,
        validators: &[&dyn ModelOutputValidator],
    ) -> crate::Result<SidecarOutput> {
        self.validate_bundle()?;
        let prompt = self.prompt()?;
        let validation = self.validate(&output, validators)?;
        let repair_prompt = if validation.valid {
            None
        } else {
            Some(build_repair_prompt(
                &self.bundle,
                &serde_json::to_string_pretty(&output).map_err(|err| {
                    crate::Error::Validation(format!("serialize model output: {err}"))
                })?,
                &validation.issues,
            )?)
        };

        Ok(SidecarOutput {
            schema_version: EvidenceBundle::CURRENT_SCHEMA_VERSION,
            header_unit_id: self.bundle.header_unit.id.clone(),
            header_name: output.header_name.clone(),
            valid: validation.valid,
            generated_header: render_header(&output),
            model_output: output,
            validation,
            prompt: Some(prompt),
            repair_prompt,
        })
    }

    pub fn run_with_model(
        &self,
        model: &dyn HeaderInferenceModel,
        validators: &[&dyn ModelOutputValidator],
        options: InferenceOptions,
    ) -> crate::Result<InferenceRun> {
        self.validate_bundle()?;
        let max_attempts = options.max_attempts.max(1);
        let mut attempts = Vec::new();
        let mut latest_sidecar = None;
        let mut prompt = self.prompt()?;

        for _ in 0..max_attempts {
            let raw_response = model.infer(&prompt)?;
            match self.parse_model_output(&raw_response) {
                Ok(parsed) => {
                    let sidecar = self.apply(parsed.clone(), validators)?;
                    let validation = sidecar.validation.clone();
                    let attempt = InferenceAttempt {
                        prompt: prompt.clone(),
                        raw_response,
                        parsed_output: Some(parsed.clone()),
                        validation: Some(validation.clone()),
                        parse_error: None,
                    };
                    attempts.push(attempt);

                    latest_sidecar = Some(sidecar.clone());

                    if validation.valid {
                        return Ok(InferenceRun {
                            success: true,
                            attempts,
                            sidecar: Some(sidecar),
                        });
                    }

                    prompt = sidecar.repair_prompt.clone().ok_or_else(|| {
                        crate::Error::Validation(
                            "invalid inference sidecar missing repair prompt".into(),
                        )
                    })?;
                }
                Err(err) => {
                    let parse_error = err.to_string();
                    attempts.push(InferenceAttempt {
                        prompt: prompt.clone(),
                        raw_response: raw_response.clone(),
                        parsed_output: None,
                        validation: None,
                        parse_error: Some(parse_error.clone()),
                    });
                    prompt = build_parse_repair_prompt(&self.bundle, &raw_response, &parse_error)?;
                }
            }
        }

        Ok(InferenceRun {
            success: false,
            attempts,
            sidecar: latest_sidecar,
        })
    }
}

pub fn render_header(output: &ModelOutput) -> String {
    let mut rendered = String::new();
    rendered.push_str("/* Generated by macho header-infer. */\n");
    rendered.push_str("#pragma once\n\n");
    for decl in &output.declarations {
        rendered.push_str(&decl.code);
        if !decl.code.ends_with('\n') {
            rendered.push('\n');
        }
        rendered.push('\n');
    }
    rendered
}
