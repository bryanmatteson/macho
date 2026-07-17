/// The c module.
pub mod c;
/// The cpp module.
pub mod cpp;
/// The objc module.
pub mod objc;
/// The prompt module.
pub mod prompt;
/// The schema module.
pub mod schema;
/// The validate module.
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
    EntityCoverageValidator, ModelOutputValidator, OutputContractValidator, ValidationIssue,
    ValidationReport, ValidationSeverity, validate_output,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ConfidenceSummary type.
pub struct ConfidenceSummary {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The overall field.
    pub overall: Option<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The highlights field.
    pub highlights: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The InferredDeclaration type.
pub struct InferredDeclaration {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The entity_id field.
    pub entity_id: Option<String>,
    /// The label field.
    pub label: String,
    /// The code field.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The confidence field.
    pub confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The rationale field.
    pub rationale: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The references field.
    pub references: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The InferredUnresolved type.
pub struct InferredUnresolved {
    /// The entity_id field.
    pub entity_id: String,
    /// The reason field.
    pub reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The fallback field.
    pub fallback: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ModelOutput type.
pub struct ModelOutput {
    /// The header_name field.
    pub header_name: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The declarations field.
    pub declarations: Vec<InferredDeclaration>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The dependencies field.
    pub dependencies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The unresolved field.
    pub unresolved: Vec<InferredUnresolved>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The confidence_summary field.
    pub confidence_summary: Option<ConfidenceSummary>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    /// The notes field.
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The SidecarOutput type.
pub struct SidecarOutput {
    /// The schema_version field.
    pub schema_version: u32,
    /// The header_unit_id field.
    pub header_unit_id: String,
    /// The header_name field.
    pub header_name: String,
    /// The valid field.
    pub valid: bool,
    /// The generated_header field.
    pub generated_header: String,
    /// The model_output field.
    pub model_output: ModelOutput,
    /// The validation field.
    pub validation: ValidationReport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The prompt field.
    pub prompt: Option<PromptSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The repair_prompt field.
    pub repair_prompt: Option<PromptSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The InferenceAttempt type.
pub struct InferenceAttempt {
    /// The prompt field.
    pub prompt: PromptSet,
    /// The raw_response field.
    pub raw_response: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The parsed_output field.
    pub parsed_output: Option<ModelOutput>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The validation field.
    pub validation: Option<ValidationReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The parse_error field.
    pub parse_error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The InferenceRun type.
pub struct InferenceRun {
    /// The success field.
    pub success: bool,
    /// The attempts field.
    pub attempts: Vec<InferenceAttempt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The sidecar field.
    pub sidecar: Option<SidecarOutput>,
}

#[derive(Debug, Clone, Copy)]
/// The InferenceOptions type.
pub struct InferenceOptions {
    /// The max_attempts field.
    pub max_attempts: usize,
}

impl Default for InferenceOptions {
    fn default() -> Self {
        Self { max_attempts: 2 }
    }
}

/// The HeaderInferenceModel type.
pub trait HeaderInferenceModel {
    /// Performs infer.
    fn infer(&self, prompt: &PromptSet) -> crate::Result<String>;
}

#[derive(Debug, Clone)]
/// The HeaderInferenceSession type.
pub struct HeaderInferenceSession {
    bundle: EvidenceBundle,
}

impl HeaderInferenceSession {
    /// Performs new.
    pub fn new(bundle: EvidenceBundle) -> Self {
        Self { bundle }
    }

    /// Performs bundle.
    pub fn bundle(&self) -> &EvidenceBundle {
        &self.bundle
    }

    /// Performs validate_bundle.
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
        Err(crate::Error::validation(format!(
            "invalid evidence bundle: {joined}"
        )))
    }

    /// Performs prompt.
    pub fn prompt(&self) -> crate::Result<PromptSet> {
        self.validate_bundle()?;
        build_prompt(&self.bundle)
    }

    /// Performs parse_model_output.
    pub fn parse_model_output(&self, json: &str) -> crate::Result<ModelOutput> {
        serde_json::from_str(json)
            .map_err(|err| crate::Error::validation(format!("parse model output JSON: {err}")))
    }

    /// Performs validate.
    pub fn validate(
        &self,
        output: &ModelOutput,
        validators: &[&dyn ModelOutputValidator],
    ) -> crate::Result<ValidationReport> {
        self.validate_bundle()?;
        validate_output(&self.bundle, output, validators)
    }

    /// Performs apply.
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
                    crate::Error::validation(format!("serialize model output: {err}"))
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

    /// Performs run_with_model.
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
                        crate::Error::validation("invalid inference sidecar missing repair prompt")
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

/// Performs render_header.
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
