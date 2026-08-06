#![deny(missing_docs)]
//! Offline, bounded, evidence-accountable header hypothesis exchange.
//!
//! This crate has no provider, network, SDK, compiler, retry, or host-process
//! integration. It consumes validated recovery reports and shared typed header
//! declarations, and produces immutable bundle/response/report artifacts.

mod artifact;
mod bundle;
mod prompt;
mod syntax;
mod validate;

pub use artifact::{
    ArtifactError, BundleConstraints, EvidenceExcerpt, FactExcerpt, HeaderSubsetVersion,
    HypothesisBundle, HypothesisDiagnostic, HypothesisDiagnosticCode, HypothesisDisposition,
    HypothesisLimits, HypothesisOperation, HypothesisOperationKind, HypothesisReport,
    HypothesisResult, HypothesisTarget, ModelResponse, ProposedHypothesis, SupportRef,
};
pub use bundle::export_bundle;
pub use prompt::build_prompt;
pub use validate::validate_response;

use crate::analysis::header_syntax::{
    HeaderParser as _, Language, TreeSitterHeaderParser, ValidationLimits, validate,
};

/// Header language accepted by the in-process convenience validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderLanguage {
    /// C header syntax.
    C,
    /// C++ header syntax.
    Cpp,
    /// Objective-C header syntax.
    ObjectiveC,
}

/// Pure header-validation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRequest<'a> {
    /// Header language.
    pub language: HeaderLanguage,
    /// Complete source text.
    pub source: &'a str,
}

/// Pure header-validation result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationOutcome {
    /// Whether syntax and semantic validation both passed.
    pub accepted: bool,
    /// Stable validator diagnostics.
    pub diagnostics: Vec<String>,
}

/// Process-free validation failure.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// The shared parser rejected the source.
    #[error("parse header: {0}")]
    Parse(String),
    /// The shared validator rejected configured bounds.
    #[error("validate header: {0}")]
    Validate(String),
}

/// Pure header validator used by tests and adapters that already own source text.
pub trait HeaderValidator: Send + Sync {
    /// Validates one complete source document.
    fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<ValidationOutcome, ValidationError>;
}

/// Shared in-process parser and semantic validator.
#[derive(Debug, Default, Clone, Copy)]
pub struct InProcessHeaderValidator;

impl HeaderValidator for InProcessHeaderValidator {
    fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<ValidationOutcome, ValidationError> {
        let language = match request.language {
            HeaderLanguage::C => Language::C,
            HeaderLanguage::Cpp => Language::Cpp,
            HeaderLanguage::ObjectiveC => Language::ObjectiveC,
        };
        let unit = TreeSitterHeaderParser
            .parse(language, request.source)
            .map_err(|error| ValidationError::Parse(error.to_string()))?;
        let report = validate(&unit, ValidationLimits::default())
            .map_err(|error| ValidationError::Validate(error.to_string()))?;
        Ok(ValidationOutcome {
            accepted: report.syntax_valid && report.semantic_valid,
            diagnostics: report
                .diagnostics
                .into_iter()
                .map(|diagnostic| format!("{:?}: {}", diagnostic.code, diagnostic.message))
                .collect(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_process_validation_rejects_unresolved_types() {
        let result = InProcessHeaderValidator
            .validate(&ValidationRequest {
                language: HeaderLanguage::C,
                source: "Missing value;\n",
            })
            .expect("validator executes");
        assert!(!result.accepted);
    }
}
