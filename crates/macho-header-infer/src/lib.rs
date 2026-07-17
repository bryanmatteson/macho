#![deny(missing_docs)]
//! Evidence aggregation, prompt generation, and injectable header validation.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Header language accepted by a validator.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum HeaderLanguage {
    /// ISO C-family declaration syntax.
    C,
    /// C++ declaration syntax.
    Cpp,
    /// Objective-C declaration syntax.
    ObjectiveC,
}

/// A pure validation request supplied to a [`HeaderValidator`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidationRequest<'a> {
    /// Language of `source`.
    pub language: HeaderLanguage,
    /// Complete header source to validate.
    pub source: &'a str,
    /// Optional SDK include roots obtained through [`SdkLocator`].
    pub include_roots: &'a [PathBuf],
}

/// Result returned by a header validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidationOutcome {
    /// Whether the validator accepted the source.
    pub accepted: bool,
    /// Structured validator diagnostics without process-specific formatting.
    pub diagnostics: Vec<String>,
}

/// Typed capability failure used when a host integration is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CapabilityError {
    /// The capability is not installed or cannot be discovered.
    #[error("capability unavailable: {capability}")]
    Unavailable {
        #[doc = "The capability field."]
        capability: &'static str,
    },
    /// The adapter returned data that could not be interpreted.
    #[error("malformed {capability} response: {detail}")]
    Malformed {
        /// The str field.
        capability: &'static str,
        /// The String field.
        detail: String,
    },
}

/// Injectable header syntax or compiler validator.
pub trait HeaderValidator: Send + Sync {
    /// Validate one complete source document.
    fn validate(
        &self,
        request: &ValidationRequest<'_>,
    ) -> Result<ValidationOutcome, CapabilityError>;
}

/// Injectable source of SDK-dependent include roots.
pub trait SdkLocator: Send + Sync {
    /// Locate deterministic include roots for a language.
    fn include_roots(&self, language: HeaderLanguage) -> Result<Vec<PathBuf>, CapabilityError>;
}

/// One weighted fact used to construct an inference prompt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InferenceEvidence {
    /// Stable evidence category such as `dwarf.type` or `symbol.signature`.
    pub kind: String,
    /// Human-readable fact content.
    pub value: String,
    /// Confidence in basis points, from zero through ten thousand.
    pub confidence_bps: u16,
}

/// Deterministically render evidence as an inference prompt.
pub fn build_prompt(language: HeaderLanguage, evidence: &[InferenceEvidence]) -> String {
    let mut sorted = evidence.to_vec();
    sorted.sort_by(|left, right| {
        right
            .confidence_bps
            .cmp(&left.confidence_bps)
            .then_with(|| left.kind.cmp(&right.kind))
            .then_with(|| left.value.cmp(&right.value))
    });
    let language = match language {
        HeaderLanguage::C => "C",
        HeaderLanguage::Cpp => "C++",
        HeaderLanguage::ObjectiveC => "Objective-C",
    };
    let mut prompt = format!("Infer a complete {language} header from these facts:\n");
    for fact in sorted {
        prompt.push_str(&format!(
            "- [{}; confidence={}] {}\n",
            fact.kind, fact.confidence_bps, fact.value
        ));
    }
    prompt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_order_is_deterministic_and_confidence_first() {
        let evidence = vec![
            InferenceEvidence {
                kind: "symbol".into(),
                value: "f".into(),
                confidence_bps: 5000,
            },
            InferenceEvidence {
                kind: "dwarf".into(),
                value: "int f(void)".into(),
                confidence_bps: 9000,
            },
        ];
        let prompt = build_prompt(HeaderLanguage::C, &evidence);
        assert!(prompt.find("dwarf").unwrap() < prompt.find("symbol").unwrap());
    }
}
