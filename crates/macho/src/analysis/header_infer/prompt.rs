//! Deterministic provider-neutral prompt serialization.

use crate::analysis::header_infer::{ArtifactError, HypothesisBundle};

/// Renders a deterministic UTF-8 prompt containing only the bounded bundle.
pub fn build_prompt(bundle: &HypothesisBundle) -> Result<String, ArtifactError> {
    bundle.validate()?;
    let language = match bundle.language() {
        crate::analysis::report::RecoveryLanguage::CAbi => "C",
        crate::analysis::report::RecoveryLanguage::Cpp => "C++",
    };
    let bundle_json = String::from_utf8(bundle.canonical_bytes()?)
        .map_err(|error| ArtifactError::Invalid(error.to_string()))?;
    let prompt = format!(
        "Propose typed {language} header hypotheses for this bounded recovery bundle.\n\
         Return only ModelResponse schema version 1 JSON. Use only listed entity, gap, fact, and \
         evidence IDs. Cover every target gap exactly once with one allowed operation or \
         unresolved_gap_ids. Declaration fragments must be HeaderDecl wire objects; raw source, \
         confidence scores, providers, and deterministic-fact edits are forbidden. A \
         propose_grouping operation must provide an exact typed scope path (namespace, record, or \
         class), exact access for record boundaries, and only qualifies the target's \
         projection_template; it cannot change the template declaration.\n\n{bundle_json}\n"
    );
    crate::analysis::header_infer::artifact::enforce(
        "prompt bytes",
        prompt.len() as u64,
        bundle.limits().max_prompt_bytes,
    )?;
    Ok(prompt)
}
