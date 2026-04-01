use serde::{Deserialize, Serialize};

use crate::headers::schema::{EvidenceBundle, HeaderLanguage, validate_bundle};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptSet {
    pub system: String,
    pub user: String,
}

pub fn build_prompt(bundle: &EvidenceBundle) -> crate::Result<PromptSet> {
    validate_bundle_or_err(bundle)?;
    let evidence_json = serde_json::to_string_pretty(bundle)
        .map_err(|err| crate::Error::Validation(format!("serialize evidence bundle: {err}")))?;
    Ok(PromptSet {
        system: system_prompt(bundle.header_unit.language),
        user: user_prompt(bundle, &evidence_json),
    })
}

pub fn build_repair_prompt(
    bundle: &EvidenceBundle,
    previous_output_json: &str,
    issues: &[crate::headers::validate::ValidationIssue],
) -> crate::Result<PromptSet> {
    validate_bundle_or_err(bundle)?;
    let issues_json = serde_json::to_string_pretty(issues)
        .map_err(|err| crate::Error::Validation(format!("serialize validation issues: {err}")))?;
    let evidence_json = serde_json::to_string_pretty(bundle)
        .map_err(|err| crate::Error::Validation(format!("serialize evidence bundle: {err}")))?;
    let mut user = String::new();
    user.push_str("Language: ");
    user.push_str(bundle.header_unit.language.prompt_name());
    user.push('\n');
    user.push_str("Target ABI: ");
    user.push_str(&bundle.header_unit.target_abi);
    user.push('\n');
    user.push_str("Goal: repair the previous declaration JSON so it remains ABI-faithful and passes validation.\n\n");
    user.push_str("Evidence bundle:\n");
    user.push_str(&evidence_json);
    user.push_str("\n\nPrevious output JSON:\n");
    user.push_str(previous_output_json);
    user.push_str("\n\nValidation issues:\n");
    user.push_str(&issues_json);
    user.push_str(
        "\n\nTasks:\n\
1. Keep valid declarations unchanged unless a validation issue requires a change.\n\
2. Resolve only the reported issues.\n\
3. Do not invent new entities or dependencies.\n\
4. Return JSON only using the same schema as before.\n",
    );

    Ok(PromptSet {
        system: system_prompt(bundle.header_unit.language),
        user,
    })
}

pub fn build_parse_repair_prompt(
    bundle: &EvidenceBundle,
    previous_response: &str,
    parse_error: &str,
) -> crate::Result<PromptSet> {
    validate_bundle_or_err(bundle)?;
    let evidence_json = serde_json::to_string_pretty(bundle)
        .map_err(|err| crate::Error::Validation(format!("serialize evidence bundle: {err}")))?;
    let mut user = String::new();
    user.push_str("Language: ");
    user.push_str(bundle.header_unit.language.prompt_name());
    user.push('\n');
    user.push_str("Target ABI: ");
    user.push_str(&bundle.header_unit.target_abi);
    user.push('\n');
    user.push_str(
        "Goal: repair the previous response so it is valid JSON matching the required schema.\n\n",
    );
    user.push_str("Evidence bundle:\n");
    user.push_str(&evidence_json);
    user.push_str("\n\nPrevious response:\n");
    user.push_str(previous_response);
    user.push_str("\n\nParse error:\n");
    user.push_str(parse_error);
    user.push_str(
        "\n\nTasks:\n\
1. Return valid JSON only.\n\
2. Use the required output schema.\n\
3. Do not invent entities or facts.\n\
4. Keep the content aligned with the evidence bundle.\n",
    );

    Ok(PromptSet {
        system: system_prompt(bundle.header_unit.language),
        user,
    })
}

fn system_prompt(language: HeaderLanguage) -> String {
    format!(
        "You reconstruct ABI-faithful {} declarations from binary evidence.\n\
Prefer explicit evidence over priors.\n\
Do not invent entities or facts.\n\
When a source spelling is unknown, use a canonical ABI-safe spelling.\n\
When a parameter or field name is unknown, use argN or fieldN.\n\
Return JSON only.",
        language.prompt_name()
    )
}

fn user_prompt(bundle: &EvidenceBundle, evidence_json: &str) -> String {
    let mut user = String::new();
    user.push_str("Language: ");
    user.push_str(bundle.header_unit.language.prompt_name());
    user.push('\n');
    user.push_str("Target ABI: ");
    user.push_str(&bundle.header_unit.target_abi);
    user.push('\n');
    if let Some(triple) = &bundle.header_unit.target_triple {
        user.push_str("Target triple: ");
        user.push_str(triple);
        user.push('\n');
    }
    user.push_str(
        "Goal: infer a compileable header that best matches the recovered ABI surface.\n\n",
    );
    user.push_str("Evidence bundle:\n");
    user.push_str(evidence_json);
    user.push_str(
        "\n\nTasks:\n\
1. Infer declarations only for entities present in the bundle.\n\
2. Preserve exact spellings from external header matches when confidence is high.\n\
3. Prefer canonical spellings when exact source spellings are unsupported.\n\
4. Report unresolved or conflicting cases explicitly.\n\
5. Return JSON with:\n\
   - header_name\n\
   - declarations[]\n\
   - dependencies[]\n\
   - unresolved[]\n\
   - confidence_summary\n\
   - notes\n",
    );
    user
}

fn validate_bundle_or_err(bundle: &EvidenceBundle) -> crate::Result<()> {
    let report = validate_bundle(bundle);
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
