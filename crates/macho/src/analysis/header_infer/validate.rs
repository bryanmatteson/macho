//! Pure response validation and shared typed-header projection.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::header_syntax::{TranslationUnit, ValidationLimits};
use crate::analysis::report::{
    HeaderDecl, HeaderOwnerKind, HeaderOwnerRef, HeaderProjection, HeaderValidationReport,
    HypothesisReportVersion, NonEmpty, RecoveryGapId, Severity,
};

use crate::analysis::header_infer::artifact::{
    ArtifactError, HypothesisBundle, HypothesisDiagnostic, HypothesisDiagnosticCode,
    HypothesisDisposition, HypothesisOperation, HypothesisReport, HypothesisResult, ModelResponse,
    SupportRef, enforce,
};
use crate::analysis::header_infer::syntax;

/// Validates a response against the exact bundle without modifying either artifact.
pub fn validate_response(
    bundle: &HypothesisBundle,
    response: &ModelResponse,
) -> Result<HypothesisReport, ArtifactError> {
    bundle.validate()?;
    if response.bundle_digest != *bundle.bundle_digest() {
        return Err(ArtifactError::Invalid(
            "response bundle digest mismatch".into(),
        ));
    }
    let target_entities = bundle
        .targets()
        .iter()
        .map(|target| target.entity_id.as_str())
        .collect::<BTreeSet<_>>();
    let target_gaps = bundle
        .targets()
        .iter()
        .flat_map(|target| target.gap_ids.as_slice())
        .map(RecoveryGapId::as_str)
        .collect::<BTreeSet<_>>();
    let fact_ids = bundle
        .facts()
        .iter()
        .map(|fact| fact.fact_id.as_str())
        .collect::<BTreeSet<_>>();
    let evidence_ids = bundle
        .evidence()
        .iter()
        .map(|record| record.evidence_id.as_str())
        .collect::<BTreeSet<_>>();
    let mut hypothesis_ids = BTreeSet::new();
    let mut dispositions = BTreeMap::<&str, &'static str>::new();
    for hypothesis in &response.hypotheses {
        if !hypothesis_ids.insert(hypothesis.id.as_str()) {
            return Err(ArtifactError::Invalid(format!(
                "duplicate hypothesis ID {}",
                hypothesis.id
            )));
        }
        if dispositions
            .insert(hypothesis.gap_id.as_str(), "hypothesis")
            .is_some()
        {
            return Err(ArtifactError::Invalid(format!(
                "duplicate operation for gap {}",
                hypothesis.gap_id
            )));
        }
        let target = bundle.target_for_gap(&hypothesis.gap_id).ok_or_else(|| {
            ArtifactError::Invalid(format!(
                "hypothesis {} references non-target gap {}",
                hypothesis.id, hypothesis.gap_id
            ))
        })?;
        if target.entity_id != hypothesis.entity_id {
            return Err(ArtifactError::Invalid(format!(
                "hypothesis {} entity does not own gap {}",
                hypothesis.id, hypothesis.gap_id
            )));
        }
        if !target
            .allowed_operations
            .as_slice()
            .contains(&hypothesis.operation.kind())
        {
            return Err(ArtifactError::Invalid(format!(
                "operation is not allowed for gap {}",
                hypothesis.gap_id
            )));
        }
        let mut support = BTreeSet::new();
        for reference in hypothesis.support.as_slice() {
            let (key, present) = match reference {
                SupportRef::Evidence { evidence_id } => (
                    format!("evidence:{evidence_id}"),
                    evidence_ids.contains(evidence_id.as_str()),
                ),
                SupportRef::DeterministicFact { fact_id } => (
                    format!("fact:{fact_id}"),
                    fact_ids.contains(fact_id.as_str()),
                ),
                SupportRef::RelatedEntity { entity_id } => (
                    format!("entity:{entity_id}"),
                    target_entities.contains(entity_id.as_str()),
                ),
            };
            if !present {
                return Err(ArtifactError::Invalid(format!(
                    "hypothesis {} has dangling support {key}",
                    hypothesis.id
                )));
            }
            if !support.insert(key.clone()) {
                return Err(ArtifactError::Invalid(format!(
                    "hypothesis {} repeats support {key}",
                    hypothesis.id
                )));
            }
        }
        validate_operation(bundle, hypothesis)?;
    }
    for gap in &response.unresolved_gap_ids {
        if !target_gaps.contains(gap.as_str()) {
            return Err(ArtifactError::Invalid(format!(
                "unresolved gap {gap} is not a bundle target"
            )));
        }
        if dispositions.insert(gap.as_str(), "unresolved").is_some() {
            return Err(ArtifactError::Invalid(format!(
                "gap {gap} has more than one response disposition"
            )));
        }
    }
    for gap in &target_gaps {
        if !dispositions.contains_key(gap) {
            return Err(ArtifactError::Invalid(format!(
                "target gap {gap} is omitted from the response"
            )));
        }
    }

    let mut lowered = Vec::new();
    let mut lowered_indexes = Vec::new();
    let mut lowered_declarations = Vec::new();
    let mut results = Vec::with_capacity(response.hypotheses.len());
    for hypothesis in &response.hypotheses {
        let mut result = HypothesisResult {
            hypothesis_id: hypothesis.id.clone(),
            entity_id: hypothesis.entity_id.clone(),
            gap_id: hypothesis.gap_id.clone(),
            disposition: HypothesisDisposition::Accepted,
            support: hypothesis.support.clone(),
            diagnostics: Vec::new(),
        };
        let mut grouped_syntax = None;
        let declaration = match &hypothesis.operation {
            HypothesisOperation::ProposeDeclarationFragment { fragment } => Some(fragment.clone()),
            HypothesisOperation::ProposeGrouping { owner } => {
                let template = bundle
                    .target_for_gap(&hypothesis.gap_id)
                    .and_then(|target| target.projection_template.as_ref());
                match template {
                    Some(template) => match apply_grouping(template, owner) {
                        Ok(declaration) => {
                            grouped_syntax = Some(syntax::declaration_in_owner(template, owner));
                            Some(declaration)
                        }
                        Err(error) => {
                            result.disposition = HypothesisDisposition::Unresolved;
                            result.diagnostics.push(diagnostic(
                                HypothesisDiagnosticCode::UnsupportedHeaderFragment,
                                error.to_string(),
                                &hypothesis.id,
                            ));
                            None
                        }
                    },
                    None => {
                        result.disposition = HypothesisDisposition::Unresolved;
                        result.diagnostics.push(diagnostic(
                            HypothesisDiagnosticCode::UnsupportedHeaderFragment,
                            "grouping target has no Macho-derived declaration template".into(),
                            &hypothesis.id,
                        ));
                        None
                    }
                }
            }
            _ => None,
        };
        if let Some(wire_declaration) = declaration {
            match grouped_syntax.unwrap_or_else(|| syntax::declaration(&wire_declaration)) {
                Ok(syntax_declaration) => {
                    lowered_indexes.push(results.len());
                    lowered.push(syntax_declaration);
                    lowered_declarations.push((results.len(), wire_declaration));
                }
                Err(error) => {
                    result.disposition = HypothesisDisposition::Rejected;
                    result.diagnostics.push(diagnostic(
                        HypothesisDiagnosticCode::UnsupportedHeaderFragment,
                        error.to_string(),
                        &hypothesis.id,
                    ));
                }
            }
        }
        results.push(result);
    }

    let language = syntax::language(bundle.language());
    let unit = TranslationUnit {
        language,
        declarations: lowered,
        declaration_spans: Vec::new(),
    };
    let mut source = crate::analysis::header_syntax::render(&unit)
        .map_err(|error| ArtifactError::Invalid(format!("render typed fragments: {error}")))?;
    let validation = crate::analysis::header_syntax::validate(&unit, ValidationLimits::default())
        .map_err(|error| {
        ArtifactError::Invalid(format!("validate typed fragments: {error}"))
    })?;
    if !validation.syntax_valid || !validation.semantic_valid {
        let code = if validation.syntax_valid {
            HypothesisDiagnosticCode::HeaderSemanticInvalid
        } else {
            HypothesisDiagnosticCode::HeaderSyntaxInvalid
        };
        let detail = validation
            .diagnostics
            .iter()
            .map(|item| format!("{:?}: {}", item.code, item.message))
            .collect::<Vec<_>>()
            .join("; ");
        for index in &lowered_indexes {
            let result = &mut results[*index];
            result.disposition = HypothesisDisposition::Rejected;
            let hypothesis_id = result.hypothesis_id.clone();
            result
                .diagnostics
                .push(diagnostic(code, detail.clone(), &hypothesis_id));
        }
        source.clear();
    }
    enforce(
        "rendered header bytes",
        source.len() as u64,
        bundle.limits().max_rendered_header_bytes,
    )?;

    let accepted_declarations = lowered_declarations
        .into_iter()
        .filter_map(|(index, declaration)| {
            (results[index].disposition == HypothesisDisposition::Accepted).then_some(declaration)
        })
        .collect::<Vec<_>>();
    let mut unresolved_gap_ids = response.unresolved_gap_ids.clone();
    unresolved_gap_ids.extend(
        results
            .iter()
            .filter(|result| result.disposition != HypothesisDisposition::Accepted)
            .map(|result| result.gap_id.clone()),
    );
    unresolved_gap_ids.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    unresolved_gap_ids.dedup();
    let wire_validation = HeaderValidationReport::from(&validation);
    let projected_header = (!accepted_declarations.is_empty()).then(|| HeaderProjection {
        language: bundle.language(),
        declarations: accepted_declarations,
        // The artifact schema identifies unresolved source gaps by stable ID
        // rather than duplicating the source gap record. A gap ID is not
        // reversible to its field, so the hypothesis report keeps the exact
        // IDs in `unresolved_gap_ids` instead of fabricating a HeaderGap field.
        unresolved: Vec::new(),
        assumption_ledger: Default::default(),
        diagnostics: Vec::new(),
        source: format!("/* hypothesis-assisted; see sidecar for authority */\n{source}"),
        validation: wire_validation.clone(),
    });

    Ok(HypothesisReport {
        schema_version: HypothesisReportVersion::CURRENT,
        bundle_digest: bundle.bundle_digest().clone(),
        response_digest: response.digest()?,
        results,
        unresolved_gap_ids,
        validation: wire_validation,
        projected_header,
    })
}

fn apply_grouping(
    template: &HeaderDecl,
    owner: &HeaderOwnerRef,
) -> Result<HeaderDecl, ArtifactError> {
    validate_grouping_owner(owner)?;
    let mut declaration = template.clone();
    match &mut declaration {
        HeaderDecl::Function {
            owner: declaration_owner,
            ..
        }
        | HeaderDecl::Variable {
            owner: declaration_owner,
            ..
        }
        | HeaderDecl::Record {
            owner: declaration_owner,
            ..
        }
        | HeaderDecl::Forward {
            owner: declaration_owner,
            ..
        } => *declaration_owner = Some(owner.clone()),
        HeaderDecl::Alias { path, .. } => {
            let mut qualified = owner.path.as_slice().to_vec();
            qualified.extend(path.as_slice().iter().cloned());
            *path = NonEmpty::new(qualified)
                .map_err(|_| ArtifactError::Invalid("grouped declaration path is empty".into()))?;
        }
        HeaderDecl::ObjcInterface { .. }
        | HeaderDecl::ObjcCategory { .. }
        | HeaderDecl::ObjcProtocol { .. }
        | HeaderDecl::ObjcForward { .. } => {
            return Err(ArtifactError::Invalid(
                "C++ grouping cannot lower an Objective-C declaration".into(),
            ));
        }
    }
    Ok(declaration)
}

fn validate_operation(
    bundle: &HypothesisBundle,
    hypothesis: &crate::analysis::header_infer::ProposedHypothesis,
) -> Result<(), ArtifactError> {
    match &hypothesis.operation {
        HypothesisOperation::ChooseCandidate { candidate_index } => {
            let supported_facts = hypothesis
                .support
                .as_slice()
                .iter()
                .filter_map(|reference| match reference {
                    SupportRef::DeterministicFact { fact_id } => Some(fact_id),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let valid = supported_facts.iter().any(|fact_id| {
                bundle
                    .facts()
                    .iter()
                    .find(|fact| fact.fact_id == **fact_id)
                    .and_then(|fact| fact.canonical_projection.get("candidates"))
                    .and_then(serde_json::Value::as_array)
                    .is_some_and(|candidates| (*candidate_index as usize) < candidates.len())
            });
            if !valid {
                return Err(ArtifactError::Invalid(format!(
                    "hypothesis {} candidate index is not supported by a referenced conflicted fact",
                    hypothesis.id
                )));
            }
        }
        HypothesisOperation::ProposeCanonicalName { .. } => {}
        HypothesisOperation::ProposeGrouping { owner } => {
            validate_grouping_owner(owner)?;
            if owner.terminal_kind() == HeaderOwnerKind::Namespace && owner.entity_id.is_some() {
                return Err(ArtifactError::Invalid(format!(
                    "hypothesis {} namespace grouping cannot name an owner entity",
                    hypothesis.id
                )));
            }
            if owner.entity_id.as_ref().is_some_and(|entity_id| {
                !bundle
                    .targets()
                    .iter()
                    .any(|target| target.entity_id == *entity_id)
            }) {
                return Err(ArtifactError::Invalid(format!(
                    "hypothesis {} grouping owner is outside the bundle",
                    hypothesis.id
                )));
            }
        }
        HypothesisOperation::ProposeDeclarationFragment { fragment } => {
            let fragment_id = match fragment {
                HeaderDecl::Function { id, .. }
                | HeaderDecl::Variable { id, .. }
                | HeaderDecl::Record { id, .. }
                | HeaderDecl::Forward { id, .. }
                | HeaderDecl::Alias { id, .. } => id,
                _ => {
                    return Err(ArtifactError::Invalid(
                        "C/C++ hypothesis bundle cannot carry Objective-C declarations".into(),
                    ));
                }
            };
            if fragment_id != &hypothesis.entity_id {
                return Err(ArtifactError::Invalid(format!(
                    "hypothesis {} declaration ID does not match its entity",
                    hypothesis.id
                )));
            }
        }
    }
    Ok(())
}

fn validate_grouping_owner(owner: &HeaderOwnerRef) -> Result<(), ArtifactError> {
    use crate::analysis::report::Access;

    if !owner.has_exact_scopes() {
        return Err(ArtifactError::Invalid(
            "grouping owner must provide one exact kind and access slot per path component".into(),
        ));
    }
    let kinds = owner.scope_kinds.as_slice();
    let access = owner.scope_access.as_slice();
    if access[0].is_some() {
        return Err(ArtifactError::Invalid(
            "the outermost owner scope cannot have member access".into(),
        ));
    }
    for index in 1..kinds.len() {
        match kinds[index - 1] {
            HeaderOwnerKind::Namespace if access[index].is_some() => {
                return Err(ArtifactError::Invalid(
                    "a namespace-owned scope cannot have member access".into(),
                ));
            }
            HeaderOwnerKind::Record | HeaderOwnerKind::Class
                if !matches!(
                    access[index],
                    Some(Access::Public | Access::Protected | Access::Private)
                ) =>
            {
                return Err(ArtifactError::Invalid(
                    "a record-owned scope requires exact member access".into(),
                ));
            }
            _ => {}
        }
    }
    match owner.terminal_kind() {
        HeaderOwnerKind::Namespace if owner.member_access.is_some() => Err(ArtifactError::Invalid(
            "namespace grouping cannot carry member access".into(),
        )),
        HeaderOwnerKind::Record | HeaderOwnerKind::Class
            if !matches!(
                owner.member_access,
                Some(Access::Public | Access::Protected | Access::Private)
            ) =>
        {
            Err(ArtifactError::Invalid(
                "record grouping requires exact declaration access".into(),
            ))
        }
        _ => Ok(()),
    }
}

fn diagnostic(
    code: HypothesisDiagnosticCode,
    message: String,
    hypothesis_id: &crate::analysis::report::HypothesisId,
) -> HypothesisDiagnostic {
    HypothesisDiagnostic {
        code,
        severity: Severity::Error,
        message,
        hypothesis_id: Some(hypothesis_id.clone()),
    }
}
