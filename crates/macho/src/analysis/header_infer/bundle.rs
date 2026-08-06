//! Deterministic bundle projection from canonical recovery reports.

use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::report::{
    Architecture, ContentHash, EntityId, EvidenceStrength, Fact, FactId, NonEmpty, RecoveredEntity,
    RecoveryField, RecoveryGap, RecoveryGapId, RecoveryGapReason, RecoveryReport, canonical_json,
    sha256_hex,
};
use serde::Serialize;

use crate::analysis::header_infer::artifact::{
    ArtifactError, BundleConstraints, EvidenceExcerpt, FactExcerpt, HeaderSubsetVersion,
    HypothesisBundle, HypothesisLimits, HypothesisOperationKind, HypothesisTarget,
};

/// Exports explicit gap IDs from one architecture of a validated recovery report.
pub fn export_bundle(
    report: &RecoveryReport,
    architecture: Architecture,
    gap_ids: &[RecoveryGapId],
    limits: HypothesisLimits,
) -> Result<HypothesisBundle, ArtifactError> {
    report
        .validate()
        .map_err(|error| ArtifactError::Invalid(error.to_string()))?;
    if gap_ids.is_empty() {
        return Err(ArtifactError::Invalid(
            "at least one explicit recovery gap is required".into(),
        ));
    }
    let mut requested = BTreeSet::new();
    for gap in gap_ids {
        if !requested.insert(gap.as_str()) {
            return Err(ArtifactError::Invalid(format!(
                "duplicate requested gap {gap}"
            )));
        }
    }
    let slice = report
        .slices
        .as_slice()
        .iter()
        .find(|slice| slice.architecture == architecture)
        .ok_or_else(|| ArtifactError::Invalid("selected architecture is absent".into()))?;

    let mut gap_index = BTreeMap::<&str, (&RecoveredEntity, &RecoveryGap)>::new();
    for entity in &slice.entities {
        for gap in &entity.gaps {
            if gap_index.insert(gap.id.as_str(), (entity, gap)).is_some() {
                return Err(ArtifactError::Invalid(format!(
                    "duplicate recovery gap {}",
                    gap.id
                )));
            }
        }
    }
    let mut selected = Vec::new();
    for gap_id in gap_ids {
        let (entity, gap) = gap_index.get(gap_id.as_str()).copied().ok_or_else(|| {
            ArtifactError::Invalid(format!("requested gap {gap_id} is absent from the slice"))
        })?;
        selected.push((entity, gap));
    }

    let mut grouped = BTreeMap::<EntityId, Vec<&RecoveryGap>>::new();
    for (entity, gap) in &selected {
        grouped.entry(entity.id.clone()).or_default().push(gap);
    }
    let mut targets = Vec::new();
    for (entity_id, mut gaps) in grouped {
        gaps.sort_by(|left, right| left.id.as_str().cmp(right.id.as_str()));
        let mut common = allowed_operations(gaps[0]);
        for gap in &gaps[1..] {
            let allowed = allowed_operations(gap);
            common.retain(|operation| allowed.contains(operation));
        }
        if common.is_empty() {
            return Err(ArtifactError::Invalid(format!(
                "selected gaps for entity {entity_id} do not share a safe operation; export a smaller explicit gap set"
            )));
        }
        targets.push(HypothesisTarget {
            entity_id,
            gap_ids: NonEmpty::new(gaps.iter().map(|gap| gap.id.clone()).collect())
                .expect("selected gap group is non-empty"),
            allowed_operations: NonEmpty::new(common)
                .expect("checked common operation set is non-empty"),
        });
    }

    let selected_entities = selected
        .iter()
        .map(|(entity, _)| entity.id.as_str())
        .collect::<BTreeSet<_>>();
    let mut facts = Vec::new();
    let mut pinned = Vec::new();
    let mut referenced_evidence = BTreeSet::<String>::new();
    for entity in &slice.entities {
        if !selected_entities.contains(entity.id.as_str()) {
            continue;
        }
        collect_entity_facts(entity, &mut facts, &mut pinned, &mut referenced_evidence)?;
    }
    for (_, gap) in &selected {
        referenced_evidence.extend(gap.evidence_ids.iter().map(ToString::to_string));
    }

    let mut evidence = Vec::new();
    for entity in &slice.entities {
        if !selected_entities.contains(entity.id.as_str()) {
            continue;
        }
        for record in &entity.evidence {
            if referenced_evidence.contains(record.id.as_str()) {
                evidence.push(EvidenceExcerpt {
                    evidence_id: record.id.clone(),
                    entity_id: entity.id.clone(),
                    canonical_projection: serde_json::to_value(record)?,
                });
            }
        }
    }
    for evidence_id in &referenced_evidence {
        if !evidence
            .iter()
            .any(|record| record.evidence_id.as_str() == evidence_id)
        {
            return Err(ArtifactError::Invalid(format!(
                "selected fact or gap references absent evidence {evidence_id}"
            )));
        }
    }

    facts.sort_by(|left, right| left.fact_id.as_str().cmp(right.fact_id.as_str()));
    evidence.sort_by(|left, right| left.evidence_id.as_str().cmp(right.evidence_id.as_str()));
    pinned.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    pinned.dedup();
    let recovery_digest = ContentHash::new(sha256_hex(&canonical_json(report)?))
        .map_err(|error| ArtifactError::Invalid(error.to_string()))?;
    HypothesisBundle::new(
        crate::analysis::header_infer::artifact::HypothesisBundleParts {
            recovery_digest,
            language: report.language,
            architecture,
            image: slice.image.clone(),
            targets: NonEmpty::new(targets).expect("at least one selected target"),
            facts,
            evidence,
            constraints: BundleConstraints {
                pinned_fact_ids: pinned,
                supported_header_subset: HeaderSubsetVersion::CURRENT,
            },
            limits,
        },
    )
}

fn allowed_operations(gap: &RecoveryGap) -> Vec<HypothesisOperationKind> {
    match &gap.reason {
        RecoveryGapReason::Conflicted { .. } => vec![HypothesisOperationKind::ChooseCandidate],
        RecoveryGapReason::Unavailable { .. } => match gap.field {
            RecoveryField::DisplayName => {
                vec![HypothesisOperationKind::ProposeCanonicalName]
            }
            RecoveryField::Owner => vec![HypothesisOperationKind::ProposeGrouping],
            _ => vec![HypothesisOperationKind::ProposeDeclarationFragment],
        },
        RecoveryGapReason::HeaderIneligible { reason } => match reason {
            crate::analysis::report::HeaderIneligibilityReason::UnprovenOwner => {
                vec![HypothesisOperationKind::ProposeGrouping]
            }
            _ => vec![HypothesisOperationKind::ProposeDeclarationFragment],
        },
    }
}

fn collect_entity_facts(
    entity: &RecoveredEntity,
    output: &mut Vec<FactExcerpt>,
    pinned: &mut Vec<FactId>,
    evidence: &mut BTreeSet<String>,
) -> Result<(), ArtifactError> {
    push_fact(
        entity,
        RecoveryField::Linkage,
        &entity.linkage,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::DisplayName,
        &entity.display_name,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Role,
        &entity.role,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Presence,
        &entity.presence,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Visibility,
        &entity.visibility,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Weakness,
        &entity.weakness,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Location,
        &entity.location,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Owner,
        &entity.owner,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::ValueType,
        &entity.value_type,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::ReturnType,
        &entity.signature.return_type,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Parameters,
        &entity.signature.parameters,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Variadic,
        &entity.signature.variadic,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::CallingConvention,
        &entity.signature.calling_convention,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Qualifiers,
        &entity.signature.qualifiers,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::LayoutSize,
        &entity.layout.size,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::LayoutAlignment,
        &entity.layout.alignment,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::LayoutFields,
        &entity.layout.fields,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::LayoutCompleteness,
        &entity.layout.completeness,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::Bases,
        &entity.hierarchy.bases,
        output,
        pinned,
        evidence,
    )?;
    push_fact(
        entity,
        RecoveryField::VirtualSurface,
        &entity.hierarchy.virtual_surface,
        output,
        pinned,
        evidence,
    )?;
    Ok(())
}

fn push_fact<T: Serialize + PartialEq>(
    entity: &RecoveredEntity,
    field: RecoveryField,
    fact: &Fact<T>,
    output: &mut Vec<FactExcerpt>,
    pinned: &mut Vec<FactId>,
    evidence: &mut BTreeSet<String>,
) -> Result<(), ArtifactError> {
    let (id, strength) = match fact {
        Fact::Known {
            id,
            strength,
            evidence_ids,
            ..
        } => {
            evidence.extend(evidence_ids.as_slice().iter().map(ToString::to_string));
            (id, Some(*strength))
        }
        Fact::Conflicted { id, candidates } => {
            for candidate in candidates.as_slice() {
                evidence.extend(
                    candidate
                        .evidence_ids
                        .as_slice()
                        .iter()
                        .map(ToString::to_string),
                );
            }
            (id, None)
        }
        Fact::Unavailable {
            id, evidence_ids, ..
        } => {
            evidence.extend(evidence_ids.iter().map(ToString::to_string));
            (id, None)
        }
    };
    if matches!(
        strength,
        Some(EvidenceStrength::Exact | EvidenceStrength::Correlated)
    ) {
        pinned.push(id.clone());
    }
    output.push(FactExcerpt {
        fact_id: id.clone(),
        entity_id: entity.id.clone(),
        field,
        canonical_projection: serde_json::to_value(fact)?,
    });
    Ok(())
}
