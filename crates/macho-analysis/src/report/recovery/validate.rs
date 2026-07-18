use std::collections::{BTreeMap, BTreeSet};

use super::*;

/// Semantic validation failure after strict wire decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RecoveryValidationError {
    #[error("recovery language does not match request language")]
    LanguageMismatch,
    #[error("invalid recovery limit at index {index}: {value} exceeds 1..={maximum}")]
    InvalidLimit {
        index: usize,
        value: u64,
        maximum: u64,
    },
    #[error("duplicate {kind} ID {id}")]
    DuplicateId { kind: &'static str, id: String },
    #[error("dangling {kind} ID {id}")]
    DanglingId { kind: &'static str, id: String },
    #[error("observation/entity conservation mismatch for {id}")]
    Conservation { id: String },
    #[error("collector outcome reference is invalid")]
    CollectorOutcome,
    #[error("collector plan/execution mismatch for {collector:?}")]
    CollectorPlan { collector: CollectorId },
    #[error("recovery limit {limit:?} exceeded: {actual} > {maximum}")]
    LimitExceeded {
        limit: RecoveryLimitName,
        actual: u64,
        maximum: u64,
    },
    #[error("header projection is invalid")]
    HeaderProjection,
    #[error("request cannot be encoded as canonical JSON")]
    CanonicalRequest,
    #[error("serialized request digest does not match the canonical request")]
    RequestDigestMismatch,
}

impl RecoveryReport {
    /// Runs limits, uniqueness, reference, conservation, and execution checks.
    pub fn validate(&self) -> Result<(), RecoveryValidationError> {
        if self.language != self.request.language {
            return Err(RecoveryValidationError::LanguageMismatch);
        }
        self.request.limits.validate()?;
        let expected_digest = canonical_request_digest(&self.request)?;
        for slice in self.slices.as_slice() {
            if slice.resolved_plan.request_digest != expected_digest
                || slice
                    .executions
                    .as_slice()
                    .iter()
                    .any(|execution| execution.request_digest != expected_digest)
            {
                return Err(RecoveryValidationError::RequestDigestMismatch);
            }
            validate_slice(slice, self.language, self.request.limits)?;
        }
        Ok(())
    }

    /// Recomputes the canonical request digest after a validated request edit.
    pub fn refresh_request_digest(&mut self) -> Result<(), RecoveryValidationError> {
        self.request.limits.validate()?;
        let digest = canonical_request_digest(&self.request)?;
        for slice in self.slices.as_mut_slice() {
            slice.resolved_plan.request_digest = digest.clone();
            for execution in slice.executions.as_mut_slice() {
                execution.request_digest = digest.clone();
            }
        }
        Ok(())
    }
}

pub(super) fn canonical_request_digest(
    request: &RecoveryRequestSummary,
) -> Result<RequestDigest, RecoveryValidationError> {
    let bytes = canonical_json(request).map_err(|_| RecoveryValidationError::CanonicalRequest)?;
    let digest = sha256_hex(&bytes);
    RequestDigest::new(digest).map_err(|_| RecoveryValidationError::CanonicalRequest)
}

pub(super) fn validate_slice(
    slice: &SliceRecovery,
    language: RecoveryLanguage,
    limits: RecoveryLimits,
) -> Result<(), RecoveryValidationError> {
    let observations = unique_ids(
        "observation",
        slice
            .observations
            .iter()
            .map(|observation| observation.id.as_str()),
    )?;
    let entities = unique_ids(
        "entity",
        slice.entities.iter().map(|entity| entity.id.as_str()),
    )?;
    let observation_index = slice
        .observations
        .iter()
        .enumerate()
        .map(|(index, observation)| (observation.id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let entity_index = slice
        .entities
        .iter()
        .enumerate()
        .map(|(index, entity)| (entity.id.as_str(), index))
        .collect::<BTreeMap<_, _>>();
    let diagnostics = unique_ids(
        "diagnostic",
        slice
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.id.as_str()),
    )?;
    require_limit(
        RecoveryLimitName::MaxObservations,
        slice.observations.len() as u64,
        limits.max_observations,
    )?;
    require_limit(
        RecoveryLimitName::MaxEntities,
        slice.entities.len() as u64,
        limits.max_entities,
    )?;
    require_limit(
        RecoveryLimitName::MaxDiagnostics,
        slice.diagnostics.len() as u64,
        limits.max_diagnostics,
    )?;
    let mut evidence = BTreeSet::new();
    let mut facts = BTreeSet::new();
    let mut gaps = BTreeSet::new();
    for entity in &slice.entities {
        for record in &entity.evidence {
            if !evidence.insert(record.id.as_str().to_owned()) {
                return Err(RecoveryValidationError::DuplicateId {
                    kind: "evidence",
                    id: record.id.to_string(),
                });
            }
            for observation_id in &record.observation_ids {
                require(&observations, observation_id.as_str(), "observation")?;
            }
        }
        validate_entity_facts(entity, &mut facts, &evidence)?;
        validate_entity_references(entity, &entities)?;
        for gap in &entity.gaps {
            if !gaps.insert(gap.id.as_str().to_owned()) {
                return Err(RecoveryValidationError::DuplicateId {
                    kind: "recovery gap",
                    id: gap.id.to_string(),
                });
            }
            for evidence_id in &gap.evidence_ids {
                require(&evidence, evidence_id.as_str(), "evidence")?;
            }
            if let RecoveryGapReason::Conflicted { fact_id } = &gap.reason {
                require(&facts, fact_id.as_str(), "fact")?;
            }
        }
    }
    require_limit(
        RecoveryLimitName::MaxEvidenceRecords,
        evidence.len() as u64,
        limits.max_evidence_records,
    )?;
    for observation in &slice.observations {
        if let ObservationDisposition::Included { entity_ids } = &observation.disposition {
            for entity_id in entity_ids.as_slice() {
                require(&entities, entity_id.as_str(), "entity")?;
                let entity = &slice.entities[*entity_index
                    .get(entity_id.as_str())
                    .expect("validated entity set and vector agree")];
                if !entity.observation_ids.as_slice().contains(&observation.id) {
                    return Err(RecoveryValidationError::Conservation {
                        id: observation.id.to_string(),
                    });
                }
            }
        }
    }
    for entity in &slice.entities {
        for observation_id in entity.observation_ids.as_slice() {
            require(&observations, observation_id.as_str(), "observation")?;
            let observation = &slice.observations[*observation_index
                .get(observation_id.as_str())
                .expect("validated observation set and vector agree")];
            if !matches!(
                &observation.disposition,
                ObservationDisposition::Included { entity_ids }
                    if entity_ids.as_slice().contains(&entity.id)
            ) {
                return Err(RecoveryValidationError::Conservation {
                    id: entity.id.to_string(),
                });
            }
        }
    }
    for selected in &slice.resolved_plan.selected_entity_ids {
        require(&entities, selected.as_str(), "entity")?;
    }
    validate_diagnostics(&slice.diagnostics, &observations, &entities, &evidence)?;
    validate_plan_and_executions(slice, &entities, &diagnostics)?;
    if let Some(header) = &slice.header {
        if !slice.resolved_plan.selected_entity_ids.is_empty()
            && slice.resolved_plan.projection.is_none()
        {
            return Err(RecoveryValidationError::HeaderProjection);
        }
        validate_header(
            header,
            language,
            &entities,
            &diagnostics,
            &slice.resolved_plan.selected_entity_ids,
        )?;
    } else if slice.resolved_plan.projection.is_some() {
        return Err(RecoveryValidationError::HeaderProjection);
    }
    if slice.inputs.selected_architecture != slice.architecture
        || slice.inputs.image != slice.image
        || slice.image.architecture != slice.architecture
    {
        return Err(RecoveryValidationError::Conservation {
            id: "slice_identity".to_owned(),
        });
    }
    Ok(())
}

fn validate_entity_references(
    entity: &RecoveredEntity,
    entities: &BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    let require_owner = |owner: &EntityOwner| {
        if let Some(entity_id) = &owner.entity_id {
            require(entities, entity_id.as_str(), "entity")?;
        }
        Ok(())
    };
    match &entity.owner {
        Fact::Known { value, .. } => require_owner(value)?,
        Fact::Conflicted { candidates, .. } => {
            for candidate in candidates.as_slice() {
                require_owner(&candidate.value)?;
            }
        }
        Fact::Unavailable { .. } => {}
    }
    if let Fact::Known { value, .. } = &entity.hierarchy.bases {
        for base in value {
            require(entities, base.base.as_str(), "entity")?;
        }
    }
    if let Fact::Known { value, .. } = &entity.hierarchy.virtual_surface {
        for member in value {
            match &member.target {
                Fact::Known { value, .. } => require(entities, value.as_str(), "entity")?,
                Fact::Conflicted { candidates, .. } => {
                    for candidate in candidates.as_slice() {
                        require(entities, candidate.value.as_str(), "entity")?;
                    }
                }
                Fact::Unavailable { .. } => {}
            }
        }
    }
    Ok(())
}

fn validate_plan_and_executions(
    slice: &SliceRecovery,
    entities: &BTreeSet<String>,
    diagnostics: &BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    let mut expected = BTreeMap::<CollectorId, Vec<EntityId>>::new();
    for spec in slice
        .resolved_plan
        .discovery
        .iter()
        .chain(&slice.resolved_plan.targeted)
    {
        if expected
            .insert(spec.collector, spec.target_entity_ids.clone())
            .is_some()
        {
            return Err(RecoveryValidationError::CollectorPlan {
                collector: spec.collector,
            });
        }
        for target in &spec.target_entity_ids {
            require(entities, target.as_str(), "entity")?;
        }
    }
    if let Some(projection) = &slice.resolved_plan.projection {
        let targets = projection.target_entity_ids.as_slice().to_vec();
        if expected
            .insert(CollectorId::HeaderProjection, targets)
            .is_some()
        {
            return Err(RecoveryValidationError::CollectorPlan {
                collector: CollectorId::HeaderProjection,
            });
        }
    }
    let mut seen = BTreeSet::new();
    for execution in slice.executions.as_slice() {
        if !seen.insert(execution.collector) {
            return Err(RecoveryValidationError::CollectorPlan {
                collector: execution.collector,
            });
        }
        let Some(targets) = expected.get(&execution.collector) else {
            return Err(RecoveryValidationError::CollectorPlan {
                collector: execution.collector,
            });
        };
        let expected_selected = if execution.collector == CollectorId::SymbolDiscovery {
            slice.resolved_plan.selected_entity_ids.len() as u64
        } else {
            targets.len() as u64
        };
        if targets != &execution.target_entity_ids
            || execution.counts.selected_targets != expected_selected
        {
            return Err(RecoveryValidationError::CollectorPlan {
                collector: execution.collector,
            });
        }
        for target in &execution.target_entity_ids {
            require(entities, target.as_str(), "entity")?;
        }
        match &execution.outcome {
            CollectorOutcome::Failed { diagnostic_id } => {
                require(diagnostics, diagnostic_id.as_str(), "diagnostic")?;
            }
            CollectorOutcome::Truncated { truncation_index } => {
                let truncation = slice
                    .truncations
                    .get(*truncation_index as usize)
                    .ok_or(RecoveryValidationError::CollectorOutcome)?;
                if truncation.collector != execution.collector {
                    return Err(RecoveryValidationError::CollectorOutcome);
                }
            }
            CollectorOutcome::Complete | CollectorOutcome::Unsupported { .. } => {}
        }
    }
    for collector in expected.keys() {
        if !seen.contains(collector) {
            return Err(RecoveryValidationError::CollectorPlan {
                collector: *collector,
            });
        }
    }
    Ok(())
}

fn validate_entity_facts(
    entity: &RecoveredEntity,
    facts: &mut BTreeSet<String>,
    evidence: &BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    validate_fact(&entity.linkage, facts, evidence)?;
    validate_fact(&entity.display_name, facts, evidence)?;
    validate_fact(&entity.role, facts, evidence)?;
    validate_fact(&entity.presence, facts, evidence)?;
    validate_fact(&entity.visibility, facts, evidence)?;
    validate_fact(&entity.weakness, facts, evidence)?;
    validate_fact(&entity.location, facts, evidence)?;
    validate_fact(&entity.owner, facts, evidence)?;
    validate_fact(&entity.value_type, facts, evidence)?;
    validate_fact(&entity.signature.return_type, facts, evidence)?;
    validate_fact(&entity.signature.parameters, facts, evidence)?;
    validate_fact(&entity.signature.variadic, facts, evidence)?;
    validate_fact(&entity.signature.calling_convention, facts, evidence)?;
    validate_fact(&entity.signature.qualifiers, facts, evidence)?;
    validate_fact(&entity.layout.size, facts, evidence)?;
    validate_fact(&entity.layout.alignment, facts, evidence)?;
    validate_fact(&entity.layout.fields, facts, evidence)?;
    validate_fact(&entity.layout.completeness, facts, evidence)?;
    validate_fact(&entity.hierarchy.bases, facts, evidence)?;
    validate_fact(&entity.hierarchy.virtual_surface, facts, evidence)?;
    if let Fact::Known {
        value: ParameterList::Known { value },
        ..
    } = &entity.signature.parameters
    {
        for parameter in value {
            validate_fact(&parameter.type_evidence, facts, evidence)?;
            validate_fact(&parameter.source_name, facts, evidence)?;
        }
    }
    if let Fact::Known { value, .. } = &entity.layout.fields {
        for field in value {
            validate_fact(&field.name, facts, evidence)?;
            validate_fact(&field.ty, facts, evidence)?;
            validate_fact(&field.offset, facts, evidence)?;
            validate_fact(&field.bit_width, facts, evidence)?;
        }
    }
    if let Fact::Known { value, .. } = &entity.hierarchy.bases {
        for base in value {
            validate_fact(&base.offset, facts, evidence)?;
            validate_fact(&base.access, facts, evidence)?;
            validate_fact(&base.is_virtual, facts, evidence)?;
        }
    }
    if let Fact::Known { value, .. } = &entity.hierarchy.virtual_surface {
        for member in value {
            validate_fact(&member.target, facts, evidence)?;
            validate_fact(&member.adjustment, facts, evidence)?;
        }
    }
    Ok(())
}

fn validate_fact<T: PartialEq>(
    fact: &Fact<T>,
    facts: &mut BTreeSet<String>,
    evidence: &BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    let (id, evidence_lists): (&FactId, Vec<&[EvidenceId]>) = match fact {
        Fact::Known {
            id, evidence_ids, ..
        } => (id, vec![evidence_ids.as_slice()]),
        Fact::Conflicted { id, candidates } => (
            id,
            candidates
                .as_slice()
                .iter()
                .map(|candidate| candidate.evidence_ids.as_slice())
                .collect(),
        ),
        Fact::Unavailable {
            id, evidence_ids, ..
        } => (id, vec![evidence_ids.as_slice()]),
    };
    if !facts.insert(id.as_str().to_owned()) {
        return Err(RecoveryValidationError::DuplicateId {
            kind: "fact",
            id: id.to_string(),
        });
    }
    for list in evidence_lists {
        for evidence_id in list {
            require(evidence, evidence_id.as_str(), "evidence")?;
        }
    }
    Ok(())
}

fn validate_diagnostics(
    diagnostics: &[RecoveryDiagnostic],
    observations: &BTreeSet<String>,
    entities: &BTreeSet<String>,
    evidence: &BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    for diagnostic in diagnostics {
        if let Some(id) = &diagnostic.observation_id {
            require(observations, id.as_str(), "observation")?;
        }
        if let Some(id) = &diagnostic.entity_id {
            require(entities, id.as_str(), "entity")?;
        }
        for id in &diagnostic.evidence_ids {
            require(evidence, id.as_str(), "evidence")?;
        }
    }
    Ok(())
}

fn validate_header(
    header: &HeaderProjection,
    language: RecoveryLanguage,
    entities: &BTreeSet<String>,
    slice_diagnostics: &BTreeSet<String>,
    targets: &[EntityId],
) -> Result<(), RecoveryValidationError> {
    if header.language != language
        || !header.validation.syntax_valid
        || !header.validation.semantic_valid
    {
        return Err(RecoveryValidationError::HeaderProjection);
    }
    let header_diagnostics = unique_ids(
        "header diagnostic",
        header
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.id.as_str()),
    )?;
    let mut unresolved_entities = BTreeSet::new();
    for gap in &header.unresolved {
        require(entities, gap.entity_id.as_str(), "entity")?;
        unresolved_entities.insert(gap.entity_id.as_str().to_owned());
        for id in &gap.diagnostic_ids {
            if !header_diagnostics.contains(id.as_str()) && !slice_diagnostics.contains(id.as_str())
            {
                return Err(RecoveryValidationError::DanglingId {
                    kind: "diagnostic",
                    id: id.to_string(),
                });
            }
        }
    }
    let mut declared_entities = BTreeSet::new();
    for declaration in &header.declarations {
        validate_declaration_entity(declaration, entities)?;
        collect_declaration_entities(declaration, &mut declared_entities)?;
    }
    if !declared_entities.is_disjoint(&unresolved_entities) {
        return Err(RecoveryValidationError::HeaderProjection);
    }
    let covered = declared_entities
        .union(&unresolved_entities)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected = targets
        .iter()
        .map(|id| id.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    if covered != expected {
        return Err(RecoveryValidationError::HeaderProjection);
    }
    Ok(())
}

fn collect_declaration_entities(
    declaration: &HeaderDecl,
    output: &mut BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    let id = match declaration {
        HeaderDecl::Function { id, .. }
        | HeaderDecl::Variable { id, .. }
        | HeaderDecl::Record { id, .. }
        | HeaderDecl::Forward { id, .. }
        | HeaderDecl::Alias { id, .. } => id,
        HeaderDecl::ObjcInterface { .. }
        | HeaderDecl::ObjcCategory { .. }
        | HeaderDecl::ObjcProtocol { .. }
        | HeaderDecl::ObjcForward { .. } => {
            return Err(RecoveryValidationError::HeaderProjection);
        }
    };
    if !output.insert(id.as_str().to_owned()) {
        return Err(RecoveryValidationError::HeaderProjection);
    }
    if let HeaderDecl::Record { members, .. } = declaration {
        for member in members {
            collect_declaration_entities(member, output)?;
        }
    }
    Ok(())
}

fn validate_declaration_entity(
    declaration: &HeaderDecl,
    entities: &BTreeSet<String>,
) -> Result<(), RecoveryValidationError> {
    match declaration {
        HeaderDecl::Function { id, .. }
        | HeaderDecl::Variable { id, .. }
        | HeaderDecl::Record { id, .. }
        | HeaderDecl::Forward { id, .. }
        | HeaderDecl::Alias { id, .. } => require(entities, id.as_str(), "entity")?,
        HeaderDecl::ObjcInterface { .. }
        | HeaderDecl::ObjcCategory { .. }
        | HeaderDecl::ObjcProtocol { .. }
        | HeaderDecl::ObjcForward { .. } => {
            return Err(RecoveryValidationError::HeaderProjection);
        }
    }
    if let HeaderDecl::Record { members, .. } = declaration {
        for member in members {
            validate_declaration_entity(member, entities)?;
        }
    }
    Ok(())
}

fn require_limit(
    limit: RecoveryLimitName,
    actual: u64,
    maximum: u64,
) -> Result<(), RecoveryValidationError> {
    if actual <= maximum {
        Ok(())
    } else {
        Err(RecoveryValidationError::LimitExceeded {
            limit,
            actual,
            maximum,
        })
    }
}

fn unique_ids<'a>(
    kind: &'static str,
    values: impl Iterator<Item = &'a str>,
) -> Result<BTreeSet<String>, RecoveryValidationError> {
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value.to_owned()) {
            return Err(RecoveryValidationError::DuplicateId {
                kind,
                id: value.to_owned(),
            });
        }
    }
    Ok(result)
}

fn require(
    values: &BTreeSet<String>,
    id: &str,
    kind: &'static str,
) -> Result<(), RecoveryValidationError> {
    if values.contains(id) {
        Ok(())
    } else {
        Err(RecoveryValidationError::DanglingId {
            kind,
            id: id.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> RecoveryReport {
        let bytes =
            macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
                name: "_widget",
                external: true,
                defined: true,
            }]);
        let container = macho_core::parse(&bytes).expect("parse fixture");
        crate::report::recover_symbol_surface(
            container.first_macho().expect("one fixture slice"),
            RecoveryLanguage::CAbi,
        )
        .expect("recover fixture")
    }

    #[test]
    fn validator_rejects_duplicate_entity_ids() {
        let mut report = report();
        let duplicate = report.slices.as_slice()[0].entities[0].clone();
        report.slices.as_mut_slice()[0].entities.push(duplicate);
        assert!(matches!(
            report.validate(),
            Err(RecoveryValidationError::DuplicateId { kind: "entity", .. })
        ));
    }

    #[test]
    fn validator_rejects_dangling_selected_entities() {
        let mut report = report();
        let dangling = EntityId::new(sha256_hex(b"dangling entity")).unwrap();
        report.slices.as_mut_slice()[0]
            .resolved_plan
            .selected_entity_ids
            .push(dangling);
        assert!(matches!(
            report.validate(),
            Err(RecoveryValidationError::DanglingId { kind: "entity", .. })
        ));
    }

    #[test]
    fn validator_rejects_asymmetric_observation_conservation() {
        let mut report = report();
        report.slices.as_mut_slice()[0].observations[0].disposition =
            ObservationDisposition::Excluded {
                reason: ExclusionReason::SyntheticNonEntity,
            };
        assert!(matches!(
            report.validate(),
            Err(RecoveryValidationError::Conservation { .. })
        ));
    }

    #[test]
    fn validator_rejects_execution_targets_outside_the_plan() {
        let mut report = report();
        let target = report.slices.as_slice()[0].entities[0].id.clone();
        report.slices.as_mut_slice()[0].executions.as_mut_slice()[0]
            .target_entity_ids
            .push(target);
        assert!(matches!(
            report.validate(),
            Err(RecoveryValidationError::CollectorPlan {
                collector: CollectorId::SymbolDiscovery
            })
        ));
    }

    #[test]
    fn validator_rejects_dangling_owner_entity() {
        let mut report = report();
        let entity = &mut report.slices.as_mut_slice()[0].entities[0];
        let evidence_id = entity.evidence[0].id.clone();
        let fact_id = match &entity.owner {
            Fact::Known { id, .. } | Fact::Conflicted { id, .. } | Fact::Unavailable { id, .. } => {
                id.clone()
            }
        };
        entity.owner = Fact::Known {
            id: fact_id,
            value: EntityOwner {
                kind: Some(HeaderOwnerKind::Class),
                path: Vec::new(),
                entity_id: Some(EntityId::new(sha256_hex(b"missing owner")).unwrap()),
            },
            strength: EvidenceStrength::Correlated,
            evidence_ids: NonEmpty::new(vec![evidence_id]).unwrap(),
        };
        assert!(matches!(
            report.validate(),
            Err(RecoveryValidationError::DanglingId { kind: "entity", .. })
        ));
    }
}
