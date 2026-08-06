//! Semantic validation for canonical Swift recovery reports.

use std::collections::BTreeSet;

use super::*;
impl SwiftReport {
    /// Validates identity uniqueness, reference integrity, conservation,
    /// partitions, and collector outcomes after strict wire decoding.
    pub fn validate(&self) -> crate::analysis::Result<()> {
        for slice in self.slices.as_slice() {
            validate_swift_slice(slice)?;
        }
        Ok(())
    }
}

fn validate_swift_slice(slice: &SwiftSliceReport) -> crate::analysis::Result<()> {
    let observation_ids = slice
        .observations
        .iter()
        .map(|value| value.id.as_str())
        .collect::<BTreeSet<_>>();
    let entity_ids = slice
        .entities
        .iter()
        .map(|value| value.id.as_str())
        .collect::<BTreeSet<_>>();
    let evidence_ids = slice
        .evidence
        .iter()
        .map(|value| value.id.as_str())
        .collect::<BTreeSet<_>>();
    if observation_ids.len() != slice.observations.len()
        || entity_ids.len() != slice.entities.len()
        || evidence_ids.len() != slice.evidence.len()
    {
        return Err(crate::analysis::AnalysisError::validation(
            "duplicate Swift report ID",
        ));
    }
    let diagnostic_ids = slice
        .diagnostics
        .iter()
        .map(|value| value.id.as_str())
        .collect::<BTreeSet<_>>();
    if diagnostic_ids.len() != slice.diagnostics.len() {
        return Err(crate::analysis::AnalysisError::validation(
            "duplicate Swift diagnostic ID",
        ));
    }
    let entity_index = slice
        .entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity))
        .collect::<std::collections::BTreeMap<_, _>>();
    let observation_index = slice
        .observations
        .iter()
        .map(|observation| (observation.id.as_str(), observation))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mut gap_ids = BTreeSet::new();
    for entity in &slice.entities {
        if entity
            .observation_ids
            .as_slice()
            .iter()
            .any(|id| !observation_ids.contains(id.as_str()))
        {
            return Err(crate::analysis::AnalysisError::validation(
                "dangling Swift observation reference",
            ));
        }
        if entity
            .gaps
            .iter()
            .flat_map(|gap| &gap.evidence_ids)
            .any(|id| !evidence_ids.contains(id.as_str()))
        {
            return Err(crate::analysis::AnalysisError::validation(
                "dangling Swift evidence reference",
            ));
        }
        for observation_id in entity.observation_ids.as_slice() {
            let observation = observation_index
                .get(observation_id.as_str())
                .expect("validated Swift observation reference");
            if !matches!(
                &observation.disposition,
                SwiftObservationDisposition::Included { entity_ids }
                    if entity_ids.as_slice().contains(&entity.id)
            ) {
                return Err(crate::analysis::AnalysisError::validation(
                    "Swift observation/entity conservation mismatch",
                ));
            }
        }
        validate_swift_value_evidence(&entity.kind, &evidence_ids)?;
        validate_swift_value_evidence(&entity.qualified_name, &evidence_ids)?;
        validate_swift_value_evidence(&entity.descriptor, &evidence_ids)?;
        validate_swift_value_evidence(&entity.parent, &evidence_ids)?;
        validate_swift_value_evidence(&entity.fields_or_cases, &evidence_ids)?;
        validate_swift_value_evidence(&entity.conformances, &evidence_ids)?;
        for gap in &entity.gaps {
            if !gap_ids.insert(gap.id.as_str()) {
                return Err(crate::analysis::AnalysisError::validation(
                    "duplicate Swift gap ID",
                ));
            }
        }
        for parent in swift_values(&entity.parent) {
            validate_swift_ref(parent, &entity_ids)?;
        }
        for conformances in swift_values(&entity.conformances) {
            for conformance in conformances {
                validate_swift_ref(&conformance.protocol, &entity_ids)?;
                if let Some(value) = &conformance.r#type {
                    validate_swift_ref(value, &entity_ids)?;
                }
            }
        }
        let unique_linkages = entity.raw_linkages.iter().collect::<BTreeSet<_>>();
        if unique_linkages.len() != entity.raw_linkages.len() {
            return Err(crate::analysis::AnalysisError::validation(
                "duplicate Swift raw linkage",
            ));
        }
        if entity.state == SwiftEntityState::MetadataDefined
            && !matches!(entity.descriptor, SwiftValue::Known { .. })
        {
            return Err(crate::analysis::AnalysisError::validation(
                "metadata-defined Swift entity lacks a descriptor",
            ));
        }
        if entity.state == SwiftEntityState::SymbolOnly
            && matches!(entity.descriptor, SwiftValue::Known { .. })
        {
            return Err(crate::analysis::AnalysisError::validation(
                "symbol-only Swift entity claims a descriptor",
            ));
        }
    }
    for item in &slice.evidence {
        for observation_id in item.observation_ids.as_slice() {
            if !observation_ids.contains(observation_id.as_str()) {
                return Err(crate::analysis::AnalysisError::validation(
                    "dangling Swift evidence observation reference",
                ));
            }
        }
    }
    for observation in &slice.observations {
        match &observation.disposition {
            SwiftObservationDisposition::Included {
                entity_ids: included,
            } => {
                for id in included.as_slice() {
                    let entity = entity_index.get(id.as_str()).ok_or_else(|| {
                        crate::analysis::AnalysisError::validation(
                            "dangling Swift entity reference",
                        )
                    })?;
                    if !entity.observation_ids.as_slice().contains(&observation.id) {
                        return Err(crate::analysis::AnalysisError::validation(
                            "Swift observation/entity conservation mismatch",
                        ));
                    }
                }
            }
            SwiftObservationDisposition::Unknown { diagnostic_id } => {
                if !diagnostic_ids.contains(diagnostic_id.as_str()) {
                    return Err(crate::analysis::AnalysisError::validation(
                        "dangling Swift observation diagnostic reference",
                    ));
                }
            }
            SwiftObservationDisposition::Excluded { .. } => {}
        }
    }
    let selected = slice
        .selection
        .selected_entity_ids
        .iter()
        .map(SwiftEntityId::as_str)
        .collect::<BTreeSet<_>>();
    if selected.len() != slice.selection.selected_entity_ids.len()
        || selected.iter().any(|id| !entity_ids.contains(id))
    {
        return Err(crate::analysis::AnalysisError::validation(
            "invalid Swift selection IDs",
        ));
    }
    let excluded = slice
        .observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.disposition,
                SwiftObservationDisposition::Excluded { .. }
            )
        })
        .count() as u64;
    if slice.selection.totals != partition_counts(&slice.entities, excluded) {
        return Err(crate::analysis::AnalysisError::validation(
            "Swift partition totals do not match entities",
        ));
    }
    for diagnostic in &slice.diagnostics {
        if diagnostic
            .observation_id
            .as_ref()
            .is_some_and(|id| !observation_ids.contains(id.as_str()))
            || diagnostic
                .entity_id
                .as_ref()
                .is_some_and(|id| !entity_ids.contains(id.as_str()))
            || diagnostic
                .evidence_ids
                .iter()
                .any(|id| !evidence_ids.contains(id.as_str()))
        {
            return Err(crate::analysis::AnalysisError::validation(
                "dangling Swift diagnostic reference",
            ));
        }
    }
    let mut collectors = BTreeSet::new();
    for execution in slice.executions.as_slice() {
        if !collectors.insert(execution.collector) {
            return Err(crate::analysis::AnalysisError::validation(
                "duplicate Swift collector execution",
            ));
        }
        if let SwiftCollectorOutcome::Failed { diagnostic_id } = &execution.outcome
            && !diagnostic_ids.contains(diagnostic_id.as_str())
        {
            return Err(crate::analysis::AnalysisError::validation(
                "dangling Swift collector diagnostic reference",
            ));
        }
    }
    Ok(())
}

fn validate_swift_value_evidence<T: PartialEq>(
    value: &SwiftValue<T>,
    evidence: &BTreeSet<&str>,
) -> crate::analysis::Result<()> {
    match value {
        SwiftValue::Known { evidence: ids, .. } => {
            for id in ids.as_slice() {
                if !evidence.contains(id.as_str()) {
                    return Err(crate::analysis::AnalysisError::validation(
                        "dangling Swift value evidence reference",
                    ));
                }
            }
        }
        SwiftValue::Conflicted { candidates } => {
            for candidate in candidates.as_slice() {
                for id in candidate.evidence.as_slice() {
                    if !evidence.contains(id.as_str()) {
                        return Err(crate::analysis::AnalysisError::validation(
                            "dangling Swift candidate evidence reference",
                        ));
                    }
                }
            }
        }
        SwiftValue::Unavailable { .. } => {}
    }
    Ok(())
}

fn swift_values<T: PartialEq>(value: &SwiftValue<T>) -> Vec<&T> {
    match value {
        SwiftValue::Known { value, .. } => vec![value],
        SwiftValue::Conflicted { candidates } => candidates
            .as_slice()
            .iter()
            .map(|candidate| &candidate.value)
            .collect(),
        SwiftValue::Unavailable { .. } => Vec::new(),
    }
}

fn validate_swift_ref(
    value: &SwiftEntityRef,
    entities: &BTreeSet<&str>,
) -> crate::analysis::Result<()> {
    if value.entity_id.is_none() && value.qualified_name.is_none() {
        return Err(crate::analysis::AnalysisError::validation(
            "empty Swift entity reference",
        ));
    }
    if value
        .entity_id
        .as_ref()
        .is_some_and(|id| !entities.contains(id.as_str()))
    {
        return Err(crate::analysis::AnalysisError::validation(
            "dangling Swift entity edge",
        ));
    }
    Ok(())
}
