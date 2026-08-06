use std::collections::BTreeSet;

use super::super::{HeaderDecl, NonEmpty, ObjCEvidenceId, ObjCHeaderMember, ObjCMemberId};
use super::types::*;

impl ObjCReport {
    /// Validates every slice after strict wire decoding.
    pub fn validate(&self) -> crate::analysis::Result<()> {
        for slice in self.slices.as_slice() {
            validate_objc_slice(slice)?;
        }
        Ok(())
    }
}

pub(super) fn validate_objc_slice(slice: &ObjCSliceReport) -> crate::analysis::Result<()> {
    let observations = unique(
        "Objective-C observation",
        slice.observations.iter().map(|value| value.id.as_str()),
    )?;
    let entities = unique(
        "Objective-C entity",
        slice
            .entities
            .iter()
            .map(|value| value.common().id.as_str()),
    )?;
    let evidence = unique(
        "Objective-C evidence",
        slice.evidence.iter().map(|value| value.id.as_str()),
    )?;
    let diagnostics = unique(
        "Objective-C diagnostic",
        slice.diagnostics.iter().map(|value| value.id.as_str()),
    )?;
    let mut members = BTreeSet::new();

    for record in &slice.evidence {
        for observation_id in record.observation_ids.as_slice() {
            require(
                &observations,
                observation_id.as_str(),
                "Objective-C observation",
            )?;
        }
    }
    for entity in &slice.entities {
        let common = entity.common();
        for observation_id in common.observation_ids.as_slice() {
            require(
                &observations,
                observation_id.as_str(),
                "Objective-C observation",
            )?;
            let observation = slice
                .observations
                .iter()
                .find(|value| value.id == *observation_id)
                .expect("validated observation set agrees with vector");
            let linked = match &observation.disposition {
                ObjCObservationDisposition::Included { entity_ids } => {
                    entity_ids.as_slice().contains(&common.id)
                }
                ObjCObservationDisposition::Referenced { entity_id } => entity_id == &common.id,
                _ => false,
            };
            if !linked {
                return invalid("Objective-C observation/entity conservation mismatch");
            }
        }
        validate_entity(entity, &entities, &evidence, &mut members)?;
    }
    for observation in &slice.observations {
        match &observation.disposition {
            ObjCObservationDisposition::Included { entity_ids } => {
                for entity_id in entity_ids.as_slice() {
                    require(&entities, entity_id.as_str(), "Objective-C entity")?;
                }
            }
            ObjCObservationDisposition::Referenced { entity_id } => {
                require(&entities, entity_id.as_str(), "Objective-C entity")?;
            }
            ObjCObservationDisposition::Malformed { diagnostic_id } => {
                require(
                    &diagnostics,
                    diagnostic_id.as_str(),
                    "Objective-C diagnostic",
                )?;
            }
            ObjCObservationDisposition::Excluded { .. } => {}
        }
    }
    for diagnostic in &slice.diagnostics {
        if let Some(observation_id) = &diagnostic.observation_id {
            require(
                &observations,
                observation_id.as_str(),
                "Objective-C diagnostic observation",
            )?;
        }
        if let Some(entity_id) = &diagnostic.entity_id {
            require(
                &entities,
                entity_id.as_str(),
                "Objective-C diagnostic entity",
            )?;
        }
        for evidence_id in &diagnostic.evidence_ids {
            require(
                &evidence,
                evidence_id.as_str(),
                "Objective-C diagnostic evidence",
            )?;
        }
    }
    unique(
        "Objective-C graph node",
        slice.graph.nodes.iter().map(|node| node.entity_id.as_str()),
    )?;
    for node in &slice.graph.nodes {
        require(&entities, node.entity_id.as_str(), "Objective-C graph node")?;
        let entity = slice
            .entities
            .iter()
            .find(|entity| entity.common().id == node.entity_id)
            .expect("validated graph node references an entity");
        if node.presence != entity.common().presence {
            return invalid("Objective-C graph node presence disagrees with entity");
        }
    }
    for edge in slice
        .graph
        .inheritance
        .iter()
        .chain(&slice.graph.conformances)
        .chain(&slice.graph.categories)
    {
        require(
            &entities,
            edge.from.as_str(),
            "Objective-C graph edge source",
        )?;
        require(&entities, edge.to.as_str(), "Objective-C graph edge target")?;
    }
    for owner in &slice.graph.selector_owners {
        if let Some(entity_id) = &owner.effective_owner {
            require(&entities, entity_id.as_str(), "Objective-C selector owner")?;
        }
        for member_id in &owner.candidates {
            if !members.contains(member_id.as_str()) {
                return invalid("dangling Objective-C selector candidate reference");
            }
        }
    }
    unique(
        "selected Objective-C entity",
        slice
            .selection
            .selected_entity_ids
            .iter()
            .map(|id| id.as_str()),
    )?;
    for selected in &slice.selection.selected_entity_ids {
        require(&entities, selected.as_str(), "selected Objective-C entity")?;
    }
    validate_totals(slice)?;
    validate_executions(slice, &diagnostics)?;
    if let Some(header) = &slice.header {
        validate_header(header, &entities, &members, &diagnostics)?;
    }
    Ok(())
}

fn validate_totals(slice: &ObjCSliceReport) -> crate::analysis::Result<()> {
    let count = |presence| {
        slice
            .entities
            .iter()
            .filter(|entity| entity.common().presence == presence)
            .count() as u64
    };
    let malformed = slice
        .observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.disposition,
                ObjCObservationDisposition::Malformed { .. }
            )
        })
        .count() as u64;
    let excluded = slice
        .observations
        .iter()
        .filter(|observation| {
            matches!(
                observation.disposition,
                ObjCObservationDisposition::Excluded { .. }
            )
        })
        .count() as u64;
    let expected = ObjCPartitionCounts {
        defined_entities: count(ObjCPresence::Defined),
        referenced_entities: count(ObjCPresence::Referenced),
        partial_entities: count(ObjCPresence::Partial),
        malformed_observations: malformed,
        excluded_observations: excluded,
    };
    if slice.selection.totals == expected {
        Ok(())
    } else {
        invalid("Objective-C partition totals do not match report contents")
    }
}

fn validate_executions(
    slice: &ObjCSliceReport,
    diagnostics: &BTreeSet<&str>,
) -> crate::analysis::Result<()> {
    let mut collectors = BTreeSet::new();
    for execution in slice.executions.as_slice() {
        if !collectors.insert(execution.collector as u8) {
            return invalid("duplicate Objective-C collector execution");
        }
        if let ObjCCollectorOutcome::Failed { diagnostic_id } = &execution.outcome {
            require(
                diagnostics,
                diagnostic_id.as_str(),
                "Objective-C collector diagnostic",
            )?;
        }
    }
    Ok(())
}

fn validate_header(
    header: &ObjCHeaderProjection,
    entities: &BTreeSet<&str>,
    members: &BTreeSet<String>,
    diagnostics: &BTreeSet<&str>,
) -> crate::analysis::Result<()> {
    if !header.validation.syntax_valid || !header.validation.semantic_valid {
        return invalid("stored Objective-C header projection is not valid");
    }
    for declaration in &header.declarations {
        match declaration {
            HeaderDecl::ObjcInterface {
                id, members: body, ..
            }
            | HeaderDecl::ObjcCategory {
                id, members: body, ..
            }
            | HeaderDecl::ObjcProtocol {
                id, members: body, ..
            } => {
                require(entities, id.as_str(), "Objective-C header entity")?;
                for member in body {
                    let id = match member {
                        ObjCHeaderMember::Method { id, .. }
                        | ObjCHeaderMember::Property { id, .. } => id,
                    };
                    if !members.contains(id.as_str()) {
                        return invalid("dangling Objective-C header member reference");
                    }
                }
            }
            // Objective-C headers may carry C record forwards required by
            // recovered ivar and method types (`struct CGPoint;`, etc.).
            // They have no runtime entity or member identity to validate.
            HeaderDecl::ObjcForward { .. } | HeaderDecl::Forward { .. } => {}
            _ => return invalid("non-Objective-C declaration in Objective-C header projection"),
        }
    }
    for gap in &header.unresolved {
        require(
            entities,
            gap.entity_id.as_str(),
            "Objective-C header gap entity",
        )?;
        if gap
            .member_id
            .as_ref()
            .is_some_and(|id| !members.contains(id.as_str()))
        {
            return invalid("dangling Objective-C header gap member reference");
        }
        for diagnostic_id in &gap.diagnostic_ids {
            require(
                diagnostics,
                diagnostic_id.as_str(),
                "Objective-C header gap diagnostic",
            )?;
        }
    }
    Ok(())
}

fn validate_entity(
    entity: &ObjCEntity,
    entities: &BTreeSet<&str>,
    evidence: &BTreeSet<&str>,
    members: &mut BTreeSet<String>,
) -> crate::analysis::Result<()> {
    validate_value_evidence(&entity.common().name, evidence)?;
    match entity {
        ObjCEntity::Class(value) => {
            validate_value_evidence(&value.superclass, evidence)?;
            validate_refs(&value.adopted_protocols, entities)?;
            for ivar in &value.ivars {
                insert_member(&ivar.id, members)?;
                validate_value_evidence(&ivar.name, evidence)?;
                validate_value_evidence(&ivar.parsed_type, evidence)?;
                validate_value_evidence(&ivar.offset, evidence)?;
                validate_value_evidence(&ivar.size, evidence)?;
                validate_value_evidence(&ivar.alignment, evidence)?;
            }
            validate_properties(&value.properties, entities, evidence, members)?;
            validate_methods(
                value.instance_methods.iter().chain(&value.class_methods),
                entities,
                evidence,
                members,
            )?;
        }
        ObjCEntity::Category(value) => {
            validate_value_evidence(&value.extended_class, evidence)?;
            validate_refs(&value.adopted_protocols, entities)?;
            validate_value_evidence(&value.fold_order, evidence)?;
            validate_properties(&value.properties, entities, evidence, members)?;
            validate_methods(
                value.instance_methods.iter().chain(&value.class_methods),
                entities,
                evidence,
                members,
            )?;
        }
        ObjCEntity::Protocol(value) => {
            validate_refs(&value.adopted_protocols, entities)?;
            validate_properties(&value.properties, entities, evidence, members)?;
            validate_methods(
                value
                    .required_instance_methods
                    .iter()
                    .chain(&value.required_class_methods)
                    .chain(&value.optional_instance_methods)
                    .chain(&value.optional_class_methods),
                entities,
                evidence,
                members,
            )?;
        }
    }
    Ok(())
}

fn validate_methods<'a>(
    values: impl Iterator<Item = &'a ObjCMethod>,
    entities: &BTreeSet<&str>,
    evidence: &BTreeSet<&str>,
    members: &mut BTreeSet<String>,
) -> crate::analysis::Result<()> {
    for value in values {
        insert_member(&value.id, members)?;
        require(entities, value.origin.as_str(), "Objective-C method origin")?;
        validate_value_evidence(&value.selector, evidence)?;
        validate_value_evidence(&value.signature, evidence)?;
        validate_value_evidence(&value.implementation, evidence)?;
    }
    Ok(())
}

fn validate_properties(
    values: &[ObjCProperty],
    entities: &BTreeSet<&str>,
    evidence: &BTreeSet<&str>,
    members: &mut BTreeSet<String>,
) -> crate::analysis::Result<()> {
    for value in values {
        insert_member(&value.id, members)?;
        require(
            entities,
            value.origin.as_str(),
            "Objective-C property origin",
        )?;
        validate_value_evidence(&value.name, evidence)?;
        validate_value_evidence(&value.parsed_attributes, evidence)?;
    }
    Ok(())
}

fn validate_refs(values: &[ObjCTypeRef], entities: &BTreeSet<&str>) -> crate::analysis::Result<()> {
    for value in values {
        if let Some(entity_id) = &value.entity_id {
            require(entities, entity_id.as_str(), "Objective-C type reference")?;
        }
    }
    Ok(())
}

fn validate_value_evidence<T: PartialEq>(
    value: &ObjCValue<T>,
    evidence: &BTreeSet<&str>,
) -> crate::analysis::Result<()> {
    match value {
        ObjCValue::Known { evidence: ids, .. } => validate_evidence_ids(ids, evidence),
        ObjCValue::Conflicted { candidates } => {
            for candidate in candidates.as_slice() {
                validate_evidence_ids(&candidate.evidence, evidence)?;
            }
            Ok(())
        }
        ObjCValue::Unavailable { .. } => Ok(()),
    }
}

fn validate_evidence_ids(
    ids: &NonEmpty<ObjCEvidenceId>,
    evidence: &BTreeSet<&str>,
) -> crate::analysis::Result<()> {
    for id in ids.as_slice() {
        require(evidence, id.as_str(), "Objective-C evidence")?;
    }
    Ok(())
}

fn insert_member(id: &ObjCMemberId, members: &mut BTreeSet<String>) -> crate::analysis::Result<()> {
    if members.insert(id.to_string()) {
        Ok(())
    } else {
        invalid("duplicate Objective-C member ID")
    }
}

fn unique<'a>(
    kind: &str,
    values: impl Iterator<Item = &'a str>,
) -> crate::analysis::Result<BTreeSet<&'a str>> {
    let mut result = BTreeSet::new();
    for value in values {
        if !result.insert(value) {
            return invalid(format!("duplicate {kind} ID"));
        }
    }
    Ok(result)
}

fn require(values: &BTreeSet<&str>, value: &str, kind: &str) -> crate::analysis::Result<()> {
    if values.contains(value) {
        Ok(())
    } else {
        invalid(format!("dangling {kind} reference"))
    }
}

fn invalid<T>(message: impl Into<String>) -> crate::analysis::Result<T> {
    Err(crate::analysis::AnalysisError::validation(message.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_objc_wire_rejects_unknown_keys() {
        let value = serde_json::json!({"schema_version": 1, "slices": [], "invented": true});
        assert!(serde_json::from_value::<ObjCReport>(value).is_err());
    }
}
