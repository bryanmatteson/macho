use std::collections::{BTreeMap, BTreeSet};

use macho_core::MachoFile;
use macho_core::model::container::MachoContainer;
use macho_objc::{ObjCMetadataScan, ObjCRecordKind};

use super::super::*;
use super::encoding;
use super::graph::{add_cycle_diagnostics, build_graph};
use super::identity::*;
use super::types::*;
use super::validate::validate_objc_slice;

/// Recovers the canonical Objective-C report for every selected container slice.
pub fn recover_objc_container(
    container: &MachoContainer<'_>,
    selected_architecture: Option<&str>,
) -> crate::Result<ObjCReport> {
    let container_kind = match container {
        MachoContainer::Thin(_) => ContainerKind::Thin,
        MachoContainer::Fat(_) => ContainerKind::Fat,
    };
    let mut slices = Vec::new();
    for (index, macho) in container.macho_files().enumerate() {
        if selected_architecture
            .is_some_and(|selected| selected != macho.header().cpu_type().name())
        {
            continue;
        }
        let mut slice = recover_objc_surface(macho)?.slices.into_vec().remove(0);
        slice.image.container = container_kind;
        slice.image.slice_index = index as u32;
        slices.push(slice);
    }
    if slices.is_empty() {
        return Err(crate::AnalysisError::invalid("no selected Mach-O slices"));
    }
    Ok(ObjCReport {
        schema_version: ObjCReportVersion::CURRENT,
        slices: NonEmpty::new(slices).expect("checked non-empty Objective-C slices"),
    })
}

/// Recovers the canonical Objective-C report for a single thin Mach-O image.
pub fn recover_objc_surface(macho: &MachoFile<'_>) -> crate::Result<ObjCReport> {
    let architecture = Architecture {
        cpu_type: macho.header().cpu_type().0,
        cpu_subtype: macho.header().cpu_subtype().0,
    };
    let image = super::super::symbol_recovery::image_identity(macho, architecture)?;
    let scan = macho_objc::scan_objc_metadata(macho)?;
    let sections = macho.all_sections().collect::<Vec<_>>();
    let category_counts = category_counts(&scan);
    let class_counts = name_counts(
        scan.metadata
            .classes
            .iter()
            .map(|value| value.name.as_str()),
    );
    let protocol_counts = name_counts(
        scan.metadata
            .protocols
            .iter()
            .map(|value| value.name.as_str()),
    );
    let record_entity_ids =
        record_entity_ids(&scan, &class_counts, &category_counts, &protocol_counts);
    let mut observations = Vec::new();
    let mut evidence = Vec::new();
    let mut diagnostics = Vec::new();
    let mut origins = BTreeMap::<String, (ObjCObservationId, ObjCEvidenceId)>::new();

    for (index, record) in scan.observations.iter().enumerate() {
        let observation_id = observation_id(&format!(
            "runtime|{:?}|{}|{}",
            record.kind, record.ordinal, record.pointer_file_offset
        ));
        let evidence_id = evidence_id(&format!("runtime|{observation_id}"));
        let location = record_location(macho, &sections, record);
        let disposition = if let Some(entity_id) = &record_entity_ids[index] {
            origins.insert(
                entity_id.to_string(),
                (observation_id.clone(), evidence_id.clone()),
            );
            ObjCObservationDisposition::Included {
                entity_ids: NonEmpty::new(vec![entity_id.clone()]).unwrap(),
            }
        } else {
            let diagnostic_id = diagnostic_id(&format!("malformed|{observation_id}"));
            diagnostics.push(ObjCDiagnostic {
                id: diagnostic_id.clone(),
                code: ObjCDiagnosticCode::MalformedMetadata,
                severity: Severity::Warning,
                message: record
                    .error
                    .clone()
                    .unwrap_or_else(|| "Objective-C runtime record was not decoded".to_owned()),
                observation_id: Some(observation_id.clone()),
                entity_id: None,
                evidence_ids: vec![evidence_id.clone()],
            });
            ObjCObservationDisposition::Malformed { diagnostic_id }
        };
        observations.push(ObjCObservation {
            id: observation_id.clone(),
            source: observation_source(record.kind),
            location: location.clone(),
            raw: HexBytes::from_bytes(&record.raw),
            disposition,
        });
        evidence.push(ObjCEvidence {
            id: evidence_id,
            observation_ids: NonEmpty::new(vec![observation_id]).unwrap(),
            kind: evidence_kind(record.kind),
            location,
            raw: HexBytes::from_bytes(&record.raw),
        });
    }

    let defined_class_ids = record_ids_for(&scan, &record_entity_ids, ObjCRecordKind::Class);
    let defined_protocol_ids = record_ids_for(&scan, &record_entity_ids, ObjCRecordKind::Protocol);
    let defined_classes = unique_defined_ids(
        scan.metadata
            .classes
            .iter()
            .map(|value| value.name.as_str()),
        &defined_class_ids,
        &class_counts,
    );
    let defined_protocols = unique_defined_ids(
        scan.metadata
            .protocols
            .iter()
            .map(|value| value.name.as_str()),
        &defined_protocol_ids,
        &protocol_counts,
    );
    let (external_classes, external_protocols) = external_references(&scan);
    let referenced_classes = external_classes
        .iter()
        .map(|name| (name.clone(), entity_id(&format!("class-ref|{name}"))))
        .collect::<BTreeMap<_, _>>();
    let referenced_protocols = external_protocols
        .iter()
        .map(|name| (name.clone(), entity_id(&format!("protocol-ref|{name}"))))
        .collect::<BTreeMap<_, _>>();
    let class_ids = defined_classes
        .iter()
        .chain(&referenced_classes)
        .map(|(name, id)| (name.clone(), id.clone()))
        .collect::<BTreeMap<_, _>>();
    let protocol_ids = defined_protocols
        .iter()
        .chain(&referenced_protocols)
        .map(|(name, id)| (name.clone(), id.clone()))
        .collect::<BTreeMap<_, _>>();

    let mut entities = Vec::new();
    for (value, id) in scan.metadata.classes.iter().zip(defined_class_ids) {
        let (observation_id, evidence_id) = origins[&id.to_string()].clone();
        let mut context = EntityBuildContext {
            macho,
            class_ids: &class_ids,
            protocol_ids: &protocol_ids,
            diagnostics: &mut diagnostics,
        };
        entities.push(ObjCEntity::Class(class_entity(
            value,
            id,
            observation_id,
            evidence_id,
            &mut context,
        )));
    }
    for (ordinal, value) in scan.metadata.categories.iter().enumerate() {
        let id = category_id(value, ordinal, &category_counts, &scan);
        let (observation_id, evidence_id) = origins[&id.to_string()].clone();
        if category_counts[&(value.class_name.clone(), value.name.clone())] > 1 {
            diagnostics.push(ObjCDiagnostic {
                id: diagnostic_id(&format!("ambiguous-category|{id}")),
                code: ObjCDiagnosticCode::AmbiguousCategoryOrder,
                severity: Severity::Warning,
                message: format!(
                    "category ordering for {}({}) is ambiguous",
                    value.class_name, value.name
                ),
                observation_id: Some(observation_id.clone()),
                entity_id: Some(id.clone()),
                evidence_ids: vec![evidence_id.clone()],
            });
        }
        let mut context = EntityBuildContext {
            macho,
            class_ids: &class_ids,
            protocol_ids: &protocol_ids,
            diagnostics: &mut diagnostics,
        };
        entities.push(ObjCEntity::Category(category_entity(
            value,
            ordinal,
            id,
            observation_id,
            evidence_id,
            &mut context,
        )));
    }
    for (value, id) in scan.metadata.protocols.iter().zip(defined_protocol_ids) {
        let (observation_id, evidence_id) = origins[&id.to_string()].clone();
        let mut context = EntityBuildContext {
            macho,
            class_ids: &class_ids,
            protocol_ids: &protocol_ids,
            diagnostics: &mut diagnostics,
        };
        entities.push(ObjCEntity::Protocol(protocol_entity(
            value,
            id,
            observation_id,
            evidence_id,
            &mut context,
        )));
    }
    for (name, id) in referenced_classes {
        let (observation_id, evidence_id) = add_reference_observation(
            &name,
            id.clone(),
            ObjCObservationSource::ClassRefs,
            ObjCEvidenceKind::ClassRef,
            &mut observations,
            &mut evidence,
        );
        entities.push(ObjCEntity::Class(empty_class(
            name,
            id,
            observation_id,
            evidence_id,
        )));
    }
    for (name, id) in referenced_protocols {
        let (observation_id, evidence_id) = add_reference_observation(
            &name,
            id.clone(),
            ObjCObservationSource::ProtocolRefs,
            ObjCEvidenceKind::ProtocolRef,
            &mut observations,
            &mut evidence,
        );
        entities.push(ObjCEntity::Protocol(empty_protocol(
            name,
            id,
            observation_id,
            evidence_id,
        )));
    }
    entities.sort_by(|left, right| left.common().id.as_str().cmp(right.common().id.as_str()));
    let graph = build_graph(&entities);
    add_cycle_diagnostics(&graph, &mut diagnostics);
    let malformed_observations = observations
        .iter()
        .filter(|value| {
            matches!(
                value.disposition,
                ObjCObservationDisposition::Malformed { .. }
            )
        })
        .count() as u64;
    let totals = partition_counts(&entities, malformed_observations);
    let selected_entity_ids = entities
        .iter()
        .map(|value| value.common().id.clone())
        .collect();
    let slice = ObjCSliceReport {
        architecture,
        image,
        graph,
        entities,
        observations,
        evidence,
        selection: ObjCSelectionResult {
            selected_entity_ids,
            totals,
        },
        header: None,
        diagnostics,
        executions: NonEmpty::new(vec![
            ObjCCollectorExecution {
                collector: ObjCCollectorId::RuntimeMetadata,
                outcome: ObjCCollectorOutcome::Complete,
                input_records: scan.observations.len() as u64,
                output_records: scan.metadata.classes.len() as u64
                    + scan.metadata.categories.len() as u64
                    + scan.metadata.protocols.len() as u64,
            },
            ObjCCollectorExecution {
                collector: ObjCCollectorId::SemanticGraph,
                outcome: ObjCCollectorOutcome::Complete,
                input_records: scan.metadata.classes.len() as u64
                    + scan.metadata.categories.len() as u64
                    + scan.metadata.protocols.len() as u64,
                output_records: 0,
            },
        ])
        .unwrap(),
    };
    let mut slice = slice;
    slice.executions.as_mut_slice()[1].output_records = slice.graph.nodes.len() as u64;
    validate_objc_slice(&slice)?;
    Ok(ObjCReport {
        schema_version: ObjCReportVersion::CURRENT,
        slices: NonEmpty::new(vec![slice]).unwrap(),
    })
}

struct EntityBuildContext<'a, 'data> {
    macho: &'a MachoFile<'data>,
    class_ids: &'a BTreeMap<String, ObjCEntityId>,
    protocol_ids: &'a BTreeMap<String, ObjCEntityId>,
    diagnostics: &'a mut Vec<ObjCDiagnostic>,
}

fn class_entity(
    value: &macho_objc::ObjCClass,
    id: ObjCEntityId,
    observation_id: ObjCObservationId,
    evidence_id: ObjCEvidenceId,
    context: &mut EntityBuildContext<'_, '_>,
) -> ObjCClassEntity {
    ObjCClassEntity {
        common: common(
            &value.name,
            id.clone(),
            ObjCPresence::Defined,
            observation_id,
            &evidence_id,
        ),
        superclass: ObjCValue::Known {
            value: value
                .superclass_name
                .as_ref()
                .map(|name| type_ref(name, context.class_ids)),
            evidence: one_evidence(&evidence_id),
        },
        adopted_protocols: value
            .protocols
            .iter()
            .map(|name| type_ref(name, context.protocol_ids))
            .collect(),
        ivars: value
            .ivars
            .iter()
            .enumerate()
            .map(|(ordinal, item)| encoding::ivar(item, ordinal, &id, &evidence_id))
            .collect(),
        properties: value
            .properties
            .iter()
            .enumerate()
            .map(|(ordinal, item)| encoding::property(item, ordinal, &id, &evidence_id))
            .collect(),
        instance_methods: value
            .instance_methods
            .iter()
            .enumerate()
            .map(|(ordinal, item)| {
                let mut method_context = encoding::MethodContext {
                    macho: context.macho,
                    origin: &id,
                    evidence_id: &evidence_id,
                    diagnostics: context.diagnostics,
                };
                encoding::method(
                    item,
                    ObjCMethodKind::Instance,
                    "instance",
                    ordinal,
                    &mut method_context,
                )
            })
            .collect(),
        class_methods: value
            .class_methods
            .iter()
            .enumerate()
            .map(|(ordinal, item)| {
                let mut method_context = encoding::MethodContext {
                    macho: context.macho,
                    origin: &id,
                    evidence_id: &evidence_id,
                    diagnostics: context.diagnostics,
                };
                encoding::method(
                    item,
                    ObjCMethodKind::Class,
                    "class",
                    ordinal,
                    &mut method_context,
                )
            })
            .collect(),
    }
}

fn category_entity(
    value: &macho_objc::ObjCCategory,
    ordinal: usize,
    id: ObjCEntityId,
    observation_id: ObjCObservationId,
    evidence_id: ObjCEvidenceId,
    context: &mut EntityBuildContext<'_, '_>,
) -> ObjCCategoryEntity {
    ObjCCategoryEntity {
        common: common(
            &value.name,
            id.clone(),
            ObjCPresence::Defined,
            observation_id,
            &evidence_id,
        ),
        extended_class: ObjCValue::Known {
            value: type_ref(&value.class_name, context.class_ids),
            evidence: one_evidence(&evidence_id),
        },
        adopted_protocols: value
            .protocols
            .iter()
            .map(|name| type_ref(name, context.protocol_ids))
            .collect(),
        properties: value
            .properties
            .iter()
            .enumerate()
            .map(|(ordinal, item)| encoding::property(item, ordinal, &id, &evidence_id))
            .collect(),
        instance_methods: value
            .instance_methods
            .iter()
            .enumerate()
            .map(|(ordinal, item)| {
                let mut method_context = encoding::MethodContext {
                    macho: context.macho,
                    origin: &id,
                    evidence_id: &evidence_id,
                    diagnostics: context.diagnostics,
                };
                encoding::method(
                    item,
                    ObjCMethodKind::Instance,
                    "instance",
                    ordinal,
                    &mut method_context,
                )
            })
            .collect(),
        class_methods: value
            .class_methods
            .iter()
            .enumerate()
            .map(|(ordinal, item)| {
                let mut method_context = encoding::MethodContext {
                    macho: context.macho,
                    origin: &id,
                    evidence_id: &evidence_id,
                    diagnostics: context.diagnostics,
                };
                encoding::method(
                    item,
                    ObjCMethodKind::Class,
                    "class",
                    ordinal,
                    &mut method_context,
                )
            })
            .collect(),
        fold_order: ObjCValue::Known {
            value: ordinal as u64,
            evidence: one_evidence(&evidence_id),
        },
    }
}

fn protocol_entity(
    value: &macho_objc::ObjCProtocol,
    id: ObjCEntityId,
    observation_id: ObjCObservationId,
    evidence_id: ObjCEvidenceId,
    context: &mut EntityBuildContext<'_, '_>,
) -> ObjCProtocolEntity {
    let mut methods = |values: &[macho_objc::ObjCMethod], kind, scope| {
        values
            .iter()
            .enumerate()
            .map(|(ordinal, item)| {
                let mut method_context = encoding::MethodContext {
                    macho: context.macho,
                    origin: &id,
                    evidence_id: &evidence_id,
                    diagnostics: context.diagnostics,
                };
                encoding::method(item, kind, scope, ordinal, &mut method_context)
            })
            .collect()
    };
    ObjCProtocolEntity {
        common: common(
            &value.name,
            id.clone(),
            ObjCPresence::Defined,
            observation_id,
            &evidence_id,
        ),
        adopted_protocols: value
            .adopted_protocols
            .iter()
            .map(|name| type_ref(name, context.protocol_ids))
            .collect(),
        required_instance_methods: methods(
            &value.instance_methods,
            ObjCMethodKind::Instance,
            "required_instance",
        ),
        required_class_methods: methods(
            &value.class_methods,
            ObjCMethodKind::Class,
            "required_class",
        ),
        optional_instance_methods: methods(
            &value.optional_instance_methods,
            ObjCMethodKind::Instance,
            "optional_instance",
        ),
        optional_class_methods: methods(
            &value.optional_class_methods,
            ObjCMethodKind::Class,
            "optional_class",
        ),
        properties: value
            .properties
            .iter()
            .enumerate()
            .map(|(ordinal, item)| encoding::property(item, ordinal, &id, &evidence_id))
            .collect(),
    }
}

fn external_references(scan: &ObjCMetadataScan) -> (BTreeSet<String>, BTreeSet<String>) {
    let classes = scan
        .metadata
        .classes
        .iter()
        .map(|value| value.name.as_str())
        .collect::<BTreeSet<_>>();
    let protocols = scan
        .metadata
        .protocols
        .iter()
        .map(|value| value.name.as_str())
        .collect::<BTreeSet<_>>();
    let mut external_classes = BTreeSet::new();
    let mut external_protocols = BTreeSet::new();
    for value in &scan.metadata.classes {
        if let Some(name) = &value.superclass_name
            && !classes.contains(name.as_str())
        {
            external_classes.insert(name.clone());
        }
        for name in &value.protocols {
            if !protocols.contains(name.as_str()) {
                external_protocols.insert(name.clone());
            }
        }
    }
    for value in &scan.metadata.categories {
        if !classes.contains(value.class_name.as_str()) {
            external_classes.insert(value.class_name.clone());
        }
        for name in &value.protocols {
            if !protocols.contains(name.as_str()) {
                external_protocols.insert(name.clone());
            }
        }
    }
    for value in &scan.metadata.protocols {
        for name in &value.adopted_protocols {
            if !protocols.contains(name.as_str()) {
                external_protocols.insert(name.clone());
            }
        }
    }
    (external_classes, external_protocols)
}

fn add_reference_observation(
    name: &str,
    entity_id: ObjCEntityId,
    source: ObjCObservationSource,
    kind: ObjCEvidenceKind,
    observations: &mut Vec<ObjCObservation>,
    evidence: &mut Vec<ObjCEvidence>,
) -> (ObjCObservationId, ObjCEvidenceId) {
    let observation_id = observation_id(&format!("reference|{source:?}|{name}"));
    let evidence_id = evidence_id(&format!("reference|{observation_id}"));
    let location = ObjCMetadataLocation {
        virtual_address: 0,
        file_offset: None,
        section: None,
    };
    let raw = HexBytes::from_bytes(name.as_bytes());
    observations.push(ObjCObservation {
        id: observation_id.clone(),
        source,
        location: location.clone(),
        raw: raw.clone(),
        disposition: ObjCObservationDisposition::Referenced {
            entity_id: entity_id.clone(),
        },
    });
    evidence.push(ObjCEvidence {
        id: evidence_id.clone(),
        observation_ids: NonEmpty::new(vec![observation_id.clone()]).unwrap(),
        kind,
        location,
        raw,
    });
    (observation_id, evidence_id)
}

fn empty_class(
    name: String,
    id: ObjCEntityId,
    observation_id: ObjCObservationId,
    evidence_id: ObjCEvidenceId,
) -> ObjCClassEntity {
    ObjCClassEntity {
        common: common(
            &name,
            id,
            ObjCPresence::Referenced,
            observation_id,
            &evidence_id,
        ),
        superclass: ObjCValue::Unavailable {
            reason: ObjCUnavailableReason::NotEncoded,
        },
        adopted_protocols: Vec::new(),
        ivars: Vec::new(),
        properties: Vec::new(),
        instance_methods: Vec::new(),
        class_methods: Vec::new(),
    }
}

fn empty_protocol(
    name: String,
    id: ObjCEntityId,
    observation_id: ObjCObservationId,
    evidence_id: ObjCEvidenceId,
) -> ObjCProtocolEntity {
    ObjCProtocolEntity {
        common: common(
            &name,
            id,
            ObjCPresence::Referenced,
            observation_id,
            &evidence_id,
        ),
        adopted_protocols: Vec::new(),
        required_instance_methods: Vec::new(),
        required_class_methods: Vec::new(),
        optional_instance_methods: Vec::new(),
        optional_class_methods: Vec::new(),
        properties: Vec::new(),
    }
}

fn common(
    name: &str,
    id: ObjCEntityId,
    presence: ObjCPresence,
    observation_id: ObjCObservationId,
    evidence_id: &ObjCEvidenceId,
) -> ObjCEntityCommon {
    ObjCEntityCommon {
        id,
        presence,
        name: ObjCValue::Known {
            value: name.to_owned(),
            evidence: one_evidence(evidence_id),
        },
        observation_ids: NonEmpty::new(vec![observation_id]).unwrap(),
    }
}

fn type_ref(name: &str, ids: &BTreeMap<String, ObjCEntityId>) -> ObjCTypeRef {
    let id = ids.get(name).cloned();
    let presence = match &id {
        Some(id)
            if *id == entity_id(&format!("class|{name}"))
                || *id == entity_id(&format!("protocol|{name}")) =>
        {
            ObjCPresence::Defined
        }
        Some(_) => ObjCPresence::Referenced,
        None => ObjCPresence::Partial,
    };
    ObjCTypeRef {
        entity_id: id,
        name: name.to_owned(),
        presence,
    }
}

fn one_evidence(value: &ObjCEvidenceId) -> NonEmpty<ObjCEvidenceId> {
    NonEmpty::new(vec![value.clone()]).unwrap()
}
