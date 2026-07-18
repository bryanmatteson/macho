//! Parent, conformance, and associated-type reflection enrichment.

use std::collections::{BTreeMap, BTreeSet};

use macho_core::{MachoFile, Section};

use super::*;

pub(super) fn enrich_reflection(
    macho: &MachoFile<'_>,
    index: &macho_swift::SwiftTypeIndex,
    sections: &[&Section],
    observations: &mut Vec<SwiftObservation>,
    evidence: &mut Vec<SwiftEvidence>,
    entities: &mut [SwiftEntity],
    diagnostics: &mut Vec<SwiftDiagnostic>,
) -> u64 {
    enrich_field_evidence(macho, index, sections, observations, evidence, entities);
    let by_name = index.types.iter().enumerate().fold(
        BTreeMap::<&str, Vec<usize>>::new(),
        |mut values, (index, value)| {
            values.entry(&value.name).or_default().push(index);
            values
        },
    );
    let unique_index = |name: &str| {
        let indexes = by_name.get(name)?;
        let metadata = indexes
            .iter()
            .copied()
            .filter(|item| {
                index.types[*item].source == macho_swift::types::SwiftTypeSource::SwiftMetadata
            })
            .collect::<Vec<_>>();
        if metadata.len() == 1 {
            metadata.first().copied()
        } else if indexes.len() == 1 {
            indexes.first().copied()
        } else {
            None
        }
    };
    let index_at_address = |address: u64| {
        index
            .types
            .iter()
            .position(|value| value.address == Some(address))
    };

    for parent in &index.parents {
        let Some(owner_index) = index
            .types
            .iter()
            .position(|value| value.address == Some(parent.descriptor_address))
        else {
            continue;
        };
        let Some(evidence_id) =
            entities[owner_index].evidence_id_for(SwiftEvidenceKind::ContextDescriptor)
        else {
            continue;
        };
        entities[owner_index].parent = SwiftValue::Known {
            value: entity_ref(&parent.parent_name, &unique_index, entities),
            evidence: NonEmpty::new(vec![evidence_id]).expect("one parent evidence ID"),
        };
        entities[owner_index]
            .gaps
            .retain(|gap| gap.field != SwiftFieldName::Parent);
    }

    let mut conformances = BTreeMap::<usize, Vec<(SwiftConformanceRef, SwiftEvidenceId)>>::new();
    let mut unresolved_conformance_owners = BTreeSet::new();
    for (ordinal, conformance) in index.conformances.iter().enumerate() {
        let raw = raw_at(macho, conformance.address, conformance.byte_len as usize);
        let location = metadata_location(macho, conformance.address, sections);
        let observation_id =
            swift_observation_id(&format!("conformance|{ordinal}|{}", conformance.address));
        let evidence_id = swift_evidence_id(&format!("conformance|{observation_id}"));
        let owner_index = conformance
            .conforming_type_address
            .and_then(&index_at_address)
            .or_else(|| {
                conformance
                    .conforming_type_name
                    .as_deref()
                    .and_then(&unique_index)
            });
        let protocol_name = conformance.protocol_name.as_deref();
        if let (Some(owner_index), Some(protocol_name)) = (owner_index, protocol_name) {
            let entity_id = entities[owner_index].id.clone();
            observations.push(SwiftObservation {
                id: observation_id.clone(),
                source: SwiftObservationSource::Conformances,
                raw: HexBytes::from_bytes(&raw),
                location: location.clone(),
                disposition: SwiftObservationDisposition::Included {
                    entity_ids: NonEmpty::new(vec![entity_id]).expect("one conformance entity"),
                },
            });
            evidence.push(SwiftEvidence {
                id: evidence_id.clone(),
                observation_ids: NonEmpty::new(vec![observation_id.clone()])
                    .expect("one conformance observation"),
                kind: SwiftEvidenceKind::ConformanceDescriptor,
                location: location.clone(),
                raw: HexBytes::from_bytes(&raw),
            });
            entities[owner_index].observation_ids.push(observation_id);
            conformances.entry(owner_index).or_default().push((
                SwiftConformanceRef {
                    protocol: entity_ref_at(
                        protocol_name,
                        conformance.protocol_address,
                        &unique_index,
                        &index_at_address,
                        entities,
                    ),
                    r#type: conformance
                        .conforming_type_name
                        .as_deref()
                        .map(|name| entity_ref(name, &unique_index, entities)),
                    descriptor: location,
                },
                evidence_id,
            ));
        } else if let Some(owner_index) = owner_index {
            unresolved_conformance_owners.insert(owner_index);
            record_unresolved_for_entity(
                observations,
                evidence,
                diagnostics,
                &mut entities[owner_index],
                UnresolvedRecord {
                    seed: format!("conformance|{ordinal}|{}", conformance.address),
                    source: SwiftObservationSource::Conformances,
                    kind: SwiftEvidenceKind::ConformanceDescriptor,
                    raw,
                    location,
                    message: format!(
                        "Swift conformance descriptor has an unresolved protocol: type={:?}, protocol={:?}",
                        conformance.conforming_type_name, conformance.protocol_name
                    ),
                },
            );
        } else {
            record_unresolved(
                observations,
                evidence,
                diagnostics,
                UnresolvedRecord {
                    seed: format!("conformance|{ordinal}|{}", conformance.address),
                    source: SwiftObservationSource::Conformances,
                    kind: SwiftEvidenceKind::ConformanceDescriptor,
                    raw,
                    location,
                    message: format!(
                        "Swift conformance descriptor has no unique conforming type and protocol: type={:?}, protocol={:?}",
                        conformance.conforming_type_name, conformance.protocol_name
                    ),
                },
            );
        }
    }
    for (entity_index, values) in conformances {
        if unresolved_conformance_owners.contains(&entity_index) {
            continue;
        }
        let (values, evidence_ids): (Vec<_>, Vec<_>) = values.into_iter().unzip();
        entities[entity_index].conformances = SwiftValue::Known {
            value: values,
            evidence: NonEmpty::new(evidence_ids).expect("one conformance evidence ID"),
        };
        entities[entity_index]
            .gaps
            .retain(|gap| gap.field != SwiftFieldName::Conformances);
    }

    for (ordinal, associated) in index.associated_types.iter().enumerate() {
        let raw = raw_at(macho, associated.address, associated.byte_len as usize);
        let location = metadata_location(macho, associated.address, sections);
        let type_name = associated
            .resolved_conforming_type_name
            .clone()
            .or_else(|| {
                associated
                    .conforming_type_name
                    .as_deref()
                    .and_then(demangle_type_reference)
            });
        let protocol_type_name = associated
            .protocol_type_name
            .as_deref()
            .and_then(demangle_type_reference);
        let owner_index = type_name.as_deref().and_then(&unique_index);
        if let Some(owner_index) = owner_index {
            let observation_id =
                swift_observation_id(&format!("associated|{ordinal}|{}", associated.address));
            let evidence_id = swift_evidence_id(&format!("associated|{observation_id}"));
            observations.push(SwiftObservation {
                id: observation_id.clone(),
                source: SwiftObservationSource::AssociatedTypes,
                raw: HexBytes::from_bytes(&raw),
                location: location.clone(),
                disposition: SwiftObservationDisposition::Included {
                    entity_ids: NonEmpty::new(vec![entities[owner_index].id.clone()])
                        .expect("one associated-type owner"),
                },
            });
            evidence.push(SwiftEvidence {
                id: evidence_id,
                observation_ids: NonEmpty::new(vec![observation_id.clone()])
                    .expect("one associated-type observation"),
                kind: SwiftEvidenceKind::AssociatedTypeDescriptor,
                location,
                raw: HexBytes::from_bytes(&raw),
            });
            entities[owner_index].observation_ids.push(observation_id);
        } else {
            record_unresolved(
                observations,
                evidence,
                diagnostics,
                UnresolvedRecord {
                    seed: format!("associated|{ordinal}|{}", associated.address),
                    source: SwiftObservationSource::AssociatedTypes,
                    kind: SwiftEvidenceKind::AssociatedTypeDescriptor,
                    raw,
                    location,
                    message: format!(
                        "Swift associated-type descriptor has no unique conforming type: type={type_name:?}, protocol_type={protocol_type_name:?}"
                    ),
                },
            );
        }
    }

    index.parents.len() as u64
        + index.conformances.len() as u64
        + index.associated_types.len() as u64
}

fn enrich_field_evidence(
    macho: &MachoFile<'_>,
    index: &macho_swift::SwiftTypeIndex,
    sections: &[&Section],
    observations: &mut Vec<SwiftObservation>,
    evidence: &mut Vec<SwiftEvidence>,
    entities: &mut [SwiftEntity],
) {
    for (ordinal, swift_type) in index.types.iter().enumerate() {
        if swift_type.fields.is_none() {
            continue;
        }
        let Some((address, raw)) = swift_type
            .address
            .and_then(|owner| field_descriptor(macho, owner))
        else {
            continue;
        };
        let observation_id = swift_observation_id(&format!("field|{ordinal}|{address}"));
        let evidence_id = swift_evidence_id(&format!("field|{observation_id}"));
        let location = metadata_location(macho, address, sections);
        observations.push(SwiftObservation {
            id: observation_id.clone(),
            source: SwiftObservationSource::Fields,
            raw: HexBytes::from_bytes(&raw),
            location: location.clone(),
            disposition: SwiftObservationDisposition::Included {
                entity_ids: NonEmpty::new(vec![entities[ordinal].id.clone()])
                    .expect("one field owner"),
            },
        });
        evidence.push(SwiftEvidence {
            id: evidence_id.clone(),
            observation_ids: NonEmpty::new(vec![observation_id.clone()])
                .expect("one field observation"),
            kind: SwiftEvidenceKind::FieldDescriptor,
            location,
            raw: HexBytes::from_bytes(&raw),
        });
        entities[ordinal].observation_ids.push(observation_id);
        if let SwiftValue::Known {
            evidence: current, ..
        } = &mut entities[ordinal].fields_or_cases
        {
            *current = NonEmpty::new(vec![evidence_id]).expect("one field evidence ID");
        }
    }
}

fn field_descriptor(macho: &MachoFile<'_>, owner: u64) -> Option<(u64, Vec<u8>)> {
    let field = owner.checked_add(16)?;
    let relative_bytes: [u8; 4] = macho
        .read_bytes_at_va(macho_core::model::addr::Va(field), 4)
        .ok()?
        .try_into()
        .ok()?;
    let relative = macho.endian().read_i32(relative_bytes);
    if relative == 0 {
        return None;
    }
    let address = if relative >= 0 {
        field.checked_add(relative as u64)?
    } else {
        field.checked_sub(relative.unsigned_abs() as u64)?
    };
    let header = macho
        .read_bytes_at_va(macho_core::model::addr::Va(address), 16)
        .ok()?;
    let record_size = macho.endian().read_u16(header[10..12].try_into().ok()?) as usize;
    let count = macho.endian().read_u32(header[12..16].try_into().ok()?) as usize;
    let length = 16usize.checked_add(record_size.checked_mul(count)?)?;
    let raw = macho
        .read_bytes_at_va(macho_core::model::addr::Va(address), length)
        .ok()?
        .to_vec();
    Some((address, raw))
}

trait SwiftEntityEvidence {
    fn evidence_id_for(&self, kind: SwiftEvidenceKind) -> Option<SwiftEvidenceId>;
}

impl SwiftEntityEvidence for SwiftEntity {
    fn evidence_id_for(&self, kind: SwiftEvidenceKind) -> Option<SwiftEvidenceId> {
        self.gaps
            .iter()
            .flat_map(|gap| &gap.evidence_ids)
            .find(|_| kind == SwiftEvidenceKind::ContextDescriptor)
            .cloned()
            .or_else(|| {
                if kind == SwiftEvidenceKind::ContextDescriptor {
                    match &self.descriptor {
                        SwiftValue::Known { evidence, .. } => evidence.as_slice().first().cloned(),
                        _ => None,
                    }
                } else {
                    None
                }
            })
    }
}

fn entity_ref(
    name: &str,
    unique_index: &impl Fn(&str) -> Option<usize>,
    entities: &[SwiftEntity],
) -> SwiftEntityRef {
    SwiftEntityRef {
        entity_id: unique_index(name).map(|index| entities[index].id.clone()),
        qualified_name: Some(qualified_name(name)),
    }
}

fn entity_ref_at(
    name: &str,
    address: Option<u64>,
    unique_index: &impl Fn(&str) -> Option<usize>,
    index_at_address: &impl Fn(u64) -> Option<usize>,
    entities: &[SwiftEntity],
) -> SwiftEntityRef {
    SwiftEntityRef {
        entity_id: address
            .and_then(index_at_address)
            .or_else(|| unique_index(name))
            .map(|index| entities[index].id.clone()),
        qualified_name: Some(qualified_name(name)),
    }
}

fn metadata_location(
    macho: &MachoFile<'_>,
    address: u64,
    sections: &[&Section],
) -> Option<SwiftMetadataLocation> {
    let section = section_at(address, sections)
        .map(|(ordinal, section)| section_identity(ordinal, section))?;
    Some(SwiftDescriptorLocation {
        virtual_address: address,
        file_offset: macho
            .address_map()
            .va_to_thin_offset(macho_core::model::addr::Va(address))
            .ok()
            .map(|offset| offset.0),
        section,
        relative_offset: None,
    })
}

fn raw_at(macho: &MachoFile<'_>, address: u64, length: usize) -> Vec<u8> {
    macho
        .read_bytes_at_va(macho_core::model::addr::Va(address), length)
        .map_or_else(|_| Vec::new(), <[u8]>::to_vec)
}

fn demangle_type_reference(raw: &[u8]) -> Option<String> {
    let raw = std::str::from_utf8(raw).ok()?;
    macho_symbols::demangle::demangle_swift_symbol(raw)
        .or_else(|| macho_symbols::demangle::demangle_swift_symbol(&format!("$s{raw}")))
}

struct UnresolvedRecord {
    seed: String,
    source: SwiftObservationSource,
    kind: SwiftEvidenceKind,
    raw: Vec<u8>,
    location: Option<SwiftMetadataLocation>,
    message: String,
}

fn record_unresolved(
    observations: &mut Vec<SwiftObservation>,
    evidence: &mut Vec<SwiftEvidence>,
    diagnostics: &mut Vec<SwiftDiagnostic>,
    record: UnresolvedRecord,
) {
    let observation_id = swift_observation_id(&record.seed);
    let evidence_id = swift_evidence_id(&format!("{}|evidence", record.seed));
    let diagnostic_id =
        SwiftDiagnosticId::new(sha256_hex(format!("{}|diagnostic", record.seed).as_bytes()))
            .expect("SHA-256 Swift diagnostic ID");
    observations.push(SwiftObservation {
        id: observation_id.clone(),
        source: record.source,
        raw: HexBytes::from_bytes(&record.raw),
        location: record.location.clone(),
        disposition: SwiftObservationDisposition::Unknown {
            diagnostic_id: diagnostic_id.clone(),
        },
    });
    evidence.push(SwiftEvidence {
        id: evidence_id.clone(),
        observation_ids: NonEmpty::new(vec![observation_id.clone()])
            .expect("one unresolved observation"),
        kind: record.kind,
        location: record.location,
        raw: HexBytes::from_bytes(&record.raw),
    });
    diagnostics.push(SwiftDiagnostic {
        id: diagnostic_id,
        code: SwiftDiagnosticCode::UnresolvedReference,
        severity: Severity::Warning,
        message: record.message,
        observation_id: Some(observation_id),
        entity_id: None,
        evidence_ids: vec![evidence_id],
    });
}

fn record_unresolved_for_entity(
    observations: &mut Vec<SwiftObservation>,
    evidence: &mut Vec<SwiftEvidence>,
    diagnostics: &mut Vec<SwiftDiagnostic>,
    entity: &mut SwiftEntity,
    record: UnresolvedRecord,
) {
    let observation_id = swift_observation_id(&record.seed);
    let evidence_id = swift_evidence_id(&format!("{}|evidence", record.seed));
    let diagnostic_id =
        SwiftDiagnosticId::new(sha256_hex(format!("{}|diagnostic", record.seed).as_bytes()))
            .expect("SHA-256 Swift diagnostic ID");
    observations.push(SwiftObservation {
        id: observation_id.clone(),
        source: record.source,
        raw: HexBytes::from_bytes(&record.raw),
        location: record.location.clone(),
        disposition: SwiftObservationDisposition::Included {
            entity_ids: NonEmpty::new(vec![entity.id.clone()])
                .expect("one unresolved conformance owner"),
        },
    });
    evidence.push(SwiftEvidence {
        id: evidence_id.clone(),
        observation_ids: NonEmpty::new(vec![observation_id.clone()])
            .expect("one unresolved conformance observation"),
        kind: record.kind,
        location: record.location,
        raw: HexBytes::from_bytes(&record.raw),
    });
    entity.observation_ids.push(observation_id.clone());
    entity.state = SwiftEntityState::Partial;
    entity.conformances = SwiftValue::Unavailable {
        reason: SwiftUnavailableReason::UnresolvedReference,
    };
    if let Some(gap) = entity
        .gaps
        .iter_mut()
        .find(|gap| gap.field == SwiftFieldName::Conformances)
    {
        gap.reason = SwiftUnavailableReason::UnresolvedReference;
        if !gap.evidence_ids.contains(&evidence_id) {
            gap.evidence_ids.push(evidence_id.clone());
        }
    }
    diagnostics.push(SwiftDiagnostic {
        id: diagnostic_id,
        code: SwiftDiagnosticCode::UnresolvedReference,
        severity: Severity::Warning,
        message: record.message,
        observation_id: Some(observation_id),
        entity_id: Some(entity.id.clone()),
        evidence_ids: vec![evidence_id],
    });
}

fn swift_observation_id(seed: &str) -> SwiftObservationId {
    SwiftObservationId::new(sha256_hex(format!("swift-observation|{seed}").as_bytes()))
        .expect("SHA-256 Swift observation ID")
}

fn swift_evidence_id(seed: &str) -> SwiftEvidenceId {
    SwiftEvidenceId::new(sha256_hex(format!("swift-evidence|{seed}").as_bytes()))
        .expect("SHA-256 Swift evidence ID")
}
