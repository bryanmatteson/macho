//! Positive-evidence C++ type-entity materialization.

use std::collections::BTreeMap;

use super::*;

#[derive(Debug)]
struct CppTypeAnchor {
    entity_index: usize,
    class_name: String,
}

pub(super) fn materialize_cpp_types(
    observations: &mut [SymbolObservation],
    entities: &mut Vec<RecoveredEntity>,
) {
    let anchors = entities
        .iter()
        .enumerate()
        .filter_map(|(entity_index, entity)| {
            let raw = match &entity.linkage {
                Fact::Known { value, .. } => value.raw.as_str(),
                _ => return None,
            };
            let record = crate::reconstruct::cpp::symbol::parse_symbol(raw, None, None)?;
            let class_name = match record.kind {
                crate::reconstruct::cpp::CppSymbolKind::Function { decl }
                    if decl.is_constructor || decl.is_destructor =>
                {
                    decl.name.parent()?.as_string()
                }
                crate::reconstruct::cpp::CppSymbolKind::Special {
                    detail:
                        crate::reconstruct::cpp::CppSpecialSymbol::VirtualTable { class_name }
                        | crate::reconstruct::cpp::CppSpecialSymbol::TypeInfo { class_name }
                        | crate::reconstruct::cpp::CppSpecialSymbol::TypeInfoName { class_name },
                } => class_name,
                _ => return None,
            };
            (!class_name.is_empty()).then_some(CppTypeAnchor {
                entity_index,
                class_name,
            })
        })
        .collect::<Vec<_>>();

    let mut groups = BTreeMap::<String, Vec<usize>>::new();
    for anchor in anchors {
        groups
            .entry(anchor.class_name)
            .or_default()
            .push(anchor.entity_index);
    }

    for (class_name, mut source_indices) in groups {
        source_indices.sort_unstable();
        source_indices.dedup();
        let type_id = id::<EntityId>(&format!("entity|Cpp|type|{class_name}"));
        let type_entity = build_cpp_type_entity(&type_id, &class_name, &source_indices, entities);

        for source_index in source_indices {
            let entity = &mut entities[source_index];
            let evidence_id = entity
                .evidence
                .first()
                .map(|record| record.id.clone())
                .expect("symbol entity has evidence");
            let fact_id = match &entity.owner {
                Fact::Known { id, .. }
                | Fact::Conflicted { id, .. }
                | Fact::Unavailable { id, .. } => id.clone(),
            };
            let path = class_name
                .split("::")
                .filter_map(|part| Identifier::new(part.to_owned()).ok())
                .collect();
            entity.owner = Fact::Known {
                id: fact_id,
                value: EntityOwner {
                    kind: Some(HeaderOwnerKind::Class),
                    path,
                    entity_id: Some(type_id.clone()),
                },
                strength: EvidenceStrength::Correlated,
                evidence_ids: NonEmpty::new(vec![evidence_id]).expect("one owner evidence ID"),
            };
            entity.gaps.retain(|gap| gap.field != RecoveryField::Owner);
            for observation_id in entity.observation_ids.as_slice() {
                if let Some(SymbolObservation {
                    disposition: ObservationDisposition::Included { entity_ids },
                    ..
                }) = observations
                    .iter_mut()
                    .find(|observation| observation.id == *observation_id)
                    && !entity_ids.as_slice().contains(&type_id)
                {
                    entity_ids.push(type_id.clone());
                }
            }
        }
        entities.push(type_entity);
    }
}

fn build_cpp_type_entity(
    type_id: &EntityId,
    class_name: &str,
    source_indices: &[usize],
    entities: &[RecoveredEntity],
) -> RecoveredEntity {
    let seed = type_id.as_str();
    let mut observation_ids = Vec::new();
    let mut evidence = Vec::new();
    let mut presence = Presence::Imported;
    for source_index in source_indices {
        let source = &entities[*source_index];
        if matches!(
            source.presence,
            Fact::Known {
                value: Presence::Defined,
                ..
            }
        ) {
            presence = Presence::Defined;
        }
        for observation_id in source.observation_ids.as_slice() {
            if !observation_ids.contains(observation_id) {
                observation_ids.push(observation_id.clone());
            }
        }
        let source_record = source.evidence.first().expect("symbol entity has evidence");
        let evidence_id =
            id::<EvidenceId>(&format!("evidence|{seed}|type_anchor|{}", source_record.id));
        evidence.push(EvidenceRecord {
            id: evidence_id,
            collector: CollectorId::SymbolDiscovery,
            observation_ids: source_record.observation_ids.clone(),
            strength: EvidenceStrength::Correlated,
            payload: source_record.payload.clone(),
        });
    }
    let evidence_ids = NonEmpty::new(evidence.iter().map(|record| record.id.clone()).collect())
        .expect("a type entity has anchor evidence");
    macro_rules! unavailable {
        ($field:expr, $reason:expr $(,)?) => {
            Fact::Unavailable {
                id: id::<FactId>(&format!("fact|{seed}|{}", $field)),
                reason: $reason,
                evidence_ids: evidence_ids.as_slice().to_vec(),
            }
        };
    }
    macro_rules! known {
        ($field:expr, $value:expr, $strength:expr $(,)?) => {
            Fact::Known {
                id: id::<FactId>(&format!("fact|{seed}|{}", $field)),
                value: $value,
                strength: $strength,
                evidence_ids: evidence_ids.clone(),
            }
        };
    }
    let gap = |field: RecoveryField, reason: UnavailableReason| RecoveryGap {
        id: id::<RecoveryGapId>(&format!("gap|{seed}|{field:?}")),
        field,
        reason: RecoveryGapReason::Unavailable { reason },
        evidence_ids: evidence_ids.as_slice().to_vec(),
    };
    RecoveredEntity {
        id: type_id.clone(),
        identity_stability: IdentityStability::CrossBuild,
        observation_ids: NonEmpty::new(observation_ids).expect("type observations are non-empty"),
        linkage: unavailable!("linkage", UnavailableReason::NotApplicable),
        display_name: known!(
            "display_name",
            class_name.to_owned(),
            EvidenceStrength::Correlated,
        ),
        role: known!("role", EntityRole::Type, EvidenceStrength::Correlated),
        presence: known!("presence", presence, EvidenceStrength::Correlated),
        visibility: known!(
            "visibility",
            Visibility::Unknown,
            EvidenceStrength::Inferred,
        ),
        weakness: known!("weakness", Weakness::Unknown, EvidenceStrength::Inferred,),
        location: unavailable!("location", UnavailableReason::NotApplicable),
        owner: unavailable!(
            "owner",
            if class_name.contains("::") {
                UnavailableReason::Ambiguous
            } else {
                UnavailableReason::NotApplicable
            },
        ),
        value_type: unavailable!("value_type", UnavailableReason::NotApplicable),
        signature: RecoveredSignature {
            return_type: unavailable!("return_type", UnavailableReason::NotApplicable),
            parameters: unavailable!("parameters", UnavailableReason::NotApplicable),
            variadic: unavailable!("variadic", UnavailableReason::NotApplicable),
            calling_convention: unavailable!(
                "calling_convention",
                UnavailableReason::NotApplicable,
            ),
            qualifiers: unavailable!("qualifiers", UnavailableReason::NotApplicable),
        },
        layout: RecoveredLayout {
            size: unavailable!("layout_size", UnavailableReason::NotEncoded),
            alignment: unavailable!("layout_alignment", UnavailableReason::NotEncoded),
            fields: unavailable!("layout_fields", UnavailableReason::NotEncoded),
            completeness: known!(
                "layout_completeness",
                LayoutCompleteness::Opaque,
                EvidenceStrength::Correlated,
            ),
        },
        hierarchy: RecoveredHierarchy {
            bases: unavailable!("bases", UnavailableReason::NotEncoded),
            virtual_surface: unavailable!("virtual_surface", UnavailableReason::NotEncoded),
        },
        evidence,
        gaps: [
            gap(RecoveryField::LayoutSize, UnavailableReason::NotEncoded),
            gap(
                RecoveryField::LayoutAlignment,
                UnavailableReason::NotEncoded,
            ),
            gap(RecoveryField::LayoutFields, UnavailableReason::NotEncoded),
            gap(RecoveryField::Bases, UnavailableReason::NotEncoded),
            gap(RecoveryField::VirtualSurface, UnavailableReason::NotEncoded),
        ]
        .into_iter()
        .chain(
            class_name
                .contains("::")
                .then(|| gap(RecoveryField::Owner, UnavailableReason::Ambiguous)),
        )
        .collect(),
    }
}
