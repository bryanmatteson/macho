//! Selection-bounded DWARF function and global-variable recovery.

use super::*;

pub(super) fn execute_dwarf(
    macho: &MachoFile<'_>,
    slice: &mut SliceRecovery,
    limits: RecoveryLimits,
) {
    let targets = selected_targets(slice, |entity| {
        matches!(
            entity_role(entity),
            Some(
                EntityRole::Function
                    | EntityRole::CppMethod
                    | EntityRole::Thunk
                    | EntityRole::Data
                    | EntityRole::Tls
                    | EntityRole::CppStaticData
            )
        )
    });
    let Some(targets) = begin_collector(slice, CollectorId::Dwarf, targets, limits) else {
        return;
    };
    let target_set = targets
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    let (index, variables) = match (
        DwarfFunctionIndex::build(macho),
        DwarfVariableIndex::build(macho),
    ) {
        (Ok(index), Ok(variables)) if !index.is_empty() || !variables.is_empty() => {
            (index, variables)
        }
        (Ok(_), Ok(_)) => {
            finish_collector(
                slice,
                CollectorId::Dwarf,
                targets,
                CollectorOutcome::Unsupported {
                    reason: UnsupportedReasonCode::MissingDebugInfo,
                },
                0,
                0,
            );
            return;
        }
        (Err(error), _) | (_, Err(error)) => {
            let diagnostic_id =
                diagnostic_id(&format!("dwarf|{}|{error}", slice.image.content_sha256));
            slice.diagnostics.push(RecoveryDiagnostic {
                id: diagnostic_id.clone(),
                code: RecoveryDiagnosticCode::CollectorFailed,
                severity: Severity::Warning,
                message: format!("DWARF collection failed: {error}"),
                observation_id: None,
                entity_id: None,
                evidence_ids: Vec::new(),
            });
            finish_collector(
                slice,
                CollectorId::Dwarf,
                targets,
                CollectorOutcome::Failed { diagnostic_id },
                0,
                0,
            );
            return;
        }
    };
    let mut outputs = 0u64;
    for entity in &mut slice.entities {
        if !target_set.contains(entity.id.as_str()) {
            continue;
        }
        if matches!(
            entity_role(entity),
            Some(EntityRole::Data | EntityRole::Tls | EntityRole::CppStaticData)
        ) {
            let variable = raw_linkage(entity)
                .and_then(|name| {
                    variables.find_by_linkage_name(name).or_else(|| {
                        name.strip_prefix('_')
                            .and_then(|stripped| variables.find_by_linkage_name(stripped))
                    })
                })
                .or_else(|| match &entity.display_name {
                    Fact::Known { value, .. } => variables.find_by_name(value),
                    Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
                });
            let Some(variable) = variable else {
                continue;
            };
            let evidence_id = evidence_id(&format!(
                "dwarf|{}|{}|{}",
                entity.id, variable.unit_offset, variable.die_offset
            ));
            entity.evidence.push(EvidenceRecord {
                id: evidence_id.clone(),
                collector: CollectorId::Dwarf,
                observation_ids: entity.observation_ids.as_slice().to_vec(),
                strength: EvidenceStrength::Exact,
                payload: EvidencePayload::Dwarf {
                    value: DwarfEvidence {
                        unit_offset: variable.unit_offset,
                        die_offset: variable.die_offset,
                        tag: DwarfTag::Variable,
                        attribute: DwarfAttribute::Type,
                        source_file: None,
                    },
                },
            });
            if let Some(ty) = dwarf_type(&variable.ty) {
                reconcile_fact(
                    &mut entity.value_type,
                    TypeEvidence::Source { ty },
                    EvidenceStrength::Exact,
                    &evidence_id,
                    entity.id.as_str(),
                    RecoveryField::ValueType,
                    &mut entity.gaps,
                );
                outputs += 1;
            }
            continue;
        }
        let function = raw_linkage(entity)
            .and_then(|name| {
                index.find_by_linkage_name(name).or_else(|| {
                    name.strip_prefix('_')
                        .and_then(|stripped| index.find_by_linkage_name(stripped))
                })
            })
            .or_else(|| entity_address(entity).and_then(|address| index.find_by_address(address)));
        let Some(function) = function else {
            continue;
        };
        let evidence_id = evidence_id(&format!(
            "dwarf|{}|{}|{}",
            entity.id, function.unit_offset, function.die_offset
        ));
        entity.evidence.push(EvidenceRecord {
            id: evidence_id.clone(),
            collector: CollectorId::Dwarf,
            observation_ids: entity.observation_ids.as_slice().to_vec(),
            strength: EvidenceStrength::Exact,
            payload: EvidencePayload::Dwarf {
                value: DwarfEvidence {
                    unit_offset: function.unit_offset,
                    die_offset: function.die_offset,
                    tag: DwarfTag::Subprogram,
                    attribute: DwarfAttribute::Type,
                    source_file: None,
                },
            },
        });
        if let Some(return_type) = dwarf_type(&function.return_type) {
            reconcile_fact(
                &mut entity.signature.return_type,
                TypeEvidence::Source { ty: return_type },
                EvidenceStrength::Exact,
                &evidence_id,
                entity.id.as_str(),
                RecoveryField::ReturnType,
                &mut entity.gaps,
            );
        }
        let parameter_types = function
            .parameters
            .iter()
            .filter(|parameter| !parameter.is_artificial)
            .map(|parameter| dwarf_type(&parameter.ty))
            .collect::<Option<Vec<_>>>();
        if let Some(parameter_types) = parameter_types {
            let parameters = parameter_types
                .into_iter()
                .zip(
                    function
                        .parameters
                        .iter()
                        .filter(|parameter| !parameter.is_artificial),
                )
                .enumerate()
                .map(|(index, (ty, parameter))| RecoveredParameter {
                    type_evidence: known_fact(
                        &format!("{}|parameter|{index}|type", entity.id),
                        TypeEvidence::Source { ty },
                        EvidenceStrength::Exact,
                        &evidence_id,
                    ),
                    source_name: known_fact(
                        &format!("{}|parameter|{index}|name", entity.id),
                        parameter
                            .name
                            .clone()
                            .unwrap_or_else(|| format!("arg{index}")),
                        EvidenceStrength::Exact,
                        &evidence_id,
                    ),
                })
                .collect();
            reconcile_fact(
                &mut entity.signature.parameters,
                ParameterList::Known { value: parameters },
                EvidenceStrength::Exact,
                &evidence_id,
                entity.id.as_str(),
                RecoveryField::Parameters,
                &mut entity.gaps,
            );
            reconcile_fact(
                &mut entity.signature.variadic,
                function.is_variadic,
                EvidenceStrength::Exact,
                &evidence_id,
                entity.id.as_str(),
                RecoveryField::Variadic,
                &mut entity.gaps,
            );
        }
        let convention = match function.calling_convention {
            DwarfCallingConvention::Normal => CallingConvention::C,
            DwarfCallingConvention::Other(_) => CallingConvention::Unknown,
            _ => CallingConvention::Unknown,
        };
        reconcile_fact(
            &mut entity.signature.calling_convention,
            convention,
            EvidenceStrength::Exact,
            &evidence_id,
            entity.id.as_str(),
            RecoveryField::CallingConvention,
            &mut entity.gaps,
        );
        outputs += 1;
    }
    finish_collector(
        slice,
        CollectorId::Dwarf,
        targets,
        CollectorOutcome::Complete,
        (index.len() + variables.len()) as u64,
        outputs,
    );
}
