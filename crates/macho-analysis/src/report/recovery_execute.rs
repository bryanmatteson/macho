//! Selection-aware execution of optional C and C++ recovery collectors.

mod abi;
mod dwarf;
mod types;

pub use abi::execute_recovery_abi;

use types::*;

use std::collections::{BTreeMap, BTreeSet};

use macho_core::model::addr::types::ThinFileOffset;
use macho_core::model::container::MachoContainer;
use macho_core::{LoadCommand, MachoFile};
use macho_dwarf::types::CallingConvention as DwarfCallingConvention;
use macho_dwarf::{DwarfFunctionIndex, DwarfVariableIndex};

use super::*;

/// Executes the source-evidence collectors required by a C or C++ surface.
///
/// Selection has already been resolved when this function is called.  Each
/// optional collector is added to the plan with its exact non-empty target set
/// before it executes.  The symbols-only APIs do not call this executor.
pub fn execute_recovery_sources(
    container: &MachoContainer<'_>,
    report: &mut RecoveryReport,
) -> crate::Result<()> {
    for (index, macho) in container.macho_files().enumerate() {
        let Some(slice) = report
            .slices
            .as_mut_slice()
            .iter_mut()
            .find(|slice| slice.image.slice_index == index as u32)
        else {
            continue;
        };
        if report.language == RecoveryLanguage::Cpp {
            enrich_itanium(slice);
        }
        execute_ranges(macho, slice, report.request.limits)?;
        dwarf::execute_dwarf(macho, slice, report.request.limits);
        if report.language == RecoveryLanguage::Cpp {
            execute_rtti(macho, slice, report.request.limits);
            execute_vtables(macho, slice, report.request.limits);
        }
    }
    Ok(())
}

/// Executes bounded ABI-body inference for only the selected, defined callable
/// entities in an already-resolved recovery report.
fn selected_targets(
    slice: &SliceRecovery,
    predicate: impl Fn(&RecoveredEntity) -> bool,
) -> Vec<EntityId> {
    let selected = slice
        .resolved_plan
        .selected_entity_ids
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    slice
        .entities
        .iter()
        .filter(|entity| selected.contains(entity.id.as_str()) && predicate(entity))
        .map(|entity| entity.id.clone())
        .collect()
}

fn begin_collector(
    slice: &mut SliceRecovery,
    collector: CollectorId,
    targets: Vec<EntityId>,
    limits: RecoveryLimits,
) -> Option<Vec<EntityId>> {
    if targets.is_empty() {
        return None;
    }
    slice.resolved_plan.targeted.push(ResolvedCollectorSpec {
        collector,
        target_entity_ids: targets.clone(),
        required: false,
        limits: CollectorLimits {
            max_records: match collector {
                CollectorId::FunctionRanges => limits.max_ranges,
                CollectorId::Dwarf => limits.max_dwarf_dies,
                _ => limits.max_evidence_records,
            },
            max_bytes: limits.max_decoded_bytes,
            max_diagnostics: limits.max_diagnostics,
        },
    });
    Some(targets)
}

fn finish_collector(
    slice: &mut SliceRecovery,
    collector: CollectorId,
    targets: Vec<EntityId>,
    outcome: CollectorOutcome,
    input_records: u64,
    output_records: u64,
) {
    slice.executions.push(CollectorExecution {
        collector,
        request_digest: slice.resolved_plan.request_digest.clone(),
        counts: CollectorCounts {
            input_records,
            output_records,
            selected_targets: targets.len() as u64,
        },
        target_entity_ids: targets,
        outcome,
    });
}

fn entity_role(entity: &RecoveredEntity) -> Option<EntityRole> {
    match &entity.role {
        Fact::Known { value, .. } => Some(*value),
        Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
    }
}

fn entity_presence(entity: &RecoveredEntity) -> Option<Presence> {
    match &entity.presence {
        Fact::Known { value, .. } => Some(*value),
        Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
    }
}

fn entity_address(entity: &RecoveredEntity) -> Option<u64> {
    match &entity.location {
        Fact::Known { value, .. } => value.address,
        Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
    }
}

fn raw_linkage(entity: &RecoveredEntity) -> Option<&str> {
    match &entity.linkage {
        Fact::Known { value, .. } => Some(value.raw.as_str()),
        Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
    }
}

fn execute_ranges(
    macho: &MachoFile<'_>,
    slice: &mut SliceRecovery,
    limits: RecoveryLimits,
) -> crate::Result<()> {
    let targets = selected_targets(slice, |entity| {
        entity_presence(entity) == Some(Presence::Defined)
            && matches!(
                entity_role(entity),
                Some(EntityRole::Function | EntityRole::CppMethod | EntityRole::Thunk)
            )
            && entity_address(entity).is_some()
    });
    let Some(targets) = begin_collector(slice, CollectorId::FunctionRanges, targets, limits) else {
        return Ok(());
    };
    let target_set = targets
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    let starts = function_starts(macho)?;
    let starts_set = starts.iter().copied().collect::<BTreeSet<_>>();
    let mut candidate_starts = starts;
    candidate_starts.extend(
        slice
            .entities
            .iter()
            .filter_map(entity_address)
            .filter(|address| *address != 0),
    );
    candidate_starts.sort_unstable();
    candidate_starts.dedup();
    let section_ends = macho
        .all_sections()
        .filter(|section| section.size() != 0)
        .map(|section| {
            (
                section.addr().0,
                section.addr().0.saturating_add(section.size()),
            )
        })
        .collect::<Vec<_>>();
    let mut outputs = 0u64;
    for entity in &mut slice.entities {
        if !target_set.contains(entity.id.as_str()) {
            continue;
        }
        let Some(start) = entity_address(entity) else {
            continue;
        };
        let next = candidate_starts
            .get(candidate_starts.partition_point(|candidate| *candidate <= start))
            .copied();
        let section_end = section_ends
            .iter()
            .find(|(section_start, section_end)| start >= *section_start && start < *section_end)
            .map(|(_, end)| *end);
        let end = match (next, section_end) {
            (Some(next), Some(section_end)) => next.min(section_end),
            (Some(next), None) => next,
            (None, Some(section_end)) => section_end,
            (None, None) => start.saturating_add(1),
        };
        let Ok(range) = AddressRange::new(start, end) else {
            continue;
        };
        let source = if starts_set.contains(&start) {
            RangeSource::FunctionStarts
        } else {
            RangeSource::SymbolAdjacency
        };
        let evidence_id = evidence_id(&format!("range|{}|{start}|{end}|{source:?}", entity.id));
        entity.evidence.push(EvidenceRecord {
            id: evidence_id.clone(),
            collector: CollectorId::FunctionRanges,
            observation_ids: entity.observation_ids.as_slice().to_vec(),
            strength: EvidenceStrength::Correlated,
            payload: EvidencePayload::Range {
                value: RangeEvidence {
                    start,
                    end_exclusive: end,
                    source,
                },
            },
        });
        if let Fact::Known {
            value,
            evidence_ids,
            ..
        } = &mut entity.location
        {
            value.range = Some(range);
            evidence_ids.push(evidence_id);
            outputs += 1;
        }
    }
    finish_collector(
        slice,
        CollectorId::FunctionRanges,
        targets,
        CollectorOutcome::Complete,
        candidate_starts.len() as u64,
        outputs,
    );
    Ok(())
}

fn function_starts(macho: &MachoFile<'_>) -> crate::Result<Vec<u64>> {
    let Some(data) = macho
        .load_commands()
        .iter()
        .find_map(|command| match command.kind() {
            LoadCommand::FunctionStarts(data) => Some(data),
            _ => None,
        })
    else {
        return Ok(Vec::new());
    };
    let bytes = macho.read_bytes_at(
        ThinFileOffset(data.data_offset as u64),
        data.data_size as usize,
    )?;
    let mut reader = macho_dyld::uleb::LebReader::new(bytes);
    let mut address = macho.image_base().0;
    let mut result = Vec::new();
    while !reader.is_empty() {
        let delta = reader.read_uleb128()?;
        if delta == 0 {
            break;
        }
        address = address
            .checked_add(delta)
            .ok_or_else(|| crate::AnalysisError::invalid("function-start address overflow"))?;
        result.push(address);
    }
    Ok(result)
}

fn enrich_itanium(slice: &mut SliceRecovery) {
    let selected = slice
        .resolved_plan
        .selected_entity_ids
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    for entity in &mut slice.entities {
        if !selected.contains(entity.id.as_str()) {
            continue;
        }
        let Some(raw) = raw_linkage(entity).map(str::to_owned) else {
            continue;
        };
        let Some(record) =
            crate::reconstruct::cpp::symbol::parse_symbol(&raw, entity_address(entity), None)
        else {
            continue;
        };
        let symbol_evidence = entity
            .evidence
            .iter()
            .find(|evidence| evidence.collector == CollectorId::SymbolDiscovery)
            .map(|evidence| evidence.id.clone());
        let Some(evidence_id) = symbol_evidence else {
            continue;
        };
        let crate::reconstruct::cpp::CppSymbolKind::Function { decl } = record.kind else {
            continue;
        };
        let mut converted = Vec::new();
        let mut variadic = false;
        for parameter in &decl.signature.params {
            if parameter.ty.render() == "..." {
                variadic = true;
                continue;
            }
            let Some(ty) = cpp_type(&parameter.ty) else {
                converted.clear();
                break;
            };
            converted.push((parameter.name.clone(), ty));
        }
        if !converted.is_empty() || decl.signature.params.is_empty() {
            let parameters = converted
                .into_iter()
                .enumerate()
                .map(|(index, (name, ty))| RecoveredParameter {
                    type_evidence: known_fact(
                        &format!("{}|itanium_parameter|{index}|type", entity.id),
                        TypeEvidence::Source { ty },
                        EvidenceStrength::Exact,
                        &evidence_id,
                    ),
                    source_name: known_fact(
                        &format!("{}|itanium_parameter|{index}|name", entity.id),
                        name,
                        EvidenceStrength::Inferred,
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
                variadic,
                EvidenceStrength::Exact,
                &evidence_id,
                entity.id.as_str(),
                RecoveryField::Variadic,
                &mut entity.gaps,
            );
        }
        if let Some(return_type) = decl.signature.return_type.as_ref().and_then(cpp_type) {
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
        let qualifiers = FunctionQualifiers {
            is_const: Some(decl.signature.is_const),
            is_volatile: Some(decl.signature.is_volatile),
            reference: decl
                .signature
                .ref_qualifier
                .as_ref()
                .map(|kind| match kind {
                    crate::reconstruct::cpp::CppRefQualifier::Lvalue => ReferenceKind::Lvalue,
                    crate::reconstruct::cpp::CppRefQualifier::Rvalue => ReferenceKind::Rvalue,
                }),
            noexcept: Some(decl.signature.noexcept),
        };
        reconcile_fact(
            &mut entity.signature.qualifiers,
            qualifiers,
            EvidenceStrength::Exact,
            &evidence_id,
            entity.id.as_str(),
            RecoveryField::Qualifiers,
            &mut entity.gaps,
        );
        if (decl.is_constructor || decl.is_destructor)
            && let Some(parent) = decl.name.parent()
            && let Some(path) = identifier_path(&parent.components)
        {
            let owner_entity_id = match &entity.owner {
                Fact::Known { value, .. } => value.entity_id.clone(),
                Fact::Conflicted { .. } | Fact::Unavailable { .. } => None,
            };
            reconcile_fact(
                &mut entity.owner,
                EntityOwner {
                    kind: Some(HeaderOwnerKind::Class),
                    path: path.into_vec(),
                    entity_id: owner_entity_id,
                },
                EvidenceStrength::Correlated,
                &evidence_id,
                entity.id.as_str(),
                RecoveryField::Owner,
                &mut entity.gaps,
            );
            reconcile_fact(
                &mut entity.role,
                EntityRole::CppMethod,
                EvidenceStrength::Correlated,
                &evidence_id,
                entity.id.as_str(),
                RecoveryField::Role,
                &mut entity.gaps,
            );
        }
    }
}

fn execute_rtti(macho: &MachoFile<'_>, slice: &mut SliceRecovery, limits: RecoveryLimits) {
    let targets = selected_targets(slice, |entity| {
        entity_role(entity) == Some(EntityRole::Typeinfo)
    });
    let Some(targets) = begin_collector(slice, CollectorId::Rtti, targets, limits) else {
        return;
    };
    let target_set = targets
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    let index = match macho_cpp::build_typeinfo_index(macho) {
        Ok(index) => index,
        Err(error) => {
            let diagnostic_id =
                diagnostic_id(&format!("rtti|{}|{error}", slice.image.content_sha256));
            slice.diagnostics.push(RecoveryDiagnostic {
                id: diagnostic_id.clone(),
                code: RecoveryDiagnosticCode::CollectorFailed,
                severity: Severity::Warning,
                message: format!("RTTI collection failed: {error}"),
                observation_id: None,
                entity_id: None,
                evidence_ids: Vec::new(),
            });
            finish_collector(
                slice,
                CollectorId::Rtti,
                targets,
                CollectorOutcome::Failed { diagnostic_id },
                0,
                0,
            );
            return;
        }
    };
    let by_address = index
        .values()
        .map(|node| (node.address, node))
        .collect::<BTreeMap<_, _>>();
    let mut outputs = 0u64;
    for entity in &mut slice.entities {
        if !target_set.contains(entity.id.as_str()) {
            continue;
        }
        let Some(node) = entity_address(entity).and_then(|address| by_address.get(&address)) else {
            continue;
        };
        let id = evidence_id(&format!("rtti|{}|{}", entity.id, node.address));
        entity.evidence.push(EvidenceRecord {
            id,
            collector: CollectorId::Rtti,
            observation_ids: entity.observation_ids.as_slice().to_vec(),
            strength: EvidenceStrength::Exact,
            payload: EvidencePayload::Rtti {
                value: RttiEvidence {
                    kind: match node.kind {
                        macho_cpp::CppTypeInfoKind::Class => RttiKind::ClassTypeInfo,
                        macho_cpp::CppTypeInfoKind::SingleInheritance => RttiKind::SiClassTypeInfo,
                        macho_cpp::CppTypeInfoKind::VirtualMultipleInheritance => {
                            RttiKind::VmiClassTypeInfo
                        }
                        _ => RttiKind::Unknown,
                    },
                    address: node.address,
                    type_identity: Some(node.name.clone()),
                },
            },
        });
        outputs += 1;
    }
    let outcome = if index.is_empty() {
        CollectorOutcome::Unsupported {
            reason: UnsupportedReasonCode::MissingRuntimeMetadata,
        }
    } else {
        CollectorOutcome::Complete
    };
    finish_collector(
        slice,
        CollectorId::Rtti,
        targets,
        outcome,
        index.len() as u64,
        outputs,
    );
}

fn execute_vtables(macho: &MachoFile<'_>, slice: &mut SliceRecovery, limits: RecoveryLimits) {
    let targets = selected_targets(slice, |entity| {
        entity_role(entity) == Some(EntityRole::Vtable)
    });
    let Some(targets) = begin_collector(slice, CollectorId::Vtables, targets, limits) else {
        return;
    };
    let target_set = targets
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    let index =
        match macho_cpp::VtableIndex::build_limited(macho, limits.max_evidence_records as usize) {
            Ok(index) => index,
            Err(error) => {
                let diagnostic_id =
                    diagnostic_id(&format!("vtables|{}|{error}", slice.image.content_sha256));
                slice.diagnostics.push(RecoveryDiagnostic {
                    id: diagnostic_id.clone(),
                    code: RecoveryDiagnosticCode::CollectorFailed,
                    severity: Severity::Warning,
                    message: format!("vtable collection failed: {error}"),
                    observation_id: None,
                    entity_id: None,
                    evidence_ids: Vec::new(),
                });
                finish_collector(
                    slice,
                    CollectorId::Vtables,
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
        let Some(vtable) = entity_address(entity)
            .and_then(|address| index.vtables().iter().find(|vtable| vtable.va.0 == address))
        else {
            continue;
        };
        let id = evidence_id(&format!("vtable|{}|{}", entity.id, vtable.va.0));
        entity.evidence.push(EvidenceRecord {
            id,
            collector: CollectorId::Vtables,
            observation_ids: entity.observation_ids.as_slice().to_vec(),
            strength: EvidenceStrength::Exact,
            payload: EvidencePayload::Vtable {
                value: VtableEvidence {
                    address: vtable.va.0,
                    owner: None,
                    slot: None,
                    target: None,
                    kind: VtableKind::Primary,
                },
            },
        });
        outputs += 1;
    }
    let outcome = if index.was_truncated() {
        let truncation_index = slice.truncations.len() as u32;
        slice.truncations.push(Truncation {
            collector: CollectorId::Vtables,
            limit_name: RecoveryLimitName::MaxEvidenceRecords,
            limit: limits.max_evidence_records,
            collected: index.vtables().len() as u64,
            omitted_lower_bound: 1,
        });
        CollectorOutcome::Truncated { truncation_index }
    } else if index.vtables().is_empty() {
        CollectorOutcome::Unsupported {
            reason: UnsupportedReasonCode::MissingRuntimeMetadata,
        }
    } else {
        CollectorOutcome::Complete
    };
    finish_collector(
        slice,
        CollectorId::Vtables,
        targets,
        outcome,
        index.vtables().len() as u64,
        outputs,
    );
}
