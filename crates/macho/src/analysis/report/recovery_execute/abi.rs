//! Explicit, selection-bounded ABI body evidence.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::MachoFile;
use crate::core::model::container::MachoContainer;

use super::super::*;
use super::types::{evidence_id, known_fact, recovery_gap_id};
use super::{
    begin_collector, entity_address, entity_presence, entity_role, finish_collector,
    selected_targets,
};

/// Executes the explicitly requested ABI-body collector for every selected slice.
///
/// This collector is selection-bounded and is never invoked by symbol-only or
/// range-only command paths.
pub fn execute_recovery_abi(
    container: &MachoContainer<'_>,
    report: &mut RecoveryReport,
) -> crate::analysis::Result<()> {
    for (index, macho) in container.macho_files().enumerate() {
        let Some(slice) = report
            .slices
            .as_mut_slice()
            .iter_mut()
            .find(|slice| slice.image.slice_index == index as u32)
        else {
            continue;
        };
        execute_abi_slice(macho, slice, report.request.limits)?;
    }
    Ok(())
}

fn execute_abi_slice(
    macho: &MachoFile<'_>,
    slice: &mut SliceRecovery,
    limits: RecoveryLimits,
) -> crate::analysis::Result<()> {
    let targets = selected_targets(slice, |entity| {
        entity_presence(entity) == Some(Presence::Defined)
            && matches!(
                entity_role(entity),
                Some(EntityRole::Function | EntityRole::CppMethod | EntityRole::Thunk)
            )
    });
    let Some(targets) = begin_collector(slice, CollectorId::AbiBody, targets, limits) else {
        return Ok(());
    };
    let target_set = targets
        .iter()
        .map(EntityId::as_str)
        .collect::<BTreeSet<_>>();
    let symbols = macho.ext::<crate::core::SymbolTable<'_>>()?;
    let by_address = symbols
        .symbols()
        .iter()
        .filter(|symbol| symbol.is_defined() && symbol.value != 0)
        .map(|symbol| (symbol.value, symbol))
        .collect::<BTreeMap<_, _>>();
    let mut outputs = 0u64;
    for entity in &mut slice.entities {
        if !target_set.contains(entity.id.as_str()) {
            continue;
        }
        let Some((address, symbol)) = entity_address(entity)
            .and_then(|address| by_address.get(&address).map(|symbol| (address, *symbol)))
        else {
            continue;
        };
        let Some(analysis) =
            crate::metadata::cpp::abi::analyze_symbol_body(macho, &symbols, symbol, None)
        else {
            continue;
        };
        let range = match &entity.location {
            Fact::Known { value, .. } => value
                .range
                .unwrap_or(AddressRange::new(address, address.saturating_add(1)).unwrap()),
            _ => AddressRange::new(address, address.saturating_add(1)).unwrap(),
        };
        let id = evidence_id(&format!("abi|{}|{address}", entity.id));
        let return_class = abi_return_class(&analysis.return_channel);
        let parameter_classes = analysis
            .argument_hints
            .iter()
            .map(abi_argument_class)
            .collect::<Vec<_>>();
        entity.evidence.push(EvidenceRecord {
            id: id.clone(),
            collector: CollectorId::AbiBody,
            observation_ids: entity.observation_ids.as_slice().to_vec(),
            strength: EvidenceStrength::Inferred,
            payload: EvidencePayload::Abi {
                value: AbiEvidence {
                    architecture: slice.architecture,
                    entity_id: entity.id.clone(),
                    range,
                    return_class,
                    parameter_classes: parameter_classes.clone(),
                    decode_gaps: Vec::new(),
                },
            },
        });
        set_abi_fact(
            &mut entity.signature.return_type,
            TypeEvidence::AbiClass {
                class: return_class,
            },
            &id,
        );
        if let Some(count) = analysis.param_count {
            let mut classes = parameter_classes;
            classes.resize(count as usize, AbiValueClass::Unknown);
            let parameters = classes
                .into_iter()
                .enumerate()
                .map(|(index, class)| RecoveredParameter {
                    type_evidence: known_fact(
                        &format!("{}|abi_parameter|{index}|type", entity.id),
                        TypeEvidence::AbiClass { class },
                        EvidenceStrength::Inferred,
                        &id,
                    ),
                    source_name: known_fact(
                        &format!("{}|abi_parameter|{index}|name", entity.id),
                        format!("arg{index}"),
                        EvidenceStrength::Inferred,
                        &id,
                    ),
                })
                .collect();
            set_abi_fact(
                &mut entity.signature.parameters,
                ParameterList::Known { value: parameters },
                &id,
            );
        }
        for field in [RecoveryField::ReturnType, RecoveryField::Parameters] {
            if !entity.gaps.iter().any(|gap| gap.field == field) {
                entity.gaps.push(RecoveryGap {
                    id: recovery_gap_id(&format!("gap|{}|{field:?}", entity.id)),
                    field,
                    reason: RecoveryGapReason::HeaderIneligible {
                        reason: HeaderIneligibilityReason::AbiClassIsNotSourceType,
                    },
                    evidence_ids: vec![id.clone()],
                });
            }
        }
        outputs += 1;
    }
    finish_collector(
        slice,
        CollectorId::AbiBody,
        targets,
        CollectorOutcome::Complete,
        symbols.len() as u64,
        outputs,
    );
    Ok(())
}

fn set_abi_fact<T>(fact: &mut Fact<T>, value: T, evidence_id: &EvidenceId) {
    if let Fact::Unavailable { id, .. } = fact {
        *fact = Fact::Known {
            id: id.clone(),
            value,
            strength: EvidenceStrength::Inferred,
            evidence_ids: NonEmpty::new(vec![evidence_id.clone()]).expect("one ABI evidence ID"),
        };
    }
}

fn abi_return_class(value: &crate::metadata::cpp::CppReturnChannel) -> AbiValueClass {
    match value {
        crate::metadata::cpp::CppReturnChannel::GeneralPurpose => AbiValueClass::Integer,
        crate::metadata::cpp::CppReturnChannel::FloatingPoint => AbiValueClass::Floating,
        crate::metadata::cpp::CppReturnChannel::AggregateIndirect => AbiValueClass::Indirect,
        crate::metadata::cpp::CppReturnChannel::Void => AbiValueClass::Void,
        crate::metadata::cpp::CppReturnChannel::Unknown => AbiValueClass::Unknown,
        _ => AbiValueClass::Unknown,
    }
}

fn abi_argument_class(value: &crate::metadata::cpp::ArgumentTypeHint) -> AbiValueClass {
    match value {
        crate::metadata::cpp::ArgumentTypeHint::FloatingPoint => AbiValueClass::Floating,
        crate::metadata::cpp::ArgumentTypeHint::Scalar => AbiValueClass::Integer,
        crate::metadata::cpp::ArgumentTypeHint::Pointer
        | crate::metadata::cpp::ArgumentTypeHint::CString
        | crate::metadata::cpp::ArgumentTypeHint::ClassPointer { .. }
        | crate::metadata::cpp::ArgumentTypeHint::ObjcObject
        | crate::metadata::cpp::ArgumentTypeHint::StructPointer => AbiValueClass::Indirect,
        crate::metadata::cpp::ArgumentTypeHint::Unknown => AbiValueClass::Unknown,
        _ => AbiValueClass::Unknown,
    }
}
