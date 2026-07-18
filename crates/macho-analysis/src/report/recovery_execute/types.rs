//! Fact reconciliation and source-type lowering for recovery collectors.

use macho_dwarf::types::DwarfType;

use super::super::*;
pub(super) fn known_fact<T>(
    seed: &str,
    value: T,
    strength: EvidenceStrength,
    evidence_id: &EvidenceId,
) -> Fact<T> {
    Fact::Known {
        id: fact_id(seed),
        value,
        strength,
        evidence_ids: NonEmpty::new(vec![evidence_id.clone()]).expect("one evidence ID"),
    }
}

pub(super) fn reconcile_fact<T: Clone + PartialEq>(
    fact: &mut Fact<T>,
    value: T,
    strength: EvidenceStrength,
    evidence_id: &EvidenceId,
    entity_seed: &str,
    field: RecoveryField,
    gaps: &mut Vec<RecoveryGap>,
) {
    let id = match fact {
        Fact::Known { id, .. } | Fact::Conflicted { id, .. } | Fact::Unavailable { id, .. } => {
            id.clone()
        }
    };
    match fact {
        Fact::Unavailable { .. } => {
            *fact = Fact::Known {
                id,
                value,
                strength,
                evidence_ids: NonEmpty::new(vec![evidence_id.clone()]).expect("one evidence ID"),
            };
            gaps.retain(|gap| gap.field != field);
        }
        Fact::Known {
            value: current,
            strength: current_strength,
            evidence_ids,
            ..
        } if *current == value => {
            evidence_ids.push(evidence_id.clone());
            if evidence_rank(strength) > evidence_rank(*current_strength) {
                *current_strength = strength;
            }
            gaps.retain(|gap| gap.field != field);
        }
        Fact::Known {
            value: current,
            strength: current_strength,
            evidence_ids,
            ..
        } => {
            let current_rank = evidence_rank(*current_strength);
            let incoming_rank = evidence_rank(strength);
            if incoming_rank > current_rank {
                *fact = Fact::Known {
                    id,
                    value,
                    strength,
                    evidence_ids: NonEmpty::new(vec![evidence_id.clone()])
                        .expect("one evidence ID"),
                };
                gaps.retain(|gap| gap.field != field);
                return;
            }
            if incoming_rank < current_rank {
                return;
            }
            let candidates = AtLeastTwo::new(vec![
                FactCandidate {
                    value: current.clone(),
                    strength: *current_strength,
                    evidence_ids: evidence_ids.clone(),
                },
                FactCandidate {
                    value,
                    strength,
                    evidence_ids: NonEmpty::new(vec![evidence_id.clone()])
                        .expect("one evidence ID"),
                },
            ])
            .expect("different fact values form a conflict");
            *fact = Fact::Conflicted {
                id: id.clone(),
                candidates,
            };
            set_conflict_gap(gaps, entity_seed, field, id, evidence_id);
        }
        Fact::Conflicted { candidates, .. } => {
            let incoming_rank = evidence_rank(strength);
            let strongest_rank = candidates
                .as_slice()
                .iter()
                .map(|candidate| evidence_rank(candidate.strength))
                .max()
                .expect("a conflict has candidates");
            if incoming_rank > strongest_rank {
                *fact = Fact::Known {
                    id,
                    value,
                    strength,
                    evidence_ids: NonEmpty::new(vec![evidence_id.clone()])
                        .expect("one evidence ID"),
                };
                gaps.retain(|gap| gap.field != field);
                return;
            }
            if incoming_rank < strongest_rank {
                return;
            }
            let mut values = candidates.as_slice().to_vec();
            if let Some(candidate) = values.iter_mut().find(|candidate| candidate.value == value) {
                if !candidate.evidence_ids.as_slice().contains(evidence_id) {
                    candidate.evidence_ids.push(evidence_id.clone());
                }
            } else {
                values.push(FactCandidate {
                    value,
                    strength,
                    evidence_ids: NonEmpty::new(vec![evidence_id.clone()])
                        .expect("one evidence ID"),
                });
            }
            *fact = Fact::Conflicted {
                id: id.clone(),
                candidates: AtLeastTwo::new(values).expect("existing conflict remains distinct"),
            };
            set_conflict_gap(gaps, entity_seed, field, id, evidence_id);
        }
    }
}

fn set_conflict_gap(
    gaps: &mut Vec<RecoveryGap>,
    entity_seed: &str,
    field: RecoveryField,
    fact_id: FactId,
    evidence_id: &EvidenceId,
) {
    gaps.retain(|gap| gap.field != field);
    gaps.push(RecoveryGap {
        id: recovery_gap_id(&format!("gap|{entity_seed}|{field:?}")),
        field,
        reason: RecoveryGapReason::Conflicted { fact_id },
        evidence_ids: vec![evidence_id.clone()],
    });
}

fn evidence_rank(value: EvidenceStrength) -> u8 {
    match value {
        EvidenceStrength::Inferred => 0,
        EvidenceStrength::Correlated => 1,
        EvidenceStrength::Exact => 2,
    }
}

pub(super) fn dwarf_type(value: &DwarfType) -> Option<HeaderType> {
    Some(match value {
        DwarfType::Void => HeaderType::Builtin {
            name: BuiltinType::Void,
        },
        DwarfType::Base { name, .. } => HeaderType::Builtin {
            name: builtin_type(name)?,
        },
        DwarfType::Pointer { pointee, .. } => HeaderType::Pointer {
            pointee: Box::new(dwarf_type(pointee)?),
            qualifiers: TypeQualifiers::default(),
        },
        DwarfType::Reference { referent } => HeaderType::Reference {
            target: Box::new(dwarf_type(referent)?),
            reference: ReferenceKind::Lvalue,
        },
        DwarfType::RvalueReference { referent } => HeaderType::Reference {
            target: Box::new(dwarf_type(referent)?),
            reference: ReferenceKind::Rvalue,
        },
        DwarfType::Const(inner) => qualify_type(dwarf_type(inner)?, true, false, false),
        DwarfType::Volatile(inner) => qualify_type(dwarf_type(inner)?, false, true, false),
        DwarfType::Restrict(inner) => qualify_type(dwarf_type(inner)?, false, false, true),
        DwarfType::Typedef { name, .. } => named_type(name, NamedTypeTag::Typedef)?,
        DwarfType::Structure {
            name: Some(name), ..
        } => named_type(name, NamedTypeTag::Struct)?,
        DwarfType::Union {
            name: Some(name), ..
        } => named_type(name, NamedTypeTag::Union)?,
        DwarfType::Enumeration {
            name: Some(name), ..
        } => named_type(name, NamedTypeTag::Enum)?,
        DwarfType::Array { element, count } => HeaderType::Array {
            element: Box::new(dwarf_type(element)?),
            count: *count,
        },
        DwarfType::Subroutine {
            return_type,
            params,
        } => HeaderType::Function {
            return_type: Box::new(dwarf_type(return_type)?),
            parameters: params
                .iter()
                .enumerate()
                .map(|(index, parameter)| {
                    Some(HeaderParameter {
                        name: Identifier::new(format!("arg{index}")).ok()?,
                        ty: dwarf_type(parameter)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            parameter_state: ParameterState::Known,
            variadic: false,
            calling_convention: CallingConvention::C,
            qualifiers: HeaderFunctionQualifiers::default(),
        },
        DwarfType::Structure { name: None, .. }
        | DwarfType::Union { name: None, .. }
        | DwarfType::Enumeration { name: None, .. }
        | DwarfType::Unresolved => return None,
        _ => return None,
    })
}

pub(super) fn cpp_type(value: &crate::reconstruct::cpp::CppType) -> Option<HeaderType> {
    use crate::reconstruct::cpp::CppType;
    Some(match value {
        CppType::Builtin { spelling } => HeaderType::Builtin {
            name: builtin_type(spelling)?,
        },
        CppType::Named { name } => named_type(&name.as_string(), NamedTypeTag::Class)?,
        CppType::Pointer { inner } => HeaderType::Pointer {
            pointee: Box::new(cpp_type(inner)?),
            qualifiers: TypeQualifiers::default(),
        },
        CppType::LvalueRef { inner } => HeaderType::Reference {
            target: Box::new(cpp_type(inner)?),
            reference: ReferenceKind::Lvalue,
        },
        CppType::RvalueRef { inner } => HeaderType::Reference {
            target: Box::new(cpp_type(inner)?),
            reference: ReferenceKind::Rvalue,
        },
        CppType::Qualified {
            is_const,
            is_volatile,
            inner,
        } => qualify_type(cpp_type(inner)?, *is_const, *is_volatile, false),
        CppType::FunctionPointer { result, params } => HeaderType::Pointer {
            pointee: Box::new(HeaderType::Function {
                return_type: Box::new(cpp_type(result)?),
                parameters: params
                    .iter()
                    .enumerate()
                    .map(|(index, parameter)| {
                        Some(HeaderParameter {
                            name: Identifier::new(format!("arg{index}")).ok()?,
                            ty: cpp_type(parameter)?,
                        })
                    })
                    .collect::<Option<Vec<_>>>()?,
                parameter_state: ParameterState::Known,
                variadic: false,
                calling_convention: CallingConvention::C,
                qualifiers: HeaderFunctionQualifiers::default(),
            }),
            qualifiers: TypeQualifiers::default(),
        },
        CppType::TemplateInstance { .. } | CppType::Spelled { .. } | CppType::Unknown { .. } => {
            return None;
        }
    })
}

fn builtin_type(value: &str) -> Option<BuiltinType> {
    Some(match value.trim() {
        "void" => BuiltinType::Void,
        "bool" | "_Bool" => BuiltinType::Bool,
        "char" => BuiltinType::Char,
        "signed char" => BuiltinType::SignedChar,
        "unsigned char" => BuiltinType::UnsignedChar,
        "short" | "short int" | "signed short" | "signed short int" => BuiltinType::Short,
        "unsigned short" | "unsigned short int" => BuiltinType::UnsignedShort,
        "int" | "signed" | "signed int" => BuiltinType::Int,
        "unsigned" | "unsigned int" => BuiltinType::UnsignedInt,
        "long" | "long int" | "signed long" | "signed long int" => BuiltinType::Long,
        "unsigned long" | "unsigned long int" => BuiltinType::UnsignedLong,
        "long long" | "long long int" | "signed long long" | "signed long long int" => {
            BuiltinType::LongLong
        }
        "unsigned long long" | "unsigned long long int" => BuiltinType::UnsignedLongLong,
        "__int128" => BuiltinType::Int128,
        "unsigned __int128" => BuiltinType::UnsignedInt128,
        "float" => BuiltinType::Float,
        "double" => BuiltinType::Double,
        "long double" => BuiltinType::LongDouble,
        _ => return None,
    })
}

fn named_type(value: &str, tag: NamedTypeTag) -> Option<HeaderType> {
    Some(HeaderType::Named {
        tag,
        path: identifier_path(
            &value
                .trim_start_matches("::")
                .split("::")
                .map(str::to_owned)
                .collect::<Vec<_>>(),
        )?,
        template_arguments: Vec::new(),
    })
}

pub(super) fn identifier_path(values: &[String]) -> Option<NonEmpty<Identifier>> {
    NonEmpty::new(
        values
            .iter()
            .map(|value| Identifier::new(value.clone()).ok())
            .collect::<Option<Vec<_>>>()?,
    )
    .ok()
}

fn qualify_type(
    value: HeaderType,
    is_const: bool,
    is_volatile: bool,
    is_restrict: bool,
) -> HeaderType {
    match value {
        HeaderType::Pointer {
            pointee,
            mut qualifiers,
        } => {
            qualifiers.is_const |= is_const;
            qualifiers.is_volatile |= is_volatile;
            qualifiers.is_restrict |= is_restrict;
            HeaderType::Pointer {
                pointee,
                qualifiers,
            }
        }
        other => other,
    }
}

fn digest(seed: &str) -> String {
    sha256_hex(seed.as_bytes())
}

pub(super) fn evidence_id(seed: &str) -> EvidenceId {
    EvidenceId::new(digest(seed)).expect("SHA-256 evidence ID")
}

fn fact_id(seed: &str) -> FactId {
    FactId::new(digest(seed)).expect("SHA-256 fact ID")
}

pub(super) fn diagnostic_id(seed: &str) -> DiagnosticId {
    DiagnosticId::new(digest(seed)).expect("SHA-256 diagnostic ID")
}

pub(super) fn recovery_gap_id(seed: &str) -> RecoveryGapId {
    RecoveryGapId::new(digest(seed)).expect("SHA-256 recovery gap ID")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unavailable() -> Fact<String> {
        Fact::Unavailable {
            id: fact_id("fact"),
            reason: UnavailableReason::NotEncoded,
            evidence_ids: Vec::new(),
        }
    }

    #[test]
    fn stronger_evidence_replaces_a_weaker_disagreement() {
        let weak = evidence_id("weak");
        let strong = evidence_id("strong");
        let mut fact = unavailable();
        let mut gaps = Vec::new();
        reconcile_fact(
            &mut fact,
            "unknown".to_owned(),
            EvidenceStrength::Inferred,
            &weak,
            "entity",
            RecoveryField::Role,
            &mut gaps,
        );
        reconcile_fact(
            &mut fact,
            "method".to_owned(),
            EvidenceStrength::Correlated,
            &strong,
            "entity",
            RecoveryField::Role,
            &mut gaps,
        );
        assert!(matches!(
            fact,
            Fact::Known {
                value,
                strength: EvidenceStrength::Correlated,
                ..
            } if value == "method"
        ));
        assert!(gaps.is_empty());
    }

    #[test]
    fn equally_strong_disagreements_remain_conflicted() {
        let left = evidence_id("left");
        let right = evidence_id("right");
        let mut fact = unavailable();
        let mut gaps = Vec::new();
        for (value, evidence) in [("left", &left), ("right", &right)] {
            reconcile_fact(
                &mut fact,
                value.to_owned(),
                EvidenceStrength::Exact,
                evidence,
                "entity",
                RecoveryField::DisplayName,
                &mut gaps,
            );
        }
        assert!(matches!(fact, Fact::Conflicted { .. }));
        assert!(matches!(
            gaps.as_slice(),
            [RecoveryGap {
                reason: RecoveryGapReason::Conflicted { .. },
                ..
            }]
        ));
    }

    #[test]
    fn stronger_evidence_can_resolve_a_weaker_conflict() {
        let left = evidence_id("left");
        let right = evidence_id("right");
        let exact = evidence_id("exact");
        let mut fact = unavailable();
        let mut gaps = Vec::new();
        for (value, evidence) in [("left", &left), ("right", &right)] {
            reconcile_fact(
                &mut fact,
                value.to_owned(),
                EvidenceStrength::Correlated,
                evidence,
                "entity",
                RecoveryField::Owner,
                &mut gaps,
            );
        }
        reconcile_fact(
            &mut fact,
            "exact".to_owned(),
            EvidenceStrength::Exact,
            &exact,
            "entity",
            RecoveryField::Owner,
            &mut gaps,
        );
        assert!(matches!(
            fact,
            Fact::Known {
                value,
                strength: EvidenceStrength::Exact,
                ..
            } if value == "exact"
        ));
        assert!(gaps.is_empty());
    }
}
