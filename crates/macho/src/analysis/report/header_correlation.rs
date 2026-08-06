//! Typed external-header correlation for C and C++ recovery.

#![allow(missing_docs)]

use std::collections::BTreeSet;

use crate::analysis::header_syntax as syntax;

use super::*;

#[derive(Debug, Clone)]
pub struct HeaderCorrelationInput {
    pub root_label: LogicalInputLabel,
    pub relative_path: String,
    pub content_sha256: ContentHash,
    pub span: syntax::SourceSpan,
    pub declaration: syntax::Decl,
}

/// Executes typed external-header correlation for the selected recovery entities.
///
/// Inputs have already been parsed by `crate::analysis::header_syntax`; textual identifier
/// occurrences never enter this path. Only one unambiguous typed declaration
/// may contribute correlated facts to an entity.
pub fn execute_header_correlation(
    report: &mut RecoveryReport,
    roots: Vec<HashedHeaderRoot>,
    declarations: &[HeaderCorrelationInput],
) -> crate::analysis::Result<()> {
    report.request.header_roots = roots.clone();
    let limits = report.request.limits;
    for slice in report.slices.as_mut_slice() {
        slice.inputs.header_roots = roots.clone();
        let targets = slice.resolved_plan.selected_entity_ids.clone();
        if targets.is_empty() {
            continue;
        }
        slice.resolved_plan.targeted.push(ResolvedCollectorSpec {
            collector: CollectorId::HeaderCorrelation,
            target_entity_ids: targets.clone(),
            required: false,
            limits: CollectorLimits {
                max_records: limits.max_header_files,
                max_bytes: limits.max_header_bytes,
                max_diagnostics: limits.max_diagnostics,
            },
        });
        let target_set = targets
            .iter()
            .map(EntityId::as_str)
            .collect::<BTreeSet<_>>();
        let mut outputs = 0u64;
        for entity in &mut slice.entities {
            if !target_set.contains(entity.id.as_str()) {
                continue;
            }
            let candidates = declarations
                .iter()
                .filter_map(|input| match_declaration(entity, report.language, input))
                .collect::<Vec<_>>();
            if candidates.len() != 1 {
                continue;
            }
            apply_match(entity, &candidates[0]);
            outputs += 1;
        }
        let execution = CollectorExecution {
            collector: CollectorId::HeaderCorrelation,
            request_digest: slice.resolved_plan.request_digest.clone(),
            target_entity_ids: targets.clone(),
            outcome: CollectorOutcome::Complete,
            counts: CollectorCounts {
                input_records: declarations.len() as u64,
                output_records: outputs,
                selected_targets: targets.len() as u64,
            },
        };
        let mut executions = slice.executions.clone().into_vec();
        executions.push(execution);
        slice.executions = NonEmpty::new(executions).expect("execution ledger remains non-empty");
    }
    Ok(())
}

struct DeclarationMatch<'a> {
    input: &'a HeaderCorrelationInput,
    name: &'a syntax::Identifier,
    ty: &'a syntax::Type,
    storage: syntax::StorageClass,
    linkage: syntax::Linkage,
    owner: Option<(&'a syntax::IdentifierPath, syntax::RecordKind)>,
    kind: DeclarationMatchKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeclarationMatchKind {
    Function,
    Variable,
}

fn match_declaration<'a>(
    entity: &RecoveredEntity,
    language: RecoveryLanguage,
    input: &'a HeaderCorrelationInput,
) -> Option<DeclarationMatch<'a>> {
    let expected = entity_terminal_name(entity, language)?;
    match &entity.role {
        Fact::Known {
            value: EntityRole::Data | EntityRole::Tls | EntityRole::CppStaticData,
            ..
        } => find_variable(&input.declaration, &expected, None).and_then(|matched| {
            let storage_matches = match &entity.role {
                Fact::Known {
                    value: EntityRole::Tls,
                    ..
                } => matched.storage == syntax::StorageClass::ThreadLocal,
                _ => matched.storage != syntax::StorageClass::ThreadLocal,
            };
            storage_matches.then_some(DeclarationMatch {
                input,
                name: matched.name,
                ty: matched.ty,
                storage: matched.storage,
                linkage: matched.linkage,
                owner: matched.owner,
                kind: DeclarationMatchKind::Variable,
            })
        }),
        Fact::Known {
            value:
                EntityRole::RuntimeArtifact
                | EntityRole::Type
                | EntityRole::Typeinfo
                | EntityRole::Vtable
                | EntityRole::Vtt
                | EntityRole::Guard,
            ..
        } => None,
        _ => find_function(&input.declaration, &expected, None).map(|matched| DeclarationMatch {
            input,
            name: matched.name,
            ty: matched.signature,
            storage: matched.storage,
            linkage: matched.linkage,
            owner: matched.owner,
            kind: DeclarationMatchKind::Function,
        }),
    }
}

struct FunctionMatch<'a> {
    name: &'a syntax::Identifier,
    signature: &'a syntax::Type,
    storage: syntax::StorageClass,
    linkage: syntax::Linkage,
    owner: Option<(&'a syntax::IdentifierPath, syntax::RecordKind)>,
}

fn find_function<'a>(
    declaration: &'a syntax::Decl,
    expected: &str,
    owner: Option<(&'a syntax::IdentifierPath, syntax::RecordKind)>,
) -> Option<FunctionMatch<'a>> {
    match declaration {
        syntax::Decl::Function {
            name,
            signature,
            storage,
            linkage,
        } if name.as_str() == expected => Some(FunctionMatch {
            name,
            signature,
            storage: *storage,
            linkage: *linkage,
            owner,
        }),
        syntax::Decl::Record {
            kind,
            path,
            members,
            ..
        } => members
            .iter()
            .find_map(|member| find_function(member, expected, Some((path, *kind)))),
        _ => None,
    }
}

struct VariableMatch<'a> {
    name: &'a syntax::Identifier,
    ty: &'a syntax::Type,
    storage: syntax::StorageClass,
    linkage: syntax::Linkage,
    owner: Option<(&'a syntax::IdentifierPath, syntax::RecordKind)>,
}

fn find_variable<'a>(
    declaration: &'a syntax::Decl,
    expected: &str,
    owner: Option<(&'a syntax::IdentifierPath, syntax::RecordKind)>,
) -> Option<VariableMatch<'a>> {
    match declaration {
        syntax::Decl::Variable {
            name,
            ty,
            storage,
            linkage,
        } if name.as_str() == expected => Some(VariableMatch {
            name,
            ty,
            storage: *storage,
            linkage: *linkage,
            owner,
        }),
        syntax::Decl::Record {
            kind,
            path,
            members,
            ..
        } => members
            .iter()
            .find_map(|member| find_variable(member, expected, Some((path, *kind)))),
        _ => None,
    }
}

fn entity_terminal_name(entity: &RecoveredEntity, language: RecoveryLanguage) -> Option<String> {
    if language == RecoveryLanguage::Cpp
        && let Fact::Known { value, .. } = &entity.linkage
        && let Some(record) =
            crate::analysis::reconstruct::cpp::symbol::parse_symbol(&value.raw, None, None)
        && let crate::analysis::reconstruct::cpp::CppSymbolKind::Function { decl } = record.kind
    {
        return decl.name.leaf().map(str::to_owned);
    }
    match &entity.display_name {
        Fact::Known { value, .. } => Some(
            value
                .split_once('(')
                .map_or(value.as_str(), |(head, _)| head)
                .rsplit("::")
                .next()
                .unwrap_or(value)
                .trim_start_matches('_')
                .to_owned(),
        ),
        _ => None,
    }
}

fn apply_match(entity: &mut RecoveredEntity, matched: &DeclarationMatch<'_>) {
    let Some(ty) = wire_type(matched.ty) else {
        return;
    };
    match matched.kind {
        DeclarationMatchKind::Function => apply_function_match(entity, matched, ty),
        DeclarationMatchKind::Variable => apply_variable_match(entity, matched, ty),
    }
}

fn match_evidence_id(entity: &RecoveredEntity, matched: &DeclarationMatch<'_>) -> EvidenceId {
    EvidenceId::new(sha256_hex(
        format!(
            "header|{}|{}|{}|{}|{}",
            matched.input.root_label.as_str(),
            matched.input.relative_path,
            matched.input.span.start,
            matched.input.span.end,
            entity.id
        )
        .as_bytes(),
    ))
    .expect("SHA-256 evidence ID")
}

fn matched_owner(matched: &DeclarationMatch<'_>) -> Option<HeaderOwnerRef> {
    matched.owner.and_then(|(path, kind)| {
        Some(HeaderOwnerRef {
            kind: owner_kind(kind)?,
            path: wire_path(path)?,
            entity_id: None,
        })
    })
}

fn apply_function_match(
    entity: &mut RecoveredEntity,
    matched: &DeclarationMatch<'_>,
    signature: HeaderType,
) {
    let HeaderType::Function {
        return_type,
        parameters,
        parameter_state,
        variadic,
        calling_convention,
        qualifiers,
    } = signature.clone()
    else {
        return;
    };
    let evidence_id = match_evidence_id(entity, matched);
    let owner = matched_owner(matched);
    entity.evidence.push(EvidenceRecord {
        id: evidence_id.clone(),
        collector: CollectorId::HeaderCorrelation,
        observation_ids: entity.observation_ids.as_slice().to_vec(),
        strength: EvidenceStrength::Correlated,
        payload: EvidencePayload::Header {
            value: HeaderCorrelationEvidence {
                root_label: matched.input.root_label.clone(),
                relative_path: matched.input.relative_path.clone(),
                content_sha256: matched.input.content_sha256.clone(),
                start_byte: matched.input.span.start as u64,
                end_byte: matched.input.span.end as u64,
                declaration: HeaderDecl::Function {
                    id: entity.id.clone(),
                    owner: owner.clone(),
                    name: Identifier::new(matched.name.as_str().to_owned())
                        .expect("syntax identifier satisfies wire identifier rules"),
                    signature,
                    storage: storage(matched.storage),
                    linkage: linkage(matched.linkage),
                },
            },
        },
    });
    correlate_fact(
        &mut entity.signature.return_type,
        TypeEvidence::Source { ty: *return_type },
        &evidence_id,
    );
    let recovered_parameters = match parameter_state {
        ParameterState::Unspecified => ParameterList::Unspecified,
        ParameterState::Known => ParameterList::Known {
            value: parameters
                .into_iter()
                .enumerate()
                .map(|(index, parameter)| RecoveredParameter {
                    type_evidence: correlated_fact(
                        &format!("{}|header_parameter|{index}|type", entity.id),
                        TypeEvidence::Source { ty: parameter.ty },
                        &evidence_id,
                    ),
                    source_name: correlated_fact(
                        &format!("{}|header_parameter|{index}|name", entity.id),
                        parameter.name.as_str().to_owned(),
                        &evidence_id,
                    ),
                })
                .collect(),
        },
    };
    correlate_fact(
        &mut entity.signature.parameters,
        recovered_parameters,
        &evidence_id,
    );
    correlate_fact(&mut entity.signature.variadic, variadic, &evidence_id);
    correlate_fact(
        &mut entity.signature.calling_convention,
        calling_convention,
        &evidence_id,
    );
    correlate_fact(
        &mut entity.signature.qualifiers,
        FunctionQualifiers {
            is_const: Some(qualifiers.is_const),
            is_volatile: Some(qualifiers.is_volatile),
            reference: qualifiers.reference,
            noexcept: qualifiers.noexcept,
        },
        &evidence_id,
    );
    if let Some(owner) = owner {
        correlate_fact(
            &mut entity.owner,
            EntityOwner {
                kind: Some(owner.kind),
                path: owner.path.into_vec(),
                entity_id: owner.entity_id,
            },
            &evidence_id,
        );
        correlate_fact(&mut entity.role, EntityRole::CppMethod, &evidence_id);
    } else {
        correlate_fact(&mut entity.role, EntityRole::Function, &evidence_id);
    }
    refresh_gap(
        &mut entity.gaps,
        RecoveryField::ReturnType,
        &entity.signature.return_type,
    );
    refresh_gap(
        &mut entity.gaps,
        RecoveryField::Parameters,
        &entity.signature.parameters,
    );
    refresh_gap(
        &mut entity.gaps,
        RecoveryField::Variadic,
        &entity.signature.variadic,
    );
    refresh_gap(
        &mut entity.gaps,
        RecoveryField::CallingConvention,
        &entity.signature.calling_convention,
    );
    refresh_gap(
        &mut entity.gaps,
        RecoveryField::Qualifiers,
        &entity.signature.qualifiers,
    );
    refresh_gap(&mut entity.gaps, RecoveryField::Owner, &entity.owner);
    refresh_gap(&mut entity.gaps, RecoveryField::Role, &entity.role);
}

fn apply_variable_match(
    entity: &mut RecoveredEntity,
    matched: &DeclarationMatch<'_>,
    ty: HeaderType,
) {
    if matches!(ty, HeaderType::Function { .. }) {
        return;
    }
    let evidence_id = match_evidence_id(entity, matched);
    let owner = matched_owner(matched);
    entity.evidence.push(EvidenceRecord {
        id: evidence_id.clone(),
        collector: CollectorId::HeaderCorrelation,
        observation_ids: entity.observation_ids.as_slice().to_vec(),
        strength: EvidenceStrength::Correlated,
        payload: EvidencePayload::Header {
            value: HeaderCorrelationEvidence {
                root_label: matched.input.root_label.clone(),
                relative_path: matched.input.relative_path.clone(),
                content_sha256: matched.input.content_sha256.clone(),
                start_byte: matched.input.span.start as u64,
                end_byte: matched.input.span.end as u64,
                declaration: HeaderDecl::Variable {
                    id: entity.id.clone(),
                    owner: owner.clone(),
                    name: Identifier::new(matched.name.as_str().to_owned())
                        .expect("syntax identifier satisfies wire identifier rules"),
                    ty: ty.clone(),
                    storage: storage(matched.storage),
                    linkage: linkage(matched.linkage),
                },
            },
        },
    });
    correlate_fact(
        &mut entity.value_type,
        TypeEvidence::Source { ty },
        &evidence_id,
    );
    if let Some(owner) = owner {
        correlate_fact(
            &mut entity.owner,
            EntityOwner {
                kind: Some(owner.kind),
                path: owner.path.into_vec(),
                entity_id: owner.entity_id,
            },
            &evidence_id,
        );
        correlate_fact(&mut entity.role, EntityRole::CppStaticData, &evidence_id);
    } else if matched.storage == syntax::StorageClass::ThreadLocal {
        correlate_fact(&mut entity.role, EntityRole::Tls, &evidence_id);
    } else {
        correlate_fact(&mut entity.role, EntityRole::Data, &evidence_id);
    }
    refresh_gap(
        &mut entity.gaps,
        RecoveryField::ValueType,
        &entity.value_type,
    );
    refresh_gap(&mut entity.gaps, RecoveryField::Owner, &entity.owner);
    refresh_gap(&mut entity.gaps, RecoveryField::Role, &entity.role);
}

fn correlated_fact<T>(seed: &str, value: T, evidence_id: &EvidenceId) -> Fact<T> {
    Fact::Known {
        id: FactId::new(sha256_hex(seed.as_bytes())).expect("SHA-256 fact ID"),
        value,
        strength: EvidenceStrength::Correlated,
        evidence_ids: NonEmpty::new(vec![evidence_id.clone()]).expect("one evidence ID"),
    }
}

fn correlate_fact<T: Clone + PartialEq>(fact: &mut Fact<T>, value: T, evidence_id: &EvidenceId) {
    match fact.clone() {
        Fact::Unavailable { id, .. } => {
            *fact = Fact::Known {
                id,
                value,
                strength: EvidenceStrength::Correlated,
                evidence_ids: NonEmpty::new(vec![evidence_id.clone()]).expect("one evidence ID"),
            };
        }
        Fact::Known {
            id,
            value: existing,
            strength,
            mut evidence_ids,
        } if existing == value => {
            if !evidence_ids.as_slice().contains(evidence_id) {
                evidence_ids.push(evidence_id.clone());
            }
            *fact = Fact::Known {
                id,
                value: existing,
                strength,
                evidence_ids,
            };
        }
        Fact::Known {
            id,
            value: _,
            strength: EvidenceStrength::Inferred,
            evidence_ids: _,
        } => {
            *fact = Fact::Known {
                id,
                value,
                strength: EvidenceStrength::Correlated,
                evidence_ids: NonEmpty::new(vec![evidence_id.clone()]).expect("one evidence ID"),
            };
        }
        Fact::Known {
            id,
            value: existing,
            strength,
            evidence_ids,
        } => {
            *fact = Fact::Conflicted {
                id,
                candidates: AtLeastTwo::new(vec![
                    FactCandidate {
                        value: existing,
                        strength,
                        evidence_ids,
                    },
                    FactCandidate {
                        value,
                        strength: EvidenceStrength::Correlated,
                        evidence_ids: NonEmpty::new(vec![evidence_id.clone()])
                            .expect("one evidence ID"),
                    },
                ])
                .expect("different fact values form a conflict"),
            };
        }
        Fact::Conflicted { .. } => {}
    }
}

fn refresh_gap<T>(gaps: &mut Vec<RecoveryGap>, field: RecoveryField, fact: &Fact<T>) {
    match fact {
        Fact::Known { .. } => gaps.retain(|gap| gap.field != field),
        Fact::Conflicted { id, .. } => {
            if let Some(gap) = gaps.iter_mut().find(|gap| gap.field == field) {
                gap.reason = RecoveryGapReason::Conflicted {
                    fact_id: id.clone(),
                };
            }
        }
        Fact::Unavailable { .. } => {}
    }
}

fn wire_type(value: &syntax::Type) -> Option<HeaderType> {
    Some(match value {
        syntax::Type::Builtin(value) => HeaderType::Builtin {
            name: builtin(*value),
        },
        syntax::Type::Named {
            tag,
            path,
            template_arguments,
        } => HeaderType::Named {
            tag: named_tag(*tag),
            path: wire_path(path)?,
            template_arguments: template_arguments
                .iter()
                .map(wire_template_argument)
                .collect::<Option<Vec<_>>>()?,
        },
        syntax::Type::Pointer {
            pointee,
            qualifiers,
        } => HeaderType::Pointer {
            pointee: Box::new(wire_type(pointee)?),
            qualifiers: type_qualifiers(*qualifiers),
        },
        syntax::Type::Reference { target, kind } => HeaderType::Reference {
            target: Box::new(wire_type(target)?),
            reference: reference(*kind),
        },
        syntax::Type::Array { element, count } => HeaderType::Array {
            element: Box::new(wire_type(element)?),
            count: *count,
        },
        syntax::Type::Function {
            return_type,
            parameters,
            parameter_state,
            variadic,
            calling_convention,
            qualifiers,
        } => HeaderType::Function {
            return_type: Box::new(wire_type(return_type)?),
            parameters: parameters
                .iter()
                .map(|parameter| {
                    Some(HeaderParameter {
                        name: Identifier::new(parameter.name.as_str().to_owned()).ok()?,
                        ty: wire_type(&parameter.ty)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            parameter_state: parameter_state_wire(*parameter_state),
            variadic: *variadic,
            calling_convention: calling_convention_wire(*calling_convention),
            qualifiers: HeaderFunctionQualifiers {
                is_const: qualifiers.is_const,
                is_volatile: qualifiers.is_volatile,
                reference: qualifiers.reference.map(reference),
                noexcept: qualifiers.noexcept,
            },
        },
        syntax::Type::ObjectiveCObject { .. } | syntax::Type::ObjectiveCBlock(_) => return None,
    })
}

fn wire_template_argument(value: &syntax::TemplateArgument) -> Option<HeaderTemplateArgument> {
    Some(match value {
        syntax::TemplateArgument::Type(value) => HeaderTemplateArgument::Type {
            value: wire_type(value)?,
        },
        syntax::TemplateArgument::Integer(value) => {
            HeaderTemplateArgument::Integer { value: *value }
        }
        syntax::TemplateArgument::Identifier(path) => HeaderTemplateArgument::Identifier {
            path: wire_path(path)?,
        },
    })
}

fn wire_path(path: &syntax::IdentifierPath) -> Option<NonEmpty<Identifier>> {
    NonEmpty::new(
        path.components()
            .iter()
            .map(|item| Identifier::new(item.as_str().to_owned()).ok())
            .collect::<Option<Vec<_>>>()?,
    )
    .ok()
}

fn builtin(value: syntax::BuiltinType) -> BuiltinType {
    match value {
        syntax::BuiltinType::Void => BuiltinType::Void,
        syntax::BuiltinType::Bool => BuiltinType::Bool,
        syntax::BuiltinType::Char => BuiltinType::Char,
        syntax::BuiltinType::SignedChar => BuiltinType::SignedChar,
        syntax::BuiltinType::UnsignedChar => BuiltinType::UnsignedChar,
        syntax::BuiltinType::Short => BuiltinType::Short,
        syntax::BuiltinType::UnsignedShort => BuiltinType::UnsignedShort,
        syntax::BuiltinType::Int => BuiltinType::Int,
        syntax::BuiltinType::UnsignedInt => BuiltinType::UnsignedInt,
        syntax::BuiltinType::Long => BuiltinType::Long,
        syntax::BuiltinType::UnsignedLong => BuiltinType::UnsignedLong,
        syntax::BuiltinType::LongLong => BuiltinType::LongLong,
        syntax::BuiltinType::UnsignedLongLong => BuiltinType::UnsignedLongLong,
        syntax::BuiltinType::Int128 => BuiltinType::Int128,
        syntax::BuiltinType::UnsignedInt128 => BuiltinType::UnsignedInt128,
        syntax::BuiltinType::Float => BuiltinType::Float,
        syntax::BuiltinType::Double => BuiltinType::Double,
        syntax::BuiltinType::LongDouble => BuiltinType::LongDouble,
    }
}

fn named_tag(value: syntax::NamedTypeTag) -> NamedTypeTag {
    match value {
        syntax::NamedTypeTag::Typedef => NamedTypeTag::Typedef,
        syntax::NamedTypeTag::Struct => NamedTypeTag::Struct,
        syntax::NamedTypeTag::Union => NamedTypeTag::Union,
        syntax::NamedTypeTag::Enum => NamedTypeTag::Enum,
        syntax::NamedTypeTag::Class => NamedTypeTag::Class,
        syntax::NamedTypeTag::Protocol => NamedTypeTag::Protocol,
    }
}

fn type_qualifiers(value: syntax::TypeQualifiers) -> TypeQualifiers {
    TypeQualifiers {
        is_const: value.is_const,
        is_volatile: value.is_volatile,
        is_restrict: value.is_restrict,
    }
}

fn reference(value: syntax::ReferenceKind) -> ReferenceKind {
    match value {
        syntax::ReferenceKind::Lvalue => ReferenceKind::Lvalue,
        syntax::ReferenceKind::Rvalue => ReferenceKind::Rvalue,
    }
}

fn parameter_state_wire(value: syntax::ParameterState) -> ParameterState {
    match value {
        syntax::ParameterState::Unspecified => ParameterState::Unspecified,
        syntax::ParameterState::Known => ParameterState::Known,
    }
}

fn calling_convention_wire(value: syntax::CallingConvention) -> CallingConvention {
    match value {
        syntax::CallingConvention::C => CallingConvention::C,
        syntax::CallingConvention::Swift => CallingConvention::Swift,
        syntax::CallingConvention::ObjectiveCMethod => CallingConvention::ObjcMethod,
        syntax::CallingConvention::Thiscall => CallingConvention::Thiscall,
        syntax::CallingConvention::Vectorcall => CallingConvention::Vectorcall,
        syntax::CallingConvention::Aapcs => CallingConvention::Aapcs,
        syntax::CallingConvention::AapcsVfp => CallingConvention::AapcsVfp,
        syntax::CallingConvention::Unknown => CallingConvention::Unknown,
    }
}

fn owner_kind(value: syntax::RecordKind) -> Option<HeaderOwnerKind> {
    match value {
        syntax::RecordKind::Class | syntax::RecordKind::Struct | syntax::RecordKind::Union => {
            Some(HeaderOwnerKind::Class)
        }
        syntax::RecordKind::Enum => None,
    }
}

fn storage(value: syntax::StorageClass) -> StorageClass {
    match value {
        syntax::StorageClass::None => StorageClass::None,
        syntax::StorageClass::Extern => StorageClass::Extern,
        syntax::StorageClass::Static => StorageClass::Static,
        syntax::StorageClass::ThreadLocal => StorageClass::ThreadLocal,
    }
}

fn linkage(value: syntax::Linkage) -> HeaderLinkage {
    match value {
        syntax::Linkage::C => HeaderLinkage::C,
        syntax::Linkage::Cpp => HeaderLinkage::Cpp,
        syntax::Linkage::ObjectiveC => HeaderLinkage::Objc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_variable_correlation_populates_value_type_not_return_type() {
        let bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
            macho_test_support::SymbolFixture {
                name: "_global_count",
                external: true,
                defined: true,
            },
        ]);
        let container = crate::core::parse(&bytes).unwrap();
        let mut report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::CAbi)
                .unwrap();
        let root_label = LogicalInputLabel::new("headers").unwrap();
        let content_hash = ContentHash::new("a".repeat(64)).unwrap();
        execute_header_correlation(
            &mut report,
            vec![HashedHeaderRoot {
                logical_label: root_label.clone(),
                content_hash: content_hash.clone(),
                files: vec![HashedHeaderFile {
                    relative_path: "globals.h".to_owned(),
                    content_sha256: content_hash.clone(),
                    byte_len: 24,
                }],
            }],
            &[HeaderCorrelationInput {
                root_label,
                relative_path: "globals.h".to_owned(),
                content_sha256: content_hash,
                span: syntax::SourceSpan {
                    start: 0,
                    end: 24,
                    line: 1,
                    column: 1,
                },
                declaration: syntax::Decl::Variable {
                    name: syntax::Identifier::new("global_count").unwrap(),
                    ty: syntax::Type::Builtin(syntax::BuiltinType::UnsignedLong),
                    storage: syntax::StorageClass::Extern,
                    linkage: syntax::Linkage::C,
                },
            }],
        )
        .unwrap();
        report.refresh_request_digest().unwrap();
        let entity = &report.slices.as_slice()[0].entities[0];
        assert!(matches!(
            entity.value_type,
            Fact::Known {
                value: TypeEvidence::Source {
                    ty: HeaderType::Builtin {
                        name: BuiltinType::UnsignedLong
                    }
                },
                strength: EvidenceStrength::Correlated,
                ..
            }
        ));
        assert!(matches!(
            entity.signature.return_type,
            Fact::Unavailable { .. }
        ));
        assert!(
            !entity
                .gaps
                .iter()
                .any(|gap| gap.field == RecoveryField::ValueType)
        );
        report.validate().unwrap();
    }
}
