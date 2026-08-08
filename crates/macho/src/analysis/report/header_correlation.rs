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
    owner: Option<HeaderOwnerRef>,
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
    let expected = entity_declaration_name(entity, language)?;
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
    owner: Option<HeaderOwnerRef>,
}

fn find_function<'a>(
    declaration: &'a syntax::Decl,
    expected: &DeclarationName,
    owner: Option<HeaderOwnerRef>,
) -> Option<FunctionMatch<'a>> {
    match declaration {
        syntax::Decl::AccessSection {
            access,
            declarations,
        } => declarations.iter().find_map(|declaration| {
            let mut owner = owner.clone()?;
            owner.member_access = Some(wire_access(*access));
            find_function(declaration, expected, Some(owner))
        }),
        syntax::Decl::Function {
            name,
            signature,
            storage,
            linkage,
        } if name.as_str() == expected.leaf && owner_path(&owner) == expected.owner => {
            Some(FunctionMatch {
                name,
                signature,
                storage: *storage,
                linkage: *linkage,
                owner: owner.clone(),
            })
        }
        syntax::Decl::Namespace { path, declarations } => {
            let owner = nested_owner(owner.as_ref(), HeaderOwnerKind::Namespace, path)?;
            declarations
                .iter()
                .find_map(|declaration| find_function(declaration, expected, Some(owner.clone())))
        }
        syntax::Decl::Record {
            kind,
            path,
            members,
            ..
        } => {
            let owner = nested_owner(owner.as_ref(), owner_kind(*kind)?, path)?;
            members
                .iter()
                .find_map(|member| find_function(member, expected, Some(owner.clone())))
        }
        _ => None,
    }
}

struct VariableMatch<'a> {
    name: &'a syntax::Identifier,
    ty: &'a syntax::Type,
    storage: syntax::StorageClass,
    linkage: syntax::Linkage,
    owner: Option<HeaderOwnerRef>,
}

fn find_variable<'a>(
    declaration: &'a syntax::Decl,
    expected: &DeclarationName,
    owner: Option<HeaderOwnerRef>,
) -> Option<VariableMatch<'a>> {
    match declaration {
        syntax::Decl::AccessSection {
            access,
            declarations,
        } => declarations.iter().find_map(|declaration| {
            let mut owner = owner.clone()?;
            owner.member_access = Some(wire_access(*access));
            find_variable(declaration, expected, Some(owner))
        }),
        syntax::Decl::Variable {
            name,
            ty,
            storage,
            linkage,
        } if name.as_str() == expected.leaf && owner_path(&owner) == expected.owner => {
            Some(VariableMatch {
                name,
                ty,
                storage: *storage,
                linkage: *linkage,
                owner: owner.clone(),
            })
        }
        syntax::Decl::Namespace { path, declarations } => {
            let owner = nested_owner(owner.as_ref(), HeaderOwnerKind::Namespace, path)?;
            declarations
                .iter()
                .find_map(|declaration| find_variable(declaration, expected, Some(owner.clone())))
        }
        syntax::Decl::Record {
            kind,
            path,
            members,
            ..
        } => {
            let owner = nested_owner(owner.as_ref(), owner_kind(*kind)?, path)?;
            members
                .iter()
                .find_map(|member| find_variable(member, expected, Some(owner.clone())))
        }
        _ => None,
    }
}

fn nested_owner(
    parent: Option<&HeaderOwnerRef>,
    kind: HeaderOwnerKind,
    path: &syntax::IdentifierPath,
) -> Option<HeaderOwnerRef> {
    // A qualified namespace definition proves every path component is a
    // namespace. A qualified record definition proves only its terminal kind;
    // the syntax tree intentionally does not guess whether preceding scopes
    // are namespaces or records, so it cannot provide an exact owner here.
    if kind != HeaderOwnerKind::Namespace && path.components().len() != 1 {
        return None;
    }
    let mut components = parent
        .map(|owner| owner.path.as_slice().to_vec())
        .unwrap_or_default();
    components.extend(
        path.components()
            .iter()
            .map(|component| Identifier::new(component.as_str().to_owned()).ok())
            .collect::<Option<Vec<_>>>()?,
    );
    let mut scope_kinds = parent
        .map(|owner| owner.scope_kinds.as_slice().to_vec())
        .unwrap_or_default();
    scope_kinds.extend(std::iter::repeat_n(kind, path.components().len()));
    let mut scope_access = parent
        .map(|owner| owner.scope_access.as_slice().to_vec())
        .unwrap_or_default();
    let first_access = parent.and_then(|owner| owner.member_access);
    scope_access.extend((0..path.components().len()).map(|index| {
        (index == 0 && kind != HeaderOwnerKind::Namespace)
            .then_some(first_access)
            .flatten()
    }));
    Some(HeaderOwnerRef {
        path: NonEmpty::new(components).ok()?,
        scope_kinds: NonEmpty::new(scope_kinds).ok()?,
        scope_access: NonEmpty::new(scope_access).ok()?,
        member_access: None,
        entity_id: None,
    })
}

fn wire_access(access: syntax::Access) -> Access {
    match access {
        syntax::Access::Public => Access::Public,
        syntax::Access::Protected => Access::Protected,
        syntax::Access::Private => Access::Private,
        syntax::Access::Unspecified => Access::Unspecified,
    }
}

struct DeclarationName {
    leaf: String,
    owner: Vec<String>,
}

fn entity_declaration_name(
    entity: &RecoveredEntity,
    language: RecoveryLanguage,
) -> Option<DeclarationName> {
    if language == RecoveryLanguage::Cpp
        && let Fact::Known { value, .. } = &entity.linkage
        && let Some(record) =
            crate::analysis::reconstruct::cpp::symbol::parse_symbol(&value.raw, None, None)
        && let crate::analysis::reconstruct::cpp::CppSymbolKind::Function { decl } = record.kind
    {
        let mut components = decl.name.components;
        let leaf = components.pop()?;
        return Some(DeclarationName {
            leaf,
            owner: components,
        });
    }
    match &entity.display_name {
        Fact::Known { value, .. } => {
            let head = value
                .split_once('(')
                .map_or(value.as_str(), |(head, _)| head);
            let mut components = head.split("::").map(str::to_owned).collect::<Vec<_>>();
            let leaf = components.pop()?.trim_start_matches('_').to_owned();
            Some(DeclarationName {
                leaf,
                owner: components,
            })
        }
        _ => None,
    }
}

fn owner_path(owner: &Option<HeaderOwnerRef>) -> Vec<String> {
    owner
        .as_ref()
        .map(|owner| {
            owner
                .path
                .as_slice()
                .iter()
                .map(|component| component.as_str().to_owned())
                .collect()
        })
        .unwrap_or_default()
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
    matched.owner.clone()
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
    correlate_parameters(
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
    correlate_qualifiers(
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
        let role = if owner.terminal_kind() == HeaderOwnerKind::Namespace {
            EntityRole::Function
        } else {
            EntityRole::CppMethod
        };
        correlate_owner(
            &mut entity.owner,
            EntityOwner {
                path: owner.path.into_vec(),
                scope_kinds: owner.scope_kinds.into_vec().into_iter().map(Some).collect(),
                scope_access: owner.scope_access.into_vec(),
                member_access: owner.member_access,
                entity_id: owner.entity_id,
            },
            &evidence_id,
        );
        correlate_role(&mut entity.role, role, &evidence_id);
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
        let role = if matched.storage == syntax::StorageClass::ThreadLocal {
            EntityRole::Tls
        } else if owner.terminal_kind() == HeaderOwnerKind::Namespace {
            EntityRole::Data
        } else {
            EntityRole::CppStaticData
        };
        correlate_owner(
            &mut entity.owner,
            EntityOwner {
                path: owner.path.into_vec(),
                scope_kinds: owner.scope_kinds.into_vec().into_iter().map(Some).collect(),
                scope_access: owner.scope_access.into_vec(),
                member_access: owner.member_access,
                entity_id: owner.entity_id,
            },
            &evidence_id,
        );
        correlate_role(&mut entity.role, role, &evidence_id);
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

fn correlate_owner(fact: &mut Fact<EntityOwner>, value: EntityOwner, evidence_id: &EvidenceId) {
    if let Fact::Known {
        value: existing,
        evidence_ids,
        strength,
        ..
    } = fact
        && existing.path == value.path
        && existing.scope_kinds.len() == value.scope_kinds.len()
        && existing
            .scope_kinds
            .iter()
            .zip(&value.scope_kinds)
            .all(|(left, right)| left.is_none() || right.is_none() || left == right)
        && existing.scope_access.len() == value.scope_access.len()
        && existing
            .scope_access
            .iter()
            .zip(&value.scope_access)
            .all(|(left, right)| left.is_none() || right.is_none() || left == right)
        && (existing.member_access.is_none()
            || value.member_access.is_none()
            || existing.member_access == value.member_access)
        && (existing.entity_id.is_none()
            || value.entity_id.is_none()
            || existing.entity_id == value.entity_id)
    {
        for (existing, correlated) in existing.scope_kinds.iter_mut().zip(value.scope_kinds) {
            if existing.is_none() {
                *existing = correlated;
            }
        }
        for (existing, correlated) in existing.scope_access.iter_mut().zip(value.scope_access) {
            if existing.is_none() {
                *existing = correlated;
            }
        }
        if existing.member_access.is_none() {
            existing.member_access = value.member_access;
        }
        if existing.entity_id.is_none() {
            existing.entity_id = value.entity_id;
        }
        *strength = EvidenceStrength::Correlated;
        if !evidence_ids.as_slice().contains(evidence_id) {
            evidence_ids.push(evidence_id.clone());
        }
        return;
    }
    correlate_fact(fact, value, evidence_id);
}

fn correlate_role(fact: &mut Fact<EntityRole>, value: EntityRole, evidence_id: &EvidenceId) {
    if let Fact::Known {
        value: existing,
        strength,
        evidence_ids,
        ..
    } = fact
        && matches!(
            (&*existing, &value),
            (EntityRole::Function, EntityRole::CppMethod)
                | (EntityRole::CppMethod, EntityRole::CppMethod)
                | (EntityRole::Data, EntityRole::CppStaticData)
                | (EntityRole::CppStaticData, EntityRole::CppStaticData)
        )
    {
        *existing = value;
        *strength = EvidenceStrength::Correlated;
        if !evidence_ids.as_slice().contains(evidence_id) {
            evidence_ids.push(evidence_id.clone());
        }
        return;
    }
    correlate_fact(fact, value, evidence_id);
}

fn correlate_parameters(
    fact: &mut Fact<ParameterList>,
    value: ParameterList,
    evidence_id: &EvidenceId,
) {
    let compatible = match (&*fact, &value) {
        (
            Fact::Known {
                value: ParameterList::Known { value: existing },
                ..
            },
            ParameterList::Known { value: correlated },
        ) => {
            existing.len() == correlated.len()
                && existing.iter().zip(correlated).all(|(left, right)| {
                    known_value(&left.type_evidence) == known_value(&right.type_evidence)
                })
        }
        _ => false,
    };

    if compatible {
        let Fact::Known {
            value: ParameterList::Known { value: existing },
            evidence_ids,
            ..
        } = fact
        else {
            unreachable!("compatible parameter lists are known")
        };
        let ParameterList::Known { value: correlated } = value else {
            unreachable!("compatible parameter lists are known")
        };
        for (existing, correlated) in existing.iter_mut().zip(correlated) {
            if let Fact::Known { value, .. } = correlated.type_evidence {
                correlate_fact(&mut existing.type_evidence, value, evidence_id);
            }
            if let Fact::Known { value, .. } = correlated.source_name {
                correlate_fact(&mut existing.source_name, value, evidence_id);
            }
        }
        if !evidence_ids.as_slice().contains(evidence_id) {
            evidence_ids.push(evidence_id.clone());
        }
        return;
    }

    correlate_fact(fact, value, evidence_id);
}

fn correlate_qualifiers(
    fact: &mut Fact<FunctionQualifiers>,
    value: FunctionQualifiers,
    evidence_id: &EvidenceId,
) {
    let compatible = match &*fact {
        Fact::Known {
            value: existing, ..
        } => {
            existing.is_const == value.is_const
                && existing.is_volatile == value.is_volatile
                && existing.reference == value.reference
                && (existing.noexcept == value.noexcept
                    || existing.noexcept.is_none()
                    || value.noexcept.is_none())
        }
        Fact::Unavailable { .. } | Fact::Conflicted { .. } => false,
    };

    if compatible {
        let Fact::Known {
            value: existing,
            evidence_ids,
            ..
        } = fact
        else {
            unreachable!("compatible qualifiers are known")
        };
        if existing.noexcept.is_none() {
            existing.noexcept = value.noexcept;
        }
        if !evidence_ids.as_slice().contains(evidence_id) {
            evidence_ids.push(evidence_id.clone());
        }
        return;
    }

    correlate_fact(fact, value, evidence_id);
}

fn known_value<T>(fact: &Fact<T>) -> Option<&T> {
    match fact {
        Fact::Known { value, .. } => Some(value),
        Fact::Unavailable { .. } | Fact::Conflicted { .. } => None,
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
        syntax::RecordKind::Class => Some(HeaderOwnerKind::Class),
        syntax::RecordKind::Struct => Some(HeaderOwnerKind::Record),
        syntax::RecordKind::Union | syntax::RecordKind::Enum => None,
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
    fn owner_typing_preserves_structs_and_rejects_ambiguous_qualified_records() {
        assert_eq!(
            owner_kind(syntax::RecordKind::Struct),
            Some(HeaderOwnerKind::Record)
        );
        assert_eq!(
            owner_kind(syntax::RecordKind::Class),
            Some(HeaderOwnerKind::Class)
        );
        assert_eq!(owner_kind(syntax::RecordKind::Union), None);

        let qualified = syntax::IdentifierPath::new(vec![
            syntax::Identifier::new("Outer").unwrap(),
            syntax::Identifier::new("Inner").unwrap(),
        ])
        .unwrap();
        assert!(nested_owner(None, HeaderOwnerKind::Class, &qualified).is_none());

        let namespaces = nested_owner(None, HeaderOwnerKind::Namespace, &qualified).unwrap();
        assert_eq!(
            namespaces.scope_kinds.as_slice(),
            &[HeaderOwnerKind::Namespace, HeaderOwnerKind::Namespace]
        );
    }

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
