use crate::analysis::report::{Presence, RecoveryLanguage};
use crate::header_syntax as syntax;

use super::{EntityKind, entity_address, entity_kind, entity_name, entity_presence};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ProjectionBlocker {
    pub field: crate::analysis::report::RecoveryField,
    pub reason: crate::analysis::report::HeaderIneligibilityReason,
}

type ProjectionResult =
    Result<(crate::analysis::report::HeaderDecl, syntax::Decl), ProjectionBlocker>;

fn blocked(
    field: crate::analysis::report::RecoveryField,
    reason: crate::analysis::report::HeaderIneligibilityReason,
) -> ProjectionBlocker {
    ProjectionBlocker { field, reason }
}

pub(super) fn project_entity_with_owner(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
    owner_override: Option<&crate::analysis::report::HeaderOwnerRef>,
) -> ProjectionResult {
    use crate::analysis::report::{
        CallingConvention, Fact, HeaderDecl, HeaderFunctionQualifiers, HeaderIneligibilityReason,
        HeaderLinkage, HeaderParameter, HeaderType, ParameterList, ParameterState, RecoveryField,
        ReferenceKind, StorageClass, TypeEvidence,
    };

    if entity_presence(entity) != Presence::Defined {
        return Err(blocked(
            RecoveryField::Presence,
            HeaderIneligibilityReason::UnavailableRequiredFact,
        ));
    }
    match entity_kind(entity) {
        Some(EntityKind::Data | EntityKind::Tls) => {
            return project_variable(entity, language, owner_override);
        }
        Some(EntityKind::Type) => return project_type(entity, language, owner_override),
        Some(EntityKind::Function | EntityKind::Method) => {}
        _ => {
            return Err(blocked(
                RecoveryField::Role,
                HeaderIneligibilityReason::UnsupportedType,
            ));
        }
    }
    let (name, owner) = match language {
        RecoveryLanguage::CAbi => (
            crate::analysis::report::Identifier::new(entity_name(entity)).map_err(|_| {
                blocked(
                    RecoveryField::DisplayName,
                    HeaderIneligibilityReason::InvalidLinkage,
                )
            })?,
            None,
        ),
        RecoveryLanguage::Cpp => {
            let raw = match &entity.linkage {
                Fact::Known { value, .. } => &value.raw,
                Fact::Conflicted { .. } => {
                    return Err(blocked(
                        RecoveryField::Linkage,
                        HeaderIneligibilityReason::ConflictedRequiredFact,
                    ));
                }
                Fact::Unavailable { .. } => {
                    return Err(blocked(
                        RecoveryField::Linkage,
                        HeaderIneligibilityReason::UnavailableRequiredFact,
                    ));
                }
            };
            let record = crate::analysis::reconstruct::cpp::symbol::parse_symbol(
                raw,
                entity_address(entity),
                None,
            )
            .ok_or_else(|| {
                blocked(
                    RecoveryField::Linkage,
                    HeaderIneligibilityReason::InvalidLinkage,
                )
            })?;
            let crate::analysis::reconstruct::cpp::CppSymbolKind::Function { decl } = record.kind
            else {
                return Err(blocked(
                    RecoveryField::Role,
                    HeaderIneligibilityReason::UnsupportedType,
                ));
            };
            if decl.is_constructor || decl.is_destructor {
                return Err(blocked(
                    RecoveryField::Role,
                    HeaderIneligibilityReason::IncompleteTemplateContext,
                ));
            }
            let name =
                crate::analysis::report::Identifier::new(decl.name.leaf().ok_or_else(|| {
                    blocked(
                        RecoveryField::DisplayName,
                        HeaderIneligibilityReason::InvalidLinkage,
                    )
                })?)
                .map_err(|_| {
                    blocked(
                        RecoveryField::DisplayName,
                        HeaderIneligibilityReason::IncompleteTemplateContext,
                    )
                })?;
            let needs_owner = decl.name.components.len() != 1
                || matches!(entity_kind(entity), Some(EntityKind::Method));
            let owner = if needs_owner {
                Some(resolve_owner(entity, owner_override)?)
            } else {
                None
            };
            if let Some(owner) = owner.as_ref() {
                validate_projectable_owner(owner)?;
            }
            (name, owner)
        }
    };
    let return_type = match &entity.signature.return_type {
        Fact::Known {
            value: TypeEvidence::Source { ty },
            strength,
            ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred => ty.clone(),
        Fact::Conflicted { .. } => {
            return Err(blocked(
                RecoveryField::ReturnType,
                HeaderIneligibilityReason::ConflictedRequiredFact,
            ));
        }
        _ => {
            return Err(blocked(
                RecoveryField::ReturnType,
                HeaderIneligibilityReason::UnavailableRequiredFact,
            ));
        }
    };
    let recovered_parameters = match &entity.signature.parameters {
        Fact::Known {
            value: ParameterList::Known { value },
            strength,
            ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred => value,
        Fact::Conflicted { .. } => {
            return Err(blocked(
                RecoveryField::Parameters,
                HeaderIneligibilityReason::ConflictedRequiredFact,
            ));
        }
        _ => {
            return Err(blocked(
                RecoveryField::Parameters,
                HeaderIneligibilityReason::UnavailableRequiredFact,
            ));
        }
    };
    let mut parameters = Vec::new();
    for (index, parameter) in recovered_parameters.iter().enumerate() {
        let ty = match &parameter.type_evidence {
            Fact::Known {
                value: TypeEvidence::Source { ty },
                strength,
                ..
            } if *strength != crate::analysis::report::EvidenceStrength::Inferred => ty.clone(),
            Fact::Conflicted { .. } => {
                return Err(blocked(
                    RecoveryField::Parameters,
                    HeaderIneligibilityReason::ConflictedRequiredFact,
                ));
            }
            _ => {
                return Err(blocked(
                    RecoveryField::Parameters,
                    HeaderIneligibilityReason::UnsupportedType,
                ));
            }
        };
        let raw_name = match &parameter.source_name {
            Fact::Known { value, .. } => value.clone(),
            _ => format!("arg{index}"),
        };
        let name = crate::analysis::report::Identifier::new(raw_name)
            .or_else(|_| crate::analysis::report::Identifier::new(format!("arg{index}")))
            .map_err(|_| {
                blocked(
                    RecoveryField::Parameters,
                    HeaderIneligibilityReason::UnsupportedType,
                )
            })?;
        parameters.push(HeaderParameter { name, ty });
    }
    let variadic = match &entity.signature.variadic {
        Fact::Known {
            value, strength, ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred => *value,
        Fact::Conflicted { .. } => {
            return Err(blocked(
                RecoveryField::Variadic,
                HeaderIneligibilityReason::ConflictedRequiredFact,
            ));
        }
        _ => {
            return Err(blocked(
                RecoveryField::Variadic,
                HeaderIneligibilityReason::UnavailableRequiredFact,
            ));
        }
    };
    let calling_convention = match &entity.signature.calling_convention {
        Fact::Known {
            value, strength, ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred
            || *value == CallingConvention::C =>
        {
            *value
        }
        Fact::Conflicted { .. } => {
            return Err(blocked(
                RecoveryField::CallingConvention,
                HeaderIneligibilityReason::ConflictedRequiredFact,
            ));
        }
        _ => {
            return Err(blocked(
                RecoveryField::CallingConvention,
                HeaderIneligibilityReason::UnavailableRequiredFact,
            ));
        }
    };
    if !matches!(calling_convention, CallingConvention::C) {
        return Err(blocked(
            RecoveryField::CallingConvention,
            HeaderIneligibilityReason::UnsupportedCallingConvention,
        ));
    }
    let qualifiers = match language {
        RecoveryLanguage::CAbi => HeaderFunctionQualifiers::default(),
        RecoveryLanguage::Cpp => match &entity.signature.qualifiers {
            Fact::Known { value, .. } => HeaderFunctionQualifiers {
                is_const: value.is_const.ok_or_else(|| {
                    blocked(
                        RecoveryField::Qualifiers,
                        HeaderIneligibilityReason::UnavailableRequiredFact,
                    )
                })?,
                is_volatile: value.is_volatile.ok_or_else(|| {
                    blocked(
                        RecoveryField::Qualifiers,
                        HeaderIneligibilityReason::UnavailableRequiredFact,
                    )
                })?,
                reference: value.reference.map(|value| match value {
                    ReferenceKind::Lvalue => ReferenceKind::Lvalue,
                    ReferenceKind::Rvalue => ReferenceKind::Rvalue,
                }),
                noexcept: value.noexcept,
            },
            Fact::Conflicted { .. } => {
                return Err(blocked(
                    RecoveryField::Qualifiers,
                    HeaderIneligibilityReason::ConflictedRequiredFact,
                ));
            }
            _ => {
                return Err(blocked(
                    RecoveryField::Qualifiers,
                    HeaderIneligibilityReason::UnavailableRequiredFact,
                ));
            }
        },
    };
    let signature = HeaderType::Function {
        return_type: Box::new(return_type),
        parameters,
        parameter_state: ParameterState::Known,
        variadic,
        calling_convention,
        qualifiers,
    };
    let syntax_signature = syntax_type(&signature).ok_or_else(|| {
        blocked(
            RecoveryField::ReturnType,
            HeaderIneligibilityReason::IncompleteTemplateContext,
        )
    })?;
    let syntax_name = syntax::Identifier::new(name.as_str()).ok_or_else(|| {
        blocked(
            RecoveryField::DisplayName,
            HeaderIneligibilityReason::InvalidLinkage,
        )
    })?;
    let linkage = match language {
        RecoveryLanguage::CAbi => HeaderLinkage::C,
        RecoveryLanguage::Cpp => HeaderLinkage::Cpp,
    };
    let syntax_linkage = match language {
        RecoveryLanguage::CAbi => syntax::Linkage::C,
        RecoveryLanguage::Cpp => syntax::Linkage::Cpp,
    };
    let syntax_declaration = syntax::Decl::Function {
        name: syntax_name,
        signature: syntax_signature,
        storage: syntax::StorageClass::None,
        linkage: syntax_linkage,
    };
    Ok((
        HeaderDecl::Function {
            id: entity.id.clone(),
            owner: owner.clone(),
            name,
            signature,
            storage: StorageClass::None,
            linkage,
        },
        wrap_owner(owner.as_ref(), syntax_declaration)?,
    ))
}

fn project_variable(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
    owner_override: Option<&crate::analysis::report::HeaderOwnerRef>,
) -> ProjectionResult {
    use crate::analysis::report::{
        EvidenceStrength, Fact, HeaderDecl, HeaderIneligibilityReason, HeaderLinkage,
        RecoveryField, StorageClass, TypeEvidence,
    };

    let raw_name = entity_name(entity);
    let qualified = raw_name.contains("::");
    let owner = if qualified {
        Some(resolve_owner(entity, owner_override)?)
    } else {
        None
    };
    if let Some(owner) = owner.as_ref() {
        validate_projectable_owner(owner)?;
    }
    let terminal_name = raw_name.rsplit("::").next().unwrap_or(raw_name.as_str());
    let name = crate::analysis::report::Identifier::new(terminal_name).map_err(|_| {
        blocked(
            RecoveryField::DisplayName,
            HeaderIneligibilityReason::IncompleteTemplateContext,
        )
    })?;
    let ty = match &entity.value_type {
        Fact::Known {
            value: TypeEvidence::Source { ty },
            strength,
            ..
        } if *strength != EvidenceStrength::Inferred => ty.clone(),
        Fact::Conflicted { .. } => {
            return Err(blocked(
                RecoveryField::ValueType,
                HeaderIneligibilityReason::ConflictedRequiredFact,
            ));
        }
        _ => {
            return Err(blocked(
                RecoveryField::ValueType,
                HeaderIneligibilityReason::UnavailableRequiredFact,
            ));
        }
    };
    let kind = entity_kind(entity).ok_or_else(|| {
        blocked(
            RecoveryField::Role,
            HeaderIneligibilityReason::UnavailableRequiredFact,
        )
    })?;
    let storage = match kind {
        EntityKind::Data => StorageClass::Extern,
        EntityKind::Tls => StorageClass::ThreadLocal,
        _ => {
            return Err(blocked(
                RecoveryField::Role,
                HeaderIneligibilityReason::UnsupportedType,
            ));
        }
    };
    let syntax_storage = match storage {
        StorageClass::Extern => syntax::StorageClass::Extern,
        StorageClass::ThreadLocal => syntax::StorageClass::ThreadLocal,
        StorageClass::None => syntax::StorageClass::None,
        StorageClass::Static => syntax::StorageClass::Static,
    };
    let linkage = match language {
        RecoveryLanguage::CAbi => HeaderLinkage::C,
        RecoveryLanguage::Cpp => HeaderLinkage::Cpp,
    };
    let syntax_linkage = match language {
        RecoveryLanguage::CAbi => syntax::Linkage::C,
        RecoveryLanguage::Cpp => syntax::Linkage::Cpp,
    };
    let syntax_declaration = syntax::Decl::Variable {
        name: syntax::Identifier::new(name.as_str()).ok_or_else(|| {
            blocked(
                RecoveryField::DisplayName,
                HeaderIneligibilityReason::InvalidLinkage,
            )
        })?,
        ty: syntax_type(&ty).ok_or_else(|| {
            blocked(
                RecoveryField::ValueType,
                HeaderIneligibilityReason::IncompleteTemplateContext,
            )
        })?,
        storage: syntax_storage,
        linkage: syntax_linkage,
    };
    Ok((
        HeaderDecl::Variable {
            id: entity.id.clone(),
            owner: owner.clone(),
            name: name.clone(),
            ty: ty.clone(),
            storage,
            linkage,
        },
        wrap_owner(owner.as_ref(), syntax_declaration)?,
    ))
}

fn project_type(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
    owner_override: Option<&crate::analysis::report::HeaderOwnerRef>,
) -> ProjectionResult {
    use crate::analysis::report::{
        Fact, HeaderDecl, HeaderIneligibilityReason, LayoutCompleteness, RecordKind, RecoveryField,
    };

    if language != RecoveryLanguage::Cpp {
        return Err(blocked(
            RecoveryField::Role,
            HeaderIneligibilityReason::UnsupportedType,
        ));
    }
    let raw_name = entity_name(entity);
    let qualified = raw_name.contains("::");
    let owner = if qualified {
        Some(resolve_owner(entity, owner_override)?)
    } else {
        None
    };
    if let Some(owner) = owner.as_ref() {
        validate_projectable_owner(owner)?;
    }
    let terminal_name = raw_name.rsplit("::").next().unwrap_or(raw_name.as_str());
    let terminal = crate::analysis::report::Identifier::new(terminal_name).map_err(|_| {
        blocked(
            RecoveryField::DisplayName,
            HeaderIneligibilityReason::IncompleteTemplateContext,
        )
    })?;
    let wire_path =
        crate::analysis::report::NonEmpty::new(vec![terminal.clone()]).map_err(|_| {
            blocked(
                RecoveryField::DisplayName,
                HeaderIneligibilityReason::UnsupportedType,
            )
        })?;
    let syntax_path = syntax::IdentifierPath::new(vec![
        syntax::Identifier::new(terminal.as_str()).ok_or_else(|| {
            blocked(
                RecoveryField::DisplayName,
                HeaderIneligibilityReason::UnsupportedType,
            )
        })?,
    ])
    .ok_or_else(|| {
        blocked(
            RecoveryField::DisplayName,
            HeaderIneligibilityReason::UnsupportedType,
        )
    })?;
    let complete = matches!(
        entity.layout.completeness,
        Fact::Known {
            value: LayoutCompleteness::Complete,
            ..
        }
    );
    if complete {
        let wire_fields = match &entity.layout.fields {
            Fact::Known { value, .. } => value
                .iter()
                .map(wire_field)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| {
                blocked(
                    RecoveryField::LayoutFields,
                    HeaderIneligibilityReason::UnsupportedType,
                )
            })?,
            _ => {
                return Err(blocked(
                    RecoveryField::LayoutFields,
                    HeaderIneligibilityReason::IncompleteLayout,
                ));
            }
        };
        let syntax_fields = wire_fields
            .iter()
            .map(syntax_field)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| {
                blocked(
                    RecoveryField::LayoutFields,
                    HeaderIneligibilityReason::UnsupportedType,
                )
            })?;
        let syntax_declaration = syntax::Decl::Record {
            kind: syntax::RecordKind::Class,
            path: syntax_path,
            bases: Vec::new(),
            fields: syntax_fields,
            members: Vec::new(),
        };
        Ok((
            HeaderDecl::Record {
                id: entity.id.clone(),
                owner: owner.clone(),
                record_kind: RecordKind::Class,
                path: wire_path,
                complete: true,
                bases: Vec::new(),
                fields: wire_fields,
                members: Vec::new(),
            },
            wrap_owner(owner.as_ref(), syntax_declaration)?,
        ))
    } else {
        let syntax_declaration = syntax::Decl::Forward {
            kind: syntax::RecordKind::Class,
            path: syntax_path,
        };
        Ok((
            HeaderDecl::Forward {
                id: entity.id.clone(),
                owner: owner.clone(),
                record_kind: RecordKind::Class,
                path: wire_path,
            },
            wrap_owner(owner.as_ref(), syntax_declaration)?,
        ))
    }
}

fn resolve_owner(
    entity: &crate::analysis::report::RecoveredEntity,
    owner_override: Option<&crate::analysis::report::HeaderOwnerRef>,
) -> Result<crate::analysis::report::HeaderOwnerRef, ProjectionBlocker> {
    owner_override
        .cloned()
        .map_or_else(|| proven_owner(entity), Ok)
}

fn proven_owner(
    entity: &crate::analysis::report::RecoveredEntity,
) -> Result<crate::analysis::report::HeaderOwnerRef, ProjectionBlocker> {
    use crate::analysis::report::{
        Fact, HeaderIneligibilityReason, HeaderOwnerRef, NonEmpty, RecoveryField,
    };

    let owner = match &entity.owner {
        Fact::Known { value, .. } => value,
        Fact::Conflicted { .. } => {
            return Err(blocked(
                RecoveryField::Owner,
                HeaderIneligibilityReason::ConflictedRequiredFact,
            ));
        }
        Fact::Unavailable { .. } => {
            return Err(blocked(
                RecoveryField::Owner,
                HeaderIneligibilityReason::UnprovenOwner,
            ));
        }
    };
    let path = NonEmpty::new(owner.path.clone()).map_err(|_| {
        blocked(
            RecoveryField::Owner,
            HeaderIneligibilityReason::UnprovenOwner,
        )
    })?;
    let scope_kinds = owner
        .scope_kinds
        .iter()
        .copied()
        .collect::<Option<Vec<_>>>()
        .and_then(|scope_kinds| NonEmpty::new(scope_kinds).ok())
        .filter(|scope_kinds| scope_kinds.as_slice().len() == path.as_slice().len())
        .ok_or_else(|| {
            blocked(
                RecoveryField::Owner,
                HeaderIneligibilityReason::UnprovenOwner,
            )
        })?;
    let scope_access = NonEmpty::new(owner.scope_access.clone())
        .ok()
        .filter(|scope_access| scope_access.as_slice().len() == path.as_slice().len())
        .ok_or_else(|| {
            blocked(
                RecoveryField::Owner,
                HeaderIneligibilityReason::UnprovenOwner,
            )
        })?;
    Ok(HeaderOwnerRef {
        path,
        scope_kinds,
        scope_access,
        member_access: owner.member_access,
        entity_id: owner.entity_id.clone(),
    })
}

fn validate_projectable_owner(
    owner: &crate::analysis::report::HeaderOwnerRef,
) -> Result<(), ProjectionBlocker> {
    use crate::analysis::report::{
        Access, HeaderIneligibilityReason, HeaderOwnerKind, RecoveryField,
    };

    if !owner.has_exact_scopes() {
        return Err(blocked(
            RecoveryField::Owner,
            HeaderIneligibilityReason::UnprovenOwner,
        ));
    }
    let kinds = owner.scope_kinds.as_slice();
    let access = owner.scope_access.as_slice();
    if access[0].is_some()
        || (1..kinds.len()).any(|index| match kinds[index - 1] {
            HeaderOwnerKind::Namespace => access[index].is_some(),
            HeaderOwnerKind::Record | HeaderOwnerKind::Class => !matches!(
                access[index],
                Some(Access::Public | Access::Protected | Access::Private)
            ),
        })
    {
        return Err(blocked(
            RecoveryField::Owner,
            HeaderIneligibilityReason::IncompleteTemplateContext,
        ));
    }
    match owner.terminal_kind() {
        HeaderOwnerKind::Namespace if owner.member_access.is_none() => Ok(()),
        HeaderOwnerKind::Record | HeaderOwnerKind::Class
            if matches!(
                owner.member_access,
                Some(Access::Public | Access::Protected | Access::Private)
            ) =>
        {
            Ok(())
        }
        _ => Err(blocked(
            RecoveryField::Owner,
            HeaderIneligibilityReason::IncompleteTemplateContext,
        )),
    }
}

fn wrap_owner(
    owner: Option<&crate::analysis::report::HeaderOwnerRef>,
    mut declaration: syntax::Decl,
) -> Result<syntax::Decl, ProjectionBlocker> {
    use crate::analysis::report::{
        Access, HeaderIneligibilityReason, HeaderOwnerKind, RecoveryField,
    };

    let Some(owner) = owner else {
        return Ok(declaration);
    };
    validate_projectable_owner(owner)?;
    let components = owner.path.as_slice();
    let kinds = owner.scope_kinds.as_slice();
    let scope_access = owner.scope_access.as_slice();
    for index in (0..components.len()).rev() {
        let identifier = syntax::Identifier::new(components[index].as_str()).ok_or_else(|| {
            blocked(
                RecoveryField::Owner,
                HeaderIneligibilityReason::UnsupportedType,
            )
        })?;
        let path = syntax::IdentifierPath::new(vec![identifier]).expect("one owner component");
        declaration = match kinds[index] {
            HeaderOwnerKind::Namespace => syntax::Decl::Namespace {
                path,
                declarations: vec![declaration],
            },
            HeaderOwnerKind::Record | HeaderOwnerKind::Class => {
                let access = if index + 1 == components.len() {
                    owner.member_access
                } else {
                    scope_access[index + 1]
                }
                .ok_or_else(|| {
                    blocked(
                        RecoveryField::Owner,
                        HeaderIneligibilityReason::IncompleteTemplateContext,
                    )
                })?;
                let access = match access {
                    Access::Public => syntax::Access::Public,
                    Access::Protected => syntax::Access::Protected,
                    Access::Private => syntax::Access::Private,
                    Access::Unspecified => {
                        return Err(blocked(
                            RecoveryField::Owner,
                            HeaderIneligibilityReason::IncompleteTemplateContext,
                        ));
                    }
                };
                syntax::Decl::Record {
                    kind: if kinds[index] == HeaderOwnerKind::Class {
                        syntax::RecordKind::Class
                    } else {
                        syntax::RecordKind::Struct
                    },
                    path,
                    bases: Vec::new(),
                    fields: Vec::new(),
                    members: vec![syntax::Decl::AccessSection {
                        access,
                        declarations: vec![declaration],
                    }],
                }
            }
        };
    }
    Ok(declaration)
}

fn wire_field(
    field: &crate::analysis::report::RecoveredField,
) -> Option<crate::analysis::report::HeaderField> {
    use crate::analysis::report::{Access, EvidenceStrength, Fact, TypeEvidence};
    let name = match &field.name {
        Fact::Known { value, .. } => {
            crate::analysis::report::Identifier::new(value.clone()).ok()?
        }
        _ => return None,
    };
    let ty = match &field.ty {
        Fact::Known {
            value: TypeEvidence::Source { ty },
            strength,
            ..
        } if *strength != EvidenceStrength::Inferred => ty.clone(),
        _ => return None,
    };
    let offset = match &field.offset {
        Fact::Known { value, .. } => Some(*value),
        _ => return None,
    };
    let bit_width = match &field.bit_width {
        Fact::Known { value, .. } => *value,
        _ => return None,
    };
    Some(crate::analysis::report::HeaderField {
        name,
        ty,
        offset,
        bit_width,
        access: Access::Unspecified,
    })
}

fn syntax_field(field: &crate::analysis::report::HeaderField) -> Option<syntax::Field> {
    Some(syntax::Field {
        name: syntax::Identifier::new(field.name.as_str())?,
        ty: syntax_type(&field.ty)?,
        offset: field.offset,
        bit_width: field.bit_width,
        access: match field.access {
            crate::analysis::report::Access::Public => syntax::Access::Public,
            crate::analysis::report::Access::Protected => syntax::Access::Protected,
            crate::analysis::report::Access::Private => syntax::Access::Private,
            crate::analysis::report::Access::Unspecified => syntax::Access::Unspecified,
        },
    })
}

fn syntax_type(value: &crate::analysis::report::HeaderType) -> Option<syntax::Type> {
    use crate::analysis::report as wire;
    Some(match value {
        wire::HeaderType::Builtin { name } => syntax::Type::Builtin(match name {
            wire::BuiltinType::Void => syntax::BuiltinType::Void,
            wire::BuiltinType::Bool => syntax::BuiltinType::Bool,
            wire::BuiltinType::Char => syntax::BuiltinType::Char,
            wire::BuiltinType::SignedChar => syntax::BuiltinType::SignedChar,
            wire::BuiltinType::UnsignedChar => syntax::BuiltinType::UnsignedChar,
            wire::BuiltinType::Short => syntax::BuiltinType::Short,
            wire::BuiltinType::UnsignedShort => syntax::BuiltinType::UnsignedShort,
            wire::BuiltinType::Int => syntax::BuiltinType::Int,
            wire::BuiltinType::UnsignedInt => syntax::BuiltinType::UnsignedInt,
            wire::BuiltinType::Long => syntax::BuiltinType::Long,
            wire::BuiltinType::UnsignedLong => syntax::BuiltinType::UnsignedLong,
            wire::BuiltinType::LongLong => syntax::BuiltinType::LongLong,
            wire::BuiltinType::UnsignedLongLong => syntax::BuiltinType::UnsignedLongLong,
            wire::BuiltinType::Int128 => syntax::BuiltinType::Int128,
            wire::BuiltinType::UnsignedInt128 => syntax::BuiltinType::UnsignedInt128,
            wire::BuiltinType::Float => syntax::BuiltinType::Float,
            wire::BuiltinType::Double => syntax::BuiltinType::Double,
            wire::BuiltinType::LongDouble => syntax::BuiltinType::LongDouble,
        }),
        wire::HeaderType::Named {
            tag,
            path,
            template_arguments,
        } if template_arguments.is_empty() => syntax::Type::Named {
            tag: match tag {
                wire::NamedTypeTag::Typedef => syntax::NamedTypeTag::Typedef,
                wire::NamedTypeTag::Struct => syntax::NamedTypeTag::Struct,
                wire::NamedTypeTag::Union => syntax::NamedTypeTag::Union,
                wire::NamedTypeTag::Enum => syntax::NamedTypeTag::Enum,
                wire::NamedTypeTag::Class => syntax::NamedTypeTag::Class,
                wire::NamedTypeTag::Protocol => syntax::NamedTypeTag::Protocol,
            },
            path: syntax::IdentifierPath::new(
                path.as_slice()
                    .iter()
                    .map(|value| syntax::Identifier::new(value.as_str()))
                    .collect::<Option<Vec<_>>>()?,
            )?,
            template_arguments: Vec::new(),
        },
        wire::HeaderType::Pointer {
            pointee,
            qualifiers,
        } => syntax::Type::Pointer {
            pointee: Box::new(syntax_type(pointee)?),
            qualifiers: syntax::TypeQualifiers {
                is_const: qualifiers.is_const,
                is_volatile: qualifiers.is_volatile,
                is_restrict: qualifiers.is_restrict,
            },
        },
        wire::HeaderType::Reference { target, reference } => syntax::Type::Reference {
            target: Box::new(syntax_type(target)?),
            kind: match reference {
                wire::ReferenceKind::Lvalue => syntax::ReferenceKind::Lvalue,
                wire::ReferenceKind::Rvalue => syntax::ReferenceKind::Rvalue,
            },
        },
        wire::HeaderType::Array { element, count } => syntax::Type::Array {
            element: Box::new(syntax_type(element)?),
            count: *count,
        },
        wire::HeaderType::Function {
            return_type,
            parameters,
            parameter_state,
            variadic,
            calling_convention,
            qualifiers,
        } => syntax::Type::Function {
            return_type: Box::new(syntax_type(return_type)?),
            parameters: parameters
                .iter()
                .map(|parameter| {
                    Some(syntax::Parameter {
                        name: syntax::Identifier::new(parameter.name.as_str())?,
                        ty: syntax_type(&parameter.ty)?,
                    })
                })
                .collect::<Option<Vec<_>>>()?,
            parameter_state: match parameter_state {
                wire::ParameterState::Unspecified => syntax::ParameterState::Unspecified,
                wire::ParameterState::Known => syntax::ParameterState::Known,
            },
            variadic: *variadic,
            calling_convention: match calling_convention {
                wire::CallingConvention::C => syntax::CallingConvention::C,
                wire::CallingConvention::Thiscall => syntax::CallingConvention::Thiscall,
                wire::CallingConvention::Vectorcall => syntax::CallingConvention::Vectorcall,
                wire::CallingConvention::Aapcs => syntax::CallingConvention::Aapcs,
                wire::CallingConvention::AapcsVfp => syntax::CallingConvention::AapcsVfp,
                wire::CallingConvention::Swift => syntax::CallingConvention::Swift,
                wire::CallingConvention::ObjcMethod => syntax::CallingConvention::ObjectiveCMethod,
                wire::CallingConvention::Unknown => syntax::CallingConvention::Unknown,
            },
            qualifiers: syntax::FunctionQualifiers {
                is_const: qualifiers.is_const,
                is_volatile: qualifiers.is_volatile,
                reference: qualifiers.reference.map(|value| match value {
                    wire::ReferenceKind::Lvalue => syntax::ReferenceKind::Lvalue,
                    wire::ReferenceKind::Rvalue => syntax::ReferenceKind::Rvalue,
                }),
                noexcept: qualifiers.noexcept,
            },
        },
        _ => return None,
    })
}
