use crate::analysis::report::{Presence, RecoveryLanguage};
use crate::header_syntax as syntax;

use super::{EntityKind, entity_address, entity_kind, entity_name, entity_presence};
pub(super) fn project_entity(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
) -> Option<(crate::analysis::report::HeaderDecl, syntax::Decl)> {
    use crate::analysis::report::{
        CallingConvention, Fact, HeaderDecl, HeaderFunctionQualifiers, HeaderLinkage,
        HeaderParameter, HeaderType, ParameterList, ParameterState, ReferenceKind, StorageClass,
        TypeEvidence,
    };

    if entity_presence(entity) != Presence::Defined {
        return None;
    }
    match entity_kind(entity) {
        Some(EntityKind::Data | EntityKind::Tls) => {
            return project_variable(entity, language);
        }
        Some(EntityKind::Type) => return project_type(entity, language),
        Some(EntityKind::Function | EntityKind::Method) => {}
        _ => return None,
    }
    let name = match language {
        RecoveryLanguage::CAbi => {
            crate::analysis::report::Identifier::new(entity_name(entity)).ok()?
        }
        RecoveryLanguage::Cpp => {
            let raw = match &entity.linkage {
                Fact::Known { value, .. } => &value.raw,
                _ => return None,
            };
            let record = crate::analysis::reconstruct::cpp::symbol::parse_symbol(
                raw,
                entity_address(entity),
                None,
            )?;
            let crate::analysis::reconstruct::cpp::CppSymbolKind::Function { decl } = record.kind
            else {
                return None;
            };
            if decl.name.components.len() != 1 || decl.is_constructor || decl.is_destructor {
                return None;
            }
            crate::analysis::report::Identifier::new(decl.name.leaf()?.to_owned()).ok()?
        }
    };
    let return_type = match &entity.signature.return_type {
        Fact::Known {
            value: TypeEvidence::Source { ty },
            strength,
            ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred => ty.clone(),
        _ => return None,
    };
    let recovered_parameters = match &entity.signature.parameters {
        Fact::Known {
            value: ParameterList::Known { value },
            strength,
            ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred => value,
        _ => return None,
    };
    let mut parameters = Vec::new();
    for (index, parameter) in recovered_parameters.iter().enumerate() {
        let ty = match &parameter.type_evidence {
            Fact::Known {
                value: TypeEvidence::Source { ty },
                strength,
                ..
            } if *strength != crate::analysis::report::EvidenceStrength::Inferred => ty.clone(),
            _ => return None,
        };
        let raw_name = match &parameter.source_name {
            Fact::Known { value, .. } => value.clone(),
            _ => format!("arg{index}"),
        };
        let name = crate::analysis::report::Identifier::new(raw_name)
            .or_else(|_| crate::analysis::report::Identifier::new(format!("arg{index}")))
            .ok()?;
        parameters.push(HeaderParameter { name, ty });
    }
    let variadic = match &entity.signature.variadic {
        Fact::Known {
            value, strength, ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred => *value,
        _ => return None,
    };
    let calling_convention = match &entity.signature.calling_convention {
        Fact::Known {
            value, strength, ..
        } if *strength != crate::analysis::report::EvidenceStrength::Inferred
            || *value == CallingConvention::C =>
        {
            *value
        }
        _ => return None,
    };
    if !matches!(calling_convention, CallingConvention::C) {
        return None;
    }
    let qualifiers = match language {
        RecoveryLanguage::CAbi => HeaderFunctionQualifiers::default(),
        RecoveryLanguage::Cpp => match &entity.signature.qualifiers {
            Fact::Known { value, .. } => HeaderFunctionQualifiers {
                is_const: value.is_const?,
                is_volatile: value.is_volatile?,
                reference: value.reference.map(|value| match value {
                    ReferenceKind::Lvalue => ReferenceKind::Lvalue,
                    ReferenceKind::Rvalue => ReferenceKind::Rvalue,
                }),
                noexcept: value.noexcept,
            },
            _ => return None,
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
    let syntax_signature = syntax_type(&signature)?;
    let syntax_name = syntax::Identifier::new(name.as_str())?;
    let linkage = match language {
        RecoveryLanguage::CAbi => HeaderLinkage::C,
        RecoveryLanguage::Cpp => HeaderLinkage::Cpp,
    };
    let syntax_linkage = match language {
        RecoveryLanguage::CAbi => syntax::Linkage::C,
        RecoveryLanguage::Cpp => syntax::Linkage::Cpp,
    };
    Some((
        HeaderDecl::Function {
            id: entity.id.clone(),
            owner: None,
            name,
            signature,
            storage: StorageClass::None,
            linkage,
        },
        syntax::Decl::Function {
            name: syntax_name,
            signature: syntax_signature,
            storage: syntax::StorageClass::None,
            linkage: syntax_linkage,
        },
    ))
}

fn project_variable(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
) -> Option<(crate::analysis::report::HeaderDecl, syntax::Decl)> {
    use crate::analysis::report::{
        EvidenceStrength, Fact, HeaderDecl, HeaderLinkage, StorageClass, TypeEvidence,
    };

    let name = crate::analysis::report::Identifier::new(entity_name(entity)).ok()?;
    let ty = match &entity.value_type {
        Fact::Known {
            value: TypeEvidence::Source { ty },
            strength,
            ..
        } if *strength != EvidenceStrength::Inferred => ty.clone(),
        _ => return None,
    };
    let kind = entity_kind(entity)?;
    let storage = match kind {
        EntityKind::Data => StorageClass::Extern,
        EntityKind::Tls => StorageClass::ThreadLocal,
        _ => return None,
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
    Some((
        HeaderDecl::Variable {
            id: entity.id.clone(),
            owner: None,
            name: name.clone(),
            ty: ty.clone(),
            storage,
            linkage,
        },
        syntax::Decl::Variable {
            name: syntax::Identifier::new(name.as_str())?,
            ty: syntax_type(&ty)?,
            storage: syntax_storage,
            linkage: syntax_linkage,
        },
    ))
}

fn project_type(
    entity: &crate::analysis::report::RecoveredEntity,
    language: RecoveryLanguage,
) -> Option<(crate::analysis::report::HeaderDecl, syntax::Decl)> {
    use crate::analysis::report::{Fact, HeaderDecl, LayoutCompleteness, RecordKind};

    if language != RecoveryLanguage::Cpp {
        return None;
    }
    let path = entity_name(entity)
        .split("::")
        .map(|component| crate::analysis::report::Identifier::new(component.to_owned()).ok())
        .collect::<Option<Vec<_>>>()?;
    if path.len() != 1 {
        return None;
    }
    let wire_path = crate::analysis::report::NonEmpty::new(path).ok()?;
    let syntax_path = syntax::IdentifierPath::new(
        wire_path
            .as_slice()
            .iter()
            .map(|component| syntax::Identifier::new(component.as_str()))
            .collect::<Option<Vec<_>>>()?,
    )?;
    let complete = matches!(
        entity.layout.completeness,
        Fact::Known {
            value: LayoutCompleteness::Complete,
            ..
        }
    );
    if complete {
        let wire_fields = match &entity.layout.fields {
            Fact::Known { value, .. } => {
                value.iter().map(wire_field).collect::<Option<Vec<_>>>()?
            }
            _ => return None,
        };
        let syntax_fields = wire_fields
            .iter()
            .map(syntax_field)
            .collect::<Option<Vec<_>>>()?;
        Some((
            HeaderDecl::Record {
                id: entity.id.clone(),
                record_kind: RecordKind::Class,
                path: wire_path,
                complete: true,
                bases: Vec::new(),
                fields: wire_fields,
                members: Vec::new(),
            },
            syntax::Decl::Record {
                kind: syntax::RecordKind::Class,
                path: syntax_path,
                bases: Vec::new(),
                fields: syntax_fields,
                members: Vec::new(),
            },
        ))
    } else {
        Some((
            HeaderDecl::Forward {
                id: entity.id.clone(),
                record_kind: RecordKind::Class,
                path: wire_path,
            },
            syntax::Decl::Forward {
                kind: syntax::RecordKind::Class,
                path: syntax_path,
            },
        ))
    }
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
