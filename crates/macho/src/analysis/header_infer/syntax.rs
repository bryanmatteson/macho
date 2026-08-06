//! Lossless lowering from the shared wire header vocabulary to syntax nodes.

use crate::analysis::header_syntax as syntax;
use crate::analysis::report as wire;

use crate::analysis::header_infer::ArtifactError;

pub(crate) fn language(value: wire::RecoveryLanguage) -> syntax::Language {
    match value {
        wire::RecoveryLanguage::CAbi => syntax::Language::C,
        wire::RecoveryLanguage::Cpp => syntax::Language::Cpp,
    }
}

pub(crate) fn declaration(value: &wire::HeaderDecl) -> Result<syntax::Decl, ArtifactError> {
    Ok(match value {
        wire::HeaderDecl::Function {
            name,
            signature,
            storage,
            linkage,
            ..
        } => syntax::Decl::Function {
            name: identifier(name)?,
            signature: ty(signature)?,
            storage: storage_class(*storage),
            linkage: linkage_kind(*linkage),
        },
        wire::HeaderDecl::Variable {
            name,
            ty: value,
            storage,
            linkage,
            ..
        } => syntax::Decl::Variable {
            name: identifier(name)?,
            ty: ty(value)?,
            storage: storage_class(*storage),
            linkage: linkage_kind(*linkage),
        },
        wire::HeaderDecl::Record {
            record_kind: wire_record_kind,
            path: value_path,
            complete,
            bases,
            fields,
            members,
            ..
        } => {
            if !complete {
                syntax::Decl::Forward {
                    kind: record_kind(*wire_record_kind),
                    path: path(value_path)?,
                }
            } else {
                syntax::Decl::Record {
                    kind: record_kind(*wire_record_kind),
                    path: path(value_path)?,
                    bases: bases
                        .iter()
                        .map(|base| {
                            Ok(syntax::Base {
                                ty: ty(&base.ty)?,
                                access: access(base.access),
                                is_virtual: base.is_virtual,
                            })
                        })
                        .collect::<Result<_, ArtifactError>>()?,
                    fields: fields
                        .iter()
                        .map(|field| {
                            Ok(syntax::Field {
                                name: identifier(&field.name)?,
                                ty: ty(&field.ty)?,
                                offset: field.offset,
                                bit_width: field.bit_width,
                                access: access(field.access),
                            })
                        })
                        .collect::<Result<_, ArtifactError>>()?,
                    members: members.iter().map(declaration).collect::<Result<_, _>>()?,
                }
            }
        }
        wire::HeaderDecl::Forward {
            record_kind: wire_record_kind,
            path: value_path,
            ..
        } => syntax::Decl::Forward {
            kind: record_kind(*wire_record_kind),
            path: path(value_path)?,
        },
        wire::HeaderDecl::Alias {
            path: value_path,
            target,
            ..
        } => syntax::Decl::Alias {
            path: path(value_path)?,
            target: ty(target)?,
        },
        wire::HeaderDecl::ObjcInterface {
            name,
            superclass,
            protocols,
            ivars,
            members,
            ..
        } => {
            let (methods, properties) = objc_members(members)?;
            syntax::Decl::ObjectiveCInterface {
                name: identifier(name)?,
                superclass: superclass.as_ref().map(identifier).transpose()?,
                protocols: protocols.iter().map(identifier).collect::<Result<_, _>>()?,
                ivars: ivars
                    .iter()
                    .map(|ivar| {
                        Ok(syntax::ObjectiveCIvar {
                            name: identifier(&ivar.name)?,
                            ty: ty(&ivar.ty)?,
                            access: objc_access(ivar.access),
                        })
                    })
                    .collect::<Result<_, ArtifactError>>()?,
                methods,
                properties,
            }
        }
        wire::HeaderDecl::ObjcCategory {
            name,
            extended_class,
            protocols,
            members,
            ..
        } => {
            let (methods, properties) = objc_members(members)?;
            syntax::Decl::ObjectiveCCategory {
                name: identifier(name)?,
                extended_class: identifier(extended_class)?,
                protocols: protocols.iter().map(identifier).collect::<Result<_, _>>()?,
                methods,
                properties,
            }
        }
        wire::HeaderDecl::ObjcProtocol {
            name,
            protocols,
            members,
            ..
        } => {
            let (methods, properties) = objc_members(members)?;
            syntax::Decl::ObjectiveCProtocol {
                name: identifier(name)?,
                protocols: protocols.iter().map(identifier).collect::<Result<_, _>>()?,
                methods,
                properties,
            }
        }
        wire::HeaderDecl::ObjcForward { entity_kind, names } => syntax::Decl::ObjectiveCForward {
            kind: match entity_kind {
                wire::ObjCForwardKind::Class => syntax::ObjectiveCForwardKind::Class,
                wire::ObjCForwardKind::Protocol => syntax::ObjectiveCForwardKind::Protocol,
            },
            names: names
                .as_slice()
                .iter()
                .map(identifier)
                .collect::<Result<_, _>>()?,
        },
    })
}

fn objc_members(
    values: &[wire::ObjCHeaderMember],
) -> Result<
    (
        Vec<syntax::ObjectiveCMethod>,
        Vec<syntax::ObjectiveCProperty>,
    ),
    ArtifactError,
> {
    let mut methods = Vec::new();
    let mut properties = Vec::new();
    for value in values {
        match value {
            wire::ObjCHeaderMember::Method {
                method_kind,
                selector,
                return_type,
                parameters,
                required,
                ..
            } => methods.push(syntax::ObjectiveCMethod {
                kind: match method_kind {
                    wire::MethodKind::Instance => syntax::MethodKind::Instance,
                    wire::MethodKind::Class => syntax::MethodKind::Class,
                },
                selector: selector.spelling.clone(),
                return_type: ty(return_type)?,
                parameters: parameters.iter().map(parameter).collect::<Result<_, _>>()?,
                required: *required,
            }),
            wire::ObjCHeaderMember::Property {
                name,
                ty: value_type,
                attributes,
                ..
            } => properties.push(syntax::ObjectiveCProperty {
                name: identifier(name)?,
                ty: ty(value_type)?,
                attributes: attributes.iter().copied().map(objc_property).collect(),
            }),
        }
    }
    Ok((methods, properties))
}

fn ty(value: &wire::HeaderType) -> Result<syntax::Type, ArtifactError> {
    Ok(match value {
        wire::HeaderType::Builtin { name } => syntax::Type::Builtin(builtin(*name)),
        wire::HeaderType::Named {
            tag,
            path: value_path,
            template_arguments,
        } => syntax::Type::Named {
            tag: named_tag(*tag),
            path: path(value_path)?,
            template_arguments: template_arguments
                .iter()
                .map(template_argument)
                .collect::<Result<_, _>>()?,
        },
        wire::HeaderType::Pointer {
            pointee,
            qualifiers,
        } => syntax::Type::Pointer {
            pointee: Box::new(ty(pointee)?),
            qualifiers: type_qualifiers(*qualifiers),
        },
        wire::HeaderType::Reference { target, reference } => syntax::Type::Reference {
            target: Box::new(ty(target)?),
            kind: reference_kind(*reference),
        },
        wire::HeaderType::Array { element, count } => syntax::Type::Array {
            element: Box::new(ty(element)?),
            count: *count,
        },
        wire::HeaderType::Function {
            return_type,
            parameters,
            parameter_state,
            variadic,
            calling_convention: wire_calling_convention,
            qualifiers,
        } => syntax::Type::Function {
            return_type: Box::new(ty(return_type)?),
            parameters: parameters.iter().map(parameter).collect::<Result<_, _>>()?,
            parameter_state: match parameter_state {
                wire::ParameterState::Unspecified => syntax::ParameterState::Unspecified,
                wire::ParameterState::Known => syntax::ParameterState::Known,
            },
            variadic: *variadic,
            calling_convention: calling_convention(*wire_calling_convention),
            qualifiers: function_qualifiers(*qualifiers),
        },
        wire::HeaderType::ObjcObject {
            name,
            protocols,
            qualifiers,
        } => syntax::Type::ObjectiveCObject {
            name: name.as_ref().map(identifier).transpose()?,
            protocols: protocols.iter().map(identifier).collect::<Result<_, _>>()?,
            qualifiers: type_qualifiers(*qualifiers),
        },
        wire::HeaderType::ObjcBlock { signature } => {
            syntax::Type::ObjectiveCBlock(Box::new(ty(signature)?))
        }
    })
}

fn parameter(value: &wire::HeaderParameter) -> Result<syntax::Parameter, ArtifactError> {
    Ok(syntax::Parameter {
        name: identifier(&value.name)?,
        ty: ty(&value.ty)?,
    })
}

fn template_argument(
    value: &wire::HeaderTemplateArgument,
) -> Result<syntax::TemplateArgument, ArtifactError> {
    Ok(match value {
        wire::HeaderTemplateArgument::Type { value } => syntax::TemplateArgument::Type(ty(value)?),
        wire::HeaderTemplateArgument::Integer { value } => {
            syntax::TemplateArgument::Integer(*value)
        }
        wire::HeaderTemplateArgument::Identifier { path: value } => {
            syntax::TemplateArgument::Identifier(path(value)?)
        }
    })
}

fn identifier(value: &wire::Identifier) -> Result<syntax::Identifier, ArtifactError> {
    syntax::Identifier::new(value.as_str()).ok_or_else(|| {
        ArtifactError::Invalid(format!(
            "wire identifier `{}` cannot be lowered",
            value.as_str()
        ))
    })
}

fn path(value: &wire::NonEmpty<wire::Identifier>) -> Result<syntax::IdentifierPath, ArtifactError> {
    syntax::IdentifierPath::new(
        value
            .as_slice()
            .iter()
            .map(identifier)
            .collect::<Result<_, _>>()?,
    )
    .ok_or_else(|| ArtifactError::Invalid("empty identifier path".into()))
}

fn builtin(value: wire::BuiltinType) -> syntax::BuiltinType {
    use syntax::BuiltinType as S;
    use wire::BuiltinType as W;
    match value {
        W::Void => S::Void,
        W::Bool => S::Bool,
        W::Char => S::Char,
        W::SignedChar => S::SignedChar,
        W::UnsignedChar => S::UnsignedChar,
        W::Short => S::Short,
        W::UnsignedShort => S::UnsignedShort,
        W::Int => S::Int,
        W::UnsignedInt => S::UnsignedInt,
        W::Long => S::Long,
        W::UnsignedLong => S::UnsignedLong,
        W::LongLong => S::LongLong,
        W::UnsignedLongLong => S::UnsignedLongLong,
        W::Int128 => S::Int128,
        W::UnsignedInt128 => S::UnsignedInt128,
        W::Float => S::Float,
        W::Double => S::Double,
        W::LongDouble => S::LongDouble,
    }
}

fn named_tag(value: wire::NamedTypeTag) -> syntax::NamedTypeTag {
    match value {
        wire::NamedTypeTag::Typedef => syntax::NamedTypeTag::Typedef,
        wire::NamedTypeTag::Struct => syntax::NamedTypeTag::Struct,
        wire::NamedTypeTag::Union => syntax::NamedTypeTag::Union,
        wire::NamedTypeTag::Enum => syntax::NamedTypeTag::Enum,
        wire::NamedTypeTag::Class => syntax::NamedTypeTag::Class,
        wire::NamedTypeTag::Protocol => syntax::NamedTypeTag::Protocol,
    }
}

fn record_kind(value: wire::RecordKind) -> syntax::RecordKind {
    match value {
        wire::RecordKind::Struct => syntax::RecordKind::Struct,
        wire::RecordKind::Union => syntax::RecordKind::Union,
        wire::RecordKind::Class => syntax::RecordKind::Class,
        wire::RecordKind::Enum => syntax::RecordKind::Enum,
    }
}

fn storage_class(value: wire::StorageClass) -> syntax::StorageClass {
    match value {
        wire::StorageClass::None => syntax::StorageClass::None,
        wire::StorageClass::Extern => syntax::StorageClass::Extern,
        wire::StorageClass::Static => syntax::StorageClass::Static,
        wire::StorageClass::ThreadLocal => syntax::StorageClass::ThreadLocal,
    }
}

fn linkage_kind(value: wire::HeaderLinkage) -> syntax::Linkage {
    match value {
        wire::HeaderLinkage::C => syntax::Linkage::C,
        wire::HeaderLinkage::Cpp => syntax::Linkage::Cpp,
        wire::HeaderLinkage::Objc => syntax::Linkage::ObjectiveC,
    }
}

fn access(value: wire::Access) -> syntax::Access {
    match value {
        wire::Access::Public => syntax::Access::Public,
        wire::Access::Protected => syntax::Access::Protected,
        wire::Access::Private => syntax::Access::Private,
        wire::Access::Unspecified => syntax::Access::Unspecified,
    }
}

fn objc_access(value: wire::ObjCAccess) -> syntax::ObjectiveCAccess {
    match value {
        wire::ObjCAccess::Public => syntax::ObjectiveCAccess::Public,
        wire::ObjCAccess::Protected => syntax::ObjectiveCAccess::Protected,
        wire::ObjCAccess::Private => syntax::ObjectiveCAccess::Private,
        wire::ObjCAccess::Package => syntax::ObjectiveCAccess::Package,
    }
}

fn reference_kind(value: wire::ReferenceKind) -> syntax::ReferenceKind {
    match value {
        wire::ReferenceKind::Lvalue => syntax::ReferenceKind::Lvalue,
        wire::ReferenceKind::Rvalue => syntax::ReferenceKind::Rvalue,
    }
}

fn calling_convention(value: wire::CallingConvention) -> syntax::CallingConvention {
    match value {
        wire::CallingConvention::C => syntax::CallingConvention::C,
        wire::CallingConvention::Swift => syntax::CallingConvention::Swift,
        wire::CallingConvention::ObjcMethod => syntax::CallingConvention::ObjectiveCMethod,
        wire::CallingConvention::Thiscall => syntax::CallingConvention::Thiscall,
        wire::CallingConvention::Vectorcall => syntax::CallingConvention::Vectorcall,
        wire::CallingConvention::Aapcs => syntax::CallingConvention::Aapcs,
        wire::CallingConvention::AapcsVfp => syntax::CallingConvention::AapcsVfp,
        wire::CallingConvention::Unknown => syntax::CallingConvention::Unknown,
    }
}

fn type_qualifiers(value: wire::TypeQualifiers) -> syntax::TypeQualifiers {
    syntax::TypeQualifiers {
        is_const: value.is_const,
        is_volatile: value.is_volatile,
        is_restrict: value.is_restrict,
    }
}

fn function_qualifiers(value: wire::HeaderFunctionQualifiers) -> syntax::FunctionQualifiers {
    syntax::FunctionQualifiers {
        is_const: value.is_const,
        is_volatile: value.is_volatile,
        reference: value.reference.map(reference_kind),
        noexcept: value.noexcept,
    }
}

fn objc_property(value: wire::ObjCPropertyAttribute) -> syntax::ObjectiveCPropertyAttribute {
    use syntax::ObjectiveCPropertyAttribute as S;
    use wire::ObjCPropertyAttribute as W;
    match value {
        W::Readonly => S::Readonly,
        W::Readwrite => S::Readwrite,
        W::Copy => S::Copy,
        W::Retain => S::Retain,
        W::Strong => S::Strong,
        W::Weak => S::Weak,
        W::Assign => S::Assign,
        W::Atomic => S::Atomic,
        W::Nonatomic => S::Nonatomic,
        W::Dynamic => S::Dynamic,
        W::Class => S::Class,
    }
}
