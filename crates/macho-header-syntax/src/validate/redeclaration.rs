//! C, C++, and Objective-C redeclaration identity and compatibility.

use crate::{Decl, IdentifierPath, Language, RecordKind, StorageClass, Type};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Redeclaration {
    Compatible { replace: bool },
    Duplicate,
    Conflict,
}

pub(super) fn declaration_identity(language: Language, declaration: &Decl) -> Option<String> {
    match declaration {
        Decl::Function {
            name, signature, ..
        } if language == Language::Cpp => {
            Some(format!("function:{name}:{}", cpp_overload_key(signature)))
        }
        Decl::Function { name, .. } | Decl::Variable { name, .. } => {
            Some(format!("ordinary:{name}"))
        }
        Decl::Alias { path, .. } => Some(format!("ordinary:{}", path_string(path))),
        Decl::Record { path, .. } | Decl::Forward { path, .. } => {
            Some(format!("tag:{}", path_string(path)))
        }
        Decl::ObjectiveCInterface { name, .. } => Some(format!("objc-class:{name}")),
        Decl::ObjectiveCCategory {
            name,
            extended_class,
            ..
        } => Some(format!("objc-category:{extended_class}:{name}")),
        Decl::ObjectiveCProtocol { name, .. } => Some(format!("objc-protocol:{name}")),
        Decl::ObjectiveCForward { .. } => None,
    }
}

pub(super) fn redeclaration(language: Language, previous: &Decl, current: &Decl) -> Redeclaration {
    match (previous, current) {
        (
            Decl::Function {
                signature: left,
                storage: left_storage,
                linkage: left_linkage,
                ..
            },
            Decl::Function {
                signature: right,
                storage: right_storage,
                linkage: right_linkage,
                ..
            },
        ) if left_linkage == right_linkage
            && compatible_storage(*left_storage, *right_storage)
            && compatible_function_types(left, right) =>
        {
            Redeclaration::Compatible { replace: false }
        }
        (
            Decl::Variable {
                ty: left,
                storage: left_storage,
                linkage: left_linkage,
                ..
            },
            Decl::Variable {
                ty: right,
                storage: right_storage,
                linkage: right_linkage,
                ..
            },
        ) if left == right
            && left_linkage == right_linkage
            && compatible_storage(*left_storage, *right_storage) =>
        {
            Redeclaration::Compatible { replace: false }
        }
        (Decl::Alias { target: left, .. }, Decl::Alias { target: right, .. }) if left == right => {
            Redeclaration::Compatible { replace: false }
        }
        (
            Decl::Forward {
                kind: left_kind, ..
            },
            Decl::Forward {
                kind: right_kind, ..
            },
        ) if compatible_record_kinds(language, *left_kind, *right_kind) => {
            Redeclaration::Compatible { replace: false }
        }
        (
            Decl::Forward {
                kind: left_kind, ..
            },
            Decl::Record {
                kind: right_kind, ..
            },
        ) if compatible_record_kinds(language, *left_kind, *right_kind) => {
            Redeclaration::Compatible { replace: true }
        }
        (
            Decl::Record {
                kind: left_kind, ..
            },
            Decl::Forward {
                kind: right_kind, ..
            },
        ) if compatible_record_kinds(language, *left_kind, *right_kind) => {
            Redeclaration::Compatible { replace: false }
        }
        _ if previous == current => Redeclaration::Duplicate,
        _ => Redeclaration::Conflict,
    }
}

fn compatible_storage(left: StorageClass, right: StorageClass) -> bool {
    left == right
        || matches!(
            (left, right),
            (StorageClass::None, StorageClass::Extern) | (StorageClass::Extern, StorageClass::None)
        )
}

fn compatible_record_kinds(language: Language, left: RecordKind, right: RecordKind) -> bool {
    left == right
        || (language == Language::Cpp
            && matches!(
                (left, right),
                (RecordKind::Struct, RecordKind::Class) | (RecordKind::Class, RecordKind::Struct)
            ))
}

fn compatible_function_types(left: &Type, right: &Type) -> bool {
    let (
        Type::Function {
            return_type: left_return,
            parameters: left_parameters,
            parameter_state: left_state,
            variadic: left_variadic,
            calling_convention: left_calling_convention,
            qualifiers: left_qualifiers,
        },
        Type::Function {
            return_type: right_return,
            parameters: right_parameters,
            parameter_state: right_state,
            variadic: right_variadic,
            calling_convention: right_calling_convention,
            qualifiers: right_qualifiers,
        },
    ) = (left, right)
    else {
        return false;
    };
    left_return == right_return
        && left_state == right_state
        && left_variadic == right_variadic
        && left_calling_convention == right_calling_convention
        && left_qualifiers == right_qualifiers
        && left_parameters.len() == right_parameters.len()
        && left_parameters
            .iter()
            .zip(right_parameters)
            .all(|(left, right)| left.ty == right.ty)
}

fn cpp_overload_key(signature: &Type) -> String {
    let Type::Function {
        parameters,
        parameter_state,
        variadic,
        calling_convention,
        qualifiers,
        ..
    } = signature
    else {
        return format!("invalid:{signature:?}");
    };
    let parameter_types = parameters
        .iter()
        .map(|parameter| &parameter.ty)
        .collect::<Vec<_>>();
    format!(
        "{parameter_types:?}:{parameter_state:?}:{variadic}:{calling_convention:?}:{qualifiers:?}"
    )
}

fn path_string(path: &IdentifierPath) -> String {
    path.components()
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join("::")
}
