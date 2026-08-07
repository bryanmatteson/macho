use swift_demangler::raw::{Node, NodeKind};
use swift_demangler::{
    Accessor, AccessorKind, AsyncSymbol, AsyncSymbolKind, Closure, ContextComponent, Destructor,
    DestructorKind, Function, FunctionConvention, HasFunctionSignature, HasGenericSignature,
    HasModule, ImplFunctionType, ReabstractionThunk, SpecializationKind, SpecializedSymbol, Symbol,
    Thunk, TypeKind, TypeRef,
};

use super::model::*;

type ManglingError = (SwiftManglingGap, String);
type FunctionContext = (
    Vec<SwiftDeclarationPathComponent>,
    Option<SwiftTypeDeclaration>,
    SwiftCallableKind,
);
type AccessorContext = (
    Vec<SwiftDeclarationPathComponent>,
    Option<SwiftTypeDeclaration>,
);
type DeclarationContext = (
    Vec<SwiftDeclarationPathComponent>,
    Option<SwiftTypeDeclaration>,
    Option<SwiftTypeDeclarationKind>,
);

pub(super) fn specialization_entity(
    symbol: SpecializedSymbol<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    let specialization = symbol.specialization;
    let role = match specialization.kind() {
        SpecializationKind::Prespecialized => SwiftCallableVariantRole::Prespecialization,
        SpecializationKind::Generic
        | SpecializationKind::GenericNotReAbstracted
        | SpecializationKind::GenericInResilienceDomain
        | SpecializationKind::Partial
        | SpecializationKind::PartialNotReAbstracted => SwiftCallableVariantRole::Specialization,
        SpecializationKind::FunctionSignature | SpecializationKind::Other => {
            return Err((
                SwiftManglingGap::UnsupportedRepresentation,
                "Swift function-signature specialization transform is not structurally admitted"
                    .into(),
            ));
        }
    };
    let substitutions = specialization
        .type_arguments()
        .into_iter()
        .map(|argument| convert_type(argument, limits))
        .collect::<Result<Vec<_>, _>>()?;
    if substitutions.is_empty() {
        return Err((
            SwiftManglingGap::UnsupportedRepresentation,
            "Swift generic specialization has no represented substitutions".into(),
        ));
    }
    let Symbol::Function(function) = *symbol.inner else {
        return Err((
            SwiftManglingGap::UnsupportedNode,
            "Swift specialization does not wrap an admitted function".into(),
        ));
    };
    let mut ast = function_entity(function, limits)?;
    ast.variant_role = Some(role);
    ast.specialization = Some(SwiftSpecializationEvidence {
        substitutions,
        pass_id: specialization.pass_id().map(|value| value.to_string()),
    });
    Ok(ast)
}

pub(super) fn thunk_entity(
    symbol: Thunk<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    match symbol {
        Thunk::Dispatch { inner, .. } => {
            let Symbol::Function(function) = *inner else {
                return Err((
                    SwiftManglingGap::UnsupportedNode,
                    "Swift dispatch thunk does not wrap an admitted function".into(),
                ));
            };
            let mut ast = function_entity(function, limits)?;
            ast.variant_role = Some(SwiftCallableVariantRole::DispatchThunk);
            Ok(ast)
        }
        Thunk::Reabstraction(thunk) => reabstraction_entity(thunk, limits),
        Thunk::PartialApply { inner, is_objc, .. } => {
            let inner = inner.ok_or_else(|| {
                (
                    SwiftManglingGap::UnsupportedNode,
                    "Swift partial-apply forwarder has no callable target".into(),
                )
            })?;
            let mut ast = match *inner {
                Symbol::Function(function) => function_entity(function, limits),
                Symbol::Closure(closure) => closure_entity(closure, limits),
                Symbol::Accessor(accessor) => accessor_entity(accessor, limits),
                Symbol::Destructor(destructor) => destructor_entity(destructor, limits),
                _ => Err((
                    SwiftManglingGap::UnsupportedNode,
                    "Swift partial-apply target is not an admitted callable".into(),
                )),
            }?;
            ast.variant_role = Some(if is_objc {
                SwiftCallableVariantRole::PartialApplyObjcForwarder
            } else {
                SwiftCallableVariantRole::PartialApplyForwarder
            });
            Ok(ast)
        }
        _ => Err((
            SwiftManglingGap::UnsupportedNode,
            "Swift thunk kind is not structurally admitted".into(),
        )),
    }
}

pub(super) fn closure_entity(
    closure: Closure<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    if closure
        .generic_signature()
        .is_some_and(|signature| !signature.requirements().is_empty())
    {
        return Err((
            SwiftManglingGap::UnsupportedRequirement,
            "generic closure requirements are not yet admitted".into(),
        ));
    }
    let module = required_text(closure.module(), "closure module", limits)?;
    let (declaration_path, declaration, _) =
        declaration_context(closure.parent_context().components(), &module, limits)?;
    let signature = closure.signature().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedRepresentation,
            "closure has no complete formal signature".into(),
        )
    })?;
    let parameters = signature
        .parameters()
        .into_iter()
        .map(|parameter| {
            Ok(SwiftFormalParameter {
                label: parameter.label.map(str::to_owned),
                r#type: convert_type(parameter.type_ref, limits)?,
                variadic: parameter.is_variadic,
            })
        })
        .collect::<Result<Vec<_>, ManglingError>>()?;
    let result = signature.return_type().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedRepresentation,
            "closure result type is absent".into(),
        )
    })?;
    Ok(SwiftMangledEntityEvidence {
        module,
        declaration_path,
        declaration,
        callable_kind: Some(SwiftCallableKind::Closure),
        base_name: Some(format!("$closure{}", closure.index().unwrap_or(0))),
        formal_type: Some(SwiftFormalTypeEvidence {
            representation: representation(signature.convention(), false),
            parameters,
            result: convert_type(result, limits)?,
            r#async: signature.is_async(),
            throwing: signature.is_throwing(),
        }),
        generic_requirements: Vec::new(),
        variant_role: Some(if signature.is_async() {
            SwiftCallableVariantRole::AsyncEntry
        } else {
            SwiftCallableVariantRole::DirectEntry
        }),
        specialization: None,
    })
}

pub(super) fn reabstraction_entity(
    thunk: ReabstractionThunk<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    if thunk
        .generic_signature()
        .is_some_and(|signature| !signature.requirements().is_empty())
    {
        return Err((
            SwiftManglingGap::UnsupportedRequirement,
            "generic reabstraction requirements are not yet admitted".into(),
        ));
    }
    let module = required_text(thunk.module(), "reabstraction type module", limits)?;
    let target = thunk.target().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedRepresentation,
            "Swift reabstraction thunk has no target function type".into(),
        )
    })?;
    let TypeKind::ImplFunction(target) = target.kind() else {
        return Err((
            SwiftManglingGap::UnsupportedRepresentation,
            "Swift reabstraction target is not an implementation function type".into(),
        ));
    };
    Ok(SwiftMangledEntityEvidence {
        module,
        declaration_path: Vec::new(),
        declaration: None,
        callable_kind: Some(SwiftCallableKind::Closure),
        base_name: Some("$reabstraction".into()),
        formal_type: Some(impl_function_formal_type(target, limits)?),
        generic_requirements: Vec::new(),
        variant_role: Some(SwiftCallableVariantRole::ReabstractionThunk),
        specialization: None,
    })
}

pub(super) fn impl_function_formal_type(
    function: ImplFunctionType<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftFormalTypeEvidence, ManglingError> {
    if function.generic_signature().is_some() || !function.substitutions().is_empty() {
        return Err((
            SwiftManglingGap::UnsupportedRequirement,
            "generic implementation-function transforms are not yet admitted".into(),
        ));
    }
    let parameters = function
        .parameters()
        .into_iter()
        .map(|parameter| {
            let r#type = parameter.type_ref().ok_or_else(|| {
                (
                    SwiftManglingGap::UnsupportedRepresentation,
                    "Swift implementation-function parameter has no type".into(),
                )
            })?;
            Ok(SwiftFormalParameter {
                label: None,
                r#type: convert_type(r#type, limits)?,
                variadic: false,
            })
        })
        .collect::<Result<Vec<_>, ManglingError>>()?;
    let results = function
        .results()
        .into_iter()
        .map(|result| {
            result.type_ref().ok_or_else(|| {
                (
                    SwiftManglingGap::UnsupportedRepresentation,
                    "Swift implementation-function result has no type".into(),
                )
            })
        })
        .map(|result| result.and_then(|result| convert_type(result, limits)))
        .collect::<Result<Vec<_>, ManglingError>>()?;
    let result = match results.as_slice() {
        [] => SwiftTypeEvidence::Tuple {
            elements: Vec::new(),
        },
        [result] => result.clone(),
        _ => SwiftTypeEvidence::Tuple {
            elements: results
                .into_iter()
                .map(|r#type| SwiftTupleElement {
                    label: None,
                    r#type,
                })
                .collect(),
        },
    };
    Ok(SwiftFormalTypeEvidence {
        representation: SwiftFunctionRepresentation::Thick,
        parameters,
        result,
        r#async: false,
        throwing: function.error_result().is_some(),
    })
}

pub(super) fn async_symbol_entity(
    symbol: AsyncSymbol<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    if !matches!(
        symbol.kind(),
        AsyncSymbolKind::AwaitResumePartial | AsyncSymbolKind::SuspendResumePartial
    ) {
        return Err((
            SwiftManglingGap::UnsupportedNode,
            "Swift async pointer marker is not an executable continuation".into(),
        ));
    }
    let function = symbol.inner_function().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedNode,
            "Swift async continuation has no inner function".into(),
        )
    })?;
    let mut ast = function_entity(function, limits)?;
    ast.variant_role = Some(SwiftCallableVariantRole::AsyncResume);
    Ok(ast)
}

pub(super) fn destructor_entity(
    destructor: Destructor<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    let module = required_text(destructor.module(), "destructor module", limits)?;
    let (declaration_path, declaration, declaration_kind) =
        declaration_context(destructor.context().components(), &module, limits)?;
    if declaration_kind != Some(SwiftTypeDeclarationKind::Class) {
        return Err((
            SwiftManglingGap::UnsupportedRepresentation,
            "Swift destructor does not belong to a class declaration".into(),
        ));
    }
    let role = match destructor.kind() {
        DestructorKind::Regular => SwiftCallableVariantRole::DestroyingDeallocator,
        DestructorKind::Deallocating | DestructorKind::IsolatedDeallocating => {
            SwiftCallableVariantRole::DeallocatingDeallocator
        }
    };
    Ok(SwiftMangledEntityEvidence {
        module,
        declaration_path,
        declaration,
        callable_kind: Some(SwiftCallableKind::Deinitializer),
        base_name: Some("deinit".into()),
        formal_type: Some(SwiftFormalTypeEvidence {
            representation: SwiftFunctionRepresentation::Method,
            parameters: Vec::new(),
            result: SwiftTypeEvidence::Tuple {
                elements: Vec::new(),
            },
            r#async: false,
            throwing: false,
        }),
        generic_requirements: Vec::new(),
        variant_role: Some(role),
        specialization: None,
    })
}

pub(super) fn accessor_entity(
    accessor: Accessor<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, ManglingError> {
    if accessor.generic_signature().is_some() {
        return Err((
            SwiftManglingGap::UnsupportedRequirement,
            "generic accessor requirements are not yet admitted".into(),
        ));
    }
    let (callable_kind, role) = match (accessor.kind(), accessor.is_subscript()) {
        (AccessorKind::Getter, false) => (
            SwiftCallableKind::PropertyGet,
            SwiftCallableVariantRole::DirectEntry,
        ),
        (AccessorKind::Getter | AccessorKind::Subscript, true) => (
            SwiftCallableKind::SubscriptGet,
            SwiftCallableVariantRole::DirectEntry,
        ),
        (AccessorKind::Read, false) => (
            SwiftCallableKind::PropertyRead,
            SwiftCallableVariantRole::CoroutineEntry,
        ),
        (AccessorKind::Modify, false) => (
            SwiftCallableKind::PropertyModify,
            SwiftCallableVariantRole::CoroutineEntry,
        ),
        _ => {
            return Err((
                SwiftManglingGap::UnsupportedNode,
                format!(
                    "Swift accessor kind `{}` is retained but not yet typed",
                    accessor.kind().name()
                ),
            ));
        }
    };
    let module = required_text(accessor.module(), "accessor module", limits)?;
    let base_name = required_text(accessor.property_name(), "accessor property name", limits)?;
    let property_type = accessor.property_type().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedRepresentation,
            "accessor property type is absent".into(),
        )
    })?;
    let (declaration_path, declaration) = accessor_context(accessor, &module, limits)?;
    let representation = if declaration.is_some() {
        SwiftFunctionRepresentation::Method
    } else {
        SwiftFunctionRepresentation::Thin
    };
    Ok(SwiftMangledEntityEvidence {
        module,
        declaration_path,
        declaration,
        callable_kind: Some(callable_kind),
        base_name: Some(base_name),
        formal_type: Some(SwiftFormalTypeEvidence {
            representation,
            parameters: Vec::new(),
            result: convert_type(property_type, limits)?,
            r#async: false,
            throwing: false,
        }),
        generic_requirements: Vec::new(),
        variant_role: Some(role),
        specialization: None,
    })
}

pub(super) fn accessor_context(
    accessor: Accessor<'_>,
    module: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<AccessorContext, ManglingError> {
    let (path, declaration, _) =
        declaration_context(accessor.context().components(), module, limits)?;
    if declaration.is_some() {
        return Ok((path, declaration));
    }
    let Some(containing_type) = accessor.containing_type() else {
        return Ok((path, None));
    };
    let names = containing_type.split('.').collect::<Vec<_>>();
    if names.is_empty() || names.len() as u64 > limits.max_context_depth {
        return Err((
            SwiftManglingGap::TypeAstDepthExceeded,
            "accessor declaration context depth exceeds the selected limit".into(),
        ));
    }
    for name in &names {
        required_text(Some(name), "accessor declaration context", limits)?;
    }
    let innermost = *names.last().expect("nonempty accessor context");
    let declaration_kind = accessor
        .raw()
        .descendants()
        .find_map(|node| {
            let kind = match node.kind() {
                NodeKind::Class => SwiftTypeDeclarationKind::Class,
                NodeKind::Structure => SwiftTypeDeclarationKind::Struct,
                NodeKind::Enum => SwiftTypeDeclarationKind::Enum,
                NodeKind::Protocol => SwiftTypeDeclarationKind::Protocol,
                NodeKind::TypeAlias => SwiftTypeDeclarationKind::TypeAlias,
                _ => return None,
            };
            node.children()
                .find(|child| child.kind() == NodeKind::Identifier)
                .and_then(|identifier| identifier.text())
                .filter(|name| *name == innermost)
                .map(|_| kind)
        })
        .ok_or_else(|| {
            (
                SwiftManglingGap::UnsupportedNode,
                "accessor containing declaration kind is unavailable".into(),
            )
        })?;
    let path = names
        .into_iter()
        .map(|value| SwiftDeclarationPathComponent::Identifier {
            value: value.to_owned(),
        })
        .collect::<Vec<_>>();
    Ok((
        path.clone(),
        Some(SwiftTypeDeclaration {
            module: module.to_owned(),
            declaration_path: path,
            kind: declaration_kind,
        }),
    ))
}

pub(super) fn function_entity(
    function: Function<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftMangledEntityEvidence, (SwiftManglingGap, String)> {
    if function
        .generic_signature()
        .is_some_and(|signature| !signature.requirements().is_empty())
    {
        return Err((
            SwiftManglingGap::UnsupportedRequirement,
            "generic function requirements are not yet admitted".into(),
        ));
    }
    let module = required_text(function.module(), "function module", limits)?;
    let (declaration_path, declaration, callable_kind) =
        function_context(function, &module, limits)?;
    let base_name = required_text(function.name(), "function base name", limits)?;
    let signature = function.signature().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedRepresentation,
            "function has no complete formal signature".into(),
        )
    })?;
    let labels = function.labels();
    let representation = representation(signature.convention(), function.is_method());
    let parameters = signature
        .parameters()
        .into_iter()
        .enumerate()
        .map(|(index, parameter)| {
            Ok(SwiftFormalParameter {
                label: labels
                    .get(index)
                    .copied()
                    .flatten()
                    .or(parameter.label)
                    .map(str::to_owned),
                r#type: convert_type(parameter.type_ref, limits)?,
                variadic: parameter.is_variadic,
            })
        })
        .collect::<Result<Vec<_>, (SwiftManglingGap, String)>>()?;
    let result = signature.return_type().ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedRepresentation,
            "function result type is absent".into(),
        )
    })?;
    Ok(SwiftMangledEntityEvidence {
        module,
        declaration_path,
        declaration,
        callable_kind: Some(callable_kind),
        base_name: Some(base_name),
        formal_type: Some(SwiftFormalTypeEvidence {
            representation,
            parameters,
            result: convert_type(result, limits)?,
            r#async: signature.is_async(),
            throwing: signature.is_throwing(),
        }),
        generic_requirements: Vec::new(),
        variant_role: Some(if signature.is_async() {
            SwiftCallableVariantRole::AsyncEntry
        } else {
            SwiftCallableVariantRole::DirectEntry
        }),
        specialization: None,
    })
}

pub(super) fn function_context(
    function: Function<'_>,
    module: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<FunctionContext, ManglingError> {
    let (path, declaration, last_kind) =
        declaration_context(function.context().components(), module, limits)?;
    let callable_kind = if declaration.is_none() {
        SwiftCallableKind::Function
    } else if function.is_static() {
        if last_kind == Some(SwiftTypeDeclarationKind::Class) {
            SwiftCallableKind::ClassMethod
        } else {
            SwiftCallableKind::StaticMethod
        }
    } else {
        SwiftCallableKind::InstanceMethod
    };
    Ok((path, declaration, callable_kind))
}

pub(super) fn declaration_context<'ctx>(
    components: impl IntoIterator<Item = ContextComponent<'ctx>>,
    module: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<DeclarationContext, ManglingError> {
    let mut path = Vec::new();
    let mut last_kind = None;
    for component in components {
        let (name, kind) = match component {
            ContextComponent::Module(_) => continue,
            ContextComponent::Class { name, .. } => (name, SwiftTypeDeclarationKind::Class),
            ContextComponent::Struct { name, .. } => (name, SwiftTypeDeclarationKind::Struct),
            ContextComponent::Enum { name, .. } => (name, SwiftTypeDeclarationKind::Enum),
            ContextComponent::Protocol { name, .. } => (name, SwiftTypeDeclarationKind::Protocol),
            ContextComponent::TypeAlias { name, .. } => (name, SwiftTypeDeclarationKind::TypeAlias),
            ContextComponent::Extension { base, .. } => (base.name(), component_kind(&base)?),
            ContextComponent::Other(_) => {
                return Err((
                    SwiftManglingGap::UnsupportedNode,
                    "unsupported declaration context component".into(),
                ));
            }
        };
        required_text(Some(name), "declaration context", limits)?;
        path.push(SwiftDeclarationPathComponent::Identifier {
            value: name.to_owned(),
        });
        last_kind = Some(kind);
    }
    if path.len() as u64 > limits.max_context_depth {
        return Err((
            SwiftManglingGap::TypeAstDepthExceeded,
            "declaration context depth exceeds the selected limit".into(),
        ));
    }
    let declaration = last_kind.map(|kind| SwiftTypeDeclaration {
        module: module.to_owned(),
        declaration_path: path.clone(),
        kind,
    });
    Ok((path, declaration, last_kind))
}

pub(super) fn component_kind(
    component: &ContextComponent<'_>,
) -> Result<SwiftTypeDeclarationKind, (SwiftManglingGap, String)> {
    match component {
        ContextComponent::Class { .. } => Ok(SwiftTypeDeclarationKind::Class),
        ContextComponent::Struct { .. } => Ok(SwiftTypeDeclarationKind::Struct),
        ContextComponent::Enum { .. } => Ok(SwiftTypeDeclarationKind::Enum),
        ContextComponent::Protocol { .. } => Ok(SwiftTypeDeclarationKind::Protocol),
        ContextComponent::TypeAlias { .. } => Ok(SwiftTypeDeclarationKind::TypeAlias),
        _ => Err((
            SwiftManglingGap::UnsupportedNode,
            "extension base is not a nominal declaration".into(),
        )),
    }
}

pub(super) fn representation(
    convention: FunctionConvention,
    method: bool,
) -> SwiftFunctionRepresentation {
    match convention {
        FunctionConvention::Swift if method => SwiftFunctionRepresentation::Method,
        FunctionConvention::Swift => SwiftFunctionRepresentation::Thick,
        FunctionConvention::C => SwiftFunctionRepresentation::CFunction,
        FunctionConvention::Block => SwiftFunctionRepresentation::Block,
        FunctionConvention::Thin => SwiftFunctionRepresentation::Thin,
    }
}

pub(super) fn convert_type(
    value: TypeRef<'_>,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<SwiftTypeEvidence, (SwiftManglingGap, String)> {
    match value.kind() {
        TypeKind::Named(named) => {
            let module = required_text(named.module(), "nominal type module", limits)?;
            let name = required_text(named.name(), "nominal type name", limits)?;
            let kind = nominal_kind(named.raw().kind())?;
            let arguments = named
                .generic_args()
                .into_iter()
                .map(|argument| convert_type(argument, limits))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(SwiftTypeEvidence::Nominal {
                declaration: SwiftTypeDeclaration {
                    module,
                    declaration_path: vec![SwiftDeclarationPathComponent::Identifier {
                        value: name,
                    }],
                    kind,
                },
                arguments,
            })
        }
        TypeKind::GenericParam { depth, index } => {
            Ok(SwiftTypeEvidence::GenericParameter { depth, index })
        }
        TypeKind::AssociatedType { base, name } => Ok(SwiftTypeEvidence::DependentMember {
            base: Box::new(convert_type(*base, limits)?),
            member: required_text(name, "dependent member", limits)?,
            protocol: None,
        }),
        TypeKind::Tuple(elements) => Ok(SwiftTypeEvidence::Tuple {
            elements: elements
                .into_iter()
                .map(|element| {
                    Ok(SwiftTupleElement {
                        label: element.label().map(str::to_owned),
                        r#type: convert_type(element.type_ref(), limits)?,
                    })
                })
                .collect::<Result<Vec<_>, (SwiftManglingGap, String)>>()?,
        }),
        TypeKind::Function(function) => {
            let parameters = function
                .parameters()
                .into_iter()
                .map(|parameter| {
                    Ok(SwiftFormalParameter {
                        label: parameter.label.map(str::to_owned),
                        r#type: convert_type(parameter.type_ref, limits)?,
                        variadic: parameter.is_variadic,
                    })
                })
                .collect::<Result<Vec<_>, (SwiftManglingGap, String)>>()?;
            let result = function.return_type().ok_or_else(|| {
                (
                    SwiftManglingGap::UnsupportedRepresentation,
                    "nested function result type is absent".into(),
                )
            })?;
            Ok(SwiftTypeEvidence::Function {
                representation: representation(function.convention(), false),
                parameters,
                result: Box::new(convert_type(result, limits)?),
                r#async: function.is_async(),
                throwing: function.is_throwing(),
            })
        }
        TypeKind::Metatype(instance) => Ok(SwiftTypeEvidence::Metatype {
            representation: metatype_representation(value.raw()),
            instance: Box::new(convert_type(*instance, limits)?),
        }),
        TypeKind::Existential(protocols) => {
            let mut declarations = protocols
                .into_iter()
                .map(|protocol| match convert_type(protocol, limits)? {
                    SwiftTypeEvidence::Nominal {
                        declaration,
                        arguments,
                    } if arguments.is_empty() => Ok(declaration),
                    _ => Err((
                        SwiftManglingGap::UnsupportedRepresentation,
                        "existential member is not a plain nominal protocol".into(),
                    )),
                })
                .collect::<Result<Vec<_>, (SwiftManglingGap, String)>>()?;
            declarations.sort();
            declarations.dedup();
            Ok(SwiftTypeEvidence::Existential {
                protocols: declarations,
                superclass: None,
                class_constraint: false,
            })
        }
        TypeKind::Any => Ok(SwiftTypeEvidence::Existential {
            protocols: Vec::new(),
            superclass: None,
            class_constraint: false,
        }),
        TypeKind::InOut(inner) => Ok(SwiftTypeEvidence::Inout {
            value: Box::new(convert_type(*inner, limits)?),
        }),
        TypeKind::Owned(inner) => Ok(SwiftTypeEvidence::Owned {
            value: Box::new(convert_type(*inner, limits)?),
        }),
        TypeKind::Shared(inner) => Ok(SwiftTypeEvidence::Shared {
            value: Box::new(convert_type(*inner, limits)?),
        }),
        TypeKind::Pack(elements) => Ok(SwiftTypeEvidence::Pack {
            elements: elements
                .into_iter()
                .map(|element| convert_type(element, limits))
                .collect::<Result<Vec<_>, _>>()?,
        }),
        TypeKind::Builtin(_) | TypeKind::BuiltinFixedArray { .. } => Err((
            SwiftManglingGap::UnsupportedBuiltin,
            "builtin type has no selected ABI profile atom".into(),
        )),
        TypeKind::ImplFunction(_) => Err((
            SwiftManglingGap::UnsupportedRepresentation,
            "SIL implementation function types are not admitted".into(),
        )),
        TypeKind::Optional(_)
        | TypeKind::Array(_)
        | TypeKind::Dictionary { .. }
        | TypeKind::Weak(_)
        | TypeKind::Unowned(_)
        | TypeKind::Sending(_)
        | TypeKind::Isolated(_)
        | TypeKind::NoDerivative(_)
        | TypeKind::ValueGeneric(_)
        | TypeKind::CompileTimeLiteral(_)
        | TypeKind::DynamicSelf(_)
        | TypeKind::ConstrainedExistential(_)
        | TypeKind::Opaque { .. }
        | TypeKind::Generic { .. }
        | TypeKind::Error
        | TypeKind::SILBox { .. }
        | TypeKind::Other(_) => Err((
            SwiftManglingGap::UnsupportedNode,
            "type node is outside the admitted typed subset".into(),
        )),
    }
}

pub(super) fn nominal_kind(
    kind: NodeKind,
) -> Result<SwiftTypeDeclarationKind, (SwiftManglingGap, String)> {
    match kind {
        NodeKind::Class | NodeKind::BoundGenericClass => Ok(SwiftTypeDeclarationKind::Class),
        NodeKind::Structure | NodeKind::BoundGenericStructure => {
            Ok(SwiftTypeDeclarationKind::Struct)
        }
        NodeKind::Enum | NodeKind::BoundGenericEnum => Ok(SwiftTypeDeclarationKind::Enum),
        NodeKind::Protocol | NodeKind::BoundGenericProtocol => {
            Ok(SwiftTypeDeclarationKind::Protocol)
        }
        NodeKind::TypeAlias | NodeKind::BoundGenericTypeAlias => {
            Ok(SwiftTypeDeclarationKind::TypeAlias)
        }
        _ => Err((
            SwiftManglingGap::UnsupportedNode,
            "nominal type kind is not admitted".into(),
        )),
    }
}

pub(super) fn metatype_representation(raw: Node<'_>) -> SwiftMetatypeRepresentation {
    let marker = raw
        .children()
        .find(|child| child.kind() == NodeKind::MetatypeRepresentation)
        .and_then(|child| child.text());
    match marker {
        Some("thin") => SwiftMetatypeRepresentation::Thin,
        Some("objc") => SwiftMetatypeRepresentation::Objc,
        _ => SwiftMetatypeRepresentation::Thick,
    }
}

pub(super) fn required_text(
    value: Option<&str>,
    subject: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<String, (SwiftManglingGap, String)> {
    let value = value.ok_or_else(|| {
        (
            SwiftManglingGap::UnsupportedNode,
            format!("{subject} is absent"),
        )
    })?;
    if value.is_empty()
        || value.len() as u64 > limits.max_identifier_bytes
        || value.chars().any(char::is_control)
    {
        return Err((
            SwiftManglingGap::UnsupportedNode,
            format!("{subject} is empty or invalid"),
        ));
    }
    Ok(value.to_owned())
}

pub(super) fn unsupported(
    raw: Vec<u8>,
    reason: SwiftManglingGap,
    safe_detail: impl Into<String>,
) -> SwiftManglingEvidence {
    SwiftManglingEvidence::Unsupported {
        raw,
        reason,
        safe_detail: safe_detail.into(),
    }
}
