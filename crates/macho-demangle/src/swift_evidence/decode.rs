use swift_demangler::raw::{Node, NodeKind};
use swift_demangler::{Context, Symbol, SymbolAttribute};

use super::convert::*;
use super::model::*;

/// Decode one Swift-looking linkage name into owned ABI evidence.
#[must_use]
pub fn decode_swift_mangling(
    raw: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> SwiftManglingEvidence {
    if let Err(error) = limits.validate() {
        return SwiftManglingEvidence::Malformed {
            raw: raw.as_bytes().to_vec(),
            diagnostic: error,
        };
    }
    let bytes = raw.as_bytes().to_vec();
    if bytes.len() as u64 > limits.max_mangling_bytes {
        return unsupported(
            bytes,
            SwiftManglingGap::TypeAstNodesExceeded,
            "mangling byte limit exceeded",
        );
    }
    let Some((scheme, parseable)) = swift_mangling_scheme(raw) else {
        return unsupported(
            bytes,
            SwiftManglingGap::UnsupportedScheme,
            "unrecognized Swift mangling scheme",
        );
    };
    let context = Context::new();
    let Some(root) = Node::parse(&context, parseable) else {
        return SwiftManglingEvidence::Malformed {
            raw: bytes,
            diagnostic: "in-process Swift demangler rejected the symbol".into(),
        };
    };
    let node_count = 1_u64.saturating_add(root.descendants().count() as u64);
    if node_count > limits.max_mangling_nodes {
        return unsupported(
            bytes,
            SwiftManglingGap::TypeAstNodesExceeded,
            "mangling node limit exceeded",
        );
    }
    let display = root.to_string();
    let dynamic_implementation = root
        .child(0)
        .is_some_and(|node| node.kind() == NodeKind::DynamicallyReplaceableFunctionImpl);
    let symbol = if dynamic_implementation {
        root.child(1).map(Symbol::classify_node)
    } else {
        Symbol::from_node(root)
    };
    let Some(symbol) = symbol else {
        return SwiftManglingEvidence::Malformed {
            raw: bytes,
            diagnostic: "Swift mangling root has no classifiable entity".into(),
        };
    };
    let mut ast = match symbol {
        Symbol::Function(function) => function_entity(function, limits),
        Symbol::Accessor(accessor) => accessor_entity(accessor, limits),
        Symbol::Destructor(destructor) => destructor_entity(destructor, limits),
        Symbol::Async(symbol) => async_symbol_entity(symbol, limits),
        Symbol::Specialization(symbol) => specialization_entity(symbol, limits),
        Symbol::Thunk(symbol) => thunk_entity(symbol, limits),
        Symbol::Suffixed(symbol) => {
            if !symbol.suffix.starts_with(".resume.") {
                Err((
                    SwiftManglingGap::UnsupportedNode,
                    "unrecognized Swift callable suffix".into(),
                ))
            } else if let Symbol::Accessor(accessor) = symbol.inner.as_ref() {
                match accessor_entity(*accessor, limits) {
                    Ok(mut ast)
                        if ast.variant_role == Some(SwiftCallableVariantRole::CoroutineEntry) =>
                    {
                        ast.variant_role = Some(SwiftCallableVariantRole::CoroutineResume);
                        Ok(ast)
                    }
                    Ok(_) => Err((
                        SwiftManglingGap::UnsupportedNode,
                        "resume suffix does not wrap a coroutine accessor".into(),
                    )),
                    Err(error) => Err(error),
                }
            } else {
                Err((
                    SwiftManglingGap::UnsupportedNode,
                    "resume suffix does not wrap an admitted accessor".into(),
                ))
            }
        }
        _ => Err((
            SwiftManglingGap::UnsupportedNode,
            "symbol is not an admitted function, accessor, destructor, thunk, specialization, or continuation"
                .into(),
        )),
    };
    let ast = match ast {
        Ok(ref mut ast) if dynamic_implementation => {
            ast.variant_role = Some(SwiftCallableVariantRole::DynamicReplacement);
            ast.clone()
        }
        Ok(ast) => ast,
        Err((reason, detail)) => return unsupported(bytes, reason, detail),
    };
    if let Err(error) = validate_entity(&ast, limits) {
        return unsupported(
            bytes,
            SwiftManglingGap::TypeAstNodesExceeded,
            error.to_string(),
        );
    }
    SwiftManglingEvidence::Supported {
        raw: bytes,
        scheme,
        entity: Box::new(ast),
        display,
    }
}

/// Decode the callable carried by an explicit Objective-C Swift attribute.
///
/// Returns `Ok(None)` for a non-Swift symbol or a Swift symbol without the
/// Objective-C attribute. Parser or supported-subset failures remain explicit.
pub fn decode_swift_objc_callable(
    raw: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<Option<SwiftMangledEntityEvidence>, String> {
    limits.validate()?;
    let Some((_, parseable)) = swift_mangling_scheme(raw) else {
        return Ok(None);
    };
    let context = Context::new();
    let root = Node::parse(&context, parseable)
        .ok_or_else(|| "in-process Swift demangler rejected the symbol".to_string())?;
    let mut symbol = Symbol::from_node(root)
        .ok_or_else(|| "Swift mangling root has no classifiable entity".to_string())?;
    let mut objc = false;
    loop {
        match symbol {
            Symbol::Attributed(attributed) => {
                objc |= attributed.attribute == SymbolAttribute::ObjC;
                symbol = *attributed.inner;
            }
            other => {
                symbol = other;
                break;
            }
        }
    }
    if !objc {
        return Ok(None);
    }
    let entity = match symbol {
        Symbol::Function(function) => function_entity(function, limits),
        Symbol::Accessor(accessor) => accessor_entity(accessor, limits),
        Symbol::Destructor(destructor) => destructor_entity(destructor, limits),
        _ => return Ok(None),
    }
    .map_err(|(_, detail)| detail)?;
    validate_entity(&entity, limits)?;
    Ok(Some(entity))
}

/// Decode the logical callable named by a dynamic-replacement marker.
///
/// `None` means that the symbol is not a dynamic-replacement marker. The
/// returned entity retains its ordinary role; callers may omit that role when
/// deriving a logical callable identity.
pub fn decode_swift_dynamic_replacement(
    raw: &str,
    limits: &SwiftCallableEvidenceLimits,
) -> Option<Result<SwiftMangledEntityEvidence, String>> {
    let (_, parseable) = swift_mangling_scheme(raw)?;
    if let Err(error) = limits.validate() {
        return Some(Err(error));
    }
    let context = Context::new();
    let root = match Node::parse(&context, parseable) {
        Some(root) => root,
        None => return Some(Err("in-process Swift demangler rejected the symbol".into())),
    };
    let marker = root.child(0)?;
    if !matches!(
        marker.kind(),
        NodeKind::DynamicallyReplaceableFunctionImpl
            | NodeKind::DynamicallyReplaceableFunctionKey
            | NodeKind::DynamicallyReplaceableFunctionVar
    ) {
        return None;
    }
    let Some(Symbol::Function(function)) = root.child(1).map(Symbol::classify_node) else {
        return Some(Err(
            "Swift dynamic-replacement marker has no function".into()
        ));
    };
    Some(
        function_entity(function, limits)
            .map_err(|(_, detail)| detail)
            .and_then(|entity| {
                validate_entity(&entity, limits)?;
                Ok(entity)
            }),
    )
}
