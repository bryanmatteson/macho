use sha2::{Digest, Sha256};

/// SHA-256 digest of exact mangling evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftEvidenceDigest([u8; 32]);

impl SwiftEvidenceDigest {
    /// Hash exact evidence bytes.
    #[must_use]
    pub fn of(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    /// Return the digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Bounded resources for one Swift mangling decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SwiftCallableEvidenceLimits {
    /// Maximum bytes in the authored mangling.
    pub max_mangling_bytes: u64,
    /// Maximum parser nodes.
    pub max_mangling_nodes: u64,
    /// Maximum bytes in one identifier.
    pub max_identifier_bytes: u64,
    /// Maximum declaration-context depth.
    pub max_context_depth: u64,
    /// Maximum converted type-AST depth.
    pub max_type_ast_depth: u64,
    /// Maximum converted type-AST nodes.
    pub max_type_ast_nodes: u64,
}

impl SwiftCallableEvidenceLimits {
    pub(super) fn validate(self) -> Result<(), String> {
        if self.max_mangling_bytes == 0
            || self.max_mangling_nodes == 0
            || self.max_identifier_bytes == 0
            || self.max_context_depth == 0
            || self.max_type_ast_depth == 0
            || self.max_type_ast_nodes == 0
        {
            return Err("Swift callable evidence limits must all be nonzero".into());
        }
        Ok(())
    }
}

/// Swift mangling family.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftManglingScheme {
    /// Stable `$s`/`$S` mangling.
    StableSwift,
    /// Embedded Swift `$e` mangling.
    EmbeddedSwift,
    /// Legacy `_T` mangling.
    LegacySwift,
}

/// Stable reason that a mangling cannot enter the supported evidence arm.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftManglingGap {
    /// The mangling prefix is outside the admitted families.
    UnsupportedScheme,
    /// The parser produced an unsupported node.
    UnsupportedNode,
    /// The ABI representation is outside the admitted subset.
    UnsupportedRepresentation,
    /// A generic requirement is outside the admitted subset.
    UnsupportedRequirement,
    /// A builtin type is outside the admitted profile.
    UnsupportedBuiltin,
    /// The selected ABI profile does not admit the evidence.
    ProfileMismatch,
    /// Type evidence exceeds the selected depth.
    TypeAstDepthExceeded,
    /// Type or parser evidence exceeds the selected node count.
    TypeAstNodesExceeded,
}

/// Swift declaration kind carried by mangling evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftTypeDeclarationKind {
    /// Class.
    Class,
    /// Structure.
    Struct,
    /// Enumeration.
    Enum,
    /// Protocol.
    Protocol,
    /// Type alias.
    TypeAlias,
    /// Opaque declaration.
    Opaque,
    /// Objective-C class.
    ObjcClass,
}

/// One declaration-context component.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftDeclarationPathComponent {
    /// Named context.
    Identifier {
        /// Identifier spelling.
        value: String,
    },
    /// Private discriminator.
    PrivateContext {
        /// Digest of the private discriminator.
        discriminator_sha256: SwiftEvidenceDigest,
    },
    /// Local discriminator.
    LocalContext {
        /// Digest of the local discriminator.
        discriminator_sha256: SwiftEvidenceDigest,
    },
    /// Extension context.
    ExtensionContext {
        /// Module that defines the extension.
        defining_module: String,
        /// Digest of the extended declaration.
        extended_declaration_sha256: SwiftEvidenceDigest,
    },
}

/// Exact nominal declaration identity carried by the mangling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftTypeDeclaration {
    /// Declaring module.
    pub module: String,
    /// Nested declaration path.
    pub declaration_path: Vec<SwiftDeclarationPathComponent>,
    /// Nominal kind.
    pub kind: SwiftTypeDeclarationKind,
}

/// Callable kind carried by the mangling.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftCallableKind {
    /// Free function.
    Function,
    /// Instance method.
    InstanceMethod,
    /// Static method.
    StaticMethod,
    /// Class method.
    ClassMethod,
    /// Initializer.
    Initializer,
    /// Allocator.
    Allocator,
    /// Deinitializer.
    Deinitializer,
    /// Subscript getter.
    SubscriptGet,
    /// Subscript setter.
    SubscriptSet,
    /// Property getter.
    PropertyGet,
    /// Property setter.
    PropertySet,
    /// Property read coroutine.
    PropertyRead,
    /// Property modify coroutine.
    PropertyModify,
    /// Closure.
    Closure,
}

/// Physical callable role carried by the mangling.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftCallableVariantRole {
    /// Direct entry.
    DirectEntry,
    /// Class-vtable entry.
    ClassVtableEntry,
    /// Protocol-witness entry.
    ProtocolWitnessEntry,
    /// Dispatch thunk.
    DispatchThunk,
    /// Reabstraction thunk.
    ReabstractionThunk,
    /// Partial-apply forwarder for a native Swift closure context.
    PartialApplyForwarder,
    /// Partial-apply forwarder bridging an Objective-C block context.
    PartialApplyObjcForwarder,
    /// Specialization.
    Specialization,
    /// Prespecialization.
    Prespecialization,
    /// Async entry.
    AsyncEntry,
    /// Async resume.
    AsyncResume,
    /// Coroutine entry.
    CoroutineEntry,
    /// Coroutine resume.
    CoroutineResume,
    /// Destroying deallocator.
    DestroyingDeallocator,
    /// Deallocating deallocator.
    DeallocatingDeallocator,
    /// Dynamic replacement.
    DynamicReplacement,
    /// Metadata accessor.
    MetadataAccessor,
    /// Witness accessor.
    WitnessAccessor,
}

/// Physical closure or closure-adapter role encoded directly by a Swift symbol.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftClosureSymbolKind {
    /// Body entry for an explicit or implicit closure.
    ClosureEntry,
    /// Reabstraction thunk adapting one Swift closure representation to another.
    ReabstractionThunk,
    /// Partial-apply forwarder unpacking a native Swift closure context.
    PartialApplyForwarder,
    /// Partial-apply forwarder unpacking an Objective-C block context.
    PartialApplyObjcForwarder,
}

/// Bounded structural classification of a closure-related Swift linkage name.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SwiftClosureSymbolEvidence {
    /// Physical role carried by the mangling.
    pub kind: SwiftClosureSymbolKind,
    /// Process-free parser spelling.
    pub display: String,
}

/// Swift function representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftFunctionRepresentation {
    /// Thin.
    Thin,
    /// Thick Swift function.
    Thick,
    /// Method.
    Method,
    /// Witness method.
    WitnessMethod,
    /// C function.
    CFunction,
    /// Objective-C block.
    Block,
}

/// Swift metatype representation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftMetatypeRepresentation {
    /// Thick.
    Thick,
    /// Thin.
    Thin,
    /// Objective-C.
    Objc,
}

/// One tuple element.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftTupleElement {
    /// Optional label.
    pub label: Option<String>,
    /// Element type.
    pub r#type: SwiftTypeEvidence,
}

/// One formal parameter.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftFormalParameter {
    /// Optional label.
    pub label: Option<String>,
    /// Parameter type.
    pub r#type: SwiftTypeEvidence,
    /// Whether the parameter is variadic.
    pub variadic: bool,
}

/// Closed Swift type evidence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftTypeEvidence {
    /// Nominal type.
    Nominal {
        /// Nominal declaration.
        declaration: SwiftTypeDeclaration,
        /// Bound generic arguments.
        arguments: Vec<Self>,
    },
    /// Generic parameter.
    GenericParameter {
        /// Generic depth.
        depth: u64,
        /// Generic index.
        index: u64,
    },
    /// Dependent member.
    DependentMember {
        /// Base dependent type.
        base: Box<Self>,
        /// Member name.
        member: String,
        /// Optional protocol qualification.
        protocol: Option<SwiftTypeDeclaration>,
    },
    /// Tuple.
    Tuple {
        /// Tuple elements.
        elements: Vec<SwiftTupleElement>,
    },
    /// Function type.
    Function {
        /// Calling representation.
        representation: SwiftFunctionRepresentation,
        /// Formal parameters.
        parameters: Vec<SwiftFormalParameter>,
        /// Formal result.
        result: Box<Self>,
        /// Async marker.
        r#async: bool,
        /// Throwing marker.
        throwing: bool,
    },
    /// Metatype.
    Metatype {
        /// Metatype representation.
        representation: SwiftMetatypeRepresentation,
        /// Instance type.
        instance: Box<Self>,
    },
    /// Existential.
    Existential {
        /// Required protocols.
        protocols: Vec<SwiftTypeDeclaration>,
        /// Optional superclass constraint.
        superclass: Option<Box<Self>>,
        /// Class-only constraint.
        class_constraint: bool,
    },
    /// Inout value.
    Inout {
        /// Wrapped value.
        value: Box<Self>,
    },
    /// Owned value.
    Owned {
        /// Wrapped value.
        value: Box<Self>,
    },
    /// Shared value.
    Shared {
        /// Wrapped value.
        value: Box<Self>,
    },
    /// Type pack.
    Pack {
        /// Pack elements.
        elements: Vec<Self>,
    },
    /// Pack expansion.
    PackExpansion {
        /// Expansion pattern.
        pattern: Box<Self>,
    },
    /// Profile-defined builtin.
    Builtin {
        /// Profile-defined atom.
        profile_atom: String,
    },
}

/// Formal callable type evidence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftFormalTypeEvidence {
    /// Calling representation.
    pub representation: SwiftFunctionRepresentation,
    /// Formal parameters.
    pub parameters: Vec<SwiftFormalParameter>,
    /// Formal result.
    pub result: SwiftTypeEvidence,
    /// Async marker.
    pub r#async: bool,
    /// Throwing marker.
    pub throwing: bool,
}

/// Generic requirement evidence.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SwiftGenericRequirementEvidence {
    /// Protocol conformance.
    Conformance {
        /// Subject type.
        subject: SwiftTypeEvidence,
        /// Required protocol.
        protocol: SwiftTypeDeclaration,
    },
    /// Same-type relation.
    SameType {
        /// Left type.
        left: SwiftTypeEvidence,
        /// Right type.
        right: SwiftTypeEvidence,
    },
    /// Superclass relation.
    Superclass {
        /// Subject type.
        subject: SwiftTypeEvidence,
        /// Required superclass.
        superclass: SwiftTypeEvidence,
    },
    /// Same-shape relation.
    SameShape {
        /// Left type.
        left: SwiftTypeEvidence,
        /// Right type.
        right: SwiftTypeEvidence,
    },
}

/// Generic specialization evidence before product-specific canonicalization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftSpecializationEvidence {
    /// Converted substitution types.
    pub substitutions: Vec<SwiftTypeEvidence>,
    /// Optional compiler pass identifier.
    pub pass_id: Option<String>,
}

/// Owned typed entity recovered from one Swift mangling.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SwiftMangledEntityEvidence {
    /// Declaring module.
    pub module: String,
    /// Declaration path.
    pub declaration_path: Vec<SwiftDeclarationPathComponent>,
    /// Optional nominal owner.
    pub declaration: Option<SwiftTypeDeclaration>,
    /// Optional callable kind.
    pub callable_kind: Option<SwiftCallableKind>,
    /// Optional base name.
    pub base_name: Option<String>,
    /// Optional formal type.
    pub formal_type: Option<SwiftFormalTypeEvidence>,
    /// Generic requirements.
    pub generic_requirements: Vec<SwiftGenericRequirementEvidence>,
    /// Optional physical role.
    pub variant_role: Option<SwiftCallableVariantRole>,
    /// Optional specialization evidence.
    pub specialization: Option<SwiftSpecializationEvidence>,
}

/// Result of parsing one Swift-looking symbol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SwiftManglingEvidence {
    /// Fully supported owned evidence.
    Supported {
        /// Exact linkage bytes.
        raw: Vec<u8>,
        /// Mangling family.
        scheme: SwiftManglingScheme,
        /// Typed entity evidence.
        entity: Box<SwiftMangledEntityEvidence>,
        /// Process-free display spelling.
        display: String,
    },
    /// Well-formed but outside the admitted evidence subset.
    Unsupported {
        /// Exact linkage bytes.
        raw: Vec<u8>,
        /// Stable reason.
        reason: SwiftManglingGap,
        /// Bounded safe detail.
        safe_detail: String,
    },
    /// Parser rejection.
    Malformed {
        /// Exact linkage bytes.
        raw: Vec<u8>,
        /// Bounded diagnostic.
        diagnostic: String,
    },
}

pub(super) fn validate_entity(
    entity: &SwiftMangledEntityEvidence,
    limits: &SwiftCallableEvidenceLimits,
) -> Result<(), String> {
    limits.validate()?;
    if entity.module.is_empty() || entity.module.len() as u64 > limits.max_identifier_bytes {
        return Err("Swift mangling module is empty or oversized".into());
    }
    if entity.declaration_path.len() as u64 > limits.max_context_depth {
        return Err("Swift mangling context depth exceeds the selected limit".into());
    }
    let mut nodes = 0_u64;
    if let Some(formal) = &entity.formal_type {
        for parameter in &formal.parameters {
            validate_type(&parameter.r#type, 1, limits, &mut nodes)?;
        }
        validate_type(&formal.result, 1, limits, &mut nodes)?;
    }
    Ok(())
}

fn validate_type(
    value: &SwiftTypeEvidence,
    depth: u64,
    limits: &SwiftCallableEvidenceLimits,
    nodes: &mut u64,
) -> Result<(), String> {
    *nodes = nodes
        .checked_add(1)
        .ok_or_else(|| "Swift type AST node count overflowed".to_string())?;
    if depth > limits.max_type_ast_depth || *nodes > limits.max_type_ast_nodes {
        return Err("Swift type AST structural limit exceeded".into());
    }
    match value {
        SwiftTypeEvidence::Nominal { arguments, .. }
        | SwiftTypeEvidence::Pack {
            elements: arguments,
        } => {
            for child in arguments {
                validate_type(child, depth + 1, limits, nodes)?;
            }
        }
        SwiftTypeEvidence::DependentMember { base, .. }
        | SwiftTypeEvidence::Metatype { instance: base, .. }
        | SwiftTypeEvidence::Inout { value: base }
        | SwiftTypeEvidence::Owned { value: base }
        | SwiftTypeEvidence::Shared { value: base }
        | SwiftTypeEvidence::PackExpansion { pattern: base } => {
            validate_type(base, depth + 1, limits, nodes)?;
        }
        SwiftTypeEvidence::Tuple { elements } => {
            for element in elements {
                validate_type(&element.r#type, depth + 1, limits, nodes)?;
            }
        }
        SwiftTypeEvidence::Function {
            parameters, result, ..
        } => {
            for parameter in parameters {
                validate_type(&parameter.r#type, depth + 1, limits, nodes)?;
            }
            validate_type(result, depth + 1, limits, nodes)?;
        }
        SwiftTypeEvidence::Existential { superclass, .. } => {
            if let Some(superclass) = superclass {
                validate_type(superclass, depth + 1, limits, nodes)?;
            }
        }
        SwiftTypeEvidence::GenericParameter { .. } | SwiftTypeEvidence::Builtin { .. } => {}
    }
    Ok(())
}

/// Classify a Swift-looking linkage name and return the parser spelling.
#[must_use]
pub fn swift_mangling_scheme(raw: &str) -> Option<(SwiftManglingScheme, &str)> {
    let value = raw.strip_prefix('_').unwrap_or(raw);
    if value.starts_with("$s") || value.starts_with("$S") {
        Some((SwiftManglingScheme::StableSwift, value))
    } else if value.starts_with("$e") {
        Some((SwiftManglingScheme::EmbeddedSwift, value))
    } else if value.starts_with("_T") {
        Some((SwiftManglingScheme::LegacySwift, value))
    } else {
        None
    }
}
