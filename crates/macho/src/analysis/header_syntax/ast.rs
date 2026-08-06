//! Typed header syntax.

use std::fmt;

/// The source language used to parse or render a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Language {
    /// ISO C syntax.
    C,
    /// C++ syntax.
    Cpp,
    /// Objective-C syntax.
    ObjectiveC,
}

/// A validated source-language identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Identifier(String);

impl Identifier {
    /// Creates an identifier when `value` follows C-family identifier rules.
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        let mut chars = value.chars();
        let first = chars.next()?;
        if !(first == '_' || first.is_ascii_alphabetic())
            || !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
        {
            return None;
        }
        Some(Self(value))
    }

    /// Borrows the identifier text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Identifier {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// A non-empty qualified identifier path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IdentifierPath(Vec<Identifier>);

impl IdentifierPath {
    /// Creates a non-empty identifier path.
    pub fn new(values: Vec<Identifier>) -> Option<Self> {
        (!values.is_empty()).then_some(Self(values))
    }

    /// Creates a path by splitting a C++ qualified name.
    pub fn parse(value: &str) -> Option<Self> {
        let values = value
            .trim()
            .trim_start_matches("::")
            .split("::")
            .map(str::trim)
            .map(Identifier::new)
            .collect::<Option<Vec<_>>>()?;
        Self::new(values)
    }

    /// Borrows the path components.
    pub fn components(&self) -> &[Identifier] {
        &self.0
    }

    /// Borrows the terminal identifier.
    pub fn last(&self) -> &Identifier {
        self.0.last().expect("IdentifierPath is non-empty")
    }
}

/// Built-in C-family scalar types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BuiltinType {
    /// `void`.
    Void,
    /// `bool` or `_Bool`.
    Bool,
    /// `char`.
    Char,
    /// `signed char`.
    SignedChar,
    /// `unsigned char`.
    UnsignedChar,
    /// `short`.
    Short,
    /// `unsigned short`.
    UnsignedShort,
    /// `int`.
    Int,
    /// `unsigned int`.
    UnsignedInt,
    /// `long`.
    Long,
    /// `unsigned long`.
    UnsignedLong,
    /// `long long`.
    LongLong,
    /// `unsigned long long`.
    UnsignedLongLong,
    /// Signed 128-bit integer.
    Int128,
    /// Unsigned 128-bit integer.
    UnsignedInt128,
    /// `float`.
    Float,
    /// `double`.
    Double,
    /// `long double`.
    LongDouble,
}

/// The namespace used to resolve a named type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NamedTypeTag {
    /// Typedef or ordinary named type.
    Typedef,
    /// C struct tag.
    Struct,
    /// C union tag.
    Union,
    /// Enumeration tag.
    Enum,
    /// C++ class name.
    Class,
    /// Objective-C protocol name.
    Protocol,
}

/// C/C++ type qualifiers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct TypeQualifiers {
    /// Whether `const` is present.
    pub is_const: bool,
    /// Whether `volatile` is present.
    pub is_volatile: bool,
    /// Whether `restrict` is present.
    pub is_restrict: bool,
}

/// C++ reference kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ReferenceKind {
    /// Lvalue reference (`&`).
    Lvalue,
    /// Rvalue reference (`&&`).
    Rvalue,
}

/// Whether a function's parameter list is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ParameterState {
    /// C's unspecified `()` parameter list.
    Unspecified,
    /// A known parameter list.
    Known,
}

/// Function calling convention.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CallingConvention {
    /// C ABI.
    C,
    /// Swift ABI.
    Swift,
    /// Objective-C method ABI.
    ObjectiveCMethod,
    /// Microsoft thiscall.
    Thiscall,
    /// Vectorcall.
    Vectorcall,
    /// ARM procedure call standard.
    Aapcs,
    /// ARM hard-float procedure call standard.
    AapcsVfp,
    /// An observed but unidentified convention.
    Unknown,
}

/// C++ function qualifiers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FunctionQualifiers {
    /// Whether the member function is `const`.
    pub is_const: bool,
    /// Whether the member function is `volatile`.
    pub is_volatile: bool,
    /// Optional reference qualifier.
    pub reference: Option<ReferenceKind>,
    /// `None` means the noexcept state is unknown.
    pub noexcept: Option<bool>,
}

/// A template argument.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TemplateArgument {
    /// Type argument.
    Type(Type),
    /// Integer non-type argument.
    Integer(i64),
    /// Identifier non-type argument.
    Identifier(IdentifierPath),
}

/// A named function parameter.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Parameter {
    /// Stable parameter name.
    pub name: Identifier,
    /// Parameter type.
    pub ty: Type,
}

/// A fully typed header type.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Type {
    /// Built-in scalar type.
    Builtin(BuiltinType),
    /// Named type.
    Named {
        /// Tag namespace.
        tag: NamedTypeTag,
        /// Qualified name.
        path: IdentifierPath,
        /// Template arguments.
        template_arguments: Vec<TemplateArgument>,
    },
    /// Pointer type.
    Pointer {
        /// Pointee type.
        pointee: Box<Type>,
        /// Pointer qualifiers.
        qualifiers: TypeQualifiers,
    },
    /// C++ reference type.
    Reference {
        /// Referenced type.
        target: Box<Type>,
        /// Reference category.
        kind: ReferenceKind,
    },
    /// Array type.
    Array {
        /// Element type.
        element: Box<Type>,
        /// Constant element count, when known.
        count: Option<u64>,
    },
    /// Function type.
    Function {
        /// Return type.
        return_type: Box<Type>,
        /// Parameters.
        parameters: Vec<Parameter>,
        /// Whether the parameter list is known.
        parameter_state: ParameterState,
        /// Whether the function is variadic.
        variadic: bool,
        /// Calling convention.
        calling_convention: CallingConvention,
        /// C++ function qualifiers.
        qualifiers: FunctionQualifiers,
    },
    /// Objective-C object pointer surface.
    ObjectiveCObject {
        /// Optional class name; absent represents `id`.
        name: Option<Identifier>,
        /// Protocol qualifications.
        protocols: Vec<Identifier>,
        /// Object-pointer qualifiers.
        qualifiers: TypeQualifiers,
    },
    /// Objective-C block signature.
    ObjectiveCBlock(Box<Type>),
}

/// Storage-class specifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StorageClass {
    /// No explicit storage class.
    None,
    /// `extern`.
    Extern,
    /// `static`.
    Static,
    /// Thread-local storage.
    ThreadLocal,
}

/// Language linkage attached to a declaration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Linkage {
    /// C linkage.
    C,
    /// C++ linkage.
    Cpp,
    /// Objective-C linkage.
    ObjectiveC,
}

/// Record declaration kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RecordKind {
    /// Struct.
    Struct,
    /// Union.
    Union,
    /// Class.
    Class,
    /// Enumeration.
    Enum,
}

/// Member access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Access {
    /// Public access.
    Public,
    /// Protected access.
    Protected,
    /// Private access.
    Private,
    /// Access was not stated.
    Unspecified,
}

/// A record base.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Base {
    /// Base type.
    pub ty: Type,
    /// Inheritance access.
    pub access: Access,
    /// Whether inheritance is virtual.
    pub is_virtual: bool,
}

/// A record field.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Field {
    /// Field name.
    pub name: Identifier,
    /// Field type.
    pub ty: Type,
    /// Byte offset when recovered.
    pub offset: Option<u64>,
    /// Bit-field width when applicable.
    pub bit_width: Option<u32>,
    /// Member access.
    pub access: Access,
}

/// Objective-C method kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MethodKind {
    /// Instance method (`-`).
    Instance,
    /// Class method (`+`).
    Class,
}

/// Objective-C method declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectiveCMethod {
    /// Instance or class method.
    pub kind: MethodKind,
    /// Complete selector spelling.
    pub selector: String,
    /// Return type.
    pub return_type: Type,
    /// Selector parameters.
    pub parameters: Vec<Parameter>,
    /// Required/optional state when declared in a protocol.
    pub required: Option<bool>,
}

/// Objective-C ivar visibility.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectiveCAccess {
    /// Public ivar.
    Public,
    /// Protected ivar.
    Protected,
    /// Private ivar.
    Private,
    /// Package-visible ivar.
    Package,
}

/// Objective-C instance-variable declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectiveCIvar {
    /// Ivar name.
    pub name: Identifier,
    /// Complete encoded type.
    pub ty: Type,
    /// Runtime visibility.
    pub access: ObjectiveCAccess,
}

/// Objective-C property attribute supported by the deterministic renderer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObjectiveCPropertyAttribute {
    /// Read-only property.
    Readonly,
    /// Read-write property.
    Readwrite,
    /// Copy ownership.
    Copy,
    /// Retain ownership.
    Retain,
    /// Strong ownership.
    Strong,
    /// Weak ownership.
    Weak,
    /// Assign ownership.
    Assign,
    /// Atomic property.
    Atomic,
    /// Non-atomic property.
    Nonatomic,
    /// Dynamically implemented property.
    Dynamic,
    /// Class property.
    Class,
}

/// Objective-C property declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ObjectiveCProperty {
    /// Property name.
    pub name: Identifier,
    /// Complete property type.
    pub ty: Type,
    /// Canonically ordered attributes.
    pub attributes: Vec<ObjectiveCPropertyAttribute>,
}

/// Objective-C forward-declaration kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjectiveCForwardKind {
    /// Class forward declaration.
    Class,
    /// Protocol forward declaration.
    Protocol,
}

/// A top-level typed declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Decl {
    /// Function declaration.
    Function {
        /// Name.
        name: Identifier,
        /// Function type.
        signature: Type,
        /// Storage class.
        storage: StorageClass,
        /// Language linkage.
        linkage: Linkage,
    },
    /// Variable declaration.
    Variable {
        /// Name.
        name: Identifier,
        /// Variable type.
        ty: Type,
        /// Storage class.
        storage: StorageClass,
        /// Language linkage.
        linkage: Linkage,
    },
    /// Complete record declaration.
    Record {
        /// Record kind.
        kind: RecordKind,
        /// Qualified name.
        path: IdentifierPath,
        /// Base classes.
        bases: Vec<Base>,
        /// Data fields.
        fields: Vec<Field>,
        /// Nested declarations.
        members: Vec<Decl>,
    },
    /// Incomplete record declaration.
    Forward {
        /// Record kind.
        kind: RecordKind,
        /// Qualified name.
        path: IdentifierPath,
    },
    /// Type alias.
    Alias {
        /// Alias name.
        path: IdentifierPath,
        /// Aliased type.
        target: Type,
    },
    /// Objective-C interface.
    ObjectiveCInterface {
        /// Class name.
        name: Identifier,
        /// Optional superclass.
        superclass: Option<Identifier>,
        /// Adopted protocols.
        protocols: Vec<Identifier>,
        /// Instance variables.
        ivars: Vec<ObjectiveCIvar>,
        /// Methods.
        methods: Vec<ObjectiveCMethod>,
        /// Properties.
        properties: Vec<ObjectiveCProperty>,
    },
    /// Objective-C category.
    ObjectiveCCategory {
        /// Category name.
        name: Identifier,
        /// Extended class.
        extended_class: Identifier,
        /// Adopted protocols.
        protocols: Vec<Identifier>,
        /// Methods.
        methods: Vec<ObjectiveCMethod>,
        /// Properties.
        properties: Vec<ObjectiveCProperty>,
    },
    /// Objective-C protocol.
    ObjectiveCProtocol {
        /// Protocol name.
        name: Identifier,
        /// Inherited protocols.
        protocols: Vec<Identifier>,
        /// Methods.
        methods: Vec<ObjectiveCMethod>,
        /// Properties.
        properties: Vec<ObjectiveCProperty>,
    },
    /// Objective-C forward declarations.
    ObjectiveCForward {
        /// Forward kind.
        kind: ObjectiveCForwardKind,
        /// Declared names.
        names: Vec<Identifier>,
    },
}

impl Decl {
    /// Returns the declaration's terminal name when it has one.
    pub fn name(&self) -> Option<&Identifier> {
        match self {
            Self::Function { name, .. }
            | Self::Variable { name, .. }
            | Self::ObjectiveCInterface { name, .. }
            | Self::ObjectiveCCategory { name, .. }
            | Self::ObjectiveCProtocol { name, .. } => Some(name),
            Self::Record { path, .. } | Self::Forward { path, .. } | Self::Alias { path, .. } => {
                Some(path.last())
            }
            Self::ObjectiveCForward { .. } => None,
        }
    }
}

/// A parsed header translation unit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TranslationUnit {
    /// Source language.
    pub language: Language,
    /// Typed declarations in source order.
    pub declarations: Vec<Decl>,
    /// Source span for each declaration when the unit came from the parser.
    ///
    /// Programmatically constructed units may leave this empty. A parsed unit
    /// always has exactly one entry per declaration; declarations lowered from
    /// one multi-declarator syntax node share that node's span.
    pub declaration_spans: Vec<crate::analysis::header_syntax::SourceSpan>,
}
