//! Serialized projection of the process-free header syntax AST.

#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use super::{EntityId, Identifier, NonEmpty, ObjCEntityId, ObjCMemberId, Severity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuiltinType {
    Void,
    Bool,
    Char,
    SignedChar,
    UnsignedChar,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    LongLong,
    UnsignedLongLong,
    Int128,
    UnsignedInt128,
    Float,
    Double,
    LongDouble,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedTypeTag {
    Typedef,
    Struct,
    Union,
    Enum,
    Class,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceKind {
    Lvalue,
    Rvalue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ParameterState {
    Unspecified,
    Known,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallingConvention {
    C,
    Swift,
    ObjcMethod,
    Thiscall,
    Vectorcall,
    Aapcs,
    AapcsVfp,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageClass {
    None,
    Extern,
    Static,
    ThreadLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderLinkage {
    C,
    Cpp,
    Objc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    Struct,
    Union,
    Class,
    Enum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCForwardKind {
    Class,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderOwnerKind {
    Namespace,
    Record,
    Class,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Access {
    Public,
    Protected,
    Private,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCAccess {
    Public,
    Protected,
    Private,
    Package,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    Instance,
    Class,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCPropertyAttribute {
    Readonly,
    Readwrite,
    Copy,
    Retain,
    Strong,
    Weak,
    Assign,
    Atomic,
    Nonatomic,
    Dynamic,
    Class,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderValidationCode {
    SyntaxError,
    DuplicateDeclaration,
    ConflictingRedeclaration,
    UnresolvedType,
    UnresolvedOwner,
    InvalidLinkage,
    InvalidStorage,
    InvalidCallingConvention,
    IncompleteTemplateContext,
    SelectorArityMismatch,
    ObjcKindMismatch,
    DependencyCycle,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypeQualifiers {
    #[serde(rename = "const")]
    pub is_const: bool,
    #[serde(rename = "volatile")]
    pub is_volatile: bool,
    #[serde(rename = "restrict")]
    pub is_restrict: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderFunctionQualifiers {
    #[serde(rename = "const")]
    pub is_const: bool,
    #[serde(rename = "volatile")]
    pub is_volatile: bool,
    pub reference: Option<ReferenceKind>,
    pub noexcept: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderTemplateArgument {
    Type { value: HeaderType },
    Integer { value: i64 },
    Identifier { path: NonEmpty<Identifier> },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderParameter {
    pub name: Identifier,
    #[serde(rename = "type")]
    pub ty: HeaderType,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderType {
    Builtin {
        name: BuiltinType,
    },
    Named {
        tag: NamedTypeTag,
        path: NonEmpty<Identifier>,
        template_arguments: Vec<HeaderTemplateArgument>,
    },
    Pointer {
        pointee: Box<HeaderType>,
        qualifiers: TypeQualifiers,
    },
    Reference {
        target: Box<HeaderType>,
        reference: ReferenceKind,
    },
    Array {
        element: Box<HeaderType>,
        count: Option<u64>,
    },
    Function {
        return_type: Box<HeaderType>,
        parameters: Vec<HeaderParameter>,
        parameter_state: ParameterState,
        variadic: bool,
        calling_convention: CallingConvention,
        qualifiers: HeaderFunctionQualifiers,
    },
    ObjcObject {
        name: Option<Identifier>,
        protocols: Vec<Identifier>,
        qualifiers: TypeQualifiers,
    },
    ObjcBlock {
        signature: Box<HeaderType>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderOwnerRef {
    pub path: NonEmpty<Identifier>,
    /// One exact scope kind for every component in `path`.
    pub scope_kinds: NonEmpty<HeaderOwnerKind>,
    /// Access of each scope within its parent, parallel to `path`. Namespace
    /// components and top-level scopes use `None`.
    pub scope_access: NonEmpty<Option<Access>>,
    /// Access of the declaration within the terminal record owner. Namespace
    /// ownership has no member access.
    pub member_access: Option<Access>,
    pub entity_id: Option<EntityId>,
}

impl HeaderOwnerRef {
    /// Returns the terminal owner kind when the typed scope path is well formed.
    pub fn terminal_kind(&self) -> HeaderOwnerKind {
        *self
            .scope_kinds
            .as_slice()
            .last()
            .expect("HeaderOwnerRef scope kinds are non-empty")
    }

    /// Returns whether every path component has an exact corresponding kind.
    pub fn has_exact_scopes(&self) -> bool {
        self.path.as_slice().len() == self.scope_kinds.as_slice().len()
            && self.path.as_slice().len() == self.scope_access.as_slice().len()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderBase {
    #[serde(rename = "type")]
    pub ty: HeaderType,
    pub access: Access,
    #[serde(rename = "virtual")]
    pub is_virtual: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderField {
    pub name: Identifier,
    #[serde(rename = "type")]
    pub ty: HeaderType,
    pub offset: Option<u64>,
    pub bit_width: Option<u32>,
    pub access: Access,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderRecordMember {
    pub access: Access,
    pub declaration: Box<HeaderDecl>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub spelling: String,
    pub colon_count: u32,
}

impl Selector {
    pub fn new(spelling: impl Into<String>) -> Self {
        let spelling = spelling.into();
        Self {
            colon_count: spelling.bytes().filter(|byte| *byte == b':').count() as u32,
            spelling,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCHeaderIvar {
    pub id: ObjCMemberId,
    pub name: Identifier,
    #[serde(rename = "type")]
    pub ty: HeaderType,
    pub access: ObjCAccess,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjCHeaderMember {
    Method {
        id: ObjCMemberId,
        method_kind: MethodKind,
        selector: Selector,
        return_type: HeaderType,
        parameters: Vec<HeaderParameter>,
        required: Option<bool>,
    },
    Property {
        id: ObjCMemberId,
        name: Identifier,
        #[serde(rename = "type")]
        ty: HeaderType,
        attributes: Vec<ObjCPropertyAttribute>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HeaderDecl {
    Function {
        id: EntityId,
        owner: Option<HeaderOwnerRef>,
        name: Identifier,
        signature: HeaderType,
        storage: StorageClass,
        linkage: HeaderLinkage,
    },
    Variable {
        id: EntityId,
        owner: Option<HeaderOwnerRef>,
        name: Identifier,
        #[serde(rename = "type")]
        ty: HeaderType,
        storage: StorageClass,
        linkage: HeaderLinkage,
    },
    Record {
        id: EntityId,
        /// Source owner scopes, kept separate from the record's local path.
        owner: Option<HeaderOwnerRef>,
        record_kind: RecordKind,
        path: NonEmpty<Identifier>,
        complete: bool,
        bases: Vec<HeaderBase>,
        fields: Vec<HeaderField>,
        members: Vec<HeaderRecordMember>,
    },
    Forward {
        id: EntityId,
        /// Source owner scopes, kept separate from the record's local path.
        owner: Option<HeaderOwnerRef>,
        record_kind: RecordKind,
        path: NonEmpty<Identifier>,
    },
    Alias {
        id: EntityId,
        path: NonEmpty<Identifier>,
        target: HeaderType,
    },
    ObjcInterface {
        id: ObjCEntityId,
        name: Identifier,
        superclass: Option<Identifier>,
        protocols: Vec<Identifier>,
        ivars: Vec<ObjCHeaderIvar>,
        members: Vec<ObjCHeaderMember>,
    },
    ObjcCategory {
        id: ObjCEntityId,
        name: Identifier,
        extended_class: Identifier,
        protocols: Vec<Identifier>,
        members: Vec<ObjCHeaderMember>,
    },
    ObjcProtocol {
        id: ObjCEntityId,
        name: Identifier,
        protocols: Vec<Identifier>,
        members: Vec<ObjCHeaderMember>,
    },
    ObjcForward {
        entity_kind: ObjCForwardKind,
        names: NonEmpty<Identifier>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderValidationDiagnostic {
    pub code: HeaderValidationCode,
    pub severity: Severity,
    pub message: String,
    pub declaration_index: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderValidationReport {
    pub syntax_valid: bool,
    pub semantic_valid: bool,
    pub diagnostics: Vec<HeaderValidationDiagnostic>,
}

impl From<&crate::analysis::header_syntax::HeaderValidationReport> for HeaderValidationReport {
    fn from(value: &crate::analysis::header_syntax::HeaderValidationReport) -> Self {
        Self {
            syntax_valid: value.syntax_valid,
            semantic_valid: value.semantic_valid,
            diagnostics: value
                .diagnostics
                .iter()
                .map(|diagnostic| HeaderValidationDiagnostic {
                    code: validation_code(diagnostic.code),
                    severity: match diagnostic.severity {
                        crate::analysis::header_syntax::Severity::Info => Severity::Info,
                        crate::analysis::header_syntax::Severity::Warning => Severity::Warning,
                        crate::analysis::header_syntax::Severity::Error => Severity::Error,
                    },
                    message: diagnostic.message.clone(),
                    declaration_index: diagnostic.declaration_index,
                })
                .collect(),
        }
    }
}

fn validation_code(
    value: crate::analysis::header_syntax::HeaderValidationCode,
) -> HeaderValidationCode {
    use crate::analysis::header_syntax::HeaderValidationCode as Source;
    match value {
        Source::SyntaxError => HeaderValidationCode::SyntaxError,
        Source::DuplicateDeclaration => HeaderValidationCode::DuplicateDeclaration,
        Source::ConflictingRedeclaration => HeaderValidationCode::ConflictingRedeclaration,
        Source::UnresolvedType => HeaderValidationCode::UnresolvedType,
        Source::UnresolvedOwner => HeaderValidationCode::UnresolvedOwner,
        Source::InvalidLinkage => HeaderValidationCode::InvalidLinkage,
        Source::InvalidStorage => HeaderValidationCode::InvalidStorage,
        Source::InvalidCallingConvention => HeaderValidationCode::InvalidCallingConvention,
        Source::IncompleteTemplateContext => HeaderValidationCode::IncompleteTemplateContext,
        Source::SelectorArityMismatch => HeaderValidationCode::SelectorArityMismatch,
        Source::ObjectiveCKindMismatch => HeaderValidationCode::ObjcKindMismatch,
        Source::DependencyCycle => HeaderValidationCode::DependencyCycle,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_header_type_key_is_rejected() {
        let error = serde_json::from_str::<HeaderType>(
            r#"{"kind":"builtin","name":"int","invented":true}"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}
