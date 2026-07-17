#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Ord, PartialOrd)]
#[serde(rename_all = "snake_case")]
/// The Confidence type.
#[non_exhaustive]
pub enum Confidence {
    /// The DwarfExact variant.
    DwarfExact,
    /// The Correlated variant.
    Correlated,
    /// The Inferred variant.
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The EvidenceKind type.
#[non_exhaustive]
pub enum EvidenceKind {
    /// The Dwarf variant.
    Dwarf,
    /// The Symbol variant.
    Symbol,
    /// The HeaderMatch variant.
    HeaderMatch,
    /// The Inference variant.
    Inference,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The EvidenceFact type.
pub struct EvidenceFact {
    /// The kind field.
    pub kind: EvidenceKind,
    /// The confidence field.
    pub confidence: Confidence,
    /// The detail field.
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
/// The SourceLocation type.
pub struct SourceLocation {
    /// The file field.
    pub file: Option<String>,
    /// The line field.
    pub line: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CTagKind type.
#[non_exhaustive]
pub enum CTagKind {
    /// The Struct variant.
    Struct,
    /// The Union variant.
    Union,
    /// The Enum variant.
    Enum,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// The CType type.
#[non_exhaustive]
pub enum CType {
    /// The Void variant.
    Void,
    /// The Builtin variant.
    Builtin {
        /// The String field.
        name: String,
    },
    /// The Named variant.
    Named {
        /// The String field.
        name: String,
        /// The item field.
        tag: Option<CTagKind>,
    },
    /// The Pointer variant.
    Pointer {
        /// The item field.
        to: Box<CType>,
    },
    /// The Array variant.
    Array {
        /// The item field.
        element: Box<CType>,
        /// The item field.
        count: Option<u64>,
    },
    /// The Const variant.
    Const {
        /// The item field.
        inner: Box<CType>,
    },
    /// The Volatile variant.
    Volatile {
        /// The item field.
        inner: Box<CType>,
    },
    /// The Restrict variant.
    Restrict {
        /// The item field.
        inner: Box<CType>,
    },
    /// The FunctionPointer variant.
    FunctionPointer {
        /// The item field.
        return_type: Box<CType>,
        /// The item field.
        params: Vec<CParamType>,
        /// The bool field.
        variadic: bool,
    },
    /// The Unknown variant.
    Unknown {
        /// The String field.
        display: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CParamType type.
pub struct CParamType {
    /// The name field.
    pub name: Option<String>,
    /// The ty field.
    pub ty: CType,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CField type.
pub struct CField {
    /// The name field.
    pub name: String,
    /// The ty field.
    pub ty: CType,
    /// The bit_size field.
    pub bit_size: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CRecordDecl type.
pub struct CRecordDecl {
    /// The kind field.
    pub kind: CTagKind,
    /// The name field.
    pub name: String,
    /// The fields field.
    pub fields: Vec<CField>,
    /// The complete field.
    pub complete: bool,
    /// The size field.
    pub size: Option<u64>,
    /// The source field.
    pub source: SourceLocation,
    /// The evidence field.
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CEnumVariant type.
pub struct CEnumVariant {
    /// The name field.
    pub name: String,
    /// The value field.
    pub value: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CEnumDecl type.
pub struct CEnumDecl {
    /// The name field.
    pub name: String,
    /// The variants field.
    pub variants: Vec<CEnumVariant>,
    /// The complete field.
    pub complete: bool,
    /// The source field.
    pub source: SourceLocation,
    /// The evidence field.
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CTypedefDecl type.
pub struct CTypedefDecl {
    /// The name field.
    pub name: String,
    /// The target field.
    pub target: CType,
    /// The source field.
    pub source: SourceLocation,
    /// The evidence field.
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CFunctionDecl type.
pub struct CFunctionDecl {
    /// The name field.
    pub name: String,
    /// The return_type field.
    pub return_type: CType,
    /// The params field.
    pub params: Vec<CParamType>,
    /// The variadic field.
    pub variadic: bool,
    /// The external field.
    pub external: bool,
    /// The address field.
    pub address: Option<u64>,
    /// The source field.
    pub source: SourceLocation,
    /// The confidence field.
    pub confidence: Confidence,
    /// The evidence field.
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CGlobalDecl type.
pub struct CGlobalDecl {
    /// The name field.
    pub name: String,
    /// The ty field.
    pub ty: CType,
    /// The external field.
    pub external: bool,
    /// The address field.
    pub address: Option<u64>,
    /// The source field.
    pub source: SourceLocation,
    /// The confidence field.
    pub confidence: Confidence,
    /// The evidence field.
    pub evidence: Vec<EvidenceFact>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The HeaderCorrelationMatch type.
pub struct HeaderCorrelationMatch {
    /// The path field.
    pub path: String,
    /// The symbol field.
    pub symbol: String,
    /// The confidence field.
    pub confidence: Confidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CHeaderUnit type.
pub struct CHeaderUnit {
    /// The name field.
    pub name: String,
    /// The declarations field.
    pub declarations: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
/// The CAnalysis type.
pub struct CAnalysis {
    /// The records field.
    pub records: Vec<CRecordDecl>,
    /// The enums field.
    pub enums: Vec<CEnumDecl>,
    /// The typedefs field.
    pub typedefs: Vec<CTypedefDecl>,
    /// The functions field.
    pub functions: Vec<CFunctionDecl>,
    /// The globals field.
    pub globals: Vec<CGlobalDecl>,
    /// The header_units field.
    pub header_units: Vec<CHeaderUnit>,
    /// The correlated_headers field.
    pub correlated_headers: Vec<HeaderCorrelationMatch>,
}

#[derive(Default)]
/// Explicit plan for one C declaration-reconstruction run.
pub struct CReconstructionPlan<'a> {
    /// Optional injected header correlation capability.
    pub correlator: Option<&'a dyn HeaderCorrelator>,
}
