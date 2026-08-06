use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppConfidence type.
#[non_exhaustive]
pub enum CppConfidence {
    /// The Exact variant.
    Exact,
    /// The High variant.
    High,
    /// The Medium variant.
    Medium,
    /// The Low variant.
    Low,
    /// The Hook variant.
    Hook,
}

impl CppConfidence {
    /// Performs max.
    pub fn max(self, other: Self) -> Self {
        self.max_by(other, |left, right| left.cmp(right))
    }

    fn max_by<F>(self, other: Self, cmp: F) -> Self
    where
        F: Fn(&Self, &Self) -> std::cmp::Ordering,
    {
        if cmp(&self, &other).is_ge() {
            self
        } else {
            other
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppEvidenceKind type.
#[non_exhaustive]
pub enum CppEvidenceKind {
    /// The MangledSymbol variant.
    MangledSymbol,
    /// The DemangledSymbol variant.
    DemangledSymbol,
    /// The Vtable variant.
    Vtable,
    /// The TypeInfo variant.
    TypeInfo,
    /// The BodyAnalysis variant.
    BodyAnalysis,
    /// The CrossBinary variant.
    CrossBinary,
    /// The ExternalHeader variant.
    ExternalHeader,
}

#[derive(Debug, Clone, Serialize)]
/// The CppEvidence type.
pub struct CppEvidence {
    /// The kind field.
    pub kind: CppEvidenceKind,
    /// The confidence field.
    pub confidence: CppConfidence,
    /// The detail field.
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
/// The CppTypeInfoKind type.
#[non_exhaustive]
pub enum CppTypeInfoKind {
    /// The Class variant.
    Class,
    /// The SingleInheritance variant.
    SingleInheritance,
    /// The VirtualMultipleInheritance variant.
    VirtualMultipleInheritance,
    /// The Unknown variant.
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
/// The CppBaseClass type.
pub struct CppBaseClass {
    /// The name field.
    pub name: String,
    /// The offset field.
    pub offset: Option<i64>,
    /// The flags field.
    pub flags: u64,
    /// The is_virtual field.
    pub is_virtual: bool,
    /// The is_public field.
    pub is_public: bool,
    /// The evidence field.
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
/// The CppTypeInfoNode type.
pub struct CppTypeInfoNode {
    /// The name field.
    pub name: String,
    /// The mangled_name field.
    pub mangled_name: String,
    /// The address field.
    pub address: u64,
    /// The kind field.
    pub kind: CppTypeInfoKind,
    /// The bases field.
    pub bases: Vec<CppBaseClass>,
    /// The evidence field.
    pub evidence: Vec<CppEvidence>,
}
