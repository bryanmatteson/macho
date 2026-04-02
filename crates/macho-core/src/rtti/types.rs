use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppConfidence {
    Exact,
    High,
    Medium,
    Low,
    Hook,
}

impl CppConfidence {
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
pub enum CppEvidenceKind {
    MangledSymbol,
    DemangledSymbol,
    Vtable,
    TypeInfo,
    BodyAnalysis,
    CrossBinary,
    ExternalHeader,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppEvidence {
    pub kind: CppEvidenceKind,
    pub confidence: CppConfidence,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CppTypeInfoKind {
    Class,
    SingleInheritance,
    VirtualMultipleInheritance,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppBaseClass {
    pub name: String,
    pub offset: Option<i64>,
    pub flags: u64,
    pub is_virtual: bool,
    pub is_public: bool,
    pub evidence: Vec<CppEvidence>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CppTypeInfoNode {
    pub name: String,
    pub mangled_name: String,
    pub address: u64,
    pub kind: CppTypeInfoKind,
    pub bases: Vec<CppBaseClass>,
    pub evidence: Vec<CppEvidence>,
}
