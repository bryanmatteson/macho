use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct SwiftTypeIndex {
    pub types: Vec<SwiftType>,
}

impl SwiftTypeIndex {
    pub fn by_kind(&self, kind: SwiftTypeKind) -> Vec<&SwiftType> {
        self.types.iter().filter(|t| t.kind == kind).collect()
    }

    pub fn find(&self, name: &str) -> Option<&SwiftType> {
        self.types.iter().find(|t| t.name == name)
    }

    pub fn classes(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Class)
    }

    pub fn structs(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Struct)
    }

    pub fn enums(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Enum)
    }

    pub fn protocols(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Protocol)
    }

    pub fn high_confidence(&self) -> Vec<&SwiftType> {
        self.types
            .iter()
            .filter(|t| t.confidence.is_high())
            .collect()
    }

    pub fn partial(&self) -> Vec<&SwiftType> {
        self.types
            .iter()
            .filter(|t| !t.confidence.is_high())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SwiftType {
    pub name: String,
    pub kind: SwiftTypeKind,
    pub mangled_name: Option<String>,
    pub address: Option<u64>,
    pub source: SwiftTypeSource,
    pub confidence: SwiftTypeConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftTypeConfidence {
    High,
    Partial,
}

impl SwiftTypeConfidence {
    pub fn is_high(self) -> bool {
        matches!(self, Self::High)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftTypeKind {
    Class,
    Struct,
    Enum,
    Protocol,
    /// Kind could not be determined from available symbols (no descriptor found).
    Unknown,
}

impl std::fmt::Display for SwiftTypeKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Class => write!(f, "class"),
            Self::Struct => write!(f, "struct"),
            Self::Enum => write!(f, "enum"),
            Self::Protocol => write!(f, "protocol"),
            Self::Unknown => write!(f, "unknown"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum SwiftTypeSource {
    #[serde(rename = "demangled_symbol")]
    DemangledSymbol,
    #[serde(rename = "objc_metadata")]
    ObjCMetadata,
}
