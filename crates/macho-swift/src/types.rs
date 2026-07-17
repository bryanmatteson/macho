use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
/// The SwiftTypeIndex type.
pub struct SwiftTypeIndex {
    /// The types field.
    pub types: Vec<SwiftType>,
}

impl SwiftTypeIndex {
    /// Performs by_kind.
    pub fn by_kind(&self, kind: SwiftTypeKind) -> Vec<&SwiftType> {
        self.types.iter().filter(|t| t.kind == kind).collect()
    }

    /// Performs find.
    pub fn find(&self, name: &str) -> Option<&SwiftType> {
        self.types.iter().find(|t| t.name == name)
    }

    /// Performs classes.
    pub fn classes(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Class)
    }

    /// Performs structs.
    pub fn structs(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Struct)
    }

    /// Performs enums.
    pub fn enums(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Enum)
    }

    /// Performs protocols.
    pub fn protocols(&self) -> Vec<&SwiftType> {
        self.by_kind(SwiftTypeKind::Protocol)
    }

    /// Performs high_confidence.
    pub fn high_confidence(&self) -> Vec<&SwiftType> {
        self.types
            .iter()
            .filter(|t| t.confidence.is_high())
            .collect()
    }

    /// Performs partial.
    pub fn partial(&self) -> Vec<&SwiftType> {
        self.types
            .iter()
            .filter(|t| !t.confidence.is_high())
            .collect()
    }
}

#[derive(Debug, Clone, Serialize)]
/// The SwiftType type.
pub struct SwiftType {
    /// The name field.
    pub name: String,
    /// The kind field.
    pub kind: SwiftTypeKind,
    /// The mangled_name field.
    pub mangled_name: Option<String>,
    /// The address field.
    pub address: Option<u64>,
    /// The source field.
    pub source: SwiftTypeSource,
    /// The confidence field.
    pub confidence: SwiftTypeConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The SwiftTypeConfidence type.
#[non_exhaustive]
pub enum SwiftTypeConfidence {
    /// The High variant.
    High,
    /// The Partial variant.
    Partial,
}

impl SwiftTypeConfidence {
    /// Performs is_high.
    pub fn is_high(self) -> bool {
        matches!(self, Self::High)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The SwiftTypeKind type.
#[non_exhaustive]
pub enum SwiftTypeKind {
    /// The Class variant.
    Class,
    /// The Struct variant.
    Struct,
    /// The Enum variant.
    Enum,
    /// The Protocol variant.
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
/// The SwiftTypeSource type.
#[non_exhaustive]
pub enum SwiftTypeSource {
    #[serde(rename = "demangled_symbol")]
    /// The DemangledSymbol variant.
    DemangledSymbol,
    #[serde(rename = "objc_metadata")]
    /// The ObjCMetadata variant.
    ObjCMetadata,
}
