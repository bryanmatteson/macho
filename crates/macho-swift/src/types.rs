use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
/// The SwiftTypeIndex type.
pub struct SwiftTypeIndex {
    /// The types field.
    pub types: Vec<SwiftType>,
    /// Parent context relationships decoded from nominal descriptors.
    pub parents: Vec<SwiftParentInfo>,
    /// Protocol conformance descriptors decoded from reflection metadata.
    pub conformances: Vec<SwiftConformanceInfo>,
    /// Associated-type descriptors decoded from reflection metadata.
    pub associated_types: Vec<SwiftAssociatedTypeInfo>,
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
    /// Stored properties or enum cases decoded from the nominal field descriptor.
    pub fields: Option<Vec<SwiftFieldInfo>>,
}

/// One record from a Swift nominal field descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwiftFieldInfo {
    /// Field/case name when the reflection string is available.
    pub name: Option<String>,
    /// Raw mangled type-reference bytes, excluding the terminating NUL.
    pub mangled_type: Option<Vec<u8>>,
    /// Resolved nominal type name when an in-image symbolic reference permits it.
    pub type_name: Option<String>,
    /// ABI field-record flags.
    pub flags: u32,
}

/// A nominal descriptor's enclosing nominal or protocol context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwiftParentInfo {
    /// Nominal descriptor virtual address.
    pub descriptor_address: u64,
    /// Fully-qualified enclosing context name.
    pub parent_name: String,
}

/// One protocol-conformance descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwiftConformanceInfo {
    /// Conformance descriptor virtual address.
    pub address: u64,
    /// Descriptor byte length.
    pub byte_len: u32,
    /// Protocol descriptor virtual address when directly resolvable.
    pub protocol_address: Option<u64>,
    /// Fully-qualified protocol name when its descriptor resolves.
    pub protocol_name: Option<String>,
    /// Conforming nominal descriptor virtual address when directly resolvable.
    pub conforming_type_address: Option<u64>,
    /// Fully-qualified conforming type name when its reference resolves.
    pub conforming_type_name: Option<String>,
}

/// One record from an associated-type descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwiftAssociatedTypeRecordInfo {
    /// Associated-type requirement name.
    pub name: Option<String>,
    /// Raw substituted-type mangling bytes.
    pub substituted_type_name: Option<Vec<u8>>,
}

/// One associated-type descriptor and its bounded records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SwiftAssociatedTypeInfo {
    /// Descriptor virtual address.
    pub address: u64,
    /// Descriptor byte length including its records.
    pub byte_len: u32,
    /// Raw conforming-type mangling bytes.
    pub conforming_type_name: Option<Vec<u8>>,
    /// Resolved conforming nominal type name when available.
    pub resolved_conforming_type_name: Option<String>,
    /// Raw protocol-type mangling bytes.
    pub protocol_type_name: Option<Vec<u8>>,
    /// Associated-type records.
    pub records: Vec<SwiftAssociatedTypeRecordInfo>,
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
    #[serde(rename = "swift_metadata")]
    /// Parsed from a native Swift context descriptor section.
    SwiftMetadata,
    #[serde(rename = "demangled_symbol")]
    /// The DemangledSymbol variant.
    DemangledSymbol,
    #[serde(rename = "objc_metadata")]
    /// The ObjCMetadata variant.
    ObjCMetadata,
}
