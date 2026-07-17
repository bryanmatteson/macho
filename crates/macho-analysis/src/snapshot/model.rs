use serde::{Deserialize, Serialize};

// -- Header --

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The HeaderSnapshot type.
pub struct HeaderSnapshot {
    /// The cpu_type field.
    pub cpu_type: String,
    /// The cpu_subtype field.
    pub cpu_subtype: String,
    /// The file_type field.
    pub file_type: String,
    /// The flags field.
    pub flags: Vec<String>,
    /// The ncmds field.
    pub ncmds: u32,
    /// The uuid field.
    pub uuid: Option<String>,
    /// The platform field.
    pub platform: Option<PlatformSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The PlatformSnapshot type.
pub struct PlatformSnapshot {
    /// The platform field.
    pub platform: String,
    /// The min_os field.
    pub min_os: String,
    /// The sdk field.
    pub sdk: String,
}

// -- Load commands --

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The LoadCommandSnapshot type.
pub struct LoadCommandSnapshot {
    /// The name field.
    pub name: String,
    /// The summary field.
    pub summary: String,
    /// The fileset_entry field.
    pub fileset_entry: Option<FilesetEntrySnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// The FilesetEntrySnapshot type.
pub struct FilesetEntrySnapshot {
    /// The entry_id field.
    pub entry_id: String,
    /// The vm_addr field.
    pub vm_addr: u64,
    /// The file_offset field.
    pub file_offset: u64,
}

// -- Segments and sections --

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The SegmentSnapshot type.
pub struct SegmentSnapshot {
    /// The name field.
    pub name: String,
    /// The vm_addr field.
    pub vm_addr: u64,
    /// The vm_size field.
    pub vm_size: u64,
    /// The file_offset field.
    pub file_offset: u64,
    /// The file_size field.
    pub file_size: u64,
    /// The max_prot field.
    pub max_prot: String,
    /// The init_prot field.
    pub init_prot: String,
    /// The sections field.
    pub sections: Vec<SectionSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The SectionSnapshot type.
pub struct SectionSnapshot {
    /// The segment_name field.
    pub segment_name: String,
    /// The section_name field.
    pub section_name: String,
    /// The addr field.
    pub addr: u64,
    /// The size field.
    pub size: u64,
    /// The section_type field.
    pub section_type: String,
}

// -- Symbols --

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The SymbolSnapshot type.
pub struct SymbolSnapshot {
    /// The name field.
    pub name: String,
    /// The sym_type field.
    pub sym_type: String,
    /// The value field.
    pub value: u64,
    /// The external field.
    pub external: bool,
    /// The undefined field.
    pub undefined: bool,
}

// -- Exports --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// The ExportSnapshot type.
pub struct ExportSnapshot {
    /// The name field.
    pub name: String,
    /// The kind field.
    pub kind: ExportKindSnapshot,
    /// The weak field.
    pub weak: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// The ExportKindSnapshot type.
#[non_exhaustive]
pub enum ExportKindSnapshot {
    /// The Regular variant.
    Regular {
        /// The u64 field.
        address: u64,
    },
    /// The ThreadLocal variant.
    ThreadLocal {
        /// The u64 field.
        address: u64,
    },
    /// The Absolute variant.
    Absolute {
        /// The u64 field.
        address: u64,
    },
    /// The Reexport variant.
    Reexport {
        /// The u64 field.
        ordinal: u64,
        /// The item field.
        name: Option<String>,
    },
    /// The StubAndResolver variant.
    StubAndResolver {
        /// The u64 field.
        stub_offset: u64,
        /// The u64 field.
        resolver_offset: u64,
    },
    /// An export kind introduced after this analysis crate was built.
    Unknown,
}

impl ExportKindSnapshot {
    /// Performs tag.
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Regular { .. } => "regular",
            Self::ThreadLocal { .. } => "thread-local",
            Self::Absolute { .. } => "absolute",
            Self::Reexport { .. } => "reexport",
            Self::StubAndResolver { .. } => "stub-and-resolver",
            Self::Unknown => "unknown",
        }
    }
}

// -- Imports --

// -- Chained fixups --

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
/// The FixupSnapshot type.
pub struct FixupSnapshot {
    /// The segment_index field.
    pub segment_index: usize,
    /// The segment_offset field.
    pub segment_offset: u64,
    /// The kind field.
    pub kind: FixupKindSnapshot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// The FixupKindSnapshot type.
#[non_exhaustive]
pub enum FixupKindSnapshot {
    /// The Rebase variant.
    Rebase {
        /// The u64 field.
        target: u64,
    },
    /// The Bind variant.
    Bind {
        /// The u32 field.
        import_index: u32,
        /// The i64 field.
        addend: i64,
    },
    /// The AuthRebase variant.
    AuthRebase {
        /// The u64 field.
        target: u64,
        /// The u16 field.
        diversity: u16,
        /// The u8 field.
        key: u8,
        /// The bool field.
        addr_div: bool,
    },
    /// The AuthBind variant.
    AuthBind {
        /// The u32 field.
        import_index: u32,
        /// The u16 field.
        diversity: u16,
        /// The u8 field.
        key: u8,
        /// The bool field.
        addr_div: bool,
    },
    /// A fixup kind introduced after this analysis crate was built.
    Unknown,
}

// -- ObjC --

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ObjCSnapshot type.
pub struct ObjCSnapshot {
    /// The classes field.
    pub classes: Vec<ObjCClassSnapshot>,
    /// The categories field.
    pub categories: Vec<ObjCCategorySnapshot>,
    /// The protocols field.
    pub protocols: Vec<ObjCProtocolSnapshot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ObjCMethodSnapshot type.
pub struct ObjCMethodSnapshot {
    /// The name field.
    pub name: String,
    /// The type_encoding field.
    pub type_encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ObjCPropertySnapshot type.
pub struct ObjCPropertySnapshot {
    /// The name field.
    pub name: String,
    /// The attributes field.
    pub attributes: String,
    /// The is_class field.
    pub is_class: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ObjCClassSnapshot type.
pub struct ObjCClassSnapshot {
    /// The name field.
    pub name: String,
    /// The superclass field.
    pub superclass: Option<String>,
    /// The instance_methods field.
    pub instance_methods: Vec<ObjCMethodSnapshot>,
    /// The class_methods field.
    pub class_methods: Vec<ObjCMethodSnapshot>,
    /// The properties field.
    pub properties: Vec<ObjCPropertySnapshot>,
    /// The protocols field.
    pub protocols: Vec<String>,
    /// The ivars field.
    pub ivars: Vec<String>,
    /// The is_swift field.
    pub is_swift: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ObjCCategorySnapshot type.
pub struct ObjCCategorySnapshot {
    /// The name field.
    pub name: String,
    /// The class_name field.
    pub class_name: String,
    /// The instance_methods field.
    pub instance_methods: Vec<ObjCMethodSnapshot>,
    /// The class_methods field.
    pub class_methods: Vec<ObjCMethodSnapshot>,
    /// The properties field.
    pub properties: Vec<ObjCPropertySnapshot>,
    /// The protocols field.
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The ObjCProtocolSnapshot type.
pub struct ObjCProtocolSnapshot {
    /// The name field.
    pub name: String,
    /// The instance_methods field.
    pub instance_methods: Vec<ObjCMethodSnapshot>,
    /// The class_methods field.
    pub class_methods: Vec<ObjCMethodSnapshot>,
    /// The optional_instance_methods field.
    pub optional_instance_methods: Vec<ObjCMethodSnapshot>,
    /// The optional_class_methods field.
    pub optional_class_methods: Vec<ObjCMethodSnapshot>,
    /// The properties field.
    pub properties: Vec<ObjCPropertySnapshot>,
    /// The adopted_protocols field.
    pub adopted_protocols: Vec<String>,
}

// -- Code signing --

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The CodesignSnapshot type.
pub struct CodesignSnapshot {
    /// The identifier field.
    pub identifier: Option<String>,
    /// The team_id field.
    pub team_id: Option<String>,
    /// The hash_type field.
    pub hash_type: String,
    /// The has_entitlements field.
    pub has_entitlements: bool,
    /// The entitlements_xml field.
    pub entitlements_xml: Option<String>,
    /// The entitlement_keys field.
    pub entitlement_keys: Vec<String>,
    /// The has_der_entitlements field.
    pub has_der_entitlements: bool,
    /// The entitlements_der_fingerprint field.
    pub entitlements_der_fingerprint: Option<String>,
    /// The has_cms_signature field.
    pub has_cms_signature: bool,
    /// The n_code_slots field.
    pub n_code_slots: u32,
    /// The code_limit field.
    pub code_limit: u64,
}
