use crate::symbols::imports::ImportRecord;
use serde::Serialize;

// -- Top-level snapshot types --

#[derive(Debug, Clone, Serialize)]
pub struct ContainerSnapshot {
    pub format: ContainerFormat,
    pub slices: Vec<SliceSnapshot>,
}

impl ContainerSnapshot {
    pub fn available_arches(&self) -> Vec<String> {
        self.slices.iter().map(|slice| slice.arch.clone()).collect()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ContainerFormat {
    Thin,
    Fat,
    Fileset,
}

impl std::fmt::Display for ContainerFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Thin => write!(f, "Thin"),
            Self::Fat => write!(f, "Fat"),
            Self::Fileset => write!(f, "Fileset"),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SliceSnapshot {
    pub arch: String,
    pub header: HeaderSnapshot,
    pub load_commands: Vec<LoadCommandSnapshot>,
    pub segments: Vec<SegmentSnapshot>,
    pub symbols: Vec<SymbolSnapshot>,
    pub exports: Vec<ExportSnapshot>,
    pub imports: Vec<ImportRecord>,
    pub fixups: Vec<FixupSnapshot>,
    pub objc: ObjCSnapshot,
    pub codesign: Option<CodesignSnapshot>,
    pub analysis_issues: Vec<AnalysisIssueSnapshot>,
    pub diagnostics: Vec<DiagnosticSnapshot>,
}

// -- Header --

#[derive(Debug, Clone, Serialize)]
pub struct HeaderSnapshot {
    pub cpu_type: String,
    pub cpu_subtype: String,
    pub file_type: String,
    pub flags: Vec<String>,
    pub ncmds: u32,
    pub uuid: Option<String>,
    pub platform: Option<PlatformSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PlatformSnapshot {
    pub platform: String,
    pub min_os: String,
    pub sdk: String,
}

// -- Load commands --

#[derive(Debug, Clone, Serialize)]
pub struct LoadCommandSnapshot {
    pub name: String,
    pub summary: String,
    pub fileset_entry: Option<FilesetEntrySnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FilesetEntrySnapshot {
    pub entry_id: String,
    pub vm_addr: u64,
    pub file_offset: u64,
}

// -- Segments and sections --

#[derive(Debug, Clone, Serialize)]
pub struct SegmentSnapshot {
    pub name: String,
    pub vm_addr: u64,
    pub vm_size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub max_prot: String,
    pub init_prot: String,
    pub sections: Vec<SectionSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionSnapshot {
    pub segment_name: String,
    pub section_name: String,
    pub addr: u64,
    pub size: u64,
    pub section_type: String,
}

// -- Symbols --

#[derive(Debug, Clone, Serialize)]
pub struct SymbolSnapshot {
    pub name: String,
    pub sym_type: String,
    pub value: u64,
    pub external: bool,
    pub undefined: bool,
}

// -- Exports --

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExportSnapshot {
    pub name: String,
    pub kind: ExportKindSnapshot,
    pub weak: bool,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ExportKindSnapshot {
    Regular {
        address: u64,
    },
    ThreadLocal {
        address: u64,
    },
    Absolute {
        address: u64,
    },
    Reexport {
        ordinal: u64,
        name: Option<String>,
    },
    StubAndResolver {
        stub_offset: u64,
        resolver_offset: u64,
    },
}

impl ExportKindSnapshot {
    pub fn tag(&self) -> &'static str {
        match self {
            Self::Regular { .. } => "regular",
            Self::ThreadLocal { .. } => "thread-local",
            Self::Absolute { .. } => "absolute",
            Self::Reexport { .. } => "reexport",
            Self::StubAndResolver { .. } => "stub-and-resolver",
        }
    }
}

// -- Imports --

// -- Chained fixups --

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct FixupSnapshot {
    pub segment_index: usize,
    pub segment_offset: u64,
    pub kind: FixupKindSnapshot,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FixupKindSnapshot {
    Rebase {
        target: u64,
    },
    Bind {
        import_index: u32,
        addend: i64,
    },
    AuthRebase {
        target: u64,
        diversity: u16,
        key: u8,
        addr_div: bool,
    },
    AuthBind {
        import_index: u32,
        diversity: u16,
        key: u8,
        addr_div: bool,
    },
}

// -- ObjC --

#[derive(Debug, Clone, Serialize)]
pub struct ObjCSnapshot {
    pub classes: Vec<ObjCClassSnapshot>,
    pub categories: Vec<ObjCCategorySnapshot>,
    pub protocols: Vec<ObjCProtocolSnapshot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjCMethodSnapshot {
    pub name: String,
    pub type_encoding: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjCPropertySnapshot {
    pub name: String,
    pub attributes: String,
    pub is_class: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjCClassSnapshot {
    pub name: String,
    pub superclass: Option<String>,
    pub instance_methods: Vec<ObjCMethodSnapshot>,
    pub class_methods: Vec<ObjCMethodSnapshot>,
    pub properties: Vec<ObjCPropertySnapshot>,
    pub protocols: Vec<String>,
    pub ivars: Vec<String>,
    pub is_swift: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjCCategorySnapshot {
    pub name: String,
    pub class_name: String,
    pub instance_methods: Vec<ObjCMethodSnapshot>,
    pub class_methods: Vec<ObjCMethodSnapshot>,
    pub properties: Vec<ObjCPropertySnapshot>,
    pub protocols: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ObjCProtocolSnapshot {
    pub name: String,
    pub instance_methods: Vec<ObjCMethodSnapshot>,
    pub class_methods: Vec<ObjCMethodSnapshot>,
    pub optional_instance_methods: Vec<ObjCMethodSnapshot>,
    pub optional_class_methods: Vec<ObjCMethodSnapshot>,
    pub properties: Vec<ObjCPropertySnapshot>,
    pub adopted_protocols: Vec<String>,
}

// -- Code signing --

#[derive(Debug, Clone, Serialize)]
pub struct CodesignSnapshot {
    pub identifier: Option<String>,
    pub team_id: Option<String>,
    pub hash_type: String,
    pub has_entitlements: bool,
    pub entitlements_xml: Option<String>,
    pub entitlement_keys: Vec<String>,
    pub has_der_entitlements: bool,
    pub entitlements_der_fingerprint: Option<String>,
    pub has_cms_signature: bool,
    pub n_code_slots: u32,
    pub code_limit: u64,
}

// -- Diagnostics --

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiagnosticSnapshot {
    pub severity: String,
    pub code: String,
    pub message: String,
    pub spans: Vec<DiagnosticSpanSnapshot>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct DiagnosticSpanSnapshot {
    pub offset: u64,
    pub size: u64,
    pub label: Option<String>,
}

// -- Analysis issues --

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnalysisIssueSnapshot {
    pub component: String,
    pub message: String,
}
