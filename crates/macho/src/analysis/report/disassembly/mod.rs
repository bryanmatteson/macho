//! Stable schema-version-1 disassembly report values.

#![allow(missing_docs)]

mod validate;

use serde::{Deserialize, Deserializer, Serialize};

use super::{ArchitectureSelection, HexBytes, ReportContainerIdentity, ReportSliceIdentity};

pub use validate::DisassemblyReportValidationError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct DisassemblySchemaVersion(u32);

impl DisassemblySchemaVersion {
    pub const CURRENT: Self = Self(1);
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl<'de> Deserialize<'de> for DisassemblySchemaVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u32::deserialize(deserializer)?;
        (value == 1).then_some(Self(value)).ok_or_else(|| {
            serde::de::Error::custom(format!("unsupported schema version {value}; expected 1"))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DisassemblyReport {
    pub schema_version: DisassemblySchemaVersion,
    pub container: ReportContainerIdentity,
    pub request: DisassemblyReportRequest,
    pub slices: Vec<DisassemblySlice>,
}

impl DisassemblyReport {
    pub fn validate(&self) -> Result<(), DisassemblyReportValidationError> {
        validate::validate(self)
    }
}

impl<'de> Deserialize<'de> for DisassemblyReport {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            schema_version: DisassemblySchemaVersion,
            container: ReportContainerIdentity,
            request: DisassemblyReportRequest,
            slices: Vec<DisassemblySlice>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let report = Self {
            schema_version: wire.schema_version,
            container: wire.container,
            request: wire.request,
            slices: wire.slices,
        };
        report.validate().map_err(serde::de::Error::custom)?;
        Ok(report)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisassemblyReportRequest {
    pub architectures: ArchitectureSelection,
    pub selection: ReportSelection,
    pub mode: ReportDecodeMode,
    pub demangle: bool,
    pub max_decoded_bytes_per_slice: u64,
    pub max_symbol_ranges_per_slice: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportSelection {
    ExecutableSections,
    Sections {
        selectors: Vec<ReportSectionSelector>,
    },
    Symbols {
        names: Vec<String>,
    },
    Address {
        start_va: u64,
        extent: ReportAddressExtent,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSectionSelector {
    pub segment: String,
    pub section: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ReportAddressExtent {
    InstructionCount { value: u64 },
    ByteLength { value: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReportDecodeMode {
    Recovering,
    Strict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisassemblySlice {
    pub identity: ReportSliceIdentity,
    pub container_offset: u64,
    pub slice_size: u64,
    pub status: DisassemblyStatus,
    pub decoded_bytes: u64,
    pub decoded_bytes_truncated: bool,
    pub symbol_ranges_truncated: bool,
    pub regions: Vec<DisassemblyRegion>,
    pub issues: Vec<DisassemblyIssue>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DisassemblyStatus {
    Complete,
    Partial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisassemblyRegion {
    pub segment: String,
    pub section: String,
    pub selection_source: SelectionSource,
    pub range_source: Option<SymbolSource>,
    pub end_source: Option<RangeEndSource>,
    pub start_va: u64,
    pub requested_end_va: Option<u64>,
    pub requested_instruction_count: Option<u64>,
    pub emitted_instruction_count: u64,
    pub examined_end_va: u64,
    pub next_unexamined_va: Option<u64>,
    pub instruction_flags: InstructionFlags,
    pub labels: Vec<DisassemblyLabel>,
    pub records: Vec<DisassemblyRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionSource {
    ExecutableSection,
    ExplicitSection,
    Symbol,
    Address,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SymbolSource {
    Nlist,
    ExportTrie,
    ObjcMetadata,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeEndSource {
    Nlist,
    ExportTrie,
    ObjcMetadata,
    SectionEnd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionFlags {
    pub pure_instructions: bool,
    pub some_instructions: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisassemblyLabel {
    pub va: u64,
    pub raw_name: String,
    pub display_name: String,
    pub source: SymbolSource,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisassemblyRecord {
    Instruction {
        va: u64,
        thin_file_offset: u64,
        container_file_offset: u64,
        size: u64,
        bytes: HexBytes,
        text: String,
        kind: InstructionKind,
        direct_target: Option<DirectTarget>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        encoding: Option<InstructionEncoding>,
    },
    Gap {
        va: u64,
        thin_file_offset: u64,
        container_file_offset: u64,
        bytes: HexBytes,
        code: String,
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionEncoding {
    pub status: InstructionEncodingStatus,
    pub boundary_confidence: InstructionBoundaryConfidence,
    pub semantics: InstructionSemanticsStatus,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionEncodingStatus {
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionBoundaryConfidence {
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionSemanticsStatus {
    Unavailable,
}

impl DisassemblyRecord {
    pub fn va(&self) -> u64 {
        match self {
            Self::Instruction { va, .. } | Self::Gap { va, .. } => *va,
        }
    }

    pub fn byte_len(&self) -> u64 {
        match self {
            Self::Instruction { size, .. } => *size,
            Self::Gap { bytes, .. } => (bytes.as_str().len() / 2) as u64,
        }
    }

    pub fn thin_file_offset(&self) -> u64 {
        match self {
            Self::Instruction {
                thin_file_offset, ..
            }
            | Self::Gap {
                thin_file_offset, ..
            } => *thin_file_offset,
        }
    }

    pub fn container_file_offset(&self) -> u64 {
        match self {
            Self::Instruction {
                container_file_offset,
                ..
            }
            | Self::Gap {
                container_file_offset,
                ..
            } => *container_file_offset,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstructionKind {
    Branch,
    Call,
    ConditionalBranch,
    Return,
    Nop,
    PcRelative,
    Other,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DirectTarget {
    pub va: u64,
    pub raw_symbol: Option<String>,
    pub display_symbol: Option<String>,
    pub source: Option<SymbolSource>,
    pub offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisassemblyIssue {
    pub code: String,
    pub message: String,
}
