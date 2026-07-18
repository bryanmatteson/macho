#![allow(missing_docs)]

use serde::{Deserialize, Serialize};

use super::super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCPresence {
    Defined,
    Referenced,
    Partial,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCCollectorId {
    RuntimeMetadata,
    SemanticGraph,
    HeaderProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCEvidenceKind {
    ClassRo,
    Category,
    Protocol,
    MethodList,
    PropertyList,
    IvarList,
    ClassRef,
    ProtocolRef,
    SelectorRef,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCObservationSource {
    ClassList,
    CategoryList,
    ProtocolList,
    ClassRefs,
    ProtocolRefs,
    SelectorRefs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCExclusionReason {
    UnselectedClass,
    UnselectedSelector,
    DuplicateAlias,
    NonObjectiveCRecord,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCUnavailableReason {
    NotEncoded,
    MalformedEncoding,
    UnresolvedReference,
    AmbiguousOwner,
    ConflictingMetadata,
    Truncated,
    UnsupportedEncoding,
    SemanticValidationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCDiagnosticCode {
    MalformedMetadata,
    MalformedEncoding,
    SelectorArityMismatch,
    AmbiguousCategoryOrder,
    GraphCycle,
    UnresolvedReference,
    ConflictingMetadata,
    CollectorFailed,
    CollectorTruncated,
    HeaderSyntaxInvalid,
    HeaderSemanticInvalid,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCPrimitive {
    Void,
    Char,
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
    Bool,
    Cstring,
    UnknownObject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCQualifier {
    Const,
    In,
    Inout,
    Out,
    Bycopy,
    Byref,
    Oneway,
    Atomic,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCOwnership {
    Assign,
    Copy,
    Retain,
    Strong,
    Weak,
    UnsafeUnretained,
    Unspecified,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCMethodKind {
    Instance,
    Class,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjCGraphEdgeKind {
    Superclass,
    AdoptsProtocol,
    ExtendsClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCCandidate<T> {
    pub value: T,
    pub evidence: NonEmpty<ObjCEvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de> + PartialEq"))]
pub enum ObjCValue<T> {
    Known {
        value: T,
        evidence: NonEmpty<ObjCEvidenceId>,
    },
    Conflicted {
        candidates: AtLeastTwo<ObjCCandidate<T>>,
    },
    Unavailable {
        reason: ObjCUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCMetadataLocation {
    pub virtual_address: u64,
    pub file_offset: Option<u64>,
    pub section: Option<SectionIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCTypeRef {
    pub entity_id: Option<ObjCEntityId>,
    pub name: String,
    pub presence: ObjCPresence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImplementationLocation {
    pub virtual_address: u64,
    pub file_offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCMethodSignature {
    pub return_type: ObjCEncodedType,
    pub parameters: Vec<ObjCEncodedType>,
    pub frame_size: Option<u64>,
    pub argument_offsets: Vec<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCPropertyAttributes {
    pub r#type: ObjCEncodedType,
    pub readonly: bool,
    pub ownership: ObjCOwnership,
    pub nonatomic: bool,
    pub dynamic: bool,
    pub getter: Option<Selector>,
    pub setter: Option<Selector>,
    pub ivar: Option<String>,
    pub unknown: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjCEncodedType {
    Primitive {
        value: ObjCPrimitive,
        qualifiers: Vec<ObjCQualifier>,
    },
    Object {
        name: Option<String>,
        protocols: Vec<String>,
        qualifiers: Vec<ObjCQualifier>,
    },
    Class,
    Selector,
    Block {
        signature: Option<Box<ObjCMethodSignature>>,
    },
    Pointer {
        pointee: Box<ObjCEncodedType>,
    },
    Array {
        count: u64,
        element: Box<ObjCEncodedType>,
    },
    Record {
        record_kind: RecordKind,
        name: Option<String>,
        fields: Vec<ObjCEncodedType>,
    },
    Bitfield {
        width: u32,
    },
    Unknown {
        raw: HexBytes,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCEvidence {
    pub id: ObjCEvidenceId,
    pub observation_ids: NonEmpty<ObjCObservationId>,
    pub kind: ObjCEvidenceKind,
    pub location: ObjCMetadataLocation,
    pub raw: HexBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjCObservationDisposition {
    Included { entity_ids: NonEmpty<ObjCEntityId> },
    Referenced { entity_id: ObjCEntityId },
    Malformed { diagnostic_id: ObjCDiagnosticId },
    Excluded { reason: ObjCExclusionReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCObservation {
    pub id: ObjCObservationId,
    pub source: ObjCObservationSource,
    pub location: ObjCMetadataLocation,
    pub raw: HexBytes,
    pub disposition: ObjCObservationDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCEntityCommon {
    pub id: ObjCEntityId,
    pub presence: ObjCPresence,
    pub name: ObjCValue<String>,
    pub observation_ids: NonEmpty<ObjCObservationId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCMethod {
    pub id: ObjCMemberId,
    pub selector: ObjCValue<Selector>,
    pub kind: ObjCMethodKind,
    pub raw_encoding: HexBytes,
    pub signature: ObjCValue<ObjCMethodSignature>,
    pub implementation: ObjCValue<Option<ImplementationLocation>>,
    pub origin: ObjCEntityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCProperty {
    pub id: ObjCMemberId,
    pub name: ObjCValue<String>,
    pub raw_attributes: HexBytes,
    pub parsed_attributes: ObjCValue<ObjCPropertyAttributes>,
    pub origin: ObjCEntityId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCIvar {
    pub id: ObjCMemberId,
    pub name: ObjCValue<String>,
    pub raw_encoding: HexBytes,
    pub parsed_type: ObjCValue<ObjCEncodedType>,
    pub offset: ObjCValue<u64>,
    pub size: ObjCValue<u64>,
    pub alignment: ObjCValue<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCClassEntity {
    pub common: ObjCEntityCommon,
    pub superclass: ObjCValue<Option<ObjCTypeRef>>,
    pub adopted_protocols: Vec<ObjCTypeRef>,
    pub ivars: Vec<ObjCIvar>,
    pub properties: Vec<ObjCProperty>,
    pub instance_methods: Vec<ObjCMethod>,
    pub class_methods: Vec<ObjCMethod>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCCategoryEntity {
    pub common: ObjCEntityCommon,
    pub extended_class: ObjCValue<ObjCTypeRef>,
    pub adopted_protocols: Vec<ObjCTypeRef>,
    pub properties: Vec<ObjCProperty>,
    pub instance_methods: Vec<ObjCMethod>,
    pub class_methods: Vec<ObjCMethod>,
    pub fold_order: ObjCValue<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCProtocolEntity {
    pub common: ObjCEntityCommon,
    pub adopted_protocols: Vec<ObjCTypeRef>,
    pub required_instance_methods: Vec<ObjCMethod>,
    pub required_class_methods: Vec<ObjCMethod>,
    pub optional_instance_methods: Vec<ObjCMethod>,
    pub optional_class_methods: Vec<ObjCMethod>,
    pub properties: Vec<ObjCProperty>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ObjCEntity {
    Class(ObjCClassEntity),
    Category(ObjCCategoryEntity),
    Protocol(ObjCProtocolEntity),
}

impl ObjCEntity {
    pub fn common(&self) -> &ObjCEntityCommon {
        match self {
            Self::Class(value) => &value.common,
            Self::Category(value) => &value.common,
            Self::Protocol(value) => &value.common,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCGraphNode {
    pub entity_id: ObjCEntityId,
    pub presence: ObjCPresence,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCGraphEdge {
    pub from: ObjCEntityId,
    pub to: ObjCEntityId,
    pub kind: ObjCGraphEdgeKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCSelectorOwner {
    pub selector: Selector,
    pub method_kind: ObjCMethodKind,
    pub effective_owner: Option<ObjCEntityId>,
    pub candidates: Vec<ObjCMemberId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCGraph {
    pub nodes: Vec<ObjCGraphNode>,
    pub inheritance: Vec<ObjCGraphEdge>,
    pub conformances: Vec<ObjCGraphEdge>,
    pub categories: Vec<ObjCGraphEdge>,
    pub selector_owners: Vec<ObjCSelectorOwner>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCPartitionCounts {
    pub defined_entities: u64,
    pub referenced_entities: u64,
    pub partial_entities: u64,
    pub malformed_observations: u64,
    pub excluded_observations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCSelectionResult {
    pub selected_entity_ids: Vec<ObjCEntityId>,
    pub totals: ObjCPartitionCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObjCCollectorOutcome {
    Complete,
    Unsupported { reason: ObjCUnavailableReason },
    Failed { diagnostic_id: ObjCDiagnosticId },
    Truncated { omitted_lower_bound: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCCollectorExecution {
    pub collector: ObjCCollectorId,
    pub outcome: ObjCCollectorOutcome,
    pub input_records: u64,
    pub output_records: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCDiagnostic {
    pub id: ObjCDiagnosticId,
    pub code: ObjCDiagnosticCode,
    pub severity: Severity,
    pub message: String,
    pub observation_id: Option<ObjCObservationId>,
    pub entity_id: Option<ObjCEntityId>,
    pub evidence_ids: Vec<ObjCEvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCHeaderGap {
    pub entity_id: ObjCEntityId,
    pub member_id: Option<ObjCMemberId>,
    pub reason: ObjCUnavailableReason,
    pub diagnostic_ids: Vec<ObjCDiagnosticId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCHeaderProjection {
    pub declarations: Vec<HeaderDecl>,
    pub unresolved: Vec<ObjCHeaderGap>,
    pub source: String,
    pub validation: HeaderValidationReport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCSliceReport {
    pub architecture: Architecture,
    pub image: ImageIdentity,
    pub graph: ObjCGraph,
    pub entities: Vec<ObjCEntity>,
    pub observations: Vec<ObjCObservation>,
    pub evidence: Vec<ObjCEvidence>,
    pub selection: ObjCSelectionResult,
    pub header: Option<ObjCHeaderProjection>,
    pub diagnostics: Vec<ObjCDiagnostic>,
    pub executions: NonEmpty<ObjCCollectorExecution>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjCReport {
    pub schema_version: ObjCReportVersion,
    pub slices: NonEmpty<ObjCSliceReport>,
}
