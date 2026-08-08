//! Canonical evidence-first C and C++ recovery report.

#![allow(missing_docs)]

mod validate;

pub use validate::RecoveryValidationError;

use serde::{Deserialize, Serialize};

use super::*;
use crate::analysis::hypothesis::{HypothesisLedger, HypothesisSelectionPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLanguage {
    CAbi,
    Cpp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryView {
    Surface,
    Header,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryScope {
    All,
    Defined,
    Referenced,
    SymbolOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisLevel {
    Sources,
    Abi,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Function,
    Data,
    Tls,
    RuntimeArtifact,
    Method,
    Type,
    Vtable,
    Typeinfo,
    Thunk,
    Guard,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Presence {
    Defined,
    Imported,
    Reexported,
    Tentative,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    Default,
    Hidden,
    Protected,
    PrivateExtern,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Weakness {
    Strong,
    WeakDefinition,
    WeakReference,
    Tentative,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityRole {
    Function,
    Data,
    Tls,
    RuntimeArtifact,
    CppMethod,
    CppStaticData,
    Type,
    Typeinfo,
    Vtable,
    Vtt,
    Thunk,
    Guard,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinkageFamily {
    Plain,
    ItaniumCpp,
    RustV0,
    RustLegacy,
    Swift,
    Objc,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayoutCompleteness {
    Complete,
    Partial,
    Opaque,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AbiValueClass {
    Integer,
    Floating,
    Vector,
    Aggregate,
    Indirect,
    Void,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    Nlist,
    ExportTrie,
    DyldBind,
    ChainedFixup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CollectorId {
    SymbolDiscovery,
    FunctionRanges,
    Dwarf,
    Rtti,
    Vtables,
    HeaderCorrelation,
    AbiBody,
    HeaderProjection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDiagnosticCode {
    MalformedKnownEncoding,
    ConflictingExactFacts,
    AmbiguousIdentity,
    UnmatchedOccurrence,
    CollectorUnsupported,
    CollectorFailed,
    CollectorTruncated,
    HeaderSyntaxInvalid,
    HeaderSemanticInvalid,
    UnsupportedHeaderSyntax,
    UnresolvedRequiredFact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionReason {
    WrongLanguage,
    UnselectedKind,
    UnselectedName,
    UnselectedPresence,
    DebugOnly,
    SyntheticNonEntity,
    DuplicateAlias,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    UnrecognizedEncoding,
    MalformedEncoding,
    AmbiguousRole,
    AmbiguousOwnership,
    MissingLocation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    NotEncoded,
    UnsupportedEncoding,
    MissingDependency,
    CollectorUnsupported,
    CollectorFailed,
    Truncated,
    Ambiguous,
    Conflicted,
    NotApplicable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReasonCode {
    Architecture,
    Format,
    MissingSection,
    MissingDebugInfo,
    MissingRuntimeMetadata,
    HeaderLanguageSubset,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HeaderIneligibilityReason {
    UnavailableRequiredFact,
    ConflictedRequiredFact,
    AbiClassIsNotSourceType,
    UnsupportedType,
    UnsupportedCallingConvention,
    UnprovenOwner,
    IncompleteLayout,
    IncompleteTemplateContext,
    InvalidLinkage,
    SemanticValidationFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryField {
    Linkage,
    DisplayName,
    Role,
    Presence,
    Visibility,
    Weakness,
    Location,
    Owner,
    ValueType,
    ReturnType,
    Parameters,
    Variadic,
    CallingConvention,
    Qualifiers,
    LayoutSize,
    LayoutAlignment,
    LayoutFields,
    LayoutCompleteness,
    Bases,
    VirtualSurface,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryLimitName {
    MaxObservations,
    MaxEntities,
    MaxEvidenceRecords,
    MaxRanges,
    MaxDwarfDies,
    MaxDecodedBytes,
    MaxHeaderFiles,
    MaxHeaderBytes,
    MaxDiagnostics,
    MaxSerializedBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetPolicy {
    AllObservations,
    SelectedEntities,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitySelection {
    pub scope: RecoveryScope,
    pub kinds: Vec<EntityKind>,
    pub name_globs: Vec<ValidatedGlob>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryLimits {
    pub max_observations: u64,
    pub max_entities: u64,
    pub max_evidence_records: u64,
    pub max_ranges: u64,
    pub max_dwarf_dies: u64,
    pub max_decoded_bytes: u64,
    pub max_header_files: u64,
    pub max_header_bytes: u64,
    pub max_diagnostics: u64,
    pub max_serialized_bytes: u64,
}

impl Default for RecoveryLimits {
    fn default() -> Self {
        Self {
            max_observations: 1_000_000,
            max_entities: 250_000,
            max_evidence_records: 2_000_000,
            max_ranges: 500_000,
            max_dwarf_dies: 2_000_000,
            max_decoded_bytes: 67_108_864,
            max_header_files: 10_000,
            max_header_bytes: 67_108_864,
            max_diagnostics: 100_000,
            max_serialized_bytes: 268_435_456,
        }
    }
}

impl RecoveryLimits {
    pub fn validate(&self) -> Result<(), RecoveryValidationError> {
        const MAXIMA: [u64; 10] = [
            8_000_000,
            2_000_000,
            8_000_000,
            4_000_000,
            16_000_000,
            1_073_741_824,
            100_000,
            536_870_912,
            1_000_000,
            1_073_741_824,
        ];
        let values = [
            self.max_observations,
            self.max_entities,
            self.max_evidence_records,
            self.max_ranges,
            self.max_dwarf_dies,
            self.max_decoded_bytes,
            self.max_header_files,
            self.max_header_bytes,
            self.max_diagnostics,
            self.max_serialized_bytes,
        ];
        for (index, (value, maximum)) in values.into_iter().zip(MAXIMA).enumerate() {
            if value == 0 || value > maximum {
                return Err(RecoveryValidationError::InvalidLimit {
                    index,
                    value,
                    maximum,
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashedHeaderFile {
    pub relative_path: String,
    pub content_sha256: ContentHash,
    pub byte_len: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HashedHeaderRoot {
    pub logical_label: LogicalInputLabel,
    pub content_hash: ContentHash,
    pub files: Vec<HashedHeaderFile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryRequestSummary {
    pub language: RecoveryLanguage,
    pub architectures: ArchitectureSelection,
    pub view: RecoveryView,
    pub selection: EntitySelection,
    pub analysis: AnalysisLevel,
    pub header_roots: Vec<HashedHeaderRoot>,
    /// Complete operator policy affecting hypothesis emission and projection.
    /// This participates in the canonical request digest.
    pub hypothesis_selection_policy: HypothesisSelectionPolicy,
    pub limits: RecoveryLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryInputs {
    pub image: ImageInputIdentity,
    pub selected_architecture: Architecture,
    pub header_roots: Vec<HashedHeaderRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorLimits {
    pub max_records: u64,
    pub max_bytes: u64,
    pub max_diagnostics: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedCollectorSpec {
    pub collector: CollectorId,
    pub target_entity_ids: Vec<EntityId>,
    pub required: bool,
    pub limits: CollectorLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderProjectionSpec {
    pub target_entity_ids: NonEmpty<EntityId>,
    pub language: RecoveryLanguage,
    /// Operator policy governing hypothesis selection for this projection.
    pub selection_policy: HypothesisSelectionPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedRecoveryPlan {
    pub request_digest: RequestDigest,
    pub discovery: Vec<ResolvedCollectorSpec>,
    pub selected_entity_ids: Vec<EntityId>,
    pub targeted: Vec<ResolvedCollectorSpec>,
    pub projection: Option<HeaderProjectionSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservationDisposition {
    Included { entity_ids: NonEmpty<EntityId> },
    Excluded { reason: ExclusionReason },
    Unknown { reason: UnknownReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolObservation {
    pub id: ObservationId,
    pub source: ObservationSource,
    pub ordinal: u64,
    pub raw_name: String,
    pub presence: Presence,
    pub address: Option<u64>,
    pub section: Option<SectionIdentity>,
    pub disposition: ObservationDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de> + PartialEq"))]
pub enum Fact<T> {
    Known {
        id: FactId,
        value: T,
        strength: EvidenceStrength,
        evidence_ids: NonEmpty<EvidenceId>,
    },
    Conflicted {
        id: FactId,
        candidates: AtLeastTwo<FactCandidate<T>>,
    },
    Unavailable {
        id: FactId,
        reason: UnavailableReason,
        evidence_ids: Vec<EvidenceId>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FactCandidate<T> {
    pub value: T,
    pub strength: EvidenceStrength,
    pub evidence_ids: NonEmpty<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkageEncoding {
    pub raw: String,
    pub normalized: String,
    pub family: LinkageFamily,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityOwner {
    pub path: Vec<Identifier>,
    /// Scope kinds parallel to `path`. `None` preserves an ABI-known name
    /// component whose namespace-vs-record kind is not encoded.
    pub scope_kinds: Vec<Option<HeaderOwnerKind>>,
    /// Access of each scope within its parent, parallel to `path`.
    pub scope_access: Vec<Option<Access>>,
    /// Access within the terminal record when proven by source evidence.
    pub member_access: Option<Access>,
    pub entity_id: Option<EntityId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TypeEvidence {
    Source {
        #[serde(rename = "type")]
        ty: HeaderType,
    },
    AbiClass {
        class: AbiValueClass,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ParameterList {
    Unspecified,
    Known { value: Vec<RecoveredParameter> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredParameter {
    pub type_evidence: Fact<TypeEvidence>,
    pub source_name: Fact<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionQualifiers {
    #[serde(rename = "const")]
    pub is_const: Option<bool>,
    #[serde(rename = "volatile")]
    pub is_volatile: Option<bool>,
    pub reference: Option<ReferenceKind>,
    pub noexcept: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredSignature {
    pub return_type: Fact<TypeEvidence>,
    pub parameters: Fact<ParameterList>,
    pub variadic: Fact<bool>,
    pub calling_convention: Fact<CallingConvention>,
    pub qualifiers: Fact<FunctionQualifiers>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredField {
    pub name: Fact<String>,
    #[serde(rename = "type")]
    pub ty: Fact<TypeEvidence>,
    pub offset: Fact<u64>,
    pub bit_width: Fact<Option<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseRelation {
    pub base: EntityId,
    pub offset: Fact<u64>,
    pub access: Fact<Access>,
    #[serde(rename = "virtual")]
    pub is_virtual: Fact<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VirtualMember {
    pub slot: u32,
    pub target: Fact<EntityId>,
    pub adjustment: Fact<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredLayout {
    pub size: Fact<u64>,
    pub alignment: Fact<u64>,
    pub fields: Fact<Vec<RecoveredField>>,
    pub completeness: Fact<LayoutCompleteness>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredHierarchy {
    pub bases: Fact<Vec<BaseRelation>>,
    pub virtual_surface: Fact<Vec<VirtualMember>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum RecoveryGapReason {
    Unavailable { reason: UnavailableReason },
    Conflicted { fact_id: FactId },
    HeaderIneligible { reason: HeaderIneligibilityReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGap {
    pub id: RecoveryGapId,
    pub field: RecoveryField,
    pub reason: RecoveryGapReason,
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymbolEvidence {
    pub raw_name: String,
    pub normalized_linkage: String,
    pub source: ObservationSource,
    pub ordinal: u64,
    pub presence: Presence,
    pub address: Option<u64>,
    pub section: Option<SectionIdentity>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeEvidence {
    pub start: u64,
    pub end_exclusive: u64,
    pub source: RangeSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DwarfTag {
    Subprogram,
    Variable,
    StructureType,
    ClassType,
    UnionType,
    EnumerationType,
    Member,
    Inheritance,
    FormalParameter,
    UnspecifiedParameters,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DwarfAttribute {
    Name,
    LinkageName,
    Type,
    ByteSize,
    Alignment,
    DataMemberLocation,
    LowPc,
    HighPc,
    CallingConvention,
    Declaration,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeSource {
    FunctionStarts,
    UnwindInfo,
    Dwarf,
    SymbolAdjacency,
    SectionBounds,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RttiKind {
    ClassTypeInfo,
    SiClassTypeInfo,
    VmiClassTypeInfo,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VtableKind {
    Primary,
    Secondary,
    Construction,
    Vtt,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DwarfEvidence {
    pub unit_offset: u64,
    pub die_offset: u64,
    pub tag: DwarfTag,
    pub attribute: DwarfAttribute,
    pub source_file: Option<ContentHash>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RttiEvidence {
    pub kind: RttiKind,
    pub address: u64,
    pub type_identity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VtableEvidence {
    pub address: u64,
    pub owner: Option<EntityId>,
    pub slot: Option<u32>,
    pub target: Option<EntityId>,
    pub kind: VtableKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderCorrelationEvidence {
    pub root_label: LogicalInputLabel,
    pub relative_path: String,
    pub content_sha256: ContentHash,
    pub start_byte: u64,
    pub end_byte: u64,
    pub declaration: HeaderDecl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AbiEvidence {
    pub architecture: Architecture,
    pub entity_id: EntityId,
    pub range: AddressRange,
    pub return_class: AbiValueClass,
    pub parameter_classes: Vec<AbiValueClass>,
    pub decode_gaps: Vec<AddressRange>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidencePayload {
    Symbol { value: SymbolEvidence },
    Dwarf { value: DwarfEvidence },
    Range { value: RangeEvidence },
    Rtti { value: RttiEvidence },
    Vtable { value: VtableEvidence },
    Header { value: HeaderCorrelationEvidence },
    Abi { value: AbiEvidence },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRecord {
    pub id: EvidenceId,
    pub collector: CollectorId,
    pub observation_ids: Vec<ObservationId>,
    pub strength: EvidenceStrength,
    pub payload: EvidencePayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredEntity {
    pub id: EntityId,
    pub identity_stability: IdentityStability,
    pub observation_ids: NonEmpty<ObservationId>,
    pub linkage: Fact<LinkageEncoding>,
    pub display_name: Fact<String>,
    pub role: Fact<EntityRole>,
    pub presence: Fact<Presence>,
    pub visibility: Fact<Visibility>,
    pub weakness: Fact<Weakness>,
    pub location: Fact<EntityLocation>,
    pub owner: Fact<EntityOwner>,
    pub value_type: Fact<TypeEvidence>,
    pub signature: RecoveredSignature,
    pub layout: RecoveredLayout,
    pub hierarchy: RecoveredHierarchy,
    pub evidence: Vec<EvidenceRecord>,
    pub gaps: Vec<RecoveryGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDiagnostic {
    pub id: DiagnosticId,
    pub code: RecoveryDiagnosticCode,
    pub severity: Severity,
    pub message: String,
    pub observation_id: Option<ObservationId>,
    pub entity_id: Option<EntityId>,
    pub evidence_ids: Vec<EvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Truncation {
    pub collector: CollectorId,
    pub limit_name: RecoveryLimitName,
    pub limit: u64,
    pub collected: u64,
    pub omitted_lower_bound: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CollectorOutcome {
    Complete,
    Unsupported { reason: UnsupportedReasonCode },
    Failed { diagnostic_id: DiagnosticId },
    Truncated { truncation_index: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorCounts {
    pub input_records: u64,
    pub output_records: u64,
    pub selected_targets: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CollectorExecution {
    pub collector: CollectorId,
    pub request_digest: RequestDigest,
    pub target_entity_ids: Vec<EntityId>,
    pub outcome: CollectorOutcome,
    pub counts: CollectorCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderGap {
    pub id: RecoveryGapId,
    pub entity_id: EntityId,
    pub field: RecoveryField,
    pub reason: HeaderIneligibilityReason,
    pub declaration_template: Option<HeaderDecl>,
    pub diagnostic_ids: Vec<DiagnosticId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderProjection {
    pub language: RecoveryLanguage,
    pub declarations: Vec<HeaderDecl>,
    pub unresolved: Vec<HeaderGap>,
    /// Ranked blockers and complete receipts for assumptions used by this
    /// projection. These records never become recovered facts.
    pub assumption_ledger: HypothesisLedger,
    pub diagnostics: Vec<RecoveryDiagnostic>,
    pub source: String,
    pub validation: HeaderValidationReport,
}

/// Reconstructs the exact conspicuous prefix required whenever selected
/// hypotheses affected a recovery header.
pub(crate) fn recovery_assumption_preamble(
    ledger: &HypothesisLedger,
    declarations: &[HeaderDecl],
) -> String {
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    let mut source = String::from(
        "/*\n * GENERATED BY MACHO USING EXPLICITLY AUTHORIZED ASSUMPTIONS.\n * These declarations are projections, not recovered facts.\n * Machine-readable receipts: JSON slices[].header.assumption_ledger.selections.\n",
    );
    for receipt in &ledger.selections {
        let _ = writeln!(
            source,
            " * {}:{} => {} ({:?} evidence, {:?} decision, {} bp).",
            receipt.subject.domain,
            receipt.subject.key,
            receipt.chosen_candidate_id,
            receipt.evidence_authority,
            receipt.decision_authority,
            receipt.confidence_basis_points
        );
    }
    source.push_str(" */\n");
    let mut declared_entities = BTreeSet::new();
    for declaration in declarations {
        collect_header_declaration_entities(declaration, &mut declared_entities);
    }
    let opaque_types = ledger
        .selections
        .iter()
        .filter(|receipt| receipt.chosen_candidate_id == "opaque_return_type")
        .filter(|receipt| {
            receipt.consequences.iter().any(|consequence| {
                consequence
                    .subject
                    .as_ref()
                    .is_some_and(|subject| declared_entities.contains(subject))
            })
        })
        .map(|receipt| format!("macho_unknown_return_{}", receipt.subject.key))
        .collect::<BTreeSet<_>>();
    for opaque_type in &opaque_types {
        let _ = writeln!(source, "class {opaque_type};");
    }
    if !opaque_types.is_empty() {
        source.push('\n');
    }
    source
}

fn collect_header_declaration_entities(
    declaration: &HeaderDecl,
    entities: &mut std::collections::BTreeSet<String>,
) {
    match declaration {
        HeaderDecl::Function { id, .. }
        | HeaderDecl::Variable { id, .. }
        | HeaderDecl::Record { id, .. }
        | HeaderDecl::Forward { id, .. }
        | HeaderDecl::Alias { id, .. } => {
            entities.insert(id.to_string());
        }
        HeaderDecl::ObjcInterface { .. }
        | HeaderDecl::ObjcCategory { .. }
        | HeaderDecl::ObjcProtocol { .. }
        | HeaderDecl::ObjcForward { .. } => {}
    }
    if let HeaderDecl::Record { members, .. } = declaration {
        for member in members {
            collect_header_declaration_entities(&member.declaration, entities);
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SliceRecovery {
    pub architecture: Architecture,
    pub image: ImageIdentity,
    pub inputs: RecoveryInputs,
    pub resolved_plan: ResolvedRecoveryPlan,
    pub executions: NonEmpty<CollectorExecution>,
    pub observations: Vec<SymbolObservation>,
    pub entities: Vec<RecoveredEntity>,
    pub header: Option<HeaderProjection>,
    pub diagnostics: Vec<RecoveryDiagnostic>,
    pub truncations: Vec<Truncation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryReport {
    pub schema_version: RecoverySchemaVersion,
    pub language: RecoveryLanguage,
    pub request: RecoveryRequestSummary,
    pub slices: NonEmpty<SliceRecovery>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn limits_reject_zero_and_values_above_hard_maximum() {
        let mut limits = RecoveryLimits {
            max_entities: 0,
            ..RecoveryLimits::default()
        };
        assert!(matches!(
            limits.validate(),
            Err(RecoveryValidationError::InvalidLimit { .. })
        ));
        limits.max_entities = 2_000_001;
        assert!(limits.validate().is_err());
    }

    #[test]
    fn strict_request_rejects_unknown_keys() {
        let value = serde_json::json!({
            "language": "c_abi",
            "architectures": {"kind": "all"},
            "view": "surface",
            "selection": {"scope":"all","kinds":[],"name_globs":[]},
            "analysis": "sources",
            "header_roots": [],
            "hypothesis_selection_policy": {"mode": "strict", "overrides": []},
            "limits": RecoveryLimits::default(),
            "invented": true
        });
        assert!(serde_json::from_value::<RecoveryRequestSummary>(value).is_err());
    }

    #[test]
    fn recovery_schema_three_rejects_version_two_artifacts() {
        assert!(serde_json::from_value::<RecoverySchemaVersion>(serde_json::json!(3)).is_ok());
        assert!(serde_json::from_value::<RecoverySchemaVersion>(serde_json::json!(2)).is_err());
    }
}
