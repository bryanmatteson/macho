//! Stable public contracts for steerable and explainable program recovery.
//!
//! Structural subject keys are intentionally independent of display names and
//! evidence ordinals. Recovery points and signals additionally carry the exact
//! selected-image identity so guidance cannot silently bind to changed bytes.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::control_flow::{ControlFlowEdgeKind, ControlFlowIndex};
use crate::analysis::executable_bytes::{
    ExecutableByteEvidence, ExecutableByteIndex, ExecutableByteKind,
};
use crate::analysis::functions::{
    FunctionEntryCandidateDisposition, FunctionEvidenceSource, FunctionOwnershipConfidence,
};
use crate::analysis::functions::{
    FunctionEvidenceConfidence, FunctionImageIdentity, FunctionIndex,
};
use crate::analysis::xref::{Xref, XrefIndex, XrefKind, XrefTarget};

/// Current major version of the steerable-recovery wire contract.
pub const RECOVERY_CONTRACT_MAJOR: u16 = 1;
/// Current minor version of the steerable-recovery wire contract.
pub const RECOVERY_CONTRACT_MINOR: u16 = 0;

/// Exact thin-image identity used by all program-recovery layers.
pub type ProgramImageIdentity = FunctionImageIdentity;

/// Stable target identity for one cross-reference subject.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RecoveryReferenceTargetKey {
    /// Address inside the selected image.
    Internal {
        /// Target virtual address.
        address: u64,
    },
    /// Imported symbol identity.
    Import {
        /// Mach-O library ordinal.
        ordinal: i32,
        /// Imported linkage name. This is semantic binding identity, not a
        /// recovered display name.
        name: String,
    },
}

/// Stable kind identity for one cross-reference subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryReferenceKind {
    /// Indirect-symbol stub or pointer-slot reference.
    Stub,
    /// Dyld chained import binding.
    ChainedBind,
    /// Dyld chained in-image rebase.
    ChainedRebase,
    /// Legacy dyld in-image rebase opcode.
    LegacyRebase,
    /// Legacy dyld binding opcode.
    LegacyBind,
    /// Mach-O relocation record.
    Relocation,
    /// Decoded direct branch or call target.
    DirectBranch,
    /// Decoded non-control-flow address use.
    Data,
}

impl From<XrefKind> for RecoveryReferenceKind {
    fn from(kind: XrefKind) -> Self {
        match kind {
            XrefKind::Stub => Self::Stub,
            XrefKind::ChainedBind => Self::ChainedBind,
            XrefKind::ChainedRebase => Self::ChainedRebase,
            XrefKind::LegacyRebase => Self::LegacyRebase,
            XrefKind::LegacyBind => Self::LegacyBind,
            XrefKind::Relocation => Self::Relocation,
            XrefKind::DirectBranch => Self::DirectBranch,
            XrefKind::Data => Self::Data,
        }
    }
}

/// Version of serialized recovery questions, guides, and derivations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryContractSchema {
    /// Breaking contract version.
    pub major: u16,
    /// Backward-compatible contract revision.
    pub minor: u16,
}

/// Canonical half-open address range used by caller-authored recovery premises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryAddressRange {
    /// First included virtual address.
    pub start: u64,
    /// First excluded virtual address.
    pub end_exclusive: u64,
}

impl RecoveryAddressRange {
    /// Construct a non-empty half-open range.
    pub fn new(start: u64, end_exclusive: u64) -> Result<Self, RecoveryGuideBuildError> {
        if start >= end_exclusive {
            return Err(RecoveryGuideBuildError::EmptyOrReversedRange);
        }
        Ok(Self {
            start,
            end_exclusive,
        })
    }
}

impl RecoveryContractSchema {
    /// Schema emitted by this library version.
    pub const CURRENT: Self = Self {
        major: RECOVERY_CONTRACT_MAJOR,
        minor: RECOVERY_CONTRACT_MINOR,
    };
}

/// Name-independent, image-local identity of a recovered or unresolved object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProgramSubjectKey {
    /// Established function entry.
    Function {
        /// Function entry address.
        entry: u64,
    },
    /// Candidate function entry.
    FunctionCandidate {
        /// Candidate entry address.
        address: u64,
    },
    /// A resolved relationship between a candidate address and existing function.
    FunctionRelationship {
        /// Candidate address being interpreted.
        address: u64,
        /// Existing owning function entry.
        owner_entry: u64,
    },
    /// Independently observed function entry displaced by guided data ownership.
    SuppressedFunctionEntry {
        /// Observed entry address.
        entry: u64,
        /// Guided data-range start.
        range_start: u64,
        /// Exclusive guided data-range end.
        range_end_exclusive: u64,
    },
    /// One half-open function range.
    FunctionRange {
        /// Owning function entry.
        function_entry: u64,
        /// Range start.
        start: u64,
        /// Exclusive range end.
        end_exclusive: u64,
    },
    /// Function-local basic block.
    BasicBlock {
        /// Owning function entry.
        function_entry: u64,
        /// Block start.
        start: u64,
    },
    /// One decoded instruction boundary.
    Instruction {
        /// Instruction start.
        address: u64,
        /// Instruction width in bytes.
        byte_len: u8,
    },
    /// One supported interpretation of bytes beginning at an address.
    InstructionInterpretation {
        /// Instruction start.
        address: u64,
        /// Instruction width in bytes.
        byte_len: u8,
        /// SHA-256 of the interpreted instruction bytes.
        encoding_sha256: String,
    },
    /// One control-flow edge.
    ControlFlowEdge {
        /// Owning function entry.
        function_entry: u64,
        /// Source instruction or block coordinate.
        source: u64,
        /// Destination coordinate.
        target: u64,
        /// Exact edge semantics. Endpoints alone are not a unique edge key.
        edge_kind: ControlFlowEdgeKind,
    },
    /// One aggregated direct-call relationship.
    DirectCall {
        /// Caller function entry.
        caller: u64,
        /// Callee function entry.
        callee: u64,
    },
    /// One exact decoded direct-call observation.
    DirectCallsite {
        /// Caller function entry.
        caller: u64,
        /// Exact call instruction address.
        instruction_address: u64,
        /// Exact decoded direct target, whether or not it is a function entry.
        target_address: u64,
    },
    /// One direct inter-procedural transfer observation.
    DirectTransfer {
        /// Source function entry.
        function_entry: u64,
        /// Controlling branch instruction.
        instruction_address: u64,
        /// Decoded direct target.
        target_address: u64,
    },
    /// One recovered jump table.
    JumpTable {
        /// Indirect dispatch instruction.
        instruction_address: u64,
        /// First table byte.
        table_address: u64,
        /// Exclusive table end.
        end_exclusive: u64,
    },
    /// One indirect control transfer.
    IndirectTransfer {
        /// Owning function entry.
        function_entry: u64,
        /// Transfer instruction.
        instruction_address: u64,
    },
    /// One recovered cross-reference.
    CrossReference {
        /// Reference source coordinate.
        source: u64,
        /// Internal address or imported binding identity.
        target: RecoveryReferenceTargetKey,
        /// Stable xref-kind code.
        reference_kind: RecoveryReferenceKind,
    },
    /// One caller-guided owner selected for an exact cross-reference use.
    ///
    /// This is an ownership relation for the reference source, not exclusive
    /// ownership of its target. Several functions can therefore retain
    /// independent references to the same string or data object.
    ReferenceOwnership {
        /// Reference source coordinate.
        source: u64,
        /// Internal address or imported binding identity.
        target: RecoveryReferenceTargetKey,
        /// Stable xref-kind code.
        reference_kind: RecoveryReferenceKind,
        /// Selected owning function entry.
        function_entry: u64,
    },
    /// One conserved executable-byte span.
    ExecutableByteRange {
        /// Global Mach-O section ordinal.
        section_ordinal: u64,
        /// Range start.
        start: u64,
        /// Exclusive range end.
        end_exclusive: u64,
    },
    /// One data object beginning at an address.
    DataObject {
        /// Object start address.
        address: u64,
    },
    /// One best-known function signature.
    FunctionSignature {
        /// Recovered function entry.
        function_entry: u64,
    },
    /// One CFI-derived stack-frame summary.
    StackFrame {
        /// Recovered function entry.
        function_entry: u64,
    },
    /// One DWARF local or formal parameter.
    LocalVariable {
        /// Physical DIE offset.
        die_offset: u64,
    },
    /// One typed conflict between retained recovery claims.
    Conflict {
        /// Stable conflict-kind code.
        conflict_kind: String,
        /// Primary conflict coordinate.
        address: u64,
        /// Optional second conflict coordinate.
        related_address: Option<u64>,
    },
    /// One unresolved recovery frontier.
    Frontier {
        /// Layer-specific stable kind code.
        layer: String,
        /// First unresolved coordinate.
        address: Option<u64>,
    },
}

/// Kind of ambiguity represented by a recovery point.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryQuestionKind {
    /// Whether an observed address is a function entry.
    FunctionEntry,
    /// Whether a function candidate is standalone, alternate, or a fragment.
    FunctionRelationship,
    /// Which ranges belong to a function.
    FunctionRanges,
    /// Which function owns a range.
    RangeOwnership,
    /// Which supported instruction boundary applies.
    InstructionBoundary,
    /// Whether executable bytes are instructions, embedded data, or another role.
    ByteRole,
    /// Whether a candidate CFG edge is feasible.
    ControlFlowEdge,
    /// Whether one exact decoded direct-call observation is valid.
    DirectCall,
    /// Which recovered function owns one exact cross-reference use.
    ReferenceOwnership,
    /// Whether a call returns normally.
    NonReturningCall,
    /// Which indirect targets are feasible.
    IndirectTargets,
    /// Which ABI or signature applies.
    FunctionAbi,
    /// Which runtime implementation candidates apply.
    RuntimeDispatch,
    /// Which image satisfies a dependency.
    DependencyImage,
}

/// Exact image-bound identity of one recovery question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPointKey {
    /// Exact selected-image identity.
    pub image: ProgramImageIdentity,
    /// Structural subject independent of names.
    pub subject: ProgramSubjectKey,
    /// Ambiguity being asked about the subject.
    pub kind: RecoveryQuestionKind,
}

/// A caller-selectable interpretation for a recovery question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryChoice {
    /// Classify an executable range with one supported byte role.
    ByteRole {
        /// Selected executable-byte classification.
        role: ExecutableByteKind,
    },
    /// Preserve the current unresolved interpretation.
    KeepUnresolved,
    /// Accept an address as a standalone function entry.
    AcceptFunctionEntry,
    /// Use the supplied ranges for one function in the selected guided view.
    FunctionRanges {
        /// Ordered, non-overlapping half-open ranges. One range must begin at
        /// the function entry.
        ranges: Vec<RecoveryAddressRange>,
    },
    /// Attach a candidate entry or range to an existing function.
    FunctionRelationship {
        /// Existing function entry.
        owner_entry: u64,
        /// Selected structural relationship.
        relationship: FunctionRelationshipChoice,
    },
    /// Suppress one exact intra-procedural CFG edge in the guided fact view.
    SuppressControlFlowEdge,
    /// Suppress one exact decoded direct-call observation in the guided fact view.
    SuppressDirectCall,
    /// Select one already-recovered source-range owner for an exact reference.
    ReferenceOwner {
        /// Selected recovered function entry.
        function_entry: u64,
    },
    /// Reject a candidate interpretation.
    Reject,
}

/// Caller-selectable structural relationship for a function candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionRelationshipChoice {
    /// A second supported entry into the same function body.
    AlternateEntry,
    /// A discontiguous cold fragment owned by the function.
    ColdFragment,
    /// A range intentionally shared with the function.
    SharedRange,
}

/// Stable kind of independently recovered signal participating in a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoverySignalKind {
    /// Function-entry metadata or language evidence.
    FunctionEntry,
    /// Candidate entry evidence such as a decoded call target.
    FunctionEntryCandidate,
    /// Existing function-range ownership relevant to a candidate relationship.
    RangeOwnership,
    /// A decoded control-flow target.
    ControlFlowTarget,
    /// A recovered bounded jump table.
    JumpTable,
    /// A recovered inline literal.
    InlineLiteral,
}

/// One durable caller-guided ownership relation for an exact reference use.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuidedReferenceOwnership {
    /// Reference source coordinate.
    pub source: u64,
    /// Internal address or imported binding identity.
    pub target: RecoveryReferenceTargetKey,
    /// Stable xref-kind code.
    pub reference_kind: RecoveryReferenceKind,
    /// Selected owning function entry.
    pub function_entry: u64,
}

impl GuidedReferenceOwnership {
    /// Stable Fact IR subject for this guided relation.
    pub fn subject(&self) -> ProgramSubjectKey {
        ProgramSubjectKey::ReferenceOwnership {
            source: self.source,
            target: self.target.clone(),
            reference_kind: self.reference_kind,
            function_entry: self.function_entry,
        }
    }
}

/// Exact image-bound identity of one recovery signal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySignalKey {
    /// Exact selected-image identity.
    pub image: ProgramImageIdentity,
    /// Kind of retained signal.
    pub kind: RecoverySignalKind,
    /// Structural subject established or proposed by the signal.
    pub subject: ProgramSubjectKey,
    /// Format or analysis source when the signal is a function observation.
    pub evidence_source: Option<FunctionEvidenceSource>,
    /// Source coordinate, when distinct from the subject.
    pub source_address: Option<u64>,
}

/// One typed signal explaining a possible interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoverySignal {
    /// Stable signal identity.
    pub key: RecoverySignalKey,
    /// Epistemic strength of the signal.
    pub confidence: FunctionEvidenceConfidence,
    /// Choices this signal supports.
    pub supports: Vec<RecoveryChoice>,
}

/// Program layer whose result can change after answering a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecoveryLayer {
    /// Function identities and ranges.
    Functions,
    /// Executable byte ownership and roles.
    ExecutableBytes,
    /// Basic blocks and control-flow edges.
    ControlFlow,
    /// Direct and indirect call relationships.
    Calls,
    /// Cross references.
    References,
    /// Sparse abstract value flow.
    ValueFlow,
    /// Data objects, signatures, stack frames, and local variables.
    Semantics,
}

/// Conservative estimate of the layers affected by a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryEffectEstimate {
    /// Deterministically ordered affected layers.
    pub affected_layers: Vec<RecoveryLayer>,
}

/// One stable ambiguity where additional knowledge can change recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryQuestion {
    /// Exact image-bound question identity.
    pub key: RecoveryPointKey,
    /// Name-independent structural subject.
    pub subject: ProgramSubjectKey,
    /// Kind of ambiguity.
    pub kind: RecoveryQuestionKind,
    /// Supported caller interpretations.
    pub choices: Vec<RecoveryChoice>,
    /// Independently retained competing signals.
    pub signals: Vec<RecoverySignal>,
    /// Layers that may change if the interpretation changes.
    pub estimated_effect: RecoveryEffectEstimate,
}

/// One neutral caller-selected interpretation of a current recovery question.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecision {
    /// Exact question being answered.
    pub point: RecoveryPointKey,
    /// Requested interpretation.
    pub choice: RecoveryChoice,
    /// Optional signals the caller expects to remain present before applying
    /// the decision.
    #[serde(default)]
    pub expected_signals: Vec<RecoverySignalKey>,
}

/// Serializable, image-bound collection of neutral recovery decisions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGuide {
    /// Recovery wire-contract version.
    pub schema: RecoveryContractSchema,
    /// Exact selected image to which every decision must bind.
    pub image: ProgramImageIdentity,
    /// Ordered recovery decisions.
    pub decisions: Vec<RecoveryDecision>,
}

/// Invalid caller-authored guide construction.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryGuideBuildError {
    /// A half-open range has no bytes or is reversed.
    #[error("recovery range must satisfy start < end_exclusive")]
    EmptyOrReversedRange,
    /// Function ranges overlap or are not ordered by start address.
    #[error("function ranges must be ordered and non-overlapping")]
    OverlappingOrUnorderedRanges,
    /// No supplied range begins at the function entry.
    #[error("one function range must begin at the function entry")]
    MissingEntryRange,
}

/// Builder for an exact-image guide containing question answers and/or
/// caller-authored premises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryGuideBuilder {
    guide: RecoveryGuide,
}

impl RecoveryGuide {
    /// Create an empty current-schema guide for one exact image.
    pub fn new(image: ProgramImageIdentity) -> Self {
        Self {
            schema: RecoveryContractSchema::CURRENT,
            image,
            decisions: Vec::new(),
        }
    }

    /// Begin authoring premises for one exact selected image.
    pub fn builder(image: ProgramImageIdentity) -> RecoveryGuideBuilder {
        RecoveryGuideBuilder {
            guide: Self::new(image),
        }
    }
}

impl RecoveryGuideBuilder {
    fn point(&self, subject: ProgramSubjectKey, kind: RecoveryQuestionKind) -> RecoveryPointKey {
        RecoveryPointKey {
            image: self.guide.image.clone(),
            subject,
            kind,
        }
    }

    fn authored(mut self, point: RecoveryPointKey, choice: RecoveryChoice) -> Self {
        self.guide.decisions.push(RecoveryDecision {
            point,
            choice,
            expected_signals: Vec::new(),
        });
        self
    }

    /// Accept an executable address as a function entry even when recovery did
    /// not emit a candidate question for it.
    pub fn accept_function(self, address: u64) -> Self {
        let point = self.point(
            ProgramSubjectKey::FunctionCandidate { address },
            RecoveryQuestionKind::FunctionEntry,
        );
        self.authored(point, RecoveryChoice::AcceptFunctionEntry)
    }

    /// Reject a possible function interpretation at an executable address.
    pub fn reject_function(self, address: u64) -> Self {
        let point = self.point(
            ProgramSubjectKey::FunctionCandidate { address },
            RecoveryQuestionKind::FunctionEntry,
        );
        self.authored(point, RecoveryChoice::Reject)
    }

    /// Attach an address to an existing function without creating a second body.
    pub fn relate_function(
        self,
        address: u64,
        owner_entry: u64,
        relationship: FunctionRelationshipChoice,
    ) -> Self {
        let point = self.point(
            ProgramSubjectKey::FunctionCandidate { address },
            RecoveryQuestionKind::FunctionRelationship,
        );
        self.authored(
            point,
            RecoveryChoice::FunctionRelationship {
                owner_entry,
                relationship,
            },
        )
    }

    /// Set one or more ranges for a function in the guided view.
    pub fn function_ranges(
        self,
        function_entry: u64,
        mut ranges: Vec<RecoveryAddressRange>,
    ) -> Result<Self, RecoveryGuideBuildError> {
        ranges.sort();
        if ranges
            .windows(2)
            .any(|pair| pair[0].end_exclusive > pair[1].start)
        {
            return Err(RecoveryGuideBuildError::OverlappingOrUnorderedRanges);
        }
        if !ranges.iter().any(|range| range.start == function_entry) {
            return Err(RecoveryGuideBuildError::MissingEntryRange);
        }
        let point = self.point(
            ProgramSubjectKey::Function {
                entry: function_entry,
            },
            RecoveryQuestionKind::FunctionRanges,
        );
        Ok(self.authored(point, RecoveryChoice::FunctionRanges { ranges }))
    }

    /// Assign any existing executable-byte role to an exact section range.
    pub fn byte_role(
        self,
        section_ordinal: u64,
        start: u64,
        end_exclusive: u64,
        role: ExecutableByteKind,
    ) -> Result<Self, RecoveryGuideBuildError> {
        let range = RecoveryAddressRange::new(start, end_exclusive)?;
        let point = self.point(
            ProgramSubjectKey::ExecutableByteRange {
                section_ordinal,
                start: range.start,
                end_exclusive: range.end_exclusive,
            },
            RecoveryQuestionKind::ByteRole,
        );
        Ok(self.authored(point, RecoveryChoice::ByteRole { role }))
    }

    /// Suppress one exact edge without suppressing other edge kinds that share
    /// the same source and destination blocks.
    pub fn suppress_control_flow_edge(
        self,
        function_entry: u64,
        source: u64,
        target: u64,
        edge_kind: ControlFlowEdgeKind,
    ) -> Self {
        let point = self.point(
            ProgramSubjectKey::ControlFlowEdge {
                function_entry,
                source,
                target,
                edge_kind,
            },
            RecoveryQuestionKind::ControlFlowEdge,
        );
        self.authored(point, RecoveryChoice::SuppressControlFlowEdge)
    }

    /// Suppress one exact direct callsite. Aggregated caller/callee edges are
    /// intentionally not accepted as editable subjects.
    pub fn suppress_direct_call(
        self,
        caller: u64,
        instruction_address: u64,
        target_address: u64,
    ) -> Self {
        let point = self.point(
            ProgramSubjectKey::DirectCallsite {
                caller,
                instruction_address,
                target_address,
            },
            RecoveryQuestionKind::DirectCall,
        );
        self.authored(point, RecoveryChoice::SuppressDirectCall)
    }

    /// Select one recovered source-range owner for an exact reference use.
    ///
    /// Validation rejects missing references and functions that do not already
    /// own the reference source.
    pub fn assign_reference_owner(
        self,
        source: u64,
        target: RecoveryReferenceTargetKey,
        reference_kind: RecoveryReferenceKind,
        function_entry: u64,
    ) -> Self {
        let point = self.point(
            ProgramSubjectKey::CrossReference {
                source,
                target,
                reference_kind,
            },
            RecoveryQuestionKind::ReferenceOwnership,
        );
        self.authored(point, RecoveryChoice::ReferenceOwner { function_entry })
    }

    /// Select a source owner directly from one retained leaf xref.
    pub fn assign_xref_owner(self, reference: &Xref, function_entry: u64) -> Self {
        let ProgramSubjectKey::CrossReference {
            source,
            target,
            reference_kind,
        } = cross_reference_subject(reference)
        else {
            unreachable!()
        };
        self.assign_reference_owner(source, target, reference_kind, function_entry)
    }

    /// Answer one currently emitted question while binding replay to its
    /// complete current signal set.
    pub fn answer_question(mut self, question: &RecoveryQuestion, choice: RecoveryChoice) -> Self {
        self.guide.decisions.push(RecoveryDecision {
            point: question.key.clone(),
            choice,
            expected_signals: question
                .signals
                .iter()
                .map(|signal| signal.key.clone())
                .collect(),
        });
        self
    }

    /// Finish the deterministic serialized guide.
    pub fn build(self) -> RecoveryGuide {
        self.guide
    }
}

/// Applicability of one guide decision to the current recovered program.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDecisionApplicability {
    /// Point, signals, and choice match the current recovery question.
    Applicable,
    /// The exact point or expected signals no longer exist.
    Stale,
    /// The decision contradicts another decision for the same point.
    Conflicting,
    /// The current schema or question does not support the requested choice.
    Unsupported,
    /// The same decision was already supplied or preserves the unresolved state.
    Redundant,
}

/// Validation result for one decision in guide order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecisionValidation {
    /// Zero-based decision position in the guide.
    pub decision_index: u64,
    /// Applicability classification.
    pub applicability: RecoveryDecisionApplicability,
    /// Stable non-prose reason code.
    pub reason: String,
}

/// Overall applicability of a recovery guide.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryGuideApplicability {
    /// Every non-redundant decision is applicable.
    Applicable,
    /// Applicable decisions coexist with stale, conflicting, unsupported, or
    /// redundant decisions.
    PartiallyApplicable,
    /// No decision can be applied to the current program.
    NotApplicable,
}

/// Deterministic validation report for a recovery guide.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGuideValidation {
    /// Aggregate applicability.
    pub applicability: RecoveryGuideApplicability,
    /// One result per decision in original guide order.
    pub decisions: Vec<RecoveryDecisionValidation>,
}

/// Result of applying one validated decision during a cold rebuild.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDecisionApplicationStatus {
    /// The guided program reflects the requested interpretation.
    Applied,
    /// The decision intentionally preserved the current interpretation.
    Redundant,
    /// An explicit recovery budget prevented the guided subject from being retained.
    BudgetExcluded,
    /// The decision was valid but did not change the recovered subject as requested.
    Ineffective,
}

/// One deterministic decision-application result in guide order.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecisionApplication {
    /// Zero-based decision position in the guide.
    pub decision_index: u64,
    /// Application result.
    pub status: RecoveryDecisionApplicationStatus,
    /// Stable non-prose reason code.
    pub reason: String,
}

/// Validation and application receipt for one cold guided rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryGuideApplication {
    /// Validation performed against the unguided base program.
    pub validation: RecoveryGuideValidation,
    /// One application result per decision in original guide order.
    pub decisions: Vec<RecoveryDecisionApplication>,
    /// Structural and byte-coverage changes from the unguided base recovery.
    pub delta: RecoveryDelta,
    /// Base signals displaced or reinterpreted by applied caller decisions.
    pub suppressed_signals: Vec<RecoverySignal>,
    /// Multi-dimensional before/after recovery coverage for the same declared
    /// universe and budgets.
    pub coverage_delta: ProgramCoverageDelta,
}

/// Unit counted by one program-coverage dimension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramCoverageUnit {
    /// Executable bytes.
    Bytes,
    /// Functions or function-entry propositions.
    Functions,
    /// Function-local control-flow graphs.
    FunctionGraphs,
    /// Direct callsites.
    Callsites,
    /// Cross-reference records.
    References,
    /// Indirect transfer sites.
    IndirectTransfers,
}

/// One truth-aware coverage dimension. Categories are intentionally allowed to
/// overlap; for example, caller-guided bytes can also remain conflicted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramCoverageDimension {
    /// Counted unit.
    pub unit: ProgramCoverageUnit,
    /// Declared observed denominator when the producing stage can state one.
    pub denominator: Option<u64>,
    /// Independently exact or derived records/bytes.
    pub independently_established: u64,
    /// Records/bytes admitted or classified by caller guidance.
    pub caller_guided: u64,
    /// Candidate-only records/bytes.
    pub candidate: u64,
    /// Records/bytes participating in a retained conflict.
    pub conflicted: u64,
    /// Explicitly rejected interpretations.
    pub rejected: u64,
    /// Retained unresolved records/bytes.
    pub unresolved: u64,
    /// Known omitted records/bytes or, where a count is unknowable, typed
    /// omitted frontiers.
    pub budget_omitted: u64,
    /// Whether the producing stage was unavailable in this program view.
    pub unavailable: bool,
    /// Stable reasons qualifying the denominator or incomplete categories.
    pub reasons: Vec<String>,
}

impl ProgramCoverageDimension {
    /// An unavailable dimension for a stage outside the selected universe.
    pub fn unavailable(unit: ProgramCoverageUnit) -> Self {
        Self {
            unit,
            denominator: None,
            independently_established: 0,
            caller_guided: 0,
            candidate: 0,
            conflicted: 0,
            rejected: 0,
            unresolved: 0,
            budget_omitted: 0,
            unavailable: true,
            reasons: vec!["program_coverage.stage_not_selected".into()],
        }
    }
}

/// Coverage vector for one exact recovered-program view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramCoverage {
    /// Selected image identity.
    pub image: ProgramImageIdentity,
    /// Executable byte classification.
    pub executable_bytes: ProgramCoverageDimension,
    /// Function identities and entry propositions.
    pub functions: ProgramCoverageDimension,
    /// Function-local CFG completion.
    pub control_flow: ProgramCoverageDimension,
    /// Direct callsite resolution.
    pub direct_calls: ProgramCoverageDimension,
    /// Internal and imported cross references.
    pub references: ProgramCoverageDimension,
    /// Indirect transfer/value-flow resolution.
    pub indirect_transfers: ProgramCoverageDimension,
}

/// Before/after coverage for one guided cold rebuild.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramCoverageDelta {
    /// Unguided base coverage.
    pub before: ProgramCoverage,
    /// Guided-view coverage under the same request and budgets.
    pub after: ProgramCoverage,
}

/// Relationship between one structural subject in base and guided recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDeltaKind {
    /// The subject exists only in guided recovery.
    Added,
    /// The subject exists only in base recovery.
    Removed,
    /// The subject exists in both views but its retained record changed.
    Reclassified,
    /// An unresolved question or executable-byte range became resolved.
    Resolved,
    /// A previously resolved subject became unresolved.
    NewlyUnresolved,
}

/// Structural reason one guide decision is attributed to a changed object.
///
/// These relations describe the recovery dependency that carried caller
/// guidance into the changed record. They do not turn the caller decision into
/// independently recovered evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryDecisionDerivationKind {
    /// The changed object is the exact subject answered by the decision.
    DirectSubject,
    /// The changed object overlaps the executable range answered by the decision.
    OverlappingRange,
    /// The changed object depends on a function affected by the decision.
    FunctionDependency,
    /// The question declared this layer affected, but no narrower structural
    /// dependency is represented by the current subject-key schema.
    AffectedLayer,
}

/// One deterministic causal link from a guide decision to a changed object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDecisionDerivation {
    /// Zero-based index into the applied [`RecoveryGuide::decisions`] array.
    pub decision_index: u64,
    /// Structural dependency used to attribute the change.
    pub kind: RecoveryDecisionDerivationKind,
}

/// One deterministic structural or executable-byte coverage change.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeltaRecord {
    /// Recovery layer containing the changed subject.
    pub layer: RecoveryLayer,
    /// Stable name-independent subject identity.
    pub subject: ProgramSubjectKey,
    /// How the guided view differs from the base view.
    pub kind: RecoveryDeltaKind,
    /// Applied decisions that caused this changed object, ordered by decision
    /// index. An ordinary unguided comparison has no decision derivations.
    #[serde(default)]
    pub derivations: Vec<RecoveryDecisionDerivation>,
}

/// Counts of each change kind in a recovery delta.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDeltaSummary {
    /// Subjects added by guided recovery.
    pub added: u64,
    /// Subjects removed by guided recovery.
    pub removed: u64,
    /// Subjects retained with a changed record.
    pub reclassified: u64,
    /// Unresolved subjects made resolved.
    pub resolved: u64,
    /// Resolved subjects made unresolved.
    pub newly_unresolved: u64,
}

/// Deterministic cold-rebuild delta between an unguided base and guided view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryDelta {
    /// Exact selected image shared by both views.
    pub image: ProgramImageIdentity,
    /// Structural changes sorted by layer, subject, and change kind.
    pub records: Vec<RecoveryDeltaRecord>,
    /// Aggregate counts derived from `records`.
    pub summary: RecoveryDeltaSummary,
}

/// Failure preventing two recovered views from being compared coherently.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryDeltaError {
    /// The views describe different selected image bytes or architectures.
    #[error("recovery delta views describe different exact images")]
    ImageMismatch,
    /// The views were constructed with different stages or limits.
    #[error("recovery delta views use different recovery requests")]
    RequestMismatch,
}

/// Validate a guide without applying it or changing recovered evidence.
pub(crate) fn validate_recovery_guide(
    image: &ProgramImageIdentity,
    questions: &[RecoveryQuestion],
    guide: &RecoveryGuide,
) -> RecoveryGuideValidation {
    let schema_supported = guide.schema == RecoveryContractSchema::CURRENT;
    let image_matches = &guide.image == image;
    let mut decisions = Vec::with_capacity(guide.decisions.len());

    for (index, decision) in guide.decisions.iter().enumerate() {
        let (applicability, reason) = if !schema_supported {
            (
                RecoveryDecisionApplicability::Unsupported,
                "recovery_guide.unsupported_schema",
            )
        } else if !image_matches || decision.point.image != guide.image {
            (
                RecoveryDecisionApplicability::Stale,
                "recovery_guide.image_mismatch",
            )
        } else if let Some(previous) = guide.decisions[..index]
            .iter()
            .find(|previous| previous.point == decision.point)
        {
            if previous.choice == decision.choice
                && previous.expected_signals == decision.expected_signals
            {
                (
                    RecoveryDecisionApplicability::Redundant,
                    "recovery_guide.duplicate_decision",
                )
            } else {
                (
                    RecoveryDecisionApplicability::Conflicting,
                    "recovery_guide.conflicting_decisions",
                )
            }
        } else if let Some(question) = questions
            .iter()
            .find(|question| question.key == decision.point)
        {
            if !question.choices.contains(&decision.choice)
                && !(decision.expected_signals.is_empty()
                    && authored_choice_matches_point(decision))
            {
                (
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.choice_not_offered",
                )
            } else if decision.expected_signals.iter().any(|expected| {
                !question
                    .signals
                    .iter()
                    .any(|signal| signal.key == *expected)
            }) {
                (
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.expected_signal_missing",
                )
            } else if decision.choice == RecoveryChoice::KeepUnresolved {
                (
                    RecoveryDecisionApplicability::Redundant,
                    "recovery_guide.already_unresolved",
                )
            } else {
                (
                    RecoveryDecisionApplicability::Applicable,
                    if question.choices.contains(&decision.choice) {
                        "recovery_guide.question_answer_applicable"
                    } else {
                        "recovery_guide.authored_premise_applicable"
                    },
                )
            }
        } else if !decision.expected_signals.is_empty() {
            (
                RecoveryDecisionApplicability::Stale,
                "recovery_guide.expected_question_missing",
            )
        } else if authored_choice_matches_point(decision) {
            (
                RecoveryDecisionApplicability::Applicable,
                "recovery_guide.authored_premise_applicable",
            )
        } else {
            (
                RecoveryDecisionApplicability::Unsupported,
                "recovery_guide.proposition_kind_mismatch",
            )
        };
        decisions.push(RecoveryDecisionValidation {
            decision_index: index as u64,
            applicability,
            reason: reason.to_owned(),
        });
    }

    let applicable = decisions
        .iter()
        .filter(|decision| decision.applicability == RecoveryDecisionApplicability::Applicable)
        .count();
    let applicability = if decisions.is_empty()
        || decisions.iter().all(|decision| {
            matches!(
                decision.applicability,
                RecoveryDecisionApplicability::Applicable
                    | RecoveryDecisionApplicability::Redundant
            )
        }) {
        RecoveryGuideApplicability::Applicable
    } else if applicable != 0 {
        RecoveryGuideApplicability::PartiallyApplicable
    } else {
        RecoveryGuideApplicability::NotApplicable
    };
    RecoveryGuideValidation {
        applicability,
        decisions,
    }
}

fn authored_choice_matches_point(decision: &RecoveryDecision) -> bool {
    matches!(
        (
            decision.point.kind,
            &decision.point.subject,
            &decision.choice
        ),
        (
            RecoveryQuestionKind::FunctionEntry,
            ProgramSubjectKey::FunctionCandidate { .. },
            RecoveryChoice::AcceptFunctionEntry | RecoveryChoice::Reject
        ) | (
            RecoveryQuestionKind::FunctionRelationship | RecoveryQuestionKind::RangeOwnership,
            ProgramSubjectKey::FunctionCandidate { .. },
            RecoveryChoice::FunctionRelationship { .. }
        ) | (
            RecoveryQuestionKind::FunctionRanges,
            ProgramSubjectKey::Function { .. },
            RecoveryChoice::FunctionRanges { .. }
        ) | (
            RecoveryQuestionKind::ByteRole,
            ProgramSubjectKey::ExecutableByteRange { .. },
            RecoveryChoice::ByteRole { .. }
        ) | (
            RecoveryQuestionKind::ControlFlowEdge,
            ProgramSubjectKey::ControlFlowEdge { .. },
            RecoveryChoice::SuppressControlFlowEdge
        ) | (
            RecoveryQuestionKind::DirectCall,
            ProgramSubjectKey::DirectCallsite { .. },
            RecoveryChoice::SuppressDirectCall
        ) | (
            RecoveryQuestionKind::ReferenceOwnership,
            ProgramSubjectKey::CrossReference { .. },
            RecoveryChoice::ReferenceOwner { .. }
        )
    )
}

/// Build the currently supported recovery-question catalog.
pub(crate) fn build_recovery_questions(
    image: &ProgramImageIdentity,
    functions: Option<&FunctionIndex>,
    control_flow: Option<&ControlFlowIndex>,
    executable_bytes: Option<&ExecutableByteIndex>,
    xrefs: Option<&XrefIndex>,
    guided_reference_ownerships: &[GuidedReferenceOwnership],
) -> Vec<RecoveryQuestion> {
    let mut questions =
        build_core_recovery_questions(image, functions, control_flow, executable_bytes);
    questions.extend(build_reference_ownership_questions(
        image,
        functions,
        xrefs,
        guided_reference_ownerships,
    ));
    questions
}

fn build_core_recovery_questions(
    image: &ProgramImageIdentity,
    functions: Option<&FunctionIndex>,
    control_flow: Option<&ControlFlowIndex>,
    executable_bytes: Option<&ExecutableByteIndex>,
) -> Vec<RecoveryQuestion> {
    let (Some(functions), Some(executable_bytes)) = (functions, executable_bytes) else {
        return Vec::new();
    };
    let mut entry_signals = BTreeMap::new();
    for candidate in functions.entry_candidates().iter().filter(|candidate| {
        if functions.relationship_at(candidate.address).is_some() {
            return false;
        }
        !matches!(
            candidate.disposition,
            FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
                | FunctionEntryCandidateDisposition::RejectedByCaller
                | FunctionEntryCandidateDisposition::RejectedRecoveredData
                | FunctionEntryCandidateDisposition::RejectedImportStub
                | FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
                | FunctionEntryCandidateDisposition::ResolvedByCallerRelationship
        )
    }) {
        entry_signals.insert(
            candidate.address,
            (
                RecoverySignalKind::FunctionEntryCandidate,
                ProgramSubjectKey::FunctionCandidate {
                    address: candidate.address,
                },
                FunctionEvidenceConfidence::Candidate,
            ),
        );
    }
    for function in functions.functions() {
        entry_signals.insert(
            function.entry,
            (
                RecoverySignalKind::FunctionEntry,
                ProgramSubjectKey::Function {
                    entry: function.entry,
                },
                function.entry_confidence,
            ),
        );
    }
    let mut questions = Vec::new();
    for span in executable_bytes.spans().iter().filter(|span| {
        span.kind == ExecutableByteKind::Unresolved
            && span.evidence.iter().any(|evidence| {
                matches!(
                    evidence,
                    ExecutableByteEvidence::JumpTableTargetConflict
                        | ExecutableByteEvidence::InlineLiteralTargetConflict
                )
            })
    }) {
        let subject = ProgramSubjectKey::ExecutableByteRange {
            section_ordinal: span.section_ordinal,
            start: span.start,
            end_exclusive: span.end_exclusive,
        };
        let mut signals = Vec::new();
        let jump_table_conflict = span
            .evidence
            .contains(&ExecutableByteEvidence::JumpTableTargetConflict);
        if jump_table_conflict {
            for table in control_flow
                .into_iter()
                .flat_map(|control_flow| {
                    control_flow
                        .functions()
                        .iter()
                        .flat_map(|function| function.jump_tables.iter())
                })
                .filter(|table| {
                    table.table_address < span.end_exclusive && table.end_exclusive > span.start
                })
            {
                signals.push(RecoverySignal {
                    key: RecoverySignalKey {
                        image: image.clone(),
                        kind: RecoverySignalKind::JumpTable,
                        subject: ProgramSubjectKey::JumpTable {
                            instruction_address: table.instruction_address,
                            table_address: table.table_address,
                            end_exclusive: table.end_exclusive,
                        },
                        evidence_source: None,
                        source_address: Some(table.instruction_address),
                    },
                    confidence: FunctionEvidenceConfidence::Candidate,
                    supports: vec![RecoveryChoice::ByteRole {
                        role: ExecutableByteKind::EmbeddedData,
                    }],
                });
            }
        } else {
            signals.push(RecoverySignal {
                key: RecoverySignalKey {
                    image: image.clone(),
                    kind: RecoverySignalKind::InlineLiteral,
                    subject: subject.clone(),
                    evidence_source: None,
                    source_address: None,
                },
                confidence: FunctionEvidenceConfidence::Candidate,
                supports: vec![RecoveryChoice::ByteRole {
                    role: ExecutableByteKind::EmbeddedData,
                }],
            });
        }
        for (address, (kind, entry_subject, confidence)) in
            entry_signals.range(span.start..span.end_exclusive)
        {
            signals.push(RecoverySignal {
                key: RecoverySignalKey {
                    image: image.clone(),
                    kind: *kind,
                    subject: entry_subject.clone(),
                    evidence_source: None,
                    source_address: Some(*address),
                },
                confidence: *confidence,
                supports: vec![RecoveryChoice::ByteRole {
                    role: ExecutableByteKind::Instruction,
                }],
            });
        }
        let kind = RecoveryQuestionKind::ByteRole;
        questions.push(RecoveryQuestion {
            key: RecoveryPointKey {
                image: image.clone(),
                subject: subject.clone(),
                kind,
            },
            subject,
            kind,
            choices: vec![
                RecoveryChoice::ByteRole {
                    role: ExecutableByteKind::Instruction,
                },
                RecoveryChoice::ByteRole {
                    role: ExecutableByteKind::EmbeddedData,
                },
                RecoveryChoice::KeepUnresolved,
            ],
            signals,
            estimated_effect: RecoveryEffectEstimate {
                affected_layers: vec![
                    RecoveryLayer::Functions,
                    RecoveryLayer::ExecutableBytes,
                    RecoveryLayer::ControlFlow,
                    RecoveryLayer::Calls,
                    RecoveryLayer::References,
                    RecoveryLayer::ValueFlow,
                    RecoveryLayer::Semantics,
                ],
            },
        });
    }
    for function in functions.functions() {
        let conflicting_ends = function
            .conflicts
            .iter()
            .filter(|conflict| {
                conflict.kind
                    == crate::analysis::functions::FunctionConflictKind::ExtentEndDisagreement
            })
            .flat_map(|conflict| {
                conflict.claims.iter().filter_map(|claim| {
                    (claim.field
                        == crate::analysis::functions::FunctionConflictField::ExtentEndExclusive
                        && claim.value > function.entry)
                        .then_some((claim.source, claim.value))
                })
            })
            .collect::<Vec<_>>();
        let mut choices = conflicting_ends
            .iter()
            .map(|(_, end_exclusive)| RecoveryChoice::FunctionRanges {
                ranges: vec![RecoveryAddressRange {
                    start: function.entry,
                    end_exclusive: *end_exclusive,
                }],
            })
            .collect::<Vec<_>>();
        choices.sort_by_key(|choice| match choice {
            RecoveryChoice::FunctionRanges { ranges } => ranges[0].end_exclusive,
            _ => 0,
        });
        choices.dedup();
        if choices.len() < 2 {
            continue;
        }
        let subject = ProgramSubjectKey::Function {
            entry: function.entry,
        };
        let mut signals = conflicting_ends
            .into_iter()
            .map(|(source, end_exclusive)| {
                let evidence = function.evidence.iter().find(|evidence| {
                    evidence.source == source
                        && evidence.extent_start == Some(function.entry)
                        && evidence.end_exclusive == Some(end_exclusive)
                });
                RecoverySignal {
                    key: RecoverySignalKey {
                        image: image.clone(),
                        kind: RecoverySignalKind::RangeOwnership,
                        subject: subject.clone(),
                        evidence_source: Some(source),
                        source_address: evidence.and_then(|evidence| evidence.source_location),
                    },
                    confidence: evidence
                        .map_or(FunctionEvidenceConfidence::Candidate, |evidence| {
                            evidence.confidence
                        }),
                    supports: vec![RecoveryChoice::FunctionRanges {
                        ranges: vec![RecoveryAddressRange {
                            start: function.entry,
                            end_exclusive,
                        }],
                    }],
                }
            })
            .collect::<Vec<_>>();
        signals.sort_by(|left, right| {
            let supported_end = |signal: &RecoverySignal| match signal.supports.first() {
                Some(RecoveryChoice::FunctionRanges { ranges }) => {
                    ranges.first().map(|range| range.end_exclusive)
                }
                _ => None,
            };
            (
                left.key.evidence_source,
                left.key.source_address,
                supported_end(left),
            )
                .cmp(&(
                    right.key.evidence_source,
                    right.key.source_address,
                    supported_end(right),
                ))
        });
        signals.dedup();
        choices.push(RecoveryChoice::KeepUnresolved);
        questions.push(RecoveryQuestion {
            key: RecoveryPointKey {
                image: image.clone(),
                subject: subject.clone(),
                kind: RecoveryQuestionKind::FunctionRanges,
            },
            subject,
            kind: RecoveryQuestionKind::FunctionRanges,
            choices,
            signals,
            estimated_effect: RecoveryEffectEstimate {
                affected_layers: vec![
                    RecoveryLayer::Functions,
                    RecoveryLayer::ExecutableBytes,
                    RecoveryLayer::ControlFlow,
                    RecoveryLayer::Calls,
                    RecoveryLayer::References,
                    RecoveryLayer::ValueFlow,
                    RecoveryLayer::Semantics,
                ],
            },
        });
    }
    for candidate in functions.entry_candidates().iter().filter(|candidate| {
        if functions.relationship_at(candidate.address).is_some() {
            return false;
        }
        !matches!(
            candidate.disposition,
            FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
                | FunctionEntryCandidateDisposition::RejectedByCaller
                | FunctionEntryCandidateDisposition::RejectedRecoveredData
                | FunctionEntryCandidateDisposition::RejectedImportStub
                | FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
                | FunctionEntryCandidateDisposition::ResolvedByCallerRelationship
        )
    }) {
        let subject = ProgramSubjectKey::FunctionCandidate {
            address: candidate.address,
        };
        let kind = match candidate.disposition {
            FunctionEntryCandidateDisposition::InsideRecoveredExtent
            | FunctionEntryCandidateDisposition::SecondaryRangeEntry => {
                RecoveryQuestionKind::FunctionRelationship
            }
            FunctionEntryCandidateDisposition::SharedOwnedRegion => {
                RecoveryQuestionKind::RangeOwnership
            }
            FunctionEntryCandidateDisposition::UnresolvedCallTarget => {
                RecoveryQuestionKind::FunctionEntry
            }
            FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
            | FunctionEntryCandidateDisposition::RejectedByCaller
            | FunctionEntryCandidateDisposition::RejectedRecoveredData
            | FunctionEntryCandidateDisposition::RejectedImportStub
            | FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
            | FunctionEntryCandidateDisposition::ResolvedByCallerRelationship => continue,
        };
        let mut choices = vec![RecoveryChoice::AcceptFunctionEntry];
        for owner in &candidate.possible_owners {
            choices.push(RecoveryChoice::FunctionRelationship {
                owner_entry: owner.entry,
                relationship: FunctionRelationshipChoice::AlternateEntry,
            });
            choices.push(RecoveryChoice::FunctionRelationship {
                owner_entry: owner.entry,
                relationship: FunctionRelationshipChoice::ColdFragment,
            });
            if candidate.disposition == FunctionEntryCandidateDisposition::SharedOwnedRegion {
                choices.push(RecoveryChoice::FunctionRelationship {
                    owner_entry: owner.entry,
                    relationship: FunctionRelationshipChoice::SharedRange,
                });
            }
        }
        choices.push(RecoveryChoice::KeepUnresolved);
        choices.push(RecoveryChoice::Reject);

        let mut signals = candidate
            .evidence
            .iter()
            .map(|evidence| RecoverySignal {
                key: RecoverySignalKey {
                    image: image.clone(),
                    kind: RecoverySignalKind::FunctionEntryCandidate,
                    subject: subject.clone(),
                    evidence_source: Some(evidence.source),
                    source_address: evidence.source_location,
                },
                confidence: evidence.confidence,
                supports: vec![RecoveryChoice::AcceptFunctionEntry],
            })
            .collect::<Vec<_>>();
        for owner in &candidate.possible_owners {
            let relationship =
                if candidate.disposition == FunctionEntryCandidateDisposition::SharedOwnedRegion {
                    FunctionRelationshipChoice::SharedRange
                } else {
                    FunctionRelationshipChoice::AlternateEntry
                };
            signals.push(RecoverySignal {
                key: RecoverySignalKey {
                    image: image.clone(),
                    kind: RecoverySignalKind::RangeOwnership,
                    subject: ProgramSubjectKey::Function { entry: owner.entry },
                    evidence_source: None,
                    source_address: Some(owner.entry),
                },
                confidence: match owner.ownership_confidence {
                    FunctionOwnershipConfidence::Exact => FunctionEvidenceConfidence::Exact,
                    FunctionOwnershipConfidence::Derived => FunctionEvidenceConfidence::Derived,
                    FunctionOwnershipConfidence::Candidate => FunctionEvidenceConfidence::Candidate,
                },
                supports: vec![RecoveryChoice::FunctionRelationship {
                    owner_entry: owner.entry,
                    relationship,
                }],
            });
        }
        questions.push(RecoveryQuestion {
            key: RecoveryPointKey {
                image: image.clone(),
                subject: subject.clone(),
                kind,
            },
            subject,
            kind,
            choices,
            signals,
            estimated_effect: RecoveryEffectEstimate {
                affected_layers: vec![
                    RecoveryLayer::Functions,
                    RecoveryLayer::ExecutableBytes,
                    RecoveryLayer::ControlFlow,
                    RecoveryLayer::Calls,
                    RecoveryLayer::References,
                    RecoveryLayer::ValueFlow,
                    RecoveryLayer::Semantics,
                ],
            },
        });
    }
    questions
}

fn build_reference_ownership_questions(
    image: &ProgramImageIdentity,
    functions: Option<&FunctionIndex>,
    xrefs: Option<&XrefIndex>,
    guided_reference_ownerships: &[GuidedReferenceOwnership],
) -> Vec<RecoveryQuestion> {
    let (Some(functions), Some(xrefs)) = (functions, xrefs) else {
        return Vec::new();
    };
    let guided_subjects = guided_reference_ownerships
        .iter()
        .map(|ownership| ProgramSubjectKey::CrossReference {
            source: ownership.source,
            target: ownership.target.clone(),
            reference_kind: ownership.reference_kind,
        })
        .collect::<std::collections::BTreeSet<_>>();
    let mut emitted = std::collections::BTreeSet::new();
    let mut questions = Vec::new();
    for reference in xrefs.all_refs() {
        let subject = cross_reference_subject(reference);
        if guided_subjects.contains(&subject) || !emitted.insert(subject.clone()) {
            continue;
        }
        let owners = functions.owners(reference.source.0).collect::<Vec<_>>();
        if owners.len() < 2 {
            continue;
        }
        let choices = owners
            .iter()
            .map(|owner| RecoveryChoice::ReferenceOwner {
                function_entry: owner.function.entry,
            })
            .chain(std::iter::once(RecoveryChoice::KeepUnresolved))
            .collect::<Vec<_>>();
        let signals = owners
            .iter()
            .map(|owner| RecoverySignal {
                key: RecoverySignalKey {
                    image: image.clone(),
                    kind: RecoverySignalKind::RangeOwnership,
                    subject: ProgramSubjectKey::Function {
                        entry: owner.function.entry,
                    },
                    evidence_source: None,
                    source_address: Some(reference.source.0),
                },
                confidence: match owner.confidence {
                    FunctionOwnershipConfidence::Exact => FunctionEvidenceConfidence::Exact,
                    FunctionOwnershipConfidence::Derived => FunctionEvidenceConfidence::Derived,
                    FunctionOwnershipConfidence::Candidate => FunctionEvidenceConfidence::Candidate,
                },
                supports: vec![RecoveryChoice::ReferenceOwner {
                    function_entry: owner.function.entry,
                }],
            })
            .collect();
        questions.push(RecoveryQuestion {
            key: RecoveryPointKey {
                image: image.clone(),
                subject: subject.clone(),
                kind: RecoveryQuestionKind::ReferenceOwnership,
            },
            subject,
            kind: RecoveryQuestionKind::ReferenceOwnership,
            choices,
            signals,
            estimated_effect: RecoveryEffectEstimate {
                affected_layers: vec![RecoveryLayer::References],
            },
        });
    }
    questions
}

/// Stable program subject for one retained leaf xref.
pub(crate) fn cross_reference_subject(reference: &Xref) -> ProgramSubjectKey {
    let target = match &reference.target {
        XrefTarget::Internal { va } => RecoveryReferenceTargetKey::Internal { address: va.0 },
        XrefTarget::Import { name, ordinal } => RecoveryReferenceTargetKey::Import {
            ordinal: *ordinal,
            name: name.clone(),
        },
    };
    let reference_kind = RecoveryReferenceKind::from(reference.kind);
    ProgramSubjectKey::CrossReference {
        source: reference.source.0,
        target,
        reference_kind,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emitted_range_ownership_choice_is_a_supported_decision() {
        let bytes = macho_test_support::disassembly_x86_64();
        let macho = match crate::core::parse(&bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => {
                panic!("expected thin image")
            }
        };
        let image = FunctionImageIdentity::from_macho(&macho);
        let decision = RecoveryDecision {
            point: RecoveryPointKey {
                image,
                subject: ProgramSubjectKey::FunctionCandidate {
                    address: 0x1_0000_0110,
                },
                kind: RecoveryQuestionKind::RangeOwnership,
            },
            choice: RecoveryChoice::FunctionRelationship {
                owner_entry: 0x1_0000_0100,
                relationship: FunctionRelationshipChoice::SharedRange,
            },
            expected_signals: Vec::new(),
        };
        assert!(authored_choice_matches_point(&decision));
    }
}
