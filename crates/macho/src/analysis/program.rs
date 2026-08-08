//! Unified construction and queries over Macho-owned program recovery.
//!
//! A [`crate::analysis::program::RecoveredProgram`] owns only the independently recoverable
//! stages selected by a [`crate::analysis::program::ProgramRecoveryRequest`]. Dependencies are closed
//! deterministically, nested limits remain explicit, and borrowed address views
//! let disassemblers consume evidence without rebuilding it.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::format::constants::{CPU_TYPE_ARM64, SectionAttributes};
use crate::core::model::macho_file::MachoFile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::call_graph::{
    DirectCallEdge, DirectCallGraph, DirectCallGraphError, DirectCallGraphLimits,
    DirectCallGraphStatus, DirectCallNode,
};
use crate::analysis::control_flow::{
    ControlFlowIndex, ControlFlowIndexStatus, ControlFlowInstruction, ControlFlowLimits,
    ControlFlowRecoveryError, ControlFlowRecoveryGuidance, FunctionControlFlow,
    FunctionControlFlowStatus,
};
use crate::analysis::dependency_index::{
    DependencyIndex, DependencyIndexStatus, DependencyRecoveryError, DependencyRecoveryLimits,
};
use crate::analysis::dwarf_index::{
    DwarfIndex, DwarfIndexStatus, DwarfRecoveryError, DwarfRecoveryLimits,
};
use crate::analysis::exception_index::{
    ExceptionIndex, ExceptionIndexStatus, ExceptionRecoveryError, ExceptionRecoveryLimits,
};
use crate::analysis::executable_bytes::{
    ExecutableByteEvidence, ExecutableByteIndex, ExecutableByteIndexStatus, ExecutableByteKind,
    ExecutableByteLimits, ExecutableByteRecoveryError, ExecutableByteRecoveryGuidance,
    ExecutableByteSpan, GuidedExecutableByteRole,
};
use crate::analysis::functions::{
    FunctionCollectorStatus, FunctionEvidenceSource, FunctionImageIdentity, FunctionIndex,
    FunctionLookup, FunctionOwner, FunctionOwners, FunctionRecoveryAuthority,
    FunctionRecoveryError, FunctionRecoveryGuidance, FunctionRecoveryInputs,
    FunctionRecoveryLimits, FunctionRelationshipKind, RecoveredFunction,
};
use crate::analysis::image_layout::{ImageLayoutError, ImageLayoutIndex, ImageLayoutLimits};
use crate::analysis::indirect_calls::{
    IndirectCallIndex, IndirectCallIndexStatus, IndirectCallRecoveryError,
    IndirectCallRecoveryInputs, IndirectCallRecoveryLimits, IndirectCallSiteStatus,
    RecoveredIndirectCall,
};
use crate::analysis::objc_index::{
    ObjcIndex, ObjcIndexStatus, ObjcRecoveryError, ObjcRecoveryLimits,
};
use crate::analysis::pointer_index::{PointerIndex, PointerRecoveryError, PointerRecoveryLimits};
use crate::analysis::recovery::{
    GuidedReferenceOwnership, ProgramCoverage, ProgramCoverageDelta, ProgramCoverageDimension,
    ProgramCoverageUnit, ProgramSubjectKey, RecoveryChoice, RecoveryContractSchema,
    RecoveryDecision, RecoveryDecisionApplicability, RecoveryDecisionApplication,
    RecoveryDecisionApplicationStatus, RecoveryDecisionDerivation, RecoveryDecisionDerivationKind,
    RecoveryDelta, RecoveryDeltaError, RecoveryDeltaKind, RecoveryDeltaRecord,
    RecoveryDeltaSummary, RecoveryFrontier, RecoveryFrontierKind, RecoveryGuide,
    RecoveryGuideApplicability, RecoveryGuideApplication, RecoveryGuideValidation, RecoveryLayer,
    RecoveryQuestion, RecoveryQuestionKind, RecoveryReferenceKind, RecoveryReferenceTargetKey,
    build_recovery_questions, cross_reference_subject, validate_recovery_guide,
};
use crate::analysis::rtti::{
    RecoveredTypeInfo, RecoveredVtable, RttiIndex, RttiIndexStatus, RttiRecoveryError,
    RttiRecoveryLimits,
};
use crate::analysis::semantic_index::{
    SemanticIndex, SemanticIndexStatus, SemanticRecoveryError, SemanticRecoveryInputs,
    SemanticRecoveryLimits,
};
use crate::analysis::string_index::{
    RecoveredString, StringIndex, StringIndexStatus, StringRecoveryError, StringRecoveryLimits,
};
use crate::analysis::swift_index::{
    SwiftIndex, SwiftIndexStatus, SwiftRecoveryError, SwiftRecoveryLimits,
};
use crate::analysis::symbol_inventory::{
    RecoveredSymbol, SymbolInventory, SymbolInventoryStatus, SymbolRecoveryError,
    SymbolRecoveryLimits,
};
use crate::analysis::transfers::{
    DirectFunctionTransfer, DirectTransferIndex, FunctionTargetResolution, RecoveredThunk,
    TransferIndexStatus, TransferRecoveryError, TransferRecoveryLimits,
};
use crate::analysis::xref::{Xref, XrefIndex, XrefIndexStatus, XrefRecoveryLimits, XrefTarget};

/// Current schema for serialized whole-program recovery limits.
pub const PROGRAM_RECOVERY_LIMITS_SCHEMA_VERSION: u32 = 1;
/// Current schema for examined-universe and stage completeness receipts.
pub const PROGRAM_COMPLETENESS_SCHEMA_VERSION: u32 = 1;
/// Current schema for durable whole-program Fact IR documents.
pub const PROGRAM_FACT_IR_SCHEMA_VERSION: u32 = 1;

/// Explicit limits for every independently selectable recovery module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProgramRecoveryLimits {
    /// Indexed segment, section, and address-translation limits.
    pub image_layout: ImageLayoutLimits,
    /// Format pointer, fixup, bind, stub, and relocation limits.
    pub pointers: PointerRecoveryLimits,
    /// Complete nlist, export, and import symbol inventory limits.
    pub symbols: SymbolRecoveryLimits,
    /// Typed and optionally heuristic string inventory limits.
    pub strings: StringRecoveryLimits,
    /// Strict Objective-C runtime metadata limits.
    pub objc: ObjcRecoveryLimits,
    /// Strict Swift ABI metadata limits.
    pub swift: SwiftRecoveryLimits,
    /// Bounded DWARF traversal limits.
    pub dwarf: DwarfRecoveryLimits,
    /// Function inventory limits.
    pub functions: FunctionRecoveryLimits,
    /// Basic-block and CFG limits.
    pub control_flow: ControlFlowLimits,
    /// Conserved executable-section byte classification limits.
    pub executable_bytes: ExecutableByteLimits,
    /// Direct call-graph limits.
    pub direct_calls: DirectCallGraphLimits,
    /// Direct branch, tail-call, and thunk limits.
    pub transfers: TransferRecoveryLimits,
    /// Indirect transfer and dynamic-dispatch limits.
    pub indirect_calls: IndirectCallRecoveryLimits,
    /// Cross-reference inventory limits.
    pub xrefs: XrefRecoveryLimits,
    /// Named and structural Itanium RTTI and vtable limits.
    pub rtti: RttiRecoveryLimits,
    /// Exception and unwind metadata limits.
    pub exceptions: ExceptionRecoveryLimits,
    /// Named dependencies and selected-universe limits.
    pub dependencies: DependencyRecoveryLimits,
    /// Data object, signature, frame, and local-variable limits.
    pub semantics: SemanticRecoveryLimits,
}

/// Strict versioned file envelope for the complete nested recovery-limit surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramRecoveryLimitsFile {
    /// Exact supported file schema.
    pub schema_version: u32,
    /// Limits for every independently selectable recovery module.
    pub limits: ProgramRecoveryLimits,
}

impl ProgramRecoveryLimitsFile {
    /// Construct the current versioned envelope.
    pub const fn current(limits: ProgramRecoveryLimits) -> Self {
        Self {
            schema_version: PROGRAM_RECOVERY_LIMITS_SCHEMA_VERSION,
            limits,
        }
    }

    /// Reject stale schemas and invalid nested limits before recovery starts.
    pub fn validate(self) -> Result<ProgramRecoveryLimits, ProgramRecoveryError> {
        if self.schema_version != PROGRAM_RECOVERY_LIMITS_SCHEMA_VERSION {
            return Err(ProgramRecoveryError::UnsupportedLimitsSchema {
                supported: PROGRAM_RECOVERY_LIMITS_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        self.limits.validate()
    }
}

impl ProgramRecoveryLimits {
    /// Validate every nested limit before any image recovery begins.
    pub fn validate(self) -> Result<Self, ProgramRecoveryError> {
        self.functions.validate()?;
        self.image_layout.validate()?;
        self.pointers.validate()?;
        self.symbols.validate()?;
        self.strings.validate()?;
        self.objc.validate()?;
        self.swift.validate()?;
        self.dwarf.validate()?;
        self.control_flow.validate()?;
        self.executable_bytes.validate()?;
        self.direct_calls.validate()?;
        self.transfers.validate()?;
        self.indirect_calls.validate()?;
        self.xrefs
            .validate()
            .map_err(|error| ProgramRecoveryError::Xrefs(error.to_string()))?;
        self.rtti.validate()?;
        self.exceptions.validate()?;
        self.dependencies.validate()?;
        self.semantics.validate()?;
        Ok(self)
    }
}

/// Failure preventing the unified program from being constructed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProgramRecoveryError {
    /// A serialized limits envelope uses an unsupported schema.
    #[error("unsupported program limits schema {actual}; supported schema is {supported}")]
    UnsupportedLimitsSchema {
        /// Supported schema.
        supported: u32,
        /// Supplied schema.
        actual: u32,
    },
    /// A constructed completeness receipt violates the shared contract.
    #[error(transparent)]
    Completeness(#[from] ProgramCompletenessValidationError),
    /// A supplied function inventory used different limits than the program.
    #[error("supplied function inventory limits differ from program limits")]
    FunctionLimitsMismatch,
    /// A supplied function inventory belongs to different image bytes.
    #[error("supplied function inventory and Mach-O image identities differ")]
    FunctionImageMismatch,
    /// A prior recovered program belongs to different image bytes.
    #[error("prior recovered program and Mach-O image identities differ")]
    ProgramImageMismatch,
    /// The selected-image leaf evidence session could not be constructed.
    #[error("selected-image evidence session failed: {0}")]
    Evidence(String),
    /// A recovery guide is stale, conflicting, or unsupported for the base program.
    #[error("recovery guide validation failed")]
    GuideValidationFailed {
        /// Complete non-mutating validation report.
        validation: RecoveryGuideValidation,
    },
    /// Image layout construction failed.
    #[error(transparent)]
    ImageLayout(#[from] ImageLayoutError),
    /// Pointer inventory construction failed.
    #[error(transparent)]
    Pointers(#[from] PointerRecoveryError),
    /// Symbol inventory construction failed.
    #[error(transparent)]
    Symbols(#[from] SymbolRecoveryError),
    /// String inventory construction failed.
    #[error(transparent)]
    Strings(#[from] StringRecoveryError),
    /// Objective-C inventory construction failed.
    #[error(transparent)]
    Objc(#[from] ObjcRecoveryError),
    /// Swift inventory construction failed.
    #[error(transparent)]
    Swift(#[from] SwiftRecoveryError),
    /// DWARF inventory construction failed.
    #[error(transparent)]
    Dwarf(#[from] DwarfRecoveryError),
    /// Function inventory construction failed.
    #[error(transparent)]
    Functions(#[from] FunctionRecoveryError),
    /// Control-flow construction failed.
    #[error(transparent)]
    ControlFlow(#[from] ControlFlowRecoveryError),
    /// Executable-byte classification failed.
    #[error(transparent)]
    ExecutableBytes(#[from] ExecutableByteRecoveryError),
    /// Direct call-graph construction failed.
    #[error(transparent)]
    DirectCalls(#[from] DirectCallGraphError),
    /// Direct transfer/thunk construction failed.
    #[error(transparent)]
    Transfers(#[from] TransferRecoveryError),
    /// Indirect transfer construction failed.
    #[error(transparent)]
    IndirectCalls(#[from] IndirectCallRecoveryError),
    /// Cross-reference construction failed.
    #[error("xref recovery failed: {0}")]
    Xrefs(String),
    /// Strict RTTI construction failed.
    #[error(transparent)]
    Rtti(#[from] RttiRecoveryError),
    /// Exception/unwind inventory construction failed.
    #[error(transparent)]
    Exceptions(#[from] ExceptionRecoveryError),
    /// Dependency inventory construction failed.
    #[error(transparent)]
    Dependencies(#[from] DependencyRecoveryError),
    /// Semantic inventory construction failed.
    #[error(transparent)]
    Semantics(#[from] SemanticRecoveryError),
}

/// Structural failure in a durable program Fact IR document.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProgramFactValidationError {
    /// The document uses an unsupported Fact IR schema.
    #[error("unsupported program Fact IR schema {actual}; supported schema is {supported}")]
    UnsupportedSchema {
        /// Supported schema.
        supported: u32,
        /// Supplied schema.
        actual: u32,
    },
    /// The selected-image content identity is malformed.
    #[error("program Fact IR image identity is malformed")]
    InvalidImageIdentity,
    /// The recovery question/guide contract does not match this library.
    #[error("program Fact IR recovery contract is unsupported")]
    UnsupportedRecoveryContract,
    /// Executed stages are not the dependency closure of the request.
    #[error("program Fact IR executed stages do not match request dependency closure")]
    StageClosureMismatch,
    /// A selected stage and its durable payload disagree.
    #[error("program Fact IR payload presence disagrees for stage {stage:?}")]
    StagePayloadMismatch {
        /// Inconsistent stage.
        stage: ProgramRecoveryStage,
    },
    /// A stage payload is bound to different image bytes.
    #[error("program Fact IR payload image differs for stage {stage:?}")]
    StageImageMismatch {
        /// Inconsistent stage.
        stage: ProgramRecoveryStage,
    },
    /// A stage payload was built under different limits.
    #[error("program Fact IR payload limits differ for stage {stage:?}")]
    StageLimitsMismatch {
        /// Inconsistent stage.
        stage: ProgramRecoveryStage,
    },
    /// A stage payload violates ordering or receipt invariants required by its readers.
    #[error("program Fact IR payload invariants are invalid for stage {stage:?}")]
    StagePayloadInvariant {
        /// Invalid stage.
        stage: ProgramRecoveryStage,
    },
    /// The stored completeness ledger is invalid.
    #[error(transparent)]
    Completeness(#[from] ProgramCompletenessValidationError),
    /// The stored completeness ledger is not derived from the payload.
    #[error("program Fact IR completeness does not match its stage payloads")]
    CompletenessMismatch,
    /// Stored coverage is not derived from the payload.
    #[error("program Fact IR coverage does not match its stage payloads")]
    CoverageMismatch,
    /// Stored recovery questions are not derived from the payload.
    #[error("program Fact IR questions do not match its stage payloads")]
    QuestionsMismatch,
    /// A guided reference owner does not identify one exact retained xref and
    /// one independently possible source-range owner.
    #[error("program Fact IR guided reference ownership is inconsistent")]
    GuidedReferenceOwnershipMismatch,
    /// Guide and application receipt presence or identity is inconsistent.
    #[error("program Fact IR guide application is inconsistent")]
    GuideApplicationMismatch,
    /// A nested recovery limit is invalid.
    #[error("program Fact IR recovery limits are invalid: {0}")]
    InvalidLimits(String),
}

/// JSON decoding or validation failure for a durable Fact IR document.
#[derive(Debug, Error)]
pub enum ProgramFactDocumentError {
    /// The input is not a syntactically valid document.
    #[error("invalid program Fact IR JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// A nested record contained a field outside the current wire schema.
    #[error("unknown program Fact IR field at {path}")]
    UnknownField {
        /// JSON path of the first unrecognized field.
        path: String,
    },
    /// The decoded document violates the Fact IR contract.
    #[error(transparent)]
    Validation(#[from] ProgramFactValidationError),
}

/// One layer of the unified recovery pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRecoveryStage {
    /// Indexed segments, sections, permissions, and address translation.
    ImageLayout,
    /// Format pointers, fixups, binds, stubs, relocations, and authentication.
    Pointers,
    /// Complete nlist, export, and import symbol inventory.
    Symbols,
    /// Typed and optionally heuristic string inventory.
    Strings,
    /// Strict Objective-C runtime metadata.
    Objc,
    /// Strict Swift ABI metadata.
    Swift,
    /// Bounded DWARF traversal and source mappings.
    Dwarf,
    /// Function identities and ownership.
    Functions,
    /// Basic blocks and intra-procedural control flow.
    ControlFlow,
    /// Conserved executable-section byte classification.
    ExecutableBytes,
    /// Direct call graph.
    DirectCalls,
    /// Direct branches, tail calls, and thunks.
    Transfers,
    /// Indirect calls, branches, and dynamic dispatch.
    IndirectCalls,
    /// Format and instruction cross-references.
    Xrefs,
    /// Named and structural Itanium RTTI, vtables, VTTs, and relationships.
    Rtti,
    /// Exception-frame function records and linked unwind lookup metadata.
    Exceptions,
    /// Named dependency declarations and runtime-open frontiers.
    Dependencies,
    /// Global data, signatures, stack frames, and local variables.
    Semantics,
}

impl ProgramRecoveryStage {
    /// Stable wire spelling used by diagnostics and frontier subjects.
    pub const fn key(self) -> &'static str {
        match self {
            Self::ImageLayout => "image_layout",
            Self::Pointers => "pointers",
            Self::Symbols => "symbols",
            Self::Strings => "strings",
            Self::Objc => "objc",
            Self::Swift => "swift",
            Self::Dwarf => "dwarf",
            Self::Functions => "functions",
            Self::ControlFlow => "control_flow",
            Self::ExecutableBytes => "executable_bytes",
            Self::DirectCalls => "direct_calls",
            Self::Transfers => "transfers",
            Self::IndirectCalls => "indirect_calls",
            Self::Xrefs => "xrefs",
            Self::Rtti => "rtti",
            Self::Exceptions => "exceptions",
            Self::Dependencies => "dependencies",
            Self::Semantics => "semantics",
        }
    }

    /// Deterministic direct dependencies required by this stage.
    pub const fn dependencies(self) -> &'static [Self] {
        match self {
            Self::ControlFlow => &[Self::Functions, Self::Pointers],
            Self::ExecutableBytes => &[Self::Functions, Self::ControlFlow],
            Self::Functions => &[
                Self::Pointers,
                Self::Dwarf,
                Self::Objc,
                Self::Swift,
                Self::Exceptions,
            ],
            Self::DirectCalls | Self::Transfers => &[Self::Functions, Self::ControlFlow],
            Self::IndirectCalls => &[
                Self::Functions,
                Self::ControlFlow,
                Self::Pointers,
                Self::Rtti,
                Self::Objc,
                Self::Swift,
            ],
            Self::Xrefs => &[Self::Functions, Self::ControlFlow, Self::Pointers],
            Self::Semantics => &[
                Self::ImageLayout,
                Self::Pointers,
                Self::Symbols,
                Self::Strings,
                Self::Objc,
                Self::Swift,
                Self::Rtti,
                Self::Dwarf,
                Self::Exceptions,
                Self::Functions,
            ],
            Self::Dependencies => &[Self::Symbols],
            Self::ImageLayout
            | Self::Pointers
            | Self::Symbols
            | Self::Strings
            | Self::Objc
            | Self::Swift
            | Self::Dwarf
            | Self::Rtti
            | Self::Exceptions => &[],
        }
    }

    /// Every currently supported recovery stage.
    pub const fn all() -> &'static [Self] {
        &[
            Self::ImageLayout,
            Self::Pointers,
            Self::Symbols,
            Self::Strings,
            Self::Objc,
            Self::Swift,
            Self::Dwarf,
            Self::Functions,
            Self::ControlFlow,
            Self::ExecutableBytes,
            Self::DirectCalls,
            Self::Transfers,
            Self::IndirectCalls,
            Self::Xrefs,
            Self::Rtti,
            Self::Exceptions,
            Self::Dependencies,
            Self::Semantics,
        ]
    }
}

/// Selective program-recovery request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramRecoveryRequest {
    requested: BTreeSet<ProgramRecoveryStage>,
    limits: ProgramRecoveryLimits,
}

impl ProgramRecoveryRequest {
    /// Select exactly the supplied stages; dependencies are added during recovery.
    pub fn new(
        stages: impl IntoIterator<Item = ProgramRecoveryStage>,
        limits: ProgramRecoveryLimits,
    ) -> Self {
        Self {
            requested: stages.into_iter().collect(),
            limits,
        }
    }

    /// Select every recovery stage.
    pub fn all(limits: ProgramRecoveryLimits) -> Self {
        Self::new(ProgramRecoveryStage::all().iter().copied(), limits)
    }

    /// Stages explicitly requested by the caller.
    pub fn requested(&self) -> &BTreeSet<ProgramRecoveryStage> {
        &self.requested
    }

    /// Limits supplied for independently selected modules.
    pub const fn limits(&self) -> ProgramRecoveryLimits {
        self.limits
    }

    fn resolved(&self) -> BTreeSet<ProgramRecoveryStage> {
        let mut resolved = self.requested.clone();
        loop {
            let prior = resolved.len();
            for stage in resolved.clone() {
                resolved.extend(stage.dependencies().iter().copied());
            }
            if resolved.len() == prior {
                return resolved;
            }
        }
    }
}

/// Completion state shared by the program and each stage receipt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRecoveryStatus {
    /// The stage retained all supported evidence without uncertainty.
    Complete,
    /// Evidence is useful but incomplete, unresolved, or candidate-only.
    Partial,
    /// At least one explicit budget omitted evidence.
    Truncated,
}

/// Completion receipt for one owned recovery stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramStageReceipt {
    /// Pipeline stage.
    pub stage: ProgramRecoveryStage,
    /// Whether the caller selected this stage directly rather than as a dependency.
    pub requested: bool,
    /// Stage completion state.
    pub status: ProgramRecoveryStatus,
    /// Stable reason codes retained from that stage.
    pub reasons: Vec<String>,
}

/// Global completion ledger for a recovered program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRecoveryCompleteness {
    /// Version of the examined-universe and stage-contract schema.
    pub schema_version: u32,
    /// Exact image, stages, named dependencies, and runtime frontiers examined.
    pub examined_universe: ProgramExaminedUniverse,
    /// Weakest completion state across all stages.
    pub status: ProgramRecoveryStatus,
    /// One receipt per stage in deterministic pipeline order.
    pub stages: Vec<ProgramStageReceipt>,
    /// Stable program-level reasons identifying incomplete stages.
    pub reasons: Vec<String>,
    /// Standard conservation contract for every executed stage.
    pub contracts: Vec<ProgramStageContract>,
}

/// Exact universe declared by one recovered-program receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramExaminedUniverse {
    /// Selected thin-image identity.
    pub image: FunctionImageIdentity,
    /// Dependency-closed recovery stages executed.
    pub stages: Vec<ProgramRecoveryStage>,
    /// Statically named dependency install names.
    pub named_dependencies: Vec<String>,
    /// Explicit runtime-open boundary reason codes.
    pub runtime_frontiers: Vec<String>,
}

/// Standard evidence and completeness ledger for one stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramStageContract {
    /// Recovery stage.
    pub stage: ProgramRecoveryStage,
    /// Supported ABI/schema version for this contract.
    pub schema_version: u32,
    /// Retained evidence records or semantic products.
    pub included: u64,
    /// Retained unresolved evidence.
    pub unknown: u64,
    /// Explicitly rejected interpretations.
    pub rejected: u64,
    /// Evidence omitted by explicit budgets.
    pub budget_excluded: u64,
    /// First resumable continuation coordinate.
    pub continuation: Option<String>,
    /// Retained cross-source conflicts.
    pub conflicts: u64,
    /// Whether each retained local product satisfies its supported contract.
    pub locally_complete: bool,
    /// Whether the complete declared stage universe is closed.
    pub globally_complete: bool,
}

/// Structural failure in a program completeness receipt.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProgramCompletenessValidationError {
    /// The receipt schema is unsupported.
    #[error("unsupported program completeness schema {actual}; supported schema is {supported}")]
    UnsupportedSchema {
        /// Supported schema.
        supported: u32,
        /// Supplied schema.
        actual: u32,
    },
    /// Stage receipts and standard contracts do not identify the same stages.
    #[error("stage receipt and contract ledgers differ")]
    StageLedgerMismatch,
    /// A stage marked complete retains uncertainty, conflict, or omitted evidence.
    #[error("complete stage {stage:?} contains unknown, conflicted, or omitted evidence")]
    FalseComplete {
        /// Stage containing impossible completion evidence.
        stage: ProgramRecoveryStage,
    },
    /// The program status is not the weakest retained stage state.
    #[error("program status does not match its stage receipts")]
    StatusMismatch,
}

impl ProgramRecoveryCompleteness {
    /// Validate schema, ledger alignment, global status, and the no-false-complete invariant.
    pub fn validate(&self) -> Result<(), ProgramCompletenessValidationError> {
        if self.schema_version != PROGRAM_COMPLETENESS_SCHEMA_VERSION {
            return Err(ProgramCompletenessValidationError::UnsupportedSchema {
                supported: PROGRAM_COMPLETENESS_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        let receipt_stages = self
            .stages
            .iter()
            .map(|receipt| receipt.stage)
            .collect::<Vec<_>>();
        let contract_stages = self
            .contracts
            .iter()
            .map(|contract| contract.stage)
            .collect::<Vec<_>>();
        if receipt_stages != contract_stages
            || self
                .contracts
                .iter()
                .any(|contract| contract.schema_version != self.schema_version)
        {
            return Err(ProgramCompletenessValidationError::StageLedgerMismatch);
        }
        for (receipt, contract) in self.stages.iter().zip(&self.contracts) {
            if receipt.status == ProgramRecoveryStatus::Complete
                && (contract.unknown != 0
                    || contract.budget_excluded != 0
                    || contract.conflicts != 0
                    || contract.continuation.is_some()
                    || !contract.locally_complete
                    || !contract.globally_complete)
            {
                return Err(ProgramCompletenessValidationError::FalseComplete {
                    stage: receipt.stage,
                });
            }
        }
        let expected = if self
            .stages
            .iter()
            .any(|stage| stage.status == ProgramRecoveryStatus::Truncated)
        {
            ProgramRecoveryStatus::Truncated
        } else if self
            .stages
            .iter()
            .any(|stage| stage.status == ProgramRecoveryStatus::Partial)
        {
            ProgramRecoveryStatus::Partial
        } else {
            ProgramRecoveryStatus::Complete
        };
        if self.status != expected {
            return Err(ProgramCompletenessValidationError::StatusMismatch);
        }
        Ok(())
    }
}

/// A function and the Macho-owned recovered layers attached to its identity.
#[derive(Debug, Clone, Copy)]
pub struct ProgramFunctionView<'program> {
    /// Authoritative function identity and extent evidence.
    pub function: &'program RecoveredFunction,
    /// Recovered CFG, if retained.
    pub control_flow: Option<&'program FunctionControlFlow>,
    /// Direct-call node, if admitted to the graph.
    pub direct_call_node: Option<&'program DirectCallNode>,
    /// Forwarding-thunk identity, if retained.
    pub thunk: Option<&'program RecoveredThunk>,
    /// Best-known evidence-bearing signature, when semantic recovery was selected.
    pub signature: Option<&'program crate::analysis::semantic_index::RecoveredFunctionSignature>,
    /// CFI-derived stack frame, when available.
    pub frame: Option<&'program crate::analysis::semantic_index::RecoveredStackFrame>,
}

/// A direct call edge paired with its current thunk-resolved destination.
#[derive(Debug, Clone)]
pub struct ResolvedDirectCallEdge<'program> {
    /// Original direct edge and its callsite evidence.
    pub edge: &'program DirectCallEdge,
    /// Direct, thunk-chain, cycle, depth-limited, or truncated resolution.
    pub resolution: FunctionTargetResolution,
}

/// One borrowed xref enriched by the selected target-address modules.
#[derive(Debug)]
pub struct ProgramReferenceView<'program> {
    /// Underlying authoritative xref.
    pub reference: &'program Xref,
    /// Selected source owner and its independent-or-guided authority.
    pub source_owner: Option<ProgramReferenceOwner<'program>>,
    /// Function ownership of an internal target, when function recovery was selected.
    pub target_function: Option<FunctionLookup<'program>>,
    /// Symbol records defining the internal target.
    pub target_symbols: Vec<&'program RecoveredSymbol>,
    /// String containing the internal target.
    pub target_string: Option<&'program RecoveredString>,
    /// Strict type-info object at the internal target.
    pub target_type_info: Option<&'program crate::metadata::cpp::ItaniumTypeInfoRecord>,
    /// Smallest semantic data object owning the internal target.
    pub target_data_object: Option<&'program crate::analysis::semantic_index::RecoveredDataObject>,
    /// Typed terminal binding for the target rather than a bare address.
    pub target_binding: ProgramReferenceBinding,
}

/// One selected function owner for an exact reference use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProgramReferenceOwner<'program> {
    /// Recovered owner and its range-ownership confidence.
    pub owner: FunctionOwner<'program>,
    /// Whether this exact ownership relation is independent or caller-guided.
    pub authority: ProgramFactAuthority,
}

/// Terminal classification of one cross-reference target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramReferenceBinding {
    /// An imported identity names the external target.
    Import,
    /// Recovered function ownership accounts for the internal address.
    Function,
    /// A semantic data object accounts for the internal address.
    DataObject,
    /// Function and data evidence overlap, or function ownership is ambiguous.
    AmbiguousInternal,
    /// No selected supported identity owns the internal address.
    UnresolvedInternal,
}

/// Allocation-free annotations for one cross-reference.
#[derive(Debug, Clone, Copy)]
pub struct ProgramReferenceAnnotations<'program> {
    program: &'program RecoveredProgram,
    reference: &'program Xref,
}

impl<'program> ProgramReferenceAnnotations<'program> {
    /// Underlying authoritative xref.
    pub const fn reference(&self) -> &'program Xref {
        self.reference
    }

    /// Selected source owner, preserving whether the relation was guided.
    pub fn source_owner(&self) -> Option<ProgramReferenceOwner<'program>> {
        self.program.reference_owner(self.reference)
    }

    /// Function ownership of an internal target, when function recovery was selected.
    pub fn target_function(&self) -> Option<FunctionOwners<'program>> {
        let address = self.target_address()?;
        self.program
            .functions
            .as_ref()
            .map(|functions| functions.owners(address))
    }

    /// Iterate symbol records defining the internal target without allocating.
    pub fn target_symbols(&self) -> impl Iterator<Item = &'program RecoveredSymbol> + 'program {
        let address = self.target_address();
        self.program
            .symbols
            .as_ref()
            .into_iter()
            .flat_map(move |symbols| {
                address
                    .into_iter()
                    .flat_map(|value| symbols.at_address(value))
            })
    }

    /// String containing the internal target.
    pub fn target_string(&self) -> Option<&'program RecoveredString> {
        self.target_address().and_then(|address| {
            self.program
                .strings
                .as_ref()
                .and_then(|strings| strings.referenced_at(address))
        })
    }

    /// Named or structurally recovered type-info object at the internal target.
    pub fn target_type_info(&self) -> Option<RecoveredTypeInfo<'program>> {
        self.target_address().and_then(|address| {
            self.program
                .rtti
                .as_ref()
                .and_then(|rtti| rtti.recovered_type_info_by_address(address))
        })
    }

    /// Smallest semantic data object owning or beginning at the target address.
    pub fn target_data_object(
        &self,
    ) -> Option<&'program crate::analysis::semantic_index::RecoveredDataObject> {
        self.target_address().and_then(|address| {
            self.program
                .semantics
                .as_ref()
                .and_then(|semantics| semantics.data_containing(address))
        })
    }

    /// Classify the target as an import, function, data object, ambiguity, or unresolved address.
    pub fn target_binding(&self) -> ProgramReferenceBinding {
        if matches!(self.reference.target, XrefTarget::Import { .. }) {
            return ProgramReferenceBinding::Import;
        }
        let function_count = self
            .target_function()
            .map(|owners| owners.len())
            .unwrap_or(0);
        let data = self.target_data_object();
        match (function_count, data) {
            (1, None) => ProgramReferenceBinding::Function,
            (0, Some(_)) => ProgramReferenceBinding::DataObject,
            (2.., _) | (1, Some(_)) => ProgramReferenceBinding::AmbiguousInternal,
            (0, None) => ProgramReferenceBinding::UnresolvedInternal,
        }
    }

    fn target_address(&self) -> Option<u64> {
        self.reference
            .target
            .internal_address()
            .map(|address| address.0)
    }
}

/// Borrowed address-centric context suitable for disassembly annotation.
#[derive(Debug)]
pub struct ProgramAddressView<'program> {
    /// Queried virtual address.
    pub address: u64,
    /// Function ownership, preserving ambiguity and confidence.
    pub function: Option<FunctionLookup<'program>>,
    /// Decoded instruction beginning at this address.
    pub instruction: Option<&'program ControlFlowInstruction>,
    /// Symbol records defining this exact address.
    pub symbols: Vec<&'program RecoveredSymbol>,
    /// String containing this address.
    pub string: Option<&'program RecoveredString>,
    /// Strict type-info object beginning at this address.
    pub type_info: Option<&'program crate::metadata::cpp::ItaniumTypeInfoRecord>,
    /// Strict vtable group containing this address.
    pub vtable: Option<&'program crate::metadata::cpp::ItaniumVtableGroupRecord>,
    /// Smallest bounded data object containing this address.
    pub data_object: Option<&'program crate::analysis::semantic_index::RecoveredDataObject>,
    /// Outgoing references enriched with borrowed target context.
    pub references: Vec<ProgramReferenceView<'program>>,
}

/// Allocation-free address annotations for streaming disassembly consumers.
#[derive(Debug, Clone, Copy)]
pub struct ProgramAnnotations<'program> {
    program: &'program RecoveredProgram,
    address: u64,
}

impl<'program> ProgramAnnotations<'program> {
    /// Queried virtual address.
    pub const fn address(&self) -> u64 {
        self.address
    }

    /// Segment containing the queried address, when layout recovery was selected.
    pub fn segment(&self) -> Option<&'program crate::analysis::image_layout::ImageSegment> {
        self.program
            .image_layout
            .as_ref()
            .and_then(|layout| layout.segment_containing(self.address))
    }

    /// Section containing the queried address, when layout recovery was selected.
    pub fn section(&self) -> Option<&'program crate::analysis::image_layout::ImageSection> {
        self.program
            .image_layout
            .as_ref()
            .and_then(|layout| layout.section_containing(self.address))
    }

    /// Function ownership, preserving ambiguity and confidence.
    pub fn function(&self) -> Option<FunctionOwners<'program>> {
        self.program
            .functions
            .as_ref()
            .map(|functions| functions.owners(self.address))
    }

    /// Decoded instruction beginning at the queried address.
    pub fn instruction(&self) -> Option<&'program ControlFlowInstruction> {
        let control_flow = self.program.control_flow.as_ref()?;
        self.function()?.find_map(|owner| {
            let graph = control_flow.by_entry(owner.function.entry)?;
            graph
                .instructions
                .binary_search_by_key(&self.address, |instruction| instruction.address)
                .ok()
                .map(|index| &graph.instructions[index])
        })
    }

    /// Iterate exact-address symbols without allocating or scanning the inventory.
    pub fn symbols(&self) -> impl Iterator<Item = &'program RecoveredSymbol> + 'program {
        let address = self.address;
        self.program
            .symbols
            .as_ref()
            .into_iter()
            .flat_map(move |symbols| symbols.at_address(address))
    }

    /// String containing the queried address.
    pub fn string(&self) -> Option<&'program RecoveredString> {
        self.program
            .strings
            .as_ref()
            .and_then(|strings| strings.containing(self.address))
    }

    /// Iterate format pointer records beginning at the queried address.
    pub fn pointers(
        &self,
    ) -> impl Iterator<Item = &'program crate::analysis::pointer_index::RecoveredPointer> + 'program
    {
        let address = self.address;
        self.program
            .pointers
            .as_ref()
            .into_iter()
            .flat_map(move |pointers| pointers.at_address(address))
    }

    /// Objective-C runtime entity beginning at the queried address.
    pub fn objc_entity(
        &self,
    ) -> Option<&'program crate::analysis::objc_index::RecoveredObjcEntity> {
        self.program
            .objc
            .as_ref()
            .and_then(|objc| objc.entity_by_address(self.address))
    }

    /// Iterate Objective-C methods implemented at the queried address.
    pub fn objc_methods(
        &self,
    ) -> impl Iterator<Item = &'program crate::analysis::objc_index::RecoveredObjcMethod> + 'program
    {
        let address = self.address;
        self.program
            .objc
            .as_ref()
            .into_iter()
            .flat_map(move |objc| objc.methods_by_implementation(address))
    }

    /// Swift nominal descriptor beginning at the queried address.
    pub fn swift_record(
        &self,
    ) -> Option<&'program crate::metadata::swift::evidence::MachoSwiftRecordV1> {
        self.program
            .swift
            .as_ref()
            .and_then(|swift| swift.record_by_descriptor(self.address))
    }

    /// Iterate physical DWARF source rows beginning at the queried address.
    pub fn dwarf_lines(
        &self,
    ) -> impl Iterator<Item = &'program crate::analysis::dwarf_index::DwarfLineAnnotation> + 'program
    {
        let address = self.address;
        self.program
            .dwarf
            .as_ref()
            .into_iter()
            .flat_map(move |dwarf| dwarf.lines_at(address))
    }

    /// Iterate exception/unwind records whose function entry is this address.
    pub fn exception_records(
        &self,
    ) -> impl Iterator<Item = &'program crate::analysis::exception_index::ExceptionFunctionRecord>
    + 'program {
        let address = self.address;
        self.program
            .exceptions
            .as_ref()
            .into_iter()
            .flat_map(move |exceptions| exceptions.by_entry(address))
    }

    /// Named or structurally recovered type-info object beginning at this address.
    pub fn type_info(&self) -> Option<RecoveredTypeInfo<'program>> {
        self.program
            .rtti
            .as_ref()
            .and_then(|rtti| rtti.recovered_type_info_by_address(self.address))
    }

    /// Named or structurally recovered vtable containing the queried address.
    pub fn vtable(&self) -> Option<RecoveredVtable<'program>> {
        self.program
            .rtti
            .as_ref()
            .and_then(|rtti| rtti.recovered_vtable_containing(self.address))
    }

    /// Smallest bounded data object containing the queried address.
    pub fn data_object(
        &self,
    ) -> Option<&'program crate::analysis::semantic_index::RecoveredDataObject> {
        self.program
            .semantics
            .as_ref()
            .and_then(|index| index.data_containing(self.address))
    }

    /// Iterate enriched outgoing references without allocating a result vector.
    pub fn references(
        &self,
    ) -> impl Iterator<Item = ProgramReferenceAnnotations<'program>> + 'program {
        let address = self.address;
        let program = self.program;
        program
            .xrefs
            .as_ref()
            .into_iter()
            .flat_map(move |xrefs| xrefs.refs_from(crate::core::model::addr::Va(address)))
            .map(move |reference| ProgramReferenceAnnotations { program, reference })
    }
}

/// Non-owning capability view for downstream analysis layers.
///
/// A consumer can accept this value when annotations are optional, or accept
/// the concrete index references it requires when the capability is mandatory.
/// No collector logic or recovered record is copied.
#[derive(Debug, Clone, Copy)]
pub struct ProgramFacts<'program> {
    /// Indexed image layout, when selected.
    pub image_layout: Option<&'program ImageLayoutIndex>,
    /// Format pointer inventory, when selected.
    pub pointers: Option<&'program PointerIndex>,
    /// Complete symbol inventory, when selected.
    pub symbols: Option<&'program SymbolInventory>,
    /// String inventory, when selected.
    pub strings: Option<&'program StringIndex>,
    /// Strict Objective-C runtime inventory, when selected or required.
    pub objc: Option<&'program ObjcIndex>,
    /// Strict Swift ABI inventory, when selected or required.
    pub swift: Option<&'program SwiftIndex>,
    /// Bounded DWARF inventory, when selected or required.
    pub dwarf: Option<&'program DwarfIndex>,
    /// Function identities and ownership, when selected or required.
    pub functions: Option<&'program FunctionIndex>,
    /// Per-function control flow, when selected or required.
    pub control_flow: Option<&'program ControlFlowIndex>,
    /// Conserved executable-section byte classifications, when selected.
    pub executable_bytes: Option<&'program ExecutableByteIndex>,
    /// Direct call graph, when selected.
    pub direct_calls: Option<&'program DirectCallGraph>,
    /// Tail calls and thunk resolution, when selected.
    pub transfers: Option<&'program DirectTransferIndex>,
    /// Indirect calls and dynamic dispatch, when selected.
    pub indirect_calls: Option<&'program IndirectCallIndex>,
    /// Cross-reference inventory, when selected.
    pub xrefs: Option<&'program XrefIndex>,
    /// Caller-guided owners of exact reference uses.
    pub guided_reference_ownerships: &'program [GuidedReferenceOwnership],
    /// Named and structural RTTI and vtable inventory, when selected.
    pub rtti: Option<&'program RttiIndex>,
    /// Exception and unwind boundary inventory, when selected.
    pub exceptions: Option<&'program ExceptionIndex>,
    /// Named dependency declarations and runtime frontiers.
    pub dependencies: Option<&'program DependencyIndex>,
    /// Data, signature, frame, and local-variable semantics.
    pub semantics: Option<&'program SemanticIndex>,
}

/// Narrow borrowed inputs for a higher-level disassembly presentation layer.
///
/// Function ownership and decoded control flow are mandatory. Every annotation
/// source is independently optional, so callers can request only the facts they
/// intend to display.
#[derive(Debug, Clone, Copy)]
pub struct DisassemblyFacts<'program> {
    /// Authoritative function identities, extents, and ownership.
    pub functions: &'program FunctionIndex,
    /// Decoded instructions, basic blocks, and CFG edges.
    pub control_flow: &'program ControlFlowIndex,
    /// Conserved executable-section byte classifications, when selected.
    pub executable_bytes: Option<&'program ExecutableByteIndex>,
    /// Indexed image layout and address translation, when selected.
    pub image_layout: Option<&'program ImageLayoutIndex>,
    /// Format pointer annotations, when selected.
    pub pointers: Option<&'program PointerIndex>,
    /// Exact-address symbol annotations, when selected.
    pub symbols: Option<&'program SymbolInventory>,
    /// Addressable string contents, when selected.
    pub strings: Option<&'program StringIndex>,
    /// Objective-C entities and implementation identities, when selected.
    pub objc: Option<&'program ObjcIndex>,
    /// Swift nominal and dispatch metadata, when selected.
    pub swift: Option<&'program SwiftIndex>,
    /// DWARF source mappings, when selected.
    pub dwarf: Option<&'program DwarfIndex>,
    /// Instruction and format references, when selected.
    pub xrefs: Option<&'program XrefIndex>,
    /// Type-info and vtable annotations, when selected.
    pub rtti: Option<&'program RttiIndex>,
    /// Exception and unwind boundaries, when selected.
    pub exceptions: Option<&'program ExceptionIndex>,
}

impl<'program> ProgramFacts<'program> {
    /// Borrow the narrow fact set used by a disassembly presentation layer.
    pub fn disassembly_inputs(&self) -> Option<DisassemblyFacts<'program>> {
        Some(DisassemblyFacts {
            functions: self.functions?,
            control_flow: self.control_flow?,
            executable_bytes: self.executable_bytes,
            image_layout: self.image_layout,
            pointers: self.pointers,
            symbols: self.symbols,
            strings: self.strings,
            objc: self.objc,
            swift: self.swift,
            dwarf: self.dwarf,
            xrefs: self.xrefs,
            rtti: self.rtti,
            exceptions: self.exceptions,
        })
    }

    /// Borrow the exact prerequisites required by a control-flow consumer.
    pub fn control_flow_inputs(
        &self,
    ) -> Option<(&'program FunctionIndex, &'program ControlFlowIndex)> {
        Some((self.functions?, self.control_flow?))
    }

    /// Borrow the exact prerequisites and product required by a direct-call consumer.
    pub fn direct_call_inputs(
        &self,
    ) -> Option<(
        &'program FunctionIndex,
        &'program ControlFlowIndex,
        &'program DirectCallGraph,
    )> {
        Some((self.functions?, self.control_flow?, self.direct_calls?))
    }

    /// Borrow the exact prerequisites and product required by a transfer consumer.
    pub fn transfer_inputs(
        &self,
    ) -> Option<(
        &'program FunctionIndex,
        &'program ControlFlowIndex,
        &'program DirectTransferIndex,
    )> {
        Some((self.functions?, self.control_flow?, self.transfers?))
    }

    /// Borrow the exact prerequisites and product required by an indirect-call consumer.
    pub fn indirect_call_inputs(
        &self,
    ) -> Option<(
        &'program FunctionIndex,
        &'program ControlFlowIndex,
        &'program IndirectCallIndex,
    )> {
        Some((self.functions?, self.control_flow?, self.indirect_calls?))
    }

    /// Borrow the exact prerequisites and product required by an xref consumer.
    pub fn xref_inputs(
        &self,
    ) -> Option<(
        &'program FunctionIndex,
        &'program ControlFlowIndex,
        &'program XrefIndex,
    )> {
        Some((self.functions?, self.control_flow?, self.xrefs?))
    }
}

/// Owned stage payloads in the durable whole-program Fact IR.
///
/// These fields are deliberately separate from the document's identity,
/// request, receipts, and guide metadata. They contain queryable recovery
/// products only; selected-image bytes remain outside the document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredProgramBody {
    /// Indexed image layout, when selected.
    pub image_layout: Option<ImageLayoutIndex>,
    /// Pointer, fixup, bind, stub, and relocation inventory, when selected.
    pub pointers: Option<PointerIndex>,
    /// Symbol inventory, when selected.
    pub symbols: Option<SymbolInventory>,
    /// String inventory, when selected.
    pub strings: Option<StringIndex>,
    /// Objective-C facts, when selected.
    pub objc: Option<ObjcIndex>,
    /// Swift ABI facts, when selected.
    pub swift: Option<SwiftIndex>,
    /// DWARF facts, when selected.
    pub dwarf: Option<DwarfIndex>,
    /// Function identities and ownership, when selected.
    pub functions: Option<FunctionIndex>,
    /// Control-flow graphs, when selected.
    pub control_flow: Option<ControlFlowIndex>,
    /// Executable-byte classifications, when selected.
    pub executable_bytes: Option<ExecutableByteIndex>,
    /// Direct-call graph, when selected.
    pub direct_calls: Option<DirectCallGraph>,
    /// Direct transfers and thunks, when selected.
    pub transfers: Option<DirectTransferIndex>,
    /// Indirect transfers and dynamic dispatch, when selected.
    pub indirect_calls: Option<IndirectCallIndex>,
    /// Cross references, when selected.
    pub xrefs: Option<XrefIndex>,
    /// Caller-guided owners of exact cross-reference uses.
    pub guided_reference_ownerships: Vec<GuidedReferenceOwnership>,
    /// C++ RTTI and vtable facts, when selected.
    pub rtti: Option<RttiIndex>,
    /// Exception and unwind facts, when selected.
    pub exceptions: Option<ExceptionIndex>,
    /// Named dependencies and runtime frontiers, when selected.
    pub dependencies: Option<DependencyIndex>,
    /// Semantic data, signature, frame, and local facts, when selected.
    pub semantics: Option<SemanticIndex>,
}

/// Strict, versioned, durable Fact IR for one exact selected Mach-O image.
///
/// The document is queryable without image bytes. Any operation that decodes
/// or deepens recovery still requires a live [`MachoFile`] whose identity
/// exactly matches [`Self::image`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramFactDocument {
    /// Exact Fact IR schema version.
    pub schema_version: u32,
    /// Version of stable recovery subject, question, and guide identities.
    pub recovery_schema: RecoveryContractSchema,
    /// Content hash, architecture, and byte length of the selected thin image.
    pub image: FunctionImageIdentity,
    /// Selective request and nested budgets that produced this document.
    pub request: ProgramRecoveryRequest,
    /// Requested stages plus deterministic dependency closure.
    pub executed: BTreeSet<ProgramRecoveryStage>,
    /// Validated completion ledger.
    pub completeness: ProgramRecoveryCompleteness,
    /// Materialized truth-aware coverage for offline inspection.
    pub coverage: ProgramCoverage,
    /// Guide retained by the current state, when caller guidance was applied.
    pub guide: Option<RecoveryGuide>,
    /// Application and provenance receipt for the retained guide.
    pub guide_application: Option<RecoveryGuideApplication>,
    /// Current stable ambiguities.
    pub questions: Vec<RecoveryQuestion>,
    /// Owned recovery-stage payloads.
    pub program: RecoveredProgramBody,
}

/// Availability and completion of one recovery stage in a program state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramStageStatus {
    /// The stage was outside the dependency-closed request.
    Absent,
    /// The stage retained its complete declared universe.
    Complete,
    /// The stage retained useful but incomplete or unresolved evidence.
    Partial,
    /// An explicit budget omitted stage evidence.
    Truncated,
}

/// Epistemic authority attached to a structural program subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramFactAuthority {
    /// Established without caller guidance in the current state.
    Independent,
    /// Established, reclassified, or admitted through caller guidance.
    Guided,
}

impl ProgramFactDocument {
    /// Decode and validate one strict JSON Fact IR document.
    pub fn load_json(bytes: &[u8]) -> Result<Self, ProgramFactDocumentError> {
        let input: serde_json::Value = serde_json::from_slice(bytes)?;
        let document: Self = serde_json::from_value(input.clone())?;
        let canonical = serde_json::to_value(&document)?;
        if let Some(path) = first_unknown_json_field(&input, &canonical, "$".to_owned()) {
            return Err(ProgramFactDocumentError::UnknownField { path });
        }
        document.validate()?;
        Ok(document)
    }

    /// Encode a stable, human-inspectable JSON Fact IR document.
    pub fn to_json_pretty(&self) -> Result<Vec<u8>, ProgramFactDocumentError> {
        self.validate()?;
        Ok(serde_json::to_vec_pretty(self)?)
    }

    /// Validate schema, identity, request closure, payload binding, receipts,
    /// coverage, questions, and guide provenance without image bytes.
    pub fn validate(&self) -> Result<(), ProgramFactValidationError> {
        if self.schema_version != PROGRAM_FACT_IR_SCHEMA_VERSION {
            return Err(ProgramFactValidationError::UnsupportedSchema {
                supported: PROGRAM_FACT_IR_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        if self.recovery_schema != RecoveryContractSchema::CURRENT {
            return Err(ProgramFactValidationError::UnsupportedRecoveryContract);
        }
        if self.image.byte_len == 0
            || self.image.cpu_type == 0
            || self.image.content_sha256.len() != 64
            || !self
                .image
                .content_sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ProgramFactValidationError::InvalidImageIdentity);
        }
        self.request
            .limits
            .validate()
            .map_err(|error| ProgramFactValidationError::InvalidLimits(error.to_string()))?;
        if self.executed != self.request.resolved() {
            return Err(ProgramFactValidationError::StageClosureMismatch);
        }

        macro_rules! validate_stage {
            ($stage:expr, $payload:expr, $limits:expr) => {{
                let selected = self.executed.contains(&$stage);
                if selected != $payload.is_some() {
                    return Err(ProgramFactValidationError::StagePayloadMismatch { stage: $stage });
                }
                if let Some(index) = $payload.as_ref() {
                    if index.image() != &self.image {
                        return Err(ProgramFactValidationError::StageImageMismatch {
                            stage: $stage,
                        });
                    }
                    if index.limits() != $limits {
                        return Err(ProgramFactValidationError::StageLimitsMismatch {
                            stage: $stage,
                        });
                    }
                }
            }};
        }
        let limits = self.request.limits;
        validate_stage!(
            ProgramRecoveryStage::ImageLayout,
            self.program.image_layout,
            limits.image_layout
        );
        validate_stage!(
            ProgramRecoveryStage::Pointers,
            self.program.pointers,
            limits.pointers
        );
        validate_stage!(
            ProgramRecoveryStage::Symbols,
            self.program.symbols,
            limits.symbols
        );
        validate_stage!(
            ProgramRecoveryStage::Strings,
            self.program.strings,
            limits.strings
        );
        validate_stage!(ProgramRecoveryStage::Objc, self.program.objc, limits.objc);
        validate_stage!(
            ProgramRecoveryStage::Swift,
            self.program.swift,
            limits.swift
        );
        validate_stage!(
            ProgramRecoveryStage::Dwarf,
            self.program.dwarf,
            limits.dwarf
        );
        validate_stage!(
            ProgramRecoveryStage::Functions,
            self.program.functions,
            limits.functions
        );
        validate_stage!(
            ProgramRecoveryStage::ControlFlow,
            self.program.control_flow,
            limits.control_flow
        );
        validate_stage!(
            ProgramRecoveryStage::ExecutableBytes,
            self.program.executable_bytes,
            limits.executable_bytes
        );
        validate_stage!(
            ProgramRecoveryStage::DirectCalls,
            self.program.direct_calls,
            limits.direct_calls
        );
        validate_stage!(
            ProgramRecoveryStage::Transfers,
            self.program.transfers,
            limits.transfers
        );
        validate_stage!(
            ProgramRecoveryStage::IndirectCalls,
            self.program.indirect_calls,
            limits.indirect_calls
        );
        validate_stage!(
            ProgramRecoveryStage::Xrefs,
            self.program.xrefs,
            limits.xrefs
        );
        validate_stage!(ProgramRecoveryStage::Rtti, self.program.rtti, limits.rtti);
        validate_stage!(
            ProgramRecoveryStage::Exceptions,
            self.program.exceptions,
            limits.exceptions
        );
        validate_stage!(
            ProgramRecoveryStage::Dependencies,
            self.program.dependencies,
            limits.dependencies
        );
        validate_stage!(
            ProgramRecoveryStage::Semantics,
            self.program.semantics,
            limits.semantics
        );
        if self
            .program
            .image_layout
            .as_ref()
            .is_some_and(|layout| !layout.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::ImageLayout,
            });
        }
        if self
            .program
            .pointers
            .as_ref()
            .is_some_and(|pointers| !pointers.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Pointers,
            });
        }
        if self
            .program
            .symbols
            .as_ref()
            .is_some_and(|symbols| !symbols.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Symbols,
            });
        }
        if self
            .program
            .strings
            .as_ref()
            .is_some_and(|strings| !strings.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Strings,
            });
        }
        if self
            .program
            .objc
            .as_ref()
            .is_some_and(|objc| !objc.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Objc,
            });
        }
        if self
            .program
            .swift
            .as_ref()
            .is_some_and(|swift| !swift.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Swift,
            });
        }
        if self
            .program
            .dwarf
            .as_ref()
            .is_some_and(|dwarf| !dwarf.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Dwarf,
            });
        }
        if self
            .program
            .exceptions
            .as_ref()
            .is_some_and(|exceptions| !exceptions.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Exceptions,
            });
        }
        if self
            .program
            .semantics
            .as_ref()
            .is_some_and(|semantics| !semantics.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Semantics,
            });
        }
        if self
            .program
            .xrefs
            .as_ref()
            .is_some_and(|xrefs| !xrefs.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Xrefs,
            });
        }
        if self
            .program
            .functions
            .as_ref()
            .is_some_and(|functions| !functions.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Functions,
            });
        }
        if self
            .program
            .control_flow
            .as_ref()
            .is_some_and(|control_flow| !control_flow.durable_invariants_hold())
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::ControlFlow,
            });
        }
        macro_rules! validate_durable_payload {
            ($stage:expr, $payload:expr) => {
                if $payload
                    .as_ref()
                    .is_some_and(|index| !index.durable_invariants_hold())
                {
                    return Err(ProgramFactValidationError::StagePayloadInvariant {
                        stage: $stage,
                    });
                }
            };
        }
        validate_durable_payload!(
            ProgramRecoveryStage::ExecutableBytes,
            self.program.executable_bytes
        );
        validate_durable_payload!(ProgramRecoveryStage::DirectCalls, self.program.direct_calls);
        validate_durable_payload!(ProgramRecoveryStage::Transfers, self.program.transfers);
        validate_durable_payload!(
            ProgramRecoveryStage::IndirectCalls,
            self.program.indirect_calls
        );
        validate_durable_payload!(ProgramRecoveryStage::Rtti, self.program.rtti);
        validate_durable_payload!(
            ProgramRecoveryStage::Dependencies,
            self.program.dependencies
        );
        if let (Some(functions), Some(control_flow)) =
            (&self.program.functions, &self.program.control_flow)
            && control_flow.functions().iter().any(|graph| {
                functions
                    .by_entry(graph.function_entry)
                    .is_none_or(|function| function.identity != graph.identity)
            })
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::ControlFlow,
            });
        }
        if let (Some(layout), Some(bytes)) =
            (&self.program.image_layout, &self.program.executable_bytes)
            && !bytes.layout_invariants_hold(layout)
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::ExecutableBytes,
            });
        }
        if let (Some(functions), Some(control_flow), Some(calls)) = (
            &self.program.functions,
            &self.program.control_flow,
            &self.program.direct_calls,
        ) && !calls.source_invariants_hold(functions, control_flow)
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::DirectCalls,
            });
        }
        if let (Some(functions), Some(control_flow), Some(transfers)) = (
            &self.program.functions,
            &self.program.control_flow,
            &self.program.transfers,
        ) && !transfers.source_invariants_hold(functions, control_flow)
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::Transfers,
            });
        }
        if let (Some(functions), Some(control_flow), Some(indirect)) = (
            &self.program.functions,
            &self.program.control_flow,
            &self.program.indirect_calls,
        ) && !indirect.source_invariants_hold(functions, control_flow)
        {
            return Err(ProgramFactValidationError::StagePayloadInvariant {
                stage: ProgramRecoveryStage::IndirectCalls,
            });
        }

        let mut prior_reference = None;
        for ownership in &self.program.guided_reference_ownerships {
            let reference_key = (
                ownership.source,
                ownership.target.clone(),
                ownership.reference_kind,
            );
            if prior_reference
                .as_ref()
                .is_some_and(|prior| prior >= &reference_key)
            {
                return Err(ProgramFactValidationError::GuidedReferenceOwnershipMismatch);
            }
            prior_reference = Some(reference_key);
            let exact_reference = ProgramSubjectKey::CrossReference {
                source: ownership.source,
                target: ownership.target.clone(),
                reference_kind: ownership.reference_kind,
            };
            if !self.program.xrefs.as_ref().is_some_and(|xrefs| {
                xrefs
                    .all_refs()
                    .iter()
                    .any(|reference| cross_reference_subject(reference) == exact_reference)
            }) || !self.program.functions.as_ref().is_some_and(|functions| {
                functions
                    .owners(ownership.source)
                    .any(|owner| owner.function.entry == ownership.function_entry)
            }) {
                return Err(ProgramFactValidationError::GuidedReferenceOwnershipMismatch);
            }
        }

        self.completeness.validate()?;
        if self.completeness.examined_universe.image != self.image
            || self.completeness.examined_universe.stages
                != self.executed.iter().copied().collect::<Vec<_>>()
        {
            return Err(ProgramFactValidationError::CompletenessMismatch);
        }
        let program = self.as_program_unchecked();
        let expected_completeness =
            program_completeness(&self.image, &self.request, program.facts());
        if self.completeness != expected_completeness {
            return Err(ProgramFactValidationError::CompletenessMismatch);
        }
        if self.coverage != build_program_coverage(&program) {
            return Err(ProgramFactValidationError::CoverageMismatch);
        }
        if self.questions
            != build_recovery_questions(
                &self.image,
                self.program.functions.as_ref(),
                self.program.control_flow.as_ref(),
                self.program.executable_bytes.as_ref(),
                self.program.xrefs.as_ref(),
                self.program.indirect_calls.as_ref(),
                &self.program.guided_reference_ownerships,
            )
        {
            return Err(ProgramFactValidationError::QuestionsMismatch);
        }
        match (&self.guide, &self.guide_application) {
            (None, None) if self.program.guided_reference_ownerships.is_empty() => {}
            (Some(guide), Some(application))
                if guide.schema == self.recovery_schema
                    && guide.image == self.image
                    && guide_application_is_consistent(
                        &self.image,
                        &self.coverage,
                        guide,
                        application,
                    )
                    && guided_reference_ownerships_are_consistent(
                        guide,
                        application,
                        &self.program.guided_reference_ownerships,
                    ) => {}
            _ => return Err(ProgramFactValidationError::GuideApplicationMismatch),
        }
        Ok(())
    }

    fn as_program_unchecked(&self) -> RecoveredProgram {
        RecoveredProgram {
            image: self.image.clone(),
            recovery_schema: self.recovery_schema,
            request: self.request.clone(),
            executed: self.executed.clone(),
            image_layout: self.program.image_layout.clone(),
            pointers: self.program.pointers.clone(),
            symbols: self.program.symbols.clone(),
            strings: self.program.strings.clone(),
            objc: self.program.objc.clone(),
            swift: self.program.swift.clone(),
            dwarf: self.program.dwarf.clone(),
            functions: self.program.functions.clone(),
            control_flow: self.program.control_flow.clone(),
            executable_bytes: self.program.executable_bytes.clone(),
            direct_calls: self.program.direct_calls.clone(),
            transfers: self.program.transfers.clone(),
            indirect_calls: self.program.indirect_calls.clone(),
            xrefs: self.program.xrefs.clone(),
            guided_reference_ownerships: self.program.guided_reference_ownerships.clone(),
            rtti: self.program.rtti.clone(),
            exceptions: self.program.exceptions.clone(),
            dependencies: self.program.dependencies.clone(),
            semantics: self.program.semantics.clone(),
            questions: self.questions.clone(),
            guide: self.guide.clone(),
            guide_application: self.guide_application.clone(),
            completeness: self.completeness.clone(),
        }
    }

    fn into_program_unchecked(self) -> RecoveredProgram {
        RecoveredProgram {
            image: self.image,
            recovery_schema: self.recovery_schema,
            request: self.request,
            executed: self.executed,
            image_layout: self.program.image_layout,
            pointers: self.program.pointers,
            symbols: self.program.symbols,
            strings: self.program.strings,
            objc: self.program.objc,
            swift: self.program.swift,
            dwarf: self.program.dwarf,
            functions: self.program.functions,
            control_flow: self.program.control_flow,
            executable_bytes: self.program.executable_bytes,
            direct_calls: self.program.direct_calls,
            transfers: self.program.transfers,
            indirect_calls: self.program.indirect_calls,
            xrefs: self.program.xrefs,
            guided_reference_ownerships: self.program.guided_reference_ownerships,
            rtti: self.program.rtti,
            exceptions: self.program.exceptions,
            dependencies: self.program.dependencies,
            semantics: self.program.semantics,
            questions: self.questions,
            guide: self.guide,
            guide_application: self.guide_application,
            completeness: self.completeness,
        }
    }
}

fn first_unknown_json_field(
    input: &serde_json::Value,
    canonical: &serde_json::Value,
    path: String,
) -> Option<String> {
    match (input, canonical) {
        (serde_json::Value::Object(input), serde_json::Value::Object(canonical)) => {
            for (key, value) in input {
                let field_path = format!("{path}.{key}");
                let Some(canonical_value) = canonical.get(key) else {
                    return Some(field_path);
                };
                if let Some(unknown) = first_unknown_json_field(value, canonical_value, field_path)
                {
                    return Some(unknown);
                }
            }
            None
        }
        (serde_json::Value::Array(input), serde_json::Value::Array(canonical)) => input
            .iter()
            .zip(canonical)
            .enumerate()
            .find_map(|(index, (value, canonical_value))| {
                first_unknown_json_field(value, canonical_value, format!("{path}[{index}]"))
            }),
        _ => None,
    }
}

fn guide_application_is_consistent(
    image: &FunctionImageIdentity,
    coverage: &ProgramCoverage,
    guide: &RecoveryGuide,
    application: &RecoveryGuideApplication,
) -> bool {
    if application.validation.decisions.len() != guide.decisions.len()
        || application.decisions.len() != guide.decisions.len()
        || application.delta.image != *image
        || application.coverage_delta.before.image != *image
        || application.coverage_delta.after != *coverage
        || application
            .suppressed_signals
            .iter()
            .any(|signal| signal.key.image != *image)
        || application
            .delta
            .records
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
    {
        return false;
    }
    if application
        .validation
        .decisions
        .iter()
        .enumerate()
        .any(|(index, decision)| decision.decision_index != index as u64)
        || application
            .decisions
            .iter()
            .enumerate()
            .any(|(index, decision)| decision.decision_index != index as u64)
        || application.delta.records.iter().any(|record| {
            record.derivations.windows(2).any(|pair| pair[0] >= pair[1])
                || record
                    .derivations
                    .iter()
                    .any(|derivation| derivation.decision_index as usize >= guide.decisions.len())
        })
    {
        return false;
    }
    let mut validation = application.validation.clone();
    summarize_guide_validation(&mut validation);
    if validation.applicability != application.validation.applicability {
        return false;
    }
    let mut summary = RecoveryDeltaSummary::default();
    for record in &application.delta.records {
        match record.kind {
            RecoveryDeltaKind::Added => summary.added += 1,
            RecoveryDeltaKind::Removed => summary.removed += 1,
            RecoveryDeltaKind::Reclassified => summary.reclassified += 1,
            RecoveryDeltaKind::Resolved => summary.resolved += 1,
            RecoveryDeltaKind::NewlyUnresolved => summary.newly_unresolved += 1,
        }
    }
    summary == application.delta.summary
}

fn guided_reference_ownerships_are_consistent(
    guide: &RecoveryGuide,
    application: &RecoveryGuideApplication,
    ownerships: &[GuidedReferenceOwnership],
) -> bool {
    let every_ownership_has_applied_decision = ownerships.iter().all(|ownership| {
        guide.decisions.iter().enumerate().any(|(index, decision)| {
            matches!(
                (&decision.point.subject, &decision.choice),
                (
                    ProgramSubjectKey::CrossReference {
                        source,
                        target,
                        reference_kind,
                    },
                    RecoveryChoice::ReferenceOwner { function_entry },
                ) if *source == ownership.source
                    && *target == ownership.target
                    && *reference_kind == ownership.reference_kind
                    && *function_entry == ownership.function_entry
            ) && application.decisions.iter().any(|result| {
                result.decision_index == index as u64
                    && result.status == RecoveryDecisionApplicationStatus::Applied
            })
        })
    });
    let every_applied_decision_has_ownership =
        guide.decisions.iter().enumerate().all(|(index, decision)| {
            let applied = application.decisions.iter().any(|result| {
                result.decision_index == index as u64
                    && result.status == RecoveryDecisionApplicationStatus::Applied
            });
            match (&decision.point.subject, &decision.choice, applied) {
                (
                    ProgramSubjectKey::CrossReference {
                        source,
                        target,
                        reference_kind,
                    },
                    RecoveryChoice::ReferenceOwner { function_entry },
                    true,
                ) => ownerships.iter().any(|ownership| {
                    ownership.source == *source
                        && ownership.target == *target
                        && ownership.reference_kind == *reference_kind
                        && ownership.function_entry == *function_entry
                }),
                _ => true,
            }
        });
    every_ownership_has_applied_decision && every_applied_decision_has_ownership
}

/// Deterministic Macho-owned recovery of one exact thin image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveredProgram {
    image: FunctionImageIdentity,
    recovery_schema: RecoveryContractSchema,
    request: ProgramRecoveryRequest,
    executed: BTreeSet<ProgramRecoveryStage>,
    image_layout: Option<ImageLayoutIndex>,
    pointers: Option<PointerIndex>,
    symbols: Option<SymbolInventory>,
    strings: Option<StringIndex>,
    objc: Option<ObjcIndex>,
    swift: Option<SwiftIndex>,
    dwarf: Option<DwarfIndex>,
    functions: Option<FunctionIndex>,
    control_flow: Option<ControlFlowIndex>,
    executable_bytes: Option<ExecutableByteIndex>,
    direct_calls: Option<DirectCallGraph>,
    transfers: Option<DirectTransferIndex>,
    indirect_calls: Option<IndirectCallIndex>,
    xrefs: Option<XrefIndex>,
    guided_reference_ownerships: Vec<GuidedReferenceOwnership>,
    rtti: Option<RttiIndex>,
    exceptions: Option<ExceptionIndex>,
    dependencies: Option<DependencyIndex>,
    semantics: Option<SemanticIndex>,
    questions: Vec<RecoveryQuestion>,
    guide: Option<RecoveryGuide>,
    guide_application: Option<RecoveryGuideApplication>,
    completeness: ProgramRecoveryCompleteness,
}

/// Wire version for operational program-recovery reuse receipts.
///
/// Reuse receipts describe how an immutable transition was computed. They are
/// intentionally separate from durable program Fact IR because reuse does not
/// change the recovered facts or their authority.
pub const PROGRAM_RECOVERY_REUSE_RECEIPT_VERSION: u32 = 1;

/// Function-local reuse performed while rebuilding the control-flow stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlFlowReuseReceipt {
    total_functions: u64,
    reused_functions: u64,
    rebuilt_functions: u64,
}

impl ControlFlowReuseReceipt {
    /// Number of final function graphs in the recovered control-flow index.
    pub const fn total_functions(&self) -> u64 {
        self.total_functions
    }

    /// Number of final function graphs admitted from the prior program.
    pub const fn reused_functions(&self) -> u64 {
        self.reused_functions
    }

    /// Number of final function graphs recovered from the current image.
    pub const fn rebuilt_functions(&self) -> u64 {
        self.rebuilt_functions
    }
}

/// Deterministic operational receipt for one immutable recovery transition.
///
/// A stage in `reused_stages` was copied as a whole. A stage in
/// `rebuilt_stages` was executed again; the control-flow receipt can still
/// report exact function-local reuse inside that rebuilt stage.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProgramRecoveryReuseReceipt {
    schema_version: u32,
    reused_stages: BTreeSet<ProgramRecoveryStage>,
    rebuilt_stages: BTreeSet<ProgramRecoveryStage>,
    control_flow: Option<ControlFlowReuseReceipt>,
}

impl ProgramRecoveryReuseReceipt {
    /// Operational receipt schema version.
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Executed stages copied whole from the prior immutable program.
    pub fn reused_stages(&self) -> &BTreeSet<ProgramRecoveryStage> {
        &self.reused_stages
    }

    /// Executed stages recomputed for the new immutable program.
    pub fn rebuilt_stages(&self) -> &BTreeSet<ProgramRecoveryStage> {
        &self.rebuilt_stages
    }

    /// Function-local detail when the transition includes control flow.
    pub const fn control_flow(&self) -> Option<&ControlFlowReuseReceipt> {
        self.control_flow.as_ref()
    }
}

/// A recovered immutable program together with its operational reuse receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramRecoveryTransition {
    program: RecoveredProgram,
    reuse_receipt: ProgramRecoveryReuseReceipt,
}

impl ProgramRecoveryTransition {
    /// Recovered program produced by the transition.
    pub const fn program(&self) -> &RecoveredProgram {
        &self.program
    }

    /// Operational reuse evidence for this transition.
    pub const fn reuse_receipt(&self) -> &ProgramRecoveryReuseReceipt {
        &self.reuse_receipt
    }

    /// Consume the transition and return only the recovered program.
    pub fn into_program(self) -> RecoveredProgram {
        self.program
    }

    /// Consume the transition and return the program and receipt separately.
    pub fn into_parts(self) -> (RecoveredProgram, ProgramRecoveryReuseReceipt) {
        (self.program, self.reuse_receipt)
    }
}

/// Immutable counterfactual preview containing both views under one exact
/// request and budget set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveryPreview {
    base: RecoveredProgram,
    guided: RecoveredProgram,
}

/// An internal, image-bound source of stage payloads whose inputs are known to
/// be unchanged for the next immutable program state.
struct ProgramRecoveryReuse<'program> {
    prior: &'program RecoveredProgram,
    dirty: BTreeSet<ProgramRecoveryStage>,
    control_flow_guidance: Option<ControlFlowRecoveryGuidance>,
}

#[derive(Default)]
struct ProgramRecoveryGuidance<'guide> {
    functions: Option<&'guide FunctionRecoveryGuidance>,
    executable_bytes: Option<&'guide ExecutableByteRecoveryGuidance>,
    control_flow: Option<&'guide ControlFlowRecoveryGuidance>,
    guide: Option<RecoveryGuide>,
    reference_ownerships: Vec<GuidedReferenceOwnership>,
}

impl ProgramRecoveryReuse<'_> {
    fn can_reuse(&self, stage: ProgramRecoveryStage) -> bool {
        self.prior.executed.contains(&stage) && !self.dirty.contains(&stage)
    }
}

fn control_flow_reuse_receipt(
    program: &RecoveredProgram,
    reused_functions: u64,
) -> Option<ControlFlowReuseReceipt> {
    program.control_flow.as_ref().map(|control_flow| {
        let total_functions = u64::try_from(control_flow.functions().len()).unwrap_or(u64::MAX);
        let reused_functions = reused_functions.min(total_functions);
        ControlFlowReuseReceipt {
            total_functions,
            reused_functions,
            rebuilt_functions: total_functions.saturating_sub(reused_functions),
        }
    })
}

fn reuse_receipt_for_unchanged_program(program: &RecoveredProgram) -> ProgramRecoveryReuseReceipt {
    let reused_functions = program.control_flow.as_ref().map_or(0, |control_flow| {
        u64::try_from(control_flow.functions().len()).unwrap_or(u64::MAX)
    });
    ProgramRecoveryReuseReceipt {
        schema_version: PROGRAM_RECOVERY_REUSE_RECEIPT_VERSION,
        reused_stages: program.executed.clone(),
        rebuilt_stages: BTreeSet::new(),
        control_flow: control_flow_reuse_receipt(program, reused_functions),
    }
}

fn reuse_receipt_for_rebuilt_program(program: &RecoveredProgram) -> ProgramRecoveryReuseReceipt {
    ProgramRecoveryReuseReceipt {
        schema_version: PROGRAM_RECOVERY_REUSE_RECEIPT_VERSION,
        reused_stages: BTreeSet::new(),
        rebuilt_stages: program.executed.clone(),
        control_flow: control_flow_reuse_receipt(program, 0),
    }
}

fn control_flow_guidance_from_guide(
    guide: Option<&RecoveryGuide>,
) -> Option<ControlFlowRecoveryGuidance> {
    let guide = guide?;
    let mut non_instruction_ranges = Vec::new();
    let mut instruction_ranges = Vec::new();
    let mut suppressed_edges = BTreeSet::new();
    let mut suppressed_direct_calls = BTreeSet::new();
    for decision in &guide.decisions {
        match (&decision.point.subject, &decision.choice) {
            (
                ProgramSubjectKey::ExecutableByteRange {
                    start,
                    end_exclusive,
                    ..
                },
                RecoveryChoice::ByteRole { role },
            ) => {
                if *role == ExecutableByteKind::Instruction {
                    instruction_ranges.push((*start, *end_exclusive));
                } else {
                    non_instruction_ranges.push((*start, *end_exclusive));
                }
            }
            (
                ProgramSubjectKey::ControlFlowEdge {
                    function_entry,
                    source,
                    target,
                    edge_kind,
                },
                RecoveryChoice::SuppressControlFlowEdge,
            ) => {
                suppressed_edges.insert((*function_entry, *source, *target, *edge_kind));
            }
            (
                ProgramSubjectKey::DirectCallsite {
                    caller,
                    instruction_address,
                    target_address,
                },
                RecoveryChoice::SuppressDirectCall,
            ) => {
                suppressed_direct_calls.insert((*caller, *instruction_address, *target_address));
            }
            _ => {}
        }
    }
    non_instruction_ranges.sort_unstable();
    instruction_ranges.sort_unstable();
    (!non_instruction_ranges.is_empty()
        || !instruction_ranges.is_empty()
        || !suppressed_edges.is_empty()
        || !suppressed_direct_calls.is_empty())
    .then_some(ControlFlowRecoveryGuidance {
        image: guide.image.clone(),
        non_instruction_ranges,
        instruction_ranges,
        suppressed_edges,
        suppressed_direct_calls,
    })
}

#[allow(clippy::too_many_arguments)]
fn recover_control_flow_stage(
    macho: &MachoFile<'_>,
    functions: &FunctionIndex,
    pointers: Option<&PointerIndex>,
    exceptions: Option<&ExceptionIndex>,
    limits: crate::analysis::control_flow::ControlFlowLimits,
    guidance: Option<&ControlFlowRecoveryGuidance>,
    reuse: Option<&ProgramRecoveryReuse<'_>>,
) -> Result<(ControlFlowIndex, u64), ControlFlowRecoveryError> {
    // Pointer and exception equality is the stage-level fast gate. The fold
    // independently validates every durable input and compares normalized
    // prior/current guidance before admitting each retained function graph.
    if let Some(reuse) = reuse
        && reuse.prior.pointers.as_ref() == pointers
        && reuse.prior.exceptions.as_ref() == exceptions
        && let (Some(prior_functions), Some(prior_control_flow)) = (
            reuse.prior.functions.as_ref(),
            reuse.prior.control_flow.as_ref(),
        )
    {
        return ControlFlowIndex::recover_reusing(
            macho,
            functions,
            pointers,
            exceptions,
            limits,
            guidance,
            crate::analysis::control_flow::ControlFlowReuse {
                functions: prior_functions,
                control_flow: prior_control_flow,
                pointers: reuse.prior.pointers.as_ref(),
                exceptions: reuse.prior.exceptions.as_ref(),
                guidance: reuse.control_flow_guidance.as_ref(),
            },
        );
    }
    let control_flow = match guidance {
        Some(guidance) => ControlFlowIndex::recover_with_guidance(
            macho, functions, pointers, exceptions, limits, guidance,
        ),
        None => {
            ControlFlowIndex::recover_with_evidence(macho, functions, pointers, exceptions, limits)
        }
    }?;
    Ok((control_flow, 0))
}

fn dependent_stage_closure(
    roots: impl IntoIterator<Item = ProgramRecoveryStage>,
    executed: &BTreeSet<ProgramRecoveryStage>,
) -> BTreeSet<ProgramRecoveryStage> {
    let mut dirty = roots.into_iter().collect::<BTreeSet<_>>();
    loop {
        let prior_len = dirty.len();
        for stage in executed {
            let declared_input_is_dirty = stage
                .dependencies()
                .iter()
                .any(|dependency| dirty.contains(dependency));
            // Symbols are optional function evidence rather than a mandatory
            // request dependency. When both stages are selected, however, the
            // function inventory consumes that symbol payload and must be
            // invalidated if it changes or is newly added.
            let optional_input_is_dirty = *stage == ProgramRecoveryStage::Functions
                && executed.contains(&ProgramRecoveryStage::Symbols)
                && dirty.contains(&ProgramRecoveryStage::Symbols);
            if declared_input_is_dirty || optional_input_is_dirty {
                dirty.insert(*stage);
            }
        }
        if dirty.len() == prior_len {
            return dirty;
        }
    }
}

fn stage_limits_equal(
    stage: ProgramRecoveryStage,
    left: ProgramRecoveryLimits,
    right: ProgramRecoveryLimits,
) -> bool {
    match stage {
        ProgramRecoveryStage::ImageLayout => left.image_layout == right.image_layout,
        ProgramRecoveryStage::Pointers => left.pointers == right.pointers,
        ProgramRecoveryStage::Symbols => left.symbols == right.symbols,
        ProgramRecoveryStage::Strings => left.strings == right.strings,
        ProgramRecoveryStage::Objc => left.objc == right.objc,
        ProgramRecoveryStage::Swift => left.swift == right.swift,
        ProgramRecoveryStage::Dwarf => left.dwarf == right.dwarf,
        ProgramRecoveryStage::Functions => left.functions == right.functions,
        ProgramRecoveryStage::ControlFlow => left.control_flow == right.control_flow,
        ProgramRecoveryStage::ExecutableBytes => left.executable_bytes == right.executable_bytes,
        ProgramRecoveryStage::DirectCalls => left.direct_calls == right.direct_calls,
        ProgramRecoveryStage::Transfers => left.transfers == right.transfers,
        ProgramRecoveryStage::IndirectCalls => left.indirect_calls == right.indirect_calls,
        ProgramRecoveryStage::Xrefs => left.xrefs == right.xrefs,
        ProgramRecoveryStage::Rtti => left.rtti == right.rtti,
        ProgramRecoveryStage::Exceptions => left.exceptions == right.exceptions,
        ProgramRecoveryStage::Dependencies => left.dependencies == right.dependencies,
        ProgramRecoveryStage::Semantics => left.semantics == right.semantics,
    }
}

impl RecoveryPreview {
    /// Unguided base view.
    pub const fn base(&self) -> &RecoveredProgram {
        &self.base
    }

    /// Guided counterfactual view.
    pub const fn guided(&self) -> &RecoveredProgram {
        &self.guided
    }

    /// Exact application, graph-delta, coverage-delta, and provenance receipt.
    /// An empty or wholly redundant guide preserves byte-for-byte base equality
    /// and therefore has no separate receipt.
    pub const fn application(&self) -> Option<&RecoveryGuideApplication> {
        self.guided.guide_application.as_ref()
    }

    /// Consume the preview and retain the guided view.
    pub fn into_program(self) -> RecoveredProgram {
        self.guided
    }
}

impl RecoveredProgram {
    /// Recover exactly the selected modules and their declared dependencies.
    pub fn recover(
        macho: &MachoFile<'_>,
        request: ProgramRecoveryRequest,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::recover_selected(macho, None, request, ProgramRecoveryGuidance::default())
    }

    /// Convenience entry point selecting every recovery module.
    pub fn recover_all(
        macho: &MachoFile<'_>,
        limits: ProgramRecoveryLimits,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::recover(macho, ProgramRecoveryRequest::all(limits))
    }

    /// Produce an immutable next program state by applying a guide to a prior
    /// state under the same request and limits.
    ///
    /// The live image must match the prior state's content hash, architecture,
    /// and byte length. The returned state always carries a guide-application
    /// receipt, including for redundant or empty guides.
    pub fn refine(
        macho: &MachoFile<'_>,
        prior: &Self,
        guide: &RecoveryGuide,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::refine_with_reuse_receipt(macho, prior, guide)
            .map(ProgramRecoveryTransition::into_program)
    }

    /// Produce an immutable guided state and report exact reuse from `prior`.
    ///
    /// The receipt is operational metadata: it is not stored in the returned
    /// program or projected into durable program Fact IR. The returned program
    /// is therefore byte-for-byte equivalent to an independent cold recovery.
    pub fn refine_with_reuse_receipt(
        macho: &MachoFile<'_>,
        prior: &Self,
        guide: &RecoveryGuide,
    ) -> Result<ProgramRecoveryTransition, ProgramRecoveryError> {
        if prior.image != FunctionImageIdentity::from_macho(macho) {
            return Err(ProgramRecoveryError::ProgramImageMismatch);
        }
        if prior.guide.as_ref() == Some(guide) && prior.guide_application.is_some() {
            return Ok(ProgramRecoveryTransition {
                program: prior.clone(),
                reuse_receipt: reuse_receipt_for_unchanged_program(prior),
            });
        }
        let base = match prior.guide {
            None => prior.clone(),
            Some(_) => Self::recover(macho, prior.request.clone())?,
        };
        let validation = base.validate_guide_for_image(macho, guide);
        let mut transition = Self::recover_guided_from_base_with_reuse(
            macho,
            prior.request.clone(),
            guide,
            &base,
            prior,
            true,
        )?;
        let next = &mut transition.program;
        if next.guide_application.is_none() {
            next.guide = Some(guide.clone());
            next.guide_application = Some(build_guide_application(&base, next, guide, validation));
        }
        Ok(transition)
    }

    /// Deepen a prior state by unioning additional requested stages and
    /// recomputing dependency closure. Passing limits replaces the complete
    /// nested limit set; `None` preserves the prior limits exactly.
    pub fn deepen(
        &self,
        macho: &MachoFile<'_>,
        extra_stages: impl IntoIterator<Item = ProgramRecoveryStage>,
        limit_overrides: Option<ProgramRecoveryLimits>,
    ) -> Result<Self, ProgramRecoveryError> {
        self.deepen_with_reuse_receipt(macho, extra_stages, limit_overrides)
            .map(ProgramRecoveryTransition::into_program)
    }

    /// Deepen this state and report whole-stage and function-local CFG reuse.
    ///
    /// The receipt describes only construction of the returned immutable
    /// state. It is intentionally excluded from that state's durable facts.
    pub fn deepen_with_reuse_receipt(
        &self,
        macho: &MachoFile<'_>,
        extra_stages: impl IntoIterator<Item = ProgramRecoveryStage>,
        limit_overrides: Option<ProgramRecoveryLimits>,
    ) -> Result<ProgramRecoveryTransition, ProgramRecoveryError> {
        if self.image != FunctionImageIdentity::from_macho(macho) {
            return Err(ProgramRecoveryError::ProgramImageMismatch);
        }
        let mut requested = self.request.requested.clone();
        requested.extend(extra_stages);
        let request =
            ProgramRecoveryRequest::new(requested, limit_overrides.unwrap_or(self.request.limits));
        match self.guide.as_ref() {
            Some(guide) => {
                let base = Self::recover(macho, request.clone())?;
                Self::recover_guided_from_base_with_reuse(macho, request, guide, &base, self, true)
            }
            None => {
                let executed = request.resolved();
                let mut roots = executed
                    .iter()
                    .copied()
                    .filter(|stage| {
                        !self.executed.contains(stage)
                            || !stage_limits_equal(*stage, self.request.limits, request.limits)
                    })
                    .collect::<BTreeSet<_>>();
                // The final function inventory is refined by a newly selected
                // CFG. Treat that feedback edge as dirty even though the
                // declared dependency direction is Functions -> ControlFlow.
                if roots.contains(&ProgramRecoveryStage::ControlFlow)
                    && self.executed.contains(&ProgramRecoveryStage::Functions)
                {
                    roots.insert(ProgramRecoveryStage::Functions);
                }
                let dirty = dependent_stage_closure(roots, &executed);
                Self::recover_selected_reusing(
                    macho,
                    None,
                    request,
                    ProgramRecoveryGuidance::default(),
                    Some(ProgramRecoveryReuse {
                        prior: self,
                        dirty,
                        control_flow_guidance: control_flow_guidance_from_guide(
                            self.guide.as_ref(),
                        ),
                    }),
                )
            }
        }
    }

    /// Convert this state to the current durable Fact IR document.
    pub fn to_fact_document(&self) -> ProgramFactDocument {
        ProgramFactDocument {
            schema_version: PROGRAM_FACT_IR_SCHEMA_VERSION,
            recovery_schema: self.recovery_schema,
            image: self.image.clone(),
            request: self.request.clone(),
            executed: self.executed.clone(),
            completeness: self.completeness.clone(),
            coverage: self.coverage(),
            guide: self.guide.clone(),
            guide_application: self.guide_application.clone(),
            questions: self.questions.clone(),
            program: RecoveredProgramBody {
                image_layout: self.image_layout.clone(),
                pointers: self.pointers.clone(),
                symbols: self.symbols.clone(),
                strings: self.strings.clone(),
                objc: self.objc.clone(),
                swift: self.swift.clone(),
                dwarf: self.dwarf.clone(),
                functions: self.functions.clone(),
                control_flow: self.control_flow.clone(),
                executable_bytes: self.executable_bytes.clone(),
                direct_calls: self.direct_calls.clone(),
                transfers: self.transfers.clone(),
                indirect_calls: self.indirect_calls.clone(),
                xrefs: self.xrefs.clone(),
                guided_reference_ownerships: self.guided_reference_ownerships.clone(),
                rtti: self.rtti.clone(),
                exceptions: self.exceptions.clone(),
                dependencies: self.dependencies.clone(),
                semantics: self.semantics.clone(),
            },
        }
    }

    /// Validate and load a durable Fact IR document for offline queries.
    pub fn from_document(
        document: ProgramFactDocument,
    ) -> Result<Self, ProgramFactValidationError> {
        document.validate()?;
        Ok(document.into_program_unchecked())
    }

    /// Compatibility spelling for [`Self::from_document`].
    pub fn from_fact_document(
        document: ProgramFactDocument,
    ) -> Result<Self, ProgramFactValidationError> {
        Self::from_document(document)
    }

    /// Validate a guide against an unguided base and rebuild every selected
    /// stage affected by its supported decisions. Unchanged stage payloads are
    /// reused only when their inputs and transitive dependencies are equal to
    /// the cold-recovery inputs.
    pub fn recover_with_guide(
        macho: &MachoFile<'_>,
        request: ProgramRecoveryRequest,
        guide: &RecoveryGuide,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::preview_guide(macho, request, guide).map(RecoveryPreview::into_program)
    }

    /// Build an immutable unguided/guided counterfactual pair without changing
    /// either view or any external state.
    pub fn preview_guide(
        macho: &MachoFile<'_>,
        request: ProgramRecoveryRequest,
        guide: &RecoveryGuide,
    ) -> Result<RecoveryPreview, ProgramRecoveryError> {
        let base = Self::recover(macho, request.clone())?;
        let guided = Self::recover_guided_from_base(macho, request, guide, &base)?;
        Ok(RecoveryPreview { base, guided })
    }

    fn recover_guided_from_base(
        macho: &MachoFile<'_>,
        request: ProgramRecoveryRequest,
        guide: &RecoveryGuide,
        base: &RecoveredProgram,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::recover_guided_from_base_with_reuse(macho, request, guide, base, base, true)
            .map(ProgramRecoveryTransition::into_program)
    }

    fn recover_guided_from_base_with_reuse(
        macho: &MachoFile<'_>,
        request: ProgramRecoveryRequest,
        guide: &RecoveryGuide,
        base: &RecoveredProgram,
        reuse_prior: &RecoveredProgram,
        reuse_unchanged_stages: bool,
    ) -> Result<ProgramRecoveryTransition, ProgramRecoveryError> {
        let mut validation = base.validate_guide_for_image(macho, guide);
        if validation.decisions.iter().any(|decision| {
            matches!(
                decision.applicability,
                RecoveryDecisionApplicability::Stale
                    | RecoveryDecisionApplicability::Conflicting
                    | RecoveryDecisionApplicability::Unsupported
            )
        }) {
            return Err(ProgramRecoveryError::GuideValidationFailed { validation });
        }

        let mut function_guidance = FunctionRecoveryGuidance::new(base.image.clone());
        let mut byte_roles = Vec::new();
        let mut suppressed_edges = BTreeSet::new();
        let mut suppressed_direct_calls = BTreeSet::new();
        let mut guided_reference_ownerships = Vec::new();
        let mut dirty_roots = BTreeSet::new();
        for (index, decision) in guide.decisions.iter().enumerate() {
            if validation.decisions[index].applicability == RecoveryDecisionApplicability::Redundant
            {
                continue;
            }
            match (&decision.point.subject, &decision.choice) {
                (_, RecoveryChoice::KeepUnresolved) => {}
                (
                    ProgramSubjectKey::FunctionCandidate { address },
                    RecoveryChoice::AcceptFunctionEntry,
                ) => {
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    function_guidance.accepted_entries.insert(*address);
                }
                (ProgramSubjectKey::FunctionCandidate { address }, RecoveryChoice::Reject) => {
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    function_guidance.rejected_entries.insert(*address);
                }
                (
                    ProgramSubjectKey::FunctionCandidate { address },
                    RecoveryChoice::FunctionRelationship {
                        owner_entry,
                        relationship,
                    },
                ) => {
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    let kind = function_relationship_kind(*relationship);
                    function_guidance
                        .relationships
                        .insert(*address, (*owner_entry, kind));
                }
                (
                    ProgramSubjectKey::Function { entry },
                    RecoveryChoice::FunctionRanges { ranges },
                ) => {
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    function_guidance.ranges.insert(
                        *entry,
                        ranges
                            .iter()
                            .map(|range| (range.start, range.end_exclusive))
                            .collect(),
                    );
                }
                (
                    ProgramSubjectKey::ExecutableByteRange {
                        section_ordinal,
                        start,
                        end_exclusive,
                    },
                    RecoveryChoice::ByteRole { role },
                ) => {
                    // Byte guidance can suppress code recovery and always
                    // changes the final CFG/byte ledger, so Functions is the
                    // conservative root of the cyclic refinement pair.
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    byte_roles.push(GuidedExecutableByteRole {
                        section_ordinal: *section_ordinal,
                        start: *start,
                        end_exclusive: *end_exclusive,
                        kind: *role,
                    });
                    if matches!(
                        role,
                        ExecutableByteKind::EmbeddedData
                            | ExecutableByteKind::Padding
                            | ExecutableByteKind::Alignment
                            | ExecutableByteKind::Stub
                            | ExecutableByteKind::LiteralPool
                    ) {
                        function_guidance
                            .suppressed_code_ranges
                            .push((*start, *end_exclusive));
                    }
                }
                (
                    ProgramSubjectKey::ControlFlowEdge {
                        function_entry,
                        source,
                        target,
                        edge_kind,
                    },
                    RecoveryChoice::SuppressControlFlowEdge,
                ) => {
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    suppressed_edges.insert((*function_entry, *source, *target, *edge_kind));
                }
                (
                    ProgramSubjectKey::DirectCallsite {
                        caller,
                        instruction_address,
                        target_address,
                    },
                    RecoveryChoice::SuppressDirectCall,
                ) => {
                    dirty_roots.insert(ProgramRecoveryStage::Functions);
                    suppressed_direct_calls.insert((
                        *caller,
                        *instruction_address,
                        *target_address,
                    ));
                    function_guidance
                        .suppressed_direct_calls
                        .insert((*instruction_address, *target_address));
                }
                (
                    ProgramSubjectKey::CrossReference {
                        source,
                        target,
                        reference_kind,
                    },
                    RecoveryChoice::ReferenceOwner { function_entry },
                ) => guided_reference_ownerships.push(GuidedReferenceOwnership {
                    source: *source,
                    target: target.clone(),
                    reference_kind: *reference_kind,
                    function_entry: *function_entry,
                }),
                _ => {
                    validation.decisions[index].applicability =
                        RecoveryDecisionApplicability::Unsupported;
                    validation.decisions[index].reason =
                        "recovery_guide.unsupported_application".to_owned();
                    summarize_guide_validation(&mut validation);
                    return Err(ProgramRecoveryError::GuideValidationFailed { validation });
                }
            }
        }
        if function_guidance.accepted_entries.is_empty()
            && function_guidance.rejected_entries.is_empty()
            && function_guidance.relationships.is_empty()
            && function_guidance.ranges.is_empty()
            && byte_roles.is_empty()
            && suppressed_edges.is_empty()
            && suppressed_direct_calls.is_empty()
            && guided_reference_ownerships.is_empty()
        {
            let reuse_receipt = if reuse_unchanged_stages && base == reuse_prior {
                reuse_receipt_for_unchanged_program(base)
            } else {
                reuse_receipt_for_rebuilt_program(base)
            };
            return Ok(ProgramRecoveryTransition {
                program: base.clone(),
                reuse_receipt,
            });
        }

        let byte_guidance = ExecutableByteRecoveryGuidance {
            image: base.image.clone(),
            roles: byte_roles,
        };
        let control_flow_guidance = ControlFlowRecoveryGuidance {
            image: base.image.clone(),
            non_instruction_ranges: byte_guidance
                .roles
                .iter()
                .filter(|role| role.kind != ExecutableByteKind::Instruction)
                .map(|role| (role.start, role.end_exclusive))
                .collect(),
            instruction_ranges: byte_guidance
                .roles
                .iter()
                .filter(|role| role.kind == ExecutableByteKind::Instruction)
                .map(|role| (role.start, role.end_exclusive))
                .collect(),
            suppressed_edges,
            suppressed_direct_calls,
        };
        let executed = request.resolved();
        let dirty = dependent_stage_closure(dirty_roots, &executed);
        let reuse = reuse_unchanged_stages.then_some(ProgramRecoveryReuse {
            prior: reuse_prior,
            dirty: if base == reuse_prior {
                dirty
            } else {
                // A replacement guide can remove any prior premise. Rebuild
                // every whole stage while still admitting function-local CFG
                // entries whose exact normalized inputs remain unchanged.
                executed.clone()
            },
            control_flow_guidance: control_flow_guidance_from_guide(reuse_prior.guide.as_ref()),
        });
        let mut transition = Self::recover_selected_reusing(
            macho,
            None,
            request,
            ProgramRecoveryGuidance {
                functions: Some(&function_guidance),
                executable_bytes: Some(&byte_guidance),
                control_flow: Some(&control_flow_guidance),
                guide: Some(guide.clone()),
                reference_ownerships: guided_reference_ownerships,
            },
            reuse,
        )?;
        let guided = &mut transition.program;
        guided.guide_application = Some(build_guide_application(base, guided, guide, validation));
        Ok(transition)
    }

    /// Convenience entry point applying a guide while selecting every recovery stage.
    pub fn recover_all_with_guide(
        macho: &MachoFile<'_>,
        limits: ProgramRecoveryLimits,
        guide: &RecoveryGuide,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::recover_with_guide(macho, ProgramRecoveryRequest::all(limits), guide)
    }

    /// Recover selected modules while reusing an authoritative function inventory.
    pub fn recover_from_functions(
        macho: &MachoFile<'_>,
        functions: FunctionIndex,
        request: ProgramRecoveryRequest,
    ) -> Result<Self, ProgramRecoveryError> {
        if functions.limits() != request.limits.functions {
            return Err(ProgramRecoveryError::FunctionLimitsMismatch);
        }
        if functions.image() != &FunctionImageIdentity::from_macho(macho) {
            return Err(ProgramRecoveryError::FunctionImageMismatch);
        }
        Self::recover_selected(
            macho,
            Some(functions),
            request,
            ProgramRecoveryGuidance::default(),
        )
    }

    /// Convenience entry point selecting every module while reusing functions.
    pub fn recover_all_from_functions(
        macho: &MachoFile<'_>,
        functions: FunctionIndex,
        limits: ProgramRecoveryLimits,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::recover_from_functions(macho, functions, ProgramRecoveryRequest::all(limits))
    }

    fn recover_selected(
        macho: &MachoFile<'_>,
        supplied_functions: Option<FunctionIndex>,
        request: ProgramRecoveryRequest,
        guidance: ProgramRecoveryGuidance<'_>,
    ) -> Result<Self, ProgramRecoveryError> {
        Self::recover_selected_reusing(macho, supplied_functions, request, guidance, None)
            .map(ProgramRecoveryTransition::into_program)
    }

    fn recover_selected_reusing(
        macho: &MachoFile<'_>,
        supplied_functions: Option<FunctionIndex>,
        request: ProgramRecoveryRequest,
        guidance: ProgramRecoveryGuidance<'_>,
        reuse: Option<ProgramRecoveryReuse<'_>>,
    ) -> Result<ProgramRecoveryTransition, ProgramRecoveryError> {
        let ProgramRecoveryGuidance {
            functions: function_guidance,
            executable_bytes: byte_guidance,
            control_flow: control_flow_guidance,
            guide,
            reference_ownerships: mut guided_reference_ownerships,
        } = guidance;
        let limits = request.limits;
        let executed = request.resolved();
        debug_assert!(reuse.as_ref().is_none_or(|reuse| {
            reuse.prior.image == FunctionImageIdentity::from_macho(macho)
                && ProgramRecoveryStage::all().iter().all(|stage| {
                    !reuse.can_reuse(*stage)
                        || stage_limits_equal(*stage, reuse.prior.request.limits, request.limits)
                })
        }));
        let can_reuse = |stage| reuse.as_ref().is_some_and(|reuse| reuse.can_reuse(stage));
        let reused_stages = executed
            .iter()
            .copied()
            .filter(|stage| can_reuse(*stage))
            .collect::<BTreeSet<_>>();
        let rebuilt_stages = executed
            .difference(&reused_stages)
            .copied()
            .collect::<BTreeSet<_>>();
        let recovers_function_inventory = executed.contains(&ProgramRecoveryStage::Functions)
            && !can_reuse(ProgramRecoveryStage::Functions)
            && supplied_functions.is_none();
        let uses_leaf_evidence = [
            ProgramRecoveryStage::Pointers,
            ProgramRecoveryStage::Objc,
            ProgramRecoveryStage::Swift,
            ProgramRecoveryStage::Rtti,
        ]
        .iter()
        .any(|stage| executed.contains(stage) && !can_reuse(*stage));
        let evidence = (uses_leaf_evidence || recovers_function_inventory)
            .then(|| crate::evidence::SelectedImageEvidence::new(macho))
            .transpose()
            .map_err(|error| ProgramRecoveryError::Evidence(error.to_string()))?;
        let function_starts = recovers_function_inventory.then(|| {
            evidence
                .as_ref()
                .expect("function recovery opened evidence")
                .function_starts(limits.functions.max_evidence_per_source as u64)
                .map_err(|error| error.to_string())
        });
        let image_layout = if can_reuse(ProgramRecoveryStage::ImageLayout) {
            reuse.as_ref().unwrap().prior.image_layout.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::ImageLayout)
                .then(|| ImageLayoutIndex::recover(macho, limits.image_layout))
                .transpose()?
        };
        let pointers = if can_reuse(ProgramRecoveryStage::Pointers) {
            reuse.as_ref().unwrap().prior.pointers.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Pointers)
                .then(|| {
                    PointerIndex::recover_with_evidence(
                        evidence.as_ref().expect("pointer stage opened evidence"),
                        limits.pointers,
                    )
                })
                .transpose()?
        };
        let symbols = if can_reuse(ProgramRecoveryStage::Symbols) {
            reuse.as_ref().unwrap().prior.symbols.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Symbols)
                .then(|| SymbolInventory::recover(macho, limits.symbols))
                .transpose()?
        };
        let dependencies = if can_reuse(ProgramRecoveryStage::Dependencies) {
            reuse.as_ref().unwrap().prior.dependencies.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Dependencies)
                .then(|| DependencyIndex::recover(macho, symbols.as_ref(), limits.dependencies))
                .transpose()?
        };
        let strings = if can_reuse(ProgramRecoveryStage::Strings) {
            reuse.as_ref().unwrap().prior.strings.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Strings)
                .then(|| StringIndex::recover(macho, limits.strings))
                .transpose()?
        };
        let objc = if can_reuse(ProgramRecoveryStage::Objc) {
            reuse.as_ref().unwrap().prior.objc.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Objc)
                .then(|| {
                    ObjcIndex::recover_with_evidence(
                        evidence
                            .as_ref()
                            .expect("Objective-C stage opened evidence"),
                        limits.objc,
                    )
                })
                .transpose()?
        };
        let swift = if can_reuse(ProgramRecoveryStage::Swift) {
            reuse.as_ref().unwrap().prior.swift.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Swift)
                .then(|| {
                    SwiftIndex::recover_with_evidence(
                        evidence.as_ref().expect("Swift stage opened evidence"),
                        limits.swift,
                    )
                })
                .transpose()?
        };
        let dwarf = if can_reuse(ProgramRecoveryStage::Dwarf) {
            reuse.as_ref().unwrap().prior.dwarf.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Dwarf)
                .then(|| DwarfIndex::recover(macho, limits.dwarf))
                .transpose()?
        };
        let rtti = if can_reuse(ProgramRecoveryStage::Rtti) {
            reuse.as_ref().unwrap().prior.rtti.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Rtti)
                .then(|| {
                    RttiIndex::recover_with_evidence(
                        evidence.as_ref().expect("RTTI stage opened evidence"),
                        limits.rtti,
                    )
                })
                .transpose()?
        };
        let exceptions = if can_reuse(ProgramRecoveryStage::Exceptions) {
            reuse.as_ref().unwrap().prior.exceptions.clone()
        } else {
            executed
                .contains(&ProgramRecoveryStage::Exceptions)
                .then(|| ExceptionIndex::recover(macho, limits.exceptions))
                .transpose()?
        };
        let mut functions = if executed.contains(&ProgramRecoveryStage::Functions) {
            if can_reuse(ProgramRecoveryStage::Functions) {
                reuse.as_ref().unwrap().prior.functions.clone()
            } else {
                Some(match supplied_functions {
                    Some(functions) => functions,
                    None => FunctionIndex::recover_with_inputs(
                        macho,
                        limits.functions,
                        FunctionRecoveryInputs {
                            function_starts: function_starts.as_ref(),
                            pointers: pointers.as_ref(),
                            symbols: symbols.as_ref(),
                            dwarf: dwarf.as_ref(),
                            objc: objc.as_ref(),
                            swift: swift.as_ref(),
                            exceptions: exceptions.as_ref(),
                            guidance: function_guidance,
                        },
                    )?,
                })
            }
        } else {
            None
        };
        let mut control_flow_reused_function_count = 0_u64;
        let mut control_flow = if executed.contains(&ProgramRecoveryStage::ControlFlow) {
            if can_reuse(ProgramRecoveryStage::ControlFlow) {
                let retained = reuse.as_ref().unwrap().prior.control_flow.clone();
                control_flow_reused_function_count = retained.as_ref().map_or(0, |control_flow| {
                    u64::try_from(control_flow.functions().len()).unwrap_or(u64::MAX)
                });
                retained
            } else {
                let functions = functions
                    .as_ref()
                    .expect("resolved control-flow dependency includes functions");
                let (recovered, reused_functions) = recover_control_flow_stage(
                    macho,
                    functions,
                    pointers.as_ref(),
                    exceptions.as_ref(),
                    limits.control_flow,
                    control_flow_guidance,
                    reuse.as_ref(),
                )?;
                control_flow_reused_function_count = reused_functions;
                Some(recovered)
            }
        } else {
            None
        };
        if functions.is_some() && control_flow.is_some() {
            let refined = functions
                .as_ref()
                .expect("checked function inventory")
                .refine_extents_from_control_flow(
                    control_flow
                        .as_ref()
                        .expect("checked provisional control flow"),
                )?;
            if Some(&refined) != functions.as_ref() {
                // Refinement changes the function inventory consumed by the final
                // graph, so the provisional graph cannot be reused. Release both
                // superseded retained structures before rebuilding instead of
                // holding two complete CFGs and two function inventories at the
                // construction peak.
                drop(control_flow.take());
                functions = Some(refined);
                let refined = functions
                    .as_ref()
                    .expect("refined function inventory was just installed");
                let (rebuilt, reused_functions) = recover_control_flow_stage(
                    macho,
                    refined,
                    pointers.as_ref(),
                    exceptions.as_ref(),
                    limits.control_flow,
                    control_flow_guidance,
                    reuse.as_ref(),
                )?;
                control_flow_reused_function_count = reused_functions;
                control_flow = Some(rebuilt);
            }
        }
        let executable_bytes = if executed.contains(&ProgramRecoveryStage::ExecutableBytes) {
            if can_reuse(ProgramRecoveryStage::ExecutableBytes) {
                reuse.as_ref().unwrap().prior.executable_bytes.clone()
            } else {
                let functions = functions
                    .as_ref()
                    .expect("resolved executable-byte dependency includes functions");
                let control_flow = control_flow
                    .as_ref()
                    .expect("resolved executable-byte dependency includes control flow");
                Some(match byte_guidance {
                    Some(guidance) => ExecutableByteIndex::recover_with_guidance(
                        macho,
                        functions,
                        control_flow,
                        limits.executable_bytes,
                        guidance,
                    )?,
                    None => ExecutableByteIndex::recover(
                        macho,
                        functions,
                        control_flow,
                        limits.executable_bytes,
                    )?,
                })
            }
        } else {
            None
        };
        let direct_calls = if executed.contains(&ProgramRecoveryStage::DirectCalls) {
            if can_reuse(ProgramRecoveryStage::DirectCalls) {
                reuse.as_ref().unwrap().prior.direct_calls.clone()
            } else {
                Some(DirectCallGraph::build(
                    functions
                        .as_ref()
                        .expect("resolved direct-call dependency includes functions"),
                    control_flow
                        .as_ref()
                        .expect("resolved direct-call dependency includes control flow"),
                    limits.direct_calls,
                )?)
            }
        } else {
            None
        };
        let transfers = if executed.contains(&ProgramRecoveryStage::Transfers) {
            if can_reuse(ProgramRecoveryStage::Transfers) {
                reuse.as_ref().unwrap().prior.transfers.clone()
            } else {
                Some(DirectTransferIndex::recover(
                    functions
                        .as_ref()
                        .expect("resolved transfer dependency includes functions"),
                    control_flow
                        .as_ref()
                        .expect("resolved transfer dependency includes control flow"),
                    limits.transfers,
                )?)
            }
        } else {
            None
        };
        let indirect_calls = if executed.contains(&ProgramRecoveryStage::IndirectCalls) {
            if can_reuse(ProgramRecoveryStage::IndirectCalls) {
                reuse.as_ref().unwrap().prior.indirect_calls.clone()
            } else {
                Some(IndirectCallIndex::recover_with_evidence(
                    macho,
                    functions
                        .as_ref()
                        .expect("resolved indirect-call dependency includes functions"),
                    control_flow
                        .as_ref()
                        .expect("resolved indirect-call dependency includes control flow"),
                    IndirectCallRecoveryInputs {
                        pointers: pointers
                            .as_ref()
                            .expect("resolved indirect-call dependency includes pointers"),
                        rtti: rtti
                            .as_ref()
                            .expect("resolved indirect-call dependency includes RTTI"),
                        objc: objc
                            .as_ref()
                            .expect("resolved indirect-call dependency includes Objective-C"),
                        swift: swift
                            .as_ref()
                            .expect("resolved indirect-call dependency includes Swift"),
                    },
                    limits.indirect_calls,
                )?)
            }
        } else {
            None
        };
        let xrefs = if executed.contains(&ProgramRecoveryStage::Xrefs) {
            if can_reuse(ProgramRecoveryStage::Xrefs) {
                reuse.as_ref().unwrap().prior.xrefs.clone()
            } else {
                Some(
                    XrefIndex::recover_with_pointers(
                        macho,
                        control_flow
                            .as_ref()
                            .expect("resolved xref dependency includes control flow"),
                        pointers
                            .as_ref()
                            .expect("resolved xref dependency includes pointers"),
                        limits.xrefs,
                    )
                    .map_err(|error| ProgramRecoveryError::Xrefs(error.to_string()))?,
                )
            }
        } else {
            None
        };
        let semantics = if executed.contains(&ProgramRecoveryStage::Semantics) {
            if can_reuse(ProgramRecoveryStage::Semantics) {
                reuse.as_ref().unwrap().prior.semantics.clone()
            } else {
                Some(SemanticIndex::recover(
                    SemanticRecoveryInputs {
                        image_layout: image_layout
                            .as_ref()
                            .expect("resolved semantic dependency includes image layout"),
                        pointers: pointers
                            .as_ref()
                            .expect("resolved semantic dependency includes pointers"),
                        symbols: symbols
                            .as_ref()
                            .expect("resolved semantic dependency includes symbols"),
                        strings: strings
                            .as_ref()
                            .expect("resolved semantic dependency includes strings"),
                        objc: objc
                            .as_ref()
                            .expect("resolved semantic dependency includes Objective-C"),
                        swift: swift
                            .as_ref()
                            .expect("resolved semantic dependency includes Swift"),
                        rtti: rtti
                            .as_ref()
                            .expect("resolved semantic dependency includes RTTI"),
                        dwarf: dwarf
                            .as_ref()
                            .expect("resolved semantic dependency includes DWARF"),
                        exceptions: exceptions
                            .as_ref()
                            .expect("resolved semantic dependency includes exceptions"),
                        functions: functions
                            .as_ref()
                            .expect("resolved semantic dependency includes functions"),
                    },
                    limits.semantics,
                )?)
            }
        } else {
            None
        };
        guided_reference_ownerships.sort();
        guided_reference_ownerships.dedup();
        let image = FunctionImageIdentity::from_macho(macho);
        let questions = build_recovery_questions(
            &image,
            functions.as_ref(),
            control_flow.as_ref(),
            executable_bytes.as_ref(),
            xrefs.as_ref(),
            indirect_calls.as_ref(),
            &guided_reference_ownerships,
        );
        let completeness = program_completeness(
            &image,
            &request,
            ProgramFacts {
                image_layout: image_layout.as_ref(),
                pointers: pointers.as_ref(),
                symbols: symbols.as_ref(),
                strings: strings.as_ref(),
                objc: objc.as_ref(),
                swift: swift.as_ref(),
                dwarf: dwarf.as_ref(),
                functions: functions.as_ref(),
                control_flow: control_flow.as_ref(),
                executable_bytes: executable_bytes.as_ref(),
                direct_calls: direct_calls.as_ref(),
                transfers: transfers.as_ref(),
                indirect_calls: indirect_calls.as_ref(),
                xrefs: xrefs.as_ref(),
                guided_reference_ownerships: &guided_reference_ownerships,
                rtti: rtti.as_ref(),
                exceptions: exceptions.as_ref(),
                dependencies: dependencies.as_ref(),
                semantics: semantics.as_ref(),
            },
        );
        completeness.validate()?;
        let program = Self {
            image,
            recovery_schema: RecoveryContractSchema::CURRENT,
            request,
            executed,
            image_layout,
            pointers,
            symbols,
            strings,
            objc,
            swift,
            dwarf,
            functions,
            control_flow,
            executable_bytes,
            direct_calls,
            transfers,
            indirect_calls,
            xrefs,
            guided_reference_ownerships,
            rtti,
            exceptions,
            dependencies,
            semantics,
            questions,
            guide,
            guide_application: None,
            completeness,
        };
        let reuse_receipt = ProgramRecoveryReuseReceipt {
            schema_version: PROGRAM_RECOVERY_REUSE_RECEIPT_VERSION,
            reused_stages,
            rebuilt_stages,
            control_flow: control_flow_reuse_receipt(&program, control_flow_reused_function_count),
        };
        Ok(ProgramRecoveryTransition {
            program,
            reuse_receipt,
        })
    }

    /// Exact content and architecture identity shared by every stage.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Version of stable recovery identities, questions, and guide validation.
    pub const fn recovery_schema(&self) -> RecoveryContractSchema {
        self.recovery_schema
    }

    /// Selective request used to construct this program.
    pub fn request(&self) -> &ProgramRecoveryRequest {
        &self.request
    }

    /// Exact nested limits supplied by the caller.
    pub const fn limits(&self) -> ProgramRecoveryLimits {
        self.request.limits
    }

    /// Requested stages plus their deterministic dependency closure.
    pub fn executed_stages(&self) -> &BTreeSet<ProgramRecoveryStage> {
        &self.executed
    }

    /// Availability and completion for one stage without guessing from an
    /// optional payload.
    pub fn stage_status(&self, stage: ProgramRecoveryStage) -> ProgramStageStatus {
        self.completeness
            .stages
            .iter()
            .find(|receipt| receipt.stage == stage)
            .map_or(ProgramStageStatus::Absent, |receipt| match receipt.status {
                ProgramRecoveryStatus::Complete => ProgramStageStatus::Complete,
                ProgramRecoveryStatus::Partial => ProgramStageStatus::Partial,
                ProgramRecoveryStatus::Truncated => ProgramStageStatus::Truncated,
            })
    }

    /// Unified completion ledger.
    pub fn completeness(&self) -> &ProgramRecoveryCompleteness {
        &self.completeness
    }

    /// Truth-aware multi-dimensional coverage for this exact program view.
    pub fn coverage(&self) -> ProgramCoverage {
        build_program_coverage(self)
    }

    /// Stable ambiguities where caller knowledge could materially change recovery.
    pub fn questions(&self) -> &[RecoveryQuestion] {
        &self.questions
    }

    /// Authority of a retained structural subject in the current state.
    ///
    /// Subjects causally attributed to an applied guide decision are guided;
    /// all other retained subjects remain independent. Returns `None` when the
    /// subject is not present in the current facts, questions, or frontiers, so
    /// absence cannot be mistaken for independent authority. Function subjects
    /// also honor the authority retained directly by function recovery.
    pub fn subject_authority(&self, subject: &ProgramSubjectKey) -> Option<ProgramFactAuthority> {
        if !self.contains_subject(subject) {
            return None;
        }
        if let ProgramSubjectKey::Function { entry } = subject
            && self
                .functions
                .as_ref()
                .and_then(|functions| functions.by_entry(*entry))
                .is_some_and(|function| {
                    function.authority
                        == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
                })
        {
            return Some(ProgramFactAuthority::Guided);
        }
        if matches!(subject, ProgramSubjectKey::ReferenceOwnership { .. }) {
            return Some(ProgramFactAuthority::Guided);
        }
        if self.guide_application.as_ref().is_some_and(|application| {
            application
                .delta
                .records
                .iter()
                .any(|record| &record.subject == subject && !record.derivations.is_empty())
        }) {
            Some(ProgramFactAuthority::Guided)
        } else {
            Some(ProgramFactAuthority::Independent)
        }
    }

    fn contains_subject(&self, subject: &ProgramSubjectKey) -> bool {
        if self
            .questions
            .iter()
            .any(|question| &question.subject == subject)
        {
            return true;
        }
        match subject {
            ProgramSubjectKey::Function { entry } => self
                .functions
                .as_ref()
                .and_then(|functions| functions.by_entry(*entry))
                .is_some(),
            ProgramSubjectKey::FunctionCandidate { address } => {
                self.functions.as_ref().is_some_and(|functions| {
                    functions
                        .entry_candidates()
                        .iter()
                        .any(|candidate| candidate.address == *address)
                })
            }
            ProgramSubjectKey::FunctionRelationship {
                address,
                owner_entry,
            } => self.functions.as_ref().is_some_and(|functions| {
                functions.relationships().iter().any(|relationship| {
                    relationship.address == *address && relationship.owner_entry == *owner_entry
                })
            }),
            ProgramSubjectKey::SuppressedFunctionEntry {
                entry,
                range_start,
                range_end_exclusive,
            } => self.functions.as_ref().is_some_and(|functions| {
                functions.suppressed_entries().iter().any(|suppressed| {
                    suppressed.entry == *entry
                        && suppressed.range_start == *range_start
                        && suppressed.range_end_exclusive == *range_end_exclusive
                })
            }),
            ProgramSubjectKey::FunctionRange {
                function_entry,
                start,
                end_exclusive,
            } => {
                self.functions
                    .as_ref()
                    .and_then(|functions| functions.by_entry(*function_entry))
                    .is_some_and(|function| {
                        function.extent.is_some_and(|extent| {
                            extent.start == *start && extent.end_exclusive == *end_exclusive
                        }) || function.caller_guided_ranges.iter().any(|range| {
                            range.start == *start && range.end_exclusive == *end_exclusive
                        })
                    })
            }
            ProgramSubjectKey::BasicBlock {
                function_entry,
                start,
            } => self
                .control_flow
                .as_ref()
                .and_then(|control_flow| control_flow.by_entry(*function_entry))
                .is_some_and(|graph| graph.blocks.iter().any(|block| block.start == *start)),
            ProgramSubjectKey::Instruction { address, byte_len } => {
                self.control_flow.as_ref().is_some_and(|control_flow| {
                    control_flow.functions().iter().any(|graph| {
                        graph.instructions.iter().any(|instruction| {
                            instruction.address == *address && instruction.byte_len == *byte_len
                        })
                    })
                })
            }
            ProgramSubjectKey::InstructionInterpretation { .. } => false,
            ProgramSubjectKey::ControlFlowEdge {
                function_entry,
                source,
                target,
                edge_kind,
            } => self
                .control_flow
                .as_ref()
                .and_then(|control_flow| control_flow.by_entry(*function_entry))
                .is_some_and(|graph| {
                    graph.edges.iter().any(|edge| {
                        graph
                            .blocks
                            .get(edge.from as usize)
                            .map(|block| block.start)
                            == Some(*source)
                            && graph.blocks.get(edge.to as usize).map(|block| block.start)
                                == Some(*target)
                            && edge.kind == *edge_kind
                    })
                }),
            ProgramSubjectKey::DirectCall { caller, callee } => {
                self.direct_calls.as_ref().is_some_and(|calls| {
                    calls
                        .edges()
                        .iter()
                        .any(|edge| edge.caller == *caller && edge.callee == *callee)
                })
            }
            ProgramSubjectKey::DirectCallsite {
                caller,
                instruction_address,
                target_address,
            } => self
                .control_flow
                .as_ref()
                .and_then(|control_flow| control_flow.by_entry(*caller))
                .is_some_and(|graph| {
                    graph.calls.iter().any(|call| {
                        call.instruction_address == *instruction_address
                            && matches!(
                                &call.target,
                                crate::analysis::control_flow::ControlFlowCallTarget::Direct {
                                    address,
                                    ..
                                } if address == target_address
                            )
                    })
                }),
            ProgramSubjectKey::DirectTransfer {
                function_entry,
                instruction_address,
                target_address,
            } => self.transfers.as_ref().is_some_and(|transfers| {
                transfers.transfers().iter().any(|transfer| {
                    transfer.source == *function_entry
                        && transfer.instruction_address == *instruction_address
                        && transfer.target_address == *target_address
                })
            }),
            ProgramSubjectKey::JumpTable {
                instruction_address,
                table_address,
                end_exclusive,
            } => self.control_flow.as_ref().is_some_and(|control_flow| {
                control_flow.functions().iter().any(|graph| {
                    graph.jump_tables.iter().any(|table| {
                        table.instruction_address == *instruction_address
                            && table.table_address == *table_address
                            && table.end_exclusive == *end_exclusive
                    })
                })
            }),
            ProgramSubjectKey::IndirectTransfer {
                function_entry,
                instruction_address,
            } => self.indirect_calls.as_ref().is_some_and(|calls| {
                calls.calls().iter().any(|call| {
                    call.source_function == *function_entry
                        && call.instruction_address == *instruction_address
                })
            }),
            ProgramSubjectKey::CrossReference {
                source,
                target,
                reference_kind,
            } => self.xrefs.as_ref().is_some_and(|xrefs| {
                xrefs.all_refs().iter().any(|reference| {
                    cross_reference_subject(reference)
                        == ProgramSubjectKey::CrossReference {
                            source: *source,
                            target: target.clone(),
                            reference_kind: *reference_kind,
                        }
                })
            }),
            ProgramSubjectKey::ReferenceOwnership {
                source,
                target,
                reference_kind,
                function_entry,
            } => self.guided_reference_ownerships.iter().any(|ownership| {
                ownership.source == *source
                    && ownership.target == *target
                    && ownership.reference_kind == *reference_kind
                    && ownership.function_entry == *function_entry
            }),
            ProgramSubjectKey::ExecutableByteRange {
                section_ordinal,
                start,
                end_exclusive,
            } => self.executable_bytes.as_ref().is_some_and(|bytes| {
                bytes.spans().iter().any(|span| {
                    span.section_ordinal == *section_ordinal
                        && span.start == *start
                        && span.end_exclusive == *end_exclusive
                })
            }),
            ProgramSubjectKey::DataObject { address } => {
                self.semantics.as_ref().is_some_and(|semantics| {
                    semantics
                        .data_objects()
                        .iter()
                        .any(|object| object.address == *address)
                })
            }
            ProgramSubjectKey::FunctionSignature { function_entry } => {
                self.semantics.as_ref().is_some_and(|semantics| {
                    semantics
                        .signatures()
                        .iter()
                        .any(|signature| signature.function_entry == *function_entry)
                })
            }
            ProgramSubjectKey::StackFrame { function_entry } => {
                self.semantics.as_ref().is_some_and(|semantics| {
                    semantics
                        .frames()
                        .iter()
                        .any(|frame| frame.function_entry == *function_entry)
                })
            }
            ProgramSubjectKey::LocalVariable { die_offset } => {
                self.semantics.as_ref().is_some_and(|semantics| {
                    semantics
                        .locals()
                        .iter()
                        .any(|local| local.die_offset == *die_offset)
                })
            }
            ProgramSubjectKey::Conflict { .. } => false,
            ProgramSubjectKey::Frontier { .. } => self.frontier_subjects().contains(subject),
        }
    }

    /// Stable typed unresolved frontiers from local recovery sites, incomplete
    /// stage contracts, and explicit runtime-open dependency boundaries.
    pub fn frontiers(&self) -> Vec<RecoveryFrontier> {
        let mut frontiers = Vec::new();
        if let Some(indirect_calls) = &self.indirect_calls {
            for call in indirect_calls
                .calls()
                .iter()
                .filter(|call| call.status != IndirectCallSiteStatus::Complete)
            {
                let subject = ProgramSubjectKey::IndirectTransfer {
                    function_entry: call.source_function,
                    instruction_address: call.instruction_address,
                };
                let reasons = if call.reasons.is_empty() {
                    vec!["indirect.target_unresolved".to_owned()]
                } else {
                    call.reasons.clone()
                };
                for reason in reasons {
                    let requires_runtime_evidence = reason.contains("runtime")
                        || reason == "indirect.swift_runtime_instantiation_open";
                    frontiers.push(RecoveryFrontier {
                        subject: subject.clone(),
                        kind: if requires_runtime_evidence {
                            RecoveryFrontierKind::RuntimeDispatch
                        } else if call.status == IndirectCallSiteStatus::Truncated
                            || call.omitted_candidate_count != 0
                        {
                            RecoveryFrontierKind::Budget
                        } else {
                            RecoveryFrontierKind::IndirectTargets
                        },
                        reason,
                        requires_runtime_evidence,
                        omitted_candidate_count: call.omitted_candidate_count,
                    });
                }
            }
        }
        if let Some(control_flow) = &self.control_flow {
            for graph in
                control_flow.functions().iter().filter(|graph| {
                    graph.completeness.reasons.iter().any(|reason| {
                        reason == "control_flow.computed_branch_transform_unsupported"
                    })
                })
            {
                for transform in &graph.computed_branch_transforms {
                    frontiers.push(RecoveryFrontier {
                        subject: ProgramSubjectKey::IndirectTransfer {
                            function_entry: graph.function_entry,
                            instruction_address: transform.instruction_address,
                        },
                        kind: RecoveryFrontierKind::ComputedBranchTransform,
                        reason: "control_flow.computed_branch_transform_unsupported".into(),
                        requires_runtime_evidence: false,
                        omitted_candidate_count: 0,
                    });
                }
            }
        }
        frontiers.extend(
            self.completeness
                .contracts
                .iter()
                .filter(|contract| {
                    !contract.globally_complete
                        || contract.budget_excluded != 0
                        || contract.continuation.is_some()
                })
                .map(|contract| RecoveryFrontier {
                    subject: ProgramSubjectKey::Frontier {
                        layer: format!("program.{}", contract.stage.key()),
                        address: None,
                    },
                    kind: if contract.budget_excluded != 0 || contract.continuation.is_some() {
                        RecoveryFrontierKind::Budget
                    } else {
                        RecoveryFrontierKind::Stage
                    },
                    reason: self
                        .completeness
                        .stages
                        .iter()
                        .find(|receipt| receipt.stage == contract.stage)
                        .and_then(|receipt| receipt.reasons.first())
                        .cloned()
                        .unwrap_or_else(|| format!("program.{}.incomplete", contract.stage.key())),
                    requires_runtime_evidence: false,
                    omitted_candidate_count: contract.budget_excluded,
                }),
        );
        if let Some(dependencies) = &self.dependencies {
            frontiers.extend(dependencies.frontiers().iter().map(|frontier| {
                let layer = match frontier.kind {
                    crate::analysis::dependency_index::RuntimeFrontierKind::RuntimeLoadedImage => {
                        "dependencies.runtime_loaded_image"
                    }
                    crate::analysis::dependency_index::RuntimeFrontierKind::ObjectiveCRuntimeMutation => {
                        "dependencies.objective_c_runtime_mutation"
                    }
                    crate::analysis::dependency_index::RuntimeFrontierKind::GeneratedCode => {
                        "dependencies.generated_code"
                    }
                    crate::analysis::dependency_index::RuntimeFrontierKind::EncryptedCode => {
                        "dependencies.encrypted_code"
                    }
                };
                RecoveryFrontier {
                    subject: ProgramSubjectKey::Frontier {
                        layer: layer.to_owned(),
                        address: None,
                    },
                    kind: RecoveryFrontierKind::Dependency,
                    reason: layer.to_owned(),
                    requires_runtime_evidence: true,
                    omitted_candidate_count: 0,
                }
            }));
        }
        frontiers.sort_by(|left, right| {
            (&left.subject, left.kind, &left.reason).cmp(&(
                &right.subject,
                right.kind,
                &right.reason,
            ))
        });
        frontiers.dedup();
        frontiers
    }

    /// Stable unresolved frontier subjects for compact identity-only consumers.
    pub fn frontier_subjects(&self) -> Vec<ProgramSubjectKey> {
        let mut subjects = self
            .frontiers()
            .into_iter()
            .map(|frontier| frontier.subject)
            .collect::<Vec<_>>();
        subjects.sort();
        subjects.dedup();
        subjects
    }

    /// Validate a neutral recovery guide without applying it or changing this program.
    pub fn validate_guide(&self, guide: &RecoveryGuide) -> RecoveryGuideValidation {
        validate_recovery_guide(&self.image, &self.questions, guide)
    }

    /// Validate question answers and caller-authored premises against the
    /// exact selected image, executable layout, selected recovery stages, and
    /// other decisions in the same guide without applying them.
    pub fn validate_guide_for_image(
        &self,
        macho: &MachoFile<'_>,
        guide: &RecoveryGuide,
    ) -> RecoveryGuideValidation {
        validate_guide_for_program(self, macho, guide)
    }

    /// Guide used for this recovered view, when a non-redundant guide was applied.
    pub fn guide(&self) -> Option<&RecoveryGuide> {
        self.guide.as_ref()
    }

    /// Validation and application receipt for this guided view.
    pub fn guide_application(&self) -> Option<&RecoveryGuideApplication> {
        self.guide_application.as_ref()
    }

    /// Compare this recovered view with a base built from the same exact image,
    /// selected stages, and limits.
    pub fn delta_from(&self, base: &Self) -> Result<RecoveryDelta, RecoveryDeltaError> {
        if self.image != base.image {
            return Err(RecoveryDeltaError::ImageMismatch);
        }
        if self.request != base.request {
            return Err(RecoveryDeltaError::RequestMismatch);
        }
        let mut delta = build_recovery_delta(base, self);
        if let (Some(guide), Some(application)) = (&self.guide, &self.guide_application) {
            attach_decision_derivations(base, self, guide, &application.decisions, &mut delta);
        }
        Ok(delta)
    }

    /// Borrow every selected index as optional, non-owning capabilities.
    ///
    /// Downstream layers can accept [`ProgramFacts`] when annotations are
    /// optional, or use its typed input helpers when a complete prerequisite
    /// set is mandatory. The returned view performs no recovery and copies no
    /// recovered records.
    pub fn facts(&self) -> ProgramFacts<'_> {
        ProgramFacts {
            image_layout: self.image_layout.as_ref(),
            pointers: self.pointers.as_ref(),
            symbols: self.symbols.as_ref(),
            strings: self.strings.as_ref(),
            objc: self.objc.as_ref(),
            swift: self.swift.as_ref(),
            dwarf: self.dwarf.as_ref(),
            functions: self.functions.as_ref(),
            control_flow: self.control_flow.as_ref(),
            executable_bytes: self.executable_bytes.as_ref(),
            direct_calls: self.direct_calls.as_ref(),
            transfers: self.transfers.as_ref(),
            indirect_calls: self.indirect_calls.as_ref(),
            xrefs: self.xrefs.as_ref(),
            guided_reference_ownerships: &self.guided_reference_ownerships,
            rtti: self.rtti.as_ref(),
            exceptions: self.exceptions.as_ref(),
            dependencies: self.dependencies.as_ref(),
            semantics: self.semantics.as_ref(),
        }
    }

    /// Overall program status.
    pub const fn status(&self) -> ProgramRecoveryStatus {
        self.completeness.status
    }

    /// Indexed image layout, when selected.
    pub fn image_layout(&self) -> Option<&ImageLayoutIndex> {
        self.image_layout.as_ref()
    }

    /// Format pointer inventory, when selected.
    pub fn pointers(&self) -> Option<&PointerIndex> {
        self.pointers.as_ref()
    }

    /// Complete symbol inventory, when selected.
    pub fn symbols(&self) -> Option<&SymbolInventory> {
        self.symbols.as_ref()
    }

    /// String inventory, when selected.
    pub fn strings(&self) -> Option<&StringIndex> {
        self.strings.as_ref()
    }

    /// Strict Objective-C runtime inventory, when selected or required.
    pub fn objc(&self) -> Option<&ObjcIndex> {
        self.objc.as_ref()
    }

    /// Strict Swift ABI inventory, when selected or required.
    pub fn swift(&self) -> Option<&SwiftIndex> {
        self.swift.as_ref()
    }

    /// Bounded DWARF inventory, when selected or required.
    pub fn dwarf(&self) -> Option<&DwarfIndex> {
        self.dwarf.as_ref()
    }

    /// Authoritative function inventory, when selected or required.
    pub fn functions(&self) -> Option<&FunctionIndex> {
        self.functions.as_ref()
    }

    /// Per-function basic blocks and CFGs.
    pub fn control_flow(&self) -> Option<&ControlFlowIndex> {
        self.control_flow.as_ref()
    }

    /// Conserved executable-section byte classification.
    pub fn executable_bytes(&self) -> Option<&ExecutableByteIndex> {
        self.executable_bytes.as_ref()
    }

    /// Direct call graph over recovered function identities.
    pub fn direct_calls(&self) -> Option<&DirectCallGraph> {
        self.direct_calls.as_ref()
    }

    /// Direct branches, tail calls, and thunk resolutions.
    pub fn transfers(&self) -> Option<&DirectTransferIndex> {
        self.transfers.as_ref()
    }

    /// Indirect calls, branches, pointer targets, and dynamic dispatch.
    pub fn indirect_calls(&self) -> Option<&IndirectCallIndex> {
        self.indirect_calls.as_ref()
    }

    /// Cross-reference inventory, when selected.
    pub fn xrefs(&self) -> Option<&XrefIndex> {
        self.xrefs.as_ref()
    }

    /// Caller-guided owners for exact reference uses, sorted by reference key.
    pub fn guided_reference_ownerships(&self) -> &[GuidedReferenceOwnership] {
        &self.guided_reference_ownerships
    }

    /// Select the source owner for one retained xref.
    ///
    /// A caller-guided relation wins only for that exact source/target/kind
    /// tuple. Otherwise this returns an independently unique range owner and
    /// leaves ambiguous or unowned references unresolved.
    pub fn reference_owner<'program>(
        &'program self,
        reference: &Xref,
    ) -> Option<ProgramReferenceOwner<'program>> {
        let functions = self.functions.as_ref()?;
        let subject = cross_reference_subject(reference);
        if let ProgramSubjectKey::CrossReference {
            source,
            target,
            reference_kind,
        } = subject
            && let Some(guided) = self.guided_reference_ownerships.iter().find(|ownership| {
                ownership.source == source
                    && ownership.target == target
                    && ownership.reference_kind == reference_kind
            })
        {
            let owner = functions
                .owners(source)
                .find(|owner| owner.function.entry == guided.function_entry)?;
            return Some(ProgramReferenceOwner {
                owner,
                authority: ProgramFactAuthority::Guided,
            });
        }
        let mut owners = functions.owners(reference.source.0);
        let owner = owners.next()?;
        if owners.next().is_some() {
            return None;
        }
        Some(ProgramReferenceOwner {
            owner,
            authority: if owner.function.authority == FunctionRecoveryAuthority::CallerGuided {
                ProgramFactAuthority::Guided
            } else {
                ProgramFactAuthority::Independent
            },
        })
    }

    /// Named and structural RTTI and vtable inventory, when selected.
    pub fn rtti(&self) -> Option<&RttiIndex> {
        self.rtti.as_ref()
    }

    /// Exception and unwind boundary inventory, when selected.
    pub fn exceptions(&self) -> Option<&ExceptionIndex> {
        self.exceptions.as_ref()
    }

    /// Named dependency declarations and runtime-open frontiers.
    pub fn dependencies(&self) -> Option<&DependencyIndex> {
        self.dependencies.as_ref()
    }

    /// Global data objects, signatures, frames, and local variables.
    pub fn semantics(&self) -> Option<&SemanticIndex> {
        self.semantics.as_ref()
    }

    /// Authoritative answer to which recovered function or functions contain
    /// an instruction address.
    pub fn function_containing(&self, instruction_address: u64) -> Option<FunctionLookup<'_>> {
        self.functions
            .as_ref()
            .map(|functions| functions.containing(instruction_address))
    }

    /// Find one function and every retained program layer attached to it.
    pub fn function_by_entry(&self, entry: u64) -> Option<ProgramFunctionView<'_>> {
        let function = self.functions.as_ref()?.by_entry(entry)?;
        Some(ProgramFunctionView {
            function,
            control_flow: self
                .control_flow
                .as_ref()
                .and_then(|control_flow| control_flow.by_entry(entry)),
            direct_call_node: self
                .direct_calls
                .as_ref()
                .and_then(|calls| calls.by_entry(entry)),
            thunk: self
                .transfers
                .as_ref()
                .and_then(|transfers| transfers.thunk_by_entry(entry)),
            signature: self
                .semantics
                .as_ref()
                .and_then(|semantics| semantics.signature(entry)),
            frame: self
                .semantics
                .as_ref()
                .and_then(|semantics| semantics.frame(entry)),
        })
    }

    /// Iterate retained direct call edges from one caller, paired with final
    /// thunk resolution when available.
    pub fn resolved_direct_outgoing(
        &self,
        caller: u64,
    ) -> impl Iterator<Item = ResolvedDirectCallEdge<'_>> {
        self.direct_calls
            .as_ref()
            .into_iter()
            .flat_map(move |calls| calls.outgoing(caller))
            .filter_map(|edge| {
                self.transfers
                    .as_ref()?
                    .resolve_function_target(edge.callee)
                    .map(|resolution| ResolvedDirectCallEdge { edge, resolution })
            })
    }

    /// Iterate direct edges whose thunk-resolved final target is `callee`.
    /// Cycles, depth-limited chains, and omitted thunk inventories never
    /// masquerade as resolved incoming edges.
    pub fn resolved_direct_incoming(
        &self,
        callee: u64,
    ) -> impl Iterator<Item = ResolvedDirectCallEdge<'_>> {
        self.direct_calls
            .as_ref()
            .into_iter()
            .flat_map(|calls| calls.edges())
            .filter_map(move |edge| {
                let resolution = self
                    .transfers
                    .as_ref()?
                    .resolve_function_target(edge.callee)?;
                (resolution.final_target == Some(callee))
                    .then_some(ResolvedDirectCallEdge { edge, resolution })
            })
    }

    /// Iterate direct branch, tail-call, and thunk evidence from one function.
    pub fn direct_transfers_from(
        &self,
        source: u64,
    ) -> impl Iterator<Item = &DirectFunctionTransfer> {
        self.transfers
            .as_ref()
            .into_iter()
            .flat_map(move |transfers| transfers.from_function(source))
    }

    /// Iterate indirect calls, branches, and dynamic dispatch from one
    /// recovered function identity.
    pub fn indirect_calls_from(&self, source: u64) -> impl Iterator<Item = &RecoveredIndirectCall> {
        self.indirect_calls
            .as_ref()
            .into_iter()
            .flat_map(move |calls| calls.from_function(source))
    }

    /// Borrow all selected recovery context relevant to one address.
    pub fn address_view(&self, address: u64) -> ProgramAddressView<'_> {
        let function = self.function_containing(address);
        let instruction = self.instruction_at(address, function.as_ref());
        let symbols = self
            .symbols
            .as_ref()
            .map(|symbols| symbols.at_address(address).collect())
            .unwrap_or_default();
        let string = self
            .strings
            .as_ref()
            .and_then(|strings| strings.containing(address));
        let type_info = self
            .rtti
            .as_ref()
            .and_then(|rtti| rtti.type_info_by_address(address));
        let vtable = self
            .rtti
            .as_ref()
            .and_then(|rtti| rtti.vtable_containing(address));
        let data_object = self
            .semantics
            .as_ref()
            .and_then(|semantics| semantics.data_containing(address));
        let references = self
            .xrefs
            .as_ref()
            .map(|xrefs| {
                xrefs
                    .refs_from(crate::core::model::addr::Va(address))
                    .map(|reference| self.reference_view(reference))
                    .collect()
            })
            .unwrap_or_default();
        ProgramAddressView {
            address,
            function,
            instruction,
            symbols,
            string,
            type_info,
            vtable,
            data_object,
            references,
        }
    }

    /// Borrow allocation-free annotations for one streaming disassembly address.
    pub const fn annotations_at(&self, address: u64) -> ProgramAnnotations<'_> {
        ProgramAnnotations {
            program: self,
            address,
        }
    }

    fn instruction_at<'program>(
        &'program self,
        address: u64,
        ownership: Option<&FunctionLookup<'program>>,
    ) -> Option<&'program ControlFlowInstruction> {
        let control_flow = self.control_flow.as_ref()?;
        let find = |entry| {
            let graph = control_flow.by_entry(entry)?;
            graph
                .instructions
                .binary_search_by_key(&address, |instruction| instruction.address)
                .ok()
                .map(|index| &graph.instructions[index])
        };
        match ownership? {
            FunctionLookup::One(owner) => find(owner.function.entry),
            FunctionLookup::Ambiguous(owners) => {
                owners.iter().find_map(|owner| find(owner.function.entry))
            }
            FunctionLookup::None => None,
        }
    }

    fn reference_view<'program>(
        &'program self,
        reference: &'program Xref,
    ) -> ProgramReferenceView<'program> {
        let target = reference.target.internal_address().map(|address| address.0);
        let target_function = target.and_then(|address| self.function_containing(address));
        let target_data_object = target.and_then(|address| {
            self.semantics
                .as_ref()
                .and_then(|semantics| semantics.data_containing(address))
        });
        let target_binding = match (&reference.target, &target_function, target_data_object) {
            (XrefTarget::Import { .. }, _, _) => ProgramReferenceBinding::Import,
            (_, Some(FunctionLookup::One(_)), None) => ProgramReferenceBinding::Function,
            (_, None | Some(FunctionLookup::None), Some(_)) => ProgramReferenceBinding::DataObject,
            (_, Some(FunctionLookup::Ambiguous(_)), _)
            | (_, Some(FunctionLookup::One(_)), Some(_)) => {
                ProgramReferenceBinding::AmbiguousInternal
            }
            (_, None | Some(FunctionLookup::None), None) => {
                ProgramReferenceBinding::UnresolvedInternal
            }
        };
        ProgramReferenceView {
            reference,
            source_owner: self.reference_owner(reference),
            target_function,
            target_symbols: target
                .and_then(|address| {
                    self.symbols
                        .as_ref()
                        .map(|symbols| symbols.at_address(address).collect())
                })
                .unwrap_or_default(),
            target_string: target.and_then(|address| {
                self.strings
                    .as_ref()
                    .and_then(|strings| strings.containing(address))
            }),
            target_type_info: target.and_then(|address| {
                self.rtti
                    .as_ref()
                    .and_then(|rtti| rtti.type_info_by_address(address))
            }),
            target_data_object,
            target_binding,
        }
    }
}

fn build_program_coverage(program: &RecoveredProgram) -> ProgramCoverage {
    ProgramCoverage {
        image: program.image.clone(),
        executable_bytes: executable_byte_coverage(program),
        functions: function_coverage(program),
        control_flow: control_flow_coverage(program),
        direct_calls: direct_call_coverage(program),
        references: reference_coverage(program),
        indirect_transfers: indirect_transfer_coverage(program),
    }
}

fn executable_byte_coverage(program: &RecoveredProgram) -> ProgramCoverageDimension {
    let Some(index) = &program.executable_bytes else {
        return ProgramCoverageDimension::unavailable(ProgramCoverageUnit::Bytes);
    };
    let mut coverage = ProgramCoverageDimension {
        unit: ProgramCoverageUnit::Bytes,
        denominator: Some(index.completeness().observed_bytes),
        independently_established: 0,
        caller_guided: 0,
        candidate: 0,
        conflicted: 0,
        rejected: 0,
        unresolved: index.completeness().unresolved_bytes,
        budget_omitted: index
            .completeness()
            .observed_bytes
            .saturating_sub(index.completeness().classified_bytes),
        unavailable: false,
        reasons: index.completeness().reasons.clone(),
    };
    for span in index.spans() {
        let len = span.end_exclusive.saturating_sub(span.start);
        let guided = span
            .evidence
            .contains(&ExecutableByteEvidence::CallerDecision);
        if guided {
            coverage.caller_guided = coverage.caller_guided.saturating_add(len);
        } else if span.kind != ExecutableByteKind::Unresolved
            && span.confidence != crate::analysis::functions::FunctionEvidenceConfidence::Candidate
        {
            coverage.independently_established =
                coverage.independently_established.saturating_add(len);
        }
        if !guided
            && span.confidence == crate::analysis::functions::FunctionEvidenceConfidence::Candidate
            && span.kind != ExecutableByteKind::Unresolved
        {
            coverage.candidate = coverage.candidate.saturating_add(len);
        }
        if span.evidence.iter().any(|evidence| {
            matches!(
                evidence,
                ExecutableByteEvidence::ConflictingInstructionBoundaries
                    | ExecutableByteEvidence::TargetedAlternativeBoundary
                    | ExecutableByteEvidence::InlineLiteralTargetConflict
                    | ExecutableByteEvidence::JumpTableTargetConflict
            )
        }) {
            coverage.conflicted = coverage.conflicted.saturating_add(len);
        }
    }
    coverage
}

fn function_coverage(program: &RecoveredProgram) -> ProgramCoverageDimension {
    let Some(index) = &program.functions else {
        return ProgramCoverageDimension::unavailable(ProgramCoverageUnit::Functions);
    };
    let rejected = index
        .entry_candidates()
        .iter()
        .filter(|candidate| {
            matches!(
                candidate.disposition,
                crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedByCaller
                    | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
                    | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedRecoveredData
                    | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedImportStub
                    | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
            )
        })
        .count() as u64;
    let candidates = index.entry_candidates().len() as u64;
    ProgramCoverageDimension {
        unit: ProgramCoverageUnit::Functions,
        denominator: Some(
            index
                .functions()
                .len()
                .saturating_add(index.entry_candidates().len()) as u64
                + index.truncated_function_count(),
        ),
        independently_established: index
            .functions()
            .iter()
            .filter(|function| {
                function.authority
                    == crate::analysis::functions::FunctionRecoveryAuthority::Independent
            })
            .count() as u64,
        caller_guided: index
            .functions()
            .iter()
            .filter(|function| {
                function.authority
                    == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
            })
            .count() as u64
            + index.relationships().len() as u64,
        candidate: candidates.saturating_sub(rejected),
        conflicted: index
            .functions()
            .iter()
            .filter(|function| !function.conflicts.is_empty())
            .count() as u64,
        rejected,
        unresolved: candidates.saturating_sub(rejected),
        budget_omitted: index.truncated_function_count(),
        unavailable: false,
        reasons: index
            .receipts()
            .iter()
            .filter_map(|receipt| receipt.diagnostic.clone())
            .collect(),
    }
}

fn control_flow_coverage(program: &RecoveredProgram) -> ProgramCoverageDimension {
    let Some(index) = &program.control_flow else {
        return ProgramCoverageDimension::unavailable(ProgramCoverageUnit::FunctionGraphs);
    };
    let guided_entries = program
        .functions
        .as_ref()
        .map(|functions| {
            functions
                .functions()
                .iter()
                .filter(|function| {
                    function.authority
                        == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
                })
                .map(|function| function.entry)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    ProgramCoverageDimension {
        unit: ProgramCoverageUnit::FunctionGraphs,
        denominator: Some(index.functions().len() as u64 + index.truncated_function_count()),
        independently_established: index
            .functions()
            .iter()
            .filter(|graph| {
                graph.completeness.status == FunctionControlFlowStatus::Complete
                    && !guided_entries.contains(&graph.function_entry)
            })
            .count() as u64,
        caller_guided: index
            .functions()
            .iter()
            .filter(|graph| guided_entries.contains(&graph.function_entry))
            .count() as u64,
        candidate: index
            .functions()
            .iter()
            .filter(|graph| graph.completeness.status == FunctionControlFlowStatus::Partial)
            .count() as u64,
        conflicted: index
            .functions()
            .iter()
            .filter(|graph| {
                graph
                    .completeness
                    .reasons
                    .iter()
                    .any(|reason| reason.contains("conflict"))
            })
            .count() as u64,
        rejected: 0,
        unresolved: index
            .functions()
            .iter()
            .filter(|graph| {
                matches!(
                    graph.completeness.status,
                    FunctionControlFlowStatus::Partial | FunctionControlFlowStatus::Unavailable
                )
            })
            .count() as u64,
        budget_omitted: index.truncated_function_count()
            + index
                .functions()
                .iter()
                .filter(|graph| graph.completeness.status == FunctionControlFlowStatus::Truncated)
                .count() as u64,
        unavailable: false,
        reasons: program
            .completeness
            .stages
            .iter()
            .find(|receipt| receipt.stage == ProgramRecoveryStage::ControlFlow)
            .map(|receipt| receipt.reasons.clone())
            .unwrap_or_default(),
    }
}

fn direct_call_coverage(program: &RecoveredProgram) -> ProgramCoverageDimension {
    let Some(index) = &program.direct_calls else {
        return ProgramCoverageDimension::unavailable(ProgramCoverageUnit::Callsites);
    };
    let receipt = index.completeness();
    let guided_entries = program
        .functions
        .as_ref()
        .map(|functions| {
            functions
                .functions()
                .iter()
                .filter(|function| {
                    function.authority
                        == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
                })
                .map(|function| function.entry)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    let guided_calls = index
        .edges()
        .iter()
        .filter(|edge| {
            guided_entries.contains(&edge.caller) || guided_entries.contains(&edge.callee)
        })
        .map(|edge| edge.observed_callsite_count)
        .sum::<u64>();
    ProgramCoverageDimension {
        unit: ProgramCoverageUnit::Callsites,
        denominator: Some(receipt.examined_callsite_count),
        independently_established: receipt
            .retained_direct_callsite_count
            .saturating_sub(guided_calls),
        caller_guided: guided_calls,
        candidate: index
            .edges()
            .iter()
            .filter(|edge| {
                edge.callee_entry_confidence
                    == crate::analysis::functions::FunctionEvidenceConfidence::Candidate
                    || edge.ownership_confidence
                        == crate::analysis::functions::FunctionOwnershipConfidence::Candidate
            })
            .map(|edge| edge.observed_callsite_count)
            .sum(),
        conflicted: 0,
        rejected: 0,
        unresolved: receipt.unresolved_callsite_count,
        budget_omitted: receipt
            .omitted_direct_callsite_count
            .saturating_add(receipt.omitted_unresolved_callsite_count),
        unavailable: false,
        reasons: receipt.reasons.clone(),
    }
}

fn reference_coverage(program: &RecoveredProgram) -> ProgramCoverageDimension {
    let Some(index) = &program.xrefs else {
        return ProgramCoverageDimension::unavailable(ProgramCoverageUnit::References);
    };
    let mut guided = 0_u64;
    let mut candidate = 0_u64;
    for reference in index.all_refs() {
        match program.reference_owner(reference) {
            Some(owner) if owner.authority == ProgramFactAuthority::Guided => guided += 1,
            Some(owner)
                if owner.owner.confidence
                    == crate::analysis::functions::FunctionOwnershipConfidence::Candidate =>
            {
                candidate += 1;
            }
            Some(_) => {}
            None if program
                .functions
                .as_ref()
                .is_some_and(|functions| functions.owners(reference.source.0).len() > 1) =>
            {
                candidate += 1;
            }
            None => {}
        }
    }
    let retained = index.all_refs().len() as u64;
    ProgramCoverageDimension {
        unit: ProgramCoverageUnit::References,
        denominator: Some(retained),
        independently_established: retained.saturating_sub(guided).saturating_sub(candidate),
        caller_guided: guided,
        candidate,
        conflicted: 0,
        rejected: 0,
        unresolved: (index.status() == XrefIndexStatus::Partial) as u64,
        budget_omitted: (index.status() == XrefIndexStatus::Truncated) as u64,
        unavailable: false,
        reasons: index.completeness().reasons.clone(),
    }
}

fn indirect_transfer_coverage(program: &RecoveredProgram) -> ProgramCoverageDimension {
    let Some(index) = &program.indirect_calls else {
        return ProgramCoverageDimension::unavailable(ProgramCoverageUnit::IndirectTransfers);
    };
    let receipt = index.completeness();
    let guided_entries = program
        .functions
        .as_ref()
        .map(|functions| {
            functions
                .functions()
                .iter()
                .filter(|function| {
                    function.authority
                        == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
                })
                .map(|function| function.entry)
                .collect::<BTreeSet<_>>()
        })
        .unwrap_or_default();
    ProgramCoverageDimension {
        unit: ProgramCoverageUnit::IndirectTransfers,
        denominator: Some(receipt.observed_transfer_count),
        independently_established: index
            .calls()
            .iter()
            .filter(|call| {
                call.status == IndirectCallSiteStatus::Complete
                    && !guided_entries.contains(&call.source_function)
            })
            .count() as u64,
        caller_guided: index
            .calls()
            .iter()
            .filter(|call| guided_entries.contains(&call.source_function))
            .count() as u64,
        candidate: index
            .calls()
            .iter()
            .filter(|call| {
                call.candidates.iter().any(|candidate| {
                    candidate.confidence
                        == crate::analysis::functions::FunctionEvidenceConfidence::Candidate
                })
            })
            .count() as u64,
        conflicted: index
            .calls()
            .iter()
            .filter(|call| !call.conflicts.is_empty())
            .count() as u64,
        rejected: 0,
        unresolved: index
            .calls()
            .iter()
            .filter(|call| call.status == IndirectCallSiteStatus::Partial)
            .count() as u64,
        budget_omitted: receipt
            .omitted_transfer_count
            .saturating_add(receipt.omitted_candidate_count),
        unavailable: false,
        reasons: receipt.reasons.clone(),
    }
}

#[derive(Debug, Clone, Copy)]
struct GuideExecutableSection {
    ordinal: u64,
    start: u64,
    end_exclusive: u64,
}

fn validate_guide_for_program(
    program: &RecoveredProgram,
    macho: &MachoFile<'_>,
    guide: &RecoveryGuide,
) -> RecoveryGuideValidation {
    let mut validation = validate_recovery_guide(&program.image, &program.questions, guide);
    if FunctionImageIdentity::from_macho(macho) != program.image {
        for decision in &mut validation.decisions {
            decision.applicability = RecoveryDecisionApplicability::Stale;
            decision.reason = "recovery_guide.validation_image_mismatch".into();
        }
        summarize_guide_validation(&mut validation);
        return validation;
    }

    let sections = macho
        .all_sections()
        .enumerate()
        .filter_map(|(ordinal, section)| {
            if !section.attributes().intersects(
                SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS,
            ) || section.size() == 0
            {
                return None;
            }
            let end_exclusive = section.addr().0.checked_add(section.size())?;
            let file_end = section.offset().0.checked_add(section.size())?;
            (file_end <= macho.file_size() as u64).then_some(GuideExecutableSection {
                ordinal: ordinal as u64,
                start: section.addr().0,
                end_exclusive,
            })
        })
        .collect::<Vec<_>>();

    for (index, result) in validation.decisions.iter_mut().enumerate() {
        if result.applicability != RecoveryDecisionApplicability::Applicable {
            continue;
        }
        let decision = &guide.decisions[index];
        if let Some((applicability, reason)) =
            validate_decision_for_program(program, macho, guide, index, decision, &sections)
        {
            result.applicability = applicability;
            result.reason = reason.into();
        }
    }
    summarize_guide_validation(&mut validation);
    validation
}

fn validate_decision_for_program(
    program: &RecoveredProgram,
    macho: &MachoFile<'_>,
    guide: &RecoveryGuide,
    decision_index: usize,
    decision: &RecoveryDecision,
    sections: &[GuideExecutableSection],
) -> Option<(RecoveryDecisionApplicability, &'static str)> {
    match (&decision.point.subject, &decision.choice) {
        (
            ProgramSubjectKey::FunctionCandidate { address },
            RecoveryChoice::AcceptFunctionEntry | RecoveryChoice::Reject,
        ) => {
            if !program.executed.contains(&ProgramRecoveryStage::Functions) {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.function_stage_not_selected",
                ));
            }
            if !address_is_executable(*address, sections) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.function_address_not_executable",
                ));
            }
        }
        (
            ProgramSubjectKey::FunctionCandidate { address },
            RecoveryChoice::FunctionRelationship { owner_entry, .. },
        ) => {
            if !program.executed.contains(&ProgramRecoveryStage::Functions) {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.function_stage_not_selected",
                ));
            }
            if !address_is_executable(*address, sections)
                || !address_is_executable(*owner_entry, sections)
            {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.function_relationship_address_not_executable",
                ));
            }
            let owner_exists = program
                .functions
                .as_ref()
                .is_some_and(|functions| functions.by_entry(*owner_entry).is_some())
                || guide.decisions.iter().any(|candidate| {
                    matches!(
                        (&candidate.point.subject, &candidate.choice),
                        (
                            ProgramSubjectKey::FunctionCandidate { address },
                            RecoveryChoice::AcceptFunctionEntry
                        ) if address == owner_entry
                    )
                });
            if !owner_exists {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.function_relationship_owner_missing",
                ));
            }
        }
        (ProgramSubjectKey::Function { entry }, RecoveryChoice::FunctionRanges { ranges }) => {
            if !program.executed.contains(&ProgramRecoveryStage::Functions) {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.function_stage_not_selected",
                ));
            }
            if ranges.is_empty()
                || !ranges.iter().any(|range| range.start == *entry)
                || ranges
                    .iter()
                    .any(|range| range.start >= range.end_exclusive)
                || ranges
                    .windows(2)
                    .any(|pair| pair[0].end_exclusive > pair[1].start)
            {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.invalid_function_ranges",
                ));
            }
            if ranges.iter().any(|range| {
                !range_is_in_one_executable_section(range.start, range.end_exclusive, sections)
            }) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.function_range_not_executable",
                ));
            }
            let function_exists = program
                .functions
                .as_ref()
                .is_some_and(|functions| functions.by_entry(*entry).is_some())
                || guide.decisions.iter().any(|candidate| {
                    matches!(
                        (&candidate.point.subject, &candidate.choice),
                        (
                            ProgramSubjectKey::FunctionCandidate { address },
                            RecoveryChoice::AcceptFunctionEntry
                        ) if address == entry
                    )
                });
            if !function_exists {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.function_range_owner_missing",
                ));
            }
        }
        (
            ProgramSubjectKey::ExecutableByteRange {
                section_ordinal,
                start,
                end_exclusive,
            },
            RecoveryChoice::ByteRole { role },
        ) => {
            if !program
                .executed
                .contains(&ProgramRecoveryStage::ExecutableBytes)
            {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.executable_byte_stage_not_selected",
                ));
            }
            if !sections.iter().any(|section| {
                section.ordinal == *section_ordinal
                    && *start < *end_exclusive
                    && *start >= section.start
                    && *end_exclusive <= section.end_exclusive
            }) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.byte_range_not_in_selected_executable_section",
                ));
            }
            if *role == ExecutableByteKind::Instruction
                && macho.header().cpu_type().0 == CPU_TYPE_ARM64
                && (*start % 4 != 0 || *end_exclusive % 4 != 0)
            {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.arm64_instruction_range_unaligned",
                ));
            }
            for previous in &guide.decisions[..decision_index] {
                if let (
                    ProgramSubjectKey::ExecutableByteRange {
                        section_ordinal: previous_section,
                        start: previous_start,
                        end_exclusive: previous_end,
                    },
                    RecoveryChoice::ByteRole {
                        role: previous_role,
                    },
                ) = (&previous.point.subject, &previous.choice)
                {
                    if previous_section == section_ordinal
                        && *previous_start < *end_exclusive
                        && *start < *previous_end
                        && previous_role != role
                    {
                        return Some((
                            RecoveryDecisionApplicability::Conflicting,
                            "recovery_guide.overlapping_byte_roles",
                        ));
                    }
                }
            }
        }
        (ProgramSubjectKey::ControlFlowEdge { .. }, RecoveryChoice::SuppressControlFlowEdge) => {
            if !program
                .executed
                .contains(&ProgramRecoveryStage::ControlFlow)
            {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.control_flow_stage_not_selected",
                ));
            }
            if !program.contains_subject(&decision.point.subject) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.control_flow_edge_missing",
                ));
            }
        }
        (ProgramSubjectKey::DirectCallsite { .. }, RecoveryChoice::SuppressDirectCall) => {
            if !program
                .executed
                .contains(&ProgramRecoveryStage::ControlFlow)
            {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.control_flow_stage_not_selected",
                ));
            }
            if !program.contains_subject(&decision.point.subject) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.direct_callsite_missing",
                ));
            }
        }
        (
            ProgramSubjectKey::CrossReference { source, .. },
            RecoveryChoice::ReferenceOwner { function_entry },
        ) => {
            if !program.executed.contains(&ProgramRecoveryStage::Xrefs)
                || !program.executed.contains(&ProgramRecoveryStage::Functions)
            {
                return Some((
                    RecoveryDecisionApplicability::Unsupported,
                    "recovery_guide.reference_ownership_stage_not_selected",
                ));
            }
            if !program.contains_subject(&decision.point.subject) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.cross_reference_missing",
                ));
            }
            let mut owners = program
                .functions
                .as_ref()
                .expect("selected function stage has payload")
                .owners(*source)
                .map(|owner| owner.function.entry)
                .collect::<BTreeSet<_>>();
            for candidate in &guide.decisions {
                if let (
                    ProgramSubjectKey::Function { entry },
                    RecoveryChoice::FunctionRanges { ranges },
                ) = (&candidate.point.subject, &candidate.choice)
                    && ranges
                        .iter()
                        .any(|range| *source >= range.start && *source < range.end_exclusive)
                {
                    owners.insert(*entry);
                }
            }
            if !owners.contains(function_entry) {
                return Some((
                    RecoveryDecisionApplicability::Stale,
                    "recovery_guide.reference_owner_not_candidate",
                ));
            }
            if owners.len() == 1 {
                return Some((
                    RecoveryDecisionApplicability::Redundant,
                    "recovery_guide.reference_owner_already_unique",
                ));
            }
        }
        _ => {
            return Some((
                RecoveryDecisionApplicability::Unsupported,
                "recovery_guide.unsupported_proposition",
            ));
        }
    }
    None
}

fn address_is_executable(address: u64, sections: &[GuideExecutableSection]) -> bool {
    sections
        .iter()
        .any(|section| address >= section.start && address < section.end_exclusive)
}

fn range_is_in_one_executable_section(
    start: u64,
    end_exclusive: u64,
    sections: &[GuideExecutableSection],
) -> bool {
    start < end_exclusive
        && sections
            .iter()
            .any(|section| start >= section.start && end_exclusive <= section.end_exclusive)
}

fn summarize_guide_validation(validation: &mut RecoveryGuideValidation) {
    let applicable = validation
        .decisions
        .iter()
        .filter(|decision| decision.applicability == RecoveryDecisionApplicability::Applicable)
        .count();
    let only_usable = validation.decisions.iter().all(|decision| {
        matches!(
            decision.applicability,
            RecoveryDecisionApplicability::Applicable | RecoveryDecisionApplicability::Redundant
        )
    });
    validation.applicability = if applicable != 0 && only_usable {
        RecoveryGuideApplicability::Applicable
    } else if applicable != 0 {
        RecoveryGuideApplicability::PartiallyApplicable
    } else {
        RecoveryGuideApplicability::NotApplicable
    };
}

fn build_guide_application(
    base: &RecoveredProgram,
    program: &RecoveredProgram,
    guide: &RecoveryGuide,
    validation: RecoveryGuideValidation,
) -> RecoveryGuideApplication {
    let decisions: Vec<RecoveryDecisionApplication> = guide
        .decisions
        .iter()
        .zip(&validation.decisions)
        .map(|(decision, validated)| {
            let (status, reason) = if validated.applicability
                == RecoveryDecisionApplicability::Redundant
            {
                (
                    RecoveryDecisionApplicationStatus::Redundant,
                    "recovery_guide.redundant",
                )
            } else {
                match (&decision.point.subject, &decision.choice) {
                    (
                        ProgramSubjectKey::FunctionCandidate { address },
                        RecoveryChoice::AcceptFunctionEntry,
                    ) => {
                        if program.functions.as_ref().is_some_and(|functions| {
                            functions.by_entry(*address).is_some_and(|function| {
                                function.authority
                                    == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
                            })
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.function_entry_applied",
                            )
                        } else if program.functions.as_ref().is_some_and(|functions| {
                            functions.truncated_function_count() != 0
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::BudgetExcluded,
                                "recovery_guide.function_budget_excluded",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.function_entry_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::ExecutableByteRange {
                            section_ordinal,
                            start,
                            end_exclusive,
                        },
                        RecoveryChoice::ByteRole { role },
                    ) => {
                        if program.executable_bytes.as_ref().is_some_and(|bytes| {
                            byte_role_is_applied(
                                bytes,
                                *section_ordinal,
                                *start,
                                *end_exclusive,
                                *role,
                            )
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.byte_role_applied",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.byte_role_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::Function { entry },
                        RecoveryChoice::FunctionRanges { ranges },
                    ) => {
                        if program.functions.as_ref().is_some_and(|functions| {
                            functions.by_entry(*entry).is_some_and(|function| {
                                function.authority
                                    == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
                                    && ranges.iter().all(|range| {
                                        function.evidence.iter().any(|evidence| {
                                            evidence.source == FunctionEvidenceSource::CallerDecision
                                                && evidence.extent_start == Some(range.start)
                                                && evidence.end_exclusive
                                                    == Some(range.end_exclusive)
                                        })
                                    })
                            })
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.function_ranges_applied",
                            )
                        } else if program.functions.as_ref().is_some_and(|functions| {
                            functions.truncated_function_count() != 0
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::BudgetExcluded,
                                "recovery_guide.function_ranges_budget_excluded",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.function_ranges_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::FunctionCandidate { address },
                        RecoveryChoice::Reject,
                    ) => {
                        if program.functions.as_ref().is_some_and(|functions| {
                            functions.entry_candidates().iter().any(|candidate| {
                                candidate.address == *address
                                    && candidate.disposition
                                        == crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedByCaller
                            })
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.function_rejection_applied",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.function_rejection_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::FunctionCandidate { address },
                        RecoveryChoice::FunctionRelationship {
                            owner_entry,
                            relationship,
                        },
                    ) => {
                        let kind = function_relationship_kind(*relationship);
                        if program.functions.as_ref().is_some_and(|functions| {
                            functions.relationships().iter().any(|resolved| {
                                resolved.address == *address
                                    && resolved.owner_entry == *owner_entry
                                    && resolved.kind == kind
                            })
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.function_relationship_applied",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.function_relationship_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::ControlFlowEdge {
                            function_entry,
                            source,
                            target,
                            edge_kind,
                        },
                        RecoveryChoice::SuppressControlFlowEdge,
                    ) => {
                        if program.control_flow.as_ref().is_some_and(|control_flow| {
                            control_flow.by_entry(*function_entry).is_some_and(|graph| {
                                graph.guided_edge_suppressions.iter().any(|suppression| {
                                    suppression.source == *source
                                        && suppression.target == *target
                                        && suppression.edge_kind == *edge_kind
                                })
                            })
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.control_flow_edge_suppressed",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.control_flow_edge_suppression_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::DirectCallsite {
                            caller,
                            instruction_address,
                            target_address,
                        },
                        RecoveryChoice::SuppressDirectCall,
                    ) => {
                        if program.control_flow.as_ref().is_some_and(|control_flow| {
                            control_flow.by_entry(*caller).is_some_and(|graph| {
                                graph.guided_direct_call_suppressions.iter().any(|suppression| {
                                    suppression.instruction_address == *instruction_address
                                        && suppression.target_address == *target_address
                                })
                            })
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.direct_call_suppressed",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.direct_call_suppression_ineffective",
                            )
                        }
                    }
                    (
                        ProgramSubjectKey::CrossReference {
                            source,
                            target,
                            reference_kind,
                        },
                        RecoveryChoice::ReferenceOwner { function_entry },
                    ) => {
                        if program.guided_reference_ownerships.iter().any(|ownership| {
                            ownership.source == *source
                                && ownership.target == *target
                                && ownership.reference_kind == *reference_kind
                                && ownership.function_entry == *function_entry
                        }) {
                            (
                                RecoveryDecisionApplicationStatus::Applied,
                                "recovery_guide.reference_owner_applied",
                            )
                        } else {
                            (
                                RecoveryDecisionApplicationStatus::Ineffective,
                                "recovery_guide.reference_owner_ineffective",
                            )
                        }
                    }
                    (_, RecoveryChoice::KeepUnresolved) => (
                        RecoveryDecisionApplicationStatus::Redundant,
                        "recovery_guide.kept_unresolved",
                    ),
                    _ => (
                        RecoveryDecisionApplicationStatus::Ineffective,
                        "recovery_guide.unsupported_application",
                    ),
                }
            };
            RecoveryDecisionApplication {
                decision_index: validated.decision_index,
                status,
                reason: reason.to_owned(),
            }
        })
        .collect();
    let mut suppressed_signals = Vec::new();
    for decision in &guide.decisions {
        if let Some(question) = base
            .questions
            .iter()
            .find(|question| question.key == decision.point)
        {
            for signal in &question.signals {
                if !suppressed_signals.iter().any(
                    |retained: &crate::analysis::recovery::RecoverySignal| {
                        retained.key == signal.key
                    },
                ) {
                    suppressed_signals.push(signal.clone());
                }
            }
        }
    }
    let mut delta = build_recovery_delta(base, program);
    attach_decision_derivations(base, program, guide, &decisions, &mut delta);
    RecoveryGuideApplication {
        validation,
        decisions,
        delta,
        suppressed_signals,
        coverage_delta: ProgramCoverageDelta {
            before: base.coverage(),
            after: program.coverage(),
        },
    }
}

fn byte_role_is_applied(
    bytes: &ExecutableByteIndex,
    section_ordinal: u64,
    start: u64,
    end_exclusive: u64,
    role: ExecutableByteKind,
) -> bool {
    let mut cursor = start;
    for span in bytes.spans().iter().filter(|span| {
        span.section_ordinal == section_ordinal
            && span.start < end_exclusive
            && span.end_exclusive > start
    }) {
        if span.start > cursor
            || span.kind != role
            || !span.evidence.contains(
                &crate::analysis::executable_bytes::ExecutableByteEvidence::CallerDecision,
            )
        {
            return false;
        }
        cursor = cursor.max(span.end_exclusive.min(end_exclusive));
        if cursor == end_exclusive {
            return true;
        }
    }
    false
}

struct DecisionDerivationContext<'a> {
    decision_index: u64,
    decision: &'a RecoveryDecision,
    affected_layers: Vec<RecoveryLayer>,
    affected_functions: BTreeSet<u64>,
}

fn attach_decision_derivations(
    base: &RecoveredProgram,
    guided: &RecoveredProgram,
    guide: &RecoveryGuide,
    applications: &[RecoveryDecisionApplication],
    delta: &mut RecoveryDelta,
) {
    let contexts = guide
        .decisions
        .iter()
        .enumerate()
        .filter_map(|(index, decision)| {
            let decision_index = u64::try_from(index).unwrap_or(u64::MAX);
            let application = applications
                .iter()
                .find(|application| application.decision_index == decision_index)?;
            if application.status != RecoveryDecisionApplicationStatus::Applied {
                return None;
            }
            let affected_layers = base
                .questions
                .iter()
                .find(|question| question.key == decision.point)
                .map_or_else(
                    || authored_affected_layers(decision),
                    |question| question.estimated_effect.affected_layers.clone(),
                );
            Some(DecisionDerivationContext {
                decision_index,
                decision,
                affected_layers,
                affected_functions: affected_functions(base, guided, decision),
            })
        })
        .collect::<Vec<_>>();

    for record in &mut delta.records {
        for context in &contexts {
            if let Some(kind) = narrow_derivation_kind(context, record) {
                record.derivations.push(RecoveryDecisionDerivation {
                    decision_index: context.decision_index,
                    kind,
                });
            }
        }
        if record.derivations.is_empty() {
            for context in &contexts {
                if context.affected_layers.contains(&record.layer) {
                    record.derivations.push(RecoveryDecisionDerivation {
                        decision_index: context.decision_index,
                        kind: RecoveryDecisionDerivationKind::AffectedLayer,
                    });
                }
            }
        }
        record.derivations.sort();
        record.derivations.dedup();
    }
    delta.records.sort();
}

fn authored_affected_layers(decision: &RecoveryDecision) -> Vec<RecoveryLayer> {
    match decision.point.kind {
        RecoveryQuestionKind::FunctionEntry
        | RecoveryQuestionKind::FunctionRelationship
        | RecoveryQuestionKind::FunctionRanges
        | RecoveryQuestionKind::RangeOwnership => vec![
            RecoveryLayer::Functions,
            RecoveryLayer::ExecutableBytes,
            RecoveryLayer::ControlFlow,
            RecoveryLayer::Calls,
            RecoveryLayer::References,
            RecoveryLayer::ValueFlow,
            RecoveryLayer::Semantics,
        ],
        RecoveryQuestionKind::InstructionBoundary | RecoveryQuestionKind::ByteRole => vec![
            RecoveryLayer::ExecutableBytes,
            RecoveryLayer::Functions,
            RecoveryLayer::ControlFlow,
            RecoveryLayer::Calls,
            RecoveryLayer::References,
            RecoveryLayer::ValueFlow,
            RecoveryLayer::Semantics,
        ],
        RecoveryQuestionKind::ControlFlowEdge | RecoveryQuestionKind::NonReturningCall => vec![
            RecoveryLayer::ControlFlow,
            RecoveryLayer::Calls,
            RecoveryLayer::References,
            RecoveryLayer::ValueFlow,
            RecoveryLayer::Semantics,
        ],
        RecoveryQuestionKind::DirectCall => vec![
            RecoveryLayer::Functions,
            RecoveryLayer::ControlFlow,
            RecoveryLayer::ExecutableBytes,
            RecoveryLayer::Calls,
            RecoveryLayer::References,
            RecoveryLayer::ValueFlow,
            RecoveryLayer::Semantics,
        ],
        RecoveryQuestionKind::ReferenceOwnership => vec![RecoveryLayer::References],
        RecoveryQuestionKind::IndirectTargets | RecoveryQuestionKind::RuntimeDispatch => {
            vec![RecoveryLayer::Calls, RecoveryLayer::ValueFlow]
        }
        RecoveryQuestionKind::FunctionAbi => vec![
            RecoveryLayer::Calls,
            RecoveryLayer::ValueFlow,
            RecoveryLayer::Semantics,
        ],
        RecoveryQuestionKind::DependencyImage => Vec::new(),
    }
}

fn narrow_derivation_kind(
    context: &DecisionDerivationContext<'_>,
    record: &RecoveryDeltaRecord,
) -> Option<RecoveryDecisionDerivationKind> {
    if context.decision.point.subject == record.subject {
        return Some(RecoveryDecisionDerivationKind::DirectSubject);
    }
    if let (
        ProgramSubjectKey::CrossReference {
            source: decision_source,
            target: decision_target,
            reference_kind: decision_kind,
        },
        ProgramSubjectKey::ReferenceOwnership {
            source,
            target,
            reference_kind,
            ..
        },
    ) = (&context.decision.point.subject, &record.subject)
        && decision_source == source
        && decision_target == target
        && decision_kind == reference_kind
    {
        return Some(RecoveryDecisionDerivationKind::DirectSubject);
    }
    if matches!(
        context.decision.point.subject,
        ProgramSubjectKey::ExecutableByteRange { .. }
            | ProgramSubjectKey::FunctionRange { .. }
            | ProgramSubjectKey::SuppressedFunctionEntry { .. }
    ) {
        if let (Some(decision_range), Some(record_range)) = (
            subject_range(&context.decision.point.subject),
            subject_range(&record.subject),
        ) {
            if ranges_overlap(decision_range, record_range) {
                return Some(RecoveryDecisionDerivationKind::OverlappingRange);
            }
        }
    }
    if subject_function_entries(&record.subject)
        .iter()
        .any(|entry| context.affected_functions.contains(entry))
    {
        return Some(RecoveryDecisionDerivationKind::FunctionDependency);
    }
    None
}

fn affected_functions(
    base: &RecoveredProgram,
    guided: &RecoveredProgram,
    decision: &RecoveryDecision,
) -> BTreeSet<u64> {
    let mut entries = BTreeSet::new();
    match (&decision.point.subject, &decision.choice) {
        (
            ProgramSubjectKey::FunctionCandidate { address },
            RecoveryChoice::FunctionRelationship { owner_entry, .. },
        ) => {
            entries.insert(*address);
            entries.insert(*owner_entry);
        }
        (ProgramSubjectKey::FunctionCandidate { address }, _) => {
            entries.insert(*address);
            for program in [base, guided] {
                if let Some(candidate) = program.functions.as_ref().and_then(|functions| {
                    functions
                        .entry_candidates()
                        .iter()
                        .find(|candidate| candidate.address == *address)
                }) {
                    entries.extend(candidate.possible_owners.iter().map(|owner| owner.entry));
                }
            }
        }
        (ProgramSubjectKey::Function { entry }, RecoveryChoice::FunctionRanges { .. }) => {
            entries.insert(*entry);
        }
        (
            ProgramSubjectKey::ExecutableByteRange {
                start,
                end_exclusive,
                ..
            },
            _,
        ) => {
            let guided_range = (*start, *end_exclusive);
            for program in [base, guided] {
                if let Some(functions) = &program.functions {
                    for function in functions.functions() {
                        let overlaps = function.extent.is_some_and(|extent| {
                            ranges_overlap(guided_range, (extent.start, extent.end_exclusive))
                        }) || (*start..*end_exclusive).contains(&function.entry);
                        if overlaps {
                            entries.insert(function.entry);
                        }
                    }
                }
                if let Some(control_flow) = &program.control_flow {
                    for graph in control_flow.functions() {
                        if graph.jump_tables.iter().any(|table| {
                            ranges_overlap(guided_range, (table.table_address, table.end_exclusive))
                        }) {
                            entries.insert(graph.function_entry);
                        }
                    }
                }
            }
        }
        (ProgramSubjectKey::ControlFlowEdge { function_entry, .. }, _)
        | (
            ProgramSubjectKey::DirectCallsite {
                caller: function_entry,
                ..
            },
            _,
        ) => {
            entries.insert(*function_entry);
        }
        (
            ProgramSubjectKey::CrossReference { .. },
            RecoveryChoice::ReferenceOwner { function_entry },
        ) => {
            entries.insert(*function_entry);
        }
        _ => {}
    }
    entries
}

fn subject_range(subject: &ProgramSubjectKey) -> Option<(u64, u64)> {
    match subject {
        ProgramSubjectKey::ExecutableByteRange {
            start,
            end_exclusive,
            ..
        }
        | ProgramSubjectKey::FunctionRange {
            start,
            end_exclusive,
            ..
        }
        | ProgramSubjectKey::SuppressedFunctionEntry {
            range_start: start,
            range_end_exclusive: end_exclusive,
            ..
        }
        | ProgramSubjectKey::JumpTable {
            table_address: start,
            end_exclusive,
            ..
        } => Some((*start, *end_exclusive)),
        ProgramSubjectKey::Instruction { address, byte_len }
        | ProgramSubjectKey::InstructionInterpretation {
            address, byte_len, ..
        } => address
            .checked_add(u64::from(*byte_len))
            .map(|end| (*address, end)),
        ProgramSubjectKey::Function { entry }
        | ProgramSubjectKey::FunctionSignature {
            function_entry: entry,
        }
        | ProgramSubjectKey::StackFrame {
            function_entry: entry,
        }
        | ProgramSubjectKey::FunctionCandidate { address: entry }
        | ProgramSubjectKey::BasicBlock { start: entry, .. }
        | ProgramSubjectKey::DataObject { address: entry } => {
            entry.checked_add(1).map(|end| (*entry, end))
        }
        ProgramSubjectKey::FunctionRelationship { address, .. }
        | ProgramSubjectKey::DirectTransfer {
            instruction_address: address,
            ..
        }
        | ProgramSubjectKey::IndirectTransfer {
            instruction_address: address,
            ..
        }
        | ProgramSubjectKey::CrossReference {
            source: address, ..
        }
        | ProgramSubjectKey::ReferenceOwnership {
            source: address, ..
        } => address.checked_add(1).map(|end| (*address, end)),
        ProgramSubjectKey::ControlFlowEdge { source, .. } => {
            source.checked_add(1).map(|end| (*source, end))
        }
        ProgramSubjectKey::DirectCallsite {
            instruction_address,
            ..
        } => instruction_address
            .checked_add(1)
            .map(|end| (*instruction_address, end)),
        ProgramSubjectKey::DirectCall { .. }
        | ProgramSubjectKey::LocalVariable { .. }
        | ProgramSubjectKey::Conflict { .. }
        | ProgramSubjectKey::Frontier { .. } => None,
    }
}

fn subject_function_entries(subject: &ProgramSubjectKey) -> Vec<u64> {
    match subject {
        ProgramSubjectKey::Function { entry }
        | ProgramSubjectKey::FunctionRange {
            function_entry: entry,
            ..
        }
        | ProgramSubjectKey::BasicBlock {
            function_entry: entry,
            ..
        }
        | ProgramSubjectKey::ControlFlowEdge {
            function_entry: entry,
            ..
        }
        | ProgramSubjectKey::DirectCallsite { caller: entry, .. }
        | ProgramSubjectKey::DirectTransfer {
            function_entry: entry,
            ..
        }
        | ProgramSubjectKey::IndirectTransfer {
            function_entry: entry,
            ..
        }
        | ProgramSubjectKey::SuppressedFunctionEntry { entry, .. } => vec![*entry],
        ProgramSubjectKey::FunctionSignature { function_entry }
        | ProgramSubjectKey::StackFrame { function_entry } => vec![*function_entry],
        ProgramSubjectKey::FunctionRelationship {
            address,
            owner_entry,
        } => vec![*address, *owner_entry],
        ProgramSubjectKey::DirectCall { caller, callee } => vec![*caller, *callee],
        ProgramSubjectKey::ReferenceOwnership { function_entry, .. } => vec![*function_entry],
        ProgramSubjectKey::FunctionCandidate { address } => vec![*address],
        ProgramSubjectKey::Instruction { .. }
        | ProgramSubjectKey::InstructionInterpretation { .. }
        | ProgramSubjectKey::JumpTable { .. }
        | ProgramSubjectKey::CrossReference { .. }
        | ProgramSubjectKey::ExecutableByteRange { .. }
        | ProgramSubjectKey::DataObject { .. }
        | ProgramSubjectKey::LocalVariable { .. }
        | ProgramSubjectKey::Conflict { .. }
        | ProgramSubjectKey::Frontier { .. } => Vec::new(),
    }
}

fn ranges_overlap(left: (u64, u64), right: (u64, u64)) -> bool {
    left.0 < right.1 && right.0 < left.1
}

fn build_recovery_delta(base: &RecoveredProgram, guided: &RecoveredProgram) -> RecoveryDelta {
    let mut records = Vec::new();

    if let (Some(base), Some(guided)) = (&base.functions, &guided.functions) {
        compare_record_maps(
            base.functions()
                .iter()
                .map(|function| (function.entry, function))
                .collect(),
            guided
                .functions()
                .iter()
                .map(|function| (function.entry, function))
                .collect(),
            RecoveryLayer::Functions,
            |entry| ProgramSubjectKey::Function { entry: *entry },
            &mut records,
        );
        compare_record_maps(
            base.relationships()
                .iter()
                .map(|relationship| {
                    (
                        (relationship.address, relationship.owner_entry),
                        relationship,
                    )
                })
                .collect(),
            guided
                .relationships()
                .iter()
                .map(|relationship| {
                    (
                        (relationship.address, relationship.owner_entry),
                        relationship,
                    )
                })
                .collect(),
            RecoveryLayer::Functions,
            |(address, owner_entry)| ProgramSubjectKey::FunctionRelationship {
                address: *address,
                owner_entry: *owner_entry,
            },
            &mut records,
        );
        compare_record_maps(
            base.entry_candidates()
                .iter()
                .map(|candidate| (candidate.address, candidate))
                .collect(),
            guided
                .entry_candidates()
                .iter()
                .map(|candidate| (candidate.address, candidate))
                .collect(),
            RecoveryLayer::Functions,
            |address| ProgramSubjectKey::FunctionCandidate { address: *address },
            &mut records,
        );
        compare_record_maps(
            base.suppressed_entries()
                .iter()
                .map(|entry| {
                    (
                        (entry.entry, entry.range_start, entry.range_end_exclusive),
                        entry,
                    )
                })
                .collect(),
            guided
                .suppressed_entries()
                .iter()
                .map(|entry| {
                    (
                        (entry.entry, entry.range_start, entry.range_end_exclusive),
                        entry,
                    )
                })
                .collect(),
            RecoveryLayer::Functions,
            |(entry, range_start, range_end_exclusive)| {
                ProgramSubjectKey::SuppressedFunctionEntry {
                    entry: *entry,
                    range_start: *range_start,
                    range_end_exclusive: *range_end_exclusive,
                }
            },
            &mut records,
        );
    }

    if let (Some(base), Some(guided)) = (&base.control_flow, &guided.control_flow) {
        let base_blocks = base
            .functions()
            .iter()
            .flat_map(|graph| {
                graph
                    .blocks
                    .iter()
                    .map(move |block| ((graph.function_entry, block.start), block))
            })
            .collect();
        let guided_blocks = guided
            .functions()
            .iter()
            .flat_map(|graph| {
                graph
                    .blocks
                    .iter()
                    .map(move |block| ((graph.function_entry, block.start), block))
            })
            .collect();
        compare_record_maps(
            base_blocks,
            guided_blocks,
            RecoveryLayer::ControlFlow,
            |(function_entry, start)| ProgramSubjectKey::BasicBlock {
                function_entry: *function_entry,
                start: *start,
            },
            &mut records,
        );

        let edge_records = |index: &ControlFlowIndex| {
            let mut edges = BTreeMap::new();
            for graph in index.functions() {
                for edge in &graph.edges {
                    let Some(source) = graph
                        .blocks
                        .get(edge.from as usize)
                        .map(|block| block.start)
                    else {
                        continue;
                    };
                    let Some(target) = graph.blocks.get(edge.to as usize).map(|block| block.start)
                    else {
                        continue;
                    };
                    edges.insert(
                        (graph.function_entry, source, target, edge.kind),
                        edge.clone(),
                    );
                }
            }
            edges
        };
        compare_owned_record_maps(
            edge_records(base),
            edge_records(guided),
            RecoveryLayer::ControlFlow,
            |(function_entry, source, target, edge_kind)| ProgramSubjectKey::ControlFlowEdge {
                function_entry: *function_entry,
                source: *source,
                target: *target,
                edge_kind: *edge_kind,
            },
            &mut records,
        );

        let direct_callsites = |index: &ControlFlowIndex| {
            index
                .functions()
                .iter()
                .flat_map(|graph| {
                    graph.calls.iter().filter_map(move |call| {
                        let crate::analysis::control_flow::ControlFlowCallTarget::Direct {
                            address,
                            ..
                        } = &call.target
                        else {
                            return None;
                        };
                        Some((
                            (graph.function_entry, call.instruction_address, *address),
                            call.clone(),
                        ))
                    })
                })
                .collect()
        };
        compare_owned_record_maps(
            direct_callsites(base),
            direct_callsites(guided),
            RecoveryLayer::Calls,
            |(caller, instruction_address, target_address)| ProgramSubjectKey::DirectCallsite {
                caller: *caller,
                instruction_address: *instruction_address,
                target_address: *target_address,
            },
            &mut records,
        );
        compare_record_maps(
            base.functions()
                .iter()
                .flat_map(|graph| {
                    graph.jump_tables.iter().map(move |table| {
                        (
                            (
                                graph.function_entry,
                                table.instruction_address,
                                table.table_address,
                                table.end_exclusive,
                            ),
                            table,
                        )
                    })
                })
                .collect(),
            guided
                .functions()
                .iter()
                .flat_map(|graph| {
                    graph.jump_tables.iter().map(move |table| {
                        (
                            (
                                graph.function_entry,
                                table.instruction_address,
                                table.table_address,
                                table.end_exclusive,
                            ),
                            table,
                        )
                    })
                })
                .collect(),
            RecoveryLayer::ControlFlow,
            |(_, instruction_address, table_address, end_exclusive)| ProgramSubjectKey::JumpTable {
                instruction_address: *instruction_address,
                table_address: *table_address,
                end_exclusive: *end_exclusive,
            },
            &mut records,
        );
    }

    if let (Some(base), Some(guided)) = (&base.executable_bytes, &guided.executable_bytes) {
        compare_executable_bytes(base.spans(), guided.spans(), &mut records);
    }

    if let (Some(base), Some(guided)) = (&base.direct_calls, &guided.direct_calls) {
        compare_record_maps(
            base.edges()
                .iter()
                .map(|edge| ((edge.caller, edge.callee), edge))
                .collect(),
            guided
                .edges()
                .iter()
                .map(|edge| ((edge.caller, edge.callee), edge))
                .collect(),
            RecoveryLayer::Calls,
            |(caller, callee)| ProgramSubjectKey::DirectCall {
                caller: *caller,
                callee: *callee,
            },
            &mut records,
        );
    }

    if let (Some(base), Some(guided)) = (&base.transfers, &guided.transfers) {
        compare_record_maps(
            base.transfers()
                .iter()
                .map(|transfer| {
                    (
                        (
                            transfer.source,
                            transfer.instruction_address,
                            transfer.target_address,
                        ),
                        transfer,
                    )
                })
                .collect(),
            guided
                .transfers()
                .iter()
                .map(|transfer| {
                    (
                        (
                            transfer.source,
                            transfer.instruction_address,
                            transfer.target_address,
                        ),
                        transfer,
                    )
                })
                .collect(),
            RecoveryLayer::Calls,
            |(function_entry, instruction_address, target_address)| {
                ProgramSubjectKey::DirectTransfer {
                    function_entry: *function_entry,
                    instruction_address: *instruction_address,
                    target_address: *target_address,
                }
            },
            &mut records,
        );
    }

    if let (Some(base), Some(guided)) = (&base.indirect_calls, &guided.indirect_calls) {
        compare_record_maps(
            base.calls()
                .iter()
                .map(|call| ((call.source_function, call.instruction_address), call))
                .collect(),
            guided
                .calls()
                .iter()
                .map(|call| ((call.source_function, call.instruction_address), call))
                .collect(),
            RecoveryLayer::Calls,
            |(function_entry, instruction_address)| ProgramSubjectKey::IndirectTransfer {
                function_entry: *function_entry,
                instruction_address: *instruction_address,
            },
            &mut records,
        );
    }

    if let (Some(base), Some(guided)) = (&base.xrefs, &guided.xrefs) {
        compare_record_maps(
            base.all_refs()
                .iter()
                .map(|reference| (xref_delta_key(reference), reference))
                .collect(),
            guided
                .all_refs()
                .iter()
                .map(|reference| (xref_delta_key(reference), reference))
                .collect(),
            RecoveryLayer::References,
            |(source, target, reference_kind)| ProgramSubjectKey::CrossReference {
                source: *source,
                target: target.clone(),
                reference_kind: *reference_kind,
            },
            &mut records,
        );
    }

    compare_record_maps(
        base.guided_reference_ownerships
            .iter()
            .map(|ownership| {
                (
                    (
                        ownership.source,
                        ownership.target.clone(),
                        ownership.reference_kind,
                        ownership.function_entry,
                    ),
                    ownership,
                )
            })
            .collect(),
        guided
            .guided_reference_ownerships
            .iter()
            .map(|ownership| {
                (
                    (
                        ownership.source,
                        ownership.target.clone(),
                        ownership.reference_kind,
                        ownership.function_entry,
                    ),
                    ownership,
                )
            })
            .collect(),
        RecoveryLayer::References,
        |(source, target, reference_kind, function_entry)| ProgramSubjectKey::ReferenceOwnership {
            source: *source,
            target: target.clone(),
            reference_kind: *reference_kind,
            function_entry: *function_entry,
        },
        &mut records,
    );

    if let (Some(base), Some(guided)) = (&base.semantics, &guided.semantics) {
        compare_record_maps(
            base.data_objects()
                .iter()
                .map(|object| ((object.address, object.kind), object))
                .collect(),
            guided
                .data_objects()
                .iter()
                .map(|object| ((object.address, object.kind), object))
                .collect(),
            RecoveryLayer::Semantics,
            |(address, _)| ProgramSubjectKey::DataObject { address: *address },
            &mut records,
        );
        compare_record_maps(
            base.signatures()
                .iter()
                .map(|signature| (signature.function_entry, signature))
                .collect(),
            guided
                .signatures()
                .iter()
                .map(|signature| (signature.function_entry, signature))
                .collect(),
            RecoveryLayer::Semantics,
            |function_entry| ProgramSubjectKey::FunctionSignature {
                function_entry: *function_entry,
            },
            &mut records,
        );
        compare_record_maps(
            base.frames()
                .iter()
                .map(|frame| (frame.function_entry, frame))
                .collect(),
            guided
                .frames()
                .iter()
                .map(|frame| (frame.function_entry, frame))
                .collect(),
            RecoveryLayer::Semantics,
            |function_entry| ProgramSubjectKey::StackFrame {
                function_entry: *function_entry,
            },
            &mut records,
        );
        compare_record_maps(
            base.locals()
                .iter()
                .map(|local| (local.die_offset, local))
                .collect(),
            guided
                .locals()
                .iter()
                .map(|local| (local.die_offset, local))
                .collect(),
            RecoveryLayer::Semantics,
            |die_offset| ProgramSubjectKey::LocalVariable {
                die_offset: *die_offset,
            },
            &mut records,
        );
    }

    compare_questions(&base.questions, &guided.questions, &mut records);
    records.sort();
    records.dedup();
    let mut summary = RecoveryDeltaSummary::default();
    for record in &records {
        match record.kind {
            RecoveryDeltaKind::Added => summary.added += 1,
            RecoveryDeltaKind::Removed => summary.removed += 1,
            RecoveryDeltaKind::Reclassified => summary.reclassified += 1,
            RecoveryDeltaKind::Resolved => summary.resolved += 1,
            RecoveryDeltaKind::NewlyUnresolved => summary.newly_unresolved += 1,
        }
    }
    RecoveryDelta {
        image: guided.image.clone(),
        records,
        summary,
    }
}

fn xref_delta_key(reference: &Xref) -> (u64, RecoveryReferenceTargetKey, RecoveryReferenceKind) {
    let target = match &reference.target {
        XrefTarget::Internal { va } => RecoveryReferenceTargetKey::Internal { address: va.0 },
        XrefTarget::Import { name, ordinal } => RecoveryReferenceTargetKey::Import {
            ordinal: *ordinal,
            name: name.clone(),
        },
    };
    let reference_kind = RecoveryReferenceKind::from(reference.kind);
    (reference.source.0, target, reference_kind)
}

fn compare_record_maps<K, V, F>(
    base: BTreeMap<K, &V>,
    guided: BTreeMap<K, &V>,
    layer: RecoveryLayer,
    subject: F,
    records: &mut Vec<RecoveryDeltaRecord>,
) where
    K: Ord,
    V: PartialEq,
    F: Fn(&K) -> ProgramSubjectKey,
{
    for (key, base_value) in &base {
        match guided.get(key) {
            None => records.push(RecoveryDeltaRecord {
                layer,
                subject: subject(key),
                kind: RecoveryDeltaKind::Removed,
                derivations: Vec::new(),
            }),
            Some(guided_value) if *base_value != *guided_value => {
                records.push(RecoveryDeltaRecord {
                    layer,
                    subject: subject(key),
                    kind: RecoveryDeltaKind::Reclassified,
                    derivations: Vec::new(),
                });
            }
            Some(_) => {}
        }
    }
    for key in guided.keys() {
        if !base.contains_key(key) {
            records.push(RecoveryDeltaRecord {
                layer,
                subject: subject(key),
                kind: RecoveryDeltaKind::Added,
                derivations: Vec::new(),
            });
        }
    }
}

fn compare_owned_record_maps<K, V, F>(
    base: BTreeMap<K, V>,
    guided: BTreeMap<K, V>,
    layer: RecoveryLayer,
    subject: F,
    records: &mut Vec<RecoveryDeltaRecord>,
) where
    K: Ord,
    V: PartialEq,
    F: Fn(&K) -> ProgramSubjectKey,
{
    for (key, base_value) in &base {
        match guided.get(key) {
            None => records.push(RecoveryDeltaRecord {
                layer,
                subject: subject(key),
                kind: RecoveryDeltaKind::Removed,
                derivations: Vec::new(),
            }),
            Some(guided_value) if base_value != guided_value => {
                records.push(RecoveryDeltaRecord {
                    layer,
                    subject: subject(key),
                    kind: RecoveryDeltaKind::Reclassified,
                    derivations: Vec::new(),
                });
            }
            Some(_) => {}
        }
    }
    for key in guided.keys() {
        if !base.contains_key(key) {
            records.push(RecoveryDeltaRecord {
                layer,
                subject: subject(key),
                kind: RecoveryDeltaKind::Added,
                derivations: Vec::new(),
            });
        }
    }
}

fn compare_executable_bytes(
    base: &[ExecutableByteSpan],
    guided: &[ExecutableByteSpan],
    records: &mut Vec<RecoveryDeltaRecord>,
) {
    let sections = base
        .iter()
        .chain(guided)
        .map(|span| span.section_ordinal)
        .collect::<BTreeSet<_>>();
    for section_ordinal in sections {
        let breakpoints = base
            .iter()
            .chain(guided)
            .filter(|span| span.section_ordinal == section_ordinal)
            .flat_map(|span| [span.start, span.end_exclusive])
            .collect::<BTreeSet<_>>();
        let breakpoints = breakpoints.into_iter().collect::<Vec<_>>();
        for bounds in breakpoints.windows(2) {
            let [start, end_exclusive] = [bounds[0], bounds[1]];
            let base_span = covering_span(base, section_ordinal, start, end_exclusive);
            let guided_span = covering_span(guided, section_ordinal, start, end_exclusive);
            let kind = match (base_span, guided_span) {
                (None, None) => continue,
                (None, Some(_)) => RecoveryDeltaKind::Added,
                (Some(_), None) => RecoveryDeltaKind::Removed,
                (Some(base), Some(guided)) if equivalent_byte_class(base, guided) => continue,
                (Some(base), Some(guided))
                    if base.kind == ExecutableByteKind::Unresolved
                        && guided.kind != ExecutableByteKind::Unresolved =>
                {
                    RecoveryDeltaKind::Resolved
                }
                (Some(base), Some(guided))
                    if base.kind != ExecutableByteKind::Unresolved
                        && guided.kind == ExecutableByteKind::Unresolved =>
                {
                    RecoveryDeltaKind::NewlyUnresolved
                }
                (Some(_), Some(_)) => RecoveryDeltaKind::Reclassified,
            };
            records.push(RecoveryDeltaRecord {
                layer: RecoveryLayer::ExecutableBytes,
                subject: ProgramSubjectKey::ExecutableByteRange {
                    section_ordinal,
                    start,
                    end_exclusive,
                },
                kind,
                derivations: Vec::new(),
            });
        }
    }
}

fn covering_span(
    spans: &[ExecutableByteSpan],
    section_ordinal: u64,
    start: u64,
    end_exclusive: u64,
) -> Option<&ExecutableByteSpan> {
    spans.iter().find(|span| {
        span.section_ordinal == section_ordinal
            && span.start <= start
            && span.end_exclusive >= end_exclusive
    })
}

fn equivalent_byte_class(base: &ExecutableByteSpan, guided: &ExecutableByteSpan) -> bool {
    base.kind == guided.kind
        && base.confidence == guided.confidence
        && base.evidence == guided.evidence
}

fn compare_questions(
    base: &[RecoveryQuestion],
    guided: &[RecoveryQuestion],
    records: &mut Vec<RecoveryDeltaRecord>,
) {
    for question in base {
        match guided.iter().find(|guided| guided.key == question.key) {
            None => records.push(RecoveryDeltaRecord {
                layer: question_layer(question.kind),
                subject: question.subject.clone(),
                kind: RecoveryDeltaKind::Resolved,
                derivations: Vec::new(),
            }),
            Some(guided) if guided != question => records.push(RecoveryDeltaRecord {
                layer: question_layer(question.kind),
                subject: question.subject.clone(),
                kind: RecoveryDeltaKind::Reclassified,
                derivations: Vec::new(),
            }),
            Some(_) => {}
        }
    }
    for question in guided {
        if !base.iter().any(|base| base.key == question.key) {
            records.push(RecoveryDeltaRecord {
                layer: question_layer(question.kind),
                subject: question.subject.clone(),
                kind: RecoveryDeltaKind::NewlyUnresolved,
                derivations: Vec::new(),
            });
        }
    }
}

const fn question_layer(kind: RecoveryQuestionKind) -> RecoveryLayer {
    match kind {
        RecoveryQuestionKind::FunctionEntry
        | RecoveryQuestionKind::FunctionRelationship
        | RecoveryQuestionKind::FunctionRanges
        | RecoveryQuestionKind::RangeOwnership
        | RecoveryQuestionKind::FunctionAbi => RecoveryLayer::Functions,
        RecoveryQuestionKind::InstructionBoundary | RecoveryQuestionKind::ByteRole => {
            RecoveryLayer::ExecutableBytes
        }
        RecoveryQuestionKind::ControlFlowEdge | RecoveryQuestionKind::NonReturningCall => {
            RecoveryLayer::ControlFlow
        }
        RecoveryQuestionKind::DirectCall => RecoveryLayer::Calls,
        RecoveryQuestionKind::ReferenceOwnership => RecoveryLayer::References,
        RecoveryQuestionKind::IndirectTargets | RecoveryQuestionKind::RuntimeDispatch => {
            RecoveryLayer::Calls
        }
        RecoveryQuestionKind::DependencyImage => RecoveryLayer::References,
    }
}

const fn function_relationship_kind(
    relationship: crate::analysis::recovery::FunctionRelationshipChoice,
) -> FunctionRelationshipKind {
    match relationship {
        crate::analysis::recovery::FunctionRelationshipChoice::AlternateEntry => {
            FunctionRelationshipKind::AlternateEntry
        }
        crate::analysis::recovery::FunctionRelationshipChoice::ColdFragment => {
            FunctionRelationshipKind::ColdFragment
        }
        crate::analysis::recovery::FunctionRelationshipChoice::SharedRange => {
            FunctionRelationshipKind::SharedRange
        }
    }
}

fn program_completeness(
    image: &FunctionImageIdentity,
    request: &ProgramRecoveryRequest,
    facts: ProgramFacts<'_>,
) -> ProgramRecoveryCompleteness {
    let ProgramFacts {
        image_layout,
        pointers,
        symbols,
        strings,
        objc,
        swift,
        dwarf,
        functions,
        control_flow,
        executable_bytes,
        direct_calls,
        transfers,
        indirect_calls,
        xrefs,
        guided_reference_ownerships: _,
        rtti,
        exceptions,
        dependencies,
        semantics,
    } = facts;
    let requested = |stage| request.requested.contains(&stage);
    let mut stages = Vec::new();
    if let Some(layout) = image_layout {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::ImageLayout,
            requested: requested(ProgramRecoveryStage::ImageLayout),
            status: if layout.completeness().complete {
                ProgramRecoveryStatus::Complete
            } else {
                ProgramRecoveryStatus::Truncated
            },
            reasons: layout.completeness().reasons.clone(),
        });
    }
    if let Some(pointers) = pointers {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Pointers,
            requested: requested(ProgramRecoveryStage::Pointers),
            status: if pointers.completeness().truncated {
                ProgramRecoveryStatus::Truncated
            } else if pointers.completeness().complete {
                ProgramRecoveryStatus::Complete
            } else {
                ProgramRecoveryStatus::Partial
            },
            reasons: pointers.completeness().reasons.clone(),
        });
    }
    if let Some(symbols) = symbols {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Symbols,
            requested: requested(ProgramRecoveryStage::Symbols),
            status: match symbols.status() {
                SymbolInventoryStatus::Complete => ProgramRecoveryStatus::Complete,
                SymbolInventoryStatus::Partial => ProgramRecoveryStatus::Partial,
                SymbolInventoryStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: symbols
                .receipts()
                .iter()
                .filter_map(|receipt| receipt.diagnostic.clone())
                .collect(),
        });
    }
    if let Some(strings) = strings {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Strings,
            requested: requested(ProgramRecoveryStage::Strings),
            status: match strings.status() {
                StringIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                StringIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                StringIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: strings.completeness().reasons.clone(),
        });
    }
    if let Some(objc) = objc {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Objc,
            requested: requested(ProgramRecoveryStage::Objc),
            status: match objc.status() {
                ObjcIndexStatus::Absent | ObjcIndexStatus::Complete => {
                    ProgramRecoveryStatus::Complete
                }
                ObjcIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                ObjcIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: objc.completeness().reasons.clone(),
        });
    }
    if let Some(swift) = swift {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Swift,
            requested: requested(ProgramRecoveryStage::Swift),
            status: match swift.status() {
                SwiftIndexStatus::Absent | SwiftIndexStatus::Complete => {
                    ProgramRecoveryStatus::Complete
                }
                SwiftIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                SwiftIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: swift.completeness().reasons.clone(),
        });
    }
    if let Some(dwarf) = dwarf {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Dwarf,
            requested: requested(ProgramRecoveryStage::Dwarf),
            status: match dwarf.status() {
                DwarfIndexStatus::Absent | DwarfIndexStatus::Complete => {
                    ProgramRecoveryStatus::Complete
                }
                DwarfIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                DwarfIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: dwarf.completeness().reasons.clone(),
        });
    }
    if let Some(functions) = functions {
        let mut receipt = function_receipt(functions);
        receipt.requested = requested(ProgramRecoveryStage::Functions);
        stages.push(receipt);
    }
    if let Some(control_flow) = control_flow {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::ControlFlow,
            requested: requested(ProgramRecoveryStage::ControlFlow),
            status: match control_flow.status() {
                ControlFlowIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                ControlFlowIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                ControlFlowIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: control_flow_reasons(control_flow),
        });
    }
    if let Some(executable_bytes) = executable_bytes {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::ExecutableBytes,
            requested: requested(ProgramRecoveryStage::ExecutableBytes),
            status: match executable_bytes.completeness().status {
                ExecutableByteIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                ExecutableByteIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                ExecutableByteIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: executable_bytes.completeness().reasons.clone(),
        });
    }
    if let Some(direct_calls) = direct_calls {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::DirectCalls,
            requested: requested(ProgramRecoveryStage::DirectCalls),
            status: match direct_calls.status() {
                DirectCallGraphStatus::Complete => ProgramRecoveryStatus::Complete,
                DirectCallGraphStatus::Partial => ProgramRecoveryStatus::Partial,
                DirectCallGraphStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: direct_calls.completeness().reasons.clone(),
        });
    }
    if let Some(transfers) = transfers {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Transfers,
            requested: requested(ProgramRecoveryStage::Transfers),
            status: match transfers.status() {
                TransferIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                TransferIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                TransferIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: transfers.completeness().reasons.clone(),
        });
    }
    if let Some(indirect_calls) = indirect_calls {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::IndirectCalls,
            requested: requested(ProgramRecoveryStage::IndirectCalls),
            status: match indirect_calls.status() {
                IndirectCallIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                IndirectCallIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                IndirectCallIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: indirect_calls.completeness().reasons.clone(),
        });
    }
    if let Some(xrefs) = xrefs {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Xrefs,
            requested: requested(ProgramRecoveryStage::Xrefs),
            status: match xrefs.status() {
                XrefIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                XrefIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                XrefIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: xrefs.completeness().reasons.clone(),
        });
    }
    if let Some(rtti) = rtti {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Rtti,
            requested: requested(ProgramRecoveryStage::Rtti),
            status: match rtti.status() {
                RttiIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                RttiIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                RttiIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: rtti
                .receipts()
                .iter()
                .flat_map(|receipt| receipt.reasons.iter().cloned())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
        });
    }
    if let Some(exceptions) = exceptions {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Exceptions,
            requested: requested(ProgramRecoveryStage::Exceptions),
            status: match exceptions.completeness().status {
                ExceptionIndexStatus::Absent | ExceptionIndexStatus::Complete => {
                    ProgramRecoveryStatus::Complete
                }
                ExceptionIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                ExceptionIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: exceptions.completeness().reasons.clone(),
        });
    }
    if let Some(dependencies) = dependencies {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Dependencies,
            requested: requested(ProgramRecoveryStage::Dependencies),
            status: match dependencies.completeness().status {
                DependencyIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                DependencyIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                DependencyIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: dependencies.completeness().reasons.clone(),
        });
    }
    if let Some(semantics) = semantics {
        stages.push(ProgramStageReceipt {
            stage: ProgramRecoveryStage::Semantics,
            requested: requested(ProgramRecoveryStage::Semantics),
            status: match semantics.completeness().status {
                SemanticIndexStatus::Complete => ProgramRecoveryStatus::Complete,
                SemanticIndexStatus::Partial => ProgramRecoveryStatus::Partial,
                SemanticIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
            },
            reasons: semantics.completeness().reasons.clone(),
        });
    }

    let status = if stages
        .iter()
        .any(|stage| stage.status == ProgramRecoveryStatus::Truncated)
    {
        ProgramRecoveryStatus::Truncated
    } else if stages
        .iter()
        .any(|stage| stage.status == ProgramRecoveryStatus::Partial)
    {
        ProgramRecoveryStatus::Partial
    } else {
        ProgramRecoveryStatus::Complete
    };
    let reasons = stages
        .iter()
        .filter(|stage| stage.status != ProgramRecoveryStatus::Complete)
        .map(|stage| {
            format!(
                "program.{}_{}",
                stage_name(stage.stage),
                match stage.status {
                    ProgramRecoveryStatus::Partial => "partial",
                    ProgramRecoveryStatus::Truncated => "truncated",
                    ProgramRecoveryStatus::Complete => unreachable!("filtered complete stage"),
                }
            )
        })
        .collect();
    let contracts = stages
        .iter()
        .map(|receipt| {
            stage_contract(
                receipt,
                image_layout,
                pointers,
                symbols,
                strings,
                objc,
                swift,
                dwarf,
                functions,
                control_flow,
                executable_bytes,
                direct_calls,
                transfers,
                indirect_calls,
                xrefs,
                rtti,
                exceptions,
                dependencies,
                semantics,
            )
        })
        .collect();
    let named_dependencies = dependencies
        .into_iter()
        .flat_map(DependencyIndex::dependencies)
        .map(|dependency| dependency.install_name.clone())
        .collect();
    let runtime_frontiers = dependencies
        .into_iter()
        .flat_map(DependencyIndex::frontiers)
        .map(|frontier| frontier.reason.clone())
        .collect();
    ProgramRecoveryCompleteness {
        schema_version: PROGRAM_COMPLETENESS_SCHEMA_VERSION,
        examined_universe: ProgramExaminedUniverse {
            image: image.clone(),
            stages: request.resolved().into_iter().collect(),
            named_dependencies,
            runtime_frontiers,
        },
        status,
        stages,
        reasons,
        contracts,
    }
}

#[allow(clippy::too_many_arguments)]
fn stage_contract(
    receipt: &ProgramStageReceipt,
    image_layout: Option<&ImageLayoutIndex>,
    pointers: Option<&PointerIndex>,
    symbols: Option<&SymbolInventory>,
    strings: Option<&StringIndex>,
    objc: Option<&ObjcIndex>,
    swift: Option<&SwiftIndex>,
    dwarf: Option<&DwarfIndex>,
    functions: Option<&FunctionIndex>,
    control_flow: Option<&ControlFlowIndex>,
    executable_bytes: Option<&ExecutableByteIndex>,
    direct_calls: Option<&DirectCallGraph>,
    transfers: Option<&DirectTransferIndex>,
    indirect_calls: Option<&IndirectCallIndex>,
    xrefs: Option<&XrefIndex>,
    rtti: Option<&RttiIndex>,
    exceptions: Option<&ExceptionIndex>,
    dependencies: Option<&DependencyIndex>,
    semantics: Option<&SemanticIndex>,
) -> ProgramStageContract {
    let (included, unknown, rejected, budget_excluded, continuation, conflicts, locally_complete) =
        match receipt.stage {
            ProgramRecoveryStage::ImageLayout => {
                let index = image_layout.expect("layout receipt has index");
                let item = index.completeness();
                let retained = index.segments().len() as u64 + index.sections().len() as u64;
                let observed = item
                    .observed_segments
                    .saturating_add(item.observed_sections);
                (
                    retained,
                    0,
                    0,
                    observed.saturating_sub(retained),
                    (!item.complete).then(|| format!("layout_record:{retained}")),
                    0,
                    item.complete,
                )
            }
            ProgramRecoveryStage::Pointers => {
                let item = pointers.expect("pointer receipt has index").completeness();
                (
                    item.retained,
                    u64::from(!item.complete && !item.truncated),
                    0,
                    u64::from(item.truncated),
                    item.truncated.then(|| format!("pointer:{}", item.retained)),
                    0,
                    item.complete,
                )
            }
            ProgramRecoveryStage::Symbols => {
                let index = symbols.expect("symbol receipt has index");
                let included = index.receipts().iter().map(|item| item.retained).sum();
                let unknown = index
                    .receipts()
                    .iter()
                    .filter(|item| {
                        matches!(
                            item.status,
                            crate::analysis::symbol_inventory::SymbolCollectorStatus::Failed
                        )
                    })
                    .count() as u64;
                let excluded = index.receipts().iter().map(|item| item.omitted).sum();
                (
                    included,
                    unknown,
                    0,
                    excluded,
                    (excluded != 0).then(|| format!("symbol:{included}")),
                    0,
                    index.status() == SymbolInventoryStatus::Complete,
                )
            }
            ProgramRecoveryStage::Strings => {
                let index = strings.expect("string receipt has index");
                let item = index.completeness();
                let included = item.observed_strings.saturating_sub(item.omitted_strings);
                (
                    included,
                    u64::from(item.status == StringIndexStatus::Partial),
                    0,
                    item.omitted_strings
                        .max(u64::from(item.status == StringIndexStatus::Truncated)),
                    (item.status == StringIndexStatus::Truncated)
                        .then(|| format!("string:{included}")),
                    0,
                    item.status == StringIndexStatus::Complete,
                )
            }
            ProgramRecoveryStage::Objc => {
                let index = objc.expect("Objective-C receipt has index");
                let item = index.completeness();
                let truncated = index.status() == ObjcIndexStatus::Truncated;
                (
                    item.included,
                    item.unknown,
                    if truncated { 0 } else { item.excluded },
                    if truncated { item.excluded.max(1) } else { 0 },
                    truncated.then(|| format!("objc:{}", item.included)),
                    0,
                    matches!(
                        index.status(),
                        ObjcIndexStatus::Absent | ObjcIndexStatus::Complete
                    ),
                )
            }
            ProgramRecoveryStage::Swift => {
                let index = swift.expect("Swift receipt has index");
                let item = index.completeness();
                let truncated = index.status() == SwiftIndexStatus::Truncated;
                (
                    item.included,
                    item.unknown,
                    if truncated { 0 } else { item.excluded },
                    if truncated { item.excluded.max(1) } else { 0 },
                    truncated.then(|| format!("swift:{}", item.included)),
                    0,
                    matches!(
                        index.status(),
                        SwiftIndexStatus::Absent | SwiftIndexStatus::Complete
                    ),
                )
            }
            ProgramRecoveryStage::Dwarf => {
                let index = dwarf.expect("DWARF receipt has index");
                let item = index.completeness();
                let included = item.sections
                    + item.units
                    + item.entries
                    + item.attributes
                    + item.line_rows
                    + item.range_entries;
                let truncated = index.status() == DwarfIndexStatus::Truncated;
                (
                    included,
                    u64::from(index.status() == DwarfIndexStatus::Partial),
                    0,
                    u64::from(truncated),
                    truncated.then(|| format!("dwarf:{included}")),
                    0,
                    matches!(
                        index.status(),
                        DwarfIndexStatus::Absent | DwarfIndexStatus::Complete
                    ),
                )
            }
            ProgramRecoveryStage::Functions => {
                let index = functions.expect("function receipt has index");
                let rejected = index.entry_candidates().iter().filter(|candidate| matches!(candidate.disposition, crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedByCaller | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedNonExecutableTarget | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedRecoveredData | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedImportStub | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation)).count() as u64;
                let unknown = index.entry_candidates().len() as u64 - rejected;
                (
                    index.functions().len() as u64,
                    unknown,
                    rejected,
                    index.truncated_function_count(),
                    None,
                    index
                        .functions()
                        .iter()
                        .map(|function| function.conflicts.len() as u64)
                        .sum(),
                    index
                        .functions()
                        .iter()
                        .all(|function| function.completeness.locally_complete),
                )
            }
            ProgramRecoveryStage::ControlFlow => {
                let index = control_flow.expect("CFG receipt has index");
                let unknown = index
                    .functions()
                    .iter()
                    .filter(|graph| graph.completeness.status == FunctionControlFlowStatus::Partial)
                    .count() as u64;
                let excluded = index.truncated_function_count()
                    + index
                        .functions()
                        .iter()
                        .filter(|graph| {
                            graph.completeness.status == FunctionControlFlowStatus::Truncated
                        })
                        .count() as u64;
                (
                    index.functions().len() as u64,
                    unknown,
                    0,
                    excluded,
                    index
                        .continuation()
                        .map(|coordinate| format!("{coordinate:?}")),
                    0,
                    index.functions().iter().all(|graph| {
                        graph.completeness.status == FunctionControlFlowStatus::Complete
                    }),
                )
            }
            ProgramRecoveryStage::ExecutableBytes => {
                let index = executable_bytes.expect("byte receipt has index");
                (
                    index.completeness().classified_bytes,
                    index.completeness().unresolved_bytes,
                    0,
                    index
                        .completeness()
                        .observed_bytes
                        .saturating_sub(index.completeness().classified_bytes),
                    index
                        .completeness()
                        .next_unexamined_address
                        .map(|address| format!("address:{address:#x}")),
                    0,
                    index.completeness().status == ExecutableByteIndexStatus::Complete,
                )
            }
            ProgramRecoveryStage::DirectCalls => {
                let index = direct_calls.expect("call receipt has index");
                let item = index.completeness();
                (
                    item.retained_direct_callsite_count
                        .saturating_add(item.external_callsite_count),
                    item.unresolved_callsite_count
                        .saturating_sub(item.non_direct_callsite_count),
                    item.non_direct_callsite_count,
                    item.omitted_direct_callsite_count
                        .saturating_add(item.omitted_unresolved_callsite_count),
                    if item.omitted_node_count != 0 {
                        Some(format!("node:{}", index.nodes().len()))
                    } else if item.omitted_direct_callsite_count != 0 {
                        Some(format!(
                            "direct_callsite:{}",
                            item.retained_direct_callsite_count
                        ))
                    } else if item.omitted_unresolved_callsite_count != 0 {
                        Some(format!(
                            "unresolved_callsite:{}",
                            item.unresolved_callsite_count
                        ))
                    } else {
                        None
                    },
                    0,
                    index.status() == DirectCallGraphStatus::Complete,
                )
            }
            ProgramRecoveryStage::Transfers => {
                let index = transfers.expect("transfer receipt has index");
                let item = index.completeness();
                (
                    index.transfers().len() as u64,
                    (index.status() == TransferIndexStatus::Partial) as u64,
                    0,
                    item.omitted_function_count
                        + item.omitted_transfer_count
                        + item.omitted_thunk_count
                        + item.omitted_conflict_count,
                    (index.status() == TransferIndexStatus::Truncated)
                        .then(|| format!("transfer:{}", index.transfers().len())),
                    0,
                    index.status() == TransferIndexStatus::Complete,
                )
            }
            ProgramRecoveryStage::IndirectCalls => {
                let index = indirect_calls.expect("indirect receipt has index");
                let item = index.completeness();
                (
                    index.calls().len() as u64,
                    index
                        .calls()
                        .iter()
                        .filter(|call| call.status == IndirectCallSiteStatus::Partial)
                        .count() as u64,
                    0,
                    item.omitted_function_count
                        .saturating_add(item.omitted_transfer_count)
                        .saturating_add(item.omitted_candidate_count),
                    item.value_flow_continuation_function
                        .map(|entry| format!("function:{entry:#x}")),
                    index
                        .calls()
                        .iter()
                        .map(|call| call.conflicts.len() as u64)
                        .sum(),
                    index
                        .calls()
                        .iter()
                        .all(|call| call.status == IndirectCallSiteStatus::Complete),
                )
            }
            ProgramRecoveryStage::Xrefs => {
                let index = xrefs.expect("xref receipt has index");
                let item = index.completeness();
                (
                    index.all_refs().len() as u64,
                    (index.status() == XrefIndexStatus::Partial) as u64,
                    0,
                    (index.status() == XrefIndexStatus::Truncated) as u64,
                    (index.status() == XrefIndexStatus::Truncated)
                        .then(|| format!("xref:{}", item.retained_refs)),
                    0,
                    index.status() == XrefIndexStatus::Complete,
                )
            }
            ProgramRecoveryStage::Rtti => {
                let index = rtti.expect("RTTI receipt has index");
                let included = index
                    .receipts()
                    .iter()
                    .map(|item| item.conservation.included)
                    .sum();
                let unknown = index
                    .receipts()
                    .iter()
                    .map(|item| item.conservation.unknown)
                    .sum();
                let excluded = index
                    .receipts()
                    .iter()
                    .map(|item| item.conservation.excluded)
                    .sum();
                (
                    included,
                    unknown,
                    0,
                    excluded,
                    (excluded != 0).then(|| format!("rtti:{included}")),
                    index.conflicts().len() as u64,
                    index.status() == RttiIndexStatus::Complete,
                )
            }
            ProgramRecoveryStage::Exceptions => {
                let index = exceptions.expect("exception receipt has index");
                let included = index.receipts().iter().map(|item| item.retained).sum();
                let unknown = index.receipts().iter().map(|item| item.unknown).sum();
                let excluded = index.receipts().iter().map(|item| item.excluded).sum();
                (
                    included,
                    unknown,
                    0,
                    excluded,
                    (excluded != 0).then(|| format!("exception:{included}")),
                    0,
                    matches!(
                        index.status(),
                        ExceptionIndexStatus::Absent | ExceptionIndexStatus::Complete
                    ),
                )
            }
            ProgramRecoveryStage::Dependencies => {
                let index = dependencies.expect("dependency receipt has index");
                let item = index.completeness();
                (
                    item.retained,
                    index.frontiers().len() as u64,
                    0,
                    item.observed.saturating_sub(item.retained),
                    item.continuation_ordinal
                        .map(|ordinal| format!("dependency:{ordinal}")),
                    0,
                    item.status == DependencyIndexStatus::Complete,
                )
            }
            ProgramRecoveryStage::Semantics => {
                let index = semantics.expect("semantic receipt has index");
                let item = index.completeness();
                (
                    item.retained,
                    (item.status == SemanticIndexStatus::Partial) as u64,
                    0,
                    item.observed.saturating_sub(item.retained),
                    item.continuation.clone(),
                    0,
                    item.status == SemanticIndexStatus::Complete,
                )
            }
        };
    ProgramStageContract {
        stage: receipt.stage,
        schema_version: PROGRAM_COMPLETENESS_SCHEMA_VERSION,
        included,
        unknown,
        rejected,
        budget_excluded,
        continuation,
        conflicts,
        locally_complete,
        globally_complete: receipt.status == ProgramRecoveryStatus::Complete,
    }
}

const fn stage_name(stage: ProgramRecoveryStage) -> &'static str {
    match stage {
        ProgramRecoveryStage::ImageLayout => "image_layout",
        ProgramRecoveryStage::Pointers => "pointers",
        ProgramRecoveryStage::Symbols => "symbols",
        ProgramRecoveryStage::Strings => "strings",
        ProgramRecoveryStage::Objc => "objc",
        ProgramRecoveryStage::Swift => "swift",
        ProgramRecoveryStage::Dwarf => "dwarf",
        ProgramRecoveryStage::Functions => "functions",
        ProgramRecoveryStage::ControlFlow => "control_flow",
        ProgramRecoveryStage::ExecutableBytes => "executable_bytes",
        ProgramRecoveryStage::DirectCalls => "direct_calls",
        ProgramRecoveryStage::Transfers => "transfers",
        ProgramRecoveryStage::IndirectCalls => "indirect_calls",
        ProgramRecoveryStage::Xrefs => "xrefs",
        ProgramRecoveryStage::Rtti => "rtti",
        ProgramRecoveryStage::Exceptions => "exceptions",
        ProgramRecoveryStage::Dependencies => "dependencies",
        ProgramRecoveryStage::Semantics => "semantics",
    }
}

fn function_receipt(functions: &FunctionIndex) -> ProgramStageReceipt {
    let truncated = functions.truncated_function_count() != 0
        || functions
            .receipts()
            .iter()
            .any(|receipt| receipt.status == FunctionCollectorStatus::Truncated);
    let has_candidate_entries = functions.entry_candidates().iter().any(|candidate| {
        !matches!(
            candidate.disposition,
            crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedByCaller
                | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
            | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedRecoveredData
            | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedImportStub
            | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
            | crate::analysis::functions::FunctionEntryCandidateDisposition::ResolvedByCallerRelationship
        )
    }) || functions.functions().iter().any(|function| {
        function.entry_confidence == crate::analysis::functions::FunctionEvidenceConfidence::Candidate
    });
    let has_caller_guidance = functions.functions().iter().any(|function| {
        function.authority == crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
    }) || functions.entry_candidates().iter().any(|candidate| {
        candidate.disposition
            == crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedByCaller
    }) || !functions.relationships().is_empty()
        || !functions.suppressed_entries().is_empty();
    let has_uncertain_extents = functions
        .functions()
        .iter()
        .any(|function| !function.completeness.extent_is_authoritative);
    let has_conflicts = functions
        .functions()
        .iter()
        .any(|function| !function.conflicts.is_empty());
    let status = if truncated {
        ProgramRecoveryStatus::Truncated
    } else if !functions.inventory_complete()
        || has_candidate_entries
        || has_uncertain_extents
        || has_conflicts
        || has_caller_guidance
    {
        ProgramRecoveryStatus::Partial
    } else {
        ProgramRecoveryStatus::Complete
    };
    let mut reasons = BTreeSet::new();
    if functions.truncated_function_count() != 0 {
        reasons.insert("functions.function_budget".to_owned());
    }
    if has_candidate_entries {
        reasons.insert("functions.candidate_entries".to_owned());
    }
    if has_uncertain_extents {
        reasons.insert("functions.uncertain_extents".to_owned());
    }
    if has_conflicts {
        reasons.insert("functions.evidence_conflicts".to_owned());
    }
    if has_caller_guidance {
        reasons.insert("functions.caller_guided".to_owned());
    }
    for receipt in functions.receipts() {
        match receipt.status {
            FunctionCollectorStatus::Complete | FunctionCollectorStatus::Absent => {}
            FunctionCollectorStatus::Truncated => {
                reasons.insert("functions.source_truncated".to_owned());
            }
            FunctionCollectorStatus::Partial => {
                reasons.insert("functions.source_partial".to_owned());
            }
            FunctionCollectorStatus::Failed => {
                reasons.insert("functions.source_failed".to_owned());
            }
            FunctionCollectorStatus::Unsupported => {
                reasons.insert("functions.source_unsupported".to_owned());
            }
        }
        if let Some(diagnostic) = &receipt.diagnostic {
            reasons.insert(diagnostic.clone());
        }
    }
    ProgramStageReceipt {
        stage: ProgramRecoveryStage::Functions,
        requested: false,
        status,
        reasons: reasons.into_iter().collect(),
    }
}

fn control_flow_reasons(control_flow: &ControlFlowIndex) -> Vec<String> {
    let mut reasons = BTreeSet::new();
    if control_flow.truncated_function_count() != 0 {
        reasons.insert("control_flow.function_budget".to_owned());
    }
    for graph in control_flow.functions() {
        reasons.extend(graph.completeness.reasons.iter().cloned());
    }
    reasons.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::control_flow::FunctionTargetRelation;
    use crate::analysis::functions::{
        FunctionEntryCandidateDisposition, FunctionEvidenceConfidence, FunctionEvidenceSource,
        FunctionIdentity, FunctionRecoveryAuthority, FunctionRelationshipKind,
    };
    use crate::analysis::indirect_calls::IndirectCallTarget;
    use crate::analysis::recovery::{
        FunctionRelationshipChoice, ProgramSubjectKey, RecoveryAddressRange, RecoveryChoice,
        RecoveryContractSchema, RecoveryDecision, RecoveryDecisionApplicability,
        RecoveryDecisionApplicationStatus, RecoveryDeltaError, RecoveryDeltaKind, RecoveryGuide,
        RecoveryGuideApplicability, RecoveryQuestionKind, RecoverySignalKind,
    };
    use crate::analysis::transfers::TransferResolutionStatus;

    const MAIN: u64 = 0x1_0000_0100;
    const THUNK: u64 = 0x1_0000_0120;
    const FINAL: u64 = 0x1_0000_0130;

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    #[test]
    fn versioned_limits_and_completeness_contracts_reject_stale_or_false_claims() {
        let envelope = ProgramRecoveryLimitsFile::current(ProgramRecoveryLimits::default());
        let json = serde_json::to_vec(&envelope).unwrap();
        assert_eq!(
            serde_json::from_slice::<ProgramRecoveryLimitsFile>(&json)
                .unwrap()
                .validate()
                .unwrap(),
            ProgramRecoveryLimits::default()
        );
        assert!(matches!(
            ProgramRecoveryLimitsFile {
                schema_version: PROGRAM_RECOVERY_LIMITS_SCHEMA_VERSION + 1,
                limits: ProgramRecoveryLimits::default(),
            }
            .validate(),
            Err(ProgramRecoveryError::UnsupportedLimitsSchema { .. })
        ));

        let bytes = macho_test_support::disassembly_x86_64();
        let program =
            RecoveredProgram::recover_all(&image(&bytes), ProgramRecoveryLimits::default())
                .unwrap();
        program.completeness().validate().unwrap();
        let mut false_claim = program.completeness().clone();
        false_claim.status = ProgramRecoveryStatus::Complete;
        for stage in &mut false_claim.stages {
            stage.status = ProgramRecoveryStatus::Complete;
        }
        false_claim.contracts[0].unknown = 1;
        false_claim.contracts[0].globally_complete = true;
        assert!(matches!(
            false_claim.validate(),
            Err(ProgramCompletenessValidationError::FalseComplete { .. })
        ));
    }

    #[test]
    fn fact_document_round_trip_is_lossless_strict_and_versioned() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let program =
            RecoveredProgram::recover_all(&macho, ProgramRecoveryLimits::default()).unwrap();
        let document = program.to_fact_document();
        document.validate().unwrap();

        let json = document.to_json_pretty().unwrap();
        let decoded = ProgramFactDocument::load_json(&json).unwrap();
        assert_eq!(decoded, document);
        assert_eq!(RecoveredProgram::from_document(decoded).unwrap(), program);

        let mut unknown: serde_json::Value = serde_json::from_slice(&json).unwrap();
        unknown
            .as_object_mut()
            .unwrap()
            .insert("future_field".to_owned(), serde_json::Value::Bool(true));
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&unknown).unwrap()),
            Err(ProgramFactDocumentError::Json(_))
        ));

        let mut unknown_body: serde_json::Value = serde_json::from_slice(&json).unwrap();
        unknown_body["program"]
            .as_object_mut()
            .unwrap()
            .insert("future_stage".to_owned(), serde_json::Value::Null);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&unknown_body).unwrap()),
            Err(ProgramFactDocumentError::Json(_))
        ));

        let mut unknown_nested: serde_json::Value = serde_json::from_slice(&json).unwrap();
        unknown_nested["program"]["image_layout"]["segments"][0]
            .as_object_mut()
            .unwrap()
            .insert("future_range_fact".to_owned(), serde_json::Value::Null);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&unknown_nested).unwrap()),
            Err(ProgramFactDocumentError::UnknownField { path })
                if path == "$.program.image_layout.segments[0].future_range_fact"
        ));

        let mut future = document.clone();
        future.schema_version += 1;
        assert!(matches!(
            future.validate(),
            Err(ProgramFactValidationError::UnsupportedSchema { .. })
        ));
    }

    #[test]
    fn fact_document_rejects_payload_and_identity_tampering() {
        let bytes = macho_test_support::disassembly_x86_64();
        let program = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Strings],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();

        let mut missing_payload = program.to_fact_document();
        missing_payload.program.strings = None;
        assert_eq!(
            missing_payload.validate(),
            Err(ProgramFactValidationError::StagePayloadMismatch {
                stage: ProgramRecoveryStage::Strings,
            })
        );

        let mut rebound = program.to_fact_document();
        rebound.image.content_sha256 = "0".repeat(64);
        assert_eq!(
            rebound.validate(),
            Err(ProgramFactValidationError::StageImageMismatch {
                stage: ProgramRecoveryStage::Strings,
            })
        );
    }

    #[test]
    fn fact_document_rejects_reordered_query_indexes() {
        let bytes = full_x86_fixture(true);
        let program = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Xrefs],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let refs = value["program"]["xrefs"]["refs"].as_array_mut().unwrap();
        let adjacent = refs
            .windows(2)
            .position(|pair| pair[0]["source"] != pair[1]["source"])
            .expect("fixture must recover references at distinct source addresses");
        refs.swap(adjacent, adjacent + 1);

        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Xrefs,
                }
            ))
        ));

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let functions = value["program"]["functions"]["functions"]
            .as_array_mut()
            .unwrap();
        assert!(functions.len() >= 2);
        functions.swap(0, 1);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Functions,
                }
            ))
        ));

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let graphs = value["program"]["control_flow"]["functions"]
            .as_array_mut()
            .unwrap();
        assert!(graphs.len() >= 2);
        graphs.swap(0, 1);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::ControlFlow,
                }
            ))
        ));

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let graphs = value["program"]["control_flow"]["functions"]
            .as_array_mut()
            .unwrap();
        assert!(!graphs.is_empty());
        graphs[0]["identity"] = serde_json::json!({
            "kind": "anonymous",
            "id": "tampered-control-flow-identity"
        });
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::ControlFlow,
                }
            ))
        ));
    }

    #[test]
    fn fact_document_rejects_corrupt_secondary_lookup_tables() {
        let bytes = x86_string_reference_fixture();
        let strings = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Strings],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        let mut value = serde_json::to_value(strings.to_fact_document()).unwrap();
        let by_reference = value["program"]["strings"]["by_reference"]
            .as_array_mut()
            .unwrap();
        assert!(!by_reference.is_empty());
        by_reference[0] = serde_json::Value::from(u64::MAX);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Strings,
                }
            ))
        ));

        let bytes = full_x86_fixture(true);
        let symbols = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Symbols],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        let mut value = serde_json::to_value(symbols.to_fact_document()).unwrap();
        let by_address = value["program"]["symbols"]["by_address"]
            .as_array_mut()
            .unwrap();
        assert!(!by_address.is_empty());
        by_address[0] = serde_json::Value::from(u64::MAX);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Symbols,
                }
            ))
        ));
    }

    #[test]
    fn fact_document_rejects_corrupt_language_receipts() {
        let bytes = full_x86_fixture(true);
        let program = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Objc, ProgramRecoveryStage::Swift],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        value["program"]["objc"]["completeness"]["attempted"] = serde_json::Value::from(u64::MAX);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Objc,
                }
            ))
        ));

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        value["program"]["swift"]["completeness"]["included"] = serde_json::Value::from(u64::MAX);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Swift,
                }
            ))
        ));
    }

    #[test]
    fn fact_document_rejects_corrupt_derived_stage_receipts() {
        let bytes = full_x86_fixture(true);
        let program =
            RecoveredProgram::recover_all(&image(&bytes), ProgramRecoveryLimits::default())
                .unwrap();

        for (stage, field, receipt_field) in [
            (ProgramRecoveryStage::Dwarf, "dwarf", "sections"),
            (
                ProgramRecoveryStage::ExecutableBytes,
                "executable_bytes",
                "classified_bytes",
            ),
            (
                ProgramRecoveryStage::DirectCalls,
                "direct_calls",
                "retained_direct_callsite_count",
            ),
            (
                ProgramRecoveryStage::Transfers,
                "transfers",
                "observed_transfer_count",
            ),
            (
                ProgramRecoveryStage::IndirectCalls,
                "indirect_calls",
                "observed_transfer_count",
            ),
            (ProgramRecoveryStage::Exceptions, "exceptions", "retained"),
            (
                ProgramRecoveryStage::Dependencies,
                "dependencies",
                "retained",
            ),
            (ProgramRecoveryStage::Semantics, "semantics", "retained"),
        ] {
            let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
            value["program"][field]["completeness"][receipt_field] =
                serde_json::Value::from(u64::MAX);
            assert!(matches!(
                ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
                Err(ProgramFactDocumentError::Validation(
                    ProgramFactValidationError::StagePayloadInvariant {
                        stage: invalid_stage,
                    }
                )) if invalid_stage == stage
            ));
        }

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        value["program"]["rtti"]["receipts"][0]["conservation"]["attempted"] =
            serde_json::Value::from(u64::MAX);
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant {
                    stage: ProgramRecoveryStage::Rtti,
                }
            ))
        ));
    }

    #[test]
    fn fact_document_rejects_derived_payloads_rebound_from_their_sources() {
        let bytes = full_x86_fixture(true);
        let program =
            RecoveredProgram::recover_all(&image(&bytes), ProgramRecoveryLimits::default())
                .unwrap();

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let spans = value["program"]["executable_bytes"]["spans"]
            .as_array_mut()
            .unwrap();
        assert!(!spans.is_empty());
        spans[0]["segment"] = serde_json::Value::String("__REBOUND".to_owned());
        assert_stage_payload_invariant(value, ProgramRecoveryStage::ExecutableBytes);

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let nodes = value["program"]["direct_calls"]["nodes"]
            .as_array_mut()
            .unwrap();
        assert!(!nodes.is_empty());
        nodes[0]["identity"] = serde_json::json!({
            "kind": "anonymous",
            "id": "rebound-direct-call-node"
        });
        assert_stage_payload_invariant(value, ProgramRecoveryStage::DirectCalls);

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        value["program"]["transfers"]["function_entries"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::Value::from(u64::MAX));
        assert_stage_payload_invariant(value, ProgramRecoveryStage::Transfers);

        let mut value = serde_json::to_value(program.to_fact_document()).unwrap();
        let calls = value["program"]["indirect_calls"]["calls"]
            .as_array_mut()
            .unwrap();
        assert!(!calls.is_empty());
        calls[0]["block"] = serde_json::Value::from(u64::MAX);
        assert_stage_payload_invariant(value, ProgramRecoveryStage::IndirectCalls);
    }

    fn assert_stage_payload_invariant(
        value: serde_json::Value,
        expected_stage: ProgramRecoveryStage,
    ) {
        assert!(matches!(
            ProgramFactDocument::load_json(&serde_json::to_vec(&value).unwrap()),
            Err(ProgramFactDocumentError::Validation(
                ProgramFactValidationError::StagePayloadInvariant { stage }
            )) if stage == expected_stage
        ));
    }

    #[test]
    fn refine_and_deepen_are_identity_bound_immutable_transitions() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let prior = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Strings, ProgramRecoveryStage::Symbols],
                limits,
            ),
        )
        .unwrap();

        let empty = RecoveryGuide::new(prior.image().clone());
        let refined_transition =
            RecoveredProgram::refine_with_reuse_receipt(&macho, &prior, &empty).unwrap();
        assert_eq!(
            refined_transition.reuse_receipt().schema_version(),
            PROGRAM_RECOVERY_REUSE_RECEIPT_VERSION
        );
        assert_eq!(
            refined_transition.reuse_receipt().reused_stages(),
            prior.executed_stages()
        );
        assert!(
            refined_transition
                .reuse_receipt()
                .rebuilt_stages()
                .is_empty()
        );
        let receipt_json = serde_json::to_value(refined_transition.reuse_receipt()).unwrap();
        assert_eq!(
            receipt_json["schema_version"],
            serde_json::Value::from(PROGRAM_RECOVERY_REUSE_RECEIPT_VERSION)
        );
        assert_eq!(
            receipt_json["reused_stages"],
            serde_json::json!(["symbols", "strings"])
        );
        let refined = refined_transition.into_program();
        assert_eq!(refined.request(), prior.request());
        assert_eq!(refined.strings(), prior.strings());
        assert_eq!(refined.guide(), Some(&empty));
        assert!(refined.guide_application().is_some());
        refined.to_fact_document().validate().unwrap();
        assert!(
            serde_json::to_value(refined.to_fact_document())
                .unwrap()
                .get("reuse_receipt")
                .is_none()
        );

        let deepened_transition = prior
            .deepen_with_reuse_receipt(&macho, [ProgramRecoveryStage::Functions], None)
            .unwrap();
        assert!(
            deepened_transition
                .reuse_receipt()
                .reused_stages()
                .contains(&ProgramRecoveryStage::Strings)
        );
        assert!(
            deepened_transition
                .reuse_receipt()
                .rebuilt_stages()
                .contains(&ProgramRecoveryStage::Functions)
        );
        let deepened = deepened_transition.into_program();
        assert!(
            deepened
                .request()
                .requested()
                .contains(&ProgramRecoveryStage::Strings)
        );
        assert!(
            deepened
                .request()
                .requested()
                .contains(&ProgramRecoveryStage::Functions)
        );
        assert_ne!(
            deepened.stage_status(ProgramRecoveryStage::Functions),
            ProgramStageStatus::Absent
        );
        assert_eq!(
            deepened.stage_status(ProgramRecoveryStage::Strings),
            prior.stage_status(ProgramRecoveryStage::Strings)
        );
        let cold_deepened = RecoveredProgram::recover(&macho, deepened.request().clone()).unwrap();
        assert_eq!(
            deepened, cold_deepened,
            "stage reuse must be exactly equivalent to cold deepening"
        );

        let dirty = dependent_stage_closure(
            [ProgramRecoveryStage::Functions],
            &ProgramRecoveryRequest::all(limits).resolved(),
        );
        assert!(dirty.contains(&ProgramRecoveryStage::Functions));
        assert!(dirty.contains(&ProgramRecoveryStage::ControlFlow));
        assert!(dirty.contains(&ProgramRecoveryStage::Semantics));
        assert!(!dirty.contains(&ProgramRecoveryStage::Pointers));
        assert!(!dirty.contains(&ProgramRecoveryStage::Strings));

        let mut changed_limits = limits;
        changed_limits.strings.max_strings = 1;
        assert!(!stage_limits_equal(
            ProgramRecoveryStage::Strings,
            limits,
            changed_limits
        ));
        assert!(stage_limits_equal(
            ProgramRecoveryStage::Symbols,
            limits,
            changed_limits
        ));
        let limited = prior.deepen(&macho, [], Some(changed_limits)).unwrap();
        let cold_limited = RecoveredProgram::recover(&macho, limited.request().clone()).unwrap();
        assert_eq!(
            limited, cold_limited,
            "a granular limit override must preserve cold-recovery equivalence"
        );

        let functions_only = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new([ProgramRecoveryStage::Functions], limits),
        )
        .unwrap();
        let symbol_enriched = functions_only
            .deepen(&macho, [ProgramRecoveryStage::Symbols], None)
            .unwrap();
        let cold_symbol_enriched =
            RecoveredProgram::recover(&macho, symbol_enriched.request().clone()).unwrap();
        assert_eq!(
            symbol_enriched, cold_symbol_enriched,
            "adding optional symbol evidence must invalidate its function consumers"
        );

        let mut changed_bytes = bytes;
        changed_bytes[0x100] ^= 1;
        let changed = image(&changed_bytes);
        assert_eq!(
            RecoveredProgram::refine(&changed, &prior, &empty),
            Err(ProgramRecoveryError::ProgramImageMismatch)
        );
        assert_eq!(
            prior.deepen(&changed, [ProgramRecoveryStage::Functions], None),
            Err(ProgramRecoveryError::ProgramImageMismatch)
        );
    }

    fn add_three_function_starts(bytes: &mut Vec<u8>) {
        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        let starts = [0x80, 0x02, 0x20, 0x10, 0x00];
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x26_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16]
            .copy_from_slice(&(starts.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&starts);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    }

    fn full_x86_fixture(with_names: bool) -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x158..0x160].copy_from_slice(&THUNK.to_le_bytes());
        bytes[0x100..0x112].copy_from_slice(&[
            0xe8, 0x1b, 0x00, 0x00, 0x00, // call THUNK
            0x48, 0xb8, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax, FINAL
            0xff, 0xd0, // call rax
            0xc3, // ret
        ]);
        bytes[0x120..0x125].copy_from_slice(&[0xe9, 0x0b, 0x00, 0x00, 0x00]);
        bytes[0x130] = 0xc3;
        add_three_function_starts(&mut bytes);
        if !with_names {
            bytes[0x161..0x16f].fill(0);
        }
        bytes
    }

    fn x86_string_reference_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0xa8..0xac].copy_from_slice(&0x8000_0002_u32.to_le_bytes());
        bytes[0x158..0x160].copy_from_slice(&0x1_0000_0130_u64.to_le_bytes());
        bytes[0x100..0x140].fill(0);
        bytes[0x100..0x108].copy_from_slice(&[0x48, 0x8d, 0x05, 0x19, 0x00, 0x00, 0x00, 0xc3]);
        bytes[0x120..0x126].copy_from_slice(b"hello\0");
        bytes[0x130] = 0xc3;
        bytes
    }

    fn x86_direct_call_candidate_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x104..0x109].copy_from_slice(&[0xe8, 0x07, 0x00, 0x00, 0x00]);
        // The call target is also reached by ordinary fallthrough, making it
        // an interior alternate-entry candidate within the helper's closed
        // CFG rather than an orphan target after a proven return.
        bytes[0x109..0x110].fill(0x90);
        bytes[0x110] = 0xc3;
        bytes
    }

    fn x86_operator_authored_function_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x100] = 0xc3;
        bytes[0x118..0x120].copy_from_slice(&[0x48, 0x8d, 0x05, 0x11, 0x00, 0x00, 0x00, 0xc3]);
        bytes
    }

    fn arm64_inline_literal_function_conflict_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_arm64();
        bytes[0x100..0x104].copy_from_slice(&0x5800_0040_u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes[0x108..0x10c].copy_from_slice(&0x9000_0010_u32.to_le_bytes());
        bytes[0x10c..0x110].copy_from_slice(&0x9104_c210_u32.to_le_bytes());

        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        let starts = [0x80, 0x02, 0x08, 0x00];
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x26_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16]
            .copy_from_slice(&(starts.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&starts);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
        bytes
    }

    fn arm64_jump_table_function_conflict_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_arm64();
        bytes[0x158..0x160].copy_from_slice(&0x1_0000_0120_u64.to_le_bytes());
        bytes[0x100..0x104].copy_from_slice(&0x1000_0188_u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0xB8A0_5909_u32.to_le_bytes());
        bytes[0x108..0x10c].copy_from_slice(&0x8B09_0109_u32.to_le_bytes());
        bytes[0x10c..0x110].copy_from_slice(&0xD61F_0120_u32.to_le_bytes());
        bytes[0x110..0x114].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x118..0x11c].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x130..0x134].copy_from_slice(&(-0x20_i32).to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&(-0x18_i32).to_le_bytes());

        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        let starts = [0x80, 0x02, 0x30, 0x00];
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x26_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16]
            .copy_from_slice(&(starts.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&starts);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
        bytes
    }

    fn arm64_bounded_jump_table_function_starts_atom_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_arm64();
        bytes[0x158..0x160].copy_from_slice(&0x1_0000_0128_u64.to_le_bytes());
        bytes[0x100..0x104].copy_from_slice(&0xF100_041F_u32.to_le_bytes()); // cmp x0,#1
        bytes[0x104..0x108].copy_from_slice(&0x5400_0108_u32.to_le_bytes()); // b.hi 0x124
        bytes[0x108..0x10c].copy_from_slice(&0x1000_014A_u32.to_le_bytes()); // adr x10,0x130
        bytes[0x10c..0x110].copy_from_slice(&0x1000_008B_u32.to_le_bytes()); // adr x11,0x11c
        bytes[0x110..0x114].copy_from_slice(&0x3860_694C_u32.to_le_bytes()); // ldrb w12,[x10,x0]
        bytes[0x114..0x118].copy_from_slice(&0x8B0C_096B_u32.to_le_bytes()); // add x11,x11,x12,lsl#2
        bytes[0x118..0x11c].copy_from_slice(&0xD61F_0160_u32.to_le_bytes()); // br x11
        bytes[0x11c..0x120].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x124..0x128].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x128..0x12c].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x130..0x132].copy_from_slice(&[0, 1]);

        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        let starts = [0x80, 0x02, 0x30, 0x00];
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x26_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16]
            .copy_from_slice(&(starts.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&starts);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
        bytes
    }

    fn recover(bytes: &[u8], limits: ProgramRecoveryLimits) -> RecoveredProgram {
        RecoveredProgram::recover_all(&image(bytes), limits).unwrap()
    }

    #[test]
    fn one_program_owns_every_index_and_authoritative_ownership_query() {
        let program = recover(&full_x86_fixture(true), ProgramRecoveryLimits::default());
        assert_eq!(
            program.completeness().stages.len(),
            ProgramRecoveryStage::all().len()
        );
        assert!(program.dependencies().is_some());
        assert!(program.semantics().is_some());
        assert!(
            program
                .completeness()
                .stages
                .windows(2)
                .all(|pair| pair[0].stage < pair[1].stage)
        );
        for image in [
            program.functions().unwrap().image(),
            program.control_flow().unwrap().image(),
            program.executable_bytes().unwrap().image(),
            program.direct_calls().unwrap().image(),
            program.transfers().unwrap().image(),
            program.indirect_calls().unwrap().image(),
            program.symbols().unwrap().image(),
            program.strings().unwrap().image(),
            program.xrefs().unwrap().image(),
            program.rtti().unwrap().image(),
        ] {
            assert_eq!(image, program.image());
        }
        let owner = match program.function_containing(MAIN + 15) {
            Some(FunctionLookup::One(owner)) => owner,
            other => panic!("expected one owner, got {other:?}"),
        };
        assert_eq!(owner.function.entry, MAIN);
        let view = program.function_by_entry(THUNK).unwrap();
        assert!(view.control_flow.is_some());
        assert!(view.direct_call_node.is_some());
        assert!(view.thunk.is_some());
    }

    #[test]
    fn exact_reference_ownership_is_guided_durable_and_string_use_scoped() {
        let bytes = x86_string_reference_fixture();
        let macho = image(&bytes);
        let base = RecoveredProgram::recover_all(&macho, ProgramRecoveryLimits::default()).unwrap();
        assert!(base.functions().unwrap().by_entry(FINAL).is_some());
        let reference_subject = base
            .xrefs()
            .unwrap()
            .all_refs()
            .iter()
            .find_map(|reference| {
                let subject = cross_reference_subject(reference);
                matches!(
                    &subject,
                    ProgramSubjectKey::CrossReference {
                        source: MAIN,
                        target: RecoveryReferenceTargetKey::Internal { address },
                        reference_kind,
                    } if *address == 0x1_0000_0120
                        && *reference_kind == RecoveryReferenceKind::Data
                )
                .then_some(subject)
            })
            .expect("fixture retains the exact string reference");
        let ProgramSubjectKey::CrossReference {
            source: invalid_source,
            target: invalid_target,
            reference_kind: invalid_kind,
        } = reference_subject.clone()
        else {
            unreachable!()
        };
        let invalid = RecoveryGuide::builder(base.image().clone())
            .assign_reference_owner(invalid_source, invalid_target, invalid_kind, FINAL)
            .build();
        let error = RecoveredProgram::recover_with_guide(&macho, base.request().clone(), &invalid)
            .unwrap_err();
        assert!(matches!(
            error,
            ProgramRecoveryError::GuideValidationFailed { validation }
                if validation.decisions[0].reason
                    == "recovery_guide.reference_owner_not_candidate"
        ));
        let ranges = vec![
            RecoveryAddressRange::new(MAIN, MAIN + 8).unwrap(),
            RecoveryAddressRange::new(FINAL, FINAL + 1).unwrap(),
        ];
        let overlap_guide = RecoveryGuide::builder(base.image().clone())
            .function_ranges(FINAL, ranges.clone())
            .unwrap()
            .build();
        let ambiguous =
            RecoveredProgram::recover_with_guide(&macho, base.request().clone(), &overlap_guide)
                .unwrap();
        let question = ambiguous
            .questions()
            .iter()
            .find(|question| {
                question.kind == RecoveryQuestionKind::ReferenceOwnership
                    && question.subject == reference_subject
            })
            .expect("an exact ambiguous reference use emits an ownership question");
        assert!(question.choices.contains(&RecoveryChoice::ReferenceOwner {
            function_entry: MAIN,
        }));
        assert!(question.choices.contains(&RecoveryChoice::ReferenceOwner {
            function_entry: FINAL,
        }));

        let ProgramSubjectKey::CrossReference {
            source,
            target,
            reference_kind,
        } = reference_subject.clone()
        else {
            unreachable!()
        };
        let guide = RecoveryGuide::builder(base.image().clone())
            .function_ranges(FINAL, ranges.clone())
            .unwrap()
            .assign_reference_owner(source, target, reference_kind, FINAL)
            .build();
        let guided = RecoveredProgram::refine(&macho, &base, &guide).unwrap();
        let cold_guided = RecoveredProgram::recover_guided_from_base_with_reuse(
            &macho,
            base.request().clone(),
            &guide,
            &base,
            &base,
            false,
        )
        .unwrap()
        .into_program();
        assert_eq!(
            guided, cold_guided,
            "selective refine must be exactly equivalent to a cold guided rebuild"
        );
        assert!(!guided.questions().iter().any(|question| {
            question.kind == RecoveryQuestionKind::ReferenceOwnership
                && question.subject == reference_subject
        }));
        let reference = guided
            .xrefs()
            .unwrap()
            .all_refs()
            .iter()
            .find(|reference| cross_reference_subject(reference) == reference_subject)
            .unwrap();
        let owner = guided.reference_owner(reference).unwrap();
        assert_eq!(owner.owner.function.entry, FINAL);
        assert_eq!(owner.authority, ProgramFactAuthority::Guided);
        assert!(guided.reference_view(reference).target_string.is_some());

        let ownership_subject = guided.guided_reference_ownerships()[0].subject();
        assert_eq!(
            guided.subject_authority(&ownership_subject),
            Some(ProgramFactAuthority::Guided)
        );
        let application = guided.guide_application().unwrap();
        assert!(application.delta.records.iter().any(|record| {
            record.subject == ownership_subject
                && record.kind == RecoveryDeltaKind::Added
                && record.derivations.iter().any(|derivation| {
                    derivation.kind == RecoveryDecisionDerivationKind::DirectSubject
                })
        }));

        let json = guided.to_fact_document().to_json_pretty().unwrap();
        let loaded =
            RecoveredProgram::from_document(ProgramFactDocument::load_json(&json).unwrap())
                .unwrap();
        let loaded_reference = loaded
            .xrefs()
            .unwrap()
            .all_refs()
            .iter()
            .find(|reference| cross_reference_subject(reference) == reference_subject)
            .unwrap();
        assert_eq!(
            loaded
                .reference_owner(loaded_reference)
                .unwrap()
                .owner
                .function
                .entry,
            FINAL
        );
        assert!(
            loaded
                .reference_view(loaded_reference)
                .target_string
                .is_some()
        );

        let warm_replacement = RecoveredProgram::refine(&macho, &loaded, &overlap_guide).unwrap();
        assert_eq!(
            warm_replacement, ambiguous,
            "replacing a strict-loaded guide must equal cold recovery for the new guide"
        );
        assert_eq!(
            warm_replacement
                .to_fact_document()
                .to_json_pretty()
                .unwrap(),
            ambiguous.to_fact_document().to_json_pretty().unwrap(),
            "warm replacement must preserve exact durable Fact IR identity"
        );

        let mut invalid_document = guided.to_fact_document();
        invalid_document.program.guided_reference_ownerships[0].function_entry = u64::MAX;
        assert_eq!(
            invalid_document.validate(),
            Err(ProgramFactValidationError::GuidedReferenceOwnershipMismatch)
        );
    }

    #[test]
    fn byte_role_conflict_is_a_stable_explainable_recovery_question() {
        let bytes = arm64_inline_literal_function_conflict_fixture();
        let first = recover(&bytes, ProgramRecoveryLimits::default());
        let second = recover(&bytes, ProgramRecoveryLimits::default());
        assert_eq!(first.recovery_schema(), RecoveryContractSchema::CURRENT);
        assert_eq!(first.questions(), second.questions());

        let question = first
            .questions()
            .iter()
            .find(|question| question.kind == RecoveryQuestionKind::ByteRole)
            .expect("inline literal versus function entry emits a byte-role question");
        assert_eq!(&question.key.image, first.image());
        assert_eq!(question.key.subject, question.subject);
        assert!(matches!(
            question.subject,
            ProgramSubjectKey::ExecutableByteRange {
                start: 0x1_0000_0108,
                end_exclusive: 0x1_0000_0110,
                ..
            }
        ));
        assert!(question.choices.contains(&RecoveryChoice::ByteRole {
            role: crate::analysis::executable_bytes::ExecutableByteKind::Instruction,
        }));
        assert!(question.choices.contains(&RecoveryChoice::ByteRole {
            role: crate::analysis::executable_bytes::ExecutableByteKind::EmbeddedData,
        }));
        assert!(
            question
                .signals
                .iter()
                .any(|signal| signal.key.kind == RecoverySignalKind::InlineLiteral)
        );
        assert!(
            question
                .signals
                .iter()
                .any(|signal| signal.key.kind == RecoverySignalKind::FunctionEntry)
        );

        let encoded = serde_json::to_value(question).expect("question serializes");
        assert_eq!(encoded["key"]["kind"], "byte_role");
        assert_eq!(encoded["subject"]["kind"], "executable_byte_range");
    }

    #[test]
    fn jump_table_function_conflict_retains_both_structural_signals() {
        let bytes = arm64_jump_table_function_conflict_fixture();
        let program = recover(&bytes, ProgramRecoveryLimits::default());
        let question = program
            .questions()
            .iter()
            .find(|question| {
                matches!(
                    question.subject,
                    ProgramSubjectKey::ExecutableByteRange {
                        start: 0x1_0000_0130,
                        ..
                    }
                )
            })
            .expect("jump table versus function entry emits a recovery question");
        let table = question
            .signals
            .iter()
            .find(|signal| signal.key.kind == RecoverySignalKind::JumpTable)
            .expect("question retains the recovered jump-table signal");
        assert_eq!(table.key.source_address, Some(0x1_0000_010c));
        assert!(matches!(
            table.key.subject,
            ProgramSubjectKey::JumpTable {
                instruction_address: 0x1_0000_010c,
                table_address: 0x1_0000_0130,
                end_exclusive: 0x1_0000_0138,
            }
        ));
        assert!(question.signals.iter().any(|signal| {
            signal.key.kind == RecoverySignalKind::FunctionEntry
                && matches!(
                    signal.key.subject,
                    ProgramSubjectKey::Function {
                        entry: 0x1_0000_0130
                    }
                )
        }));
    }

    #[test]
    fn bounded_jump_table_rejects_uncorroborated_function_starts_data_atom() {
        let program = recover(
            &arm64_bounded_jump_table_function_starts_atom_fixture(),
            ProgramRecoveryLimits::default(),
        );
        let table_start = 0x1_0000_0130_u64;
        assert!(program.functions().unwrap().by_entry(table_start).is_none());
        let rejected = program
            .functions()
            .unwrap()
            .entry_candidates()
            .iter()
            .find(|candidate| candidate.address == table_start)
            .expect("function-starts data atom remains in the entry ledger");
        assert_eq!(
            rejected.disposition,
            FunctionEntryCandidateDisposition::RejectedRecoveredData
        );
        assert_eq!(
            rejected.reason,
            "function_starts_entry_is_bounded_jump_table"
        );
        assert!(rejected.evidence.iter().any(|evidence| {
            evidence.source == FunctionEvidenceSource::FunctionStarts
                && evidence.confidence == FunctionEvidenceConfidence::Exact
        }));
        let span = program
            .executable_bytes()
            .unwrap()
            .spans()
            .iter()
            .find(|span| table_start >= span.start && table_start < span.end_exclusive)
            .expect("bounded table has byte ownership");
        assert_eq!(span.kind, ExecutableByteKind::EmbeddedData);
        assert_eq!(span.confidence, FunctionEvidenceConfidence::Derived);
        assert!(program.questions().iter().all(|question| question.subject
            != ProgramSubjectKey::FunctionCandidate {
                address: table_start,
            }));
    }

    #[test]
    fn corroborated_entry_at_bounded_jump_table_remains_an_explicit_conflict() {
        let mut bytes = arm64_bounded_jump_table_function_starts_atom_fixture();
        let table_start = 0x1_0000_0130_u64;
        bytes[0x158..0x160].copy_from_slice(&table_start.to_le_bytes());
        let program = recover(&bytes, ProgramRecoveryLimits::default());
        assert!(program.functions().unwrap().by_entry(table_start).is_some());
        assert!(
            !program
                .functions()
                .unwrap()
                .entry_candidates()
                .iter()
                .any(|candidate| candidate.address == table_start
                    && candidate.disposition
                        == FunctionEntryCandidateDisposition::RejectedRecoveredData)
        );
        let span = program
            .executable_bytes()
            .unwrap()
            .spans()
            .iter()
            .find(|span| table_start >= span.start && table_start < span.end_exclusive)
            .expect("corroborated table entry remains classified");
        assert_eq!(span.kind, ExecutableByteKind::Unresolved);
        assert!(
            span.evidence
                .contains(&ExecutableByteEvidence::JumpTableTargetConflict)
        );
        assert!(program.questions().iter().any(|question| {
            matches!(
                question.subject,
                ProgramSubjectKey::ExecutableByteRange { start, .. } if start == table_start
            )
        }));
    }

    #[test]
    fn direct_call_candidate_is_an_actionable_function_relationship_question() {
        let bytes = x86_direct_call_candidate_fixture();
        let program = recover(&bytes, ProgramRecoveryLimits::default());
        let question = program
            .questions()
            .iter()
            .find(|question| {
                question.subject
                    == ProgramSubjectKey::FunctionCandidate {
                        address: 0x1_0000_0110,
                    }
            })
            .expect("direct-call-only target emits a recovery question");
        assert_eq!(question.kind, RecoveryQuestionKind::FunctionRelationship);
        assert!(question.signals.iter().any(|signal| {
            signal.key.kind == RecoverySignalKind::FunctionEntryCandidate
                && signal.key.evidence_source == Some(FunctionEvidenceSource::DirectCall)
                && signal.key.source_address == Some(0x1_0000_0104)
        }));
        assert!(
            question
                .signals
                .iter()
                .any(|signal| signal.key.kind == RecoverySignalKind::RangeOwnership)
        );
        assert!(
            question
                .choices
                .contains(&RecoveryChoice::FunctionRelationship {
                    owner_entry: 0x1_0000_0104,
                    relationship: FunctionRelationshipChoice::AlternateEntry,
                })
        );
        assert!(
            question
                .choices
                .contains(&RecoveryChoice::FunctionRelationship {
                    owner_entry: 0x1_0000_0104,
                    relationship: FunctionRelationshipChoice::ColdFragment,
                })
        );

        let mut stripped_bytes = bytes;
        stripped_bytes[0x161..0x16f].fill(0);
        let stripped = recover(&stripped_bytes, ProgramRecoveryLimits::default());
        let structural_questions = |program: &RecoveredProgram| {
            program
                .questions()
                .iter()
                .map(|question| {
                    (
                        question.subject.clone(),
                        question.kind,
                        question.choices.clone(),
                        question
                            .signals
                            .iter()
                            .map(|signal| {
                                (
                                    signal.key.kind,
                                    signal.key.subject.clone(),
                                    signal.key.evidence_source,
                                    signal.key.source_address,
                                    signal.confidence,
                                    signal.supports.clone(),
                                )
                            })
                            .collect::<Vec<_>>(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_ne!(program.image(), stripped.image());
        assert_eq!(
            structural_questions(&program),
            structural_questions(&stripped),
            "exact point identities rebind to changed bytes while structural questions ignore names"
        );
    }

    fn guide_for_choice(
        program: &RecoveredProgram,
        address: u64,
        choice: RecoveryChoice,
    ) -> RecoveryGuide {
        let question = program
            .questions()
            .iter()
            .find(|question| question.subject == ProgramSubjectKey::FunctionCandidate { address })
            .expect("fixture retains the requested candidate question");
        RecoveryGuide {
            schema: RecoveryContractSchema::CURRENT,
            image: program.image().clone(),
            decisions: vec![RecoveryDecision {
                point: question.key.clone(),
                choice,
                expected_signals: question
                    .signals
                    .iter()
                    .map(|signal| signal.key.clone())
                    .collect(),
            }],
        }
    }

    #[test]
    fn operator_authored_function_and_ranges_need_no_emitted_question() {
        let bytes = x86_operator_authored_function_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let entry = 0x1_0000_0118;
        let end_exclusive = 0x1_0000_0120;
        assert!(base.questions().iter().all(|question| {
            question.subject != ProgramSubjectKey::FunctionCandidate { address: entry }
        }));

        let guide = RecoveryGuide::builder(base.image().clone())
            .accept_function(entry)
            .function_ranges(
                entry,
                vec![RecoveryAddressRange::new(entry, end_exclusive).unwrap()],
            )
            .unwrap()
            .build();
        let validation = base.validate_guide_for_image(&macho, &guide);
        assert_eq!(
            validation.applicability,
            RecoveryGuideApplicability::Applicable
        );
        assert!(validation.decisions.iter().all(|decision| {
            decision.applicability == RecoveryDecisionApplicability::Applicable
                && decision.reason == "recovery_guide.authored_premise_applicable"
        }));

        let preview =
            RecoveredProgram::preview_guide(&macho, ProgramRecoveryRequest::all(limits), &guide)
                .unwrap();
        assert_eq!(preview.base(), &base);
        let application = preview.application().unwrap();
        assert!(
            application.coverage_delta.after.functions.caller_guided
                > application.coverage_delta.before.functions.caller_guided
        );
        assert_eq!(
            application
                .coverage_delta
                .before
                .executable_bytes
                .denominator,
            application
                .coverage_delta
                .after
                .executable_bytes
                .denominator
        );
        let guided = preview.into_program();
        let function = guided.functions().unwrap().by_entry(entry).unwrap();
        assert_eq!(
            function.authority,
            crate::analysis::functions::FunctionRecoveryAuthority::CallerGuided
        );
        assert_eq!(
            function
                .extent
                .map(|extent| (extent.start, extent.end_exclusive)),
            Some((entry, end_exclusive))
        );
        let graph = guided.control_flow().unwrap().by_entry(entry).unwrap();
        assert!(
            graph
                .instructions
                .iter()
                .all(|instruction| instruction.address >= entry
                    && instruction.address < end_exclusive)
        );
        let application = guided.guide_application().unwrap();
        assert!(
            application
                .decisions
                .iter()
                .all(|decision| decision.status == RecoveryDecisionApplicationStatus::Applied)
        );
        assert!(
            application
                .delta
                .records
                .iter()
                .all(|record| !record.derivations.is_empty())
        );
    }

    #[test]
    fn operator_authored_byte_roles_cover_the_complete_public_role_enum() {
        let bytes = macho_test_support::disassembly_arm64();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let section_ordinal = base
            .executable_bytes()
            .unwrap()
            .spans()
            .iter()
            .find(|span| span.start <= MAIN && span.end_exclusive >= MAIN + 4)
            .unwrap()
            .section_ordinal;
        let roles = [
            ExecutableByteKind::Instruction,
            ExecutableByteKind::EmbeddedData,
            ExecutableByteKind::Padding,
            ExecutableByteKind::Alignment,
            ExecutableByteKind::Stub,
            ExecutableByteKind::LiteralPool,
            ExecutableByteKind::Unresolved,
        ];
        for role in roles {
            let guide = RecoveryGuide::builder(base.image().clone())
                .byte_role(section_ordinal, MAIN, MAIN + 4, role)
                .unwrap()
                .build();
            let validation = base.validate_guide_for_image(&macho, &guide);
            assert_eq!(
                validation.applicability,
                RecoveryGuideApplicability::Applicable,
                "role {role:?} validates without an emitted question"
            );
            let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
            assert!(byte_role_is_applied(
                guided.executable_bytes().unwrap(),
                section_ordinal,
                MAIN,
                MAIN + 4,
                role,
            ));
            assert_eq!(
                guided.guide_application().unwrap().decisions[0].status,
                RecoveryDecisionApplicationStatus::Applied
            );
        }
    }

    #[test]
    fn operator_authored_rejection_and_relationship_need_no_candidate_question() {
        let bytes = x86_operator_authored_function_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let address = 0x1_0000_0118;

        let rejected_guide = RecoveryGuide::builder(base.image().clone())
            .reject_function(address)
            .build();
        let rejected =
            RecoveredProgram::recover_all_with_guide(&macho, limits, &rejected_guide).unwrap();
        assert!(
            rejected
                .functions()
                .unwrap()
                .entry_candidates()
                .iter()
                .any(|candidate| {
                    candidate.address == address
                        && candidate.disposition
                            == FunctionEntryCandidateDisposition::RejectedByCaller
                        && candidate.evidence.iter().any(|evidence| {
                            evidence.source == FunctionEvidenceSource::CallerDecision
                        })
                })
        );
        assert_eq!(
            rejected.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );

        let relationship_guide = RecoveryGuide::builder(base.image().clone())
            .relate_function(address, MAIN, FunctionRelationshipChoice::AlternateEntry)
            .build();
        let related =
            RecoveredProgram::recover_all_with_guide(&macho, limits, &relationship_guide).unwrap();
        let relationship = related
            .functions()
            .unwrap()
            .relationship_at(address)
            .unwrap();
        assert_eq!(relationship.owner_entry, MAIN);
        assert_eq!(relationship.kind, FunctionRelationshipKind::AlternateEntry);
        assert_eq!(
            related.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
    }

    #[test]
    fn operator_authored_split_ranges_are_the_active_cfg_and_ownership_view() {
        let bytes = x86_operator_authored_function_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let guide = RecoveryGuide::builder(base.image().clone())
            .function_ranges(
                MAIN,
                vec![
                    RecoveryAddressRange::new(MAIN, MAIN + 1).unwrap(),
                    RecoveryAddressRange::new(0x1_0000_0118, 0x1_0000_0120).unwrap(),
                ],
            )
            .unwrap()
            .build();
        let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
        let function = guided.functions().unwrap().by_entry(MAIN).unwrap();
        assert_eq!(function.caller_guided_ranges.len(), 2);
        let owners = guided
            .functions()
            .unwrap()
            .owners(0x1_0000_0118)
            .map(|owner| owner.function.entry)
            .collect::<Vec<_>>();
        assert_eq!(owners, vec![MAIN]);
        assert!(matches!(
            guided.function_containing(0x1_0000_0118),
            Some(FunctionLookup::One(owner)) if owner.function.entry == MAIN
        ));
        let graph = guided.control_flow().unwrap().by_entry(MAIN).unwrap();
        assert!(
            graph
                .instructions
                .iter()
                .any(|instruction| instruction.address == 0x1_0000_0118)
        );
        assert!(graph.instructions.iter().all(|instruction| {
            instruction.address == MAIN
                || (instruction.address >= 0x1_0000_0118 && instruction.address < 0x1_0000_0120)
        }));
    }

    #[test]
    fn authored_premises_reject_invalid_coordinates_and_internal_role_conflicts() {
        let bytes = macho_test_support::disassembly_arm64();
        let macho = image(&bytes);
        let base = RecoveredProgram::recover_all(&macho, ProgramRecoveryLimits::default()).unwrap();
        let invalid = RecoveryGuide::builder(base.image().clone())
            .accept_function(0xdead_beef)
            .build();
        let validation = base.validate_guide_for_image(&macho, &invalid);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Stale
        );

        let section_ordinal = base.executable_bytes().unwrap().spans()[0].section_ordinal;
        let orphan_entry = (MAIN..MAIN + 0x40)
            .step_by(4)
            .find(|entry| base.functions().unwrap().by_entry(*entry).is_none())
            .expect("fixture has an executable address without a function identity");
        let orphan_ranges = RecoveryGuide::builder(base.image().clone())
            .function_ranges(
                orphan_entry,
                vec![RecoveryAddressRange::new(orphan_entry, orphan_entry + 4).unwrap()],
            )
            .unwrap()
            .build();
        let validation = base.validate_guide_for_image(&macho, &orphan_ranges);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Stale
        );
        assert_eq!(
            validation.decisions[0].reason,
            "recovery_guide.function_range_owner_missing"
        );

        let wrong_section = RecoveryGuide::builder(base.image().clone())
            .byte_role(u64::MAX, MAIN, MAIN + 4, ExecutableByteKind::Instruction)
            .unwrap()
            .build();
        let validation = base.validate_guide_for_image(&macho, &wrong_section);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Stale
        );

        let unaligned_instruction = RecoveryGuide::builder(base.image().clone())
            .byte_role(
                section_ordinal,
                MAIN + 1,
                MAIN + 5,
                ExecutableByteKind::Instruction,
            )
            .unwrap()
            .build();
        let validation = base.validate_guide_for_image(&macho, &unaligned_instruction);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Unsupported
        );

        let conflicting = RecoveryGuide::builder(base.image().clone())
            .byte_role(
                section_ordinal,
                MAIN,
                MAIN + 4,
                ExecutableByteKind::Instruction,
            )
            .unwrap()
            .byte_role(
                section_ordinal,
                MAIN,
                MAIN + 4,
                ExecutableByteKind::EmbeddedData,
            )
            .unwrap()
            .build();
        let validation = base.validate_guide_for_image(&macho, &conflicting);
        assert_eq!(
            validation.decisions[1].applicability,
            RecoveryDecisionApplicability::Conflicting
        );
    }

    #[test]
    fn precise_edge_and_direct_call_suppressions_cold_rebuild_every_consumer() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();

        let (caller, instruction_address, target_address) = base
            .control_flow()
            .unwrap()
            .functions()
            .iter()
            .find_map(|graph| {
                graph.calls.iter().find_map(|call| match &call.target {
                    crate::analysis::control_flow::ControlFlowCallTarget::Direct {
                        address,
                        ..
                    } => Some((graph.function_entry, call.instruction_address, *address)),
                    crate::analysis::control_flow::ControlFlowCallTarget::Indirect { .. } => None,
                })
            })
            .expect("fixture has a direct callsite");
        let edge_graph = base
            .control_flow()
            .unwrap()
            .functions()
            .iter()
            .find(|graph| !graph.edges.is_empty())
            .expect("fixture has a retained CFG edge");
        let edge = &edge_graph.edges[0];
        let edge_source = edge_graph.blocks[edge.from as usize].start;
        let edge_target = edge_graph.blocks[edge.to as usize].start;

        let edge_guide = RecoveryGuide::builder(base.image().clone())
            .suppress_control_flow_edge(
                edge_graph.function_entry,
                edge_source,
                edge_target,
                edge.kind,
            )
            .build();
        let edge_guided =
            RecoveredProgram::recover_all_with_guide(&macho, limits, &edge_guide).unwrap();
        let guided_edge_graph = edge_guided
            .control_flow()
            .unwrap()
            .by_entry(edge_graph.function_entry)
            .unwrap();
        assert!(
            guided_edge_graph
                .guided_edge_suppressions
                .iter()
                .any(|item| {
                    item.source == edge_source
                        && item.target == edge_target
                        && item.edge_kind == edge.kind
                })
        );
        assert!(!guided_edge_graph.edges.iter().any(|item| {
            guided_edge_graph.blocks[item.from as usize].start == edge_source
                && guided_edge_graph.blocks[item.to as usize].start == edge_target
                && item.kind == edge.kind
        }));

        let direct_guide = RecoveryGuide::builder(base.image().clone())
            .suppress_direct_call(caller, instruction_address, target_address)
            .build();
        let validation = base.validate_guide_for_image(&macho, &direct_guide);
        assert!(validation.decisions.iter().all(|decision| {
            decision.applicability == RecoveryDecisionApplicability::Applicable
        }));
        let transition =
            RecoveredProgram::refine_with_reuse_receipt(&macho, &base, &direct_guide).unwrap();
        let control_flow_reuse = transition
            .reuse_receipt()
            .control_flow()
            .expect("control-flow transition has a function-local receipt");
        assert_eq!(
            control_flow_reuse.reused_functions() + control_flow_reuse.rebuilt_functions(),
            control_flow_reuse.total_functions()
        );
        assert!(control_flow_reuse.reused_functions() > 0);
        assert!(control_flow_reuse.rebuilt_functions() > 0);
        assert!(
            transition
                .reuse_receipt()
                .rebuilt_stages()
                .contains(&ProgramRecoveryStage::ControlFlow)
        );
        let guided = transition.into_program();
        let guided_call_graph = guided.control_flow().unwrap().by_entry(caller).unwrap();
        assert!(
            guided_call_graph
                .guided_direct_call_suppressions
                .iter()
                .any(|item| {
                    item.instruction_address == instruction_address
                        && item.target_address == target_address
                })
        );
        assert!(!guided_call_graph.calls.iter().any(|call| {
            call.instruction_address == instruction_address
                && matches!(
                    &call.target,
                    crate::analysis::control_flow::ControlFlowCallTarget::Direct {
                        address,
                        ..
                    } if *address == target_address
                )
        }));
        assert!(
            guided
                .functions()
                .unwrap()
                .functions()
                .iter()
                .all(|function| {
                    function.evidence.iter().all(|evidence| {
                        !(evidence.source == FunctionEvidenceSource::DirectCall
                            && evidence.source_location == Some(instruction_address)
                            && evidence.entry == target_address)
                    })
                })
        );
        assert!(!guided.xrefs().unwrap().all_refs().iter().any(|reference| {
            reference.source.0 == instruction_address
                && reference.target
                    == crate::analysis::xref::refs::XrefTarget::Internal {
                        va: crate::core::model::addr::Va(target_address),
                    }
                && reference.kind == crate::analysis::xref::refs::XrefKind::DirectBranch
        }));
        assert!(
            guided
                .direct_calls()
                .unwrap()
                .edges()
                .iter()
                .all(|call_edge| {
                    call_edge.callsites.iter().all(|callsite| {
                        call_edge.caller != caller
                            || callsite.instruction_address != instruction_address
                    })
                })
        );

        let edge_application = edge_guided.guide_application().unwrap();
        assert_eq!(
            edge_application.decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        let edge_subject = ProgramSubjectKey::ControlFlowEdge {
            function_entry: edge_graph.function_entry,
            source: edge_source,
            target: edge_target,
            edge_kind: edge.kind,
        };
        assert!(edge_application.delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Removed
                && record.subject == edge_subject
                && !record.derivations.is_empty()
        }));
        let application = guided.guide_application().unwrap();
        assert_eq!(
            application.decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        let call_subject = ProgramSubjectKey::DirectCallsite {
            caller,
            instruction_address,
            target_address,
        };
        assert!(application.delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Removed
                && record.subject == call_subject
                && !record.derivations.is_empty()
        }));

        let document = guided.to_fact_document();
        let loaded = ProgramFactDocument::load_json(&document.to_json_pretty().unwrap()).unwrap();
        assert_eq!(RecoveredProgram::from_document(loaded).unwrap(), guided);
        assert_eq!(
            RecoveredProgram::refine(&macho, &guided, &direct_guide).unwrap(),
            guided
        );
    }

    #[test]
    fn suppression_validation_rejects_stale_and_aggregate_coordinates() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let base = RecoveredProgram::recover_all(&macho, ProgramRecoveryLimits::default()).unwrap();
        let stale = RecoveryGuide::builder(base.image().clone())
            .suppress_direct_call(MAIN, u64::MAX - 1, u64::MAX)
            .build();
        assert_eq!(
            base.validate_guide_for_image(&macho, &stale).decisions[0].applicability,
            RecoveryDecisionApplicability::Stale
        );

        let mut aggregate = RecoveryGuide::new(base.image().clone());
        aggregate.decisions.push(RecoveryDecision {
            point: crate::analysis::recovery::RecoveryPointKey {
                image: base.image().clone(),
                subject: ProgramSubjectKey::DirectCall {
                    caller: MAIN,
                    callee: THUNK,
                },
                kind: RecoveryQuestionKind::DirectCall,
            },
            choice: RecoveryChoice::SuppressDirectCall,
            expected_signals: Vec::new(),
        });
        let validation = base.validate_guide_for_image(&macho, &aggregate);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Unsupported
        );
        assert!(matches!(
            RecoveredProgram::recover_all_with_guide(
                &macho,
                ProgramRecoveryLimits::default(),
                &aggregate,
            ),
            Err(ProgramRecoveryError::GuideValidationFailed { .. })
        ));
    }

    #[test]
    fn accepting_a_function_candidate_cold_rebuilds_downstream_layers() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let candidate = 0x1_0000_0110;
        let guide = guide_for_choice(&base, candidate, RecoveryChoice::AcceptFunctionEntry);

        let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
        let replay = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
        assert_eq!(guided, replay, "guided cold rebuild is deterministic");
        let document = guided.to_fact_document();
        let loaded = ProgramFactDocument::load_json(&document.to_json_pretty().unwrap()).unwrap();
        assert_eq!(RecoveredProgram::from_document(loaded).unwrap(), guided);
        assert_eq!(
            RecoveredProgram::refine(&macho, &guided, &guide).unwrap(),
            guided,
            "a complete guide can be reapplied to an already-guided prior"
        );
        let empty = RecoveryGuide::new(base.image().clone());
        let cleared = RecoveredProgram::refine(&macho, &guided, &empty).unwrap();
        assert!(cleared.functions().unwrap().by_entry(candidate).is_none());
        assert_eq!(cleared.guide(), Some(&empty));
        assert!(cleared.guide_application().is_some());
        assert_eq!(guided.guide(), Some(&guide));
        assert_eq!(
            guided.delta_from(&base).unwrap(),
            guided.guide_application().unwrap().delta
        );
        assert_eq!(
            guided.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        let delta = &guided.guide_application().unwrap().delta;
        assert!(delta.records.windows(2).all(|pair| pair[0] <= pair[1]));
        assert!(
            delta
                .records
                .iter()
                .all(|record| !record.derivations.is_empty()),
            "every changed object identifies the applied decision that caused it"
        );
        assert!(delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Added
                && record.subject == ProgramSubjectKey::Function { entry: candidate }
                && record.derivations.iter().any(|derivation| {
                    derivation.decision_index == 0
                        && derivation.kind == RecoveryDecisionDerivationKind::FunctionDependency
                })
        }));
        assert!(delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Added
                && matches!(
                    record.subject,
                    ProgramSubjectKey::BasicBlock {
                        function_entry,
                        ..
                    } if function_entry == candidate
                )
        }));
        assert!(delta.records.iter().any(|record| {
            record.layer == RecoveryLayer::Semantics
                && record.kind == RecoveryDeltaKind::Added
                && record.subject
                    == ProgramSubjectKey::FunctionSignature {
                        function_entry: candidate,
                    }
                && !record.derivations.is_empty()
        }));
        assert!(delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Resolved
                && record.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
        let function = guided.functions().unwrap().by_entry(candidate).unwrap();
        assert_eq!(function.authority, FunctionRecoveryAuthority::CallerGuided);
        assert_eq!(
            guided.subject_authority(&ProgramSubjectKey::Function { entry: candidate }),
            Some(ProgramFactAuthority::Guided)
        );
        assert_eq!(
            guided.subject_authority(&ProgramSubjectKey::Function { entry: MAIN }),
            Some(ProgramFactAuthority::Independent)
        );
        assert_eq!(
            guided.subject_authority(&ProgramSubjectKey::Function { entry: u64::MAX }),
            None,
            "an absent subject must not masquerade as independently established"
        );
        assert!(function.evidence.iter().any(|evidence| {
            evidence.source == FunctionEvidenceSource::CallerDecision
                && evidence.detail == "recovery_guide_accept_function_entry"
        }));
        assert!(guided.control_flow().unwrap().by_entry(candidate).is_some());
        assert!(
            guided
                .direct_calls()
                .unwrap()
                .edges()
                .iter()
                .any(|edge| edge.callee == candidate)
        );
        assert!(!guided.questions().iter().any(|question| {
            question.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
        assert!(
            guided
                .completeness()
                .reasons
                .iter()
                .any(|reason| reason == "program.functions_partial")
        );
        assert!(guided.completeness().stages.iter().any(|stage| {
            stage.stage == ProgramRecoveryStage::Functions
                && stage
                    .reasons
                    .iter()
                    .any(|reason| reason == "functions.caller_guided")
        }));
        assert!(base.functions().unwrap().by_entry(candidate).is_none());
    }

    #[test]
    fn rejecting_a_function_candidate_is_retained_without_building_a_function() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let candidate = 0x1_0000_0110;
        let guide = guide_for_choice(&base, candidate, RecoveryChoice::Reject);

        let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
        assert!(guided.functions().unwrap().by_entry(candidate).is_none());
        assert!(
            guided
                .functions()
                .unwrap()
                .entry_candidates()
                .iter()
                .any(|entry| {
                    entry.address == candidate
                        && entry.disposition == FunctionEntryCandidateDisposition::RejectedByCaller
                })
        );
        assert!(!guided.questions().iter().any(|question| {
            question.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
        assert_eq!(
            guided.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        let delta = &guided.guide_application().unwrap().delta;
        assert!(delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Reclassified
                && record.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
        assert!(delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Resolved
                && record.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
    }

    #[test]
    fn function_relationship_guide_resolves_without_inventing_a_second_body() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let candidate = 0x1_0000_0110;
        let owner = base
            .functions()
            .unwrap()
            .entry_candidates()
            .iter()
            .find(|entry| entry.address == candidate)
            .and_then(|entry| entry.possible_owners.first())
            .expect("fixture candidate has an existing possible owner")
            .entry;
        let guide = guide_for_choice(
            &base,
            candidate,
            RecoveryChoice::FunctionRelationship {
                owner_entry: owner,
                relationship: FunctionRelationshipChoice::AlternateEntry,
            },
        );

        let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
        assert!(guided.functions().unwrap().by_entry(candidate).is_none());
        let relationship = guided
            .functions()
            .unwrap()
            .relationship_at(candidate)
            .unwrap();
        assert_eq!(relationship.owner_entry, owner);
        assert_eq!(relationship.kind, FunctionRelationshipKind::AlternateEntry);
        assert_eq!(
            relationship.authority,
            FunctionRecoveryAuthority::CallerGuided
        );
        assert!(!relationship.evidence.is_empty());
        assert!(
            guided
                .functions()
                .unwrap()
                .entry_candidates()
                .iter()
                .any(|entry| {
                    entry.address == candidate
                        && entry.disposition
                            == FunctionEntryCandidateDisposition::ResolvedByCallerRelationship
                })
        );
        assert!(!guided.questions().iter().any(|question| {
            question.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
        assert!(guided.direct_calls().unwrap().edges().iter().any(|edge| {
            edge.callee == owner
                && edge.target_relation == FunctionTargetRelation::CallerGuidedAlternateEntry
        }));
        let application = guided.guide_application().unwrap();
        assert_eq!(
            application.decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        assert!(application.delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Added
                && record.subject
                    == ProgramSubjectKey::FunctionRelationship {
                        address: candidate,
                        owner_entry: owner,
                    }
        }));
        assert!(application.delta.records.iter().any(|record| {
            record.kind == RecoveryDeltaKind::Resolved
                && record.subject == ProgramSubjectKey::FunctionCandidate { address: candidate }
        }));
    }

    #[test]
    fn recovery_delta_requires_the_same_request_and_exact_image() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let all = RecoveredProgram::recover_all(&macho, ProgramRecoveryLimits::default()).unwrap();
        let functions = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Functions],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        assert_eq!(
            all.delta_from(&functions),
            Err(RecoveryDeltaError::RequestMismatch)
        );

        let mut other_bytes = bytes;
        other_bytes[0x110] = 0x90;
        let other =
            RecoveredProgram::recover_all(&image(&other_bytes), ProgramRecoveryLimits::default())
                .unwrap();
        assert_eq!(
            all.delta_from(&other),
            Err(RecoveryDeltaError::ImageMismatch)
        );
    }

    #[test]
    fn empty_and_stale_guides_have_strict_outcomes() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let empty = RecoveryGuide::new(base.image().clone());
        assert_eq!(
            RecoveredProgram::recover_all_with_guide(&macho, limits, &empty).unwrap(),
            base,
            "an empty guide is exactly the unguided program"
        );

        let mut stale = guide_for_choice(&base, 0x1_0000_0110, RecoveryChoice::AcceptFunctionEntry);
        stale.image.content_sha256 = "stale".into();
        assert!(matches!(
            RecoveredProgram::recover_all_with_guide(&macho, limits, &stale),
            Err(ProgramRecoveryError::GuideValidationFailed { .. })
        ));
    }

    #[test]
    fn byte_role_guidance_rebuilds_code_and_data_views_coherently() {
        let bytes = arm64_inline_literal_function_conflict_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let question = base
            .questions()
            .iter()
            .find(|question| question.kind == RecoveryQuestionKind::ByteRole)
            .unwrap();
        let make_guide = |role| RecoveryGuide {
            schema: RecoveryContractSchema::CURRENT,
            image: base.image().clone(),
            decisions: vec![RecoveryDecision {
                point: question.key.clone(),
                choice: RecoveryChoice::ByteRole { role },
                expected_signals: question
                    .signals
                    .iter()
                    .map(|signal| signal.key.clone())
                    .collect(),
            }],
        };
        let (section_ordinal, start, end_exclusive) = match question.subject {
            ProgramSubjectKey::ExecutableByteRange {
                section_ordinal,
                start,
                end_exclusive,
            } => (section_ordinal, start, end_exclusive),
            _ => panic!("expected byte range"),
        };
        assert!(base.xrefs().unwrap().all_refs().iter().any(|reference| {
            reference.source.0 == 0x1_0000_010c
                && reference.kind == crate::analysis::xref::XrefKind::Data
                && reference.target.internal_address().map(|va| va.0) == Some(0x1_0000_0130)
        }));

        let data_guide = make_guide(ExecutableByteKind::EmbeddedData);
        let data = RecoveredProgram::recover_all_with_guide(&macho, limits, &data_guide).unwrap();
        assert!(data.functions().unwrap().by_entry(start).is_none());
        assert!(
            data.functions()
                .unwrap()
                .suppressed_entries()
                .iter()
                .any(|entry| {
                    entry.entry == start
                        && entry.range_start == start
                        && entry.range_end_exclusive == end_exclusive
                        && !entry.evidence.is_empty()
                })
        );
        assert!(data.control_flow().unwrap().by_entry(start).is_none());
        assert!(byte_role_is_applied(
            data.executable_bytes().unwrap(),
            section_ordinal,
            start,
            end_exclusive,
            ExecutableByteKind::EmbeddedData,
        ));
        assert!(
            data.questions()
                .iter()
                .all(|candidate| candidate.key != question.key)
        );
        let data_application = data.guide_application().unwrap();
        assert_eq!(
            data_application.decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        assert_eq!(
            data_application.suppressed_signals.len(),
            question.signals.len()
        );
        assert!(data_application.delta.records.iter().any(|record| {
            record.layer == RecoveryLayer::References
                && record.kind == RecoveryDeltaKind::Removed
                && matches!(
                    &record.subject,
                    ProgramSubjectKey::CrossReference {
                        source: 0x1_0000_010c,
                        target: RecoveryReferenceTargetKey::Internal {
                            address: 0x1_0000_0130
                        },
                        reference_kind,
                    } if *reference_kind == RecoveryReferenceKind::Data
                )
                && record.derivations.iter().any(|derivation| {
                    derivation.decision_index == 0
                        && derivation.kind == RecoveryDecisionDerivationKind::OverlappingRange
                })
        }));

        let instruction_guide = make_guide(ExecutableByteKind::Instruction);
        let instruction =
            RecoveredProgram::recover_all_with_guide(&macho, limits, &instruction_guide).unwrap();
        assert!(instruction.functions().unwrap().by_entry(start).is_some());
        assert!(
            instruction
                .control_flow()
                .unwrap()
                .by_entry(start)
                .is_some()
        );
        assert!(byte_role_is_applied(
            instruction.executable_bytes().unwrap(),
            section_ordinal,
            start,
            end_exclusive,
            ExecutableByteKind::Instruction,
        ));
        assert!(
            instruction
                .questions()
                .iter()
                .all(|candidate| candidate.key != question.key)
        );
        assert_eq!(
            instruction.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
    }

    #[test]
    fn byte_role_instruction_choice_suppresses_competing_jump_table_edges() {
        let bytes = arm64_jump_table_function_conflict_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let question = base
            .questions()
            .iter()
            .find(|question| question.kind == RecoveryQuestionKind::ByteRole)
            .unwrap();
        let (section_ordinal, start, end_exclusive) = match &question.subject {
            ProgramSubjectKey::ExecutableByteRange {
                section_ordinal,
                start,
                end_exclusive,
            } => (*section_ordinal, *start, *end_exclusive),
            _ => panic!("expected byte range"),
        };
        assert!(
            base.control_flow()
                .unwrap()
                .functions()
                .iter()
                .any(|graph| {
                    graph.jump_tables.iter().any(|table| {
                        table.table_address < end_exclusive && table.end_exclusive > start
                    })
                })
        );
        let make_guide = |role| RecoveryGuide {
            schema: RecoveryContractSchema::CURRENT,
            image: base.image().clone(),
            decisions: vec![RecoveryDecision {
                point: question.key.clone(),
                choice: RecoveryChoice::ByteRole { role },
                expected_signals: question
                    .signals
                    .iter()
                    .map(|signal| signal.key.clone())
                    .collect(),
            }],
        };

        let guide = make_guide(ExecutableByteKind::Instruction);
        let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();
        assert!(
            guided
                .control_flow()
                .unwrap()
                .functions()
                .iter()
                .all(|graph| {
                    graph.jump_tables.iter().all(|table| {
                        table.table_address >= end_exclusive || table.end_exclusive <= start
                    })
                })
        );
        assert!(byte_role_is_applied(
            guided.executable_bytes().unwrap(),
            section_ordinal,
            start,
            end_exclusive,
            ExecutableByteKind::Instruction,
        ));
        assert_eq!(
            guided.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        assert!(
            guided
                .guide_application()
                .unwrap()
                .delta
                .records
                .iter()
                .any(|record| {
                    record.kind == RecoveryDeltaKind::Removed
                        && matches!(record.subject, ProgramSubjectKey::JumpTable { .. })
                        && record.derivations.iter().any(|derivation| {
                            derivation.decision_index == 0
                                && derivation.kind
                                    == RecoveryDecisionDerivationKind::OverlappingRange
                        })
                })
        );

        let data_guide = make_guide(ExecutableByteKind::EmbeddedData);
        let data = RecoveredProgram::recover_all_with_guide(&macho, limits, &data_guide).unwrap();
        assert!(data.functions().unwrap().by_entry(start).is_none());
        assert!(
            data.functions()
                .unwrap()
                .suppressed_entries()
                .iter()
                .any(|entry| entry.entry == start && entry.range_end_exclusive == end_exclusive)
        );
        assert!(
            data.control_flow()
                .unwrap()
                .functions()
                .iter()
                .any(|graph| {
                    graph.jump_tables.iter().any(|table| {
                        table.table_address < end_exclusive && table.end_exclusive > start
                    })
                })
        );
        assert!(byte_role_is_applied(
            data.executable_bytes().unwrap(),
            section_ordinal,
            start,
            end_exclusive,
            ExecutableByteKind::EmbeddedData,
        ));
    }

    #[test]
    fn guided_function_entry_respects_the_unchanged_function_budget() {
        let bytes = x86_direct_call_candidate_fixture();
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits {
            functions: FunctionRecoveryLimits {
                max_functions: 2,
                ..FunctionRecoveryLimits::default()
            },
            ..ProgramRecoveryLimits::default()
        };
        let base = RecoveredProgram::recover_all(&macho, limits).unwrap();
        let candidate = 0x1_0000_0110;
        let guide = guide_for_choice(&base, candidate, RecoveryChoice::AcceptFunctionEntry);
        let guided = RecoveredProgram::recover_all_with_guide(&macho, limits, &guide).unwrap();

        assert!(guided.functions().unwrap().by_entry(candidate).is_none());
        assert_eq!(guided.status(), ProgramRecoveryStatus::Truncated);
        assert_eq!(
            guided.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::BudgetExcluded
        );

        let raised = RecoveredProgram::recover_all_with_guide(
            &macho,
            ProgramRecoveryLimits::default(),
            &guide,
        )
        .unwrap();
        assert_eq!(
            raised.guide_application().unwrap().decisions[0].status,
            RecoveryDecisionApplicationStatus::Applied
        );
        assert!(raised.functions().unwrap().by_entry(candidate).is_some());
        let raised_entries = raised
            .functions()
            .unwrap()
            .functions()
            .iter()
            .map(|function| function.entry)
            .collect::<BTreeSet<_>>();
        assert!(
            guided
                .functions()
                .unwrap()
                .functions()
                .iter()
                .all(|function| raised_entries.contains(&function.entry))
        );
    }

    #[test]
    fn recovery_guide_validation_is_strict_and_non_mutating() {
        let bytes = arm64_inline_literal_function_conflict_fixture();
        let program = recover(&bytes, ProgramRecoveryLimits::default());
        let question = program
            .questions()
            .iter()
            .find(|question| question.kind == RecoveryQuestionKind::ByteRole)
            .expect("fixture has one byte-role conflict");
        let decision = RecoveryDecision {
            point: question.key.clone(),
            choice: RecoveryChoice::ByteRole {
                role: crate::analysis::executable_bytes::ExecutableByteKind::EmbeddedData,
            },
            expected_signals: question
                .signals
                .iter()
                .map(|signal| signal.key.clone())
                .collect(),
        };
        let guide = RecoveryGuide {
            schema: RecoveryContractSchema::CURRENT,
            image: program.image().clone(),
            decisions: vec![decision.clone()],
        };
        let encoded_guide = serde_json::to_vec(&guide).expect("guide serializes");
        let decoded_guide: RecoveryGuide =
            serde_json::from_slice(&encoded_guide).expect("guide deserializes");
        assert_eq!(decoded_guide, guide);
        let mut unknown_field = serde_json::to_value(&guide).expect("guide serializes to JSON");
        unknown_field
            .as_object_mut()
            .expect("guide is a JSON object")
            .insert("operator_policy".to_owned(), serde_json::Value::Bool(true));
        assert!(
            serde_json::from_value::<RecoveryGuide>(unknown_field).is_err(),
            "the format-local guide contract rejects undeclared policy fields"
        );
        let before = serde_json::to_value(&program).expect("program serializes");
        let validation = program.validate_guide(&guide);
        let after = serde_json::to_value(&program).expect("program still serializes");
        assert_eq!(before, after, "validation must not mutate recovery");
        assert_eq!(
            validation.applicability,
            RecoveryGuideApplicability::Applicable
        );
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Applicable
        );

        let mut conflicting = guide.clone();
        conflicting.decisions.push(RecoveryDecision {
            choice: RecoveryChoice::ByteRole {
                role: crate::analysis::executable_bytes::ExecutableByteKind::Instruction,
            },
            ..decision.clone()
        });
        let validation = program.validate_guide(&conflicting);
        assert_eq!(
            validation.applicability,
            RecoveryGuideApplicability::PartiallyApplicable
        );
        assert_eq!(
            validation.decisions[1].applicability,
            RecoveryDecisionApplicability::Conflicting
        );

        let mut stale = guide.clone();
        stale.image.content_sha256 = "changed-image".to_owned();
        let validation = program.validate_guide(&stale);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Stale
        );

        let mut unsupported = guide;
        unsupported.schema = RecoveryContractSchema::unsupported_fixture(0);
        let validation = program.validate_guide(&unsupported);
        assert_eq!(
            validation.decisions[0].applicability,
            RecoveryDecisionApplicability::Unsupported
        );
    }

    #[test]
    fn direct_callers_are_resolved_through_macho_owned_thunks() {
        let program = recover(&full_x86_fixture(true), ProgramRecoveryLimits::default());
        let incoming = program.resolved_direct_incoming(FINAL).collect::<Vec<_>>();
        assert_eq!(incoming.len(), 1);
        assert_eq!(incoming[0].edge.caller, MAIN);
        assert_eq!(incoming[0].edge.callee, THUNK);
        assert_eq!(
            incoming[0].resolution.resolution,
            TransferResolutionStatus::ThroughThunks
        );
        assert_eq!(incoming[0].resolution.final_target, Some(FINAL));

        let indirect = program.indirect_calls_from(MAIN).collect::<Vec<_>>();
        assert!(indirect.iter().any(|call| {
            call.candidates.iter().any(|candidate| {
                matches!(
                    &candidate.target,
                    IndirectCallTarget::Internal { address, .. } if *address == FINAL
                )
            })
        }));
    }

    #[test]
    fn stripping_changes_names_not_program_structure_or_resolved_callers() {
        let rich = recover(&full_x86_fixture(true), ProgramRecoveryLimits::default());
        let stripped = recover(&full_x86_fixture(false), ProgramRecoveryLimits::default());
        assert!(matches!(
            rich.function_by_entry(THUNK).unwrap().function.identity,
            FunctionIdentity::Named { .. }
        ));
        assert!(matches!(
            stripped.function_by_entry(THUNK).unwrap().function.identity,
            FunctionIdentity::Anonymous { .. }
        ));
        assert_eq!(
            rich.control_flow().unwrap().functions().len(),
            stripped.control_flow().unwrap().functions().len()
        );
        assert_eq!(
            rich.direct_calls().unwrap().edges(),
            stripped.direct_calls().unwrap().edges()
        );
        assert_eq!(
            rich.transfers().unwrap().transfers(),
            stripped.transfers().unwrap().transfers()
        );
        assert_eq!(
            rich.indirect_calls().unwrap().calls(),
            stripped.indirect_calls().unwrap().calls()
        );
        let rich_incoming = rich
            .resolved_direct_incoming(FINAL)
            .map(|edge| (edge.edge.caller, edge.edge.callee, edge.resolution))
            .collect::<Vec<_>>();
        let stripped_incoming = stripped
            .resolved_direct_incoming(FINAL)
            .map(|edge| (edge.edge.caller, edge.edge.callee, edge.resolution))
            .collect::<Vec<_>>();
        assert_eq!(rich_incoming, stripped_incoming);
    }

    #[test]
    fn nested_budget_truncation_is_conserved_globally_and_by_stage() {
        let limits = ProgramRecoveryLimits {
            functions: FunctionRecoveryLimits {
                max_functions: 1,
                ..FunctionRecoveryLimits::default()
            },
            ..ProgramRecoveryLimits::default()
        };
        let program = recover(&full_x86_fixture(true), limits);
        assert_eq!(program.status(), ProgramRecoveryStatus::Truncated);
        let function_stage = program
            .completeness()
            .stages
            .iter()
            .find(|stage| stage.stage == ProgramRecoveryStage::Functions)
            .unwrap();
        assert_eq!(function_stage.status, ProgramRecoveryStatus::Truncated);
        assert!(
            program
                .completeness()
                .reasons
                .contains(&"program.functions_truncated".to_owned())
        );
    }

    #[test]
    fn every_serialized_nested_limit_is_validated() {
        fn numeric_paths(
            value: &serde_json::Value,
            prefix: &mut Vec<String>,
            out: &mut Vec<Vec<String>>,
        ) {
            match value {
                serde_json::Value::Object(fields) => {
                    for (name, value) in fields {
                        prefix.push(name.clone());
                        numeric_paths(value, prefix, out);
                        prefix.pop();
                    }
                }
                serde_json::Value::Number(_) => out.push(prefix.clone()),
                _ => {}
            }
        }
        fn replace(value: &mut serde_json::Value, path: &[String]) {
            let mut cursor = value;
            for component in &path[..path.len() - 1] {
                cursor = cursor.as_object_mut().unwrap().get_mut(component).unwrap();
            }
            cursor
                .as_object_mut()
                .unwrap()
                .insert(path.last().unwrap().clone(), serde_json::json!(0));
        }

        let encoded = serde_json::to_value(ProgramRecoveryLimits::default()).unwrap();
        let mut paths = Vec::new();
        numeric_paths(&encoded, &mut Vec::new(), &mut paths);
        assert!(
            paths.len() >= 80,
            "nested limit surface unexpectedly shrank"
        );
        for path in paths {
            let mut invalid = encoded.clone();
            replace(&mut invalid, &path);
            let limits: ProgramRecoveryLimits =
                serde_json::from_value(invalid).unwrap_or_else(|error| {
                    panic!("{} failed to deserialize: {error}", path.join("."))
                });
            assert!(
                limits.validate().is_err(),
                "zero nested limit escaped validation: {}",
                path.join(".")
            );
        }
    }

    #[test]
    fn primary_budget_of_every_stage_is_deterministic_and_monotonic() {
        type LimitCase = (ProgramRecoveryStage, fn(&mut ProgramRecoveryLimits));
        let cases: &[LimitCase] = &[
            (ProgramRecoveryStage::ImageLayout, |limits| {
                limits.image_layout.max_sections = 1
            }),
            (ProgramRecoveryStage::Pointers, |limits| {
                limits.pointers.max_records = 1
            }),
            (ProgramRecoveryStage::Symbols, |limits| {
                limits.symbols.max_nlist_symbols = 1
            }),
            (ProgramRecoveryStage::Strings, |limits| {
                limits.strings.max_strings = 1
            }),
            (ProgramRecoveryStage::Objc, |limits| {
                limits.objc.max_observations = 1
            }),
            (ProgramRecoveryStage::Swift, |limits| {
                limits.swift.max_observations = 1
            }),
            (ProgramRecoveryStage::Dwarf, |limits| {
                limits.dwarf.max_entries = 1
            }),
            (ProgramRecoveryStage::Functions, |limits| {
                limits.functions.max_functions = 1
            }),
            (ProgramRecoveryStage::ControlFlow, |limits| {
                limits.control_flow.max_functions = 1
            }),
            (ProgramRecoveryStage::ExecutableBytes, |limits| {
                limits.executable_bytes.max_spans = 1
            }),
            (ProgramRecoveryStage::DirectCalls, |limits| {
                limits.direct_calls.max_nodes = 1
            }),
            (ProgramRecoveryStage::Transfers, |limits| {
                limits.transfers.max_functions = 1
            }),
            (ProgramRecoveryStage::IndirectCalls, |limits| {
                limits.indirect_calls.max_functions = 1
            }),
            (ProgramRecoveryStage::Xrefs, |limits| {
                limits.xrefs.max_refs = 1
            }),
            (ProgramRecoveryStage::Rtti, |limits| {
                limits.rtti.type_info.max_records = 1
            }),
            (ProgramRecoveryStage::Exceptions, |limits| {
                limits.exceptions.max_records = 1
            }),
            (ProgramRecoveryStage::Dependencies, |limits| {
                limits.dependencies.max_dependencies = 1
            }),
            (ProgramRecoveryStage::Semantics, |limits| {
                limits.semantics.max_data_objects = 1
            }),
        ];
        assert_eq!(cases.len(), ProgramRecoveryStage::all().len());
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        for &(stage, constrain) in cases {
            let mut low_limits = ProgramRecoveryLimits::default();
            constrain(&mut low_limits);
            let request = ProgramRecoveryRequest::new([stage], low_limits);
            let low = RecoveredProgram::recover(&macho, request.clone()).unwrap();
            let replay = RecoveredProgram::recover(&macho, request).unwrap();
            assert_eq!(low, replay, "{stage:?} low-budget replay changed");
            let high = RecoveredProgram::recover(
                &macho,
                ProgramRecoveryRequest::new([stage], ProgramRecoveryLimits::default()),
            )
            .unwrap();
            let contract = |program: &RecoveredProgram| {
                let contract = program
                    .completeness()
                    .contracts
                    .iter()
                    .find(|contract| contract.stage == stage)
                    .unwrap();
                (contract.included, contract.budget_excluded)
            };
            let low_contract = contract(&low);
            let high_contract = contract(&high);
            assert!(
                low_contract.0 <= high_contract.0,
                "raising {stage:?} budget removed retained evidence"
            );
            assert!(
                high_contract.1 <= low_contract.1,
                "raising {stage:?} budget increased exclusions"
            );
        }
    }

    #[test]
    fn closed_cfg_removes_uncertain_function_boundary_reason() {
        let program = recover(&full_x86_fixture(true), ProgramRecoveryLimits::default());
        let function_stage = program
            .completeness()
            .stages
            .iter()
            .find(|stage| stage.stage == ProgramRecoveryStage::Functions)
            .unwrap();
        assert_eq!(function_stage.status, ProgramRecoveryStatus::Complete);
        assert!(function_stage.reasons.is_empty());
        assert!(
            !function_stage
                .reasons
                .contains(&"functions.uncertain_extents".to_owned())
        );
        assert!(
            program
                .functions()
                .unwrap()
                .functions()
                .iter()
                .all(|function| function.completeness.extent_is_authoritative)
        );
    }

    #[test]
    fn closed_cfg_promotes_only_proven_extents_and_rebuilds_the_graph() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let functions_only = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Functions],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        assert!(
            functions_only
                .functions()
                .unwrap()
                .functions()
                .iter()
                .all(|function| !function.completeness.extent_is_authoritative
                    && function.extent.is_some_and(|extent| {
                        extent.confidence == FunctionEvidenceConfidence::Candidate
                    }))
        );

        let program = recover(&bytes, ProgramRecoveryLimits::default());
        let refined = program
            .functions()
            .unwrap()
            .functions()
            .iter()
            .filter(|function| {
                function.evidence.iter().any(|evidence| {
                    evidence.source == FunctionEvidenceSource::ControlFlow
                        && evidence.detail == "entry_reachable_cfg_closed_extent"
                })
            })
            .collect::<Vec<_>>();
        assert!(!refined.is_empty());
        for function in refined {
            assert!(function.completeness.extent_is_authoritative);
            assert_eq!(
                function.extent.unwrap().confidence,
                FunctionEvidenceConfidence::Derived
            );
            let graph = program
                .control_flow()
                .unwrap()
                .by_entry(function.entry)
                .unwrap();
            assert_eq!(
                graph.completeness.boundary_confidence,
                Some(FunctionEvidenceConfidence::Derived)
            );
            assert!(
                !graph
                    .completeness
                    .reasons
                    .contains(&"control_flow.uncertain_boundary".to_owned()),
                "the final graph must be rebuilt from the promoted extent"
            );
        }
    }

    #[test]
    fn truncated_cfg_never_promotes_a_candidate_function_extent() {
        let limits = ProgramRecoveryLimits {
            control_flow: ControlFlowLimits {
                max_decoded_bytes: 1,
                ..ControlFlowLimits::default()
            },
            ..ProgramRecoveryLimits::default()
        };
        let program = recover(&full_x86_fixture(true), limits);
        assert!(
            program
                .functions()
                .unwrap()
                .functions()
                .iter()
                .all(|function| !function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source == FunctionEvidenceSource::ControlFlow))
        );
        assert_eq!(
            program.control_flow().unwrap().status(),
            ControlFlowIndexStatus::Truncated
        );
    }

    #[test]
    fn selective_recovery_validates_only_executed_modules() {
        let limits = ProgramRecoveryLimits {
            indirect_calls: IndirectCallRecoveryLimits {
                max_transfers: 0,
                ..IndirectCallRecoveryLimits::default()
            },
            ..ProgramRecoveryLimits::default()
        };
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let functions_only = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new([ProgramRecoveryStage::Functions], limits),
        )
        .unwrap();
        assert!(functions_only.functions().is_some());
        assert!(functions_only.indirect_calls().is_none());
        assert_eq!(
            RecoveredProgram::recover(
                &macho,
                ProgramRecoveryRequest::new([ProgramRecoveryStage::IndirectCalls], limits),
            )
            .unwrap_err(),
            ProgramRecoveryError::IndirectCalls(IndirectCallRecoveryError::InvalidLimits)
        );
    }

    #[test]
    fn requests_execute_only_selected_modules_and_declared_dependencies() {
        let bytes = full_x86_fixture(true);
        let program = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Symbols, ProgramRecoveryStage::Rtti],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        assert!(program.symbols().is_some());
        assert!(program.rtti().is_some());
        assert!(program.functions().is_none());
        assert!(program.control_flow().is_none());
        assert!(program.xrefs().is_none());
        assert_eq!(program.executed_stages(), program.request().requested());

        let xrefs = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Xrefs],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        assert_eq!(
            xrefs.executed_stages(),
            &BTreeSet::from([
                ProgramRecoveryStage::Pointers,
                ProgramRecoveryStage::Objc,
                ProgramRecoveryStage::Swift,
                ProgramRecoveryStage::Dwarf,
                ProgramRecoveryStage::Exceptions,
                ProgramRecoveryStage::Functions,
                ProgramRecoveryStage::ControlFlow,
                ProgramRecoveryStage::Xrefs,
            ])
        );
        assert!(xrefs.symbols().is_none());
        assert!(xrefs.strings().is_none());
        assert!(xrefs.direct_calls().is_none());
        assert!(xrefs.rtti().is_none());
        assert!(
            xrefs.completeness().stages.iter().any(|stage| {
                stage.stage == ProgramRecoveryStage::Functions && !stage.requested
            })
        );
    }

    #[test]
    fn downstream_layers_borrow_only_selected_capabilities() {
        let bytes = x86_string_reference_fixture();
        let program = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Strings, ProgramRecoveryStage::Xrefs],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();

        let facts = program.facts();
        let disassembly = facts
            .disassembly_inputs()
            .expect("xref dependencies provide functions and control flow");
        assert_eq!(disassembly.functions.image(), program.image());
        assert_eq!(disassembly.control_flow.image(), program.image());
        assert!(disassembly.strings.is_some());
        assert!(disassembly.xrefs.is_some());
        assert!(disassembly.symbols.is_none());
        assert!(disassembly.rtti.is_none());
        assert!(facts.direct_calls.is_none());
        assert!(facts.transfers.is_none());
        assert!(facts.indirect_calls.is_none());
        assert!(facts.xref_inputs().is_some());
        assert!(facts.direct_call_inputs().is_none());
    }

    #[test]
    fn borrowed_address_view_resolves_instruction_string_reference() {
        let bytes = x86_string_reference_fixture();
        let program = RecoveredProgram::recover(
            &image(&bytes),
            ProgramRecoveryRequest::new(
                [ProgramRecoveryStage::Xrefs, ProgramRecoveryStage::Semantics],
                ProgramRecoveryLimits::default(),
            ),
        )
        .unwrap();
        let view = program.address_view(MAIN);
        assert!(view.function.is_some());
        assert_eq!(
            view.instruction.map(|instruction| instruction.address),
            Some(MAIN)
        );
        let string_reference = view
            .references
            .iter()
            .find(|reference| reference.reference.kind == crate::analysis::xref::XrefKind::Data)
            .expect("LEA produces one data xref");
        assert_eq!(
            string_reference
                .target_string
                .map(|value| value.value.as_str()),
            Some("hello")
        );
        assert_eq!(
            string_reference
                .target_data_object
                .map(|object| object.kind),
            Some(crate::analysis::semantic_index::DataObjectKind::String)
        );
        assert_eq!(
            string_reference.target_binding,
            ProgramReferenceBinding::DataObject
        );

        let annotations = program.annotations_at(MAIN);
        assert_eq!(annotations.address(), MAIN);
        assert!(annotations.function().is_some());
        assert_eq!(
            annotations
                .instruction()
                .map(|instruction| instruction.address),
            Some(MAIN)
        );
        let string_reference = annotations
            .references()
            .find(|reference| reference.reference().kind == crate::analysis::xref::XrefKind::Data)
            .expect("LEA produces one streaming data xref");
        assert_eq!(
            string_reference
                .target_string()
                .map(|value| value.value.as_str()),
            Some("hello")
        );
        assert_eq!(
            string_reference
                .target_data_object()
                .map(|object| object.kind),
            Some(crate::analysis::semantic_index::DataObjectKind::String)
        );
        assert_eq!(
            string_reference.target_binding(),
            ProgramReferenceBinding::DataObject
        );
    }

    #[test]
    fn prebuilt_function_inventory_is_reused_without_changing_program_recovery() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let functions = FunctionIndex::recover(&macho, limits.functions).unwrap();
        let reused =
            RecoveredProgram::recover_all_from_functions(&macho, functions, limits).unwrap();
        let direct = RecoveredProgram::recover_all(&macho, limits).unwrap();
        assert_eq!(reused.functions(), direct.functions());
        assert_eq!(reused.control_flow(), direct.control_flow());
        assert_eq!(reused.direct_calls(), direct.direct_calls());
        assert_eq!(reused.transfers(), direct.transfers());
        assert_eq!(reused.indirect_calls(), direct.indirect_calls());
        assert_eq!(reused.completeness(), direct.completeness());
    }

    #[test]
    fn explicitly_selected_symbol_inventory_is_reused_by_function_recovery() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let functions_only = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new([ProgramRecoveryStage::Functions], limits),
        )
        .unwrap();
        let with_symbols = RecoveredProgram::recover(
            &macho,
            ProgramRecoveryRequest::new(
                [
                    ProgramRecoveryStage::Symbols,
                    ProgramRecoveryStage::Functions,
                ],
                limits,
            ),
        )
        .unwrap();
        assert_eq!(with_symbols.functions(), functions_only.functions());
        assert!(with_symbols.symbols().is_some());
        assert!(functions_only.symbols().is_none());
    }

    #[test]
    fn unified_construction_supports_x86_arm64_and_arm64e() {
        for bytes in [
            macho_test_support::disassembly_x86_64(),
            macho_test_support::disassembly_arm64(),
            macho_test_support::disassembly_arm64e(),
        ] {
            let program = recover(&bytes, ProgramRecoveryLimits::default());
            assert!(!program.functions().unwrap().functions().is_empty());
            assert_eq!(
                program.completeness().stages.len(),
                ProgramRecoveryStage::all().len()
            );
        }
    }

    #[cfg(target_os = "macos")]
    fn strip_nlist_names(macho: &crate::core::MachoFile<'_>) -> Vec<u8> {
        use crate::core::model::load_command::LoadCommand;

        let mut stripped = macho.bytes().to_vec();
        if let Some(symbols) = macho.load_commands().iter().find_map(|command| {
            if let LoadCommand::Symtab(symbols) = command.kind() {
                Some(symbols)
            } else {
                None
            }
        }) {
            let start = symbols.str_offset as usize;
            let end = start.saturating_add(symbols.str_size as usize);
            stripped
                .get_mut(start..end)
                .expect("validated string table bounds")
                .fill(0);
        }
        stripped
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_corpus_stays_within_recovery_ceilings_and_survives_name_stripping() {
        use std::time::{Duration, Instant};

        let limits = ProgramRecoveryLimits::default();
        let mut recovered = 0_usize;
        for path in ["/bin/ls", "/bin/cp", "/usr/bin/file", "/usr/bin/xcrun"] {
            let bytes = std::fs::read(path).expect("macOS system corpus member exists");
            let container = crate::core::parse(&bytes).expect("system corpus member parses");
            for macho in container.macho_files() {
                let started = Instant::now();
                let program =
                    RecoveredProgram::recover_all(macho, limits).expect("supported system slice");
                let elapsed = started.elapsed();
                assert_eq!(
                    program.completeness().status,
                    ProgramRecoveryStatus::Complete,
                    "all-stage recovery must close for {path} CPU {:#x}/{:#x}: {:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                    program.completeness().reasons,
                );
                assert!(!program.functions().unwrap().functions().is_empty());
                let indirect_completeness = program.indirect_calls().unwrap().completeness();
                assert_eq!(
                    indirect_completeness.status,
                    crate::analysis::indirect_calls::IndirectCallIndexStatus::Complete,
                    "static indirect recovery must close for {path} CPU {:#x}/{:#x}: {:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                    indirect_completeness.reasons,
                );
                assert!(
                    indirect_completeness.value_flow_work
                        <= limits.indirect_calls.max_value_flow_work
                );
                assert!(
                    !indirect_completeness.value_flow_truncated,
                    "value flow truncated for {path} CPU {:#x}/{:#x} after {} work units at {:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                    indirect_completeness.value_flow_work,
                    indirect_completeness.value_flow_continuation_function,
                );
                assert!(
                    elapsed < Duration::from_secs(10),
                    "program recovery exceeded the real-corpus ceiling for {path} CPU {:#x}/{:#x}: {elapsed:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                );

                let stripped_bytes = strip_nlist_names(macho);
                let stripped_macho = image(&stripped_bytes);
                let stripped = RecoveredProgram::recover_all(&stripped_macho, limits)
                    .expect("name-stripped system slice");
                let structure = |program: &RecoveredProgram| {
                    program
                        .functions()
                        .unwrap()
                        .functions()
                        .iter()
                        .map(|function| {
                            (
                                function.entry,
                                function.entry_confidence,
                                function.extent,
                                function.conflicts.clone(),
                                function.completeness.extent_is_authoritative,
                            )
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(structure(&program), structure(&stripped));
                assert_eq!(
                    (
                        program.exceptions().unwrap().call_sites(),
                        program.exceptions().unwrap().cfi_rows(),
                    ),
                    (
                        stripped.exceptions().unwrap().call_sites(),
                        stripped.exceptions().unwrap().cfi_rows(),
                    ),
                    "name stripping changed semantic exception evidence for {path} CPU {:#x}/{:#x}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                );
                assert_eq!(
                    program.functions().unwrap().entry_candidates(),
                    stripped.functions().unwrap().entry_candidates(),
                    "name stripping changed entry-candidate reconciliation for {path} CPU {:#x}/{:#x}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                );
                let direct_edges = |program: &RecoveredProgram| {
                    program
                        .direct_calls()
                        .unwrap()
                        .edges()
                        .iter()
                        .map(|edge| {
                            (
                                edge.caller,
                                edge.callee,
                                edge.callsites
                                    .iter()
                                    .map(|callsite| callsite.instruction_address)
                                    .collect::<Vec<_>>(),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(direct_edges(&program), direct_edges(&stripped));
                let indirect_structure = |program: &RecoveredProgram| {
                    program
                        .indirect_calls()
                        .unwrap()
                        .calls()
                        .iter()
                        .filter(|call| {
                            call.carriers.iter().any(|carrier| {
                                matches!(
                                    carrier,
                                    crate::analysis::indirect_calls::IndirectTargetCarrier::StridedPointerTable { .. }
                                )
                            })
                        })
                        .map(|call| {
                            (
                                call.source_function,
                                call.instruction_address,
                                call.carriers.clone(),
                                call.candidates
                                    .iter()
                                    .map(|candidate| {
                                        let (kind, address, ordinal) = match &candidate.target {
                                            crate::analysis::indirect_calls::IndirectCallTarget::Import {
                                                library_ordinal,
                                                ..
                                            } => (0_u8, 0, *library_ordinal),
                                            crate::analysis::indirect_calls::IndirectCallTarget::Internal {
                                                address,
                                                ..
                                            } => (1, *address, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::ObjectiveCMethod {
                                                implementation,
                                                ..
                                            } => (2, *implementation, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::SwiftImplementation {
                                                implementation,
                                                ..
                                            } => (3, *implementation, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::CppVirtualMethod {
                                                implementation,
                                                ..
                                            } => (4, *implementation, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::SwiftProtocolWitness {
                                                implementation,
                                                ..
                                            } => (5, *implementation, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::BlockInvoke {
                                                implementation,
                                                ..
                                            } => (6, *implementation, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::SwiftClosure {
                                                implementation,
                                                ..
                                            } => (7, *implementation, None),
                                            crate::analysis::indirect_calls::IndirectCallTarget::CppVirtualMethodImport {
                                                library_ordinal,
                                                ..
                                            } => (8, 0, *library_ordinal),
                                            crate::analysis::indirect_calls::IndirectCallTarget::SwiftProtocolWitnessImport {
                                                library_ordinal,
                                                ..
                                            } => (9, 0, *library_ordinal),
                                            crate::analysis::indirect_calls::IndirectCallTarget::BlockInvokeImport {
                                                library_ordinal,
                                                ..
                                            } => (10, 0, *library_ordinal),
                                        };
                                        (
                                            kind,
                                            address,
                                            ordinal,
                                            candidate.source,
                                            candidate.confidence,
                                            candidate.evidence_address,
                                            candidate.authentication,
                                            candidate.detail.clone(),
                                        )
                                    })
                                    .collect::<Vec<_>>(),
                                call.status,
                                call.reasons.clone(),
                            )
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    indirect_structure(&program),
                    indirect_structure(&stripped),
                    "name stripping changed indirect-target recovery for {path} CPU {:#x}/{:#x}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                );
                assert_eq!(
                    stripped.indirect_calls().unwrap().status(),
                    crate::analysis::indirect_calls::IndirectCallIndexStatus::Complete,
                    "name-stripped indirect recovery must close for {path} CPU {:#x}/{:#x}: {:#?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                    stripped
                        .indirect_calls()
                        .unwrap()
                        .calls()
                        .iter()
                        .filter(|call| call.status
                            != crate::analysis::indirect_calls::IndirectCallSiteStatus::Complete)
                        .collect::<Vec<_>>(),
                );
                assert_eq!(
                    stripped.completeness().status,
                    ProgramRecoveryStatus::Complete,
                    "name-stripped all-stage recovery must close for {path} CPU {:#x}/{:#x}: {:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                    stripped.completeness().reasons,
                );
                let structural_exits = |program: &RecoveredProgram| {
                    program
                        .control_flow()
                        .unwrap()
                        .functions()
                        .iter()
                        .flat_map(|graph| {
                            graph.exits.iter().map(|exit| {
                                (
                                    graph.function_entry,
                                    exit.block,
                                    exit.instruction_address,
                                    exit.kind,
                                    exit.target,
                                )
                            })
                        })
                        .collect::<Vec<_>>()
                };
                assert_eq!(
                    structural_exits(&program),
                    structural_exits(&stripped),
                    "name stripping changed structural exit classification for {path} CPU {:#x}/{:#x}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                );
                let non_returning_calls = |program: &RecoveredProgram| {
                    program
                        .control_flow()
                        .unwrap()
                        .functions()
                        .iter()
                        .flat_map(|graph| {
                            graph.calls.iter().filter_map(|call| {
                                (call.return_behavior
                                    == crate::analysis::control_flow::ControlFlowCallReturnBehavior::NonReturning)
                                    .then_some((
                                        graph.function_entry,
                                        call.instruction_address,
                                        call.non_returning_callee,
                                    ))
                            })
                        })
                        .collect::<Vec<_>>()
                };
                let retained_non_returning = non_returning_calls(&program);
                assert!(
                    !retained_non_returning.is_empty(),
                    "system corpus should exercise imported non-returning calls"
                );
                assert_eq!(
                    retained_non_returning,
                    non_returning_calls(&stripped),
                    "stub-to-bind non-returning behavior changed after name stripping"
                );
                if path == "/bin/ls"
                    && macho.header().cpu_type().0 == crate::core::format::constants::CPU_TYPE_ARM64
                {
                    assert!(
                        retained_non_returning
                            .iter()
                            .any(|(_, _, callee)| callee.is_some()),
                        "ARM64e corpus should exercise a local non-returning summary"
                    );
                }
                if path == "/usr/bin/file"
                    && macho.header().cpu_type().0
                        == crate::core::format::constants::CPU_TYPE_X86_64
                {
                    let exceptions = program.exceptions().unwrap();
                    assert!(!exceptions.cfi_rows().is_empty());
                    let limited = crate::analysis::exception_index::ExceptionIndex::recover(
                        macho,
                        crate::analysis::exception_index::ExceptionRecoveryLimits {
                            max_cfi_rows: 1,
                            ..crate::analysis::exception_index::ExceptionRecoveryLimits::default()
                        },
                    )
                    .unwrap();
                    assert_eq!(
                        limited.status(),
                        crate::analysis::exception_index::ExceptionIndexStatus::Truncated
                    );
                    assert_eq!(limited.cfi_rows().len(), 1);
                }
                if matches!(path, "/bin/ls" | "/usr/bin/file") {
                    assert!(
                        program
                            .functions()
                            .unwrap()
                            .functions()
                            .iter()
                            .all(|function| function.completeness.extent_is_authoritative),
                        "/bin/ls must retain authoritative extents for every established function"
                    );
                    let graphs = program.control_flow().unwrap().functions();
                    assert!(
                        graphs.iter().all(|graph| {
                            graph.completeness.status
                                == crate::analysis::control_flow::FunctionControlFlowStatus::Complete
                        }),
                        "/bin/ls must close every established function CFG"
                    );
                    assert!(graphs.iter().all(|graph| {
                        graph.completeness.observed_bytes
                            == graph.completeness.instruction_bytes
                                + graph.completeness.data_bytes
                                + graph.completeness.gap_bytes
                                + graph.completeness.omitted_bytes
                    }));
                    assert!(graphs.iter().all(|graph| {
                        graph.completeness.gap_bytes == 0 && graph.completeness.omitted_bytes == 0
                    }));
                    assert!(!graphs.iter().flat_map(|graph| &graph.exits).any(|exit| {
                        exit.kind == crate::analysis::control_flow::ControlFlowExitKind::IndirectBranch
                    }));
                    assert!(graphs.iter().flat_map(|graph| &graph.exits).any(|exit| {
                        exit.kind == crate::analysis::control_flow::ControlFlowExitKind::JumpTableDispatch
                    }));
                }
                if path == "/bin/ls" {
                    let graphs = program.control_flow().unwrap().functions();
                    assert!(graphs.iter().flat_map(|graph| &graph.exits).any(|exit| {
                        exit.kind
                            == crate::analysis::control_flow::ControlFlowExitKind::TailDispatch
                    }));
                }
                recovered += 1;
            }
        }
        assert_ne!(recovered, 0);
    }
}
