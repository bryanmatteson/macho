//! Bounded basic-block and intra-procedural control-flow recovery.
//!
//! Graphs are tied to an exact [`crate::analysis::functions::FunctionIndex`] image
//! identity. Candidate function bounds remain candidate graph coverage, decode
//! gaps remain explicit, and branches outside a recovered function are exits
//! rather than invented intra-procedural edges.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::format::constants::{
    CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};
use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::insn::{
    Arch, BranchTarget, InsnKind, MemoryEffect, Operand, PcRelKind, Reg, RegClass, RegisterShift,
    ValueEffect,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::exception_index::{
    ExceptionActionKind, ExceptionCallSiteRecord, ExceptionIndex,
};
use crate::analysis::functions::{
    FunctionEvidenceConfidence, FunctionEvidenceSource, FunctionIdentity, FunctionImageIdentity,
    FunctionIndex, FunctionOwnershipConfidence, RecoveredFunction,
};
use crate::analysis::pointer_index::{PointerIndex, PointerRecordKind};
use crate::analysis::xref::refs::XrefTarget;

/// Explicit limits for one control-flow recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowLimits {
    /// Maximum functions admitted in entry-address order.
    pub max_functions: usize,
    /// Maximum cumulative function bytes examined.
    pub max_decoded_bytes: usize,
    /// Maximum decoded instructions retained per function.
    pub max_instructions_per_function: usize,
    /// Maximum basic blocks retained per function.
    pub max_blocks_per_function: usize,
    /// Maximum internal CFG edges retained per function.
    pub max_edges_per_function: usize,
    /// Maximum decode gaps retained per function.
    pub max_gaps_per_function: usize,
    /// Maximum recovered jump-table records retained per function.
    pub max_jump_tables_per_function: usize,
    /// Maximum entries retained from any one jump table.
    pub max_jump_table_entries: usize,
}

impl Default for ControlFlowLimits {
    fn default() -> Self {
        Self {
            max_functions: 1_000_000,
            max_decoded_bytes: 256 * 1024 * 1024,
            max_instructions_per_function: 1_000_000,
            max_blocks_per_function: 250_000,
            max_edges_per_function: 500_000,
            max_gaps_per_function: 65_536,
            max_jump_tables_per_function: 65_536,
            max_jump_table_entries: 65_536,
        }
    }
}

impl ControlFlowLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, ControlFlowRecoveryError> {
        if self.max_functions == 0
            || self.max_decoded_bytes == 0
            || self.max_instructions_per_function == 0
            || self.max_blocks_per_function == 0
            || self.max_edges_per_function == 0
            || self.max_gaps_per_function == 0
            || self.max_jump_tables_per_function == 0
            || self.max_jump_table_entries == 0
        {
            return Err(ControlFlowRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing control-flow recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ControlFlowRecoveryError {
    /// At least one explicit limit is zero.
    #[error("control-flow recovery limits must be non-zero")]
    InvalidLimits,
    /// The supplied function index belongs to different bytes or architecture.
    #[error("function index and Mach-O image identities differ")]
    ImageMismatch,
    /// The selected CPU tuple has no instruction decoder.
    #[error("control-flow recovery does not support this CPU tuple")]
    UnsupportedArchitecture,
}

/// Validated caller byte-role premises used during a cold CFG rebuild.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ControlFlowRecoveryGuidance {
    pub(crate) image: FunctionImageIdentity,
    pub(crate) non_instruction_ranges: Vec<(u64, u64)>,
    pub(crate) instruction_ranges: Vec<(u64, u64)>,
}

/// Coarse instruction semantics retained for graph consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowInstructionKind {
    /// Unconditional branch.
    Branch,
    /// Call instruction.
    Call,
    /// Conditional branch.
    ConditionalBranch,
    /// Function return.
    Return,
    /// Instruction without direct control-flow semantics.
    Other,
}

/// Representation of an indirect control-flow target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectTargetKind {
    /// Register-indirect target.
    Register,
    /// Memory-indirect target.
    Memory,
    /// Indexed memory expression.
    IndexedMemory,
    /// Target representation added after this decoder was built.
    Unknown,
}

/// Target retained on a branch or call instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InstructionTarget {
    /// Direct virtual address.
    Direct {
        /// Resolved virtual address.
        address: u64,
    },
    /// Indirect target class.
    Indirect {
        /// Register, memory, or unknown indirect representation.
        target_kind: IndirectTargetKind,
    },
    /// Indexed memory target retained for jump-table recovery.
    IndexedMemory {
        /// Optional mapped base register.
        base: Option<ControlFlowRegister>,
        /// Index register.
        index: ControlFlowRegister,
        /// Index scale in bytes.
        scale: u8,
        /// Signed encoded displacement.
        displacement: i64,
    },
}

/// One decoded instruction retained for graph and later call-graph recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowInstruction {
    /// Instruction virtual address.
    pub address: u64,
    /// Encoded byte length.
    pub byte_len: u8,
    /// Coarse semantics.
    pub kind: ControlFlowInstructionKind,
    /// Direct or indirect control-flow target.
    pub target: Option<InstructionTarget>,
    /// Architecture-neutral decoded operands in source order.
    pub operands: Vec<ControlFlowOperand>,
    /// First explicitly written register, when represented by the decoder.
    pub written_register: Option<ControlFlowRegister>,
    /// Address-value effect on the written register.
    pub value_effect: ControlFlowValueEffect,
    /// Supported explicit memory-write semantics.
    pub memory_effect: ControlFlowMemoryEffect,
    /// Whether the instruction has an implicit GPR0 write.
    pub writes_implicit_gpr0: bool,
    /// PC-relative address or memory reference, when present.
    pub pc_relative: Option<ControlFlowPcRelative>,
    /// Confidence of the function range admitting this instruction.
    pub coverage_confidence: FunctionEvidenceConfidence,
}

/// Architecture-neutral register retained for local value-flow recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ControlFlowRegister {
    /// General-purpose or floating-point/SIMD class.
    pub class: ControlFlowRegisterClass,
    /// Architecture-native register number within the class.
    pub number: u8,
}

/// Register class retained on decoded operands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowRegisterClass {
    /// General-purpose register.
    GeneralPurpose,
    /// Floating-point or SIMD register.
    FloatingPoint,
}

/// One decoded instruction operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlFlowOperand {
    /// Register operand.
    Register {
        /// Referenced register.
        register: ControlFlowRegister,
    },
    /// Register operand transformed by an encoded shift.
    ShiftedRegister {
        /// Referenced register.
        register: ControlFlowRegister,
        /// Shift operation.
        shift: ControlFlowRegisterShift,
        /// Shift amount in bits.
        amount: u8,
    },
    /// Signed immediate operand.
    Immediate {
        /// Signed immediate value.
        value: i64,
    },
    /// Base-plus-displacement memory operand.
    Memory {
        /// Address base register.
        base: ControlFlowRegister,
        /// Signed byte displacement.
        displacement: i64,
    },
    /// Indexed memory operand.
    IndexedMemory {
        /// Address base register.
        base: ControlFlowRegister,
        /// Index register.
        index: ControlFlowRegister,
        /// Index scale in bytes.
        scale: u8,
        /// Signed byte displacement.
        displacement: i64,
    },
}

/// Shift retained on a register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowRegisterShift {
    /// Logical shift left.
    LogicalLeft,
    /// Logical shift right.
    LogicalRight,
    /// Arithmetic shift right.
    ArithmeticRight,
    /// Rotate right.
    RotateRight,
}

/// Architecture-neutral value effect retained for indirect-target recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowValueEffect {
    /// No explicitly written first operand.
    None,
    /// Assignment from a register or immediate operand.
    Set,
    /// Address computation from a memory-form operand.
    Address,
    /// Load through a memory-form operand.
    Load,
    /// Addition of a signed immediate to a source register.
    AddImmediate,
    /// Addition of one source register to another.
    AddRegister,
    /// Subtraction of the second source register from the first.
    SubtractRegister,
    /// Bitwise masking by an immediate.
    BitwiseAndImmediate,
    /// Shift by an immediate amount.
    ShiftImmediate,
    /// Conditional selection between decoded sources.
    ConditionalSelect,
    /// Zero-extend the low 8 bits of the source.
    ZeroExtend8,
    /// Zero-extend the low 16 bits of the source.
    ZeroExtend16,
    /// Zero-extend the low 32 bits of the source.
    ZeroExtend32,
    /// Sign-extend the low 8 bits of the source.
    SignExtend8,
    /// Sign-extend the low 16 bits of the source.
    SignExtend16,
    /// Sign-extend the low 32 bits of the source.
    SignExtend32,
    /// Sign a pointer with the IA key.
    SignPointerIa,
    /// Sign a pointer with the IB key.
    SignPointerIb,
    /// Sign a pointer with the DA key.
    SignPointerDa,
    /// Sign a pointer with the DB key.
    SignPointerDb,
    /// Authenticate a pointer with the IA key.
    AuthenticatePointerIa,
    /// Authenticate a pointer with the IB key.
    AuthenticatePointerIb,
    /// Authenticate a pointer with the DA key.
    AuthenticatePointerDa,
    /// Authenticate a pointer with the DB key.
    AuthenticatePointerDb,
    /// Strip pointer authentication from the value.
    StripPointerAuthentication,
    /// Written value has no safe decoded transfer model.
    UnknownWrite,
}

/// Architecture-neutral explicit memory effect retained for value flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowMemoryEffect {
    /// No supported explicit memory write.
    None,
    /// A source register is stored through a decoded memory operand.
    Store,
    /// Memory is written but cannot be precisely modeled.
    UnknownWrite,
}

/// Semantics of a retained PC-relative instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowPcRelativeKind {
    /// Exact address materialization.
    Address,
    /// Page-address materialization.
    PageAddress,
    /// Memory reference at the target.
    Memory,
}

/// Resolved PC-relative target retained on an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowPcRelative {
    /// Resolved virtual address.
    pub address: u64,
    /// Address, page-address, or memory semantics.
    pub kind: ControlFlowPcRelativeKind,
}

/// Why instruction decoding skipped a byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowGapKind {
    /// Bytes did not decode as an instruction.
    InvalidInstruction,
    /// A recovered range could not be mapped to file bytes.
    UnmappedRange,
}

/// One explicit decode gap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowGap {
    /// Gap start address.
    pub start: u64,
    /// Exclusive gap end.
    pub end_exclusive: u64,
    /// Gap classification.
    pub kind: ControlFlowGapKind,
    /// Confidence of the range in which the gap occurred.
    pub coverage_confidence: FunctionEvidenceConfidence,
}

/// Function coverage intentionally excluded from instruction decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowDataRange {
    /// First byte classified as data.
    pub start: u64,
    /// Exclusive data-range end.
    pub end_exclusive: u64,
    /// Displaced function-coverage confidence.
    pub coverage_confidence: FunctionEvidenceConfidence,
    /// Evidence establishing data ownership.
    pub reason: ControlFlowDataRangeReason,
}

/// Evidence that excludes a range from instruction decoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowDataRangeReason {
    /// Explicit validated caller guidance.
    CallerGuided,
    /// A bounded, readable jump table consumed by an indirect branch.
    RecoveredJumpTable,
}

/// Exactly one retained function-local classification for an admitted byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowByteRangeKind {
    /// Bytes retained by one decoded instruction stream.
    Instruction,
    /// Bytes retained as embedded data rather than decoded instructions.
    Data,
    /// Bytes examined but not decoded or mapped successfully.
    Gap,
    /// Bytes admitted by function coverage but omitted by a budget or local limit.
    Omitted,
}

/// One non-overlapping range in the function-local byte-conservation ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowByteRange {
    /// First accounted byte.
    pub start: u64,
    /// Exclusive range end.
    pub end_exclusive: u64,
    /// Retained byte classification.
    pub kind: ControlFlowByteRangeKind,
}

/// Why a basic block ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BasicBlockTermination {
    /// Return instruction.
    Return,
    /// Unconditional branch.
    Branch,
    /// Conditional branch.
    ConditionalBranch,
    /// Call followed by a potential return site.
    Call,
    /// Ordinary fallthrough into another block.
    Fallthrough,
    /// Decoded coverage or a candidate function bound ended.
    RangeBoundary,
}

/// One maximal straight-line instruction sequence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BasicBlock {
    /// Function-local deterministic block identifier.
    pub id: u64,
    /// First instruction address.
    pub start: u64,
    /// Exclusive end of the last instruction.
    pub end_exclusive: u64,
    /// First instruction ordinal in the function instruction array.
    pub first_instruction: u64,
    /// Number of instructions in the block.
    pub instruction_count: u64,
    /// Whether control flow from the entry reaches this block. This remains
    /// unknown when incomplete edge or decode coverage could hide a path.
    pub reachability: ControlFlowReachability,
    /// Terminator or boundary that ends the block.
    pub termination: BasicBlockTermination,
    /// Weakest coverage confidence among the block's instructions.
    pub coverage_confidence: FunctionEvidenceConfidence,
}

/// Reachability of a retained basic block from its recovered function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowReachability {
    /// A retained path from the entry reaches this block.
    Reachable,
    /// Complete local control-flow evidence proves no path reaches this block.
    Unreachable,
    /// Missing, uncertain, or budget-truncated evidence may hide a path.
    Unknown,
}

/// Kind of an intra-procedural CFG edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowEdgeKind {
    /// Ordinary sequential flow.
    Fallthrough,
    /// Target of an unconditional branch.
    Branch,
    /// Taken side of a conditional branch.
    ConditionalTaken,
    /// Not-taken side of a conditional branch.
    ConditionalNotTaken,
    /// Return site after a call.
    CallReturn,
    /// Candidate target recovered from a bounded jump table.
    JumpTableCandidate,
    /// Exceptional transfer from a protected call site to a local landing pad.
    Exceptional,
}

/// One retained edge between blocks in the same recovered function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowEdge {
    /// Source block identifier.
    pub from: u64,
    /// Destination block identifier.
    pub to: u64,
    /// Edge semantics.
    pub kind: ControlFlowEdgeKind,
}

/// Supported on-disk jump-table encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JumpTableEncoding {
    /// Eight-byte absolute function-local target pointers.
    AbsolutePointer64,
    /// Four-byte signed offsets relative to a materialized table base.
    RelativeSigned32,
    /// Unsigned byte offsets scaled by four from a separately materialized target base.
    RelativeUnsigned8Scaled4,
    /// Unsigned halfword offsets scaled by four from a separately materialized target base.
    RelativeUnsigned16Scaled4,
}

/// One retained jump-table entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpTableEntry {
    /// Zero-based table index.
    pub index: u64,
    /// Address of the encoded table entry.
    pub entry_address: u64,
    /// Decoded target address.
    pub target: u64,
    /// Function-local target block after block construction.
    pub target_block: u64,
}

/// Evidence that bounds a recovered jump table and identifies its default path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JumpTableRangeEvidence {
    /// Comparison instruction establishing the inclusive maximum, when used.
    pub compare_instruction_address: Option<u64>,
    /// Conditional branch rejecting an index above the maximum.
    pub guard_instruction_address: u64,
    /// Semantics used to reject or normalize an out-of-range index.
    pub guard_kind: JumpTableRangeGuardKind,
    /// Function-local block containing the guard branch.
    pub guard_block: u64,
    /// Largest index admitted by the guard.
    pub maximum_index: u64,
    /// Exact entry count implied by the inclusive maximum.
    pub entry_count: u64,
    /// Destination for an out-of-range index, when the guard has such a path.
    pub default_target: Option<u64>,
    /// Function-local default block, when retained by the current block budget.
    pub default_block: Option<u64>,
}

/// Supported range-guard behavior for a jump table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JumpTableRangeGuardKind {
    /// `B.HI` transfers an index above the maximum to a direct default block.
    BranchAbove,
    /// `B.HS`/`JAE` rejects an index greater than or equal to an exclusive count.
    BranchAboveOrEqual,
    /// `CSEL ..., LS` replaces an index above the maximum with table index zero.
    ClampToFirstEntry,
    /// A bitwise mask makes every resulting index fall within the table range.
    BitMask,
    /// A 64-bit logical right shift leaves a bounded number of low result bits.
    LogicalShiftRight,
}

/// One bounded candidate jump table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredJumpTable {
    /// Indirect branch instruction consuming the table.
    pub instruction_address: u64,
    /// Function-local source block.
    pub source_block: u64,
    /// First encoded table byte.
    pub table_address: u64,
    /// Exclusive end of retained table bytes.
    pub end_exclusive: u64,
    /// Entry encoding.
    pub encoding: JumpTableEncoding,
    /// Retained candidate entries.
    pub entries: Vec<JumpTableEntry>,
    /// Proven range-check and default-path evidence, when supported.
    pub range: Option<JumpTableRangeEvidence>,
    /// Whether the per-table entry budget omitted a supported entry.
    pub truncated: bool,
    /// Stable reason codes limiting certainty.
    pub reasons: Vec<String>,
}

/// Why control flow leaves known intra-procedural blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowExitKind {
    /// Function return.
    Return,
    /// A call with a supported non-returning contract.
    NonReturningCall,
    /// A terminal branch to a supported non-returning import or local function.
    NonReturningTransfer,
    /// Direct branch outside this recovered function.
    DirectBranch,
    /// Complete bounded jump-table dispatch with retained candidate targets.
    JumpTableDispatch,
    /// Terminal dispatch through a function pointer loaded from a statically
    /// addressed global slot. The runtime-selected target remains unresolved.
    TailDispatch,
    /// An LSDA-covered call may unwind out of this function.
    ExceptionalUnwind,
    /// Register- or memory-indirect branch.
    IndirectBranch,
    /// Conditional fallthrough has no retained destination block.
    FallthroughOutsideCoverage,
    /// Ordinary decoded coverage ended.
    RangeBoundary,
}

/// One exit from retained intra-procedural control flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowExit {
    /// Source block identifier.
    pub block: u64,
    /// Address of the controlling instruction, when one exists.
    pub instruction_address: Option<u64>,
    /// Exit classification.
    pub kind: ControlFlowExitKind,
    /// Direct target address, when present.
    pub target: Option<u64>,
    /// Recovered target function entry, when the target is an exact entry.
    pub recovered_function: Option<u64>,
    /// Every recovered identity that could own the target address.
    pub possible_functions: Vec<RecoveredFunctionTarget>,
}

/// How a decoded address relates to a recovered function identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionTargetRelation {
    /// The decoded address equals the function entry.
    ExactEntry,
    /// Caller guidance identifies a second entry into an existing function.
    CallerGuidedAlternateEntry,
    /// Caller guidance identifies a discontiguous cold fragment.
    CallerGuidedColdFragment,
    /// Caller guidance identifies an intentionally shared range.
    CallerGuidedSharedRange,
    /// A retained exact, derived, or candidate extent contains the address.
    ContainingExtent,
}

/// One possible recovered owner of a branch or call target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredFunctionTarget {
    /// Recovered function entry.
    pub entry: u64,
    /// Exact-entry or containing-extent relationship.
    pub relation: FunctionTargetRelation,
    /// Confidence that the identity is a function entry.
    pub entry_confidence: FunctionEvidenceConfidence,
    /// Confidence that this function owns the decoded target address.
    pub ownership_confidence: FunctionOwnershipConfidence,
}

/// Target of one callsite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlFlowCallTarget {
    /// Direct call target.
    Direct {
        /// Target virtual address.
        address: u64,
        /// Recovered callee entry at that exact address.
        recovered_function: Option<u64>,
        /// Confidence of the recovered callee entry.
        entry_confidence: Option<FunctionEvidenceConfidence>,
        /// Every recovered identity that could own the direct target.
        possible_functions: Vec<RecoveredFunctionTarget>,
    },
    /// Indirect call target.
    Indirect {
        /// Register, memory, or unknown indirect representation.
        target_kind: IndirectTargetKind,
    },
}

/// One call instruction associated with its containing basic block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowCallsite {
    /// Containing block identifier.
    pub block: u64,
    /// Call instruction address.
    pub instruction_address: u64,
    /// Direct or indirect target.
    pub target: ControlFlowCallTarget,
    /// Supported normal-return behavior.
    pub return_behavior: ControlFlowCallReturnBehavior,
    /// Imported symbol establishing non-returning behavior, when present.
    pub non_returning_symbol: Option<String>,
    /// Recovered local callee whose closed CFG establishes non-returning behavior.
    pub non_returning_callee: Option<u64>,
    /// Semantic exceptional behavior established by an LSDA call-site entry.
    #[serde(default)]
    pub exceptional_behavior: ControlFlowCallExceptionBehavior,
    /// Local landing-pad addresses established for this call.
    #[serde(default)]
    pub landing_pads: Vec<u64>,
}

/// Supported exceptional behavior of one retained callsite.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowCallExceptionBehavior {
    /// No semantic LSDA entry was associated with this call.
    #[default]
    NotEstablished,
    /// The call has one or more local landing-pad destinations.
    LocalLandingPad,
    /// The call-site entry has no local landing pad and unwinding continues outward.
    UnwindsOutOfFunction,
}

/// Provenance for one exceptional CFG edge or outward-unwind exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlFlowExceptionalTransfer {
    /// Call instruction covered by the LSDA entry.
    pub instruction_address: u64,
    /// Source block containing the call.
    pub source_block: u64,
    /// Local landing-pad address, absent for outward unwind.
    pub landing_pad: Option<u64>,
    /// Destination block for a retained local landing pad.
    pub destination_block: Option<u64>,
    /// LSDA virtual address establishing the transfer.
    pub lsda_address: u64,
    /// One-based action-table selector.
    pub action_offset: u64,
    /// Retained action semantics in chain order.
    pub actions: Vec<ExceptionActionKind>,
}

/// Supported normal-return behavior for one callsite.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowCallReturnBehavior {
    /// No supported evidence rules out a normal return.
    MayReturn,
    /// A known import contract or transitively closed local callee proves no
    /// normal return.
    NonReturning,
}

/// Completeness state of one recovered function graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionControlFlowStatus {
    /// All admitted exact ranges decoded without gaps or conflicts.
    Complete,
    /// Graph is useful but depends on uncertain bounds, gaps, or incomplete evidence.
    Partial,
    /// An explicit recovery budget stopped graph construction.
    Truncated,
    /// No decodable function coverage was available.
    Unavailable,
}

/// Exact first coordinate omitted by a control-flow recovery budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ControlFlowContinuation {
    /// A whole function was omitted by the function-count budget.
    Function {
        /// First omitted function entry.
        entry: u64,
    },
    /// Byte recovery stopped before this address.
    Byte {
        /// Containing function entry.
        function_entry: u64,
        /// First omitted byte address.
        address: u64,
    },
    /// Instruction retention stopped before decoding this address.
    Instruction {
        /// Containing function entry.
        function_entry: u64,
        /// First omitted instruction address.
        address: u64,
    },
    /// Basic-block retention stopped at this derived block.
    Block {
        /// Containing function entry.
        function_entry: u64,
        /// First omitted function-local block identifier.
        block: u64,
        /// First omitted block start address.
        start: u64,
    },
    /// Edge retention stopped at this derived edge.
    Edge {
        /// Containing function entry.
        function_entry: u64,
        /// First omitted edge.
        edge: ControlFlowEdge,
    },
    /// Decode-gap retention stopped at this address.
    Gap {
        /// Containing function entry.
        function_entry: u64,
        /// Start of the first omitted gap.
        address: u64,
    },
    /// Jump-table retention stopped at this table entry.
    JumpTable {
        /// Containing function entry.
        function_entry: u64,
        /// Indirect branch consuming the table.
        instruction_address: u64,
        /// First table byte.
        table_address: u64,
        /// First omitted entry index; zero denotes an omitted table record.
        index: u64,
    },
}

/// Completeness and work receipt for one function graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionControlFlowCompleteness {
    /// Overall graph state.
    pub status: FunctionControlFlowStatus,
    /// Weakest admitted range confidence.
    pub boundary_confidence: Option<FunctionEvidenceConfidence>,
    /// Bytes examined for this function.
    pub decoded_bytes: u64,
    /// Total bytes admitted by the retained function coverage.
    #[serde(default)]
    pub observed_bytes: u64,
    /// Bytes retained as instructions.
    #[serde(default)]
    pub instruction_bytes: u64,
    /// Bytes retained as embedded data.
    #[serde(default)]
    pub data_bytes: u64,
    /// Bytes retained as explicit decode or mapping gaps.
    #[serde(default)]
    pub gap_bytes: u64,
    /// Bytes admitted but omitted by a budget or local construction limit.
    #[serde(default)]
    pub omitted_bytes: u64,
    /// Stable reason codes explaining non-completeness.
    pub reasons: Vec<String>,
    /// Exact first coordinate omitted by a local budget.
    #[serde(default)]
    pub continuation: Option<ControlFlowContinuation>,
}

/// Recovered instructions, blocks, edges, exits, and calls for one function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionControlFlow {
    /// Recovered function entry.
    pub function_entry: u64,
    /// Function identity copied from the inventory.
    pub identity: FunctionIdentity,
    /// Decoded instructions sorted by address.
    pub instructions: Vec<ControlFlowInstruction>,
    /// Explicit decode gaps sorted by address.
    pub gaps: Vec<ControlFlowGap>,
    /// Caller-guided embedded-data ranges excluded before instruction decoding.
    #[serde(default)]
    pub data_ranges: Vec<ControlFlowDataRange>,
    /// Exact non-overlapping classification of every admitted function byte.
    #[serde(default)]
    pub byte_ranges: Vec<ControlFlowByteRange>,
    /// Basic blocks sorted by start address.
    pub blocks: Vec<BasicBlock>,
    /// Internal edges sorted by source, destination, and kind.
    pub edges: Vec<ControlFlowEdge>,
    /// Exits from retained intra-procedural coverage.
    pub exits: Vec<ControlFlowExit>,
    /// Callsites sorted by instruction address.
    pub calls: Vec<ControlFlowCallsite>,
    /// Exceptional transfers with exact LSDA provenance.
    #[serde(default)]
    pub exceptional_transfers: Vec<ControlFlowExceptionalTransfer>,
    /// Bounded candidate jump tables sorted by controlling instruction.
    pub jump_tables: Vec<RecoveredJumpTable>,
    /// Graph-local completeness and work receipt.
    pub completeness: FunctionControlFlowCompleteness,
}

/// Global status for one bounded control-flow index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowIndexStatus {
    /// Every admitted function graph completed.
    Complete,
    /// At least one graph is partial or unavailable.
    Partial,
    /// At least one explicit global budget was exhausted.
    Truncated,
}

/// Bounded control-flow inventory tied to one function index and image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ControlFlowIndex {
    image: FunctionImageIdentity,
    limits: ControlFlowLimits,
    functions: Vec<FunctionControlFlow>,
    status: ControlFlowIndexStatus,
    decoded_bytes: u64,
    truncated_function_count: u64,
    continuation: Option<ControlFlowContinuation>,
}

impl ControlFlowIndex {
    /// Recover per-function basic blocks and intra-procedural edges.
    pub fn recover(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        limits: ControlFlowLimits,
    ) -> Result<Self, ControlFlowRecoveryError> {
        Self::recover_internal(macho, functions, None, None, limits, None)
    }

    /// Recover control flow while using format-level stubs to establish known
    /// non-returning imported calls.
    pub fn recover_with_pointers(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        pointers: &PointerIndex,
        limits: ControlFlowLimits,
    ) -> Result<Self, ControlFlowRecoveryError> {
        Self::recover_internal(macho, functions, Some(pointers), None, limits, None)
    }

    /// Recover control flow with pointer and semantic exception evidence.
    pub fn recover_with_evidence(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        pointers: Option<&PointerIndex>,
        exceptions: Option<&ExceptionIndex>,
        limits: ControlFlowLimits,
    ) -> Result<Self, ControlFlowRecoveryError> {
        Self::recover_internal(macho, functions, pointers, exceptions, limits, None)
    }

    pub(crate) fn recover_with_guidance(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        pointers: Option<&PointerIndex>,
        exceptions: Option<&ExceptionIndex>,
        limits: ControlFlowLimits,
        guidance: &ControlFlowRecoveryGuidance,
    ) -> Result<Self, ControlFlowRecoveryError> {
        Self::recover_internal(
            macho,
            functions,
            pointers,
            exceptions,
            limits,
            Some(guidance),
        )
    }

    fn recover_internal(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        pointers: Option<&PointerIndex>,
        exceptions: Option<&ExceptionIndex>,
        limits: ControlFlowLimits,
        guidance: Option<&ControlFlowRecoveryGuidance>,
    ) -> Result<Self, ControlFlowRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        if &image != functions.image()
            || pointers.is_some_and(|index| index.image() != &image)
            || exceptions.is_some_and(|index| index.image() != &image)
            || guidance.is_some_and(|guide| guide.image != image)
        {
            return Err(ControlFlowRecoveryError::ImageMismatch);
        }
        let arch =
            instruction_arch(macho).ok_or(ControlFlowRecoveryError::UnsupportedArchitecture)?;
        let non_returning_stubs = non_returning_stub_symbols(macho, arch, pointers);
        let admitted = functions.functions().len().min(limits.max_functions);
        let mut non_returning_functions = BTreeSet::new();
        let (graphs, decoded_bytes, remaining_bytes) = loop {
            let recovery = FunctionRecoveryContext {
                macho,
                function_index: functions,
                arch,
                limits,
                non_returning_stubs: &non_returning_stubs,
                non_returning_functions: &non_returning_functions,
                exceptions,
                guidance,
            };
            let mut remaining_bytes = limits.max_decoded_bytes;
            let mut graphs = Vec::with_capacity(admitted);
            let mut decoded_bytes = 0_u64;
            for function in functions.functions().iter().take(admitted) {
                if remaining_bytes == 0 {
                    break;
                }
                let graph = recover_function(&recovery, function, &mut remaining_bytes);
                decoded_bytes = decoded_bytes.saturating_add(graph.completeness.decoded_bytes);
                graphs.push(graph);
            }
            let previous = non_returning_functions.len();
            non_returning_functions.extend(
                graphs
                    .iter()
                    .filter(|graph| graph_proves_non_returning(graph))
                    .map(|graph| graph.function_entry),
            );
            if non_returning_functions.len() == previous {
                break (graphs, decoded_bytes, remaining_bytes);
            }
        };
        let globally_truncated = functions.functions().len() > admitted
            || graphs
                .iter()
                .any(|graph| graph.completeness.status == FunctionControlFlowStatus::Truncated);
        let truncated_function_count =
            functions.functions().len().saturating_sub(graphs.len()) as u64;
        let continuation = graphs
            .iter()
            .find_map(|graph| graph.completeness.continuation.clone())
            .or_else(|| {
                functions.functions().get(graphs.len()).map(|function| {
                    if graphs.len() < admitted && remaining_bytes == 0 {
                        ControlFlowContinuation::Byte {
                            function_entry: function.entry,
                            address: function.entry,
                        }
                    } else {
                        ControlFlowContinuation::Function {
                            entry: function.entry,
                        }
                    }
                })
            });
        let status = if globally_truncated || truncated_function_count != 0 {
            ControlFlowIndexStatus::Truncated
        } else if graphs
            .iter()
            .any(|graph| graph.completeness.status != FunctionControlFlowStatus::Complete)
        {
            ControlFlowIndexStatus::Partial
        } else {
            ControlFlowIndexStatus::Complete
        };
        Ok(Self {
            image,
            limits,
            functions: graphs,
            status,
            decoded_bytes,
            truncated_function_count,
            continuation,
        })
    }

    /// Exact image identity shared with the source function inventory.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Limits used for this recovery operation.
    pub const fn limits(&self) -> ControlFlowLimits {
        self.limits
    }

    /// Function graphs sorted by recovered entry address.
    pub fn functions(&self) -> &[FunctionControlFlow] {
        &self.functions
    }

    /// Overall index status.
    pub const fn status(&self) -> ControlFlowIndexStatus {
        self.status
    }

    /// Cumulative bytes examined.
    pub const fn decoded_bytes(&self) -> u64 {
        self.decoded_bytes
    }

    /// Function identities omitted by global limits.
    pub const fn truncated_function_count(&self) -> u64 {
        self.truncated_function_count
    }

    /// Exact first coordinate omitted by any control-flow budget.
    pub fn continuation(&self) -> Option<&ControlFlowContinuation> {
        self.continuation.as_ref()
    }

    /// Find the graph for one exact recovered function entry.
    pub fn by_entry(&self, entry: u64) -> Option<&FunctionControlFlow> {
        self.functions
            .binary_search_by_key(&entry, |graph| graph.function_entry)
            .ok()
            .map(|index| &self.functions[index])
    }
}

fn graph_proves_non_returning(graph: &FunctionControlFlow) -> bool {
    if matches!(
        graph.completeness.status,
        FunctionControlFlowStatus::Truncated | FunctionControlFlowStatus::Unavailable
    ) || graph.completeness.continuation.is_some()
    {
        return false;
    }
    let reachable = graph
        .blocks
        .iter()
        .filter(|block| block.reachability == ControlFlowReachability::Reachable)
        .map(|block| block.id)
        .collect::<BTreeSet<_>>();
    let reachable_exits = graph
        .exits
        .iter()
        .filter(|exit| reachable.contains(&exit.block))
        .collect::<Vec<_>>();
    !reachable_exits.is_empty()
        && reachable_exits.iter().all(|exit| {
            matches!(
                exit.kind,
                ControlFlowExitKind::NonReturningCall | ControlFlowExitKind::NonReturningTransfer
            )
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CoverageRange {
    start: u64,
    end: u64,
    confidence: FunctionEvidenceConfidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct CoverageEvent {
    position: u64,
    starts: bool,
    confidence: FunctionEvidenceConfidence,
}

fn function_coverage(function: &RecoveredFunction) -> Vec<CoverageRange> {
    if !function.caller_guided_ranges.is_empty() {
        return function
            .caller_guided_ranges
            .iter()
            .map(|extent| CoverageRange {
                start: extent.start,
                end: extent.end_exclusive,
                confidence: extent.confidence,
            })
            .collect();
    }
    let mut raw = Vec::new();
    if let Some(extent) = function.extent {
        raw.push(CoverageRange {
            start: extent.start,
            end: extent.end_exclusive,
            confidence: extent.confidence,
        });
    }
    for evidence in &function.evidence {
        if function.completeness.extent_is_authoritative
            && evidence.confidence == FunctionEvidenceConfidence::Candidate
        {
            continue;
        }
        if let (Some(start), Some(end)) = (evidence.extent_start, evidence.end_exclusive)
            && end > start
        {
            raw.push(CoverageRange {
                start,
                end,
                confidence: evidence.confidence,
            });
        }
    }
    let mut events = Vec::with_capacity(raw.len().saturating_mul(2));
    for range in raw {
        events.push(CoverageEvent {
            position: range.start,
            starts: true,
            confidence: range.confidence,
        });
        events.push(CoverageEvent {
            position: range.end,
            starts: false,
            confidence: range.confidence,
        });
    }
    events.sort();
    let mut active = BTreeMap::<FunctionEvidenceConfidence, usize>::new();
    let mut result = Vec::<CoverageRange>::new();
    let mut cursor = events.first().map_or(0, |event| event.position);
    let mut index = 0;
    while index < events.len() {
        let position = events[index].position;
        if cursor < position
            && let Some((&confidence, _)) = active.last_key_value()
        {
            if let Some(previous) = result.last_mut()
                && previous.end == cursor
                && previous.confidence == confidence
            {
                previous.end = position;
            } else {
                result.push(CoverageRange {
                    start: cursor,
                    end: position,
                    confidence,
                });
            }
        }
        while index < events.len() && events[index].position == position && !events[index].starts {
            if let Some(count) = active.get_mut(&events[index].confidence) {
                *count -= 1;
                if *count == 0 {
                    active.remove(&events[index].confidence);
                }
            }
            index += 1;
        }
        while index < events.len() && events[index].position == position && events[index].starts {
            *active.entry(events[index].confidence).or_default() += 1;
            index += 1;
        }
        cursor = position;
    }
    result
}

fn partition_guided_data_ranges(
    coverage: Vec<CoverageRange>,
    guided_data: &[(u64, u64)],
) -> (Vec<CoverageRange>, Vec<ControlFlowDataRange>) {
    let mut code = Vec::new();
    let mut data = Vec::new();
    for range in coverage {
        let mut fragments = vec![(range.start, range.end)];
        for &(data_start, data_end) in guided_data {
            if data_start >= data_end || data_start >= range.end || data_end <= range.start {
                continue;
            }
            let overlap_start = data_start.max(range.start);
            let overlap_end = data_end.min(range.end);
            data.push(ControlFlowDataRange {
                start: overlap_start,
                end_exclusive: overlap_end,
                coverage_confidence: range.confidence,
                reason: ControlFlowDataRangeReason::CallerGuided,
            });
            fragments = fragments
                .into_iter()
                .flat_map(|(start, end)| {
                    let mut retained = Vec::with_capacity(2);
                    if start < overlap_start {
                        retained.push((start, overlap_start.min(end)));
                    }
                    if overlap_end < end {
                        retained.push((overlap_end.max(start), end));
                    }
                    retained.into_iter().filter(|(start, end)| start < end)
                })
                .collect();
        }
        code.extend(fragments.into_iter().map(|(start, end)| CoverageRange {
            start,
            end,
            confidence: range.confidence,
        }));
    }
    code.sort_by_key(|range| (range.start, range.end));
    data.sort_by_key(|range| (range.start, range.end_exclusive));
    data.dedup();
    (code, data)
}

fn non_returning_stub_symbols(
    macho: &MachoFile<'_>,
    arch: Arch,
    pointers: Option<&PointerIndex>,
) -> BTreeMap<u64, String> {
    let Some(pointers) = pointers else {
        return BTreeMap::new();
    };
    let known_pointer_targets = pointers
        .pointers()
        .iter()
        .filter_map(|pointer| {
            let XrefTarget::Import { name, .. } = &pointer.target else {
                return None;
            };
            known_non_returning_import(name).then(|| (pointer.address, name.clone()))
        })
        .collect::<BTreeMap<_, _>>();
    let bound_slots = pointers
        .pointers()
        .iter()
        .filter(|pointer| pointer.kind != PointerRecordKind::Stub)
        .map(|pointer| pointer.address)
        .collect::<BTreeSet<_>>();
    pointers
        .pointers()
        .iter()
        .filter(|pointer| {
            pointer.kind == PointerRecordKind::Stub && !bound_slots.contains(&pointer.address)
        })
        .filter_map(|pointer| {
            if let XrefTarget::Import { name, .. } = &pointer.target
                && known_non_returning_import(name)
            {
                return Some((pointer.address, name.clone()));
            }
            stub_pointer_slots(macho, arch, pointer.address)
                .into_iter()
                .find_map(|slot| known_pointer_targets.get(&slot).cloned())
                .map(|name| (pointer.address, name))
        })
        .collect()
}

fn stub_pointer_slots(macho: &MachoFile<'_>, arch: Arch, address: u64) -> Vec<u64> {
    let Ok(bytes) = macho.read_bytes_at_va(Va(address), 32) else {
        return Vec::new();
    };
    let mut slots = BTreeSet::new();
    if arch == Arch::X86_64
        && matches!(bytes.get(..2), Some([0xff, 0x25]))
        && let Some(encoded) = bytes.get(2..6)
    {
        let displacement = i32::from_le_bytes(encoded.try_into().expect("four-byte slice"));
        if let Some(slot) = address
            .checked_add(6)
            .and_then(|next| next.checked_add_signed(displacement as i64))
        {
            slots.insert(slot);
        }
    }
    let mut values = BTreeMap::<ControlFlowRegister, u64>::new();
    let mut offset = 0_usize;
    for _ in 0..6 {
        let Ok(decoded) = crate::insn::decode_one(&bytes[offset..], address + offset as u64, arch)
        else {
            break;
        };
        if decoded.len == 0 || offset.saturating_add(decoded.len) > bytes.len() {
            break;
        }
        let instruction = convert_instruction(
            decoded,
            address + offset as u64,
            FunctionEvidenceConfidence::Derived,
            arch,
        );
        if let Some(reference) = instruction.pc_relative {
            if reference.kind == ControlFlowPcRelativeKind::Memory {
                slots.insert(reference.address);
            }
            if matches!(
                reference.kind,
                ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::PageAddress
            ) && let Some(register) = instruction.written_register
            {
                values.insert(register, reference.address);
            }
        }
        for operand in &instruction.operands {
            if let ControlFlowOperand::Memory { base, displacement } = operand
                && let Some(base) = values.get(base)
                && let Some(slot) = base.checked_add_signed(*displacement)
            {
                slots.insert(slot);
            }
        }
        if instruction.value_effect == ControlFlowValueEffect::AddImmediate
            && let Some(destination) = instruction.written_register
            && let Some(base) = instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    ControlFlowOperand::Register { register } => values.get(register).copied(),
                    _ => None,
                })
            && let Some(immediate) = instruction
                .operands
                .iter()
                .find_map(|operand| match operand {
                    ControlFlowOperand::Immediate { value } => Some(*value),
                    _ => None,
                })
            && let Some(value) = base.checked_add_signed(immediate)
        {
            values.insert(destination, value);
        } else if matches!(
            instruction.value_effect,
            ControlFlowValueEffect::Load | ControlFlowValueEffect::UnknownWrite
        ) && let Some(register) = instruction.written_register
        {
            values.remove(&register);
        }
        offset += instruction.byte_len as usize;
        if matches!(
            instruction.kind,
            ControlFlowInstructionKind::Branch | ControlFlowInstructionKind::Return
        ) {
            break;
        }
    }
    slots.into_iter().collect()
}

fn known_non_returning_import(name: &str) -> bool {
    matches!(
        name.trim_start_matches('_'),
        "Exit"
            | "abort"
            | "assert_rtn"
            | "cxa_throw"
            | "err"
            | "errc"
            | "errx"
            | "exit"
            | "longjmp"
            | "objc_exception_throw"
            | "pthread_exit"
            | "siglongjmp"
            | "stack_chk_fail"
            | "verr"
            | "verrc"
            | "verrx"
            | "xcselect_invoke_xcrun"
    )
}

struct FunctionRecoveryContext<'context, 'image> {
    macho: &'context MachoFile<'image>,
    function_index: &'context FunctionIndex,
    arch: Arch,
    limits: ControlFlowLimits,
    non_returning_stubs: &'context BTreeMap<u64, String>,
    non_returning_functions: &'context BTreeSet<u64>,
    exceptions: Option<&'context ExceptionIndex>,
    guidance: Option<&'context ControlFlowRecoveryGuidance>,
}

fn recover_function(
    recovery: &FunctionRecoveryContext<'_, '_>,
    function: &RecoveredFunction,
    remaining_bytes: &mut usize,
) -> FunctionControlFlow {
    let FunctionRecoveryContext {
        macho,
        function_index,
        arch,
        limits,
        non_returning_stubs,
        non_returning_functions,
        exceptions,
        guidance,
    } = recovery;
    let arch = *arch;
    let limits = *limits;
    let guidance = *guidance;
    let original_coverage = function_coverage(function);
    let boundary_confidence = original_coverage.iter().map(|range| range.confidence).min();
    let (coverage, mut data_ranges) = partition_guided_data_ranges(
        original_coverage.clone(),
        guidance.map_or(&[], |guide| &guide.non_instruction_ranges),
    );
    let mut instructions = Vec::new();
    let mut gaps = Vec::new();
    let mut reasons = BTreeSet::<String>::new();
    let mut decoded_bytes = 0_u64;
    let mut truncated = false;
    let mut continuation = None;
    if coverage.is_empty() {
        reasons.insert("control_flow.no_extent".into());
    }
    if !function.conflicts.is_empty() {
        reasons.insert("control_flow.function_conflicts".into());
    }
    if !function.completeness.extent_is_authoritative
        && function
            .completeness
            .incomplete_sources
            .iter()
            .any(|source| *source != FunctionEvidenceSource::DirectCall)
    {
        reasons.insert("control_flow.function_inventory_incomplete".into());
    }
    if boundary_confidence == Some(FunctionEvidenceConfidence::Candidate) {
        reasons.insert("control_flow.uncertain_boundary".into());
    }
    if !data_ranges.is_empty() {
        reasons.insert("control_flow.caller_guided_non_instruction".into());
    }
    for range in coverage {
        if *remaining_bytes == 0 {
            truncated = true;
            reasons.insert("control_flow.byte_budget".into());
            continuation.get_or_insert(ControlFlowContinuation::Byte {
                function_entry: function.entry,
                address: range.start,
            });
            break;
        }
        if instructions.len() >= limits.max_instructions_per_function {
            truncated = true;
            reasons.insert("control_flow.instruction_budget".into());
            continuation.get_or_insert(ControlFlowContinuation::Instruction {
                function_entry: function.entry,
                address: range.start,
            });
            break;
        }
        let natural_len = usize::try_from(range.end - range.start).unwrap_or(usize::MAX);
        let admitted_len = natural_len.min(*remaining_bytes);
        let clipped = admitted_len < natural_len;
        let lookahead = if arch.is_arm64() { 3 } else { 15 };
        let probe_len = admitted_len.saturating_add(lookahead).min(natural_len);
        let bytes = match macho.read_bytes_at_va(Va(range.start), probe_len) {
            Ok(bytes) => bytes,
            Err(_) => {
                if let Some(address) = push_gap(
                    &mut gaps,
                    limits.max_gaps_per_function,
                    ControlFlowGap {
                        start: range.start,
                        end_exclusive: range.end,
                        kind: ControlFlowGapKind::UnmappedRange,
                        coverage_confidence: range.confidence,
                    },
                    &mut truncated,
                    &mut reasons,
                ) {
                    continuation.get_or_insert(ControlFlowContinuation::Gap {
                        function_entry: function.entry,
                        address,
                    });
                }
                reasons.insert("control_flow.unmapped_range".into());
                continue;
            }
        };
        let mut offset = 0_usize;
        let mut decoder = crate::insn::DecodeCursor::new(bytes, range.start, arch);
        while offset < admitted_len {
            if instructions.len() >= limits.max_instructions_per_function {
                truncated = true;
                reasons.insert("control_flow.instruction_budget".into());
                continuation.get_or_insert(ControlFlowContinuation::Instruction {
                    function_entry: function.entry,
                    address: range.start + offset as u64,
                });
                break;
            }
            let address = range.start + offset as u64;
            match decoder.decode_at(offset) {
                Ok(instruction) if offset.saturating_add(instruction.len) <= admitted_len => {
                    instructions.push(convert_instruction(
                        instruction,
                        address,
                        range.confidence,
                        arch,
                    ));
                    offset += instructions.last().expect("just pushed").byte_len as usize;
                }
                Ok(_) if clipped => {
                    truncated = true;
                    reasons.insert("control_flow.byte_budget".into());
                    continuation.get_or_insert(ControlFlowContinuation::Byte {
                        function_entry: function.entry,
                        address,
                    });
                    break;
                }
                Ok(_) => {
                    let end = range.end;
                    if let Some(address) = push_gap(
                        &mut gaps,
                        limits.max_gaps_per_function,
                        ControlFlowGap {
                            start: address,
                            end_exclusive: end,
                            kind: ControlFlowGapKind::InvalidInstruction,
                            coverage_confidence: range.confidence,
                        },
                        &mut truncated,
                        &mut reasons,
                    ) {
                        continuation.get_or_insert(ControlFlowContinuation::Gap {
                            function_entry: function.entry,
                            address,
                        });
                    }
                    reasons.insert("control_flow.partial_instruction_boundary".into());
                    offset = admitted_len;
                }
                Err(_) => {
                    let step = if arch.is_arm64() { 4 } else { 1 }.min(admitted_len - offset);
                    if let Some(address) = push_gap(
                        &mut gaps,
                        limits.max_gaps_per_function,
                        ControlFlowGap {
                            start: address,
                            end_exclusive: address + step as u64,
                            kind: ControlFlowGapKind::InvalidInstruction,
                            coverage_confidence: range.confidence,
                        },
                        &mut truncated,
                        &mut reasons,
                    ) {
                        continuation.get_or_insert(ControlFlowContinuation::Gap {
                            function_entry: function.entry,
                            address,
                        });
                    }
                    reasons.insert("control_flow.decode_gap".into());
                    offset += step;
                }
            }
        }
        decoded_bytes = decoded_bytes.saturating_add(offset as u64);
        *remaining_bytes -= offset;
        if clipped {
            truncated = true;
            reasons.insert("control_flow.byte_budget".into());
            continuation.get_or_insert(ControlFlowContinuation::Byte {
                function_entry: function.entry,
                address: range.start + offset as u64,
            });
            break;
        }
        if truncated {
            break;
        }
    }
    instructions.sort_by_key(|instruction| instruction.address);
    instructions.dedup_by_key(|instruction| instruction.address);
    gaps.sort_by_key(|gap| (gap.start, gap.end_exclusive));

    let (mut raw_jump_tables, mut jump_table_continuation) = recover_jump_tables(
        macho,
        arch,
        &instructions,
        limits.max_jump_tables_per_function,
        limits.max_jump_table_entries,
    );
    if let Some(guidance) = guidance {
        let before = raw_jump_tables.len();
        raw_jump_tables.retain(|table| {
            !guidance.instruction_ranges.iter().any(|(start, end)| {
                let table_end = table
                    .table_address
                    .saturating_add(table.entry_width.saturating_mul(table.entries.len() as u64));
                table.table_address < *end && table_end > *start
            })
        });
        if raw_jump_tables.len() != before {
            reasons.insert("control_flow.caller_guided_instruction".into());
        }
        if jump_table_continuation.is_some_and(|(_, table_address, _)| {
            guidance
                .instruction_ranges
                .iter()
                .any(|(start, end)| table_address >= *start && table_address < *end)
        }) {
            jump_table_continuation = None;
        }
    }
    if let Some((instruction_address, table_address, index)) = jump_table_continuation {
        truncated = true;
        reasons.insert("control_flow.jump_table_budget".into());
        continuation.get_or_insert(ControlFlowContinuation::JumpTable {
            function_entry: function.entry,
            instruction_address,
            table_address,
            index,
        });
    }
    let recovered_table_ranges = raw_jump_tables
        .iter()
        .filter(|table| {
            !table.truncated
                && !table.incomplete
                && table.range.is_some()
                && !table.entries.is_empty()
        })
        .filter_map(|table| {
            let end_exclusive = table
                .table_address
                .checked_add(table.entry_width.checked_mul(table.entries.len() as u64)?)?;
            Some((table.table_address, end_exclusive))
        })
        .collect::<Vec<_>>();
    if !recovered_table_ranges.is_empty() {
        instructions.retain(|instruction| {
            let end = instruction.address + instruction.byte_len as u64;
            !recovered_table_ranges
                .iter()
                .any(|(start, table_end)| instruction.address < *table_end && end > *start)
        });
        gaps = subtract_ranges_from_gaps(gaps, &recovered_table_ranges);
        if gaps.is_empty() {
            reasons.remove("control_flow.decode_gap");
        }
        data_ranges.extend(recovered_table_ranges.iter().map(|(start, end_exclusive)| {
            ControlFlowDataRange {
                start: *start,
                end_exclusive: *end_exclusive,
                coverage_confidence: FunctionEvidenceConfidence::Derived,
                reason: ControlFlowDataRangeReason::RecoveredJumpTable,
            }
        }));
        data_ranges.sort_by_key(|range| (range.start, range.end_exclusive, range.reason));
        data_ranges.dedup();
    }
    let jump_targets = raw_jump_tables
        .iter()
        .flat_map(|table| table.entries.iter().map(|(_, target)| *target))
        .collect::<BTreeSet<_>>();

    let (mut blocks, block_continuation) = build_blocks(
        &instructions,
        function.entry,
        &jump_targets,
        limits.max_blocks_per_function,
    );
    if let Some((block, start)) = block_continuation {
        truncated = true;
        reasons.insert("control_flow.block_budget".into());
        continuation.get_or_insert(ControlFlowContinuation::Block {
            function_entry: function.entry,
            block,
            start,
        });
    }
    let retained_instruction_count = blocks.last().map_or(0, |block| {
        (block.first_instruction + block.instruction_count) as usize
    });
    if retained_instruction_count < instructions.len() {
        instructions.truncate(retained_instruction_count);
    }
    let jump_tables = finalize_jump_tables(raw_jump_tables, &blocks);
    if jump_tables.iter().any(|table| {
        table.truncated
            || table.range.is_none()
            || table.reasons.iter().any(|reason| {
                matches!(
                    reason.as_str(),
                    "jump_table.target_block_omitted"
                        | "jump_table.entry_budget"
                        | "jump_table.invalid_or_unreadable_entry"
                        | "jump_table.range_guard_block_omitted"
                        | "jump_table.range_check_unresolved"
                )
            })
    }) {
        reasons.insert("control_flow.jump_table_partial".into());
    }
    let (mut edges, mut exits, mut calls, edge_continuation) = connect_blocks(
        &instructions,
        &blocks,
        &jump_tables,
        function_index,
        non_returning_stubs,
        non_returning_functions,
        limits.max_edges_per_function,
    );
    if let Some(edge) = edge_continuation {
        truncated = true;
        reasons.insert("control_flow.edge_budget".into());
        continuation.get_or_insert(ControlFlowContinuation::Edge {
            function_entry: function.entry,
            edge,
        });
    }
    let (exceptional_transfers, exceptional_continuation, exceptional_partial) =
        apply_exception_evidence(
            exceptions.as_deref(),
            function.entry,
            &blocks,
            &mut edges,
            &mut exits,
            &mut calls,
            limits.max_edges_per_function,
        );
    if exceptional_partial {
        reasons.insert("control_flow.exception_evidence_partial".into());
    }
    if let Some(edge) = exceptional_continuation {
        truncated = true;
        reasons.insert("control_flow.edge_budget".into());
        continuation.get_or_insert(ControlFlowContinuation::Edge {
            function_entry: function.entry,
            edge,
        });
    }
    // Boundary confidence answers whether decoded bytes belong to this function;
    // it does not make a missing path through a fully decoded graph possible.
    // First solve the retained graph exactly. Negative answers are weakened only
    // when omitted work or a gap reachable from that graph could hide a path.
    mark_reachability(&mut blocks, &edges, function.entry, false);
    let reachable_gap = exits.iter().any(|exit| {
        blocks
            .get(exit.block as usize)
            .filter(|block| block.id == exit.block)
            .is_some_and(|block| {
                block.reachability == ControlFlowReachability::Reachable
                    && gaps.iter().any(|gap| {
                        exit.target
                            .is_some_and(|target| target >= gap.start && target < gap.end_exclusive)
                            || block.end_exclusive == gap.start
                    })
            })
    });
    if truncated || reachable_gap {
        mark_reachability(&mut blocks, &edges, function.entry, true);
    }
    if exits.iter().any(|exit| {
        exit.kind == ControlFlowExitKind::IndirectBranch
            && blocks
                .get(exit.block as usize)
                .filter(|block| block.id == exit.block)
                .is_some_and(|block| block.reachability != ControlFlowReachability::Unreachable)
    }) {
        reasons.insert("control_flow.indirect_branch_unresolved".into());
        if exits.iter().any(|exit| {
            exit.kind == ControlFlowExitKind::IndirectBranch
                && exit.instruction_address.is_some_and(|address| {
                    unresolved_computed_branch_transform(&instructions, address)
                })
        }) {
            reasons.insert("control_flow.computed_branch_transform_unsupported".into());
        }
    }
    let (byte_ranges, byte_classification_conflict) =
        function_byte_ranges(&original_coverage, &instructions, &data_ranges, &gaps);
    if byte_classification_conflict {
        reasons.insert("control_flow.byte_classification_conflict".into());
    }
    if byte_ranges
        .iter()
        .any(|range| range.kind == ControlFlowByteRangeKind::Omitted)
    {
        reasons.insert("control_flow.omitted_bytes".into());
    }
    let bytes_of_kind = |kind| {
        byte_ranges
            .iter()
            .filter(|range| range.kind == kind)
            .map(|range| range.end_exclusive - range.start)
            .sum::<u64>()
    };
    let instruction_bytes = bytes_of_kind(ControlFlowByteRangeKind::Instruction);
    let data_bytes = bytes_of_kind(ControlFlowByteRangeKind::Data);
    let gap_bytes = bytes_of_kind(ControlFlowByteRangeKind::Gap);
    let omitted_bytes = bytes_of_kind(ControlFlowByteRangeKind::Omitted);
    let observed_bytes = instruction_bytes
        .saturating_add(data_bytes)
        .saturating_add(gap_bytes)
        .saturating_add(omitted_bytes);
    let status = if truncated {
        FunctionControlFlowStatus::Truncated
    } else if instructions.is_empty() {
        FunctionControlFlowStatus::Unavailable
    } else if !reasons.is_empty() || !gaps.is_empty() {
        FunctionControlFlowStatus::Partial
    } else {
        FunctionControlFlowStatus::Complete
    };
    FunctionControlFlow {
        function_entry: function.entry,
        identity: function.identity.clone(),
        instructions,
        gaps,
        data_ranges,
        byte_ranges,
        blocks,
        edges,
        exits,
        calls,
        exceptional_transfers,
        jump_tables,
        completeness: FunctionControlFlowCompleteness {
            status,
            boundary_confidence,
            decoded_bytes,
            observed_bytes,
            instruction_bytes,
            data_bytes,
            gap_bytes,
            omitted_bytes,
            reasons: reasons.into_iter().collect(),
            continuation,
        },
    }
}

fn unresolved_computed_branch_transform(
    instructions: &[ControlFlowInstruction],
    address: u64,
) -> bool {
    let Some(index) = instructions
        .iter()
        .position(|instruction| instruction.address == address)
    else {
        return false;
    };
    instructions[index.saturating_sub(6)..=index]
        .iter()
        .any(|instruction| {
            instruction
                .operands
                .iter()
                .any(|operand| matches!(operand, ControlFlowOperand::IndexedMemory { .. }))
        })
}

fn apply_exception_evidence(
    exceptions: Option<&ExceptionIndex>,
    function_entry: u64,
    blocks: &[BasicBlock],
    edges: &mut Vec<ControlFlowEdge>,
    exits: &mut Vec<ControlFlowExit>,
    calls: &mut [ControlFlowCallsite],
    maximum_edges: usize,
) -> (
    Vec<ControlFlowExceptionalTransfer>,
    Option<ControlFlowEdge>,
    bool,
) {
    let evidence = exceptions.map_or_else(Vec::new, |index| {
        index
            .call_sites_by_entry(function_entry)
            .cloned()
            .collect::<Vec<_>>()
    });
    apply_exception_records(&evidence, blocks, edges, exits, calls, maximum_edges)
}

fn apply_exception_records(
    evidence_records: &[ExceptionCallSiteRecord],
    blocks: &[BasicBlock],
    edges: &mut Vec<ControlFlowEdge>,
    exits: &mut Vec<ControlFlowExit>,
    calls: &mut [ControlFlowCallsite],
    maximum_edges: usize,
) -> (
    Vec<ControlFlowExceptionalTransfer>,
    Option<ControlFlowEdge>,
    bool,
) {
    let mut transfers = Vec::new();
    let mut continuation = None;
    let mut partial = false;
    for evidence in evidence_records {
        for call in calls.iter_mut().filter(|call| {
            call.instruction_address >= evidence.start
                && call.instruction_address < evidence.end_exclusive
        }) {
            let actions = evidence
                .actions
                .iter()
                .map(|action| action.kind)
                .collect::<Vec<_>>();
            match evidence.landing_pad {
                Some(landing_pad) => {
                    if call.exceptional_behavior
                        == ControlFlowCallExceptionBehavior::UnwindsOutOfFunction
                    {
                        partial = true;
                    }
                    call.exceptional_behavior = ControlFlowCallExceptionBehavior::LocalLandingPad;
                    if !call.landing_pads.contains(&landing_pad) {
                        call.landing_pads.push(landing_pad);
                        call.landing_pads.sort_unstable();
                    }
                    let destination = blocks
                        .iter()
                        .find(|block| {
                            landing_pad >= block.start && landing_pad < block.end_exclusive
                        })
                        .map(|block| block.id);
                    let edge = destination.map(|to| ControlFlowEdge {
                        from: call.block,
                        to,
                        kind: ControlFlowEdgeKind::Exceptional,
                    });
                    if let Some(edge) = edge
                        && !edges.contains(&edge)
                    {
                        if edges.len() < maximum_edges {
                            edges.push(edge);
                        } else {
                            continuation.get_or_insert(edge);
                        }
                    }
                    partial |= destination.is_none();
                    transfers.push(ControlFlowExceptionalTransfer {
                        instruction_address: call.instruction_address,
                        source_block: call.block,
                        landing_pad: Some(landing_pad),
                        destination_block: destination,
                        lsda_address: evidence.lsda_address,
                        action_offset: evidence.action_offset,
                        actions,
                    });
                }
                None => {
                    if call.exceptional_behavior
                        == ControlFlowCallExceptionBehavior::LocalLandingPad
                    {
                        partial = true;
                    }
                    call.exceptional_behavior =
                        ControlFlowCallExceptionBehavior::UnwindsOutOfFunction;
                    if !exits.iter().any(|exit| {
                        exit.block == call.block
                            && exit.instruction_address == Some(call.instruction_address)
                            && exit.kind == ControlFlowExitKind::ExceptionalUnwind
                    }) {
                        exits.push(ControlFlowExit {
                            block: call.block,
                            instruction_address: Some(call.instruction_address),
                            kind: ControlFlowExitKind::ExceptionalUnwind,
                            target: None,
                            recovered_function: None,
                            possible_functions: Vec::new(),
                        });
                    }
                    transfers.push(ControlFlowExceptionalTransfer {
                        instruction_address: call.instruction_address,
                        source_block: call.block,
                        landing_pad: None,
                        destination_block: None,
                        lsda_address: evidence.lsda_address,
                        action_offset: evidence.action_offset,
                        actions,
                    });
                }
            }
        }
    }
    edges.sort_by_key(|edge| (edge.from, edge.to, edge.kind));
    exits.sort_by_key(|exit| {
        (
            exit.block,
            exit.instruction_address,
            exit.kind as u8,
            exit.target,
        )
    });
    transfers.sort_by_key(|transfer| {
        (
            transfer.instruction_address,
            transfer.landing_pad,
            transfer.lsda_address,
        )
    });
    transfers.dedup();
    (transfers, continuation, partial)
}

fn function_byte_ranges(
    coverage: &[CoverageRange],
    instructions: &[ControlFlowInstruction],
    data_ranges: &[ControlFlowDataRange],
    gaps: &[ControlFlowGap],
) -> (Vec<ControlFlowByteRange>, bool) {
    let mut coverage_intervals = coverage
        .iter()
        .map(|range| (range.start, range.end))
        .collect::<Vec<_>>();
    let mut instruction_intervals = instructions
        .iter()
        .map(|instruction| {
            (
                instruction.address,
                instruction.address + instruction.byte_len as u64,
            )
        })
        .collect::<Vec<_>>();
    let mut data_intervals = data_ranges
        .iter()
        .map(|range| (range.start, range.end_exclusive))
        .collect::<Vec<_>>();
    let mut gap_intervals = gaps
        .iter()
        .map(|gap| (gap.start, gap.end_exclusive))
        .collect::<Vec<_>>();
    sort_intervals_if_needed(&mut coverage_intervals);
    sort_intervals_if_needed(&mut instruction_intervals);
    sort_intervals_if_needed(&mut data_intervals);
    sort_intervals_if_needed(&mut gap_intervals);
    let coverage_index = interval_prefix_max(&coverage_intervals);
    let instruction_index = interval_prefix_max(&instruction_intervals);
    let data_index = interval_prefix_max(&data_intervals);
    let gap_index = interval_prefix_max(&gap_intervals);
    let coverage_boundaries = interval_boundaries(&coverage_intervals);
    let instruction_boundaries = interval_boundaries(&instruction_intervals);
    let data_boundaries = interval_boundaries(&data_intervals);
    let gap_boundaries = interval_boundaries(&gap_intervals);
    let mut result = Vec::<ControlFlowByteRange>::new();
    let mut conflict = false;
    for_each_merged_boundary_window(
        [
            coverage_boundaries.as_slice(),
            instruction_boundaries.as_slice(),
            data_boundaries.as_slice(),
            gap_boundaries.as_slice(),
        ],
        |start, end_exclusive| {
            if !interval_contains(&coverage_intervals, &coverage_index, start, end_exclusive) {
                return;
            }
            let instruction = interval_contains(
                &instruction_intervals,
                &instruction_index,
                start,
                end_exclusive,
            );
            let data = interval_contains(&data_intervals, &data_index, start, end_exclusive);
            let gap = interval_contains(&gap_intervals, &gap_index, start, end_exclusive);
            let classifications = usize::from(instruction) + usize::from(data) + usize::from(gap);
            conflict |= classifications > 1;
            let kind = match (classifications, instruction, data, gap) {
                (0, _, _, _) => ControlFlowByteRangeKind::Omitted,
                (1, true, _, _) => ControlFlowByteRangeKind::Instruction,
                (1, _, true, _) => ControlFlowByteRangeKind::Data,
                (1, _, _, true) => ControlFlowByteRangeKind::Gap,
                _ => ControlFlowByteRangeKind::Gap,
            };
            if let Some(previous) = result.last_mut()
                && previous.end_exclusive == start
                && previous.kind == kind
            {
                previous.end_exclusive = end_exclusive;
            } else {
                result.push(ControlFlowByteRange {
                    start,
                    end_exclusive,
                    kind,
                });
            }
        },
    );
    (result, conflict)
}

fn interval_prefix_max(intervals: &[(u64, u64)]) -> Vec<u64> {
    let mut result = Vec::with_capacity(intervals.len());
    let mut maximum = 0;
    for &(_, end) in intervals {
        maximum = maximum.max(end);
        result.push(maximum);
    }
    result
}

fn sort_intervals_if_needed(intervals: &mut [(u64, u64)]) {
    if intervals
        .windows(2)
        .any(|pair| pair[0].0 > pair[1].0 || pair[0].0 == pair[1].0 && pair[0].1 > pair[1].1)
    {
        intervals.sort_unstable();
    }
}

fn interval_boundaries(intervals: &[(u64, u64)]) -> Vec<u64> {
    let mut result = Vec::with_capacity(intervals.len().saturating_mul(2));
    for &(start, end) in intervals {
        result.push(start);
        result.push(end);
    }
    if result.windows(2).any(|pair| pair[0] > pair[1]) {
        result.sort_unstable();
    }
    result.dedup();
    result
}

fn for_each_merged_boundary_window<const N: usize>(
    sources: [&[u64]; N],
    mut visit: impl FnMut(u64, u64),
) {
    let mut positions = [0_usize; N];
    let mut previous = None;
    loop {
        let next = sources
            .iter()
            .enumerate()
            .filter_map(|(index, source)| source.get(positions[index]).copied())
            .min();
        let Some(next) = next else {
            break;
        };
        if let Some(previous) = previous {
            visit(previous, next);
        }
        previous = Some(next);
        for (index, source) in sources.iter().enumerate() {
            while source.get(positions[index]) == Some(&next) {
                positions[index] += 1;
            }
        }
    }
}

fn interval_contains(
    intervals: &[(u64, u64)],
    prefix_max_end: &[u64],
    start: u64,
    end_exclusive: u64,
) -> bool {
    let preceding_count = intervals.partition_point(|(range_start, _)| *range_start <= start);
    preceding_count > 0 && prefix_max_end[preceding_count - 1] >= end_exclusive
}

fn push_gap(
    gaps: &mut Vec<ControlFlowGap>,
    maximum: usize,
    gap: ControlFlowGap,
    truncated: &mut bool,
    reasons: &mut BTreeSet<String>,
) -> Option<u64> {
    if let Some(previous) = gaps.last_mut()
        && previous.end_exclusive == gap.start
        && previous.kind == gap.kind
        && previous.coverage_confidence == gap.coverage_confidence
    {
        previous.end_exclusive = gap.end_exclusive;
    } else if gaps.len() < maximum {
        gaps.push(gap);
    } else {
        *truncated = true;
        reasons.insert("control_flow.gap_budget".into());
        return Some(gap.start);
    }
    None
}

fn subtract_ranges_from_gaps(
    gaps: Vec<ControlFlowGap>,
    excluded: &[(u64, u64)],
) -> Vec<ControlFlowGap> {
    gaps.into_iter()
        .flat_map(|gap| {
            let mut fragments = vec![gap];
            for &(start, end) in excluded {
                fragments = fragments
                    .into_iter()
                    .flat_map(|fragment| {
                        if start >= fragment.end_exclusive || end <= fragment.start {
                            return vec![fragment];
                        }
                        let mut retained = Vec::with_capacity(2);
                        if fragment.start < start {
                            retained.push(ControlFlowGap {
                                end_exclusive: start.min(fragment.end_exclusive),
                                ..fragment.clone()
                            });
                        }
                        if end < fragment.end_exclusive {
                            retained.push(ControlFlowGap {
                                start: end.max(fragment.start),
                                ..fragment
                            });
                        }
                        retained
                    })
                    .collect();
            }
            fragments
        })
        .collect()
}

fn convert_instruction(
    instruction: crate::insn::Insn,
    address: u64,
    confidence: FunctionEvidenceConfidence,
    architecture: Arch,
) -> ControlFlowInstruction {
    let operands = instruction
        .operands()
        .iter()
        .filter_map(convert_operand)
        .collect();
    let written_register = instruction.op0_write_target().and_then(convert_register);
    let value_effect = match instruction.value_effect {
        ValueEffect::None => ControlFlowValueEffect::None,
        ValueEffect::Set => ControlFlowValueEffect::Set,
        ValueEffect::Address => ControlFlowValueEffect::Address,
        ValueEffect::Load => ControlFlowValueEffect::Load,
        ValueEffect::AddImmediate => ControlFlowValueEffect::AddImmediate,
        ValueEffect::AddRegister => ControlFlowValueEffect::AddRegister,
        ValueEffect::SubtractRegister => ControlFlowValueEffect::SubtractRegister,
        ValueEffect::BitwiseAndImmediate => ControlFlowValueEffect::BitwiseAndImmediate,
        ValueEffect::ShiftImmediate => ControlFlowValueEffect::ShiftImmediate,
        ValueEffect::ConditionalSelect => ControlFlowValueEffect::ConditionalSelect,
        ValueEffect::ZeroExtend8 => ControlFlowValueEffect::ZeroExtend8,
        ValueEffect::ZeroExtend16 => ControlFlowValueEffect::ZeroExtend16,
        ValueEffect::ZeroExtend32 => ControlFlowValueEffect::ZeroExtend32,
        ValueEffect::SignExtend8 => ControlFlowValueEffect::SignExtend8,
        ValueEffect::SignExtend16 => ControlFlowValueEffect::SignExtend16,
        ValueEffect::SignExtend32 => ControlFlowValueEffect::SignExtend32,
        ValueEffect::SignPointerIa => ControlFlowValueEffect::SignPointerIa,
        ValueEffect::SignPointerIb => ControlFlowValueEffect::SignPointerIb,
        ValueEffect::SignPointerDa => ControlFlowValueEffect::SignPointerDa,
        ValueEffect::SignPointerDb => ControlFlowValueEffect::SignPointerDb,
        ValueEffect::AuthenticatePointerIa => ControlFlowValueEffect::AuthenticatePointerIa,
        ValueEffect::AuthenticatePointerIb => ControlFlowValueEffect::AuthenticatePointerIb,
        ValueEffect::AuthenticatePointerDa => ControlFlowValueEffect::AuthenticatePointerDa,
        ValueEffect::AuthenticatePointerDb => ControlFlowValueEffect::AuthenticatePointerDb,
        ValueEffect::StripPointerAuthentication => {
            ControlFlowValueEffect::StripPointerAuthentication
        }
        ValueEffect::UnknownWrite => ControlFlowValueEffect::UnknownWrite,
        _ => ControlFlowValueEffect::UnknownWrite,
    };
    let writes_implicit_gpr0 = instruction.writes_implicit_gpr0;
    let memory_effect = match instruction.memory_effect {
        MemoryEffect::None => ControlFlowMemoryEffect::None,
        MemoryEffect::Store => ControlFlowMemoryEffect::Store,
        MemoryEffect::UnknownWrite => ControlFlowMemoryEffect::UnknownWrite,
        _ => ControlFlowMemoryEffect::UnknownWrite,
    };
    let pc_relative = match &instruction.kind {
        InsnKind::PcRelative(info) => Some(ControlFlowPcRelative {
            address: address.wrapping_add_signed(info.displacement),
            kind: match info.kind {
                PcRelKind::Address => ControlFlowPcRelativeKind::Address,
                PcRelKind::PageAddress => ControlFlowPcRelativeKind::PageAddress,
                PcRelKind::Memory => ControlFlowPcRelativeKind::Memory,
            },
        }),
        _ if architecture == Arch::X86_64 => {
            instruction
                .operands()
                .iter()
                .find_map(|operand| match operand {
                    Operand::Mem { base, disp }
                        if base.class == RegClass::Gpr && base.num == 16 =>
                    {
                        Some(ControlFlowPcRelative {
                            address: address
                                .wrapping_add(instruction.len as u64)
                                .wrapping_add_signed(*disp),
                            kind: ControlFlowPcRelativeKind::Memory,
                        })
                    }
                    _ => None,
                })
        }
        _ => None,
    };
    let kind = match instruction.kind {
        InsnKind::Branch(_) => ControlFlowInstructionKind::Branch,
        InsnKind::Call(_) => ControlFlowInstructionKind::Call,
        InsnKind::CondBranch(_) => ControlFlowInstructionKind::ConditionalBranch,
        InsnKind::Return => ControlFlowInstructionKind::Return,
        _ => ControlFlowInstructionKind::Other,
    };
    let target = branch_target(&instruction, address);
    ControlFlowInstruction {
        address,
        byte_len: instruction.len as u8,
        kind,
        target,
        operands,
        written_register,
        value_effect,
        memory_effect,
        writes_implicit_gpr0,
        pc_relative,
        coverage_confidence: confidence,
    }
}

fn convert_register(register: Reg) -> Option<ControlFlowRegister> {
    let class = match register.class {
        RegClass::Gpr => ControlFlowRegisterClass::GeneralPurpose,
        RegClass::Fp => ControlFlowRegisterClass::FloatingPoint,
        _ => return None,
    };
    Some(ControlFlowRegister {
        class,
        number: register.num,
    })
}

fn convert_operand(operand: &Operand) -> Option<ControlFlowOperand> {
    match *operand {
        Operand::Reg(register) => Some(ControlFlowOperand::Register {
            register: convert_register(register)?,
        }),
        Operand::ShiftedReg {
            register,
            shift,
            amount,
        } => Some(ControlFlowOperand::ShiftedRegister {
            register: convert_register(register)?,
            shift: match shift {
                RegisterShift::LogicalLeft => ControlFlowRegisterShift::LogicalLeft,
                RegisterShift::LogicalRight => ControlFlowRegisterShift::LogicalRight,
                RegisterShift::ArithmeticRight => ControlFlowRegisterShift::ArithmeticRight,
                RegisterShift::RotateRight => ControlFlowRegisterShift::RotateRight,
                _ => return None,
            },
            amount,
        }),
        Operand::Imm(value) => Some(ControlFlowOperand::Immediate { value }),
        Operand::Mem { base, disp } => Some(ControlFlowOperand::Memory {
            base: convert_register(base)?,
            displacement: disp,
        }),
        Operand::IndexedMem {
            base,
            index,
            scale,
            disp,
        } => Some(ControlFlowOperand::IndexedMemory {
            base: convert_register(base)?,
            index: convert_register(index)?,
            scale,
            displacement: disp,
        }),
        _ => None,
    }
}

fn branch_target(instruction: &crate::insn::Insn, address: u64) -> Option<InstructionTarget> {
    let target = match &instruction.kind {
        InsnKind::Branch(info) | InsnKind::Call(info) | InsnKind::CondBranch(info) => &info.target,
        _ => return None,
    };
    Some(match target {
        BranchTarget::Direct(displacement) => InstructionTarget::Direct {
            address: address.wrapping_add_signed(*displacement),
        },
        BranchTarget::Register => InstructionTarget::Indirect {
            target_kind: IndirectTargetKind::Register,
        },
        BranchTarget::Indirect => InstructionTarget::Indirect {
            target_kind: IndirectTargetKind::Memory,
        },
        BranchTarget::IndexedMemory {
            base,
            index,
            scale,
            displacement,
        } => InstructionTarget::IndexedMemory {
            base: base.and_then(convert_register),
            index: convert_register(*index)?,
            scale: *scale,
            displacement: *displacement,
        },
        _ => InstructionTarget::Indirect {
            target_kind: IndirectTargetKind::Unknown,
        },
    })
}

#[derive(Debug)]
struct RawJumpTable {
    instruction_address: u64,
    table_address: u64,
    entry_width: u64,
    encoding: JumpTableEncoding,
    entries: Vec<(u64, u64)>,
    truncated: bool,
    range: Option<RawJumpTableRange>,
    incomplete: bool,
}

#[derive(Debug, Clone, Copy)]
struct RawJumpTableRange {
    compare_instruction_address: Option<u64>,
    guard_instruction_address: u64,
    guard_kind: JumpTableRangeGuardKind,
    maximum_index: u64,
    entry_count: u64,
    default: RawJumpTableDefault,
}

#[derive(Debug, Clone, Copy)]
enum RawJumpTableDefault {
    Direct(u64),
    FirstEntry,
    None,
}

#[derive(Debug, Clone, Copy)]
struct JumpTableDescriptor {
    table_address: u64,
    entry_width: u64,
    encoding: JumpTableEncoding,
    relative_base: Option<u64>,
    range: Option<RawJumpTableRange>,
}

fn recover_jump_tables(
    macho: &MachoFile<'_>,
    arch: Arch,
    instructions: &[ControlFlowInstruction],
    maximum_tables: usize,
    maximum_entries: usize,
) -> (Vec<RawJumpTable>, Option<(u64, u64, u64)>) {
    let instruction_addresses = instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect::<BTreeSet<_>>();
    let mut tables = Vec::new();
    let mut continuation = None;
    for (instruction_index, instruction) in instructions.iter().enumerate() {
        if instruction.kind != ControlFlowInstructionKind::Branch {
            continue;
        }
        let descriptor = match arch {
            Arch::X86_64 => match instruction.target.as_ref() {
                Some(InstructionTarget::IndexedMemory {
                    base,
                    index,
                    scale: 8,
                    displacement,
                }) => indexed_table_address(instructions, instruction_index, *base, *displacement)
                    .map(|table_address| JumpTableDescriptor {
                        table_address,
                        entry_width: 8,
                        encoding: JumpTableEncoding::AbsolutePointer64,
                        relative_base: None,
                        range: x86_index_range(macho, instructions, instruction_index, *index),
                    }),
                Some(InstructionTarget::Indirect {
                    target_kind: IndirectTargetKind::Register,
                }) => relative_jump_table_descriptor(instructions, instruction_index).map(
                    |mut descriptor| {
                        descriptor.range =
                            x86_relative_index_register(instructions, instruction_index).and_then(
                                |(index, load_index)| {
                                    x86_index_range(macho, instructions, load_index, index)
                                },
                            );
                        descriptor
                    },
                ),
                _ => None,
            },
            Arch::Arm64 | Arch::Arm64e => {
                arm64_jump_table_descriptor(macho, instructions, instruction_index)
            }
            _ => None,
        };
        let Some(descriptor) = descriptor else {
            continue;
        };
        let mut observed = Vec::new();
        let scan_count = descriptor
            .range
            .map(|range| usize::try_from(range.entry_count).unwrap_or(usize::MAX))
            .unwrap_or_else(|| maximum_entries.saturating_add(1))
            .min(maximum_entries.saturating_add(1));
        for index in 0..scan_count {
            let Some(entry_address) = descriptor
                .table_address
                .checked_add((index as u64).saturating_mul(descriptor.entry_width))
            else {
                break;
            };
            let target = match descriptor.encoding {
                JumpTableEncoding::AbsolutePointer64 => {
                    let Ok(bytes) = macho.read_bytes_at_va(Va(entry_address), 8) else {
                        break;
                    };
                    u64::from_le_bytes(bytes.try_into().expect("read exactly eight bytes"))
                }
                JumpTableEncoding::RelativeSigned32 => {
                    let Ok(bytes) = macho.read_bytes_at_va(Va(entry_address), 4) else {
                        break;
                    };
                    let offset =
                        i32::from_le_bytes(bytes.try_into().expect("read exactly four bytes"))
                            as i64;
                    descriptor
                        .relative_base
                        .expect("relative encoding has a base")
                        .wrapping_add_signed(offset)
                }
                JumpTableEncoding::RelativeUnsigned8Scaled4 => {
                    let Ok(bytes) = macho.read_bytes_at_va(Va(entry_address), 1) else {
                        break;
                    };
                    descriptor
                        .relative_base
                        .expect("relative encoding has a base")
                        .wrapping_add(u64::from(bytes[0]).saturating_mul(4))
                }
                JumpTableEncoding::RelativeUnsigned16Scaled4 => {
                    let Ok(bytes) = macho.read_bytes_at_va(Va(entry_address), 2) else {
                        break;
                    };
                    let offset =
                        u16::from_le_bytes(bytes.try_into().expect("read exactly two bytes"));
                    descriptor
                        .relative_base
                        .expect("relative encoding has a base")
                        .wrapping_add(u64::from(offset).saturating_mul(4))
                }
            };
            if !instruction_addresses.contains(&target) {
                break;
            }
            observed.push((entry_address, target));
        }
        if observed.len() < 2 {
            continue;
        }
        let observed_end = descriptor
            .table_address
            .saturating_add((observed.len() as u64).saturating_mul(descriptor.entry_width));
        if instruction.address >= descriptor.table_address && instruction.address < observed_end {
            continue;
        }
        let incomplete = descriptor
            .range
            .is_some_and(|range| observed.len() as u64 != range.entry_count.min(scan_count as u64));
        let truncated = descriptor
            .range
            .is_some_and(|range| range.entry_count > maximum_entries as u64)
            || observed.len() > maximum_entries;
        observed.truncate(maximum_entries);
        if tables.len() == maximum_tables {
            continuation.get_or_insert((instruction.address, descriptor.table_address, 0));
            break;
        }
        if truncated {
            continuation.get_or_insert((
                instruction.address,
                descriptor.table_address,
                maximum_entries as u64,
            ));
        }
        tables.push(RawJumpTable {
            instruction_address: instruction.address,
            table_address: descriptor.table_address,
            entry_width: descriptor.entry_width,
            encoding: descriptor.encoding,
            entries: observed,
            truncated,
            range: descriptor.range,
            incomplete,
        });
    }
    (tables, continuation)
}

fn arm64_jump_table_descriptor(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    branch_index: usize,
) -> Option<JumpTableDescriptor> {
    let branch_register = branch_register(instructions.get(branch_index)?)?;
    let (writer_index, writer) = last_register_writer(instructions, branch_index, branch_register)?;

    if writer.value_effect == ControlFlowValueEffect::Load {
        let ControlFlowOperand::IndexedMemory {
            base,
            scale: 8,
            displacement,
            ..
        } = writer.operands.get(1)?
        else {
            return None;
        };
        return indexed_table_address(instructions, writer_index, Some(*base), *displacement).map(
            |table_address| JumpTableDescriptor {
                table_address,
                entry_width: 8,
                encoding: JumpTableEncoding::AbsolutePointer64,
                relative_base: None,
                range: None,
            },
        );
    }

    if let Some(descriptor) =
        arm64_scaled_offset_table_descriptor(macho, instructions, branch_index, branch_register)
    {
        return Some(descriptor);
    }

    let mut descriptor = relative_jump_table_descriptor(instructions, branch_index)?;
    descriptor.range = arm64_clamped_entry_range(macho, instructions, branch_index);
    Some(descriptor)
}

fn arm64_scaled_offset_table_descriptor(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    branch_index: usize,
    branch_register: ControlFlowRegister,
) -> Option<JumpTableDescriptor> {
    let (add_index, add) = last_register_writer(instructions, branch_index, branch_register)?;
    if add.value_effect != ControlFlowValueEffect::AddRegister {
        return None;
    }
    let ControlFlowOperand::Register {
        register: target_base_register,
    } = add.operands.get(1)?
    else {
        return None;
    };
    let ControlFlowOperand::ShiftedRegister {
        register: offset_register,
        shift: ControlFlowRegisterShift::LogicalLeft,
        amount: 2,
    } = add.operands.get(2)?
    else {
        return None;
    };
    let (load_index, load) = last_register_writer(instructions, add_index, *offset_register)?;
    if !matches!(
        load.value_effect,
        ControlFlowValueEffect::Load
            | ControlFlowValueEffect::ZeroExtend8
            | ControlFlowValueEffect::ZeroExtend16
    ) {
        return None;
    }
    let (table_base_register, index_register, entry_width, displacement) =
        load.operands.iter().find_map(|operand| match operand {
            ControlFlowOperand::IndexedMemory {
                base,
                index,
                scale: scale @ (1 | 2),
                displacement,
                ..
            } => Some((*base, *index, u64::from(*scale), *displacement)),
            _ => None,
        })?;
    let range = arm64_guarded_entry_count(macho, instructions, load_index, index_register)?;
    let table_address = indexed_table_address(
        instructions,
        load_index,
        Some(table_base_register),
        displacement,
    )?;
    let target_base = resolve_register_address(instructions, add_index, *target_base_register, 0)?;
    let encoding = match entry_width {
        1 => JumpTableEncoding::RelativeUnsigned8Scaled4,
        2 => JumpTableEncoding::RelativeUnsigned16Scaled4,
        _ => return None,
    };
    Some(JumpTableDescriptor {
        table_address,
        entry_width,
        encoding,
        relative_base: Some(target_base),
        range: Some(range),
    })
}

fn arm64_guarded_entry_count(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    load_index: usize,
    index_register: ControlFlowRegister,
) -> Option<RawJumpTableRange> {
    let first = load_index.saturating_sub(32);
    for compare_index in (first..load_index).rev() {
        let compare = instructions.get(compare_index)?;
        let bytes = macho.read_bytes_at_va(Va(compare.address), 4).ok()?;
        let word = u32::from_le_bytes(bytes.try_into().ok()?);
        // CMP Wn/Xn,#imm is SUBS to WZR/XZR. Shifted immediates are not
        // admitted because supported compiler table bounds are small counts.
        if word & 0x7F80_001F != 0x7100_001F || ((word >> 5) & 0x1F) as u8 != index_register.number
        {
            continue;
        }
        let guard = instructions.get(compare_index + 1)?;
        if compare_index + 1 >= load_index
            || guard.kind != ControlFlowInstructionKind::ConditionalBranch
        {
            continue;
        }
        let Ok(bytes) = macho.read_bytes_at_va(Va(guard.address), 4) else {
            continue;
        };
        let branch = u32::from_le_bytes(bytes.try_into().expect("read four bytes"));
        if branch & 0xFF00_0010 != 0x5400_0000 || !matches!(branch & 0xF, 0x8 | 0x2) {
            continue;
        }
        let Some(InstructionTarget::Direct {
            address: default_target,
        }) = guard.target.as_ref()
        else {
            continue;
        };
        let compared = u64::from((word >> 10) & 0xFFF);
        let exclusive = branch & 0xF == 0x2;
        if exclusive && compared == 0 {
            continue;
        }
        let maximum_index = if exclusive { compared - 1 } else { compared };
        return Some(RawJumpTableRange {
            compare_instruction_address: Some(compare.address),
            guard_instruction_address: guard.address,
            guard_kind: if exclusive {
                JumpTableRangeGuardKind::BranchAboveOrEqual
            } else {
                JumpTableRangeGuardKind::BranchAbove
            },
            maximum_index,
            entry_count: compared.saturating_add(u64::from(!exclusive)),
            default: RawJumpTableDefault::Direct(*default_target),
        });
    }
    None
}

fn arm64_clamped_entry_range(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    branch_index: usize,
) -> Option<RawJumpTableRange> {
    let branch_register = branch_register(instructions.get(branch_index)?)?;
    let (add_index, add) = last_register_writer(instructions, branch_index, branch_register)?;
    if add.value_effect != ControlFlowValueEffect::AddRegister {
        return None;
    }
    let (load_index, load) = last_register_writer(instructions, add_index, branch_register)?;
    if !matches!(
        load.value_effect,
        ControlFlowValueEffect::Load | ControlFlowValueEffect::SignExtend32
    ) {
        return None;
    }
    let index_register = load.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::IndexedMemory {
            index, scale: 4, ..
        } => Some(*index),
        _ => None,
    })?;
    let first = load_index.saturating_sub(32);
    for compare_index in (first..load_index).rev() {
        let compare = instructions.get(compare_index)?;
        let bytes = macho.read_bytes_at_va(Va(compare.address), 4).ok()?;
        let compare_word = u32::from_le_bytes(bytes.try_into().ok()?);
        if compare_word & 0x7F80_001F != 0x7100_001F
            || ((compare_word >> 5) & 0x1F) as u8 != index_register.number
        {
            continue;
        }
        let select = instructions.get(compare_index + 1)?;
        if compare_index + 1 >= load_index {
            continue;
        }
        let bytes = macho.read_bytes_at_va(Va(select.address), 4).ok()?;
        let select_word = u32::from_le_bytes(bytes.try_into().ok()?);
        let is_clamp_to_zero = select_word & 0x7FE0_0C00 == 0x1A80_0000
            && (select_word & 0x1F) as u8 == index_register.number
            && ((select_word >> 5) & 0x1F) as u8 == index_register.number
            && (select_word >> 16) & 0x1F == 31
            && (select_word >> 12) & 0xF == 9; // CSEL index,index,xzr,LS
        if !is_clamp_to_zero {
            continue;
        }
        let maximum_index = u64::from((compare_word >> 10) & 0xFFF);
        return Some(RawJumpTableRange {
            compare_instruction_address: Some(compare.address),
            guard_instruction_address: select.address,
            guard_kind: JumpTableRangeGuardKind::ClampToFirstEntry,
            maximum_index,
            entry_count: maximum_index.saturating_add(1),
            default: RawJumpTableDefault::FirstEntry,
        });
    }
    None
}

fn branch_register(instruction: &ControlFlowInstruction) -> Option<ControlFlowRegister> {
    match instruction.operands.first()? {
        ControlFlowOperand::Register { register } => Some(*register),
        _ => None,
    }
}

fn x86_relative_index_register(
    instructions: &[ControlFlowInstruction],
    branch_index: usize,
) -> Option<(ControlFlowRegister, usize)> {
    let target_register = branch_register(instructions.get(branch_index)?)?;
    let (add_index, add) = last_register_writer(instructions, branch_index, target_register)?;
    if add.value_effect != ControlFlowValueEffect::AddRegister {
        return None;
    }
    let (load_index, load) = last_register_writer(instructions, add_index, target_register)?;
    if !matches!(
        load.value_effect,
        ControlFlowValueEffect::Load | ControlFlowValueEffect::SignExtend32
    ) {
        return None;
    }
    load.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::IndexedMemory {
            index, scale: 4, ..
        } => Some((*index, load_index)),
        _ => None,
    })
}

fn x86_index_range(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    index_register: ControlFlowRegister,
) -> Option<RawJumpTableRange> {
    x86_register_origins(instructions, before_index, index_register)
        .into_iter()
        .find_map(|register| x86_guarded_entry_range(macho, instructions, before_index, register))
        .or_else(|| x86_masked_entry_range(macho, instructions, before_index, index_register))
        .or_else(|| x86_shifted_entry_range(macho, instructions, before_index, index_register))
}

fn x86_register_origins(
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    register: ControlFlowRegister,
) -> Vec<ControlFlowRegister> {
    let mut result = vec![register];
    let mut current = register;
    let mut cursor = before_index;
    for _ in 0..4 {
        let Some((writer_index, writer)) = last_register_writer(instructions, cursor, current)
        else {
            break;
        };
        if writer.value_effect != ControlFlowValueEffect::Set {
            break;
        }
        let Some(ControlFlowOperand::Register { register: source }) = writer.operands.get(1) else {
            break;
        };
        current = *source;
        cursor = writer_index;
        if !result.contains(&current) {
            result.push(current);
        }
    }
    result
}

fn x86_guarded_entry_range(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    index_register: ControlFlowRegister,
) -> Option<RawJumpTableRange> {
    let first = before_index.saturating_sub(32);
    for compare_index in (first..before_index).rev() {
        let compare = instructions.get(compare_index)?;
        let [
            ControlFlowOperand::Register { register },
            ControlFlowOperand::Immediate { value },
            ..,
        ] = compare.operands.as_slice()
        else {
            continue;
        };
        if *register != index_register || *value < 0 {
            continue;
        }
        let compare_bytes = macho
            .read_bytes_at_va(Va(compare.address), compare.byte_len as usize)
            .ok()?;
        if !is_x86_cmp_immediate(compare_bytes) {
            continue;
        }
        let mut guard = None;
        for candidate in &instructions[compare_index + 1..before_index] {
            if candidate.kind == ControlFlowInstructionKind::ConditionalBranch {
                guard = Some(candidate);
                break;
            }
            let bytes = macho
                .read_bytes_at_va(Va(candidate.address), candidate.byte_len as usize)
                .ok()?;
            if !is_x86_flag_preserving_between_compare_and_guard(bytes) {
                break;
            }
        }
        let Some(guard) = guard else {
            continue;
        };
        let guard_bytes = macho
            .read_bytes_at_va(Va(guard.address), guard.byte_len as usize)
            .ok()?;
        let exclusive = matches!(guard_bytes, [0x73, _] | [0x0F, 0x83, _, _, _, _]);
        if !exclusive && !matches!(guard_bytes, [0x77, _] | [0x0F, 0x87, _, _, _, _]) {
            continue;
        }
        let Some(InstructionTarget::Direct {
            address: default_target,
        }) = guard.target.as_ref()
        else {
            continue;
        };
        let compared = u64::try_from(*value).ok()?;
        if exclusive && compared == 0 {
            continue;
        }
        let maximum_index = if exclusive { compared - 1 } else { compared };
        return Some(RawJumpTableRange {
            compare_instruction_address: Some(compare.address),
            guard_instruction_address: guard.address,
            guard_kind: if exclusive {
                JumpTableRangeGuardKind::BranchAboveOrEqual
            } else {
                JumpTableRangeGuardKind::BranchAbove
            },
            maximum_index,
            entry_count: compared.saturating_add(u64::from(!exclusive)),
            default: RawJumpTableDefault::Direct(*default_target),
        });
    }
    None
}

fn x86_masked_entry_range(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    index_register: ControlFlowRegister,
) -> Option<RawJumpTableRange> {
    let (_, mask_instruction) = last_register_writer(instructions, before_index, index_register)?;
    let [
        ControlFlowOperand::Register { register },
        ControlFlowOperand::Immediate { value },
        ..,
    ] = mask_instruction.operands.as_slice()
    else {
        return None;
    };
    if *register != index_register || *value < 0 {
        return None;
    }
    let mask = u64::try_from(*value).ok()?;
    if !mask.saturating_add(1).is_power_of_two() {
        return None;
    }
    let bytes = macho
        .read_bytes_at_va(
            Va(mask_instruction.address),
            mask_instruction.byte_len as usize,
        )
        .ok()?;
    if !is_x86_and_immediate(bytes) {
        return None;
    }
    Some(RawJumpTableRange {
        compare_instruction_address: None,
        guard_instruction_address: mask_instruction.address,
        guard_kind: JumpTableRangeGuardKind::BitMask,
        maximum_index: mask,
        entry_count: mask.saturating_add(1),
        default: RawJumpTableDefault::None,
    })
}

fn x86_shifted_entry_range(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    index_register: ControlFlowRegister,
) -> Option<RawJumpTableRange> {
    let (_, shift_instruction) = last_register_writer(instructions, before_index, index_register)?;
    if shift_instruction.value_effect != ControlFlowValueEffect::ShiftImmediate {
        return None;
    }
    let [
        ControlFlowOperand::Register { register },
        ControlFlowOperand::ShiftedRegister {
            register: shifted,
            shift: ControlFlowRegisterShift::LogicalRight,
            amount,
        },
        ..,
    ] = shift_instruction.operands.as_slice()
    else {
        return None;
    };
    if *register != index_register || *shifted != index_register || !(1..64).contains(amount) {
        return None;
    }
    let result_bits = 64_u8.checked_sub(*amount)?;
    if result_bits > 16 {
        return None;
    }
    let bytes = macho
        .read_bytes_at_va(
            Va(shift_instruction.address),
            shift_instruction.byte_len as usize,
        )
        .ok()?;
    if !is_x86_64_logical_shift_right_immediate(bytes) {
        return None;
    }
    let entry_count = 1_u64.checked_shl(u32::from(result_bits))?;
    Some(RawJumpTableRange {
        compare_instruction_address: None,
        guard_instruction_address: shift_instruction.address,
        guard_kind: JumpTableRangeGuardKind::LogicalShiftRight,
        maximum_index: entry_count - 1,
        entry_count,
        default: RawJumpTableDefault::None,
    })
}

fn is_x86_64_logical_shift_right_immediate(bytes: &[u8]) -> bool {
    matches!(bytes, [rex, 0xC1, modrm, _] if rex & 0xF8 == 0x48 && modrm >> 6 == 0b11 && (modrm >> 3) & 7 == 5)
}

fn is_x86_and_immediate(bytes: &[u8]) -> bool {
    let opcode_index = usize::from(
        bytes
            .first()
            .is_some_and(|byte| (0x40..=0x4F).contains(byte)),
    );
    match bytes.get(opcode_index).copied() {
        Some(0x25) => true,
        Some(0x80 | 0x81 | 0x83) => bytes
            .get(opcode_index + 1)
            .is_some_and(|modrm| modrm >> 6 == 0b11 && (modrm >> 3) & 7 == 4),
        _ => false,
    }
}

fn is_x86_flag_preserving_between_compare_and_guard(bytes: &[u8]) -> bool {
    let opcode_index = usize::from(
        bytes
            .first()
            .is_some_and(|byte| (0x40..=0x4F).contains(byte)),
    );
    match bytes.get(opcode_index).copied() {
        Some(0x88..=0x8B | 0x8D | 0x90 | 0xB8..=0xBF | 0xC6 | 0xC7) => true,
        Some(0x0F) => bytes
            .get(opcode_index + 1)
            .is_some_and(|opcode| (0x40..=0x4F).contains(opcode)), // CMOVcc
        _ => false,
    }
}

fn is_x86_cmp_immediate(bytes: &[u8]) -> bool {
    let opcode_index = usize::from(
        bytes
            .first()
            .is_some_and(|byte| (0x40..=0x4F).contains(byte)),
    );
    match bytes.get(opcode_index).copied() {
        Some(0x3D) => true,
        Some(0x81 | 0x83) => bytes
            .get(opcode_index + 1)
            .is_some_and(|modrm| modrm >> 6 == 0b11 && (modrm >> 3) & 7 == 7),
        _ => false,
    }
}

fn last_register_writer(
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    register: ControlFlowRegister,
) -> Option<(usize, &ControlFlowInstruction)> {
    instructions[..before_index]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, instruction)| instruction.written_register == Some(register))
}

fn relative_jump_table_descriptor(
    instructions: &[ControlFlowInstruction],
    branch_index: usize,
) -> Option<JumpTableDescriptor> {
    let branch_register = branch_register(&instructions[branch_index])?;
    let (add_index, add) = last_register_writer(instructions, branch_index, branch_register)?;
    if add.value_effect != ControlFlowValueEffect::AddRegister {
        return None;
    }
    let ControlFlowOperand::Register {
        register: base_register,
    } = add.operands.get(1)?
    else {
        return None;
    };
    let (load_index, load) = last_register_writer(instructions, add_index, branch_register)?;
    if !matches!(
        load.value_effect,
        ControlFlowValueEffect::Load | ControlFlowValueEffect::SignExtend32
    ) {
        return None;
    }
    let displacement = load.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::IndexedMemory {
            scale: 4,
            displacement,
            ..
        } => Some(*displacement),
        _ => None,
    })?;
    let table_base = load.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::IndexedMemory { base, .. } => Some(*base),
        _ => None,
    })?;
    let base_address = indexed_table_address(instructions, load_index, Some(table_base), 0)?;
    let relative_target_base =
        resolve_register_address(instructions, add_index, *base_register, 0)?;
    Some(JumpTableDescriptor {
        table_address: base_address.wrapping_add_signed(displacement),
        entry_width: 4,
        encoding: JumpTableEncoding::RelativeSigned32,
        relative_base: Some(relative_target_base),
        range: None,
    })
}

fn indexed_table_address(
    instructions: &[ControlFlowInstruction],
    branch_index: usize,
    base: Option<ControlFlowRegister>,
    displacement: i64,
) -> Option<u64> {
    let Some(base) = base else {
        return u64::try_from(displacement).ok();
    };
    resolve_register_address(instructions, branch_index, base, 0)
        .map(|address| address.wrapping_add_signed(displacement))
}

fn resolve_register_address(
    instructions: &[ControlFlowInstruction],
    before_index: usize,
    register: ControlFlowRegister,
    depth: u8,
) -> Option<u64> {
    if depth >= 4 {
        return None;
    }
    let (writer_index, writer) = last_register_writer(instructions, before_index, register)?;
    if let Some(reference) = writer.pc_relative
        && matches!(
            reference.kind,
            ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::PageAddress
        )
    {
        return Some(reference.address);
    }
    if writer.value_effect != ControlFlowValueEffect::AddImmediate {
        return None;
    }
    let ControlFlowOperand::Register { register: source } = writer.operands.get(1)? else {
        return None;
    };
    let ControlFlowOperand::Immediate { value } = writer.operands.get(2)? else {
        return None;
    };
    resolve_register_address(instructions, writer_index, *source, depth + 1)
        .map(|address| address.wrapping_add_signed(*value))
}

fn finalize_jump_tables(raw: Vec<RawJumpTable>, blocks: &[BasicBlock]) -> Vec<RecoveredJumpTable> {
    let block_by_start = blocks
        .iter()
        .map(|block| (block.start, block.id))
        .collect::<BTreeMap<_, _>>();
    raw.into_iter()
        .filter_map(|table| {
            let source_block = blocks
                .iter()
                .find(|block| {
                    table.instruction_address >= block.start
                        && table.instruction_address < block.end_exclusive
                })?
                .id;
            let observed_entry_count = table.entries.len();
            let entries = table
                .entries
                .into_iter()
                .enumerate()
                .filter_map(|(index, (entry_address, target))| {
                    Some(JumpTableEntry {
                        index: index as u64,
                        entry_address,
                        target,
                        target_block: *block_by_start.get(&target)?,
                    })
                })
                .collect::<Vec<_>>();
            let mut reasons = if table.range.is_some() {
                vec!["jump_table.range_check_derived".into()]
            } else {
                vec!["jump_table.range_check_unresolved".into()]
            };
            if entries.len() != observed_entry_count {
                reasons.push("jump_table.target_block_omitted".into());
            }
            if table.truncated {
                reasons.push("jump_table.entry_budget".into());
            }
            if table.incomplete {
                reasons.push("jump_table.invalid_or_unreadable_entry".into());
            }
            let range = table.range.and_then(|range| {
                let guard_block = blocks
                    .iter()
                    .find(|block| {
                        range.guard_instruction_address >= block.start
                            && range.guard_instruction_address < block.end_exclusive
                    })?
                    .id;
                let default_target = match range.default {
                    RawJumpTableDefault::Direct(target) => Some(target),
                    RawJumpTableDefault::FirstEntry => Some(entries.first()?.target),
                    RawJumpTableDefault::None => None,
                };
                Some(JumpTableRangeEvidence {
                    compare_instruction_address: range.compare_instruction_address,
                    guard_instruction_address: range.guard_instruction_address,
                    guard_kind: range.guard_kind,
                    guard_block,
                    maximum_index: range.maximum_index,
                    entry_count: range.entry_count,
                    default_target,
                    default_block: default_target
                        .and_then(|target| block_by_start.get(&target).copied()),
                })
            });
            if table.range.is_some() && range.is_none() {
                reasons.push("jump_table.range_guard_block_omitted".into());
            }
            Some(RecoveredJumpTable {
                instruction_address: table.instruction_address,
                source_block,
                table_address: table.table_address,
                end_exclusive: table
                    .table_address
                    .saturating_add((entries.len() as u64).saturating_mul(table.entry_width)),
                encoding: table.encoding,
                entries,
                range,
                truncated: table.truncated,
                reasons,
            })
        })
        .collect()
}

fn build_blocks(
    instructions: &[ControlFlowInstruction],
    function_entry: u64,
    additional_leaders: &BTreeSet<u64>,
    maximum: usize,
) -> (Vec<BasicBlock>, Option<(u64, u64)>) {
    if instructions.is_empty() {
        return (Vec::new(), None);
    }
    let has_address = |address| {
        instructions
            .binary_search_by_key(&address, |instruction| instruction.address)
            .is_ok()
    };
    let mut leaders = BTreeSet::new();
    if has_address(function_entry) {
        leaders.insert(function_entry);
    }
    leaders.insert(instructions[0].address);
    leaders.extend(additional_leaders.iter().copied());
    for (index, instruction) in instructions.iter().enumerate() {
        if index > 0 {
            let previous = &instructions[index - 1];
            if previous.address + previous.byte_len as u64 != instruction.address {
                leaders.insert(instruction.address);
            }
        }
        if matches!(
            instruction.kind,
            ControlFlowInstructionKind::Branch
                | ControlFlowInstructionKind::Call
                | ControlFlowInstructionKind::ConditionalBranch
                | ControlFlowInstructionKind::Return
        ) && let Some(next) = instructions.get(index + 1)
        {
            leaders.insert(next.address);
        }
        if let Some(InstructionTarget::Direct { address }) = instruction.target
            && has_address(address)
        {
            leaders.insert(address);
        }
    }
    let mut ranges = Vec::<(usize, usize)>::new();
    let mut start = 0;
    for (index, instruction) in instructions.iter().enumerate().skip(1) {
        if leaders.contains(&instruction.address) {
            ranges.push((start, index));
            start = index;
        }
    }
    ranges.push((start, instructions.len()));
    let continuation = ranges
        .get(maximum)
        .map(|(start, _)| (maximum as u64, instructions[*start].address));
    ranges.truncate(maximum);
    let blocks = ranges
        .into_iter()
        .enumerate()
        .map(|(id, (start, end))| {
            let last = &instructions[end - 1];
            let termination = match last.kind {
                ControlFlowInstructionKind::Return => BasicBlockTermination::Return,
                ControlFlowInstructionKind::Branch => BasicBlockTermination::Branch,
                ControlFlowInstructionKind::ConditionalBranch => {
                    BasicBlockTermination::ConditionalBranch
                }
                ControlFlowInstructionKind::Call => BasicBlockTermination::Call,
                _ if instructions
                    .get(end)
                    .is_some_and(|next| last.address + last.byte_len as u64 == next.address) =>
                {
                    BasicBlockTermination::Fallthrough
                }
                _ => BasicBlockTermination::RangeBoundary,
            };
            BasicBlock {
                id: id as u64,
                start: instructions[start].address,
                end_exclusive: last.address + last.byte_len as u64,
                first_instruction: start as u64,
                instruction_count: (end - start) as u64,
                reachability: ControlFlowReachability::Unknown,
                termination,
                coverage_confidence: instructions[start..end]
                    .iter()
                    .map(|instruction| instruction.coverage_confidence)
                    .min()
                    .expect("block is nonempty"),
            }
        })
        .collect();
    (blocks, continuation)
}

fn connect_blocks(
    instructions: &[ControlFlowInstruction],
    blocks: &[BasicBlock],
    jump_tables: &[RecoveredJumpTable],
    functions: &FunctionIndex,
    non_returning_stubs: &BTreeMap<u64, String>,
    non_returning_functions: &BTreeSet<u64>,
    maximum_edges: usize,
) -> (
    Vec<ControlFlowEdge>,
    Vec<ControlFlowExit>,
    Vec<ControlFlowCallsite>,
    Option<ControlFlowEdge>,
) {
    let block_at = |address| {
        blocks
            .binary_search_by_key(&address, |block| block.start)
            .ok()
            .map(|index| blocks[index].id)
    };
    let mut edges = Vec::new();
    let mut exits = Vec::new();
    let mut calls = Vec::new();
    let mut continuation = None;
    for block in blocks {
        let start = block.first_instruction as usize;
        let end = start + block.instruction_count as usize;
        for instruction in &instructions[start..end] {
            if instruction.kind == ControlFlowInstructionKind::Call
                && let Some(target) = instruction.target.as_ref()
            {
                let non_returning_symbol = match target {
                    InstructionTarget::Direct { address } => {
                        non_returning_stubs.get(address).cloned()
                    }
                    _ => None,
                };
                let non_returning_callee = match target {
                    InstructionTarget::Direct { address }
                        if non_returning_functions.contains(address) =>
                    {
                        Some(*address)
                    }
                    _ => None,
                };
                calls.push(ControlFlowCallsite {
                    block: block.id,
                    instruction_address: instruction.address,
                    target: call_target(target, functions),
                    return_behavior: if non_returning_symbol.is_some()
                        || non_returning_callee.is_some()
                    {
                        ControlFlowCallReturnBehavior::NonReturning
                    } else {
                        ControlFlowCallReturnBehavior::MayReturn
                    },
                    non_returning_symbol,
                    non_returning_callee,
                    exceptional_behavior: ControlFlowCallExceptionBehavior::NotEstablished,
                    landing_pads: Vec::new(),
                });
            }
        }
        let last = &instructions[end - 1];
        let fallthrough = last.address + last.byte_len as u64;
        match last.kind {
            ControlFlowInstructionKind::Return => exits.push(ControlFlowExit {
                block: block.id,
                instruction_address: Some(last.address),
                kind: ControlFlowExitKind::Return,
                target: None,
                recovered_function: None,
                possible_functions: Vec::new(),
            }),
            ControlFlowInstructionKind::Branch => match last.target.as_ref() {
                Some(InstructionTarget::Direct { address }) => {
                    if let Some(to) = block_at(*address) {
                        push_edge(
                            &mut edges,
                            maximum_edges,
                            ControlFlowEdge {
                                from: block.id,
                                to,
                                kind: ControlFlowEdgeKind::Branch,
                            },
                            &mut continuation,
                        );
                    } else {
                        let mut exit = direct_exit(block.id, last.address, *address, functions);
                        if non_returning_stubs.contains_key(address)
                            || non_returning_functions.contains(address)
                        {
                            exit.kind = ControlFlowExitKind::NonReturningTransfer;
                        }
                        exits.push(exit);
                    }
                }
                _ => exits.push(ControlFlowExit {
                    block: block.id,
                    instruction_address: Some(last.address),
                    kind: if jump_tables
                        .iter()
                        .any(|table| table.source_block == block.id)
                    {
                        ControlFlowExitKind::JumpTableDispatch
                    } else if global_pointer_tail_dispatch(&instructions[start..end]) {
                        ControlFlowExitKind::TailDispatch
                    } else {
                        ControlFlowExitKind::IndirectBranch
                    },
                    target: None,
                    recovered_function: None,
                    possible_functions: Vec::new(),
                }),
            },
            ControlFlowInstructionKind::ConditionalBranch => {
                if let Some(InstructionTarget::Direct { address }) = last.target.as_ref() {
                    if let Some(to) = block_at(*address) {
                        push_edge(
                            &mut edges,
                            maximum_edges,
                            ControlFlowEdge {
                                from: block.id,
                                to,
                                kind: ControlFlowEdgeKind::ConditionalTaken,
                            },
                            &mut continuation,
                        );
                    } else {
                        let mut exit = direct_exit(block.id, last.address, *address, functions);
                        if non_returning_stubs.contains_key(address)
                            || non_returning_functions.contains(address)
                        {
                            exit.kind = ControlFlowExitKind::NonReturningTransfer;
                        }
                        exits.push(exit);
                    }
                }
                push_fallthrough(
                    block,
                    last.address,
                    fallthrough,
                    ControlFlowEdgeKind::ConditionalNotTaken,
                    blocks,
                    &mut edges,
                    &mut exits,
                    maximum_edges,
                    &mut continuation,
                );
            }
            ControlFlowInstructionKind::Call => {
                let non_returning = match last.target.as_ref() {
                    Some(InstructionTarget::Direct { address }) => {
                        non_returning_stubs.contains_key(address)
                            || non_returning_functions.contains(address)
                    }
                    _ => false,
                };
                if non_returning {
                    exits.push(ControlFlowExit {
                        block: block.id,
                        instruction_address: Some(last.address),
                        kind: ControlFlowExitKind::NonReturningCall,
                        target: match last.target {
                            Some(InstructionTarget::Direct { address }) => Some(address),
                            _ => None,
                        },
                        recovered_function: None,
                        possible_functions: Vec::new(),
                    });
                } else {
                    push_fallthrough(
                        block,
                        last.address,
                        fallthrough,
                        ControlFlowEdgeKind::CallReturn,
                        blocks,
                        &mut edges,
                        &mut exits,
                        maximum_edges,
                        &mut continuation,
                    );
                }
            }
            _ if block.termination == BasicBlockTermination::Fallthrough => push_fallthrough(
                block,
                last.address,
                fallthrough,
                ControlFlowEdgeKind::Fallthrough,
                blocks,
                &mut edges,
                &mut exits,
                maximum_edges,
                &mut continuation,
            ),
            _ => exits.push(ControlFlowExit {
                block: block.id,
                instruction_address: Some(last.address),
                kind: ControlFlowExitKind::RangeBoundary,
                target: None,
                recovered_function: None,
                possible_functions: Vec::new(),
            }),
        }
    }
    for table in jump_tables {
        for entry in &table.entries {
            push_edge(
                &mut edges,
                maximum_edges,
                ControlFlowEdge {
                    from: table.source_block,
                    to: entry.target_block,
                    kind: ControlFlowEdgeKind::JumpTableCandidate,
                },
                &mut continuation,
            );
        }
    }
    edges.sort_by_key(|edge| (edge.from, edge.to, edge.kind as u8));
    edges.dedup();
    exits.sort_by_key(|exit| {
        (
            exit.block,
            exit.instruction_address,
            exit.kind as u8,
            exit.target,
        )
    });
    calls.sort_by_key(|call| call.instruction_address);
    (edges, exits, calls, continuation)
}

fn global_pointer_tail_dispatch(instructions: &[ControlFlowInstruction]) -> bool {
    let Some(branch) = instructions.last() else {
        return false;
    };
    if matches!(
        branch.operands.first(),
        Some(ControlFlowOperand::Memory { base, .. })
            if base.class == ControlFlowRegisterClass::GeneralPurpose && base.number == 16
    ) && branch
        .pc_relative
        .is_some_and(|relative| relative.kind == ControlFlowPcRelativeKind::Memory)
    {
        return true;
    }
    let Some(ControlFlowOperand::Register { register: target }) = branch.operands.first() else {
        return false;
    };
    let Some((writer_index, writer)) = instructions[..instructions.len().saturating_sub(1)]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, instruction)| instruction.written_register == Some(*target))
    else {
        return false;
    };
    if writer.value_effect != ControlFlowValueEffect::Load {
        return false;
    }
    if writer
        .pc_relative
        .is_some_and(|relative| relative.kind == ControlFlowPcRelativeKind::Memory)
    {
        return true;
    }
    let Some(base) = writer.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::Memory { base, .. }
        | ControlFlowOperand::IndexedMemory { base, .. } => Some(*base),
        _ => None,
    }) else {
        return false;
    };
    instructions[..writer_index]
        .iter()
        .rev()
        .any(|instruction| {
            instruction.written_register == Some(base)
                && instruction
                    .pc_relative
                    .is_some_and(|relative| relative.kind == ControlFlowPcRelativeKind::PageAddress)
        })
}

fn call_target(target: &InstructionTarget, functions: &FunctionIndex) -> ControlFlowCallTarget {
    match target {
        InstructionTarget::Direct { address } => {
            let recovered = functions.by_entry(*address);
            ControlFlowCallTarget::Direct {
                address: *address,
                recovered_function: recovered.map(|function| function.entry),
                entry_confidence: recovered.map(|function| function.entry_confidence),
                possible_functions: recovered_function_targets(functions, *address),
            }
        }
        InstructionTarget::Indirect { target_kind } => ControlFlowCallTarget::Indirect {
            target_kind: *target_kind,
        },
        InstructionTarget::IndexedMemory { .. } => ControlFlowCallTarget::Indirect {
            target_kind: IndirectTargetKind::IndexedMemory,
        },
    }
}

fn direct_exit(
    block: u64,
    instruction_address: u64,
    target: u64,
    functions: &FunctionIndex,
) -> ControlFlowExit {
    let possible_functions = recovered_function_targets(functions, target);
    ControlFlowExit {
        block,
        instruction_address: Some(instruction_address),
        kind: ControlFlowExitKind::DirectBranch,
        target: Some(target),
        recovered_function: functions.by_entry(target).map(|function| function.entry),
        possible_functions,
    }
}

#[allow(clippy::too_many_arguments)]
fn push_fallthrough(
    block: &BasicBlock,
    instruction_address: u64,
    target: u64,
    kind: ControlFlowEdgeKind,
    blocks: &[BasicBlock],
    edges: &mut Vec<ControlFlowEdge>,
    exits: &mut Vec<ControlFlowExit>,
    maximum_edges: usize,
    continuation: &mut Option<ControlFlowEdge>,
) {
    if let Ok(index) = blocks.binary_search_by_key(&target, |block| block.start) {
        push_edge(
            edges,
            maximum_edges,
            ControlFlowEdge {
                from: block.id,
                to: blocks[index].id,
                kind,
            },
            continuation,
        );
    } else {
        exits.push(ControlFlowExit {
            block: block.id,
            instruction_address: Some(instruction_address),
            kind: ControlFlowExitKind::FallthroughOutsideCoverage,
            target: Some(target),
            recovered_function: None,
            possible_functions: Vec::new(),
        });
    }
}

fn push_edge(
    edges: &mut Vec<ControlFlowEdge>,
    maximum: usize,
    edge: ControlFlowEdge,
    continuation: &mut Option<ControlFlowEdge>,
) {
    if edges.len() < maximum {
        edges.push(edge);
    } else {
        continuation.get_or_insert(edge);
    }
}

fn mark_reachability(
    blocks: &mut [BasicBlock],
    edges: &[ControlFlowEdge],
    entry: u64,
    incomplete: bool,
) {
    let Some(entry_id) = blocks
        .iter()
        .find(|block| block.start == entry)
        .map(|block| block.id)
    else {
        return;
    };
    let mut successors = vec![Vec::<usize>::new(); blocks.len()];
    for edge in edges {
        if let (Ok(from), Ok(to)) = (usize::try_from(edge.from), usize::try_from(edge.to))
            && let Some(next) = successors.get_mut(from)
            && to < blocks.len()
        {
            next.push(to);
        }
    }
    let Ok(entry_id) = usize::try_from(entry_id) else {
        return;
    };
    let mut work = vec![entry_id];
    let mut reached = vec![false; blocks.len()];
    while let Some(block) = work.pop() {
        let Some(was_reached) = reached.get_mut(block) else {
            continue;
        };
        if *was_reached {
            continue;
        }
        *was_reached = true;
        if let Some(next) = successors.get(block) {
            work.extend(next.iter().copied());
        }
    }
    for block in blocks {
        block.reachability = if usize::try_from(block.id)
            .ok()
            .and_then(|id| reached.get(id))
            .copied()
            .unwrap_or(false)
        {
            ControlFlowReachability::Reachable
        } else if incomplete {
            ControlFlowReachability::Unknown
        } else {
            ControlFlowReachability::Unreachable
        };
    }
}

fn recovered_function_targets(
    functions: &FunctionIndex,
    address: u64,
) -> Vec<RecoveredFunctionTarget> {
    let exact_entry = functions.by_entry(address).map(|function| function.entry);
    let guided_relationship = functions.relationship_at(address);
    let mut targets = BTreeMap::<u64, RecoveredFunctionTarget>::new();
    let mut add_owner = |entry: u64, ownership_confidence: FunctionOwnershipConfidence| {
        let function = functions
            .by_entry(entry)
            .expect("function lookup returned an indexed identity");
        targets.insert(
            entry,
            RecoveredFunctionTarget {
                entry,
                relation: if Some(entry) == exact_entry {
                    FunctionTargetRelation::ExactEntry
                } else if guided_relationship
                    .is_some_and(|relationship| relationship.owner_entry == entry)
                {
                    match guided_relationship
                        .expect("relationship was just matched")
                        .kind
                    {
                        crate::analysis::functions::FunctionRelationshipKind::AlternateEntry => {
                            FunctionTargetRelation::CallerGuidedAlternateEntry
                        }
                        crate::analysis::functions::FunctionRelationshipKind::ColdFragment => {
                            FunctionTargetRelation::CallerGuidedColdFragment
                        }
                        crate::analysis::functions::FunctionRelationshipKind::SharedRange => {
                            FunctionTargetRelation::CallerGuidedSharedRange
                        }
                    }
                } else {
                    FunctionTargetRelation::ContainingExtent
                },
                entry_confidence: function.entry_confidence,
                ownership_confidence,
            },
        );
    };
    for owner in functions.owners(address) {
        add_owner(owner.function.entry, owner.confidence);
    }
    if let Some(entry) = exact_entry {
        add_owner(
            entry,
            match functions
                .by_entry(entry)
                .expect("entry exists")
                .entry_confidence
            {
                FunctionEvidenceConfidence::Exact => FunctionOwnershipConfidence::Exact,
                FunctionEvidenceConfidence::Derived => FunctionOwnershipConfidence::Derived,
                FunctionEvidenceConfidence::Candidate => FunctionOwnershipConfidence::Candidate,
            },
        );
    }
    targets.into_values().collect()
}

fn instruction_arch(macho: &MachoFile<'_>) -> Option<Arch> {
    let cpu_type = macho.header().cpu_type().0;
    let cpu_subtype = macho.header().cpu_subtype().0;
    match cpu_type {
        CPU_TYPE_X86_64 => Some(Arch::X86_64),
        CPU_TYPE_ARM64 if cpu_subtype & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E => {
            Some(Arch::Arm64e)
        }
        CPU_TYPE_ARM64 => Some(Arch::Arm64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::functions::FunctionRecoveryLimits;

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    fn move_helper(bytes: &mut [u8], address: u64) {
        bytes[0x158..0x160].copy_from_slice(&address.to_le_bytes());
    }

    fn x86_branching_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes, 0x1_0000_0120);
        bytes[0x100..0x109]
            .copy_from_slice(&[0x74, 0x05, 0xe8, 0x19, 0x00, 0x00, 0x00, 0x90, 0xc3]);
        bytes[0x120] = 0xc3;
        bytes
    }

    fn x86_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x10a].copy_from_slice(&[
            0x48, 0x8d, 0x15, 0x29, 0x00, 0x00, 0x00, // lea rdx,[rip+0x29] => 0x130
            0xff, 0x24, 0xc2, // jmp [rdx+rax*8]
        ]);
        bytes[0x10a..0x120].fill(0x90);
        bytes[0x110] = 0xc3;
        bytes[0x118] = 0xc3;
        bytes[0x130..0x138].copy_from_slice(&0x1_0000_0110_u64.to_le_bytes());
        bytes[0x138..0x140].copy_from_slice(&0x1_0000_0118_u64.to_le_bytes());
        bytes
    }

    fn x86_relative_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x110].copy_from_slice(&[
            0x48, 0x8d, 0x15, 0x29, 0x00, 0x00, 0x00, // lea rdx,[rip+0x29] => 0x130
            0x48, 0x63, 0x04, 0x82, // movsxd rax,dword [rdx+rax*4]
            0x48, 0x01, 0xd0, // add rax,rdx
            0xff, 0xe0, // jmp rax
        ]);
        bytes[0x110..0x120].fill(0x90);
        bytes[0x110] = 0xc3;
        bytes[0x118] = 0xc3;
        bytes[0x130..0x134].copy_from_slice(&(-0x20_i32).to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&(-0x18_i32).to_le_bytes());
        bytes[0x138..0x13c].fill(0);
        bytes
    }

    fn x86_guarded_relative_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x115].copy_from_slice(&[
            0x83, 0xf8, 0x01, // cmp eax,1
            0x77, 0x17, // ja 0x11c
            0x48, 0x8d, 0x15, 0x24, 0x00, 0x00, 0x00, // lea rdx,[rip+0x24] => 0x130
            0x48, 0x63, 0x04, 0x82, // movsxd rax,dword [rdx+rax*4]
            0x48, 0x01, 0xd0, // add rax,rdx
            0xff, 0xe0, // jmp rax
        ]);
        bytes[0x115] = 0xc3;
        bytes[0x118] = 0xc3;
        bytes[0x11c] = 0xc3;
        bytes[0x130..0x134].copy_from_slice(&(-0x1b_i32).to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&(-0x18_i32).to_le_bytes());
        bytes
    }

    fn x86_exclusive_guarded_relative_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_guarded_relative_jump_table_fixture();
        bytes[0x102] = 0x02; // cmp eax,2: exclusive entry count
        bytes[0x103] = 0x73; // jae 0x11c
        bytes
    }

    fn x86_nonadjacent_guarded_relative_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x118].copy_from_slice(&[
            0x83, 0xf8, 0x01, // cmp eax,1
            0x48, 0x89, 0xdb, // mov rbx,rbx (flags preserved)
            0x77, 0x14, // ja 0x11c
            0x48, 0x8d, 0x15, 0x21, 0x00, 0x00, 0x00, // lea rdx,[rip+0x21] => 0x130
            0x48, 0x63, 0x04, 0x82, // movsxd rax,dword [rdx+rax*4]
            0x48, 0x01, 0xd0, // add rax,rdx
            0xff, 0xe0, // jmp rax
        ]);
        bytes[0x118] = 0xc3;
        bytes[0x11a] = 0xc3;
        bytes[0x11c] = 0xc3;
        bytes[0x130..0x134].copy_from_slice(&(-0x18_i32).to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&(-0x16_i32).to_le_bytes());
        bytes
    }

    fn x86_masked_relative_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x113].copy_from_slice(&[
            0x83, 0xe0, 0x01, // and eax,1
            0x48, 0x8d, 0x15, 0x26, 0x00, 0x00, 0x00, // lea rdx,[rip+0x26] => 0x130
            0x48, 0x63, 0x04, 0x82, // movsxd rax,dword [rdx+rax*4]
            0x48, 0x01, 0xd0, // add rax,rdx
            0xff, 0xe0, // jmp rax
        ]);
        bytes[0x114] = 0xc3;
        bytes[0x118] = 0xc3;
        bytes[0x130..0x134].copy_from_slice(&(-0x1c_i32).to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&(-0x18_i32).to_le_bytes());
        bytes
    }

    fn x86_shifted_relative_jump_table_fixture() -> Vec<u8> {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x114].copy_from_slice(&[
            0x48, 0xc1, 0xe8, 0x3e, // shr rax,62 => exact index range 0..=3
            0x48, 0x8d, 0x15, 0x25, 0x00, 0x00, 0x00, // lea rdx,[rip+0x25] => 0x130
            0x48, 0x63, 0x04, 0x82, // movsxd rax,dword [rdx+rax*4]
            0x48, 0x01, 0xd0, // add rax,rdx
            0xff, 0xe0, // jmp rax
        ]);
        for address in [0x114, 0x118, 0x11c, 0x120] {
            bytes[address] = 0xc3;
        }
        for (offset, relative) in [-0x1c_i32, -0x18, -0x14, -0x1c].into_iter().enumerate() {
            let start = 0x130 + offset * 4;
            bytes[start..start + 4].copy_from_slice(&relative.to_le_bytes());
        }
        bytes
    }

    fn arm_branching_fixture(arm64e: bool) -> Vec<u8> {
        let mut bytes = if arm64e {
            macho_test_support::disassembly_arm64e()
        } else {
            macho_test_support::disassembly_arm64()
        };
        move_helper(&mut bytes, 0x1_0000_0120);
        bytes[0x100..0x104].copy_from_slice(&0x5400_0040_u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0x9400_0007_u32.to_le_bytes());
        bytes[0x108..0x10c].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes
    }

    fn arm_jump_table_fixture(arm64e: bool, relative: bool) -> Vec<u8> {
        let mut bytes = arm_branching_fixture(arm64e);
        // ADR x8, 0x130 from 0x100.
        bytes[0x100..0x104].copy_from_slice(&0x1000_0188_u32.to_le_bytes());
        if relative {
            bytes[0x104..0x108].copy_from_slice(&0xB8A0_5909_u32.to_le_bytes());
            bytes[0x108..0x10c].copy_from_slice(&0x8B09_0109_u32.to_le_bytes());
            bytes[0x10c..0x110].copy_from_slice(&0xD61F_0120_u32.to_le_bytes());
            bytes[0x130..0x134].copy_from_slice(&(-0x20_i32).to_le_bytes());
            bytes[0x134..0x138].copy_from_slice(&(-0x18_i32).to_le_bytes());
        } else {
            bytes[0x104..0x108].copy_from_slice(&0xF860_7909_u32.to_le_bytes());
            bytes[0x108..0x10c].copy_from_slice(&0xD61F_0120_u32.to_le_bytes());
            bytes[0x130..0x138].copy_from_slice(&0x1_0000_0110_u64.to_le_bytes());
            bytes[0x138..0x140].copy_from_slice(&0x1_0000_0118_u64.to_le_bytes());
        }
        bytes[0x110..0x114].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x118..0x11c].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes
    }

    fn arm_separate_relative_base_fixture(arm64e: bool) -> Vec<u8> {
        let mut bytes = arm_branching_fixture(arm64e);
        // ADR x17, 0x130; LDRSW x16, [x17, x16, LSL #2].
        bytes[0x100..0x104].copy_from_slice(&0x1000_0191_u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0xB8B0_7A30_u32.to_le_bytes());
        // ADR x18, 0x110; ADD x16, x18, x16; BR x16. The target base is
        // intentionally distinct from the table base in x17.
        bytes[0x108..0x10c].copy_from_slice(&0x1000_0052_u32.to_le_bytes());
        bytes[0x10c..0x110].copy_from_slice(&0x8B10_0250_u32.to_le_bytes());
        bytes[0x110..0x114].copy_from_slice(&0xD61F_0200_u32.to_le_bytes());
        bytes[0x114..0x118].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x118..0x11c].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x130..0x134].copy_from_slice(&4_i32.to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&8_i32.to_le_bytes());
        bytes
    }

    fn arm_scaled_offset_table_fixture(arm64e: bool, halfword: bool) -> Vec<u8> {
        let mut bytes = arm_branching_fixture(arm64e);
        move_helper(&mut bytes, 0x1_0000_0128);
        bytes[0x100..0x104].copy_from_slice(&0xF100_041F_u32.to_le_bytes()); // cmp x0,#1
        bytes[0x104..0x108].copy_from_slice(&0x5400_0108_u32.to_le_bytes()); // b.hi 0x124
        bytes[0x108..0x10c].copy_from_slice(&0x1000_014A_u32.to_le_bytes()); // adr x10,0x130
        bytes[0x10c..0x110].copy_from_slice(&0x1000_008B_u32.to_le_bytes()); // adr x11,0x11c
        let load: u32 = if halfword { 0x7860_794C } else { 0x3860_694C };
        bytes[0x110..0x114].copy_from_slice(&load.to_le_bytes());
        bytes[0x114..0x118].copy_from_slice(&0x8B0C_096B_u32.to_le_bytes()); // add x11,x11,x12,lsl #2
        bytes[0x118..0x11c].copy_from_slice(&0xD61F_0160_u32.to_le_bytes()); // br x11
        bytes[0x11c..0x120].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        if halfword {
            bytes[0x130..0x132].copy_from_slice(&0_u16.to_le_bytes());
            bytes[0x132..0x134].copy_from_slice(&1_u16.to_le_bytes());
            bytes[0x134..0x136].copy_from_slice(&u16::MAX.to_le_bytes());
        } else {
            bytes[0x130..0x133].copy_from_slice(&[0, 1, u8::MAX]);
        }
        bytes
    }

    fn arm_clamped_signed_table_fixture(arm64e: bool) -> Vec<u8> {
        let mut bytes = arm_branching_fixture(arm64e);
        move_helper(&mut bytes, 0x1_0000_0128);
        bytes[0x100..0x104].copy_from_slice(&0xF100_041F_u32.to_le_bytes()); // cmp x0,#1
        bytes[0x104..0x108].copy_from_slice(&0x9A9F_9000_u32.to_le_bytes()); // csel x0,x0,xzr,ls
        bytes[0x108..0x10c].copy_from_slice(&0x1000_0151_u32.to_le_bytes()); // adr x17,0x130
        bytes[0x10c..0x110].copy_from_slice(&0xB8A0_7A30_u32.to_le_bytes()); // ldrsw x16,[x17,x0,lsl #2]
        bytes[0x110..0x114].copy_from_slice(&0x1000_0092_u32.to_le_bytes()); // adr x18,0x120
        bytes[0x114..0x118].copy_from_slice(&0x8B10_0250_u32.to_le_bytes()); // add x16,x18,x16
        bytes[0x118..0x11c].copy_from_slice(&0xD61F_0200_u32.to_le_bytes()); // br x16
        bytes[0x120..0x124].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x124..0x128].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x130..0x134].copy_from_slice(&0_i32.to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&4_i32.to_le_bytes());
        bytes
    }

    fn recover(bytes: &[u8], limits: ControlFlowLimits) -> ControlFlowIndex {
        let macho = image(bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        ControlFlowIndex::recover(&macho, &functions, limits).unwrap()
    }

    #[test]
    fn known_non_returning_import_contract_is_positive_and_conservative() {
        for name in [
            "_abort",
            "___assert_rtn",
            "___stack_chk_fail",
            "_err",
            "_errc",
            "_errx",
            "_exit",
            "_longjmp",
            "_objc_exception_throw",
            "_pthread_exit",
            "_verr",
            "_verrc",
            "_verrx",
            "_xcselect_invoke_xcrun",
        ] {
            assert!(known_non_returning_import(name), "missing {name}");
        }
        for name in ["_free", "_printf", "_warn", "_warnx"] {
            assert!(!known_non_returning_import(name), "overclassified {name}");
        }
    }

    #[test]
    fn direct_tail_transfer_requires_non_returning_target_evidence() {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x105].copy_from_slice(&[0xe9, 0x1b, 0x00, 0x00, 0x00]);
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let ordinary =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let main = ordinary.by_entry(0x1_0000_0100).unwrap();
        assert!(main.exits.iter().any(|exit| {
            exit.target == Some(0x1_0000_0120) && exit.kind == ControlFlowExitKind::DirectBranch
        }));

        let (_, exits, _, _) = connect_blocks(
            &main.instructions,
            &main.blocks,
            &main.jump_tables,
            &functions,
            &BTreeMap::new(),
            &BTreeSet::from([0x1_0000_0120]),
            usize::MAX,
        );
        assert!(exits.iter().any(|exit| {
            exit.target == Some(0x1_0000_0120)
                && exit.kind == ControlFlowExitKind::NonReturningTransfer
        }));
    }

    #[test]
    fn global_pointer_branches_are_terminal_dispatches_on_x86_and_arm64() {
        let mut x86 = x86_branching_fixture();
        x86[0x100..0x109].copy_from_slice(&[
            0x48, 0x8b, 0x05, 0x29, 0x00, 0x00, 0x00, // mov rax,[rip+0x29] => 0x130
            0xff, 0xe0, // jmp rax
        ]);
        let x86_cfg = recover(&x86, ControlFlowLimits::default());
        assert!(
            x86_cfg
                .by_entry(0x1_0000_0100)
                .unwrap()
                .exits
                .iter()
                .any(|exit| exit.instruction_address == Some(0x1_0000_0107)
                    && exit.kind == ControlFlowExitKind::TailDispatch)
        );

        let mut x86_direct = x86_branching_fixture();
        x86_direct[0x100..0x106].copy_from_slice(&[0xff, 0x25, 0x2a, 0x00, 0x00, 0x00]);
        let x86_direct_cfg = recover(&x86_direct, ControlFlowLimits::default());
        let x86_direct_graph = x86_direct_cfg.by_entry(0x1_0000_0100).unwrap();
        let x86_direct_branch = &x86_direct_graph.instructions[0];
        assert_eq!(x86_direct_branch.kind, ControlFlowInstructionKind::Branch);
        assert_eq!(
            x86_direct_branch.pc_relative,
            Some(ControlFlowPcRelative {
                address: 0x1_0000_0130,
                kind: ControlFlowPcRelativeKind::Memory,
            })
        );
        assert!(x86_direct_graph.exits.iter().any(|exit| {
            exit.instruction_address == Some(0x1_0000_0100)
                && exit.kind == ControlFlowExitKind::TailDispatch
        }));

        let mut x86_call = x86_branching_fixture();
        x86_call[0x100..0x106].copy_from_slice(&[0xff, 0x15, 0x2a, 0x00, 0x00, 0x00]);
        let x86_call_cfg = recover(&x86_call, ControlFlowLimits::default());
        let x86_call_instruction = &x86_call_cfg.by_entry(0x1_0000_0100).unwrap().instructions[0];
        assert_eq!(x86_call_instruction.kind, ControlFlowInstructionKind::Call);
        assert_eq!(
            x86_call_instruction.pc_relative,
            Some(ControlFlowPcRelative {
                address: 0x1_0000_0130,
                kind: ControlFlowPcRelativeKind::Memory,
            })
        );

        let mut arm = arm_branching_fixture(false);
        arm[0x100..0x104].copy_from_slice(&0x9000_0008_u32.to_le_bytes()); // adrp x8,page
        arm[0x104..0x108].copy_from_slice(&0xF940_8502_u32.to_le_bytes()); // ldr x2,[x8,#0x108]
        arm[0x108..0x10c].copy_from_slice(&0xD61F_0040_u32.to_le_bytes()); // br x2
        let arm_cfg = recover(&arm, ControlFlowLimits::default());
        assert!(
            arm_cfg
                .by_entry(0x1_0000_0100)
                .unwrap()
                .exits
                .iter()
                .any(|exit| exit.instruction_address == Some(0x1_0000_0108)
                    && exit.kind == ControlFlowExitKind::TailDispatch)
        );
    }

    #[test]
    fn unsubstantiated_register_branch_remains_unresolved() {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x102].copy_from_slice(&[0xff, 0xe0]); // jmp rax
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        assert!(
            main.exits
                .iter()
                .any(|exit| exit.instruction_address == Some(0x1_0000_0100)
                    && exit.kind == ControlFlowExitKind::IndirectBranch)
        );
        assert_eq!(main.completeness.status, FunctionControlFlowStatus::Partial);
        assert!(
            main.completeness
                .reasons
                .contains(&"control_flow.indirect_branch_unresolved".to_owned())
        );
    }

    #[test]
    fn x86_blocks_edges_calls_and_reachability_share_function_identity() {
        let bytes = x86_branching_fixture();
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        assert_eq!(main.blocks[0].start, 0x1_0000_0100);
        assert_eq!(
            main.blocks[0].termination,
            BasicBlockTermination::ConditionalBranch
        );
        assert!(
            main.blocks
                .iter()
                .take(3)
                .all(|block| { block.reachability == ControlFlowReachability::Reachable })
        );
        assert!(
            main.blocks
                .iter()
                .skip(3)
                .any(|block| { block.reachability == ControlFlowReachability::Unreachable })
        );
        assert!(main.edges.iter().any(|edge| {
            edge.kind == ControlFlowEdgeKind::ConditionalTaken
                && main.blocks[edge.to as usize].start == 0x1_0000_0107
        }));
        assert!(main.edges.iter().any(|edge| {
            edge.kind == ControlFlowEdgeKind::ConditionalNotTaken
                && main.blocks[edge.to as usize].start == 0x1_0000_0102
        }));
        assert_eq!(main.calls.len(), 1);
        assert_eq!(main.calls[0].instruction_address, 0x1_0000_0102);
        assert!(matches!(
            main.calls[0].target,
            ControlFlowCallTarget::Direct {
                address: 0x1_0000_0120,
                recovered_function: Some(0x1_0000_0120),
                ..
            }
        ));
        let ControlFlowCallTarget::Direct {
            possible_functions, ..
        } = &main.calls[0].target
        else {
            unreachable!()
        };
        assert!(possible_functions.iter().any(|target| {
            target.entry == 0x1_0000_0120 && target.relation == FunctionTargetRelation::ExactEntry
        }));
        assert_eq!(
            main.completeness.boundary_confidence,
            Some(FunctionEvidenceConfidence::Candidate)
        );
        assert_eq!(main.completeness.status, FunctionControlFlowStatus::Partial);
    }

    #[test]
    fn arm64_and_arm64e_recover_the_same_branch_shape() {
        for bytes in [arm_branching_fixture(false), arm_branching_fixture(true)] {
            let cfg = recover(&bytes, ControlFlowLimits::default());
            let main = cfg.by_entry(0x1_0000_0100).unwrap();
            assert!(main.edges.iter().any(|edge| {
                edge.kind == ControlFlowEdgeKind::ConditionalTaken
                    && main.blocks[edge.to as usize].start == 0x1_0000_0108
            }));
            assert!(matches!(
                main.calls[0].target,
                ControlFlowCallTarget::Direct {
                    recovered_function: Some(0x1_0000_0120),
                    ..
                }
            ));
        }
    }

    #[test]
    fn lsda_call_sites_add_typed_exceptional_edges_and_outward_exits() {
        let cfg = recover(&x86_branching_fixture(), ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        let local = ExceptionCallSiteRecord {
            function_entry: main.function_entry,
            start: 0x1_0000_0102,
            end_exclusive: 0x1_0000_0107,
            landing_pad: Some(0x1_0000_0107),
            action_offset: 1,
            actions: Vec::new(),
            lsda_address: 0x1_0000_0130,
        };
        let mut edges = main.edges.clone();
        let mut exits = main.exits.clone();
        let mut calls = main.calls.clone();
        let (transfers, continuation, partial) = apply_exception_records(
            &[local],
            &main.blocks,
            &mut edges,
            &mut exits,
            &mut calls,
            usize::MAX,
        );
        assert!(!partial);
        assert_eq!(continuation, None);
        assert_eq!(transfers.len(), 1);
        assert_eq!(transfers[0].landing_pad, Some(0x1_0000_0107));
        assert_eq!(
            calls[0].exceptional_behavior,
            ControlFlowCallExceptionBehavior::LocalLandingPad
        );
        assert_eq!(calls[0].landing_pads, vec![0x1_0000_0107]);
        assert!(edges.iter().any(|edge| {
            edge.from == calls[0].block
                && main.blocks[edge.to as usize].start == 0x1_0000_0107
                && edge.kind == ControlFlowEdgeKind::Exceptional
        }));

        let outward = ExceptionCallSiteRecord {
            landing_pad: None,
            ..transfers_to_call_site(&transfers[0], main.function_entry, 0x1_0000_0107)
        };
        let mut edges = main.edges.clone();
        let mut exits = main.exits.clone();
        let mut calls = main.calls.clone();
        let (_, _, partial) = apply_exception_records(
            &[outward],
            &main.blocks,
            &mut edges,
            &mut exits,
            &mut calls,
            usize::MAX,
        );
        assert!(!partial);
        assert_eq!(
            calls[0].exceptional_behavior,
            ControlFlowCallExceptionBehavior::UnwindsOutOfFunction
        );
        assert!(exits.iter().any(|exit| {
            exit.instruction_address == Some(calls[0].instruction_address)
                && exit.kind == ControlFlowExitKind::ExceptionalUnwind
        }));
    }

    #[test]
    fn semantic_exception_index_flows_through_public_cfg_recovery() {
        let bytes = x86_branching_fixture();
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let exceptions = ExceptionIndex::from_call_sites_for_test(
            &macho,
            vec![ExceptionCallSiteRecord {
                function_entry: 0x1_0000_0100,
                start: 0x1_0000_0102,
                end_exclusive: 0x1_0000_0107,
                landing_pad: Some(0x1_0000_0107),
                action_offset: 1,
                actions: Vec::new(),
                lsda_address: 0x1_0000_0130,
            }],
        );
        let cfg = ControlFlowIndex::recover_with_evidence(
            &macho,
            &functions,
            None,
            Some(&exceptions),
            ControlFlowLimits::default(),
        )
        .unwrap();
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        assert_eq!(main.exceptional_transfers.len(), 1);
        assert!(
            main.edges
                .iter()
                .any(|edge| edge.kind == ControlFlowEdgeKind::Exceptional)
        );
        assert_eq!(
            main.calls[0].exceptional_behavior,
            ControlFlowCallExceptionBehavior::LocalLandingPad
        );
    }

    fn transfers_to_call_site(
        transfer: &ControlFlowExceptionalTransfer,
        function_entry: u64,
        end_exclusive: u64,
    ) -> ExceptionCallSiteRecord {
        ExceptionCallSiteRecord {
            function_entry,
            start: transfer.instruction_address,
            end_exclusive,
            landing_pad: transfer.landing_pad,
            action_offset: transfer.action_offset,
            actions: Vec::new(),
            lsda_address: transfer.lsda_address,
        }
    }

    #[test]
    fn direct_branch_to_another_function_is_an_exit_not_cfg_edge() {
        let mut bytes = x86_branching_fixture();
        bytes[0x100..0x105].copy_from_slice(&[0xe9, 0x1b, 0x00, 0x00, 0x00]);
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        assert!(!main.edges.iter().any(|edge| edge.from == 0));
        assert!(main.exits.iter().any(|exit| {
            exit.kind == ControlFlowExitKind::DirectBranch
                && exit.target == Some(0x1_0000_0120)
                && exit.recovered_function == Some(0x1_0000_0120)
        }));
    }

    #[test]
    fn x86_absolute_pointer_jump_table_adds_bounded_candidate_edges() {
        let bytes = x86_jump_table_fixture();
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        let table = main.jump_tables.first().expect("jump table recovered");

        assert_eq!(table.instruction_address, 0x1_0000_0107);
        assert_eq!(table.table_address, 0x1_0000_0130);
        assert_eq!(table.end_exclusive, 0x1_0000_0140);
        assert_eq!(
            table
                .entries
                .iter()
                .map(|entry| entry.target)
                .collect::<Vec<_>>(),
            vec![0x1_0000_0110, 0x1_0000_0118]
        );
        assert!(
            table
                .reasons
                .contains(&"jump_table.range_check_unresolved".into())
        );
        assert!(table.entries.iter().all(|entry| {
            main.edges.iter().any(|edge| {
                edge.from == table.source_block
                    && edge.to == entry.target_block
                    && edge.kind == ControlFlowEdgeKind::JumpTableCandidate
            })
        }));

        let limited = recover(
            &bytes,
            ControlFlowLimits {
                max_jump_table_entries: 1,
                ..ControlFlowLimits::default()
            },
        );
        assert_eq!(
            limited.continuation(),
            Some(&ControlFlowContinuation::JumpTable {
                function_entry: 0x1_0000_0100,
                instruction_address: 0x1_0000_0107,
                table_address: 0x1_0000_0130,
                index: 1,
            })
        );
    }

    #[test]
    fn x86_relative_jump_table_idiom_recovers_signed_targets() {
        let bytes = x86_relative_jump_table_fixture();
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        let table = main.jump_tables.first().expect("relative table recovered");

        assert_eq!(table.instruction_address, 0x1_0000_010e);
        assert_eq!(table.table_address, 0x1_0000_0130);
        assert_eq!(table.end_exclusive, 0x1_0000_0138);
        assert_eq!(table.encoding, JumpTableEncoding::RelativeSigned32);
        assert_eq!(
            table
                .entries
                .iter()
                .map(|entry| entry.target)
                .collect::<Vec<_>>(),
            vec![0x1_0000_0110, 0x1_0000_0118]
        );
    }

    #[test]
    fn x86_unsigned_guard_bounds_relative_table_and_retains_default() {
        let cfg = recover(
            &x86_guarded_relative_jump_table_fixture(),
            ControlFlowLimits::default(),
        );
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        let table = main.jump_tables.first().expect("guarded table recovered");
        assert_eq!(table.entries.len(), 2);
        let range = table.range.expect("x86 guard retained");
        assert_eq!(range.guard_kind, JumpTableRangeGuardKind::BranchAbove);
        assert_eq!(range.compare_instruction_address, Some(0x1_0000_0100));
        assert_eq!(range.guard_instruction_address, 0x1_0000_0103);
        assert_eq!(range.maximum_index, 1);
        assert_eq!(range.entry_count, 2);
        assert_eq!(range.default_target, Some(0x1_0000_011c));
        assert!(range.default_block.is_some());
        assert!(main.data_ranges.iter().any(|data| {
            data.start == table.table_address
                && data.end_exclusive == table.end_exclusive
                && data.reason == ControlFlowDataRangeReason::RecoveredJumpTable
        }));
        assert!(
            main.byte_ranges
                .iter()
                .filter(|range| {
                    range.start < table.end_exclusive && range.end_exclusive > table.table_address
                })
                .all(|range| range.kind == ControlFlowByteRangeKind::Data)
        );
        assert_eq!(main.completeness.omitted_bytes, 0);
        assert_eq!(main.completeness.gap_bytes, 0);
        assert!(main.instructions.iter().all(|instruction| {
            instruction.address < table.table_address || instruction.address >= table.end_exclusive
        }));
        assert!(main.exits.iter().any(|exit| {
            exit.instruction_address == Some(table.instruction_address)
                && exit.kind == ControlFlowExitKind::JumpTableDispatch
        }));
        assert!(
            !main
                .completeness
                .reasons
                .iter()
                .any(|reason| reason == "control_flow.decode_gap"),
            "table bytes conserved as typed data must not leave a stale decode-gap reason"
        );
    }

    #[test]
    fn x86_unsigned_exclusive_guard_bounds_relative_table() {
        let cfg = recover(
            &x86_exclusive_guarded_relative_jump_table_fixture(),
            ControlFlowLimits::default(),
        );
        let table = cfg
            .by_entry(0x1_0000_0100)
            .unwrap()
            .jump_tables
            .first()
            .expect("exclusively guarded table recovered");
        let range = table.range.expect("exclusive guard retained");
        assert_eq!(
            range.guard_kind,
            JumpTableRangeGuardKind::BranchAboveOrEqual
        );
        assert_eq!(range.maximum_index, 1);
        assert_eq!(range.entry_count, 2);
        assert_eq!(range.default_target, Some(0x1_0000_011c));
    }

    #[test]
    fn x86_guard_survives_flag_preserving_intervening_move() {
        let cfg = recover(
            &x86_nonadjacent_guarded_relative_jump_table_fixture(),
            ControlFlowLimits::default(),
        );
        let table = cfg
            .by_entry(0x1_0000_0100)
            .unwrap()
            .jump_tables
            .first()
            .expect("non-adjacent guard retained");
        let range = table.range.expect("range retained");
        assert_eq!(range.compare_instruction_address, Some(0x1_0000_0100));
        assert_eq!(range.guard_instruction_address, 0x1_0000_0106);
        assert_eq!(range.entry_count, 2);
    }

    #[test]
    fn x86_bit_mask_bounds_table_without_inventing_default_path() {
        let cfg = recover(
            &x86_masked_relative_jump_table_fixture(),
            ControlFlowLimits::default(),
        );
        let table = cfg
            .by_entry(0x1_0000_0100)
            .unwrap()
            .jump_tables
            .first()
            .expect("mask-bounded table retained");
        let range = table.range.expect("mask range retained");
        assert_eq!(range.guard_kind, JumpTableRangeGuardKind::BitMask);
        assert_eq!(range.compare_instruction_address, None);
        assert_eq!(range.guard_instruction_address, 0x1_0000_0100);
        assert_eq!(range.maximum_index, 1);
        assert_eq!(range.entry_count, 2);
        assert_eq!(range.default_target, None);
        assert_eq!(range.default_block, None);
    }

    #[test]
    fn x86_logical_right_shift_proves_a_small_exact_table_range() {
        let cfg = recover(
            &x86_shifted_relative_jump_table_fixture(),
            ControlFlowLimits::default(),
        );
        let table = cfg
            .by_entry(0x1_0000_0100)
            .unwrap()
            .jump_tables
            .first()
            .expect("shift-bounded table retained");
        let range = table.range.expect("shift range retained");
        assert_eq!(range.guard_kind, JumpTableRangeGuardKind::LogicalShiftRight);
        assert_eq!(range.guard_instruction_address, 0x1_0000_0100);
        assert_eq!(range.maximum_index, 3);
        assert_eq!(range.entry_count, 4);
        assert_eq!(table.entries.len(), 4);
    }

    #[test]
    fn arm64_and_arm64e_absolute_pointer_tables_recover_candidate_edges() {
        for bytes in [
            arm_jump_table_fixture(false, false),
            arm_jump_table_fixture(true, false),
        ] {
            let cfg = recover(&bytes, ControlFlowLimits::default());
            let main = cfg.by_entry(0x1_0000_0100).unwrap();
            let table = main.jump_tables.first().expect("absolute table recovered");
            assert_eq!(table.instruction_address, 0x1_0000_0108);
            assert_eq!(table.table_address, 0x1_0000_0130);
            assert_eq!(table.encoding, JumpTableEncoding::AbsolutePointer64);
            assert_eq!(
                table
                    .entries
                    .iter()
                    .map(|entry| entry.target)
                    .collect::<Vec<_>>(),
                vec![0x1_0000_0110, 0x1_0000_0118]
            );
        }
    }

    #[test]
    fn arm64_and_arm64e_signed_relative_tables_recover_candidate_edges() {
        for bytes in [
            arm_jump_table_fixture(false, true),
            arm_jump_table_fixture(true, true),
        ] {
            let cfg = recover(&bytes, ControlFlowLimits::default());
            let main = cfg.by_entry(0x1_0000_0100).unwrap();
            let table = main.jump_tables.first().expect("relative table recovered");
            assert_eq!(table.instruction_address, 0x1_0000_010c);
            assert_eq!(table.table_address, 0x1_0000_0130);
            assert_eq!(table.encoding, JumpTableEncoding::RelativeSigned32);
            assert_eq!(
                table
                    .entries
                    .iter()
                    .map(|entry| entry.target)
                    .collect::<Vec<_>>(),
                vec![0x1_0000_0110, 0x1_0000_0118]
            );
        }
    }

    #[test]
    fn arm64_relative_table_can_use_a_separate_target_base() {
        for bytes in [
            arm_separate_relative_base_fixture(false),
            arm_separate_relative_base_fixture(true),
        ] {
            let cfg = recover(&bytes, ControlFlowLimits::default());
            let main = cfg.by_entry(0x1_0000_0100).unwrap();
            let table = main.jump_tables.first().expect("relative table recovered");
            assert_eq!(table.table_address, 0x1_0000_0130);
            assert_eq!(
                table
                    .entries
                    .iter()
                    .map(|entry| entry.target)
                    .collect::<Vec<_>>(),
                vec![0x1_0000_0114, 0x1_0000_0118]
            );
            assert!(
                table
                    .reasons
                    .contains(&"jump_table.range_check_unresolved".into())
            );
        }
    }

    #[test]
    fn arm64_byte_and_halfword_scaled_offset_tables_recover() {
        for (halfword, encoding, end_exclusive) in [
            (
                false,
                JumpTableEncoding::RelativeUnsigned8Scaled4,
                0x1_0000_0132,
            ),
            (
                true,
                JumpTableEncoding::RelativeUnsigned16Scaled4,
                0x1_0000_0134,
            ),
        ] {
            let cfg = recover(
                &arm_scaled_offset_table_fixture(true, halfword),
                ControlFlowLimits::default(),
            );
            let main = cfg.by_entry(0x1_0000_0100).unwrap();
            let table = main.jump_tables.first().expect("scaled table recovered");
            assert_eq!(table.encoding, encoding);
            assert_eq!(table.table_address, 0x1_0000_0130);
            assert_eq!(table.end_exclusive, end_exclusive);
            assert_eq!(
                table
                    .entries
                    .iter()
                    .map(|entry| entry.target)
                    .collect::<Vec<_>>(),
                vec![0x1_0000_011c, 0x1_0000_0120]
            );
            assert!(
                table
                    .reasons
                    .contains(&"jump_table.range_check_derived".into())
            );
            let range = table.range.expect("range evidence retained");
            assert_eq!(range.compare_instruction_address, Some(0x1_0000_0100));
            assert_eq!(range.guard_instruction_address, 0x1_0000_0104);
            assert_eq!(range.maximum_index, 1);
            assert_eq!(range.entry_count, 2);
            assert_eq!(range.default_target, Some(0x1_0000_0124));
            let default_block = range.default_block.expect("default block retained");
            assert!(main.edges.iter().any(|edge| {
                edge.from == range.guard_block
                    && edge.to == default_block
                    && edge.kind == ControlFlowEdgeKind::ConditionalTaken
            }));
        }
    }

    #[test]
    fn arm64_scaled_offset_table_requires_an_upper_bound_guard() {
        let mut bytes = arm_scaled_offset_table_fixture(false, false);
        bytes[0x104..0x108].copy_from_slice(&0x5400_0100_u32.to_le_bytes()); // b.eq, not b.hi
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let main = cfg.by_entry(0x1_0000_0100).unwrap();
        assert!(main.jump_tables.is_empty());
    }

    #[test]
    fn arm64_clamped_signed_table_retains_range_and_first_entry_default() {
        for bytes in [
            arm_clamped_signed_table_fixture(false),
            arm_clamped_signed_table_fixture(true),
        ] {
            let cfg = recover(&bytes, ControlFlowLimits::default());
            let main = cfg.by_entry(0x1_0000_0100).unwrap();
            let table = main.jump_tables.first().expect("clamped table recovered");
            assert_eq!(table.encoding, JumpTableEncoding::RelativeSigned32);
            assert_eq!(table.entries.len(), 2);
            let range = table.range.expect("clamp range retained");
            assert_eq!(range.guard_kind, JumpTableRangeGuardKind::ClampToFirstEntry);
            assert_eq!(range.maximum_index, 1);
            assert_eq!(range.entry_count, 2);
            assert_eq!(range.default_target, Some(table.entries[0].target));
            assert_eq!(range.default_block, Some(table.entries[0].target_block));
            assert!(
                table
                    .reasons
                    .contains(&"jump_table.range_check_derived".into())
            );
        }
    }

    #[test]
    fn byte_and_block_budgets_truncate_without_false_completion() {
        let bytes = x86_branching_fixture();
        let byte_limited = recover(
            &bytes,
            ControlFlowLimits {
                max_decoded_bytes: 1,
                ..ControlFlowLimits::default()
            },
        );
        assert_eq!(byte_limited.status(), ControlFlowIndexStatus::Truncated);
        assert_eq!(
            byte_limited.functions()[0].completeness.status,
            FunctionControlFlowStatus::Truncated
        );
        assert!(
            byte_limited.functions()[0]
                .completeness
                .reasons
                .contains(&"control_flow.byte_budget".to_string())
        );
        assert_eq!(
            byte_limited.continuation(),
            Some(&ControlFlowContinuation::Byte {
                function_entry: 0x1_0000_0100,
                address: 0x1_0000_0100,
            })
        );
        let byte_limited_graph = &byte_limited.functions()[0];
        assert_ne!(byte_limited_graph.completeness.omitted_bytes, 0);
        assert_eq!(
            byte_limited_graph.completeness.observed_bytes,
            byte_limited_graph.completeness.instruction_bytes
                + byte_limited_graph.completeness.data_bytes
                + byte_limited_graph.completeness.gap_bytes
                + byte_limited_graph.completeness.omitted_bytes
        );
        assert!(byte_limited_graph.byte_ranges.iter().any(|range| {
            range.start == 0x1_0000_0100 && range.kind == ControlFlowByteRangeKind::Omitted
        }));

        let instruction_limited = recover(
            &bytes,
            ControlFlowLimits {
                max_instructions_per_function: 1,
                ..ControlFlowLimits::default()
            },
        );
        assert_eq!(
            instruction_limited.continuation(),
            Some(&ControlFlowContinuation::Instruction {
                function_entry: 0x1_0000_0100,
                address: 0x1_0000_0102,
            })
        );

        let block_limited = recover(
            &bytes,
            ControlFlowLimits {
                max_blocks_per_function: 1,
                ..ControlFlowLimits::default()
            },
        );
        let main = block_limited.by_entry(0x1_0000_0100).unwrap();
        assert_eq!(main.blocks.len(), 1);
        assert_eq!(
            main.completeness.status,
            FunctionControlFlowStatus::Truncated
        );
        assert!(
            main.blocks
                .iter()
                .skip(1)
                .all(|block| { block.reachability == ControlFlowReachability::Unknown })
        );
        assert_eq!(
            block_limited.continuation(),
            Some(&ControlFlowContinuation::Block {
                function_entry: 0x1_0000_0100,
                block: 1,
                start: 0x1_0000_0102,
            })
        );

        let edge_limited = recover(
            &bytes,
            ControlFlowLimits {
                max_edges_per_function: 1,
                ..ControlFlowLimits::default()
            },
        );
        let main = edge_limited.by_entry(0x1_0000_0100).unwrap();
        assert_eq!(
            main.completeness.status,
            FunctionControlFlowStatus::Truncated
        );
        assert!(
            main.blocks
                .iter()
                .any(|block| { block.reachability == ControlFlowReachability::Unknown })
        );
        assert_eq!(
            edge_limited.continuation(),
            Some(&ControlFlowContinuation::Edge {
                function_entry: 0x1_0000_0100,
                edge: ControlFlowEdge {
                    from: 0,
                    to: 1,
                    kind: ControlFlowEdgeKind::ConditionalNotTaken,
                },
            })
        );

        let function_limited = recover(
            &bytes,
            ControlFlowLimits {
                max_functions: 1,
                ..ControlFlowLimits::default()
            },
        );
        assert_eq!(
            function_limited.continuation(),
            Some(&ControlFlowContinuation::Function {
                entry: 0x1_0000_0120,
            })
        );
    }

    #[test]
    fn gap_budget_reports_the_first_unretained_gap_address() {
        let mut gaps = vec![ControlFlowGap {
            start: 0x100,
            end_exclusive: 0x101,
            kind: ControlFlowGapKind::InvalidInstruction,
            coverage_confidence: FunctionEvidenceConfidence::Exact,
        }];
        let mut truncated = false;
        let mut reasons = BTreeSet::new();
        let continuation = push_gap(
            &mut gaps,
            1,
            ControlFlowGap {
                start: 0x102,
                end_exclusive: 0x103,
                kind: ControlFlowGapKind::InvalidInstruction,
                coverage_confidence: FunctionEvidenceConfidence::Exact,
            },
            &mut truncated,
            &mut reasons,
        );

        assert_eq!(continuation, Some(0x102));
        assert!(truncated);
        assert!(reasons.contains("control_flow.gap_budget"));
    }

    #[test]
    fn clipped_or_invalid_tail_is_an_explicit_partial_graph() {
        let bytes = macho_test_support::disassembly_x86_64();
        let cfg = recover(&bytes, ControlFlowLimits::default());
        let helper = cfg.by_entry(0x1_0000_0104).unwrap();
        assert!(!helper.gaps.is_empty());
        assert_eq!(
            helper.completeness.status,
            FunctionControlFlowStatus::Partial
        );
        assert!(
            helper
                .completeness
                .reasons
                .contains(&"control_flow.decode_gap".to_string())
        );
    }

    #[test]
    fn function_index_is_bound_to_exact_image_bytes() {
        let first = x86_branching_fixture();
        let second = macho_test_support::disassembly_x86_64();
        let first_macho = image(&first);
        let second_macho = image(&second);
        let functions =
            FunctionIndex::recover(&first_macho, FunctionRecoveryLimits::default()).unwrap();
        let error =
            ControlFlowIndex::recover(&second_macho, &functions, ControlFlowLimits::default())
                .unwrap_err();
        assert_eq!(error, ControlFlowRecoveryError::ImageMismatch);
    }
}
