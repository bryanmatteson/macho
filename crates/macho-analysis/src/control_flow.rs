//! Bounded basic-block and intra-procedural control-flow recovery.
//!
//! Graphs are tied to an exact [`crate::functions::FunctionIndex`] image
//! identity. Candidate function bounds remain candidate graph coverage, decode
//! gaps remain explicit, and branches outside a recovered function are exits
//! rather than invented intra-procedural edges.

use std::collections::{BTreeMap, BTreeSet};

use macho_core::format::constants::{
    CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};
use macho_core::model::addr::Va;
use macho_core::model::macho_file::MachoFile;
use macho_insn::{Arch, BranchTarget, InsnKind, Operand, PcRelKind, Reg, RegClass, ValueEffect};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::functions::{
    FunctionEvidenceConfidence, FunctionIdentity, FunctionImageIdentity, FunctionIndex,
    FunctionLookup, FunctionOwnershipConfidence, RecoveredFunction,
};

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
    /// Written value has no safe decoded transfer model.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Why control flow leaves known intra-procedural blocks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlFlowExitKind {
    /// Function return.
    Return,
    /// Direct branch outside this recovered function.
    DirectBranch,
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

/// Completeness and work receipt for one function graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionControlFlowCompleteness {
    /// Overall graph state.
    pub status: FunctionControlFlowStatus,
    /// Weakest admitted range confidence.
    pub boundary_confidence: Option<FunctionEvidenceConfidence>,
    /// Bytes examined for this function.
    pub decoded_bytes: u64,
    /// Stable reason codes explaining non-completeness.
    pub reasons: Vec<String>,
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
    /// Basic blocks sorted by start address.
    pub blocks: Vec<BasicBlock>,
    /// Internal edges sorted by source, destination, and kind.
    pub edges: Vec<ControlFlowEdge>,
    /// Exits from retained intra-procedural coverage.
    pub exits: Vec<ControlFlowExit>,
    /// Callsites sorted by instruction address.
    pub calls: Vec<ControlFlowCallsite>,
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
}

impl ControlFlowIndex {
    /// Recover per-function basic blocks and intra-procedural edges.
    pub fn recover(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        limits: ControlFlowLimits,
    ) -> Result<Self, ControlFlowRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        if &image != functions.image() {
            return Err(ControlFlowRecoveryError::ImageMismatch);
        }
        let arch =
            instruction_arch(macho).ok_or(ControlFlowRecoveryError::UnsupportedArchitecture)?;
        let admitted = functions.functions().len().min(limits.max_functions);
        let mut remaining_bytes = limits.max_decoded_bytes;
        let mut graphs = Vec::with_capacity(admitted);
        let mut decoded_bytes = 0_u64;
        let mut globally_truncated = functions.functions().len() > admitted;
        for function in functions.functions().iter().take(admitted) {
            if remaining_bytes == 0 {
                globally_truncated = true;
                break;
            }
            let graph = recover_function(
                macho,
                functions,
                function,
                arch,
                limits,
                &mut remaining_bytes,
            );
            decoded_bytes = decoded_bytes.saturating_add(graph.completeness.decoded_bytes);
            globally_truncated |= graph.completeness.status == FunctionControlFlowStatus::Truncated;
            graphs.push(graph);
        }
        let truncated_function_count =
            functions.functions().len().saturating_sub(graphs.len()) as u64;
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

    /// Find the graph for one exact recovered function entry.
    pub fn by_entry(&self, entry: u64) -> Option<&FunctionControlFlow> {
        self.functions
            .binary_search_by_key(&entry, |graph| graph.function_entry)
            .ok()
            .map(|index| &self.functions[index])
    }
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
    let mut raw = Vec::new();
    if let Some(extent) = function.extent {
        raw.push(CoverageRange {
            start: extent.start,
            end: extent.end_exclusive,
            confidence: extent.confidence,
        });
    }
    for evidence in &function.evidence {
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

fn recover_function(
    macho: &MachoFile<'_>,
    function_index: &FunctionIndex,
    function: &RecoveredFunction,
    arch: Arch,
    limits: ControlFlowLimits,
    remaining_bytes: &mut usize,
) -> FunctionControlFlow {
    let coverage = function_coverage(function);
    let boundary_confidence = coverage.iter().map(|range| range.confidence).min();
    let mut instructions = Vec::new();
    let mut gaps = Vec::new();
    let mut reasons = BTreeSet::<String>::new();
    let mut decoded_bytes = 0_u64;
    let mut truncated = false;
    if coverage.is_empty() {
        reasons.insert("control_flow.no_extent".into());
    }
    if !function.conflicts.is_empty() {
        reasons.insert("control_flow.function_conflicts".into());
    }
    if !function.completeness.locally_complete {
        reasons.insert("control_flow.function_inventory_incomplete".into());
    }
    if boundary_confidence != Some(FunctionEvidenceConfidence::Exact) {
        reasons.insert("control_flow.uncertain_boundary".into());
    }
    for range in coverage {
        if *remaining_bytes == 0 {
            truncated = true;
            reasons.insert("control_flow.byte_budget".into());
            break;
        }
        if instructions.len() >= limits.max_instructions_per_function {
            truncated = true;
            reasons.insert("control_flow.instruction_budget".into());
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
                push_gap(
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
                );
                reasons.insert("control_flow.unmapped_range".into());
                continue;
            }
        };
        let mut offset = 0_usize;
        while offset < admitted_len {
            if instructions.len() >= limits.max_instructions_per_function {
                truncated = true;
                reasons.insert("control_flow.instruction_budget".into());
                break;
            }
            let address = range.start + offset as u64;
            match macho_insn::decode_one(&bytes[offset..], address, arch) {
                Ok(instruction) if offset.saturating_add(instruction.len) <= admitted_len => {
                    instructions.push(convert_instruction(instruction, address, range.confidence));
                    offset += instructions.last().expect("just pushed").byte_len as usize;
                }
                Ok(_) if clipped => {
                    truncated = true;
                    reasons.insert("control_flow.byte_budget".into());
                    break;
                }
                Ok(_) => {
                    let end = range.end;
                    push_gap(
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
                    );
                    reasons.insert("control_flow.partial_instruction_boundary".into());
                    offset = admitted_len;
                }
                Err(_) => {
                    let step = if arch.is_arm64() { 4 } else { 1 }.min(admitted_len - offset);
                    push_gap(
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
                    );
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
            break;
        }
        if truncated {
            break;
        }
    }
    instructions.sort_by_key(|instruction| instruction.address);
    instructions.dedup_by_key(|instruction| instruction.address);
    gaps.sort_by_key(|gap| (gap.start, gap.end_exclusive));

    let (mut blocks, block_truncated) = build_blocks(
        &instructions,
        function.entry,
        limits.max_blocks_per_function,
    );
    if block_truncated {
        truncated = true;
        reasons.insert("control_flow.block_budget".into());
    }
    let retained_instruction_count = blocks.last().map_or(0, |block| {
        (block.first_instruction + block.instruction_count) as usize
    });
    if retained_instruction_count < instructions.len() {
        instructions.truncate(retained_instruction_count);
    }
    let (edges, exits, calls, edge_truncated) = connect_blocks(
        &instructions,
        &blocks,
        function_index,
        limits.max_edges_per_function,
    );
    if edge_truncated {
        truncated = true;
        reasons.insert("control_flow.edge_budget".into());
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
        blocks,
        edges,
        exits,
        calls,
        completeness: FunctionControlFlowCompleteness {
            status,
            boundary_confidence,
            decoded_bytes,
            reasons: reasons.into_iter().collect(),
        },
    }
}

fn push_gap(
    gaps: &mut Vec<ControlFlowGap>,
    maximum: usize,
    gap: ControlFlowGap,
    truncated: &mut bool,
    reasons: &mut BTreeSet<String>,
) {
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
    }
}

fn convert_instruction(
    instruction: macho_insn::Insn,
    address: u64,
    confidence: FunctionEvidenceConfidence,
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
        ValueEffect::UnknownWrite => ControlFlowValueEffect::UnknownWrite,
        _ => ControlFlowValueEffect::UnknownWrite,
    };
    let writes_implicit_gpr0 = instruction.writes_implicit_gpr0;
    let pc_relative = match &instruction.kind {
        InsnKind::PcRelative(info) => Some(ControlFlowPcRelative {
            address: address.wrapping_add_signed(info.displacement),
            kind: match info.kind {
                PcRelKind::Address => ControlFlowPcRelativeKind::Address,
                PcRelKind::PageAddress => ControlFlowPcRelativeKind::PageAddress,
                PcRelKind::Memory => ControlFlowPcRelativeKind::Memory,
            },
        }),
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
        Operand::Imm(value) => Some(ControlFlowOperand::Immediate { value }),
        Operand::Mem { base, disp } => Some(ControlFlowOperand::Memory {
            base: convert_register(base)?,
            displacement: disp,
        }),
        _ => None,
    }
}

fn branch_target(instruction: &macho_insn::Insn, address: u64) -> Option<InstructionTarget> {
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
        _ => InstructionTarget::Indirect {
            target_kind: IndirectTargetKind::Unknown,
        },
    })
}

fn build_blocks(
    instructions: &[ControlFlowInstruction],
    function_entry: u64,
    maximum: usize,
) -> (Vec<BasicBlock>, bool) {
    if instructions.is_empty() {
        return (Vec::new(), false);
    }
    let addresses = instructions
        .iter()
        .enumerate()
        .map(|(index, instruction)| (instruction.address, index))
        .collect::<BTreeMap<_, _>>();
    let mut leaders = BTreeSet::new();
    if addresses.contains_key(&function_entry) {
        leaders.insert(function_entry);
    }
    leaders.insert(instructions[0].address);
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
            && addresses.contains_key(&address)
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
    let truncated = ranges.len() > maximum;
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
    (blocks, truncated)
}

fn connect_blocks(
    instructions: &[ControlFlowInstruction],
    blocks: &[BasicBlock],
    functions: &FunctionIndex,
    maximum_edges: usize,
) -> (
    Vec<ControlFlowEdge>,
    Vec<ControlFlowExit>,
    Vec<ControlFlowCallsite>,
    bool,
) {
    let block_by_start = blocks
        .iter()
        .map(|block| (block.start, block.id))
        .collect::<BTreeMap<_, _>>();
    let mut edges = Vec::new();
    let mut exits = Vec::new();
    let mut calls = Vec::new();
    let mut truncated = false;
    for block in blocks {
        let start = block.first_instruction as usize;
        let end = start + block.instruction_count as usize;
        for instruction in &instructions[start..end] {
            if instruction.kind == ControlFlowInstructionKind::Call
                && let Some(target) = instruction.target.as_ref()
            {
                calls.push(ControlFlowCallsite {
                    block: block.id,
                    instruction_address: instruction.address,
                    target: call_target(target, functions),
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
                    if let Some(&to) = block_by_start.get(address) {
                        push_edge(
                            &mut edges,
                            maximum_edges,
                            ControlFlowEdge {
                                from: block.id,
                                to,
                                kind: ControlFlowEdgeKind::Branch,
                            },
                            &mut truncated,
                        );
                    } else {
                        exits.push(direct_exit(block.id, last.address, *address, functions));
                    }
                }
                _ => exits.push(ControlFlowExit {
                    block: block.id,
                    instruction_address: Some(last.address),
                    kind: ControlFlowExitKind::IndirectBranch,
                    target: None,
                    recovered_function: None,
                    possible_functions: Vec::new(),
                }),
            },
            ControlFlowInstructionKind::ConditionalBranch => {
                if let Some(InstructionTarget::Direct { address }) = last.target.as_ref() {
                    if let Some(&to) = block_by_start.get(address) {
                        push_edge(
                            &mut edges,
                            maximum_edges,
                            ControlFlowEdge {
                                from: block.id,
                                to,
                                kind: ControlFlowEdgeKind::ConditionalTaken,
                            },
                            &mut truncated,
                        );
                    } else {
                        exits.push(direct_exit(block.id, last.address, *address, functions));
                    }
                }
                push_fallthrough(
                    block,
                    last.address,
                    fallthrough,
                    ControlFlowEdgeKind::ConditionalNotTaken,
                    &block_by_start,
                    &mut edges,
                    &mut exits,
                    maximum_edges,
                    &mut truncated,
                );
            }
            ControlFlowInstructionKind::Call => push_fallthrough(
                block,
                last.address,
                fallthrough,
                ControlFlowEdgeKind::CallReturn,
                &block_by_start,
                &mut edges,
                &mut exits,
                maximum_edges,
                &mut truncated,
            ),
            _ if block.termination == BasicBlockTermination::Fallthrough => push_fallthrough(
                block,
                last.address,
                fallthrough,
                ControlFlowEdgeKind::Fallthrough,
                &block_by_start,
                &mut edges,
                &mut exits,
                maximum_edges,
                &mut truncated,
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
    (edges, exits, calls, truncated)
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
    block_by_start: &BTreeMap<u64, u64>,
    edges: &mut Vec<ControlFlowEdge>,
    exits: &mut Vec<ControlFlowExit>,
    maximum_edges: usize,
    truncated: &mut bool,
) {
    if let Some(&to) = block_by_start.get(&target) {
        push_edge(
            edges,
            maximum_edges,
            ControlFlowEdge {
                from: block.id,
                to,
                kind,
            },
            truncated,
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
    truncated: &mut bool,
) {
    if edges.len() < maximum {
        edges.push(edge);
    } else {
        *truncated = true;
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
    let mut successors = BTreeMap::<u64, Vec<u64>>::new();
    for edge in edges {
        successors.entry(edge.from).or_default().push(edge.to);
    }
    let mut work = vec![entry_id];
    let mut reached = BTreeSet::new();
    while let Some(block) = work.pop() {
        if !reached.insert(block) {
            continue;
        }
        if let Some(next) = successors.get(&block) {
            work.extend(next.iter().copied());
        }
    }
    for block in blocks {
        block.reachability = if reached.contains(&block.id) {
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
                } else {
                    FunctionTargetRelation::ContainingExtent
                },
                entry_confidence: function.entry_confidence,
                ownership_confidence,
            },
        );
    };
    match functions.containing(address) {
        FunctionLookup::None => {}
        FunctionLookup::One(owner) => add_owner(owner.function.entry, owner.confidence),
        FunctionLookup::Ambiguous(owners) => {
            for owner in owners {
                add_owner(owner.function.entry, owner.confidence);
            }
        }
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
    use crate::functions::FunctionRecoveryLimits;

    fn image(bytes: &[u8]) -> macho_core::MachoFile<'_> {
        match macho_core::parse(bytes).expect("fixture parses") {
            macho_core::model::container::MachoContainer::Thin(macho) => macho,
            macho_core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
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

    fn recover(bytes: &[u8], limits: ControlFlowLimits) -> ControlFlowIndex {
        let macho = image(bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        ControlFlowIndex::recover(&macho, &functions, limits).unwrap()
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
