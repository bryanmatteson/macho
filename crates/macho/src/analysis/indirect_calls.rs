//! Evidence-bearing recovery of indirect calls, branches, import stubs, and
//! dynamic-dispatch candidates.
//!
//! Every retained indirect instruction remains in the inventory even when no
//! target can be resolved. Static pointer, fixup, vtable, Objective-C, Swift,
//! and authenticated-pointer evidence is additive rather than exclusive.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::Arc;

use crate::core::format::constants::{
    CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};
use crate::core::format::relocations_for_section;
use crate::core::model::addr::Va;
use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::relocation::Relocation;
use crate::core::model::symbol::SymbolTable;
use crate::metadata::cpp::vtable::{SlotTarget, VtableIndex};
use crate::metadata::demangle::swift_evidence::{
    SwiftClosureSymbolKind, classify_swift_closure_symbol,
};
use crate::metadata::dyld::{FixupKind, parse_bind_entries, parse_chained_fixups};
use crate::metadata::symbols::{
    IndirectBindingKind, IndirectBindingsOutcome, IndirectSymbolTarget, decode_indirect_bindings,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::control_flow::{
    ControlFlowCallTarget, ControlFlowIndex, ControlFlowIndexStatus, ControlFlowInstruction,
    ControlFlowInstructionKind, ControlFlowMemoryEffect, ControlFlowOperand,
    ControlFlowPcRelativeKind, ControlFlowReachability, ControlFlowRegister,
    ControlFlowRegisterClass, ControlFlowRegisterShift, ControlFlowValueEffect,
    FunctionControlFlow, FunctionControlFlowStatus,
};
use crate::analysis::functions::{
    FunctionEvidenceConfidence, FunctionIdentity, FunctionImageIdentity, FunctionIndex,
    FunctionOwnershipConfidence,
};
use crate::analysis::objc_index::ObjcIndex;
use crate::analysis::pointer_index::{PointerIndex, PointerRecordKind};
use crate::analysis::rtti::RttiIndex;
use crate::analysis::swift_index::SwiftIndex;

/// Explicit limits for one indirect-transfer recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectCallRecoveryLimits {
    /// Maximum function CFGs examined.
    pub max_functions: usize,
    /// Maximum indirect or import-stub transfer records retained.
    pub max_transfers: usize,
    /// Maximum indirect-symbol bindings retained.
    pub max_indirect_bindings: u64,
    /// Maximum chained-fixup records retained in the pointer catalog.
    pub max_chained_fixups: usize,
    /// Maximum legacy bind records retained in the pointer catalog.
    pub max_legacy_binds: usize,
    /// Maximum relocation records retained in the pointer catalog.
    pub max_relocations: usize,
    /// Maximum C++ vtable identities decoded.
    pub max_cpp_vtables: usize,
    /// Maximum Objective-C method implementations retained for dispatch.
    pub max_objc_methods: usize,
    /// Maximum Swift dispatch records retained.
    pub max_swift_dispatch_records: usize,
    /// Maximum candidate targets retained on any transfer.
    pub max_candidates_per_transfer: usize,
    /// Maximum distinct abstract values retained per register at a merge.
    pub max_values_per_register: usize,
    /// Maximum loop-carried values retained per register before widening the
    /// register to unknown.
    pub max_loop_values_per_register: usize,
    /// Maximum aggregate value-flow work units across all function CFGs.
    ///
    /// A unit is charged for each block visit, instruction evaluation,
    /// successor propagation, cloned abstract value, and merged abstract
    /// value. Exhaustion truncates value flow deterministically while leaving
    /// indirect transfer sites in the inventory as unresolved evidence.
    pub max_value_flow_work: u64,
    /// Maximum value-flow work units consumed by any one function under the global ceiling.
    pub max_value_flow_work_per_function: u64,
}

impl Default for IndirectCallRecoveryLimits {
    fn default() -> Self {
        Self {
            max_functions: 1_000_000,
            max_transfers: 16_000_000,
            max_indirect_bindings: 8_000_000,
            max_chained_fixups: 8_000_000,
            max_legacy_binds: 8_000_000,
            max_relocations: 8_000_000,
            max_cpp_vtables: 1_000_000,
            max_objc_methods: 8_000_000,
            max_swift_dispatch_records: 8_000_000,
            max_candidates_per_transfer: 1_000_000,
            max_values_per_register: 4_096,
            max_loop_values_per_register: 64,
            max_value_flow_work: 8_000_000,
            max_value_flow_work_per_function: 2_000_000,
        }
    }
}

impl IndirectCallRecoveryLimits {
    /// Reject zero-valued caller limits.
    pub fn validate(self) -> Result<Self, IndirectCallRecoveryError> {
        if self.max_functions == 0
            || self.max_transfers == 0
            || self.max_indirect_bindings == 0
            || self.max_chained_fixups == 0
            || self.max_legacy_binds == 0
            || self.max_relocations == 0
            || self.max_cpp_vtables == 0
            || self.max_objc_methods == 0
            || self.max_swift_dispatch_records == 0
            || self.max_candidates_per_transfer == 0
            || self.max_values_per_register == 0
            || self.max_loop_values_per_register == 0
            || self.max_value_flow_work == 0
            || self.max_value_flow_work_per_function == 0
        {
            return Err(IndirectCallRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing indirect recovery from starting.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum IndirectCallRecoveryError {
    /// At least one explicit limit is zero.
    #[error("indirect-call recovery limits must be non-zero")]
    InvalidLimits,
    /// Source indexes and image do not describe identical bytes.
    #[error("function, control-flow, and Mach-O image identities differ")]
    ImageMismatch,
    /// The image CPU has no supported indirect-value-flow model.
    #[error("indirect-call recovery does not support this CPU tuple")]
    UnsupportedArchitecture,
}

/// Static or dynamic evidence source supporting an indirect target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectCallEvidenceSource {
    /// Indirect-symbol table stub or pointer entry.
    IndirectSymbols,
    /// Legacy dyld bind opcode.
    LegacyBind,
    /// Legacy dyld rebase opcode.
    LegacyRebase,
    /// Chained bind or rebase.
    ChainedFixup,
    /// Mach-O section relocation.
    Relocation,
    /// Raw pointer bytes without relocation metadata.
    RawPointer,
    /// Address materialized by instructions.
    InstructionValueFlow,
    /// Function address assigned to a non-escaping global slot by recovered code.
    GlobalStoreSummary,
    /// Bounded candidate recovered from a CFG jump table.
    JumpTable,
    /// C++ vtable slot.
    CppVtable,
    /// Objective-C selector/method dispatch.
    ObjectiveC,
    /// Swift class vtable, override, or protocol dispatch record.
    Swift,
    /// Clang block/closure literal recovered from ABI metadata.
    BlockClosure,
}

/// Kind of recovered transfer site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectTransferKind {
    /// Register- or memory-indirect call instruction.
    Call,
    /// Register- or memory-indirect branch instruction.
    Branch,
    /// Direct call to a symbol stub whose destination is imported.
    ImportStubCall,
    /// Call through an Objective-C messaging gateway.
    ObjectiveCDispatch,
    /// Call through an RTTI-qualified C++ vtable slot.
    CppVirtualDispatch,
    /// Call through Swift class or protocol dispatch metadata.
    SwiftDispatch,
    /// Call through a Clang block literal invoke field.
    BlockInvoke,
    /// Call to a Swift closure body or closure-adapter thunk.
    SwiftClosureDispatch,
}

/// Decoded carrier of an indirect target.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IndirectTargetCarrier {
    /// Target value held in a register.
    Register {
        /// Register carrying the destination value.
        register: ControlFlowRegister,
    },
    /// Target loaded from a statically recovered pointer slot.
    PointerSlot {
        /// Virtual address of the pointer slot.
        address: u64,
    },
    /// Memory operand with no recovered base value.
    DynamicMemory {
        /// Base register when one was decoded.
        base: Option<ControlFlowRegister>,
        /// Signed byte displacement from the base.
        displacement: i64,
    },
    /// Direct call to a statically bound import stub.
    ImportStub {
        /// Virtual address of the symbol stub.
        address: u64,
    },
    /// Bounded jump table consumed by the transfer.
    JumpTable {
        /// First table byte.
        address: u64,
    },
    /// Pointer field selected from a statically bounded strided record table.
    StridedPointerTable {
        /// First pointer field.
        address: u64,
        /// Distance in bytes between pointer fields.
        stride: u64,
        /// Number of records proven by the loop guard.
        entry_count: u64,
    },
    /// Decoder retained no more specific carrier.
    Unknown,
}

/// Authentication evidence associated with an indirect target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct PointerAuthentication {
    /// Pointer-authentication key encoding when supplied by a chained fixup.
    pub key: Option<u8>,
    /// Diversity value when supplied by a chained fixup.
    pub diversity: Option<u16>,
    /// Whether the pointer address participates in authentication.
    pub address_diversity: Option<bool>,
    /// Pointer-authentication key selected by the controlling instruction
    /// (`0` for A, `1` for B), when decoded.
    pub instruction_key: Option<u8>,
    /// Explicit instruction modifier register, when present.
    pub instruction_modifier: Option<ControlFlowRegister>,
    /// Whether the instruction uses the implicit zero modifier form.
    pub instruction_zero_modifier: Option<bool>,
    /// Whether the controlling ARM64e instruction is authenticated.
    pub authenticated_instruction: bool,
}

/// One recovered possible destination.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum IndirectCallTarget {
    /// Imported symbol destination.
    Import {
        /// Imported symbol name.
        name: String,
        /// Dyld library ordinal when encoded by the source.
        library_ordinal: Option<i32>,
    },
    /// In-image address and every possible recovered function owner.
    Internal {
        /// Recovered destination address.
        address: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
    },
    /// Objective-C method implementation selected by runtime dispatch.
    ObjectiveCMethod {
        /// Declaring class name.
        class_name: String,
        /// Objective-C selector.
        selector: String,
        /// Whether this is a class rather than instance method.
        class_method: bool,
        /// Method implementation address.
        implementation: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
    },
    /// Swift dispatch implementation.
    SwiftImplementation {
        /// Dispatch slot number when known.
        slot: Option<u32>,
        /// Implementation address.
        implementation: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
        /// Stable metadata-record description.
        detail: String,
    },
    /// C++ virtual method whose vtable and RTTI identities agree.
    CppVirtualMethod {
        /// Vtable group start.
        vtable: u64,
        /// Address point used by the dispatch.
        address_point: u64,
        /// Zero-based function-slot ordinal.
        slot: u64,
        /// Exact encoded RTTI type name.
        type_name: String,
        /// Method or adjustment-thunk address.
        implementation: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
    },
    /// Imported C++ virtual method whose vtable and RTTI identities agree.
    CppVirtualMethodImport {
        /// Vtable group start.
        vtable: u64,
        /// Address point used by the dispatch.
        address_point: u64,
        /// Zero-based function-slot ordinal.
        slot: u64,
        /// Exact encoded RTTI type name.
        type_name: String,
        /// Imported method or adjustment-thunk symbol.
        symbol: String,
        /// Dyld library ordinal when encoded.
        library_ordinal: Option<i32>,
    },
    /// Swift protocol-witness implementation tied to one conformance pattern.
    SwiftProtocolWitness {
        /// Witness-table pattern address.
        witness_table: u64,
        /// Zero-based protocol requirement index.
        requirement: u32,
        /// Protocol name when decoded.
        protocol: Option<String>,
        /// Conforming type name when decoded.
        conforming_type: Option<String>,
        /// Whether runtime generic instantiation may replace this pattern entry.
        runtime_instantiated: bool,
        /// Witness implementation address.
        implementation: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
    },
    /// Imported Swift protocol-witness implementation tied to one conformance pattern.
    SwiftProtocolWitnessImport {
        /// Witness-table pattern address.
        witness_table: u64,
        /// Zero-based protocol requirement index.
        requirement: u32,
        /// Protocol name when decoded.
        protocol: Option<String>,
        /// Conforming type name when decoded.
        conforming_type: Option<String>,
        /// Whether runtime generic instantiation may replace this pattern entry.
        runtime_instantiated: bool,
        /// Imported witness symbol.
        symbol: String,
        /// Dyld library ordinal when encoded.
        library_ordinal: Option<i32>,
    },
    /// Native Swift closure body or closure-adapter trampoline identified by
    /// exact mangling metadata.
    SwiftClosure {
        /// Physical closure-entry or adapter role.
        role: SwiftClosureRole,
        /// Exact linkage name carrying the role.
        symbol: String,
        /// Process-free demangled spelling.
        display: String,
        /// Closure or trampoline implementation address.
        implementation: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
    },
    /// Invoke entry stored in a Clang block literal.
    BlockInvoke {
        /// Static, stack, or heap identity of the block literal.
        literal: BlockLiteralLocation,
        /// Block descriptor address when materialized.
        descriptor: Option<u64>,
        /// Runtime storage class encoded by the literal's isa pointer.
        storage: BlockStorageKind,
        /// Invoke implementation address.
        implementation: u64,
        /// Every possible recovered function owner.
        functions: Vec<IndirectFunctionCandidate>,
    },
    /// Imported invoke entry stored in a Clang block literal.
    BlockInvokeImport {
        /// Static, stack, or heap identity of the block literal.
        literal: BlockLiteralLocation,
        /// Block descriptor address when materialized.
        descriptor: Option<u64>,
        /// Runtime storage class encoded by the literal's isa pointer.
        storage: BlockStorageKind,
        /// Imported invoke symbol.
        symbol: String,
        /// Dyld library ordinal when encoded.
        library_ordinal: Option<i32>,
    },
}

/// Physical native-Swift closure role carried by a linkage name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftClosureRole {
    /// Body entry for an explicit or implicit closure.
    ClosureEntry,
    /// Reabstraction thunk adapting closure representations.
    ReabstractionThunk,
    /// Partial-apply forwarder for a native Swift context.
    PartialApplyForwarder,
    /// Partial-apply forwarder bridging an Objective-C block context.
    PartialApplyObjcForwarder,
}

/// Runtime storage class of a metadata-backed Clang block literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockStorageKind {
    /// `_NSConcreteGlobalBlock`.
    Global,
    /// `_NSConcreteStackBlock`.
    Stack,
    /// `_NSConcreteMallocBlock`.
    Malloc,
    /// Another `_NSConcrete*Block` runtime class.
    Unknown,
}

/// Stable identity of a recovered Clang block literal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum BlockLiteralLocation {
    /// Literal materialized at a static virtual address.
    Static {
        /// Literal virtual address.
        address: u64,
    },
    /// Literal materialized in one function's stack frame.
    Stack {
        /// Owning function entry.
        function: u64,
        /// Signed frame-relative base offset.
        offset: i64,
    },
    /// Literal materialized in an abstract heap allocation.
    Heap {
        /// Callsite or other stable allocation identity.
        allocation: u64,
        /// Signed allocation-relative base offset.
        offset: i64,
    },
}

/// One possible function owner of an internal target address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct IndirectFunctionCandidate {
    /// Recovered function entry.
    pub entry: u64,
    /// Entry confidence.
    pub entry_confidence: FunctionEvidenceConfidence,
    /// Address ownership confidence.
    pub ownership_confidence: FunctionOwnershipConfidence,
}

/// Evidence supporting one possible destination.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectCallCandidate {
    /// Possible destination.
    pub target: IndirectCallTarget,
    /// Evidence source.
    pub source: IndirectCallEvidenceSource,
    /// Exact, derived, or candidate interpretation strength.
    pub confidence: FunctionEvidenceConfidence,
    /// Static pointer/stub/metadata address supporting this target.
    pub evidence_address: Option<u64>,
    /// Pointer-authentication evidence.
    pub authentication: Option<PointerAuthentication>,
    /// Stable source-specific detail.
    pub detail: String,
}

/// Local completion state for one indirect transfer site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectCallSiteStatus {
    /// Retained local evidence resolves without uncertainty or omission.
    Complete,
    /// Local evidence is unresolved, candidate-only, conflicting, or rests on
    /// incomplete control flow.
    Partial,
    /// A local candidate or value-flow budget omitted evidence.
    Truncated,
}

/// One contradictory interpretation at the same static evidence address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectCallConflict {
    /// Pointer, stub, or metadata address with contradictory interpretations.
    pub evidence_address: u64,
    /// Distinct contradictory destinations in deterministic order.
    pub targets: Vec<IndirectCallTarget>,
    /// Evidence sources participating in the disagreement.
    pub sources: Vec<IndirectCallEvidenceSource>,
}

/// One recovered indirect or dynamic-dispatch transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredIndirectCall {
    /// Source function entry.
    pub source_function: u64,
    /// Source-local block identifier.
    pub block: u64,
    /// Controlling instruction address.
    pub instruction_address: u64,
    /// Call, branch, stub, or Objective-C dispatch classification.
    pub kinds: Vec<IndirectTransferKind>,
    /// Register, pointer slot, dynamic memory, or stub carrier.
    pub carriers: Vec<IndirectTargetCarrier>,
    /// Source block reachability.
    pub reachability: ControlFlowReachability,
    /// Every retained possible destination.
    pub candidates: Vec<IndirectCallCandidate>,
    /// Contradictory source interpretations retained before candidate
    /// truncation.
    pub conflicts: Vec<IndirectCallConflict>,
    /// Candidate count omitted by the per-transfer budget.
    pub omitted_candidate_count: u64,
    /// Whether this function's abstract value flow exceeded its merge budget.
    pub value_flow_truncated: bool,
    /// Whether a loop-carried register was widened to unknown.
    #[serde(default)]
    pub value_flow_widened: bool,
    /// Local completion state.
    pub status: IndirectCallSiteStatus,
    /// Stable reason codes for unresolved or incomplete evidence.
    pub reasons: Vec<String>,
}

/// Collector completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectCollectorStatus {
    /// Source was absent.
    Absent,
    /// Source completed.
    Complete,
    /// Explicit limits omitted records.
    Truncated,
    /// Source was present but malformed or rejected.
    Failed,
}

/// Work and retention receipt for one evidence source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectCollectorReceipt {
    /// Evidence source.
    pub source: IndirectCallEvidenceSource,
    /// Collector state.
    pub status: IndirectCollectorStatus,
    /// Records examined or reported available.
    pub examined: u64,
    /// Records retained in the static evidence catalog.
    pub retained: u64,
    /// Stable diagnostic code.
    pub diagnostic: Option<String>,
}

/// Global completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IndirectCallIndexStatus {
    /// All supported evidence and transfer records completed.
    Complete,
    /// Evidence completed but some targets remain unresolved or candidate-only.
    Partial,
    /// An explicit source or output budget omitted evidence.
    Truncated,
}

/// Global completeness and work receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndirectCallCompleteness {
    /// Overall state.
    pub status: IndirectCallIndexStatus,
    /// Stable reasons for partiality or truncation.
    pub reasons: Vec<String>,
    /// Function CFGs examined.
    pub examined_function_count: u64,
    /// Function CFGs omitted by limits.
    pub omitted_function_count: u64,
    /// Transfer sites observed.
    pub observed_transfer_count: u64,
    /// Transfer sites omitted by output limits.
    pub omitted_transfer_count: u64,
    /// Candidate destinations omitted by per-transfer limits.
    pub omitted_candidate_count: u64,
    /// Whether abstract value merging exceeded its explicit bound.
    pub value_flow_truncated: bool,
    /// Whether loop-carried values exceeded the explicit widening bound.
    #[serde(default)]
    pub value_flow_widened: bool,
    /// Aggregate deterministic value-flow work units consumed.
    pub value_flow_work: u64,
    /// First function whose value flow could not finish under a selected budget.
    pub value_flow_continuation_function: Option<u64>,
}

/// One abstract return fact retained by an interprocedural ABI summary.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AbiReturnValue {
    /// The return value is copied from one ABI argument.
    Argument {
        /// Zero-based ABI argument ordinal.
        ordinal: u8,
        /// Pointer-authentication state applied by the callee, when established.
        authentication: Option<PointerAuthentication>,
    },
    /// Exact in-image address returned by the callee.
    InternalAddress {
        /// Returned virtual address.
        address: u64,
        /// Pointer-authentication state applied by the callee, when established.
        authentication: Option<PointerAuthentication>,
    },
    /// Exact pointer slot whose loaded value is returned.
    PointerSlot {
        /// Pointer-slot virtual address.
        address: u64,
        /// Pointer-authentication state applied by the callee, when established.
        authentication: Option<PointerAuthentication>,
    },
}

/// Locally complete return-value summary for one recovered function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionAbiSummary {
    /// Recovered function entry.
    pub function_entry: u64,
    /// Reachable return instructions establishing the summary.
    pub return_instructions: Vec<u64>,
    /// Deterministically ordered possible return facts.
    pub values: Vec<AbiReturnValue>,
}

/// Deterministic indirect-call and branch inventory tied to one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IndirectCallIndex {
    image: FunctionImageIdentity,
    limits: IndirectCallRecoveryLimits,
    calls: Vec<RecoveredIndirectCall>,
    abi_summaries: Vec<FunctionAbiSummary>,
    receipts: Vec<IndirectCollectorReceipt>,
    completeness: IndirectCallCompleteness,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum StaticTarget {
    Import { name: String, ordinal: Option<i32> },
    Internal(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StaticEvidence {
    source: IndirectCallEvidenceSource,
    target: StaticTarget,
    confidence: FunctionEvidenceConfidence,
    authentication: Option<PointerAuthentication>,
    detail: String,
}

#[derive(Default)]
struct Catalog {
    slots: BTreeMap<u64, Vec<StaticEvidence>>,
    cpp_offsets: BTreeMap<i64, Vec<StaticEvidence>>,
    swift_offsets: BTreeMap<i64, Vec<SwiftDispatch>>,
    swift_unindexed: Vec<SwiftDispatch>,
    cpp_slots: BTreeMap<u64, Vec<CppDispatch>>,
    cpp_offsets_agreed: BTreeMap<i64, Vec<CppDispatch>>,
    swift_witness_slots: BTreeMap<u64, Vec<SwiftWitnessDispatch>>,
    swift_witness_offsets: BTreeMap<i64, Vec<SwiftWitnessDispatch>>,
    block_invoke_slots: BTreeMap<u64, Vec<BlockDispatch>>,
    block_offsets: BTreeMap<i64, Vec<BlockDispatch>>,
    objc_methods: Vec<ObjcDispatch>,
    objc_class_addresses: BTreeMap<u64, String>,
    objc_metaclass_addresses: BTreeMap<u64, String>,
    objc_superclasses: BTreeMap<String, Option<String>>,
    objc_protocol_adopters: BTreeMap<String, BTreeSet<String>>,
    objc_protocol_arguments: BTreeMap<(u64, u8), BTreeSet<String>>,
    allocator_stubs: BTreeSet<u64>,
    receipts: Vec<IndirectCollectorReceipt>,
    truncated: bool,
    failed: bool,
}

#[derive(Debug, Clone)]
struct ObjcDispatch {
    class_name: String,
    selector: String,
    class_method: bool,
    implementation: u64,
}

#[derive(Debug, Clone)]
struct SwiftDispatch {
    slot: Option<u32>,
    implementation: u64,
    authentication: Option<PointerAuthentication>,
    runtime_instantiated: bool,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CppDispatch {
    vtable: u64,
    address_point: u64,
    slot: u64,
    type_name: String,
    implementation: StaticTarget,
    confidence: FunctionEvidenceConfidence,
    authentication: Option<PointerAuthentication>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct SwiftWitnessDispatch {
    witness_table: u64,
    requirement: u32,
    protocol: Option<String>,
    conforming_type: Option<String>,
    runtime_instantiated: bool,
    implementation: StaticTarget,
    authentication: Option<PointerAuthentication>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BlockDispatch {
    literal: BlockLiteralLocation,
    descriptor: Option<u64>,
    storage: BlockStorageKind,
    implementation: StaticTarget,
    authentication: Option<PointerAuthentication>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractValueKind {
    Address(u64),
    PointerSlot(u64),
    DynamicSlot(i64),
    StackAddress(i64),
    Argument(u8),
    ProtocolArgument { function: u64, ordinal: u8 },
    HeapAddress { allocation: u64, offset: i64 },
}

#[derive(Debug, Clone, Copy)]
struct AbstractValue {
    kind: AbstractValueKind,
    authentication: Option<PointerAuthentication>,
    instruction: u64,
}

impl PartialEq for AbstractValue {
    fn eq(&self, other: &Self) -> bool {
        (self.kind, self.authentication) == (other.kind, other.authentication)
    }
}

impl Eq for AbstractValue {}

impl PartialOrd for AbstractValue {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AbstractValue {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.kind, self.authentication).cmp(&(other.kind, other.authentication))
    }
}

type RegisterValues = BTreeMap<ControlFlowRegister, Arc<BTreeSet<AbstractValue>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractMemoryLocation {
    Stack(i64),
    Global(u64),
    Heap {
        allocation: u64,
        offset: i64,
    },
    IndexedAlias {
        base: AbstractMemoryBase,
        displacement: i64,
        scale: u8,
    },
}

type MemoryValues = BTreeMap<AbstractMemoryLocation, Arc<BTreeSet<AbstractValue>>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractMemoryBase {
    Stack(i64),
    Global(u64),
    Heap { allocation: u64, offset: i64 },
}

#[derive(Default)]
struct AbiSummaries {
    returns: BTreeMap<u64, BTreeSet<AbstractValue>>,
    protocol_arguments: BTreeMap<(u64, u8), BTreeSet<String>>,
    allocator_stubs: BTreeSet<u64>,
    enable_allocators: bool,
}

impl AbiSummaries {
    #[cfg(test)]
    fn new() -> Self {
        Self::default()
    }

    fn from_catalog(catalog: &Catalog) -> Self {
        Self {
            returns: BTreeMap::new(),
            protocol_arguments: catalog.objc_protocol_arguments.clone(),
            allocator_stubs: catalog.allocator_stubs.clone(),
            enable_allocators: true,
        }
    }

    fn get(&self, entry: &u64) -> Option<&BTreeSet<AbstractValue>> {
        self.returns.get(entry)
    }

    fn insert(&mut self, entry: u64, values: BTreeSet<AbstractValue>) {
        self.returns.insert(entry, values);
    }

    fn iter(&self) -> impl Iterator<Item = (&u64, &BTreeSet<AbstractValue>)> {
        self.returns.iter()
    }
}

/// Predecoded static evidence borrowed by indirect-transfer recovery.
#[derive(Debug, Clone, Copy)]
pub struct IndirectCallRecoveryInputs<'index> {
    /// Format pointers, fixups, relocations, and pointer authentication.
    pub pointers: &'index PointerIndex,
    /// Itanium RTTI and vtable slots.
    pub rtti: &'index RttiIndex,
    /// Objective-C method implementations.
    pub objc: &'index ObjcIndex,
    /// Swift dispatch metadata.
    pub swift: &'index SwiftIndex,
}

impl IndirectCallIndex {
    /// Recover indirect calls, branches, import stubs, and dynamic dispatch.
    pub fn recover(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: IndirectCallRecoveryLimits,
    ) -> Result<Self, IndirectCallRecoveryError> {
        let catalog = Catalog::collect(macho, limits);
        Self::recover_with_catalog(macho, functions, control_flow, limits, catalog)
    }

    /// Recover indirect transfers while reusing selected static evidence indexes.
    pub fn recover_with_evidence(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        inputs: IndirectCallRecoveryInputs<'_>,
        limits: IndirectCallRecoveryLimits,
    ) -> Result<Self, IndirectCallRecoveryError> {
        let image = FunctionImageIdentity::from_macho(macho);
        if inputs.pointers.image() != &image
            || inputs.rtti.image() != &image
            || inputs.objc.image() != &image
            || inputs.swift.image() != &image
        {
            return Err(IndirectCallRecoveryError::ImageMismatch);
        }
        let catalog = Catalog::collect_indexes(
            macho,
            inputs.pointers,
            inputs.rtti,
            inputs.objc,
            inputs.swift,
            limits,
        );
        Self::recover_with_catalog(macho, functions, control_flow, limits, catalog)
    }

    fn recover_with_catalog(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: IndirectCallRecoveryLimits,
        mut catalog: Catalog,
    ) -> Result<Self, IndirectCallRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        if &image != functions.image() || &image != control_flow.image() {
            return Err(IndirectCallRecoveryError::ImageMismatch);
        }
        let architecture = Architecture::from_macho(macho)
            .ok_or(IndirectCallRecoveryError::UnsupportedArchitecture)?;
        let admitted = control_flow.functions().len().min(limits.max_functions);
        let omitted_function_count = control_flow.functions().len().saturating_sub(admitted) as u64;
        let mut reasons = BTreeSet::<String>::new();
        if omitted_function_count != 0 {
            reasons.insert("indirect.function_budget".into());
        }
        if !functions.inventory_complete() {
            reasons.insert("indirect.function_inventory_incomplete".into());
        }
        match control_flow.status() {
            ControlFlowIndexStatus::Complete => {}
            ControlFlowIndexStatus::Partial => {
                reasons.insert("indirect.control_flow_partial".into());
            }
            ControlFlowIndexStatus::Truncated => {
                reasons.insert("indirect.control_flow_truncated".into());
            }
        }

        let mut calls = Vec::new();
        let mut observed_transfer_count = 0_u64;
        let mut omitted_transfer_count = 0_u64;
        let mut omitted_candidate_count = 0_u64;
        let mut value_flow_truncated = false;
        let mut value_flow_widened = false;
        let mut value_flow_budget = ValueFlowWorkBudget::new(limits.max_value_flow_work);
        let (abi_summaries, summary_truncated, summary_widened, summary_continuation) =
            recover_abi_summaries(
                control_flow,
                architecture,
                limits.max_values_per_register,
                limits.max_loop_values_per_register,
                limits.max_value_flow_work_per_function,
                &catalog,
                &mut value_flow_budget,
            );
        let abi_summary_records = public_abi_summaries(control_flow, &abi_summaries);
        value_flow_truncated |= summary_truncated;
        value_flow_widened |= summary_widened;
        let mut value_flow_continuation_function = summary_continuation;
        let global_dispatch_slots = global_dispatch_slots(control_flow, admitted, architecture);
        if !global_dispatch_slots.is_empty() {
            let global_stores = recover_global_store_summaries(
                functions,
                control_flow,
                admitted,
                &global_dispatch_slots,
                architecture,
                limits.max_values_per_register,
                limits.max_loop_values_per_register,
                limits.max_value_flow_work_per_function,
                &abi_summaries,
                &mut value_flow_budget,
            );
            for (slot, evidence) in global_stores.evidence {
                catalog.slots.entry(slot).or_default().extend(evidence);
            }
            for evidence in catalog.slots.values_mut() {
                evidence.sort_by(|left, right| {
                    (left.source, &left.target, &left.detail).cmp(&(
                        right.source,
                        &right.target,
                        &right.detail,
                    ))
                });
                evidence.dedup();
            }
            value_flow_truncated |= global_stores.truncated;
            if global_stores.truncated && value_flow_continuation_function.is_none() {
                value_flow_continuation_function = global_stores.continuation_function;
            }
        }
        for graph in control_flow.functions().iter().take(admitted) {
            value_flow_budget.begin_function(limits.max_value_flow_work_per_function);
            let observation_addresses = graph
                .calls
                .iter()
                .filter_map(|call| match &call.target {
                    ControlFlowCallTarget::Indirect { .. } => Some(call.instruction_address),
                    ControlFlowCallTarget::Direct { address, .. }
                        if catalog.slot_is_objc_dispatch(*address) =>
                    {
                        Some(call.instruction_address)
                    }
                    ControlFlowCallTarget::Direct { .. } => None,
                })
                .chain(graph.exits.iter().filter_map(|exit| {
                    (matches!(
                        exit.kind,
                        crate::analysis::control_flow::ControlFlowExitKind::IndirectBranch
                            | crate::analysis::control_flow::ControlFlowExitKind::JumpTableDispatch
                            | crate::analysis::control_flow::ControlFlowExitKind::TailDispatch
                    ))
                    .then_some(exit.instruction_address)
                    .flatten()
                }))
                .collect::<BTreeSet<_>>();
            let flow = recover_value_flow(
                graph,
                architecture,
                limits.max_values_per_register,
                limits.max_loop_values_per_register,
                &observation_addresses,
                &abi_summaries,
                &mut value_flow_budget,
            );
            value_flow_truncated |= flow.truncated;
            if flow.truncated && value_flow_continuation_function.is_none() {
                value_flow_continuation_function = Some(graph.function_entry);
            }
            value_flow_widened |= flow.widened;
            for call in &graph.calls {
                let direct_stub = match &call.target {
                    ControlFlowCallTarget::Direct { address, .. }
                        if catalog.slots.contains_key(address) =>
                    {
                        Some(*address)
                    }
                    _ => None,
                };
                let indirect = matches!(&call.target, ControlFlowCallTarget::Indirect { .. });
                if !indirect && direct_stub.is_none() {
                    continue;
                }
                observed_transfer_count = observed_transfer_count.saturating_add(1);
                if calls.len() == limits.max_transfers {
                    omitted_transfer_count = omitted_transfer_count.saturating_add(1);
                    continue;
                }
                let instruction = instruction(graph, call.instruction_address);
                let recovered = recover_site(
                    macho,
                    functions,
                    graph,
                    instruction,
                    call.block,
                    IndirectTransferKind::Call,
                    direct_stub,
                    flow.before.get(&call.instruction_address),
                    flow.memory_before.get(&call.instruction_address),
                    &catalog,
                    architecture,
                    limits.max_candidates_per_transfer,
                    flow.truncated,
                    flow.widened,
                );
                omitted_candidate_count =
                    omitted_candidate_count.saturating_add(recovered.omitted_candidate_count);
                calls.push(recovered);
            }
            for exit in &graph.exits {
                if !matches!(
                    exit.kind,
                    crate::analysis::control_flow::ControlFlowExitKind::IndirectBranch
                        | crate::analysis::control_flow::ControlFlowExitKind::JumpTableDispatch
                        | crate::analysis::control_flow::ControlFlowExitKind::TailDispatch
                ) {
                    continue;
                }
                let Some(address) = exit.instruction_address else {
                    continue;
                };
                observed_transfer_count = observed_transfer_count.saturating_add(1);
                if calls.len() == limits.max_transfers {
                    omitted_transfer_count = omitted_transfer_count.saturating_add(1);
                    continue;
                }
                let recovered = recover_site(
                    macho,
                    functions,
                    graph,
                    instruction(graph, address),
                    exit.block,
                    IndirectTransferKind::Branch,
                    None,
                    flow.before.get(&address),
                    flow.memory_before.get(&address),
                    &catalog,
                    architecture,
                    limits.max_candidates_per_transfer,
                    flow.truncated,
                    flow.widened,
                );
                omitted_candidate_count =
                    omitted_candidate_count.saturating_add(recovered.omitted_candidate_count);
                calls.push(recovered);
            }
        }
        calls.sort_by_key(|call| (call.source_function, call.instruction_address));
        if omitted_transfer_count != 0 {
            reasons.insert("indirect.transfer_budget".into());
        }
        if omitted_candidate_count != 0 {
            reasons.insert("indirect.candidate_budget".into());
        }
        if value_flow_truncated {
            reasons.insert("indirect.value_flow_budget".into());
        }
        if calls.iter().any(|call| call.value_flow_widened) {
            reasons.insert("indirect.value_flow_widened".into());
        }
        if catalog.truncated {
            reasons.insert("indirect.static_evidence_truncated".into());
        }
        if catalog.failed {
            reasons.insert("indirect.static_evidence_failed".into());
        }
        if calls.iter().any(|call| call.candidates.is_empty()) {
            reasons.insert("indirect.unresolved_targets".into());
        }
        if calls.iter().any(|call| {
            call.candidates
                .iter()
                .any(|candidate| candidate.confidence == FunctionEvidenceConfidence::Candidate)
        }) {
            reasons.insert("indirect.candidate_targets".into());
        }
        if calls.iter().any(|call| !call.conflicts.is_empty()) {
            reasons.insert("indirect.evidence_conflicts".into());
        }
        if calls.iter().any(|call| {
            call.reasons
                .iter()
                .any(|reason| reason == "indirect.target_without_function_identity")
        }) {
            reasons.insert("indirect.targets_without_function_identity".into());
        }
        if calls.iter().any(|call| {
            call.reasons
                .iter()
                .any(|reason| reason == "indirect.function_ownership_uncertain")
        }) {
            reasons.insert("indirect.function_ownership_uncertain".into());
        }
        let truncated = omitted_function_count != 0
            || omitted_transfer_count != 0
            || omitted_candidate_count != 0
            || value_flow_truncated
            || catalog.truncated
            || control_flow.status() == ControlFlowIndexStatus::Truncated;
        let partial = !functions.inventory_complete()
            || control_flow.status() == ControlFlowIndexStatus::Partial
            || catalog.failed
            || calls
                .iter()
                .any(|call| call.status != IndirectCallSiteStatus::Complete);
        let status = if truncated {
            IndirectCallIndexStatus::Truncated
        } else if partial {
            IndirectCallIndexStatus::Partial
        } else {
            IndirectCallIndexStatus::Complete
        };
        catalog.receipts.sort_by_key(|receipt| receipt.source);
        let index = Self {
            image,
            limits,
            calls,
            abi_summaries: abi_summary_records,
            receipts: catalog.receipts,
            completeness: IndirectCallCompleteness {
                status,
                reasons: reasons.into_iter().collect(),
                examined_function_count: admitted as u64,
                omitted_function_count,
                observed_transfer_count,
                omitted_transfer_count,
                omitted_candidate_count,
                value_flow_truncated,
                value_flow_widened,
                value_flow_work: value_flow_budget.consumed,
                value_flow_continuation_function,
            },
        };
        debug_assert!(
            index.durable_invariants_hold(),
            "indirect durable invariant failed: completeness={:?}, limits={:?}, calls={}, summaries={}, receipts={:?}, bad_call={:?}, bad_summary={:?}, omitted_sum={}",
            index.completeness,
            index.limits,
            index.calls.len(),
            index.abi_summaries.len(),
            index.receipts,
            index.calls.iter().find(|call| {
                !indirect_call_durable_invariants_hold(
                    call,
                    index.limits.max_candidates_per_transfer,
                )
            }),
            index.abi_summaries.iter().position(|summary| {
                summary
                    .return_instructions
                    .windows(2)
                    .any(|pair| pair[0] >= pair[1])
                    || summary.values.windows(2).any(|pair| pair[0] >= pair[1])
            }),
            index
                .calls
                .iter()
                .map(|call| call.omitted_candidate_count)
                .sum::<u64>(),
        );
        Ok(index)
    }

    /// Exact image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Recovery limits.
    pub const fn limits(&self) -> IndirectCallRecoveryLimits {
        self.limits
    }

    /// Indirect and dynamic-dispatch sites sorted by source and instruction.
    pub fn calls(&self) -> &[RecoveredIndirectCall] {
        &self.calls
    }

    /// Locally complete interprocedural ABI return summaries used by value flow.
    pub fn abi_summaries(&self) -> &[FunctionAbiSummary] {
        &self.abi_summaries
    }

    /// Static evidence collector receipts.
    pub fn receipts(&self) -> &[IndirectCollectorReceipt] {
        &self.receipts
    }

    /// Global completeness.
    pub fn completeness(&self) -> &IndirectCallCompleteness {
        &self.completeness
    }

    /// Overall status.
    pub const fn status(&self) -> IndirectCallIndexStatus {
        self.completeness.status
    }

    /// Iterate sites owned by one recovered function.
    pub fn from_function(&self, entry: u64) -> impl Iterator<Item = &RecoveredIndirectCall> {
        self.calls
            .iter()
            .filter(move |call| call.source_function == entry)
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err()
            || self.calls.len() > self.limits.max_transfers
            || self.calls.windows(2).any(|pair| {
                (pair[0].source_function, pair[0].instruction_address)
                    > (pair[1].source_function, pair[1].instruction_address)
            })
            || self
                .abi_summaries
                .windows(2)
                .any(|pair| pair[0].function_entry >= pair[1].function_entry)
            || self
                .receipts
                .windows(2)
                .any(|pair| pair[0].source >= pair[1].source)
            || self
                .completeness
                .reasons
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return false;
        }
        if self.calls.iter().any(|call| {
            !indirect_call_durable_invariants_hold(call, self.limits.max_candidates_per_transfer)
        }) {
            return false;
        }
        if self.abi_summaries.iter().any(|summary| {
            summary
                .return_instructions
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
                || summary.values.windows(2).any(|pair| pair[0] >= pair[1])
        }) || self
            .receipts
            .iter()
            .any(|receipt| !indirect_collector_receipt_is_valid(receipt))
        {
            return false;
        }
        let receipt = &self.completeness;
        let omitted_candidates = self
            .calls
            .iter()
            .map(|call| call.omitted_candidate_count)
            .sum::<u64>();
        let truncated = receipt.omitted_function_count != 0
            || receipt.omitted_transfer_count != 0
            || receipt.omitted_candidate_count != 0
            || receipt.value_flow_truncated
            || self
                .receipts
                .iter()
                .any(|item| item.status == IndirectCollectorStatus::Truncated)
            || receipt
                .reasons
                .iter()
                .any(|reason| reason == "indirect.control_flow_truncated");
        let partial = self
            .calls
            .iter()
            .any(|call| call.status != IndirectCallSiteStatus::Complete)
            || self
                .receipts
                .iter()
                .any(|item| item.status == IndirectCollectorStatus::Failed)
            || receipt.reasons.iter().any(|reason| {
                reason == "indirect.control_flow_partial"
                    || reason == "indirect.function_inventory_incomplete"
            });
        let expected_status = if truncated {
            IndirectCallIndexStatus::Truncated
        } else if partial {
            IndirectCallIndexStatus::Partial
        } else {
            IndirectCallIndexStatus::Complete
        };
        receipt.examined_function_count <= self.limits.max_functions as u64
            && receipt.observed_transfer_count
                == self.calls.len() as u64 + receipt.omitted_transfer_count
            && receipt.omitted_candidate_count == omitted_candidates
            && (!self.calls.iter().any(|call| call.value_flow_widened)
                || receipt.value_flow_widened)
            && receipt.value_flow_work <= self.limits.max_value_flow_work
            && receipt.value_flow_continuation_function.is_some() == receipt.value_flow_truncated
            && receipt.status == expected_status
    }

    pub(crate) fn source_invariants_hold(
        &self,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
    ) -> bool {
        self.image == *functions.image()
            && self.image == *control_flow.image()
            && self.calls.iter().all(|call| {
                control_flow
                    .by_entry(call.source_function)
                    .is_some_and(|graph| {
                        graph.calls.iter().any(|source| {
                            source.block == call.block
                                && source.instruction_address == call.instruction_address
                        }) || graph.exits.iter().any(|source| {
                            source.block == call.block
                                && source.instruction_address == Some(call.instruction_address)
                        })
                    })
                    && call
                        .candidates
                        .iter()
                        .all(|candidate| target_functions_match(&candidate.target, functions))
            })
            && self
                .abi_summaries
                .iter()
                .all(|summary| functions.by_entry(summary.function_entry).is_some())
    }
}

fn indirect_collector_receipt_is_valid(receipt: &IndirectCollectorReceipt) -> bool {
    (!matches!(receipt.status, IndirectCollectorStatus::Absent)
        || (receipt.examined == 0 && receipt.retained == 0))
        && (!matches!(receipt.status, IndirectCollectorStatus::Complete)
            || receipt.diagnostic.is_none())
        && (!matches!(
            receipt.status,
            IndirectCollectorStatus::Truncated | IndirectCollectorStatus::Failed
        ) || receipt.diagnostic.is_some())
}

fn candidate_key(
    candidate: &IndirectCallCandidate,
) -> (
    &IndirectCallTarget,
    IndirectCallEvidenceSource,
    Option<u64>,
    &str,
) {
    (
        &candidate.target,
        candidate.source,
        candidate.evidence_address,
        &candidate.detail,
    )
}

fn indirect_call_durable_invariants_hold(
    call: &RecoveredIndirectCall,
    maximum_candidates: usize,
) -> bool {
    !call.kinds.is_empty()
        && call
            .kinds
            .windows(2)
            .all(|pair| (pair[0] as u8) < pair[1] as u8)
        && !call.carriers.is_empty()
        && call.carriers.windows(2).all(|pair| pair[0] < pair[1])
        && call.candidates.len() <= maximum_candidates
        && call
            .candidates
            .windows(2)
            .all(|pair| candidate_key(&pair[0]) <= candidate_key(&pair[1]) && pair[0] != pair[1])
        && call
            .conflicts
            .windows(2)
            .all(|pair| pair[0].evidence_address < pair[1].evidence_address)
        && call.conflicts.iter().all(|conflict| {
            conflict.targets.len() >= 2
                && conflict.targets.windows(2).all(|pair| pair[0] < pair[1])
                && conflict.sources.windows(2).all(|pair| pair[0] < pair[1])
        })
        && call.reasons.windows(2).all(|pair| pair[0] < pair[1])
        && indirect_site_status_is_valid(call)
        && call
            .candidates
            .iter()
            .all(|candidate| target_functions_are_canonical(&candidate.target))
}

fn target_functions_are_canonical(target: &IndirectCallTarget) -> bool {
    let functions = match target {
        IndirectCallTarget::Import { .. }
        | IndirectCallTarget::CppVirtualMethodImport { .. }
        | IndirectCallTarget::SwiftProtocolWitnessImport { .. }
        | IndirectCallTarget::BlockInvokeImport { .. } => return true,
        IndirectCallTarget::Internal { functions, .. }
        | IndirectCallTarget::ObjectiveCMethod { functions, .. }
        | IndirectCallTarget::SwiftImplementation { functions, .. }
        | IndirectCallTarget::CppVirtualMethod { functions, .. }
        | IndirectCallTarget::SwiftProtocolWitness { functions, .. }
        | IndirectCallTarget::SwiftClosure { functions, .. }
        | IndirectCallTarget::BlockInvoke { functions, .. } => functions,
    };
    functions.windows(2).all(|pair| pair[0] < pair[1])
}

fn target_functions_match(target: &IndirectCallTarget, functions: &FunctionIndex) -> bool {
    let candidates = match target {
        IndirectCallTarget::Import { .. }
        | IndirectCallTarget::CppVirtualMethodImport { .. }
        | IndirectCallTarget::SwiftProtocolWitnessImport { .. }
        | IndirectCallTarget::BlockInvokeImport { .. } => return true,
        IndirectCallTarget::Internal { functions, .. }
        | IndirectCallTarget::ObjectiveCMethod { functions, .. }
        | IndirectCallTarget::SwiftImplementation { functions, .. }
        | IndirectCallTarget::CppVirtualMethod { functions, .. }
        | IndirectCallTarget::SwiftProtocolWitness { functions, .. }
        | IndirectCallTarget::SwiftClosure { functions, .. }
        | IndirectCallTarget::BlockInvoke { functions, .. } => functions,
    };
    candidates.iter().all(|candidate| {
        functions
            .by_entry(candidate.entry)
            .is_some_and(|function| function.entry_confidence == candidate.entry_confidence)
    })
}

fn indirect_site_status_is_valid(call: &RecoveredIndirectCall) -> bool {
    let truncated = call.omitted_candidate_count != 0 || call.value_flow_truncated;
    let partial = call.candidates.is_empty()
        || !call.conflicts.is_empty()
        || call.value_flow_widened
        || call.reachability == ControlFlowReachability::Unknown
        || call
            .candidates
            .iter()
            .any(|candidate| candidate.confidence == FunctionEvidenceConfidence::Candidate)
        || call
            .reasons
            .iter()
            .any(|reason| indirect_reason_requires_partial(reason));
    call.status
        == if truncated {
            IndirectCallSiteStatus::Truncated
        } else if partial {
            IndirectCallSiteStatus::Partial
        } else {
            IndirectCallSiteStatus::Complete
        }
}

fn indirect_reason_requires_partial(reason: &str) -> bool {
    matches!(
        reason,
        "indirect.source_control_flow_incomplete"
            | "indirect.target_without_function_identity"
            | "indirect.function_ownership_uncertain"
            | "indirect.objc_runtime_dispatch_open"
            | "indirect.objc_selector_unresolved"
            | "indirect.objc_selector_without_implementation"
            | "indirect.objc_receiver_unresolved"
            | "indirect.swift_runtime_instantiation_open"
            | "indirect.objc_dispatch_ambiguous"
    )
}

#[derive(Debug, Clone, Copy)]
enum Architecture {
    X86_64,
    Arm64,
    Arm64e,
}

impl Architecture {
    fn from_macho(macho: &MachoFile<'_>) -> Option<Self> {
        match macho.header().cpu_type().0 {
            CPU_TYPE_X86_64 => Some(Self::X86_64),
            CPU_TYPE_ARM64
                if macho.header().cpu_subtype().0 & CPU_SUBTYPE_MASK == CPU_SUBTYPE_ARM64E =>
            {
                Some(Self::Arm64e)
            }
            CPU_TYPE_ARM64 => Some(Self::Arm64),
            _ => None,
        }
    }

    fn selector_register(self) -> ControlFlowRegister {
        ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: match self {
                Self::X86_64 => 6,
                Self::Arm64 | Self::Arm64e => 1,
            },
        }
    }

    fn stack_register(self) -> ControlFlowRegister {
        ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: match self {
                Self::X86_64 => 4,
                Self::Arm64 | Self::Arm64e => 31,
            },
        }
    }

    fn receiver_register(self) -> ControlFlowRegister {
        ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: match self {
                Self::X86_64 => 7,
                Self::Arm64 | Self::Arm64e => 0,
            },
        }
    }

    fn return_register(self) -> ControlFlowRegister {
        ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        }
    }

    fn argument_registers(self) -> &'static [u8] {
        match self {
            Self::X86_64 => &[7, 6, 2, 1, 8, 9],
            Self::Arm64 | Self::Arm64e => &[0, 1, 2, 3, 4, 5, 6, 7],
        }
    }
}

impl Catalog {
    fn slot_is_objc_dispatch(&self, address: u64) -> bool {
        self.slots.get(&address).is_some_and(|evidence| {
            evidence.iter().any(|item| {
                matches!(
                    &item.target,
                    StaticTarget::Import { name, .. }
                        if name.trim_start_matches('_').starts_with("objc_msgSend")
                )
            })
        })
    }

    fn collect_indexes(
        macho: &MachoFile<'_>,
        pointers: &PointerIndex,
        rtti: &RttiIndex,
        objc: &ObjcIndex,
        swift: &SwiftIndex,
        limits: IndirectCallRecoveryLimits,
    ) -> Self {
        let mut catalog = Self::default();
        catalog.collect_pointer_index(pointers);
        catalog.collect_rtti_index(rtti, limits.max_cpp_vtables);
        catalog.collect_objc_index(objc, limits.max_objc_methods);
        catalog.collect_swift_index(swift, limits.max_swift_dispatch_records);
        catalog.collect_blocks(macho);
        for evidence in catalog.slots.values_mut() {
            evidence.sort_by(|left, right| {
                (left.source, &left.target, &left.detail).cmp(&(
                    right.source,
                    &right.target,
                    &right.detail,
                ))
            });
            evidence.dedup();
        }
        catalog
    }

    fn collect_pointer_index(&mut self, pointers: &PointerIndex) {
        let sources = [
            (
                PointerRecordKind::Stub,
                IndirectCallEvidenceSource::IndirectSymbols,
            ),
            (
                PointerRecordKind::ChainedBind,
                IndirectCallEvidenceSource::ChainedFixup,
            ),
            (
                PointerRecordKind::ChainedRebase,
                IndirectCallEvidenceSource::ChainedFixup,
            ),
            (
                PointerRecordKind::LegacyBind,
                IndirectCallEvidenceSource::LegacyBind,
            ),
            (
                PointerRecordKind::LegacyRebase,
                IndirectCallEvidenceSource::LegacyRebase,
            ),
            (
                PointerRecordKind::Relocation,
                IndirectCallEvidenceSource::Relocation,
            ),
        ];
        for (pointer_kind, source) in sources {
            let records = pointers
                .pointers()
                .iter()
                .filter(|pointer| pointer.kind == pointer_kind)
                .collect::<Vec<_>>();
            for pointer in &records {
                let target = match &pointer.target {
                    crate::analysis::xref::XrefTarget::Internal { va } => {
                        StaticTarget::Internal(va.0)
                    }
                    crate::analysis::xref::XrefTarget::Import { name, ordinal } => {
                        StaticTarget::Import {
                            name: name.clone(),
                            ordinal: Some(*ordinal),
                        }
                    }
                };
                if pointer_kind == PointerRecordKind::Stub
                    && matches!(&target, StaticTarget::Import { name, .. } if known_heap_allocator(name))
                {
                    self.allocator_stubs.insert(pointer.address);
                }
                let authentication =
                    pointer
                        .authentication
                        .map(|authentication| PointerAuthentication {
                            key: Some(authentication.key),
                            diversity: Some(authentication.diversity),
                            address_diversity: Some(authentication.address_diversity),
                            instruction_key: None,
                            instruction_modifier: None,
                            instruction_zero_modifier: None,
                            authenticated_instruction: false,
                        });
                self.slots
                    .entry(pointer.address)
                    .or_default()
                    .push(StaticEvidence {
                        source,
                        target,
                        confidence: FunctionEvidenceConfidence::Exact,
                        authentication,
                        detail: format!("shared_{pointer_kind:?}").to_lowercase(),
                    });
            }
            let truncated = pointers.completeness().truncated && !records.is_empty();
            let failed = !pointers.completeness().complete
                && !pointers.completeness().truncated
                && !records.is_empty();
            self.truncated |= truncated;
            self.failed |= failed;
            self.receipts.push(receipt(
                source,
                if truncated {
                    IndirectCollectorStatus::Truncated
                } else if failed {
                    IndirectCollectorStatus::Failed
                } else if records.is_empty() {
                    IndirectCollectorStatus::Absent
                } else {
                    IndirectCollectorStatus::Complete
                },
                records.len() as u64,
                records.len() as u64,
                if truncated {
                    Some("shared_pointer_budget")
                } else if failed {
                    Some("shared_pointer_partial")
                } else {
                    None
                },
            ));
        }
        self.receipts.sort_by_key(|receipt| receipt.source);
        self.receipts.dedup_by(|left, right| {
            if left.source != right.source {
                return false;
            }
            left.examined = left.examined.saturating_add(right.examined);
            left.retained = left.retained.saturating_add(right.retained);
            left.status = merge_collector_status(left.status, right.status);
            left.diagnostic = left.diagnostic.clone().or_else(|| right.diagnostic.clone());
            true
        });
    }

    fn collect_rtti_index(&mut self, rtti: &RttiIndex, limit: usize) {
        let mut groups = 0_usize;
        let mut retained = 0_u64;
        for record in &rtti.vtables().records {
            let crate::metadata::cpp::StrictVtableRecord::Group { record } = record else {
                continue;
            };
            if groups == limit {
                self.truncated = true;
                break;
            }
            groups += 1;
            for point in &record.address_points {
                let agreed_type_name = agreed_cpp_type_name(rtti, point.va, &point.typeinfo.target);
                for slot in &point.slots {
                    let target = match &slot.pointer.target {
                        crate::metadata::cpp::StrictPointerTarget::Local { va } => {
                            StaticTarget::Internal(*va)
                        }
                        crate::metadata::cpp::StrictPointerTarget::External {
                            symbol,
                            library_ordinal,
                        } => StaticTarget::Import {
                            name: symbol.clone(),
                            ordinal: Some(*library_ordinal),
                        },
                        crate::metadata::cpp::StrictPointerTarget::Null => continue,
                    };
                    let authentication = match &slot.pointer.authentication {
                        crate::metadata::cpp::StrictPointerAuthentication::Authenticated {
                            key,
                            diversity,
                            address_diversity,
                        } => Some(PointerAuthentication {
                            key: Some(*key),
                            diversity: Some(*diversity),
                            address_diversity: Some(*address_diversity),
                            instruction_key: None,
                            instruction_modifier: None,
                            instruction_zero_modifier: None,
                            authenticated_instruction: false,
                        }),
                        crate::metadata::cpp::StrictPointerAuthentication::NotApplicable => None,
                    };
                    let offset =
                        i64::try_from(slot.ordinal.saturating_mul(u64::from(record.pointer_width)))
                            .unwrap_or(i64::MAX);
                    let address = point.va.saturating_add(offset as u64);
                    let evidence = StaticEvidence {
                        source: IndirectCallEvidenceSource::CppVtable,
                        target: target.clone(),
                        confidence: FunctionEvidenceConfidence::Exact,
                        authentication,
                        detail: record.symbol.clone(),
                    };
                    self.slots
                        .entry(address)
                        .or_default()
                        .push(evidence.clone());
                    self.cpp_offsets.entry(offset).or_default().push(evidence);
                    if let Some(type_name) = &agreed_type_name {
                        let dispatch = CppDispatch {
                            vtable: record.va,
                            address_point: point.va,
                            slot: slot.ordinal,
                            type_name: type_name.clone(),
                            implementation: target,
                            confidence: FunctionEvidenceConfidence::Exact,
                            authentication,
                        };
                        self.cpp_slots
                            .entry(address)
                            .or_default()
                            .push(dispatch.clone());
                        self.cpp_offsets_agreed
                            .entry(offset)
                            .or_default()
                            .push(dispatch);
                    }
                    retained = retained.saturating_add(1);
                }
            }
        }
        let strict_ranges = rtti
            .vtables()
            .records
            .iter()
            .filter_map(|record| match record {
                crate::metadata::cpp::StrictVtableRecord::Group { record } => {
                    Some((record.va, record.va.saturating_add(record.byte_length)))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        for record in rtti.structural_vtables().iter().filter(|record| {
            !strict_ranges
                .iter()
                .any(|&(start, end)| start <= record.start && record.start < end)
        }) {
            if groups == limit {
                self.truncated = true;
                break;
            }
            groups += 1;
            let pointer_width = record.address_point.saturating_sub(record.start) / 2;
            let type_name = match &record.typeinfo.target {
                crate::metadata::cpp::StrictPointerTarget::Local { va } => rtti
                    .structural_type_info()
                    .iter()
                    .find(|type_info| type_info.address == *va)
                    .map(|type_info| type_info.type_name.as_str()),
                _ => None,
            }
            .unwrap_or("anonymous_cpp_vtable");
            let agreed_type_name = match &record.typeinfo.target {
                crate::metadata::cpp::StrictPointerTarget::Local { va }
                    if !rtti
                        .conflicts()
                        .iter()
                        .any(|conflict| conflict.address == *va) =>
                {
                    rtti.recovered_type_info_by_address(*va)
                        .map(|type_info| match type_info {
                            crate::analysis::rtti::RecoveredTypeInfo::Strict(record) => {
                                record.type_name.clone()
                            }
                            crate::analysis::rtti::RecoveredTypeInfo::Structural(record) => {
                                record.type_name.clone()
                            }
                        })
                }
                _ => None,
            };
            for slot in &record.slots {
                let target = match &slot.pointer.target {
                    crate::metadata::cpp::StrictPointerTarget::Local { va } => {
                        StaticTarget::Internal(*va)
                    }
                    crate::metadata::cpp::StrictPointerTarget::External {
                        symbol,
                        library_ordinal,
                    } => StaticTarget::Import {
                        name: symbol.clone(),
                        ordinal: Some(*library_ordinal),
                    },
                    crate::metadata::cpp::StrictPointerTarget::Null => continue,
                };
                let authentication =
                    slot.pointer
                        .authentication
                        .map(|authentication| PointerAuthentication {
                            key: Some(authentication.key),
                            diversity: Some(authentication.diversity),
                            address_diversity: Some(authentication.address_diversity),
                            instruction_key: None,
                            instruction_modifier: None,
                            instruction_zero_modifier: None,
                            authenticated_instruction: false,
                        });
                let offset =
                    i64::try_from(slot.ordinal.saturating_mul(pointer_width)).unwrap_or(i64::MAX);
                let evidence = StaticEvidence {
                    source: IndirectCallEvidenceSource::CppVtable,
                    target: target.clone(),
                    confidence: FunctionEvidenceConfidence::Derived,
                    authentication,
                    detail: type_name.to_owned(),
                };
                self.slots
                    .entry(slot.address)
                    .or_default()
                    .push(evidence.clone());
                self.cpp_offsets.entry(offset).or_default().push(evidence);
                if let Some(type_name) = &agreed_type_name {
                    let dispatch = CppDispatch {
                        vtable: record.start,
                        address_point: record.address_point,
                        slot: slot.ordinal,
                        type_name: type_name.clone(),
                        implementation: target,
                        confidence: FunctionEvidenceConfidence::Derived,
                        authentication,
                    };
                    self.cpp_slots
                        .entry(slot.address)
                        .or_default()
                        .push(dispatch.clone());
                    self.cpp_offsets_agreed
                        .entry(offset)
                        .or_default()
                        .push(dispatch);
                }
                retained = retained.saturating_add(1);
            }
        }
        let partial = rtti.status() == crate::analysis::rtti::RttiIndexStatus::Partial;
        let truncated =
            self.truncated || rtti.status() == crate::analysis::rtti::RttiIndexStatus::Truncated;
        self.failed |= partial;
        self.truncated |= truncated;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::CppVtable,
            if truncated {
                IndirectCollectorStatus::Truncated
            } else if partial {
                IndirectCollectorStatus::Failed
            } else if groups == 0 {
                IndirectCollectorStatus::Absent
            } else {
                IndirectCollectorStatus::Complete
            },
            groups as u64,
            retained,
            if truncated {
                Some("shared_rtti_budget")
            } else if partial {
                Some("shared_rtti_partial")
            } else {
                None
            },
        ));
    }

    fn collect_objc_index(&mut self, objc: &ObjcIndex, limit: usize) {
        let available = objc.methods().len();
        for class in objc.classes() {
            if let Some(address) = class.address {
                self.objc_class_addresses
                    .insert(address, class.name.clone());
            }
            if let Some(address) = class.metaclass_address {
                self.objc_metaclass_addresses
                    .insert(address, class.name.clone());
            }
            self.objc_superclasses
                .insert(class.name.clone(), class.superclass.clone());
            for protocol in &class.protocols {
                self.objc_protocol_adopters
                    .entry(protocol.clone())
                    .or_default()
                    .insert(class.name.clone());
            }
        }
        let protocol_parents = objc
            .protocols()
            .iter()
            .map(|protocol| (protocol.name.clone(), protocol.adopted_protocols.clone()))
            .collect::<BTreeMap<_, _>>();
        for class in objc.classes() {
            let mut work = class.protocols.clone();
            let mut superclass = class.superclass.clone();
            while let Some(name) = superclass {
                if let Some(parent) = objc
                    .classes()
                    .iter()
                    .find(|candidate| candidate.name == name)
                {
                    work.extend(parent.protocols.iter().cloned());
                    superclass = parent.superclass.clone();
                } else {
                    break;
                }
            }
            let mut seen = BTreeSet::new();
            while let Some(protocol) = work.pop() {
                if !seen.insert(protocol.clone()) {
                    continue;
                }
                self.objc_protocol_adopters
                    .entry(protocol.clone())
                    .or_default()
                    .insert(class.name.clone());
                work.extend(
                    protocol_parents
                        .get(&protocol)
                        .into_iter()
                        .flatten()
                        .cloned(),
                );
            }
        }
        for method in objc.methods().iter().take(limit) {
            self.objc_methods.push(ObjcDispatch {
                class_name: method.class_name.clone(),
                selector: method.selector.clone(),
                class_method: method.class_method,
                implementation: method.implementation,
            });
            if let Ok(signature) =
                crate::metadata::objc::encoding::ObjCMethodSignature::parse(&method.type_encoding)
            {
                for (argument_index, argument) in signature.arguments.iter().enumerate() {
                    let crate::metadata::objc::encoding::ObjCType::Object { protocols, .. } =
                        &argument.ty.ty
                    else {
                        continue;
                    };
                    if protocols.is_empty() {
                        continue;
                    }
                    let ordinal = u8::try_from(argument_index.saturating_add(2));
                    if let Ok(ordinal) = ordinal {
                        self.objc_protocol_arguments
                            .entry((method.implementation, ordinal))
                            .or_default()
                            .extend(protocols.iter().cloned());
                    }
                }
            }
        }
        self.objc_methods.sort_by(|left, right| {
            (
                &left.selector,
                &left.class_name,
                left.class_method,
                left.implementation,
            )
                .cmp(&(
                    &right.selector,
                    &right.class_name,
                    right.class_method,
                    right.implementation,
                ))
        });
        let retained = self.objc_methods.len();
        let truncated = retained < available
            || objc.status() == crate::analysis::objc_index::ObjcIndexStatus::Truncated;
        let failed = objc.status() == crate::analysis::objc_index::ObjcIndexStatus::Partial;
        self.truncated |= truncated;
        self.failed |= failed;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::ObjectiveC,
            if truncated {
                IndirectCollectorStatus::Truncated
            } else if failed {
                IndirectCollectorStatus::Failed
            } else if objc.status() == crate::analysis::objc_index::ObjcIndexStatus::Absent {
                IndirectCollectorStatus::Absent
            } else {
                IndirectCollectorStatus::Complete
            },
            objc.completeness().attempted,
            retained as u64,
            truncated
                .then_some("shared_objc_budget")
                .or_else(|| failed.then_some("shared_objc_partial")),
        ));
    }

    fn collect_swift_index(&mut self, swift: &SwiftIndex, limit: usize) {
        let batch = swift.batch();
        let available = batch
            .class_vtable_entries
            .len()
            .saturating_add(batch.class_overrides.len())
            .saturating_add(
                batch
                    .conformances
                    .iter()
                    .filter_map(|record| record.witness_table_pattern.as_ref())
                    .map(|pattern| pattern.entries.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                batch
                    .protocol_requirements
                    .iter()
                    .filter(|record| record.default_implementation_va.is_some())
                    .count(),
            );
        let mut retained = 0_usize;
        for record in batch.class_vtable_entries.iter().take(limit) {
            self.swift_offsets
                .entry(i64::from(record.slot_index) * 8)
                .or_default()
                .push(SwiftDispatch {
                    slot: Some(record.slot_index),
                    implementation: record.implementation_va,
                    authentication: None,
                    runtime_instantiated: false,
                    detail: "swift_class_vtable".into(),
                });
            retained += 1;
        }
        for record in batch
            .class_overrides
            .iter()
            .take(limit.saturating_sub(retained))
        {
            self.swift_unindexed.push(SwiftDispatch {
                slot: None,
                implementation: record.implementation_va,
                authentication: None,
                runtime_instantiated: false,
                detail: "swift_class_override".into(),
            });
            retained += 1;
        }
        for conformance in &batch.conformances {
            let Some(pattern) = &conformance.witness_table_pattern else {
                continue;
            };
            for entry in pattern.entries.iter().take(limit.saturating_sub(retained)) {
                let authentication = swift_witness_authentication(&entry.provenance);
                let runtime_instantiated = !conformance.conditional_requirements.is_empty();
                let confidence = if runtime_instantiated {
                    FunctionEvidenceConfidence::Candidate
                } else {
                    FunctionEvidenceConfidence::Exact
                };
                let detail = if runtime_instantiated {
                    "swift_runtime_instantiated_witness"
                } else {
                    "swift_witness_pattern"
                };
                match &entry.target {
                    crate::metadata::swift::evidence::MachoSwiftWitnessPointerTargetV1::Resolved { va } => {
                        let witness = SwiftWitnessDispatch {
                            witness_table: pattern.pattern_va,
                            requirement: entry.requirement_index,
                            protocol: conformance.protocol_name.clone(),
                            conforming_type: conformance.conforming_type_name.clone(),
                            runtime_instantiated,
                            implementation: StaticTarget::Internal(*va),
                            authentication,
                        };
                        self.swift_witness_slots
                            .entry(entry.slot_va)
                            .or_default()
                            .push(witness.clone());
                        let offset = entry.slot_va.saturating_sub(pattern.pattern_va);
                        self.swift_witness_offsets
                            .entry(i64::try_from(offset).unwrap_or(i64::MAX))
                            .or_default()
                            .push(witness);
                        self.swift_offsets
                            .entry(i64::try_from(offset).unwrap_or(i64::MAX))
                            .or_default()
                            .push(SwiftDispatch {
                                slot: Some(entry.requirement_index),
                                implementation: *va,
                                authentication,
                                runtime_instantiated,
                                detail: format!(
                                    "swift_witness:{}:{}",
                                    conformance.conforming_type_name.as_deref().unwrap_or("?"),
                                    conformance.protocol_name.as_deref().unwrap_or("?")
                                ),
                            });
                        self.slots
                            .entry(entry.slot_va)
                            .or_default()
                            .push(StaticEvidence {
                                source: IndirectCallEvidenceSource::Swift,
                                target: StaticTarget::Internal(*va),
                                confidence,
                                authentication,
                                detail: detail.into(),
                            });
                    }
                    crate::metadata::swift::evidence::MachoSwiftWitnessPointerTargetV1::External {
                        symbol,
                    } => {
                        let implementation = StaticTarget::Import {
                            name: symbol.clone(),
                            ordinal: None,
                        };
                        let witness = SwiftWitnessDispatch {
                            witness_table: pattern.pattern_va,
                            requirement: entry.requirement_index,
                            protocol: conformance.protocol_name.clone(),
                            conforming_type: conformance.conforming_type_name.clone(),
                            runtime_instantiated,
                            implementation: implementation.clone(),
                            authentication,
                        };
                        self.swift_witness_slots
                            .entry(entry.slot_va)
                            .or_default()
                            .push(witness.clone());
                        let offset = entry.slot_va.saturating_sub(pattern.pattern_va);
                        self.swift_witness_offsets
                            .entry(i64::try_from(offset).unwrap_or(i64::MAX))
                            .or_default()
                            .push(witness);
                        self.slots
                            .entry(entry.slot_va)
                            .or_default()
                            .push(StaticEvidence {
                                source: IndirectCallEvidenceSource::Swift,
                                target: implementation,
                                confidence,
                                authentication,
                                detail: if runtime_instantiated {
                                    "swift_runtime_instantiated_external_witness"
                                } else {
                                    "swift_external_witness"
                                }
                                .into(),
                            });
                    }
                }
                retained += 1;
            }
        }
        for record in batch
            .protocol_requirements
            .iter()
            .filter(|record| record.default_implementation_va.is_some())
            .take(limit.saturating_sub(retained))
        {
            if let Some(implementation) = record.default_implementation_va {
                self.swift_offsets
                    .entry(i64::from(record.requirement_index) * 8)
                    .or_default()
                    .push(SwiftDispatch {
                        slot: Some(record.requirement_index),
                        implementation,
                        authentication: None,
                        runtime_instantiated: false,
                        detail: "swift_protocol_default".into(),
                    });
                retained += 1;
            }
        }
        let truncated = retained < available
            || swift.status() == crate::analysis::swift_index::SwiftIndexStatus::Truncated;
        let failed = swift.status() == crate::analysis::swift_index::SwiftIndexStatus::Partial;
        self.truncated |= truncated;
        self.failed |= failed;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::Swift,
            if truncated {
                IndirectCollectorStatus::Truncated
            } else if failed {
                IndirectCollectorStatus::Failed
            } else if swift.status() == crate::analysis::swift_index::SwiftIndexStatus::Absent {
                IndirectCollectorStatus::Absent
            } else {
                IndirectCollectorStatus::Complete
            },
            swift.completeness().attempted,
            retained as u64,
            truncated
                .then_some("shared_swift_budget")
                .or_else(|| failed.then_some("shared_swift_partial")),
        ));
    }

    fn collect_blocks(&mut self, macho: &MachoFile<'_>) {
        const INVOKE_OFFSET: u64 = 16;
        const DESCRIPTOR_OFFSET: u64 = 24;
        let literals = self
            .slots
            .iter()
            .filter_map(|(&address, evidence)| {
                if !block_literal_storage_section(macho, address) {
                    return None;
                }
                evidence.iter().find_map(|record| {
                    let StaticTarget::Import { name, .. } = &record.target else {
                        return None;
                    };
                    block_storage_kind(name).map(|storage| (address, storage))
                })
            })
            .collect::<Vec<_>>();
        let mut attempted = 0_u64;
        let mut retained = 0_u64;
        let mut unresolved = 0_u64;
        for (literal, storage) in literals.iter().copied() {
            if storage == BlockStorageKind::Global
                && read_u32(macho, literal.saturating_add(8))
                    .is_none_or(|flags| flags & (1 << 28) == 0)
            {
                continue;
            }
            let Some(invoke_slot) = literal.checked_add(INVOKE_OFFSET) else {
                continue;
            };
            attempted = attempted.saturating_add(1);
            let mut implementations = self
                .slots
                .get(&invoke_slot)
                .into_iter()
                .flatten()
                .map(|record| (record.target.clone(), record.authentication))
                .collect::<BTreeSet<_>>();
            if implementations.is_empty()
                && let Some(raw) = read_pointer(macho, invoke_slot).filter(|address| *address != 0)
            {
                implementations.insert((StaticTarget::Internal(raw), None));
            }
            if implementations.is_empty() {
                unresolved = unresolved.saturating_add(1);
                continue;
            }
            let descriptor = literal
                .checked_add(DESCRIPTOR_OFFSET)
                .and_then(|slot| {
                    static_internal_target(&self.slots, slot).or_else(|| read_pointer(macho, slot))
                })
                .filter(|address| *address != 0);
            for (implementation, authentication) in implementations {
                let dispatch = BlockDispatch {
                    literal: BlockLiteralLocation::Static { address: literal },
                    descriptor,
                    storage,
                    implementation,
                    authentication,
                };
                self.block_invoke_slots
                    .entry(invoke_slot)
                    .or_default()
                    .push(dispatch.clone());
                self.block_offsets
                    .entry(INVOKE_OFFSET as i64)
                    .or_default()
                    .push(dispatch);
                retained = retained.saturating_add(1);
            }
        }
        for dispatches in self.block_offsets.values_mut() {
            dispatches.sort();
            dispatches.dedup();
        }
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::BlockClosure,
            if attempted == 0 {
                IndirectCollectorStatus::Absent
            } else if unresolved != 0 {
                IndirectCollectorStatus::Failed
            } else {
                IndirectCollectorStatus::Complete
            },
            attempted,
            retained,
            (unresolved != 0).then_some("block_invoke_unresolved"),
        ));
        self.failed |= unresolved != 0;
    }

    fn collect(macho: &MachoFile<'_>, limits: IndirectCallRecoveryLimits) -> Self {
        let mut catalog = Self::default();
        catalog.collect_indirect_symbols(macho, limits.max_indirect_bindings);
        catalog.collect_chained(macho, limits.max_chained_fixups);
        catalog.collect_legacy(macho, limits.max_legacy_binds);
        catalog.collect_relocations(macho, limits.max_relocations);
        catalog.collect_blocks(macho);
        match RttiIndex::recover(macho, crate::analysis::rtti::RttiRecoveryLimits::default()) {
            Ok(rtti) => catalog.collect_rtti_index(&rtti, limits.max_cpp_vtables),
            Err(_) => catalog.collect_cpp(macho, limits.max_cpp_vtables),
        }
        catalog.collect_objc(macho, limits.max_objc_methods);
        catalog.collect_swift(macho, limits.max_swift_dispatch_records);
        for evidence in catalog.slots.values_mut() {
            evidence.sort_by(|left, right| {
                (left.source, &left.target, &left.detail).cmp(&(
                    right.source,
                    &right.target,
                    &right.detail,
                ))
            });
            evidence.dedup();
        }
        catalog
    }

    fn collect_indirect_symbols(&mut self, macho: &MachoFile<'_>, limit: u64) {
        match decode_indirect_bindings(macho, limit) {
            Ok(IndirectBindingsOutcome::Absent) => self.receipts.push(receipt(
                IndirectCallEvidenceSource::IndirectSymbols,
                IndirectCollectorStatus::Absent,
                0,
                0,
                None,
            )),
            Ok(IndirectBindingsOutcome::Complete(bindings)) => {
                let count = bindings.len() as u64;
                let retained = self.admit_indirect_bindings(bindings);
                self.receipts.push(receipt(
                    IndirectCallEvidenceSource::IndirectSymbols,
                    IndirectCollectorStatus::Complete,
                    count,
                    retained,
                    None,
                ));
            }
            Ok(IndirectBindingsOutcome::Truncated {
                bindings,
                available,
                ..
            }) => {
                let retained = self.admit_indirect_bindings(bindings);
                self.truncated = true;
                self.receipts.push(receipt(
                    IndirectCallEvidenceSource::IndirectSymbols,
                    IndirectCollectorStatus::Truncated,
                    available,
                    retained,
                    Some("indirect_symbol_budget"),
                ));
            }
            Err(_) => self.receipts.push(receipt(
                IndirectCallEvidenceSource::IndirectSymbols,
                IndirectCollectorStatus::Failed,
                0,
                0,
                Some("indirect_symbols_malformed"),
            )),
        }
        self.failed |= self.receipts.last().is_some_and(|receipt| {
            receipt.source == IndirectCallEvidenceSource::IndirectSymbols
                && receipt.status == IndirectCollectorStatus::Failed
        });
    }

    fn admit_indirect_bindings(
        &mut self,
        bindings: Vec<crate::metadata::symbols::IndirectSymbolBinding>,
    ) -> u64 {
        let mut retained = 0_u64;
        for binding in bindings {
            let target = match binding.target {
                IndirectSymbolTarget::Symbol(symbol) if symbol.is_undefined() => {
                    let ordinal = i32::from(symbol.library_ordinal());
                    StaticTarget::Import {
                        name: symbol.name,
                        ordinal: Some(ordinal),
                    }
                }
                IndirectSymbolTarget::Symbol(symbol) => StaticTarget::Internal(symbol.value),
                IndirectSymbolTarget::Local
                | IndirectSymbolTarget::Absolute
                | IndirectSymbolTarget::LocalAbsolute => continue,
            };
            self.slots
                .entry(binding.address.0)
                .or_default()
                .push(StaticEvidence {
                    source: IndirectCallEvidenceSource::IndirectSymbols,
                    target,
                    confidence: FunctionEvidenceConfidence::Exact,
                    authentication: None,
                    detail: match binding.kind {
                        IndirectBindingKind::Stub => "symbol_stub",
                        IndirectBindingKind::NonLazyPointer => "non_lazy_pointer",
                        IndirectBindingKind::LazyPointer => "lazy_pointer",
                    }
                    .into(),
                });
            retained = retained.saturating_add(1);
        }
        retained
    }

    fn collect_chained(&mut self, macho: &MachoFile<'_>, limit: usize) {
        let present = macho
            .load_commands()
            .iter()
            .any(|command| matches!(command.kind(), LoadCommand::DyldChainedFixups(_)));
        if !present {
            self.receipts.push(receipt(
                IndirectCallEvidenceSource::ChainedFixup,
                IndirectCollectorStatus::Absent,
                0,
                0,
                None,
            ));
            return;
        }
        let parsed = match parse_chained_fixups(macho) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.failed = true;
                self.receipts.push(receipt(
                    IndirectCallEvidenceSource::ChainedFixup,
                    IndirectCollectorStatus::Failed,
                    0,
                    0,
                    Some("chained_fixups_malformed"),
                ));
                return;
            }
        };
        let available = parsed.fixups.len();
        let admitted = available.min(limit);
        let mut retained = 0_u64;
        let mut failed = false;
        for fixup in parsed.fixups.iter().take(admitted) {
            let Some(segment) = macho.segments().get(fixup.segment_index) else {
                failed = true;
                continue;
            };
            let Some(slot) = segment.vm_addr().0.checked_add(fixup.segment_offset) else {
                failed = true;
                continue;
            };
            let (target, authentication, confidence, detail) = match &fixup.kind {
                FixupKind::Bind {
                    import_index,
                    addend,
                } => {
                    let Some(import) = parsed.imports.get(*import_index as usize) else {
                        failed = true;
                        continue;
                    };
                    (
                        StaticTarget::Import {
                            name: import.name.to_owned(),
                            ordinal: Some(import.lib_ordinal),
                        },
                        None,
                        if *addend == 0 && import.addend == 0 {
                            FunctionEvidenceConfidence::Exact
                        } else {
                            FunctionEvidenceConfidence::Derived
                        },
                        format!(
                            "chained_bind_pointer_addend_{addend}_import_addend_{}",
                            import.addend
                        ),
                    )
                }
                FixupKind::AuthBind {
                    import_index,
                    diversity,
                    key,
                    addr_div,
                } => {
                    let Some(import) = parsed.imports.get(*import_index as usize) else {
                        failed = true;
                        continue;
                    };
                    (
                        StaticTarget::Import {
                            name: import.name.to_owned(),
                            ordinal: Some(import.lib_ordinal),
                        },
                        Some(PointerAuthentication {
                            key: Some(*key),
                            diversity: Some(*diversity),
                            address_diversity: Some(*addr_div),
                            instruction_key: None,
                            instruction_modifier: None,
                            instruction_zero_modifier: None,
                            authenticated_instruction: false,
                        }),
                        if import.addend == 0 {
                            FunctionEvidenceConfidence::Exact
                        } else {
                            FunctionEvidenceConfidence::Derived
                        },
                        "authenticated_chained_bind".into(),
                    )
                }
                FixupKind::Rebase { target } => {
                    let Some(target) = chained_target(macho, *target) else {
                        failed = true;
                        continue;
                    };
                    (
                        StaticTarget::Internal(target),
                        None,
                        FunctionEvidenceConfidence::Exact,
                        "chained_rebase".into(),
                    )
                }
                FixupKind::AuthRebase {
                    target,
                    diversity,
                    key,
                    addr_div,
                } => {
                    let Some(target) = chained_target(macho, *target) else {
                        failed = true;
                        continue;
                    };
                    (
                        StaticTarget::Internal(target),
                        Some(PointerAuthentication {
                            key: Some(*key),
                            diversity: Some(*diversity),
                            address_diversity: Some(*addr_div),
                            instruction_key: None,
                            instruction_modifier: None,
                            instruction_zero_modifier: None,
                            authenticated_instruction: false,
                        }),
                        FunctionEvidenceConfidence::Exact,
                        "authenticated_chained_rebase".into(),
                    )
                }
                _ => {
                    failed = true;
                    continue;
                }
            };
            self.slots.entry(slot).or_default().push(StaticEvidence {
                source: IndirectCallEvidenceSource::ChainedFixup,
                target,
                confidence,
                authentication,
                detail,
            });
            retained = retained.saturating_add(1);
        }
        let truncated = available > admitted;
        self.truncated |= truncated;
        self.failed |= failed;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::ChainedFixup,
            if failed {
                IndirectCollectorStatus::Failed
            } else if truncated {
                IndirectCollectorStatus::Truncated
            } else {
                IndirectCollectorStatus::Complete
            },
            available as u64,
            retained,
            if failed {
                Some("chained_fixup_records_unresolved")
            } else {
                truncated.then_some("chained_fixup_budget")
            },
        ));
    }

    fn collect_legacy(&mut self, macho: &MachoFile<'_>, limit: usize) {
        let parsed = match parse_bind_entries(macho) {
            Ok(parsed) => parsed,
            Err(_) => {
                self.failed = true;
                self.receipts.push(receipt(
                    IndirectCallEvidenceSource::LegacyBind,
                    IndirectCollectorStatus::Failed,
                    0,
                    0,
                    Some("legacy_bind_malformed"),
                ));
                return;
            }
        };
        let all = parsed.0.iter().chain(&parsed.1).chain(&parsed.2);
        let available = all.clone().count();
        let admitted = available.min(limit);
        let mut retained = 0_u64;
        let mut failed = false;
        for bind in all.take(admitted) {
            let Some(segment) = macho.segments().get(bind.segment_index) else {
                failed = true;
                continue;
            };
            let Some(slot) = segment.vm_addr().0.checked_add(bind.segment_offset) else {
                failed = true;
                continue;
            };
            self.slots.entry(slot).or_default().push(StaticEvidence {
                source: IndirectCallEvidenceSource::LegacyBind,
                target: StaticTarget::Import {
                    name: bind.symbol_name.to_owned(),
                    ordinal: Some(bind.lib_ordinal.clamp(i32::MIN as i64, i32::MAX as i64) as i32),
                },
                confidence: if bind.addend == 0 {
                    FunctionEvidenceConfidence::Exact
                } else {
                    FunctionEvidenceConfidence::Derived
                },
                authentication: None,
                detail: if bind.lazy {
                    "legacy_lazy_bind"
                } else {
                    "legacy_bind"
                }
                .into(),
            });
            retained = retained.saturating_add(1);
        }
        let truncated = available > admitted;
        self.truncated |= truncated;
        self.failed |= failed;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::LegacyBind,
            if failed {
                IndirectCollectorStatus::Failed
            } else if truncated {
                IndirectCollectorStatus::Truncated
            } else if available == 0 {
                IndirectCollectorStatus::Absent
            } else {
                IndirectCollectorStatus::Complete
            },
            available as u64,
            retained,
            if failed {
                Some("legacy_bind_records_unresolved")
            } else {
                truncated.then_some("legacy_bind_budget")
            },
        ));
    }

    fn collect_relocations(&mut self, macho: &MachoFile<'_>, limit: usize) {
        let available = macho
            .all_sections()
            .map(|section| section.relocation_count() as u64)
            .sum::<u64>();
        if available == 0 {
            self.receipts.push(receipt(
                IndirectCallEvidenceSource::Relocation,
                IndirectCollectorStatus::Absent,
                0,
                0,
                None,
            ));
            return;
        }

        let symbols = macho.ext::<SymbolTable<'_>>().ok();
        let mut examined = 0_usize;
        let mut retained = 0_u64;
        let mut failed = false;
        'sections: for section in macho.all_sections() {
            if section.relocation_count() == 0 {
                continue;
            }
            let relocations = match relocations_for_section(macho, section) {
                Ok(relocations) => relocations,
                Err(_) => {
                    failed = true;
                    continue;
                }
            };
            for relocation in relocations {
                if examined == limit {
                    break 'sections;
                }
                examined += 1;
                let Some(source) = section
                    .addr()
                    .0
                    .checked_add(u64::from(relocation.address()))
                else {
                    failed = true;
                    continue;
                };
                let evidence = match relocation {
                    Relocation::Standard(relocation) if relocation.is_extern => {
                        let Some(symbol) = symbols
                            .as_ref()
                            .and_then(|symbols| symbols.get(relocation.symbol_num as usize))
                        else {
                            failed = true;
                            continue;
                        };
                        let target = if symbol.is_undefined() {
                            StaticTarget::Import {
                                name: symbol.name.to_owned(),
                                ordinal: Some(i32::from(symbol.library_ordinal())),
                            }
                        } else if symbol.is_defined() {
                            StaticTarget::Internal(symbol.value)
                        } else {
                            continue;
                        };
                        Some(StaticEvidence {
                            source: IndirectCallEvidenceSource::Relocation,
                            target,
                            confidence: FunctionEvidenceConfidence::Derived,
                            authentication: None,
                            detail: format!(
                                "external_relocation_type_{}_length_{}",
                                relocation.reloc_type, relocation.length
                            ),
                        })
                    }
                    Relocation::Standard(relocation) => {
                        read_pointer(macho, source).and_then(|target| {
                            (target != 0).then_some(StaticEvidence {
                                source: IndirectCallEvidenceSource::Relocation,
                                target: StaticTarget::Internal(target),
                                confidence: FunctionEvidenceConfidence::Candidate,
                                authentication: None,
                                detail: format!(
                                    "local_relocation_section_{}_type_{}",
                                    relocation.symbol_num, relocation.reloc_type
                                ),
                            })
                        })
                    }
                    Relocation::Scattered(relocation) => Some(StaticEvidence {
                        source: IndirectCallEvidenceSource::Relocation,
                        target: StaticTarget::Internal(u64::from(relocation.value as u32)),
                        confidence: FunctionEvidenceConfidence::Derived,
                        authentication: None,
                        detail: format!("scattered_relocation_type_{}", relocation.reloc_type),
                    }),
                };
                if let Some(evidence) = evidence {
                    self.slots.entry(source).or_default().push(evidence);
                    retained = retained.saturating_add(1);
                }
            }
        }
        let truncated = (examined as u64) < available;
        self.truncated |= truncated;
        self.failed |= failed;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::Relocation,
            if failed {
                IndirectCollectorStatus::Failed
            } else if truncated {
                IndirectCollectorStatus::Truncated
            } else {
                IndirectCollectorStatus::Complete
            },
            available,
            retained,
            if failed {
                Some("relocation_evidence_incomplete")
            } else if truncated {
                Some("relocation_budget")
            } else {
                None
            },
        ));
    }

    fn collect_cpp(&mut self, macho: &MachoFile<'_>, limit: usize) {
        match VtableIndex::build_limited(macho, limit) {
            Ok(index) => {
                let mut retained = 0_u64;
                for vtable in index.vtables() {
                    for slot in &vtable.slots {
                        let SlotTarget::Function { va, .. } = &slot.target else {
                            continue;
                        };
                        let evidence = StaticEvidence {
                            source: IndirectCallEvidenceSource::CppVtable,
                            target: StaticTarget::Internal(va.0),
                            confidence: FunctionEvidenceConfidence::Exact,
                            authentication: None,
                            detail: vtable
                                .name
                                .clone()
                                .unwrap_or_else(|| "anonymous_cpp_vtable".into()),
                        };
                        self.slots
                            .entry(slot.va.0)
                            .or_default()
                            .push(evidence.clone());
                        self.cpp_offsets
                            .entry(slot.offset as i64)
                            .or_default()
                            .push(evidence);
                        retained = retained.saturating_add(1);
                    }
                }
                let truncated = index.was_truncated();
                self.truncated |= truncated;
                self.receipts.push(receipt(
                    IndirectCallEvidenceSource::CppVtable,
                    if truncated {
                        IndirectCollectorStatus::Truncated
                    } else if index.vtables().is_empty() {
                        IndirectCollectorStatus::Absent
                    } else {
                        IndirectCollectorStatus::Complete
                    },
                    index.vtables().len() as u64,
                    retained,
                    truncated.then_some("cpp_vtable_budget"),
                ));
            }
            Err(_) => {
                self.failed = true;
                self.receipts.push(receipt(
                    IndirectCallEvidenceSource::CppVtable,
                    IndirectCollectorStatus::Failed,
                    0,
                    0,
                    Some("cpp_vtable_malformed"),
                ));
            }
        }
    }

    fn collect_objc(&mut self, macho: &MachoFile<'_>, limit: usize) {
        let present = macho.all_sections().any(|section| {
            section.section_name() == "__objc_classlist"
                || section.section_name() == "__objc_catlist"
        });
        if !present {
            self.receipts.push(receipt(
                IndirectCallEvidenceSource::ObjectiveC,
                IndirectCollectorStatus::Absent,
                0,
                0,
                None,
            ));
            return;
        }
        let mut examined = 0_u64;
        let mut truncated = false;
        let result = crate::metadata::objc::fold_method_imps(macho, (), |_, method| {
            examined = examined.saturating_add(1);
            if self.objc_methods.len() == limit {
                truncated = true;
                return Err(crate::metadata::objc::ObjcError::unsupported(
                    "indirect Objective-C method budget",
                ));
            }
            self.objc_methods.push(ObjcDispatch {
                class_name: method.class_name.to_owned(),
                selector: method.method_name.to_owned(),
                class_method: matches!(method.kind, crate::metadata::objc::ObjCMethodKind::Class),
                implementation: method.imp.0,
            });
            Ok(())
        });
        self.objc_methods.sort_by(|left, right| {
            (
                &left.selector,
                &left.class_name,
                left.class_method,
                left.implementation,
            )
                .cmp(&(
                    &right.selector,
                    &right.class_name,
                    right.class_method,
                    right.implementation,
                ))
        });
        let failed = result.is_err() && !truncated;
        self.truncated |= truncated;
        self.failed |= failed;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::ObjectiveC,
            if truncated {
                IndirectCollectorStatus::Truncated
            } else if failed {
                IndirectCollectorStatus::Failed
            } else {
                IndirectCollectorStatus::Complete
            },
            examined,
            self.objc_methods.len() as u64,
            if truncated {
                Some("objc_method_budget")
            } else if failed {
                Some("objc_methods_malformed")
            } else {
                None
            },
        ));
    }

    fn collect_swift(&mut self, macho: &MachoFile<'_>, limit: usize) {
        use crate::metadata::swift::evidence::{SwiftDecodeOutcomeV1, SwiftEvidenceLimits};
        let present = macho.all_sections().any(|section| {
            section.section_name() == "__swift5_types"
                || section.section_name() == "__swift5_proto"
                || section.section_name() == "__swift5_protos"
        });
        if !present {
            self.receipts.push(receipt(
                IndirectCallEvidenceSource::Swift,
                IndirectCollectorStatus::Absent,
                0,
                0,
                None,
            ));
            return;
        }
        let cap = u64::try_from(limit).unwrap_or(u64::MAX);
        let limits = SwiftEvidenceLimits {
            max_identifier_bytes: 65_536,
            max_mangling_bytes: 262_144,
            max_nominal_descriptors: cap.clamp(1, 4_000_000),
            max_protocol_requirements: cap.clamp(1, 4_000_000),
            max_conformances: cap.clamp(1, 4_000_000),
            max_dispatch_slots: cap.clamp(1, 8_000_000),
            max_observations: cap.clamp(1, 32_000_000),
        };
        let batch = crate::metadata::swift::evidence::decode_swift_strict(macho, &limits);
        if batch.outcome == SwiftDecodeOutcomeV1::Rejected {
            let budget = batch
                .gaps
                .iter()
                .any(|gap| gap.code == "swift_structural_budget_exceeded");
            self.truncated |= budget;
            self.failed |= !budget;
            self.receipts.push(receipt(
                IndirectCallEvidenceSource::Swift,
                if budget {
                    IndirectCollectorStatus::Truncated
                } else {
                    IndirectCollectorStatus::Failed
                },
                batch.conservation.attempted,
                0,
                Some(if budget {
                    "swift_dispatch_budget"
                } else {
                    "swift_dispatch_malformed"
                }),
            ));
            return;
        }
        let available = batch
            .class_vtable_entries
            .len()
            .saturating_add(batch.class_overrides.len())
            .saturating_add(
                batch
                    .conformances
                    .iter()
                    .filter_map(|record| record.witness_table_pattern.as_ref())
                    .map(|pattern| pattern.entries.len())
                    .sum::<usize>(),
            )
            .saturating_add(
                batch
                    .protocol_requirements
                    .iter()
                    .filter(|record| record.default_implementation_va.is_some())
                    .count(),
            );
        let mut retained = 0_usize;
        for record in batch.class_vtable_entries.iter().take(limit) {
            self.swift_offsets
                .entry(i64::from(record.slot_index) * 8)
                .or_default()
                .push(SwiftDispatch {
                    slot: Some(record.slot_index),
                    implementation: record.implementation_va,
                    authentication: None,
                    runtime_instantiated: false,
                    detail: "swift_class_vtable".into(),
                });
            retained += 1;
        }
        for conformance in &batch.conformances {
            let Some(pattern) = &conformance.witness_table_pattern else {
                continue;
            };
            for entry in pattern.entries.iter().take(limit.saturating_sub(retained)) {
                let authentication = swift_witness_authentication(&entry.provenance);
                let runtime_instantiated = !conformance.conditional_requirements.is_empty();
                let confidence = if runtime_instantiated {
                    FunctionEvidenceConfidence::Candidate
                } else {
                    FunctionEvidenceConfidence::Exact
                };
                match &entry.target {
                    crate::metadata::swift::evidence::MachoSwiftWitnessPointerTargetV1::Resolved { va } => {
                        let witness = SwiftWitnessDispatch {
                            witness_table: pattern.pattern_va,
                            requirement: entry.requirement_index,
                            protocol: conformance.protocol_name.clone(),
                            conforming_type: conformance.conforming_type_name.clone(),
                            runtime_instantiated,
                            implementation: StaticTarget::Internal(*va),
                            authentication,
                        };
                        self.swift_witness_slots
                            .entry(entry.slot_va)
                            .or_default()
                            .push(witness.clone());
                        let offset = entry.slot_va.saturating_sub(pattern.pattern_va);
                        self.swift_witness_offsets
                            .entry(i64::try_from(offset).unwrap_or(i64::MAX))
                            .or_default()
                            .push(witness);
                        self.swift_offsets
                            .entry(i64::try_from(offset).unwrap_or(i64::MAX))
                            .or_default()
                            .push(SwiftDispatch {
                                slot: Some(entry.requirement_index),
                                implementation: *va,
                                authentication,
                                runtime_instantiated,
                                detail: format!(
                                    "swift_witness:{}:{}",
                                    conformance.conforming_type_name.as_deref().unwrap_or("?"),
                                    conformance.protocol_name.as_deref().unwrap_or("?")
                                ),
                            });
                        self.slots.entry(entry.slot_va).or_default().push(StaticEvidence {
                            source: IndirectCallEvidenceSource::Swift,
                            target: StaticTarget::Internal(*va),
                            confidence,
                            authentication,
                            detail: if runtime_instantiated {
                                "swift_runtime_instantiated_witness"
                            } else {
                                "swift_witness_pattern"
                            }.into(),
                        });
                    }
                    crate::metadata::swift::evidence::MachoSwiftWitnessPointerTargetV1::External { symbol } => {
                        let implementation = StaticTarget::Import {
                            name: symbol.clone(),
                            ordinal: None,
                        };
                        let witness = SwiftWitnessDispatch {
                            witness_table: pattern.pattern_va,
                            requirement: entry.requirement_index,
                            protocol: conformance.protocol_name.clone(),
                            conforming_type: conformance.conforming_type_name.clone(),
                            runtime_instantiated,
                            implementation: implementation.clone(),
                            authentication,
                        };
                        self.swift_witness_slots
                            .entry(entry.slot_va)
                            .or_default()
                            .push(witness.clone());
                        let offset = entry.slot_va.saturating_sub(pattern.pattern_va);
                        self.swift_witness_offsets
                            .entry(i64::try_from(offset).unwrap_or(i64::MAX))
                            .or_default()
                            .push(witness);
                        self.slots.entry(entry.slot_va).or_default().push(StaticEvidence {
                            source: IndirectCallEvidenceSource::Swift,
                            target: implementation,
                            confidence,
                            authentication,
                            detail: if runtime_instantiated {
                                "swift_runtime_instantiated_external_witness"
                            } else {
                                "swift_external_witness"
                            }.into(),
                        });
                    }
                }
                retained += 1;
            }
        }
        for record in batch
            .class_overrides
            .iter()
            .take(limit.saturating_sub(retained))
        {
            self.swift_unindexed.push(SwiftDispatch {
                slot: None,
                implementation: record.implementation_va,
                authentication: None,
                runtime_instantiated: false,
                detail: "swift_class_override".into(),
            });
            retained += 1;
        }
        for record in batch
            .protocol_requirements
            .iter()
            .filter(|record| record.default_implementation_va.is_some())
            .take(limit.saturating_sub(retained))
        {
            if let Some(implementation) = record.default_implementation_va {
                self.swift_offsets
                    .entry(i64::from(record.requirement_index) * 8)
                    .or_default()
                    .push(SwiftDispatch {
                        slot: Some(record.requirement_index),
                        implementation,
                        authentication: None,
                        runtime_instantiated: false,
                        detail: "swift_protocol_default".into(),
                    });
                retained += 1;
            }
        }
        let truncated = available > retained;
        self.truncated |= truncated;
        self.receipts.push(receipt(
            IndirectCallEvidenceSource::Swift,
            if truncated {
                IndirectCollectorStatus::Truncated
            } else {
                IndirectCollectorStatus::Complete
            },
            available as u64,
            retained as u64,
            truncated.then_some("swift_dispatch_retention_budget"),
        ));
    }
}

fn block_storage_kind(name: &str) -> Option<BlockStorageKind> {
    let name = name.trim_start_matches('_');
    if !name.starts_with("NSConcrete") || !name.ends_with("Block") {
        return None;
    }
    Some(if name.contains("Global") {
        BlockStorageKind::Global
    } else if name.contains("Stack") {
        BlockStorageKind::Stack
    } else if name.contains("Malloc") {
        BlockStorageKind::Malloc
    } else {
        BlockStorageKind::Unknown
    })
}

fn block_literal_storage_section(macho: &MachoFile<'_>, literal: u64) -> bool {
    let Some(section) = macho.all_sections().find(|section| {
        section.addr().0 <= literal
            && literal
                .checked_add(32)
                .is_some_and(|end| end <= section.addr().0.saturating_add(section.size()))
    }) else {
        return false;
    };
    section.section_name() != "__stubs"
        && section.section_name() != "__stub_helper"
        && section.section_name() != "__got"
        && section.section_name() != "__la_symbol_ptr"
        && section.section_name() != "__nl_symbol_ptr"
}

fn agreed_cpp_type_name(
    rtti: &RttiIndex,
    address_point: u64,
    typeinfo: &crate::metadata::cpp::StrictPointerTarget,
) -> Option<String> {
    let relation = rtti.vtable_type_relations().iter().find(|relation| {
        relation.address_point == address_point && &relation.typeinfo == typeinfo
    })?;
    let crate::metadata::cpp::StrictPointerTarget::Local { va } = relation.typeinfo else {
        return None;
    };
    if rtti
        .conflicts()
        .iter()
        .any(|conflict| conflict.address == va)
    {
        return None;
    }
    rtti.recovered_type_info_by_address(va)
        .map(|record| match record {
            crate::analysis::rtti::RecoveredTypeInfo::Strict(record) => record.type_name.clone(),
            crate::analysis::rtti::RecoveredTypeInfo::Structural(record) => {
                record.type_name.clone()
            }
        })
}

fn static_internal_target(slots: &BTreeMap<u64, Vec<StaticEvidence>>, slot: u64) -> Option<u64> {
    let targets = slots
        .get(&slot)?
        .iter()
        .filter_map(|record| match record.target {
            StaticTarget::Internal(address) => Some(address),
            StaticTarget::Import { .. } => None,
        })
        .collect::<BTreeSet<_>>();
    (targets.len() == 1).then(|| *targets.first().expect("one static target"))
}

fn dynamic_block_dispatches(
    macho: &MachoFile<'_>,
    memory: &MemoryValues,
    catalog: &Catalog,
    function: u64,
    implementation: &StaticTarget,
    invocation_authentication: Option<PointerAuthentication>,
    invoke_locations: &BTreeSet<AbstractMemoryLocation>,
) -> Vec<BlockDispatch> {
    let mut result = BTreeSet::new();
    for invoke_location in invoke_locations {
        let Some(values) = memory.get(invoke_location) else {
            continue;
        };
        let matching = values
            .iter()
            .filter(|value| {
                abstract_value_static_targets(macho, value, catalog).contains(implementation)
            })
            .collect::<Vec<_>>();
        if matching.is_empty() {
            continue;
        }
        let Some(base) = shift_memory_location(*invoke_location, -16) else {
            continue;
        };
        let Some(isa_values) = memory.get(&base) else {
            continue;
        };
        let storage = isa_values
            .iter()
            .filter_map(|value| abstract_value_import_name(value, catalog))
            .filter_map(block_storage_kind)
            .collect::<BTreeSet<_>>();
        if storage.is_empty() {
            continue;
        }
        let descriptor = shift_memory_location(base, 24)
            .and_then(|location| memory.get(&location))
            .into_iter()
            .flat_map(|values| values.iter())
            .filter_map(|value| abstract_value_address(macho, value))
            .filter(|address| *address != 0)
            .collect::<BTreeSet<_>>();
        let descriptor = (descriptor.len() == 1)
            .then(|| *descriptor.first().expect("one dynamic block descriptor"));
        let literal = match base {
            AbstractMemoryLocation::Global(address) => BlockLiteralLocation::Static { address },
            AbstractMemoryLocation::Stack(offset) => {
                BlockLiteralLocation::Stack { function, offset }
            }
            AbstractMemoryLocation::Heap { allocation, offset } => {
                BlockLiteralLocation::Heap { allocation, offset }
            }
            AbstractMemoryLocation::IndexedAlias { .. } => continue,
        };
        for storage in &storage {
            for value in &matching {
                result.insert(BlockDispatch {
                    literal,
                    descriptor,
                    storage: *storage,
                    implementation: implementation.clone(),
                    authentication: merge_authentication(
                        value.authentication,
                        invocation_authentication,
                    ),
                });
            }
        }
    }
    result.into_iter().collect()
}

fn value_origin_memory_locations(
    graph: &FunctionControlFlow,
    state: Option<&RegisterValues>,
    instruction: u64,
    architecture: Architecture,
) -> BTreeSet<AbstractMemoryLocation> {
    let Some(state) = state else {
        return BTreeSet::new();
    };
    graph
        .instructions
        .binary_search_by_key(&instruction, |record| record.address)
        .ok()
        .and_then(|index| graph.instructions.get(index))
        .map(|instruction| memory_locations(state, instruction, architecture))
        .unwrap_or_default()
}

fn shift_memory_location(
    location: AbstractMemoryLocation,
    delta: i64,
) -> Option<AbstractMemoryLocation> {
    match location {
        AbstractMemoryLocation::Global(address) => address
            .checked_add_signed(delta)
            .map(AbstractMemoryLocation::Global),
        AbstractMemoryLocation::Stack(offset) => {
            offset.checked_add(delta).map(AbstractMemoryLocation::Stack)
        }
        AbstractMemoryLocation::Heap { allocation, offset } => offset
            .checked_add(delta)
            .map(|offset| AbstractMemoryLocation::Heap { allocation, offset }),
        AbstractMemoryLocation::IndexedAlias { .. } => None,
    }
}

fn abstract_value_address(macho: &MachoFile<'_>, value: &AbstractValue) -> Option<u64> {
    match value.kind {
        AbstractValueKind::Address(address) => Some(address),
        AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
        _ => None,
    }
}

fn abstract_value_static_targets(
    macho: &MachoFile<'_>,
    value: &AbstractValue,
    catalog: &Catalog,
) -> BTreeSet<StaticTarget> {
    let slot = match value.kind {
        AbstractValueKind::PointerSlot(slot) => Some(slot),
        AbstractValueKind::Address(address)
            if catalog.slots.get(&address).is_some_and(|records| {
                records.iter().any(|record| record.detail == "symbol_stub")
            }) =>
        {
            Some(address)
        }
        AbstractValueKind::Address(address) => {
            return BTreeSet::from([StaticTarget::Internal(address)]);
        }
        _ => return BTreeSet::new(),
    };
    let slot = slot.expect("pointer-backed abstract value has one slot");
    let targets = catalog
        .slots
        .get(&slot)
        .into_iter()
        .flatten()
        .map(|record| record.target.clone())
        .collect::<BTreeSet<_>>();
    if targets.is_empty() {
        read_pointer(macho, slot)
            .filter(|address| *address != 0)
            .map(StaticTarget::Internal)
            .into_iter()
            .collect()
    } else {
        targets
    }
}

fn abstract_value_import_name<'a>(value: &AbstractValue, catalog: &'a Catalog) -> Option<&'a str> {
    let slot = match value.kind {
        AbstractValueKind::Address(address) | AbstractValueKind::PointerSlot(address) => address,
        _ => return None,
    };
    catalog
        .slots
        .get(&slot)?
        .iter()
        .find_map(|record| match &record.target {
            StaticTarget::Import { name, .. } => Some(name.as_str()),
            StaticTarget::Internal(_) => None,
        })
}

#[derive(Default)]
struct ValueFlow {
    before: BTreeMap<u64, RegisterValues>,
    memory_before: BTreeMap<u64, MemoryValues>,
    truncated: bool,
    widened: bool,
}

#[derive(Default)]
struct GlobalStoreRecovery {
    evidence: BTreeMap<u64, Vec<StaticEvidence>>,
    truncated: bool,
    continuation_function: Option<u64>,
}

#[derive(Default)]
struct GlobalStoreAccumulator {
    values_by_slot: BTreeMap<u64, BTreeSet<AbstractValue>>,
    complete_writes: BTreeMap<u64, bool>,
    escaped_addresses: BTreeSet<u64>,
}

#[derive(Default)]
struct BlockTransferSummary {
    /// Registers whose incoming values may affect a decoded transfer.
    input_registers: BTreeSet<ControlFlowRegister>,
    /// Registers definitely written or invalidated by the block.
    written_registers: BTreeSet<ControlFlowRegister>,
    /// Memory or call behavior makes a register-only fast path unsafe.
    memory_sensitive: bool,
    /// Observation state must be refreshed when any incoming fact changes.
    observes: bool,
}

#[derive(Default)]
struct PendingFacts {
    registers: BTreeSet<ControlFlowRegister>,
    memory: bool,
    full: bool,
}

struct ValueFlowWorkBudget {
    remaining: u64,
    consumed: u64,
    exhausted: bool,
    function_remaining: u64,
}

impl ValueFlowWorkBudget {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            consumed: 0,
            exhausted: false,
            function_remaining: u64::MAX,
        }
    }

    fn begin_function(&mut self, limit: u64) {
        self.function_remaining = limit;
    }

    fn consume(&mut self, units: u64) -> bool {
        if units <= self.remaining && units <= self.function_remaining {
            self.remaining -= units;
            self.function_remaining -= units;
            self.consumed += units;
            true
        } else {
            let consumed = self.remaining.min(self.function_remaining);
            self.consumed += consumed;
            self.remaining -= consumed;
            self.function_remaining -= consumed;
            self.exhausted = self.remaining == 0;
            false
        }
    }
}

fn global_dispatch_slots(
    control_flow: &ControlFlowIndex,
    admitted: usize,
    architecture: Architecture,
) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    for graph in control_flow.functions().iter().take(admitted) {
        let sites = graph
            .calls
            .iter()
            .filter_map(|call| {
                matches!(call.target, ControlFlowCallTarget::Indirect { .. })
                    .then_some(call.instruction_address)
            })
            .chain(graph.exits.iter().filter_map(|exit| {
                matches!(
                    exit.kind,
                    crate::analysis::control_flow::ControlFlowExitKind::IndirectBranch
                        | crate::analysis::control_flow::ControlFlowExitKind::TailDispatch
                )
                .then_some(exit.instruction_address)
                .flatten()
            }));
        for address in sites {
            let Ok(index) = graph
                .instructions
                .binary_search_by_key(&address, |instruction| instruction.address)
            else {
                continue;
            };
            let instruction = &graph.instructions[index];
            let slot = instruction
                .pc_relative
                .filter(|relative| relative.kind == ControlFlowPcRelativeKind::Memory)
                .map(|relative| relative.address)
                .or_else(|| {
                    if !architecture_matches_x86(architecture) {
                        return None;
                    }
                    instruction
                        .operands
                        .first()
                        .and_then(|operand| match operand {
                            ControlFlowOperand::Memory { base, displacement }
                                if base.number == 16 =>
                            {
                                Some(
                                    instruction
                                        .address
                                        .wrapping_add(u64::from(instruction.byte_len))
                                        .wrapping_add_signed(*displacement),
                                )
                            }
                            _ => None,
                        })
                })
                .or_else(|| {
                    let target = instruction.operands.first().and_then(operand_register)?;
                    static_pointer_slot_writer(graph, index, target)
                });
            if let Some(slot) = slot {
                result.insert(slot);
            }
        }
    }
    // Only dispatch slots with an exactly materialized static store need the
    // interprocedural mutable-global pass. This admits zero-, local-, and
    // import-initialized callback globals without turning ARM64 page aliases
    // into broad whole-program rescans.
    let stored_slots = control_flow
        .functions()
        .iter()
        .take(admitted)
        .flat_map(|graph| exact_static_store_slots(graph, architecture))
        .collect::<BTreeSet<_>>();
    result.retain(|slot| stored_slots.contains(slot));
    result
}

fn exact_static_store_slots(
    graph: &FunctionControlFlow,
    architecture: Architecture,
) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    for (index, instruction) in graph
        .instructions
        .iter()
        .enumerate()
        .filter(|(_, instruction)| instruction.memory_effect == ControlFlowMemoryEffect::Store)
    {
        if let Some(relative) = instruction
            .pc_relative
            .filter(|relative| relative.kind == ControlFlowPcRelativeKind::Memory)
        {
            result.insert(relative.address);
        }
        for operand in &instruction.operands {
            let ControlFlowOperand::Memory { base, displacement } = operand else {
                continue;
            };
            if architecture_matches_x86(architecture) && base.number == 16 {
                result.insert(
                    instruction
                        .address
                        .wrapping_add(u64::from(instruction.byte_len))
                        .wrapping_add_signed(*displacement),
                );
            } else if let Some(address) =
                resolve_local_register_address(&graph.instructions, index, *base, 0)
            {
                result.insert(address.wrapping_add_signed(*displacement));
            }
        }
    }
    result
}

fn static_pointer_slot_writer(
    graph: &FunctionControlFlow,
    before: usize,
    target: ControlFlowRegister,
) -> Option<u64> {
    let first = before.saturating_sub(12);
    let (writer_index, writer) = graph.instructions[first..before]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, instruction)| instruction.written_register == Some(target))?;
    let writer_index = first + writer_index;
    if let Some(relative) = writer
        .pc_relative
        .filter(|relative| relative.kind == ControlFlowPcRelativeKind::Memory)
    {
        return Some(relative.address);
    }
    let (base, displacement) = writer.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::Memory { base, displacement } => Some((*base, *displacement)),
        _ => None,
    })?;
    let base_writer = graph.instructions[writer_index.saturating_sub(12)..writer_index]
        .iter()
        .rev()
        .find(|instruction| instruction.written_register == Some(base))?;
    let relative = base_writer.pc_relative?;
    matches!(
        relative.kind,
        ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::PageAddress
    )
    .then(|| relative.address.wrapping_add_signed(displacement))
}

fn static_strided_pointer_table(
    macho: &MachoFile<'_>,
    graph: &FunctionControlFlow,
    before: usize,
    target: ControlFlowRegister,
    architecture: Architecture,
) -> Option<(u64, u64, u64)> {
    let instructions = &graph.instructions;
    let (load_index, load) = local_last_register_writer(instructions, before, target)?;
    if load.value_effect != ControlFlowValueEffect::Load {
        return None;
    }
    let (address, stride, index_register) =
        load.operands.iter().find_map(|operand| match operand {
            ControlFlowOperand::Memory { base, displacement } => {
                let (base, stride, index) = local_indexed_address(instructions, load_index, *base)?;
                Some((base.wrapping_add_signed(*displacement), stride, index))
            }
            ControlFlowOperand::IndexedMemory {
                base,
                index,
                scale,
                displacement,
            } => {
                let base = resolve_local_register_address(instructions, load_index, *base, 0)?;
                let (multiplier, origin) = local_index_multiplier(instructions, load_index, *index);
                Some((
                    base.wrapping_add_signed(*displacement),
                    u64::from(*scale).checked_mul(multiplier)?,
                    origin,
                ))
            }
            _ => None,
        })?;
    if stride == 0 || stride > 4096 {
        return None;
    }
    let entry_count = locally_bounded_loop_count(
        macho,
        instructions,
        load_index,
        before,
        index_register,
        architecture,
    )?;
    Some((address, stride, entry_count))
}

fn local_indexed_address(
    instructions: &[ControlFlowInstruction],
    before: usize,
    register: ControlFlowRegister,
) -> Option<(u64, u64, ControlFlowRegister)> {
    let (writer_index, writer) = local_last_register_writer(instructions, before, register)?;
    if writer.value_effect == ControlFlowValueEffect::Address {
        let ControlFlowOperand::IndexedMemory {
            base,
            index,
            scale,
            displacement,
        } = writer
            .operands
            .iter()
            .find(|operand| matches!(operand, ControlFlowOperand::IndexedMemory { .. }))?
        else {
            return None;
        };
        let base = resolve_local_register_address(instructions, writer_index, *base, 0)?;
        let (multiplier, origin) = local_index_multiplier(instructions, writer_index, *index);
        return Some((
            base.wrapping_add_signed(*displacement),
            u64::from(*scale).checked_mul(multiplier)?,
            origin,
        ));
    }
    if writer.value_effect != ControlFlowValueEffect::AddRegister {
        return None;
    }
    let ControlFlowOperand::Register { register: base } = writer.operands.get(1)? else {
        return None;
    };
    let ControlFlowOperand::ShiftedRegister {
        register: index,
        shift: ControlFlowRegisterShift::LogicalLeft,
        amount,
    } = writer.operands.get(2)?
    else {
        return None;
    };
    let base = resolve_local_register_address(instructions, writer_index, *base, 0)?;
    Some((base, 1_u64.checked_shl(u32::from(*amount))?, *index))
}

fn local_index_multiplier(
    instructions: &[ControlFlowInstruction],
    before: usize,
    register: ControlFlowRegister,
) -> (u64, ControlFlowRegister) {
    let Some((shift_index, shift)) = local_last_register_writer(instructions, before, register)
    else {
        return (1, register);
    };
    if shift.value_effect != ControlFlowValueEffect::ShiftImmediate {
        return (1, register);
    }
    let Some(amount) = shift.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::ShiftedRegister {
            register: source,
            shift: ControlFlowRegisterShift::LogicalLeft,
            amount,
        } if *source == register => Some(*amount),
        _ => None,
    }) else {
        return (1, register);
    };
    let origin = local_last_register_writer(instructions, shift_index, register)
        .and_then(|(_, writer)| {
            (writer.value_effect == ControlFlowValueEffect::Set)
                .then(|| writer.operands.get(1).and_then(operand_register))
                .flatten()
        })
        .unwrap_or(register);
    let multiplier = 1_u64.checked_shl(u32::from(amount)).unwrap_or(1);
    (multiplier, origin)
}

fn resolve_local_register_address(
    instructions: &[ControlFlowInstruction],
    before: usize,
    register: ControlFlowRegister,
    depth: u8,
) -> Option<u64> {
    if depth >= 6 {
        return None;
    }
    let (writer_index, writer) = local_last_register_writer(instructions, before, register)?;
    if let Some(reference) = writer.pc_relative
        && matches!(
            reference.kind,
            ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::PageAddress
        )
    {
        return Some(reference.address);
    }
    match writer.value_effect {
        ControlFlowValueEffect::AddImmediate => {
            let source = writer.operands.get(1).and_then(operand_register)?;
            let value = writer
                .operands
                .iter()
                .skip(2)
                .find_map(|operand| match operand {
                    ControlFlowOperand::Immediate { value } => Some(*value),
                    _ => None,
                })?;
            resolve_local_register_address(instructions, writer_index, source, depth + 1)
                .map(|address| address.wrapping_add_signed(value))
        }
        ControlFlowValueEffect::Set => {
            if let Some(value) = writer
                .operands
                .iter()
                .skip(1)
                .find_map(|operand| match operand {
                    ControlFlowOperand::Immediate { value } => Some(*value as u64),
                    _ => None,
                })
            {
                Some(value)
            } else {
                let source = writer.operands.get(1).and_then(operand_register)?;
                resolve_local_register_address(instructions, writer_index, source, depth + 1)
            }
        }
        _ => None,
    }
}

fn local_last_register_writer(
    instructions: &[ControlFlowInstruction],
    before: usize,
    register: ControlFlowRegister,
) -> Option<(usize, &ControlFlowInstruction)> {
    let first = before.saturating_sub(64);
    instructions[first..before]
        .iter()
        .enumerate()
        .rev()
        .find(|(_, instruction)| instruction.written_register == Some(register))
        .map(|(index, instruction)| (first + index, instruction))
}

fn locally_bounded_loop_count(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    load_index: usize,
    site_index: usize,
    index_register: ControlFlowRegister,
    architecture: Architecture,
) -> Option<u64> {
    let last = instructions.len().min(site_index.saturating_add(384));
    for branch_index in site_index + 1..last {
        let branch = &instructions[branch_index];
        let Some(crate::analysis::control_flow::InstructionTarget::Direct {
            address: loop_target,
        }) = branch.target
        else {
            continue;
        };
        if branch.kind != ControlFlowInstructionKind::ConditionalBranch
            || loop_target > instructions[load_index].address
            || !is_not_equal_branch(macho, branch, architecture)
        {
            continue;
        }
        let compare = instructions[branch_index.saturating_sub(2)..branch_index]
            .iter()
            .rev()
            .find(|instruction| {
                instruction
                    .operands
                    .iter()
                    .any(|operand| operand_register(operand) == Some(index_register))
            })?;
        let entry_count = compare.operands.iter().find_map(|operand| match operand {
            ControlFlowOperand::Immediate { value }
                if (1..=1024).contains(&value.unsigned_abs()) =>
            {
                Some(value.unsigned_abs())
            }
            _ => None,
        })?;
        let (increment_index, increment) =
            local_last_register_writer(instructions, branch_index, index_register)?;
        if increment_index <= site_index
            || !is_unit_increment(macho, increment, index_register, architecture)
        {
            continue;
        }
        let loop_index = instructions
            .binary_search_by_key(&loop_target, |instruction| instruction.address)
            .ok()?;
        instructions[loop_index.saturating_sub(64)..loop_index]
            .iter()
            .rev()
            .find(|instruction| {
                is_zero_initializer(macho, instruction, index_register, architecture)
            })?;
        return Some(entry_count);
    }
    None
}

fn is_zero_initializer(
    macho: &MachoFile<'_>,
    instruction: &ControlFlowInstruction,
    register: ControlFlowRegister,
    architecture: Architecture,
) -> bool {
    if instruction.value_effect == ControlFlowValueEffect::Set
        && instruction
            .operands
            .iter()
            .any(|operand| matches!(operand, ControlFlowOperand::Immediate { value: 0 }))
    {
        return true;
    }
    if matches!(architecture, Architecture::Arm64 | Architecture::Arm64e) {
        return instruction_bytes(macho, instruction)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
            .is_some_and(|word| {
                (word & 0xffff_ffe0 == 0xd280_0000 || word & 0xffff_ffe0 == 0x5280_0000)
                    && (word & 0x1f) as u8 == register.number
            });
    }
    if !architecture_matches_x86(architecture)
        || instruction.written_register != Some(register)
        || instruction
            .operands
            .iter()
            .filter_map(operand_register)
            .count()
            < 2
        || !instruction
            .operands
            .iter()
            .filter_map(operand_register)
            .all(|candidate| candidate == register)
    {
        return false;
    }
    instruction_bytes(macho, instruction).is_some_and(|bytes| {
        let opcode = bytes
            .iter()
            .copied()
            .find(|byte| !(0x40..=0x4f).contains(byte));
        matches!(opcode, Some(0x31 | 0x33))
    })
}

fn is_unit_increment(
    macho: &MachoFile<'_>,
    instruction: &ControlFlowInstruction,
    register: ControlFlowRegister,
    architecture: Architecture,
) -> bool {
    if instruction.written_register != Some(register) {
        return false;
    }
    if instruction.value_effect == ControlFlowValueEffect::AddImmediate
        && instruction
            .operands
            .iter()
            .any(|operand| matches!(operand, ControlFlowOperand::Immediate { value: 1 }))
    {
        return true;
    }
    architecture_matches_x86(architecture)
        && instruction_bytes(macho, instruction).is_some_and(|bytes| {
            let opcode_index = usize::from(
                bytes
                    .first()
                    .is_some_and(|byte| (0x40..=0x4f).contains(byte)),
            );
            bytes.get(opcode_index) == Some(&0xff)
                && bytes
                    .get(opcode_index + 1)
                    .is_some_and(|modrm| modrm >> 6 == 0b11 && (modrm >> 3) & 7 == 0)
        })
}

fn is_not_equal_branch(
    macho: &MachoFile<'_>,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
) -> bool {
    let Some(bytes) = instruction_bytes(macho, instruction) else {
        return false;
    };
    match architecture {
        Architecture::X86_64 => {
            bytes.first() == Some(&0x75) || bytes.get(..2) == Some(&[0x0f, 0x85])
        }
        Architecture::Arm64 | Architecture::Arm64e => bytes
            .get(..4)
            .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
            .map(u32::from_le_bytes)
            .is_some_and(|word| word & 0xff00_001f == 0x5400_0001),
    }
}

fn instruction_bytes<'macho>(
    macho: &'macho MachoFile<'_>,
    instruction: &ControlFlowInstruction,
) -> Option<&'macho [u8]> {
    macho
        .read_bytes_at_va(Va(instruction.address), usize::from(instruction.byte_len))
        .ok()
}

fn static_record_lookup_table(
    macho: &MachoFile<'_>,
    functions: &FunctionIndex,
    graph: &FunctionControlFlow,
    instruction: &ControlFlowInstruction,
    catalog: &Catalog,
    architecture: Architecture,
) -> Option<(u64, u64, u64)> {
    let site_index = graph
        .instructions
        .binary_search_by_key(&instruction.address, |candidate| candidate.address)
        .ok()?;

    if let Some(ControlFlowOperand::IndexedMemory {
        base,
        index,
        scale,
        displacement,
    }) = instruction.operands.first()
    {
        if *scale != 1 {
            return None;
        }
        for (loop_register, static_register, static_scale) in
            [(*base, *index, 1_u64), (*index, *base, 1)]
        {
            let Some((initial, stride, count, loop_start, loop_end)) = numeric_lookup_loop(
                macho,
                &graph.instructions,
                site_index,
                loop_register,
                architecture,
            ) else {
                continue;
            };
            let static_base = graph.instructions[loop_start..loop_end]
                .iter()
                .rev()
                .find_map(|writer| {
                    (writer.written_register == Some(static_register))
                        .then_some(writer.pc_relative)
                        .flatten()
                        .filter(|relative| {
                            matches!(
                                relative.kind,
                                ControlFlowPcRelativeKind::Address
                                    | ControlFlowPcRelativeKind::PageAddress
                            )
                        })
                        .map(|relative| relative.address)
                });
            let Some(static_base) = static_base else {
                continue;
            };
            let Some(first) = static_base
                .checked_mul(static_scale)
                .and_then(|address| address.checked_add(initial))
                .map(|address| address.wrapping_add_signed(*displacement))
            else {
                continue;
            };
            let slots = (0..count)
                .map(|index| first.saturating_add(index.saturating_mul(stride)))
                .collect::<Vec<_>>();
            let callable_count = slots
                .iter()
                .filter(|slot| callable_catalog_slot(catalog, functions, **slot))
                .count();
            if count >= 2
                && callable_count != 0
                && slots.iter().all(|slot| {
                    callable_catalog_slot(catalog, functions, *slot)
                        || read_pointer(macho, *slot) == Some(0)
                })
            {
                return Some((first, stride, count));
            }
        }
    }

    let target = instruction.operands.first().and_then(operand_register)?;
    let (load_index, load) = local_last_register_writer(&graph.instructions, site_index, target)?;
    if load.value_effect != ControlFlowValueEffect::Load {
        return None;
    }
    let base = load.operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::Memory {
            base,
            displacement: 0,
        } => Some(*base),
        _ => None,
    })?;
    for (increment_index, increment) in graph.instructions[..load_index].iter().enumerate().rev() {
        if increment.written_register != Some(base)
            || increment.value_effect != ControlFlowValueEffect::AddImmediate
        {
            continue;
        }
        let Some(stride) = increment.operands.iter().find_map(|operand| match operand {
            ControlFlowOperand::Immediate { value } if (1..=4096).contains(value) => {
                u64::try_from(*value).ok()
            }
            _ => None,
        }) else {
            continue;
        };
        let Some(first) =
            resolve_local_register_address(&graph.instructions, increment_index, base, 0)
        else {
            continue;
        };
        if !callable_catalog_slot(catalog, functions, first) {
            continue;
        }
        let mut count = 0_u64;
        while count < 1024
            && callable_catalog_slot(
                catalog,
                functions,
                first.saturating_add(count.saturating_mul(stride)),
            )
        {
            count += 1;
        }
        let terminator = first.saturating_add(count.saturating_mul(stride));
        if count >= 2 && read_pointer(macho, terminator) == Some(0) {
            return Some((first, stride, count));
        }
    }
    None
}

fn numeric_lookup_loop(
    macho: &MachoFile<'_>,
    instructions: &[ControlFlowInstruction],
    before: usize,
    register: ControlFlowRegister,
    architecture: Architecture,
) -> Option<(u64, u64, u64, usize, usize)> {
    for branch_index in (1..before).rev() {
        let branch = &instructions[branch_index];
        let Some(crate::analysis::control_flow::InstructionTarget::Direct {
            address: loop_target,
        }) = branch.target
        else {
            continue;
        };
        if branch.kind != ControlFlowInstructionKind::ConditionalBranch
            || !is_not_equal_branch(macho, branch, architecture)
        {
            continue;
        }
        let Ok(loop_start) =
            instructions.binary_search_by_key(&loop_target, |instruction| instruction.address)
        else {
            continue;
        };
        if loop_start >= branch_index {
            continue;
        }
        let compare = instructions[branch_index.saturating_sub(2)..branch_index]
            .iter()
            .rev()
            .find(|instruction| {
                instruction
                    .operands
                    .iter()
                    .any(|operand| operand_register(operand) == Some(register))
            });
        let Some(terminal) = compare.and_then(|compare| {
            compare.operands.iter().find_map(|operand| match operand {
                ControlFlowOperand::Immediate { value } => Some(value.unsigned_abs()),
                _ => None,
            })
        }) else {
            continue;
        };
        let Some((increment_index, increment)) =
            local_last_register_writer(instructions, branch_index, register)
        else {
            continue;
        };
        if increment_index < loop_start
            || increment.value_effect != ControlFlowValueEffect::AddImmediate
        {
            continue;
        }
        let Some(stride) = increment.operands.iter().find_map(|operand| match operand {
            ControlFlowOperand::Immediate { value } if (1..=4096).contains(value) => {
                u64::try_from(*value).ok()
            }
            _ => None,
        }) else {
            continue;
        };
        let Some(initializer) = instructions[loop_start.saturating_sub(64)..loop_start]
            .iter()
            .rev()
            .find(|instruction| instruction.written_register == Some(register))
        else {
            continue;
        };
        let Some(initial) = initializer
            .operands
            .iter()
            .find_map(|operand| match operand {
                ControlFlowOperand::Immediate { value } if *value >= 0 => {
                    u64::try_from(*value).ok()
                }
                _ => None,
            })
        else {
            continue;
        };
        let Some(distance) = terminal.checked_sub(initial) else {
            continue;
        };
        if stride == 0 || distance == 0 || distance % stride != 0 {
            continue;
        }
        return Some((initial, stride, distance / stride, loop_start, branch_index));
    }
    None
}

fn callable_catalog_slot(catalog: &Catalog, functions: &FunctionIndex, slot: u64) -> bool {
    catalog.slots.get(&slot).is_some_and(|evidence| {
        evidence.iter().any(|record| {
            matches!(record.target, StaticTarget::Internal(target) if !function_candidates(functions, target).is_empty())
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn recover_global_store_summaries(
    functions: &FunctionIndex,
    control_flow: &ControlFlowIndex,
    admitted: usize,
    target_slots: &BTreeSet<u64>,
    architecture: Architecture,
    maximum: usize,
    loop_maximum: usize,
    per_function_work: u64,
    abi_summaries: &AbiSummaries,
    work_budget: &mut ValueFlowWorkBudget,
) -> GlobalStoreRecovery {
    let mut result = GlobalStoreRecovery::default();
    let graphs = control_flow
        .functions()
        .iter()
        .take(admitted)
        .map(|graph| (graph.function_entry, graph))
        .collect::<BTreeMap<_, _>>();
    let mut accumulator = GlobalStoreAccumulator::default();
    for graph in graphs.values().filter(|graph| {
        target_slots
            .iter()
            .any(|slot| graph_may_reference_slot(graph, *slot))
    }) {
        scan_global_store_graph(
            functions,
            graph,
            architecture,
            maximum,
            loop_maximum,
            per_function_work,
            abi_summaries,
            work_budget,
            &mut accumulator,
            &mut result,
        );
    }

    let complete_authority = !result.truncated
        && functions.inventory_complete()
        && control_flow.status() == ControlFlowIndexStatus::Complete
        && admitted == control_flow.functions().len();
    for &slot in target_slots {
        let values = accumulator.values_by_slot.remove(&slot).unwrap_or_default();
        let closed = complete_authority
            && accumulator.complete_writes.get(&slot) == Some(&true)
            && !accumulator.escaped_addresses.contains(&slot);
        let confidence = if closed {
            FunctionEvidenceConfidence::Derived
        } else {
            FunctionEvidenceConfidence::Candidate
        };
        let detail = if closed {
            "closed_non_escaping_global_store_set"
        } else {
            "open_global_store_set_candidate"
        };
        let recovered = values
            .into_iter()
            .filter_map(|value| {
                let AbstractValueKind::Address(target) = value.kind else {
                    return None;
                };
                Some(StaticEvidence {
                    source: IndirectCallEvidenceSource::GlobalStoreSummary,
                    target: StaticTarget::Internal(target),
                    confidence,
                    authentication: value.authentication,
                    detail: detail.into(),
                })
            })
            .collect::<Vec<_>>();
        if !recovered.is_empty() {
            result.evidence.entry(slot).or_default().extend(recovered);
        }
    }
    result
}

#[allow(clippy::too_many_arguments)]
fn scan_global_store_graph(
    functions: &FunctionIndex,
    graph: &FunctionControlFlow,
    architecture: Architecture,
    maximum: usize,
    loop_maximum: usize,
    per_function_work: u64,
    abi_summaries: &AbiSummaries,
    work_budget: &mut ValueFlowWorkBudget,
    accumulator: &mut GlobalStoreAccumulator,
    result: &mut GlobalStoreRecovery,
) {
    let observations = graph
        .instructions
        .iter()
        .filter(|instruction| {
            instruction.memory_effect == ControlFlowMemoryEffect::Store
                || matches!(
                    instruction.kind,
                    ControlFlowInstructionKind::Call
                        | ControlFlowInstructionKind::Branch
                        | ControlFlowInstructionKind::Return
                )
        })
        .map(|instruction| instruction.address)
        .collect::<BTreeSet<_>>();
    if observations.is_empty() {
        return;
    }
    work_budget.begin_function(per_function_work);
    let flow = recover_value_flow(
        graph,
        architecture,
        maximum,
        loop_maximum,
        &observations,
        abi_summaries,
        work_budget,
    );
    if flow.truncated {
        result.truncated = true;
        result
            .continuation_function
            .get_or_insert(graph.function_entry);
    }
    for instruction in graph
        .instructions
        .iter()
        .filter(|instruction| observations.contains(&instruction.address))
    {
        let state = flow.before.get(&instruction.address);
        if instruction.memory_effect == ControlFlowMemoryEffect::Store {
            let source =
                state.and_then(|state| store_source_values(state, instruction, architecture));
            if let Some(source) = source {
                accumulator
                    .escaped_addresses
                    .extend(source.iter().filter_map(|value| match value.kind {
                        AbstractValueKind::Address(address) => Some(address),
                        _ => None,
                    }));
            }
            let locations = state
                .map(|state| memory_locations(state, instruction, architecture))
                .unwrap_or_default();
            for slot in locations.into_iter().filter_map(|location| match location {
                AbstractMemoryLocation::Global(slot) => Some(slot),
                _ => None,
            }) {
                let write_is_complete = source.is_some_and(|values| {
                    !values.is_empty()
                        && values.iter().all(|value| match value.kind {
                            AbstractValueKind::Address(0) => true,
                            AbstractValueKind::Address(address) => {
                                functions.by_entry(address).is_some()
                            }
                            _ => false,
                        })
                });
                accumulator
                    .complete_writes
                    .entry(slot)
                    .and_modify(|complete| *complete &= write_is_complete)
                    .or_insert(write_is_complete);
                if let Some(source) = source {
                    accumulator.values_by_slot.entry(slot).or_default().extend(
                        source.iter().copied().filter(|value| match value.kind {
                            AbstractValueKind::Address(address) => {
                                functions.by_entry(address).is_some()
                            }
                            _ => false,
                        }),
                    );
                }
            }
        }
        let Some(state) = state else {
            continue;
        };
        let escaping_registers: &[u8] = match instruction.kind {
            ControlFlowInstructionKind::Call | ControlFlowInstructionKind::Branch => {
                architecture.argument_registers()
            }
            ControlFlowInstructionKind::Return => &[0],
            ControlFlowInstructionKind::ConditionalBranch | ControlFlowInstructionKind::Other => {
                &[]
            }
        };
        for number in escaping_registers {
            let register = ControlFlowRegister {
                class: ControlFlowRegisterClass::GeneralPurpose,
                number: *number,
            };
            if let Some(values) = state.get(&register) {
                accumulator
                    .escaped_addresses
                    .extend(values.iter().filter_map(|value| match value.kind {
                        AbstractValueKind::Address(address) => Some(address),
                        _ => None,
                    }));
            }
        }
    }
}

fn graph_may_reference_slot(graph: &FunctionControlFlow, slot: u64) -> bool {
    graph.instructions.iter().any(|instruction| {
        instruction.pc_relative.is_some_and(|relative| {
            relative.address == slot
                || (relative.kind == ControlFlowPcRelativeKind::PageAddress
                    && relative.address & !0xfff == slot & !0xfff)
        })
    })
}

fn store_source_values<'state>(
    state: &'state RegisterValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
) -> Option<&'state BTreeSet<AbstractValue>> {
    let operand = match architecture {
        Architecture::X86_64 => instruction.operands.get(1),
        Architecture::Arm64 | Architecture::Arm64e => instruction.operands.first(),
    }?;
    let register = match operand {
        ControlFlowOperand::Register { register }
        | ControlFlowOperand::ShiftedRegister { register, .. } => *register,
        _ => return None,
    };
    state.get(&register).map(AsRef::as_ref)
}

fn recover_value_flow(
    graph: &FunctionControlFlow,
    architecture: Architecture,
    maximum: usize,
    loop_maximum: usize,
    observation_addresses: &BTreeSet<u64>,
    abi_summaries: &AbiSummaries,
    work_budget: &mut ValueFlowWorkBudget,
) -> ValueFlow {
    let mut result = ValueFlow::default();
    if observation_addresses.is_empty() {
        return result;
    }
    if work_budget.exhausted {
        result.truncated = true;
        return result;
    }
    let mut entries = vec![None::<RegisterValues>; graph.blocks.len()];
    let mut memory_entries = vec![None::<MemoryValues>; graph.blocks.len()];
    let mut exits = vec![None::<RegisterValues>; graph.blocks.len()];
    let mut memory_exits = vec![None::<MemoryValues>; graph.blocks.len()];
    let mut queued = vec![false; graph.blocks.len()];
    let observation_blocks = graph
        .blocks
        .iter()
        .filter(|block| {
            observation_addresses
                .range(block.start..block.end_exclusive)
                .next()
                .is_some()
        })
        .map(|block| block.id as usize)
        .collect::<BTreeSet<_>>();
    let mut predecessors = vec![Vec::<usize>::new(); graph.blocks.len()];
    for edge in &graph.edges {
        let source = edge.from as usize;
        let target = edge.to as usize;
        if source < predecessors.len() && target < predecessors.len() {
            predecessors[target].push(source);
        }
    }
    let mut relevant_blocks = observation_blocks.clone();
    let mut relevance_work = observation_blocks.into_iter().collect::<Vec<_>>();
    while let Some(block) = relevance_work.pop() {
        for &predecessor in &predecessors[block] {
            if relevant_blocks.insert(predecessor) {
                relevance_work.push(predecessor);
            }
        }
    }
    if relevant_blocks.is_empty() {
        return result;
    }
    let summaries = graph
        .blocks
        .iter()
        .map(|block| {
            summarize_block(
                graph,
                block,
                architecture,
                observation_addresses
                    .range(block.start..block.end_exclusive)
                    .next()
                    .is_some(),
            )
        })
        .collect::<Vec<_>>();
    let mut successors = vec![Vec::<usize>::new(); graph.blocks.len()];
    for edge in &graph.edges {
        let source = edge.from as usize;
        let target = edge.to as usize;
        if source < successors.len()
            && target < successors.len()
            && relevant_blocks.contains(&source)
            && relevant_blocks.contains(&target)
        {
            successors[source].push(target);
        }
    }
    for targets in &mut successors {
        targets.sort_unstable();
        targets.dedup();
    }
    let mut work = VecDeque::new();
    let mut pending = (0..graph.blocks.len())
        .map(|_| PendingFacts::default())
        .collect::<Vec<_>>();
    if let Some(entry) = graph.blocks.iter().find(|block| {
        block.start == graph.function_entry && relevant_blocks.contains(&(block.id as usize))
    }) {
        let initial = initial_register_values(architecture, graph.function_entry, abi_summaries);
        entries[entry.id as usize] = Some(initial);
        memory_entries[entry.id as usize] = Some(MemoryValues::new());
        work.push_back(entry.id as usize);
        queued[entry.id as usize] = true;
        pending[entry.id as usize].full = true;
    }
    while let Some(block_index) = work.pop_front() {
        if !work_budget.consume(1) {
            result.truncated = true;
            return result;
        }
        queued[block_index] = false;
        let dirty = std::mem::take(&mut pending[block_index]);
        let block = &graph.blocks[block_index];
        let entry_state = entries[block_index].as_ref().cloned().unwrap_or_default();
        if !work_budget.consume(register_value_count(&entry_state)) {
            result.truncated = true;
            return result;
        }
        let summary = &summaries[block_index];
        let requires_replay = dirty.full
            || exits[block_index].is_none()
            || dirty.memory
            || summary.memory_sensitive
            || summary.observes
            || dirty
                .registers
                .iter()
                .any(|register| summary.input_registers.contains(register));
        let (state, memory, output_registers, memory_output_changed) = if requires_replay {
            let mut state = entry_state;
            let mut memory = memory_entries[block_index]
                .as_ref()
                .cloned()
                .unwrap_or_default();
            let start = block.first_instruction as usize;
            let end = start + block.instruction_count as usize;
            for instruction in &graph.instructions[start..end] {
                if !work_budget.consume(1) {
                    result.truncated = true;
                    return result;
                }
                if observation_addresses.contains(&instruction.address) {
                    record_observation_state(
                        &mut result.before,
                        &mut result.memory_before,
                        instruction.address,
                        &state,
                        &memory,
                        maximum,
                        &mut result.truncated,
                        work_budget,
                    );
                }
                apply_instruction_with_summaries(
                    &mut state,
                    &mut memory,
                    instruction,
                    architecture,
                    abi_summaries,
                    maximum,
                    &mut result.truncated,
                    work_budget,
                );
                if graph.instructions.len() > loop_maximum.saturating_mul(16) {
                    result.widened |= widen_semantic_regions(&mut state, &mut memory);
                }
                if work_budget.exhausted {
                    result.truncated = true;
                    return result;
                }
            }
            let output_registers = exits[block_index].as_ref().map_or_else(
                || state.keys().copied().collect(),
                |prior| state_changes(prior, &state),
            );
            let memory_changed = memory_exits[block_index]
                .as_ref()
                .is_none_or(|prior| prior != &memory);
            exits[block_index] = Some(state.clone());
            memory_exits[block_index] = Some(memory.clone());
            (state, memory, output_registers, memory_changed)
        } else {
            let mut state = exits[block_index].as_ref().cloned().unwrap_or_default();
            let mut output_registers = BTreeSet::new();
            for register in dirty.registers {
                if summary.written_registers.contains(&register) {
                    continue;
                }
                let prior = state.get(&register);
                let incoming = entries[block_index]
                    .as_ref()
                    .and_then(|values| values.get(&register));
                if prior == incoming {
                    continue;
                }
                if let Some(values) = incoming {
                    state.insert(register, values.clone());
                } else {
                    state.remove(&register);
                }
                output_registers.insert(register);
            }
            exits[block_index] = Some(state.clone());
            (
                state,
                memory_exits[block_index]
                    .as_ref()
                    .cloned()
                    .unwrap_or_default(),
                output_registers,
                false,
            )
        };
        if output_registers.is_empty() && !memory_output_changed {
            continue;
        }
        for &target in &successors[block_index] {
            if !work_budget.consume(1) {
                result.truncated = true;
                return result;
            }
            let changed_registers = if let Some(existing) = entries[target].as_mut() {
                merge_state_changes(
                    existing,
                    &state,
                    maximum,
                    &mut result.truncated,
                    (target <= block_index).then_some(loop_maximum),
                    &mut result.widened,
                    work_budget,
                )
            } else {
                if !work_budget.consume(register_value_count(&state)) {
                    result.truncated = true;
                    return result;
                }
                entries[target] = Some(state.clone());
                state.keys().copied().collect()
            };
            let memory_changed = if let Some(existing) = memory_entries[target].as_mut() {
                merge_memory(
                    existing,
                    &memory,
                    maximum,
                    &mut result.truncated,
                    (target <= block_index).then_some(loop_maximum),
                    &mut result.widened,
                    work_budget,
                )
            } else {
                memory_entries[target] = Some(memory.clone());
                !memory.is_empty()
            };
            pending[target].registers.extend(changed_registers);
            pending[target].memory |= memory_changed;
            if (!pending[target].registers.is_empty() || pending[target].memory) && !queued[target]
            {
                work.push_back(target);
                queued[target] = true;
            }
        }
    }
    // Unreachable or unknown blocks still contain evidence. Analyze them from
    // an empty state so local address materialization is not discarded.
    for block in &graph.blocks {
        if !relevant_blocks.contains(&(block.id as usize)) || entries[block.id as usize].is_some() {
            continue;
        }
        let mut state = initial_register_values(architecture, graph.function_entry, abi_summaries);
        let mut memory = MemoryValues::new();
        let start = block.first_instruction as usize;
        let end = start + block.instruction_count as usize;
        for instruction in &graph.instructions[start..end] {
            if !work_budget.consume(1) {
                result.truncated = true;
                return result;
            }
            if observation_addresses.contains(&instruction.address) {
                record_observation_state(
                    &mut result.before,
                    &mut result.memory_before,
                    instruction.address,
                    &state,
                    &memory,
                    maximum,
                    &mut result.truncated,
                    work_budget,
                );
            }
            apply_instruction_with_summaries(
                &mut state,
                &mut memory,
                instruction,
                architecture,
                abi_summaries,
                maximum,
                &mut result.truncated,
                work_budget,
            );
            if graph.instructions.len() > loop_maximum.saturating_mul(16) {
                result.widened |= widen_semantic_regions(&mut state, &mut memory);
            }
            if work_budget.exhausted {
                result.truncated = true;
                return result;
            }
        }
    }
    result
}

fn widen_semantic_regions(state: &mut RegisterValues, memory: &mut MemoryValues) -> bool {
    let state_before = state.len();
    state.retain(|_, values| {
        !values
            .iter()
            .any(|value| matches!(value.kind, AbstractValueKind::HeapAddress { .. }))
    });
    let memory_before = memory.len();
    memory.retain(|location, _| {
        !matches!(
            location,
            AbstractMemoryLocation::Heap { .. } | AbstractMemoryLocation::IndexedAlias { .. }
        )
    });
    state.len() != state_before || memory.len() != memory_before
}

#[allow(clippy::too_many_arguments)]
fn recover_abi_summaries(
    control_flow: &ControlFlowIndex,
    architecture: Architecture,
    maximum: usize,
    loop_maximum: usize,
    per_function_work: u64,
    catalog: &Catalog,
    work_budget: &mut ValueFlowWorkBudget,
) -> (AbiSummaries, bool, bool, Option<u64>) {
    let graphs = control_flow
        .functions()
        .iter()
        .map(|graph| (graph.function_entry, graph))
        .collect::<BTreeMap<_, _>>();
    let roots = control_flow
        .functions()
        .iter()
        .filter(|graph| {
            graph.calls.iter().any(|call| match &call.target {
                ControlFlowCallTarget::Indirect { .. } => true,
                ControlFlowCallTarget::Direct { address, .. } => {
                    catalog.slot_is_objc_dispatch(*address)
                }
            }) || graph.exits.iter().any(|exit| {
                matches!(
                    exit.kind,
                    crate::analysis::control_flow::ControlFlowExitKind::IndirectBranch
                        | crate::analysis::control_flow::ControlFlowExitKind::JumpTableDispatch
                        | crate::analysis::control_flow::ControlFlowExitKind::TailDispatch
                )
            })
        })
        .map(|graph| graph.function_entry)
        .collect::<Vec<_>>();
    let mut needed = BTreeSet::new();
    let mut work = roots;
    while let Some(entry) = work.pop() {
        let Some(graph) = graphs.get(&entry) else {
            continue;
        };
        for call in &graph.calls {
            let ControlFlowCallTarget::Direct { address, .. } = call.target else {
                continue;
            };
            if graphs.contains_key(&address) && needed.insert(address) {
                work.push(address);
            }
        }
    }
    if needed.is_empty() {
        return (AbiSummaries::from_catalog(catalog), false, false, None);
    }

    let mut summaries = AbiSummaries::from_catalog(catalog);
    // Fresh heap identities are site-local facts.  Propagating them while
    // solving the transitive return-summary fixed point needlessly explodes
    // helper state and would incorrectly make one callee allocation identity
    // global.  Enable them for the caller/site pass after summaries close.
    summaries.enable_allocators = false;
    let mut widened = false;
    for _ in 0..=needed.len() {
        let mut changed = false;
        for &entry in &needed {
            let graph = graphs[&entry];
            if !abi_summary_graph_is_closed(graph) {
                continue;
            }
            let returns = graph
                .blocks
                .iter()
                .filter(|block| block.reachability == ControlFlowReachability::Reachable)
                .flat_map(|block| {
                    let start = block.first_instruction as usize;
                    let end = start + block.instruction_count as usize;
                    graph.instructions[start..end].iter()
                })
                .filter(|instruction| instruction.kind == ControlFlowInstructionKind::Return)
                .map(|instruction| instruction.address)
                .collect::<BTreeSet<_>>();
            if returns.is_empty() {
                continue;
            }
            work_budget.begin_function(per_function_work);
            let flow = recover_value_flow(
                graph,
                architecture,
                maximum,
                loop_maximum,
                &returns,
                &summaries,
                work_budget,
            );
            widened |= flow.widened;
            if flow.truncated {
                summaries.enable_allocators = true;
                return (summaries, true, widened, Some(entry));
            }
            let return_register = architecture.return_register();
            let mut values = BTreeSet::new();
            let mut complete = true;
            for address in &returns {
                let Some(state) = flow.before.get(address) else {
                    complete = false;
                    break;
                };
                let Some(retained) = state.get(&return_register) else {
                    complete = false;
                    break;
                };
                for value in retained.iter() {
                    if matches!(
                        value.kind,
                        AbstractValueKind::DynamicSlot(_) | AbstractValueKind::StackAddress(_)
                    ) {
                        complete = false;
                        break;
                    }
                    let mut value = *value;
                    value.instruction = entry;
                    values.insert(value);
                }
                if !complete {
                    break;
                }
            }
            if complete
                && !flow.widened
                && !values.is_empty()
                && summaries.get(&entry) != Some(&values)
            {
                summaries.insert(entry, values);
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    summaries.enable_allocators = true;
    (summaries, false, widened, None)
}

fn abi_summary_graph_is_closed(graph: &FunctionControlFlow) -> bool {
    let reachable = graph
        .blocks
        .iter()
        .filter(|block| block.reachability == ControlFlowReachability::Reachable)
        .collect::<Vec<_>>();
    !reachable.is_empty()
        && reachable.iter().all(|block| {
            !graph
                .gaps
                .iter()
                .any(|gap| gap.start < block.end_exclusive && gap.end_exclusive > block.start)
        })
        && graph.exits.iter().all(|exit| {
            graph.blocks.get(exit.block as usize).is_none_or(|block| {
                block.reachability != ControlFlowReachability::Reachable
                    || exit.kind == crate::analysis::control_flow::ControlFlowExitKind::Return
            })
        })
}

fn public_abi_summaries(
    control_flow: &ControlFlowIndex,
    summaries: &AbiSummaries,
) -> Vec<FunctionAbiSummary> {
    summaries
        .iter()
        .filter_map(|(&function_entry, values)| {
            let graph = control_flow.by_entry(function_entry)?;
            let mut return_instructions = graph
                .blocks
                .iter()
                .filter(|block| block.reachability == ControlFlowReachability::Reachable)
                .flat_map(|block| {
                    let start = block.first_instruction as usize;
                    let end = start + block.instruction_count as usize;
                    graph.instructions[start..end].iter()
                })
                .filter(|instruction| instruction.kind == ControlFlowInstructionKind::Return)
                .map(|instruction| instruction.address)
                .collect::<Vec<_>>();
            return_instructions.sort_unstable();
            return_instructions.dedup();
            let mut values = values
                .iter()
                .filter_map(|value| match value.kind {
                    AbstractValueKind::Argument(ordinal)
                    | AbstractValueKind::ProtocolArgument { ordinal, .. } => {
                        Some(AbiReturnValue::Argument {
                            ordinal,
                            authentication: value.authentication,
                        })
                    }
                    AbstractValueKind::Address(address) => Some(AbiReturnValue::InternalAddress {
                        address,
                        authentication: value.authentication,
                    }),
                    AbstractValueKind::PointerSlot(address) => Some(AbiReturnValue::PointerSlot {
                        address,
                        authentication: value.authentication,
                    }),
                    AbstractValueKind::DynamicSlot(_)
                    | AbstractValueKind::StackAddress(_)
                    | AbstractValueKind::HeapAddress { .. } => None,
                })
                .collect::<Vec<_>>();
            values.sort();
            values.dedup();
            Some(FunctionAbiSummary {
                function_entry,
                return_instructions,
                values,
            })
        })
        .collect()
}

fn initial_register_values(
    architecture: Architecture,
    instruction: u64,
    semantics: &AbiSummaries,
) -> RegisterValues {
    let mut state = RegisterValues::new();
    state.insert(
        architecture.stack_register(),
        Arc::new(BTreeSet::from([AbstractValue {
            kind: AbstractValueKind::StackAddress(0),
            authentication: None,
            instruction,
        }])),
    );
    for (ordinal, number) in architecture
        .argument_registers()
        .iter()
        .copied()
        .enumerate()
    {
        state.insert(
            ControlFlowRegister {
                class: ControlFlowRegisterClass::GeneralPurpose,
                number,
            },
            Arc::new(BTreeSet::from([AbstractValue {
                kind: if semantics
                    .protocol_arguments
                    .contains_key(&(instruction, ordinal as u8))
                {
                    AbstractValueKind::ProtocolArgument {
                        function: instruction,
                        ordinal: ordinal as u8,
                    }
                } else {
                    AbstractValueKind::Argument(ordinal as u8)
                },
                authentication: None,
                instruction,
            }])),
        );
    }
    state
}

fn summarize_block(
    graph: &FunctionControlFlow,
    block: &crate::analysis::control_flow::BasicBlock,
    architecture: Architecture,
    observes: bool,
) -> BlockTransferSummary {
    let mut summary = BlockTransferSummary {
        observes,
        ..BlockTransferSummary::default()
    };
    let mut written = BTreeSet::new();
    let start = block.first_instruction as usize;
    let end = start + block.instruction_count as usize;
    for instruction in &graph.instructions[start..end] {
        let destination_is_read = matches!(
            instruction.value_effect,
            ControlFlowValueEffect::AddImmediate
                | ControlFlowValueEffect::AddRegister
                | ControlFlowValueEffect::SubtractRegister
                | ControlFlowValueEffect::BitwiseAndImmediate
                | ControlFlowValueEffect::ShiftImmediate
                | ControlFlowValueEffect::ConditionalSelect
                | ControlFlowValueEffect::ZeroExtend8
                | ControlFlowValueEffect::ZeroExtend16
                | ControlFlowValueEffect::ZeroExtend32
                | ControlFlowValueEffect::SignExtend8
                | ControlFlowValueEffect::SignExtend16
                | ControlFlowValueEffect::SignExtend32
                | ControlFlowValueEffect::SignPointerIa
                | ControlFlowValueEffect::SignPointerIb
                | ControlFlowValueEffect::SignPointerDa
                | ControlFlowValueEffect::SignPointerDb
                | ControlFlowValueEffect::AuthenticatePointerIa
                | ControlFlowValueEffect::AuthenticatePointerIb
                | ControlFlowValueEffect::AuthenticatePointerDa
                | ControlFlowValueEffect::AuthenticatePointerDb
                | ControlFlowValueEffect::StripPointerAuthentication
        );
        for (operand_index, operand) in instruction.operands.iter().enumerate() {
            let mut retain = |register| {
                if !written.contains(&register) {
                    summary.input_registers.insert(register);
                }
            };
            match operand {
                ControlFlowOperand::Register { register } => {
                    if operand_index != 0
                        || destination_is_read
                        || instruction.written_register != Some(*register)
                    {
                        retain(*register);
                    }
                }
                ControlFlowOperand::ShiftedRegister { register, .. } => retain(*register),
                ControlFlowOperand::Memory { base, .. } => retain(*base),
                ControlFlowOperand::IndexedMemory { base, index, .. } => {
                    retain(*base);
                    retain(*index);
                }
                ControlFlowOperand::Immediate { .. } => {}
            }
        }
        if let Some(register) = instruction.written_register {
            written.insert(register);
            summary.written_registers.insert(register);
        }
        if instruction.writes_implicit_gpr0 {
            let register = ControlFlowRegister {
                class: ControlFlowRegisterClass::GeneralPurpose,
                number: 0,
            };
            written.insert(register);
            summary.written_registers.insert(register);
        }
        summary.memory_sensitive |= instruction.memory_effect != ControlFlowMemoryEffect::None
            || instruction.value_effect == ControlFlowValueEffect::Load;
        if instruction.kind == ControlFlowInstructionKind::Call {
            summary.memory_sensitive = true;
            for number in 0..=31 {
                let register = ControlFlowRegister {
                    class: ControlFlowRegisterClass::GeneralPurpose,
                    number,
                };
                if caller_saved(architecture, register) {
                    written.insert(register);
                    summary.written_registers.insert(register);
                }
            }
        }
    }
    summary
}

fn state_changes(
    prior: &RegisterValues,
    current: &RegisterValues,
) -> BTreeSet<ControlFlowRegister> {
    prior
        .keys()
        .chain(current.keys())
        .copied()
        .filter(|register| prior.get(register) != current.get(register))
        .collect()
}

fn register_value_count(state: &RegisterValues) -> u64 {
    state.len() as u64
}

#[cfg(test)]
fn apply_instruction(
    state: &mut RegisterValues,
    memory: &mut MemoryValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
    maximum: usize,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) {
    apply_instruction_with_summaries(
        state,
        memory,
        instruction,
        architecture,
        &AbiSummaries::new(),
        maximum,
        truncated,
        work_budget,
    );
}

#[allow(clippy::too_many_arguments)]
fn apply_instruction_with_summaries(
    state: &mut RegisterValues,
    memory: &mut MemoryValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
    abi_summaries: &AbiSummaries,
    maximum: usize,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) {
    apply_memory_effect(
        state,
        memory,
        instruction,
        architecture,
        maximum,
        truncated,
        work_budget,
    );
    if let Some(destination) = instruction.written_register {
        let mut values = BTreeSet::new();
        if let Some(relative) = instruction.pc_relative {
            values.insert(AbstractValue {
                kind: match relative.kind {
                    ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::PageAddress => {
                        AbstractValueKind::Address(relative.address)
                    }
                    ControlFlowPcRelativeKind::Memory => {
                        AbstractValueKind::PointerSlot(relative.address)
                    }
                },
                authentication: None,
                instruction: instruction.address,
            });
        } else if let Some(value) = evaluate_written_value(
            state,
            memory,
            instruction,
            architecture,
            truncated,
            work_budget,
        ) {
            values.extend(value);
        }
        if values.len() > maximum {
            values = values.into_iter().take(maximum).collect();
            *truncated = true;
        }
        if values.is_empty() {
            state.remove(&destination);
        } else {
            state.insert(destination, Arc::new(values));
        }
    }
    if instruction.writes_implicit_gpr0 {
        state.remove(&ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        });
    }
    if instruction.kind == ControlFlowInstructionKind::Call {
        let direct_target = match &instruction.target {
            Some(crate::analysis::control_flow::InstructionTarget::Direct { address }) => {
                Some(*address)
            }
            _ => None,
        };
        let summarized_return = match direct_target {
            Some(address)
                if abi_summaries.enable_allocators
                    && abi_summaries.allocator_stubs.contains(&address) =>
            {
                Some(BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::HeapAddress {
                        allocation: instruction.address,
                        offset: 0,
                    },
                    authentication: None,
                    instruction: instruction.address,
                }]))
            }
            Some(address) => abi_summaries.get(&address).map(|summary| {
                instantiate_abi_summary(summary, state, architecture, maximum, instruction.address)
            }),
            _ => None,
        };
        state.retain(|register, _| !caller_saved(architecture, *register));
        // A call cannot address the caller's frame through a normal ABI
        // argument once its location has not escaped, but it may mutate any
        // global/object region. Preserve precise frame facts and invalidate
        // the open-world portion of abstract memory.
        memory.retain(|location, _| {
            matches!(
                location,
                AbstractMemoryLocation::Stack(_)
                    | AbstractMemoryLocation::IndexedAlias {
                        base: AbstractMemoryBase::Stack(_),
                        ..
                    }
            )
        });
        if let Some(values) = summarized_return.filter(|values| !values.is_empty()) {
            state.insert(architecture.return_register(), Arc::new(values));
        }
    }
}

fn instantiate_abi_summary(
    summary: &BTreeSet<AbstractValue>,
    caller: &RegisterValues,
    architecture: Architecture,
    maximum: usize,
    callsite: u64,
) -> BTreeSet<AbstractValue> {
    let mut values = BTreeSet::new();
    for value in summary {
        match value.kind {
            AbstractValueKind::Argument(ordinal)
            | AbstractValueKind::ProtocolArgument { ordinal, .. } => {
                let Some(number) = architecture.argument_registers().get(ordinal as usize) else {
                    continue;
                };
                let register = ControlFlowRegister {
                    class: ControlFlowRegisterClass::GeneralPurpose,
                    number: *number,
                };
                if let Some(arguments) = caller.get(&register) {
                    values.extend(arguments.iter().copied());
                }
            }
            AbstractValueKind::HeapAddress { offset, .. } => {
                let mut value = *value;
                value.kind = AbstractValueKind::HeapAddress {
                    allocation: callsite,
                    offset,
                };
                value.instruction = callsite;
                values.insert(value);
            }
            _ => {
                values.insert(*value);
            }
        }
        if values.len() > maximum {
            values = values.into_iter().take(maximum).collect();
            break;
        }
    }
    values
}

fn evaluate_written_value(
    state: &RegisterValues,
    memory: &MemoryValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) -> Option<BTreeSet<AbstractValue>> {
    let operands = &instruction.operands;
    match instruction.value_effect {
        ControlFlowValueEffect::Set => match operands.get(1)? {
            ControlFlowOperand::Register { register } => {
                let values = state.get(register)?;
                if !work_budget.consume(values.len() as u64) {
                    *truncated = true;
                    return None;
                }
                Some(values.as_ref().clone())
            }
            ControlFlowOperand::Immediate { value } => Some(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(*value as u64),
                authentication: None,
                instruction: instruction.address,
            }])),
            ControlFlowOperand::Memory { .. }
            | ControlFlowOperand::IndexedMemory { .. }
            | ControlFlowOperand::ShiftedRegister { .. } => None,
        },
        ControlFlowValueEffect::ZeroExtend8
        | ControlFlowValueEffect::ZeroExtend16
        | ControlFlowValueEffect::ZeroExtend32
        | ControlFlowValueEffect::SignExtend8
        | ControlFlowValueEffect::SignExtend16
        | ControlFlowValueEffect::SignExtend32 => {
            let values = source_values(state, memory, instruction, architecture)?;
            let (bits, signed) = match instruction.value_effect {
                ControlFlowValueEffect::ZeroExtend8 => (8, false),
                ControlFlowValueEffect::ZeroExtend16 => (16, false),
                ControlFlowValueEffect::ZeroExtend32 => (32, false),
                ControlFlowValueEffect::SignExtend8 => (8, true),
                ControlFlowValueEffect::SignExtend16 => (16, true),
                ControlFlowValueEffect::SignExtend32 => (32, true),
                _ => unreachable!(),
            };
            transform_register_values(
                &values,
                instruction.address,
                truncated,
                work_budget,
                |value| extend_integer(value, bits, signed),
            )
        }
        ControlFlowValueEffect::SignPointerIa
        | ControlFlowValueEffect::SignPointerIb
        | ControlFlowValueEffect::SignPointerDa
        | ControlFlowValueEffect::SignPointerDb
        | ControlFlowValueEffect::AuthenticatePointerIa
        | ControlFlowValueEffect::AuthenticatePointerIb
        | ControlFlowValueEffect::AuthenticatePointerDa
        | ControlFlowValueEffect::AuthenticatePointerDb => {
            let values = source_values(state, memory, instruction, architecture)?;
            let key = pointer_authentication_key(instruction.value_effect)?;
            let modifier = operands.get(2).and_then(operand_register);
            let zero_modifier = modifier.is_some_and(|register| register.number == 31);
            let authenticated = matches!(
                instruction.value_effect,
                ControlFlowValueEffect::AuthenticatePointerIa
                    | ControlFlowValueEffect::AuthenticatePointerIb
                    | ControlFlowValueEffect::AuthenticatePointerDa
                    | ControlFlowValueEffect::AuthenticatePointerDb
            );
            Some(
                values
                    .into_iter()
                    .map(|mut value| {
                        value.instruction = instruction.address;
                        value.authentication = Some(PointerAuthentication {
                            key: Some(key),
                            diversity: None,
                            address_diversity: None,
                            instruction_key: Some(key),
                            instruction_modifier: modifier.filter(|_| !zero_modifier),
                            instruction_zero_modifier: Some(zero_modifier),
                            authenticated_instruction: authenticated,
                        });
                        value
                    })
                    .collect(),
            )
        }
        ControlFlowValueEffect::StripPointerAuthentication => {
            let values = source_values(state, memory, instruction, architecture)?;
            Some(
                values
                    .into_iter()
                    .map(|mut value| {
                        value.instruction = instruction.address;
                        value.authentication = None;
                        value
                    })
                    .collect(),
            )
        }
        ControlFlowValueEffect::Address | ControlFlowValueEffect::Load => {
            let locations = memory_locations(state, instruction, architecture);
            if instruction.value_effect == ControlFlowValueEffect::Load {
                let mut loaded = BTreeSet::new();
                for location in &locations {
                    loaded.extend(memory_values_at(memory, *location).into_iter().map(
                        |mut value| {
                            value.instruction = instruction.address;
                            value
                        },
                    ));
                }
                if !loaded.is_empty() {
                    return Some(loaded);
                }
            }
            let mut result = BTreeSet::new();
            for location in locations {
                if !work_budget.consume(1) {
                    *truncated = true;
                    break;
                }
                let kind = match (instruction.value_effect, location) {
                    (ControlFlowValueEffect::Load, AbstractMemoryLocation::Global(address)) => {
                        AbstractValueKind::PointerSlot(address)
                    }
                    (ControlFlowValueEffect::Address, AbstractMemoryLocation::Global(address)) => {
                        AbstractValueKind::Address(address)
                    }
                    (ControlFlowValueEffect::Address, AbstractMemoryLocation::Stack(offset)) => {
                        AbstractValueKind::StackAddress(offset)
                    }
                    (
                        ControlFlowValueEffect::Address,
                        AbstractMemoryLocation::Heap { allocation, offset },
                    ) => AbstractValueKind::HeapAddress { allocation, offset },
                    (ControlFlowValueEffect::Load, AbstractMemoryLocation::Stack(_)) => continue,
                    (ControlFlowValueEffect::Load, AbstractMemoryLocation::Heap { .. }) => continue,
                    (_, AbstractMemoryLocation::IndexedAlias { .. }) => continue,
                    _ => continue,
                };
                result.insert(AbstractValue {
                    kind,
                    authentication: None,
                    instruction: instruction.address,
                });
            }
            if !result.is_empty() {
                return Some(result);
            }
            let displacement = operands.iter().find_map(|operand| match operand {
                ControlFlowOperand::Memory { displacement, .. }
                | ControlFlowOperand::IndexedMemory { displacement, .. } => Some(*displacement),
                _ => None,
            })?;
            (instruction.value_effect == ControlFlowValueEffect::Load).then(|| {
                BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::DynamicSlot(displacement),
                    authentication: None,
                    instruction: instruction.address,
                }])
            })
        }
        ControlFlowValueEffect::AddImmediate => {
            let (source, addend) = match architecture {
                Architecture::X86_64 => {
                    let destination = instruction.written_register?;
                    let addend = operands.iter().skip(1).find_map(|operand| match operand {
                        ControlFlowOperand::Immediate { value } => Some(*value),
                        _ => None,
                    })?;
                    (destination, addend)
                }
                Architecture::Arm64 | Architecture::Arm64e => {
                    let ControlFlowOperand::Register { register } = operands.get(1)? else {
                        return None;
                    };
                    let ControlFlowOperand::Immediate { value } = operands.get(2)? else {
                        return None;
                    };
                    (*register, *value)
                }
            };
            let mut result = BTreeSet::new();
            for value in state.get(&source)?.iter() {
                if !work_budget.consume(1) {
                    *truncated = true;
                    break;
                }
                if let Some(value) = match value.kind {
                    AbstractValueKind::Address(address) => Some(AbstractValue {
                        kind: AbstractValueKind::Address(address.wrapping_add_signed(addend)),
                        authentication: None,
                        instruction: instruction.address,
                    }),
                    AbstractValueKind::PointerSlot(address) if addend == 0 => Some(AbstractValue {
                        kind: AbstractValueKind::PointerSlot(address),
                        authentication: value.authentication,
                        instruction: instruction.address,
                    }),
                    AbstractValueKind::DynamicSlot(offset) => Some(AbstractValue {
                        kind: AbstractValueKind::DynamicSlot(offset.saturating_add(addend)),
                        authentication: None,
                        instruction: instruction.address,
                    }),
                    AbstractValueKind::StackAddress(offset) => Some(AbstractValue {
                        kind: AbstractValueKind::StackAddress(offset.saturating_add(addend)),
                        authentication: None,
                        instruction: instruction.address,
                    }),
                    AbstractValueKind::HeapAddress { allocation, offset } => Some(AbstractValue {
                        kind: AbstractValueKind::HeapAddress {
                            allocation,
                            offset: offset.saturating_add(addend),
                        },
                        authentication: value.authentication,
                        instruction: instruction.address,
                    }),
                    _ => None,
                } {
                    result.insert(value);
                }
            }
            Some(result)
        }
        ControlFlowValueEffect::AddRegister | ControlFlowValueEffect::SubtractRegister => {
            let (left, right) = match architecture {
                Architecture::X86_64 => (
                    instruction.written_register?,
                    operands.get(1).and_then(operand_register)?,
                ),
                Architecture::Arm64 | Architecture::Arm64e => (
                    operands.get(1).and_then(operand_register)?,
                    operands.get(2).and_then(operand_register)?,
                ),
            };
            combine_register_values(
                state,
                left,
                right,
                operands,
                instruction,
                instruction.value_effect == ControlFlowValueEffect::SubtractRegister,
                truncated,
                work_budget,
            )
        }
        ControlFlowValueEffect::BitwiseAndImmediate => {
            let source = match architecture {
                Architecture::X86_64 => instruction.written_register?,
                Architecture::Arm64 | Architecture::Arm64e => {
                    operands.get(1).and_then(operand_register)?
                }
            };
            let mask = operands.iter().find_map(|operand| match operand {
                ControlFlowOperand::Immediate { value } => Some(*value as u64),
                _ => None,
            })?;
            transform_register_values(
                state.get(&source)?,
                instruction.address,
                truncated,
                work_budget,
                |value| value & mask,
            )
        }
        ControlFlowValueEffect::ShiftImmediate => {
            let shifted = operands.iter().find_map(|operand| match operand {
                ControlFlowOperand::ShiftedRegister {
                    register,
                    shift,
                    amount,
                } => Some((*register, *shift, *amount)),
                _ => None,
            })?;
            transform_register_values(
                state.get(&shifted.0)?,
                instruction.address,
                truncated,
                work_budget,
                |value| apply_shift(value, shifted.1, shifted.2),
            )
        }
        ControlFlowValueEffect::ConditionalSelect => {
            let mut result = BTreeSet::new();
            if matches!(architecture, Architecture::X86_64)
                && let Some(destination) = instruction.written_register
                && let Some(values) = state.get(&destination)
            {
                result.extend(values.iter().copied());
            }
            for operand in operands.iter().skip(1) {
                if let Some(register) = operand_register(operand)
                    && let Some(values) = state.get(&register)
                {
                    if !work_budget.consume(values.len() as u64) {
                        *truncated = true;
                        break;
                    }
                    result.extend(values.iter().copied());
                }
            }
            (!result.is_empty()).then_some(result)
        }
        ControlFlowValueEffect::None | ControlFlowValueEffect::UnknownWrite => None,
    }
}

fn operand_register(operand: &ControlFlowOperand) -> Option<ControlFlowRegister> {
    match operand {
        ControlFlowOperand::Register { register }
        | ControlFlowOperand::ShiftedRegister { register, .. } => Some(*register),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn combine_register_values(
    state: &RegisterValues,
    left: ControlFlowRegister,
    right: ControlFlowRegister,
    operands: &[ControlFlowOperand],
    instruction: &ControlFlowInstruction,
    subtract: bool,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) -> Option<BTreeSet<AbstractValue>> {
    let left_values = state.get(&left)?;
    let right_values = state.get(&right)?;
    let shift = operands.iter().find_map(|operand| match operand {
        ControlFlowOperand::ShiftedRegister {
            register,
            shift,
            amount,
        } if *register == right => Some((*shift, *amount)),
        _ => None,
    });
    let mut result = BTreeSet::new();
    for lhs in left_values.iter() {
        for rhs in right_values.iter() {
            if !work_budget.consume(1) {
                *truncated = true;
                return Some(result);
            }
            let AbstractValueKind::Address(raw_rhs) = rhs.kind else {
                continue;
            };
            let rhs = shift.map_or(raw_rhs, |(kind, amount)| apply_shift(raw_rhs, kind, amount));
            let signed_rhs = rhs as i64;
            let addend = if subtract {
                signed_rhs.wrapping_neg()
            } else {
                signed_rhs
            };
            let kind = match lhs.kind {
                AbstractValueKind::Address(value) => {
                    AbstractValueKind::Address(value.wrapping_add_signed(addend))
                }
                AbstractValueKind::PointerSlot(value) if rhs == 0 => {
                    AbstractValueKind::PointerSlot(value)
                }
                AbstractValueKind::DynamicSlot(value) => {
                    AbstractValueKind::DynamicSlot(value.saturating_add(addend))
                }
                AbstractValueKind::StackAddress(value) => {
                    AbstractValueKind::StackAddress(value.saturating_add(addend))
                }
                AbstractValueKind::HeapAddress { allocation, offset } => {
                    AbstractValueKind::HeapAddress {
                        allocation,
                        offset: offset.saturating_add(addend),
                    }
                }
                _ => continue,
            };
            result.insert(AbstractValue {
                kind,
                authentication: None,
                instruction: instruction.address,
            });
        }
    }
    Some(result)
}

fn transform_register_values(
    values: &BTreeSet<AbstractValue>,
    instruction: u64,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
    transform: impl Fn(u64) -> u64,
) -> Option<BTreeSet<AbstractValue>> {
    let mut result = BTreeSet::new();
    for value in values {
        if !work_budget.consume(1) {
            *truncated = true;
            break;
        }
        let kind = match value.kind {
            AbstractValueKind::Address(address) => AbstractValueKind::Address(transform(address)),
            AbstractValueKind::PointerSlot(address) => {
                AbstractValueKind::PointerSlot(transform(address))
            }
            AbstractValueKind::HeapAddress { allocation, offset } => {
                AbstractValueKind::HeapAddress {
                    allocation,
                    offset: transform(offset as u64) as i64,
                }
            }
            AbstractValueKind::DynamicSlot(_)
            | AbstractValueKind::StackAddress(_)
            | AbstractValueKind::Argument(_)
            | AbstractValueKind::ProtocolArgument { .. } => continue,
        };
        result.insert(AbstractValue {
            kind,
            authentication: None,
            instruction,
        });
    }
    (!result.is_empty()).then_some(result)
}

fn source_values(
    state: &RegisterValues,
    memory: &MemoryValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
) -> Option<BTreeSet<AbstractValue>> {
    match instruction.operands.get(1)? {
        ControlFlowOperand::Register { register }
        | ControlFlowOperand::ShiftedRegister { register, .. } => {
            state.get(register).map(|values| values.as_ref().clone())
        }
        ControlFlowOperand::Memory { .. } | ControlFlowOperand::IndexedMemory { .. } => {
            let mut values = BTreeSet::new();
            for location in memory_locations(state, instruction, architecture) {
                values.extend(memory_values_at(memory, location));
            }
            (!values.is_empty()).then_some(values)
        }
        ControlFlowOperand::Immediate { .. } => None,
    }
}

fn extend_integer(value: u64, bits: u8, signed: bool) -> u64 {
    let mask = (1_u64 << bits) - 1;
    let value = value & mask;
    if signed && value & (1_u64 << (bits - 1)) != 0 {
        value | !mask
    } else {
        value
    }
}

fn pointer_authentication_key(effect: ControlFlowValueEffect) -> Option<u8> {
    match effect {
        ControlFlowValueEffect::SignPointerIa | ControlFlowValueEffect::AuthenticatePointerIa => {
            Some(0)
        }
        ControlFlowValueEffect::SignPointerIb | ControlFlowValueEffect::AuthenticatePointerIb => {
            Some(1)
        }
        ControlFlowValueEffect::SignPointerDa | ControlFlowValueEffect::AuthenticatePointerDa => {
            Some(2)
        }
        ControlFlowValueEffect::SignPointerDb | ControlFlowValueEffect::AuthenticatePointerDb => {
            Some(3)
        }
        _ => None,
    }
}

fn apply_shift(value: u64, shift: ControlFlowRegisterShift, amount: u8) -> u64 {
    let amount = u32::from(amount) & 63;
    match shift {
        ControlFlowRegisterShift::LogicalLeft => value.wrapping_shl(amount),
        ControlFlowRegisterShift::LogicalRight => value.wrapping_shr(amount),
        ControlFlowRegisterShift::ArithmeticRight => ((value as i64) >> amount) as u64,
        ControlFlowRegisterShift::RotateRight => value.rotate_right(amount),
    }
}

fn apply_memory_effect(
    state: &RegisterValues,
    memory: &mut MemoryValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
    maximum: usize,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) {
    match instruction.memory_effect {
        ControlFlowMemoryEffect::None => {}
        ControlFlowMemoryEffect::UnknownWrite => memory.clear(),
        ControlFlowMemoryEffect::Store => {
            let locations = memory_locations(state, instruction, architecture);
            if locations.is_empty() {
                memory.clear();
                return;
            }
            let source = match architecture {
                Architecture::X86_64 => instruction.operands.get(1),
                Architecture::Arm64 | Architecture::Arm64e => instruction.operands.first(),
            }
            .and_then(|operand| match operand {
                ControlFlowOperand::Register { register } => state.get(register),
                _ => None,
            });
            let Some(source) = source else {
                for location in locations {
                    invalidate_memory_location(memory, location);
                }
                return;
            };
            for location in locations {
                if !work_budget.consume(source.len() as u64) {
                    *truncated = true;
                    return;
                }
                let values = source
                    .iter()
                    .copied()
                    .take(maximum)
                    .collect::<BTreeSet<_>>();
                if source.len() > maximum {
                    *truncated = true;
                }
                invalidate_memory_location(memory, location);
                memory.insert(location, Arc::new(values));
            }
        }
    }
}

fn memory_locations(
    state: &RegisterValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
) -> BTreeSet<AbstractMemoryLocation> {
    let mut result = BTreeSet::new();
    if let Some(relative) = instruction.pc_relative
        && relative.kind == ControlFlowPcRelativeKind::Memory
    {
        result.insert(AbstractMemoryLocation::Global(relative.address));
    }
    for operand in &instruction.operands {
        let (base, index, scale, displacement) = match operand {
            ControlFlowOperand::Memory { base, displacement } => (*base, None, 1_u8, *displacement),
            ControlFlowOperand::IndexedMemory {
                base,
                index,
                scale,
                displacement,
            } => (*base, Some(*index), *scale, *displacement),
            _ => continue,
        };
        if architecture_matches_x86(architecture) && base.number == 16 {
            result.insert(AbstractMemoryLocation::Global(
                instruction
                    .address
                    .wrapping_add(u64::from(instruction.byte_len))
                    .wrapping_add_signed(displacement),
            ));
            continue;
        }
        let index_offsets = index
            .and_then(|register| state.get(&register))
            .map(|values| {
                values
                    .iter()
                    .filter_map(|value| match value.kind {
                        AbstractValueKind::Address(value) => {
                            Some(value.wrapping_mul(u64::from(scale)))
                        }
                        _ => None,
                    })
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_else(|| BTreeSet::from([0]));
        if let Some(values) = state.get(&base) {
            for value in values.iter() {
                if index.is_some() && index_offsets.is_empty() {
                    if let Some(base) = abstract_memory_base(value.kind) {
                        result.insert(AbstractMemoryLocation::IndexedAlias {
                            base,
                            displacement,
                            scale: scale.max(1),
                        });
                    }
                    continue;
                }
                for index_offset in &index_offsets {
                    match value.kind {
                        AbstractValueKind::Address(address) => {
                            result.insert(AbstractMemoryLocation::Global(
                                address
                                    .wrapping_add(*index_offset)
                                    .wrapping_add_signed(displacement),
                            ));
                        }
                        AbstractValueKind::StackAddress(offset) => {
                            result.insert(AbstractMemoryLocation::Stack(
                                offset
                                    .saturating_add(*index_offset as i64)
                                    .saturating_add(displacement),
                            ));
                        }
                        AbstractValueKind::HeapAddress { allocation, offset } => {
                            result.insert(AbstractMemoryLocation::Heap {
                                allocation,
                                offset: offset
                                    .saturating_add(*index_offset as i64)
                                    .saturating_add(displacement),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    result
}

fn abstract_memory_base(kind: AbstractValueKind) -> Option<AbstractMemoryBase> {
    match kind {
        AbstractValueKind::Address(address) => Some(AbstractMemoryBase::Global(address)),
        AbstractValueKind::StackAddress(offset) => Some(AbstractMemoryBase::Stack(offset)),
        AbstractValueKind::HeapAddress { allocation, offset } => {
            Some(AbstractMemoryBase::Heap { allocation, offset })
        }
        _ => None,
    }
}

fn memory_values_at(
    memory: &MemoryValues,
    location: AbstractMemoryLocation,
) -> BTreeSet<AbstractValue> {
    let mut values = memory
        .get(&location)
        .map_or_else(BTreeSet::new, |values| values.as_ref().clone());
    for (candidate, retained) in memory {
        if matches!(candidate, AbstractMemoryLocation::IndexedAlias { .. })
            && alias_may_contain(*candidate, location)
        {
            values.extend(retained.iter().copied());
        }
    }
    values
}

fn invalidate_memory_location(memory: &mut MemoryValues, location: AbstractMemoryLocation) {
    match location {
        AbstractMemoryLocation::IndexedAlias { .. } => {
            memory.retain(|candidate, _| !alias_may_contain(location, *candidate));
        }
        _ => {
            memory.remove(&location);
        }
    }
}

fn alias_may_contain(alias: AbstractMemoryLocation, location: AbstractMemoryLocation) -> bool {
    let AbstractMemoryLocation::IndexedAlias {
        base,
        displacement,
        scale,
    } = alias
    else {
        return alias == location;
    };
    if matches!(location, AbstractMemoryLocation::IndexedAlias { .. }) {
        return alias == location;
    }
    let delta = match (base, location) {
        (AbstractMemoryBase::Stack(base), AbstractMemoryLocation::Stack(offset)) => {
            offset.saturating_sub(base).saturating_sub(displacement)
        }
        (AbstractMemoryBase::Global(base), AbstractMemoryLocation::Global(address)) => {
            let Some(delta) = address.checked_sub(base) else {
                return false;
            };
            (delta as i64).saturating_sub(displacement)
        }
        (
            AbstractMemoryBase::Heap {
                allocation: left,
                offset: base,
            },
            AbstractMemoryLocation::Heap {
                allocation: right,
                offset,
            },
        ) if left == right => offset.saturating_sub(base).saturating_sub(displacement),
        _ => return false,
    };
    delta >= 0 && delta % i64::from(scale.max(1)) == 0
}

fn merge_memory(
    destination: &mut MemoryValues,
    source: &MemoryValues,
    maximum: usize,
    truncated: &mut bool,
    widening_limit: Option<usize>,
    widened: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) -> bool {
    let aliases_before = destination.len();
    if widening_limit.is_some() {
        destination.retain(|location, _| {
            !matches!(
                location,
                AbstractMemoryLocation::Heap { .. } | AbstractMemoryLocation::IndexedAlias { .. }
            )
        });
        if destination.len() != aliases_before {
            *widened = true;
        }
    }
    let prior = destination.len();
    destination.retain(|location, _| source.contains_key(location));
    let mut changed = prior != destination.len() || destination.len() != aliases_before;
    let mut widened_locations = Vec::new();
    for (location, values) in destination.iter_mut() {
        let incoming = &source[location];
        for value in incoming.iter() {
            if !work_budget.consume(1) {
                *truncated = true;
                return changed;
            }
            if values.len() == maximum && !values.contains(value) {
                *truncated = true;
                continue;
            }
            changed |= Arc::make_mut(values).insert(*value);
            if widening_limit.is_some_and(|limit| values.len() > limit) {
                widened_locations.push(*location);
                *widened = true;
                changed = true;
                break;
            }
        }
    }
    for location in widened_locations {
        destination.remove(&location);
    }
    changed
}

#[allow(clippy::too_many_arguments)]
fn merge_state_changes(
    destination: &mut RegisterValues,
    source: &RegisterValues,
    maximum: usize,
    truncated: &mut bool,
    widening_limit: Option<usize>,
    widened: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) -> BTreeSet<ControlFlowRegister> {
    let prior = destination.clone();
    merge_state(
        destination,
        source,
        maximum,
        truncated,
        widening_limit,
        widened,
        work_budget,
    );
    state_changes(&prior, destination)
}

fn merge_state(
    destination: &mut RegisterValues,
    source: &RegisterValues,
    maximum: usize,
    truncated: &mut bool,
    widening_limit: Option<usize>,
    widened: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) -> bool {
    let prior_register_count = destination.len();
    destination.retain(|register, _| source.contains_key(register));
    let mut changed = destination.len() != prior_register_count;
    let mut widened_registers = Vec::new();
    for (register, retained) in destination.iter_mut() {
        let values = source
            .get(register)
            .expect("join retained only registers known on every path");
        if widening_limit.is_some_and(|limit| retained.len() > limit) {
            widened_registers.push(*register);
            continue;
        }
        for value in values.iter() {
            if !work_budget.consume(1) {
                *truncated = true;
                return changed;
            }
            if widening_limit
                .is_some_and(|limit| !retained.contains(value) && retained.len() == limit)
            {
                widened_registers.push(*register);
                break;
            }
            if retained.len() == maximum && !retained.contains(value) {
                *truncated = true;
                continue;
            }
            changed |= Arc::make_mut(retained).insert(*value);
        }
    }
    for register in widened_registers {
        changed |= destination.remove(&register).is_some();
        *widened = true;
    }
    changed
}

#[allow(clippy::too_many_arguments)]
fn record_observation_state(
    observations: &mut BTreeMap<u64, RegisterValues>,
    memory_observations: &mut BTreeMap<u64, MemoryValues>,
    address: u64,
    state: &RegisterValues,
    memory: &MemoryValues,
    maximum: usize,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) {
    if let Some(existing) = observations.get_mut(&address) {
        let mut widened = false;
        merge_state(
            existing,
            state,
            maximum,
            truncated,
            None,
            &mut widened,
            work_budget,
        );
    } else if work_budget.consume(register_value_count(state)) {
        observations.insert(address, state.clone());
    } else {
        *truncated = true;
    }
    if let Some(existing) = memory_observations.get_mut(&address) {
        let mut widened = false;
        merge_memory(
            existing,
            memory,
            maximum,
            truncated,
            None,
            &mut widened,
            work_budget,
        );
    } else if work_budget.consume(memory.len() as u64) {
        memory_observations.insert(address, memory.clone());
    } else {
        *truncated = true;
    }
}

fn caller_saved(architecture: Architecture, register: ControlFlowRegister) -> bool {
    if register.class != ControlFlowRegisterClass::GeneralPurpose {
        return true;
    }
    match architecture {
        Architecture::X86_64 => matches!(register.number, 0 | 1 | 2 | 6..=11),
        Architecture::Arm64 | Architecture::Arm64e => {
            register.number <= 18 || register.number == 30
        }
    }
}

struct ValueCandidateContext<'a, 'data> {
    macho: &'a MachoFile<'data>,
    functions: &'a FunctionIndex,
    graph: &'a FunctionControlFlow,
    state: Option<&'a RegisterValues>,
    memory: Option<&'a MemoryValues>,
    architecture: Architecture,
    catalog: &'a Catalog,
    instruction_authentication: Option<PointerAuthentication>,
}

#[allow(clippy::too_many_arguments)]
fn recover_site(
    macho: &MachoFile<'_>,
    functions: &FunctionIndex,
    graph: &FunctionControlFlow,
    instruction: &ControlFlowInstruction,
    block: u64,
    base_kind: IndirectTransferKind,
    direct_stub: Option<u64>,
    state: Option<&RegisterValues>,
    memory: Option<&MemoryValues>,
    catalog: &Catalog,
    architecture: Architecture,
    maximum_candidates: usize,
    value_flow_truncated: bool,
    value_flow_widened: bool,
) -> RecoveredIndirectCall {
    let reachability = graph
        .blocks
        .get(block as usize)
        .filter(|candidate| candidate.id == block)
        .map_or(ControlFlowReachability::Unknown, |block| block.reachability);
    let instruction_authentication = instruction_authentication(macho, instruction, architecture);
    let mut kinds = vec![if direct_stub.is_some() {
        IndirectTransferKind::ImportStubCall
    } else {
        base_kind
    }];
    let mut carriers = Vec::new();
    let mut candidates = Vec::new();
    let mut reasons = BTreeSet::<String>::new();
    let mut dynamic_dispatch_open = false;
    let value_candidate_context = ValueCandidateContext {
        macho,
        functions,
        graph,
        state,
        memory,
        architecture,
        catalog,
        instruction_authentication,
    };

    if let Some(stub) = direct_stub {
        carriers.push(IndirectTargetCarrier::ImportStub { address: stub });
        add_slot_candidates(
            macho,
            functions,
            stub,
            catalog,
            instruction_authentication,
            &mut candidates,
        );
    } else {
        let record_table =
            static_record_lookup_table(macho, functions, graph, instruction, catalog, architecture);
        if let Some((address, stride, entry_count)) = record_table {
            carriers.push(IndirectTargetCarrier::StridedPointerTable {
                address,
                stride,
                entry_count,
            });
            for index in 0..entry_count {
                let Some(slot) = index
                    .checked_mul(stride)
                    .and_then(|offset| address.checked_add(offset))
                else {
                    break;
                };
                add_slot_candidates(
                    macho,
                    functions,
                    slot,
                    catalog,
                    instruction_authentication,
                    &mut candidates,
                );
            }
        }
        let target_register = instruction
            .operands
            .first()
            .and_then(|operand| match operand {
                ControlFlowOperand::Register { register } => Some(*register),
                _ => None,
            });
        if let Some(register) = target_register {
            carriers.push(IndirectTargetCarrier::Register { register });
            let strided_table = record_table.or_else(|| {
                graph
                    .instructions
                    .binary_search_by_key(&instruction.address, |candidate| candidate.address)
                    .ok()
                    .and_then(|index| {
                        static_strided_pointer_table(macho, graph, index, register, architecture)
                    })
            });
            if record_table.is_some() {
                // The cross-block record lookup already supplied the exact
                // callback field set.  Merged register histories are a less
                // precise superset and must not dilute that proof.
            } else if let Some((address, stride, entry_count)) = strided_table {
                carriers.push(IndirectTargetCarrier::StridedPointerTable {
                    address,
                    stride,
                    entry_count,
                });
                for index in 0..entry_count {
                    let Some(slot) = index
                        .checked_mul(stride)
                        .and_then(|offset| address.checked_add(offset))
                    else {
                        break;
                    };
                    add_slot_candidates(
                        macho,
                        functions,
                        slot,
                        catalog,
                        instruction_authentication,
                        &mut candidates,
                    );
                }
            } else if let Some(values) = state.and_then(|state| state.get(&register)) {
                for value in values.iter() {
                    add_value_candidates(
                        &value_candidate_context,
                        *value,
                        &mut carriers,
                        &mut candidates,
                    );
                }
            }
        }
        if let Some(ControlFlowOperand::Memory { base, displacement }) =
            instruction.operands.first()
        {
            let slot = if architecture_matches_x86(architecture) && base.number == 16 {
                Some(
                    instruction
                        .address
                        .wrapping_add(u64::from(instruction.byte_len))
                        .wrapping_add_signed(*displacement),
                )
            } else {
                None
            };
            if let Some(slot) = slot {
                carriers.push(IndirectTargetCarrier::PointerSlot { address: slot });
                add_slot_candidates(
                    macho,
                    functions,
                    slot,
                    catalog,
                    instruction_authentication,
                    &mut candidates,
                );
            } else {
                carriers.push(IndirectTargetCarrier::DynamicMemory {
                    base: Some(*base),
                    displacement: *displacement,
                });
                let tracked = memory
                    .map(|memory| {
                        state
                            .map(|state| memory_locations(state, instruction, architecture))
                            .unwrap_or_default()
                            .into_iter()
                            .flat_map(|location| memory_values_at(memory, location))
                            .map(|mut value| {
                                value.instruction = instruction.address;
                                value
                            })
                            .collect::<BTreeSet<_>>()
                    })
                    .unwrap_or_default();
                if !tracked.is_empty() {
                    for value in tracked {
                        add_value_candidates(
                            &value_candidate_context,
                            value,
                            &mut carriers,
                            &mut candidates,
                        );
                    }
                } else {
                    let concrete = concrete_base_addresses(macho, state, *base, None)
                        .into_iter()
                        .map(|address| address.wrapping_add_signed(*displacement))
                        .collect::<BTreeSet<_>>();
                    if concrete.is_empty() {
                        add_dynamic_slot_candidates(
                            functions,
                            *displacement,
                            catalog,
                            &mut candidates,
                        );
                    } else {
                        for slot in concrete {
                            carriers.push(IndirectTargetCarrier::PointerSlot { address: slot });
                            add_slot_candidates(
                                macho,
                                functions,
                                slot,
                                catalog,
                                instruction_authentication,
                                &mut candidates,
                            );
                        }
                    }
                }
            }
        }
        if let Some(table) = graph
            .jump_tables
            .iter()
            .find(|table| table.instruction_address == instruction.address)
        {
            let confidence = if table.range.is_some()
                && !table.truncated
                && graph.completeness.status == FunctionControlFlowStatus::Complete
            {
                FunctionEvidenceConfidence::Derived
            } else {
                FunctionEvidenceConfidence::Candidate
            };
            carriers.push(IndirectTargetCarrier::JumpTable {
                address: table.table_address,
            });
            for entry in &table.entries {
                candidates.push(IndirectCallCandidate {
                    target: IndirectCallTarget::Internal {
                        address: entry.target,
                        functions: function_candidates(functions, entry.target),
                    },
                    source: IndirectCallEvidenceSource::JumpTable,
                    confidence,
                    evidence_address: Some(entry.entry_address),
                    authentication: None,
                    detail: "bounded_jump_table_entry".into(),
                });
            }
        }
        if carriers.is_empty() {
            carriers.push(IndirectTargetCarrier::Unknown);
        }
    }

    let imports_objc = candidates.iter().any(|candidate| {
        matches!(
            &candidate.target,
            IndirectCallTarget::Import { name, .. }
                if name.trim_start_matches('_').starts_with("objc_msgSend")
        )
    });
    if base_kind == IndirectTransferKind::Call
        && carriers
            .iter()
            .any(|carrier| matches!(carrier, IndirectTargetCarrier::ImportStub { .. }))
        && candidates
            .iter()
            .any(|candidate| matches!(&candidate.target, IndirectCallTarget::Import { .. }))
    {
        kinds.push(IndirectTransferKind::ImportStubCall);
    }
    if imports_objc {
        kinds.push(IndirectTransferKind::ObjectiveCDispatch);
        let selectors = selector_candidates(macho, state, architecture.selector_register());
        let super_dispatch = candidates.iter().any(|candidate| matches!(&candidate.target, IndirectCallTarget::Import { name, .. } if name.trim_start_matches('_').starts_with("objc_msgSendSuper")));
        let receiver_targets = if super_dispatch {
            let values =
                objc_super_receiver_values(macho, state, memory, architecture.receiver_register());
            objc_receiver_targets_from_class_values(macho, &values, catalog)
        } else {
            objc_receiver_targets(
                macho,
                state,
                memory,
                architecture.receiver_register(),
                catalog,
            )
        };
        let protocol_qualified_receiver = !super_dispatch
            && objc_receiver_protocols(state, architecture.receiver_register(), catalog).is_some();
        let mut matched = 0_u64;
        for method in &catalog.objc_methods {
            if !selectors.is_empty() && !selectors.contains(&method.selector) {
                continue;
            }
            if !receiver_targets.is_empty()
                && !receiver_targets.contains(&(method.class_name.clone(), method.class_method))
            {
                continue;
            }
            candidates.push(IndirectCallCandidate {
                target: IndirectCallTarget::ObjectiveCMethod {
                    class_name: method.class_name.clone(),
                    selector: method.selector.clone(),
                    class_method: method.class_method,
                    implementation: method.implementation,
                    functions: function_candidates(functions, method.implementation),
                },
                source: IndirectCallEvidenceSource::ObjectiveC,
                confidence: if selectors.contains(&method.selector) {
                    FunctionEvidenceConfidence::Derived
                } else {
                    FunctionEvidenceConfidence::Candidate
                },
                evidence_address: Some(method.implementation),
                authentication: None,
                detail: if selectors.is_empty() {
                    "objc_selector_unresolved"
                } else if super_dispatch && !receiver_targets.is_empty() {
                    "objc_super_layout_hierarchy_match"
                } else if !receiver_targets.is_empty() {
                    if protocol_qualified_receiver {
                        "objc_protocol_qualified_receiver_match"
                    } else {
                        "objc_selector_receiver_hierarchy_match"
                    }
                } else {
                    "objc_selector_match"
                }
                .into(),
            });
            matched = matched.saturating_add(1);
        }
        if selectors.is_empty() {
            reasons.insert("indirect.objc_selector_unresolved".into());
            dynamic_dispatch_open = true;
        } else if matched == 0 {
            reasons.insert("indirect.objc_selector_without_implementation".into());
            dynamic_dispatch_open = true;
        }
        if receiver_targets.is_empty() {
            reasons.insert("indirect.objc_receiver_unresolved".into());
            dynamic_dispatch_open = true;
        }
        if super_dispatch && receiver_targets.is_empty() {
            reasons.insert("indirect.objc_super_runtime_open".into());
        }
        if matched > 1 && receiver_targets.is_empty() {
            reasons.insert("indirect.objc_dispatch_ambiguous".into());
        }
    }
    if candidates
        .iter()
        .any(|candidate| candidate.detail.starts_with("swift_runtime_instantiated_"))
    {
        reasons.insert("indirect.swift_runtime_instantiation_open".into());
    }
    if candidates.iter().any(|candidate| {
        matches!(
            &candidate.target,
            IndirectCallTarget::CppVirtualMethod { .. }
                | IndirectCallTarget::CppVirtualMethodImport { .. }
        )
    }) {
        kinds.push(IndirectTransferKind::CppVirtualDispatch);
    }
    if candidates.iter().any(|candidate| {
        matches!(
            &candidate.target,
            IndirectCallTarget::SwiftImplementation { .. }
                | IndirectCallTarget::SwiftProtocolWitness { .. }
                | IndirectCallTarget::SwiftProtocolWitnessImport { .. }
        )
    }) {
        kinds.push(IndirectTransferKind::SwiftDispatch);
    }
    if candidates.iter().any(|candidate| {
        matches!(
            &candidate.target,
            IndirectCallTarget::BlockInvoke { .. } | IndirectCallTarget::BlockInvokeImport { .. }
        )
    }) {
        kinds.push(IndirectTransferKind::BlockInvoke);
    }
    if candidates
        .iter()
        .any(|candidate| matches!(&candidate.target, IndirectCallTarget::SwiftClosure { .. }))
    {
        kinds.push(IndirectTransferKind::SwiftClosureDispatch);
    }
    reconcile_import_aliases(&mut candidates);
    candidates.sort_by(|left, right| {
        (
            &left.target,
            left.source,
            left.evidence_address,
            &left.detail,
        )
            .cmp(&(
                &right.target,
                right.source,
                right.evidence_address,
                &right.detail,
            ))
    });
    candidates.dedup();
    let conflicts = indirect_conflicts(&candidates);
    let missing_function_identity = candidates.iter().any(|candidate| match &candidate.target {
        IndirectCallTarget::Import { .. }
        | IndirectCallTarget::CppVirtualMethodImport { .. }
        | IndirectCallTarget::SwiftProtocolWitnessImport { .. }
        | IndirectCallTarget::BlockInvokeImport { .. } => false,
        IndirectCallTarget::Internal { functions, .. }
        | IndirectCallTarget::ObjectiveCMethod { functions, .. }
        | IndirectCallTarget::SwiftImplementation { functions, .. }
        | IndirectCallTarget::CppVirtualMethod { functions, .. }
        | IndirectCallTarget::SwiftProtocolWitness { functions, .. }
        | IndirectCallTarget::SwiftClosure { functions, .. }
        | IndirectCallTarget::BlockInvoke { functions, .. } => functions.is_empty(),
    });
    let uncertain_function_ownership = candidates
        .iter()
        .any(|candidate| target_has_uncertain_function_ownership(&candidate.target));
    let omitted_candidate_count = candidates.len().saturating_sub(maximum_candidates) as u64;
    candidates.truncate(maximum_candidates);
    if candidates.is_empty() {
        reasons.insert("indirect.target_unresolved".into());
    }
    if omitted_candidate_count != 0 {
        reasons.insert("indirect.candidate_budget".into());
    }
    if reachability == ControlFlowReachability::Unknown {
        reasons.insert("indirect.reachability_unknown".into());
    } else if reachability == ControlFlowReachability::Unreachable {
        reasons.insert("indirect.unreachable_source".into());
    }
    if graph.completeness.status != FunctionControlFlowStatus::Complete {
        reasons.insert("indirect.source_control_flow_incomplete".into());
    }
    if value_flow_truncated {
        reasons.insert("indirect.value_flow_budget".into());
    }
    let site_value_flow_widened = value_flow_widened
        && direct_stub.is_none()
        && (candidates.iter().any(|candidate| {
            matches!(
                candidate.source,
                IndirectCallEvidenceSource::InstructionValueFlow
                    | IndirectCallEvidenceSource::RawPointer
            )
        }) || candidates.is_empty());
    if site_value_flow_widened {
        reasons.insert("indirect.value_flow_widened".into());
    }
    if !conflicts.is_empty() {
        reasons.insert("indirect.evidence_conflict".into());
    }
    if missing_function_identity {
        reasons.insert("indirect.target_without_function_identity".into());
    }
    if uncertain_function_ownership {
        reasons.insert("indirect.function_ownership_uncertain".into());
    }
    if dynamic_dispatch_open {
        reasons.insert("indirect.objc_runtime_dispatch_open".into());
    }
    let status = if omitted_candidate_count != 0 || value_flow_truncated {
        IndirectCallSiteStatus::Truncated
    } else if candidates.is_empty()
        || !conflicts.is_empty()
        || missing_function_identity
        || uncertain_function_ownership
        || dynamic_dispatch_open
        || site_value_flow_widened
        || reachability == ControlFlowReachability::Unknown
        || graph.completeness.status != FunctionControlFlowStatus::Complete
        || candidates
            .iter()
            .any(|candidate| candidate.confidence == FunctionEvidenceConfidence::Candidate)
    {
        IndirectCallSiteStatus::Partial
    } else {
        IndirectCallSiteStatus::Complete
    };
    kinds.sort_by_key(|kind| *kind as u8);
    kinds.dedup();
    carriers.sort();
    carriers.dedup();
    RecoveredIndirectCall {
        source_function: graph.function_entry,
        block,
        instruction_address: instruction.address,
        kinds,
        carriers,
        reachability,
        candidates,
        conflicts,
        omitted_candidate_count,
        value_flow_truncated,
        value_flow_widened: site_value_flow_widened,
        status,
        reasons: reasons.into_iter().collect(),
    }
}

fn reconcile_import_aliases(candidates: &mut [IndirectCallCandidate]) {
    let observations = candidates
        .iter()
        .filter_map(|candidate| {
            let IndirectCallTarget::Import {
                name,
                library_ordinal,
            } = &candidate.target
            else {
                return None;
            };
            (!name.is_empty()).then(|| (candidate.evidence_address, *library_ordinal, name.clone()))
        })
        .collect::<Vec<_>>();
    for candidate in candidates {
        let IndirectCallTarget::Import {
            name,
            library_ordinal,
        } = &mut candidate.target
        else {
            continue;
        };
        if name.is_empty() {
            let aliases = observations
                .iter()
                .filter(|(address, ordinal, _)| {
                    *address == candidate.evidence_address
                        && (library_ordinal.is_none()
                            || ordinal.is_none()
                            || ordinal == library_ordinal)
                })
                .map(|(_, _, alias)| alias.clone())
                .collect::<BTreeSet<_>>();
            if aliases.len() == 1 {
                name.clone_from(aliases.first().expect("one import alias"));
            }
        }
        if library_ordinal.is_none() && !name.is_empty() {
            let ordinals = observations
                .iter()
                .filter(|(address, _, alias)| {
                    *address == candidate.evidence_address && alias == name
                })
                .filter_map(|(_, ordinal, _)| *ordinal)
                .collect::<BTreeSet<_>>();
            if ordinals.len() == 1 {
                *library_ordinal = ordinals.first().copied();
            }
        }
    }
}

fn target_has_uncertain_function_ownership(target: &IndirectCallTarget) -> bool {
    let functions = match target {
        IndirectCallTarget::Import { .. }
        | IndirectCallTarget::CppVirtualMethodImport { .. }
        | IndirectCallTarget::SwiftProtocolWitnessImport { .. }
        | IndirectCallTarget::BlockInvokeImport { .. } => return false,
        IndirectCallTarget::Internal { functions, .. }
        | IndirectCallTarget::ObjectiveCMethod { functions, .. }
        | IndirectCallTarget::SwiftImplementation { functions, .. }
        | IndirectCallTarget::CppVirtualMethod { functions, .. }
        | IndirectCallTarget::SwiftProtocolWitness { functions, .. }
        | IndirectCallTarget::SwiftClosure { functions, .. }
        | IndirectCallTarget::BlockInvoke { functions, .. } => functions,
    };
    !functions.is_empty()
        && (functions.len() != 1
            || functions.iter().any(|function| {
                function.entry_confidence == FunctionEvidenceConfidence::Candidate
                    || function.ownership_confidence == FunctionOwnershipConfidence::Candidate
            }))
}

fn indirect_conflicts(candidates: &[IndirectCallCandidate]) -> Vec<IndirectCallConflict> {
    let mut by_address = BTreeMap::<
        u64,
        (
            BTreeSet<IndirectCallTarget>,
            BTreeSet<IndirectCallEvidenceSource>,
        ),
    >::new();
    for candidate in candidates {
        if !matches!(
            candidate.source,
            IndirectCallEvidenceSource::IndirectSymbols
                | IndirectCallEvidenceSource::LegacyBind
                | IndirectCallEvidenceSource::LegacyRebase
                | IndirectCallEvidenceSource::ChainedFixup
                | IndirectCallEvidenceSource::Relocation
                | IndirectCallEvidenceSource::RawPointer
                | IndirectCallEvidenceSource::CppVtable
                | IndirectCallEvidenceSource::Swift
                | IndirectCallEvidenceSource::BlockClosure
        ) {
            continue;
        }
        let Some(address) = candidate.evidence_address else {
            continue;
        };
        let record = by_address.entry(address).or_default();
        record.0.insert(candidate.target.clone());
        record.1.insert(candidate.source);
    }
    by_address
        .into_iter()
        .filter_map(|(evidence_address, (targets, sources))| {
            (targets.len() > 1).then(|| IndirectCallConflict {
                evidence_address,
                targets: targets.into_iter().collect(),
                sources: sources.into_iter().collect(),
            })
        })
        .collect()
}

fn add_value_candidates(
    context: &ValueCandidateContext<'_, '_>,
    value: AbstractValue,
    carriers: &mut Vec<IndirectTargetCarrier>,
    candidates: &mut Vec<IndirectCallCandidate>,
) {
    let macho = context.macho;
    let functions = context.functions;
    let graph = context.graph;
    let state = context.state;
    let memory = context.memory;
    let architecture = context.architecture;
    let catalog = context.catalog;
    let instruction_authentication = context.instruction_authentication;
    let authentication = merge_authentication(value.authentication, instruction_authentication);
    let origin_locations =
        value_origin_memory_locations(graph, state, value.instruction, architecture);
    let dynamic_blocks = memory
        .into_iter()
        .flat_map(|memory| {
            abstract_value_static_targets(macho, &value, catalog)
                .into_iter()
                .flat_map(|implementation| {
                    dynamic_block_dispatches(
                        macho,
                        memory,
                        catalog,
                        graph.function_entry,
                        &implementation,
                        authentication,
                        &origin_locations,
                    )
                })
        })
        .collect::<BTreeSet<_>>();
    if !dynamic_blocks.is_empty() {
        for record in dynamic_blocks {
            candidates.push(block_dispatch_candidate(
                functions,
                &record,
                FunctionEvidenceConfidence::Derived,
                None,
            ));
        }
        return;
    }
    match value.kind {
        AbstractValueKind::Address(address) => {
            let is_import_stub = catalog.slots.get(&address).is_some_and(|evidence| {
                evidence.iter().any(|record| record.detail == "symbol_stub")
            });
            if is_import_stub {
                carriers.push(IndirectTargetCarrier::ImportStub { address });
                add_slot_candidates(
                    macho,
                    functions,
                    address,
                    catalog,
                    authentication,
                    candidates,
                );
            } else {
                candidates.push(internal_candidate(
                    functions,
                    address,
                    IndirectCallEvidenceSource::InstructionValueFlow,
                    FunctionEvidenceConfidence::Derived,
                    Some(value.instruction),
                    authentication,
                    "materialized_address",
                ));
            }
        }
        AbstractValueKind::PointerSlot(address) => {
            carriers.push(IndirectTargetCarrier::PointerSlot { address });
            add_slot_candidates(
                macho,
                functions,
                address,
                catalog,
                authentication,
                candidates,
            );
        }
        AbstractValueKind::DynamicSlot(displacement) => {
            carriers.push(IndirectTargetCarrier::DynamicMemory {
                base: None,
                displacement,
            });
            let concrete = concrete_dynamic_slots(macho, graph, state, value);
            if concrete.is_empty() {
                add_dynamic_slot_candidates(functions, displacement, catalog, candidates);
            } else {
                for slot in concrete {
                    carriers.push(IndirectTargetCarrier::PointerSlot { address: slot });
                    add_slot_candidates(
                        macho,
                        functions,
                        slot,
                        catalog,
                        authentication,
                        candidates,
                    );
                }
            }
        }
        AbstractValueKind::StackAddress(_)
        | AbstractValueKind::Argument(_)
        | AbstractValueKind::ProtocolArgument { .. }
        | AbstractValueKind::HeapAddress { .. } => {}
    }
}

fn concrete_dynamic_slots(
    macho: &MachoFile<'_>,
    graph: &FunctionControlFlow,
    state: Option<&RegisterValues>,
    value: AbstractValue,
) -> BTreeSet<u64> {
    let AbstractValueKind::DynamicSlot(displacement) = value.kind else {
        return BTreeSet::new();
    };
    let Some(instruction) = graph
        .instructions
        .binary_search_by_key(&value.instruction, |instruction| instruction.address)
        .ok()
        .and_then(|index| graph.instructions.get(index))
    else {
        return BTreeSet::new();
    };
    let Some(base) = instruction
        .operands
        .iter()
        .find_map(|operand| match operand {
            ControlFlowOperand::Memory { base, .. }
            | ControlFlowOperand::IndexedMemory { base, .. } => Some(*base),
            _ => None,
        })
    else {
        return BTreeSet::new();
    };
    concrete_base_addresses(macho, state, base, Some(value.instruction))
        .into_iter()
        .map(|address| address.wrapping_add_signed(displacement))
        .collect()
}

fn concrete_base_addresses(
    macho: &MachoFile<'_>,
    state: Option<&RegisterValues>,
    base: ControlFlowRegister,
    defined_no_later_than: Option<u64>,
) -> BTreeSet<u64> {
    state
        .and_then(|state| state.get(&base))
        .into_iter()
        .flat_map(|values| values.iter())
        .filter(|value| {
            defined_no_later_than.is_none_or(|instruction| value.instruction <= instruction)
        })
        .filter_map(|value| match value.kind {
            AbstractValueKind::Address(address) => Some(address),
            AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
            _ => None,
        })
        .filter(|address| *address != 0)
        .collect()
}

fn add_slot_candidates(
    macho: &MachoFile<'_>,
    functions: &FunctionIndex,
    slot: u64,
    catalog: &Catalog,
    instruction_authentication: Option<PointerAuthentication>,
    candidates: &mut Vec<IndirectCallCandidate>,
) {
    let mut represented_raw_target = false;
    let specialized_targets = catalog
        .cpp_slots
        .get(&slot)
        .into_iter()
        .flatten()
        .map(|record| record.implementation.clone())
        .chain(
            catalog
                .swift_witness_slots
                .get(&slot)
                .into_iter()
                .flatten()
                .map(|record| record.implementation.clone()),
        )
        .chain(
            catalog
                .block_invoke_slots
                .get(&slot)
                .into_iter()
                .flatten()
                .map(|record| record.implementation.clone()),
        )
        .collect::<BTreeSet<_>>();
    if let Some(evidence) = catalog.slots.get(&slot) {
        for record in evidence {
            if specialized_targets.contains(&record.target) {
                represented_raw_target = true;
                continue;
            }
            if matches!(record.target, StaticTarget::Internal(target) if function_candidates(functions, target).is_empty())
            {
                continue;
            }
            let authentication =
                merge_authentication(record.authentication, instruction_authentication);
            if matches!(
                &record.target,
                StaticTarget::Internal(target) if read_pointer(macho, slot) == Some(*target)
            ) {
                represented_raw_target = true;
            }
            candidates.push(static_candidate(
                functions,
                record,
                Some(slot),
                authentication,
            ));
        }
    }
    if let Some(records) = catalog.cpp_slots.get(&slot) {
        for record in records {
            candidates.push(cpp_dispatch_candidate(functions, record, Some(slot)));
        }
    }
    if let Some(records) = catalog.swift_witness_slots.get(&slot) {
        for record in records {
            candidates.push(swift_witness_candidate(
                functions,
                record,
                FunctionEvidenceConfidence::Exact,
                Some(slot),
            ));
        }
    }
    if let Some(records) = catalog.block_invoke_slots.get(&slot) {
        for record in records {
            candidates.push(block_dispatch_candidate(
                functions,
                record,
                FunctionEvidenceConfidence::Exact,
                Some(slot),
            ));
        }
    }
    if let Some(raw) = read_pointer(macho, slot)
        && raw != 0
        && !represented_raw_target
        && !function_candidates(functions, raw).is_empty()
    {
        candidates.push(internal_candidate(
            functions,
            raw,
            IndirectCallEvidenceSource::RawPointer,
            FunctionEvidenceConfidence::Candidate,
            Some(slot),
            instruction_authentication,
            "raw_pointer_without_fixup",
        ));
    }
}

fn add_dynamic_slot_candidates(
    functions: &FunctionIndex,
    displacement: i64,
    catalog: &Catalog,
    candidates: &mut Vec<IndirectCallCandidate>,
) {
    if let Some(records) = catalog.cpp_offsets_agreed.get(&displacement) {
        for record in records {
            candidates.push(cpp_dispatch_candidate(functions, record, None));
        }
    }
    if let Some(records) = catalog.swift_witness_offsets.get(&displacement) {
        for record in records {
            candidates.push(swift_witness_candidate(
                functions,
                record,
                FunctionEvidenceConfidence::Candidate,
                None,
            ));
        }
    }
    if let Some(records) = catalog.swift_offsets.get(&displacement) {
        for record in records {
            if record.detail.starts_with("swift_witness:") {
                continue;
            }
            candidates.push(IndirectCallCandidate {
                target: IndirectCallTarget::SwiftImplementation {
                    slot: record.slot,
                    implementation: record.implementation,
                    functions: function_candidates(functions, record.implementation),
                    detail: record.detail.clone(),
                },
                source: IndirectCallEvidenceSource::Swift,
                confidence: FunctionEvidenceConfidence::Candidate,
                evidence_address: None,
                authentication: record.authentication,
                detail: if record.runtime_instantiated {
                    "swift_runtime_instantiated_slot_candidate"
                } else {
                    "dynamic_slot_offset_match"
                }
                .into(),
            });
        }
    }
    for record in &catalog.swift_unindexed {
        candidates.push(IndirectCallCandidate {
            target: IndirectCallTarget::SwiftImplementation {
                slot: record.slot,
                implementation: record.implementation,
                functions: function_candidates(functions, record.implementation),
                detail: record.detail.clone(),
            },
            source: IndirectCallEvidenceSource::Swift,
            confidence: FunctionEvidenceConfidence::Candidate,
            evidence_address: None,
            authentication: record.authentication,
            detail: if record.runtime_instantiated {
                "swift_runtime_instantiated_unindexed_candidate"
            } else {
                "unindexed_swift_override_candidate"
            }
            .into(),
        });
    }
    if let Some(records) = catalog.block_offsets.get(&displacement) {
        for record in records {
            candidates.push(block_dispatch_candidate(
                functions,
                record,
                FunctionEvidenceConfidence::Candidate,
                None,
            ));
        }
    }
}

fn swift_witness_authentication(
    provenance: &crate::metadata::swift::evidence::MachoSwiftWitnessPointerProvenanceV1,
) -> Option<PointerAuthentication> {
    use crate::metadata::swift::evidence::MachoSwiftWitnessPointerProvenanceV1::{
        ChainedAuthBind, ChainedAuthRebase,
    };

    let (diversity, key, address_diversity) = match provenance {
        ChainedAuthRebase {
            diversity,
            key,
            address_diversity,
        }
        | ChainedAuthBind {
            diversity,
            key,
            address_diversity,
        } => (*diversity, *key, *address_diversity),
        _ => return None,
    };
    Some(PointerAuthentication {
        key: Some(key),
        diversity: Some(diversity),
        address_diversity: Some(address_diversity),
        instruction_key: None,
        instruction_modifier: None,
        instruction_zero_modifier: None,
        authenticated_instruction: false,
    })
}

fn static_candidate(
    functions: &FunctionIndex,
    evidence: &StaticEvidence,
    address: Option<u64>,
    authentication: Option<PointerAuthentication>,
) -> IndirectCallCandidate {
    match &evidence.target {
        StaticTarget::Import { name, ordinal } => IndirectCallCandidate {
            target: IndirectCallTarget::Import {
                name: name.clone(),
                library_ordinal: *ordinal,
            },
            source: evidence.source,
            confidence: evidence.confidence,
            evidence_address: address,
            authentication,
            detail: evidence.detail.clone(),
        },
        StaticTarget::Internal(target) => internal_candidate(
            functions,
            *target,
            evidence.source,
            evidence.confidence,
            address,
            authentication,
            &evidence.detail,
        ),
    }
}

fn internal_candidate(
    functions: &FunctionIndex,
    address: u64,
    source: IndirectCallEvidenceSource,
    confidence: FunctionEvidenceConfidence,
    evidence_address: Option<u64>,
    authentication: Option<PointerAuthentication>,
    detail: &str,
) -> IndirectCallCandidate {
    let functions_for_target = function_candidates(functions, address);
    let target = if let Some((role, symbol, display)) = swift_closure_metadata(functions, address) {
        IndirectCallTarget::SwiftClosure {
            role,
            symbol,
            display,
            implementation: address,
            functions: functions_for_target,
        }
    } else {
        IndirectCallTarget::Internal {
            address,
            functions: functions_for_target,
        }
    };
    IndirectCallCandidate {
        target,
        source,
        confidence,
        evidence_address,
        authentication,
        detail: detail.into(),
    }
}

fn swift_closure_metadata(
    functions: &FunctionIndex,
    address: u64,
) -> Option<(SwiftClosureRole, String, String)> {
    let function = functions.by_entry(address)?;
    let FunctionIdentity::Named { primary, aliases } = &function.identity else {
        return None;
    };
    std::iter::once(primary).chain(aliases).find_map(|symbol| {
        let evidence = classify_swift_closure_symbol(symbol)?;
        let role = match evidence.kind {
            SwiftClosureSymbolKind::ClosureEntry => SwiftClosureRole::ClosureEntry,
            SwiftClosureSymbolKind::ReabstractionThunk => SwiftClosureRole::ReabstractionThunk,
            SwiftClosureSymbolKind::PartialApplyForwarder => {
                SwiftClosureRole::PartialApplyForwarder
            }
            SwiftClosureSymbolKind::PartialApplyObjcForwarder => {
                SwiftClosureRole::PartialApplyObjcForwarder
            }
        };
        Some((role, symbol.clone(), evidence.display))
    })
}

fn cpp_dispatch_candidate(
    functions: &FunctionIndex,
    record: &CppDispatch,
    evidence_address: Option<u64>,
) -> IndirectCallCandidate {
    IndirectCallCandidate {
        target: match &record.implementation {
            StaticTarget::Internal(implementation) => IndirectCallTarget::CppVirtualMethod {
                vtable: record.vtable,
                address_point: record.address_point,
                slot: record.slot,
                type_name: record.type_name.clone(),
                implementation: *implementation,
                functions: function_candidates(functions, *implementation),
            },
            StaticTarget::Import { name, ordinal } => IndirectCallTarget::CppVirtualMethodImport {
                vtable: record.vtable,
                address_point: record.address_point,
                slot: record.slot,
                type_name: record.type_name.clone(),
                symbol: name.clone(),
                library_ordinal: *ordinal,
            },
        },
        source: IndirectCallEvidenceSource::CppVtable,
        confidence: if evidence_address.is_some() {
            record.confidence
        } else {
            FunctionEvidenceConfidence::Candidate
        },
        evidence_address,
        authentication: record.authentication,
        detail: "cpp_rtti_vtable_agreement".into(),
    }
}

fn swift_witness_candidate(
    functions: &FunctionIndex,
    record: &SwiftWitnessDispatch,
    confidence: FunctionEvidenceConfidence,
    evidence_address: Option<u64>,
) -> IndirectCallCandidate {
    let confidence = if record.runtime_instantiated {
        FunctionEvidenceConfidence::Candidate
    } else {
        confidence
    };
    IndirectCallCandidate {
        target: match &record.implementation {
            StaticTarget::Internal(implementation) => IndirectCallTarget::SwiftProtocolWitness {
                witness_table: record.witness_table,
                requirement: record.requirement,
                protocol: record.protocol.clone(),
                conforming_type: record.conforming_type.clone(),
                runtime_instantiated: record.runtime_instantiated,
                implementation: *implementation,
                functions: function_candidates(functions, *implementation),
            },
            StaticTarget::Import { name, ordinal } => {
                IndirectCallTarget::SwiftProtocolWitnessImport {
                    witness_table: record.witness_table,
                    requirement: record.requirement,
                    protocol: record.protocol.clone(),
                    conforming_type: record.conforming_type.clone(),
                    runtime_instantiated: record.runtime_instantiated,
                    symbol: name.clone(),
                    library_ordinal: *ordinal,
                }
            }
        },
        source: IndirectCallEvidenceSource::Swift,
        confidence,
        evidence_address,
        authentication: record.authentication,
        detail: if record.runtime_instantiated {
            "swift_runtime_instantiated_witness"
        } else if evidence_address.is_some() {
            "swift_witness_table_identity_match"
        } else {
            "swift_witness_slot_candidate"
        }
        .into(),
    }
}

fn block_dispatch_candidate(
    functions: &FunctionIndex,
    record: &BlockDispatch,
    confidence: FunctionEvidenceConfidence,
    evidence_address: Option<u64>,
) -> IndirectCallCandidate {
    IndirectCallCandidate {
        target: match &record.implementation {
            StaticTarget::Internal(implementation) => IndirectCallTarget::BlockInvoke {
                literal: record.literal,
                descriptor: record.descriptor,
                storage: record.storage,
                implementation: *implementation,
                functions: function_candidates(functions, *implementation),
            },
            StaticTarget::Import { name, ordinal } => IndirectCallTarget::BlockInvokeImport {
                literal: record.literal,
                descriptor: record.descriptor,
                storage: record.storage,
                symbol: name.clone(),
                library_ordinal: *ordinal,
            },
        },
        source: IndirectCallEvidenceSource::BlockClosure,
        confidence,
        evidence_address,
        authentication: record.authentication,
        detail: if evidence_address.is_some() {
            "block_literal_invoke_slot"
        } else {
            "block_invoke_offset_candidate"
        }
        .into(),
    }
}

fn function_candidates(functions: &FunctionIndex, address: u64) -> Vec<IndirectFunctionCandidate> {
    let mut result = BTreeMap::<u64, IndirectFunctionCandidate>::new();
    let mut add = |entry: u64, ownership_confidence: FunctionOwnershipConfidence| {
        let function = functions.by_entry(entry).expect("indexed owner");
        result.insert(
            entry,
            IndirectFunctionCandidate {
                entry,
                entry_confidence: function.entry_confidence,
                ownership_confidence,
            },
        );
    };
    for owner in functions.owners(address) {
        add(owner.function.entry, owner.confidence);
    }
    if let Some(function) = functions.by_entry(address) {
        add(
            function.entry,
            match function.entry_confidence {
                FunctionEvidenceConfidence::Exact => FunctionOwnershipConfidence::Exact,
                FunctionEvidenceConfidence::Derived => FunctionOwnershipConfidence::Derived,
                FunctionEvidenceConfidence::Candidate => FunctionOwnershipConfidence::Candidate,
            },
        );
    }
    result.into_values().collect()
}

fn selector_candidates(
    macho: &MachoFile<'_>,
    state: Option<&RegisterValues>,
    register: ControlFlowRegister,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    let Some(values) = state.and_then(|state| state.get(&register)) else {
        return result;
    };
    for value in values.iter() {
        let address = match value.kind {
            AbstractValueKind::Address(address) => Some(address),
            AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
            AbstractValueKind::DynamicSlot(_) => None,
            AbstractValueKind::StackAddress(_) => None,
            AbstractValueKind::Argument(_) => None,
            AbstractValueKind::ProtocolArgument { .. } | AbstractValueKind::HeapAddress { .. } => {
                None
            }
        };
        if let Some(address) = address
            && let Some(selector) = read_cstring(macho, address)
        {
            result.insert(selector);
        }
    }
    result
}

fn objc_receiver_targets(
    macho: &MachoFile<'_>,
    state: Option<&RegisterValues>,
    memory: Option<&MemoryValues>,
    register: ControlFlowRegister,
    catalog: &Catalog,
) -> BTreeSet<(String, bool)> {
    let mut result = BTreeSet::new();
    let Some(values) = state.and_then(|state| state.get(&register)) else {
        return result;
    };
    for value in values.iter() {
        if let AbstractValueKind::ProtocolArgument { function, ordinal } = value.kind {
            if let Some(protocols) = catalog.objc_protocol_arguments.get(&(function, ordinal)) {
                let mut matching = None::<BTreeSet<String>>;
                for protocol in protocols {
                    let adopters = catalog
                        .objc_protocol_adopters
                        .get(protocol)
                        .cloned()
                        .unwrap_or_default();
                    matching = Some(matching.map_or(adopters.clone(), |current| {
                        current.intersection(&adopters).cloned().collect()
                    }));
                }
                for class in matching.unwrap_or_default() {
                    add_objc_hierarchy(&mut result, class, false, catalog);
                }
            }
            continue;
        }
        let address = match value.kind {
            AbstractValueKind::Address(address) => Some(address),
            AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
            AbstractValueKind::DynamicSlot(_)
            | AbstractValueKind::StackAddress(_)
            | AbstractValueKind::Argument(_)
            | AbstractValueKind::ProtocolArgument { .. }
            | AbstractValueKind::HeapAddress { .. } => None,
        };
        let Some(address) = address else {
            continue;
        };
        if let Some(name) = catalog
            .objc_class_addresses
            .get(&address)
            .or_else(|| catalog.objc_metaclass_addresses.get(&address))
        {
            add_objc_hierarchy(&mut result, name.clone(), true, catalog);
            continue;
        }
        let isa = memory
            .and_then(|memory| memory.get(&AbstractMemoryLocation::Global(address)))
            .and_then(|values| {
                values.iter().find_map(|value| match value.kind {
                    AbstractValueKind::Address(address) => Some(address),
                    AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
                    _ => None,
                })
            })
            .or_else(|| read_pointer(macho, address));
        if let Some(name) = isa.and_then(|isa| catalog.objc_class_addresses.get(&isa)) {
            add_objc_hierarchy(&mut result, name.clone(), false, catalog);
        } else if let Some(name) = isa.and_then(|isa| catalog.objc_metaclass_addresses.get(&isa)) {
            add_objc_hierarchy(&mut result, name.clone(), true, catalog);
        }
    }
    result
}

fn objc_receiver_protocols<'catalog>(
    state: Option<&RegisterValues>,
    register: ControlFlowRegister,
    catalog: &'catalog Catalog,
) -> Option<&'catalog BTreeSet<String>> {
    state
        .and_then(|state| state.get(&register))
        .and_then(|values| {
            values.iter().find_map(|value| match value.kind {
                AbstractValueKind::ProtocolArgument { function, ordinal } => {
                    catalog.objc_protocol_arguments.get(&(function, ordinal))
                }
                _ => None,
            })
        })
}

fn add_objc_hierarchy(
    result: &mut BTreeSet<(String, bool)>,
    mut name: String,
    class_method: bool,
    catalog: &Catalog,
) {
    let mut seen = BTreeSet::new();
    while seen.insert(name.clone()) {
        result.insert((name.clone(), class_method));
        let Some(Some(parent)) = catalog.objc_superclasses.get(&name) else {
            break;
        };
        name = parent.clone();
    }
}

#[cfg(test)]
fn objc_super_receiver_classes(
    macho: &MachoFile<'_>,
    state: Option<&RegisterValues>,
    memory: Option<&MemoryValues>,
    register: ControlFlowRegister,
    catalog: &Catalog,
) -> BTreeSet<String> {
    let values = objc_super_receiver_values(macho, state, memory, register);
    objc_classes_from_values(macho, &values, catalog)
}

fn objc_receiver_targets_from_class_values(
    macho: &MachoFile<'_>,
    values: &BTreeSet<AbstractValue>,
    catalog: &Catalog,
) -> BTreeSet<(String, bool)> {
    let class_method = objc_values_are_metaclasses(macho, values, catalog);
    objc_classes_from_values(macho, values, catalog)
        .into_iter()
        .map(|name| (name, class_method))
        .collect()
}

fn objc_super_receiver_values(
    macho: &MachoFile<'_>,
    state: Option<&RegisterValues>,
    memory: Option<&MemoryValues>,
    register: ControlFlowRegister,
) -> BTreeSet<AbstractValue> {
    let Some(values) = state.and_then(|state| state.get(&register)) else {
        return BTreeSet::new();
    };
    let mut class_values = BTreeSet::new();
    for value in values.iter() {
        match value.kind {
            AbstractValueKind::StackAddress(offset) => {
                if let Some(values) = memory.and_then(|memory| {
                    memory.get(&AbstractMemoryLocation::Stack(offset.saturating_add(8)))
                }) {
                    class_values.extend(values.iter().copied());
                }
            }
            AbstractValueKind::Address(address) => {
                if let Some(values) = memory.and_then(|memory| {
                    memory.get(&AbstractMemoryLocation::Global(address.saturating_add(8)))
                }) {
                    class_values.extend(values.iter().copied());
                } else if let Some(class) = read_pointer(macho, address.saturating_add(8)) {
                    class_values.insert(AbstractValue {
                        kind: AbstractValueKind::Address(class),
                        authentication: None,
                        instruction: value.instruction,
                    });
                }
            }
            AbstractValueKind::PointerSlot(slot) => {
                if let Some(address) = read_pointer(macho, slot)
                    && let Some(class) = read_pointer(macho, address.saturating_add(8))
                {
                    class_values.insert(AbstractValue {
                        kind: AbstractValueKind::Address(class),
                        authentication: None,
                        instruction: value.instruction,
                    });
                }
            }
            AbstractValueKind::HeapAddress { allocation, offset } => {
                if let Some(values) = memory.and_then(|memory| {
                    memory.get(&AbstractMemoryLocation::Heap {
                        allocation,
                        offset: offset.saturating_add(8),
                    })
                }) {
                    class_values.extend(values.iter().copied());
                }
            }
            AbstractValueKind::DynamicSlot(_)
            | AbstractValueKind::Argument(_)
            | AbstractValueKind::ProtocolArgument { .. } => {}
        }
    }
    class_values
}

fn objc_classes_from_values(
    macho: &MachoFile<'_>,
    values: &BTreeSet<AbstractValue>,
    catalog: &Catalog,
) -> BTreeSet<String> {
    let mut result = BTreeSet::new();
    for value in values {
        let address = match value.kind {
            AbstractValueKind::Address(address) => Some(address),
            AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
            AbstractValueKind::DynamicSlot(_)
            | AbstractValueKind::StackAddress(_)
            | AbstractValueKind::Argument(_)
            | AbstractValueKind::ProtocolArgument { .. }
            | AbstractValueKind::HeapAddress { .. } => None,
        };
        let Some(mut name) = address.and_then(|address| {
            catalog
                .objc_class_addresses
                .get(&address)
                .or_else(|| catalog.objc_metaclass_addresses.get(&address))
                .cloned()
        }) else {
            continue;
        };
        let mut seen = BTreeSet::new();
        while seen.insert(name.clone()) {
            result.insert(name.clone());
            let Some(Some(parent)) = catalog.objc_superclasses.get(&name) else {
                break;
            };
            name = parent.clone();
        }
    }
    result
}

fn objc_values_are_metaclasses(
    macho: &MachoFile<'_>,
    values: &BTreeSet<AbstractValue>,
    catalog: &Catalog,
) -> bool {
    values.iter().any(|value| {
        let address = match value.kind {
            AbstractValueKind::Address(address) => Some(address),
            AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
            AbstractValueKind::DynamicSlot(_)
            | AbstractValueKind::StackAddress(_)
            | AbstractValueKind::Argument(_)
            | AbstractValueKind::ProtocolArgument { .. }
            | AbstractValueKind::HeapAddress { .. } => None,
        };
        address.is_some_and(|address| catalog.objc_metaclass_addresses.contains_key(&address))
    })
}

fn read_pointer(macho: &MachoFile<'_>, address: u64) -> Option<u64> {
    let bytes = macho.read_bytes_at_va(Va(address), 8).ok()?;
    Some(macho.endian().read_u64(bytes.try_into().ok()?))
}

fn read_u32(macho: &MachoFile<'_>, address: u64) -> Option<u32> {
    let bytes = macho.read_bytes_at_va(Va(address), 4).ok()?;
    Some(macho.endian().read_u32(bytes.try_into().ok()?))
}

fn read_cstring(macho: &MachoFile<'_>, address: u64) -> Option<String> {
    let available = macho
        .all_sections()
        .find_map(|section| {
            let end = section.addr().0.checked_add(section.size())?;
            (section.addr().0 <= address && address < end).then(|| end - address)
        })
        .or_else(|| {
            macho.segments().iter().find_map(|segment| {
                let relative = address.checked_sub(segment.vm_addr().0)?;
                (relative < segment.file_size()).then(|| segment.file_size() - relative)
            })
        })?;
    let length = usize::try_from(available.min(4_096)).ok()?;
    let bytes = macho.read_bytes_at_va(Va(address), length).ok()?;
    let end = bytes.iter().position(|byte| *byte == 0)?;
    std::str::from_utf8(&bytes[..end]).ok().map(str::to_owned)
}

fn instruction(graph: &FunctionControlFlow, address: u64) -> &ControlFlowInstruction {
    let index = graph
        .instructions
        .binary_search_by_key(&address, |instruction| instruction.address)
        .expect("control-flow record references retained instruction");
    &graph.instructions[index]
}

fn merge_authentication(
    chained: Option<PointerAuthentication>,
    instruction: Option<PointerAuthentication>,
) -> Option<PointerAuthentication> {
    match (chained, instruction) {
        (None, None) => None,
        (Some(authentication), None) | (None, Some(authentication)) => Some(authentication),
        (Some(mut chained), Some(instruction)) => {
            chained.instruction_key = instruction.instruction_key;
            chained.instruction_modifier = instruction.instruction_modifier;
            chained.instruction_zero_modifier = instruction.instruction_zero_modifier;
            chained.authenticated_instruction = true;
            Some(chained)
        }
    }
}

fn instruction_authentication(
    macho: &MachoFile<'_>,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
) -> Option<PointerAuthentication> {
    if !matches!(architecture, Architecture::Arm64e) {
        return None;
    }
    let Ok(bytes) = macho.read_bytes_at_va(Va(instruction.address), 4) else {
        return None;
    };
    let word = u32::from_le_bytes(bytes.try_into().expect("four bytes"));
    let authenticated = word & 0xFE00_0000 == 0xD600_0000
        && word & 0xFFFF_FC1F != 0xD61F_0000
        && word & 0xFFFF_FC1F != 0xD63F_0000;
    authenticated.then(|| {
        let zero_modifier = word & 0x0100_0000 == 0;
        PointerAuthentication {
            key: None,
            diversity: None,
            address_diversity: None,
            instruction_key: Some(((word >> 10) & 1) as u8),
            instruction_modifier: (!zero_modifier).then_some(ControlFlowRegister {
                class: ControlFlowRegisterClass::GeneralPurpose,
                number: (word & 0x1f) as u8,
            }),
            instruction_zero_modifier: Some(zero_modifier),
            authenticated_instruction: true,
        }
    })
}

fn chained_target(macho: &MachoFile<'_>, target: u64) -> Option<u64> {
    macho.image_base().0.checked_add(target)
}

const fn architecture_matches_x86(architecture: Architecture) -> bool {
    matches!(architecture, Architecture::X86_64)
}

fn receipt(
    source: IndirectCallEvidenceSource,
    status: IndirectCollectorStatus,
    examined: u64,
    retained: u64,
    diagnostic: Option<&str>,
) -> IndirectCollectorReceipt {
    IndirectCollectorReceipt {
        source,
        status,
        examined,
        retained,
        diagnostic: diagnostic.map(str::to_owned),
    }
}

fn known_heap_allocator(name: &str) -> bool {
    matches!(
        name.trim_start_matches('_'),
        "malloc"
            | "calloc"
            | "realloc"
            | "aligned_alloc"
            | "valloc"
            | "operator new"
            | "Znwm"
            | "Znam"
            | "objc_alloc"
            | "objc_allocWithZone"
            | "class_createInstance"
    )
}

const fn merge_collector_status(
    left: IndirectCollectorStatus,
    right: IndirectCollectorStatus,
) -> IndirectCollectorStatus {
    use IndirectCollectorStatus::{Absent, Complete, Failed, Truncated};
    match (left, right) {
        (Failed, _) | (_, Failed) => Failed,
        (Truncated, _) | (_, Truncated) => Truncated,
        (Complete, _) | (_, Complete) => Complete,
        (Absent, Absent) => Absent,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::control_flow::ControlFlowLimits;
    use crate::analysis::functions::{
        FunctionIdentity, FunctionImageIdentity, FunctionRecoveryLimits,
    };
    use crate::analysis::recovery::{ProgramSubjectKey, RecoveryQuestionKind};

    const MAIN: u64 = 0x1_0000_0100;
    const HELPER: u64 = 0x1_0000_0120;
    const SLOT: u64 = 0x1_0000_0130;

    #[test]
    fn collector_receipt_allows_one_examined_record_to_retain_multiple_facts() {
        let receipt = receipt(
            IndirectCallEvidenceSource::CppVtable,
            IndirectCollectorStatus::Complete,
            1,
            2,
            None,
        );

        assert!(indirect_collector_receipt_is_valid(&receipt));
    }

    #[test]
    fn unresolved_objc_dispatch_reasons_require_partial_status() {
        for reason in [
            "indirect.objc_runtime_dispatch_open",
            "indirect.objc_selector_unresolved",
            "indirect.objc_selector_without_implementation",
            "indirect.objc_receiver_unresolved",
        ] {
            assert!(indirect_reason_requires_partial(reason), "{reason}");
        }
    }

    fn flow_instruction(address: u64) -> ControlFlowInstruction {
        ControlFlowInstruction {
            address,
            byte_len: 4,
            kind: ControlFlowInstructionKind::Other,
            target: None,
            operands: Vec::new().into_boxed_slice(),
            written_register: None,
            value_effect: ControlFlowValueEffect::None,
            memory_effect: ControlFlowMemoryEffect::None,
            writes_implicit_gpr0: false,
            pc_relative: None,
            coverage_confidence: FunctionEvidenceConfidence::Exact,
        }
    }

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    fn move_helper(bytes: &mut [u8]) {
        bytes[0x158..0x160].copy_from_slice(&HELPER.to_le_bytes());
    }

    #[test]
    fn cstring_lookup_below_a_section_does_not_underflow() {
        let bytes = macho_test_support::disassembly_x86_64();
        let macho = image(&bytes);
        assert_eq!(read_cstring(&macho, 0), None);

        let segment = &macho.segments()[0];
        let beyond_file = segment
            .vm_addr()
            .0
            .checked_add(segment.file_size())
            .and_then(|address| address.checked_add(1))
            .unwrap();
        assert_eq!(read_cstring(&macho, beyond_file), None);
    }

    #[test]
    fn indirect_symbol_leaf_preserves_import_and_internal_targets() {
        use crate::core::model::addr::ThinFileOffset;
        use crate::core::model::symbol::SymbolType;
        use crate::metadata::symbols::{
            IndirectBoundSymbol, IndirectSymbolBinding, IndirectSymbolTarget,
        };

        let binding = |address, symbol_type, desc, value, name: &str| IndirectSymbolBinding {
            section_index: 0,
            segment_name: "__DATA".into(),
            section_name: "__la_symbol_ptr".into(),
            kind: IndirectBindingKind::LazyPointer,
            entry_index: 0,
            address: Va(address),
            file_offset: ThinFileOffset(0),
            size: 8,
            indirect_table_index: 0,
            raw_indirect_index: 0,
            target: IndirectSymbolTarget::Symbol(IndirectBoundSymbol {
                index: 0,
                name: name.into(),
                symbol_type,
                external: true,
                private_external: false,
                section_index: 0,
                desc,
                value,
            }),
        };
        let mut catalog = Catalog::default();
        assert_eq!(
            catalog.admit_indirect_bindings(vec![
                binding(SLOT, SymbolType::Undefined, 3 << 8, 0, "_external"),
                binding(HELPER, SymbolType::Section, 0, MAIN, "_internal"),
            ]),
            2
        );
        assert!(matches!(
            catalog.slots[&SLOT][0].target,
            StaticTarget::Import {
                ref name,
                ordinal: Some(3)
            } if name == "_external"
        ));
        assert_eq!(
            catalog.slots[&HELPER][0].target,
            StaticTarget::Internal(MAIN)
        );
    }

    fn add_two_function_starts(bytes: &mut Vec<u8>) {
        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        let starts = [0x80, 0x02, 0x20, 0x00];
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

    fn x86_materialized_fixture(with_names: bool) -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x10d].copy_from_slice(&[
            0x48, 0xb8, 0x20, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax, HELPER
            0xff, 0xd0, // call rax
            0xc3, // ret
        ]);
        bytes[0x120] = 0xc3;
        add_two_function_starts(&mut bytes);
        if !with_names {
            bytes[0x161..0x16f].fill(0);
        }
        bytes
    }

    fn x86_pointer_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x107].copy_from_slice(&[0xff, 0x15, 0x2a, 0x00, 0x00, 0x00, 0xc3]);
        bytes[0x120] = 0xc3;
        bytes[0x130..0x138].copy_from_slice(&HELPER.to_le_bytes());
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_direct_only_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x106].copy_from_slice(&[
            0xe8, 0x1b, 0x00, 0x00, 0x00, // call helper
            0xc3, // ret
        ]);
        bytes[0x120] = 0xc3;
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_interprocedural_return_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x112].copy_from_slice(&[
            0x48, 0xbf, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rdi, MAIN
            0xe8, 0x11, 0x00, 0x00, 0x00, // call HELPER
            0xff, 0xd0, // call rax
            0xc3, // ret
        ]);
        bytes[0x120..0x124].copy_from_slice(&[0x48, 0x89, 0xf8, 0xc3]); // mov rax,rdi; ret
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_cross_function_global_store_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x117].copy_from_slice(&[
            0x48, 0xb8, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax, MAIN
            0x48, 0x89, 0x05, 0x1f, 0x00, 0x00, 0x00, // mov [rip+0x1f],rax => SLOT
            0xe8, 0x0a, 0x00, 0x00, 0x00, // call HELPER
            0xc3, // ret
        ]);
        bytes[0x120..0x127].copy_from_slice(&[
            0xff, 0x15, 0x0a, 0x00, 0x00, 0x00, // call [rip+0xa] => SLOT
            0xc3, // ret
        ]);
        bytes[0x130..0x138].fill(0);
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_merged_indirect_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x11d].copy_from_slice(&[
            0x85, 0xff, // test edi,edi
            0x74, 0x0c, // je 0x110
            0x48, 0xb8, 0x10, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax,MAIN+0x10
            0xeb, 0x0a, // jmp 0x11a
            0x48, 0xb8, 0x18, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax,MAIN+0x18
            0xff, 0xd0, // call rax
            0xc3, // ret
        ]);
        bytes[0x120] = 0xc3;
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_jump_table_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x10a].copy_from_slice(&[
            0x48, 0x8d, 0x15, 0x29, 0x00, 0x00, 0x00, // lea rdx,[rip+0x29]
            0xff, 0x24, 0xc2, // jmp [rdx+rax*8]
        ]);
        bytes[0x10a..0x120].fill(0x90);
        bytes[0x110] = 0xc3;
        bytes[0x118] = 0xc3;
        bytes[0x130..0x138].copy_from_slice(&(MAIN + 0x10).to_le_bytes());
        bytes[0x138..0x140].copy_from_slice(&(MAIN + 0x18).to_le_bytes());
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_base_relative_pointer_fixture() -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x110].copy_from_slice(&[
            0x48, 0xb8, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov rax, SLOT
            0x48, 0x8b, 0x00, // mov rax, [rax]
            0xff, 0xd0, // call rax
            0xc3, // ret
        ]);
        bytes[0x120] = 0xc3;
        bytes[0x130..0x138].copy_from_slice(&HELPER.to_le_bytes());
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn x86_relocation_fixture() -> Vec<u8> {
        let mut bytes = x86_pointer_fixture();
        let relocation_offset = bytes.len() as u32;
        bytes[0xa0..0xa4].copy_from_slice(&relocation_offset.to_le_bytes());
        bytes[0xa4..0xa8].copy_from_slice(&1_u32.to_le_bytes());
        bytes.extend_from_slice(&0x30_u32.to_le_bytes());
        let relocation_info = 1_u32 | (3 << 25) | (1 << 27);
        bytes.extend_from_slice(&relocation_info.to_le_bytes());
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
        bytes
    }

    fn arm_pointer_fixture(arm64e: bool) -> Vec<u8> {
        let mut bytes = if arm64e {
            macho_test_support::disassembly_arm64e()
        } else {
            macho_test_support::disassembly_arm64()
        };
        move_helper(&mut bytes);
        bytes[0x100..0x104].copy_from_slice(&0x9000_0010_u32.to_le_bytes()); // adrp x16
        bytes[0x104..0x108].copy_from_slice(&0xf940_9a10_u32.to_le_bytes()); // ldr x16,[x16,#0x130]
        bytes[0x108..0x10c].copy_from_slice(
            &(if arm64e {
                0xd73f_0a00_u32
            } else {
                0xd63f_0200_u32
            })
            .to_le_bytes(),
        );
        bytes[0x10c..0x110].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes[0x130..0x138].copy_from_slice(&HELPER.to_le_bytes());
        add_two_function_starts(&mut bytes);
        bytes
    }

    fn recover(bytes: &[u8], limits: IndirectCallRecoveryLimits) -> IndirectCallIndex {
        let macho = image(bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        IndirectCallIndex::recover(&macho, &functions, &control_flow, limits).unwrap()
    }

    fn internal_address(candidate: &IndirectCallCandidate) -> Option<u64> {
        match &candidate.target {
            IndirectCallTarget::Internal { address, .. } => Some(*address),
            _ => None,
        }
    }

    #[test]
    fn rich_and_stripped_x86_images_retain_the_same_indirect_identity() {
        let rich = recover(
            &x86_materialized_fixture(true),
            IndirectCallRecoveryLimits::default(),
        );
        let stripped = recover(
            &x86_materialized_fixture(false),
            IndirectCallRecoveryLimits::default(),
        );
        let rich_call = rich
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 10)
            .unwrap();
        let stripped_call = stripped
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 10)
            .unwrap();
        assert!(rich_call.candidates.iter().any(|candidate| {
            candidate.source == IndirectCallEvidenceSource::InstructionValueFlow
                && internal_address(candidate) == Some(HELPER)
        }));
        assert_eq!(
            rich_call
                .candidates
                .iter()
                .map(internal_address)
                .collect::<Vec<_>>(),
            stripped_call
                .candidates
                .iter()
                .map(internal_address)
                .collect::<Vec<_>>()
        );

        let rich_bytes = x86_materialized_fixture(true);
        let rich_macho = image(&rich_bytes);
        let rich_functions =
            FunctionIndex::recover(&rich_macho, FunctionRecoveryLimits::default()).unwrap();
        let stripped_bytes = x86_materialized_fixture(false);
        let stripped_macho = image(&stripped_bytes);
        let stripped_functions =
            FunctionIndex::recover(&stripped_macho, FunctionRecoveryLimits::default()).unwrap();
        assert!(matches!(
            rich_functions.by_entry(HELPER).unwrap().identity,
            FunctionIdentity::Named { .. }
        ));
        assert!(matches!(
            stripped_functions.by_entry(HELPER).unwrap().identity,
            FunctionIdentity::Anonymous { .. }
        ));
    }

    #[test]
    fn x86_rip_relative_memory_call_recovers_raw_pointer_slot() {
        let index = recover(
            &x86_pointer_fixture(),
            IndirectCallRecoveryLimits::default(),
        );
        let call = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN)
            .unwrap();
        assert!(
            call.carriers
                .contains(&IndirectTargetCarrier::PointerSlot { address: SLOT }),
            "{call:#?}"
        );
        assert!(call.candidates.iter().any(|candidate| {
            candidate.source == IndirectCallEvidenceSource::RawPointer
                && candidate.evidence_address == Some(SLOT)
                && internal_address(candidate) == Some(HELPER)
        }));
        assert_eq!(call.status, IndirectCallSiteStatus::Partial);
    }

    #[test]
    fn x86_base_relative_load_preserves_a_pointer_chain() {
        let index = recover(
            &x86_base_relative_pointer_fixture(),
            IndirectCallRecoveryLimits::default(),
        );
        let call = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 13)
            .unwrap();
        assert!(
            call.carriers
                .contains(&IndirectTargetCarrier::PointerSlot { address: SLOT })
        );
        assert!(call.candidates.iter().any(|candidate| {
            candidate.source == IndirectCallEvidenceSource::RawPointer
                && candidate.evidence_address == Some(SLOT)
                && internal_address(candidate) == Some(HELPER)
        }));
    }

    #[test]
    fn total_value_flow_work_budget_truncates_deterministically() {
        let index = recover(
            &x86_base_relative_pointer_fixture(),
            IndirectCallRecoveryLimits {
                max_value_flow_work: 1,
                ..IndirectCallRecoveryLimits::default()
            },
        );
        assert_eq!(index.status(), IndirectCallIndexStatus::Truncated);
        assert!(index.completeness().value_flow_truncated);
        assert_eq!(index.completeness().value_flow_work, 1);
        assert!(
            index
                .completeness()
                .reasons
                .contains(&"indirect.value_flow_budget".to_owned())
        );
    }

    #[test]
    fn per_function_value_flow_budget_reports_the_exact_function() {
        let index = recover(
            &x86_base_relative_pointer_fixture(),
            IndirectCallRecoveryLimits {
                max_value_flow_work_per_function: 1,
                ..IndirectCallRecoveryLimits::default()
            },
        );
        assert_eq!(index.status(), IndirectCallIndexStatus::Truncated);
        assert!(index.completeness().value_flow_truncated);
        assert_eq!(index.completeness().value_flow_work, 1);
        assert_eq!(
            index.completeness().value_flow_continuation_function,
            Some(MAIN)
        );
    }

    #[test]
    fn raising_value_flow_work_only_adds_recovered_candidates() {
        let bytes = x86_materialized_fixture(true);
        let limited = recover(
            &bytes,
            IndirectCallRecoveryLimits {
                max_value_flow_work: 1,
                ..IndirectCallRecoveryLimits::default()
            },
        );
        let complete = recover(&bytes, IndirectCallRecoveryLimits::default());
        let candidate_keys = |index: &IndirectCallIndex| {
            index
                .calls()
                .iter()
                .flat_map(|call| {
                    call.candidates
                        .iter()
                        .map(move |candidate| (call.instruction_address, candidate.target.clone()))
                })
                .collect::<BTreeSet<_>>()
        };
        let limited_candidates = candidate_keys(&limited);
        let complete_candidates = candidate_keys(&complete);

        assert!(limited_candidates.is_subset(&complete_candidates));
        assert!(complete_candidates.len() > limited_candidates.len());
        assert!(limited.completeness().value_flow_truncated);
        assert!(!complete.completeness().value_flow_truncated);
    }

    #[test]
    fn raising_value_retention_limit_only_adds_candidates() {
        let bytes = x86_merged_indirect_fixture();
        let candidate_keys = |index: &IndirectCallIndex| {
            index
                .calls()
                .iter()
                .flat_map(|call| {
                    call.candidates
                        .iter()
                        .map(move |candidate| (call.instruction_address, candidate.target.clone()))
                })
                .collect::<BTreeSet<_>>()
        };
        let one_value = recover(
            &bytes,
            IndirectCallRecoveryLimits {
                max_values_per_register: 1,
                ..IndirectCallRecoveryLimits::default()
            },
        );
        let all_values = recover(
            &bytes,
            IndirectCallRecoveryLimits {
                max_values_per_register: 8,
                ..IndirectCallRecoveryLimits::default()
            },
        );
        let limited = candidate_keys(&one_value);
        let complete = candidate_keys(&all_values);
        assert!(limited.is_subset(&complete), "{limited:#?}\n{complete:#?}");
        assert!(
            complete.len() > limited.len(),
            "{limited:#?}\n{complete:#?}"
        );
        assert!(one_value.completeness().value_flow_truncated);
        assert!(!all_values.completeness().value_flow_truncated);
    }

    #[test]
    fn raising_candidate_retention_limit_only_adds_candidates() {
        let bytes = x86_jump_table_fixture();
        let recover_with_limit = |limit| {
            recover(
                &bytes,
                IndirectCallRecoveryLimits {
                    max_candidates_per_transfer: limit,
                    ..IndirectCallRecoveryLimits::default()
                },
            )
        };
        let limited = recover_with_limit(1);
        let complete = recover_with_limit(8);
        let targets = |index: &IndirectCallIndex| {
            index.calls()[0]
                .candidates
                .iter()
                .map(|candidate| candidate.target.clone())
                .collect::<BTreeSet<_>>()
        };
        let limited_targets = targets(&limited);
        let complete_targets = targets(&complete);
        assert!(limited_targets.is_subset(&complete_targets));
        assert!(complete_targets.len() > limited_targets.len());
        assert!(limited.completeness().omitted_candidate_count > 0);
        assert_eq!(complete.completeness().omitted_candidate_count, 0);
    }

    #[test]
    fn raising_loop_widening_limit_preserves_every_lower_limit_value() {
        let register = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        };
        let value = |address| AbstractValue {
            kind: AbstractValueKind::Address(address),
            authentication: None,
            instruction: address,
        };
        let initial =
            RegisterValues::from([(register, Arc::new(BTreeSet::from([value(1), value(2)])))]);
        let incoming = RegisterValues::from([(
            register,
            Arc::new(BTreeSet::from([value(1), value(2), value(3)])),
        )]);
        let merge = |limit| {
            let mut state = initial.clone();
            let mut truncated = false;
            let mut widened = false;
            let mut work = ValueFlowWorkBudget::new(100);
            merge_state(
                &mut state,
                &incoming,
                8,
                &mut truncated,
                Some(limit),
                &mut widened,
                &mut work,
            );
            (state, truncated, widened)
        };
        let (lower, lower_truncated, lower_widened) = merge(2);
        let (higher, higher_truncated, higher_widened) = merge(3);
        let lower_values = lower.get(&register).map(AsRef::as_ref);
        let higher_values = higher.get(&register).map(AsRef::as_ref);
        assert!(lower_values.is_none());
        assert_eq!(higher_values, Some(incoming[&register].as_ref()));
        assert!(!lower_truncated && !higher_truncated);
        assert!(lower_widened && !higher_widened);
    }

    #[test]
    fn functions_without_indirect_observation_sites_consume_no_value_flow_work() {
        let index = recover(
            &x86_direct_only_fixture(),
            IndirectCallRecoveryLimits::default(),
        );
        assert_eq!(index.completeness().value_flow_work, 0);
        assert!(!index.completeness().value_flow_truncated);
        assert!(index.calls().is_empty());
    }

    #[test]
    fn interprocedural_argument_return_summary_resolves_an_indirect_call() {
        let bytes = x86_interprocedural_return_fixture();
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let index = IndirectCallIndex::recover(
            &macho,
            &functions,
            &control_flow,
            IndirectCallRecoveryLimits::default(),
        )
        .unwrap();
        let call = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 15)
            .unwrap();
        assert!(
            call.candidates.iter().any(|candidate| {
                candidate.source == IndirectCallEvidenceSource::InstructionValueFlow
                    && internal_address(candidate) == Some(MAIN)
            }),
            "{call:#?}\n{:#?}",
            control_flow.functions()
        );
        assert_eq!(
            index.abi_summaries(),
            &[FunctionAbiSummary {
                function_entry: HELPER,
                return_instructions: vec![HELPER + 3],
                values: vec![AbiReturnValue::Argument {
                    ordinal: 0,
                    authentication: None,
                }],
            }]
        );
        assert!(!call.value_flow_truncated);
    }

    #[test]
    fn closed_cross_function_global_store_set_resolves_zero_fill_slot() {
        let bytes = x86_cross_function_global_store_fixture();
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let provisional =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let functions = functions
            .refine_extents_from_control_flow(&provisional)
            .unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let index = IndirectCallIndex::recover(
            &macho,
            &functions,
            &control_flow,
            IndirectCallRecoveryLimits::default(),
        )
        .unwrap();
        let call = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == HELPER)
            .expect("dispatcher retained");
        assert!(
            call.candidates.iter().any(|candidate| {
                candidate.source == IndirectCallEvidenceSource::GlobalStoreSummary
                    && candidate.confidence == FunctionEvidenceConfidence::Derived
                    && candidate.detail == "closed_non_escaping_global_store_set"
                    && internal_address(candidate) == Some(MAIN)
            }),
            "{call:#?}"
        );
        assert_eq!(call.status, IndirectCallSiteStatus::Complete, "{call:#?}");
    }

    #[test]
    fn initialized_global_dispatch_slot_unions_later_closed_stores() {
        let mut bytes = x86_cross_function_global_store_fixture();
        bytes[0x130..0x138].copy_from_slice(&HELPER.to_le_bytes());
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let provisional =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let functions = functions
            .refine_extents_from_control_flow(&provisional)
            .unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let index = IndirectCallIndex::recover(
            &macho,
            &functions,
            &control_flow,
            IndirectCallRecoveryLimits::default(),
        )
        .unwrap();
        let call = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == HELPER)
            .expect("dispatcher retained");
        let targets = call
            .candidates
            .iter()
            .filter_map(internal_address)
            .collect::<BTreeSet<_>>();
        assert!(targets.contains(&MAIN), "{call:#?}");
        assert!(targets.contains(&HELPER), "{call:#?}");
        assert!(call.candidates.iter().any(|candidate| {
            candidate.source == IndirectCallEvidenceSource::GlobalStoreSummary
                && internal_address(candidate) == Some(MAIN)
        }));
        assert_eq!(call.status, IndirectCallSiteStatus::Partial, "{call:#?}");

        let questions = crate::analysis::recovery::build_recovery_questions(
            &FunctionImageIdentity::from_macho(&macho),
            None,
            None,
            None,
            None,
            Some(&index),
            &[],
        );
        assert!(questions.iter().any(|question| {
            question.kind == RecoveryQuestionKind::IndirectTargets
                && question.subject
                    == ProgramSubjectKey::IndirectTransfer {
                        function_entry: call.source_function,
                        instruction_address: call.instruction_address,
                    }
        }));
    }

    #[test]
    fn mutable_dispatch_admission_does_not_depend_on_the_initial_pointee() {
        let mut bytes = x86_cross_function_global_store_fixture();
        bytes[0x130..0x138].copy_from_slice(&0xdead_beef_u64.to_le_bytes());
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let provisional =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let functions = functions
            .refine_extents_from_control_flow(&provisional)
            .unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();

        assert!(
            global_dispatch_slots(
                &control_flow,
                control_flow.functions().len(),
                Architecture::X86_64,
            )
            .contains(&SLOT)
        );
    }

    #[test]
    fn loop_merge_widens_an_expanding_register_to_unknown() {
        let register = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        };
        let value = |address| AbstractValue {
            kind: AbstractValueKind::Address(address),
            authentication: None,
            instruction: address,
        };
        let mut destination =
            RegisterValues::from([(register, Arc::new(BTreeSet::from([value(1), value(2)])))]);
        let source = RegisterValues::from([(
            register,
            Arc::new(BTreeSet::from([value(1), value(2), value(3)])),
        )]);
        let mut truncated = false;
        let mut widened = false;
        let mut work_budget = ValueFlowWorkBudget::new(100);

        let changed = merge_state(
            &mut destination,
            &source,
            4_096,
            &mut truncated,
            Some(2),
            &mut widened,
            &mut work_budget,
        );

        assert!(changed);
        assert!(widened);
        assert!(!truncated);
        assert!(!destination.contains_key(&register));
    }

    #[test]
    fn stack_store_and_reload_preserve_function_pointer_value() {
        let rsp = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 4,
        };
        let rax = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        };
        let rcx = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 1,
        };
        let pointer = AbstractValue {
            kind: AbstractValueKind::Address(HELPER),
            authentication: None,
            instruction: MAIN,
        };
        let mut state = RegisterValues::from([
            (
                rsp,
                Arc::new(BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::StackAddress(0),
                    authentication: None,
                    instruction: MAIN,
                }])),
            ),
            (rax, Arc::new(BTreeSet::from([pointer]))),
        ]);
        let mut memory = MemoryValues::new();
        let mut budget = ValueFlowWorkBudget::new(100);
        let mut truncated = false;
        let base = |address| ControlFlowInstruction {
            address,
            byte_len: 4,
            kind: ControlFlowInstructionKind::Other,
            target: None,
            operands: Vec::new().into_boxed_slice(),
            written_register: None,
            value_effect: ControlFlowValueEffect::None,
            memory_effect: ControlFlowMemoryEffect::None,
            writes_implicit_gpr0: false,
            pc_relative: None,
            coverage_confidence: FunctionEvidenceConfidence::Exact,
        };
        let mut store = base(MAIN);
        store.operands = vec![
            ControlFlowOperand::Memory {
                base: rsp,
                displacement: 8,
            },
            ControlFlowOperand::Register { register: rax },
        ]
        .into_boxed_slice();
        store.memory_effect = ControlFlowMemoryEffect::Store;
        apply_instruction(
            &mut state,
            &mut memory,
            &store,
            Architecture::X86_64,
            8,
            &mut truncated,
            &mut budget,
        );
        state.remove(&rax);
        let mut load = base(MAIN + 4);
        load.operands = vec![
            ControlFlowOperand::Register { register: rcx },
            ControlFlowOperand::Memory {
                base: rsp,
                displacement: 8,
            },
        ]
        .into_boxed_slice();
        load.written_register = Some(rcx);
        load.value_effect = ControlFlowValueEffect::Load;
        apply_instruction(
            &mut state,
            &mut memory,
            &load,
            Architecture::X86_64,
            8,
            &mut truncated,
            &mut budget,
        );
        assert_eq!(state[&rcx].as_ref(), &BTreeSet::from([pointer]));
        assert!(!truncated);
    }

    #[test]
    fn arithmetic_indexed_memory_and_abi_call_effects_are_conservative() {
        let reg = |number| ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number,
        };
        let value = |address| AbstractValue {
            kind: AbstractValueKind::Address(address),
            authentication: None,
            instruction: MAIN,
        };
        let mut state = RegisterValues::from([
            (reg(0), Arc::new(BTreeSet::from([value(0x1000)]))),
            (reg(1), Arc::new(BTreeSet::from([value(3)]))),
        ]);
        let mut memory = MemoryValues::from([
            (
                AbstractMemoryLocation::Stack(8),
                Arc::new(BTreeSet::from([value(HELPER)])),
            ),
            (
                AbstractMemoryLocation::Global(SLOT),
                Arc::new(BTreeSet::from([value(HELPER)])),
            ),
        ]);
        let mut budget = ValueFlowWorkBudget::new(100);
        let mut truncated = false;
        let mut add = ControlFlowInstruction {
            address: MAIN,
            byte_len: 3,
            kind: ControlFlowInstructionKind::Other,
            target: None,
            operands: vec![
                ControlFlowOperand::Register { register: reg(0) },
                ControlFlowOperand::Register { register: reg(1) },
            ]
            .into_boxed_slice(),
            written_register: Some(reg(0)),
            value_effect: ControlFlowValueEffect::AddRegister,
            memory_effect: ControlFlowMemoryEffect::None,
            writes_implicit_gpr0: false,
            pc_relative: None,
            coverage_confidence: FunctionEvidenceConfidence::Exact,
        };
        apply_instruction(
            &mut state,
            &mut memory,
            &add,
            Architecture::X86_64,
            8,
            &mut truncated,
            &mut budget,
        );
        assert_eq!(
            state[&reg(0)].iter().next().unwrap().kind,
            AbstractValueKind::Address(0x1003)
        );

        add.operands = vec![ControlFlowOperand::IndexedMemory {
            base: reg(0),
            index: reg(1),
            scale: 8,
            displacement: 4,
        }]
        .into_boxed_slice();
        assert_eq!(
            memory_locations(&state, &add, Architecture::X86_64),
            BTreeSet::from([AbstractMemoryLocation::Global(0x101f)])
        );

        add.kind = ControlFlowInstructionKind::Call;
        add.written_register = None;
        add.value_effect = ControlFlowValueEffect::None;
        add.operands = Vec::new().into_boxed_slice();
        apply_instruction(
            &mut state,
            &mut memory,
            &add,
            Architecture::X86_64,
            8,
            &mut truncated,
            &mut budget,
        );
        assert!(!state.contains_key(&reg(0)));
        assert!(!state.contains_key(&reg(1)));
        assert!(memory.contains_key(&AbstractMemoryLocation::Stack(8)));
        assert!(!memory.contains_key(&AbstractMemoryLocation::Global(SLOT)));
        assert!(!truncated);
    }

    #[test]
    fn semantic_heap_regions_retain_unresolved_index_aliases() {
        let heap = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        };
        let index = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 1,
        };
        let source = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 2,
        };
        let loaded = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 3,
        };
        let mut state = RegisterValues::from([
            (
                index,
                Arc::new(BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::Argument(1),
                    authentication: None,
                    instruction: MAIN,
                }])),
            ),
            (
                source,
                Arc::new(BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::Address(HELPER),
                    authentication: None,
                    instruction: MAIN,
                }])),
            ),
        ]);
        let mut memory = MemoryValues::new();
        let mut summaries = AbiSummaries::new();
        summaries.allocator_stubs.insert(SLOT);
        summaries.enable_allocators = true;
        let mut allocation = flow_instruction(MAIN);
        allocation.kind = ControlFlowInstructionKind::Call;
        allocation.target =
            Some(crate::analysis::control_flow::InstructionTarget::Direct { address: SLOT });
        let mut truncated = false;
        let mut budget = ValueFlowWorkBudget::new(1_000);
        apply_instruction_with_summaries(
            &mut state,
            &mut memory,
            &allocation,
            Architecture::X86_64,
            &summaries,
            32,
            &mut truncated,
            &mut budget,
        );
        assert!(matches!(
            state.get(&heap).unwrap().iter().next().unwrap().kind,
            AbstractValueKind::HeapAddress { allocation, offset: 0 } if allocation == MAIN
        ));

        let adjusted = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 4,
        };
        state.insert(adjusted, state[&heap].clone());
        let mut add_immediate = flow_instruction(MAIN + 1);
        add_immediate.operands = vec![
            ControlFlowOperand::Register { register: adjusted },
            ControlFlowOperand::Immediate { value: 16 },
        ]
        .into_boxed_slice();
        add_immediate.written_register = Some(adjusted);
        add_immediate.value_effect = ControlFlowValueEffect::AddImmediate;
        apply_instruction(
            &mut state,
            &mut memory,
            &add_immediate,
            Architecture::X86_64,
            32,
            &mut truncated,
            &mut budget,
        );
        assert!(matches!(
            state[&adjusted].iter().next().unwrap().kind,
            AbstractValueKind::HeapAddress { allocation, offset: 16 } if allocation == MAIN
        ));

        let register_addend = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 5,
        };
        state.insert(register_addend, state[&heap].clone());
        state.insert(
            index,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(24),
                authentication: None,
                instruction: MAIN,
            }])),
        );
        let mut add_register = flow_instruction(MAIN + 2);
        add_register.operands = vec![
            ControlFlowOperand::Register {
                register: register_addend,
            },
            ControlFlowOperand::Register { register: index },
        ]
        .into_boxed_slice();
        add_register.written_register = Some(register_addend);
        add_register.value_effect = ControlFlowValueEffect::AddRegister;
        apply_instruction(
            &mut state,
            &mut memory,
            &add_register,
            Architecture::X86_64,
            32,
            &mut truncated,
            &mut budget,
        );
        assert!(matches!(
            state[&register_addend].iter().next().unwrap().kind,
            AbstractValueKind::HeapAddress { allocation, offset: 24 } if allocation == MAIN
        ));

        state.insert(
            index,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Argument(1),
                authentication: None,
                instruction: MAIN,
            }])),
        );
        state.insert(
            source,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(HELPER),
                authentication: None,
                instruction: MAIN,
            }])),
        );
        let mut store = flow_instruction(MAIN + 1);
        store.operands = vec![
            ControlFlowOperand::IndexedMemory {
                base: heap,
                index,
                scale: 8,
                displacement: 16,
            },
            ControlFlowOperand::Register { register: source },
        ]
        .into_boxed_slice();
        store.memory_effect = ControlFlowMemoryEffect::Store;
        apply_memory_effect(
            &state,
            &mut memory,
            &store,
            Architecture::X86_64,
            32,
            &mut truncated,
            &mut budget,
        );
        assert!(memory.keys().any(|location| matches!(
            location,
            AbstractMemoryLocation::IndexedAlias {
                base: AbstractMemoryBase::Heap { allocation, offset: 0 },
                displacement: 16,
                scale: 8,
            } if *allocation == MAIN
        )));

        state.insert(
            index,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(2),
                authentication: None,
                instruction: MAIN + 2,
            }])),
        );
        let mut load = flow_instruction(MAIN + 2);
        load.operands = vec![
            ControlFlowOperand::Register { register: loaded },
            ControlFlowOperand::IndexedMemory {
                base: heap,
                index,
                scale: 8,
                displacement: 16,
            },
        ]
        .into_boxed_slice();
        load.written_register = Some(loaded);
        load.value_effect = ControlFlowValueEffect::Load;
        apply_instruction(
            &mut state,
            &mut memory,
            &load,
            Architecture::X86_64,
            32,
            &mut truncated,
            &mut budget,
        );
        assert!(
            state[&loaded]
                .iter()
                .any(|value| value.kind == AbstractValueKind::Address(HELPER))
        );
        assert!(!truncated);
    }

    #[test]
    fn protocol_qualified_arguments_narrow_objective_c_receivers() {
        let bytes = x86_materialized_fixture(true);
        let macho = image(&bytes);
        let receiver = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 7,
        };
        let mut catalog = Catalog::default();
        catalog.objc_protocol_arguments.insert(
            (MAIN, 2),
            BTreeSet::from(["Runnable".to_owned(), "Named".to_owned()]),
        );
        catalog.objc_protocol_adopters.insert(
            "Runnable".into(),
            BTreeSet::from(["Worker".into(), "Other".into()]),
        );
        catalog
            .objc_protocol_adopters
            .insert("Named".into(), BTreeSet::from(["Worker".into()]));
        catalog
            .objc_superclasses
            .insert("Worker".into(), Some("NSObject".into()));
        catalog.objc_superclasses.insert("NSObject".into(), None);
        let state = RegisterValues::from([(
            receiver,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::ProtocolArgument {
                    function: MAIN,
                    ordinal: 2,
                },
                authentication: None,
                instruction: MAIN,
            }])),
        )]);
        assert_eq!(
            objc_receiver_targets(&macho, Some(&state), None, receiver, &catalog),
            BTreeSet::from([("NSObject".into(), false), ("Worker".into(), false)])
        );
    }

    #[test]
    fn pointer_authentication_and_extensions_survive_supported_value_flow() {
        let reg = |number| ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number,
        };
        let value = |address| AbstractValue {
            kind: AbstractValueKind::Address(address),
            authentication: None,
            instruction: MAIN,
        };
        let mut state = RegisterValues::from([
            (reg(0), Arc::new(BTreeSet::from([value(HELPER)]))),
            (reg(1), Arc::new(BTreeSet::from([value(0x55)]))),
        ]);
        let mut memory = MemoryValues::new();
        let mut budget = ValueFlowWorkBudget::new(100);
        let mut truncated = false;
        let mut instruction = ControlFlowInstruction {
            address: MAIN,
            byte_len: 4,
            kind: ControlFlowInstructionKind::Other,
            target: None,
            operands: vec![
                ControlFlowOperand::Register { register: reg(0) },
                ControlFlowOperand::Register { register: reg(0) },
                ControlFlowOperand::Register { register: reg(1) },
            ]
            .into_boxed_slice(),
            written_register: Some(reg(0)),
            value_effect: ControlFlowValueEffect::SignPointerIa,
            memory_effect: ControlFlowMemoryEffect::None,
            writes_implicit_gpr0: false,
            pc_relative: None,
            coverage_confidence: FunctionEvidenceConfidence::Exact,
        };
        apply_instruction(
            &mut state,
            &mut memory,
            &instruction,
            Architecture::Arm64e,
            8,
            &mut truncated,
            &mut budget,
        );
        let signed = state[&reg(0)].iter().next().copied().unwrap();
        assert_eq!(signed.kind, AbstractValueKind::Address(HELPER));
        assert_eq!(signed.authentication.unwrap().instruction_key, Some(0));
        assert_eq!(
            signed.authentication.unwrap().instruction_modifier,
            Some(reg(1))
        );
        assert!(!signed.authentication.unwrap().authenticated_instruction);

        instruction.address += 4;
        instruction.value_effect = ControlFlowValueEffect::AuthenticatePointerIa;
        apply_instruction(
            &mut state,
            &mut memory,
            &instruction,
            Architecture::Arm64e,
            8,
            &mut truncated,
            &mut budget,
        );
        assert!(
            state[&reg(0)]
                .iter()
                .next()
                .unwrap()
                .authentication
                .unwrap()
                .authenticated_instruction
        );

        instruction.address += 4;
        instruction.operands = instruction.operands[..2].to_vec().into_boxed_slice();
        instruction.value_effect = ControlFlowValueEffect::StripPointerAuthentication;
        apply_instruction(
            &mut state,
            &mut memory,
            &instruction,
            Architecture::Arm64e,
            8,
            &mut truncated,
            &mut budget,
        );
        assert!(
            state[&reg(0)]
                .iter()
                .next()
                .unwrap()
                .authentication
                .is_none()
        );

        state.insert(reg(2), Arc::new(BTreeSet::from([value(0xffff_ff80)])));
        instruction.address += 4;
        instruction.operands = vec![
            ControlFlowOperand::Register { register: reg(3) },
            ControlFlowOperand::Register { register: reg(2) },
        ]
        .into_boxed_slice();
        instruction.written_register = Some(reg(3));
        instruction.value_effect = ControlFlowValueEffect::SignExtend8;
        apply_instruction(
            &mut state,
            &mut memory,
            &instruction,
            Architecture::Arm64e,
            8,
            &mut truncated,
            &mut budget,
        );
        assert_eq!(
            state[&reg(3)].iter().next().unwrap().kind,
            AbstractValueKind::Address(u64::MAX - 0x7f)
        );
        assert!(!truncated);
    }

    #[test]
    fn objc_super_stack_layout_recovers_starting_class_hierarchy() {
        let bytes = x86_base_relative_pointer_fixture();
        let macho = image(&bytes);
        let receiver = ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 7,
        };
        let state = RegisterValues::from([(
            receiver,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::StackAddress(0),
                authentication: None,
                instruction: MAIN,
            }])),
        )]);
        let memory = MemoryValues::from([(
            AbstractMemoryLocation::Stack(8),
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(0x1234),
                authentication: None,
                instruction: MAIN,
            }])),
        )]);
        let catalog = Catalog {
            objc_class_addresses: BTreeMap::from([(0x1234, "Child".into())]),
            objc_superclasses: BTreeMap::from([
                ("Child".into(), Some("Parent".into())),
                ("Parent".into(), None),
            ]),
            ..Catalog::default()
        };
        assert_eq!(
            objc_super_receiver_classes(&macho, Some(&state), Some(&memory), receiver, &catalog,),
            BTreeSet::from(["Child".into(), "Parent".into()])
        );
        let metaclass_values = BTreeSet::from([AbstractValue {
            kind: AbstractValueKind::Address(0x5678),
            authentication: None,
            instruction: MAIN,
        }]);
        let mut catalog = catalog;
        catalog
            .objc_metaclass_addresses
            .insert(0x5678, "Child".into());
        assert!(objc_values_are_metaclasses(
            &macho,
            &metaclass_values,
            &catalog
        ));
        assert_eq!(
            objc_classes_from_values(&macho, &metaclass_values, &catalog),
            BTreeSet::from(["Child".into(), "Parent".into()])
        );

        let object = 0x9abc;
        let instance_state = RegisterValues::from([(
            receiver,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(object),
                authentication: None,
                instruction: MAIN,
            }])),
        )]);
        let instance_memory = MemoryValues::from([(
            AbstractMemoryLocation::Global(object),
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(0x1234),
                authentication: None,
                instruction: MAIN,
            }])),
        )]);
        assert_eq!(
            objc_receiver_targets(
                &macho,
                Some(&instance_state),
                Some(&instance_memory),
                receiver,
                &catalog,
            ),
            BTreeSet::from([("Child".into(), false), ("Parent".into(), false)])
        );
        let class_state = RegisterValues::from([(
            receiver,
            Arc::new(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(0x1234),
                authentication: None,
                instruction: MAIN,
            }])),
        )]);
        assert_eq!(
            objc_receiver_targets(&macho, Some(&class_state), None, receiver, &catalog),
            BTreeSet::from([("Child".into(), true), ("Parent".into(), true)])
        );
    }

    #[test]
    fn value_flow_result_is_independent_of_edge_storage_order() {
        let bytes = x86_base_relative_pointer_fixture();
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let graph = control_flow.by_entry(MAIN).unwrap();
        let mut reversed = graph.clone();
        reversed.edges.reverse();
        let observations = BTreeSet::from([MAIN + 13]);
        let mut first_budget = ValueFlowWorkBudget::new(1_000_000);
        first_budget.begin_function(1_000_000);
        let first = recover_value_flow(
            graph,
            Architecture::X86_64,
            4_096,
            64,
            &observations,
            &AbiSummaries::new(),
            &mut first_budget,
        );
        let mut second_budget = ValueFlowWorkBudget::new(1_000_000);
        second_budget.begin_function(1_000_000);
        let second = recover_value_flow(
            &reversed,
            Architecture::X86_64,
            4_096,
            64,
            &observations,
            &AbiSummaries::new(),
            &mut second_budget,
        );
        assert_eq!(first.before, second.before);
        assert_eq!(first.truncated, second.truncated);
        assert_eq!(first.widened, second.widened);
    }

    #[test]
    fn arm64_and_arm64e_follow_adrp_ldr_indirect_calls() {
        for arm64e in [false, true] {
            let rich_bytes = arm_pointer_fixture(arm64e);
            let mut stripped_bytes = rich_bytes.clone();
            stripped_bytes[0x161..0x16f].fill(0);
            let rich = recover(&rich_bytes, IndirectCallRecoveryLimits::default());
            let stripped = recover(&stripped_bytes, IndirectCallRecoveryLimits::default());
            let call = rich
                .calls()
                .iter()
                .find(|call| call.instruction_address == MAIN + 8)
                .unwrap();
            let candidate = call
                .candidates
                .iter()
                .find(|candidate| internal_address(candidate) == Some(HELPER))
                .unwrap_or_else(|| panic!("HELPER candidate missing: {call:#?}"));
            assert_eq!(candidate.evidence_address, Some(SLOT));
            assert_eq!(
                candidate
                    .authentication
                    .map(|auth| auth.authenticated_instruction),
                arm64e.then_some(true)
            );
            assert_eq!(rich.calls(), stripped.calls());

            let rich_macho = image(&rich_bytes);
            let rich_functions =
                FunctionIndex::recover(&rich_macho, FunctionRecoveryLimits::default()).unwrap();
            let stripped_macho = image(&stripped_bytes);
            let stripped_functions =
                FunctionIndex::recover(&stripped_macho, FunctionRecoveryLimits::default()).unwrap();
            assert!(matches!(
                rich_functions.by_entry(HELPER).unwrap().identity,
                FunctionIdentity::Named { .. }
            ));
            assert!(matches!(
                stripped_functions.by_entry(HELPER).unwrap().identity,
                FunctionIdentity::Anonymous { .. }
            ));
        }
    }

    #[test]
    fn unknown_writes_do_not_masquerade_as_pointer_copies() {
        let mut bytes = x86_materialized_fixture(true);
        bytes[0x10a..0x10f].copy_from_slice(&[
            0x48, 0x31, 0xc0, // xor rax,rax
            0xff, 0xd0, // call rax
        ]);
        let index = recover(&bytes, IndirectCallRecoveryLimits::default());
        let call = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 13)
            .unwrap();
        assert!(call.candidates.is_empty());
        assert!(call.reasons.contains(&"indirect.target_unresolved".into()));
    }

    #[test]
    fn indirect_tail_branch_retains_the_same_function_identity() {
        let mut bytes = x86_materialized_fixture(true);
        bytes[0x10b] = 0xe0; // jmp rax
        let index = recover(&bytes, IndirectCallRecoveryLimits::default());
        let branch = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 10)
            .unwrap();
        assert_eq!(branch.kinds, vec![IndirectTransferKind::Branch]);
        assert!(
            branch
                .candidates
                .iter()
                .any(|candidate| internal_address(candidate) == Some(HELPER))
        );
    }

    #[test]
    fn jump_table_entries_feed_indirect_branch_candidates() {
        let index = recover(
            &x86_jump_table_fixture(),
            IndirectCallRecoveryLimits::default(),
        );
        let branch = index
            .calls()
            .iter()
            .find(|call| call.instruction_address == MAIN + 7)
            .expect("indexed branch retained");

        assert!(branch.carriers.contains(&IndirectTargetCarrier::JumpTable {
            address: MAIN + 0x30,
        }));
        assert_eq!(
            branch
                .candidates
                .iter()
                .filter(|candidate| candidate.source == IndirectCallEvidenceSource::JumpTable)
                .filter_map(internal_address)
                .collect::<Vec<_>>(),
            vec![MAIN + 0x10, MAIN + 0x18]
        );
        assert_eq!(branch.status, IndirectCallSiteStatus::Partial);
    }

    #[test]
    fn transfer_budget_reports_observed_and_omitted_sites() {
        let mut bytes = x86_materialized_fixture(true);
        bytes[0x10c] = 0xff;
        bytes[0x10d] = 0xd0;
        bytes[0x10e] = 0xc3;
        let index = recover(
            &bytes,
            IndirectCallRecoveryLimits {
                max_transfers: 1,
                ..IndirectCallRecoveryLimits::default()
            },
        );
        assert_eq!(index.calls().len(), 1);
        assert_eq!(index.completeness().observed_transfer_count, 2);
        assert_eq!(index.completeness().omitted_transfer_count, 1);
        assert_eq!(index.status(), IndirectCallIndexStatus::Truncated);
    }

    #[test]
    fn contradictory_static_targets_are_explicit_conflicts() {
        let target = |address, source| IndirectCallCandidate {
            target: IndirectCallTarget::Internal {
                address,
                functions: Vec::new(),
            },
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            evidence_address: Some(SLOT),
            authentication: None,
            detail: "test".into(),
        };
        let conflicts = indirect_conflicts(&[
            target(HELPER, IndirectCallEvidenceSource::ChainedFixup),
            target(MAIN, IndirectCallEvidenceSource::Relocation),
        ]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].evidence_address, SLOT);
        assert_eq!(conflicts[0].targets.len(), 2);
        assert_eq!(
            conflicts[0].sources,
            vec![
                IndirectCallEvidenceSource::ChainedFixup,
                IndirectCallEvidenceSource::Relocation,
            ]
        );
    }

    #[test]
    fn unnamed_and_named_import_evidence_share_one_semantic_identity() {
        let import = |name: &str, ordinal, source| IndirectCallCandidate {
            target: IndirectCallTarget::Import {
                name: name.into(),
                library_ordinal: ordinal,
            },
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            evidence_address: Some(SLOT),
            authentication: None,
            detail: "test".into(),
        };
        let mut candidates = vec![
            import("", None, IndirectCallEvidenceSource::IndirectSymbols),
            import(
                "____chkstk_darwin",
                Some(4),
                IndirectCallEvidenceSource::ChainedFixup,
            ),
        ];
        reconcile_import_aliases(&mut candidates);
        assert_eq!(candidates[0].target, candidates[1].target);
        assert!(indirect_conflicts(&candidates).is_empty());
    }

    #[test]
    fn candidate_or_ambiguous_function_ownership_is_never_complete() {
        let function = |entry, entry_confidence, ownership_confidence| IndirectFunctionCandidate {
            entry,
            entry_confidence,
            ownership_confidence,
        };
        let exact = IndirectCallTarget::Internal {
            address: HELPER,
            functions: vec![function(
                HELPER,
                FunctionEvidenceConfidence::Exact,
                FunctionOwnershipConfidence::Exact,
            )],
        };
        assert!(!target_has_uncertain_function_ownership(&exact));

        let candidate = IndirectCallTarget::Internal {
            address: HELPER,
            functions: vec![function(
                HELPER,
                FunctionEvidenceConfidence::Candidate,
                FunctionOwnershipConfidence::Candidate,
            )],
        };
        assert!(target_has_uncertain_function_ownership(&candidate));

        let ambiguous = IndirectCallTarget::Internal {
            address: HELPER,
            functions: vec![
                function(
                    HELPER,
                    FunctionEvidenceConfidence::Exact,
                    FunctionOwnershipConfidence::Exact,
                ),
                function(
                    MAIN,
                    FunctionEvidenceConfidence::Exact,
                    FunctionOwnershipConfidence::Exact,
                ),
            ],
        };
        assert!(target_has_uncertain_function_ownership(&ambiguous));
    }

    #[test]
    fn relocation_backed_pointer_slot_is_collected_with_a_receipt() {
        let bytes = x86_relocation_fixture();
        let macho = image(&bytes);
        let catalog = Catalog::collect(&macho, IndirectCallRecoveryLimits::default());
        let evidence = catalog.slots.get(&SLOT).unwrap();
        assert!(evidence.iter().any(|evidence| {
            evidence.source == IndirectCallEvidenceSource::Relocation
                && evidence.target == StaticTarget::Internal(HELPER)
        }));
        let receipt = catalog
            .receipts
            .iter()
            .find(|receipt| receipt.source == IndirectCallEvidenceSource::Relocation)
            .unwrap();
        assert_eq!(receipt.status, IndirectCollectorStatus::Complete);
        assert_eq!(receipt.examined, 1);
        assert_eq!(receipt.retained, 1);
    }

    #[test]
    fn swift_authenticated_witness_provenance_is_conserved() {
        use crate::metadata::swift::evidence::MachoSwiftWitnessPointerProvenanceV1::{
            ChainedAuthBind, Direct,
        };

        let authentication = swift_witness_authentication(&ChainedAuthBind {
            diversity: 0x1234,
            key: 2,
            address_diversity: true,
        })
        .unwrap();
        assert_eq!(authentication.key, Some(2));
        assert_eq!(authentication.diversity, Some(0x1234));
        assert_eq!(authentication.address_diversity, Some(true));
        assert!(!authentication.authenticated_instruction);
        assert!(swift_witness_authentication(&Direct).is_none());
    }

    #[test]
    fn block_literal_metadata_closes_invoke_to_function_identity() {
        let mut bytes = x86_pointer_fixture();
        bytes[0x108..0x10c].copy_from_slice(&(1_u32 << 28).to_le_bytes());
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let literal = MAIN;
        let invoke_slot = literal + 16;
        let mut catalog = Catalog::default();
        catalog.slots.insert(
            literal,
            vec![StaticEvidence {
                source: IndirectCallEvidenceSource::ChainedFixup,
                target: StaticTarget::Import {
                    name: "_NSConcreteGlobalBlock".into(),
                    ordinal: Some(1),
                },
                confidence: FunctionEvidenceConfidence::Exact,
                authentication: None,
                detail: "test_block_isa".into(),
            }],
        );
        catalog.slots.insert(
            invoke_slot,
            vec![StaticEvidence {
                source: IndirectCallEvidenceSource::Relocation,
                target: StaticTarget::Internal(HELPER),
                confidence: FunctionEvidenceConfidence::Exact,
                authentication: None,
                detail: "test_block_invoke".into(),
            }],
        );
        catalog.collect_blocks(&macho);

        let mut candidates = Vec::new();
        add_slot_candidates(
            &macho,
            &functions,
            invoke_slot,
            &catalog,
            None,
            &mut candidates,
        );
        assert!(candidates.iter().any(|candidate| matches!(
            &candidate.target,
            IndirectCallTarget::BlockInvoke {
                literal: BlockLiteralLocation::Static { address },
                storage: BlockStorageKind::Global,
                implementation,
                functions,
                ..
            } if *address == MAIN && *implementation == HELPER && functions.len() == 1
        )));
    }

    #[test]
    fn stack_block_construction_closes_invoke_to_function_identity() {
        let bytes = x86_pointer_fixture();
        let macho = image(&bytes);
        let mut catalog = Catalog::default();
        let imported_invoke_slot = SLOT + 8;
        catalog.slots.insert(
            SLOT,
            vec![StaticEvidence {
                source: IndirectCallEvidenceSource::ChainedFixup,
                target: StaticTarget::Import {
                    name: "_NSConcreteStackBlock".into(),
                    ordinal: Some(1),
                },
                confidence: FunctionEvidenceConfidence::Exact,
                authentication: None,
                detail: "test_stack_block_isa".into(),
            }],
        );
        catalog.slots.insert(
            imported_invoke_slot,
            vec![StaticEvidence {
                source: IndirectCallEvidenceSource::ChainedFixup,
                target: StaticTarget::Import {
                    name: "_external_block_invoke".into(),
                    ordinal: Some(3),
                },
                confidence: FunctionEvidenceConfidence::Exact,
                authentication: None,
                detail: "test_imported_block_invoke".into(),
            }],
        );
        let memory = BTreeMap::from([
            (
                AbstractMemoryLocation::Stack(-48),
                Arc::new(BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::PointerSlot(SLOT),
                    authentication: None,
                    instruction: MAIN,
                }])),
            ),
            (
                AbstractMemoryLocation::Stack(-32),
                Arc::new(BTreeSet::from([
                    AbstractValue {
                        kind: AbstractValueKind::Address(HELPER),
                        authentication: None,
                        instruction: MAIN,
                    },
                    AbstractValue {
                        kind: AbstractValueKind::PointerSlot(imported_invoke_slot),
                        authentication: None,
                        instruction: MAIN,
                    },
                ])),
            ),
            (
                AbstractMemoryLocation::Stack(-24),
                Arc::new(BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::Address(MAIN),
                    authentication: None,
                    instruction: MAIN,
                }])),
            ),
        ]);
        let records = dynamic_block_dispatches(
            &macho,
            &memory,
            &catalog,
            MAIN,
            &StaticTarget::Internal(HELPER),
            None,
            &BTreeSet::from([AbstractMemoryLocation::Stack(-32)]),
        );
        assert!(matches!(
            records.as_slice(),
            [BlockDispatch {
                literal: BlockLiteralLocation::Stack {
                    function: MAIN,
                    offset: -48,
                },
                descriptor: Some(MAIN),
                storage: BlockStorageKind::Stack,
                implementation: StaticTarget::Internal(HELPER),
                ..
            }]
        ));

        let imported_target = StaticTarget::Import {
            name: "_external_block_invoke".into(),
            ordinal: Some(3),
        };
        let imported_records = dynamic_block_dispatches(
            &macho,
            &memory,
            &catalog,
            MAIN,
            &imported_target,
            None,
            &BTreeSet::from([AbstractMemoryLocation::Stack(-32)]),
        );
        assert!(matches!(
            imported_records.as_slice(),
            [BlockDispatch {
                literal: BlockLiteralLocation::Stack {
                    function: MAIN,
                    offset: -48,
                },
                implementation: StaticTarget::Import { name, ordinal: Some(3) },
                ..
            }] if name == "_external_block_invoke"
        ));
    }

    #[test]
    fn qualified_cpp_and_swift_targets_retain_dispatch_identity() {
        let bytes = x86_pointer_fixture();
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let cpp = cpp_dispatch_candidate(
            &functions,
            &CppDispatch {
                vtable: SLOT - 16,
                address_point: SLOT,
                slot: 0,
                type_name: "7Fixture".into(),
                implementation: StaticTarget::Internal(HELPER),
                confidence: FunctionEvidenceConfidence::Exact,
                authentication: None,
            },
            Some(SLOT),
        );
        assert!(matches!(
            cpp.target,
            IndirectCallTarget::CppVirtualMethod {
                vtable,
                implementation: HELPER,
                ref functions,
                ..
            } if vtable == SLOT - 16 && functions.len() == 1
        ));

        let swift = swift_witness_candidate(
            &functions,
            &SwiftWitnessDispatch {
                witness_table: SLOT - 8,
                requirement: 3,
                protocol: Some("FixtureProtocol".into()),
                conforming_type: Some("FixtureType".into()),
                runtime_instantiated: false,
                implementation: StaticTarget::Internal(HELPER),
                authentication: None,
            },
            FunctionEvidenceConfidence::Exact,
            Some(SLOT),
        );
        assert!(matches!(
            swift.target,
            IndirectCallTarget::SwiftProtocolWitness {
                witness_table,
                requirement: 3,
                implementation: HELPER,
                ref functions,
                ..
            } if witness_table == SLOT - 8 && functions.len() == 1
        ));

        let cpp_import = cpp_dispatch_candidate(
            &functions,
            &CppDispatch {
                vtable: SLOT - 16,
                address_point: SLOT,
                slot: 1,
                type_name: "7Fixture".into(),
                implementation: StaticTarget::Import {
                    name: "__ZN7Fixture7virtualEv".into(),
                    ordinal: Some(2),
                },
                confidence: FunctionEvidenceConfidence::Exact,
                authentication: None,
            },
            Some(SLOT),
        );
        assert!(matches!(
            cpp_import.target,
            IndirectCallTarget::CppVirtualMethodImport {
                slot: 1,
                ref symbol,
                library_ordinal: Some(2),
                ..
            } if symbol == "__ZN7Fixture7virtualEv"
        ));

        let swift_import = swift_witness_candidate(
            &functions,
            &SwiftWitnessDispatch {
                witness_table: SLOT - 8,
                requirement: 4,
                protocol: Some("FixtureProtocol".into()),
                conforming_type: Some("FixtureType".into()),
                runtime_instantiated: false,
                implementation: StaticTarget::Import {
                    name: "$s7Fixture7witnessyyF".into(),
                    ordinal: None,
                },
                authentication: None,
            },
            FunctionEvidenceConfidence::Exact,
            Some(SLOT),
        );
        assert!(matches!(
            swift_import.target,
            IndirectCallTarget::SwiftProtocolWitnessImport {
                requirement: 4,
                ref symbol,
                library_ordinal: None,
                ..
            } if symbol == "$s7Fixture7witnessyyF"
        ));

        let block_import = block_dispatch_candidate(
            &functions,
            &BlockDispatch {
                literal: BlockLiteralLocation::Static { address: MAIN },
                descriptor: Some(SLOT),
                storage: BlockStorageKind::Global,
                implementation: StaticTarget::Import {
                    name: "_external_block_invoke".into(),
                    ordinal: Some(3),
                },
                authentication: None,
            },
            FunctionEvidenceConfidence::Exact,
            Some(SLOT),
        );
        assert!(matches!(
            block_import.target,
            IndirectCallTarget::BlockInvokeImport {
                literal: BlockLiteralLocation::Static { address: MAIN },
                ref symbol,
                library_ordinal: Some(3),
                ..
            } if symbol == "_external_block_invoke"
        ));
    }

    #[test]
    fn contradictory_swift_witnesses_keep_the_site_incomplete() {
        let candidate = |implementation| IndirectCallCandidate {
            target: IndirectCallTarget::SwiftProtocolWitness {
                witness_table: SLOT,
                requirement: 0,
                protocol: Some("FixtureProtocol".into()),
                conforming_type: Some("FixtureType".into()),
                runtime_instantiated: false,
                implementation,
                functions: Vec::new(),
            },
            source: IndirectCallEvidenceSource::Swift,
            confidence: FunctionEvidenceConfidence::Exact,
            evidence_address: Some(SLOT),
            authentication: None,
            detail: "test_witness_conflict".into(),
        };
        let conflicts = indirect_conflicts(&[candidate(MAIN), candidate(HELPER)]);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].targets.len(), 2);
    }
}
