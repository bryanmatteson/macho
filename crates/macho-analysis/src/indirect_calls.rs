//! Evidence-bearing recovery of indirect calls, branches, import stubs, and
//! dynamic-dispatch candidates.
//!
//! Every retained indirect instruction remains in the inventory even when no
//! target can be resolved. Static pointer, fixup, vtable, Objective-C, Swift,
//! and authenticated-pointer evidence is additive rather than exclusive.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use macho_core::format::constants::{
    CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64, CPU_TYPE_X86_64,
};
use macho_core::format::relocations_for_section;
use macho_core::model::addr::Va;
use macho_core::model::load_command::LoadCommand;
use macho_core::model::macho_file::MachoFile;
use macho_core::model::relocation::Relocation;
use macho_core::model::symbol::SymbolTable;
use macho_cpp::vtable::{SlotTarget, VtableIndex};
use macho_dyld::{FixupKind, parse_bind_entries, parse_chained_fixups};
use macho_symbols::{
    IndirectBindingKind, IndirectBindingsOutcome, IndirectSymbolTarget, decode_indirect_bindings,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::control_flow::{
    ControlFlowCallTarget, ControlFlowIndex, ControlFlowIndexStatus, ControlFlowInstruction,
    ControlFlowInstructionKind, ControlFlowOperand, ControlFlowPcRelativeKind,
    ControlFlowReachability, ControlFlowRegister, ControlFlowRegisterClass, ControlFlowValueEffect,
    FunctionControlFlow, FunctionControlFlowStatus,
};
use crate::functions::{
    FunctionEvidenceConfidence, FunctionImageIdentity, FunctionIndex, FunctionLookup,
    FunctionOwnershipConfidence,
};

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
    /// Maximum aggregate value-flow work units across all function CFGs.
    ///
    /// A unit is charged for each block visit, instruction evaluation,
    /// successor propagation, cloned abstract value, and merged abstract
    /// value. Exhaustion truncates value flow deterministically while leaving
    /// indirect transfer sites in the inventory as unresolved evidence.
    pub max_value_flow_work: u64,
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
            max_value_flow_work: 8_000_000,
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
            || self.max_value_flow_work == 0
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
    /// Chained bind or rebase.
    ChainedFixup,
    /// Mach-O section relocation.
    Relocation,
    /// Raw pointer bytes without relocation metadata.
    RawPointer,
    /// Address materialized by instructions.
    InstructionValueFlow,
    /// C++ vtable slot.
    CppVtable,
    /// Objective-C selector/method dispatch.
    ObjectiveC,
    /// Swift class vtable, override, or protocol dispatch record.
    Swift,
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
    /// Decoder retained no more specific carrier.
    Unknown,
}

/// Authentication evidence associated with an indirect target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Aggregate deterministic value-flow work units consumed.
    pub value_flow_work: u64,
}

/// Deterministic indirect-call and branch inventory tied to one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct IndirectCallIndex {
    image: FunctionImageIdentity,
    limits: IndirectCallRecoveryLimits,
    calls: Vec<RecoveredIndirectCall>,
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
    objc_methods: Vec<ObjcDispatch>,
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
    detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum AbstractValueKind {
    Address(u64),
    PointerSlot(u64),
    DynamicSlot(i64),
}

#[derive(Debug, Clone, Copy)]
struct AbstractValue {
    kind: AbstractValueKind,
    instruction: u64,
}

impl PartialEq for AbstractValue {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind
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
        self.kind.cmp(&other.kind)
    }
}

type RegisterValues = BTreeMap<ControlFlowRegister, BTreeSet<AbstractValue>>;

impl IndirectCallIndex {
    /// Recover indirect calls, branches, import stubs, and dynamic dispatch.
    pub fn recover(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: IndirectCallRecoveryLimits,
    ) -> Result<Self, IndirectCallRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        if &image != functions.image() || &image != control_flow.image() {
            return Err(IndirectCallRecoveryError::ImageMismatch);
        }
        let architecture = Architecture::from_macho(macho)
            .ok_or(IndirectCallRecoveryError::UnsupportedArchitecture)?;
        let mut catalog = Catalog::collect(macho, limits);
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
        let mut value_flow_budget = ValueFlowWorkBudget::new(limits.max_value_flow_work);
        for graph in control_flow.functions().iter().take(admitted) {
            let flow = recover_value_flow(
                graph,
                architecture,
                limits.max_values_per_register,
                &mut value_flow_budget,
            );
            value_flow_truncated |= flow.truncated;
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
                    &catalog,
                    architecture,
                    limits.max_candidates_per_transfer,
                    flow.truncated,
                );
                omitted_candidate_count =
                    omitted_candidate_count.saturating_add(recovered.omitted_candidate_count);
                calls.push(recovered);
            }
            for exit in &graph.exits {
                if exit.kind != crate::control_flow::ControlFlowExitKind::IndirectBranch {
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
                    &catalog,
                    architecture,
                    limits.max_candidates_per_transfer,
                    flow.truncated,
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
        Ok(Self {
            image,
            limits,
            calls,
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
                value_flow_work: value_flow_budget.consumed,
            },
        })
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
}

impl Catalog {
    fn collect(macho: &MachoFile<'_>, limits: IndirectCallRecoveryLimits) -> Self {
        let mut catalog = Self::default();
        catalog.collect_indirect_symbols(macho, limits.max_indirect_bindings);
        catalog.collect_chained(macho, limits.max_chained_fixups);
        catalog.collect_legacy(macho, limits.max_legacy_binds);
        catalog.collect_relocations(macho, limits.max_relocations);
        catalog.collect_cpp(macho, limits.max_cpp_vtables);
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
        bindings: Vec<macho_symbols::IndirectSymbolBinding>,
    ) -> u64 {
        let mut retained = 0_u64;
        for binding in bindings {
            let target = match binding.target {
                IndirectSymbolTarget::Symbol { name, .. } => StaticTarget::Import {
                    name,
                    ordinal: None,
                },
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
        let result = macho_objc::fold_method_imps(macho, (), |_, method| {
            examined = examined.saturating_add(1);
            if self.objc_methods.len() == limit {
                truncated = true;
                return Err(macho_objc::ObjcError::unsupported(
                    "indirect Objective-C method budget",
                ));
            }
            self.objc_methods.push(ObjcDispatch {
                class_name: method.class_name.to_owned(),
                selector: method.method_name.to_owned(),
                class_method: matches!(method.kind, macho_objc::ObjCMethodKind::Class),
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
        use macho_swift::evidence::{SwiftDecodeOutcomeV1, SwiftEvidenceLimits};
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
        let batch = macho_swift::evidence::decode_swift_strict(macho, &limits);
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

#[derive(Default)]
struct ValueFlow {
    before: BTreeMap<u64, RegisterValues>,
    truncated: bool,
}

struct ValueFlowWorkBudget {
    remaining: u64,
    consumed: u64,
    exhausted: bool,
}

impl ValueFlowWorkBudget {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            consumed: 0,
            exhausted: false,
        }
    }

    fn consume(&mut self, units: u64) -> bool {
        if units <= self.remaining {
            self.remaining -= units;
            self.consumed += units;
            true
        } else {
            self.consumed += self.remaining;
            self.remaining = 0;
            self.exhausted = true;
            false
        }
    }
}

fn recover_value_flow(
    graph: &FunctionControlFlow,
    architecture: Architecture,
    maximum: usize,
    work_budget: &mut ValueFlowWorkBudget,
) -> ValueFlow {
    let mut result = ValueFlow::default();
    if work_budget.exhausted {
        result.truncated = true;
        return result;
    }
    let mut entries = vec![None::<RegisterValues>; graph.blocks.len()];
    let mut queued = vec![false; graph.blocks.len()];
    let mut successors = vec![Vec::<usize>::new(); graph.blocks.len()];
    for edge in &graph.edges {
        let source = edge.from as usize;
        let target = edge.to as usize;
        if source < successors.len() && target < successors.len() {
            successors[source].push(target);
        }
    }
    for targets in &mut successors {
        targets.sort_unstable();
        targets.dedup();
    }
    let mut work = VecDeque::new();
    if let Some(entry) = graph
        .blocks
        .iter()
        .find(|block| block.start == graph.function_entry)
    {
        entries[entry.id as usize] = Some(RegisterValues::new());
        work.push_back(entry.id as usize);
        queued[entry.id as usize] = true;
    }
    while let Some(block_index) = work.pop_front() {
        if !work_budget.consume(1) {
            result.truncated = true;
            return result;
        }
        queued[block_index] = false;
        let block = &graph.blocks[block_index];
        let entry_state = entries[block_index].as_ref().cloned().unwrap_or_default();
        if !work_budget.consume(register_value_count(&entry_state)) {
            result.truncated = true;
            return result;
        }
        let mut state = entry_state;
        let start = block.first_instruction as usize;
        let end = start + block.instruction_count as usize;
        for instruction in &graph.instructions[start..end] {
            if !work_budget.consume(1) {
                result.truncated = true;
                return result;
            }
            merge_state(
                result.before.entry(instruction.address).or_default(),
                &state,
                maximum,
                &mut result.truncated,
                work_budget,
            );
            apply_instruction(
                &mut state,
                instruction,
                architecture,
                maximum,
                &mut result.truncated,
                work_budget,
            );
            if work_budget.exhausted {
                result.truncated = true;
                return result;
            }
        }
        for &target in &successors[block_index] {
            if !work_budget.consume(1) {
                result.truncated = true;
                return result;
            }
            let changed = if let Some(existing) = entries[target].as_mut() {
                merge_state(
                    existing,
                    &state,
                    maximum,
                    &mut result.truncated,
                    work_budget,
                )
            } else {
                if !work_budget.consume(register_value_count(&state)) {
                    result.truncated = true;
                    return result;
                }
                entries[target] = Some(state.clone());
                true
            };
            if changed && !queued[target] {
                work.push_back(target);
                queued[target] = true;
            }
        }
    }
    // Unreachable or unknown blocks still contain evidence. Analyze them from
    // an empty state so local address materialization is not discarded.
    for block in &graph.blocks {
        if entries[block.id as usize].is_some() {
            continue;
        }
        let mut state = RegisterValues::new();
        let start = block.first_instruction as usize;
        let end = start + block.instruction_count as usize;
        for instruction in &graph.instructions[start..end] {
            if !work_budget.consume(1) {
                result.truncated = true;
                return result;
            }
            merge_state(
                result.before.entry(instruction.address).or_default(),
                &state,
                maximum,
                &mut result.truncated,
                work_budget,
            );
            apply_instruction(
                &mut state,
                instruction,
                architecture,
                maximum,
                &mut result.truncated,
                work_budget,
            );
            if work_budget.exhausted {
                result.truncated = true;
                return result;
            }
        }
    }
    result
}

fn register_value_count(state: &RegisterValues) -> u64 {
    state
        .values()
        .map(|values| values.len() as u64)
        .sum::<u64>()
}

fn apply_instruction(
    state: &mut RegisterValues,
    instruction: &ControlFlowInstruction,
    architecture: Architecture,
    maximum: usize,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) {
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
                instruction: instruction.address,
            });
        } else if let Some(value) =
            evaluate_written_value(state, instruction, architecture, truncated, work_budget)
        {
            values.extend(value);
        }
        if values.len() > maximum {
            values = values.into_iter().take(maximum).collect();
            *truncated = true;
        }
        if values.is_empty() {
            state.remove(&destination);
        } else {
            state.insert(destination, values);
        }
    }
    if instruction.writes_implicit_gpr0 {
        state.remove(&ControlFlowRegister {
            class: ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        });
    }
    if instruction.kind == ControlFlowInstructionKind::Call {
        state.retain(|register, _| !caller_saved(architecture, *register));
    }
}

fn evaluate_written_value(
    state: &RegisterValues,
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
                Some(values.clone())
            }
            ControlFlowOperand::Immediate { value } => Some(BTreeSet::from([AbstractValue {
                kind: AbstractValueKind::Address(*value as u64),
                instruction: instruction.address,
            }])),
            ControlFlowOperand::Memory { .. } => None,
        },
        ControlFlowValueEffect::Address | ControlFlowValueEffect::Load => {
            let (base, displacement) = operands.iter().find_map(|operand| match operand {
                ControlFlowOperand::Memory { base, displacement } => Some((base, displacement)),
                _ => None,
            })?;
            if let Some(base_values) = state.get(base) {
                let mut result = BTreeSet::new();
                for value in base_values {
                    if !work_budget.consume(1) {
                        *truncated = true;
                        break;
                    }
                    if let Some(value) = match value.kind {
                        AbstractValueKind::Address(address) => Some(AbstractValue {
                            kind: if instruction.value_effect == ControlFlowValueEffect::Load {
                                AbstractValueKind::PointerSlot(
                                    address.wrapping_add_signed(*displacement),
                                )
                            } else {
                                AbstractValueKind::Address(
                                    address.wrapping_add_signed(*displacement),
                                )
                            },
                            instruction: instruction.address,
                        }),
                        _ => None,
                    } {
                        result.insert(value);
                    }
                }
                return Some(result);
            }
            (instruction.value_effect == ControlFlowValueEffect::Load).then(|| {
                BTreeSet::from([AbstractValue {
                    kind: AbstractValueKind::DynamicSlot(*displacement),
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
            for value in state.get(&source)? {
                if !work_budget.consume(1) {
                    *truncated = true;
                    break;
                }
                if let Some(value) = match value.kind {
                    AbstractValueKind::Address(address) => Some(AbstractValue {
                        kind: AbstractValueKind::Address(address.wrapping_add_signed(addend)),
                        instruction: instruction.address,
                    }),
                    AbstractValueKind::PointerSlot(address) if addend == 0 => Some(AbstractValue {
                        kind: AbstractValueKind::PointerSlot(address),
                        instruction: instruction.address,
                    }),
                    AbstractValueKind::DynamicSlot(offset) => Some(AbstractValue {
                        kind: AbstractValueKind::DynamicSlot(offset.saturating_add(addend)),
                        instruction: instruction.address,
                    }),
                    _ => None,
                } {
                    result.insert(value);
                }
            }
            Some(result)
        }
        ControlFlowValueEffect::None | ControlFlowValueEffect::UnknownWrite => None,
    }
}

fn merge_state(
    destination: &mut RegisterValues,
    source: &RegisterValues,
    maximum: usize,
    truncated: &mut bool,
    work_budget: &mut ValueFlowWorkBudget,
) -> bool {
    let mut changed = false;
    for (register, values) in source {
        let retained = destination.entry(*register).or_default();
        for value in values {
            if !work_budget.consume(1) {
                *truncated = true;
                return changed;
            }
            if retained.len() == maximum && !retained.contains(value) {
                *truncated = true;
                continue;
            }
            changed |= retained.insert(*value);
        }
    }
    changed
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
    catalog: &Catalog,
    architecture: Architecture,
    maximum_candidates: usize,
    value_flow_truncated: bool,
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
        let target_register = instruction
            .operands
            .first()
            .and_then(|operand| match operand {
                ControlFlowOperand::Register { register } => Some(*register),
                _ => None,
            });
        if let Some(register) = target_register {
            carriers.push(IndirectTargetCarrier::Register { register });
            if let Some(values) = state.and_then(|state| state.get(&register)) {
                for value in values {
                    add_value_candidates(
                        macho,
                        functions,
                        *value,
                        catalog,
                        instruction_authentication,
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
                add_dynamic_slot_candidates(functions, *displacement, catalog, &mut candidates);
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
        let mut matched = 0_u64;
        for method in &catalog.objc_methods {
            if !selectors.is_empty() && !selectors.contains(&method.selector) {
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
                } else {
                    "objc_selector_match"
                }
                .into(),
            });
            matched = matched.saturating_add(1);
        }
        if selectors.is_empty() {
            reasons.insert("indirect.objc_selector_unresolved".into());
        } else if matched == 0 {
            reasons.insert("indirect.objc_selector_without_implementation".into());
        }
    }
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
        IndirectCallTarget::Import { .. } => false,
        IndirectCallTarget::Internal { functions, .. }
        | IndirectCallTarget::ObjectiveCMethod { functions, .. }
        | IndirectCallTarget::SwiftImplementation { functions, .. } => functions.is_empty(),
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
    if !conflicts.is_empty() {
        reasons.insert("indirect.evidence_conflict".into());
    }
    if missing_function_identity {
        reasons.insert("indirect.target_without_function_identity".into());
    }
    if uncertain_function_ownership {
        reasons.insert("indirect.function_ownership_uncertain".into());
    }
    let status = if omitted_candidate_count != 0 || value_flow_truncated {
        IndirectCallSiteStatus::Truncated
    } else if candidates.is_empty()
        || !conflicts.is_empty()
        || missing_function_identity
        || uncertain_function_ownership
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
        status,
        reasons: reasons.into_iter().collect(),
    }
}

fn target_has_uncertain_function_ownership(target: &IndirectCallTarget) -> bool {
    let functions = match target {
        IndirectCallTarget::Import { .. } => return false,
        IndirectCallTarget::Internal { functions, .. }
        | IndirectCallTarget::ObjectiveCMethod { functions, .. }
        | IndirectCallTarget::SwiftImplementation { functions, .. } => functions,
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
                | IndirectCallEvidenceSource::ChainedFixup
                | IndirectCallEvidenceSource::Relocation
                | IndirectCallEvidenceSource::RawPointer
                | IndirectCallEvidenceSource::CppVtable
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
    macho: &MachoFile<'_>,
    functions: &FunctionIndex,
    value: AbstractValue,
    catalog: &Catalog,
    instruction_authentication: Option<PointerAuthentication>,
    carriers: &mut Vec<IndirectTargetCarrier>,
    candidates: &mut Vec<IndirectCallCandidate>,
) {
    match value.kind {
        AbstractValueKind::Address(address) => {
            candidates.push(internal_candidate(
                functions,
                address,
                IndirectCallEvidenceSource::InstructionValueFlow,
                FunctionEvidenceConfidence::Derived,
                Some(value.instruction),
                instruction_authentication,
                "materialized_address",
            ));
            if catalog.slots.get(&address).is_some_and(|evidence| {
                evidence.iter().any(|record| record.detail == "symbol_stub")
            }) {
                carriers.push(IndirectTargetCarrier::ImportStub { address });
                add_slot_candidates(
                    macho,
                    functions,
                    address,
                    catalog,
                    instruction_authentication,
                    candidates,
                );
            }
        }
        AbstractValueKind::PointerSlot(address) => {
            carriers.push(IndirectTargetCarrier::PointerSlot { address });
            add_slot_candidates(
                macho,
                functions,
                address,
                catalog,
                instruction_authentication,
                candidates,
            );
        }
        AbstractValueKind::DynamicSlot(displacement) => {
            carriers.push(IndirectTargetCarrier::DynamicMemory {
                base: None,
                displacement,
            });
            add_dynamic_slot_candidates(functions, displacement, catalog, candidates);
        }
    }
}

fn add_slot_candidates(
    macho: &MachoFile<'_>,
    functions: &FunctionIndex,
    slot: u64,
    catalog: &Catalog,
    instruction_authentication: Option<PointerAuthentication>,
    candidates: &mut Vec<IndirectCallCandidate>,
) {
    if let Some(evidence) = catalog.slots.get(&slot) {
        for record in evidence {
            let authentication =
                merge_authentication(record.authentication, instruction_authentication);
            candidates.push(static_candidate(
                functions,
                record,
                Some(slot),
                authentication,
            ));
        }
        return;
    }
    if let Some(raw) = read_pointer(macho, slot)
        && raw != 0
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
    if let Some(records) = catalog.cpp_offsets.get(&displacement) {
        for record in records {
            candidates.push(static_candidate(functions, record, None, None));
        }
    }
    if let Some(records) = catalog.swift_offsets.get(&displacement) {
        for record in records {
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
                authentication: None,
                detail: "dynamic_slot_offset_match".into(),
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
            authentication: None,
            detail: "unindexed_swift_override_candidate".into(),
        });
    }
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
    IndirectCallCandidate {
        target: IndirectCallTarget::Internal {
            address,
            functions: function_candidates(functions, address),
        },
        source,
        confidence,
        evidence_address,
        authentication,
        detail: detail.into(),
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
    match functions.containing(address) {
        FunctionLookup::None => {}
        FunctionLookup::One(owner) => add(owner.function.entry, owner.confidence),
        FunctionLookup::Ambiguous(owners) => {
            for owner in owners {
                add(owner.function.entry, owner.confidence);
            }
        }
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
    for value in values {
        let address = match value.kind {
            AbstractValueKind::Address(address) => Some(address),
            AbstractValueKind::PointerSlot(slot) => read_pointer(macho, slot),
            AbstractValueKind::DynamicSlot(_) => None,
        };
        if let Some(address) = address
            && let Some(selector) = read_cstring(macho, address)
        {
            result.insert(selector);
        }
    }
    result
}

fn read_pointer(macho: &MachoFile<'_>, address: u64) -> Option<u64> {
    let bytes = macho.read_bytes_at_va(Va(address), 8).ok()?;
    Some(macho.endian().read_u64(bytes.try_into().ok()?))
}

fn read_cstring(macho: &MachoFile<'_>, address: u64) -> Option<String> {
    let available = macho
        .all_sections()
        .find_map(|section| {
            let end = section.addr().0.checked_add(section.size())?;
            (section.addr().0 <= address && address < end).then_some(end - address)
        })
        .or_else(|| {
            macho.segments().iter().find_map(|segment| {
                let relative = address.checked_sub(segment.vm_addr().0)?;
                (relative < segment.file_size()).then_some(segment.file_size() - relative)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_flow::ControlFlowLimits;
    use crate::functions::{FunctionIdentity, FunctionRecoveryLimits};

    const MAIN: u64 = 0x1_0000_0100;
    const HELPER: u64 = 0x1_0000_0120;
    const SLOT: u64 = 0x1_0000_0130;

    fn image(bytes: &[u8]) -> macho_core::MachoFile<'_> {
        match macho_core::parse(bytes).expect("fixture parses") {
            macho_core::model::container::MachoContainer::Thin(macho) => macho,
            macho_core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    fn move_helper(bytes: &mut [u8]) {
        bytes[0x158..0x160].copy_from_slice(&HELPER.to_le_bytes());
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
                .unwrap();
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
}
