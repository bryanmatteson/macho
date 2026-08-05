//! Unified construction and queries over Macho-owned program recovery.
//!
//! A [`crate::program::RecoveredProgram`] owns the function inventory, control-flow graphs,
//! direct call graph, direct transfer/thunk index, and indirect-transfer index
//! for one exact thin image. Nested limits remain explicit, stage partiality is
//! conserved, and callers do not need to reconstruct relationships between
//! independently built indexes.

use std::collections::BTreeSet;

use macho_core::model::macho_file::MachoFile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::call_graph::{
    DirectCallEdge, DirectCallGraph, DirectCallGraphError, DirectCallGraphLimits,
    DirectCallGraphStatus, DirectCallNode,
};
use crate::control_flow::{
    ControlFlowIndex, ControlFlowIndexStatus, ControlFlowLimits, ControlFlowRecoveryError,
    FunctionControlFlow,
};
use crate::functions::{
    FunctionCollectorStatus, FunctionImageIdentity, FunctionIndex, FunctionLookup,
    FunctionRecoveryError, FunctionRecoveryLimits, RecoveredFunction,
};
use crate::indirect_calls::{
    IndirectCallIndex, IndirectCallIndexStatus, IndirectCallRecoveryError,
    IndirectCallRecoveryLimits, RecoveredIndirectCall,
};
use crate::transfers::{
    DirectFunctionTransfer, DirectTransferIndex, FunctionTargetResolution, RecoveredThunk,
    TransferIndexStatus, TransferRecoveryError, TransferRecoveryLimits,
};

/// Explicit nested limits for one complete program-recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ProgramRecoveryLimits {
    /// Function inventory limits.
    pub functions: FunctionRecoveryLimits,
    /// Basic-block and CFG limits.
    pub control_flow: ControlFlowLimits,
    /// Direct call-graph limits.
    pub direct_calls: DirectCallGraphLimits,
    /// Direct branch, tail-call, and thunk limits.
    pub transfers: TransferRecoveryLimits,
    /// Indirect transfer and dynamic-dispatch limits.
    pub indirect_calls: IndirectCallRecoveryLimits,
}

impl ProgramRecoveryLimits {
    /// Validate every nested limit before any image recovery begins.
    pub fn validate(self) -> Result<Self, ProgramRecoveryError> {
        self.functions.validate()?;
        self.control_flow.validate()?;
        self.direct_calls.validate()?;
        self.transfers.validate()?;
        self.indirect_calls.validate()?;
        Ok(self)
    }
}

/// Failure preventing the unified program from being constructed.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ProgramRecoveryError {
    /// A supplied function inventory used different limits than the program.
    #[error("supplied function inventory limits differ from program limits")]
    FunctionLimitsMismatch,
    /// A supplied function inventory belongs to different image bytes.
    #[error("supplied function inventory and Mach-O image identities differ")]
    FunctionImageMismatch,
    /// Function inventory construction failed.
    #[error(transparent)]
    Functions(#[from] FunctionRecoveryError),
    /// Control-flow construction failed.
    #[error(transparent)]
    ControlFlow(#[from] ControlFlowRecoveryError),
    /// Direct call-graph construction failed.
    #[error(transparent)]
    DirectCalls(#[from] DirectCallGraphError),
    /// Direct transfer/thunk construction failed.
    #[error(transparent)]
    Transfers(#[from] TransferRecoveryError),
    /// Indirect transfer construction failed.
    #[error(transparent)]
    IndirectCalls(#[from] IndirectCallRecoveryError),
}

/// One layer of the unified recovery pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramRecoveryStage {
    /// Function identities and ownership.
    Functions,
    /// Basic blocks and intra-procedural control flow.
    ControlFlow,
    /// Direct call graph.
    DirectCalls,
    /// Direct branches, tail calls, and thunks.
    Transfers,
    /// Indirect calls, branches, and dynamic dispatch.
    IndirectCalls,
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
    /// Stage completion state.
    pub status: ProgramRecoveryStatus,
    /// Stable reason codes retained from that stage.
    pub reasons: Vec<String>,
}

/// Global completion ledger for a recovered program.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProgramRecoveryCompleteness {
    /// Weakest completion state across all stages.
    pub status: ProgramRecoveryStatus,
    /// One receipt per stage in deterministic pipeline order.
    pub stages: Vec<ProgramStageReceipt>,
    /// Stable program-level reasons identifying incomplete stages.
    pub reasons: Vec<String>,
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
}

/// A direct call edge paired with its current thunk-resolved destination.
#[derive(Debug, Clone)]
pub struct ResolvedDirectCallEdge<'program> {
    /// Original direct edge and its callsite evidence.
    pub edge: &'program DirectCallEdge,
    /// Direct, thunk-chain, cycle, depth-limited, or truncated resolution.
    pub resolution: FunctionTargetResolution,
}

/// Deterministic Macho-owned recovery of one exact thin image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RecoveredProgram {
    image: FunctionImageIdentity,
    limits: ProgramRecoveryLimits,
    functions: FunctionIndex,
    control_flow: ControlFlowIndex,
    direct_calls: DirectCallGraph,
    transfers: DirectTransferIndex,
    indirect_calls: IndirectCallIndex,
    completeness: ProgramRecoveryCompleteness,
}

impl RecoveredProgram {
    /// Recover every owned program layer from one image and one explicit limit
    /// set. All limits are validated before the first collector runs.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: ProgramRecoveryLimits,
    ) -> Result<Self, ProgramRecoveryError> {
        let limits = limits.validate()?;
        let functions = FunctionIndex::recover(macho, limits.functions)?;
        Self::recover_from_validated_functions(macho, functions, limits)
    }

    /// Recover all program layers from an already constructed authoritative
    /// function inventory. This lets selective Macho consumers reuse function
    /// recovery without collecting its evidence twice.
    pub fn recover_from_functions(
        macho: &MachoFile<'_>,
        functions: FunctionIndex,
        limits: ProgramRecoveryLimits,
    ) -> Result<Self, ProgramRecoveryError> {
        let limits = limits.validate()?;
        if functions.limits() != limits.functions {
            return Err(ProgramRecoveryError::FunctionLimitsMismatch);
        }
        if functions.image() != &FunctionImageIdentity::from_macho(macho) {
            return Err(ProgramRecoveryError::FunctionImageMismatch);
        }
        Self::recover_from_validated_functions(macho, functions, limits)
    }

    fn recover_from_validated_functions(
        macho: &MachoFile<'_>,
        functions: FunctionIndex,
        limits: ProgramRecoveryLimits,
    ) -> Result<Self, ProgramRecoveryError> {
        let control_flow = ControlFlowIndex::recover(macho, &functions, limits.control_flow)?;
        let direct_calls = DirectCallGraph::build(&functions, &control_flow, limits.direct_calls)?;
        let transfers = DirectTransferIndex::recover(&functions, &control_flow, limits.transfers)?;
        let indirect_calls =
            IndirectCallIndex::recover(macho, &functions, &control_flow, limits.indirect_calls)?;
        let completeness = program_completeness(
            &functions,
            &control_flow,
            &direct_calls,
            &transfers,
            &indirect_calls,
        );
        Ok(Self {
            image: functions.image().clone(),
            limits,
            functions,
            control_flow,
            direct_calls,
            transfers,
            indirect_calls,
            completeness,
        })
    }

    /// Exact content and architecture identity shared by every stage.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact nested limits used to construct this program.
    pub const fn limits(&self) -> ProgramRecoveryLimits {
        self.limits
    }

    /// Unified completion ledger.
    pub fn completeness(&self) -> &ProgramRecoveryCompleteness {
        &self.completeness
    }

    /// Overall program status.
    pub const fn status(&self) -> ProgramRecoveryStatus {
        self.completeness.status
    }

    /// Authoritative function inventory.
    pub fn functions(&self) -> &FunctionIndex {
        &self.functions
    }

    /// Per-function basic blocks and CFGs.
    pub fn control_flow(&self) -> &ControlFlowIndex {
        &self.control_flow
    }

    /// Direct call graph over recovered function identities.
    pub fn direct_calls(&self) -> &DirectCallGraph {
        &self.direct_calls
    }

    /// Direct branches, tail calls, and thunk resolutions.
    pub fn transfers(&self) -> &DirectTransferIndex {
        &self.transfers
    }

    /// Indirect calls, branches, pointer targets, and dynamic dispatch.
    pub fn indirect_calls(&self) -> &IndirectCallIndex {
        &self.indirect_calls
    }

    /// Authoritative answer to which recovered function or functions contain
    /// an instruction address.
    pub fn function_containing(&self, instruction_address: u64) -> FunctionLookup<'_> {
        self.functions.containing(instruction_address)
    }

    /// Find one function and every retained program layer attached to it.
    pub fn function_by_entry(&self, entry: u64) -> Option<ProgramFunctionView<'_>> {
        let function = self.functions.by_entry(entry)?;
        Some(ProgramFunctionView {
            function,
            control_flow: self.control_flow.by_entry(entry),
            direct_call_node: self.direct_calls.by_entry(entry),
            thunk: self.transfers.thunk_by_entry(entry),
        })
    }

    /// Iterate retained direct call edges from one caller, paired with final
    /// thunk resolution when available.
    pub fn resolved_direct_outgoing(
        &self,
        caller: u64,
    ) -> impl Iterator<Item = ResolvedDirectCallEdge<'_>> {
        self.direct_calls.outgoing(caller).filter_map(|edge| {
            self.transfers
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
        self.direct_calls.edges().iter().filter_map(move |edge| {
            let resolution = self.transfers.resolve_function_target(edge.callee)?;
            (resolution.final_target == Some(callee))
                .then_some(ResolvedDirectCallEdge { edge, resolution })
        })
    }

    /// Iterate direct branch, tail-call, and thunk evidence from one function.
    pub fn direct_transfers_from(
        &self,
        source: u64,
    ) -> impl Iterator<Item = &DirectFunctionTransfer> {
        self.transfers.from_function(source)
    }

    /// Iterate indirect calls, branches, and dynamic dispatch from one
    /// recovered function identity.
    pub fn indirect_calls_from(&self, source: u64) -> impl Iterator<Item = &RecoveredIndirectCall> {
        self.indirect_calls.from_function(source)
    }
}

fn program_completeness(
    functions: &FunctionIndex,
    control_flow: &ControlFlowIndex,
    direct_calls: &DirectCallGraph,
    transfers: &DirectTransferIndex,
    indirect_calls: &IndirectCallIndex,
) -> ProgramRecoveryCompleteness {
    let mut stages = vec![function_receipt(functions)];
    stages.push(ProgramStageReceipt {
        stage: ProgramRecoveryStage::ControlFlow,
        status: match control_flow.status() {
            ControlFlowIndexStatus::Complete => ProgramRecoveryStatus::Complete,
            ControlFlowIndexStatus::Partial => ProgramRecoveryStatus::Partial,
            ControlFlowIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
        },
        reasons: control_flow_reasons(control_flow),
    });
    stages.push(ProgramStageReceipt {
        stage: ProgramRecoveryStage::DirectCalls,
        status: match direct_calls.status() {
            DirectCallGraphStatus::Complete => ProgramRecoveryStatus::Complete,
            DirectCallGraphStatus::Partial => ProgramRecoveryStatus::Partial,
            DirectCallGraphStatus::Truncated => ProgramRecoveryStatus::Truncated,
        },
        reasons: direct_calls.completeness().reasons.clone(),
    });
    stages.push(ProgramStageReceipt {
        stage: ProgramRecoveryStage::Transfers,
        status: match transfers.status() {
            TransferIndexStatus::Complete => ProgramRecoveryStatus::Complete,
            TransferIndexStatus::Partial => ProgramRecoveryStatus::Partial,
            TransferIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
        },
        reasons: transfers.completeness().reasons.clone(),
    });
    stages.push(ProgramStageReceipt {
        stage: ProgramRecoveryStage::IndirectCalls,
        status: match indirect_calls.status() {
            IndirectCallIndexStatus::Complete => ProgramRecoveryStatus::Complete,
            IndirectCallIndexStatus::Partial => ProgramRecoveryStatus::Partial,
            IndirectCallIndexStatus::Truncated => ProgramRecoveryStatus::Truncated,
        },
        reasons: indirect_calls.completeness().reasons.clone(),
    });

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
        .map(|stage| match (stage.stage, stage.status) {
            (ProgramRecoveryStage::Functions, ProgramRecoveryStatus::Partial) => {
                "program.functions_partial"
            }
            (ProgramRecoveryStage::Functions, ProgramRecoveryStatus::Truncated) => {
                "program.functions_truncated"
            }
            (ProgramRecoveryStage::ControlFlow, ProgramRecoveryStatus::Partial) => {
                "program.control_flow_partial"
            }
            (ProgramRecoveryStage::ControlFlow, ProgramRecoveryStatus::Truncated) => {
                "program.control_flow_truncated"
            }
            (ProgramRecoveryStage::DirectCalls, ProgramRecoveryStatus::Partial) => {
                "program.direct_calls_partial"
            }
            (ProgramRecoveryStage::DirectCalls, ProgramRecoveryStatus::Truncated) => {
                "program.direct_calls_truncated"
            }
            (ProgramRecoveryStage::Transfers, ProgramRecoveryStatus::Partial) => {
                "program.transfers_partial"
            }
            (ProgramRecoveryStage::Transfers, ProgramRecoveryStatus::Truncated) => {
                "program.transfers_truncated"
            }
            (ProgramRecoveryStage::IndirectCalls, ProgramRecoveryStatus::Partial) => {
                "program.indirect_calls_partial"
            }
            (ProgramRecoveryStage::IndirectCalls, ProgramRecoveryStatus::Truncated) => {
                "program.indirect_calls_truncated"
            }
            (_, ProgramRecoveryStatus::Complete) => unreachable!("filtered complete stage"),
        })
        .map(str::to_owned)
        .collect();
    ProgramRecoveryCompleteness {
        status,
        stages,
        reasons,
    }
}

fn function_receipt(functions: &FunctionIndex) -> ProgramStageReceipt {
    let truncated = functions.truncated_function_count() != 0
        || functions
            .receipts()
            .iter()
            .any(|receipt| receipt.status == FunctionCollectorStatus::Truncated);
    let has_candidate_entries = functions.functions().iter().any(|function| {
        function.entry_confidence == crate::functions::FunctionEvidenceConfidence::Candidate
    });
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
    use crate::functions::FunctionIdentity;
    use crate::indirect_calls::IndirectCallTarget;
    use crate::transfers::TransferResolutionStatus;

    const MAIN: u64 = 0x1_0000_0100;
    const THUNK: u64 = 0x1_0000_0120;
    const FINAL: u64 = 0x1_0000_0130;

    fn image(bytes: &[u8]) -> macho_core::MachoFile<'_> {
        match macho_core::parse(bytes).expect("fixture parses") {
            macho_core::model::container::MachoContainer::Thin(macho) => macho,
            macho_core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
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

    fn recover(bytes: &[u8], limits: ProgramRecoveryLimits) -> RecoveredProgram {
        RecoveredProgram::recover(&image(bytes), limits).unwrap()
    }

    #[test]
    fn one_program_owns_every_index_and_authoritative_ownership_query() {
        let program = recover(&full_x86_fixture(true), ProgramRecoveryLimits::default());
        assert_eq!(program.completeness().stages.len(), 5);
        assert!(
            program
                .completeness()
                .stages
                .windows(2)
                .all(|pair| pair[0].stage < pair[1].stage)
        );
        for image in [
            program.functions().image(),
            program.control_flow().image(),
            program.direct_calls().image(),
            program.transfers().image(),
            program.indirect_calls().image(),
        ] {
            assert_eq!(image, program.image());
        }
        let owner = match program.function_containing(MAIN + 15) {
            FunctionLookup::One(owner) => owner,
            other => panic!("expected one owner, got {other:?}"),
        };
        assert_eq!(owner.function.entry, MAIN);
        let view = program.function_by_entry(THUNK).unwrap();
        assert!(view.control_flow.is_some());
        assert!(view.direct_call_node.is_some());
        assert!(view.thunk.is_some());
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
            rich.control_flow().functions().len(),
            stripped.control_flow().functions().len()
        );
        assert_eq!(rich.direct_calls().edges(), stripped.direct_calls().edges());
        assert_eq!(
            rich.transfers().transfers(),
            stripped.transfers().transfers()
        );
        assert_eq!(
            rich.indirect_calls().calls(),
            stripped.indirect_calls().calls()
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
    fn complete_function_receipt_requires_authoritative_function_boundaries() {
        let program = recover(&full_x86_fixture(true), ProgramRecoveryLimits::default());
        let function_stage = program
            .completeness()
            .stages
            .iter()
            .find(|stage| stage.stage == ProgramRecoveryStage::Functions)
            .unwrap();
        assert_eq!(function_stage.status, ProgramRecoveryStatus::Partial);
        assert!(
            function_stage
                .reasons
                .contains(&"functions.uncertain_extents".to_owned())
        );
    }

    #[test]
    fn all_limits_are_validated_before_recovery() {
        let limits = ProgramRecoveryLimits {
            indirect_calls: IndirectCallRecoveryLimits {
                max_transfers: 0,
                ..IndirectCallRecoveryLimits::default()
            },
            ..ProgramRecoveryLimits::default()
        };
        assert_eq!(
            RecoveredProgram::recover(&image(&full_x86_fixture(true)), limits).unwrap_err(),
            ProgramRecoveryError::IndirectCalls(IndirectCallRecoveryError::InvalidLimits)
        );
    }

    #[test]
    fn prebuilt_function_inventory_is_reused_without_changing_program_recovery() {
        let bytes = full_x86_fixture(true);
        let macho = image(&bytes);
        let limits = ProgramRecoveryLimits::default();
        let functions = FunctionIndex::recover(&macho, limits.functions).unwrap();
        let reused = RecoveredProgram::recover_from_functions(&macho, functions, limits).unwrap();
        let direct = RecoveredProgram::recover(&macho, limits).unwrap();
        assert_eq!(reused.functions(), direct.functions());
        assert_eq!(reused.control_flow(), direct.control_flow());
        assert_eq!(reused.direct_calls(), direct.direct_calls());
        assert_eq!(reused.transfers(), direct.transfers());
        assert_eq!(reused.indirect_calls(), direct.indirect_calls());
        assert_eq!(reused.completeness(), direct.completeness());
    }

    #[test]
    fn unified_construction_supports_x86_arm64_and_arm64e() {
        for bytes in [
            macho_test_support::disassembly_x86_64(),
            macho_test_support::disassembly_arm64(),
            macho_test_support::disassembly_arm64e(),
        ] {
            let program = recover(&bytes, ProgramRecoveryLimits::default());
            assert!(!program.functions().functions().is_empty());
            assert_eq!(program.completeness().stages.len(), 5);
        }
    }

    #[cfg(target_os = "macos")]
    fn strip_nlist_names(macho: &macho_core::MachoFile<'_>) -> Vec<u8> {
        use macho_core::model::load_command::LoadCommand;

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
        for path in ["/bin/ls", "/usr/bin/file"] {
            let bytes = std::fs::read(path).expect("macOS system corpus member exists");
            let container = macho_core::parse(&bytes).expect("system corpus member parses");
            for macho in container.macho_files() {
                let started = Instant::now();
                let program =
                    RecoveredProgram::recover(macho, limits).expect("supported system slice");
                let elapsed = started.elapsed();
                assert!(!program.functions().functions().is_empty());
                assert!(
                    program.indirect_calls().completeness().value_flow_work
                        <= limits.indirect_calls.max_value_flow_work
                );
                assert!(
                    elapsed < Duration::from_secs(10),
                    "program recovery exceeded the real-corpus ceiling for {path} CPU {:#x}/{:#x}: {elapsed:?}",
                    macho.header().cpu_type().0,
                    macho.header().cpu_subtype().0,
                );

                let stripped_bytes = strip_nlist_names(macho);
                let stripped_macho = image(&stripped_bytes);
                let stripped = RecoveredProgram::recover(&stripped_macho, limits)
                    .expect("name-stripped system slice");
                let structure = |program: &RecoveredProgram| {
                    program
                        .functions()
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
                let direct_edges = |program: &RecoveredProgram| {
                    program
                        .direct_calls()
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
                recovered += 1;
            }
        }
        assert_ne!(recovered, 0);
    }
}
