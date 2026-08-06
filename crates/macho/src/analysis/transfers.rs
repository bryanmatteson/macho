//! Bounded recovery of inter-procedural direct branches, tail calls, and thunks.
//!
//! This layer consumes the exact function identities and per-function CFGs
//! recovered by this crate. A direct branch outside one recovered function is
//! retained with every supported semantic interpretation. Thunk resolution
//! accepts converging multi-block forwarders and reports cycles, uncertainty,
//! and depth limits explicitly.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::control_flow::{
    ControlFlowExit, ControlFlowExitKind, ControlFlowIndex, ControlFlowIndexStatus,
    ControlFlowInstructionKind, ControlFlowReachability, FunctionControlFlow,
    FunctionControlFlowStatus, RecoveredFunctionTarget,
};
use crate::analysis::functions::{
    FunctionCollectorStatus, FunctionEvidenceConfidence, FunctionIdentity, FunctionImageIdentity,
    FunctionIndex,
};

/// Explicit limits for one direct-transfer recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferRecoveryLimits {
    /// Maximum function CFGs examined in entry-address order.
    pub max_functions: usize,
    /// Maximum exits examined across admitted functions.
    pub max_examined_exits: usize,
    /// Maximum inter-procedural transfer records retained.
    pub max_transfers: usize,
    /// Maximum thunk identities retained.
    pub max_thunks: usize,
    /// Maximum nested thunk hops followed during target resolution.
    pub max_thunk_chain_depth: usize,
    /// Maximum semantic conflicts retained.
    pub max_conflicts: usize,
}

impl Default for TransferRecoveryLimits {
    fn default() -> Self {
        Self {
            max_functions: 1_000_000,
            max_examined_exits: 16_000_000,
            max_transfers: 8_000_000,
            max_thunks: 1_000_000,
            max_thunk_chain_depth: 256,
            max_conflicts: 1_000_000,
        }
    }
}

impl TransferRecoveryLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, TransferRecoveryError> {
        if self.max_functions == 0
            || self.max_examined_exits == 0
            || self.max_transfers == 0
            || self.max_thunks == 0
            || self.max_thunk_chain_depth == 0
            || self.max_conflicts == 0
        {
            return Err(TransferRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing direct-transfer recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransferRecoveryError {
    /// At least one explicit limit is zero.
    #[error("direct-transfer recovery limits must be non-zero")]
    InvalidLimits,
    /// The function and CFG indexes belong to different exact images.
    #[error("function and control-flow image identities differ")]
    ImageMismatch,
}

/// Semantic classification of one cross-function direct branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectTransferKind {
    /// Decoded direct branch whose target has no retained intra-procedural block.
    DirectBranch,
    /// The target may remain inside the source function, but no retained CFG
    /// block begins at the decoded address.
    IntraFunctionBranch,
    /// Reachable unconditional branch to another recovered function entry.
    TailCall,
    /// The only reachable behavior is a bounded forwarding block.
    ThunkForward,
}

/// One non-exclusive semantic interpretation of a direct transfer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectTransferInterpretation {
    /// Observed branch, possible tail call, or possible thunk forwarding.
    pub kind: DirectTransferKind,
    /// Strength of this interpretation without suppressing weaker alternatives.
    pub confidence: FunctionEvidenceConfidence,
    /// Stable evidence and uncertainty codes specific to this interpretation.
    pub reasons: Vec<String>,
}

/// Outcome of following a recovered direct target through known thunks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferResolutionStatus {
    /// Target is a recovered non-thunk function.
    Direct,
    /// One or more thunk functions were followed to a final function.
    ThroughThunks,
    /// The direct address has no recovered function identity.
    UnresolvedTarget,
    /// The target is a proven import-stub node on the external frontier.
    ExternalFrontier,
    /// Thunk forwarding contains a cycle.
    Cycle,
    /// The explicit chain-depth budget stopped resolution.
    DepthLimited,
    /// A thunk on the path was recognized but omitted by a retention budget.
    ThunkInventoryTruncated,
}

/// One retained inter-procedural direct branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectFunctionTransfer {
    /// Source function entry.
    pub source: u64,
    /// Source-local basic block identifier.
    pub block: u64,
    /// Controlling branch instruction address.
    pub instruction_address: u64,
    /// Decoded direct target address.
    pub target_address: u64,
    /// Exact recovered target entry, when one exists.
    pub target_function: Option<u64>,
    /// Target-entry confidence, when recovered.
    pub target_entry_confidence: Option<FunctionEvidenceConfidence>,
    /// Every recovered identity that could own the decoded target.
    pub possible_target_functions: Vec<RecoveredFunctionTarget>,
    /// Reachability of the source block.
    pub block_reachability: ControlFlowReachability,
    /// All supported, non-exclusive semantic interpretations.
    pub interpretations: Vec<DirectTransferInterpretation>,
    /// Result of following the target through recovered thunks.
    pub resolution: TransferResolutionStatus,
    /// Final non-thunk target, when resolution succeeded.
    pub final_target: Option<u64>,
    /// Ordered thunk entries followed after the direct target.
    pub thunk_chain: Vec<u64>,
    /// Stable reason codes explaining candidate or unresolved state.
    pub reasons: Vec<String>,
}

/// Resolution state of one function classified as a forwarding thunk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredThunk {
    /// Thunk function entry.
    pub entry: u64,
    /// Named or anonymous function identity.
    pub identity: FunctionIdentity,
    /// Address encoded by the forwarding branch.
    pub target_address: u64,
    /// Recovered immediate target function.
    pub target_function: Option<u64>,
    /// Address of the forwarding branch instruction.
    pub instruction_address: u64,
    /// Number of instructions in the reachable forwarding block.
    pub instruction_count: u64,
    /// Strength of the thunk classification.
    pub confidence: FunctionEvidenceConfidence,
    /// Chain-resolution outcome.
    pub resolution: TransferResolutionStatus,
    /// Final non-thunk function, when resolved.
    pub final_target: Option<u64>,
    /// Ordered thunk entries followed, beginning with this thunk.
    pub chain: Vec<u64>,
    /// Stable reason codes explaining uncertainty or failed resolution.
    pub reasons: Vec<String>,
}

/// Canonical target answer for any recovered function entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionTargetResolution {
    /// Function entry supplied by the caller.
    pub requested_target: u64,
    /// Direct, thunk-resolved, cyclic, or truncated result.
    pub resolution: TransferResolutionStatus,
    /// Final non-thunk identity, when resolution succeeded.
    pub final_target: Option<u64>,
    /// Ordered thunk entries followed, beginning with the requested target.
    pub thunk_chain: Vec<u64>,
}

/// Semantic transfer conflict retained during resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferConflictKind {
    /// A set of forwarding thunks eventually targets itself.
    ThunkCycle,
}

/// One deterministic conflict record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferConflict {
    /// Conflict classification.
    pub kind: TransferConflictKind,
    /// Sorted function entries participating in the conflict.
    pub functions: Vec<u64>,
}

/// Global completion state for direct-transfer recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferIndexStatus {
    /// Source evidence was complete and every result was retained.
    Complete,
    /// Results are useful but contain uncertain or unresolved evidence.
    Partial,
    /// A source or transfer budget omitted evidence.
    Truncated,
}

/// Completeness and work receipt for a transfer index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferIndexCompleteness {
    /// Overall state.
    pub status: TransferIndexStatus,
    /// Stable reason codes explaining non-completeness.
    pub reasons: Vec<String>,
    /// Function CFGs examined.
    pub examined_function_count: u64,
    /// Function CFGs omitted by `max_functions`.
    pub omitted_function_count: u64,
    /// CFG exits examined.
    pub examined_exit_count: u64,
    /// Cross-function direct branches observed.
    pub observed_transfer_count: u64,
    /// Transfer records omitted by `max_transfers`.
    pub omitted_transfer_count: u64,
    /// Forwarding thunk shapes observed.
    pub observed_thunk_count: u64,
    /// Thunks omitted by `max_thunks`.
    pub omitted_thunk_count: u64,
    /// Conflicts omitted by `max_conflicts`.
    pub omitted_conflict_count: u64,
}

/// Bounded direct-transfer and thunk inventory tied to one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectTransferIndex {
    image: FunctionImageIdentity,
    limits: TransferRecoveryLimits,
    transfers: Vec<DirectFunctionTransfer>,
    thunks: Vec<RecoveredThunk>,
    conflicts: Vec<TransferConflict>,
    completeness: TransferIndexCompleteness,
    unretained_thunk_entries: Vec<u64>,
    #[serde(skip)]
    function_entries: Vec<u64>,
}

impl DirectTransferIndex {
    /// Recover cross-function branches, tail calls, and forwarding thunks.
    pub fn recover(
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: TransferRecoveryLimits,
    ) -> Result<Self, TransferRecoveryError> {
        let limits = limits.validate()?;
        if functions.image() != control_flow.image() {
            return Err(TransferRecoveryError::ImageMismatch);
        }

        let admitted = control_flow.functions().len().min(limits.max_functions);
        let omitted_function_count = control_flow.functions().len().saturating_sub(admitted) as u64;
        let mut reasons = BTreeSet::<String>::new();
        if omitted_function_count != 0 {
            reasons.insert("transfers.function_budget".into());
        }
        let function_source_truncated = functions.truncated_function_count() != 0
            || functions
                .receipts()
                .iter()
                .any(|receipt| receipt.status == FunctionCollectorStatus::Truncated);
        if function_source_truncated {
            reasons.insert("transfers.function_inventory_truncated".into());
        } else if !functions.inventory_complete() {
            reasons.insert("transfers.function_inventory_incomplete".into());
        }
        match control_flow.status() {
            ControlFlowIndexStatus::Complete => {}
            ControlFlowIndexStatus::Partial => {
                reasons.insert("transfers.control_flow_partial".into());
            }
            ControlFlowIndexStatus::Truncated => {
                reasons.insert("transfers.control_flow_truncated".into());
            }
        }
        let import_stubs = functions
            .import_stubs()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();

        let mut transfers = Vec::new();
        let mut examined_exit_count = 0_usize;
        let mut observed_transfer_count = 0_u64;
        let mut omitted_transfer_count = 0_u64;
        let mut exit_budget_hit = false;
        'functions: for graph in control_flow.functions().iter().take(admitted) {
            for exit in &graph.exits {
                if examined_exit_count == limits.max_examined_exits {
                    exit_budget_hit = true;
                    reasons.insert("transfers.exit_budget".into());
                    break 'functions;
                }
                examined_exit_count += 1;
                if exit.kind != ControlFlowExitKind::DirectBranch {
                    continue;
                }
                let Some(instruction_address) = exit.instruction_address else {
                    continue;
                };
                let Some(target_address) = exit.target else {
                    continue;
                };
                observed_transfer_count = observed_transfer_count.saturating_add(1);
                if transfers.len() == limits.max_transfers {
                    omitted_transfer_count = omitted_transfer_count.saturating_add(1);
                    reasons.insert("transfers.transfer_budget".into());
                    continue;
                }
                transfers.push(transfer_from_exit(
                    graph,
                    exit,
                    instruction_address,
                    target_address,
                    functions,
                    import_stubs.contains(&target_address),
                ));
            }
        }
        transfers.sort_by_key(|transfer| {
            (
                transfer.source,
                transfer.instruction_address,
                transfer.target_address,
            )
        });

        let transfer_by_instruction = transfers
            .iter()
            .enumerate()
            .map(|(index, transfer)| ((transfer.source, transfer.instruction_address), index))
            .collect::<BTreeMap<_, _>>();
        let mut raw_thunks = Vec::<RawThunk>::new();
        let mut observed_thunk_entries = BTreeSet::<u64>::new();
        let mut observed_thunk_count = 0_u64;
        let mut omitted_thunk_count = 0_u64;
        for graph in control_flow.functions().iter().take(admitted) {
            let Some(shape) = forwarding_shape(graph) else {
                continue;
            };
            observed_thunk_count = observed_thunk_count.saturating_add(1);
            observed_thunk_entries.insert(graph.function_entry);
            let Some(&transfer_index) =
                transfer_by_instruction.get(&(graph.function_entry, shape.instruction_address))
            else {
                omitted_thunk_count = omitted_thunk_count.saturating_add(1);
                reasons.insert("transfers.thunk_evidence_omitted".into());
                continue;
            };
            if raw_thunks.len() == limits.max_thunks {
                omitted_thunk_count = omitted_thunk_count.saturating_add(1);
                reasons.insert("transfers.thunk_budget".into());
                continue;
            }
            let transfer = &mut transfers[transfer_index];
            let confidence = semantic_confidence(
                graph,
                transfer.target_entry_confidence,
                transfer.resolution == TransferResolutionStatus::ExternalFrontier,
                transfer.block_reachability,
            );
            transfer.interpretations.push(DirectTransferInterpretation {
                kind: DirectTransferKind::ThunkForward,
                confidence,
                reasons: if confidence == FunctionEvidenceConfidence::Candidate {
                    vec!["transfers.thunk_candidate".into()]
                } else {
                    Vec::new()
                },
            });
            transfer
                .interpretations
                .sort_by_key(|interpretation| interpretation.kind as u8);
            raw_thunks.push(RawThunk {
                entry: graph.function_entry,
                identity: graph.identity.clone(),
                target_address: transfer.target_address,
                target_function: transfer.target_function,
                target_external: transfer.resolution == TransferResolutionStatus::ExternalFrontier,
                instruction_address: shape.instruction_address,
                instruction_count: shape.instruction_count,
                confidence,
            });
        }

        let raw_by_entry = raw_thunks
            .iter()
            .enumerate()
            .map(|(index, thunk)| (thunk.entry, index))
            .collect::<BTreeMap<_, _>>();
        let mut thunks = raw_thunks
            .iter()
            .map(|thunk| {
                resolve_thunk(
                    thunk,
                    &raw_thunks,
                    &raw_by_entry,
                    &observed_thunk_entries,
                    limits.max_thunk_chain_depth,
                )
            })
            .collect::<Vec<_>>();
        thunks.sort_by_key(|thunk| thunk.entry);
        let resolved_by_entry = thunks
            .iter()
            .map(|thunk| (thunk.entry, thunk))
            .collect::<BTreeMap<_, _>>();
        let retained_thunk_entries = thunks
            .iter()
            .map(|thunk| thunk.entry)
            .collect::<BTreeSet<_>>();
        let unretained_thunk_entries = observed_thunk_entries
            .difference(&retained_thunk_entries)
            .copied()
            .collect::<Vec<_>>();
        for transfer in &mut transfers {
            apply_resolution(transfer, &resolved_by_entry, &observed_thunk_entries);
        }

        let mut conflicts = Vec::new();
        let mut cycle_sets = BTreeSet::<Vec<u64>>::new();
        let mut omitted_conflict_count = 0_u64;
        for thunk in &thunks {
            if thunk.resolution != TransferResolutionStatus::Cycle {
                continue;
            }
            let mut functions = thunk.chain.clone();
            functions.sort_unstable();
            functions.dedup();
            if !cycle_sets.insert(functions.clone()) {
                continue;
            }
            if conflicts.len() < limits.max_conflicts {
                conflicts.push(TransferConflict {
                    kind: TransferConflictKind::ThunkCycle,
                    functions,
                });
            } else {
                omitted_conflict_count = omitted_conflict_count.saturating_add(1);
                reasons.insert("transfers.conflict_budget".into());
            }
        }

        if thunks
            .iter()
            .any(|thunk| thunk.resolution == TransferResolutionStatus::DepthLimited)
        {
            reasons.insert("transfers.thunk_chain_depth".into());
        }
        if !conflicts.is_empty() {
            reasons.insert("transfers.thunk_cycle".into());
        }
        let truncated = omitted_function_count != 0
            || exit_budget_hit
            || omitted_transfer_count != 0
            || omitted_thunk_count != 0
            || omitted_conflict_count != 0
            || function_source_truncated
            || control_flow.status() == ControlFlowIndexStatus::Truncated
            || thunks
                .iter()
                .any(|thunk| thunk.resolution == TransferResolutionStatus::DepthLimited);
        let partial = !functions.inventory_complete()
            || control_flow.status() == ControlFlowIndexStatus::Partial
            || transfers.iter().any(|transfer| {
                transfer.interpretations.iter().any(|interpretation| {
                    interpretation.confidence == FunctionEvidenceConfidence::Candidate
                }) || matches!(
                    transfer.resolution,
                    TransferResolutionStatus::UnresolvedTarget
                        | TransferResolutionStatus::Cycle
                        | TransferResolutionStatus::ThunkInventoryTruncated
                )
            });
        let status = if truncated {
            TransferIndexStatus::Truncated
        } else if partial {
            TransferIndexStatus::Partial
        } else {
            TransferIndexStatus::Complete
        };

        Ok(Self {
            image: functions.image().clone(),
            limits,
            transfers,
            thunks,
            conflicts,
            completeness: TransferIndexCompleteness {
                status,
                reasons: reasons.into_iter().collect(),
                examined_function_count: admitted as u64,
                omitted_function_count,
                examined_exit_count: examined_exit_count as u64,
                observed_transfer_count,
                omitted_transfer_count,
                observed_thunk_count,
                omitted_thunk_count,
                omitted_conflict_count,
            },
            unretained_thunk_entries,
            function_entries: functions
                .functions()
                .iter()
                .map(|function| function.entry)
                .collect(),
        })
    }

    /// Exact image identity shared by the source indexes.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Limits used for this recovery operation.
    pub const fn limits(&self) -> TransferRecoveryLimits {
        self.limits
    }

    /// Transfers sorted by source and instruction address.
    pub fn transfers(&self) -> &[DirectFunctionTransfer] {
        &self.transfers
    }

    /// Recovered forwarding thunks sorted by entry address.
    pub fn thunks(&self) -> &[RecoveredThunk] {
        &self.thunks
    }

    /// Semantic conflicts sorted deterministically.
    pub fn conflicts(&self) -> &[TransferConflict] {
        &self.conflicts
    }

    /// Observed forwarding-thunk entries whose records were omitted by a
    /// transfer or thunk budget.
    pub fn unretained_thunk_entries(&self) -> &[u64] {
        &self.unretained_thunk_entries
    }

    /// Completeness and work receipt.
    pub fn completeness(&self) -> &TransferIndexCompleteness {
        &self.completeness
    }

    /// Overall index status.
    pub const fn status(&self) -> TransferIndexStatus {
        self.completeness.status
    }

    /// Find a recovered thunk by exact function entry.
    pub fn thunk_by_entry(&self, entry: u64) -> Option<&RecoveredThunk> {
        self.thunks
            .binary_search_by_key(&entry, |thunk| thunk.entry)
            .ok()
            .map(|index| &self.thunks[index])
    }

    /// Resolve a known function entry to its final non-thunk identity.
    pub fn resolved_target(&self, entry: u64) -> Option<u64> {
        self.resolve_function_target(entry)
            .and_then(|resolution| resolution.final_target)
    }

    /// Return the typed direct or thunk-chain resolution for a function entry.
    pub fn resolve_function_target(&self, entry: u64) -> Option<FunctionTargetResolution> {
        if let Some(thunk) = self.thunk_by_entry(entry) {
            return Some(FunctionTargetResolution {
                requested_target: entry,
                resolution: if thunk.resolution == TransferResolutionStatus::Direct {
                    TransferResolutionStatus::ThroughThunks
                } else {
                    thunk.resolution
                },
                final_target: thunk.final_target,
                thunk_chain: thunk.chain.clone(),
            });
        }
        if self.unretained_thunk_entries.binary_search(&entry).is_ok() {
            return Some(FunctionTargetResolution {
                requested_target: entry,
                resolution: TransferResolutionStatus::ThunkInventoryTruncated,
                final_target: None,
                thunk_chain: vec![entry],
            });
        }
        self.function_entries
            .binary_search(&entry)
            .ok()
            .map(|_| FunctionTargetResolution {
                requested_target: entry,
                resolution: TransferResolutionStatus::Direct,
                final_target: Some(entry),
                thunk_chain: Vec::new(),
            })
    }

    /// Iterate transfers originating in one function.
    pub fn from_function(&self, source: u64) -> impl Iterator<Item = &DirectFunctionTransfer> {
        self.transfers
            .iter()
            .filter(move |transfer| transfer.source == source)
    }
}

fn transfer_from_exit(
    graph: &FunctionControlFlow,
    exit: &ControlFlowExit,
    instruction_address: u64,
    target_address: u64,
    functions: &FunctionIndex,
    target_external: bool,
) -> DirectFunctionTransfer {
    let block_reachability = graph
        .blocks
        .get(exit.block as usize)
        .filter(|block| block.id == exit.block)
        .map_or(ControlFlowReachability::Unknown, |block| block.reachability);
    let target = exit
        .recovered_function
        .and_then(|entry| functions.by_entry(entry));
    let mut reasons = BTreeSet::<String>::new();
    match block_reachability {
        ControlFlowReachability::Reachable => {}
        ControlFlowReachability::Unreachable => {
            reasons.insert("transfers.unreachable_source_block".into());
        }
        ControlFlowReachability::Unknown => {
            reasons.insert("transfers.source_reachability_unknown".into());
        }
    }
    match graph.completeness.status {
        FunctionControlFlowStatus::Complete => {}
        FunctionControlFlowStatus::Partial => {
            reasons.insert("transfers.source_control_flow_partial".into());
        }
        FunctionControlFlowStatus::Truncated => {
            reasons.insert("transfers.source_control_flow_truncated".into());
        }
        FunctionControlFlowStatus::Unavailable => {
            reasons.insert("transfers.source_control_flow_unavailable".into());
        }
    }
    if target.is_none() && !target_external {
        reasons.insert("transfers.target_unrecovered".into());
    }
    if target
        .is_some_and(|function| function.entry_confidence == FunctionEvidenceConfidence::Candidate)
    {
        reasons.insert("transfers.target_entry_candidate".into());
    }
    if target_address == graph.function_entry {
        reasons.insert("transfers.self_branch".into());
    }
    let unconditional = graph
        .instructions
        .binary_search_by_key(&instruction_address, |instruction| instruction.address)
        .ok()
        .is_some_and(|index| graph.instructions[index].kind == ControlFlowInstructionKind::Branch);
    if !unconditional {
        reasons.insert("transfers.conditional_or_unknown_branch".into());
    }
    let target_entry_confidence = target.map(|function| function.entry_confidence);
    let instruction_confidence = graph
        .instructions
        .binary_search_by_key(&instruction_address, |instruction| instruction.address)
        .ok()
        .map_or(FunctionEvidenceConfidence::Candidate, |index| {
            graph.instructions[index].coverage_confidence
        });
    let mut interpretations = vec![DirectTransferInterpretation {
        kind: DirectTransferKind::DirectBranch,
        confidence: instruction_confidence,
        reasons: Vec::new(),
    }];
    let source_ownership = exit
        .possible_functions
        .iter()
        .find(|candidate| candidate.entry == graph.function_entry);
    if let Some(source) = source_ownership {
        interpretations.push(DirectTransferInterpretation {
            kind: DirectTransferKind::IntraFunctionBranch,
            confidence: match source.ownership_confidence {
                crate::analysis::functions::FunctionOwnershipConfidence::Exact => {
                    FunctionEvidenceConfidence::Exact
                }
                crate::analysis::functions::FunctionOwnershipConfidence::Derived => {
                    FunctionEvidenceConfidence::Derived
                }
                crate::analysis::functions::FunctionOwnershipConfidence::Candidate => {
                    FunctionEvidenceConfidence::Candidate
                }
            },
            reasons: Vec::new(),
        });
    }
    let has_other_target = exit
        .possible_functions
        .iter()
        .any(|candidate| candidate.entry != graph.function_entry);
    if unconditional
        && target_address != graph.function_entry
        && (has_other_target || source_ownership.is_none())
    {
        let confidence = semantic_confidence(
            graph,
            target_entry_confidence,
            target_external,
            block_reachability,
        );
        interpretations.push(DirectTransferInterpretation {
            kind: DirectTransferKind::TailCall,
            confidence,
            reasons: if confidence == FunctionEvidenceConfidence::Candidate {
                vec!["transfers.tail_call_candidate".into()]
            } else {
                Vec::new()
            },
        });
    }
    DirectFunctionTransfer {
        source: graph.function_entry,
        block: exit.block,
        instruction_address,
        target_address,
        target_function: target.map(|function| function.entry),
        target_entry_confidence,
        possible_target_functions: exit.possible_functions.clone(),
        block_reachability,
        interpretations,
        resolution: if target.is_some() {
            TransferResolutionStatus::Direct
        } else if target_external {
            TransferResolutionStatus::ExternalFrontier
        } else {
            TransferResolutionStatus::UnresolvedTarget
        },
        final_target: target.map(|function| function.entry),
        thunk_chain: Vec::new(),
        reasons: reasons.into_iter().collect(),
    }
}

fn semantic_confidence(
    graph: &FunctionControlFlow,
    target: Option<FunctionEvidenceConfidence>,
    target_external: bool,
    reachability: ControlFlowReachability,
) -> FunctionEvidenceConfidence {
    if graph.completeness.status == FunctionControlFlowStatus::Complete
        && reachability == ControlFlowReachability::Reachable
        && (target_external
            || target.is_some_and(|confidence| confidence != FunctionEvidenceConfidence::Candidate))
    {
        FunctionEvidenceConfidence::Derived
    } else {
        FunctionEvidenceConfidence::Candidate
    }
}

#[derive(Debug, Clone, Copy)]
struct ForwardingShape {
    instruction_address: u64,
    instruction_count: u64,
}

fn forwarding_shape(graph: &FunctionControlFlow) -> Option<ForwardingShape> {
    if graph.completeness.status == FunctionControlFlowStatus::Unavailable {
        return None;
    }
    let possible_blocks = graph
        .blocks
        .iter()
        .filter(|block| block.reachability != ControlFlowReachability::Unreachable)
        .collect::<Vec<_>>();
    if possible_blocks.is_empty()
        || possible_blocks
            .iter()
            .all(|block| block.start != graph.function_entry)
        || graph
            .calls
            .iter()
            .any(|call| possible_blocks.iter().any(|block| block.id == call.block))
    {
        return None;
    }
    let exits = graph
        .exits
        .iter()
        .filter(|exit| possible_blocks.iter().any(|block| block.id == exit.block))
        .collect::<Vec<_>>();
    if exits.len() != 1
        || exits[0].kind != ControlFlowExitKind::DirectBranch
        || exits[0].target == Some(graph.function_entry)
        || exits[0]
            .possible_functions
            .iter()
            .any(|target| target.entry == graph.function_entry)
    {
        return None;
    }
    let instruction_address = exits[0].instruction_address?;
    let instruction = graph
        .instructions
        .binary_search_by_key(&instruction_address, |instruction| instruction.address)
        .ok()
        .map(|index| &graph.instructions[index])?;
    if instruction.kind != ControlFlowInstructionKind::Branch {
        return None;
    }
    Some(ForwardingShape {
        instruction_address,
        instruction_count: possible_blocks
            .iter()
            .map(|block| block.instruction_count)
            .sum(),
    })
}

#[derive(Debug, Clone)]
struct RawThunk {
    entry: u64,
    identity: FunctionIdentity,
    target_address: u64,
    target_function: Option<u64>,
    target_external: bool,
    instruction_address: u64,
    instruction_count: u64,
    confidence: FunctionEvidenceConfidence,
}

fn resolve_thunk(
    thunk: &RawThunk,
    thunks: &[RawThunk],
    by_entry: &BTreeMap<u64, usize>,
    observed_thunk_entries: &BTreeSet<u64>,
    maximum_depth: usize,
) -> RecoveredThunk {
    let mut chain = vec![thunk.entry];
    let mut confidence = thunk.confidence;
    let mut reasons = BTreeSet::<String>::new();
    if thunk.confidence == FunctionEvidenceConfidence::Candidate {
        reasons.insert("transfers.thunk_candidate".into());
    }
    let (resolution, final_target) = match thunk.target_function {
        None if thunk.target_external => (TransferResolutionStatus::ExternalFrontier, None),
        None => {
            reasons.insert("transfers.target_unrecovered".into());
            (TransferResolutionStatus::UnresolvedTarget, None)
        }
        Some(mut target) => {
            let mut hops = 0_usize;
            loop {
                let Some(&next_index) = by_entry.get(&target) else {
                    if observed_thunk_entries.contains(&target) {
                        reasons.insert("transfers.thunk_inventory_truncated".into());
                        break (TransferResolutionStatus::ThunkInventoryTruncated, None);
                    }
                    break (TransferResolutionStatus::Direct, Some(target));
                };
                if chain.contains(&target) {
                    chain.push(target);
                    reasons.insert("transfers.thunk_cycle".into());
                    break (TransferResolutionStatus::Cycle, None);
                }
                if hops == maximum_depth {
                    reasons.insert("transfers.thunk_chain_depth".into());
                    break (TransferResolutionStatus::DepthLimited, None);
                }
                chain.push(target);
                hops += 1;
                let next = &thunks[next_index];
                confidence = confidence.min(next.confidence);
                let Some(next_target) = next.target_function else {
                    reasons.insert("transfers.target_unrecovered".into());
                    break (TransferResolutionStatus::UnresolvedTarget, None);
                };
                target = next_target;
            }
        }
    };
    let resolution = if resolution == TransferResolutionStatus::Direct && chain.len() > 1 {
        TransferResolutionStatus::ThroughThunks
    } else {
        resolution
    };
    if confidence == FunctionEvidenceConfidence::Candidate {
        reasons.insert("transfers.thunk_candidate".into());
    }
    RecoveredThunk {
        entry: thunk.entry,
        identity: thunk.identity.clone(),
        target_address: thunk.target_address,
        target_function: thunk.target_function,
        instruction_address: thunk.instruction_address,
        instruction_count: thunk.instruction_count,
        confidence,
        resolution,
        final_target,
        chain,
        reasons: reasons.into_iter().collect(),
    }
}

fn apply_resolution(
    transfer: &mut DirectFunctionTransfer,
    thunks: &BTreeMap<u64, &RecoveredThunk>,
    observed_thunk_entries: &BTreeSet<u64>,
) {
    let Some(target) = transfer.target_function else {
        return;
    };
    let Some(thunk) = thunks.get(&target) else {
        if observed_thunk_entries.contains(&target) {
            transfer.resolution = TransferResolutionStatus::ThunkInventoryTruncated;
            transfer.final_target = None;
            transfer
                .reasons
                .push("transfers.thunk_inventory_truncated".into());
            transfer.reasons.sort();
            transfer.reasons.dedup();
        }
        return;
    };
    transfer.resolution = if thunk.resolution == TransferResolutionStatus::Direct {
        TransferResolutionStatus::ThroughThunks
    } else {
        thunk.resolution
    };
    transfer.final_target = thunk.final_target;
    transfer.thunk_chain = thunk.chain.clone();
    match thunk.resolution {
        TransferResolutionStatus::Cycle => transfer.reasons.push("transfers.thunk_cycle".into()),
        TransferResolutionStatus::DepthLimited => {
            transfer.reasons.push("transfers.thunk_chain_depth".into())
        }
        TransferResolutionStatus::UnresolvedTarget => {
            transfer.reasons.push("transfers.target_unrecovered".into())
        }
        TransferResolutionStatus::ThunkInventoryTruncated => transfer
            .reasons
            .push("transfers.thunk_inventory_truncated".into()),
        TransferResolutionStatus::Direct
        | TransferResolutionStatus::ThroughThunks
        | TransferResolutionStatus::ExternalFrontier => {}
    }
    transfer.reasons.sort();
    transfer.reasons.dedup();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::control_flow::ControlFlowLimits;
    use crate::analysis::functions::FunctionRecoveryLimits;

    const FIRST: u64 = 0x1_0000_0100;
    const SECOND: u64 = 0x1_0000_0120;
    const FINAL: u64 = 0x1_0000_0130;

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    fn move_helper(bytes: &mut [u8]) {
        bytes[0x158..0x160].copy_from_slice(&SECOND.to_le_bytes());
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

    fn x86_chain_fixture(with_names: bool) -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x105].copy_from_slice(&[0xe9, 0x1b, 0x00, 0x00, 0x00]);
        bytes[0x120..0x125].copy_from_slice(&[0xe9, 0x0b, 0x00, 0x00, 0x00]);
        bytes[0x130] = 0xc3;
        add_three_function_starts(&mut bytes);
        if !with_names {
            bytes[0x161..0x16f].fill(0);
        }
        bytes
    }

    fn arm_chain_fixture(arm64e: bool) -> Vec<u8> {
        let mut bytes = if arm64e {
            macho_test_support::disassembly_arm64e()
        } else {
            macho_test_support::disassembly_arm64()
        };
        move_helper(&mut bytes);
        bytes[0x100..0x104].copy_from_slice(&0x1400_0008_u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0x1400_0004_u32.to_le_bytes());
        bytes[0x130..0x134].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        add_three_function_starts(&mut bytes);
        bytes
    }

    fn source_indexes(bytes: &[u8]) -> (FunctionIndex, ControlFlowIndex) {
        let macho = image(bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        (functions, control_flow)
    }

    fn recover(bytes: &[u8], limits: TransferRecoveryLimits) -> DirectTransferIndex {
        let (functions, control_flow) = source_indexes(bytes);
        DirectTransferIndex::recover(&functions, &control_flow, limits).unwrap()
    }

    #[test]
    fn resolves_a_bounded_forwarding_chain_to_its_final_identity() {
        let index = recover(&x86_chain_fixture(true), TransferRecoveryLimits::default());
        assert_eq!(index.thunks().len(), 2);
        let first = index.thunk_by_entry(FIRST).unwrap();
        assert_eq!(first.target_function, Some(SECOND));
        assert_eq!(first.final_target, Some(FINAL));
        assert_eq!(first.resolution, TransferResolutionStatus::ThroughThunks);
        assert_eq!(first.chain, vec![FIRST, SECOND]);
        assert_eq!(index.resolved_target(FIRST), Some(FINAL));
        assert_eq!(
            index.resolve_function_target(FINAL),
            Some(FunctionTargetResolution {
                requested_target: FINAL,
                resolution: TransferResolutionStatus::Direct,
                final_target: Some(FINAL),
                thunk_chain: Vec::new(),
            })
        );
        assert_eq!(index.resolve_function_target(u64::MAX), None);

        let transfer = index.from_function(FIRST).next().unwrap();
        assert!(
            transfer
                .interpretations
                .iter()
                .any(|interpretation| { interpretation.kind == DirectTransferKind::ThunkForward })
        );
        assert!(
            transfer
                .interpretations
                .iter()
                .any(|interpretation| { interpretation.kind == DirectTransferKind::DirectBranch })
        );
        assert!(
            transfer
                .interpretations
                .iter()
                .any(|interpretation| { interpretation.kind == DirectTransferKind::TailCall })
        );
        assert_eq!(transfer.target_function, Some(SECOND));
        assert_eq!(transfer.final_target, Some(FINAL));
        assert_eq!(transfer.resolution, TransferResolutionStatus::ThroughThunks);
        assert_eq!(transfer.thunk_chain, vec![SECOND]);
    }

    #[test]
    fn stripping_changes_names_not_thunks_transfers_or_resolution() {
        let rich = recover(&x86_chain_fixture(true), TransferRecoveryLimits::default());
        let stripped = recover(&x86_chain_fixture(false), TransferRecoveryLimits::default());
        assert!(matches!(
            rich.thunk_by_entry(FIRST).unwrap().identity,
            FunctionIdentity::Named { .. }
        ));
        assert!(matches!(
            stripped.thunk_by_entry(FIRST).unwrap().identity,
            FunctionIdentity::Anonymous { .. }
        ));
        assert_eq!(
            rich.transfers()
                .iter()
                .map(|transfer| (
                    transfer.source,
                    transfer.target_function,
                    transfer.interpretations.clone(),
                    transfer.resolution,
                    transfer.final_target,
                ))
                .collect::<Vec<_>>(),
            stripped
                .transfers()
                .iter()
                .map(|transfer| (
                    transfer.source,
                    transfer.target_function,
                    transfer.interpretations.clone(),
                    transfer.resolution,
                    transfer.final_target,
                ))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn arm64_and_arm64e_resolve_the_same_thunk_chain() {
        for bytes in [arm_chain_fixture(false), arm_chain_fixture(true)] {
            let index = recover(&bytes, TransferRecoveryLimits::default());
            let first = index.thunk_by_entry(FIRST).unwrap();
            assert_eq!(first.final_target, Some(FINAL));
            assert_eq!(first.resolution, TransferResolutionStatus::ThroughThunks);
        }
    }

    #[test]
    fn richer_reachable_control_flow_is_a_tail_call_not_a_thunk() {
        let mut bytes = x86_chain_fixture(true);
        bytes[0x100..0x10c].copy_from_slice(&[
            0x74, 0x05, // je 0x107
            0xc3, // return on the not-taken path
            0x90, 0x90, 0x90, 0x90, // unreachable padding
            0xe9, 0x14, 0x00, 0x00, 0x00, // tail branch to 0x120
        ]);
        let index = recover(&bytes, TransferRecoveryLimits::default());
        assert!(index.thunk_by_entry(FIRST).is_none());
        let transfer = index
            .from_function(FIRST)
            .find(|transfer| transfer.instruction_address == FIRST + 7)
            .unwrap();
        assert!(transfer.interpretations.iter().any(|interpretation| {
            interpretation.kind == DirectTransferKind::TailCall
                && interpretation.confidence == FunctionEvidenceConfidence::Candidate
        }));
        assert_eq!(transfer.final_target, Some(FINAL));
    }

    #[test]
    fn converging_multi_block_forwarder_is_not_narrowed_to_single_block_thunks() {
        let mut bytes = x86_chain_fixture(true);
        bytes[0x100..0x10c].copy_from_slice(&[
            0x74, 0x05, // je 0x107
            0xe9, 0x00, 0x00, 0x00, 0x00, // jmp 0x107
            0xe9, 0x14, 0x00, 0x00, 0x00, // jmp 0x120
        ]);
        let index = recover(&bytes, TransferRecoveryLimits::default());
        let thunk = index.thunk_by_entry(FIRST).expect("multi-block forwarder");
        assert_eq!(thunk.target_function, Some(SECOND));
        assert_eq!(thunk.instruction_count, 3);
        let transfer = index
            .from_function(FIRST)
            .find(|transfer| transfer.instruction_address == FIRST + 7)
            .unwrap();
        assert!(
            transfer
                .interpretations
                .iter()
                .any(|interpretation| { interpretation.kind == DirectTransferKind::ThunkForward })
        );
    }

    #[test]
    fn conditional_external_branch_remains_a_candidate() {
        let mut bytes = x86_chain_fixture(true);
        bytes[0x100..0x103].copy_from_slice(&[0x74, 0x1e, 0xc3]);
        let index = recover(&bytes, TransferRecoveryLimits::default());
        let transfer = index
            .from_function(FIRST)
            .find(|transfer| transfer.instruction_address == FIRST)
            .unwrap();
        assert_eq!(transfer.interpretations.len(), 1);
        assert_eq!(
            transfer.interpretations[0].kind,
            DirectTransferKind::DirectBranch
        );
        assert!(
            transfer
                .reasons
                .contains(&"transfers.conditional_or_unknown_branch".to_string())
        );
    }

    #[test]
    fn thunk_cycles_are_conflicts_not_final_targets() {
        let mut bytes = x86_chain_fixture(true);
        bytes[0x120..0x125].copy_from_slice(&[0xe9, 0xdb, 0xff, 0xff, 0xff]);
        let index = recover(&bytes, TransferRecoveryLimits::default());
        assert_eq!(index.conflicts().len(), 1);
        assert_eq!(
            index.conflicts()[0],
            TransferConflict {
                kind: TransferConflictKind::ThunkCycle,
                functions: vec![FIRST, SECOND],
            }
        );
        assert_eq!(
            index.thunk_by_entry(FIRST).unwrap().resolution,
            TransferResolutionStatus::Cycle
        );
        assert_eq!(index.resolved_target(FIRST), None);
    }

    #[test]
    fn transfer_and_thunk_budgets_preserve_truncation() {
        let bytes = x86_chain_fixture(true);
        let transfer_limited = recover(
            &bytes,
            TransferRecoveryLimits {
                max_transfers: 1,
                ..TransferRecoveryLimits::default()
            },
        );
        assert_eq!(transfer_limited.transfers().len(), 1);
        assert_eq!(transfer_limited.completeness().observed_transfer_count, 2);
        assert_eq!(transfer_limited.completeness().omitted_transfer_count, 1);
        assert_eq!(transfer_limited.status(), TransferIndexStatus::Truncated);

        let thunk_limited = recover(
            &bytes,
            TransferRecoveryLimits {
                max_thunks: 1,
                ..TransferRecoveryLimits::default()
            },
        );
        assert_eq!(thunk_limited.thunks().len(), 1);
        assert_eq!(thunk_limited.completeness().observed_thunk_count, 2);
        assert_eq!(thunk_limited.completeness().omitted_thunk_count, 1);
        assert_eq!(thunk_limited.unretained_thunk_entries(), &[SECOND]);
        assert_eq!(
            thunk_limited.thunk_by_entry(FIRST).unwrap().resolution,
            TransferResolutionStatus::ThunkInventoryTruncated
        );
        assert_eq!(
            thunk_limited.resolve_function_target(SECOND),
            Some(FunctionTargetResolution {
                requested_target: SECOND,
                resolution: TransferResolutionStatus::ThunkInventoryTruncated,
                final_target: None,
                thunk_chain: vec![SECOND],
            })
        );
        assert_eq!(thunk_limited.status(), TransferIndexStatus::Truncated);
    }

    #[test]
    fn chain_depth_is_a_typed_truncation() {
        let anonymous = |entry| FunctionIdentity::Anonymous {
            id: format!("sub_{entry:016x}"),
        };
        let thunks = vec![
            RawThunk {
                entry: 1,
                identity: anonymous(1),
                target_address: 2,
                target_function: Some(2),
                target_external: false,
                instruction_address: 1,
                instruction_count: 1,
                confidence: FunctionEvidenceConfidence::Derived,
            },
            RawThunk {
                entry: 2,
                identity: anonymous(2),
                target_address: 3,
                target_function: Some(3),
                target_external: false,
                instruction_address: 2,
                instruction_count: 1,
                confidence: FunctionEvidenceConfidence::Derived,
            },
            RawThunk {
                entry: 3,
                identity: anonymous(3),
                target_address: 4,
                target_function: Some(4),
                target_external: false,
                instruction_address: 3,
                instruction_count: 1,
                confidence: FunctionEvidenceConfidence::Derived,
            },
        ];
        let by_entry = thunks
            .iter()
            .enumerate()
            .map(|(index, thunk)| (thunk.entry, index))
            .collect::<BTreeMap<_, _>>();
        let observed = thunks.iter().map(|thunk| thunk.entry).collect();
        let resolved = resolve_thunk(&thunks[0], &thunks, &by_entry, &observed, 1);
        assert_eq!(resolved.resolution, TransferResolutionStatus::DepthLimited);
        assert_eq!(resolved.final_target, None);
        assert_eq!(resolved.chain, vec![1, 2]);
    }

    #[test]
    fn source_indexes_must_share_an_exact_image() {
        let rich_bytes = x86_chain_fixture(true);
        let stripped_bytes = x86_chain_fixture(false);
        let (rich_functions, rich_control_flow) = source_indexes(&rich_bytes);
        let (stripped_functions, _) = source_indexes(&stripped_bytes);
        assert_eq!(
            DirectTransferIndex::recover(
                &stripped_functions,
                &rich_control_flow,
                TransferRecoveryLimits::default(),
            )
            .unwrap_err(),
            TransferRecoveryError::ImageMismatch
        );
        DirectTransferIndex::recover(
            &rich_functions,
            &rich_control_flow,
            TransferRecoveryLimits::default(),
        )
        .unwrap();
    }
}
