//! Bounded direct-call graph recovery.
//!
//! Nodes are recovered function identities, not symbol names. Edges are
//! assembled only from call instructions retained by [`crate::analysis::control_flow`].
//! Calls into proven import stubs become explicit external-frontier records.
//! Indirect calls and genuinely unexplained direct targets remain classified
//! records rather than disappearing from the result.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::control_flow::{
    ControlFlowCallTarget, ControlFlowIndex, ControlFlowIndexStatus, ControlFlowReachability,
    FunctionControlFlow, FunctionControlFlowStatus, FunctionTargetRelation, IndirectTargetKind,
    RecoveredFunctionTarget,
};
use crate::analysis::functions::{
    FunctionCollectorStatus, FunctionEvidenceConfidence, FunctionIdentity, FunctionImageIdentity,
    FunctionIndex, FunctionOwnershipConfidence,
};

/// Explicit limits for one direct call-graph construction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectCallGraphLimits {
    /// Maximum function nodes admitted in entry-address order.
    pub max_nodes: usize,
    /// Maximum callsites examined across admitted callers.
    pub max_examined_callsites: usize,
    /// Maximum distinct caller/callee edges retained.
    pub max_edges: usize,
    /// Maximum callsite records retained on any one edge.
    pub max_callsites_per_edge: usize,
    /// Maximum non-edge callsites retained globally.
    pub max_unresolved_callsites: usize,
}

impl Default for DirectCallGraphLimits {
    fn default() -> Self {
        Self {
            max_nodes: 1_000_000,
            max_examined_callsites: 16_000_000,
            max_edges: 8_000_000,
            max_callsites_per_edge: 1_000_000,
            max_unresolved_callsites: 8_000_000,
        }
    }
}

impl DirectCallGraphLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, DirectCallGraphError> {
        if self.max_nodes == 0
            || self.max_examined_callsites == 0
            || self.max_edges == 0
            || self.max_callsites_per_edge == 0
            || self.max_unresolved_callsites == 0
        {
            return Err(DirectCallGraphError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing direct call-graph construction from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DirectCallGraphError {
    /// At least one explicit limit is zero.
    #[error("direct call-graph limits must be non-zero")]
    InvalidLimits,
    /// The function and control-flow indexes belong to different images.
    #[error("function and control-flow image identities differ")]
    ImageMismatch,
}

/// Local state of outgoing-call recovery for one function node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectCallNodeStatus {
    /// The source CFG and call-graph projection completed.
    Complete,
    /// Calls are useful but the source CFG has uncertain or incomplete coverage.
    Partial,
    /// A CFG or call-graph budget omitted outgoing-call evidence.
    Truncated,
    /// No function CFG was available.
    Unavailable,
}

/// One function node in the direct call graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectCallNode {
    /// Recovered function entry and stable graph key.
    pub entry: u64,
    /// Named or anonymous identity copied from the function inventory.
    pub identity: FunctionIdentity,
    /// Strength of the recovered entry claim.
    pub entry_confidence: FunctionEvidenceConfidence,
    /// Completeness of outgoing-call evidence for this node.
    pub status: DirectCallNodeStatus,
    /// Stable reason codes explaining non-completeness.
    pub reasons: Vec<String>,
    /// Number of retained incoming edges.
    pub incoming_edge_count: u64,
    /// Number of retained outgoing edges.
    pub outgoing_edge_count: u64,
}

/// One exact call instruction supporting a direct graph edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectCallsiteEvidence {
    /// Call instruction address.
    pub instruction_address: u64,
    /// Caller-local basic block identifier.
    pub block: u64,
    /// Reachability of the containing block.
    pub block_reachability: ControlFlowReachability,
    /// Exact-entry or containing-extent relationship supporting this edge.
    pub target_relation: FunctionTargetRelation,
    /// Confidence that the callee owns the decoded direct target.
    pub ownership_confidence: FunctionOwnershipConfidence,
    /// Confidence of the recovered caller range containing this instruction.
    pub coverage_confidence: FunctionEvidenceConfidence,
}

/// One aggregated direct caller/callee relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectCallEdge {
    /// Caller function entry.
    pub caller: u64,
    /// Callee function entry.
    pub callee: u64,
    /// Strength of the callee entry identity.
    pub callee_entry_confidence: FunctionEvidenceConfidence,
    /// Strongest target relationship retained on this edge.
    pub target_relation: FunctionTargetRelation,
    /// Strongest ownership confidence retained on this edge.
    pub ownership_confidence: FunctionOwnershipConfidence,
    /// Total observed callsites for this edge within the examination budget.
    pub observed_callsite_count: u64,
    /// Retained callsite evidence, sorted by instruction address.
    pub callsites: Vec<DirectCallsiteEvidence>,
    /// Observed callsites omitted by the per-edge retention budget.
    pub omitted_callsite_count: u64,
}

/// One statically direct call whose target is a proven external import stub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalDirectCallsite {
    /// Recovered caller function.
    pub caller: u64,
    /// Exact call instruction.
    pub instruction_address: u64,
    /// Caller-local block identifier.
    pub block: u64,
    /// Reachability of the containing block.
    pub block_reachability: ControlFlowReachability,
    /// Confidence of the caller range containing this instruction.
    pub coverage_confidence: FunctionEvidenceConfidence,
    /// Exact decoded import-stub address.
    pub stub_address: u64,
}

/// Why a call instruction did not become a direct graph edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedCallReason {
    /// The instruction calls through a register or memory operand.
    IndirectTarget,
    /// A direct address has no recovered function entry.
    NoRecoveredFunction,
    /// The target function exists but was omitted by the graph node budget.
    FunctionOmittedByNodeBudget,
    /// Candidate owning functions exist but could not be represented as edges.
    CandidateFunctionsOmittedByBudget,
}

/// Target evidence retained for a non-edge callsite.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UnresolvedCallTarget {
    /// Direct target address.
    Direct {
        /// Decoded virtual address.
        address: u64,
        /// Recovered entry confidence when only the graph node was omitted.
        entry_confidence: Option<FunctionEvidenceConfidence>,
        /// Every recovered identity that could own the decoded address.
        possible_functions: Vec<RecoveredFunctionTarget>,
    },
    /// Indirect target class.
    Indirect {
        /// Register, memory, or unknown decoder representation.
        target_kind: IndirectTargetKind,
    },
}

/// One callsite which could not become a retained direct edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedCallsite {
    /// Caller function entry.
    pub caller: u64,
    /// Call instruction address.
    pub instruction_address: u64,
    /// Caller-local basic block identifier.
    pub block: u64,
    /// Reachability of the containing block.
    pub block_reachability: ControlFlowReachability,
    /// Confidence of the recovered caller range containing this instruction.
    pub coverage_confidence: FunctionEvidenceConfidence,
    /// Why no direct edge was produced.
    pub reason: UnresolvedCallReason,
    /// Direct address or indirect target class.
    pub target: UnresolvedCallTarget,
}

/// Global state of one bounded direct call graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectCallGraphStatus {
    /// Every function and CFG was complete and every graph record was retained.
    Complete,
    /// The graph is useful but inherits incomplete source evidence.
    Partial,
    /// An explicit source or graph budget omitted evidence.
    Truncated,
}

/// Global completeness and work receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectCallGraphCompleteness {
    /// Overall graph state.
    pub status: DirectCallGraphStatus,
    /// Stable reason codes explaining non-completeness.
    pub reasons: Vec<String>,
    /// Function identities examined for node admission.
    pub source_function_count: u64,
    /// Function identities omitted by `max_nodes`.
    pub omitted_node_count: u64,
    /// Callsites examined during graph construction.
    pub examined_callsite_count: u64,
    /// Direct callsites retained on edges.
    pub retained_direct_callsite_count: u64,
    /// Direct callsites omitted by edge or per-edge budgets.
    pub omitted_direct_callsite_count: u64,
    /// Non-edge callsites observed within the examination budget.
    pub unresolved_callsite_count: u64,
    /// Direct callsites resolved to proven import-stub frontier nodes.
    #[serde(default)]
    pub external_callsite_count: u64,
    /// Indirect call instructions classified outside the direct-edge surface.
    #[serde(default)]
    pub non_direct_callsite_count: u64,
    /// Non-edge callsites omitted by their retention budget.
    pub omitted_unresolved_callsite_count: u64,
}

/// Deterministic direct call graph tied to exact function and CFG indexes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DirectCallGraph {
    image: FunctionImageIdentity,
    limits: DirectCallGraphLimits,
    nodes: Vec<DirectCallNode>,
    edges: Vec<DirectCallEdge>,
    external_callsites: Vec<ExternalDirectCallsite>,
    unresolved_callsites: Vec<UnresolvedCallsite>,
    completeness: DirectCallGraphCompleteness,
}

impl DirectCallGraph {
    /// Build a bounded direct call graph without decoding the image again.
    pub fn build(
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: DirectCallGraphLimits,
    ) -> Result<Self, DirectCallGraphError> {
        let limits = limits.validate()?;
        if functions.image() != control_flow.image() {
            return Err(DirectCallGraphError::ImageMismatch);
        }

        let admitted = functions.functions().len().min(limits.max_nodes);
        let mut reasons = BTreeSet::<String>::new();
        let omitted_node_count = functions.functions().len().saturating_sub(admitted) as u64;
        if omitted_node_count != 0 {
            reasons.insert("call_graph.node_budget".into());
        }
        if !functions.inventory_complete() {
            reasons.insert("call_graph.function_inventory_incomplete".into());
        }
        let function_source_truncated = functions.truncated_function_count() != 0
            || functions
                .receipts()
                .iter()
                .any(|receipt| receipt.status == FunctionCollectorStatus::Truncated);
        if function_source_truncated {
            reasons.insert("call_graph.function_inventory_truncated".into());
        }
        match control_flow.status() {
            ControlFlowIndexStatus::Complete => {}
            ControlFlowIndexStatus::Partial => {
                reasons.insert("call_graph.control_flow_partial".into());
            }
            ControlFlowIndexStatus::Truncated => {
                reasons.insert("call_graph.control_flow_truncated".into());
            }
        }

        let mut nodes = functions
            .functions()
            .iter()
            .take(admitted)
            .map(|function| node_from_function(function, control_flow))
            .collect::<Vec<_>>();
        let node_by_entry = nodes
            .iter()
            .enumerate()
            .map(|(index, node)| (node.entry, index))
            .collect::<BTreeMap<_, _>>();
        let mut edges = BTreeMap::<(u64, u64), EdgeAccumulator>::new();
        let import_stubs = functions
            .import_stubs()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        let mut external_callsites = Vec::new();
        let mut unresolved = Vec::new();
        let mut examined_callsites = 0_usize;
        let mut omitted_direct_callsites = 0_u64;
        let mut unresolved_callsite_count = 0_u64;
        let mut non_direct_callsite_count = 0_u64;
        let mut omitted_unresolved_callsites = 0_u64;
        let mut truncated_callers = BTreeSet::<u64>::new();
        let mut unresolved_direct_callers = BTreeSet::<u64>::new();
        let mut callsite_budget_cutoff = None;

        'functions: for graph in control_flow.functions() {
            if !node_by_entry.contains_key(&graph.function_entry) {
                continue;
            }
            for call in &graph.calls {
                if examined_callsites == limits.max_examined_callsites {
                    reasons.insert("call_graph.callsite_budget".into());
                    callsite_budget_cutoff = Some(graph.function_entry);
                    break 'functions;
                }
                examined_callsites += 1;
                let (block_reachability, coverage_confidence) =
                    callsite_context(graph, call.block, call.instruction_address);
                match &call.target {
                    ControlFlowCallTarget::Direct {
                        address,
                        recovered_function,
                        entry_confidence,
                        possible_functions,
                    } => {
                        if possible_functions.is_empty() && import_stubs.contains(address) {
                            external_callsites.push(ExternalDirectCallsite {
                                caller: graph.function_entry,
                                instruction_address: call.instruction_address,
                                block: call.block,
                                block_reachability,
                                coverage_confidence,
                                stub_address: *address,
                            });
                            continue;
                        }
                        let admitted_targets = possible_functions
                            .iter()
                            .copied()
                            .filter(|target| node_by_entry.contains_key(&target.entry))
                            .collect::<Vec<_>>();
                        let omitted_targets = possible_functions
                            .iter()
                            .copied()
                            .filter(|target| !node_by_entry.contains_key(&target.entry))
                            .collect::<Vec<_>>();
                        if possible_functions.is_empty() || !omitted_targets.is_empty() {
                            unresolved_callsite_count = unresolved_callsite_count.saturating_add(1);
                            let reason = if possible_functions.is_empty() {
                                reasons.insert("call_graph.unresolved_direct_targets".into());
                                unresolved_direct_callers.insert(graph.function_entry);
                                UnresolvedCallReason::NoRecoveredFunction
                            } else if recovered_function.is_some_and(|entry| {
                                omitted_targets.iter().any(|target| target.entry == entry)
                            }) {
                                UnresolvedCallReason::FunctionOmittedByNodeBudget
                            } else {
                                UnresolvedCallReason::CandidateFunctionsOmittedByBudget
                            };
                            push_unresolved(
                                &mut unresolved,
                                limits.max_unresolved_callsites,
                                UnresolvedCallsite {
                                    caller: graph.function_entry,
                                    instruction_address: call.instruction_address,
                                    block: call.block,
                                    block_reachability,
                                    coverage_confidence,
                                    reason,
                                    target: UnresolvedCallTarget::Direct {
                                        address: *address,
                                        entry_confidence: *entry_confidence,
                                        possible_functions: omitted_targets,
                                    },
                                },
                                &mut omitted_unresolved_callsites,
                                &mut reasons,
                                &mut truncated_callers,
                            );
                        }
                        for target in admitted_targets {
                            let evidence = DirectCallsiteEvidence {
                                instruction_address: call.instruction_address,
                                block: call.block,
                                block_reachability,
                                coverage_confidence,
                                target_relation: target.relation,
                                ownership_confidence: target.ownership_confidence,
                            };
                            let key = (graph.function_entry, target.entry);
                            if let Some(edge) = edges.get_mut(&key) {
                                edge.push(evidence, limits.max_callsites_per_edge);
                                if edge.omitted_callsite_count != 0 {
                                    reasons.insert("call_graph.edge_callsite_budget".into());
                                    truncated_callers.insert(graph.function_entry);
                                }
                            } else if edges.len() < limits.max_edges {
                                edges.insert(
                                    key,
                                    EdgeAccumulator::new(
                                        graph.function_entry,
                                        target.entry,
                                        target.entry_confidence,
                                        evidence,
                                    ),
                                );
                            } else {
                                omitted_direct_callsites =
                                    omitted_direct_callsites.saturating_add(1);
                                reasons.insert("call_graph.edge_budget".into());
                                truncated_callers.insert(graph.function_entry);
                            }
                        }
                    }
                    ControlFlowCallTarget::Indirect { target_kind } => {
                        non_direct_callsite_count = non_direct_callsite_count.saturating_add(1);
                        unresolved_callsite_count = unresolved_callsite_count.saturating_add(1);
                        push_unresolved(
                            &mut unresolved,
                            limits.max_unresolved_callsites,
                            UnresolvedCallsite {
                                caller: graph.function_entry,
                                instruction_address: call.instruction_address,
                                block: call.block,
                                block_reachability,
                                coverage_confidence,
                                reason: UnresolvedCallReason::IndirectTarget,
                                target: UnresolvedCallTarget::Indirect {
                                    target_kind: *target_kind,
                                },
                            },
                            &mut omitted_unresolved_callsites,
                            &mut reasons,
                            &mut truncated_callers,
                        );
                    }
                }
            }
        }

        if let Some(cutoff) = callsite_budget_cutoff {
            for node in &nodes {
                if node.entry >= cutoff && control_flow.by_entry(node.entry).is_some() {
                    truncated_callers.insert(node.entry);
                }
            }
        }
        for entry in truncated_callers {
            let index = node_by_entry[&entry];
            nodes[index].status = DirectCallNodeStatus::Truncated;
            nodes[index]
                .reasons
                .push("call_graph.outgoing_evidence_truncated".into());
            nodes[index].reasons.sort();
            nodes[index].reasons.dedup();
        }
        for entry in unresolved_direct_callers {
            let index = node_by_entry[&entry];
            if nodes[index].status == DirectCallNodeStatus::Complete {
                nodes[index].status = DirectCallNodeStatus::Partial;
            }
            nodes[index]
                .reasons
                .push("call_graph.unresolved_direct_target".into());
            nodes[index].reasons.sort();
            nodes[index].reasons.dedup();
        }

        let mut edges = edges
            .into_values()
            .map(EdgeAccumulator::finish)
            .collect::<Vec<_>>();
        edges.sort_by_key(|edge| (edge.caller, edge.callee));
        unresolved.sort_by_key(|call| (call.caller, call.instruction_address));
        external_callsites.sort_by_key(|call| (call.caller, call.instruction_address));
        for edge in &edges {
            nodes[node_by_entry[&edge.caller]].outgoing_edge_count += 1;
            nodes[node_by_entry[&edge.callee]].incoming_edge_count += 1;
        }

        let retained_direct_callsite_count =
            edges.iter().map(|edge| edge.callsites.len() as u64).sum();
        omitted_direct_callsites = omitted_direct_callsites.saturating_add(
            edges
                .iter()
                .map(|edge| edge.omitted_callsite_count)
                .sum::<u64>(),
        );
        let truncated = omitted_node_count != 0
            || callsite_budget_cutoff.is_some()
            || omitted_direct_callsites != 0
            || omitted_unresolved_callsites != 0
            || function_source_truncated
            || control_flow.status() == ControlFlowIndexStatus::Truncated;
        let partial = !functions.inventory_complete()
            || control_flow.status() == ControlFlowIndexStatus::Partial
            || nodes.iter().any(|node| {
                matches!(
                    node.status,
                    DirectCallNodeStatus::Partial | DirectCallNodeStatus::Unavailable
                )
            });
        let status = if truncated {
            DirectCallGraphStatus::Truncated
        } else if partial {
            DirectCallGraphStatus::Partial
        } else {
            DirectCallGraphStatus::Complete
        };
        let external_callsite_count = external_callsites.len() as u64;

        Ok(Self {
            image: functions.image().clone(),
            limits,
            nodes,
            edges,
            external_callsites,
            unresolved_callsites: unresolved,
            completeness: DirectCallGraphCompleteness {
                status,
                reasons: reasons.into_iter().collect(),
                source_function_count: functions.functions().len() as u64,
                omitted_node_count,
                examined_callsite_count: examined_callsites as u64,
                retained_direct_callsite_count,
                omitted_direct_callsite_count: omitted_direct_callsites,
                unresolved_callsite_count,
                external_callsite_count,
                non_direct_callsite_count,
                omitted_unresolved_callsite_count: omitted_unresolved_callsites,
            },
        })
    }

    /// Exact image identity shared by both source indexes.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Limits used to construct this graph.
    pub const fn limits(&self) -> DirectCallGraphLimits {
        self.limits
    }

    /// Function nodes sorted by entry address.
    pub fn nodes(&self) -> &[DirectCallNode] {
        &self.nodes
    }

    /// Aggregated edges sorted by caller then callee entry.
    pub fn edges(&self) -> &[DirectCallEdge] {
        &self.edges
    }

    /// Statically direct calls resolved to the external import frontier.
    pub fn external_callsites(&self) -> &[ExternalDirectCallsite] {
        &self.external_callsites
    }

    /// Callsites which did not produce direct graph edges.
    pub fn unresolved_callsites(&self) -> &[UnresolvedCallsite] {
        &self.unresolved_callsites
    }

    /// Global completeness and work receipt.
    pub fn completeness(&self) -> &DirectCallGraphCompleteness {
        &self.completeness
    }

    /// Overall graph status.
    pub const fn status(&self) -> DirectCallGraphStatus {
        self.completeness.status
    }

    /// Find one exact function node.
    pub fn by_entry(&self, entry: u64) -> Option<&DirectCallNode> {
        self.nodes
            .binary_search_by_key(&entry, |node| node.entry)
            .ok()
            .map(|index| &self.nodes[index])
    }

    /// Iterate retained outgoing edges for one caller.
    pub fn outgoing(&self, caller: u64) -> impl Iterator<Item = &DirectCallEdge> {
        self.edges.iter().filter(move |edge| edge.caller == caller)
    }

    /// Iterate retained incoming edges for one callee.
    pub fn incoming(&self, callee: u64) -> impl Iterator<Item = &DirectCallEdge> {
        self.edges.iter().filter(move |edge| edge.callee == callee)
    }
}

fn node_from_function(
    function: &crate::analysis::functions::RecoveredFunction,
    control_flow: &ControlFlowIndex,
) -> DirectCallNode {
    let (status, reasons) = match control_flow.by_entry(function.entry) {
        Some(graph) => (
            match graph.completeness.status {
                FunctionControlFlowStatus::Complete => DirectCallNodeStatus::Complete,
                FunctionControlFlowStatus::Partial => DirectCallNodeStatus::Partial,
                FunctionControlFlowStatus::Truncated => DirectCallNodeStatus::Truncated,
                FunctionControlFlowStatus::Unavailable => DirectCallNodeStatus::Unavailable,
            },
            graph.completeness.reasons.clone(),
        ),
        None if control_flow.status() == ControlFlowIndexStatus::Truncated => (
            DirectCallNodeStatus::Truncated,
            vec!["call_graph.control_flow_function_omitted".into()],
        ),
        None => (
            DirectCallNodeStatus::Unavailable,
            vec!["call_graph.control_flow_unavailable".into()],
        ),
    };
    DirectCallNode {
        entry: function.entry,
        identity: function.identity.clone(),
        entry_confidence: function.entry_confidence,
        status,
        reasons,
        incoming_edge_count: 0,
        outgoing_edge_count: 0,
    }
}

fn callsite_context(
    graph: &FunctionControlFlow,
    block: u64,
    instruction_address: u64,
) -> (ControlFlowReachability, FunctionEvidenceConfidence) {
    let instruction = graph
        .instructions
        .binary_search_by_key(&instruction_address, |instruction| instruction.address)
        .ok()
        .map(|index| &graph.instructions[index])
        .expect("control-flow callsite references a retained instruction");
    let block_reachability = graph
        .blocks
        .get(block as usize)
        .filter(|candidate| candidate.id == block)
        .map_or(ControlFlowReachability::Unknown, |block| block.reachability);
    (block_reachability, instruction.coverage_confidence)
}

#[allow(clippy::too_many_arguments)]
fn push_unresolved(
    unresolved: &mut Vec<UnresolvedCallsite>,
    maximum: usize,
    callsite: UnresolvedCallsite,
    omitted: &mut u64,
    reasons: &mut BTreeSet<String>,
    truncated_callers: &mut BTreeSet<u64>,
) {
    if unresolved.len() < maximum {
        unresolved.push(callsite);
    } else {
        *omitted = omitted.saturating_add(1);
        reasons.insert("call_graph.unresolved_callsite_budget".into());
        truncated_callers.insert(callsite.caller);
    }
}

struct EdgeAccumulator {
    caller: u64,
    callee: u64,
    callee_entry_confidence: FunctionEvidenceConfidence,
    target_relation: FunctionTargetRelation,
    ownership_confidence: FunctionOwnershipConfidence,
    observed_callsite_count: u64,
    callsites: Vec<DirectCallsiteEvidence>,
    omitted_callsite_count: u64,
}

impl EdgeAccumulator {
    fn new(
        caller: u64,
        callee: u64,
        callee_entry_confidence: FunctionEvidenceConfidence,
        callsite: DirectCallsiteEvidence,
    ) -> Self {
        Self {
            caller,
            callee,
            callee_entry_confidence,
            target_relation: callsite.target_relation,
            ownership_confidence: callsite.ownership_confidence,
            observed_callsite_count: 1,
            callsites: vec![callsite],
            omitted_callsite_count: 0,
        }
    }

    fn push(&mut self, callsite: DirectCallsiteEvidence, maximum: usize) {
        self.observed_callsite_count = self.observed_callsite_count.saturating_add(1);
        self.target_relation = self.target_relation.min(callsite.target_relation);
        self.ownership_confidence = self.ownership_confidence.max(callsite.ownership_confidence);
        if self.callsites.len() < maximum {
            self.callsites.push(callsite);
        } else {
            self.omitted_callsite_count = self.omitted_callsite_count.saturating_add(1);
        }
    }

    fn finish(mut self) -> DirectCallEdge {
        self.callsites
            .sort_by_key(|callsite| callsite.instruction_address);
        DirectCallEdge {
            caller: self.caller,
            callee: self.callee,
            callee_entry_confidence: self.callee_entry_confidence,
            target_relation: self.target_relation,
            ownership_confidence: self.ownership_confidence,
            observed_callsite_count: self.observed_callsite_count,
            callsites: self.callsites,
            omitted_callsite_count: self.omitted_callsite_count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::control_flow::{ControlFlowIndex, ControlFlowLimits};
    use crate::analysis::functions::FunctionRecoveryLimits;

    const MAIN: u64 = 0x1_0000_0100;
    const HELPER: u64 = 0x1_0000_0120;

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    fn move_helper(bytes: &mut [u8]) {
        bytes[0x158..0x160].copy_from_slice(&HELPER.to_le_bytes());
    }

    fn add_function_starts(bytes: &mut Vec<u8>) {
        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x26_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16].copy_from_slice(&4_u32.to_le_bytes());
        bytes.extend_from_slice(&[0x80, 0x02, 0x20, 0x00]);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    }

    fn x86_calls_fixture(with_names: bool) -> Vec<u8> {
        let mut bytes = macho_test_support::disassembly_x86_64();
        move_helper(&mut bytes);
        bytes[0x100..0x112].copy_from_slice(&[
            0xe8, 0x1b, 0x00, 0x00, 0x00, // call helper
            0xe8, 0x16, 0x00, 0x00, 0x00, // call helper again
            0xff, 0xd0, // call rax
            0xe8, 0x6f, 0x00, 0x00, 0x00, // call outside executable coverage
            0xc3, // ret
        ]);
        bytes[0x120] = 0xc3;
        add_function_starts(&mut bytes);
        if !with_names {
            bytes[0x161..0x16f].fill(0);
        }
        bytes
    }

    fn arm_calls_fixture(arm64e: bool) -> Vec<u8> {
        let mut bytes = if arm64e {
            macho_test_support::disassembly_arm64e()
        } else {
            macho_test_support::disassembly_arm64()
        };
        move_helper(&mut bytes);
        bytes[0x100..0x104].copy_from_slice(&0x9400_0008_u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes[0x120..0x124].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes
    }

    fn source_indexes(bytes: &[u8]) -> (FunctionIndex, ControlFlowIndex) {
        let macho = image(bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        (functions, control_flow)
    }

    fn recover(bytes: &[u8], limits: DirectCallGraphLimits) -> DirectCallGraph {
        let (functions, control_flow) = source_indexes(bytes);
        DirectCallGraph::build(&functions, &control_flow, limits).unwrap()
    }

    #[test]
    fn aggregates_direct_calls_and_retains_non_edges() {
        let bytes = x86_calls_fixture(true);
        let graph = recover(&bytes, DirectCallGraphLimits::default());

        assert_eq!(graph.edges().len(), 1);
        let edge = &graph.edges()[0];
        assert_eq!((edge.caller, edge.callee), (MAIN, HELPER));
        assert_eq!(edge.observed_callsite_count, 2);
        assert_eq!(edge.callsites.len(), 2);
        assert!(
            edge.callsites.iter().all(|callsite| {
                callsite.block_reachability == ControlFlowReachability::Reachable
            })
        );
        assert_eq!(graph.by_entry(MAIN).unwrap().outgoing_edge_count, 1);
        assert_eq!(graph.by_entry(HELPER).unwrap().incoming_edge_count, 1);
        assert_eq!(graph.outgoing(MAIN).count(), 1);
        assert_eq!(graph.incoming(HELPER).count(), 1);

        assert_eq!(graph.unresolved_callsites().len(), 2);
        assert!(
            graph.unresolved_callsites().iter().any(|callsite| {
                callsite.reason == UnresolvedCallReason::IndirectTarget
                    && matches!(
                        callsite.target,
                        UnresolvedCallTarget::Indirect {
                            target_kind: IndirectTargetKind::Register
                        }
                    )
            }),
            "{:?}",
            graph.unresolved_callsites()
        );
        assert!(graph.unresolved_callsites().iter().any(|callsite| {
            callsite.reason == UnresolvedCallReason::NoRecoveredFunction
                && matches!(
                    callsite.target,
                    UnresolvedCallTarget::Direct {
                        address: 0x1_0000_0180,
                        entry_confidence: None,
                        ..
                    }
                )
        }));
        assert_eq!(graph.completeness().examined_callsite_count, 4);
        assert_eq!(graph.completeness().retained_direct_callsite_count, 2);
        assert_eq!(graph.completeness().unresolved_callsite_count, 2);
        assert!(
            graph
                .completeness()
                .reasons
                .contains(&"call_graph.unresolved_direct_targets".to_owned())
        );
        assert!(
            graph
                .by_entry(MAIN)
                .unwrap()
                .reasons
                .contains(&"call_graph.unresolved_direct_target".to_owned())
        );
    }

    #[test]
    fn stripping_changes_names_not_nodes_edges_or_call_ownership() {
        let rich = recover(&x86_calls_fixture(true), DirectCallGraphLimits::default());
        let stripped = recover(&x86_calls_fixture(false), DirectCallGraphLimits::default());

        assert!(matches!(
            rich.by_entry(MAIN).unwrap().identity,
            FunctionIdentity::Named { .. }
        ));
        assert!(matches!(
            stripped.by_entry(MAIN).unwrap().identity,
            FunctionIdentity::Anonymous { .. }
        ));
        assert_eq!(
            rich.nodes()
                .iter()
                .map(|node| node.entry)
                .collect::<Vec<_>>(),
            stripped
                .nodes()
                .iter()
                .map(|node| node.entry)
                .collect::<Vec<_>>()
        );
        assert_eq!(
            rich.edges()
                .iter()
                .map(|edge| (edge.caller, edge.callee, edge.callsites.clone()))
                .collect::<Vec<_>>(),
            stripped
                .edges()
                .iter()
                .map(|edge| (edge.caller, edge.callee, edge.callsites.clone()))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn arm64_and_arm64e_produce_the_same_direct_edge() {
        for bytes in [arm_calls_fixture(false), arm_calls_fixture(true)] {
            let graph = recover(&bytes, DirectCallGraphLimits::default());
            assert!(
                graph
                    .edges()
                    .iter()
                    .any(|edge| edge.caller == MAIN && edge.callee == HELPER)
            );
        }
    }

    #[test]
    fn node_budget_preserves_calls_to_omitted_function_as_unresolved() {
        let graph = recover(
            &x86_calls_fixture(true),
            DirectCallGraphLimits {
                max_nodes: 1,
                ..DirectCallGraphLimits::default()
            },
        );
        assert_eq!(graph.nodes().len(), 1);
        assert!(graph.edges().is_empty());
        assert_eq!(graph.status(), DirectCallGraphStatus::Truncated);
        assert_eq!(graph.completeness().omitted_node_count, 1);
        assert_eq!(graph.unresolved_callsites().len(), 4);
        assert_eq!(
            graph
                .unresolved_callsites()
                .iter()
                .filter(|callsite| {
                    callsite.reason == UnresolvedCallReason::FunctionOmittedByNodeBudget
                })
                .count(),
            2
        );
    }

    #[test]
    fn retention_and_work_budgets_never_claim_completion() {
        let bytes = x86_calls_fixture(true);
        let per_edge = recover(
            &bytes,
            DirectCallGraphLimits {
                max_callsites_per_edge: 1,
                ..DirectCallGraphLimits::default()
            },
        );
        assert_eq!(per_edge.edges()[0].observed_callsite_count, 2);
        assert_eq!(per_edge.edges()[0].callsites.len(), 1);
        assert_eq!(per_edge.edges()[0].omitted_callsite_count, 1);
        assert_eq!(per_edge.status(), DirectCallGraphStatus::Truncated);

        let mut two_edges_bytes = bytes.clone();
        // Redirect the second call to the independently established main entry.
        // A direct-call-only target deliberately remains an unresolved entry
        // candidate and therefore cannot be used to exercise the edge budget.
        two_edges_bytes[0x106..0x10a].copy_from_slice(&(-10_i32).to_le_bytes());
        let edge_limited = recover(
            &two_edges_bytes,
            DirectCallGraphLimits {
                max_edges: 1,
                ..DirectCallGraphLimits::default()
            },
        );
        assert_eq!(edge_limited.edges().len(), 1);
        assert_eq!(edge_limited.completeness().omitted_direct_callsite_count, 1);
        assert_eq!(edge_limited.status(), DirectCallGraphStatus::Truncated);

        let unresolved = recover(
            &bytes,
            DirectCallGraphLimits {
                max_unresolved_callsites: 1,
                ..DirectCallGraphLimits::default()
            },
        );
        assert_eq!(unresolved.unresolved_callsites().len(), 1);
        assert_eq!(
            unresolved.completeness().omitted_unresolved_callsite_count,
            1
        );
        assert_eq!(unresolved.status(), DirectCallGraphStatus::Truncated);

        let examined = recover(
            &bytes,
            DirectCallGraphLimits {
                max_examined_callsites: 1,
                ..DirectCallGraphLimits::default()
            },
        );
        assert_eq!(examined.completeness().examined_callsite_count, 1);
        assert_eq!(examined.status(), DirectCallGraphStatus::Truncated);
        assert_eq!(
            examined.by_entry(MAIN).unwrap().status,
            DirectCallNodeStatus::Truncated
        );
    }

    #[test]
    fn source_function_budget_remains_truncated_in_the_call_graph() {
        let bytes = x86_calls_fixture(true);
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(
            &macho,
            FunctionRecoveryLimits {
                max_functions: 1,
                ..FunctionRecoveryLimits::default()
            },
        )
        .unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let graph =
            DirectCallGraph::build(&functions, &control_flow, DirectCallGraphLimits::default())
                .unwrap();
        assert_eq!(graph.status(), DirectCallGraphStatus::Truncated);
        assert!(
            graph
                .completeness()
                .reasons
                .contains(&"call_graph.function_inventory_truncated".to_string())
        );
    }

    #[test]
    fn source_cfg_partiality_is_visible_on_nodes_and_graph() {
        let graph = recover(&x86_calls_fixture(true), DirectCallGraphLimits::default());
        assert_eq!(graph.status(), DirectCallGraphStatus::Partial);
        assert_eq!(
            graph.by_entry(MAIN).unwrap().status,
            DirectCallNodeStatus::Partial
        );
        assert!(
            graph
                .completeness()
                .reasons
                .contains(&"call_graph.control_flow_partial".to_string())
        );
    }

    #[test]
    fn source_indexes_must_belong_to_the_same_exact_image() {
        let rich_bytes = x86_calls_fixture(true);
        let stripped_bytes = x86_calls_fixture(false);
        let (rich_functions, rich_control_flow) = source_indexes(&rich_bytes);
        let (stripped_functions, _) = source_indexes(&stripped_bytes);
        assert_eq!(
            DirectCallGraph::build(
                &stripped_functions,
                &rich_control_flow,
                DirectCallGraphLimits::default(),
            )
            .unwrap_err(),
            DirectCallGraphError::ImageMismatch
        );
        DirectCallGraph::build(
            &rich_functions,
            &rich_control_flow,
            DirectCallGraphLimits::default(),
        )
        .unwrap();
    }
}
