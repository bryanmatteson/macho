use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::analysis::Result;
use crate::analysis::control_flow::{
    ControlFlowDecodeArena, ControlFlowGapKind, ControlFlowIndex, ControlFlowIndexStatus,
    ControlFlowInstruction, ControlFlowInstructionKind, ControlFlowLimits, ControlFlowOperand,
    ControlFlowPcRelativeKind, ControlFlowRegister, ControlFlowValueEffect, FunctionControlFlow,
    InstructionTarget,
};
use crate::analysis::dyld::bind::parse_bind_entries;
use crate::analysis::dyld::chained::parse_chained_fixups;
use crate::analysis::dyld::types::FixupKind;
use crate::analysis::ext::MachoExt;
use crate::analysis::format::constants::*;
use crate::analysis::format::relocations_for_section;
use crate::analysis::functions::{FunctionControlFlowRefinement, FunctionIndex};
use crate::analysis::model::addr::types::{ThinFileOffset, Va};
use crate::analysis::model::macho_file::MachoFile;
use crate::analysis::model::relocation::Relocation;
use crate::analysis::model::section::SectionType;
use crate::analysis::model::symbol::SymbolTable;
use crate::analysis::program::RecoveredProgram;

/// Explicit limits for one authoritative xref recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefRecoveryLimits {
    /// Maximum references retained across all sources.
    pub max_refs: usize,
    /// Maximum executable bytes decoded by compatibility scanners.
    pub max_decoded_bytes: usize,
    /// Maximum fixed-point operations used to compose address values.
    pub max_value_flow_work: u64,
    /// Maximum distinct address values retained for one register.
    pub max_values_per_register: usize,
}

impl Default for XrefRecoveryLimits {
    fn default() -> Self {
        Self {
            max_refs: 16_000_000,
            max_decoded_bytes: 256 * 1024 * 1024,
            max_value_flow_work: 8_000_000,
            max_values_per_register: 64,
        }
    }
}

impl XrefRecoveryLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self> {
        if self.max_refs == 0
            || self.max_decoded_bytes == 0
            || self.max_value_flow_work == 0
            || self.max_values_per_register == 0
        {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::InvalidInput,
                "xref recovery limits must be non-zero",
            ));
        }
        Ok(self)
    }
}

/// Completion state for the authoritative xref inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefIndexStatus {
    /// Every source and requested CFG completed without omissions.
    Complete,
    /// Useful references exist but source CFG coverage is incomplete.
    Partial,
    /// A reference or decode budget omitted evidence.
    Truncated,
}

/// Independent source contributing xref evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefEvidenceSource {
    /// Indirect-symbol stubs and pointer slots.
    Stubs,
    /// Dyld chained fixups.
    ChainedFixups,
    /// Legacy dyld rebase opcodes.
    LegacyRebases,
    /// Legacy dyld bind opcodes.
    LegacyBinds,
    /// Mach-O relocation records.
    Relocations,
    /// Instructions supplied by an authoritative CFG or compatibility scan.
    Instructions,
}

/// Terminal state of one xref source collector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum XrefCollectorStatus {
    /// The image has no corresponding source.
    Absent,
    /// The source completed without omissions.
    Complete,
    /// The source completed with uncertain local coverage.
    Partial,
    /// The source was malformed and its attempted records were discarded.
    Failed,
    /// The global reference budget omitted source records.
    Truncated,
}

/// Per-source xref receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefCollectorReceipt {
    /// Evidence source.
    pub source: XrefEvidenceSource,
    /// Terminal collector state.
    pub status: XrefCollectorStatus,
    /// Records retained from this source.
    pub retained: u64,
    /// Stable diagnostic code when incomplete.
    pub diagnostic: Option<String>,
}

/// Completeness receipt for the authoritative xref inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct XrefCompleteness {
    /// Overall status.
    pub status: XrefIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Retained reference count.
    pub retained_refs: u64,
    /// Retained CFG decode-gap count.
    pub decode_gaps: u64,
    /// One receipt per xref source in deterministic order.
    pub collectors: Vec<XrefCollectorReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// The XrefIndex type.
pub struct XrefIndex {
    image: crate::analysis::functions::FunctionImageIdentity,
    limits: XrefRecoveryLimits,
    refs: Vec<Xref>,
    decode_gaps: Vec<crate::insn::DecodeGap>,
    refs_truncated: bool,
    decoded_bytes_truncated: bool,
    completeness: XrefCompleteness,
}

struct XrefBuild {
    refs: Vec<Xref>,
    decode_gaps: Vec<crate::insn::DecodeGap>,
    refs_truncated: bool,
    decoded_bytes_truncated: bool,
    decode_budget_truncated: bool,
    source_control_flow_truncated: bool,
    value_flow_truncated: bool,
    partial: bool,
    collectors: Vec<XrefCollectorReceipt>,
}

struct InstructionXrefAccumulator {
    limits: XrefRecoveryLimits,
    instruction_limit: usize,
    refs: Vec<Xref>,
    decode_gaps: Vec<crate::insn::DecodeGap>,
    instruction_truncated: bool,
    decode_budget_truncated: bool,
    value_flow_budget: XrefValueFlowBudget,
    value_flow_truncated: bool,
    remaining_decoded_bytes: u64,
    stopped: bool,
}

impl InstructionXrefAccumulator {
    fn new(limits: XrefRecoveryLimits, instruction_limit: usize) -> Self {
        Self {
            limits,
            instruction_limit,
            refs: Vec::new(),
            decode_gaps: Vec::new(),
            instruction_truncated: false,
            decode_budget_truncated: false,
            value_flow_budget: XrefValueFlowBudget::new(limits.max_value_flow_work),
            value_flow_truncated: false,
            remaining_decoded_bytes: limits.max_decoded_bytes as u64,
            stopped: false,
        }
    }

    fn observe(&mut self, graph: &FunctionControlFlow) {
        if self.stopped {
            return;
        }
        let graph_bytes = graph.completeness.decoded_bytes;
        if graph_bytes > self.remaining_decoded_bytes {
            self.decode_budget_truncated = true;
            self.stopped = true;
            return;
        }
        self.remaining_decoded_bytes -= graph_bytes;
        for gap in &graph.gaps {
            self.decode_gaps.push(crate::insn::DecodeGap {
                offset: 0,
                len: usize::try_from(gap.end_exclusive.saturating_sub(gap.start))
                    .unwrap_or(usize::MAX),
                va: gap.start,
                error: crate::insn::DecodeError {
                    kind: crate::insn::DecodeErrorKind::InvalidEncoding,
                    message: match gap.kind {
                        ControlFlowGapKind::InvalidInstruction => {
                            "invalid instruction in recovered function".into()
                        }
                        ControlFlowGapKind::UnmappedRange => {
                            "unmapped recovered function range".into()
                        }
                    },
                },
            });
        }
        for instruction in &graph.instructions {
            if let Some(InstructionTarget::Direct { address }) = &instruction.target
                && !direct_call_target_is_suppressed(graph, instruction, *address)
            {
                let _ = push_ref(
                    &mut self.refs,
                    self.instruction_limit,
                    &mut self.instruction_truncated,
                    Xref {
                        source: Va(instruction.address),
                        target: XrefTarget::Internal { va: Va(*address) },
                        kind: XrefKind::DirectBranch,
                    },
                );
            }
            if self.instruction_truncated {
                self.stopped = true;
                return;
            }
        }
        let data = recover_data_references(
            graph,
            self.limits.max_values_per_register,
            &mut self.value_flow_budget,
        );
        self.value_flow_truncated |= data.truncated;
        for (source, target) in data.references {
            if !push_ref(
                &mut self.refs,
                self.instruction_limit,
                &mut self.instruction_truncated,
                Xref {
                    source: Va(source),
                    target: XrefTarget::Internal { va: Va(target) },
                    kind: XrefKind::Data,
                },
            ) {
                break;
            }
        }
        if self.instruction_truncated || self.value_flow_budget.exhausted {
            self.value_flow_truncated |= self.value_flow_budget.exhausted;
            self.stopped = true;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
/// The Xref type.
pub struct Xref {
    #[serde(
        serialize_with = "crate::analysis::serde_addr::va",
        deserialize_with = "crate::analysis::serde_addr::va_from"
    )]
    /// The source field.
    pub source: Va,
    /// The target field.
    pub target: XrefTarget,
    /// The kind field.
    pub kind: XrefKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
/// The XrefTarget type.
#[non_exhaustive]
pub enum XrefTarget {
    /// The Internal variant.
    Internal {
        #[serde(
            serialize_with = "crate::analysis::serde_addr::va",
            deserialize_with = "crate::analysis::serde_addr::va_from"
        )]
        /// The Va field.
        va: Va,
    },
    /// The Import variant.
    Import {
        /// The String field.
        name: String,
        /// The i32 field.
        ordinal: i32,
    },
}

impl XrefTarget {
    /// Return the internal target address, if this is an in-image reference.
    pub const fn internal_address(&self) -> Option<Va> {
        match self {
            Self::Internal { va } => Some(*va),
            Self::Import { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The XrefKind type.
#[non_exhaustive]
pub enum XrefKind {
    /// The Stub variant.
    Stub,
    /// The ChainedBind variant.
    ChainedBind,
    /// The ChainedRebase variant.
    ChainedRebase,
    /// The LegacyRebase variant.
    LegacyRebase,
    /// The LegacyBind variant.
    LegacyBind,
    /// The Relocation variant.
    Relocation,
    /// The DirectBranch variant.
    DirectBranch,
    /// Non-branch instruction materializing or loading an internal address.
    Data,
}

impl XrefIndex {
    /// Performs build.
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        Self::build_limited(macho, usize::MAX, usize::MAX)
    }

    /// Build while bounding retained references and decoded executable bytes.
    pub fn build_limited(
        macho: &MachoFile<'_>,
        max_refs: usize,
        max_decoded_bytes: usize,
    ) -> Result<Self> {
        let mut refs = Vec::new();
        let mut refs_truncated = false;

        let mut collectors = collect_format_refs(macho, &mut refs, max_refs, &mut refs_truncated);

        // 5. Scan for arm64 direct branches in executable sections
        let mut decode_gaps = Vec::new();
        let mut instruction_refs = Vec::new();
        let mut instruction_truncated = false;
        let decoded_bytes_truncated = collect_direct_branches(
            macho,
            &mut instruction_refs,
            &mut decode_gaps,
            max_refs.saturating_sub(refs.len()),
            max_decoded_bytes,
            &mut instruction_truncated,
        );
        let instruction_partial = !decode_gaps.is_empty();
        collectors.push(instruction_receipt(
            instruction_refs.len(),
            if instruction_truncated {
                Some("xrefs.retention_budget")
            } else if decoded_bytes_truncated {
                Some("xrefs.decode_budget")
            } else {
                None
            },
            instruction_partial,
        ));
        refs.extend(instruction_refs);
        refs_truncated |= instruction_truncated;

        // Sort by source address
        refs.sort_by_key(|r| r.source);

        Ok(Self::finish(
            macho,
            XrefRecoveryLimits {
                max_refs,
                max_decoded_bytes,
                ..XrefRecoveryLimits::default()
            },
            XrefBuild {
                refs,
                decode_gaps,
                refs_truncated,
                decoded_bytes_truncated,
                decode_budget_truncated: decoded_bytes_truncated,
                source_control_flow_truncated: false,
                value_flow_truncated: false,
                partial: instruction_partial,
                collectors,
            },
        ))
    }

    /// Recover only format-level stubs, fixups, binds, and relocations.
    ///
    /// This performs no instruction decoding and is the shared foundation for
    /// pointer inventories and full xref recovery.
    pub fn recover_format(macho: &MachoFile<'_>, max_refs: usize) -> Result<Self> {
        if max_refs == 0 {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::InvalidInput,
                "format xref retention limit must be non-zero",
            ));
        }
        let mut refs = Vec::new();
        let mut refs_truncated = false;
        let collectors = collect_format_refs(macho, &mut refs, max_refs, &mut refs_truncated);
        refs.sort_by_key(|reference| reference.source);
        Ok(Self::finish(
            macho,
            XrefRecoveryLimits {
                max_refs,
                ..XrefRecoveryLimits::default()
            },
            XrefBuild {
                refs,
                decode_gaps: Vec::new(),
                refs_truncated,
                decoded_bytes_truncated: false,
                decode_budget_truncated: false,
                source_control_flow_truncated: false,
                value_flow_truncated: false,
                partial: false,
                collectors,
            },
        ))
    }

    /// Recover format references under a selected-image evidence session.
    pub(crate) fn recover_format_with_evidence(
        evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
        max_refs: usize,
    ) -> Result<Self> {
        if max_refs == 0 {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::InvalidInput,
                "format xref retention limit must be non-zero",
            ));
        }
        let mut refs = Vec::new();
        let mut refs_truncated = false;
        let collectors =
            collect_format_refs_with_evidence(evidence, &mut refs, max_refs, &mut refs_truncated);
        refs.sort_by_key(|reference| reference.source);
        Ok(Self::finish(
            evidence.image(),
            XrefRecoveryLimits {
                max_refs,
                ..XrefRecoveryLimits::default()
            },
            XrefBuild {
                refs,
                decode_gaps: Vec::new(),
                refs_truncated,
                decoded_bytes_truncated: false,
                decode_budget_truncated: false,
                source_control_flow_truncated: false,
                value_flow_truncated: false,
                partial: false,
                collectors,
            },
        ))
    }

    /// Recover format and instruction references from an authoritative CFG.
    pub fn recover(
        macho: &MachoFile<'_>,
        control_flow: &ControlFlowIndex,
        limits: XrefRecoveryLimits,
    ) -> Result<Self> {
        Self::recover_seeded(macho, control_flow, limits, None)
    }

    /// Recover instruction references while reusing a selected pointer inventory.
    pub fn recover_with_pointers(
        macho: &MachoFile<'_>,
        control_flow: &ControlFlowIndex,
        pointers: &crate::analysis::pointer_index::PointerIndex,
        limits: XrefRecoveryLimits,
    ) -> Result<Self> {
        if pointers.image() != &crate::analysis::functions::FunctionImageIdentity::from_macho(macho)
        {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Validation,
                "pointer and xref image identities differ",
            ));
        }
        Self::recover_seeded(macho, control_flow, limits, Some(pointers.format_index()))
    }

    pub(crate) fn recover_streaming_with_pointers(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        pointers: &crate::analysis::pointer_index::PointerIndex,
        control_flow_limits: ControlFlowLimits,
        limits: XrefRecoveryLimits,
    ) -> Result<Self> {
        let limits = limits.validate()?;
        let image = crate::analysis::functions::FunctionImageIdentity::from_macho(macho);
        if functions.image() != &image || pointers.image() != &image {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Validation,
                "function, pointer, and xref image identities differ",
            ));
        }
        let format = pointers.format_index();
        let mut refs = format.refs.clone();
        let mut refs_truncated = format.refs_truncated;
        if refs.len() > limits.max_refs {
            refs.truncate(limits.max_refs);
            refs_truncated = true;
        }
        let mut collectors = format.completeness.collectors.clone();
        reconcile_format_collector_retention(&mut collectors, &refs);
        let instruction_limit = limits.max_refs.saturating_sub(refs.len());

        // Once authoritative format records consume the complete retention
        // budget, no instruction reference can be admitted.  Do not recover
        // and refine every function graph merely to rediscover that fixed
        // budget boundary.
        if instruction_limit == 0 {
            return Ok(Self::finish_instruction_saturated(
                macho, limits, refs, collectors,
            ));
        }
        let refinement_only_provisional = macho.header().cpu_type().0
            == crate::core::format::constants::CPU_TYPE_X86_64
            && FunctionControlFlowRefinement::may_change(functions);
        let decode_arena = refinement_only_provisional.then(|| {
            std::cell::RefCell::new(ControlFlowDecodeArena::new(
                control_flow_limits.max_decoded_bytes,
            ))
        });
        struct ProvisionalFold {
            refinement: FunctionControlFlowRefinement,
            instructions: InstructionXrefAccumulator,
        }

        let fold_error = |error: crate::analysis::control_flow::ControlFlowRecoveryError| {
            let kind = if matches!(
                error,
                crate::analysis::control_flow::ControlFlowRecoveryError::UnsupportedArchitecture
            ) {
                crate::analysis::AnalysisErrorKind::UnsupportedCapability
            } else {
                crate::analysis::AnalysisErrorKind::Parse
            };
            crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                kind,
                format!("recover streaming control flow: {error}"),
            )
        };
        let (mut instructions, summary) = if refinement_only_provisional {
            let (refinement, _) = ControlFlowIndex::fold_with_pointers(
                macho,
                functions,
                pointers,
                control_flow_limits,
                decode_arena.as_ref(),
                |_| FunctionControlFlowRefinement::new(functions),
                |refinement, graph| refinement.observe(functions, &graph),
            )
            .map_err(&fold_error)?;
            let refined = refinement.finish_if_changed(functions);
            ControlFlowIndex::fold_with_pointers(
                macho,
                refined.as_ref().unwrap_or(functions),
                pointers,
                control_flow_limits,
                decode_arena.as_ref(),
                |_| InstructionXrefAccumulator::new(limits, instruction_limit),
                |accumulator, graph| accumulator.observe(&graph),
            )
            .map_err(&fold_error)?
        } else {
            let (provisional, provisional_summary) = ControlFlowIndex::fold_with_pointers(
                macho,
                functions,
                pointers,
                control_flow_limits,
                None,
                |_| ProvisionalFold {
                    refinement: FunctionControlFlowRefinement::new(functions),
                    instructions: InstructionXrefAccumulator::new(limits, instruction_limit),
                },
                |accumulator, graph| {
                    accumulator.refinement.observe(functions, &graph);
                    accumulator.instructions.observe(&graph);
                },
            )
            .map_err(&fold_error)?;
            let refined = provisional.refinement.finish_if_changed(functions);
            if let Some(refined) = refined {
                ControlFlowIndex::fold_with_pointers(
                    macho,
                    &refined,
                    pointers,
                    control_flow_limits,
                    None,
                    |_| InstructionXrefAccumulator::new(limits, instruction_limit),
                    |accumulator, graph| accumulator.observe(&graph),
                )
                .map_err(&fold_error)?
            } else {
                (provisional.instructions, provisional_summary)
            }
        };

        instructions
            .decode_gaps
            .sort_by_key(|gap| (gap.va, gap.len));
        instructions
            .decode_gaps
            .dedup_by_key(|gap| (gap.va, gap.len));
        let control_flow_truncated = summary.status == ControlFlowIndexStatus::Truncated;
        let control_flow_partial = summary.status == ControlFlowIndexStatus::Partial;
        collectors.push(instruction_receipt(
            instructions.refs.len(),
            if instructions.instruction_truncated {
                Some("xrefs.retention_budget")
            } else if instructions.decode_budget_truncated {
                Some("xrefs.decode_budget")
            } else if instructions.value_flow_truncated {
                Some("xrefs.value_flow_budget")
            } else if control_flow_truncated {
                Some("xrefs.source_control_flow_truncated")
            } else {
                None
            },
            control_flow_partial,
        ));
        refs.extend(instructions.refs);
        refs_truncated |= instructions.instruction_truncated;
        refs.sort_by_key(|reference| reference.source);
        Ok(Self::finish(
            macho,
            limits,
            XrefBuild {
                refs,
                decode_gaps: instructions.decode_gaps,
                refs_truncated,
                decoded_bytes_truncated: control_flow_truncated
                    || instructions.decode_budget_truncated,
                decode_budget_truncated: instructions.decode_budget_truncated,
                source_control_flow_truncated: control_flow_truncated,
                value_flow_truncated: instructions.value_flow_truncated,
                partial: control_flow_partial,
                collectors,
            },
        ))
    }

    fn recover_seeded(
        macho: &MachoFile<'_>,
        control_flow: &ControlFlowIndex,
        limits: XrefRecoveryLimits,
        format: Option<&XrefIndex>,
    ) -> Result<Self> {
        let limits = limits.validate()?;
        if control_flow.image()
            != &crate::analysis::functions::FunctionImageIdentity::from_macho(macho)
        {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Validation,
                "control-flow and xref image identities differ",
            ));
        }
        let (mut refs, mut refs_truncated, mut collectors) = if let Some(format) = format {
            let mut refs = format.refs.clone();
            let mut truncated = format.refs_truncated;
            if refs.len() > limits.max_refs {
                refs.truncate(limits.max_refs);
                truncated = true;
            }
            let mut collectors = format.completeness.collectors.clone();
            reconcile_format_collector_retention(&mut collectors, &refs);
            (refs, truncated, collectors)
        } else {
            let mut refs = Vec::new();
            let mut truncated = false;
            let collectors = collect_format_refs(macho, &mut refs, limits.max_refs, &mut truncated);
            (refs, truncated, collectors)
        };

        let instruction_limit = limits.max_refs.saturating_sub(refs.len());
        if instruction_limit == 0 {
            return Ok(Self::finish_instruction_saturated(
                macho, limits, refs, collectors,
            ));
        }
        let mut decode_gaps = Vec::new();
        let mut instruction_refs = Vec::new();
        let mut instruction_truncated = false;
        let mut decode_budget_truncated = false;
        let mut value_flow_budget = XrefValueFlowBudget::new(limits.max_value_flow_work);
        let mut value_flow_truncated = false;
        let mut remaining_decoded_bytes = limits.max_decoded_bytes as u64;
        for graph in control_flow.functions() {
            let graph_bytes = graph.completeness.decoded_bytes;
            if graph_bytes > remaining_decoded_bytes {
                decode_budget_truncated = true;
                break;
            }
            remaining_decoded_bytes -= graph_bytes;
            for gap in &graph.gaps {
                decode_gaps.push(crate::insn::DecodeGap {
                    offset: 0,
                    len: usize::try_from(gap.end_exclusive.saturating_sub(gap.start))
                        .unwrap_or(usize::MAX),
                    va: gap.start,
                    error: crate::insn::DecodeError {
                        kind: crate::insn::DecodeErrorKind::InvalidEncoding,
                        message: match gap.kind {
                            ControlFlowGapKind::InvalidInstruction => {
                                "invalid instruction in recovered function".into()
                            }
                            ControlFlowGapKind::UnmappedRange => {
                                "unmapped recovered function range".into()
                            }
                        },
                    },
                });
            }
            for instruction in &graph.instructions {
                if let Some(InstructionTarget::Direct { address }) = &instruction.target
                    && !direct_call_target_is_suppressed(graph, instruction, *address)
                {
                    let _ = push_ref(
                        &mut instruction_refs,
                        instruction_limit,
                        &mut instruction_truncated,
                        Xref {
                            source: Va(instruction.address),
                            target: XrefTarget::Internal { va: Va(*address) },
                            kind: XrefKind::DirectBranch,
                        },
                    );
                }
                if instruction_truncated {
                    break;
                }
            }
            if instruction_truncated {
                break;
            }
            let data = recover_data_references(
                graph,
                limits.max_values_per_register,
                &mut value_flow_budget,
            );
            value_flow_truncated |= data.truncated;
            for (source, target) in data.references {
                if !push_ref(
                    &mut instruction_refs,
                    instruction_limit,
                    &mut instruction_truncated,
                    Xref {
                        source: Va(source),
                        target: XrefTarget::Internal { va: Va(target) },
                        kind: XrefKind::Data,
                    },
                ) {
                    break;
                }
            }
            if instruction_truncated || value_flow_budget.exhausted {
                value_flow_truncated |= value_flow_budget.exhausted;
                break;
            }
        }
        decode_gaps.sort_by_key(|gap| (gap.va, gap.len));
        decode_gaps.dedup_by_key(|gap| (gap.va, gap.len));
        let control_flow_truncated = control_flow.status()
            == crate::analysis::control_flow::ControlFlowIndexStatus::Truncated;
        let control_flow_partial =
            control_flow.status() == crate::analysis::control_flow::ControlFlowIndexStatus::Partial;
        collectors.push(instruction_receipt(
            instruction_refs.len(),
            if instruction_truncated {
                Some("xrefs.retention_budget")
            } else if decode_budget_truncated {
                Some("xrefs.decode_budget")
            } else if value_flow_truncated {
                Some("xrefs.value_flow_budget")
            } else if control_flow_truncated {
                Some("xrefs.source_control_flow_truncated")
            } else {
                None
            },
            control_flow_partial,
        ));
        refs.extend(instruction_refs);
        refs_truncated |= instruction_truncated;
        refs.sort_by_key(|reference| reference.source);
        Ok(Self::finish(
            macho,
            limits,
            XrefBuild {
                refs,
                decode_gaps,
                refs_truncated,
                decoded_bytes_truncated: control_flow_truncated || decode_budget_truncated,
                decode_budget_truncated,
                source_control_flow_truncated: control_flow_truncated,
                value_flow_truncated,
                partial: control_flow_partial,
                collectors,
            },
        ))
    }

    /// Build the legacy xref projection from a Macho-owned recovered program.
    ///
    /// Format-level stub, fixup, bind, and relocation references remain
    /// collected from their authoritative records. Direct code references and
    /// decode gaps are projected from the program CFGs without rescanning
    /// executable sections or inventing separate function ownership.
    pub fn from_recovered_program_limited(
        macho: &MachoFile<'_>,
        program: &RecoveredProgram,
        max_refs: usize,
    ) -> Result<Self> {
        if program.image() != &crate::analysis::functions::FunctionImageIdentity::from_macho(macho)
        {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Validation,
                "recovered program and xref image identities differ",
            ));
        }
        let control_flow = program.control_flow().ok_or_else(|| {
            crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Validation,
                "recovered program did not execute the control-flow dependency",
            )
        })?;
        Self::recover(
            macho,
            control_flow,
            XrefRecoveryLimits {
                max_refs,
                max_decoded_bytes: control_flow.limits().max_decoded_bytes,
                ..XrefRecoveryLimits::default()
            },
        )
    }

    /// Discover direct branches to an exact set of internal target addresses.
    ///
    /// The target set is supplied by separately validated format evidence, so
    /// this scan does not parse unrelated symbols, imports, fixups, or xrefs.
    pub fn direct_branches_to_targets_limited(
        macho: &MachoFile<'_>,
        targets: &BTreeSet<u64>,
        max_refs: usize,
        max_decoded_bytes: usize,
    ) -> Result<Self> {
        let mut refs = Vec::new();
        let mut decode_gaps = Vec::new();
        let mut refs_truncated = false;
        let mut collectors = Vec::new();
        let decoded_bytes_truncated = collect_direct_branches_to_targets(
            macho,
            targets,
            &mut refs,
            &mut decode_gaps,
            max_refs,
            max_decoded_bytes,
            &mut refs_truncated,
        );
        collectors.push(instruction_receipt(
            refs.len(),
            decoded_bytes_truncated.then_some("xrefs.decode_budget"),
            !decode_gaps.is_empty(),
        ));
        let partial = !decode_gaps.is_empty();
        refs.sort_by_key(|reference| reference.source);
        Ok(Self::finish(
            macho,
            XrefRecoveryLimits {
                max_refs,
                max_decoded_bytes,
                ..XrefRecoveryLimits::default()
            },
            XrefBuild {
                refs,
                decode_gaps,
                refs_truncated,
                decoded_bytes_truncated,
                decode_budget_truncated: decoded_bytes_truncated,
                source_control_flow_truncated: false,
                value_flow_truncated: false,
                partial,
                collectors,
            },
        ))
    }

    fn finish(macho: &MachoFile<'_>, limits: XrefRecoveryLimits, build: XrefBuild) -> Self {
        let XrefBuild {
            refs,
            decode_gaps,
            refs_truncated,
            decoded_bytes_truncated,
            decode_budget_truncated,
            source_control_flow_truncated,
            value_flow_truncated,
            partial,
            collectors,
        } = build;
        let status = if refs_truncated || decoded_bytes_truncated || value_flow_truncated {
            XrefIndexStatus::Truncated
        } else if partial
            || collectors.iter().any(|receipt| {
                matches!(
                    receipt.status,
                    XrefCollectorStatus::Partial | XrefCollectorStatus::Failed
                )
            })
        {
            XrefIndexStatus::Partial
        } else {
            XrefIndexStatus::Complete
        };
        let mut reasons = Vec::new();
        if refs_truncated {
            reasons.push("xrefs.retention_budget".to_owned());
        }
        if decode_budget_truncated {
            reasons.push("xrefs.decode_budget".to_owned());
        }
        if source_control_flow_truncated {
            reasons.push("xrefs.source_control_flow_truncated".to_owned());
        }
        if value_flow_truncated {
            reasons.push("xrefs.value_flow_budget".to_owned());
        }
        if partial {
            reasons.push("xrefs.source_control_flow_partial".to_owned());
        }
        reasons.extend(
            collectors
                .iter()
                .filter_map(|receipt| receipt.diagnostic.clone()),
        );
        reasons.sort();
        reasons.dedup();
        Self {
            image: crate::analysis::functions::FunctionImageIdentity::from_macho(macho),
            limits,
            completeness: XrefCompleteness {
                status,
                reasons,
                retained_refs: refs.len() as u64,
                decode_gaps: decode_gaps.len() as u64,
                collectors,
            },
            refs,
            decode_gaps,
            refs_truncated,
            decoded_bytes_truncated,
        }
    }

    fn finish_instruction_saturated(
        macho: &MachoFile<'_>,
        limits: XrefRecoveryLimits,
        mut refs: Vec<Xref>,
        mut collectors: Vec<XrefCollectorReceipt>,
    ) -> Self {
        collectors.push(instruction_receipt(
            0,
            Some("xrefs.retention_budget"),
            false,
        ));
        refs.sort_by_key(|reference| reference.source);
        Self::finish(
            macho,
            limits,
            XrefBuild {
                refs,
                decode_gaps: Vec::new(),
                refs_truncated: true,
                decoded_bytes_truncated: false,
                decode_budget_truncated: false,
                source_control_flow_truncated: false,
                value_flow_truncated: false,
                partial: false,
                collectors,
            },
        )
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &crate::analysis::functions::FunctionImageIdentity {
        &self.image
    }

    /// Exact limits used for recovery.
    pub const fn limits(&self) -> XrefRecoveryLimits {
        self.limits
    }

    /// Completeness and work receipt.
    pub fn completeness(&self) -> &XrefCompleteness {
        &self.completeness
    }

    /// Overall xref status.
    pub const fn status(&self) -> XrefIndexStatus {
        self.completeness.status
    }

    /// Performs refs_from.
    pub fn refs_from(&self, source: Va) -> impl Iterator<Item = &Xref> {
        let lo = self.refs.partition_point(|r| r.source < source);
        self.refs[lo..]
            .iter()
            .take_while(move |r| r.source == source)
    }

    /// Find all xrefs whose target is the given internal VA.
    ///
    /// Scans linearly: refs are sorted by source address, not target.
    pub fn refs_to(&self, target: Va) -> impl Iterator<Item = &Xref> {
        self.refs.iter().filter(move |r| match &r.target {
            XrefTarget::Internal { va } => *va == target,
            _ => false,
        })
    }

    /// Performs refs_in_range.
    pub fn refs_in_range(&self, start: Va, end: Va) -> &[Xref] {
        let lo = self.refs.partition_point(|r| r.source < start);
        let hi = self.refs.partition_point(|r| r.source < end);
        &self.refs[lo..hi]
    }

    /// Performs all_refs.
    pub fn all_refs(&self) -> &[Xref] {
        &self.refs
    }

    /// Performs decode_gaps.
    pub fn decode_gaps(&self) -> &[crate::insn::DecodeGap] {
        &self.decode_gaps
    }

    /// Whether additional references were discarded at the requested limit.
    pub const fn refs_truncated(&self) -> bool {
        self.refs_truncated
    }

    /// Whether executable bytes were skipped at the requested decode limit.
    pub const fn decoded_bytes_truncated(&self) -> bool {
        self.decoded_bytes_truncated
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.refs.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.refs.is_empty()
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        let refs_are_sorted = self
            .refs
            .windows(2)
            .all(|pair| pair[0].source <= pair[1].source);
        let reasons_are_canonical = self
            .completeness
            .reasons
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
        let collectors_are_canonical = self
            .completeness
            .collectors
            .windows(2)
            .all(|pair| xref_source_rank(pair[0].source) < xref_source_rank(pair[1].source));
        let collector_receipts_are_valid = self.completeness.collectors.iter().all(|receipt| {
            let actual = self
                .refs
                .iter()
                .filter(|reference| xref_kind_source(reference.kind) == receipt.source)
                .count() as u64;
            let state_is_valid = match receipt.status {
                XrefCollectorStatus::Absent => {
                    receipt.retained == 0 && receipt.diagnostic.is_none()
                }
                XrefCollectorStatus::Complete => receipt.diagnostic.is_none(),
                XrefCollectorStatus::Partial => true,
                XrefCollectorStatus::Failed => {
                    receipt.retained == 0 && receipt.diagnostic.is_some()
                }
                XrefCollectorStatus::Truncated => receipt.diagnostic.is_some(),
            };
            receipt.retained == actual
                && state_is_valid
                && receipt
                    .diagnostic
                    .as_ref()
                    .is_none_or(|diagnostic| self.completeness.reasons.contains(diagnostic))
        });
        let every_ref_has_a_receipt = self.refs.iter().all(|reference| {
            let source = xref_kind_source(reference.kind);
            self.completeness
                .collectors
                .iter()
                .any(|receipt| receipt.source == source)
        });
        let retained_by_collectors = self
            .completeness
            .collectors
            .iter()
            .try_fold(0_u64, |total, receipt| total.checked_add(receipt.retained));
        let retention_reason = self
            .completeness
            .reasons
            .iter()
            .any(|reason| reason == "xrefs.retention_budget");
        let decode_reason = self.completeness.reasons.iter().any(|reason| {
            reason == "xrefs.decode_budget" || reason == "xrefs.source_control_flow_truncated"
        });
        let value_flow_truncated = self
            .completeness
            .reasons
            .iter()
            .any(|reason| reason == "xrefs.value_flow_budget");
        let partial = self
            .completeness
            .reasons
            .iter()
            .any(|reason| reason == "xrefs.source_control_flow_partial")
            || self.completeness.collectors.iter().any(|receipt| {
                matches!(
                    receipt.status,
                    XrefCollectorStatus::Partial | XrefCollectorStatus::Failed
                )
            });
        let expected_status =
            if self.refs_truncated || self.decoded_bytes_truncated || value_flow_truncated {
                XrefIndexStatus::Truncated
            } else if partial {
                XrefIndexStatus::Partial
            } else {
                XrefIndexStatus::Complete
            };
        self.limits.validate().is_ok()
            && self.refs.len() <= self.limits.max_refs
            && refs_are_sorted
            && reasons_are_canonical
            && collectors_are_canonical
            && collector_receipts_are_valid
            && every_ref_has_a_receipt
            && self.completeness.retained_refs == self.refs.len() as u64
            && self.completeness.decode_gaps == self.decode_gaps.len() as u64
            && retained_by_collectors == Some(self.refs.len() as u64)
            && retention_reason == self.refs_truncated
            && decode_reason == self.decoded_bytes_truncated
            && self.completeness.status == expected_status
    }
}

const fn xref_source_rank(source: XrefEvidenceSource) -> u8 {
    match source {
        XrefEvidenceSource::Stubs => 0,
        XrefEvidenceSource::ChainedFixups => 1,
        XrefEvidenceSource::LegacyRebases => 2,
        XrefEvidenceSource::LegacyBinds => 3,
        XrefEvidenceSource::Relocations => 4,
        XrefEvidenceSource::Instructions => 5,
    }
}

const fn xref_kind_source(kind: XrefKind) -> XrefEvidenceSource {
    match kind {
        XrefKind::Stub => XrefEvidenceSource::Stubs,
        XrefKind::ChainedBind | XrefKind::ChainedRebase => XrefEvidenceSource::ChainedFixups,
        XrefKind::LegacyRebase => XrefEvidenceSource::LegacyRebases,
        XrefKind::LegacyBind => XrefEvidenceSource::LegacyBinds,
        XrefKind::Relocation => XrefEvidenceSource::Relocations,
        XrefKind::DirectBranch | XrefKind::Data => XrefEvidenceSource::Instructions,
    }
}

fn reconcile_format_collector_retention(
    collectors: &mut [XrefCollectorReceipt],
    retained_refs: &[Xref],
) {
    for receipt in collectors
        .iter_mut()
        .filter(|receipt| receipt.source != XrefEvidenceSource::Instructions)
    {
        let retained = retained_refs
            .iter()
            .filter(|reference| xref_kind_source(reference.kind) == receipt.source)
            .count() as u64;
        if retained < receipt.retained {
            receipt.status = XrefCollectorStatus::Truncated;
            receipt.diagnostic = Some("xrefs.retention_budget".to_owned());
        }
        receipt.retained = retained;
    }
}

fn direct_call_target_is_suppressed(
    graph: &FunctionControlFlow,
    instruction: &ControlFlowInstruction,
    target_address: u64,
) -> bool {
    instruction.kind == ControlFlowInstructionKind::Call
        && graph
            .guided_direct_call_suppressions
            .iter()
            .any(|suppression| {
                suppression.instruction_address == instruction.address
                    && suppression.target_address == target_address
            })
}

impl<'data> MachoExt<'data> for XrefIndex {
    type Error = crate::analysis::AnalysisError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        Self::build(macho)
    }
}

fn collect_format_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Vec<XrefCollectorReceipt> {
    collect_format_refs_with_leaf_collectors(
        macho,
        refs,
        max_refs,
        truncated,
        FormatRefCollectors {
            stubs: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_stub_refs(macho, local, limit, truncated)
                })
            },
            chained: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_chained_fixup_refs(macho, local, limit, truncated)
                })
            },
            legacy_rebases: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_legacy_rebase_refs(macho, local, limit, truncated)
                })
            },
            legacy_binds: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_legacy_bind_refs(macho, local, limit, truncated)
                })
            },
        },
    )
}

fn collect_format_refs_with_evidence(
    evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Vec<XrefCollectorReceipt> {
    collect_format_refs_with_leaf_collectors(
        evidence.image(),
        refs,
        max_refs,
        truncated,
        FormatRefCollectors {
            stubs: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_stub_refs_with_evidence(evidence, local, limit, truncated)
                })
            },
            chained: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_chained_fixup_refs_with_evidence(evidence, local, limit, truncated)
                })
            },
            legacy_rebases: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_legacy_rebase_refs_with_evidence(evidence, local, limit, truncated)
                })
            },
            legacy_binds: |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_legacy_bind_refs_with_evidence(evidence, local, limit, truncated)
                })
            },
        },
    )
}

struct FormatRefCollectors<Stubs, Chained, LegacyRebases, LegacyBinds> {
    stubs: Stubs,
    chained: Chained,
    legacy_rebases: LegacyRebases,
    legacy_binds: LegacyBinds,
}

fn collect_format_refs_with_leaf_collectors<Stubs, Chained, LegacyRebases, LegacyBinds>(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
    collectors: FormatRefCollectors<Stubs, Chained, LegacyRebases, LegacyBinds>,
) -> Vec<XrefCollectorReceipt>
where
    Stubs: FnOnce(usize) -> CollectedFormatRefs,
    Chained: FnOnce(usize) -> CollectedFormatRefs,
    LegacyRebases: FnOnce(usize) -> CollectedFormatRefs,
    LegacyBinds: FnOnce(usize) -> CollectedFormatRefs,
{
    use crate::analysis::model::load_command::LoadCommand;

    let FormatRefCollectors {
        stubs: stub_collector,
        chained: chained_collector,
        legacy_rebases: legacy_rebase_collector,
        legacy_binds: legacy_bind_collector,
    } = collectors;

    let has_stubs = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::Dysymtab(_)));
    let has_chained = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::DyldChainedFixups(_)));
    let (has_legacy_rebases, has_legacy_binds) = macho
        .load_commands()
        .iter()
        .find_map(|command| match command.kind() {
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => Some((
                data.rebase_size != 0,
                data.bind_size != 0 || data.weak_bind_size != 0 || data.lazy_bind_size != 0,
            )),
            _ => None,
        })
        .unwrap_or((false, false));
    let has_relocations = macho
        .all_sections()
        .any(|section| section.relocation_count() != 0);
    vec![
        run_format_collector(
            XrefEvidenceSource::Stubs,
            "xrefs.stubs_malformed",
            has_stubs,
            refs,
            max_refs,
            truncated,
            stub_collector,
        ),
        run_format_collector(
            XrefEvidenceSource::ChainedFixups,
            "xrefs.chained_fixups_malformed",
            has_chained,
            refs,
            max_refs,
            truncated,
            chained_collector,
        ),
        run_format_collector(
            XrefEvidenceSource::LegacyRebases,
            "xrefs.legacy_rebases_malformed",
            has_legacy_rebases,
            refs,
            max_refs,
            truncated,
            legacy_rebase_collector,
        ),
        run_format_collector(
            XrefEvidenceSource::LegacyBinds,
            "xrefs.legacy_binds_malformed",
            has_legacy_binds,
            refs,
            max_refs,
            truncated,
            legacy_bind_collector,
        ),
        run_format_collector(
            XrefEvidenceSource::Relocations,
            "xrefs.relocations_malformed",
            has_relocations,
            refs,
            max_refs,
            truncated,
            |limit| {
                collect_local_refs(limit, |local, truncated| {
                    collect_relocation_refs(macho, local, limit, truncated)
                })
            },
        ),
    ]
}

struct CollectedFormatRefs {
    refs: Vec<Xref>,
    truncated: bool,
    result: Result<()>,
}

fn collect_local_refs(
    _limit: usize,
    collector: impl FnOnce(&mut Vec<Xref>, &mut bool) -> Result<()>,
) -> CollectedFormatRefs {
    let mut refs = Vec::new();
    let mut truncated = false;
    let result = collector(&mut refs, &mut truncated);
    CollectedFormatRefs {
        refs,
        truncated,
        result,
    }
}

#[allow(clippy::too_many_arguments)]
fn run_format_collector(
    source: XrefEvidenceSource,
    failure: &str,
    present: bool,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
    collector: impl FnOnce(usize) -> CollectedFormatRefs,
) -> XrefCollectorReceipt {
    if !present {
        return XrefCollectorReceipt {
            source,
            status: XrefCollectorStatus::Absent,
            retained: 0,
            diagnostic: None,
        };
    }
    let remaining = max_refs.saturating_sub(refs.len());
    let CollectedFormatRefs {
        refs: local,
        truncated: local_truncated,
        result,
    } = collector(remaining);
    if result.is_err() {
        return XrefCollectorReceipt {
            source,
            status: XrefCollectorStatus::Failed,
            retained: 0,
            diagnostic: Some(failure.to_owned()),
        };
    }
    let retained = local.len() as u64;
    refs.extend(local);
    *truncated |= local_truncated;
    XrefCollectorReceipt {
        source,
        status: if local_truncated {
            XrefCollectorStatus::Truncated
        } else {
            XrefCollectorStatus::Complete
        },
        retained,
        diagnostic: local_truncated.then(|| "xrefs.retention_budget".to_owned()),
    }
}

fn instruction_receipt(
    retained: usize,
    truncation_reason: Option<&str>,
    partial: bool,
) -> XrefCollectorReceipt {
    XrefCollectorReceipt {
        source: XrefEvidenceSource::Instructions,
        status: if truncation_reason.is_some() {
            XrefCollectorStatus::Truncated
        } else if partial {
            XrefCollectorStatus::Partial
        } else {
            XrefCollectorStatus::Complete
        },
        retained: retained as u64,
        diagnostic: if let Some(reason) = truncation_reason {
            Some(reason.to_owned())
        } else if partial {
            Some("xrefs.source_control_flow_partial".to_owned())
        } else {
            None
        },
    }
}

type XrefRegisterState = BTreeMap<ControlFlowRegister, BTreeSet<u64>>;

struct XrefValueFlowBudget {
    remaining: u64,
    exhausted: bool,
}

impl XrefValueFlowBudget {
    const fn new(limit: u64) -> Self {
        Self {
            remaining: limit,
            exhausted: false,
        }
    }

    fn consume(&mut self, units: u64) -> bool {
        if units <= self.remaining {
            self.remaining -= units;
            true
        } else {
            self.remaining = 0;
            self.exhausted = true;
            false
        }
    }
}

#[derive(Default)]
struct RecoveredDataReferences {
    references: BTreeSet<(u64, u64)>,
    truncated: bool,
}

fn recover_data_references(
    graph: &FunctionControlFlow,
    maximum: usize,
    budget: &mut XrefValueFlowBudget,
) -> RecoveredDataReferences {
    let mut result = RecoveredDataReferences::default();
    if budget.exhausted {
        result.truncated = true;
        return result;
    }
    let mut entries = vec![None::<XrefRegisterState>; graph.blocks.len()];
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
        let index = entry.id as usize;
        if index < entries.len() {
            entries[index] = Some(XrefRegisterState::new());
            work.push_back(index);
            queued[index] = true;
        }
    }
    loop {
        if work.is_empty()
            && let Some(index) = entries.iter().position(Option::is_none)
        {
            entries[index] = Some(XrefRegisterState::new());
            work.push_back(index);
            queued[index] = true;
        }
        let Some(block_index) = work.pop_front() else {
            break;
        };
        if !budget.consume(1) {
            result.truncated = true;
            return result;
        }
        queued[block_index] = false;
        let mut state = entries[block_index].clone().unwrap_or_default();
        apply_data_block(
            graph,
            block_index,
            &mut state,
            maximum,
            budget,
            &mut result,
            false,
        );
        if result.truncated && budget.exhausted {
            return result;
        }
        for &target in &successors[block_index] {
            if !budget.consume(1) {
                result.truncated = true;
                return result;
            }
            let changed = if let Some(existing) = entries[target].as_mut() {
                intersect_xref_state(existing, &state, budget, &mut result.truncated)
            } else {
                let value_count = state.values().map(BTreeSet::len).sum::<usize>() as u64;
                if !budget.consume(value_count) {
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
    for block in &graph.blocks {
        let index = block.id as usize;
        if index >= entries.len() {
            continue;
        }
        let mut state = entries[index].clone().unwrap_or_default();
        apply_data_block(graph, index, &mut state, maximum, budget, &mut result, true);
        if result.truncated && budget.exhausted {
            return result;
        }
    }
    result
}

fn apply_data_block(
    graph: &FunctionControlFlow,
    block_index: usize,
    state: &mut XrefRegisterState,
    maximum: usize,
    budget: &mut XrefValueFlowBudget,
    result: &mut RecoveredDataReferences,
    collect_references: bool,
) {
    let Some(block) = graph.blocks.get(block_index) else {
        return;
    };
    let start = block.first_instruction as usize;
    let end = start.saturating_add(block.instruction_count as usize);
    let Some(instructions) = graph.instructions.get(start..end) else {
        result.truncated = true;
        return;
    };
    for instruction in instructions {
        if !budget.consume(1) {
            result.truncated = true;
            return;
        }
        if collect_references {
            for target in
                xref_instruction_addresses(state, instruction, budget, &mut result.truncated)
            {
                result.references.insert((instruction.address, target));
            }
        }
        apply_xref_instruction(state, instruction, maximum, budget, &mut result.truncated);
        if budget.exhausted {
            result.truncated = true;
            return;
        }
    }
}

fn xref_instruction_addresses(
    state: &XrefRegisterState,
    instruction: &ControlFlowInstruction,
    budget: &mut XrefValueFlowBudget,
    truncated: &mut bool,
) -> BTreeSet<u64> {
    if let Some(relative) = instruction.pc_relative {
        return match relative.kind {
            ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::Memory => {
                BTreeSet::from([relative.address])
            }
            ControlFlowPcRelativeKind::PageAddress => BTreeSet::new(),
        };
    }
    match instruction.value_effect {
        ControlFlowValueEffect::Address | ControlFlowValueEffect::Load => {
            memory_addresses(state, instruction, budget, truncated)
        }
        ControlFlowValueEffect::ZeroExtend8
        | ControlFlowValueEffect::ZeroExtend16
        | ControlFlowValueEffect::ZeroExtend32
        | ControlFlowValueEffect::SignExtend8
        | ControlFlowValueEffect::SignExtend16
        | ControlFlowValueEffect::SignExtend32
            if instruction.operands.get(1).is_some_and(|operand| {
                matches!(
                    operand,
                    ControlFlowOperand::Memory { .. } | ControlFlowOperand::IndexedMemory { .. }
                )
            }) =>
        {
            memory_addresses(state, instruction, budget, truncated)
        }
        ControlFlowValueEffect::AddImmediate => {
            added_addresses(state, instruction, budget, truncated)
        }
        ControlFlowValueEffect::None
        | ControlFlowValueEffect::Set
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
        | ControlFlowValueEffect::UnknownWrite => BTreeSet::new(),
    }
}

fn apply_xref_instruction(
    state: &mut XrefRegisterState,
    instruction: &ControlFlowInstruction,
    maximum: usize,
    budget: &mut XrefValueFlowBudget,
    truncated: &mut bool,
) {
    if let Some(destination) = instruction.written_register {
        let mut values = if let Some(relative) = instruction.pc_relative {
            match relative.kind {
                ControlFlowPcRelativeKind::Address | ControlFlowPcRelativeKind::PageAddress => {
                    BTreeSet::from([relative.address])
                }
                ControlFlowPcRelativeKind::Memory => BTreeSet::new(),
            }
        } else {
            match instruction.value_effect {
                ControlFlowValueEffect::Set => instruction
                    .operands
                    .get(1)
                    .and_then(|operand| match operand {
                        ControlFlowOperand::Register { register } => state.get(register).cloned(),
                        ControlFlowOperand::Immediate { .. }
                        | ControlFlowOperand::Memory { .. }
                        | ControlFlowOperand::IndexedMemory { .. }
                        | ControlFlowOperand::ShiftedRegister { .. } => None,
                    })
                    .unwrap_or_default(),
                ControlFlowValueEffect::Address => {
                    memory_addresses(state, instruction, budget, truncated)
                }
                ControlFlowValueEffect::AddImmediate => {
                    added_addresses(state, instruction, budget, truncated)
                }
                ControlFlowValueEffect::SignPointerIa
                | ControlFlowValueEffect::SignPointerIb
                | ControlFlowValueEffect::SignPointerDa
                | ControlFlowValueEffect::SignPointerDb
                | ControlFlowValueEffect::AuthenticatePointerIa
                | ControlFlowValueEffect::AuthenticatePointerIb
                | ControlFlowValueEffect::AuthenticatePointerDa
                | ControlFlowValueEffect::AuthenticatePointerDb
                | ControlFlowValueEffect::StripPointerAuthentication => instruction
                    .operands
                    .get(1)
                    .and_then(|operand| match operand {
                        ControlFlowOperand::Register { register }
                        | ControlFlowOperand::ShiftedRegister { register, .. } => {
                            state.get(register).cloned()
                        }
                        _ => None,
                    })
                    .unwrap_or_default(),
                ControlFlowValueEffect::ZeroExtend8
                | ControlFlowValueEffect::ZeroExtend16
                | ControlFlowValueEffect::ZeroExtend32
                | ControlFlowValueEffect::SignExtend8
                | ControlFlowValueEffect::SignExtend16
                | ControlFlowValueEffect::SignExtend32 => instruction
                    .operands
                    .get(1)
                    .and_then(|operand| match operand {
                        ControlFlowOperand::Register { register }
                        | ControlFlowOperand::ShiftedRegister { register, .. } => {
                            state.get(register)
                        }
                        _ => None,
                    })
                    .map(|values| {
                        let (bits, signed) = match instruction.value_effect {
                            ControlFlowValueEffect::ZeroExtend8 => (8, false),
                            ControlFlowValueEffect::ZeroExtend16 => (16, false),
                            ControlFlowValueEffect::ZeroExtend32 => (32, false),
                            ControlFlowValueEffect::SignExtend8 => (8, true),
                            ControlFlowValueEffect::SignExtend16 => (16, true),
                            ControlFlowValueEffect::SignExtend32 => (32, true),
                            _ => unreachable!(),
                        };
                        values
                            .iter()
                            .filter_map(|value| {
                                if budget.consume(1) {
                                    Some(extend_xref_integer(*value, bits, signed))
                                } else {
                                    *truncated = true;
                                    None
                                }
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                ControlFlowValueEffect::None
                | ControlFlowValueEffect::Load
                | ControlFlowValueEffect::AddRegister
                | ControlFlowValueEffect::SubtractRegister
                | ControlFlowValueEffect::BitwiseAndImmediate
                | ControlFlowValueEffect::ShiftImmediate
                | ControlFlowValueEffect::ConditionalSelect
                | ControlFlowValueEffect::UnknownWrite => BTreeSet::new(),
            }
        };
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
            class: crate::analysis::control_flow::ControlFlowRegisterClass::GeneralPurpose,
            number: 0,
        });
    }
    if instruction.kind == ControlFlowInstructionKind::Call {
        state.clear();
    }
}

fn extend_xref_integer(value: u64, bits: u8, signed: bool) -> u64 {
    let mask = (1_u64 << bits) - 1;
    let value = value & mask;
    if signed && value & (1_u64 << (bits - 1)) != 0 {
        value | !mask
    } else {
        value
    }
}

fn memory_addresses(
    state: &XrefRegisterState,
    instruction: &ControlFlowInstruction,
    budget: &mut XrefValueFlowBudget,
    truncated: &mut bool,
) -> BTreeSet<u64> {
    let Some((base, displacement)) =
        instruction
            .operands
            .iter()
            .find_map(|operand| match operand {
                ControlFlowOperand::Memory { base, displacement } => Some((base, *displacement)),
                _ => None,
            })
    else {
        return BTreeSet::new();
    };
    offset_addresses(state.get(base), displacement, budget, truncated)
}

fn added_addresses(
    state: &XrefRegisterState,
    instruction: &ControlFlowInstruction,
    budget: &mut XrefValueFlowBudget,
    truncated: &mut bool,
) -> BTreeSet<u64> {
    let (register, value) = match (instruction.operands.get(1), instruction.operands.get(2)) {
        (
            Some(ControlFlowOperand::Register { register }),
            Some(ControlFlowOperand::Immediate { value }),
        ) => (*register, *value),
        (Some(ControlFlowOperand::Immediate { value }), _) => {
            let Some(register) = instruction.written_register else {
                return BTreeSet::new();
            };
            (register, *value)
        }
        _ => return BTreeSet::new(),
    };
    offset_addresses(state.get(&register), value, budget, truncated)
}

fn offset_addresses(
    values: Option<&BTreeSet<u64>>,
    displacement: i64,
    budget: &mut XrefValueFlowBudget,
    truncated: &mut bool,
) -> BTreeSet<u64> {
    let mut result = BTreeSet::new();
    for value in values.into_iter().flatten() {
        if !budget.consume(1) {
            *truncated = true;
            break;
        }
        result.insert(value.wrapping_add_signed(displacement));
    }
    result
}

fn intersect_xref_state(
    destination: &mut XrefRegisterState,
    source: &XrefRegisterState,
    budget: &mut XrefValueFlowBudget,
    truncated: &mut bool,
) -> bool {
    let mut changed = false;
    destination.retain(|register, values| {
        let Some(source_values) = source.get(register) else {
            changed = true;
            return false;
        };
        values.retain(|value| {
            if !budget.consume(1) {
                *truncated = true;
                return false;
            }
            let retained = source_values.contains(value);
            changed |= !retained;
            retained
        });
        let retained = !values.is_empty();
        changed |= !retained;
        retained
    });
    changed
}

fn collect_stub_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    let symtab = macho.ext::<SymbolTable<'_>>()?;

    let dysymtab = match macho.find_load_command(|lc| {
        matches!(
            lc,
            crate::analysis::model::load_command::LoadCommand::Dysymtab(_)
        )
    }) {
        Some(lc) => match lc.kind().as_dysymtab() {
            Some(d) => d.clone(),
            None => return Ok(()),
        },
        None => return Ok(()),
    };

    if dysymtab.nindirectsyms == 0 {
        return Ok(());
    }

    let indirect_off = dysymtab.indirectsymoff as usize;
    let n_indirect = dysymtab.nindirectsyms as usize;
    let endian = macho.endian();

    // Read the indirect symbol table
    let indirect_data = macho.read_bytes_at(ThinFileOffset(indirect_off as u64), n_indirect * 4)?;

    for sect in macho.all_sections() {
        let is_stub_section = matches!(
            sect.section_type(),
            SectionType::SymbolStubs
                | SectionType::NonLazySymbolPointers
                | SectionType::LazySymbolPointers
        );
        if !is_stub_section {
            continue;
        }

        let indirect_start = sect.reserved1() as usize;
        let entry_size = match sect.section_type() {
            SectionType::SymbolStubs => {
                if sect.reserved2() == 0 {
                    continue;
                }
                sect.reserved2() as u64
            }
            _ => {
                // Pointer-sized entries
                if macho.is_64bit() { 8u64 } else { 4u64 }
            }
        };

        let Some(n_entries) = sect
            .size()
            .checked_div(entry_size)
            .and_then(|count| usize::try_from(count).ok())
        else {
            continue;
        };

        for i in 0..n_entries {
            let isym_idx = indirect_start + i;
            if isym_idx >= n_indirect {
                break;
            }

            let table_offset = isym_idx * 4;
            if table_offset + 4 > indirect_data.len() {
                break;
            }

            let raw_index = endian.interpret_u32(u32::from_ne_bytes([
                indirect_data[table_offset],
                indirect_data[table_offset + 1],
                indirect_data[table_offset + 2],
                indirect_data[table_offset + 3],
            ]));

            // Skip INDIRECT_SYMBOL_LOCAL (0x80000000), INDIRECT_SYMBOL_ABS
            // (0x40000000), and any combination of these flag bits.
            if raw_index & 0xC0000000 != 0 {
                continue;
            }

            let source_va = Va(sect.addr().0 + i as u64 * entry_size);

            if let Some(sym) = symtab.get(raw_index as usize) {
                let target = if sym.is_undefined() {
                    XrefTarget::Import {
                        name: sym.name.to_string(),
                        ordinal: sym.library_ordinal() as i32,
                    }
                } else {
                    XrefTarget::Internal { va: Va(sym.value) }
                };

                if !push_ref(
                    refs,
                    max_refs,
                    truncated,
                    Xref {
                        source: source_va,
                        target,
                        kind: XrefKind::Stub,
                    },
                ) {
                    return Ok(());
                }
            }
        }
    }

    Ok(())
}

fn collect_stub_refs_with_evidence(
    evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    use crate::metadata::symbols::{IndirectBindingsOutcome, IndirectSymbolTarget};

    let outcome = evidence
        .indirect_bindings(max_refs as u64)
        .map_err(|error| {
            crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Parse,
                format!("decode indirect-symbol evidence: {error}"),
            )
        })?;
    let bindings = match outcome {
        IndirectBindingsOutcome::Absent => return Ok(()),
        IndirectBindingsOutcome::Complete(bindings) => bindings,
        IndirectBindingsOutcome::Truncated { bindings, .. } => {
            *truncated = true;
            bindings
        }
    };
    for binding in bindings {
        let IndirectSymbolTarget::Symbol(symbol) = binding.target else {
            continue;
        };
        let target = if symbol.is_undefined() {
            let ordinal = i32::from(symbol.library_ordinal());
            XrefTarget::Import {
                name: symbol.name,
                ordinal,
            }
        } else {
            XrefTarget::Internal {
                va: Va(symbol.value),
            }
        };
        if !push_ref(
            refs,
            max_refs,
            truncated,
            Xref {
                source: binding.address,
                target,
                kind: XrefKind::Stub,
            },
        ) {
            break;
        }
    }
    Ok(())
}

fn collect_chained_fixup_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    let fixups = parse_chained_fixups(macho)?;

    let segments = macho.segments();

    for fixup in &fixups.fixups {
        let seg = match segments.get(fixup.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let source_va = Va(seg.vm_addr().0 + fixup.segment_offset);

        match &fixup.kind {
            FixupKind::Bind { import_index, .. } | FixupKind::AuthBind { import_index, .. } => {
                let target = match fixups.imports.get(*import_index as usize) {
                    Some(imp) => XrefTarget::Import {
                        name: imp.name.to_string(),
                        ordinal: imp.lib_ordinal,
                    },
                    None => continue,
                };
                if !push_ref(
                    refs,
                    max_refs,
                    truncated,
                    Xref {
                        source: source_va,
                        target,
                        kind: XrefKind::ChainedBind,
                    },
                ) {
                    return Ok(());
                }
            }
            FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                let target = macho.image_base().0.checked_add(*target).ok_or_else(|| {
                    crate::analysis::error::AnalysisError::invalid(
                        "chained rebase target overflows the selected image address space",
                    )
                })?;
                if !push_ref(
                    refs,
                    max_refs,
                    truncated,
                    Xref {
                        source: source_va,
                        target: XrefTarget::Internal { va: Va(target) },
                        kind: XrefKind::ChainedRebase,
                    },
                ) {
                    return Ok(());
                }
            }
            _ => continue,
        }
    }
    Ok(())
}

fn collect_chained_fixup_refs_with_evidence(
    evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    use crate::metadata::dyld::resolve::{
        InventoryPointerTarget, PointerEncoding, PointerInventory,
    };

    let outcome = evidence
        .pointer_inventory(u64::try_from(max_refs.max(1)).unwrap_or(u64::MAX))
        .map_err(|error| {
            crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Parse,
                format!("decode chained-pointer evidence: {error}"),
            )
        })?;
    let pointers = match outcome {
        PointerInventory::Absent => return Ok(()),
        PointerInventory::Complete(pointers) => pointers,
        PointerInventory::Truncated { pointers, .. } => {
            *truncated = true;
            pointers
        }
    };
    for pointer in pointers {
        let (kind, target) = match (pointer.encoding, pointer.target) {
            (
                PointerEncoding::ChainedBind,
                InventoryPointerTarget::Import {
                    name,
                    library_ordinal: Some(ordinal),
                    ..
                },
            ) => (XrefKind::ChainedBind, XrefTarget::Import { name, ordinal }),
            (PointerEncoding::ChainedRebase, InventoryPointerTarget::Address(va)) => {
                (XrefKind::ChainedRebase, XrefTarget::Internal { va })
            }
            (PointerEncoding::ChainedBind | PointerEncoding::ChainedRebase, _) => {
                return Err(crate::analysis::AnalysisError::new(
                    crate::analysis::AnalysisDomain::Xrefs,
                    crate::analysis::AnalysisErrorKind::Parse,
                    "chained-pointer evidence has an incompatible semantic target",
                ));
            }
            (
                PointerEncoding::Direct
                | PointerEncoding::LegacyRebase
                | PointerEncoding::LegacyBind,
                _,
            ) => continue,
        };
        if !push_ref(
            refs,
            max_refs,
            truncated,
            Xref {
                source: pointer.source_va,
                target,
                kind,
            },
        ) {
            break;
        }
    }
    Ok(())
}

fn collect_legacy_rebase_refs_with_evidence(
    evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    use crate::metadata::dyld::resolve::{
        InventoryPointerTarget, PointerEncoding, PointerInventory,
    };

    let outcome = evidence
        .legacy_rebases(u64::try_from(max_refs.max(1)).unwrap_or(u64::MAX))
        .map_err(|error| {
            crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Parse,
                format!("decode legacy-rebase evidence: {error}"),
            )
        })?;
    let pointers = match outcome {
        PointerInventory::Absent => return Ok(()),
        PointerInventory::Complete(pointers) => pointers,
        PointerInventory::Truncated { pointers, .. } => {
            *truncated = true;
            pointers
        }
    };
    for pointer in pointers {
        let target = match (pointer.encoding, pointer.target) {
            (PointerEncoding::LegacyRebase, InventoryPointerTarget::Address(va)) => {
                XrefTarget::Internal { va }
            }
            (PointerEncoding::LegacyRebase, InventoryPointerTarget::Null) => continue,
            _ => {
                return Err(crate::analysis::AnalysisError::new(
                    crate::analysis::AnalysisDomain::Xrefs,
                    crate::analysis::AnalysisErrorKind::Parse,
                    "legacy-rebase evidence has an incompatible encoding or target",
                ));
            }
        };
        if !push_ref(
            refs,
            max_refs,
            truncated,
            Xref {
                source: pointer.source_va,
                target,
                kind: XrefKind::LegacyRebase,
            },
        ) {
            break;
        }
    }
    Ok(())
}

fn collect_legacy_rebase_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    let evidence = crate::evidence::SelectedImageEvidence::new(macho).map_err(|error| {
        crate::analysis::AnalysisError::new(
            crate::analysis::AnalysisDomain::Xrefs,
            crate::analysis::AnalysisErrorKind::Parse,
            format!("decode legacy-rebase evidence: {error}"),
        )
    })?;
    collect_legacy_rebase_refs_with_evidence(&evidence, refs, max_refs, truncated)
}

fn collect_legacy_bind_refs_with_evidence(
    evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    use crate::metadata::dyld::resolve::{
        InventoryPointerTarget, PointerEncoding, PointerInventory,
    };

    let outcome = evidence
        .legacy_bindings(u64::try_from(max_refs.max(1)).unwrap_or(u64::MAX))
        .map_err(|error| {
            crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Parse,
                format!("decode legacy-bind evidence: {error}"),
            )
        })?;
    let pointers = match outcome {
        PointerInventory::Absent => return Ok(()),
        PointerInventory::Complete(pointers) => pointers,
        PointerInventory::Truncated { pointers, .. } => {
            *truncated = true;
            pointers
        }
    };
    for pointer in pointers {
        let name = match (pointer.encoding, pointer.target) {
            (PointerEncoding::LegacyBind, InventoryPointerTarget::Import { name, .. }) => name,
            _ => {
                return Err(crate::analysis::AnalysisError::new(
                    crate::analysis::AnalysisDomain::Xrefs,
                    crate::analysis::AnalysisErrorKind::Parse,
                    "legacy-bind evidence has an incompatible encoding or target",
                ));
            }
        };
        if pointer.legacy_bind_occurrences.is_empty() {
            return Err(crate::analysis::AnalysisError::new(
                crate::analysis::AnalysisDomain::Xrefs,
                crate::analysis::AnalysisErrorKind::Parse,
                "legacy-bind evidence has no retained source occurrence",
            ));
        }
        for occurrence in pointer.legacy_bind_occurrences {
            if !push_ref(
                refs,
                max_refs,
                truncated,
                Xref {
                    source: pointer.source_va,
                    target: XrefTarget::Import {
                        name: name.clone(),
                        ordinal: occurrence.library_ordinal,
                    },
                    kind: XrefKind::LegacyBind,
                },
            ) {
                return Ok(());
            }
        }
    }
    Ok(())
}

fn collect_legacy_bind_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    let (regular, weak, lazy) = parse_bind_entries(macho)?;

    let segments = macho.segments();

    for bind in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
        let seg = match segments.get(bind.segment_index) {
            Some(s) => s,
            None => continue,
        };
        let source_va = Va(seg.vm_addr().0 + bind.segment_offset);

        if !push_ref(
            refs,
            max_refs,
            truncated,
            Xref {
                source: source_va,
                target: XrefTarget::Import {
                    name: bind.symbol_name.to_string(),
                    ordinal: bind.lib_ordinal.clamp(i32::MIN as i64, i32::MAX as i64) as i32,
                },
                kind: XrefKind::LegacyBind,
            },
        ) {
            return Ok(());
        }
    }
    Ok(())
}

fn collect_relocation_refs(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    max_refs: usize,
    truncated: &mut bool,
) -> Result<()> {
    let symtab = macho.ext::<SymbolTable<'_>>()?;

    for sect in macho.all_sections() {
        if sect.relocation_count() == 0 {
            continue;
        }
        let relocs = relocations_for_section(macho, sect)?;

        for reloc in &relocs {
            match reloc {
                Relocation::Standard(sr) => {
                    let source_va = Va(sect.addr().0 + sr.address as u64);
                    if sr.is_extern {
                        if let Some(sym) = symtab.get(sr.symbol_num as usize) {
                            let target = if sym.is_undefined() {
                                XrefTarget::Import {
                                    name: sym.name.to_string(),
                                    ordinal: sym.library_ordinal() as i32,
                                }
                            } else {
                                XrefTarget::Internal { va: Va(sym.value) }
                            };
                            if !push_ref(
                                refs,
                                max_refs,
                                truncated,
                                Xref {
                                    source: source_va,
                                    target,
                                    kind: XrefKind::Relocation,
                                },
                            ) {
                                return Ok(());
                            }
                        }
                    } else {
                        // Non-extern: symbol_num is a section ordinal, target
                        // is an internal VA. We can't easily resolve the exact
                        // target without addend decoding, so skip these.
                    }
                }
                Relocation::Scattered(_) => {
                    // Scattered relocations are 32-bit-only and are not
                    // converted into xrefs.
                }
            }
        }
    }
    Ok(())
}

fn collect_direct_branches(
    macho: &MachoFile<'_>,
    refs: &mut Vec<Xref>,
    gaps: &mut Vec<crate::insn::DecodeGap>,
    max_refs: usize,
    max_decoded_bytes: usize,
    refs_truncated: &mut bool,
) -> bool {
    let cpu_type = macho.header().cpu_type().0;

    let arch = if cpu_type == CPU_TYPE_ARM64 {
        crate::insn::Arch::Arm64
    } else if cpu_type == CPU_TYPE_X86_64 {
        crate::insn::Arch::X86_64
    } else {
        return false;
    };

    let min_insn_size: u64 = if arch.is_arm64() { 4 } else { 5 };

    let mut remaining = max_decoded_bytes;
    let mut decoded_bytes_truncated = false;
    for sect in macho.all_sections() {
        if !sect
            .attributes()
            .contains(SectionAttributes::PURE_INSTRUCTIONS)
        {
            continue;
        }
        if sect.size() < min_insn_size {
            continue;
        }

        if remaining == 0 {
            decoded_bytes_truncated = true;
            break;
        }
        let requested = usize::try_from(sect.size()).unwrap_or(usize::MAX);
        let mut decode_len = requested.min(remaining);
        if arch.is_arm64() {
            decode_len -= decode_len % 4;
        }
        if decode_len < requested {
            decoded_bytes_truncated = true;
        }
        if decode_len < min_insn_size as usize {
            continue;
        }
        let sect_bytes = match macho.read_bytes_at(sect.offset(), decode_len) {
            Ok(b) => b,
            Err(_) => continue,
        };
        remaining -= decode_len;

        let report = crate::insn::decode_lossy(sect_bytes, sect.addr().0, arch);
        gaps.extend(report.gaps);
        for insn in report.instructions {
            let insn_va = sect.addr().0 + insn.offset as u64;

            // Only collect direct branches and calls (not register-indirect).
            match &insn.kind {
                crate::insn::InsnKind::Branch(_) | crate::insn::InsnKind::Call(_) => {}
                _ => continue,
            }

            if let Some(target) = crate::insn::resolve_branch_target(&insn, insn_va) {
                let _ = push_ref(
                    refs,
                    max_refs,
                    refs_truncated,
                    Xref {
                        source: Va(insn_va),
                        target: XrefTarget::Internal { va: Va(target) },
                        kind: XrefKind::DirectBranch,
                    },
                );
            }
        }
    }
    decoded_bytes_truncated
}

fn collect_direct_branches_to_targets(
    macho: &MachoFile<'_>,
    targets: &BTreeSet<u64>,
    refs: &mut Vec<Xref>,
    gaps: &mut Vec<crate::insn::DecodeGap>,
    max_refs: usize,
    max_decoded_bytes: usize,
    refs_truncated: &mut bool,
) -> bool {
    if targets.is_empty() {
        return false;
    }
    let cpu_type = macho.header().cpu_type().0;
    let arch = if cpu_type == CPU_TYPE_ARM64 {
        crate::insn::Arch::Arm64
    } else if cpu_type == CPU_TYPE_X86_64 {
        crate::insn::Arch::X86_64
    } else {
        return false;
    };
    let mut remaining = max_decoded_bytes;
    let mut decoded_bytes_truncated = false;
    for section in macho.all_sections().filter(|section| {
        section
            .attributes()
            .contains(SectionAttributes::PURE_INSTRUCTIONS)
    }) {
        if remaining == 0 {
            decoded_bytes_truncated = true;
            break;
        }
        let requested = usize::try_from(section.size()).unwrap_or(usize::MAX);
        let mut decode_len = requested.min(remaining);
        if arch.is_arm64() {
            decode_len -= decode_len % 4;
        }
        if decode_len < requested {
            decoded_bytes_truncated = true;
        }
        if decode_len == 0 {
            continue;
        }
        let section_bytes = match macho.read_bytes_at(section.offset(), decode_len) {
            Ok(bytes) => bytes,
            Err(_) => continue,
        };
        remaining -= decode_len;
        if arch.is_arm64() {
            for (index, bytes) in section_bytes.chunks_exact(4).enumerate() {
                let word = macho
                    .endian()
                    .interpret_u32(u32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]));
                if word & 0x7c00_0000 != 0x1400_0000 {
                    continue;
                }
                let source = section.addr().0 + u64::try_from(index).unwrap_or(u64::MAX) * 4;
                let Some(target) = arm64_direct_branch_target(word, source)
                    .filter(|target| targets.contains(target))
                else {
                    continue;
                };
                if !push_ref(
                    refs,
                    max_refs,
                    refs_truncated,
                    Xref {
                        source: Va(source),
                        target: XrefTarget::Internal { va: Va(target) },
                        kind: XrefKind::DirectBranch,
                    },
                ) {
                    return decoded_bytes_truncated;
                }
            }
        } else {
            let report = crate::insn::decode_lossy(section_bytes, section.addr().0, arch);
            gaps.extend(report.gaps);
            for instruction in report.instructions {
                let source = section.addr().0 + instruction.offset as u64;
                let Some(target) = crate::insn::resolve_branch_target(&instruction, source)
                    .filter(|target| targets.contains(target))
                else {
                    continue;
                };
                if !push_ref(
                    refs,
                    max_refs,
                    refs_truncated,
                    Xref {
                        source: Va(source),
                        target: XrefTarget::Internal { va: Va(target) },
                        kind: XrefKind::DirectBranch,
                    },
                ) {
                    return decoded_bytes_truncated;
                }
            }
        }
    }
    decoded_bytes_truncated
}

fn arm64_direct_branch_target(word: u32, source: u64) -> Option<u64> {
    if word & 0x7c00_0000 != 0x1400_0000 {
        return None;
    }
    let immediate = i64::from(((word & 0x03ff_ffff) << 6) as i32 >> 6) * 4;
    if immediate >= 0 {
        source.checked_add(immediate as u64)
    } else {
        source.checked_sub(immediate.unsigned_abs())
    }
}

fn push_ref(refs: &mut Vec<Xref>, max_refs: usize, truncated: &mut bool, reference: Xref) -> bool {
    if refs.len() >= max_refs {
        *truncated = true;
        return false;
    }
    refs.push(reference);
    true
}

#[cfg(test)]
mod targeted_tests {
    use std::collections::BTreeSet;

    use super::{
        Xref, XrefCollectorStatus, XrefEvidenceSource, XrefIndex, XrefIndexStatus, XrefKind,
        XrefRecoveryLimits, XrefTarget, arm64_direct_branch_target,
    };
    use crate::analysis::control_flow::{ControlFlowIndex, ControlFlowLimits, InstructionTarget};
    use crate::analysis::functions::{FunctionIndex, FunctionRecoveryLimits};
    use crate::analysis::model::addr::types::Va;
    use crate::analysis::pointer_index::PointerIndex;
    use crate::analysis::program::{ProgramRecoveryLimits, RecoveredProgram};

    #[test]
    fn arm64_target_filter_decodes_only_direct_branch_words() {
        assert_eq!(
            arm64_direct_branch_target(0x9400_0040, 0x4000),
            Some(0x4100)
        );
        assert_eq!(
            arm64_direct_branch_target(0x17ff_fffc, 0x5000),
            Some(0x4ff0)
        );
        assert_eq!(arm64_direct_branch_target(0xd503_201f, 0x4000), None);
    }

    #[test]
    fn legacy_direct_xrefs_are_projected_from_recovered_program_instructions() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let macho = container.first_macho().unwrap();
        let program =
            RecoveredProgram::recover_all(macho, ProgramRecoveryLimits::default()).unwrap();
        let index = XrefIndex::from_recovered_program_limited(macho, &program, usize::MAX).unwrap();
        let expected = program
            .control_flow()
            .unwrap()
            .functions()
            .iter()
            .flat_map(|graph| &graph.instructions)
            .filter_map(|instruction| match &instruction.target {
                Some(InstructionTarget::Direct { address }) => {
                    Some((instruction.address, *address))
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let actual = index
            .all_refs()
            .iter()
            .filter_map(|reference| match (&reference.kind, &reference.target) {
                (XrefKind::DirectBranch, XrefTarget::Internal { va }) => {
                    Some((reference.source.0, va.0))
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert!(!expected.is_empty());
        assert_eq!(actual, expected);
    }

    #[test]
    fn streaming_projection_matches_retained_cfg_across_architectures() {
        for bytes in [
            macho_test_support::disassembly_x86_64(),
            macho_test_support::disassembly_arm64(),
        ] {
            let container = crate::core::parse(&bytes).unwrap();
            let macho = container.first_macho().unwrap();
            for control_flow in [
                ControlFlowLimits::default(),
                ControlFlowLimits {
                    max_decoded_bytes: 8,
                    ..ControlFlowLimits::default()
                },
                ControlFlowLimits {
                    max_instructions_per_function: 1,
                    ..ControlFlowLimits::default()
                },
                ControlFlowLimits {
                    max_blocks_per_function: 1,
                    max_edges_per_function: 1,
                    ..ControlFlowLimits::default()
                },
            ] {
                let limits = ProgramRecoveryLimits {
                    control_flow,
                    ..ProgramRecoveryLimits::default()
                };
                let functions = FunctionIndex::recover(macho, limits.functions).unwrap();
                let pointers = PointerIndex::recover(macho, limits.pointers).unwrap();
                let retained = RecoveredProgram::recover_from_functions(
                    macho,
                    functions.clone(),
                    crate::analysis::program::ProgramRecoveryRequest::new(
                        [crate::analysis::program::ProgramRecoveryStage::Xrefs],
                        limits,
                    ),
                )
                .unwrap();
                let streaming = XrefIndex::recover_streaming_with_pointers(
                    macho,
                    &functions,
                    &pointers,
                    limits.control_flow,
                    limits.xrefs,
                )
                .unwrap();
                assert_eq!(Some(&streaming), retained.xrefs());
            }
        }
    }

    #[test]
    #[ignore = "requires MACHO_XREF_PARITY_FIXTURE"]
    fn streaming_projection_matches_retained_cfg_on_external_fixture() {
        let path = std::env::var("MACHO_XREF_PARITY_FIXTURE")
            .expect("MACHO_XREF_PARITY_FIXTURE names a representative Mach-O binary");
        let bytes = std::fs::read(path).expect("fixture can be read");
        let container = crate::core::parse(&bytes).expect("fixture parses");
        let macho = container
            .first_macho()
            .expect("fixture contains a Mach-O image");
        let limits = ProgramRecoveryLimits {
            control_flow: ControlFlowLimits {
                max_decoded_bytes: 4 * 1024 * 1024,
                ..ControlFlowLimits::default()
            },
            xrefs: XrefRecoveryLimits {
                max_refs: 1_000_000,
                max_decoded_bytes: 4 * 1024 * 1024,
                ..XrefRecoveryLimits::default()
            },
            ..ProgramRecoveryLimits::default()
        };
        let functions = FunctionIndex::recover(macho, limits.functions).unwrap();
        let pointers = PointerIndex::recover(macho, limits.pointers).unwrap();
        let retained = RecoveredProgram::recover_from_functions(
            macho,
            functions.clone(),
            crate::analysis::program::ProgramRecoveryRequest::new(
                [crate::analysis::program::ProgramRecoveryStage::Xrefs],
                limits,
            ),
        )
        .unwrap();
        let streaming = XrefIndex::recover_streaming_with_pointers(
            macho,
            &functions,
            &pointers,
            limits.control_flow,
            limits.xrefs,
        )
        .unwrap();
        assert_eq!(Some(&streaming), retained.xrefs());
    }

    #[test]
    fn saturated_format_budget_skips_instruction_projection_consistently() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let macho = container.first_macho().unwrap();
        let functions = FunctionIndex::recover(macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(macho, &functions, ControlFlowLimits::default()).unwrap();
        assert!(control_flow.functions().iter().any(|graph| {
            graph.instructions.iter().any(|instruction| {
                matches!(instruction.target, Some(InstructionTarget::Direct { .. }))
            })
        }));

        let mut format = XrefIndex::recover_format(macho, usize::MAX).unwrap();
        format.refs = vec![Xref {
            source: Va(0x1000),
            target: XrefTarget::Internal { va: Va(0x2000) },
            kind: XrefKind::Stub,
        }];
        format.refs_truncated = false;
        format.completeness.collectors.clear();
        format.completeness.retained_refs = 1;

        let saturated = XrefIndex::recover_seeded(
            macho,
            &control_flow,
            XrefRecoveryLimits {
                max_refs: 1,
                ..XrefRecoveryLimits::default()
            },
            Some(&format),
        )
        .unwrap();
        assert_eq!(saturated.all_refs(), format.all_refs());
        assert_eq!(saturated.status(), XrefIndexStatus::Truncated);
        assert!(saturated.decode_gaps().is_empty());
        assert!(saturated.completeness().collectors.iter().any(|receipt| {
            receipt.source == XrefEvidenceSource::Instructions
                && receipt.status == XrefCollectorStatus::Truncated
                && receipt.retained == 0
                && receipt.diagnostic.as_deref() == Some("xrefs.retention_budget")
        }));
    }

    #[test]
    fn format_budget_edges_are_admitted_deterministically() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let macho = container.first_macho().unwrap();
        let functions = FunctionIndex::recover(macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(macho, &functions, ControlFlowLimits::default()).unwrap();
        let mut format = XrefIndex::recover_format(macho, usize::MAX).unwrap();
        format.refs = vec![
            Xref {
                source: Va(0x1000),
                target: XrefTarget::Internal { va: Va(0x2000) },
                kind: XrefKind::Stub,
            },
            Xref {
                source: Va(0x1008),
                target: XrefTarget::Internal { va: Va(0x2008) },
                kind: XrefKind::Stub,
            },
        ];
        format.refs_truncated = false;
        format.completeness.retained_refs = format.refs.len() as u64;
        let stub_receipt = format
            .completeness
            .collectors
            .iter_mut()
            .find(|receipt| receipt.source == XrefEvidenceSource::Stubs)
            .unwrap();
        stub_receipt.status = XrefCollectorStatus::Complete;
        stub_receipt.retained = format.refs.len() as u64;
        stub_receipt.diagnostic = None;

        for max_refs in [1, 2, 3] {
            let limits = XrefRecoveryLimits {
                max_refs,
                ..XrefRecoveryLimits::default()
            };
            let first =
                XrefIndex::recover_seeded(macho, &control_flow, limits, Some(&format)).unwrap();
            let repeated =
                XrefIndex::recover_seeded(macho, &control_flow, limits, Some(&format)).unwrap();
            assert_eq!(first, repeated);
            assert_eq!(first.all_refs().len(), max_refs);
            assert!(first.durable_invariants_hold());
            assert_eq!(
                first
                    .all_refs()
                    .iter()
                    .filter(|reference| reference.kind == XrefKind::Stub)
                    .count(),
                max_refs.min(2)
            );
            if max_refs == 1 {
                let receipt = first
                    .completeness()
                    .collectors
                    .iter()
                    .find(|receipt| receipt.source == XrefEvidenceSource::Stubs)
                    .unwrap();
                assert_eq!(receipt.status, XrefCollectorStatus::Truncated);
                assert_eq!(receipt.retained, 1);
                assert_eq!(
                    receipt.diagnostic.as_deref(),
                    Some("xrefs.retention_budget")
                );
            }
        }
    }

    #[test]
    fn cfg_projection_enforces_its_own_decode_budget() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = crate::core::parse(&bytes).unwrap();
        let macho = container.first_macho().unwrap();
        let functions = FunctionIndex::recover(macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(macho, &functions, ControlFlowLimits::default()).unwrap();
        let index = XrefIndex::recover(
            macho,
            &control_flow,
            XrefRecoveryLimits {
                max_decoded_bytes: 1,
                ..XrefRecoveryLimits::default()
            },
        )
        .unwrap();
        assert_eq!(index.status(), XrefIndexStatus::Truncated);
        assert!(index.decoded_bytes_truncated());
        assert!(
            index
                .completeness()
                .reasons
                .contains(&"xrefs.decode_budget".to_owned())
        );
        assert!(
            !index
                .all_refs()
                .iter()
                .any(|reference| matches!(reference.kind, XrefKind::DirectBranch | XrefKind::Data))
        );
    }

    #[test]
    fn arm64_and_arm64e_compose_adrp_add_data_references() {
        for mut bytes in [
            macho_test_support::disassembly_arm64(),
            macho_test_support::disassembly_arm64e(),
        ] {
            bytes[0x158..0x160].copy_from_slice(&0x1_0000_0120_u64.to_le_bytes());
            bytes[0x100..0x104].copy_from_slice(&0x9000_0010_u32.to_le_bytes());
            bytes[0x104..0x108].copy_from_slice(&0x9104_c210_u32.to_le_bytes());
            bytes[0x108..0x10c].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
            let container = crate::core::parse(&bytes).unwrap();
            let macho = container.first_macho().unwrap();
            let functions =
                FunctionIndex::recover(macho, FunctionRecoveryLimits::default()).unwrap();
            let control_flow =
                ControlFlowIndex::recover(macho, &functions, ControlFlowLimits::default()).unwrap();
            let index =
                XrefIndex::recover(macho, &control_flow, XrefRecoveryLimits::default()).unwrap();
            assert!(index.all_refs().iter().any(|reference| {
                reference.source.0 == 0x1_0000_0104
                    && reference.kind == XrefKind::Data
                    && reference.target.internal_address().map(|va| va.0) == Some(0x1_0000_0130)
            }));
        }
    }
}
