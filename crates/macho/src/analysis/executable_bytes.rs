//! Conserved executable-section byte classification.
//!
//! This index projects existing function and CFG evidence into one ordered,
//! non-overlapping ledger per executable section. Section-declared stubs and
//! literal pools take precedence over decoding. Conflicting instruction
//! boundaries and uncovered bytes remain unresolved instead of being silently
//! interpreted as instructions.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::format::constants::{CPU_TYPE_ARM64, CPU_TYPE_X86_64, SectionAttributes};
use crate::core::model::addr::ThinFileOffset;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::section::{Section, SectionType};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::control_flow::{
    ControlFlowDataRangeReason, ControlFlowIndex, ControlFlowInstruction,
    ControlFlowPcRelativeKind, ControlFlowReachability, InstructionTarget,
};
use crate::analysis::functions::{
    FunctionEvidenceConfidence, FunctionImageIdentity, FunctionIndex,
};
use crate::analysis::image_layout::ImageLayoutIndex;

/// Bounds for one executable-byte classification operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableByteLimits {
    /// Maximum executable sections examined in image order.
    pub max_sections: usize,
    /// Maximum executable bytes examined across admitted sections.
    pub max_bytes: usize,
    /// Maximum coalesced classification spans retained.
    pub max_spans: usize,
}

impl Default for ExecutableByteLimits {
    fn default() -> Self {
        Self {
            max_sections: 1_000_000,
            max_bytes: 256 * 1024 * 1024,
            max_spans: 16_000_000,
        }
    }
}

impl ExecutableByteLimits {
    /// Reject zero-valued caller limits.
    pub fn validate(self) -> Result<Self, ExecutableByteRecoveryError> {
        if self.max_sections == 0 || self.max_bytes == 0 || self.max_spans == 0 {
            return Err(ExecutableByteRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing executable-byte classification from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExecutableByteRecoveryError {
    /// At least one explicit limit is zero.
    #[error("executable-byte recovery limits must be non-zero")]
    InvalidLimits,
    /// The source indexes and selected image do not describe identical bytes.
    #[error("function, control-flow, and Mach-O image identities differ")]
    ImageMismatch,
}

/// Retained classification of one executable-section byte range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableByteKind {
    /// Bytes belonging to one decoded instruction boundary.
    Instruction,
    /// Inline or embedded data established by supported structural evidence.
    EmbeddedData,
    /// Intentional instruction-stream padding.
    Padding,
    /// Alignment fill between established objects.
    Alignment,
    /// Linker-declared symbol-stub bytes.
    Stub,
    /// Linker-declared literal-pool bytes.
    LiteralPool,
    /// Evidence is insufficient or contradictory.
    Unresolved,
}

/// Stable evidence explaining a byte classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableByteEvidence {
    /// One or more CFGs retain the same decoded instruction boundary.
    DecodedInstruction,
    /// Mach-O section type is `S_SYMBOL_STUBS`.
    SectionDeclaredStub,
    /// Conventional `__TEXT,__stub_helper` section containing dyld lazy-bind
    /// helper stubs.
    SectionNamedStubHelper,
    /// Mach-O section type declares fixed-width or pointer literals.
    SectionDeclaredLiteral,
    /// The CFG retained an explicit decoder gap.
    DecodeGap,
    /// Different retained instruction boundaries cover the same byte.
    ConflictingInstructionBoundaries,
    /// A recovered target lands inside a decoded x86 instruction boundary.
    TargetedAlternativeBoundary,
    /// An architecture-defined NOP occurs only in CFG-proven unreachable blocks.
    UnreachableNopPadding,
    /// One complete NOP aligns the next exact function or recovered table.
    FunctionAlignmentNop,
    /// Zero fill between closed instruction coverage and the next exact
    /// function entry.
    ZeroFillFunctionAlignment,
    /// An ARM64 literal-load instruction establishes the referenced byte width.
    Arm64LiteralLoad,
    /// A retained control-flow target contradicts an inline-literal range.
    InlineLiteralTargetConflict,
    /// A bounded CFG jump-table record establishes candidate data bytes.
    RecoveredJumpTable,
    /// A retained control-flow target contradicts a jump-table byte range.
    JumpTableTargetConflict,
    /// No retained function/CFG evidence classifies the byte.
    NoRecoveredCoverage,
    /// Explicit validated caller byte-role decision.
    CallerDecision,
    /// The executable section has no valid file-backed range.
    UnmappedSection,
}

/// One non-empty, half-open classification span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableByteSpan {
    /// Global Mach-O section ordinal.
    pub section_ordinal: u64,
    /// Containing segment name.
    pub segment: String,
    /// Section name.
    pub section: String,
    /// Virtual start address.
    pub start: u64,
    /// Exclusive virtual end address.
    pub end_exclusive: u64,
    /// Unique retained byte classification.
    pub kind: ExecutableByteKind,
    /// Strength of the evidence supporting the classification.
    pub confidence: FunctionEvidenceConfidence,
    /// Stable evidence codes; multiple codes are sorted and deduplicated.
    pub evidence: Vec<ExecutableByteEvidence>,
}

/// Global status of one executable-byte ledger.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableByteIndexStatus {
    /// Every executable byte has a supported non-unresolved classification.
    Complete,
    /// Every byte was retained, but at least one span remains unresolved.
    Partial,
    /// A section, byte, or span budget omitted classifications.
    Truncated,
}

/// Completeness and byte-conservation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutableByteCompleteness {
    /// Overall ledger state.
    pub status: ExecutableByteIndexStatus,
    /// Executable sections observed before budgets.
    pub observed_sections: u64,
    /// Executable bytes observed before budgets.
    pub observed_bytes: u64,
    /// Bytes represented by retained classification spans.
    pub classified_bytes: u64,
    /// Retained bytes classified as unresolved.
    pub unresolved_bytes: u64,
    /// Retained bytes whose classification or admitting coverage is only a candidate.
    pub candidate_bytes: u64,
    /// First virtual address omitted by a byte or span budget.
    pub next_unexamined_address: Option<u64>,
    /// Stable reason codes explaining partiality or truncation.
    pub reasons: Vec<String>,
}

/// Image-bound executable-byte classification ledger.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableByteIndex {
    image: FunctionImageIdentity,
    limits: ExecutableByteLimits,
    spans: Vec<ExecutableByteSpan>,
    completeness: ExecutableByteCompleteness,
}

/// One validated caller byte-role premise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GuidedExecutableByteRole {
    pub(crate) section_ordinal: u64,
    pub(crate) start: u64,
    pub(crate) end_exclusive: u64,
    pub(crate) kind: ExecutableByteKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExecutableByteRecoveryGuidance {
    pub(crate) image: FunctionImageIdentity,
    pub(crate) roles: Vec<GuidedExecutableByteRole>,
}

impl ExecutableByteIndex {
    /// Classify admitted executable sections using existing function and CFG evidence.
    pub fn recover(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: ExecutableByteLimits,
    ) -> Result<Self, ExecutableByteRecoveryError> {
        Self::recover_internal(macho, functions, control_flow, limits, None)
    }

    pub(crate) fn recover_with_guidance(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: ExecutableByteLimits,
        guidance: &ExecutableByteRecoveryGuidance,
    ) -> Result<Self, ExecutableByteRecoveryError> {
        Self::recover_internal(macho, functions, control_flow, limits, Some(guidance))
    }

    fn recover_internal(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        control_flow: &ControlFlowIndex,
        limits: ExecutableByteLimits,
        guidance: Option<&ExecutableByteRecoveryGuidance>,
    ) -> Result<Self, ExecutableByteRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        if functions.image() != &image
            || control_flow.image() != &image
            || guidance.is_some_and(|guide| guide.image != image)
        {
            return Err(ExecutableByteRecoveryError::ImageMismatch);
        }

        let sections = macho
            .all_sections()
            .enumerate()
            .filter(|(_, section)| is_executable(section) && section.size() != 0)
            .collect::<Vec<_>>();
        let observed_sections = sections.len() as u64;
        let observed_bytes = sections
            .iter()
            .map(|(_, section)| section.size())
            .fold(0_u64, u64::saturating_add);
        let mut remaining_bytes = limits.max_bytes as u64;
        let mut spans = Vec::new();
        let mut reasons = BTreeSet::new();
        let mut next_unexamined_address = None;

        for (section_index, (ordinal, section)) in sections.iter().enumerate() {
            if section_index == limits.max_sections {
                reasons.insert("executable_bytes.section_budget".to_owned());
                next_unexamined_address = Some(section.addr().0);
                break;
            }
            if remaining_bytes == 0 {
                reasons.insert("executable_bytes.byte_budget".to_owned());
                next_unexamined_address = Some(section.addr().0);
                break;
            }
            let Some(section_end) = section.addr().0.checked_add(section.size()) else {
                reasons.insert("executable_bytes.section_address_overflow".to_owned());
                continue;
            };
            let admitted_len = section.size().min(remaining_bytes);
            let admitted_end = section.addr().0 + admitted_len;
            let candidates = classify_section(
                macho,
                *ordinal as u64,
                section,
                admitted_end,
                functions,
                control_flow,
                guidance.map_or(&[][..], |guide| guide.roles.as_slice()),
            );
            for candidate in candidates {
                if spans.len() == limits.max_spans {
                    reasons.insert("executable_bytes.span_budget".to_owned());
                    next_unexamined_address = Some(candidate.start);
                    break;
                }
                push_span(&mut spans, candidate);
            }
            if next_unexamined_address.is_some() {
                break;
            }
            remaining_bytes -= admitted_len;
            if admitted_end < section_end {
                reasons.insert("executable_bytes.byte_budget".to_owned());
                next_unexamined_address = Some(admitted_end);
                break;
            }
        }

        if sections.len() > limits.max_sections && next_unexamined_address.is_none() {
            reasons.insert("executable_bytes.section_budget".to_owned());
            next_unexamined_address = sections
                .get(limits.max_sections)
                .map(|(_, section)| section.addr().0);
        }
        let classified_bytes = spans
            .iter()
            .map(|span| span.end_exclusive - span.start)
            .fold(0_u64, u64::saturating_add);
        let unresolved_bytes = spans
            .iter()
            .filter(|span| span.kind == ExecutableByteKind::Unresolved)
            .map(|span| span.end_exclusive - span.start)
            .fold(0_u64, u64::saturating_add);
        let candidate_bytes = spans
            .iter()
            .filter(|span| span.confidence == FunctionEvidenceConfidence::Candidate)
            .map(|span| span.end_exclusive - span.start)
            .fold(0_u64, u64::saturating_add);
        if unresolved_bytes != 0 {
            reasons.insert("executable_bytes.unresolved".to_owned());
        }
        if candidate_bytes != 0 {
            reasons.insert("executable_bytes.candidate_classification".to_owned());
        }
        let truncated = next_unexamined_address.is_some()
            || reasons.iter().any(|reason| {
                matches!(
                    reason.as_str(),
                    "executable_bytes.section_budget"
                        | "executable_bytes.byte_budget"
                        | "executable_bytes.span_budget"
                )
            });
        let status = if truncated {
            ExecutableByteIndexStatus::Truncated
        } else if unresolved_bytes != 0
            || candidate_bytes != 0
            || classified_bytes != observed_bytes
        {
            ExecutableByteIndexStatus::Partial
        } else {
            ExecutableByteIndexStatus::Complete
        };
        let index = Self {
            image,
            limits,
            spans,
            completeness: ExecutableByteCompleteness {
                status,
                observed_sections,
                observed_bytes,
                classified_bytes,
                unresolved_bytes,
                candidate_bytes,
                next_unexamined_address,
                reasons: reasons.into_iter().collect(),
            },
        };
        debug_assert!(index.durable_invariants_hold());
        Ok(index)
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact limits used for classification.
    pub const fn limits(&self) -> ExecutableByteLimits {
        self.limits
    }

    /// Non-overlapping spans in section and address order.
    pub fn spans(&self) -> &[ExecutableByteSpan] {
        &self.spans
    }

    /// Byte-conservation and completeness receipt.
    pub const fn completeness(&self) -> &ExecutableByteCompleteness {
        &self.completeness
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err()
            || self.spans.len() > self.limits.max_spans
            || !strictly_sorted(&self.completeness.reasons)
        {
            return false;
        }
        let mut prior: Option<&ExecutableByteSpan> = None;
        let mut classified = 0_u64;
        let mut unresolved = 0_u64;
        let mut candidate = 0_u64;
        for span in &self.spans {
            if span.start >= span.end_exclusive
                || span.evidence.is_empty()
                || !strictly_sorted(&span.evidence)
                || prior.is_some_and(|previous| {
                    previous.section_ordinal > span.section_ordinal
                        || (previous.section_ordinal == span.section_ordinal
                            && (previous.segment != span.segment
                                || previous.section != span.section
                                || previous.end_exclusive > span.start))
                })
            {
                return false;
            }
            let len = span.end_exclusive - span.start;
            let Some(next_classified) = classified.checked_add(len) else {
                return false;
            };
            classified = next_classified;
            if span.kind == ExecutableByteKind::Unresolved {
                unresolved = unresolved.saturating_add(len);
            }
            if span.confidence == FunctionEvidenceConfidence::Candidate {
                candidate = candidate.saturating_add(len);
            }
            prior = Some(span);
        }
        let receipt = &self.completeness;
        let has = |reason: &str| receipt.reasons.iter().any(|item| item == reason);
        let truncated_reason = receipt.reasons.iter().any(|reason| {
            matches!(
                reason.as_str(),
                "executable_bytes.section_budget"
                    | "executable_bytes.byte_budget"
                    | "executable_bytes.span_budget"
            )
        });
        let expected_status = if receipt.next_unexamined_address.is_some() || truncated_reason {
            ExecutableByteIndexStatus::Truncated
        } else if unresolved != 0 || candidate != 0 || classified != receipt.observed_bytes {
            ExecutableByteIndexStatus::Partial
        } else {
            ExecutableByteIndexStatus::Complete
        };
        classified == receipt.classified_bytes
            && unresolved == receipt.unresolved_bytes
            && candidate == receipt.candidate_bytes
            && classified <= receipt.observed_bytes
            && classified <= self.limits.max_bytes as u64
            && self
                .spans
                .iter()
                .map(|span| span.section_ordinal)
                .collect::<BTreeSet<_>>()
                .len()
                <= self.limits.max_sections
            && receipt.observed_sections
                >= self
                    .spans
                    .iter()
                    .map(|span| span.section_ordinal)
                    .collect::<BTreeSet<_>>()
                    .len() as u64
            && has("executable_bytes.unresolved") == (unresolved != 0)
            && has("executable_bytes.candidate_classification") == (candidate != 0)
            && truncated_reason == receipt.next_unexamined_address.is_some()
            && receipt.status == expected_status
    }

    pub(crate) fn layout_invariants_hold(&self, layout: &ImageLayoutIndex) -> bool {
        self.image == *layout.image()
            && self.spans.iter().all(|span| {
                match layout
                    .sections()
                    .iter()
                    .find(|section| section.ordinal == span.section_ordinal)
                {
                    Some(section) => {
                        section.segment == span.segment
                            && section.name == span.section
                            && section.address <= span.start
                            && section
                                .address
                                .checked_add(section.size)
                                .is_some_and(|end| span.end_exclusive <= end)
                    }
                    None => !layout.completeness().complete,
                }
            })
    }
}

fn strictly_sorted<T: Ord>(values: &[T]) -> bool {
    values.windows(2).all(|pair| pair[0] < pair[1])
}

fn classify_section(
    macho: &MachoFile<'_>,
    ordinal: u64,
    section: &Section,
    admitted_end: u64,
    functions: &FunctionIndex,
    control_flow: &ControlFlowIndex,
    guidance: &[GuidedExecutableByteRole],
) -> Vec<ExecutableByteSpan> {
    let start = section.addr().0;
    let file_backed = section
        .offset()
        .0
        .checked_add(section.size())
        .is_some_and(|end| end <= macho.file_size() as u64)
        && !section.section_type().is_zerofill();
    if !file_backed {
        return vec![span(
            ordinal,
            section,
            start,
            admitted_end,
            ExecutableByteKind::Unresolved,
            FunctionEvidenceConfidence::Exact,
            vec![ExecutableByteEvidence::UnmappedSection],
        )];
    }
    let section_default = if section.section_type() == SectionType::SymbolStubs {
        Some((
            ExecutableByteKind::Stub,
            FunctionEvidenceConfidence::Exact,
            ExecutableByteEvidence::SectionDeclaredStub,
        ))
    } else if section.segment_name() == "__TEXT" && section.section_name() == "__stub_helper" {
        Some((
            ExecutableByteKind::Stub,
            FunctionEvidenceConfidence::Derived,
            ExecutableByteEvidence::SectionNamedStubHelper,
        ))
    } else if is_literal_section(section.section_type()) {
        Some((
            ExecutableByteKind::LiteralPool,
            FunctionEvidenceConfidence::Exact,
            ExecutableByteEvidence::SectionDeclaredLiteral,
        ))
    } else {
        None
    };

    let instructions = control_flow
        .functions()
        .iter()
        .flat_map(|graph| graph.instructions.iter())
        .filter(|instruction| overlaps_instruction(instruction, start, admitted_end))
        .collect::<Vec<_>>();
    let gaps = control_flow
        .functions()
        .iter()
        .flat_map(|graph| graph.gaps.iter())
        .filter(|gap| gap.start < admitted_end && gap.end_exclusive > start)
        .collect::<Vec<_>>();
    let forced_instruction = |range_start: u64, range_end: u64| {
        guidance.iter().any(|role| {
            role.section_ordinal == ordinal
                && role.kind == ExecutableByteKind::Instruction
                && range_start < role.end_exclusive
                && range_end > role.start
        })
    };
    let jump_tables = control_flow
        .functions()
        .iter()
        .flat_map(|graph| {
            graph.jump_tables.iter().map(|table| {
                let confidence = if graph.data_ranges.iter().any(|range| {
                    range.reason == ControlFlowDataRangeReason::RecoveredJumpTable
                        && range.start == table.table_address
                        && range.end_exclusive == table.end_exclusive
                }) {
                    FunctionEvidenceConfidence::Derived
                } else {
                    FunctionEvidenceConfidence::Candidate
                };
                (table, confidence)
            })
        })
        .filter(|(table, _)| table.table_address < admitted_end && table.end_exclusive > start)
        .map(|(table, confidence)| {
            (
                table.table_address.max(start),
                table.end_exclusive.min(admitted_end),
                confidence,
            )
        })
        .filter(|(table_start, table_end, _)| !forced_instruction(*table_start, *table_end))
        .collect::<Vec<_>>();
    let inside_jump_table = |address: u64| {
        jump_tables
            .iter()
            .any(|(table_start, table_end, _)| address >= *table_start && address < *table_end)
    };
    let targeted_boundaries = functions
        .functions()
        .iter()
        .map(|function| function.entry)
        .chain(
            functions
                .entry_candidates()
                .iter()
                .filter(|candidate| {
                    !matches!(
                        candidate.disposition,
                        crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
                            | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedByCaller
                            | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedRecoveredData
                            | crate::analysis::functions::FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
                            | crate::analysis::functions::FunctionEntryCandidateDisposition::ResolvedByCallerRelationship
                    ) && candidate.evidence.iter().any(|evidence| {
                        evidence
                            .source_location
                            .is_none_or(|source| !inside_jump_table(source))
                    })
                })
                .map(|candidate| candidate.address),
        )
        .chain(control_flow.functions().iter().flat_map(|graph| {
            graph
                .instructions
                .iter()
                .filter(|instruction| !inside_jump_table(instruction.address))
                .filter_map(|instruction| match instruction.target {
                    Some(InstructionTarget::Direct { address }) => Some(address),
                    _ => None,
                })
        }))
        .filter(|address| *address >= start && *address < admitted_end)
        .collect::<BTreeSet<_>>();
    let exact_function_entries = functions
        .functions()
        .iter()
        .filter(|function| function.entry_confidence == FunctionEvidenceConfidence::Exact)
        .map(|function| function.entry)
        .collect::<BTreeSet<_>>();
    let inline_literals = arm64_inline_literals(macho, section, admitted_end, control_flow)
        .into_iter()
        .filter(|(literal_start, literal_end, _)| !forced_instruction(*literal_start, *literal_end))
        .collect::<Vec<_>>();
    let unreachable_boundaries = unreachable_instruction_boundaries(control_flow);
    let mut boundaries = vec![start, admitted_end];
    let mut instruction_events = Vec::with_capacity(instructions.len().saturating_mul(2));
    for instruction in &instructions {
        let range_start = instruction.address.max(start);
        let range_end = instruction
            .address
            .saturating_add(instruction.byte_len as u64)
            .min(admitted_end);
        boundaries.push(range_start);
        boundaries.push(range_end);
        let key = (
            instruction.address,
            instruction
                .address
                .saturating_add(instruction.byte_len as u64),
            instruction.coverage_confidence,
        );
        instruction_events.push((range_start, true, key));
        instruction_events.push((range_end, false, key));
    }
    let mut gap_events = Vec::with_capacity(gaps.len().saturating_mul(2));
    for gap in &gaps {
        let range_start = gap.start.max(start);
        let range_end = gap.end_exclusive.min(admitted_end);
        boundaries.push(range_start);
        boundaries.push(range_end);
        gap_events.push((range_start, true));
        gap_events.push((range_end, false));
    }
    for (literal_start, literal_end, _) in &inline_literals {
        boundaries.push(*literal_start);
        boundaries.push(*literal_end);
    }
    for (table_start, table_end, _) in &jump_tables {
        boundaries.push(*table_start);
        boundaries.push(*table_end);
    }
    for role in guidance
        .iter()
        .filter(|role| role.section_ordinal == ordinal)
    {
        boundaries.push(role.start.max(start));
        boundaries.push(role.end_exclusive.min(admitted_end));
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    instruction_events.sort_unstable();
    gap_events.sort_unstable();

    let mut active_instructions = BTreeMap::<(u64, u64, FunctionEvidenceConfidence), usize>::new();
    let mut active_gaps = 0_usize;
    let mut instruction_event_index = 0;
    let mut gap_event_index = 0;
    let mut result = Vec::with_capacity(boundaries.len().saturating_sub(1));
    let classification = IntervalClassificationContext {
        ordinal,
        section,
        macho,
        targeted_boundaries: &targeted_boundaries,
        exact_function_entries: &exact_function_entries,
        unreachable_boundaries: &unreachable_boundaries,
        inline_literals: &inline_literals,
        jump_tables: &jump_tables,
        section_default,
        guidance,
    };
    for window in boundaries.windows(2) {
        let range_start = window[0];
        let range_end = window[1];
        while instruction_events
            .get(instruction_event_index)
            .is_some_and(|event| event.0 == range_start)
        {
            let (_, starts, key) = instruction_events[instruction_event_index];
            if starts {
                *active_instructions.entry(key).or_default() += 1;
            } else if let Some(count) = active_instructions.get_mut(&key) {
                *count -= 1;
                if *count == 0 {
                    active_instructions.remove(&key);
                }
            }
            instruction_event_index += 1;
        }
        while gap_events
            .get(gap_event_index)
            .is_some_and(|event| event.0 == range_start)
        {
            let (_, starts) = gap_events[gap_event_index];
            if starts {
                active_gaps += 1;
            } else {
                active_gaps = active_gaps.saturating_sub(1);
            }
            gap_event_index += 1;
        }
        if range_start < range_end {
            result.push(classify_interval(
                &classification,
                range_start,
                range_end,
                &active_instructions,
                active_gaps != 0,
            ));
        }
    }
    result
}

struct IntervalClassificationContext<'context, 'image> {
    ordinal: u64,
    section: &'context Section,
    macho: &'context MachoFile<'image>,
    targeted_boundaries: &'context BTreeSet<u64>,
    exact_function_entries: &'context BTreeSet<u64>,
    unreachable_boundaries: &'context BTreeSet<(u64, u64)>,
    inline_literals: &'context [(u64, u64, FunctionEvidenceConfidence)],
    jump_tables: &'context [(u64, u64, FunctionEvidenceConfidence)],
    section_default: Option<(
        ExecutableByteKind,
        FunctionEvidenceConfidence,
        ExecutableByteEvidence,
    )>,
    guidance: &'context [GuidedExecutableByteRole],
}

fn classify_interval(
    classification: &IntervalClassificationContext<'_, '_>,
    start: u64,
    end: u64,
    instructions: &BTreeMap<(u64, u64, FunctionEvidenceConfidence), usize>,
    covered_by_gap: bool,
) -> ExecutableByteSpan {
    let IntervalClassificationContext {
        ordinal,
        section,
        macho,
        targeted_boundaries,
        exact_function_entries,
        unreachable_boundaries,
        inline_literals,
        jump_tables,
        section_default,
        guidance,
    } = classification;
    let ordinal = *ordinal;
    let section_default = *section_default;
    let guided_role = guidance.iter().find(|role| {
        role.section_ordinal == ordinal && start >= role.start && end <= role.end_exclusive
    });
    if let Some(role) = guided_role.filter(|role| role.kind != ExecutableByteKind::Instruction) {
        return span(
            ordinal,
            section,
            start,
            end,
            role.kind,
            FunctionEvidenceConfidence::Candidate,
            vec![ExecutableByteEvidence::CallerDecision],
        );
    }
    if let Some((kind, confidence, evidence)) = section_default {
        return span(
            ordinal,
            section,
            start,
            end,
            kind,
            confidence,
            vec![evidence],
        );
    }
    let distinct_boundaries = instructions
        .keys()
        .map(|(start, end, _)| (*start, *end))
        .collect::<BTreeSet<_>>();

    if let Some((table_start, table_end, confidence)) = jump_tables
        .iter()
        .find(|(table_start, table_end, _)| start >= *table_start && end <= *table_end)
    {
        let target_conflict = targeted_boundaries
            .range(*table_start..*table_end)
            .next()
            .is_some();
        return span(
            ordinal,
            section,
            start,
            end,
            if target_conflict {
                ExecutableByteKind::Unresolved
            } else {
                ExecutableByteKind::EmbeddedData
            },
            if target_conflict {
                FunctionEvidenceConfidence::Candidate
            } else {
                *confidence
            },
            vec![if target_conflict {
                ExecutableByteEvidence::JumpTableTargetConflict
            } else {
                ExecutableByteEvidence::RecoveredJumpTable
            }],
        );
    }

    if let Some((literal_start, literal_end, confidence)) = inline_literals
        .iter()
        .find(|(literal_start, literal_end, _)| start >= *literal_start && end <= *literal_end)
    {
        let target_conflict = targeted_boundaries
            .range(*literal_start..*literal_end)
            .next()
            .is_some();
        return span(
            ordinal,
            section,
            start,
            end,
            if target_conflict {
                ExecutableByteKind::Unresolved
            } else {
                ExecutableByteKind::EmbeddedData
            },
            if target_conflict {
                FunctionEvidenceConfidence::Candidate
            } else {
                *confidence
            },
            vec![if target_conflict {
                ExecutableByteEvidence::InlineLiteralTargetConflict
            } else {
                ExecutableByteEvidence::Arm64LiteralLoad
            }],
        );
    }

    if instructions.is_empty()
        && (exact_function_entries.contains(&end)
            || jump_tables
                .iter()
                .any(|(table_start, _, _)| *table_start == end))
        && !targeted_boundaries.contains(&start)
        && range_is_zero_fill(macho, section, start, end)
    {
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Alignment,
            FunctionEvidenceConfidence::Derived,
            vec![ExecutableByteEvidence::ZeroFillFunctionAlignment],
        );
    }
    if instructions.is_empty()
        && (exact_function_entries.contains(&end)
            || jump_tables
                .iter()
                .any(|(table_start, _, _)| *table_start == end))
        && !targeted_boundaries.contains(&start)
        && is_architecture_nop(macho, section, start, end)
    {
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Padding,
            FunctionEvidenceConfidence::Derived,
            vec![ExecutableByteEvidence::FunctionAlignmentNop],
        );
    }

    if covered_by_gap && !instructions.is_empty() || distinct_boundaries.len() > 1 {
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Unresolved,
            FunctionEvidenceConfidence::Candidate,
            vec![ExecutableByteEvidence::ConflictingInstructionBoundaries],
        );
    }
    if macho.header().cpu_type().0 == CPU_TYPE_X86_64
        && let Some((instruction_start, instruction_end)) = distinct_boundaries.first().copied()
        && targeted_boundaries
            .range(instruction_start.saturating_add(1)..instruction_end)
            .next()
            .is_some()
    {
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Unresolved,
            FunctionEvidenceConfidence::Candidate,
            vec![ExecutableByteEvidence::TargetedAlternativeBoundary],
        );
    }
    if let Some((instruction_start, instruction_end)) = distinct_boundaries.first().copied()
        && unreachable_boundaries.contains(&(instruction_start, instruction_end))
        && is_architecture_nop(macho, section, instruction_start, instruction_end)
    {
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Padding,
            FunctionEvidenceConfidence::Derived,
            vec![ExecutableByteEvidence::UnreachableNopPadding],
        );
    }
    if let Some((_, _, confidence)) = instructions.keys().next() {
        let mut evidence = vec![ExecutableByteEvidence::DecodedInstruction];
        if guided_role.is_some_and(|role| role.kind == ExecutableByteKind::Instruction) {
            evidence.push(ExecutableByteEvidence::CallerDecision);
        }
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Instruction,
            *confidence,
            evidence,
        );
    }
    if covered_by_gap {
        return span(
            ordinal,
            section,
            start,
            end,
            ExecutableByteKind::Unresolved,
            FunctionEvidenceConfidence::Candidate,
            vec![ExecutableByteEvidence::DecodeGap],
        );
    }
    span(
        ordinal,
        section,
        start,
        end,
        ExecutableByteKind::Unresolved,
        FunctionEvidenceConfidence::Candidate,
        vec![ExecutableByteEvidence::NoRecoveredCoverage],
    )
}

fn range_is_zero_fill(macho: &MachoFile<'_>, section: &Section, start: u64, end: u64) -> bool {
    let Some(relative) = start.checked_sub(section.addr().0) else {
        return false;
    };
    let Some(file_offset) = section.offset().0.checked_add(relative) else {
        return false;
    };
    let Ok(length) = usize::try_from(end.saturating_sub(start)) else {
        return false;
    };
    length != 0
        && macho
            .read_bytes_at(ThinFileOffset(file_offset), length)
            .is_ok_and(|bytes| bytes.iter().all(|byte| *byte == 0))
}

fn arm64_inline_literals(
    macho: &MachoFile<'_>,
    section: &Section,
    admitted_end: u64,
    control_flow: &ControlFlowIndex,
) -> Vec<(u64, u64, FunctionEvidenceConfidence)> {
    if macho.header().cpu_type().0 != CPU_TYPE_ARM64 {
        return Vec::new();
    }
    let section_start = section.addr().0;
    let mut literals = control_flow
        .functions()
        .iter()
        .flat_map(|graph| graph.instructions.iter())
        .filter_map(|instruction| {
            let reference = instruction.pc_relative?;
            if reference.kind != ControlFlowPcRelativeKind::Memory || instruction.byte_len != 4 {
                return None;
            }
            let relative = instruction.address.checked_sub(section_start)?;
            let file_offset = section.offset().0.checked_add(relative)?;
            let bytes = macho.read_bytes_at(ThinFileOffset(file_offset), 4).ok()?;
            let word = u32::from_le_bytes(bytes.try_into().ok()?);
            if word & 0x3b00_0000 != 0x1800_0000 {
                return None;
            }
            let vector = (word >> 26) & 1;
            let opcode = (word >> 30) & 3;
            let width = match (vector, opcode) {
                (0, 0 | 2) | (1, 0) => 4,
                (0 | 1, 1) => 8,
                (1, 2) => 16,
                _ => return None,
            };
            let end = reference.address.checked_add(width)?;
            (reference.address >= section_start && end <= admitted_end).then_some((
                reference.address,
                end,
                FunctionEvidenceConfidence::Derived,
            ))
        })
        .collect::<Vec<_>>();
    literals.sort_unstable();
    literals.dedup();
    literals
}

fn span(
    ordinal: u64,
    section: &Section,
    start: u64,
    end_exclusive: u64,
    kind: ExecutableByteKind,
    confidence: FunctionEvidenceConfidence,
    evidence: Vec<ExecutableByteEvidence>,
) -> ExecutableByteSpan {
    ExecutableByteSpan {
        section_ordinal: ordinal,
        segment: section.segment_name().to_string(),
        section: section.section_name().to_string(),
        start,
        end_exclusive,
        kind,
        confidence,
        evidence,
    }
}

fn push_span(spans: &mut Vec<ExecutableByteSpan>, candidate: ExecutableByteSpan) {
    if let Some(previous) = spans.last_mut()
        && previous.section_ordinal == candidate.section_ordinal
        && previous.end_exclusive == candidate.start
        && previous.kind == candidate.kind
        && previous.confidence == candidate.confidence
        && previous.evidence == candidate.evidence
    {
        previous.end_exclusive = candidate.end_exclusive;
    } else {
        spans.push(candidate);
    }
}

fn unreachable_instruction_boundaries(control_flow: &ControlFlowIndex) -> BTreeSet<(u64, u64)> {
    let mut observations = BTreeMap::<(u64, u64), (bool, bool)>::new();
    for graph in control_flow.functions() {
        for block in &graph.blocks {
            let first = block.first_instruction as usize;
            let end = first.saturating_add(block.instruction_count as usize);
            for instruction in graph.instructions.get(first..end).unwrap_or_default() {
                let boundary = (
                    instruction.address,
                    instruction
                        .address
                        .saturating_add(instruction.byte_len as u64),
                );
                let observation = observations.entry(boundary).or_default();
                if block.reachability == ControlFlowReachability::Unreachable {
                    observation.0 = true;
                } else {
                    observation.1 = true;
                }
            }
        }
    }
    observations
        .into_iter()
        .filter_map(|(boundary, (unreachable, other))| (unreachable && !other).then_some(boundary))
        .collect()
}

fn is_architecture_nop(macho: &MachoFile<'_>, section: &Section, start: u64, end: u64) -> bool {
    let Some(relative) = start.checked_sub(section.addr().0) else {
        return false;
    };
    let Some(file_offset) = section.offset().0.checked_add(relative) else {
        return false;
    };
    let Ok(length) = usize::try_from(end.saturating_sub(start)) else {
        return false;
    };
    let Ok(bytes) = macho.read_bytes_at(ThinFileOffset(file_offset), length) else {
        return false;
    };
    match macho.header().cpu_type().0 {
        CPU_TYPE_X86_64 => matches!(
            bytes,
            [0x90]
                | [0x66, 0x90]
                | [0x0f, 0x1f, 0x00]
                | [0x0f, 0x1f, 0x40, 0x00]
                | [0x0f, 0x1f, 0x44, 0x00, 0x00]
                | [0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00]
                | [0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00]
                | [0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
                | [0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00]
        ),
        CPU_TYPE_ARM64 => bytes == [0x1f, 0x20, 0x03, 0xd5],
        _ => false,
    }
}

fn overlaps_instruction(instruction: &ControlFlowInstruction, start: u64, end: u64) -> bool {
    instruction.address < end
        && instruction
            .address
            .saturating_add(instruction.byte_len as u64)
            > start
}

fn is_executable(section: &Section) -> bool {
    section
        .attributes()
        .intersects(SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS)
}

fn is_literal_section(section_type: SectionType) -> bool {
    matches!(
        section_type,
        SectionType::FourByteLiterals
            | SectionType::EightByteLiterals
            | SectionType::SixteenByteLiterals
            | SectionType::LiteralPointers
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::control_flow::ControlFlowLimits;
    use crate::analysis::functions::FunctionRecoveryLimits;

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    fn recover(bytes: &[u8], limits: ExecutableByteLimits) -> ExecutableByteIndex {
        let macho = image(bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        ExecutableByteIndex::recover(&macho, &functions, &control_flow, limits).unwrap()
    }

    #[test]
    fn every_admitted_executable_byte_has_one_ordered_classification() {
        let bytes = macho_test_support::disassembly_x86_64();
        let index = recover(&bytes, ExecutableByteLimits::default());
        assert_eq!(
            index.completeness().classified_bytes,
            index.completeness().observed_bytes
        );
        assert!(index.spans().windows(2).all(|pair| {
            pair[0].section_ordinal < pair[1].section_ordinal
                || (pair[0].section_ordinal == pair[1].section_ordinal
                    && pair[0].end_exclusive == pair[1].start)
        }));
        assert_eq!(
            index.completeness().status,
            ExecutableByteIndexStatus::Partial,
            "uncovered or ambiguous bytes must prevent false completion"
        );
    }

    #[test]
    fn conventional_stub_helper_is_conserved_as_stubs_and_guidance_can_override_a_subrange() {
        let mut bytes = macho_test_support::thin64_x86_64_with_symbols(&[]);
        bytes[104..120].fill(0);
        bytes[104..117].copy_from_slice(b"__stub_helper");
        let macho = image(&bytes);
        let functions = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let control_flow =
            ControlFlowIndex::recover(&macho, &functions, ControlFlowLimits::default()).unwrap();
        let base = ExecutableByteIndex::recover(
            &macho,
            &functions,
            &control_flow,
            ExecutableByteLimits::default(),
        )
        .unwrap();
        assert!(base.spans().iter().all(|span| {
            span.kind == ExecutableByteKind::Stub
                && span.confidence == FunctionEvidenceConfidence::Derived
                && span
                    .evidence
                    .contains(&ExecutableByteEvidence::SectionNamedStubHelper)
        }));
        assert_eq!(
            base.completeness().unresolved_bytes,
            0,
            "the conventional helper section is not unowned executable space"
        );

        let section = macho.all_sections().next().unwrap();
        let guidance = ExecutableByteRecoveryGuidance {
            image: FunctionImageIdentity::from_macho(&macho),
            roles: vec![GuidedExecutableByteRole {
                section_ordinal: 0,
                start: section.addr().0,
                end_exclusive: section.addr().0 + 4,
                kind: ExecutableByteKind::EmbeddedData,
            }],
        };
        let guided = ExecutableByteIndex::recover_with_guidance(
            &macho,
            &functions,
            &control_flow,
            ExecutableByteLimits::default(),
            &guidance,
        )
        .unwrap();
        assert!(guided.spans().iter().any(|span| {
            span.start == section.addr().0
                && span.end_exclusive == section.addr().0 + 4
                && span.kind == ExecutableByteKind::EmbeddedData
                && span
                    .evidence
                    .contains(&ExecutableByteEvidence::CallerDecision)
        }));
    }

    #[test]
    fn byte_budget_reports_the_first_omitted_address() {
        let bytes = macho_test_support::disassembly_x86_64();
        let index = recover(
            &bytes,
            ExecutableByteLimits {
                max_bytes: 1,
                ..ExecutableByteLimits::default()
            },
        );
        assert_eq!(
            index.completeness().status,
            ExecutableByteIndexStatus::Truncated
        );
        assert_eq!(index.completeness().classified_bytes, 1);
        assert_eq!(
            index.completeness().next_unexamined_address,
            index.spans().last().map(|span| span.end_exclusive)
        );
    }

    #[test]
    fn stripping_names_does_not_change_byte_classification() {
        let rich = function_starts_fixture(true);
        let stripped = function_starts_fixture(false);
        let rich_index = recover(&rich, ExecutableByteLimits::default());
        let stripped_index = recover(&stripped, ExecutableByteLimits::default());
        let semantic_spans = |index: &ExecutableByteIndex| {
            index
                .spans()
                .iter()
                .map(|span| {
                    (
                        span.section_ordinal,
                        span.start,
                        span.end_exclusive,
                        span.kind,
                        span.confidence,
                        span.evidence.clone(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(semantic_spans(&rich_index), semantic_spans(&stripped_index));
        assert_eq!(
            rich_index.completeness().classified_bytes,
            stripped_index.completeness().classified_bytes
        );
        assert_eq!(
            rich_index.completeness().unresolved_bytes,
            stripped_index.completeness().unresolved_bytes
        );
    }

    #[test]
    fn targeted_x86_interior_boundary_is_not_silently_selected() {
        let mut bytes = macho_test_support::thin64_x86_64_with_symbols(&[]);
        let entry = 0x1_0000_0100_u64;
        bytes[0x100..0x106].copy_from_slice(&[
            0xe8, 0xfd, 0xff, 0xff, 0xff, // call entry + 2
            0xc3, // ret
        ]);
        add_single_function_start(&mut bytes);

        let index = recover(&bytes, ExecutableByteLimits::default());
        let ambiguous = index
            .spans()
            .iter()
            .find(|span| {
                span.start <= entry
                    && span.end_exclusive >= entry + 5
                    && span
                        .evidence
                        .contains(&ExecutableByteEvidence::TargetedAlternativeBoundary)
            })
            .expect("interior call target makes the x86 instruction boundary ambiguous");
        assert_eq!(ambiguous.kind, ExecutableByteKind::Unresolved);
        assert_eq!(ambiguous.confidence, FunctionEvidenceConfidence::Candidate);
    }

    #[test]
    fn only_unreachable_nops_are_classified_as_padding() {
        let mut bytes = macho_test_support::thin64_x86_64_with_symbols(&[]);
        let entry = 0x1_0000_0100_u64;
        bytes[0x100..0x104].copy_from_slice(&[
            0x90, // reachable nop
            0xc3, // ret
            0x90, 0x90, // unreachable padding
        ]);
        add_single_function_start(&mut bytes);

        let index = recover(&bytes, ExecutableByteLimits::default());
        let reachable_nop = index
            .spans()
            .iter()
            .find(|span| span.start <= entry && span.end_exclusive > entry)
            .expect("entry byte is classified");
        assert_eq!(reachable_nop.kind, ExecutableByteKind::Instruction);
        let padding = index
            .spans()
            .iter()
            .find(|span| {
                span.start <= entry + 2
                    && span.end_exclusive >= entry + 4
                    && span
                        .evidence
                        .contains(&ExecutableByteEvidence::UnreachableNopPadding)
            })
            .expect("unreachable NOP run is retained as padding");
        assert_eq!(padding.kind, ExecutableByteKind::Padding);
        assert_eq!(padding.confidence, FunctionEvidenceConfidence::Derived);
    }

    #[test]
    fn clipped_zero_fill_before_an_exact_function_entry_is_alignment_not_a_decode_failure() {
        let mut bytes = function_starts_fixture(false);
        let entry = 0x1_0000_0100_u64;
        bytes[0x100..0x105].copy_from_slice(&[
            0x90, 0x90, 0xc3, // complete first function instructions
            0x00, // cannot form an x86 instruction before the next exact entry
            0xc3, // next function
        ]);

        let index = recover(&bytes, ExecutableByteLimits::default());
        let alignment = index
            .spans()
            .iter()
            .find(|span| span.start == entry + 3 && span.end_exclusive == entry + 4)
            .expect("the clipped fill byte is retained");
        assert_eq!(alignment.kind, ExecutableByteKind::Alignment);
        assert_eq!(alignment.confidence, FunctionEvidenceConfidence::Derived);
        assert_eq!(
            alignment.evidence,
            vec![ExecutableByteEvidence::ZeroFillFunctionAlignment]
        );
    }

    #[test]
    fn arm64_literal_loads_classify_inline_bytes_before_linear_decode() {
        let mut bytes = macho_test_support::disassembly_arm64();
        let entry = 0x1_0000_0100_u64;
        bytes[0x100..0x104].copy_from_slice(&0x5800_0040_u32.to_le_bytes()); // ldr x0, entry+8
        bytes[0x104..0x108].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes()); // ret
        bytes[0x108..0x110].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
        add_single_function_start(&mut bytes);

        let index = recover(&bytes, ExecutableByteLimits::default());
        let literal = index
            .spans()
            .iter()
            .find(|span| {
                span.start <= entry + 8
                    && span.end_exclusive >= entry + 16
                    && span
                        .evidence
                        .contains(&ExecutableByteEvidence::Arm64LiteralLoad)
            })
            .expect("literal-load width establishes the inline data range");
        assert_eq!(literal.kind, ExecutableByteKind::EmbeddedData);
        assert_eq!(literal.confidence, FunctionEvidenceConfidence::Derived);
    }

    #[test]
    fn arm64_literal_with_a_function_entry_is_an_explicit_conflict() {
        let mut bytes = macho_test_support::disassembly_arm64();
        let entry = 0x1_0000_0100_u64;
        bytes[0x100..0x104].copy_from_slice(&0x5800_0040_u32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0xd65f_03c0_u32.to_le_bytes());
        bytes[0x108..0x110].copy_from_slice(&0x1122_3344_5566_7788_u64.to_le_bytes());
        add_function_starts(&mut bytes);
        let starts_offset = bytes.len() - 4;
        bytes[starts_offset + 2] = 8; // second function entry at the literal address

        let index = recover(&bytes, ExecutableByteLimits::default());
        let conflict = index
            .spans()
            .iter()
            .find(|span| {
                span.start <= entry + 8
                    && span.end_exclusive >= entry + 16
                    && span
                        .evidence
                        .contains(&ExecutableByteEvidence::InlineLiteralTargetConflict)
            })
            .expect("control-flow entry conflicts with the inline literal");
        assert_eq!(conflict.kind, ExecutableByteKind::Unresolved);
        assert_eq!(conflict.confidence, FunctionEvidenceConfidence::Candidate);
    }

    #[test]
    fn recovered_x86_jump_table_bytes_override_linear_decode() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x158..0x160].copy_from_slice(&0x1_0000_0120_u64.to_le_bytes());
        bytes[0x100..0x10a].copy_from_slice(&[
            0x48, 0x8d, 0x15, 0x29, 0x00, 0x00, 0x00, // lea rdx,[rip+0x29]
            0xff, 0x24, 0xc2, // jmp [rdx+rax*8]
        ]);
        bytes[0x10a..0x120].fill(0x90);
        bytes[0x110] = 0xc3;
        bytes[0x118] = 0xc3;
        bytes[0x130..0x138].copy_from_slice(&0x1_0000_0110_u64.to_le_bytes());
        bytes[0x138..0x140].copy_from_slice(&0x1_0000_0118_u64.to_le_bytes());

        let index = recover(&bytes, ExecutableByteLimits::default());
        let table = index
            .spans()
            .iter()
            .find(|span| {
                span.start <= 0x1_0000_0130
                    && span.end_exclusive >= 0x1_0000_0140
                    && span
                        .evidence
                        .contains(&ExecutableByteEvidence::RecoveredJumpTable)
            })
            .expect("jump-table bytes retain their data classification");
        assert_eq!(table.kind, ExecutableByteKind::EmbeddedData);
        assert_eq!(table.confidence, FunctionEvidenceConfidence::Candidate);
    }

    #[test]
    fn recovered_arm64_jump_table_bytes_override_linear_decode() {
        let mut bytes = macho_test_support::disassembly_arm64();
        bytes[0x158..0x160].copy_from_slice(&0x1_0000_0120_u64.to_le_bytes());
        bytes[0x100..0x104].copy_from_slice(&0x1000_0188_u32.to_le_bytes()); // adr x8,0x130
        bytes[0x104..0x108].copy_from_slice(&0xB8A0_5909_u32.to_le_bytes()); // ldrsw x9,[x8,w0,uxtw #2]
        bytes[0x108..0x10c].copy_from_slice(&0x8B09_0109_u32.to_le_bytes()); // add x9,x8,x9
        bytes[0x10c..0x110].copy_from_slice(&0xD61F_0120_u32.to_le_bytes()); // br x9
        bytes[0x110..0x114].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x118..0x11c].copy_from_slice(&0xD65F_03C0_u32.to_le_bytes());
        bytes[0x130..0x134].copy_from_slice(&(-0x20_i32).to_le_bytes());
        bytes[0x134..0x138].copy_from_slice(&(-0x18_i32).to_le_bytes());

        let index = recover(&bytes, ExecutableByteLimits::default());
        let table = index
            .spans()
            .iter()
            .find(|span| {
                span.start <= 0x1_0000_0130
                    && span.end_exclusive >= 0x1_0000_0138
                    && span
                        .evidence
                        .contains(&ExecutableByteEvidence::RecoveredJumpTable)
            })
            .expect("ARM64 table bytes supersede speculative fixed-width decoding");
        assert_eq!(table.kind, ExecutableByteKind::EmbeddedData);
        assert_eq!(table.confidence, FunctionEvidenceConfidence::Candidate);
    }

    fn function_starts_fixture(with_symbols: bool) -> Vec<u8> {
        let symbols = if with_symbols {
            vec![
                macho_test_support::SymbolFixture {
                    name: "_main",
                    external: true,
                    defined: true,
                },
                macho_test_support::SymbolFixture {
                    name: "_helper",
                    external: false,
                    defined: true,
                },
            ]
        } else {
            Vec::new()
        };
        let mut bytes = macho_test_support::thin64_x86_64_with_symbols(&symbols);
        add_function_starts(&mut bytes);
        bytes
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
        bytes[command_offset + 12..command_offset + 16].copy_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[0x80, 0x02, 0x04, 0x00]);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    }

    fn add_single_function_start(bytes: &mut Vec<u8>) {
        let command_offset = 32 + 72 + 80 + 24;
        let data_offset = bytes.len();
        bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
        bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
        bytes[command_offset..command_offset + 4].copy_from_slice(&0x26_u32.to_le_bytes());
        bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16_u32.to_le_bytes());
        bytes[command_offset + 8..command_offset + 12]
            .copy_from_slice(&(data_offset as u32).to_le_bytes());
        bytes[command_offset + 12..command_offset + 16].copy_from_slice(&3_u32.to_le_bytes());
        bytes.extend_from_slice(&[0x80, 0x02, 0x00]);
        let file_size = bytes.len() as u64;
        bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    }
}
