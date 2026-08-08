//! Bounded, evidence-bearing function inventory recovery.
//!
//! The index intentionally distinguishes a proven range from an adjacency
//! bound. A later known entry or an executable-section end is useful for
//! limiting a search, but is never reported as the proven end of a function.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::format::constants::{
    CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64, CPU_TYPE_X86_64, SectionAttributes,
};
use crate::core::model::addr::ThinFileOffset;
use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::section::Section;
use crate::core::model::symbol::SymbolType;
use crate::insn::{Arch, InsnKind};
use crate::metadata::dyld::ExportKind;
use crate::metadata::dyld::FunctionStartsOutcome;
use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::control_flow::{
    ControlFlowDataRangeReason, ControlFlowExitKind, ControlFlowIndex, ControlFlowReachability,
    FunctionControlFlow, FunctionControlFlowStatus,
};
use crate::analysis::dwarf_index::{DwarfIndex, DwarfIndexStatus};
use crate::analysis::exception_index::{
    ExceptionCollectorStatus, ExceptionIndex, ExceptionRecordRangeKind, ExceptionRecordSource,
};
use crate::analysis::objc_index::{ObjcIndex, ObjcIndexStatus};
use crate::analysis::pointer_index::{PointerIndex, PointerRecordKind};
use crate::analysis::swift_index::{SwiftIndex, SwiftIndexStatus};
use crate::analysis::symbol_inventory::{
    NlistSymbolKind, RecoveredSymbolKind, SymbolCollectorStatus, SymbolEvidenceSource,
    SymbolInventory,
};

/// Limits for one thin-image function-recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRecoveryLimits {
    /// Maximum recovered function identities.
    pub max_functions: usize,
    /// Maximum retained observations from any one evidence source.
    pub max_evidence_per_source: usize,
    /// Maximum bytes retained across all evidence names.
    pub max_name_bytes: usize,
    /// Maximum executable bytes examined for direct calls.
    pub max_decoded_bytes: usize,
    /// Maximum bytes read from any unwind or exception section.
    pub max_unwind_bytes: usize,
    /// Maximum combined bytes loaded by bounded DWARF traversal.
    pub max_dwarf_section_bytes: u64,
    /// Maximum DWARF DIEs retained by bounded traversal.
    pub max_dwarf_entries: u64,
}

impl Default for FunctionRecoveryLimits {
    fn default() -> Self {
        Self {
            max_functions: 1_000_000,
            max_evidence_per_source: 2_000_000,
            max_name_bytes: 64 * 1024 * 1024,
            max_decoded_bytes: 64 * 1024 * 1024,
            max_unwind_bytes: 64 * 1024 * 1024,
            max_dwarf_section_bytes: 64 * 1024 * 1024,
            max_dwarf_entries: 2_000_000,
        }
    }
}

impl FunctionRecoveryLimits {
    /// Validate that every caller-controlled bound is non-zero.
    pub fn validate(self) -> Result<Self, FunctionRecoveryError> {
        if self.max_functions == 0
            || self.max_evidence_per_source == 0
            || self.max_name_bytes == 0
            || self.max_decoded_bytes == 0
            || self.max_unwind_bytes == 0
            || self.max_dwarf_section_bytes == 0
            || self.max_dwarf_entries == 0
        {
            return Err(FunctionRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Error returned before recovery begins.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FunctionRecoveryError {
    /// At least one explicit recovery limit is zero.
    #[error("function recovery limits must be non-zero")]
    InvalidLimits,
    /// One supplied evidence index belongs to different image bytes.
    #[error("function recovery evidence index belongs to a different image")]
    EvidenceImageMismatch,
}

/// Optional predecoded evidence reused by function recovery.
#[derive(Debug, Clone, Copy, Default)]
pub struct FunctionRecoveryInputs<'index> {
    /// Bounded `LC_FUNCTION_STARTS` evidence decoded by the selected-image session.
    pub function_starts: Option<&'index Result<FunctionStartsOutcome, String>>,
    /// Format pointer and import-stub evidence.
    pub pointers: Option<&'index PointerIndex>,
    /// Nlist and export-trie symbol evidence.
    pub symbols: Option<&'index SymbolInventory>,
    /// Bounded DWARF traversal.
    pub dwarf: Option<&'index DwarfIndex>,
    /// Strict Objective-C runtime metadata.
    pub objc: Option<&'index ObjcIndex>,
    /// Strict Swift ABI metadata.
    pub swift: Option<&'index SwiftIndex>,
    /// Compact-unwind, linked-unwind, and exception-frame evidence.
    pub exceptions: Option<&'index ExceptionIndex>,
    /// Validated neutral caller guidance for function-entry reconciliation.
    pub guidance: Option<&'index FunctionRecoveryGuidance>,
}

/// Validated function-entry decisions projected from a recovery guide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionRecoveryGuidance {
    /// Exact image to which the projected decisions bind.
    pub(crate) image: FunctionImageIdentity,
    /// Candidate entries to admit as caller-guided functions.
    pub(crate) accepted_entries: BTreeSet<u64>,
    /// Candidate entries to retain as explicitly rejected observations.
    pub(crate) rejected_entries: BTreeSet<u64>,
    /// Candidate addresses attached to an existing function identity.
    pub(crate) relationships: BTreeMap<u64, (u64, FunctionRelationshipKind)>,
    /// Caller-authored ranges belonging to a function in the guided view.
    pub(crate) ranges: BTreeMap<u64, Vec<(u64, u64)>>,
    /// Executable ranges the caller classifies as non-code.
    pub(crate) suppressed_code_ranges: Vec<(u64, u64)>,
    /// Exact decoded direct-call observations excluded from function evidence.
    pub(crate) suppressed_direct_calls: BTreeSet<(u64, u64)>,
}

impl FunctionRecoveryGuidance {
    pub(crate) fn new(image: FunctionImageIdentity) -> Self {
        Self {
            image,
            accepted_entries: BTreeSet::new(),
            rejected_entries: BTreeSet::new(),
            relationships: BTreeMap::new(),
            ranges: BTreeMap::new(),
            suppressed_code_ranges: Vec::new(),
            suppressed_direct_calls: BTreeSet::new(),
        }
    }
}

/// Identity binding a function index to one exact thin Mach-O image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionImageIdentity {
    /// SHA-256 of the complete thin-image bytes.
    pub content_sha256: String,
    /// Thin-image byte length.
    pub byte_len: u64,
    /// Raw Mach CPU type.
    pub cpu_type: i32,
    /// Raw Mach CPU subtype.
    pub cpu_subtype: i32,
}

impl FunctionImageIdentity {
    pub(crate) fn from_macho(macho: &MachoFile<'_>) -> Self {
        Self {
            content_sha256: macho
                .content_sha256(|| crate::analysis::report::sha256_hex(macho.bytes()))
                .to_owned(),
            byte_len: macho.file_size() as u64,
            cpu_type: macho.header().cpu_type().0,
            cpu_subtype: macho.header().cpu_subtype().0,
        }
    }
}

/// Source of one function-recovery observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum FunctionEvidenceSource {
    /// `LC_FUNCTION_STARTS` delta stream.
    FunctionStarts,
    /// Defined `nlist` section symbol.
    Nlist,
    /// Regular or thread-local export-trie address.
    ExportTrie,
    /// `DW_TAG_subprogram` low/high PC or range list.
    Dwarf,
    /// Objective-C method implementation.
    ObjectiveC,
    /// Swift vtable, override, or default implementation.
    Swift,
    /// Object-file compact-unwind record with a true function extent.
    CompactUnwind,
    /// Exception-frame FDE.
    ExceptionFrame,
    /// Direct decoded call target.
    DirectCall,
    /// Entry-reachable control-flow closure.
    ControlFlow,
    /// Executable-section boundary used only as a candidate bound.
    ExecutableSection,
    /// Explicit caller decision retained separately from independent evidence.
    CallerDecision,
}

/// Epistemic strength of an entry or extent observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionEvidenceConfidence {
    /// Plausible, but the source does not prove a function boundary.
    Candidate,
    /// Mechanically inferred from authoritative metadata.
    Derived,
    /// Explicitly encoded by the source.
    Exact,
}

/// What one evidence record establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionEvidenceRole {
    /// Establishes or proposes the entry address.
    Entry,
    /// Contributes a human-readable name.
    Name,
    /// Establishes a half-open extent.
    Extent,
    /// Supplies only a candidate upper bound.
    CandidateUpperBound,
}

/// One exact evidence record retained on a recovered function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEvidence {
    /// Deterministic function-local evidence ordinal after sorting.
    pub ordinal: u64,
    /// Evidence source.
    pub source: FunctionEvidenceSource,
    /// Roles established by this record.
    pub roles: Vec<FunctionEvidenceRole>,
    /// Strength of the boundary claim.
    pub confidence: FunctionEvidenceConfidence,
    /// Entry address proposed or established by the record.
    pub entry: u64,
    /// Start of the supported half-open extent, when present.
    pub extent_start: Option<u64>,
    /// Exact or derived half-open end, when encoded by this record.
    pub end_exclusive: Option<u64>,
    /// Name contributed by this record.
    pub name: Option<String>,
    /// Source-specific location, such as a callsite or DIE offset.
    pub source_location: Option<u64>,
    /// Stable, non-prose source detail.
    pub detail: String,
}

/// Stable disposition of an observed address that has not been established as
/// an independent function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionEntryCandidateDisposition {
    /// The address lies within one retained function extent and may be an
    /// alternate entry or ordinary internal label.
    InsideRecoveredExtent,
    /// The address exactly starts a retained secondary metadata range for one
    /// recovered function.
    SecondaryRangeEntry,
    /// More than one retained function range can own the address, as with a
    /// shared tail or conflicting extents.
    SharedOwnedRegion,
    /// No retained function extent explains an executable call target.
    UnresolvedCallTarget,
    /// The decoded target is outside every executable section and therefore
    /// cannot establish a supported function entry.
    RejectedNonExecutableTarget,
    /// A validated caller guide rejects the candidate in this recovery view.
    RejectedByCaller,
    /// A complete, bounded recovered data object contradicts the entry and no
    /// independent code-bearing source corroborates it.
    RejectedRecoveredData,
    /// The target is a proven import stub, not an independent function body.
    RejectedImportStub,
    /// Both the source and target exist only in a self-supporting x86
    /// alternative decode and conflict with the closed conventional CFG.
    RejectedAlternativeInterpretation,
    /// A validated caller guide attaches this observation to an existing function.
    ResolvedByCallerRelationship,
}

/// Supported caller-guided relationship between a candidate address and a function.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionRelationshipKind {
    /// A second supported entry into the same function body.
    AlternateEntry,
    /// A discontiguous cold fragment owned by the function.
    ColdFragment,
    /// A range intentionally shared with the function.
    SharedRange,
}

/// One caller-guided relationship that resolves a candidate without creating a body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionRelationship {
    /// Candidate address being interpreted.
    pub address: u64,
    /// Existing owning function entry.
    pub owner_entry: u64,
    /// Selected structural relationship.
    pub kind: FunctionRelationshipKind,
    /// Relationship authority: independently established metadata or caller guidance.
    pub authority: FunctionRecoveryAuthority,
    /// Original candidate evidence retained for provenance.
    pub evidence: Vec<FunctionEvidence>,
}

/// One range that independent non-candidate metadata assigns to more than one
/// recovered function.  This is the supported representation for folded or
/// deliberately shared tails; it is not an ownership conflict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionSharedRange {
    /// First shared byte.
    pub start: u64,
    /// Exclusive end of the shared range.
    pub end_exclusive: u64,
    /// Function entries independently claiming the exact same range.
    pub owners: Vec<u64>,
    /// Weakest authority among the retained owner claims.
    pub confidence: FunctionEvidenceConfidence,
    /// Exact range-bearing evidence from every owner.
    pub evidence: Vec<FunctionEvidence>,
}

/// Independently observed function entry suppressed by a caller byte-role decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressedFunctionEntry {
    /// Observed function entry.
    pub entry: u64,
    /// Guided embedded-data range containing the entry.
    pub range_start: u64,
    /// Exclusive guided range end.
    pub range_end_exclusive: u64,
    /// Original independently recovered evidence.
    pub evidence: Vec<FunctionEvidence>,
}

/// One possible owner of a candidate function entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEntryCandidateOwner {
    /// Recovered owner entry.
    pub entry: u64,
    /// Strength of the extent that contains the candidate address.
    pub ownership_confidence: FunctionOwnershipConfidence,
}

/// Retained entry evidence that is insufficient to create an independent
/// [`RecoveredFunction`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionEntryCandidate {
    /// Observed candidate address.
    pub address: u64,
    /// Stable classification of the unresolved observation.
    pub disposition: FunctionEntryCandidateDisposition,
    /// Stable reason code for the disposition.
    pub reason: String,
    /// Retained function extents that could explain the address.
    pub possible_owners: Vec<FunctionEntryCandidateOwner>,
    /// Every source observation supporting this candidate.
    pub evidence: Vec<FunctionEvidence>,
}

/// Stable identity of a recovered function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FunctionIdentity {
    /// At least one source supplied a name.
    Named {
        /// Deterministically selected primary name.
        primary: String,
        /// Other distinct names at the same entry.
        aliases: Vec<String>,
    },
    /// No retained evidence supplied a name.
    Anonymous {
        /// Stable image-local identity derived from the entry address.
        id: String,
    },
}

/// Best-known half-open function extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionExtent {
    /// Entry address.
    pub start: u64,
    /// Best-known exclusive end.
    pub end_exclusive: u64,
    /// Strength of the selected extent.
    pub confidence: FunctionEvidenceConfidence,
}

/// Kind of contradictory boundary evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionConflictKind {
    /// Exact or derived sources disagree on the exclusive end.
    ExtentEndDisagreement,
    /// A caller-selected range disagrees with independently recovered extent evidence.
    CallerGuidedExtentDisagreement,
    /// Caller-selected function ranges overlap another retained function range.
    CallerGuidedRangeOverlap,
    /// An authoritative extent crosses an executable-section boundary.
    ExtentOutsideExecutableSection,
    /// Two distinct authoritative function extents overlap.
    AuthoritativeExtentOverlap,
    /// An authoritative extent contains another authoritative entry.
    AuthoritativeExtentContainsEntry,
}

/// Boundary field participating in a function conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionConflictField {
    /// Proposed function entry.
    Entry,
    /// Proposed extent start.
    ExtentStart,
    /// Proposed exclusive extent end.
    ExtentEndExclusive,
}

/// One source-to-field claim retained in a function conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FunctionConflictClaim {
    /// Source making the claim.
    pub source: FunctionEvidenceSource,
    /// Boundary field being claimed.
    pub field: FunctionConflictField,
    /// Address value supplied by the source.
    pub value: u64,
}

/// Boundary conflict retained instead of silently choosing a source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionConflict {
    /// Conflict classification.
    pub kind: FunctionConflictKind,
    /// Values participating in the conflict.
    pub values: Vec<u64>,
    /// Sources participating in the conflict.
    pub sources: Vec<FunctionEvidenceSource>,
    /// Exact source-to-field claims participating in the conflict.
    #[serde(default)]
    pub claims: Vec<FunctionConflictClaim>,
}

/// Local completeness information for one recovered function.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCompleteness {
    /// Whether all enabled collectors completed without truncation or failure.
    pub locally_complete: bool,
    /// Sources whose incomplete collection can affect this identity.
    pub incomplete_sources: Vec<FunctionEvidenceSource>,
    /// Whether the function has an authoritative extent.
    pub extent_is_authoritative: bool,
}

/// Authority responsible for admitting a function into the current view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum FunctionRecoveryAuthority {
    /// Independently recovered from the selected image and enabled producers.
    #[default]
    Independent,
    /// Admitted by an explicit validated caller decision.
    CallerGuided,
}

/// One recovered function identity and all retained supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredFunction {
    /// Function entry address.
    pub entry: u64,
    /// Strength of the entry claim.
    pub entry_confidence: FunctionEvidenceConfidence,
    /// Whether independent recovery or caller guidance admitted this identity.
    #[serde(default)]
    pub authority: FunctionRecoveryAuthority,
    /// Named or stable anonymous identity.
    pub identity: FunctionIdentity,
    /// Best-known extent; adjacency-derived ends remain candidates.
    pub extent: Option<FunctionExtent>,
    /// Exact ranges selected by caller guidance for this view. Independent
    /// range evidence remains in `evidence` and disagreements remain conflicts,
    /// but downstream ownership and CFG recovery use these ranges.
    #[serde(default)]
    pub caller_guided_ranges: Vec<FunctionExtent>,
    /// Exact records supporting this function.
    pub evidence: Vec<FunctionEvidence>,
    /// Contradictory evidence retained during reconciliation.
    pub conflicts: Vec<FunctionConflict>,
    /// Function-local completeness statement.
    pub completeness: FunctionCompleteness,
}

/// Collector completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionCollectorStatus {
    /// Source was present and completely collected.
    Complete,
    /// Source was not present in the image.
    Absent,
    /// An explicit budget stopped collection.
    Truncated,
    /// A recoverable suffix or decode gap prevented complete collection.
    Partial,
    /// Present source could not be decoded safely.
    Failed,
    /// Source cannot be interpreted for this image architecture or format.
    Unsupported,
}

/// Bounded work and output receipt for one evidence source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCollectorReceipt {
    /// Evidence source.
    pub source: FunctionEvidenceSource,
    /// Completion state.
    pub status: FunctionCollectorStatus,
    /// Records or bytes examined, as described by `unit`.
    pub examined: u64,
    /// Retained evidence observations.
    pub retained: u64,
    /// Unit for the examined counter.
    pub unit: String,
    /// Stable diagnostic code when incomplete.
    pub diagnostic: Option<String>,
}

/// Confidence attached to an address-ownership answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FunctionOwnershipConfidence {
    /// The address lies in one non-conflicted authoritative extent.
    Exact,
    /// The address lies in one non-conflicted mechanically derived extent.
    Derived,
    /// The address lies only in an adjacency- or section-bounded candidate.
    Candidate,
}

/// One possible owner returned for an ambiguous address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FunctionOwner<'index> {
    /// Recovered function.
    pub function: &'index RecoveredFunction,
    /// Strength of this ownership result.
    pub confidence: FunctionOwnershipConfidence,
}

/// Result of asking which function contains an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FunctionLookup<'index> {
    /// No retained entry or extent owns the address.
    None,
    /// One unambiguous owner.
    One(FunctionOwner<'index>),
    /// Multiple retained extents contain the address.
    Ambiguous(Vec<FunctionOwner<'index>>),
}

/// Allocation-free iterator over every retained function owning one address.
#[derive(Debug, Clone)]
pub struct FunctionOwners<'index> {
    index: &'index FunctionIndex,
    span_owners: &'index [(usize, FunctionEvidenceConfidence)],
    exact_index: Option<usize>,
    position: usize,
    exact_emitted: bool,
}

impl FunctionOwners<'_> {
    /// Number of distinct retained owners not yet yielded.
    pub fn len(&self) -> usize {
        self.remaining_len()
    }

    /// Whether no retained function owns the address.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn remaining_len(&self) -> usize {
        let span_remaining = self.span_owners.len().saturating_sub(self.position);
        let exact_is_extra = !self.exact_emitted
            && self.exact_index.is_some_and(|exact| {
                !self.span_owners[self.position..]
                    .iter()
                    .any(|(index, _)| *index == exact)
            });
        span_remaining + usize::from(exact_is_extra)
    }
}

impl<'index> Iterator for FunctionOwners<'index> {
    type Item = FunctionOwner<'index>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(&(index, mut confidence)) = self.span_owners.get(self.position) {
            self.position += 1;
            if self.exact_index == Some(index) {
                confidence = confidence.max(self.index.functions[index].entry_confidence);
                self.exact_emitted = true;
            }
            return Some(self.index.owner(index, confidence));
        }
        if !self.exact_emitted {
            self.exact_emitted = true;
            if let Some(index) = self.exact_index {
                return Some(
                    self.index
                        .owner(index, self.index.functions[index].entry_confidence),
                );
            }
        }
        None
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.remaining_len();
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for FunctionOwners<'_> {}

/// Deterministic, bounded function inventory for one thin Mach-O image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FunctionIndex {
    image: FunctionImageIdentity,
    limits: FunctionRecoveryLimits,
    functions: Vec<RecoveredFunction>,
    entry_candidates: Vec<FunctionEntryCandidate>,
    relationships: Vec<FunctionRelationship>,
    /// Independently established multiply-owned ranges.
    #[serde(default)]
    shared_ranges: Vec<FunctionSharedRange>,
    /// Proven import-stub addresses excluded from function identities.
    #[serde(default)]
    import_stubs: Vec<u64>,
    suppressed_entries: Vec<SuppressedFunctionEntry>,
    receipts: Vec<FunctionCollectorReceipt>,
    inventory_complete: bool,
    truncated_function_count: u64,
    ownership: Vec<OwnershipSpan>,
}

pub(crate) struct FunctionControlFlowRefinement {
    recovered_table_ranges: BTreeSet<(u64, u64)>,
    closed_extents: BTreeMap<u64, u64>,
    relevant_sources: BTreeSet<u64>,
    observed_source_starts: BTreeSet<u64>,
    relevant_targets: BTreeSet<u64>,
    interior_targets: BTreeSet<u64>,
}

impl FunctionControlFlowRefinement {
    pub(crate) fn new(index: &FunctionIndex) -> Self {
        let alternatives = index.entry_candidates.iter().filter(|candidate| {
            !candidate.evidence.is_empty()
                && candidate.evidence.iter().all(|evidence| {
                    evidence.detail == "decoded_alternative_direct_call_target"
                        && evidence.source_location.is_some()
                })
        });
        let relevant_targets = alternatives
            .clone()
            .map(|candidate| candidate.address)
            .collect();
        let relevant_sources = alternatives
            .flat_map(|candidate| {
                candidate
                    .evidence
                    .iter()
                    .filter_map(|evidence| evidence.source_location)
            })
            .collect();
        Self {
            recovered_table_ranges: BTreeSet::new(),
            closed_extents: BTreeMap::new(),
            relevant_sources,
            observed_source_starts: BTreeSet::new(),
            relevant_targets,
            interior_targets: BTreeSet::new(),
        }
    }

    pub(crate) fn observe(&mut self, index: &FunctionIndex, graph: &FunctionControlFlow) {
        self.recovered_table_ranges.extend(
            graph
                .data_ranges
                .iter()
                .filter(|range| range.reason == ControlFlowDataRangeReason::RecoveredJumpTable)
                .map(|range| (range.start, range.end_exclusive)),
        );
        if let Some(function) = index.by_entry(graph.function_entry)
            && let Some(end_exclusive) = closed_control_flow_extent(graph, function)
        {
            self.closed_extents
                .insert(graph.function_entry, end_exclusive);
        }
        for instruction in &graph.instructions {
            if self.relevant_sources.contains(&instruction.address) {
                self.observed_source_starts.insert(instruction.address);
            }
        }
        let Some(first) = graph.instructions.first() else {
            return;
        };
        let Some(last) = graph.instructions.last() else {
            return;
        };
        let end = last.address.saturating_add(u64::from(last.byte_len));
        for target in self.relevant_targets.range(first.address..end) {
            let preceding = graph
                .instructions
                .partition_point(|instruction| instruction.address < *target);
            if preceding > 0 {
                let instruction = &graph.instructions[preceding - 1];
                if instruction
                    .address
                    .saturating_add(u64::from(instruction.byte_len))
                    > *target
                {
                    self.interior_targets.insert(*target);
                }
            }
        }
    }

    pub(crate) fn finish_if_changed(self, index: &FunctionIndex) -> Option<FunctionIndex> {
        if !self.would_change(index) {
            return None;
        }
        Some(self.finish(index))
    }

    pub(crate) fn may_change(index: &FunctionIndex) -> bool {
        index.functions.iter().any(|function| {
            function_starts_only(function) || can_refine_control_flow_extent(function)
        }) || index.entry_candidates.iter().any(|candidate| {
            !candidate.evidence.is_empty()
                && candidate
                    .evidence
                    .iter()
                    .all(|evidence| evidence.detail == "decoded_alternative_direct_call_target")
        })
    }

    fn would_change(&self, index: &FunctionIndex) -> bool {
        let removes_recovered_data_entry = index.functions.iter().any(|function| {
            function_starts_only(function)
                && self
                    .recovered_table_ranges
                    .iter()
                    .any(|(start, _)| *start == function.entry)
        });
        let promotes_extent = index.functions.iter().any(|function| {
            can_refine_control_flow_extent(function)
                && self.closed_extents.contains_key(&function.entry)
        });
        let rejects_alternative = index.entry_candidates.iter().any(|candidate| {
            let alternative_only = !candidate.evidence.is_empty()
                && candidate.evidence.iter().all(|evidence| {
                    evidence.detail == "decoded_alternative_direct_call_target"
                        && evidence
                            .source_location
                            .is_some_and(|source| !self.observed_source_starts.contains(&source))
                });
            alternative_only
                && self.interior_targets.contains(&candidate.address)
                && (candidate.disposition
                    != FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
                    || candidate.reason
                        != "self_supporting_alternative_decode_conflicts_with_closed_cfg")
        });
        removes_recovered_data_entry || promotes_extent || rejects_alternative
    }

    pub(crate) fn finish(self, index: &FunctionIndex) -> FunctionIndex {
        let mut refined = index.clone();
        let mut rejected_data_entries = Vec::new();
        refined.functions.retain(|function| {
            let Some(&(range_start, range_end_exclusive)) = self
                .recovered_table_ranges
                .iter()
                .find(|(start, _)| *start == function.entry)
            else {
                return true;
            };
            if !function_starts_only(function) {
                return true;
            }
            rejected_data_entries.push(FunctionEntryCandidate {
                address: function.entry,
                disposition: FunctionEntryCandidateDisposition::RejectedRecoveredData,
                reason: "function_starts_entry_is_bounded_jump_table".into(),
                possible_owners: Vec::new(),
                evidence: function.evidence.clone(),
            });
            debug_assert!(range_end_exclusive > range_start);
            false
        });
        refined.entry_candidates.extend(rejected_data_entries);
        refined
            .entry_candidates
            .sort_by_key(|candidate| candidate.address);
        for function in &mut refined.functions {
            if !can_refine_control_flow_extent(function) {
                continue;
            }
            let Some(&end_exclusive) = self.closed_extents.get(&function.entry) else {
                continue;
            };
            function.extent = Some(FunctionExtent {
                start: function.entry,
                end_exclusive,
                confidence: FunctionEvidenceConfidence::Derived,
            });
            function.evidence.push(FunctionEvidence {
                ordinal: function.evidence.len() as u64,
                source: FunctionEvidenceSource::ControlFlow,
                roles: vec![FunctionEvidenceRole::Extent],
                confidence: FunctionEvidenceConfidence::Derived,
                entry: function.entry,
                extent_start: Some(function.entry),
                end_exclusive: Some(end_exclusive),
                name: None,
                source_location: Some(function.entry),
                detail: "entry_reachable_cfg_closed_extent".into(),
            });
            function.completeness.extent_is_authoritative = true;
        }
        refresh_entry_candidate_ownership(&mut refined.entry_candidates, &refined.functions);
        for candidate in &mut refined.entry_candidates {
            let alternative_only = !candidate.evidence.is_empty()
                && candidate.evidence.iter().all(|evidence| {
                    evidence.detail == "decoded_alternative_direct_call_target"
                        && evidence
                            .source_location
                            .is_some_and(|source| !self.observed_source_starts.contains(&source))
                });
            if alternative_only && self.interior_targets.contains(&candidate.address) {
                candidate.disposition =
                    FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation;
                candidate.reason =
                    "self_supporting_alternative_decode_conflicts_with_closed_cfg".into();
            }
        }
        refined.shared_ranges = independently_shared_ranges(&refined.functions);
        refined.ownership = build_ownership(&refined.functions);
        refined
    }
}

fn function_starts_only(function: &RecoveredFunction) -> bool {
    function.evidence.iter().all(|evidence| {
        matches!(
            evidence.source,
            FunctionEvidenceSource::FunctionStarts | FunctionEvidenceSource::ExecutableSection
        )
    }) && function.evidence.iter().any(|evidence| {
        evidence.source == FunctionEvidenceSource::FunctionStarts
            && evidence.roles.contains(&FunctionEvidenceRole::Entry)
    })
}

fn can_refine_control_flow_extent(function: &RecoveredFunction) -> bool {
    function.authority == FunctionRecoveryAuthority::Independent
        && function
            .extent
            .is_none_or(|extent| extent.confidence == FunctionEvidenceConfidence::Candidate)
        && function.conflicts.is_empty()
}

impl FunctionIndex {
    /// Recover one function inventory using explicit caller-provided limits.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: FunctionRecoveryLimits,
    ) -> Result<Self, FunctionRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        let sections = ExecutableSections::new(macho);
        let mut context = CollectionContext::new(limits, sections);

        collect_function_starts(macho, &mut context);
        collect_nlist(macho, &mut context);
        collect_exports(macho, &mut context);
        collect_dwarf(macho, &mut context);
        collect_objc(macho, &mut context);
        collect_swift(macho, &mut context);
        collect_compact_unwind(macho, &mut context);
        collect_exception_frames(macho, &mut context);
        collect_direct_calls(macho, &mut context);
        context.push_section_receipt();

        Ok(context.finish(image))
    }

    /// Recover functions while reusing already selected language and DWARF evidence.
    pub fn recover_with_inputs(
        macho: &MachoFile<'_>,
        limits: FunctionRecoveryLimits,
        inputs: FunctionRecoveryInputs<'_>,
    ) -> Result<Self, FunctionRecoveryError> {
        let limits = limits.validate()?;
        let image = FunctionImageIdentity::from_macho(macho);
        if inputs.symbols.is_some_and(|index| index.image() != &image)
            || inputs.pointers.is_some_and(|index| index.image() != &image)
            || inputs.dwarf.is_some_and(|index| index.image() != &image)
            || inputs.objc.is_some_and(|index| index.image() != &image)
            || inputs.swift.is_some_and(|index| index.image() != &image)
            || inputs
                .exceptions
                .is_some_and(|index| index.image() != &image)
            || inputs
                .guidance
                .is_some_and(|guidance| guidance.image != image)
        {
            return Err(FunctionRecoveryError::EvidenceImageMismatch);
        }
        let sections = ExecutableSections::new(macho);
        let mut context = CollectionContext::new(limits, sections);
        if let Some(pointers) = inputs.pointers {
            context.import_stubs.extend(
                pointers
                    .pointers()
                    .iter()
                    .filter(|pointer| pointer.kind == PointerRecordKind::Stub)
                    .map(|pointer| pointer.address),
            );
        }

        match inputs.function_starts {
            Some(outcome) => collect_function_starts_outcome(outcome, &mut context),
            None => collect_function_starts(macho, &mut context),
        }
        match inputs.symbols {
            Some(index) => collect_symbol_index(macho, index, &mut context),
            None => {
                collect_nlist(macho, &mut context);
                collect_exports(macho, &mut context);
            }
        }
        match inputs.dwarf {
            Some(index) => collect_dwarf_index(macho, index, &mut context),
            None => collect_dwarf(macho, &mut context),
        }
        match inputs.objc {
            Some(index) => collect_objc_index(index, &mut context),
            None => collect_objc(macho, &mut context),
        }
        match inputs.swift {
            Some(index) => collect_swift_index(index, &mut context),
            None => collect_swift(macho, &mut context),
        }
        match inputs.exceptions {
            Some(index) => collect_exception_index(index, &mut context),
            None => {
                collect_compact_unwind(macho, &mut context);
                collect_exception_frames(macho, &mut context);
            }
        }
        collect_direct_calls(macho, &mut context);
        if let Some(guidance) = inputs.guidance {
            context.apply_guidance(guidance);
        }
        context.push_section_receipt();

        Ok(context.finish(image))
    }

    /// Return a new inventory whose candidate extents are promoted only when
    /// the supplied graph proves a closed, entry-reachable instruction range.
    ///
    /// Adjacency remains only the search bound used by CFG recovery. A derived
    /// end requires every reachable exit to be accounted for and rejects
    /// decode gaps, omitted work, unknown reachability, unexplained indirect
    /// branches, and reachable fallthrough at the candidate boundary.
    pub fn refine_extents_from_control_flow(
        &self,
        control_flow: &ControlFlowIndex,
    ) -> Result<Self, FunctionRecoveryError> {
        if control_flow.image() != &self.image {
            return Err(FunctionRecoveryError::EvidenceImageMismatch);
        }
        let mut refinement = FunctionControlFlowRefinement::new(self);
        for graph in control_flow.functions() {
            refinement.observe(self, graph);
        }
        Ok(refinement.finish(self))
    }

    /// Recovered functions sorted by entry address.
    pub fn functions(&self) -> &[RecoveredFunction] {
        &self.functions
    }

    /// Entry observations that remain candidates rather than independent
    /// recovered function identities.
    pub fn entry_candidates(&self) -> &[FunctionEntryCandidate] {
        &self.entry_candidates
    }

    /// Caller-guided candidate relationships sorted by candidate address and owner.
    pub fn relationships(&self) -> &[FunctionRelationship] {
        &self.relationships
    }

    /// Exact ranges independently owned by multiple functions.
    pub fn shared_ranges(&self) -> &[FunctionSharedRange] {
        &self.shared_ranges
    }

    /// Proven import stubs in deterministic address order.
    pub fn import_stubs(&self) -> &[u64] {
        &self.import_stubs
    }

    /// Whether an exact address is a proven import stub.
    pub fn is_import_stub(&self, address: u64) -> bool {
        self.import_stubs.binary_search(&address).is_ok()
    }

    /// Find the caller-guided relationship selected for one candidate address.
    pub fn relationship_at(&self, address: u64) -> Option<&FunctionRelationship> {
        self.relationships
            .binary_search_by_key(&address, |relationship| relationship.address)
            .ok()
            .map(|index| &self.relationships[index])
    }

    /// Independently observed entries displaced by caller-guided data ownership.
    pub fn suppressed_entries(&self) -> &[SuppressedFunctionEntry] {
        &self.suppressed_entries
    }

    /// Exact thin-image identity used for recovery.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact limits used to build this index.
    pub const fn limits(&self) -> FunctionRecoveryLimits {
        self.limits
    }

    /// Collector receipts sorted by evidence source.
    pub fn receipts(&self) -> &[FunctionCollectorReceipt] {
        &self.receipts
    }

    /// Whether every enabled source completed and no identity was discarded.
    pub const fn inventory_complete(&self) -> bool {
        self.inventory_complete
    }

    /// Number of distinct recovered entries discarded by `max_functions`.
    pub const fn truncated_function_count(&self) -> u64 {
        self.truncated_function_count
    }

    /// Find a function with exactly this entry address.
    pub fn by_entry(&self, entry: u64) -> Option<&RecoveredFunction> {
        self.functions
            .binary_search_by_key(&entry, |function| function.entry)
            .ok()
            .map(|index| &self.functions[index])
    }

    /// Iterate every retained function extent containing `address` without allocating.
    pub fn owners(&self, address: u64) -> FunctionOwners<'_> {
        let span_index = self.ownership.partition_point(|span| span.start <= address);
        let span_owners = span_index
            .checked_sub(1)
            .and_then(|index| self.ownership.get(index))
            .filter(|span| address < span.end)
            .map_or(&[][..], |span| span.owners.as_slice());
        let exact_index = self
            .functions
            .binary_search_by_key(&address, |function| function.entry)
            .ok();
        FunctionOwners {
            index: self,
            span_owners,
            exact_index,
            position: 0,
            exact_emitted: false,
        }
    }

    /// Resolve every retained function extent containing `address`.
    pub fn containing(&self, address: u64) -> FunctionLookup<'_> {
        let owners = self.owners(address).collect::<Vec<_>>();
        match owners.len() {
            0 => FunctionLookup::None,
            1 => FunctionLookup::One(owners[0]),
            _ => FunctionLookup::Ambiguous(owners),
        }
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        let functions_are_canonical = self
            .functions
            .windows(2)
            .all(|pair| pair[0].entry < pair[1].entry);
        let candidates_are_sorted = self
            .entry_candidates
            .windows(2)
            .all(|pair| pair[0].address <= pair[1].address);
        let relationships_are_sorted = self.relationships.windows(2).all(|pair| {
            (pair[0].address, pair[0].owner_entry) <= (pair[1].address, pair[1].owner_entry)
        });
        let shared_ranges_are_sorted = self.shared_ranges.windows(2).all(|pair| {
            (pair[0].start, pair[0].end_exclusive, &pair[0].owners)
                <= (pair[1].start, pair[1].end_exclusive, &pair[1].owners)
        });
        let import_stubs_are_canonical = self.import_stubs.windows(2).all(|pair| pair[0] < pair[1]);
        let suppressed_entries_are_sorted = self
            .suppressed_entries
            .windows(2)
            .all(|pair| pair[0].entry <= pair[1].entry);
        let receipts_are_sorted = self
            .receipts
            .windows(2)
            .all(|pair| pair[0].source < pair[1].source);
        let functions_are_well_formed = self.functions.iter().all(|function| {
            function.extent.is_none_or(|extent| {
                extent.start == function.entry && extent.start < extent.end_exclusive
            }) && function
                .caller_guided_ranges
                .iter()
                .all(|extent| extent.start < extent.end_exclusive)
                && function
                    .evidence
                    .iter()
                    .enumerate()
                    .all(|(ordinal, evidence)| evidence.ordinal == ordinal as u64)
        });
        let relationships_are_bound = self.relationships.iter().all(|relationship| {
            self.functions
                .binary_search_by_key(&relationship.owner_entry, |function| function.entry)
                .is_ok()
        });
        self.limits.validate().is_ok()
            && self.functions.len() <= self.limits.max_functions
            && functions_are_canonical
            && candidates_are_sorted
            && relationships_are_sorted
            && shared_ranges_are_sorted
            && import_stubs_are_canonical
            && suppressed_entries_are_sorted
            && receipts_are_sorted
            && functions_are_well_formed
            && relationships_are_bound
            && self.shared_ranges == independently_shared_ranges(&self.functions)
            && self.ownership == build_ownership(&self.functions)
    }

    fn owner(&self, index: usize, matched: FunctionEvidenceConfidence) -> FunctionOwner<'_> {
        let function = &self.functions[index];
        let confidence = if function.conflicts.is_empty() {
            match matched {
                FunctionEvidenceConfidence::Exact => FunctionOwnershipConfidence::Exact,
                FunctionEvidenceConfidence::Derived => FunctionOwnershipConfidence::Derived,
                FunctionEvidenceConfidence::Candidate => FunctionOwnershipConfidence::Candidate,
            }
        } else {
            FunctionOwnershipConfidence::Candidate
        };
        FunctionOwner {
            function,
            confidence,
        }
    }
}

#[derive(Debug, Clone)]
struct RawEvidence {
    source: FunctionEvidenceSource,
    confidence: FunctionEvidenceConfidence,
    entry: u64,
    extent_start: Option<u64>,
    end_exclusive: Option<u64>,
    name: Option<String>,
    source_location: Option<u64>,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnershipSpan {
    start: u64,
    end: u64,
    owners: Vec<(usize, FunctionEvidenceConfidence)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct OwnershipEvent {
    position: u64,
    starts: bool,
    function_index: usize,
    confidence: FunctionEvidenceConfidence,
}

impl RawEvidence {
    fn roles(&self) -> Vec<FunctionEvidenceRole> {
        let mut roles = vec![FunctionEvidenceRole::Entry];
        if self.name.is_some() {
            roles.push(FunctionEvidenceRole::Name);
        }
        if self.extent_start.is_some() && self.end_exclusive.is_some() {
            roles.push(FunctionEvidenceRole::Extent);
        }
        roles
    }

    fn into_public(self, ordinal: u64) -> FunctionEvidence {
        let roles = self.roles();
        FunctionEvidence {
            ordinal,
            source: self.source,
            roles,
            confidence: self.confidence,
            entry: self.entry,
            extent_start: self.extent_start,
            end_exclusive: self.end_exclusive,
            name: self.name,
            source_location: self.source_location,
            detail: self.detail,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct ExecutableSpan {
    start: u64,
    end: u64,
    file_offset: u64,
}

#[derive(Debug)]
struct ExecutableSections {
    spans: Vec<ExecutableSpan>,
    examined: u64,
    invalid: u64,
}

impl ExecutableSections {
    fn new(macho: &MachoFile<'_>) -> Self {
        let mut spans = Vec::new();
        let mut examined = 0;
        let mut invalid = 0;
        for section in macho.all_sections() {
            examined += 1;
            if !is_executable(section) || section.size() == 0 {
                continue;
            }
            let Some(end) = section.addr().0.checked_add(section.size()) else {
                invalid += 1;
                continue;
            };
            let Some(file_end) = section.offset().0.checked_add(section.size()) else {
                invalid += 1;
                continue;
            };
            if file_end > macho.file_size() as u64 {
                invalid += 1;
                continue;
            }
            spans.push(ExecutableSpan {
                start: section.addr().0,
                end,
                file_offset: section.offset().0,
            });
        }
        spans.sort_by_key(|span| (span.start, span.end, span.file_offset));
        Self {
            spans,
            examined,
            invalid,
        }
    }

    fn containing(&self, address: u64) -> Option<ExecutableSpan> {
        self.spans
            .iter()
            .copied()
            .find(|span| address >= span.start && address < span.end)
    }
}

fn is_executable(section: &Section) -> bool {
    section
        .attributes()
        .intersects(SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS)
}

struct CollectionContext {
    limits: FunctionRecoveryLimits,
    sections: ExecutableSections,
    evidence: Vec<RawEvidence>,
    receipts: Vec<FunctionCollectorReceipt>,
    retained_by_source: BTreeMap<FunctionEvidenceSource, usize>,
    name_bytes: usize,
    name_truncated_sources: BTreeSet<FunctionEvidenceSource>,
    rejected_entries: BTreeSet<u64>,
    guided_relationships: BTreeMap<u64, (u64, FunctionRelationshipKind)>,
    guided_ranges: BTreeMap<u64, Vec<(u64, u64)>>,
    suppressed_code_ranges: Vec<(u64, u64)>,
    import_stubs: BTreeSet<u64>,
}

impl CollectionContext {
    fn new(limits: FunctionRecoveryLimits, sections: ExecutableSections) -> Self {
        Self {
            limits,
            sections,
            evidence: Vec::new(),
            receipts: Vec::new(),
            retained_by_source: BTreeMap::new(),
            name_bytes: 0,
            name_truncated_sources: BTreeSet::new(),
            rejected_entries: BTreeSet::new(),
            guided_relationships: BTreeMap::new(),
            guided_ranges: BTreeMap::new(),
            suppressed_code_ranges: Vec::new(),
            import_stubs: BTreeSet::new(),
        }
    }

    fn apply_guidance(&mut self, guidance: &FunctionRecoveryGuidance) {
        if !guidance.suppressed_direct_calls.is_empty() {
            self.evidence.retain(|evidence| {
                evidence.source != FunctionEvidenceSource::DirectCall
                    || !evidence.source_location.is_some_and(|instruction_address| {
                        guidance
                            .suppressed_direct_calls
                            .contains(&(instruction_address, evidence.entry))
                    })
            });
            let retained = self
                .evidence
                .iter()
                .filter(|evidence| evidence.source == FunctionEvidenceSource::DirectCall)
                .count();
            self.retained_by_source
                .insert(FunctionEvidenceSource::DirectCall, retained);
            if let Some(receipt) = self
                .receipts
                .iter_mut()
                .find(|receipt| receipt.source == FunctionEvidenceSource::DirectCall)
            {
                receipt.retained = retained as u64;
            }
        }
        for &entry in &guidance.accepted_entries {
            self.admit(RawEvidence {
                source: FunctionEvidenceSource::CallerDecision,
                confidence: FunctionEvidenceConfidence::Candidate,
                entry,
                extent_start: None,
                end_exclusive: None,
                name: None,
                source_location: Some(entry),
                detail: "recovery_guide_accept_function_entry".into(),
            });
        }
        self.rejected_entries
            .extend(guidance.rejected_entries.iter().copied());
        self.guided_relationships.extend(
            guidance
                .relationships
                .iter()
                .map(|(address, relationship)| (*address, *relationship)),
        );
        for (&entry, ranges) in &guidance.ranges {
            self.guided_ranges.insert(entry, ranges.clone());
            for &(start, end_exclusive) in ranges {
                self.admit(RawEvidence {
                    source: FunctionEvidenceSource::CallerDecision,
                    confidence: FunctionEvidenceConfidence::Candidate,
                    entry,
                    extent_start: Some(start),
                    end_exclusive: Some(end_exclusive),
                    name: None,
                    source_location: Some(start),
                    detail: "recovery_guide_function_range".into(),
                });
            }
        }
        self.suppressed_code_ranges
            .extend(guidance.suppressed_code_ranges.iter().copied());
        self.suppressed_code_ranges.sort_unstable();
        self.suppressed_code_ranges.dedup();
    }

    fn admit(&mut self, mut evidence: RawEvidence) -> bool {
        if self.sections.containing(evidence.entry).is_none()
            && evidence.source != FunctionEvidenceSource::DirectCall
        {
            return false;
        }
        let retained = self.retained_by_source.entry(evidence.source).or_default();
        if *retained >= self.limits.max_evidence_per_source {
            return false;
        }
        if let Some(name) = &evidence.name {
            if self.name_bytes.saturating_add(name.len()) > self.limits.max_name_bytes {
                evidence.name = None;
                self.name_truncated_sources.insert(evidence.source);
            } else {
                self.name_bytes += name.len();
            }
        }
        *retained += 1;
        self.evidence.push(evidence);
        true
    }

    fn retained(&self, source: FunctionEvidenceSource) -> u64 {
        self.retained_by_source.get(&source).copied().unwrap_or(0) as u64
    }

    fn receipt(
        &mut self,
        source: FunctionEvidenceSource,
        status: FunctionCollectorStatus,
        examined: u64,
        unit: &str,
        diagnostic: Option<&str>,
    ) {
        let (status, diagnostic) = if self.name_truncated_sources.contains(&source)
            && matches!(status, FunctionCollectorStatus::Complete)
        {
            (
                FunctionCollectorStatus::Truncated,
                Some("function_name_byte_budget"),
            )
        } else {
            (status, diagnostic)
        };
        self.receipts.push(FunctionCollectorReceipt {
            source,
            status,
            examined,
            retained: self.retained(source),
            unit: unit.to_owned(),
            diagnostic: diagnostic.map(str::to_owned),
        });
    }

    fn push_section_receipt(&mut self) {
        let partial = self.sections.invalid != 0;
        self.receipt(
            FunctionEvidenceSource::ExecutableSection,
            if partial {
                FunctionCollectorStatus::Partial
            } else {
                FunctionCollectorStatus::Complete
            },
            self.sections.examined,
            "sections",
            partial.then_some("executable_section_unmapped"),
        );
    }

    fn finish(mut self, image: FunctionImageIdentity) -> FunctionIndex {
        self.evidence.sort_by(|left, right| {
            (
                left.entry,
                left.source,
                &left.name,
                left.extent_start,
                left.end_exclusive,
                &left.detail,
            )
                .cmp(&(
                    right.entry,
                    right.source,
                    &right.name,
                    right.extent_start,
                    right.end_exclusive,
                    &right.detail,
                ))
        });
        self.evidence.dedup_by(|left, right| {
            left.entry == right.entry
                && left.source == right.source
                && left.name == right.name
                && left.extent_start == right.extent_start
                && left.end_exclusive == right.end_exclusive
                && left.source_location == right.source_location
                && left.detail == right.detail
        });

        let incomplete_sources = self
            .receipts
            .iter()
            .filter(|receipt| {
                !matches!(
                    receipt.status,
                    FunctionCollectorStatus::Complete | FunctionCollectorStatus::Absent
                )
            })
            .map(|receipt| receipt.source)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut grouped = BTreeMap::<u64, Vec<RawEvidence>>::new();
        for evidence in self.evidence {
            grouped.entry(evidence.entry).or_default().push(evidence);
        }
        let mut established_groups = BTreeMap::<u64, Vec<RawEvidence>>::new();
        let mut candidate_groups = BTreeMap::<u64, Vec<RawEvidence>>::new();
        let mut suppressed_groups = BTreeMap::<u64, ((u64, u64), Vec<RawEvidence>)>::new();
        for (entry, evidence) in grouped {
            if let Some(&range) = self
                .suppressed_code_ranges
                .iter()
                .find(|(start, end)| entry >= *start && entry < *end)
            {
                suppressed_groups.insert(entry, (range, evidence));
            } else if evidence
                .iter()
                .any(|observation| observation.source != FunctionEvidenceSource::DirectCall)
            {
                established_groups.insert(entry, evidence);
            } else {
                candidate_groups.insert(entry, evidence);
            }
        }
        let range_backed_entries = established_groups
            .iter()
            .flat_map(|(&owner, evidence)| {
                evidence.iter().filter_map(move |observation| {
                    let start = observation.extent_start?;
                    let end = observation.end_exclusive?;
                    (observation.confidence != FunctionEvidenceConfidence::Candidate)
                        .then_some((owner, start, end))
                })
            })
            .collect::<Vec<_>>();
        let alternate_entries = established_groups
            .iter()
            .filter_map(|(&entry, evidence)| {
                let has_body_range = evidence.iter().any(|observation| {
                    observation.extent_start.is_some() && observation.end_exclusive.is_some()
                });
                (!has_body_range
                    && range_backed_entries.iter().any(|(owner, start, end)| {
                        *owner != entry && entry >= *start && entry < *end
                    }))
                .then_some(entry)
            })
            .collect::<Vec<_>>();
        for entry in alternate_entries {
            if let Some(evidence) = established_groups.remove(&entry) {
                candidate_groups.entry(entry).or_default().extend(evidence);
            }
        }
        for &address in self
            .rejected_entries
            .iter()
            .chain(self.guided_relationships.keys())
        {
            if !established_groups.contains_key(&address)
                && !candidate_groups.contains_key(&address)
            {
                candidate_groups.insert(
                    address,
                    vec![RawEvidence {
                        source: FunctionEvidenceSource::CallerDecision,
                        confidence: FunctionEvidenceConfidence::Candidate,
                        entry: address,
                        extent_start: None,
                        end_exclusive: None,
                        name: None,
                        source_location: Some(address),
                        detail: "recovery_guide_function_candidate_disposition".into(),
                    }],
                );
            }
        }
        let distinct_count = established_groups.len();
        // Candidate adjacency bounds are evidence about the image, not retained-output
        // bookkeeping. Keep every independently established entry available while
        // reconciling admitted functions so `max_functions` cannot change the inferred
        // end of the last retained identity. A direct-call-only target is deliberately
        // excluded: it must not create a function or shorten another function's extent.
        let all_observed_entries = established_groups.keys().copied().collect::<Vec<_>>();
        let retained_groups = established_groups
            .into_iter()
            .take(self.limits.max_functions)
            .collect::<Vec<_>>();
        let truncated_function_count = distinct_count.saturating_sub(retained_groups.len()) as u64;
        let mut functions = retained_groups
            .into_iter()
            .map(|(entry, evidence)| {
                reconcile_function(
                    entry,
                    evidence,
                    &all_observed_entries,
                    &self.sections,
                    &incomplete_sources,
                )
            })
            .collect::<Vec<_>>();
        apply_guided_function_ranges(&mut functions, &self.guided_ranges);
        mark_overlaps(&mut functions);
        mark_caller_guided_range_overlaps(&mut functions);
        let shared_ranges = independently_shared_ranges(&functions);
        let candidate_ownership = build_candidate_ownership(&functions);
        let secondary_range_entries = secondary_range_entries(&functions);
        let entry_candidates = reconcile_entry_candidates(
            candidate_groups,
            EntryCandidateReconciliation {
                functions: &functions,
                ownership: &candidate_ownership,
                secondary_range_entries: &secondary_range_entries,
                sections: &self.sections,
                rejected_entries: &self.rejected_entries,
                guided_relationships: &self.guided_relationships,
                import_stubs: &self.import_stubs,
            },
        );
        let mut relationships = entry_candidates
            .iter()
            .filter(|candidate| {
                candidate.disposition == FunctionEntryCandidateDisposition::SecondaryRangeEntry
                    && candidate.possible_owners.len() == 1
            })
            .filter_map(|candidate| {
                let owner_entry = candidate.possible_owners[0].entry;
                let owner = functions
                    .iter()
                    .find(|function| function.entry == owner_entry)?;
                let mut evidence = candidate.evidence.clone();
                evidence.extend(
                    owner
                        .evidence
                        .iter()
                        .filter(|item| {
                            item.extent_start == Some(candidate.address)
                                && item
                                    .end_exclusive
                                    .is_some_and(|end| end > candidate.address)
                        })
                        .cloned(),
                );
                evidence.sort_by_key(|item| item.ordinal);
                evidence.dedup();
                Some(FunctionRelationship {
                    address: candidate.address,
                    owner_entry,
                    kind: FunctionRelationshipKind::ColdFragment,
                    authority: FunctionRecoveryAuthority::Independent,
                    evidence,
                })
            })
            .chain(
                entry_candidates
                    .iter()
                    .filter(|candidate| {
                        candidate.disposition
                            == FunctionEntryCandidateDisposition::InsideRecoveredExtent
                            && candidate.possible_owners.len() == 1
                            && candidate.evidence.iter().any(|evidence| {
                                !matches!(
                                    evidence.source,
                                    FunctionEvidenceSource::DirectCall
                                        | FunctionEvidenceSource::CallerDecision
                                )
                            })
                    })
                    .filter_map(|candidate| {
                        let owner_entry = candidate.possible_owners[0].entry;
                        let owner = functions
                            .iter()
                            .find(|function| function.entry == owner_entry)?;
                        let mut evidence = candidate.evidence.clone();
                        evidence.extend(
                            owner
                                .evidence
                                .iter()
                                .filter(|item| {
                                    item.confidence != FunctionEvidenceConfidence::Candidate
                                        && item.extent_start.is_some_and(|start| {
                                            candidate.address >= start
                                                && item
                                                    .end_exclusive
                                                    .is_some_and(|end| candidate.address < end)
                                        })
                                })
                                .cloned(),
                        );
                        evidence.sort_by_key(|item| item.ordinal);
                        evidence.dedup();
                        Some(FunctionRelationship {
                            address: candidate.address,
                            owner_entry,
                            kind: FunctionRelationshipKind::AlternateEntry,
                            authority: FunctionRecoveryAuthority::Independent,
                            evidence,
                        })
                    }),
            )
            .chain(entry_candidates.iter().filter_map(|candidate| {
                let &(owner_entry, kind) = self.guided_relationships.get(&candidate.address)?;
                functions
                    .iter()
                    .any(|function| function.entry == owner_entry)
                    .then_some(())?;
                Some(FunctionRelationship {
                    address: candidate.address,
                    owner_entry,
                    kind,
                    authority: FunctionRecoveryAuthority::CallerGuided,
                    evidence: candidate.evidence.clone(),
                })
            }))
            .collect::<Vec<_>>();
        relationships.sort_by_key(|relationship| (relationship.address, relationship.owner_entry));
        let ownership = build_ownership(&functions);
        let suppressed_entries = suppressed_groups
            .into_iter()
            .map(|(entry, ((range_start, range_end_exclusive), evidence))| {
                SuppressedFunctionEntry {
                    entry,
                    range_start,
                    range_end_exclusive,
                    evidence: evidence
                        .into_iter()
                        .enumerate()
                        .map(|(ordinal, evidence)| evidence.into_public(ordinal as u64))
                        .collect(),
                }
            })
            .collect();
        self.receipts.sort_by_key(|receipt| receipt.source);
        let inventory_complete = truncated_function_count == 0
            && incomplete_sources.is_empty()
            && self.name_truncated_sources.is_empty();
        let import_stubs = self.import_stubs.iter().copied().collect::<Vec<_>>();
        FunctionIndex {
            image,
            limits: self.limits,
            functions,
            entry_candidates,
            relationships,
            shared_ranges,
            import_stubs,
            suppressed_entries,
            receipts: self.receipts,
            inventory_complete,
            truncated_function_count,
            ownership,
        }
    }
}

struct EntryCandidateReconciliation<'a> {
    functions: &'a [RecoveredFunction],
    ownership: &'a [OwnershipSpan],
    secondary_range_entries: &'a BTreeSet<u64>,
    sections: &'a ExecutableSections,
    rejected_entries: &'a BTreeSet<u64>,
    guided_relationships: &'a BTreeMap<u64, (u64, FunctionRelationshipKind)>,
    import_stubs: &'a BTreeSet<u64>,
}

fn reconcile_entry_candidates(
    groups: BTreeMap<u64, Vec<RawEvidence>>,
    context: EntryCandidateReconciliation<'_>,
) -> Vec<FunctionEntryCandidate> {
    let EntryCandidateReconciliation {
        functions,
        ownership,
        secondary_range_entries,
        sections,
        rejected_entries,
        guided_relationships,
        import_stubs,
    } = context;
    groups
        .into_iter()
        .map(|(address, evidence)| {
            let executable = sections.containing(address).is_some();
            let mut possible_owners = if executable {
                candidate_owners(functions, ownership, address)
            } else {
                Vec::new()
            };
            possible_owners.sort_by_key(|owner| (owner.entry, owner.ownership_confidence));
            possible_owners.dedup();
            let secondary_range_entry = executable
                && possible_owners.len() == 1
                && secondary_range_entries.contains(&address);
            let (disposition, reason) = if guided_relationships.contains_key(&address) {
                (
                    FunctionEntryCandidateDisposition::ResolvedByCallerRelationship,
                    "recovery_guide_resolved_function_relationship",
                )
            } else if rejected_entries.contains(&address) {
                (
                    FunctionEntryCandidateDisposition::RejectedByCaller,
                    "recovery_guide_rejected_function_entry",
                )
            } else if import_stubs.contains(&address) {
                (
                    FunctionEntryCandidateDisposition::RejectedImportStub,
                    "direct_call_target_is_import_stub",
                )
            } else if !executable {
                (
                    FunctionEntryCandidateDisposition::RejectedNonExecutableTarget,
                    "direct_call_target_outside_executable_sections",
                )
            } else if possible_owners.len() > 1 {
                (
                    FunctionEntryCandidateDisposition::SharedOwnedRegion,
                    "direct_call_target_has_multiple_possible_owners",
                )
            } else if secondary_range_entry {
                (
                    FunctionEntryCandidateDisposition::SecondaryRangeEntry,
                    "direct_call_target_matches_secondary_extent_start",
                )
            } else if possible_owners.is_empty() {
                (
                    FunctionEntryCandidateDisposition::UnresolvedCallTarget,
                    "direct_call_target_has_no_recovered_owner",
                )
            } else {
                (
                    FunctionEntryCandidateDisposition::InsideRecoveredExtent,
                    "direct_call_target_inside_recovered_extent",
                )
            };
            FunctionEntryCandidate {
                address,
                disposition,
                reason: reason.into(),
                possible_owners,
                evidence: evidence
                    .into_iter()
                    .enumerate()
                    .map(|(ordinal, evidence)| evidence.into_public(ordinal as u64))
                    .collect(),
            }
        })
        .collect()
}

fn candidate_owners(
    functions: &[RecoveredFunction],
    ownership: &[OwnershipSpan],
    address: u64,
) -> Vec<FunctionEntryCandidateOwner> {
    let span_index = ownership.partition_point(|span| span.start <= address);
    span_index
        .checked_sub(1)
        .and_then(|index| ownership.get(index))
        .filter(|span| address < span.end)
        .map_or(&[][..], |span| span.owners.as_slice())
        .iter()
        .map(|&(function_index, confidence)| {
            let function = &functions[function_index];
            FunctionEntryCandidateOwner {
                entry: function.entry,
                ownership_confidence: if function.conflicts.is_empty() {
                    match confidence {
                        FunctionEvidenceConfidence::Exact => FunctionOwnershipConfidence::Exact,
                        FunctionEvidenceConfidence::Derived => FunctionOwnershipConfidence::Derived,
                        FunctionEvidenceConfidence::Candidate => {
                            FunctionOwnershipConfidence::Candidate
                        }
                    }
                } else {
                    FunctionOwnershipConfidence::Candidate
                },
            }
        })
        .collect()
}

fn secondary_range_entries(functions: &[RecoveredFunction]) -> BTreeSet<u64> {
    functions
        .iter()
        .flat_map(|function| {
            function.evidence.iter().filter_map(|evidence| {
                let start = evidence.extent_start?;
                (function.entry != start && evidence.end_exclusive.is_some_and(|end| end > start))
                    .then_some(start)
            })
        })
        .collect()
}

fn closed_control_flow_extent(
    graph: &FunctionControlFlow,
    function: &RecoveredFunction,
) -> Option<u64> {
    if matches!(
        graph.completeness.status,
        FunctionControlFlowStatus::Truncated | FunctionControlFlowStatus::Unavailable
    ) || graph.completeness.continuation.is_some()
        || graph
            .data_ranges
            .iter()
            .any(|range| range.reason == ControlFlowDataRangeReason::CallerGuided)
        || graph.blocks.is_empty()
        || graph.jump_tables.iter().any(|table| {
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
        })
    {
        return None;
    }

    let table_blocks = graph
        .jump_tables
        .iter()
        .filter(|table| {
            !table.truncated
                && table.range.is_some()
                && !table.entries.is_empty()
                && !table.reasons.iter().any(|reason| {
                    matches!(
                        reason.as_str(),
                        "jump_table.target_block_omitted"
                            | "jump_table.entry_budget"
                            | "jump_table.invalid_or_unreadable_entry"
                            | "jump_table.range_guard_block_omitted"
                            | "jump_table.range_check_unresolved"
                    )
                })
        })
        .map(|table| table.source_block)
        .collect::<BTreeSet<_>>();
    let mut end_exclusive = graph
        .blocks
        .iter()
        .filter(|block| block.reachability == ControlFlowReachability::Reachable)
        .map(|block| block.end_exclusive)
        .max()?;
    if let Some(candidate_end) = function.extent.map(|extent| extent.end_exclusive) {
        end_exclusive = end_exclusive.max(
            graph
                .data_ranges
                .iter()
                .filter(|range| {
                    range.reason == ControlFlowDataRangeReason::RecoveredJumpTable
                        && range.end_exclusive <= candidate_end
                })
                .map(|range| range.end_exclusive)
                .max()
                .unwrap_or(end_exclusive),
        );
    }
    if graph.function_entry >= end_exclusive
        || graph.gaps.iter().any(|gap| gap.start < end_exclusive)
        || graph.blocks.iter().any(|block| {
            block.start < end_exclusive && block.reachability == ControlFlowReachability::Unknown
        })
    {
        return None;
    }

    let block_reachability = graph
        .blocks
        .iter()
        .map(|block| (block.id, block.reachability))
        .collect::<BTreeMap<_, _>>();
    let decoded_start = graph
        .instructions
        .first()
        .map(|instruction| instruction.address)?;
    let decoded_end = graph
        .instructions
        .last()
        .map(|instruction| instruction.address + instruction.byte_len as u64)?;
    let candidate_end = function.extent.map(|extent| extent.end_exclusive)?;
    let mut recovered_data_ranges = graph
        .data_ranges
        .iter()
        .filter(|range| range.reason == ControlFlowDataRangeReason::RecoveredJumpTable)
        .map(|range| (range.start, range.end_exclusive))
        .collect::<Vec<_>>();
    recovered_data_ranges.sort_unstable();
    let exits_are_closed = graph.exits.iter().all(|exit| {
        if block_reachability.get(&exit.block) != Some(&ControlFlowReachability::Reachable) {
            return true;
        }
        match exit.kind {
            ControlFlowExitKind::Return
            | ControlFlowExitKind::NonReturningCall
            | ControlFlowExitKind::NonReturningTransfer
            | ControlFlowExitKind::ExceptionalUnwind => true,
            // A direct target outside the completely decoded candidate range is
            // a mechanically established tail exit even when the destination
            // has no recovered identity. An interior non-block target could be
            // an alternative instruction boundary and therefore stays open.
            ControlFlowExitKind::DirectBranch => exit
                .target
                .is_some_and(|target| target < decoded_start || target >= decoded_end),
            ControlFlowExitKind::JumpTableDispatch => table_blocks.contains(&exit.block),
            ControlFlowExitKind::TailDispatch => true,
            ControlFlowExitKind::RangeBoundary
            | ControlFlowExitKind::FallthroughOutsideCoverage => graph
                .blocks
                .iter()
                .find(|block| block.id == exit.block)
                .is_some_and(|block| {
                    contiguous_ranges_cover(
                        block.end_exclusive,
                        candidate_end,
                        &recovered_data_ranges,
                    )
                }),
            ControlFlowExitKind::IndirectBranch => false,
        }
    });
    exits_are_closed.then_some(end_exclusive)
}

fn contiguous_ranges_cover(start: u64, end_exclusive: u64, ranges: &[(u64, u64)]) -> bool {
    if start >= end_exclusive {
        return false;
    }
    let mut cursor = start;
    for &(range_start, range_end) in ranges {
        if range_end <= cursor {
            continue;
        }
        if range_start != cursor || range_end <= range_start || range_end > end_exclusive {
            return false;
        }
        cursor = range_end;
        if cursor == end_exclusive {
            return true;
        }
    }
    false
}

fn refresh_entry_candidate_ownership(
    candidates: &mut [FunctionEntryCandidate],
    functions: &[RecoveredFunction],
) {
    let ownership = build_candidate_ownership(functions);
    let secondary_range_entries = secondary_range_entries(functions);
    for candidate in candidates {
        if matches!(
            candidate.disposition,
            FunctionEntryCandidateDisposition::RejectedByCaller
                | FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
                | FunctionEntryCandidateDisposition::RejectedRecoveredData
                | FunctionEntryCandidateDisposition::RejectedImportStub
                | FunctionEntryCandidateDisposition::RejectedAlternativeInterpretation
                | FunctionEntryCandidateDisposition::ResolvedByCallerRelationship
        ) {
            continue;
        }
        let mut owners = candidate_owners(functions, &ownership, candidate.address);
        owners.sort_by_key(|owner| (owner.entry, owner.ownership_confidence));
        owners.dedup();
        let secondary_range_entry =
            owners.len() == 1 && secondary_range_entries.contains(&candidate.address);
        (candidate.disposition, candidate.reason) = if owners.len() > 1 {
            (
                FunctionEntryCandidateDisposition::SharedOwnedRegion,
                "direct_call_target_has_multiple_possible_owners".into(),
            )
        } else if secondary_range_entry {
            (
                FunctionEntryCandidateDisposition::SecondaryRangeEntry,
                "direct_call_target_matches_secondary_extent_start".into(),
            )
        } else if owners.is_empty() {
            (
                FunctionEntryCandidateDisposition::UnresolvedCallTarget,
                "direct_call_target_has_no_recovered_owner".into(),
            )
        } else {
            (
                FunctionEntryCandidateDisposition::InsideRecoveredExtent,
                "direct_call_target_inside_recovered_extent".into(),
            )
        };
        candidate.possible_owners = owners;
    }
}

fn build_ownership(functions: &[RecoveredFunction]) -> Vec<OwnershipSpan> {
    let mut intervals = BTreeMap::<(u64, u64, usize), FunctionEvidenceConfidence>::new();
    for (function_index, function) in functions.iter().enumerate() {
        if !function.caller_guided_ranges.is_empty() {
            for extent in &function.caller_guided_ranges {
                intervals
                    .entry((extent.start, extent.end_exclusive, function_index))
                    .and_modify(|confidence| *confidence = (*confidence).max(extent.confidence))
                    .or_insert(extent.confidence);
            }
            continue;
        }
        if let Some(extent) = function.extent {
            intervals
                .entry((extent.start, extent.end_exclusive, function_index))
                .and_modify(|confidence| *confidence = (*confidence).max(extent.confidence))
                .or_insert(extent.confidence);
        }
        for evidence in &function.evidence {
            if function.completeness.extent_is_authoritative
                && evidence.confidence == FunctionEvidenceConfidence::Candidate
            {
                continue;
            }
            let (Some(start), Some(end)) = (evidence.extent_start, evidence.end_exclusive) else {
                continue;
            };
            if end <= start {
                continue;
            }
            intervals
                .entry((start, end, function_index))
                .and_modify(|confidence| *confidence = (*confidence).max(evidence.confidence))
                .or_insert(evidence.confidence);
        }
    }
    build_ownership_spans(intervals)
}

fn build_candidate_ownership(functions: &[RecoveredFunction]) -> Vec<OwnershipSpan> {
    let mut intervals = BTreeMap::<(u64, u64, usize), FunctionEvidenceConfidence>::new();
    for (function_index, function) in functions.iter().enumerate() {
        if let Some(extent) = function.extent {
            intervals
                .entry((extent.start, extent.end_exclusive, function_index))
                .and_modify(|confidence| *confidence = (*confidence).max(extent.confidence))
                .or_insert(extent.confidence);
        }
        for evidence in &function.evidence {
            if function.completeness.extent_is_authoritative
                && evidence.confidence == FunctionEvidenceConfidence::Candidate
            {
                continue;
            }
            let (Some(start), Some(end)) = (evidence.extent_start, evidence.end_exclusive) else {
                continue;
            };
            if end <= start {
                continue;
            }
            intervals
                .entry((start, end, function_index))
                .and_modify(|confidence| *confidence = (*confidence).max(evidence.confidence))
                .or_insert(evidence.confidence);
        }
    }
    build_ownership_spans(intervals)
}

fn build_ownership_spans(
    intervals: BTreeMap<(u64, u64, usize), FunctionEvidenceConfidence>,
) -> Vec<OwnershipSpan> {
    let mut events = Vec::with_capacity(intervals.len().saturating_mul(2));
    for ((start, end, function_index), confidence) in intervals {
        events.push(OwnershipEvent {
            position: start,
            starts: true,
            function_index,
            confidence,
        });
        events.push(OwnershipEvent {
            position: end,
            starts: false,
            function_index,
            confidence,
        });
    }
    events.sort();
    let mut result = Vec::<OwnershipSpan>::new();
    let mut active = BTreeMap::<(usize, FunctionEvidenceConfidence), usize>::new();
    let mut cursor = events.first().map_or(0, |event| event.position);
    let mut event_index = 0;
    while event_index < events.len() {
        let position = events[event_index].position;
        if cursor < position && !active.is_empty() {
            let mut owners = BTreeMap::<usize, FunctionEvidenceConfidence>::new();
            for &(function_index, confidence) in active.keys() {
                owners
                    .entry(function_index)
                    .and_modify(|current| *current = (*current).max(confidence))
                    .or_insert(confidence);
            }
            let owners = owners.into_iter().collect::<Vec<_>>();
            if let Some(previous) = result.last_mut()
                && previous.end == cursor
                && previous.owners == owners
            {
                previous.end = position;
            } else {
                result.push(OwnershipSpan {
                    start: cursor,
                    end: position,
                    owners,
                });
            }
        }
        while event_index < events.len()
            && events[event_index].position == position
            && !events[event_index].starts
        {
            let key = (
                events[event_index].function_index,
                events[event_index].confidence,
            );
            if let Some(count) = active.get_mut(&key) {
                *count -= 1;
                if *count == 0 {
                    active.remove(&key);
                }
            }
            event_index += 1;
        }
        while event_index < events.len()
            && events[event_index].position == position
            && events[event_index].starts
        {
            *active
                .entry((
                    events[event_index].function_index,
                    events[event_index].confidence,
                ))
                .or_default() += 1;
            event_index += 1;
        }
        cursor = position;
    }
    result
}

fn reconcile_function(
    entry: u64,
    raw: Vec<RawEvidence>,
    entries: &[u64],
    sections: &ExecutableSections,
    incomplete_sources: &[FunctionEvidenceSource],
) -> RecoveredFunction {
    let authority = if raw
        .iter()
        .any(|evidence| evidence.source == FunctionEvidenceSource::CallerDecision)
    {
        FunctionRecoveryAuthority::CallerGuided
    } else {
        FunctionRecoveryAuthority::Independent
    };
    let entry_confidence = raw
        .iter()
        .map(|evidence| evidence.confidence)
        .max()
        .unwrap_or(FunctionEvidenceConfidence::Candidate);
    let mut ranked_names = raw
        .iter()
        .filter_map(|evidence| {
            evidence
                .name
                .as_ref()
                .map(|name| (name_rank(evidence.source), evidence.source, name.clone()))
        })
        .collect::<Vec<_>>();
    ranked_names.sort();
    ranked_names.dedup_by(|left, right| left.2 == right.2);
    let identity = if let Some((_, _, primary)) = ranked_names.first() {
        FunctionIdentity::Named {
            primary: primary.clone(),
            aliases: ranked_names
                .iter()
                .skip(1)
                .map(|(_, _, name)| name.clone())
                .collect(),
        }
    } else {
        FunctionIdentity::Anonymous {
            id: format!("sub_{entry:016x}"),
        }
    };

    let mut conflicts = Vec::new();
    let mut bounds = raw
        .iter()
        .filter_map(|evidence| {
            (evidence.extent_start == Some(entry))
                .then_some(evidence.end_exclusive)
                .flatten()
                .map(|end| (evidence.confidence, end, evidence.source))
        })
        .filter(|(_, end, _)| *end > entry)
        .collect::<Vec<_>>();
    bounds.sort();
    let authoritative = bounds
        .iter()
        .filter(|(confidence, _, _)| *confidence != FunctionEvidenceConfidence::Candidate)
        .copied()
        .collect::<Vec<_>>();
    let distinct_authoritative = authoritative
        .iter()
        .map(|(_, end, _)| *end)
        .collect::<BTreeSet<_>>();
    if distinct_authoritative.len() > 1 {
        let claims = authoritative
            .iter()
            .map(|(_, end, source)| FunctionConflictClaim {
                source: *source,
                field: FunctionConflictField::ExtentEndExclusive,
                value: *end,
            })
            .collect();
        conflicts.push(FunctionConflict {
            kind: FunctionConflictKind::ExtentEndDisagreement,
            values: distinct_authoritative.iter().copied().collect(),
            sources: authoritative
                .iter()
                .map(|(_, _, source)| *source)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            claims,
        });
    }
    let section = sections.containing(entry);
    let outside = raw
        .iter()
        .filter(|evidence| evidence.confidence != FunctionEvidenceConfidence::Candidate)
        .filter_map(|evidence| {
            Some((
                evidence.extent_start?,
                evidence.end_exclusive?,
                evidence.source,
            ))
        })
        .filter(|(start, end, _)| {
            sections
                .containing(*start)
                .is_none_or(|span| *end > span.end)
        })
        .collect::<Vec<_>>();
    if !outside.is_empty() {
        let claims = outside
            .iter()
            .flat_map(|(start, end, source)| {
                [
                    FunctionConflictClaim {
                        source: *source,
                        field: FunctionConflictField::ExtentStart,
                        value: *start,
                    },
                    FunctionConflictClaim {
                        source: *source,
                        field: FunctionConflictField::ExtentEndExclusive,
                        value: *end,
                    },
                ]
            })
            .collect();
        conflicts.push(FunctionConflict {
            kind: FunctionConflictKind::ExtentOutsideExecutableSection,
            values: outside
                .iter()
                .flat_map(|(start, end, _)| [*start, *end])
                .collect(),
            sources: outside
                .iter()
                .map(|(_, _, source)| *source)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
            claims,
        });
    }

    let selected_authoritative = authoritative
        .iter()
        .min_by_key(|(confidence, end, source)| (*end, *confidence, *source))
        .copied();
    let (extent, candidate_bound) =
        if let Some((confidence, authoritative_end, _)) = selected_authoritative {
            let end = section.map_or(authoritative_end, |span| authoritative_end.min(span.end));
            let confidence = if end != authoritative_end || distinct_authoritative.len() > 1 {
                FunctionEvidenceConfidence::Derived
            } else {
                confidence
            };
            (
                Some(FunctionExtent {
                    start: entry,
                    end_exclusive: end,
                    confidence,
                }),
                None,
            )
        } else {
            let next = entries
                .get(entries.partition_point(|candidate| *candidate <= entry))
                .copied()
                .filter(|next| section.is_some_and(|span| *next < span.end));
            let candidate = next.or_else(|| section.map(|span| span.end));
            (
                candidate.map(|end| FunctionExtent {
                    start: entry,
                    end_exclusive: end,
                    confidence: FunctionEvidenceConfidence::Candidate,
                }),
                candidate,
            )
        };

    let mut evidence = raw
        .into_iter()
        .enumerate()
        .map(|(ordinal, evidence)| evidence.into_public(ordinal as u64))
        .collect::<Vec<_>>();
    if let Some(end) = candidate_bound {
        evidence.push(FunctionEvidence {
            ordinal: evidence.len() as u64,
            source: FunctionEvidenceSource::ExecutableSection,
            roles: vec![FunctionEvidenceRole::CandidateUpperBound],
            confidence: FunctionEvidenceConfidence::Candidate,
            entry,
            extent_start: Some(entry),
            end_exclusive: Some(end),
            name: None,
            source_location: None,
            detail: if entries.binary_search(&end).is_ok() {
                "next_recovered_entry".into()
            } else {
                "executable_section_end".into()
            },
        });
    }
    let extent_is_authoritative = extent.is_some_and(|extent| {
        extent.confidence != FunctionEvidenceConfidence::Candidate && conflicts.is_empty()
    });
    RecoveredFunction {
        entry,
        entry_confidence,
        authority,
        identity,
        extent,
        caller_guided_ranges: Vec::new(),
        evidence,
        conflicts,
        completeness: FunctionCompleteness {
            locally_complete: incomplete_sources.is_empty(),
            incomplete_sources: incomplete_sources.to_vec(),
            extent_is_authoritative,
        },
    }
}

fn apply_guided_function_ranges(
    functions: &mut [RecoveredFunction],
    guided_ranges: &BTreeMap<u64, Vec<(u64, u64)>>,
) {
    for function in functions {
        let Some(ranges) = guided_ranges.get(&function.entry) else {
            continue;
        };
        function.authority = FunctionRecoveryAuthority::CallerGuided;
        let Some(&(start, end_exclusive)) = ranges
            .iter()
            .find(|(start, end_exclusive)| *start == function.entry && end_exclusive > start)
        else {
            continue;
        };

        let independent_ends = function
            .evidence
            .iter()
            .filter(|evidence| evidence.source != FunctionEvidenceSource::CallerDecision)
            .filter(|evidence| evidence.confidence != FunctionEvidenceConfidence::Candidate)
            .filter(|evidence| evidence.extent_start == Some(function.entry))
            .filter_map(|evidence| {
                evidence
                    .end_exclusive
                    .filter(|independent_end| *independent_end != end_exclusive)
                    .map(|independent_end| (evidence.source, independent_end))
            })
            .collect::<Vec<_>>();
        if !independent_ends.is_empty() {
            let mut values = independent_ends
                .iter()
                .map(|(_, end)| *end)
                .chain([end_exclusive])
                .collect::<Vec<_>>();
            values.sort_unstable();
            values.dedup();
            let mut sources = independent_ends
                .iter()
                .map(|(source, _)| *source)
                .chain([FunctionEvidenceSource::CallerDecision])
                .collect::<Vec<_>>();
            sources.sort_unstable();
            sources.dedup();
            let mut claims = independent_ends
                .iter()
                .map(|(source, end)| FunctionConflictClaim {
                    source: *source,
                    field: FunctionConflictField::ExtentEndExclusive,
                    value: *end,
                })
                .collect::<Vec<_>>();
            claims.push(FunctionConflictClaim {
                source: FunctionEvidenceSource::CallerDecision,
                field: FunctionConflictField::ExtentEndExclusive,
                value: end_exclusive,
            });
            claims.sort();
            claims.dedup();
            function.conflicts.push(FunctionConflict {
                kind: FunctionConflictKind::CallerGuidedExtentDisagreement,
                values,
                sources,
                claims,
            });
        }

        function.extent = Some(FunctionExtent {
            start,
            end_exclusive,
            confidence: FunctionEvidenceConfidence::Candidate,
        });
        function.caller_guided_ranges = ranges
            .iter()
            .map(|(start, end_exclusive)| FunctionExtent {
                start: *start,
                end_exclusive: *end_exclusive,
                confidence: FunctionEvidenceConfidence::Candidate,
            })
            .collect();
        function.completeness.extent_is_authoritative = false;
    }
}

const fn name_rank(source: FunctionEvidenceSource) -> u8 {
    match source {
        FunctionEvidenceSource::Dwarf => 0,
        FunctionEvidenceSource::ObjectiveC => 1,
        FunctionEvidenceSource::Nlist => 2,
        FunctionEvidenceSource::ExportTrie => 3,
        _ => 4,
    }
}

fn mark_overlaps(functions: &mut [RecoveredFunction]) {
    let shared = independently_shared_ranges(functions)
        .into_iter()
        .map(|range| {
            (
                range.start,
                range.end_exclusive,
                range.owners.into_iter().collect::<BTreeSet<_>>(),
            )
        })
        .collect::<Vec<_>>();
    for left_index in 0..functions.len() {
        let Some(left_extent) = functions[left_index].extent else {
            continue;
        };
        if left_extent.confidence == FunctionEvidenceConfidence::Candidate
            && functions[left_index].authority != FunctionRecoveryAuthority::CallerGuided
        {
            continue;
        }
        let mut right_index = left_index + 1;
        while right_index < functions.len()
            && functions[right_index].entry < left_extent.end_exclusive
        {
            if functions[right_index].entry_confidence == FunctionEvidenceConfidence::Exact
                || functions[right_index].authority == FunctionRecoveryAuthority::CallerGuided
            {
                let mut claims = authoritative_extent_claims(&functions[left_index]);
                claims.extend(exact_entry_claims(&functions[right_index]));
                claims.sort();
                claims.dedup();
                let conflict = FunctionConflict {
                    kind: if functions[left_index].authority
                        == FunctionRecoveryAuthority::CallerGuided
                        || functions[right_index].authority
                            == FunctionRecoveryAuthority::CallerGuided
                    {
                        FunctionConflictKind::CallerGuidedRangeOverlap
                    } else {
                        FunctionConflictKind::AuthoritativeExtentContainsEntry
                    },
                    values: vec![left_extent.end_exclusive, functions[right_index].entry],
                    sources: authoritative_sources(&functions[left_index])
                        .into_iter()
                        .chain(exact_entry_sources(&functions[right_index]))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    claims,
                };
                functions[left_index].conflicts.push(conflict.clone());
                functions[right_index].conflicts.push(conflict);
                functions[left_index].completeness.extent_is_authoritative = false;
                functions[right_index].completeness.extent_is_authoritative = false;
            }
            let Some(right_extent) = functions[right_index].extent else {
                right_index += 1;
                continue;
            };
            if right_extent.confidence != FunctionEvidenceConfidence::Candidate
                || functions[right_index].authority == FunctionRecoveryAuthority::CallerGuided
            {
                let overlap_start = left_extent.start.max(right_extent.start);
                let overlap_end = left_extent.end_exclusive.min(right_extent.end_exclusive);
                let independently_shared = shared.iter().any(|(start, end, owners)| {
                    *start == overlap_start
                        && *end == overlap_end
                        && owners.contains(&functions[left_index].entry)
                        && owners.contains(&functions[right_index].entry)
                });
                if independently_shared {
                    right_index += 1;
                    continue;
                }
                let values = vec![left_extent.end_exclusive, right_extent.end_exclusive];
                let sources = authoritative_sources(&functions[left_index])
                    .into_iter()
                    .chain(authoritative_sources(&functions[right_index]))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let mut claims = authoritative_extent_claims(&functions[left_index]);
                claims.extend(authoritative_extent_claims(&functions[right_index]));
                claims.sort();
                claims.dedup();
                let conflict = FunctionConflict {
                    kind: if functions[left_index].authority
                        == FunctionRecoveryAuthority::CallerGuided
                        || functions[right_index].authority
                            == FunctionRecoveryAuthority::CallerGuided
                    {
                        FunctionConflictKind::CallerGuidedRangeOverlap
                    } else {
                        FunctionConflictKind::AuthoritativeExtentOverlap
                    },
                    values,
                    sources,
                    claims,
                };
                functions[left_index].conflicts.push(conflict.clone());
                functions[right_index].conflicts.push(conflict);
                functions[left_index].completeness.extent_is_authoritative = false;
                functions[right_index].completeness.extent_is_authoritative = false;
            }
            right_index += 1;
        }
    }
}

fn independently_shared_ranges(functions: &[RecoveredFunction]) -> Vec<FunctionSharedRange> {
    let mut claims = BTreeMap::<(u64, u64), Vec<(u64, FunctionEvidence)>>::new();
    for function in functions {
        if function.authority != FunctionRecoveryAuthority::Independent {
            continue;
        }
        for evidence in &function.evidence {
            let (Some(start), Some(end_exclusive)) =
                (evidence.extent_start, evidence.end_exclusive)
            else {
                continue;
            };
            if end_exclusive <= start
                || evidence.confidence == FunctionEvidenceConfidence::Candidate
                || evidence.source == FunctionEvidenceSource::ExecutableSection
            {
                continue;
            }
            claims
                .entry((start, end_exclusive))
                .or_default()
                .push((function.entry, evidence.clone()));
        }
    }
    let mut ranges = claims
        .into_iter()
        .filter_map(|((start, end_exclusive), mut claims)| {
            claims.sort_by_key(|(owner, evidence)| (*owner, evidence.ordinal));
            claims.dedup();
            let owners = claims
                .iter()
                .map(|(owner, _)| *owner)
                .collect::<BTreeSet<_>>();
            (owners.len() > 1).then(|| FunctionSharedRange {
                start,
                end_exclusive,
                owners: owners.into_iter().collect(),
                confidence: claims
                    .iter()
                    .map(|(_, evidence)| evidence.confidence)
                    .min()
                    .unwrap_or(FunctionEvidenceConfidence::Derived),
                evidence: claims.into_iter().map(|(_, evidence)| evidence).collect(),
            })
        })
        .collect::<Vec<_>>();
    ranges.sort_by_key(|range| (range.start, range.end_exclusive, range.owners.clone()));
    ranges
}

fn mark_caller_guided_range_overlaps(functions: &mut [RecoveredFunction]) {
    let mut ranges = functions
        .iter()
        .enumerate()
        .flat_map(|(owner, function)| {
            let caller_guided = !function.caller_guided_ranges.is_empty();
            active_conflict_ranges(function)
                .into_iter()
                .filter(|range| range.start < range.end_exclusive)
                .map(move |range| (range.start, range.end_exclusive, owner, caller_guided))
        })
        .collect::<Vec<_>>();
    ranges.sort_unstable();

    let mut overlaps = BTreeSet::new();
    for left_range_index in 0..ranges.len() {
        let (left_start, left_end, left_owner, left_guided) = ranges[left_range_index];
        for &(right_start, right_end, right_owner, right_guided) in &ranges[left_range_index + 1..]
        {
            if right_start >= left_end {
                break;
            }
            if left_owner == right_owner || (!left_guided && !right_guided) {
                continue;
            }
            let overlap_start = left_start.max(right_start);
            let overlap_end = left_end.min(right_end);
            if overlap_start < overlap_end {
                let (left_owner, right_owner) = if left_owner < right_owner {
                    (left_owner, right_owner)
                } else {
                    (right_owner, left_owner)
                };
                overlaps.insert((left_owner, right_owner, overlap_start, overlap_end));
            }
        }
    }

    for (left_index, right_index, overlap_start, overlap_end) in overlaps {
        let values = vec![overlap_start, overlap_end];
        if functions[left_index].conflicts.iter().any(|conflict| {
            conflict.kind == FunctionConflictKind::CallerGuidedRangeOverlap
                && conflict.values == values
        }) {
            continue;
        }
        let mut sources = authoritative_sources(&functions[left_index])
            .into_iter()
            .chain(authoritative_sources(&functions[right_index]))
            .collect::<Vec<_>>();
        sources.sort_unstable();
        sources.dedup();
        let mut claims = authoritative_extent_claims(&functions[left_index]);
        claims.extend(authoritative_extent_claims(&functions[right_index]));
        claims.sort();
        claims.dedup();
        let conflict = FunctionConflict {
            kind: FunctionConflictKind::CallerGuidedRangeOverlap,
            values,
            sources,
            claims,
        };
        functions[left_index].conflicts.push(conflict.clone());
        functions[right_index].conflicts.push(conflict);
        functions[left_index].completeness.extent_is_authoritative = false;
        functions[right_index].completeness.extent_is_authoritative = false;
    }
}

fn active_conflict_ranges(function: &RecoveredFunction) -> Vec<FunctionExtent> {
    if !function.caller_guided_ranges.is_empty() {
        return function.caller_guided_ranges.clone();
    }
    function
        .extent
        .filter(|extent| extent.confidence != FunctionEvidenceConfidence::Candidate)
        .into_iter()
        .collect()
}

fn authoritative_sources(function: &RecoveredFunction) -> Vec<FunctionEvidenceSource> {
    function
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.end_exclusive.is_some()
                && (evidence.confidence != FunctionEvidenceConfidence::Candidate
                    || evidence.source == FunctionEvidenceSource::CallerDecision)
        })
        .map(|evidence| evidence.source)
        .collect()
}

fn exact_entry_sources(function: &RecoveredFunction) -> Vec<FunctionEvidenceSource> {
    function
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.confidence == FunctionEvidenceConfidence::Exact
                || evidence.source == FunctionEvidenceSource::CallerDecision
        })
        .map(|evidence| evidence.source)
        .collect()
}

fn authoritative_extent_claims(function: &RecoveredFunction) -> Vec<FunctionConflictClaim> {
    function
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.confidence != FunctionEvidenceConfidence::Candidate
                || evidence.source == FunctionEvidenceSource::CallerDecision
        })
        .filter_map(|evidence| {
            Some([
                FunctionConflictClaim {
                    source: evidence.source,
                    field: FunctionConflictField::ExtentStart,
                    value: evidence.extent_start?,
                },
                FunctionConflictClaim {
                    source: evidence.source,
                    field: FunctionConflictField::ExtentEndExclusive,
                    value: evidence.end_exclusive?,
                },
            ])
        })
        .flatten()
        .collect()
}

fn exact_entry_claims(function: &RecoveredFunction) -> Vec<FunctionConflictClaim> {
    function
        .evidence
        .iter()
        .filter(|evidence| evidence.confidence == FunctionEvidenceConfidence::Exact)
        .map(|evidence| FunctionConflictClaim {
            source: evidence.source,
            field: FunctionConflictField::Entry,
            value: evidence.entry,
        })
        .collect()
}

fn collect_function_starts(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::FunctionStarts;
    let Some(data) = macho
        .load_commands()
        .iter()
        .find_map(|command| match command.kind() {
            LoadCommand::FunctionStarts(data) => Some(data),
            _ => None,
        })
    else {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "entries", None);
        return;
    };
    let bytes = match macho.read_bytes_at(
        ThinFileOffset(data.data_offset as u64),
        data.data_size as usize,
    ) {
        Ok(bytes) => bytes,
        Err(_) => {
            context.receipt(
                source,
                FunctionCollectorStatus::Failed,
                0,
                "entries",
                Some("function_starts_bounds"),
            );
            return;
        }
    };
    let mut reader = crate::metadata::dyld::uleb::LebReader::new(bytes);
    let mut address = macho.image_base().0;
    let mut examined = 0_u64;
    let mut status = FunctionCollectorStatus::Complete;
    while !reader.is_empty() {
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            status = FunctionCollectorStatus::Truncated;
            break;
        }
        let encoded_offset = u64::from(data.data_offset).saturating_add(reader.pos() as u64);
        let delta = match reader.read_uleb128() {
            Ok(delta) => delta,
            Err(_) => {
                status = FunctionCollectorStatus::Failed;
                break;
            }
        };
        if delta == 0 {
            break;
        }
        examined += 1;
        let Some(next) = address.checked_add(delta) else {
            status = FunctionCollectorStatus::Failed;
            break;
        };
        address = next;
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: address,
            extent_start: None,
            end_exclusive: None,
            name: None,
            source_location: Some(encoded_offset),
            detail: "lc_function_starts_delta".into(),
        });
    }
    let diagnostic = match status {
        FunctionCollectorStatus::Truncated => Some("function_starts_budget"),
        FunctionCollectorStatus::Failed => Some("function_starts_malformed"),
        _ => None,
    };
    context.receipt(source, status, examined, "entries", diagnostic);
}

fn collect_function_starts_outcome(
    outcome: &Result<FunctionStartsOutcome, String>,
    context: &mut CollectionContext,
) {
    let source = FunctionEvidenceSource::FunctionStarts;
    let (starts, status, examined, diagnostic) = match outcome {
        Ok(FunctionStartsOutcome::Absent) => {
            context.receipt(source, FunctionCollectorStatus::Absent, 0, "entries", None);
            return;
        }
        Ok(FunctionStartsOutcome::Complete(starts)) => (
            starts.as_slice(),
            FunctionCollectorStatus::Complete,
            starts.len() as u64,
            None,
        ),
        Ok(FunctionStartsOutcome::Truncated {
            starts,
            continuation,
        }) => (
            starts.as_slice(),
            FunctionCollectorStatus::Truncated,
            continuation.decoded_count,
            Some("function_starts_budget"),
        ),
        Err(_) => {
            context.receipt(
                source,
                FunctionCollectorStatus::Failed,
                0,
                "entries",
                Some("function_starts_malformed"),
            );
            return;
        }
    };
    for start in starts {
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: start.address.0,
            extent_start: None,
            end_exclusive: None,
            name: None,
            source_location: Some(start.encoded_offset.0),
            detail: "lc_function_starts_delta".into(),
        });
    }
    context.receipt(source, status, examined, "entries", diagnostic);
}

fn collect_nlist(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::Nlist;
    if !macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::Symtab(_)))
    {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "symbols", None);
        return;
    }
    let mut examined = 0_u64;
    let mut limited = false;
    let result = crate::core::format::fold_symbols(macho, (), |_, symbol| {
        examined += 1;
        if symbol.sym_type != SymbolType::Section
            || (symbol.value == 0
                && macho.header().file_type() != crate::core::model::header::FileType::Object)
        {
            return Ok(());
        }
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            limited = true;
            return Err(crate::core::ParseError::limit(
                "function-index nlist budget",
            ));
        }
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Candidate,
            entry: symbol.value,
            extent_start: None,
            end_exclusive: None,
            name: (!symbol.name.is_empty()).then(|| symbol.name.to_owned()),
            source_location: Some(symbol.index as u64),
            detail: if symbol.is_alt_entry() {
                "nlist_alt_entry".into()
            } else {
                "nlist_section_symbol".into()
            },
        });
        Ok(())
    });
    let (status, diagnostic) = if limited {
        (FunctionCollectorStatus::Truncated, Some("nlist_budget"))
    } else if result.is_err() {
        (FunctionCollectorStatus::Failed, Some("nlist_malformed"))
    } else {
        (FunctionCollectorStatus::Complete, None)
    };
    context.receipt(source, status, examined, "symbols", diagnostic);
}

fn collect_exports(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::ExportTrie;
    let has_exports = macho
        .load_commands()
        .iter()
        .any(|command| match command.kind() {
            LoadCommand::DyldExportsTrie(data) => data.data_size > 0,
            LoadCommand::DyldInfo(data) | LoadCommand::DyldInfoOnly(data) => data.export_size > 0,
            _ => false,
        });
    if !has_exports {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "exports", None);
        return;
    }
    let mut examined = 0_u64;
    let mut limited = false;
    let result = crate::metadata::dyld::fold_exports(macho, (), |_, export| {
        examined += 1;
        let relative = match export.kind {
            ExportKind::Regular { address } | ExportKind::ThreadLocal { address } => address,
            _ => return Ok(()),
        };
        let Some(entry) = macho.image_base().0.checked_add(relative) else {
            return Err(crate::metadata::dyld::DyldError::address(
                "export address overflow",
            ));
        };
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            limited = true;
            return Err(crate::metadata::dyld::DyldError::unsupported(
                "function-index export budget",
            ));
        }
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Candidate,
            entry,
            extent_start: None,
            end_exclusive: None,
            name: Some(export.name),
            source_location: None,
            detail: "export_trie_address".into(),
        });
        Ok(())
    });
    let (status, diagnostic) = if limited {
        (FunctionCollectorStatus::Truncated, Some("export_budget"))
    } else if result.is_err() {
        (FunctionCollectorStatus::Failed, Some("export_malformed"))
    } else {
        (FunctionCollectorStatus::Complete, None)
    };
    context.receipt(source, status, examined, "exports", diagnostic);
}

fn collect_symbol_index(
    macho: &MachoFile<'_>,
    index: &SymbolInventory,
    context: &mut CollectionContext,
) {
    for (evidence_source, function_source, unit) in [
        (
            SymbolEvidenceSource::Nlist,
            FunctionEvidenceSource::Nlist,
            "symbols",
        ),
        (
            SymbolEvidenceSource::ExportTrie,
            FunctionEvidenceSource::ExportTrie,
            "exports",
        ),
    ] {
        let receipt = index
            .receipts()
            .iter()
            .find(|receipt| receipt.source == evidence_source);
        let (mut status, examined, diagnostic) =
            receipt.map_or((FunctionCollectorStatus::Absent, 0, None), |receipt| {
                (
                    match receipt.status {
                        SymbolCollectorStatus::Absent => FunctionCollectorStatus::Absent,
                        SymbolCollectorStatus::Complete => FunctionCollectorStatus::Complete,
                        SymbolCollectorStatus::Failed => FunctionCollectorStatus::Failed,
                        SymbolCollectorStatus::Truncated => FunctionCollectorStatus::Truncated,
                    },
                    receipt.examined,
                    receipt.diagnostic.as_deref(),
                )
            });
        for symbol in index
            .symbols()
            .iter()
            .filter(|symbol| symbol.source == evidence_source)
        {
            let admissible = match &symbol.kind {
                RecoveredSymbolKind::Nlist { symbol_type, .. } => {
                    *symbol_type == NlistSymbolKind::Section
                        && (symbol.address != Some(0)
                            || macho.header().file_type()
                                == crate::core::model::header::FileType::Object)
                }
                RecoveredSymbolKind::ExportRegular | RecoveredSymbolKind::ExportThreadLocal => {
                    symbol.address.is_some()
                }
                _ => false,
            };
            if !admissible {
                continue;
            }
            if context.retained(function_source) as usize >= context.limits.max_evidence_per_source
            {
                status = FunctionCollectorStatus::Truncated;
                break;
            }
            let Some(entry) = symbol.address else {
                continue;
            };
            context.admit(RawEvidence {
                source: function_source,
                confidence: FunctionEvidenceConfidence::Candidate,
                entry,
                extent_start: None,
                end_exclusive: None,
                name: (!symbol.name.is_empty()).then(|| symbol.name.clone()),
                source_location: (evidence_source == SymbolEvidenceSource::Nlist)
                    .then_some(symbol.ordinal),
                detail: match evidence_source {
                    SymbolEvidenceSource::Nlist if symbol.alternate_entry => "nlist_alt_entry",
                    SymbolEvidenceSource::Nlist => "nlist_section_symbol",
                    SymbolEvidenceSource::ExportTrie => "export_trie_address",
                    SymbolEvidenceSource::DyldImport => unreachable!("imports are not iterated"),
                }
                .to_owned(),
            });
        }
        context.receipt(
            function_source,
            status,
            examined,
            unit,
            if status == FunctionCollectorStatus::Truncated {
                Some(match evidence_source {
                    SymbolEvidenceSource::Nlist => "nlist_budget",
                    SymbolEvidenceSource::ExportTrie => "export_budget",
                    SymbolEvidenceSource::DyldImport => unreachable!("imports are not iterated"),
                })
            } else {
                diagnostic
            },
        );
    }
}

fn collect_dwarf(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::Dwarf;
    if has_unresolved_dwarf_relocations(macho) {
        context.receipt(
            source,
            FunctionCollectorStatus::Partial,
            0,
            "dies",
            Some("dwarf_relocations_unresolved"),
        );
        return;
    }
    let limits = crate::metadata::dwarf::DwarfTraversalLimits {
        max_section_bytes: context.limits.max_dwarf_section_bytes,
        max_units: context.limits.max_dwarf_entries,
        max_entries: context.limits.max_dwarf_entries,
        max_attributes: context.limits.max_dwarf_entries.saturating_mul(16),
        max_line_rows: context.limits.max_dwarf_entries.saturating_mul(8),
        max_range_entries: context.limits.max_dwarf_entries.saturating_mul(8),
    };
    let traversal = match crate::metadata::dwarf::traverse_dwarf(macho, limits) {
        Ok(Some(traversal)) => traversal,
        Ok(None) => {
            context.receipt(source, FunctionCollectorStatus::Absent, 0, "dies", None);
            return;
        }
        Err(error) => {
            let truncated = error.message().contains("exceed") || error.message().contains("limit");
            context.receipt(
                source,
                if truncated {
                    FunctionCollectorStatus::Truncated
                } else {
                    FunctionCollectorStatus::Failed
                },
                0,
                "dies",
                Some(if truncated {
                    "dwarf_budget"
                } else {
                    "dwarf_malformed"
                }),
            );
            return;
        }
    };
    let examined = traversal.entries.len() as u64;
    let subprograms = traversal
        .entries
        .iter()
        .filter(|entry| entry.tag == gimli::DW_TAG_subprogram.0)
        .collect::<Vec<_>>();
    let mut status = FunctionCollectorStatus::Complete;
    for entry_record in subprograms {
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            status = FunctionCollectorStatus::Truncated;
            break;
        }
        let attrs = traversal.attributes.iter().filter(|attribute| {
            attribute.unit_ordinal == entry_record.unit_ordinal
                && attribute.entry_offset == entry_record.offset
        });
        let mut low_pc = None;
        let mut entry_pc = None;
        let mut high_pc = None;
        let mut high_pc_is_address = false;
        let mut name = None;
        let mut linkage_name = None;
        for attribute in attrs {
            match attribute.name {
                value if value == gimli::DW_AT_low_pc.0 => low_pc = attribute.unsigned,
                value if value == gimli::DW_AT_entry_pc.0 => entry_pc = attribute.unsigned,
                value if value == gimli::DW_AT_high_pc.0 => {
                    high_pc = attribute.unsigned;
                    high_pc_is_address = attribute.value_kind == "address";
                }
                value if value == gimli::DW_AT_name.0 => {
                    name = attribute
                        .text
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .map(str::to_owned)
                }
                value if value == gimli::DW_AT_linkage_name.0 => {
                    linkage_name = attribute
                        .text
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .map(str::to_owned)
                }
                _ => {}
            }
        }
        let range_entries = traversal.range_entries.iter().filter(|range| {
            range.unit_ordinal == entry_record.unit_ordinal
                && range.entry_offset == entry_record.offset
                && range.disposition == "range"
        });
        let mut ranges = range_entries
            .filter_map(|range| Some((range.start?, range.end?)))
            .collect::<Vec<_>>();
        if ranges.is_empty()
            && let Some(start) = low_pc
            && let Some(high) = high_pc
        {
            let end = if high_pc_is_address {
                high
            } else {
                start.saturating_add(high)
            };
            ranges.push((start, end));
        }
        if ranges.is_empty()
            && let Some(start) = low_pc
        {
            ranges.push((start, start));
        }
        ranges.sort_unstable();
        let Some(canonical_entry) = entry_pc
            .or_else(|| ranges.first().map(|(start, _)| *start))
            .or(low_pc)
        else {
            continue;
        };
        for (range_index, (start, end)) in ranges.into_iter().enumerate() {
            if context.retained(source) as usize >= context.limits.max_evidence_per_source {
                status = FunctionCollectorStatus::Truncated;
                break;
            }
            context.admit(RawEvidence {
                source,
                confidence: FunctionEvidenceConfidence::Exact,
                entry: canonical_entry,
                extent_start: (end > start).then_some(start),
                end_exclusive: (end > start).then_some(end),
                name: (range_index == 0)
                    .then(|| linkage_name.clone().or_else(|| name.clone()))
                    .flatten(),
                source_location: Some(entry_record.debug_info_offset),
                detail: format!("dwarf_subprogram_range_{range_index}"),
            });
        }
    }
    context.receipt(
        source,
        status,
        examined,
        "dies",
        (status == FunctionCollectorStatus::Truncated).then_some("dwarf_evidence_budget"),
    );
}

fn collect_objc(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::ObjectiveC;
    let present = macho.all_sections().any(|section| {
        section.section_name() == "__objc_classlist" || section.section_name() == "__objc_catlist"
    });
    if !present {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "methods", None);
        return;
    }
    let mut examined = 0_u64;
    let mut limited = false;
    let result = crate::metadata::objc::fold_method_imps(macho, (), |_, method| {
        examined += 1;
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            limited = true;
            return Err(crate::metadata::objc::ObjcError::unsupported(
                "function-index Objective-C budget",
            ));
        }
        let sigil = match method.kind {
            crate::metadata::objc::ObjCMethodKind::Instance => '-',
            crate::metadata::objc::ObjCMethodKind::Class => '+',
        };
        let name = match method.category_name {
            Some(category) => format!(
                "{sigil}[{}({category}) {}]",
                method.class_name, method.method_name
            ),
            None => format!("{sigil}[{} {}]", method.class_name, method.method_name),
        };
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: method.imp.0,
            extent_start: None,
            end_exclusive: None,
            name: Some(name),
            source_location: None,
            detail: "objc_method_implementation".into(),
        });
        Ok(())
    });
    let (status, diagnostic) = if limited {
        (FunctionCollectorStatus::Truncated, Some("objc_budget"))
    } else if result.is_err() {
        (FunctionCollectorStatus::Failed, Some("objc_malformed"))
    } else {
        (FunctionCollectorStatus::Complete, None)
    };
    context.receipt(source, status, examined, "methods", diagnostic);
}

fn collect_dwarf_index(macho: &MachoFile<'_>, index: &DwarfIndex, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::Dwarf;
    if has_unresolved_dwarf_relocations(macho) {
        context.receipt(
            source,
            FunctionCollectorStatus::Partial,
            0,
            "dies",
            Some("dwarf_relocations_unresolved"),
        );
        return;
    }
    let Some(traversal) = index.traversal() else {
        let (status, diagnostic) = match index.status() {
            DwarfIndexStatus::Absent => (FunctionCollectorStatus::Absent, None),
            DwarfIndexStatus::Truncated => {
                (FunctionCollectorStatus::Truncated, Some("dwarf_budget"))
            }
            DwarfIndexStatus::Partial => (FunctionCollectorStatus::Failed, Some("dwarf_malformed")),
            DwarfIndexStatus::Complete => (
                FunctionCollectorStatus::Failed,
                Some("dwarf_traversal_missing"),
            ),
        };
        context.receipt(source, status, 0, "dies", diagnostic);
        return;
    };
    let examined = traversal.entries.len() as u64;
    let mut status = match index.status() {
        DwarfIndexStatus::Complete => FunctionCollectorStatus::Complete,
        DwarfIndexStatus::Partial => FunctionCollectorStatus::Partial,
        DwarfIndexStatus::Truncated => FunctionCollectorStatus::Truncated,
        DwarfIndexStatus::Absent => FunctionCollectorStatus::Absent,
    };
    for entry_record in traversal
        .entries
        .iter()
        .filter(|entry| entry.tag == gimli::DW_TAG_subprogram.0)
    {
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            status = FunctionCollectorStatus::Truncated;
            break;
        }
        let mut low_pc = None;
        let mut entry_pc = None;
        let mut high_pc = None;
        let mut high_pc_is_address = false;
        let mut name = None;
        let mut linkage_name = None;
        for attribute in traversal.attributes.iter().filter(|attribute| {
            attribute.unit_ordinal == entry_record.unit_ordinal
                && attribute.entry_offset == entry_record.offset
        }) {
            match attribute.name {
                value if value == gimli::DW_AT_low_pc.0 => low_pc = attribute.unsigned,
                value if value == gimli::DW_AT_entry_pc.0 => entry_pc = attribute.unsigned,
                value if value == gimli::DW_AT_high_pc.0 => {
                    high_pc = attribute.unsigned;
                    high_pc_is_address = attribute.value_kind == "address";
                }
                value if value == gimli::DW_AT_name.0 => {
                    name = attribute
                        .text
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .map(str::to_owned);
                }
                value if value == gimli::DW_AT_linkage_name.0 => {
                    linkage_name = attribute
                        .text
                        .as_deref()
                        .and_then(|bytes| std::str::from_utf8(bytes).ok())
                        .map(str::to_owned);
                }
                _ => {}
            }
        }
        let mut ranges = traversal
            .range_entries
            .iter()
            .filter(|range| {
                range.unit_ordinal == entry_record.unit_ordinal
                    && range.entry_offset == entry_record.offset
                    && range.disposition == "range"
            })
            .filter_map(|range| Some((range.start?, range.end?)))
            .collect::<Vec<_>>();
        if ranges.is_empty()
            && let (Some(start), Some(high)) = (low_pc, high_pc)
        {
            ranges.push((
                start,
                if high_pc_is_address {
                    high
                } else {
                    start.saturating_add(high)
                },
            ));
        }
        if ranges.is_empty()
            && let Some(start) = low_pc
        {
            ranges.push((start, start));
        }
        ranges.sort_unstable();
        let Some(canonical_entry) = entry_pc
            .or_else(|| ranges.first().map(|(start, _)| *start))
            .or(low_pc)
        else {
            continue;
        };
        for (range_index, (start, end)) in ranges.into_iter().enumerate() {
            if context.retained(source) as usize >= context.limits.max_evidence_per_source {
                status = FunctionCollectorStatus::Truncated;
                break;
            }
            context.admit(RawEvidence {
                source,
                confidence: FunctionEvidenceConfidence::Exact,
                entry: canonical_entry,
                extent_start: (end > start).then_some(start),
                end_exclusive: (end > start).then_some(end),
                name: (range_index == 0)
                    .then(|| linkage_name.clone().or_else(|| name.clone()))
                    .flatten(),
                source_location: Some(entry_record.debug_info_offset),
                detail: format!("dwarf_subprogram_range_{range_index}"),
            });
        }
    }
    context.receipt(
        source,
        status,
        examined,
        "dies",
        match status {
            FunctionCollectorStatus::Truncated => Some("dwarf_evidence_budget"),
            FunctionCollectorStatus::Partial => Some("dwarf_source_partial"),
            _ => None,
        },
    );
}

fn has_unresolved_dwarf_relocations(macho: &MachoFile<'_>) -> bool {
    macho.header().file_type() == crate::core::model::header::FileType::Object
        && macho.all_sections().any(|section| {
            section
                .section_name()
                .as_str_lossy()
                .starts_with("__debug_")
                && section.relocation_count() != 0
        })
}

fn collect_objc_index(index: &ObjcIndex, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::ObjectiveC;
    let (mut status, diagnostic) = match index.status() {
        ObjcIndexStatus::Absent => (FunctionCollectorStatus::Absent, None),
        ObjcIndexStatus::Complete => (FunctionCollectorStatus::Complete, None),
        ObjcIndexStatus::Partial => (FunctionCollectorStatus::Failed, Some("objc_rejected")),
        ObjcIndexStatus::Truncated => (FunctionCollectorStatus::Truncated, Some("objc_budget")),
    };
    if status == FunctionCollectorStatus::Absent {
        context.receipt(source, status, 0, "methods", diagnostic);
        return;
    }
    let examined = index.completeness().attempted;
    for method in index.methods() {
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            status = FunctionCollectorStatus::Truncated;
            break;
        }
        let sigil = if method.class_method { '+' } else { '-' };
        let name = match &method.category_name {
            Some(category) => format!(
                "{sigil}[{}({category}) {}]",
                method.class_name, method.selector
            ),
            None => format!("{sigil}[{} {}]", method.class_name, method.selector),
        };
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: method.implementation,
            extent_start: None,
            end_exclusive: None,
            name: Some(name),
            source_location: Some(method.record_file_offset),
            detail: "objc_method_implementation".into(),
        });
    }
    context.receipt(
        source,
        status,
        examined,
        "methods",
        if status == FunctionCollectorStatus::Truncated {
            Some("objc_budget")
        } else {
            diagnostic
        },
    );
}

fn collect_swift_index(index: &SwiftIndex, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::Swift;
    let mut status = match index.status() {
        SwiftIndexStatus::Absent => FunctionCollectorStatus::Absent,
        SwiftIndexStatus::Complete => FunctionCollectorStatus::Complete,
        SwiftIndexStatus::Partial => FunctionCollectorStatus::Failed,
        SwiftIndexStatus::Truncated => FunctionCollectorStatus::Truncated,
    };
    if status == FunctionCollectorStatus::Absent {
        context.receipt(source, status, 0, "observations", None);
        return;
    }
    if matches!(
        status,
        FunctionCollectorStatus::Failed | FunctionCollectorStatus::Truncated
    ) {
        context.receipt(
            source,
            status,
            index.completeness().attempted,
            "observations",
            Some(if status == FunctionCollectorStatus::Truncated {
                "swift_decoder_budget"
            } else {
                "swift_rejected"
            }),
        );
        return;
    }
    for record in index.class_vtable_entries() {
        if !admit_swift(
            context,
            record.implementation_va,
            Some(record.descriptor_va),
            format!("swift_vtable_slot_{}", record.slot_index),
        ) {
            status = FunctionCollectorStatus::Truncated;
            break;
        }
    }
    if status != FunctionCollectorStatus::Truncated {
        for record in index.class_overrides() {
            if !admit_swift(
                context,
                record.implementation_va,
                Some(record.descriptor_va),
                format!("swift_override_{}", record.override_index),
            ) {
                status = FunctionCollectorStatus::Truncated;
                break;
            }
        }
    }
    if status != FunctionCollectorStatus::Truncated {
        for record in &index.batch().protocol_requirements {
            let Some(implementation) = record.default_implementation_va else {
                continue;
            };
            if !admit_swift(
                context,
                implementation,
                Some(record.descriptor_va),
                format!("swift_protocol_default_{}", record.requirement_index),
            ) {
                status = FunctionCollectorStatus::Truncated;
                break;
            }
        }
    }
    context.receipt(
        source,
        status,
        index.completeness().attempted,
        "observations",
        (status == FunctionCollectorStatus::Truncated).then_some("swift_evidence_budget"),
    );
}

fn collect_swift(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    use crate::metadata::swift::evidence::{SwiftDecodeOutcomeV1, SwiftEvidenceLimits};

    let source = FunctionEvidenceSource::Swift;
    let present = macho.all_sections().any(|section| {
        section.section_name() == "__swift5_types"
            || section.section_name() == "__swift5_proto"
            || section.section_name() == "__swift5_protos"
    });
    if !present {
        context.receipt(
            source,
            FunctionCollectorStatus::Absent,
            0,
            "observations",
            None,
        );
        return;
    }
    let cap = context.limits.max_evidence_per_source as u64;
    let swift_limits = SwiftEvidenceLimits {
        max_identifier_bytes: (context.limits.max_name_bytes as u64).clamp(1, 65_536),
        max_mangling_bytes: (context.limits.max_name_bytes as u64).clamp(1, 262_144),
        max_nominal_descriptors: cap.clamp(1, 4_000_000),
        max_protocol_requirements: cap.clamp(1, 4_000_000),
        max_conformances: cap.clamp(1, 4_000_000),
        max_dispatch_slots: cap.clamp(1, 8_000_000),
        max_observations: cap.clamp(1, 32_000_000),
    };
    let batch = crate::metadata::swift::evidence::decode_swift_strict(macho, &swift_limits);
    let examined = batch.conservation.attempted;
    if batch.outcome == SwiftDecodeOutcomeV1::Rejected {
        let budget_exceeded = batch
            .gaps
            .iter()
            .any(|gap| gap.code == "swift_structural_budget_exceeded");
        context.receipt(
            source,
            if budget_exceeded {
                FunctionCollectorStatus::Truncated
            } else {
                FunctionCollectorStatus::Failed
            },
            examined,
            "observations",
            Some(if budget_exceeded {
                "swift_decoder_budget"
            } else {
                "swift_rejected"
            }),
        );
        return;
    }
    let mut limited = false;
    for record in &batch.class_vtable_entries {
        if !admit_swift(
            context,
            record.implementation_va,
            Some(record.descriptor_va),
            format!("swift_vtable_slot_{}", record.slot_index),
        ) {
            limited = true;
            break;
        }
    }
    if !limited {
        for record in &batch.class_overrides {
            if !admit_swift(
                context,
                record.implementation_va,
                Some(record.descriptor_va),
                format!("swift_override_{}", record.override_index),
            ) {
                limited = true;
                break;
            }
        }
    }
    if !limited {
        for record in &batch.protocol_requirements {
            let Some(implementation) = record.default_implementation_va else {
                continue;
            };
            if !admit_swift(
                context,
                implementation,
                Some(record.descriptor_va),
                format!("swift_protocol_default_{}", record.requirement_index),
            ) {
                limited = true;
                break;
            }
        }
    }
    context.receipt(
        source,
        if limited {
            FunctionCollectorStatus::Truncated
        } else {
            FunctionCollectorStatus::Complete
        },
        examined,
        "observations",
        limited.then_some("swift_evidence_budget"),
    );
}

fn admit_swift(
    context: &mut CollectionContext,
    entry: u64,
    source_location: Option<u64>,
    detail: String,
) -> bool {
    if context.retained(FunctionEvidenceSource::Swift) as usize
        >= context.limits.max_evidence_per_source
    {
        return false;
    }
    context.admit(RawEvidence {
        source: FunctionEvidenceSource::Swift,
        confidence: FunctionEvidenceConfidence::Exact,
        entry,
        extent_start: None,
        end_exclusive: None,
        name: None,
        source_location,
        detail,
    });
    true
}

fn collect_exception_index(index: &ExceptionIndex, context: &mut CollectionContext) {
    for (function_source, record_sources, unit) in [
        (
            FunctionEvidenceSource::CompactUnwind,
            &[ExceptionRecordSource::CompactUnwind][..],
            "entries",
        ),
        (
            FunctionEvidenceSource::ExceptionFrame,
            &[ExceptionRecordSource::ExceptionFrame][..],
            "fdes",
        ),
    ] {
        let source_receipts = index
            .receipts()
            .iter()
            .filter(|receipt| record_sources.contains(&receipt.source))
            .collect::<Vec<_>>();
        let examined = source_receipts
            .iter()
            .map(|receipt| receipt.attempted)
            .sum();
        let mut status = if source_receipts
            .iter()
            .all(|receipt| receipt.status == ExceptionCollectorStatus::Absent)
        {
            FunctionCollectorStatus::Absent
        } else if source_receipts
            .iter()
            .any(|receipt| receipt.status == ExceptionCollectorStatus::Truncated)
        {
            FunctionCollectorStatus::Truncated
        } else if source_receipts
            .iter()
            .any(|receipt| receipt.status == ExceptionCollectorStatus::Partial)
        {
            FunctionCollectorStatus::Partial
        } else {
            FunctionCollectorStatus::Complete
        };
        for record in index.records().iter().filter(|record| {
            record_sources.contains(&record.source)
                && record.range_kind == ExceptionRecordRangeKind::FunctionExtent
        }) {
            if context.retained(function_source) as usize >= context.limits.max_evidence_per_source
            {
                status = FunctionCollectorStatus::Truncated;
                break;
            }
            context.admit(RawEvidence {
                source: function_source,
                confidence: record.confidence,
                entry: record.entry,
                extent_start: record.end_exclusive.map(|_| record.entry),
                end_exclusive: record.end_exclusive,
                name: None,
                source_location: record.source_location,
                detail: match record.source {
                    ExceptionRecordSource::CompactUnwind => "compact_unwind_record",
                    ExceptionRecordSource::LinkedUnwindInfo => {
                        unreachable!("lookup ranges are not function evidence")
                    }
                    ExceptionRecordSource::ExceptionFrame => "eh_frame_fde",
                    ExceptionRecordSource::LanguageSpecificData => "lsda_call_site",
                }
                .to_owned(),
            });
        }
        context.receipt(
            function_source,
            status,
            examined,
            unit,
            match status {
                FunctionCollectorStatus::Partial => Some("exception_source_partial"),
                FunctionCollectorStatus::Truncated => Some("exception_source_budget"),
                _ => None,
            },
        );
    }
}

fn collect_compact_unwind(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::CompactUnwind;
    let compact = macho
        .all_sections()
        .find(|section| section.section_name() == "__compact_unwind");
    if compact.is_none() {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "entries", None);
        return;
    }
    let mut examined = 0_u64;
    let mut status = FunctionCollectorStatus::Complete;
    let mut diagnostic = None;
    if let Some(section) = compact {
        match compact_unwind_records(macho, section, context.limits.max_unwind_bytes) {
            Ok(records) => {
                for (entry, end, location) in records {
                    examined += 1;
                    if context.retained(source) as usize >= context.limits.max_evidence_per_source {
                        status = FunctionCollectorStatus::Truncated;
                        diagnostic = Some("compact_unwind_evidence_budget");
                        break;
                    }
                    context.admit(RawEvidence {
                        source,
                        confidence: FunctionEvidenceConfidence::Exact,
                        entry,
                        extent_start: Some(entry),
                        end_exclusive: Some(end),
                        name: None,
                        source_location: Some(location),
                        detail: "compact_unwind_record".into(),
                    });
                }
            }
            Err(error) => {
                status = if error == "budget" {
                    FunctionCollectorStatus::Truncated
                } else {
                    FunctionCollectorStatus::Failed
                };
                diagnostic = Some(if error == "budget" {
                    "compact_unwind_byte_budget"
                } else {
                    "compact_unwind_malformed"
                });
            }
        }
    }
    context.receipt(source, status, examined, "entries", diagnostic);
}

fn compact_unwind_records(
    macho: &MachoFile<'_>,
    section: &Section,
    max_bytes: usize,
) -> Result<Vec<(u64, u64, u64)>, &'static str> {
    let size = usize::try_from(section.size()).map_err(|_| "budget")?;
    if size > max_bytes {
        return Err("budget");
    }
    if !macho.is_64bit() || size % 32 != 0 {
        return Err("malformed");
    }
    let bytes = macho
        .read_bytes_at(section.offset(), size)
        .map_err(|_| "malformed")?;
    let mut result = Vec::with_capacity(size / 32);
    for (index, record) in bytes.chunks_exact(32).enumerate() {
        let entry = read_u64(macho, &record[0..8]);
        let length = read_u32(macho, &record[8..12]) as u64;
        let Some(end) = entry.checked_add(length) else {
            return Err("malformed");
        };
        if entry != 0 && length != 0 {
            result.push((entry, end, section.offset().0 + (index * 32) as u64));
        }
    }
    Ok(result)
}

fn collect_exception_frames(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::ExceptionFrame;
    let Some(section) = macho
        .all_sections()
        .find(|section| section.section_name() == "__eh_frame")
    else {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "fdes", None);
        return;
    };
    let size = match usize::try_from(section.size()) {
        Ok(size) if size <= context.limits.max_unwind_bytes => size,
        _ => {
            context.receipt(
                source,
                FunctionCollectorStatus::Truncated,
                0,
                "fdes",
                Some("eh_frame_byte_budget"),
            );
            return;
        }
    };
    let bytes = match macho.read_bytes_at(section.offset(), size) {
        Ok(bytes) => bytes,
        Err(_) => {
            context.receipt(
                source,
                FunctionCollectorStatus::Failed,
                0,
                "fdes",
                Some("eh_frame_bounds"),
            );
            return;
        }
    };
    let endian = match macho.endian() {
        crate::core::format::io::Endian::Little => RunTimeEndian::Little,
        crate::core::format::io::Endian::Big => RunTimeEndian::Big,
    };
    let frame = EhFrame::new(bytes, endian);
    let bases = BaseAddresses::default().set_eh_frame(section.addr().0);
    let mut entries = frame.entries(&bases);
    let mut examined = 0_u64;
    let mut status = FunctionCollectorStatus::Complete;
    let mut diagnostic = None;
    loop {
        let item = match entries.next() {
            Ok(item) => item,
            Err(_) => {
                status = FunctionCollectorStatus::Failed;
                diagnostic = Some("eh_frame_malformed");
                break;
            }
        };
        let Some(item) = item else {
            break;
        };
        let CieOrFde::Fde(partial) = item else {
            continue;
        };
        examined += 1;
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            status = FunctionCollectorStatus::Truncated;
            diagnostic = Some("eh_frame_evidence_budget");
            break;
        }
        let fde = match partial.parse(EhFrame::cie_from_offset) {
            Ok(fde) => fde,
            Err(_) => {
                status = FunctionCollectorStatus::Failed;
                diagnostic = Some("eh_frame_malformed");
                break;
            }
        };
        if fde.len() == 0 {
            continue;
        }
        context.admit(RawEvidence {
            source,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: fde.initial_address(),
            extent_start: Some(fde.initial_address()),
            end_exclusive: Some(fde.end_address()),
            name: None,
            source_location: None,
            detail: "eh_frame_fde".into(),
        });
    }
    context.receipt(source, status, examined, "fdes", diagnostic);
}

fn read_u32(macho: &MachoFile<'_>, raw: &[u8]) -> u32 {
    let bytes: [u8; 4] = raw.try_into().expect("checked four-byte field");
    match macho.endian() {
        crate::core::format::io::Endian::Little => u32::from_le_bytes(bytes),
        crate::core::format::io::Endian::Big => u32::from_be_bytes(bytes),
    }
}

fn read_u64(macho: &MachoFile<'_>, raw: &[u8]) -> u64 {
    let bytes: [u8; 8] = raw.try_into().expect("checked eight-byte field");
    match macho.endian() {
        crate::core::format::io::Endian::Little => u64::from_le_bytes(bytes),
        crate::core::format::io::Endian::Big => u64::from_be_bytes(bytes),
    }
}

fn collect_direct_calls(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::DirectCall;
    let arch = match instruction_arch(macho) {
        Some(arch) => arch,
        None => {
            context.receipt(
                source,
                FunctionCollectorStatus::Unsupported,
                0,
                "bytes",
                Some("direct_call_arch_unsupported"),
            );
            return;
        }
    };
    if context.sections.spans.is_empty() {
        context.receipt(source, FunctionCollectorStatus::Absent, 0, "bytes", None);
        return;
    }
    let spans = context.sections.spans.clone();
    let mut remaining = context.limits.max_decoded_bytes;
    let mut examined = 0_u64;
    let mut truncated = false;
    let mut mapping_gaps = false;
    let mut evidence_limited = false;
    for span in spans {
        if remaining == 0 {
            truncated = true;
            break;
        }
        let span_len = usize::try_from(span.end - span.start).unwrap_or(usize::MAX);
        let len = span_len.min(remaining);
        if len < span_len {
            truncated = true;
        }
        let bytes = match macho.read_bytes_at(ThinFileOffset(span.file_offset), len) {
            Ok(bytes) => bytes,
            Err(_) => {
                mapping_gaps = true;
                continue;
            }
        };
        if arch == Arch::X86_64 {
            // x86 has no architecturally privileged instruction boundary.
            // Retain the conventional linear interpretation, then examine
            // every other byte as an alternative start. Alternative direct
            // calls remain candidate-only evidence and therefore cannot
            // manufacture a function body, but they are no longer silently
            // discarded when another valid instruction crosses the byte.
            let mut canonical_starts = BTreeSet::new();
            let mut canonical_offset = 0_usize;
            let mut canonical_decoder = crate::insn::DecodeCursor::new(bytes, span.start, arch);
            while canonical_offset < bytes.len() {
                canonical_starts.insert(canonical_offset);
                canonical_offset += canonical_decoder
                    .probe_direct_call_at(canonical_offset)
                    .map_or(1, |(length, _)| {
                        length.max(1).min(bytes.len() - canonical_offset)
                    });
            }
            let mut alternative_decoder = crate::insn::DecodeCursor::new(bytes, span.start, arch);
            for offset in 0..bytes.len() {
                let va = span.start + offset as u64;
                if !crate::insn::could_start_direct_call(&bytes[offset..], arch) {
                    continue;
                }
                let Ok((_, target)) = alternative_decoder.probe_direct_call_at(offset) else {
                    continue;
                };
                if let Some(target) = target {
                    if context.retained(source) as usize >= context.limits.max_evidence_per_source {
                        evidence_limited = true;
                        break;
                    }
                    context.admit(RawEvidence {
                        source,
                        confidence: FunctionEvidenceConfidence::Candidate,
                        entry: target,
                        extent_start: None,
                        end_exclusive: None,
                        name: None,
                        source_location: Some(va),
                        detail: if canonical_starts.contains(&offset) {
                            "decoded_direct_call_target"
                        } else {
                            "decoded_alternative_direct_call_target"
                        }
                        .into(),
                    });
                }
            }
            examined += bytes.len() as u64;
            remaining -= bytes.len();
            if evidence_limited {
                break;
            }
            continue;
        }
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let va = span.start + offset as u64;
            match crate::insn::decode_one(&bytes[offset..], va, arch) {
                Ok(instruction) => {
                    let length = instruction.len.max(1).min(bytes.len() - offset);
                    if let InsnKind::Call(_) = instruction.kind
                        && let Some(target) = crate::insn::resolve_branch_target(&instruction, va)
                    {
                        if context.retained(source) as usize
                            >= context.limits.max_evidence_per_source
                        {
                            evidence_limited = true;
                            break;
                        }
                        context.admit(RawEvidence {
                            source,
                            confidence: FunctionEvidenceConfidence::Candidate,
                            entry: target,
                            extent_start: None,
                            end_exclusive: None,
                            name: None,
                            source_location: Some(va),
                            detail: "decoded_direct_call_target".into(),
                        });
                    }
                    offset += length;
                }
                Err(_) => {
                    mapping_gaps = true;
                    offset += if arch.is_arm64() { 4 } else { 1 }.min(bytes.len() - offset);
                }
            }
        }
        examined += offset as u64;
        remaining -= offset;
        if evidence_limited {
            break;
        }
    }
    let (status, diagnostic) = if truncated || evidence_limited {
        (
            FunctionCollectorStatus::Truncated,
            Some(if evidence_limited {
                "direct_call_evidence_budget"
            } else {
                "direct_call_byte_budget"
            }),
        )
    } else if mapping_gaps {
        (
            FunctionCollectorStatus::Partial,
            Some("direct_call_mapping_gaps"),
        )
    } else {
        (FunctionCollectorStatus::Complete, None)
    };
    context.receipt(source, status, examined, "bytes", diagnostic);
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

    fn image(bytes: &[u8]) -> crate::core::MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            crate::core::model::container::MachoContainer::Thin(macho) => macho,
            crate::core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    #[test]
    fn exact_image_digest_is_cached_per_parsed_image() {
        let bytes = macho_test_support::disassembly_x86_64();
        let macho = image(&bytes);
        let first = FunctionImageIdentity::from_macho(&macho);
        let cached = macho.content_sha256(|| panic!("digest was recomputed"));
        assert_eq!(cached, first.content_sha256);
        assert_eq!(first, FunctionImageIdentity::from_macho(&macho));
    }

    #[test]
    fn contiguous_recovered_data_can_close_a_candidate_boundary() {
        assert!(contiguous_ranges_cover(
            0x120,
            0x140,
            &[(0x120, 0x130), (0x130, 0x140)]
        ));
        assert!(!contiguous_ranges_cover(
            0x120,
            0x140,
            &[(0x120, 0x128), (0x130, 0x140)]
        ));
        assert!(!contiguous_ranges_cover(0x120, 0x140, &[(0x120, 0x130)]));
    }

    #[test]
    fn symbols_create_candidate_bounds_not_exact_extents() {
        let bytes = macho_test_support::disassembly_x86_64();
        let macho = image(&bytes);
        let index = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
        let main = index.by_entry(0x1_0000_0100).unwrap();
        assert_eq!(main.entry_confidence, FunctionEvidenceConfidence::Candidate);
        assert_eq!(
            main.extent.unwrap().confidence,
            FunctionEvidenceConfidence::Candidate
        );
        assert!(main.evidence.iter().any(|evidence| {
            evidence
                .roles
                .contains(&FunctionEvidenceRole::CandidateUpperBound)
                && evidence.detail == "next_recovered_entry"
        }));
        assert_eq!(
            index.containing(0x1_0000_0101),
            FunctionLookup::One(FunctionOwner {
                function: main,
                confidence: FunctionOwnershipConfidence::Candidate,
            })
        );
        assert_eq!(
            index.owners(0x1_0000_0101).collect::<Vec<_>>(),
            vec![FunctionOwner {
                function: main,
                confidence: FunctionOwnershipConfidence::Candidate,
            }]
        );
    }

    #[test]
    fn stripping_names_preserves_function_start_identity() {
        let rich_bytes = function_starts_fixture(true);
        let stripped_bytes = function_starts_fixture(false);
        let rich_macho = image(&rich_bytes);
        let stripped_macho = image(&stripped_bytes);
        let limits = FunctionRecoveryLimits::default();
        let rich = FunctionIndex::recover(&rich_macho, limits).unwrap();
        let stripped = FunctionIndex::recover(&stripped_macho, limits).unwrap();
        let rich_entries = rich
            .functions()
            .iter()
            .map(|function| function.entry)
            .collect::<Vec<_>>();
        let stripped_entries = stripped
            .functions()
            .iter()
            .map(|function| function.entry)
            .collect::<Vec<_>>();
        assert_eq!(rich_entries, stripped_entries);
        assert!(matches!(
            rich.functions()[0].identity,
            FunctionIdentity::Named { .. }
        ));
        assert!(matches!(
            stripped.functions()[0].identity,
            FunctionIdentity::Anonymous { .. }
        ));
        assert_eq!(
            stripped.functions()[0].entry_confidence,
            FunctionEvidenceConfidence::Exact
        );
    }

    #[test]
    fn function_budget_is_deterministic_and_reported() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let limits = FunctionRecoveryLimits {
            max_functions: 1,
            ..FunctionRecoveryLimits::default()
        };
        let index = FunctionIndex::recover(&macho, limits).unwrap();
        assert_eq!(index.functions().len(), 1);
        assert_eq!(index.functions()[0].entry, 0x1_0000_0100);
        assert_eq!(
            index.functions()[0].extent.unwrap().end_exclusive,
            0x1_0000_0104,
            "an omitted output identity must still bound its predecessor"
        );
        assert_eq!(index.truncated_function_count(), 1);
        assert!(!index.inventory_complete());
    }

    #[test]
    fn function_starts_and_direct_calls_recover_on_supported_architectures() {
        let mut x86 = macho_test_support::disassembly_x86_64();
        x86[0x104..0x109].copy_from_slice(&[0xe8, 0xf7, 0xff, 0xff, 0xff]);
        let mut arm64 = macho_test_support::disassembly_arm64();
        arm64[0x100..0x104].copy_from_slice(&0x9400_0001_u32.to_le_bytes());
        let mut arm64e = macho_test_support::disassembly_arm64e();
        arm64e[0x100..0x104].copy_from_slice(&0x9400_0001_u32.to_le_bytes());

        for bytes in [&mut x86, &mut arm64, &mut arm64e] {
            add_function_starts(bytes);
            let macho = image(bytes);
            let index = FunctionIndex::recover(&macho, FunctionRecoveryLimits::default()).unwrap();
            assert!(
                index
                    .functions()
                    .iter()
                    .all(|function| function.entry_confidence == FunctionEvidenceConfidence::Exact)
            );
            assert!(index.functions().iter().any(|function| {
                function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source == FunctionEvidenceSource::DirectCall)
            }));
        }
    }

    #[test]
    fn direct_call_only_target_is_retained_without_becoming_a_function() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let mut context = CollectionContext::new(FunctionRecoveryLimits::default(), sections);
        let established = 0x1_0000_0100;
        let candidate = established + 2;
        assert!(context.admit(RawEvidence {
            source: FunctionEvidenceSource::FunctionStarts,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: established,
            extent_start: None,
            end_exclusive: None,
            name: None,
            source_location: None,
            detail: "function_starts_delta".into(),
        }));
        assert!(context.admit(RawEvidence {
            source: FunctionEvidenceSource::DirectCall,
            confidence: FunctionEvidenceConfidence::Candidate,
            entry: candidate,
            extent_start: None,
            end_exclusive: None,
            name: None,
            source_location: Some(established),
            detail: "decoded_direct_call_target".into(),
        }));

        let index = context.finish(FunctionImageIdentity::from_macho(&macho));
        assert_eq!(index.functions().len(), 1);
        assert!(index.by_entry(candidate).is_none());
        assert_eq!(index.entry_candidates().len(), 1);
        assert_eq!(index.entry_candidates()[0].address, candidate);
        assert_eq!(
            index.entry_candidates()[0].reason,
            "direct_call_target_inside_recovered_extent"
        );
        assert_eq!(
            index.entry_candidates()[0].disposition,
            FunctionEntryCandidateDisposition::InsideRecoveredExtent
        );
        assert_eq!(
            index.entry_candidates()[0].possible_owners,
            vec![FunctionEntryCandidateOwner {
                entry: established,
                ownership_confidence: FunctionOwnershipConfidence::Candidate,
            }]
        );
        assert_eq!(
            index.entry_candidates()[0].evidence[0].source,
            FunctionEvidenceSource::DirectCall
        );
    }

    #[test]
    fn exact_secondary_range_and_call_target_establish_an_independent_cold_fragment() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let mut context = CollectionContext::new(FunctionRecoveryLimits::default(), sections);
        let entry = 0x1_0000_0100;
        let fragment = entry + 0x20;
        for (start, end) in [(entry, entry + 8), (fragment, fragment + 4)] {
            assert!(context.admit(RawEvidence {
                source: FunctionEvidenceSource::Dwarf,
                confidence: FunctionEvidenceConfidence::Exact,
                entry,
                extent_start: Some(start),
                end_exclusive: Some(end),
                name: None,
                source_location: Some(start),
                detail: "dwarf_subprogram_range".into(),
            }));
        }
        assert!(context.admit(RawEvidence {
            source: FunctionEvidenceSource::DirectCall,
            confidence: FunctionEvidenceConfidence::Candidate,
            entry: fragment,
            extent_start: None,
            end_exclusive: None,
            name: None,
            source_location: Some(entry),
            detail: "decoded_direct_call_target".into(),
        }));
        let index = context.finish(FunctionImageIdentity::from_macho(&macho));
        let relationship = index.relationship_at(fragment).unwrap();
        assert_eq!(relationship.owner_entry, entry);
        assert_eq!(relationship.kind, FunctionRelationshipKind::ColdFragment);
        assert_eq!(
            relationship.authority,
            FunctionRecoveryAuthority::Independent
        );
        assert!(relationship.evidence.iter().any(|evidence| {
            evidence.source == FunctionEvidenceSource::Dwarf
                && evidence.extent_start == Some(fragment)
        }));
    }

    #[test]
    fn identical_authoritative_secondary_ranges_establish_a_shared_tail() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let first = 0x1_0000_0100;
        let second = first + 8;
        let tail = first + 0x20;
        let mut context = CollectionContext::new(FunctionRecoveryLimits::default(), sections);
        for (entry, primary_end, source_location) in
            [(first, first + 4, 1), (second, second + 4, 2)]
        {
            for (start, end, detail) in [
                (entry, primary_end, "primary_range"),
                (tail, tail + 8, "folded_shared_tail"),
            ] {
                assert!(context.admit(RawEvidence {
                    source: FunctionEvidenceSource::Dwarf,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry,
                    extent_start: Some(start),
                    end_exclusive: Some(end),
                    name: None,
                    source_location: Some(source_location),
                    detail: detail.into(),
                }));
            }
        }
        let index = context.finish(FunctionImageIdentity::from_macho(&macho));
        assert_eq!(index.shared_ranges().len(), 1);
        assert_eq!(index.shared_ranges()[0].start, tail);
        assert_eq!(index.shared_ranges()[0].end_exclusive, tail + 8);
        assert_eq!(index.shared_ranges()[0].owners, vec![first, second]);
        assert!(
            index.shared_ranges()[0]
                .evidence
                .iter()
                .all(|evidence| evidence.detail == "folded_shared_tail")
        );
        assert!(
            matches!(index.containing(tail), FunctionLookup::Ambiguous(owners) if owners.len() == 2)
        );
    }

    #[test]
    fn range_less_non_call_entry_inside_exact_body_is_an_independent_alternate_entry() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let mut context = CollectionContext::new(FunctionRecoveryLimits::default(), sections);
        let entry = 0x1_0000_0100;
        let alternate = entry + 4;
        assert!(context.admit(RawEvidence {
            source: FunctionEvidenceSource::Dwarf,
            confidence: FunctionEvidenceConfidence::Exact,
            entry,
            extent_start: Some(entry),
            end_exclusive: Some(entry + 0x10),
            name: Some("body".into()),
            source_location: Some(1),
            detail: "dwarf_subprogram_range".into(),
        }));
        assert!(context.admit(RawEvidence {
            source: FunctionEvidenceSource::Nlist,
            confidence: FunctionEvidenceConfidence::Exact,
            entry: alternate,
            extent_start: None,
            end_exclusive: None,
            name: Some("alternate".into()),
            source_location: Some(2),
            detail: "nlist_external_text_symbol".into(),
        }));

        let index = context.finish(FunctionImageIdentity::from_macho(&macho));
        assert_eq!(index.functions().len(), 1);
        assert!(index.by_entry(alternate).is_none());
        let candidate = index
            .entry_candidates()
            .iter()
            .find(|candidate| candidate.address == alternate)
            .unwrap();
        assert_eq!(
            candidate.disposition,
            FunctionEntryCandidateDisposition::InsideRecoveredExtent
        );
        let relationship = index.relationship_at(alternate).unwrap();
        assert_eq!(relationship.owner_entry, entry);
        assert_eq!(relationship.kind, FunctionRelationshipKind::AlternateEntry);
        assert_eq!(
            relationship.authority,
            FunctionRecoveryAuthority::Independent
        );
        assert!(
            relationship
                .evidence
                .iter()
                .any(|evidence| evidence.source == FunctionEvidenceSource::Nlist)
        );
        assert!(
            relationship
                .evidence
                .iter()
                .any(|evidence| evidence.source == FunctionEvidenceSource::Dwarf)
        );
    }

    #[test]
    fn entry_candidates_distinguish_fragments_shared_regions_and_rejections() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let first = 0x1_0000_0100;
        let second = first + 8;
        let shared = first + 10;
        let fragment = first + 0x20;
        let rejected = sections.spans.last().unwrap().end;
        let entries = [first, second];
        let mut functions = vec![
            reconcile_function(
                first,
                vec![
                    RawEvidence {
                        source: FunctionEvidenceSource::Dwarf,
                        confidence: FunctionEvidenceConfidence::Exact,
                        entry: first,
                        extent_start: Some(first),
                        end_exclusive: Some(first + 0x10),
                        name: None,
                        source_location: Some(1),
                        detail: "primary_range".into(),
                    },
                    RawEvidence {
                        source: FunctionEvidenceSource::Dwarf,
                        confidence: FunctionEvidenceConfidence::Exact,
                        entry: first,
                        extent_start: Some(fragment),
                        end_exclusive: Some(fragment + 4),
                        name: None,
                        source_location: Some(1),
                        detail: "secondary_range".into(),
                    },
                ],
                &entries,
                &sections,
                &[],
            ),
            reconcile_function(
                second,
                vec![RawEvidence {
                    source: FunctionEvidenceSource::Dwarf,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry: second,
                    extent_start: Some(second),
                    end_exclusive: Some(second + 0x10),
                    name: None,
                    source_location: Some(2),
                    detail: "primary_range".into(),
                }],
                &entries,
                &sections,
                &[],
            ),
        ];
        mark_overlaps(&mut functions);
        let call_evidence = |target| {
            vec![RawEvidence {
                source: FunctionEvidenceSource::DirectCall,
                confidence: FunctionEvidenceConfidence::Candidate,
                entry: target,
                extent_start: None,
                end_exclusive: None,
                name: None,
                source_location: Some(first),
                detail: "decoded_direct_call_target".into(),
            }]
        };
        let candidate_ownership = build_candidate_ownership(&functions);
        let secondary_range_entries = secondary_range_entries(&functions);
        let candidates = reconcile_entry_candidates(
            BTreeMap::from([
                (shared, call_evidence(shared)),
                (fragment, call_evidence(fragment)),
                (rejected, call_evidence(rejected)),
            ]),
            EntryCandidateReconciliation {
                functions: &functions,
                ownership: &candidate_ownership,
                secondary_range_entries: &secondary_range_entries,
                sections: &sections,
                rejected_entries: &BTreeSet::new(),
                guided_relationships: &BTreeMap::new(),
                import_stubs: &BTreeSet::new(),
            },
        );

        assert_eq!(
            candidates
                .iter()
                .find(|candidate| candidate.address == shared)
                .unwrap()
                .disposition,
            FunctionEntryCandidateDisposition::SharedOwnedRegion
        );
        assert_eq!(
            candidates
                .iter()
                .find(|candidate| candidate.address == fragment)
                .unwrap()
                .disposition,
            FunctionEntryCandidateDisposition::SecondaryRangeEntry
        );
        let rejected = candidates
            .iter()
            .find(|candidate| candidate.address == rejected)
            .unwrap();
        assert_eq!(
            rejected.disposition,
            FunctionEntryCandidateDisposition::RejectedNonExecutableTarget
        );
        assert!(rejected.possible_owners.is_empty());
        assert_eq!(
            rejected.reason,
            "direct_call_target_outside_executable_sections"
        );
    }

    #[test]
    fn name_budget_removes_names_not_identities() {
        let bytes = function_starts_fixture(true);
        let macho = image(&bytes);
        let limits = FunctionRecoveryLimits {
            max_name_bytes: 1,
            ..FunctionRecoveryLimits::default()
        };
        let index = FunctionIndex::recover(&macho, limits).unwrap();
        assert_eq!(index.functions().len(), 2);
        assert!(matches!(
            index.functions()[0].identity,
            FunctionIdentity::Anonymous { .. }
        ));
        assert!(!index.inventory_complete());
        assert_eq!(
            index
                .receipts()
                .iter()
                .find(|receipt| receipt.source == FunctionEvidenceSource::Nlist)
                .unwrap()
                .status,
            FunctionCollectorStatus::Truncated
        );
    }

    #[test]
    fn conflicting_authoritative_extents_are_retained() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let function = reconcile_function(
            0x1_0000_0100,
            vec![
                RawEvidence {
                    source: FunctionEvidenceSource::Dwarf,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry: 0x1_0000_0100,
                    extent_start: Some(0x1_0000_0100),
                    end_exclusive: Some(0x1_0000_0110),
                    name: None,
                    source_location: None,
                    detail: "a".into(),
                },
                RawEvidence {
                    source: FunctionEvidenceSource::ExceptionFrame,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry: 0x1_0000_0100,
                    extent_start: Some(0x1_0000_0100),
                    end_exclusive: Some(0x1_0000_0114),
                    name: None,
                    source_location: None,
                    detail: "b".into(),
                },
            ],
            &[0x1_0000_0100],
            &sections,
            &[],
        );
        assert_eq!(
            function.conflicts[0].kind,
            FunctionConflictKind::ExtentEndDisagreement
        );
        assert_eq!(
            function.conflicts[0].claims,
            vec![
                FunctionConflictClaim {
                    source: FunctionEvidenceSource::Dwarf,
                    field: FunctionConflictField::ExtentEndExclusive,
                    value: 0x1_0000_0110,
                },
                FunctionConflictClaim {
                    source: FunctionEvidenceSource::ExceptionFrame,
                    field: FunctionConflictField::ExtentEndExclusive,
                    value: 0x1_0000_0114,
                },
            ]
        );
        assert!(!function.completeness.extent_is_authoritative);
    }

    #[test]
    fn extent_disagreement_emits_actionable_range_choices() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let mut context = CollectionContext::new(FunctionRecoveryLimits::default(), sections);
        let entry = 0x1_0000_0100;
        for (source, end_exclusive) in [
            (FunctionEvidenceSource::Dwarf, entry + 0x10),
            (FunctionEvidenceSource::ExceptionFrame, entry + 0x14),
        ] {
            assert!(context.admit(RawEvidence {
                source,
                confidence: FunctionEvidenceConfidence::Exact,
                entry,
                extent_start: Some(entry),
                end_exclusive: Some(end_exclusive),
                name: None,
                source_location: Some(end_exclusive),
                detail: "conflicting_exact_extent".into(),
            }));
        }
        let functions = context.finish(FunctionImageIdentity::from_macho(&macho));
        let control_flow = crate::analysis::control_flow::ControlFlowIndex::recover(
            &macho,
            &functions,
            crate::analysis::control_flow::ControlFlowLimits::default(),
        )
        .unwrap();
        let executable = crate::analysis::executable_bytes::ExecutableByteIndex::recover(
            &macho,
            &functions,
            &control_flow,
            crate::analysis::executable_bytes::ExecutableByteLimits::default(),
        )
        .unwrap();
        let image = FunctionImageIdentity::from_macho(&macho);
        let questions = crate::analysis::recovery::build_recovery_questions(
            &image,
            Some(&functions),
            Some(&control_flow),
            Some(&executable),
            None,
            None,
            &[],
        );
        let question = questions
            .iter()
            .find(|question| {
                question.kind == crate::analysis::recovery::RecoveryQuestionKind::FunctionRanges
            })
            .expect("extent conflict emits a function-range question");
        for end_exclusive in [entry + 0x10, entry + 0x14] {
            assert!(question.choices.contains(
                &crate::analysis::recovery::RecoveryChoice::FunctionRanges {
                    ranges: vec![crate::analysis::recovery::RecoveryAddressRange {
                        start: entry,
                        end_exclusive,
                    }],
                }
            ));
        }
        assert_eq!(question.signals.len(), 2);
    }

    #[test]
    fn authoritative_extent_conflicts_with_nested_exact_entry() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let entries = [0x1_0000_0100, 0x1_0000_0104];
        let mut functions = vec![
            reconcile_function(
                entries[0],
                vec![RawEvidence {
                    source: FunctionEvidenceSource::Dwarf,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry: entries[0],
                    extent_start: Some(entries[0]),
                    end_exclusive: Some(0x1_0000_0110),
                    name: None,
                    source_location: None,
                    detail: "range".into(),
                }],
                &entries,
                &sections,
                &[],
            ),
            reconcile_function(
                entries[1],
                vec![RawEvidence {
                    source: FunctionEvidenceSource::FunctionStarts,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry: entries[1],
                    extent_start: None,
                    end_exclusive: None,
                    name: None,
                    source_location: None,
                    detail: "entry".into(),
                }],
                &entries,
                &sections,
                &[],
            ),
        ];
        mark_overlaps(&mut functions);
        assert!(functions.iter().all(|function| {
            function.conflicts.iter().any(|conflict| {
                conflict.kind == FunctionConflictKind::AuthoritativeExtentContainsEntry
            })
        }));
    }

    #[test]
    fn secondary_dwarf_range_keeps_one_identity_and_exact_ownership() {
        let bytes = function_starts_fixture(false);
        let macho = image(&bytes);
        let sections = ExecutableSections::new(&macho);
        let entry = 0x1_0000_0100;
        let function = reconcile_function(
            entry,
            vec![
                RawEvidence {
                    source: FunctionEvidenceSource::Dwarf,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry,
                    extent_start: Some(entry),
                    end_exclusive: Some(entry + 4),
                    name: Some("split".into()),
                    source_location: Some(1),
                    detail: "range_0".into(),
                },
                RawEvidence {
                    source: FunctionEvidenceSource::Dwarf,
                    confidence: FunctionEvidenceConfidence::Exact,
                    entry,
                    extent_start: Some(entry + 0x20),
                    end_exclusive: Some(entry + 0x24),
                    name: None,
                    source_location: Some(1),
                    detail: "range_1".into(),
                },
            ],
            &[entry],
            &sections,
            &[],
        );
        let functions = vec![function];
        let ownership = build_ownership(&functions);
        let index = FunctionIndex {
            image: FunctionImageIdentity::from_macho(&macho),
            limits: FunctionRecoveryLimits::default(),
            functions,
            entry_candidates: Vec::new(),
            relationships: Vec::new(),
            shared_ranges: Vec::new(),
            import_stubs: Vec::new(),
            suppressed_entries: Vec::new(),
            receipts: Vec::new(),
            inventory_complete: true,
            truncated_function_count: 0,
            ownership,
        };
        assert_eq!(index.functions().len(), 1);
        assert_eq!(
            index.functions()[0].extent.unwrap().end_exclusive,
            entry + 4
        );
        assert!(matches!(
            index.containing(entry + 0x22),
            FunctionLookup::One(FunctionOwner {
                confidence: FunctionOwnershipConfidence::Exact,
                ..
            })
        ));
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
}
