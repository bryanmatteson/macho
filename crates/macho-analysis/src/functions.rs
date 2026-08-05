//! Bounded, evidence-bearing function inventory recovery.
//!
//! The index intentionally distinguishes a proven range from an adjacency
//! bound. A later known entry or an executable-section end is useful for
//! limiting a search, but is never reported as the proven end of a function.

use std::collections::{BTreeMap, BTreeSet};

use gimli::{BaseAddresses, CieOrFde, EhFrame, RunTimeEndian, UnwindSection};
use macho_core::format::constants::{
    CPU_SUBTYPE_ARM64E, CPU_SUBTYPE_MASK, CPU_TYPE_ARM64, CPU_TYPE_X86_64, SectionAttributes,
};
use macho_core::model::addr::ThinFileOffset;
use macho_core::model::load_command::LoadCommand;
use macho_core::model::macho_file::MachoFile;
use macho_core::model::section::Section;
use macho_core::model::symbol::SymbolType;
use macho_dyld::ExportKind;
use macho_insn::{Arch, InsnKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

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
}

/// Identity binding a function index to one exact thin Mach-O image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
        let digest = Sha256::digest(macho.bytes());
        Self {
            content_sha256: format!("{digest:x}"),
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
    /// Object compact-unwind record or linked unwind-info page.
    CompactUnwind,
    /// Exception-frame FDE.
    ExceptionFrame,
    /// Direct decoded call target.
    DirectCall,
    /// Executable-section boundary used only as a candidate bound.
    ExecutableSection,
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
    /// An authoritative extent crosses an executable-section boundary.
    ExtentOutsideExecutableSection,
    /// Two distinct authoritative function extents overlap.
    AuthoritativeExtentOverlap,
    /// An authoritative extent contains another authoritative entry.
    AuthoritativeExtentContainsEntry,
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

/// One recovered function identity and all retained supporting evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredFunction {
    /// Function entry address.
    pub entry: u64,
    /// Strength of the entry claim.
    pub entry_confidence: FunctionEvidenceConfidence,
    /// Named or stable anonymous identity.
    pub identity: FunctionIdentity,
    /// Best-known extent; adjacency-derived ends remain candidates.
    pub extent: Option<FunctionExtent>,
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

/// Deterministic, bounded function inventory for one thin Mach-O image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FunctionIndex {
    image: FunctionImageIdentity,
    limits: FunctionRecoveryLimits,
    functions: Vec<RecoveredFunction>,
    receipts: Vec<FunctionCollectorReceipt>,
    inventory_complete: bool,
    truncated_function_count: u64,
    #[serde(skip)]
    ownership: Vec<OwnershipSpan>,
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

    /// Recovered functions sorted by entry address.
    pub fn functions(&self) -> &[RecoveredFunction] {
        &self.functions
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

    /// Resolve every retained function extent containing `address`.
    pub fn containing(&self, address: u64) -> FunctionLookup<'_> {
        let mut matches = BTreeMap::<usize, FunctionEvidenceConfidence>::new();
        let span_index = self.ownership.partition_point(|span| span.start <= address);
        if let Some(span) = span_index
            .checked_sub(1)
            .and_then(|index| self.ownership.get(index))
            .filter(|span| address < span.end)
        {
            matches.extend(span.owners.iter().copied());
        }
        if let Ok(index) = self
            .functions
            .binary_search_by_key(&address, |function| function.entry)
        {
            matches
                .entry(index)
                .and_modify(|confidence| {
                    *confidence = (*confidence).max(self.functions[index].entry_confidence)
                })
                .or_insert(self.functions[index].entry_confidence);
        }
        let owners = matches
            .into_iter()
            .map(|(index, matched)| {
                let function = &self.functions[index];
                let confidence = if function.conflicts.is_empty() {
                    match matched {
                        FunctionEvidenceConfidence::Exact => FunctionOwnershipConfidence::Exact,
                        FunctionEvidenceConfidence::Derived => FunctionOwnershipConfidence::Derived,
                        FunctionEvidenceConfidence::Candidate => {
                            FunctionOwnershipConfidence::Candidate
                        }
                    }
                } else {
                    FunctionOwnershipConfidence::Candidate
                };
                FunctionOwner {
                    function,
                    confidence,
                }
            })
            .collect::<Vec<_>>();
        match owners.len() {
            0 => FunctionLookup::None,
            1 => FunctionLookup::One(owners[0]),
            _ => FunctionLookup::Ambiguous(owners),
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
        }
    }

    fn admit(&mut self, mut evidence: RawEvidence) -> bool {
        if self.sections.containing(evidence.entry).is_none() {
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
        let distinct_count = grouped.len();
        // Candidate adjacency bounds are evidence about the image, not retained-output
        // bookkeeping. Keep every observed entry available while reconciling admitted
        // functions so `max_functions` cannot change the inferred end of the last
        // retained identity.
        let all_observed_entries = grouped.keys().copied().collect::<Vec<_>>();
        let retained_groups = grouped
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
        mark_overlaps(&mut functions);
        let ownership = build_ownership(&functions);
        self.receipts.sort_by_key(|receipt| receipt.source);
        let inventory_complete = truncated_function_count == 0
            && incomplete_sources.is_empty()
            && self.name_truncated_sources.is_empty();
        FunctionIndex {
            image,
            limits: self.limits,
            functions,
            receipts: self.receipts,
            inventory_complete,
            truncated_function_count,
            ownership,
        }
    }
}

fn build_ownership(functions: &[RecoveredFunction]) -> Vec<OwnershipSpan> {
    let mut intervals = BTreeMap::<(u64, u64, usize), FunctionEvidenceConfidence>::new();
    for (function_index, function) in functions.iter().enumerate() {
        if let Some(extent) = function.extent {
            intervals
                .entry((extent.start, extent.end_exclusive, function_index))
                .and_modify(|confidence| *confidence = (*confidence).max(extent.confidence))
                .or_insert(extent.confidence);
        }
        for evidence in &function.evidence {
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
        conflicts.push(FunctionConflict {
            kind: FunctionConflictKind::ExtentEndDisagreement,
            values: distinct_authoritative.iter().copied().collect(),
            sources: authoritative
                .iter()
                .map(|(_, _, source)| *source)
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect(),
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
        .map(|(ordinal, evidence)| FunctionEvidence {
            ordinal: ordinal as u64,
            source: evidence.source,
            roles: evidence.roles(),
            confidence: evidence.confidence,
            entry: evidence.entry,
            extent_start: evidence.extent_start,
            end_exclusive: evidence.end_exclusive,
            name: evidence.name,
            source_location: evidence.source_location,
            detail: evidence.detail,
        })
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
        identity,
        extent,
        evidence,
        conflicts,
        completeness: FunctionCompleteness {
            locally_complete: incomplete_sources.is_empty(),
            incomplete_sources: incomplete_sources.to_vec(),
            extent_is_authoritative,
        },
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
    for left_index in 0..functions.len() {
        let Some(left_extent) = functions[left_index].extent else {
            continue;
        };
        if left_extent.confidence == FunctionEvidenceConfidence::Candidate {
            continue;
        }
        let mut right_index = left_index + 1;
        while right_index < functions.len()
            && functions[right_index].entry < left_extent.end_exclusive
        {
            if functions[right_index].entry_confidence == FunctionEvidenceConfidence::Exact {
                let conflict = FunctionConflict {
                    kind: FunctionConflictKind::AuthoritativeExtentContainsEntry,
                    values: vec![left_extent.end_exclusive, functions[right_index].entry],
                    sources: authoritative_sources(&functions[left_index])
                        .into_iter()
                        .chain(exact_entry_sources(&functions[right_index]))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
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
            if right_extent.confidence != FunctionEvidenceConfidence::Candidate {
                let values = vec![left_extent.end_exclusive, right_extent.end_exclusive];
                let sources = authoritative_sources(&functions[left_index])
                    .into_iter()
                    .chain(authoritative_sources(&functions[right_index]))
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect::<Vec<_>>();
                let conflict = FunctionConflict {
                    kind: FunctionConflictKind::AuthoritativeExtentOverlap,
                    values,
                    sources,
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

fn authoritative_sources(function: &RecoveredFunction) -> Vec<FunctionEvidenceSource> {
    function
        .evidence
        .iter()
        .filter(|evidence| {
            evidence.end_exclusive.is_some()
                && evidence.confidence != FunctionEvidenceConfidence::Candidate
        })
        .map(|evidence| evidence.source)
        .collect()
}

fn exact_entry_sources(function: &RecoveredFunction) -> Vec<FunctionEvidenceSource> {
    function
        .evidence
        .iter()
        .filter(|evidence| evidence.confidence == FunctionEvidenceConfidence::Exact)
        .map(|evidence| evidence.source)
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
    let mut reader = macho_dyld::uleb::LebReader::new(bytes);
    let mut address = macho.image_base().0;
    let mut examined = 0_u64;
    let mut status = FunctionCollectorStatus::Complete;
    while !reader.is_empty() {
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            status = FunctionCollectorStatus::Truncated;
            break;
        }
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
            source_location: None,
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
    let result = macho_core::format::fold_symbols(macho, (), |_, symbol| {
        examined += 1;
        if symbol.sym_type != SymbolType::Section || symbol.value == 0 {
            return Ok(());
        }
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            limited = true;
            return Err(macho_core::ParseError::limit("function-index nlist budget"));
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
    let result = macho_dyld::fold_exports(macho, (), |_, export| {
        examined += 1;
        let relative = match export.kind {
            ExportKind::Regular { address } | ExportKind::ThreadLocal { address } => address,
            _ => return Ok(()),
        };
        let Some(entry) = macho.image_base().0.checked_add(relative) else {
            return Err(macho_dyld::DyldError::address("export address overflow"));
        };
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            limited = true;
            return Err(macho_dyld::DyldError::unsupported(
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

fn collect_dwarf(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::Dwarf;
    let limits = macho_dwarf::DwarfTraversalLimits {
        max_section_bytes: context.limits.max_dwarf_section_bytes,
        max_units: context.limits.max_dwarf_entries,
        max_entries: context.limits.max_dwarf_entries,
        max_attributes: context.limits.max_dwarf_entries.saturating_mul(16),
        max_line_rows: context.limits.max_dwarf_entries.saturating_mul(8),
        max_range_entries: context.limits.max_dwarf_entries.saturating_mul(8),
    };
    let traversal = match macho_dwarf::traverse_dwarf(macho, limits) {
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
    let result = macho_objc::fold_method_imps(macho, (), |_, method| {
        examined += 1;
        if context.retained(source) as usize >= context.limits.max_evidence_per_source {
            limited = true;
            return Err(macho_objc::ObjcError::unsupported(
                "function-index Objective-C budget",
            ));
        }
        let sigil = match method.kind {
            macho_objc::ObjCMethodKind::Instance => '-',
            macho_objc::ObjCMethodKind::Class => '+',
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

fn collect_swift(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    use macho_swift::evidence::{SwiftDecodeOutcomeV1, SwiftEvidenceLimits};

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
    let batch = macho_swift::evidence::decode_swift_strict(macho, &swift_limits);
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

fn collect_compact_unwind(macho: &MachoFile<'_>, context: &mut CollectionContext) {
    let source = FunctionEvidenceSource::CompactUnwind;
    let compact = macho
        .all_sections()
        .find(|section| section.section_name() == "__compact_unwind");
    let linked = macho
        .all_sections()
        .find(|section| section.section_name() == "__unwind_info");
    if compact.is_none() && linked.is_none() {
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
    if status == FunctionCollectorStatus::Complete
        && let Some(section) = linked
    {
        match linked_unwind_records(macho, section, context.limits.max_unwind_bytes) {
            Ok(records) => {
                for (entry, end, location) in records {
                    examined += 1;
                    if context.retained(source) as usize >= context.limits.max_evidence_per_source {
                        status = FunctionCollectorStatus::Truncated;
                        diagnostic = Some("unwind_info_evidence_budget");
                        break;
                    }
                    context.admit(RawEvidence {
                        source,
                        confidence: FunctionEvidenceConfidence::Derived,
                        entry,
                        extent_start: Some(entry),
                        end_exclusive: Some(end),
                        name: None,
                        source_location: Some(location),
                        detail: "unwind_info_lookup_range".into(),
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
                    "unwind_info_byte_budget"
                } else {
                    "unwind_info_malformed"
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

fn linked_unwind_records(
    macho: &MachoFile<'_>,
    section: &Section,
    max_bytes: usize,
) -> Result<Vec<(u64, u64, u64)>, &'static str> {
    const HEADER_SIZE: usize = 28;
    const INDEX_SIZE: usize = 12;
    const UNWIND_SECOND_LEVEL_REGULAR: u32 = 2;
    const UNWIND_SECOND_LEVEL_COMPRESSED: u32 = 3;
    const UNWIND_IS_NOT_FUNCTION_START: u32 = 0x8000_0000;

    let size = usize::try_from(section.size()).map_err(|_| "budget")?;
    if size > max_bytes {
        return Err("budget");
    }
    let bytes = macho
        .read_bytes_at(section.offset(), size)
        .map_err(|_| "malformed")?;
    if bytes.len() < HEADER_SIZE || read_u32(macho, &bytes[0..4]) != 1 {
        return Err("malformed");
    }
    let common_offset = read_u32(macho, &bytes[4..8]) as usize;
    let common_count = read_u32(macho, &bytes[8..12]) as usize;
    let index_offset = read_u32(macho, &bytes[20..24]) as usize;
    let index_count = read_u32(macho, &bytes[24..28]) as usize;
    if index_count < 2 {
        return Ok(Vec::new());
    }
    let index_end = index_offset
        .checked_add(index_count.checked_mul(INDEX_SIZE).ok_or("malformed")?)
        .ok_or("malformed")?;
    let common_end = common_offset
        .checked_add(common_count.checked_mul(4).ok_or("malformed")?)
        .ok_or("malformed")?;
    if index_end > bytes.len() || common_end > bytes.len() {
        return Err("malformed");
    }
    let mut indexes = Vec::with_capacity(index_count);
    for index in 0..index_count {
        let offset = index_offset + index * INDEX_SIZE;
        indexes.push((
            read_u32(macho, &bytes[offset..offset + 4]),
            read_u32(macho, &bytes[offset + 4..offset + 8]),
        ));
    }
    let mut raw = Vec::<(u32, u32, u64)>::new();
    for &(base_function, page_offset) in indexes.iter().take(index_count - 1) {
        if page_offset == 0 {
            continue;
        }
        let page = page_offset as usize;
        let kind = read_u32_checked(macho, bytes, page)?;
        match kind {
            UNWIND_SECOND_LEVEL_REGULAR => {
                let entries_offset = read_u16_checked(macho, bytes, page + 4)? as usize;
                let entries_count = read_u16_checked(macho, bytes, page + 6)? as usize;
                let start = page.checked_add(entries_offset).ok_or("malformed")?;
                for entry_index in 0..entries_count {
                    let offset = start
                        .checked_add(entry_index.checked_mul(8).ok_or("malformed")?)
                        .ok_or("malformed")?;
                    let function_offset = read_u32_checked(macho, bytes, offset)?;
                    let encoding = read_u32_checked(macho, bytes, offset + 4)?;
                    raw.push((
                        function_offset,
                        encoding,
                        section.offset().0 + offset as u64,
                    ));
                }
            }
            UNWIND_SECOND_LEVEL_COMPRESSED => {
                let entries_offset = read_u16_checked(macho, bytes, page + 4)? as usize;
                let entries_count = read_u16_checked(macho, bytes, page + 6)? as usize;
                let encodings_offset = read_u16_checked(macho, bytes, page + 8)? as usize;
                let encodings_count = read_u16_checked(macho, bytes, page + 10)? as usize;
                let entries_start = page.checked_add(entries_offset).ok_or("malformed")?;
                let encodings_start = page.checked_add(encodings_offset).ok_or("malformed")?;
                for entry_index in 0..entries_count {
                    let offset = entries_start
                        .checked_add(entry_index.checked_mul(4).ok_or("malformed")?)
                        .ok_or("malformed")?;
                    let compressed = read_u32_checked(macho, bytes, offset)?;
                    let function_offset = base_function
                        .checked_add(compressed & 0x00ff_ffff)
                        .ok_or("malformed")?;
                    let encoding_index = (compressed >> 24) as usize;
                    let encoding = if encoding_index < common_count {
                        read_u32_checked(macho, bytes, common_offset + encoding_index * 4)?
                    } else {
                        let page_encoding = encoding_index - common_count;
                        if page_encoding >= encodings_count {
                            return Err("malformed");
                        }
                        read_u32_checked(macho, bytes, encodings_start + page_encoding * 4)?
                    };
                    raw.push((
                        function_offset,
                        encoding,
                        section.offset().0 + offset as u64,
                    ));
                }
            }
            _ => return Err("malformed"),
        }
    }
    raw.sort_by_key(|(offset, _, location)| (*offset, *location));
    raw.dedup_by_key(|(offset, _, _)| *offset);
    let sentinel = indexes
        .last()
        .map(|(offset, _)| *offset)
        .ok_or("malformed")?;
    let mut result = Vec::new();
    for index in 0..raw.len() {
        let (start, encoding, location) = raw[index];
        if encoding & UNWIND_IS_NOT_FUNCTION_START != 0 {
            continue;
        }
        let end = raw.get(index + 1).map_or(sentinel, |record| record.0);
        if end <= start {
            continue;
        }
        let entry = macho
            .image_base()
            .0
            .checked_add(start as u64)
            .ok_or("malformed")?;
        let end = macho
            .image_base()
            .0
            .checked_add(end as u64)
            .ok_or("malformed")?;
        result.push((entry, end, location));
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
        macho_core::format::io::Endian::Little => RunTimeEndian::Little,
        macho_core::format::io::Endian::Big => RunTimeEndian::Big,
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

fn read_u16_checked(
    macho: &MachoFile<'_>,
    bytes: &[u8],
    offset: usize,
) -> Result<u16, &'static str> {
    let raw = bytes.get(offset..offset + 2).ok_or("malformed")?;
    Ok(match macho.endian() {
        macho_core::format::io::Endian::Little => u16::from_le_bytes([raw[0], raw[1]]),
        macho_core::format::io::Endian::Big => u16::from_be_bytes([raw[0], raw[1]]),
    })
}

fn read_u32_checked(
    macho: &MachoFile<'_>,
    bytes: &[u8],
    offset: usize,
) -> Result<u32, &'static str> {
    let raw = bytes.get(offset..offset + 4).ok_or("malformed")?;
    Ok(read_u32(macho, raw))
}

fn read_u32(macho: &MachoFile<'_>, raw: &[u8]) -> u32 {
    let bytes: [u8; 4] = raw.try_into().expect("checked four-byte field");
    match macho.endian() {
        macho_core::format::io::Endian::Little => u32::from_le_bytes(bytes),
        macho_core::format::io::Endian::Big => u32::from_be_bytes(bytes),
    }
}

fn read_u64(macho: &MachoFile<'_>, raw: &[u8]) -> u64 {
    let bytes: [u8; 8] = raw.try_into().expect("checked eight-byte field");
    match macho.endian() {
        macho_core::format::io::Endian::Little => u64::from_le_bytes(bytes),
        macho_core::format::io::Endian::Big => u64::from_be_bytes(bytes),
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
    let mut gaps = false;
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
                gaps = true;
                continue;
            }
        };
        let mut offset = 0_usize;
        while offset < bytes.len() {
            let va = span.start + offset as u64;
            match macho_insn::decode_one(&bytes[offset..], va, arch) {
                Ok(instruction) => {
                    let length = instruction.len.max(1).min(bytes.len() - offset);
                    if let InsnKind::Call(_) = instruction.kind
                        && let Some(target) = macho_insn::resolve_branch_target(&instruction, va)
                        && context.sections.containing(target).is_some()
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
                    gaps = true;
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
    } else if gaps {
        (
            FunctionCollectorStatus::Partial,
            Some("direct_call_decode_gaps"),
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

    fn image(bytes: &[u8]) -> macho_core::MachoFile<'_> {
        match macho_core::parse(bytes).expect("fixture parses") {
            macho_core::model::container::MachoContainer::Thin(macho) => macho,
            macho_core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
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
        assert!(!function.completeness.extent_is_authoritative);
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
