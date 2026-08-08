//! Image-bound exception, compact-unwind, and exception-frame recovery.

use std::collections::BTreeMap;

use crate::core::format::relocations_for_section;
use crate::core::model::addr::{ThinFileOffset, Va};
use crate::core::model::macho_file::MachoFile;
use crate::core::model::relocation::Relocation;
use crate::core::model::section::Section;
use crate::core::model::symbol::SymbolTable;
use crate::metadata::dyld::resolve::{PointerResolver, PointerTarget};
use gimli::{
    BaseAddresses, CfaRule, CieOrFde, EhFrame, Pointer, RegisterRule, RunTimeEndian, UnwindContext,
    UnwindSection,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::{FunctionEvidenceConfidence, FunctionImageIdentity};

/// Explicit limits for exception and unwind records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionRecoveryLimits {
    /// Maximum compact-unwind and exception-frame records retained.
    pub max_records: usize,
    /// Maximum bytes read from any one unwind section.
    pub max_section_bytes: usize,
    /// Maximum bytes examined from any one language-specific data area.
    pub max_lsda_bytes: usize,
    /// Maximum semantic call-site records retained across all LSDAs.
    pub max_call_sites: usize,
    /// Maximum action-chain records retained across all call sites.
    pub max_actions: usize,
    /// Maximum evaluated call-frame-information rows.
    pub max_cfi_rows: usize,
}

impl Default for ExceptionRecoveryLimits {
    fn default() -> Self {
        Self {
            max_records: 8_000_000,
            max_section_bytes: 256 * 1024 * 1024,
            max_lsda_bytes: 16 * 1024 * 1024,
            max_call_sites: 8_000_000,
            max_actions: 16_000_000,
            max_cfi_rows: 16_000_000,
        }
    }
}

impl ExceptionRecoveryLimits {
    /// Reject a zero record or section-byte limit.
    pub fn validate(self) -> Result<Self, ExceptionRecoveryError> {
        if self.max_records == 0
            || self.max_section_bytes == 0
            || self.max_lsda_bytes == 0
            || self.max_call_sites == 0
            || self.max_actions == 0
            || self.max_cfi_rows == 0
        {
            return Err(ExceptionRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing exception recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ExceptionRecoveryError {
    /// At least one explicit limit is zero.
    #[error("exception recovery limits must be non-zero")]
    InvalidLimits,
}

/// Exception/unwind record source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionRecordSource {
    /// Object `__compact_unwind` record.
    CompactUnwind,
    /// Linked `__unwind_info` second-level page.
    LinkedUnwindInfo,
    /// Exception-frame FDE.
    ExceptionFrame,
    /// Itanium ABI language-specific data area.
    LanguageSpecificData,
}

/// Meaning of the retained address interval. Linked `__unwind_info` entries
/// are lookup-table ranges for one unwind encoding and can span multiple real
/// functions; they are not function extents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionRecordRangeKind {
    /// The source directly encodes one function's address range.
    FunctionExtent,
    /// The source encodes the address range over which an unwind lookup entry
    /// applies, potentially across multiple functions.
    UnwindLookupRange,
}

/// Resolved personality or language-specific-data target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExceptionPointerTarget {
    /// Address within the selected image.
    Internal {
        /// Unslid target address.
        address: u64,
        /// Whether the encoding points to a slot that must be dereferenced.
        indirect: bool,
    },
    /// Imported personality routine.
    Import {
        /// Imported symbol spelling.
        name: String,
        /// Dynamic-library ordinal when encoded.
        library_ordinal: Option<i32>,
    },
}

/// One function extent or unwind-lookup range established by exception
/// metadata. Inspect `range_kind` before using the interval as function
/// ownership evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionFunctionRecord {
    /// Metadata source.
    pub source: ExceptionRecordSource,
    /// Function entry or unwind lookup-range start.
    pub entry: u64,
    /// Exclusive function or lookup-range end, when encoded.
    pub end_exclusive: Option<u64>,
    /// Whether the interval is a function extent or only an unwind lookup
    /// range.
    pub range_kind: ExceptionRecordRangeKind,
    /// Boundary confidence.
    pub confidence: FunctionEvidenceConfidence,
    /// Compact-unwind encoding, when supplied by that source.
    pub unwind_encoding: Option<u32>,
    /// Language personality routine, when encoded.
    pub personality: Option<ExceptionPointerTarget>,
    /// Language-specific data area, when encoded.
    pub lsda: Option<ExceptionPointerTarget>,
    /// Source record location in the thin image.
    pub source_location: Option<u64>,
}

/// Meaning of one retained LSDA action-chain element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionActionKind {
    /// A zero type filter runs cleanup code without selecting a catch type.
    Cleanup,
    /// A positive type filter selects one catch-type-table entry.
    Catch,
    /// A negative type filter refers to an exception specification.
    ExceptionSpecification,
}

/// One action in the chain referenced by an LSDA call-site record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionActionRecord {
    /// Byte offset of this action within the LSDA.
    pub offset: u64,
    /// Signed Itanium ABI type filter.
    pub type_filter: i64,
    /// Semantic action classification.
    pub kind: ExceptionActionKind,
    /// Next action's signed relative displacement, or zero at chain end.
    pub next_offset: i64,
}

/// One semantic entry from an Itanium ABI LSDA call-site table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionCallSiteRecord {
    /// Function whose unwind metadata points to this LSDA.
    pub function_entry: u64,
    /// First instruction address covered by this entry.
    pub start: u64,
    /// Exclusive covered address.
    pub end_exclusive: u64,
    /// Local landing-pad address; absent means unwinding continues outward.
    pub landing_pad: Option<u64>,
    /// One-based raw action-table selector from the call-site entry.
    pub action_offset: u64,
    /// Retained action chain, in execution-table order.
    pub actions: Vec<ExceptionActionRecord>,
    /// LSDA virtual address establishing this record.
    pub lsda_address: u64,
}

/// Canonical-frame-address rule retained for one evaluated CFI row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExceptionCfaRule {
    /// CFA is a signed offset from one architecture-defined DWARF register.
    RegisterAndOffset {
        /// Architecture-defined DWARF register number.
        register: u16,
        /// Signed byte offset from the register value.
        offset: i64,
    },
    /// CFA requires a DWARF expression not interpreted by this layer.
    Expression,
}

/// Register recovery rule retained from an evaluated CFI row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ExceptionRegisterRule {
    /// Previous value cannot be recovered.
    Undefined,
    /// Register retains its current value.
    SameValue,
    /// Previous value is stored at CFA plus this offset.
    Offset {
        /// Signed CFA-relative byte offset.
        offset: i64,
    },
    /// Previous value equals CFA plus this offset.
    ValueOffset {
        /// Signed CFA-relative value offset.
        offset: i64,
    },
    /// Previous value is held in another register.
    Register {
        /// Architecture-defined DWARF register number.
        register: u16,
    },
    /// Location requires a DWARF expression.
    Expression,
    /// Value requires a DWARF expression.
    ValueExpression,
    /// Rule is defined by an external architecture extension.
    Architectural,
    /// Pseudo-register has a constant value.
    Constant {
        /// Retained constant value.
        value: u64,
    },
}

/// One non-default register rule in an evaluated CFI row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionRegisterRecovery {
    /// Architecture-defined DWARF register number.
    pub register: u16,
    /// Evaluated recovery rule.
    pub rule: ExceptionRegisterRule,
}

/// One evaluated call-frame-information state row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionCfiRow {
    /// Function entry owning the FDE.
    pub function_entry: u64,
    /// First PC governed by this state.
    pub start: u64,
    /// Exclusive governed PC.
    pub end_exclusive: u64,
    /// Argument-area size established by CFI.
    pub saved_args_size: u64,
    /// Canonical-frame-address rule.
    pub cfa: ExceptionCfaRule,
    /// Sorted non-default register rules.
    pub registers: Vec<ExceptionRegisterRecovery>,
}

/// Terminal state for one exception source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionCollectorStatus {
    /// The corresponding section is absent.
    Absent,
    /// Every admitted source record was decoded and retained.
    Complete,
    /// Structural content was malformed or could not be resolved.
    Partial,
    /// An explicit byte or record limit omitted evidence.
    Truncated,
}

/// Conservation receipt for one exception source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionCollectorReceipt {
    /// Metadata source.
    pub source: ExceptionRecordSource,
    /// Terminal state.
    pub status: ExceptionCollectorStatus,
    /// Source records attempted.
    pub attempted: u64,
    /// Records retained.
    pub retained: u64,
    /// Records structurally unresolved.
    pub unknown: u64,
    /// Records omitted by explicit limits.
    pub excluded: u64,
    /// Stable reason codes.
    pub reasons: Vec<String>,
}

/// Exception inventory completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionIndexStatus {
    /// Every supported source is absent.
    Absent,
    /// Every present source was decoded and conserved.
    Complete,
    /// At least one source contained unresolved structural evidence.
    Partial,
    /// An explicit source or retention budget omitted records.
    Truncated,
}

/// Completeness receipt for exception recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExceptionIndexCompleteness {
    /// Overall status.
    pub status: ExceptionIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Retained semantic records.
    pub retained: u64,
}

/// Deterministic exception/unwind inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExceptionIndex {
    image: FunctionImageIdentity,
    limits: ExceptionRecoveryLimits,
    records: Vec<ExceptionFunctionRecord>,
    call_sites: Vec<ExceptionCallSiteRecord>,
    cfi_rows: Vec<ExceptionCfiRow>,
    receipts: Vec<ExceptionCollectorReceipt>,
    completeness: ExceptionIndexCompleteness,
}

impl ExceptionIndex {
    /// Recover compact unwind, linked unwind info, and EH-frame semantics.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: ExceptionRecoveryLimits,
    ) -> Result<Self, ExceptionRecoveryError> {
        let limits = limits.validate()?;
        let mut records = Vec::new();
        let mut receipts = Vec::new();
        collect_compact_unwind(macho, limits, &mut records, &mut receipts);
        collect_linked_unwind(macho, limits, &mut records, &mut receipts);
        let mut cfi_rows = Vec::new();
        collect_eh_frame(macho, limits, &mut records, &mut cfi_rows, &mut receipts);
        cfi_rows.sort_by_key(|row| (row.function_entry, row.start, row.end_exclusive));
        records.sort_by_key(|record| (record.entry, record.source, record.source_location));
        records.dedup();
        receipts.sort_by_key(|receipt| receipt.source);
        let mut call_sites = Vec::new();
        collect_lsdas(macho, limits, &records, &mut call_sites, &mut receipts);
        call_sites.sort_by_key(|record| {
            (
                record.function_entry,
                record.start,
                record.end_exclusive,
                record.lsda_address,
            )
        });
        call_sites.dedup();
        receipts.sort_by_key(|receipt| receipt.source);
        let status = if receipts
            .iter()
            .any(|receipt| receipt.status == ExceptionCollectorStatus::Truncated)
        {
            ExceptionIndexStatus::Truncated
        } else if receipts
            .iter()
            .any(|receipt| receipt.status == ExceptionCollectorStatus::Partial)
        {
            ExceptionIndexStatus::Partial
        } else if receipts
            .iter()
            .all(|receipt| receipt.status == ExceptionCollectorStatus::Absent)
        {
            ExceptionIndexStatus::Absent
        } else {
            ExceptionIndexStatus::Complete
        };
        let mut reasons = receipts
            .iter()
            .flat_map(|receipt| receipt.reasons.iter().cloned())
            .collect::<Vec<_>>();
        reasons.sort();
        reasons.dedup();
        let index = Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            completeness: ExceptionIndexCompleteness {
                status,
                reasons,
                retained: (records.len() + call_sites.len() + cfi_rows.len()) as u64,
            },
            records,
            call_sites,
            cfi_rows,
            receipts,
        };
        debug_assert!(
            index.durable_invariants_hold(),
            "exception durable invariant failed: completeness={:?}, limits={:?}, records={}, call_sites={}, cfi_rows={}, receipts={:?}",
            index.completeness,
            index.limits,
            index.records.len(),
            index.call_sites.len(),
            index.cfi_rows.len(),
            index.receipts,
        );
        Ok(index)
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact recovery limits.
    pub const fn limits(&self) -> ExceptionRecoveryLimits {
        self.limits
    }

    /// Semantic records sorted by function entry and source.
    pub fn records(&self) -> &[ExceptionFunctionRecord] {
        &self.records
    }

    /// Semantic LSDA call-site records sorted by function and covered range.
    pub fn call_sites(&self) -> &[ExceptionCallSiteRecord] {
        &self.call_sites
    }

    /// Evaluated CFI rows sorted by function and address range.
    pub fn cfi_rows(&self) -> &[ExceptionCfiRow] {
        &self.cfi_rows
    }

    /// Iterate semantic LSDA call sites for one recovered function entry.
    pub fn call_sites_by_entry(
        &self,
        entry: u64,
    ) -> impl Iterator<Item = &ExceptionCallSiteRecord> {
        let start = self
            .call_sites
            .partition_point(|record| record.function_entry < entry);
        let end = self
            .call_sites
            .partition_point(|record| record.function_entry <= entry);
        self.call_sites[start..end].iter()
    }

    #[cfg(test)]
    pub(crate) fn from_call_sites_for_test(
        macho: &MachoFile<'_>,
        mut call_sites: Vec<ExceptionCallSiteRecord>,
    ) -> Self {
        call_sites.sort_by_key(|record| {
            (
                record.function_entry,
                record.start,
                record.end_exclusive,
                record.lsda_address,
            )
        });
        let index = Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits: ExceptionRecoveryLimits::default(),
            records: Vec::new(),
            cfi_rows: Vec::new(),
            receipts: vec![ExceptionCollectorReceipt {
                source: ExceptionRecordSource::LanguageSpecificData,
                status: ExceptionCollectorStatus::Complete,
                attempted: call_sites.len() as u64,
                retained: call_sites.len() as u64,
                unknown: 0,
                excluded: 0,
                reasons: Vec::new(),
            }],
            completeness: ExceptionIndexCompleteness {
                status: ExceptionIndexStatus::Complete,
                reasons: Vec::new(),
                retained: call_sites.len() as u64,
            },
            call_sites,
        };
        debug_assert!(index.durable_invariants_hold());
        index
    }

    /// Per-source conservation receipts.
    pub fn receipts(&self) -> &[ExceptionCollectorReceipt] {
        &self.receipts
    }

    /// Overall completion state.
    pub const fn status(&self) -> ExceptionIndexStatus {
        self.completeness.status
    }

    /// Completeness and retention receipt.
    pub const fn completeness(&self) -> &ExceptionIndexCompleteness {
        &self.completeness
    }

    /// Iterate exception/unwind records for one function entry.
    pub fn by_entry(&self, entry: u64) -> impl Iterator<Item = &ExceptionFunctionRecord> {
        let start = self.records.partition_point(|record| record.entry < entry);
        let end = self.records.partition_point(|record| record.entry <= entry);
        self.records[start..end].iter()
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err()
            || self.records.len() > self.limits.max_records
            || self.call_sites.len() > self.limits.max_call_sites
            || self.cfi_rows.len() > self.limits.max_cfi_rows
            || self
                .call_sites
                .iter()
                .try_fold(0_usize, |count, record| {
                    count.checked_add(record.actions.len())
                })
                .is_none_or(|count| count > self.limits.max_actions)
        {
            return false;
        }
        let records_are_canonical = self.records.windows(2).all(|pair| {
            (pair[0].entry, pair[0].source, pair[0].source_location)
                <= (pair[1].entry, pair[1].source, pair[1].source_location)
        }) && self
            .records
            .iter()
            .all(|record| record.end_exclusive.is_none_or(|end| record.entry < end));
        let call_sites_are_canonical = self.call_sites.windows(2).all(|pair| {
            (
                pair[0].function_entry,
                pair[0].start,
                pair[0].end_exclusive,
                pair[0].lsda_address,
            ) <= (
                pair[1].function_entry,
                pair[1].start,
                pair[1].end_exclusive,
                pair[1].lsda_address,
            )
        }) && self.call_sites.iter().all(|record| {
            record.start < record.end_exclusive
                && record
                    .actions
                    .windows(2)
                    .all(|pair| pair[0].offset != pair[1].offset)
        });
        let cfi_rows_are_canonical = self.cfi_rows.windows(2).all(|pair| {
            (pair[0].function_entry, pair[0].start, pair[0].end_exclusive)
                <= (pair[1].function_entry, pair[1].start, pair[1].end_exclusive)
        }) && self.cfi_rows.iter().all(|row| {
            row.start < row.end_exclusive
                && row
                    .registers
                    .windows(2)
                    .all(|pair| pair[0].register < pair[1].register)
        });
        let receipts_are_canonical = self
            .receipts
            .windows(2)
            .all(|pair| pair[0].source < pair[1].source)
            && self.receipts.iter().all(exception_receipt_is_valid);
        let status = if self
            .receipts
            .iter()
            .any(|receipt| receipt.status == ExceptionCollectorStatus::Truncated)
        {
            ExceptionIndexStatus::Truncated
        } else if self
            .receipts
            .iter()
            .any(|receipt| receipt.status == ExceptionCollectorStatus::Partial)
        {
            ExceptionIndexStatus::Partial
        } else if self
            .receipts
            .iter()
            .all(|receipt| receipt.status == ExceptionCollectorStatus::Absent)
        {
            ExceptionIndexStatus::Absent
        } else {
            ExceptionIndexStatus::Complete
        };
        let mut reasons = self
            .receipts
            .iter()
            .flat_map(|receipt| receipt.reasons.iter().cloned())
            .collect::<Vec<_>>();
        reasons.sort();
        reasons.dedup();
        let retained = self
            .records
            .len()
            .checked_add(self.call_sites.len())
            .and_then(|count| count.checked_add(self.cfi_rows.len()))
            .and_then(|count| u64::try_from(count).ok());

        records_are_canonical
            && call_sites_are_canonical
            && cfi_rows_are_canonical
            && receipts_are_canonical
            && self.completeness.status == status
            && self.completeness.reasons == reasons
            && retained == Some(self.completeness.retained)
    }
}

fn exception_receipt_is_valid(receipt: &ExceptionCollectorReceipt) -> bool {
    let reasons_are_canonical = receipt.reasons.windows(2).all(|pair| pair[0] < pair[1]);
    let allows_retained_fanout = receipt.source == ExceptionRecordSource::LanguageSpecificData;
    reasons_are_canonical
        && match receipt.status {
            ExceptionCollectorStatus::Absent => {
                receipt.attempted == 0
                    && receipt.retained == 0
                    && receipt.unknown == 0
                    && receipt.excluded == 0
                    && receipt.reasons.is_empty()
            }
            ExceptionCollectorStatus::Complete => {
                (allows_retained_fanout || receipt.attempted == receipt.retained)
                    && receipt.unknown == 0
                    && receipt.excluded == 0
                    && receipt.reasons.is_empty()
            }
            ExceptionCollectorStatus::Partial => {
                receipt.excluded == 0
                    && receipt.unknown != 0
                    && !receipt.reasons.is_empty()
                    && (allows_retained_fanout || receipt.attempted >= receipt.retained)
            }
            ExceptionCollectorStatus::Truncated => {
                receipt.excluded != 0
                    && !receipt.reasons.is_empty()
                    && (allows_retained_fanout || receipt.attempted >= receipt.retained)
            }
        }
}

fn collect_compact_unwind(
    macho: &MachoFile<'_>,
    limits: ExceptionRecoveryLimits,
    records: &mut Vec<ExceptionFunctionRecord>,
    receipts: &mut Vec<ExceptionCollectorReceipt>,
) {
    let source = ExceptionRecordSource::CompactUnwind;
    let Some(section) = find_section(macho, "__compact_unwind") else {
        receipts.push(absent(source));
        return;
    };
    let size = match bounded_section_size(section, limits.max_section_bytes) {
        Ok(size) => size,
        Err(reason) => {
            receipts.push(truncated(source, reason));
            return;
        }
    };
    if !macho.is_64bit() || size % 32 != 0 {
        receipts.push(partial(source, "exceptions.compact_unwind_malformed", 1));
        return;
    }
    let Ok(bytes) = macho.read_bytes_at(section.offset(), size) else {
        receipts.push(partial(source, "exceptions.compact_unwind_unreadable", 1));
        return;
    };
    let relocations = compact_relocations(macho, section);
    let resolver = PointerResolver::new(macho).ok();
    let available = size / 32;
    let admitted = available.min(limits.max_records.saturating_sub(records.len()));
    let mut unknown = 0_u64;
    for (ordinal, raw) in bytes.chunks_exact(32).take(admitted).enumerate() {
        let relative = (ordinal * 32) as u64;
        let function = resolve_field(
            macho,
            resolver.as_ref(),
            section,
            relative,
            read_u64(macho, &raw[0..8]),
            &relocations,
        );
        let Some(ExceptionPointerTarget::Internal { address: entry, .. }) = function else {
            unknown = unknown.saturating_add(1);
            continue;
        };
        let length = u64::from(read_u32(macho, &raw[8..12]));
        let Some(end) = entry.checked_add(length).filter(|_| length != 0) else {
            unknown = unknown.saturating_add(1);
            continue;
        };
        let personality = resolve_optional_field(
            macho,
            resolver.as_ref(),
            section,
            relative + 16,
            read_u64(macho, &raw[16..24]),
            &relocations,
        );
        let lsda = resolve_optional_field(
            macho,
            resolver.as_ref(),
            section,
            relative + 24,
            read_u64(macho, &raw[24..32]),
            &relocations,
        );
        records.push(ExceptionFunctionRecord {
            source,
            entry,
            end_exclusive: Some(end),
            range_kind: ExceptionRecordRangeKind::FunctionExtent,
            confidence: FunctionEvidenceConfidence::Exact,
            unwind_encoding: Some(read_u32(macho, &raw[12..16])),
            personality,
            lsda,
            source_location: Some(section.offset().0 + relative),
        });
    }
    let excluded = available.saturating_sub(admitted) as u64;
    receipts.push(finish_receipt(
        source,
        available as u64,
        admitted.saturating_sub(unknown as usize) as u64,
        unknown,
        excluded,
        "exceptions.compact_unwind_record_unresolved",
        "exceptions.record_budget",
    ));
}

#[derive(Debug)]
struct LinkedUnwindRecord {
    start: u32,
    end: u32,
    encoding: u32,
    location: u64,
    personality_offset: Option<u32>,
    lsda_offset: Option<u32>,
}

fn collect_linked_unwind(
    macho: &MachoFile<'_>,
    limits: ExceptionRecoveryLimits,
    records: &mut Vec<ExceptionFunctionRecord>,
    receipts: &mut Vec<ExceptionCollectorReceipt>,
) {
    const HEADER_SIZE: usize = 28;
    const INDEX_SIZE: usize = 12;
    const REGULAR: u32 = 2;
    const COMPRESSED: u32 = 3;
    const NOT_FUNCTION_START: u32 = 0x8000_0000;
    const PERSONALITY_MASK: u32 = 0x3000_0000;

    let source = ExceptionRecordSource::LinkedUnwindInfo;
    let Some(section) = find_section(macho, "__unwind_info") else {
        receipts.push(absent(source));
        return;
    };
    let size = match bounded_section_size(section, limits.max_section_bytes) {
        Ok(size) => size,
        Err(reason) => {
            receipts.push(truncated(source, reason));
            return;
        }
    };
    let Ok(bytes) = macho.read_bytes_at(section.offset(), size) else {
        receipts.push(partial(source, "exceptions.unwind_info_unreadable", 1));
        return;
    };
    let parsed = (|| -> Result<Vec<LinkedUnwindRecord>, ()> {
        if bytes.len() < HEADER_SIZE || read_u32(macho, &bytes[0..4]) != 1 {
            return Err(());
        }
        let common_offset = read_u32(macho, &bytes[4..8]) as usize;
        let common_count = read_u32(macho, &bytes[8..12]) as usize;
        let personality_offset = read_u32(macho, &bytes[12..16]) as usize;
        let personality_count = read_u32(macho, &bytes[16..20]) as usize;
        let index_offset = read_u32(macho, &bytes[20..24]) as usize;
        let index_count = read_u32(macho, &bytes[24..28]) as usize;
        if index_count < 2 {
            return Ok(Vec::new());
        }
        checked_end(common_offset, common_count, 4, bytes.len())?;
        checked_end(personality_offset, personality_count, 4, bytes.len())?;
        checked_end(index_offset, index_count, INDEX_SIZE, bytes.len())?;
        let personalities = (0..personality_count)
            .map(|index| read_u32_at(macho, bytes, personality_offset + index * 4))
            .collect::<Result<Vec<_>, _>>()?;
        let indexes = (0..index_count)
            .map(|index| {
                let offset = index_offset + index * INDEX_SIZE;
                Ok((
                    read_u32_at(macho, bytes, offset)?,
                    read_u32_at(macho, bytes, offset + 4)?,
                    read_u32_at(macho, bytes, offset + 8)?,
                ))
            })
            .collect::<Result<Vec<_>, ()>>()?;
        let mut lsdas = BTreeMap::new();
        for pair in indexes.windows(2) {
            let start = pair[0].2 as usize;
            let end = pair[1].2 as usize;
            if start == 0 && end == 0 {
                continue;
            }
            if start > end || end > bytes.len() || (end - start) % 8 != 0 {
                return Err(());
            }
            for offset in (start..end).step_by(8) {
                lsdas.insert(
                    read_u32_at(macho, bytes, offset)?,
                    read_u32_at(macho, bytes, offset + 4)?,
                );
            }
        }
        let mut raw = Vec::new();
        for &(base_function, page_offset, _) in indexes.iter().take(index_count - 1) {
            if page_offset == 0 {
                continue;
            }
            let page = page_offset as usize;
            match read_u32_at(macho, bytes, page)? {
                REGULAR => {
                    let entries_offset = usize::from(read_u16_at(macho, bytes, page + 4)?);
                    let entries_count = usize::from(read_u16_at(macho, bytes, page + 6)?);
                    let start = page.checked_add(entries_offset).ok_or(())?;
                    checked_end(start, entries_count, 8, bytes.len())?;
                    for ordinal in 0..entries_count {
                        let offset = start + ordinal * 8;
                        raw.push((
                            read_u32_at(macho, bytes, offset)?,
                            read_u32_at(macho, bytes, offset + 4)?,
                            section.offset().0 + offset as u64,
                        ));
                    }
                }
                COMPRESSED => {
                    let entries_offset = usize::from(read_u16_at(macho, bytes, page + 4)?);
                    let entries_count = usize::from(read_u16_at(macho, bytes, page + 6)?);
                    let encodings_offset = usize::from(read_u16_at(macho, bytes, page + 8)?);
                    let encodings_count = usize::from(read_u16_at(macho, bytes, page + 10)?);
                    let entries_start = page.checked_add(entries_offset).ok_or(())?;
                    let encodings_start = page.checked_add(encodings_offset).ok_or(())?;
                    checked_end(entries_start, entries_count, 4, bytes.len())?;
                    checked_end(encodings_start, encodings_count, 4, bytes.len())?;
                    for ordinal in 0..entries_count {
                        let offset = entries_start + ordinal * 4;
                        let compressed = read_u32_at(macho, bytes, offset)?;
                        let function = base_function
                            .checked_add(compressed & 0x00ff_ffff)
                            .ok_or(())?;
                        let encoding_index = (compressed >> 24) as usize;
                        let encoding = if encoding_index < common_count {
                            read_u32_at(macho, bytes, common_offset + encoding_index * 4)?
                        } else {
                            let local = encoding_index - common_count;
                            if local >= encodings_count {
                                return Err(());
                            }
                            read_u32_at(macho, bytes, encodings_start + local * 4)?
                        };
                        raw.push((function, encoding, section.offset().0 + offset as u64));
                    }
                }
                _ => return Err(()),
            }
        }
        raw.sort_by_key(|record| (record.0, record.2));
        raw.dedup_by_key(|record| record.0);
        let sentinel = indexes.last().ok_or(())?.0;
        Ok(raw
            .iter()
            .enumerate()
            .filter_map(|(index, &(function, encoding, location))| {
                if encoding & NOT_FUNCTION_START != 0 {
                    return None;
                }
                let end = raw.get(index + 1).map_or(sentinel, |next| next.0);
                let personality_index = ((encoding & PERSONALITY_MASK) >> 28) as usize;
                let personality = personality_index
                    .checked_sub(1)
                    .and_then(|index| personalities.get(index).copied());
                (end > function).then_some(LinkedUnwindRecord {
                    start: function,
                    end,
                    encoding,
                    location,
                    personality_offset: personality,
                    lsda_offset: lsdas.get(&function).copied(),
                })
            })
            .collect())
    })();
    let Ok(parsed) = parsed else {
        receipts.push(partial(source, "exceptions.unwind_info_malformed", 1));
        return;
    };
    let available = parsed.len();
    let admitted = available.min(limits.max_records.saturating_sub(records.len()));
    let mut retained = 0_u64;
    let mut unknown = 0_u64;
    for record in parsed.iter().take(admitted) {
        let personality = record
            .personality_offset
            .and_then(|offset| macho.image_base().0.checked_add(u64::from(offset)))
            .map(|address| ExceptionPointerTarget::Internal {
                address,
                indirect: false,
            });
        let lsda = record
            .lsda_offset
            .and_then(|offset| macho.image_base().0.checked_add(u64::from(offset)))
            .map(|address| ExceptionPointerTarget::Internal {
                address,
                indirect: false,
            });
        let Some(entry) = macho.image_base().0.checked_add(u64::from(record.start)) else {
            unknown = unknown.saturating_add(1);
            continue;
        };
        let Some(end_exclusive) = macho.image_base().0.checked_add(u64::from(record.end)) else {
            unknown = unknown.saturating_add(1);
            continue;
        };
        records.push(ExceptionFunctionRecord {
            source,
            entry,
            end_exclusive: Some(end_exclusive),
            range_kind: ExceptionRecordRangeKind::UnwindLookupRange,
            confidence: FunctionEvidenceConfidence::Derived,
            unwind_encoding: Some(record.encoding),
            personality,
            lsda,
            source_location: Some(record.location),
        });
        retained = retained.saturating_add(1);
    }
    receipts.push(finish_receipt(
        source,
        available as u64,
        retained,
        unknown,
        available.saturating_sub(admitted) as u64,
        "exceptions.unwind_info_record_unresolved",
        "exceptions.record_budget",
    ));
}

fn collect_eh_frame(
    macho: &MachoFile<'_>,
    limits: ExceptionRecoveryLimits,
    records: &mut Vec<ExceptionFunctionRecord>,
    cfi_rows: &mut Vec<ExceptionCfiRow>,
    receipts: &mut Vec<ExceptionCollectorReceipt>,
) {
    let source = ExceptionRecordSource::ExceptionFrame;
    let Some(section) = find_section(macho, "__eh_frame") else {
        receipts.push(absent(source));
        return;
    };
    let size = match bounded_section_size(section, limits.max_section_bytes) {
        Ok(size) => size,
        Err(reason) => {
            receipts.push(truncated(source, reason));
            return;
        }
    };
    let Ok(bytes) = macho.read_bytes_at(section.offset(), size) else {
        receipts.push(partial(source, "exceptions.eh_frame_unreadable", 1));
        return;
    };
    let endian = match macho.endian() {
        crate::core::format::io::Endian::Little => RunTimeEndian::Little,
        crate::core::format::io::Endian::Big => RunTimeEndian::Big,
    };
    let frame = EhFrame::new(bytes, endian);
    let mut bases = BaseAddresses::default().set_eh_frame(section.addr().0);
    if let Some(text) = find_section(macho, "__text") {
        bases = bases.set_text(text.addr().0);
    }
    if let Some(got) = find_section(macho, "__got") {
        bases = bases.set_got(got.addr().0);
    }
    let mut entries = frame.entries(&bases);
    let mut attempted = 0_u64;
    let mut retained = 0_u64;
    let mut unknown = 0_u64;
    let mut excluded = 0_u64;
    loop {
        let item = match entries.next() {
            Ok(item) => item,
            Err(_) => {
                unknown = unknown.saturating_add(1);
                break;
            }
        };
        let Some(CieOrFde::Fde(partial)) = item else {
            if item.is_none() {
                break;
            }
            continue;
        };
        attempted = attempted.saturating_add(1);
        if records.len() >= limits.max_records {
            excluded = excluded.saturating_add(1);
            continue;
        }
        let Ok(fde) = partial.parse(EhFrame::cie_from_offset) else {
            unknown = unknown.saturating_add(1);
            continue;
        };
        if fde.len() == 0 {
            unknown = unknown.saturating_add(1);
            continue;
        }
        let function_entry = fde.initial_address();
        let mut context = UnwindContext::new();
        match fde.rows(&frame, &bases, &mut context) {
            Ok(mut table) => loop {
                match table.next_row() {
                    Ok(Some(row)) => {
                        if cfi_rows.len() >= limits.max_cfi_rows {
                            excluded = excluded.saturating_add(1);
                            break;
                        }
                        let mut registers = row
                            .registers()
                            .map(|&(register, ref rule)| ExceptionRegisterRecovery {
                                register: register.0,
                                rule: exception_register_rule(rule),
                            })
                            .collect::<Vec<_>>();
                        registers.sort_by_key(|rule| rule.register);
                        cfi_rows.push(ExceptionCfiRow {
                            function_entry,
                            start: row.start_address(),
                            end_exclusive: row.end_address(),
                            saved_args_size: row.saved_args_size(),
                            cfa: match row.cfa() {
                                CfaRule::RegisterAndOffset { register, offset } => {
                                    ExceptionCfaRule::RegisterAndOffset {
                                        register: register.0,
                                        offset: *offset,
                                    }
                                }
                                CfaRule::Expression(_) => ExceptionCfaRule::Expression,
                            },
                            registers,
                        });
                    }
                    Ok(None) => break,
                    Err(_) => {
                        unknown = unknown.saturating_add(1);
                        break;
                    }
                }
            },
            Err(_) => unknown = unknown.saturating_add(1),
        }
        records.push(ExceptionFunctionRecord {
            source,
            entry: function_entry,
            end_exclusive: Some(fde.end_address()),
            range_kind: ExceptionRecordRangeKind::FunctionExtent,
            confidence: FunctionEvidenceConfidence::Exact,
            unwind_encoding: None,
            personality: fde.personality().map(pointer_target),
            lsda: fde.lsda().map(pointer_target),
            source_location: None,
        });
        retained = retained.saturating_add(1);
    }
    receipts.push(finish_receipt(
        source,
        attempted,
        retained,
        unknown,
        excluded,
        "exceptions.eh_frame_record_unresolved",
        "exceptions.record_budget",
    ));
}

fn exception_register_rule<T: gimli::ReaderOffset>(
    rule: &RegisterRule<T>,
) -> ExceptionRegisterRule {
    match rule {
        RegisterRule::Undefined => ExceptionRegisterRule::Undefined,
        RegisterRule::SameValue => ExceptionRegisterRule::SameValue,
        RegisterRule::Offset(offset) => ExceptionRegisterRule::Offset { offset: *offset },
        RegisterRule::ValOffset(offset) => ExceptionRegisterRule::ValueOffset { offset: *offset },
        RegisterRule::Register(register) => ExceptionRegisterRule::Register {
            register: register.0,
        },
        RegisterRule::Expression(_) => ExceptionRegisterRule::Expression,
        RegisterRule::ValExpression(_) => ExceptionRegisterRule::ValueExpression,
        RegisterRule::Architectural => ExceptionRegisterRule::Architectural,
        RegisterRule::Constant(value) => ExceptionRegisterRule::Constant { value: *value },
    }
}

fn collect_lsdas(
    macho: &MachoFile<'_>,
    limits: ExceptionRecoveryLimits,
    function_records: &[ExceptionFunctionRecord],
    call_sites: &mut Vec<ExceptionCallSiteRecord>,
    receipts: &mut Vec<ExceptionCollectorReceipt>,
) {
    let source = ExceptionRecordSource::LanguageSpecificData;
    let mut inputs = function_records
        .iter()
        .filter_map(|record| match record.lsda.as_ref()? {
            ExceptionPointerTarget::Internal {
                address,
                indirect: false,
            } => Some((record.entry, *address)),
            ExceptionPointerTarget::Internal { indirect: true, .. }
            | ExceptionPointerTarget::Import { .. } => None,
        })
        .collect::<Vec<_>>();
    inputs.sort_unstable();
    inputs.dedup();
    if inputs.is_empty() {
        receipts.push(absent(source));
        return;
    }
    let mut attempted = 0_u64;
    let mut retained = 0_u64;
    let mut unknown = 0_u64;
    let mut excluded = 0_u64;
    let mut retained_actions = 0_usize;
    for (function_entry, lsda_address) in inputs {
        attempted = attempted.saturating_add(1);
        if call_sites.len() >= limits.max_call_sites || retained_actions >= limits.max_actions {
            excluded = excluded.saturating_add(1);
            continue;
        }
        match parse_lsda(
            macho,
            function_entry,
            lsda_address,
            limits,
            limits.max_call_sites - call_sites.len(),
            limits.max_actions - retained_actions,
        ) {
            Ok(mut parsed) => {
                retained = retained.saturating_add(parsed.len() as u64);
                retained_actions = retained_actions.saturating_add(
                    parsed
                        .iter()
                        .map(|record| record.actions.len())
                        .sum::<usize>(),
                );
                call_sites.append(&mut parsed);
            }
            Err(LsdaParseError::Budget) => excluded = excluded.saturating_add(1),
            Err(LsdaParseError::Malformed | LsdaParseError::UnsupportedEncoding) => {
                unknown = unknown.saturating_add(1);
            }
        }
    }
    receipts.push(finish_receipt(
        source,
        attempted,
        retained,
        unknown,
        excluded,
        "exceptions.lsda_unresolved",
        "exceptions.lsda_budget",
    ));
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LsdaParseError {
    Malformed,
    UnsupportedEncoding,
    Budget,
}

fn parse_lsda(
    macho: &MachoFile<'_>,
    function_entry: u64,
    lsda_address: u64,
    limits: ExceptionRecoveryLimits,
    remaining_call_sites: usize,
    remaining_actions: usize,
) -> Result<Vec<ExceptionCallSiteRecord>, LsdaParseError> {
    const OMIT: u8 = 0xff;
    let section = macho
        .all_sections()
        .find(|section| {
            lsda_address >= section.addr().0
                && lsda_address < section.addr().0.saturating_add(section.size())
        })
        .ok_or(LsdaParseError::Malformed)?;
    let relative = lsda_address
        .checked_sub(section.addr().0)
        .ok_or(LsdaParseError::Malformed)?;
    let available = usize::try_from(section.size().saturating_sub(relative))
        .map_err(|_| LsdaParseError::Budget)?;
    let length = available.min(limits.max_lsda_bytes);
    let bytes = macho
        .read_bytes_at_va(Va(lsda_address), length)
        .map_err(|_| LsdaParseError::Malformed)?;
    let mut cursor = 0_usize;
    let lpstart_encoding = read_byte(bytes, &mut cursor)?;
    let landing_pad_base = if lpstart_encoding == OMIT {
        function_entry
    } else {
        read_encoded_pointer(
            macho,
            bytes,
            &mut cursor,
            lpstart_encoding,
            lsda_address,
            function_entry,
        )?
    };
    let type_encoding = read_byte(bytes, &mut cursor)?;
    if type_encoding != OMIT {
        let _type_table_offset = read_uleb(bytes, &mut cursor)?;
    }
    let call_site_encoding = read_byte(bytes, &mut cursor)?;
    if call_site_encoding == OMIT || call_site_encoding & 0xf0 != 0 {
        return Err(LsdaParseError::UnsupportedEncoding);
    }
    let table_length =
        usize::try_from(read_uleb(bytes, &mut cursor)?).map_err(|_| LsdaParseError::Malformed)?;
    let table_end = cursor
        .checked_add(table_length)
        .filter(|end| *end <= bytes.len())
        .ok_or(LsdaParseError::Malformed)?;
    let action_table_start = table_end;
    let mut result = Vec::new();
    while cursor < table_end {
        if result.len() == remaining_call_sites {
            return Err(LsdaParseError::Budget);
        }
        let start_offset = read_encoded_offset(macho, bytes, &mut cursor, call_site_encoding)?;
        let length = read_encoded_offset(macho, bytes, &mut cursor, call_site_encoding)?;
        let landing_offset = read_encoded_offset(macho, bytes, &mut cursor, call_site_encoding)?;
        let action_offset = read_uleb(bytes, &mut cursor)?;
        if cursor > table_end || length == 0 {
            return Err(LsdaParseError::Malformed);
        }
        let start = landing_pad_base
            .checked_add(start_offset)
            .ok_or(LsdaParseError::Malformed)?;
        let end_exclusive = start.checked_add(length).ok_or(LsdaParseError::Malformed)?;
        let landing_pad = if landing_offset == 0 {
            None
        } else {
            Some(
                landing_pad_base
                    .checked_add(landing_offset)
                    .ok_or(LsdaParseError::Malformed)?,
            )
        };
        let actions = parse_action_chain(
            bytes,
            action_table_start,
            action_offset,
            remaining_actions.saturating_sub(
                result
                    .iter()
                    .map(|record: &ExceptionCallSiteRecord| record.actions.len())
                    .sum::<usize>(),
            ),
        )?;
        result.push(ExceptionCallSiteRecord {
            function_entry,
            start,
            end_exclusive,
            landing_pad,
            action_offset,
            actions,
            lsda_address,
        });
    }
    Ok(result)
}

fn parse_action_chain(
    bytes: &[u8],
    action_table_start: usize,
    action_offset: u64,
    remaining_actions: usize,
) -> Result<Vec<ExceptionActionRecord>, LsdaParseError> {
    if action_offset == 0 {
        return Ok(Vec::new());
    }
    let mut cursor = action_table_start
        .checked_add(usize::try_from(action_offset - 1).map_err(|_| LsdaParseError::Malformed)?)
        .ok_or(LsdaParseError::Malformed)?;
    let mut result = Vec::new();
    let mut visited = std::collections::BTreeSet::new();
    loop {
        if result.len() == remaining_actions {
            return Err(LsdaParseError::Budget);
        }
        if !visited.insert(cursor) {
            return Err(LsdaParseError::Malformed);
        }
        let offset = cursor;
        let type_filter = read_sleb(bytes, &mut cursor)?;
        let displacement_base = cursor;
        let next_offset = read_sleb(bytes, &mut cursor)?;
        result.push(ExceptionActionRecord {
            offset: offset as u64,
            type_filter,
            kind: if type_filter == 0 {
                ExceptionActionKind::Cleanup
            } else if type_filter > 0 {
                ExceptionActionKind::Catch
            } else {
                ExceptionActionKind::ExceptionSpecification
            },
            next_offset,
        });
        if next_offset == 0 {
            break;
        }
        cursor = displacement_base
            .checked_add_signed(
                isize::try_from(next_offset).map_err(|_| LsdaParseError::Malformed)?,
            )
            .ok_or(LsdaParseError::Malformed)?;
    }
    Ok(result)
}

fn read_byte(bytes: &[u8], cursor: &mut usize) -> Result<u8, LsdaParseError> {
    let value = *bytes.get(*cursor).ok_or(LsdaParseError::Malformed)?;
    *cursor += 1;
    Ok(value)
}

fn read_uleb(bytes: &[u8], cursor: &mut usize) -> Result<u64, LsdaParseError> {
    let mut reader = crate::metadata::dyld::uleb::LebReader::at(bytes, *cursor);
    let value = reader
        .read_uleb128()
        .map_err(|_| LsdaParseError::Malformed)?;
    *cursor = reader.pos();
    Ok(value)
}

fn read_sleb(bytes: &[u8], cursor: &mut usize) -> Result<i64, LsdaParseError> {
    let mut reader = crate::metadata::dyld::uleb::LebReader::at(bytes, *cursor);
    let value = reader
        .read_sleb128()
        .map_err(|_| LsdaParseError::Malformed)?;
    *cursor = reader.pos();
    Ok(value)
}

fn read_encoded_offset(
    macho: &MachoFile<'_>,
    bytes: &[u8],
    cursor: &mut usize,
    encoding: u8,
) -> Result<u64, LsdaParseError> {
    if encoding & 0xf0 != 0 {
        return Err(LsdaParseError::UnsupportedEncoding);
    }
    read_encoded_scalar(macho, bytes, cursor, encoding & 0x0f)
}

fn read_encoded_pointer(
    macho: &MachoFile<'_>,
    bytes: &[u8],
    cursor: &mut usize,
    encoding: u8,
    lsda_address: u64,
    function_entry: u64,
) -> Result<u64, LsdaParseError> {
    if encoding & 0x80 != 0 || encoding & 0x70 == 0x50 {
        return Err(LsdaParseError::UnsupportedEncoding);
    }
    let field_address = lsda_address
        .checked_add(*cursor as u64)
        .ok_or(LsdaParseError::Malformed)?;
    let value = read_encoded_scalar(macho, bytes, cursor, encoding & 0x0f)?;
    match encoding & 0x70 {
        0x00 => Ok(value),
        0x10 => field_address
            .checked_add(value)
            .ok_or(LsdaParseError::Malformed),
        0x40 => function_entry
            .checked_add(value)
            .ok_or(LsdaParseError::Malformed),
        _ => Err(LsdaParseError::UnsupportedEncoding),
    }
}

fn read_encoded_scalar(
    macho: &MachoFile<'_>,
    bytes: &[u8],
    cursor: &mut usize,
    format: u8,
) -> Result<u64, LsdaParseError> {
    let take = |cursor: &mut usize, width: usize| {
        let raw = bytes
            .get(*cursor..cursor.saturating_add(width))
            .ok_or(LsdaParseError::Malformed)?;
        *cursor += width;
        Ok::<_, LsdaParseError>(raw)
    };
    match format {
        0x00 => {
            let width = if macho.is_64bit() { 8 } else { 4 };
            let raw = take(cursor, width)?;
            Ok(if width == 8 {
                read_u64(macho, raw)
            } else {
                u64::from(read_u32(macho, raw))
            })
        }
        0x01 => read_uleb(bytes, cursor),
        0x02 => Ok(u64::from(read_u16(macho, take(cursor, 2)?))),
        0x03 => Ok(u64::from(read_u32(macho, take(cursor, 4)?))),
        0x04 => Ok(read_u64(macho, take(cursor, 8)?)),
        0x09 => u64::try_from(read_sleb(bytes, cursor)?).map_err(|_| LsdaParseError::Malformed),
        0x0a => i64::from(read_i16(macho, take(cursor, 2)?))
            .try_into()
            .map_err(|_| LsdaParseError::Malformed),
        0x0b => i64::from(read_i32(macho, take(cursor, 4)?))
            .try_into()
            .map_err(|_| LsdaParseError::Malformed),
        0x0c => read_i64(macho, take(cursor, 8)?)
            .try_into()
            .map_err(|_| LsdaParseError::Malformed),
        _ => Err(LsdaParseError::UnsupportedEncoding),
    }
}

fn compact_relocations(
    macho: &MachoFile<'_>,
    section: &Section,
) -> BTreeMap<u64, ExceptionPointerTarget> {
    let Ok(relocations) = relocations_for_section(macho, section) else {
        return BTreeMap::new();
    };
    let symbols = macho.ext::<SymbolTable<'_>>().ok();
    let sections = macho.all_sections().collect::<Vec<_>>();
    relocations
        .into_iter()
        .filter_map(|relocation| match relocation {
            Relocation::Standard(relocation) if relocation.is_extern => {
                let symbol = symbols.as_ref()?.get(relocation.symbol_num as usize)?;
                let target = if symbol.is_undefined() {
                    ExceptionPointerTarget::Import {
                        name: symbol.name.to_owned(),
                        library_ordinal: Some(symbol.library_ordinal() as i32),
                    }
                } else {
                    ExceptionPointerTarget::Internal {
                        address: symbol.value.checked_add(relocation_addend(
                            macho,
                            section,
                            u64::from(relocation.address),
                        )?)?,
                        indirect: false,
                    }
                };
                Some((u64::from(relocation.address), target))
            }
            Relocation::Standard(relocation) => {
                let target_section = sections.get(relocation.symbol_num.checked_sub(1)? as usize)?;
                Some((
                    u64::from(relocation.address),
                    ExceptionPointerTarget::Internal {
                        address: target_section.addr().0.checked_add(relocation_addend(
                            macho,
                            section,
                            u64::from(relocation.address),
                        )?)?,
                        indirect: false,
                    },
                ))
            }
            Relocation::Scattered(relocation) => {
                let relative = u64::from(relocation.address);
                Some((
                    relative,
                    ExceptionPointerTarget::Internal {
                        address: u64::from(relocation.value as u32)
                            .checked_add(relocation_addend(macho, section, relative)?)?,
                        indirect: false,
                    },
                ))
            }
        })
        .collect()
}

fn relocation_addend(macho: &MachoFile<'_>, section: &Section, relative: u64) -> Option<u64> {
    let offset = section.offset().0.checked_add(relative)?;
    let raw = macho.read_bytes_at(ThinFileOffset(offset), 8).ok()?;
    Some(read_u64(macho, raw))
}

fn resolve_optional_field(
    macho: &MachoFile<'_>,
    resolver: Option<&PointerResolver<'_, '_>>,
    section: &Section,
    relative: u64,
    raw: u64,
    relocations: &BTreeMap<u64, ExceptionPointerTarget>,
) -> Option<ExceptionPointerTarget> {
    if raw == 0 && !relocations.contains_key(&relative) {
        None
    } else {
        resolve_field(macho, resolver, section, relative, raw, relocations)
    }
}

fn resolve_field(
    _macho: &MachoFile<'_>,
    resolver: Option<&PointerResolver<'_, '_>>,
    section: &Section,
    relative: u64,
    raw: u64,
    relocations: &BTreeMap<u64, ExceptionPointerTarget>,
) -> Option<ExceptionPointerTarget> {
    if let Some(target) = relocations.get(&relative) {
        return Some(target.clone());
    }
    let offset = section.offset().0.checked_add(relative)?;
    if let Some(resolver) = resolver
        && let Ok(observation) = resolver.observe_at_offset(ThinFileOffset(offset))
    {
        return match observation.target {
            PointerTarget::Null => None,
            PointerTarget::Address(address) => Some(ExceptionPointerTarget::Internal {
                address: address.0,
                indirect: false,
            }),
            PointerTarget::Import {
                name,
                library_ordinal,
            } => Some(ExceptionPointerTarget::Import {
                name,
                library_ordinal,
            }),
        };
    }
    (raw != 0).then_some(ExceptionPointerTarget::Internal {
        address: raw,
        indirect: false,
    })
}

fn pointer_target(pointer: Pointer) -> ExceptionPointerTarget {
    match pointer {
        Pointer::Direct(address) => ExceptionPointerTarget::Internal {
            address,
            indirect: false,
        },
        Pointer::Indirect(address) => ExceptionPointerTarget::Internal {
            address,
            indirect: true,
        },
    }
}

fn find_section<'a>(macho: &'a MachoFile<'_>, name: &str) -> Option<&'a Section> {
    macho
        .all_sections()
        .find(|section| section.section_name() == name)
}

fn bounded_section_size(section: &Section, limit: usize) -> Result<usize, &'static str> {
    let size = usize::try_from(section.size()).map_err(|_| "exceptions.section_budget")?;
    (size <= limit)
        .then_some(size)
        .ok_or("exceptions.section_budget")
}

fn checked_end(start: usize, count: usize, stride: usize, len: usize) -> Result<(), ()> {
    let end = start
        .checked_add(count.checked_mul(stride).ok_or(())?)
        .ok_or(())?;
    (end <= len).then_some(()).ok_or(())
}

fn read_u16_at(macho: &MachoFile<'_>, bytes: &[u8], offset: usize) -> Result<u16, ()> {
    let raw = bytes.get(offset..offset + 2).ok_or(())?;
    Ok(macho.endian().read_u16(raw.try_into().map_err(|_| ())?))
}

fn read_u32_at(macho: &MachoFile<'_>, bytes: &[u8], offset: usize) -> Result<u32, ()> {
    let raw = bytes.get(offset..offset + 4).ok_or(())?;
    Ok(read_u32(macho, raw))
}

fn read_u32(macho: &MachoFile<'_>, raw: &[u8]) -> u32 {
    macho
        .endian()
        .read_u32(raw.try_into().expect("validated four-byte field"))
}

fn read_u16(macho: &MachoFile<'_>, raw: &[u8]) -> u16 {
    macho
        .endian()
        .read_u16(raw.try_into().expect("validated two-byte field"))
}

fn read_i16(macho: &MachoFile<'_>, raw: &[u8]) -> i16 {
    read_u16(macho, raw) as i16
}

fn read_i32(macho: &MachoFile<'_>, raw: &[u8]) -> i32 {
    read_u32(macho, raw) as i32
}

fn read_i64(macho: &MachoFile<'_>, raw: &[u8]) -> i64 {
    read_u64(macho, raw) as i64
}

fn read_u64(macho: &MachoFile<'_>, raw: &[u8]) -> u64 {
    macho
        .endian()
        .read_u64(raw.try_into().expect("validated eight-byte field"))
}

fn absent(source: ExceptionRecordSource) -> ExceptionCollectorReceipt {
    ExceptionCollectorReceipt {
        source,
        status: ExceptionCollectorStatus::Absent,
        attempted: 0,
        retained: 0,
        unknown: 0,
        excluded: 0,
        reasons: Vec::new(),
    }
}

fn partial(source: ExceptionRecordSource, reason: &str, unknown: u64) -> ExceptionCollectorReceipt {
    ExceptionCollectorReceipt {
        source,
        status: ExceptionCollectorStatus::Partial,
        attempted: unknown,
        retained: 0,
        unknown,
        excluded: 0,
        reasons: vec![reason.to_owned()],
    }
}

fn truncated(source: ExceptionRecordSource, reason: &str) -> ExceptionCollectorReceipt {
    ExceptionCollectorReceipt {
        source,
        status: ExceptionCollectorStatus::Truncated,
        attempted: 0,
        retained: 0,
        unknown: 0,
        excluded: 1,
        reasons: vec![reason.to_owned()],
    }
}

#[allow(clippy::too_many_arguments)]
fn finish_receipt(
    source: ExceptionRecordSource,
    attempted: u64,
    retained: u64,
    unknown: u64,
    excluded: u64,
    partial_reason: &str,
    truncated_reason: &str,
) -> ExceptionCollectorReceipt {
    let (status, reasons) = if excluded != 0 {
        (
            ExceptionCollectorStatus::Truncated,
            vec![truncated_reason.to_owned()],
        )
    } else if unknown != 0 {
        (
            ExceptionCollectorStatus::Partial,
            vec![partial_reason.to_owned()],
        )
    } else {
        (ExceptionCollectorStatus::Complete, Vec::new())
    };
    ExceptionCollectorReceipt {
        source,
        status,
        attempted,
        retained,
        unknown,
        excluded,
        reasons,
    }
}

#[cfg(test)]
mod tests {
    use crate::core::model::container::MachoContainer;

    use super::*;

    fn image(bytes: &[u8]) -> MachoFile<'_> {
        match crate::core::parse(bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        }
    }

    #[test]
    fn lsda_receipt_allows_one_table_to_retain_multiple_call_sites() {
        let receipt = ExceptionCollectorReceipt {
            source: ExceptionRecordSource::LanguageSpecificData,
            status: ExceptionCollectorStatus::Complete,
            attempted: 1,
            retained: 2,
            unknown: 0,
            excluded: 0,
            reasons: Vec::new(),
        };

        assert!(exception_receipt_is_valid(&receipt));
    }

    #[test]
    fn compact_unwind_recovers_boundaries_personality_and_lsda() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x68..0x78].fill(0);
        bytes[0x68..0x78][..16.min("__compact_unwind".len())]
            .copy_from_slice(&b"__compact_unwind"[..16]);
        bytes[0x90..0x98].copy_from_slice(&32_u64.to_le_bytes());
        bytes[0x100..0x140].fill(0);
        bytes[0x100..0x108].copy_from_slice(&0x1_0000_0200_u64.to_le_bytes());
        bytes[0x108..0x10c].copy_from_slice(&0x20_u32.to_le_bytes());
        bytes[0x10c..0x110].copy_from_slice(&0x1234_u32.to_le_bytes());
        bytes[0x110..0x118].copy_from_slice(&0x1_0000_0300_u64.to_le_bytes());
        bytes[0x118..0x120].copy_from_slice(&0x1_0000_0400_u64.to_le_bytes());

        let index =
            ExceptionIndex::recover(&image(&bytes), ExceptionRecoveryLimits::default()).unwrap();
        assert_eq!(index.status(), ExceptionIndexStatus::Partial);
        let record = &index.records()[0];
        assert_eq!(record.entry, 0x1_0000_0200);
        assert_eq!(record.end_exclusive, Some(0x1_0000_0220));
        assert_eq!(record.range_kind, ExceptionRecordRangeKind::FunctionExtent);
        assert_eq!(record.unwind_encoding, Some(0x1234));
        assert_eq!(
            record.personality,
            Some(ExceptionPointerTarget::Internal {
                address: 0x1_0000_0300,
                indirect: false
            })
        );
        assert_eq!(
            record.lsda,
            Some(ExceptionPointerTarget::Internal {
                address: 0x1_0000_0400,
                indirect: false
            })
        );
        let lsda = index
            .receipts()
            .iter()
            .find(|receipt| receipt.source == ExceptionRecordSource::LanguageSpecificData)
            .unwrap();
        assert_eq!(lsda.status, ExceptionCollectorStatus::Partial);
        assert_eq!(lsda.unknown, 1);
    }

    #[test]
    fn lsda_recovers_call_site_landing_pad_and_action_chain() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x130..0x13a]
            .copy_from_slice(&[0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x20, 0x01, 0x01, 0x00]);
        let macho = image(&bytes);
        let call_sites = parse_lsda(
            &macho,
            0x1_0000_0100,
            0x1_0000_0130,
            ExceptionRecoveryLimits::default(),
            8,
            8,
        )
        .unwrap();
        assert_eq!(call_sites.len(), 1);
        assert_eq!(call_sites[0].start, 0x1_0000_0100);
        assert_eq!(call_sites[0].end_exclusive, 0x1_0000_0105);
        assert_eq!(call_sites[0].landing_pad, Some(0x1_0000_0120));
        assert_eq!(call_sites[0].action_offset, 1);
        assert_eq!(call_sites[0].actions.len(), 1);
        assert_eq!(call_sites[0].actions[0].kind, ExceptionActionKind::Catch);
        assert_eq!(call_sites[0].actions[0].type_filter, 1);
    }

    #[test]
    fn lsda_rejects_unsupported_encoding_and_conserves_action_budget() {
        let mut unsupported = macho_test_support::disassembly_x86_64();
        unsupported[0x130..0x134].copy_from_slice(&[0xff, 0xff, 0x11, 0x00]);
        assert_eq!(
            parse_lsda(
                &image(&unsupported),
                0x1_0000_0100,
                0x1_0000_0130,
                ExceptionRecoveryLimits::default(),
                8,
                8,
            ),
            Err(LsdaParseError::UnsupportedEncoding)
        );

        let mut limited = macho_test_support::disassembly_x86_64();
        limited[0x130..0x13a]
            .copy_from_slice(&[0xff, 0xff, 0x01, 0x04, 0x00, 0x05, 0x20, 0x01, 0x01, 0x00]);
        assert_eq!(
            parse_lsda(
                &image(&limited),
                0x1_0000_0100,
                0x1_0000_0130,
                ExceptionRecoveryLimits::default(),
                8,
                0,
            ),
            Err(LsdaParseError::Budget)
        );
    }

    #[test]
    fn checked_in_arm64_and_x86_linked_unwind_is_fully_conserved() {
        for bytes in [
            include_bytes!("../../tests/fixtures/arm64-darwin-tagged-rtti.dylib").as_slice(),
            include_bytes!("../../tests/fixtures/x86_64-darwin-tagged-rtti.dylib").as_slice(),
        ] {
            let index =
                ExceptionIndex::recover(&image(bytes), ExceptionRecoveryLimits::default()).unwrap();
            assert_eq!(index.status(), ExceptionIndexStatus::Complete);
            assert!(!index.records().is_empty());
            let linked = index
                .receipts()
                .iter()
                .find(|receipt| receipt.source == ExceptionRecordSource::LinkedUnwindInfo)
                .unwrap();
            assert_eq!(linked.status, ExceptionCollectorStatus::Complete);
            assert!(
                index
                    .records()
                    .iter()
                    .filter(|record| record.source == ExceptionRecordSource::LinkedUnwindInfo)
                    .all(|record| {
                        record.range_kind == ExceptionRecordRangeKind::UnwindLookupRange
                    })
            );
            assert_eq!(linked.attempted, linked.retained);
            assert_eq!(linked.unknown, 0);
            assert_eq!(linked.excluded, 0);
        }
    }
}
