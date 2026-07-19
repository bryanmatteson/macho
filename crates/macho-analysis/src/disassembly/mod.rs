//! Bounded, architecture-aware disassembly service.

mod decode;
mod metadata;
mod section_index;
mod selection;
mod sink;

#[cfg(test)]
mod tests;

use std::num::NonZeroUsize;

use macho_core::format::constants::{CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64, CPU_TYPE_X86_64};
use macho_core::model::addr::Va;
use macho_core::model::container::MachoContainer;
use macho_core::model::header::ArchSpec;
use macho_insn::Arch;

use crate::report::disassembly::{
    DisassemblyReport, DisassemblyReportRequest, ReportAddressExtent, ReportDecodeMode,
    ReportSectionSelector, ReportSelection,
};
use crate::report::{Architecture, ContainerKind, ReportContainerIdentity};

use self::decode::decode_slice;
use self::metadata::collect_metadata;
use self::selection::{SelectedSlice, resolve_regions};
use self::sink::CollectingSink;
pub use self::sink::{DisassemblySink, RegionHeader, RegionSummary, SliceHeader, SliceSummary};

/// Unsupported selected CPU tuple.
pub const ARCH_UNSUPPORTED_CODE: &str = "analysis.disassembly.arch.unsupported";
/// Ambiguous display architecture selector.
pub const ARCH_AMBIGUOUS_CODE: &str = "analysis.disassembly.arch.ambiguous";
/// Malformed exact section selector.
pub const SECTION_INVALID_CODE: &str = "analysis.disassembly.section.invalid";
/// Missing or non-file-backed exact section.
pub const SECTION_MISSING_CODE: &str = "analysis.disassembly.section.missing";
/// Missing exact raw symbol.
pub const SYMBOL_MISSING_CODE: &str = "analysis.disassembly.symbol.missing";
/// Exact raw symbol resolving to multiple addresses.
pub const SYMBOL_AMBIGUOUS_CODE: &str = "analysis.disassembly.symbol.ambiguous";
/// Exact symbol outside an instruction section.
pub const SYMBOL_NON_CODE_CODE: &str = "analysis.disassembly.symbol.non_code";
/// Malformed metadata needed for symbol ownership.
pub const SYMBOL_METADATA_INVALID_CODE: &str = "analysis.disassembly.symbol.metadata_invalid";
/// Address outside a file-backed section.
pub const ADDRESS_UNMAPPED_CODE: &str = "analysis.disassembly.address.unmapped";
/// Explicit address range crossing a section boundary.
pub const ADDRESS_CROSS_SECTION_CODE: &str = "analysis.disassembly.address.cross_section";
/// Unaligned ARM instruction start.
pub const ADDRESS_UNALIGNED_CODE: &str = "analysis.disassembly.address.unaligned";
/// Caller-selected byte end inside a valid instruction.
pub const PARTIAL_INSTRUCTION_CODE: &str = "analysis.disassembly.selection.partial_instruction";
/// Natural section end before a requested instruction count.
pub const COUNT_UNSATISFIED_CODE: &str = "analysis.disassembly.count.unsatisfied";
/// Invalid request construction or cross-field combination.
pub const REQUEST_INVALID_CODE: &str = "analysis.disassembly.request.invalid";
/// Internally or externally inconsistent schema-version-1 report.
pub const REPORT_INVALID_CODE: &str = "analysis.disassembly.report.invalid";
/// Failure writing streamed disassembly output through a sink.
pub const OUTPUT_FAILED_CODE: &str = "analysis.disassembly.output.failed";

/// Requested slices.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SliceSelection {
    /// Every slice, in container order.
    All,
    /// One exact raw CPU tuple.
    Exact(Architecture),
}

/// One exact Mach-O section selector.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SectionSelector {
    /// Segment name.
    pub(crate) segment: String,
    /// Section name.
    pub(crate) section: String,
}

impl SectionSelector {
    /// Construct an exact segment/section selector.
    pub fn new(
        segment: impl Into<String>,
        section: impl Into<String>,
    ) -> Result<Self, DisassemblyError> {
        let segment = segment.into();
        let section = section.into();
        if segment.is_empty()
            || section.is_empty()
            || segment.contains(',')
            || section.contains(',')
        {
            return Err(DisassemblyError::new(
                SECTION_INVALID_CODE,
                "section selectors require non-empty exact names without commas",
            ));
        }
        Ok(Self { segment, section })
    }

    /// Exact segment name.
    pub fn segment(&self) -> &str {
        &self.segment
    }

    /// Exact section name.
    pub fn section(&self) -> &str {
        &self.section
    }
}

/// An owned collection that statically contains at least one value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonEmpty<T> {
    values: Vec<T>,
}

impl<T> NonEmpty<T> {
    /// Validate and retain an owned collection.
    pub fn try_from_vec(values: Vec<T>) -> Result<Self, DisassemblyError> {
        if values.is_empty() {
            return Err(DisassemblyError::new(
                REQUEST_INVALID_CODE,
                "selection values must not be empty",
            ));
        }
        Ok(Self { values })
    }

    /// Borrow the retained values.
    pub fn as_slice(&self) -> &[T] {
        &self.values
    }

    /// Number of retained values.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// This validated collection is never empty.
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Iterate over retained values.
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.values.iter()
    }
}

/// Requested disassembly region source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisassemblySelection {
    /// Every non-empty file-backed section carrying either instruction flag.
    ExecutableSections,
    /// Exact section pairs.
    Sections(NonEmpty<SectionSelector>),
    /// Exact raw nlist or export-trie names.
    Symbols(NonEmpty<String>),
    /// One virtual address and extent.
    Address {
        /// Start virtual address.
        start: Va,
        /// Requested extent.
        extent: AddressExtent,
    },
}

/// Address-selection extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressExtent {
    /// Decode exactly this many instructions.
    InstructionCount(NonZeroUsize),
    /// Examine exactly this many bytes.
    ByteLength(NonZeroUsize),
}

/// Decode failure behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeMode {
    /// Retain invalid selected bytes as explicit gaps.
    Recovering,
    /// Fail on the first invalid byte or clipped instruction.
    Strict,
}

/// Complete owned request for one disassembly operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DisassemblyRequest {
    /// Slice selection.
    pub(crate) arches: SliceSelection,
    /// Region selection.
    pub(crate) selection: DisassemblySelection,
    /// Decode behavior.
    pub(crate) mode: DecodeMode,
    /// Demangle retained labels.
    pub(crate) demangle: bool,
    /// Cumulative examined-byte limit for each slice.
    pub(crate) max_decoded_bytes_per_slice: NonZeroUsize,
    /// Retained symbol-observation limit for each slice.
    pub(crate) max_symbol_ranges_per_slice: NonZeroUsize,
}

impl Default for DisassemblyRequest {
    fn default() -> Self {
        Self {
            arches: SliceSelection::All,
            selection: DisassemblySelection::ExecutableSections,
            mode: DecodeMode::Recovering,
            demangle: false,
            max_decoded_bytes_per_slice: NonZeroUsize::new(64 * 1024 * 1024)
                .expect("default is non-zero"),
            max_symbol_ranges_per_slice: NonZeroUsize::new(1_000_000).expect("default is non-zero"),
        }
    }
}

impl DisassemblyRequest {
    /// Construct a request whose limits and selector cardinalities are valid.
    pub fn new(
        arches: SliceSelection,
        selection: DisassemblySelection,
        mode: DecodeMode,
        demangle: bool,
        max_decoded_bytes_per_slice: NonZeroUsize,
        max_symbol_ranges_per_slice: NonZeroUsize,
    ) -> Result<Self, DisassemblyError> {
        if let DisassemblySelection::Symbols(names) = &selection {
            let unique_names: std::collections::BTreeSet<&str> =
                names.iter().map(String::as_str).collect();
            if unique_names.contains("") {
                return Err(DisassemblyError::new(
                    REQUEST_INVALID_CODE,
                    "requested symbol names must not be empty",
                ));
            }
            if unique_names.len() > max_symbol_ranges_per_slice.get() {
                return Err(DisassemblyError::new(
                    REQUEST_INVALID_CODE,
                    "requested symbol count exceeds the symbol-range limit",
                ));
            }
        }
        Ok(Self {
            arches,
            selection,
            mode,
            demangle,
            max_decoded_bytes_per_slice,
            max_symbol_ranges_per_slice,
        })
    }

    /// Selected slices.
    pub fn arches(&self) -> &SliceSelection {
        &self.arches
    }

    /// Selected regions.
    pub fn selection(&self) -> &DisassemblySelection {
        &self.selection
    }

    /// Decode behavior.
    pub fn mode(&self) -> DecodeMode {
        self.mode
    }

    /// Whether presentation names are demangled.
    pub fn demangle(&self) -> bool {
        self.demangle
    }

    /// Cumulative examined-byte limit per slice.
    pub fn max_decoded_bytes_per_slice(&self) -> NonZeroUsize {
        self.max_decoded_bytes_per_slice
    }

    /// Retained symbol-observation limit per slice.
    pub fn max_symbol_ranges_per_slice(&self) -> NonZeroUsize {
        self.max_symbol_ranges_per_slice
    }
}

/// Stable disassembly failure with a command-specific diagnostic code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct DisassemblyError {
    code: &'static str,
    message: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct WorkStats {
    pub(crate) container_bytes_hashed: u64,
    pub(crate) slice_bytes_hashed: u64,
    pub(crate) metadata_traversals: [u64; 3],
    pub(crate) metadata_observations_visited: [u64; 3],
    pub(crate) metadata_name_bytes_visited: [u64; 3],
    pub(crate) aliases_retained: u64,
    pub(crate) sections_visited: u64,
    pub(crate) section_index_entries: u64,
    pub(crate) section_index_queries: u64,
    pub(crate) boundary_queries: u64,
    pub(crate) label_range_queries: u64,
    pub(crate) target_owner_queries: u64,
    pub(crate) decode_attempts: u64,
    pub(crate) decoder_input_bytes: u64,
    pub(crate) unexamined_lookahead_bytes: u64,
    pub(crate) decode_eligible_bytes: u64,
    pub(crate) examined_bytes: u64,
    pub(crate) raw_bytes_retained: u64,
    pub(crate) records_retained: u64,
    pub(crate) owned_report_bytes: u64,
    pub(crate) serialized_bytes: u64,
}

impl DisassemblyError {
    /// Stable diagnostic code.
    pub const fn code(&self) -> &'static str {
        self.code
    }

    /// Human-readable diagnostic detail.
    pub fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

impl From<std::io::Error> for DisassemblyError {
    fn from(error: std::io::Error) -> Self {
        Self::new(
            OUTPUT_FAILED_CODE,
            format!("failed to write disassembly output: {error}"),
        )
    }
}

/// Resolve a display architecture name or exact raw tuple against the input.
pub fn resolve_architecture_selector(
    container: &MachoContainer<'_>,
    selector: &str,
) -> Result<Architecture, DisassemblyError> {
    let available = container_architectures(container);
    if let Some(raw) = parse_raw_architecture(selector) {
        return available
            .into_iter()
            .find(|candidate| *candidate == raw)
            .ok_or_else(|| {
                DisassemblyError::new(
                    "analysis.disassembly.arch.unsupported",
                    format!("architecture {selector} is not present in the input"),
                )
            });
    }
    let matches: Vec<_> = available
        .into_iter()
        .filter(|candidate| {
            ArchSpec {
                cpu_type: macho_core::model::header::CpuType(candidate.cpu_type),
                cpu_subtype: macho_core::model::header::CpuSubtype(candidate.cpu_subtype),
            }
            .name()
            .eq_ignore_ascii_case(selector)
        })
        .collect();
    match matches.as_slice() {
        [architecture] => Ok(*architecture),
        [] => Err(DisassemblyError::new(
            "analysis.disassembly.arch.unsupported",
            format!("architecture '{selector}' is not present in the input"),
        )),
        _ => Err(DisassemblyError::new(
            "analysis.disassembly.arch.ambiguous",
            format!(
                "architecture name '{selector}' matches multiple raw CPU tuples; use one of: {}",
                matches
                    .iter()
                    .map(|architecture| format!(
                        "0x{:08x}:0x{:08x}",
                        architecture.cpu_type as u32, architecture.cpu_subtype as u32
                    ))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// Execute a validated, bounded disassembly request, materializing the report.
pub fn disassemble(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
) -> Result<DisassemblyReport, DisassemblyError> {
    let mut sink = CollectingSink::new();
    streaming_inner(container, request, &mut sink, None)?;
    let report = sink.into_report();
    report
        .validate()
        .map_err(|error| DisassemblyError::new(REPORT_INVALID_CODE, error.to_string()))?;
    Ok(report)
}

/// Execute a validated, bounded disassembly request, streaming each record to
/// `sink` with output-side memory that is constant in the instruction count.
pub fn disassemble_streaming(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
    sink: &mut dyn DisassemblySink,
) -> Result<(), DisassemblyError> {
    streaming_inner(container, request, sink, None)
}

fn streaming_inner(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
    sink: &mut dyn DisassemblySink,
    mut observer: Option<&mut WorkStats>,
) -> Result<(), DisassemblyError> {
    validate_request(container, request)?;
    let selected = selected_slices(container, &request.arches)?;
    let report_request = report_request(request)?;
    let container_kind = if container.is_thin() {
        ContainerKind::Thin
    } else {
        ContainerKind::Fat
    };
    let container_hash =
        crate::report::ContentHash::new(crate::report::sha256_hex(container.bytes()))
            .expect("SHA-256 is canonical lowercase hexadecimal");
    if let Some(stats) = observer.as_deref_mut() {
        stats.container_bytes_hashed = container.bytes().len() as u64;
    }
    let container_identity = ReportContainerIdentity {
        content_sha256: container_hash.clone(),
        byte_len: container.bytes().len() as u64,
        container: container_kind,
        slice_count: selected.len() as u32,
    };
    sink.begin(&container_identity, &report_request)?;

    let symbol_mode = matches!(request.selection, DisassemblySelection::Symbols(_));
    let requested_names = match &request.selection {
        DisassemblySelection::Symbols(names) => names.as_slice(),
        _ => &[],
    };
    for selected_slice in selected {
        let mut metadata = collect_metadata(
            selected_slice.macho,
            requested_names,
            request.max_symbol_ranges_per_slice.get(),
            request.demangle,
            symbol_mode,
        )?;
        if let Some(stats) = observer.as_deref_mut() {
            if container_kind == ContainerKind::Fat {
                stats.slice_bytes_hashed += selected_slice.macho.file_size() as u64;
            }
        }
        let regions = resolve_regions(&selected_slice, request, &metadata)?;
        decode_slice(
            &selected_slice,
            request,
            regions,
            &mut metadata,
            container_hash.clone(),
            container_kind,
            sink,
            observer.as_deref_mut(),
        )?;
        if let Some(stats) = observer.as_deref_mut() {
            for index in 0..3 {
                stats.metadata_traversals[index] += metadata.traversals[index];
                stats.metadata_observations_visited[index] += metadata.observations_visited[index];
                stats.metadata_name_bytes_visited[index] += metadata.name_bytes_visited[index];
            }
            stats.aliases_retained += metadata.retained.len() as u64;
            stats.sections_visited += metadata.sections_visited();
            stats.section_index_entries += metadata.section_index_entries();
            stats.section_index_queries += metadata.section_query_count();
            stats.boundary_queries += metadata.boundary_query_count();
            stats.label_range_queries += metadata.label_range_query_count();
            stats.target_owner_queries += metadata.target_owner_query_count();
        }
    }
    sink.finish()?;
    Ok(())
}

#[cfg(test)]
fn owned_report_bytes(report: &DisassemblyReport) -> u64 {
    use std::mem::size_of;

    use crate::report::disassembly::{DisassemblyRecord, ReportSelection};

    let mut bytes = report.container.content_sha256.capacity() as u64;
    bytes += (report.slices.capacity() * size_of::<crate::report::disassembly::DisassemblySlice>())
        as u64;
    match &report.request.selection {
        ReportSelection::Sections { selectors } => {
            bytes += (selectors.capacity()
                * size_of::<crate::report::disassembly::ReportSectionSelector>())
                as u64;
            bytes += selectors
                .iter()
                .map(|selector| selector.segment.capacity() + selector.section.capacity())
                .sum::<usize>() as u64;
        }
        ReportSelection::Symbols { names } => {
            bytes += (names.capacity() * size_of::<String>()) as u64;
            bytes += names.iter().map(String::capacity).sum::<usize>() as u64;
        }
        ReportSelection::ExecutableSections | ReportSelection::Address { .. } => {}
    }
    for slice in &report.slices {
        bytes += slice.identity.image.content_sha256.capacity() as u64;
        bytes += slice
            .identity
            .image
            .uuid
            .as_ref()
            .map_or(0, crate::report::CanonicalUuid::capacity) as u64;
        bytes += (slice.regions.capacity()
            * size_of::<crate::report::disassembly::DisassemblyRegion>()) as u64;
        bytes += (slice.issues.capacity()
            * size_of::<crate::report::disassembly::DisassemblyIssue>()) as u64;
        for issue in &slice.issues {
            bytes += (issue.code.capacity() + issue.message.capacity()) as u64;
        }
        for region in &slice.regions {
            bytes += (region.segment.capacity() + region.section.capacity()) as u64;
            bytes += (region.labels.capacity()
                * size_of::<crate::report::disassembly::DisassemblyLabel>())
                as u64;
            bytes += (region.records.capacity() * size_of::<DisassemblyRecord>()) as u64;
            for label in &region.labels {
                bytes += (label.raw_name.capacity() + label.display_name.capacity()) as u64;
            }
            for record in &region.records {
                match record {
                    DisassemblyRecord::Instruction {
                        bytes: raw,
                        text,
                        direct_target,
                        ..
                    } => {
                        bytes += (raw.capacity() + text.capacity()) as u64;
                        if let Some(target) = direct_target {
                            bytes += target.raw_symbol.as_ref().map_or(0, String::capacity) as u64;
                            bytes +=
                                target.display_symbol.as_ref().map_or(0, String::capacity) as u64;
                        }
                    }
                    DisassemblyRecord::Gap {
                        bytes: raw,
                        code,
                        message,
                        ..
                    } => {
                        bytes += (raw.capacity() + code.capacity() + message.capacity()) as u64;
                    }
                }
            }
        }
    }
    bytes
}

#[cfg(test)]
fn disassemble_with_work_stats(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
) -> Result<(DisassemblyReport, WorkStats), DisassemblyError> {
    let mut stats = WorkStats::default();
    let mut sink = CollectingSink::new();
    streaming_inner(container, request, &mut sink, Some(&mut stats))?;
    let report = sink.into_report();
    report
        .validate()
        .map_err(|error| DisassemblyError::new(REPORT_INVALID_CODE, error.to_string()))?;
    stats.serialized_bytes = serde_json::to_vec(&report)
        .map_err(|error| {
            DisassemblyError::new(
                REPORT_INVALID_CODE,
                format!("failed to measure serialized report: {error}"),
            )
        })?
        .len() as u64;
    stats.owned_report_bytes = owned_report_bytes(&report);
    Ok((report, stats))
}

fn validate_request(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
) -> Result<(), DisassemblyError> {
    match &request.selection {
        DisassemblySelection::Sections(selectors)
            if selectors.iter().any(|selector| {
                selector.segment.is_empty()
                    || selector.section.is_empty()
                    || selector.segment.contains(',')
                    || selector.section.contains(',')
            }) =>
        {
            Err(DisassemblyError::new(
                "analysis.disassembly.section.invalid",
                "section selectors require non-empty exact names without commas",
            ))
        }
        DisassemblySelection::Symbols(names)
            if names.iter().any(String::is_empty)
                || names
                    .iter()
                    .collect::<std::collections::BTreeSet<_>>()
                    .len()
                    > request.max_symbol_ranges_per_slice.get() =>
        {
            Err(DisassemblyError::new(
                REQUEST_INVALID_CODE,
                "symbol names must be non-empty and fit within --max-ranges",
            ))
        }
        DisassemblySelection::Address { .. }
            if container.is_fat() && matches!(request.arches, SliceSelection::All) =>
        {
            Err(DisassemblyError::new(
                REQUEST_INVALID_CODE,
                "address selection on a universal input requires an exact architecture",
            ))
        }
        _ => Ok(()),
    }
}

fn report_request(
    request: &DisassemblyRequest,
) -> Result<DisassemblyReportRequest, DisassemblyError> {
    let arch = match request.arches {
        SliceSelection::All => None,
        SliceSelection::Exact(value) => Some(value),
    };
    let selection = match &request.selection {
        DisassemblySelection::ExecutableSections => ReportSelection::ExecutableSections,
        DisassemblySelection::Sections(values) => {
            let mut values = values.as_slice().to_vec();
            values.sort();
            values.dedup();
            ReportSelection::Sections {
                selectors: values
                    .into_iter()
                    .map(|value| ReportSectionSelector {
                        segment: value.segment,
                        section: value.section,
                    })
                    .collect(),
            }
        }
        DisassemblySelection::Symbols(values) => {
            let mut names = values.as_slice().to_vec();
            names.sort();
            names.dedup();
            ReportSelection::Symbols { names }
        }
        DisassemblySelection::Address { start, extent } => ReportSelection::Address {
            start_va: start.0,
            extent: match extent {
                AddressExtent::InstructionCount(value) => ReportAddressExtent::InstructionCount {
                    value: value.get() as u64,
                },
                AddressExtent::ByteLength(value) => ReportAddressExtent::ByteLength {
                    value: value.get() as u64,
                },
            },
        },
    };
    Ok(DisassemblyReportRequest {
        arch,
        selection,
        mode: match request.mode {
            DecodeMode::Recovering => ReportDecodeMode::Recovering,
            DecodeMode::Strict => ReportDecodeMode::Strict,
        },
        demangle: request.demangle,
        max_decoded_bytes_per_slice: request.max_decoded_bytes_per_slice.get() as u64,
        max_symbol_ranges_per_slice: request.max_symbol_ranges_per_slice.get() as u64,
    })
}

fn parse_raw_architecture(selector: &str) -> Option<Architecture> {
    let (cpu, subtype) = selector.split_once(':')?;
    if cpu.len() != 10
        || subtype.len() != 10
        || !cpu.starts_with("0x")
        || !subtype.starts_with("0x")
    {
        return None;
    }
    Some(Architecture {
        cpu_type: u32::from_str_radix(&cpu[2..], 16).ok()? as i32,
        cpu_subtype: u32::from_str_radix(&subtype[2..], 16).ok()? as i32,
    })
}

fn container_architectures(container: &MachoContainer<'_>) -> Vec<Architecture> {
    match container {
        MachoContainer::Thin(macho) => vec![architecture_for_macho(macho)],
        MachoContainer::Fat(fat) => fat
            .arches()
            .iter()
            .map(|arch| Architecture {
                cpu_type: arch.spec().cpu_type.0,
                cpu_subtype: arch.spec().cpu_subtype.0,
            })
            .collect(),
    }
}

fn selected_slices<'input, 'data>(
    container: &'input MachoContainer<'data>,
    selection: &SliceSelection,
) -> Result<Vec<SelectedSlice<'input, 'data>>, DisassemblyError> {
    let wanted = match selection {
        SliceSelection::All => None,
        SliceSelection::Exact(value) => Some(*value),
    };
    let mut slices = Vec::new();
    match container {
        MachoContainer::Thin(macho) => {
            let architecture = architecture_for_macho(macho);
            if wanted.is_none_or(|wanted| wanted == architecture) {
                slices.push(SelectedSlice::new(macho, 0, 0, architecture)?);
            }
        }
        MachoContainer::Fat(fat) => {
            for (index, fat_arch) in fat.arches().iter().enumerate() {
                let architecture = Architecture {
                    cpu_type: fat_arch.spec().cpu_type.0,
                    cpu_subtype: fat_arch.spec().cpu_subtype.0,
                };
                if wanted.is_none_or(|wanted| wanted == architecture) {
                    slices.push(SelectedSlice::new(
                        fat_arch.macho(),
                        index as u32,
                        fat_arch.fat_offset().0,
                        architecture,
                    )?);
                }
            }
        }
    }
    if slices.is_empty() {
        return Err(DisassemblyError::new(
            "analysis.disassembly.arch.unsupported",
            "the selected raw architecture is not present in the input",
        ));
    }
    Ok(slices)
}

fn architecture_for_macho(macho: &macho_core::model::macho_file::MachoFile<'_>) -> Architecture {
    Architecture {
        cpu_type: macho.header().cpu_type().0,
        cpu_subtype: macho.header().cpu_subtype().0,
    }
}

pub(crate) fn instruction_arch(architecture: Architecture) -> Result<Arch, DisassemblyError> {
    match architecture.cpu_type {
        CPU_TYPE_X86_64 => Ok(Arch::X86_64),
        CPU_TYPE_ARM64
            if architecture.cpu_subtype & macho_core::format::constants::CPU_SUBTYPE_MASK
                == CPU_SUBTYPE_ARM64E =>
        {
            Ok(Arch::Arm64e)
        }
        CPU_TYPE_ARM64 => Ok(Arch::Arm64),
        _ => Err(DisassemblyError::new(
            "analysis.disassembly.arch.unsupported",
            format!(
                "unsupported CPU tuple 0x{:08x}:0x{:08x}; supported CPU types are x86_64 (0x{:08x}) and arm64/arm64e (0x{:08x})",
                architecture.cpu_type as u32,
                architecture.cpu_subtype as u32,
                CPU_TYPE_X86_64 as u32,
                CPU_TYPE_ARM64 as u32
            ),
        )),
    }
}
