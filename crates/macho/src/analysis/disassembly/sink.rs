//! Streaming disassembly event sink.
//!
//! The decode core emits one event per record instead of collecting records
//! into `Vec`s. `CollectingSink` reassembles the events into the same
//! `DisassemblyReport` the materialized API returns, so there is one decode
//! path; the CLI implements line-oriented sinks over the same events for
//! constant-memory output.

use crate::analysis::report::disassembly::{
    DisassemblyIssue, DisassemblyLabel, DisassemblyRecord, DisassemblyRegion, DisassemblySlice,
    DisassemblyStatus, InstructionFlags, RangeEndSource, SelectionSource, SymbolSource,
};
use crate::analysis::report::disassembly::{
    DisassemblyReport, DisassemblyReportRequest, DisassemblySchemaVersion,
};
use crate::analysis::report::{ReportContainerIdentity, ReportSliceIdentity};

use super::DisassemblyError;

/// Per-slice fields known before decoding.
#[derive(Debug, Clone)]
pub struct SliceHeader {
    /// Slice identity (image hash, architecture, uuid, slice index).
    pub identity: ReportSliceIdentity,
    /// Byte offset of the slice within its container.
    pub container_offset: u64,
    /// Byte length of the slice.
    pub slice_size: u64,
}

/// Per-region fields known before decoding.
#[derive(Debug, Clone)]
pub struct RegionHeader {
    /// Segment name.
    pub segment: String,
    /// Section name.
    pub section: String,
    /// How the region was selected.
    pub selection_source: SelectionSource,
    /// Symbol source that provided the region start, if any.
    pub range_source: Option<SymbolSource>,
    /// Source that provided the region end, if any.
    pub end_source: Option<RangeEndSource>,
    /// Region start VA.
    pub start_va: u64,
    /// Requested byte-extent end VA, if any.
    pub requested_end_va: Option<u64>,
    /// Requested instruction count, if any.
    pub requested_instruction_count: Option<u64>,
    /// Instruction flags of the owning section.
    pub instruction_flags: InstructionFlags,
}

/// Per-region fields known after decoding.
#[derive(Debug, Clone)]
pub struct RegionSummary {
    /// Number of decoded instructions emitted.
    pub emitted_instruction_count: u64,
    /// VA examined up to (exclusive).
    pub examined_end_va: u64,
    /// First unexamined VA when the region was truncated.
    pub next_unexamined_va: Option<u64>,
}

/// Per-slice fields known after decoding.
#[derive(Debug, Clone)]
pub struct SliceSummary {
    /// Whether decoding was complete or partial.
    pub status: DisassemblyStatus,
    /// Total decoded bytes across the slice.
    pub decoded_bytes: u64,
    /// Whether the decoded-byte limit truncated the slice.
    pub decoded_bytes_truncated: bool,
    /// Whether the symbol-range limit truncated retained labels.
    pub symbol_ranges_truncated: bool,
}

/// Receives streaming disassembly events in document order.
pub trait DisassemblySink {
    /// Begin a report with its container identity and echoed request.
    fn begin(
        &mut self,
        container: &ReportContainerIdentity,
        request: &DisassemblyReportRequest,
    ) -> Result<(), DisassemblyError>;

    /// Start a slice.
    fn slice_start(&mut self, header: SliceHeader) -> Result<(), DisassemblyError>;

    /// Start a region within the current slice.
    fn region_start(&mut self, header: RegionHeader) -> Result<(), DisassemblyError>;

    /// Emit one record, with the (bounded) labels whose VA equals the record VA.
    fn record(
        &mut self,
        record: &DisassemblyRecord,
        labels: &[DisassemblyLabel],
    ) -> Result<(), DisassemblyError>;

    /// End the current region with its summary and its full label set.
    fn region_end(
        &mut self,
        summary: RegionSummary,
        labels: &[DisassemblyLabel],
    ) -> Result<(), DisassemblyError>;

    /// End the current slice with its summary and issues.
    fn slice_end(
        &mut self,
        summary: SliceSummary,
        issues: &[DisassemblyIssue],
    ) -> Result<(), DisassemblyError>;

    /// Finish the report. Default is a no-op.
    fn finish(&mut self) -> Result<(), DisassemblyError> {
        Ok(())
    }
}

/// A sink that rebuilds the materialized `DisassemblyReport`.
#[derive(Debug, Default)]
pub(crate) struct CollectingSink {
    container: Option<ReportContainerIdentity>,
    request: Option<DisassemblyReportRequest>,
    slices: Vec<DisassemblySlice>,
    slice: Option<SliceBuild>,
    region: Option<RegionBuild>,
}

#[derive(Debug)]
struct SliceBuild {
    header: SliceHeader,
    regions: Vec<DisassemblyRegion>,
}

#[derive(Debug)]
struct RegionBuild {
    header: RegionHeader,
    records: Vec<DisassemblyRecord>,
}

impl CollectingSink {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Assemble the accumulated events into a report.
    pub(crate) fn into_report(self) -> DisassemblyReport {
        DisassemblyReport {
            schema_version: DisassemblySchemaVersion::CURRENT,
            container: self.container.expect("begin() runs before into_report()"),
            request: self.request.expect("begin() runs before into_report()"),
            slices: self.slices,
        }
    }
}

impl DisassemblySink for CollectingSink {
    fn begin(
        &mut self,
        container: &ReportContainerIdentity,
        request: &DisassemblyReportRequest,
    ) -> Result<(), DisassemblyError> {
        self.container = Some(container.clone());
        self.request = Some(request.clone());
        Ok(())
    }

    fn slice_start(&mut self, header: SliceHeader) -> Result<(), DisassemblyError> {
        self.slice = Some(SliceBuild {
            header,
            regions: Vec::new(),
        });
        Ok(())
    }

    fn region_start(&mut self, header: RegionHeader) -> Result<(), DisassemblyError> {
        self.region = Some(RegionBuild {
            header,
            records: Vec::new(),
        });
        Ok(())
    }

    fn record(
        &mut self,
        record: &DisassemblyRecord,
        _labels: &[DisassemblyLabel],
    ) -> Result<(), DisassemblyError> {
        self.region
            .as_mut()
            .expect("region_start() runs before record()")
            .records
            .push(record.clone());
        Ok(())
    }

    fn region_end(
        &mut self,
        summary: RegionSummary,
        labels: &[DisassemblyLabel],
    ) -> Result<(), DisassemblyError> {
        let RegionBuild { header, records } = self
            .region
            .take()
            .expect("region_start() runs before region_end()");
        let region = DisassemblyRegion {
            segment: header.segment,
            section: header.section,
            selection_source: header.selection_source,
            range_source: header.range_source,
            end_source: header.end_source,
            start_va: header.start_va,
            requested_end_va: header.requested_end_va,
            requested_instruction_count: header.requested_instruction_count,
            emitted_instruction_count: summary.emitted_instruction_count,
            examined_end_va: summary.examined_end_va,
            next_unexamined_va: summary.next_unexamined_va,
            instruction_flags: header.instruction_flags,
            labels: labels.to_vec(),
            records,
        };
        self.slice
            .as_mut()
            .expect("slice_start() runs before region_end()")
            .regions
            .push(region);
        Ok(())
    }

    fn slice_end(
        &mut self,
        summary: SliceSummary,
        issues: &[DisassemblyIssue],
    ) -> Result<(), DisassemblyError> {
        let SliceBuild { header, regions } = self
            .slice
            .take()
            .expect("slice_start() runs before slice_end()");
        self.slices.push(DisassemblySlice {
            identity: header.identity,
            container_offset: header.container_offset,
            slice_size: header.slice_size,
            status: summary.status,
            decoded_bytes: summary.decoded_bytes,
            decoded_bytes_truncated: summary.decoded_bytes_truncated,
            symbol_ranges_truncated: summary.symbol_ranges_truncated,
            regions,
            issues: issues.to_vec(),
        });
        Ok(())
    }
}
