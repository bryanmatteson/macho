use std::io::Write;
use std::num::NonZeroUsize;

use anyhow::Result;
use macho::analysis::disassembly::{
    AddressExtent, DecodeMode, DisassemblyRequest, DisassemblySelection, DisassemblySink, NonEmpty,
    RegionHeader, RegionSummary, SectionSelector, SliceHeader, SliceSelection, SliceSummary,
    disassemble_streaming, resolve_architecture_selector,
};
use macho::analysis::report::disassembly::{
    DisassemblyIssue, DisassemblyLabel, DisassemblyRecord, DisassemblyReportRequest,
    DisassemblyStatus, InstructionFlags, RangeEndSource, SelectionSource, SymbolSource,
};
use macho::analysis::report::{Architecture, ReportContainerIdentity, ReportSliceIdentity};
use serde::Serialize;

use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::output::{Format, Options};
use crate::commands::subcommands::common::map_input;
use crate::commands::usage_message;

#[derive(Debug, clap::Args)]
#[command(
    after_help = "Output streams one line per record with constant memory: pretty text by default, or one JSON object per line with --format json (newline-delimited JSON, not a single document). SARIF output is supported only by the audit command.\n\nExamples:\n  macho disassemble app\n  macho disassemble app --arch arm64e --symbol _main\n  macho disassemble app --address 0x100003f50 --count 8\n  macho disassemble app --section __TEXT,__text --format json"
)]
/// Arguments for bounded instruction disassembly.
pub struct DisassembleArgs {
    #[command(flatten)]
    input: InputArgs,

    #[command(flatten)]
    architecture: ArchitectureArgs,

    /// Select an exact raw nlist or export-trie symbol name (repeatable).
    #[arg(long, action = clap::ArgAction::Append, conflicts_with_all = ["section", "address"])]
    symbol: Vec<String>,

    /// Select an exact SEGMENT,SECTION pair (repeatable).
    #[arg(long, value_parser = parse_section, action = clap::ArgAction::Append, conflicts_with_all = ["symbol", "address"])]
    section: Vec<SectionSelector>,

    /// Select one virtual address (hexadecimal, with optional 0x prefix).
    #[arg(long, value_parser = parse_va, conflicts_with_all = ["symbol", "section"])]
    address: Option<u64>,

    /// Select this many bytes from --address (decimal or 0x-prefixed hexadecimal).
    #[arg(long, value_parser = parse_nonzero_length, requires = "address", conflicts_with = "count")]
    length: Option<NonZeroUsize>,

    /// Decode this many instructions from --address.
    #[arg(long, value_parser = parse_nonzero_decimal, requires = "address", conflicts_with = "length")]
    count: Option<NonZeroUsize>,

    /// Demangle retained symbol labels while preserving their raw names.
    #[arg(long)]
    demangle: bool,

    /// Fail on the first invalid byte or caller-clipped instruction.
    #[arg(long)]
    strict: bool,

    /// Maximum decoded bytes examined per selected slice.
    #[arg(long, default_value = "67108864", value_parser = parse_nonzero_decimal)]
    max_decoded_bytes: NonZeroUsize,

    /// Maximum symbol observations retained per selected slice.
    #[arg(long = "max-ranges", default_value = "1000000", value_parser = parse_nonzero_decimal)]
    max_ranges: NonZeroUsize,
}

/// Execute the disassembly command, streaming one line per record directly to
/// `out` with output-side memory constant in the instruction count. Text is the
/// default; `--format json` emits newline-delimited JSON (one object per line).
pub fn run_streaming(args: DisassembleArgs, output: Options, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)?;
    if args
        .symbol
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        > args.max_ranges.get()
    {
        return Err(usage_message(
            "the number of requested symbols exceeds --max-ranges",
        ));
    }
    let arches = match args.architecture.arch.as_deref() {
        Some(selector) => {
            if selector.contains(':') && parse_raw_arch(selector).is_none() {
                return Err(usage_message(
                    "--arch raw tuples must use 0xCCCCCCCC:0xSSSSSSSS",
                ));
            }
            SliceSelection::Exact(resolve_architecture_selector(&container, selector)?)
        }
        None => SliceSelection::All,
    };
    if args.address.is_some() && container.is_fat() && matches!(arches, SliceSelection::All) {
        return Err(usage_message(
            "--address on a universal input requires --arch",
        ));
    }
    let selection = if !args.symbol.is_empty() {
        DisassemblySelection::Symbols(
            NonEmpty::try_from_vec(args.symbol).expect("non-empty selector branch"),
        )
    } else if !args.section.is_empty() {
        DisassemblySelection::Sections(
            NonEmpty::try_from_vec(args.section).expect("non-empty selector branch"),
        )
    } else if let Some(start) = args.address {
        let extent = match (args.length, args.count) {
            (Some(length), None) => AddressExtent::ByteLength(length),
            (None, Some(count)) => AddressExtent::InstructionCount(count),
            (None, None) => {
                AddressExtent::InstructionCount(NonZeroUsize::new(1).expect("one is non-zero"))
            }
            (Some(_), Some(_)) => unreachable!("Clap rejects conflicting extents"),
        };
        DisassemblySelection::Address {
            start: macho::model::addr::Va(start),
            extent,
        }
    } else {
        DisassemblySelection::ExecutableSections
    };
    let request = DisassemblyRequest::new(
        arches,
        selection,
        if args.strict {
            DecodeMode::Strict
        } else {
            DecodeMode::Recovering
        },
        args.demangle,
        args.max_decoded_bytes,
        args.max_ranges,
    )?;
    match output.format() {
        Format::Json => {
            let mut sink = NdjsonSink::new(out);
            disassemble_streaming(&container, &request, &mut sink)?;
        }
        Format::Text => {
            let mut sink = TextLineSink::new(output, out);
            disassemble_streaming(&container, &request, &mut sink)?;
        }
        Format::Sarif => unreachable!("central output policy rejects disassembly SARIF"),
    }
    Ok(())
}

// ───────────────────────── text line sink ─────────────────────────

struct TextLineSink<'a> {
    out: &'a mut dyn Write,
    options: Options,
    multiple: bool,
    raw_width: usize,
    pending_titles: Vec<String>,
    emitted_any_region: bool,
}

impl<'a> TextLineSink<'a> {
    fn new(options: Options, out: &'a mut dyn Write) -> Self {
        Self {
            out,
            options,
            multiple: false,
            raw_width: 8,
            pending_titles: Vec::new(),
            emitted_any_region: false,
        }
    }
}

impl DisassemblySink for TextLineSink<'_> {
    fn begin(
        &mut self,
        container: &ReportContainerIdentity,
        _request: &DisassemblyReportRequest,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.multiple = container.slice_count > 1;
        Ok(())
    }

    fn slice_start(
        &mut self,
        header: SliceHeader,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        let architecture = header.identity.image.architecture;
        self.raw_width = if architecture.cpu_type == 0x0100_0007 {
            30
        } else {
            8
        };
        if self.multiple {
            let title = self.options.style().title(&format!(
                "=== {} [slice {}, 0x{:08x}:0x{:08x}] ===",
                architecture_name(architecture),
                header.identity.image.slice_index + 1,
                architecture.cpu_type as u32,
                architecture.cpu_subtype as u32
            ));
            if self.emitted_any_region {
                writeln!(self.out, "{title}")?;
            } else {
                self.pending_titles.push(title);
            }
        }
        Ok(())
    }

    fn region_start(
        &mut self,
        header: RegionHeader,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        if !self.emitted_any_region {
            for title in std::mem::take(&mut self.pending_titles) {
                writeln!(self.out, "{title}")?;
            }
            self.emitted_any_region = true;
        }
        let extent = header
            .requested_end_va
            .map(|end| format!("{:#018x}..{end:#018x}", header.start_va))
            .unwrap_or_else(|| {
                format!(
                    "{:#018x} ({} instructions)",
                    header.start_va,
                    header.requested_instruction_count.unwrap_or(0)
                )
            });
        writeln!(
            self.out,
            "{}  {}",
            self.options
                .style()
                .heading(&format!("{},{}", header.segment, header.section)),
            extent
        )?;
        Ok(())
    }

    fn record(
        &mut self,
        record: &DisassemblyRecord,
        labels: &[DisassemblyLabel],
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        let style = self.options.style();
        for label in labels {
            writeln!(
                self.out,
                "{}",
                style.accent(&format!("{}:", label.display_name))
            )?;
        }
        let (va, bytes, tail) = match record {
            DisassemblyRecord::Instruction {
                va,
                bytes,
                text,
                direct_target,
                ..
            } => {
                let annotation = direct_target.as_ref().map_or_else(String::new, |target| {
                    target.display_symbol.as_ref().map_or_else(
                        || format!("; {:#x}", target.va),
                        |name| {
                            let offset = target.offset.unwrap_or(0);
                            if offset == 0 {
                                format!("; {name}")
                            } else {
                                format!("; {name}+{offset:#x}")
                            }
                        },
                    )
                });
                (
                    *va,
                    bytes.as_str().to_owned(),
                    format!("{text}{annotation}"),
                )
            }
            DisassemblyRecord::Gap {
                va,
                bytes,
                code,
                message,
                ..
            } => (
                *va,
                bytes.as_str().to_owned(),
                format!("<{code}> {message}"),
            ),
        };
        let mut line = String::from("  ");
        line.push_str(&style.address(&format!("{va:#018x}")));
        line.push_str("  ");
        line.push_str(&bytes);
        for _ in bytes.len()..self.raw_width {
            line.push(' ');
        }
        line.push_str("  ");
        line.push_str(&tail);
        writeln!(self.out, "{line}")?;
        Ok(())
    }

    fn region_end(
        &mut self,
        summary: RegionSummary,
        _labels: &[DisassemblyLabel],
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        if let Some(next) = summary.next_unexamined_va {
            writeln!(
                self.out,
                "  {} decoded-byte limit reached; next VA {next:#x}",
                self.options.style().warning("Partial:")
            )?;
        }
        Ok(())
    }

    fn slice_end(
        &mut self,
        summary: SliceSummary,
        issues: &[DisassemblyIssue],
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        let style = self.options.style();
        if summary.symbol_ranges_truncated {
            writeln!(
                self.out,
                "{} symbol range limit reached",
                style.warning("Partial:")
            )?;
        }
        for issue in issues {
            writeln!(
                self.out,
                "{} [{}] {}",
                style.warning("Warning:"),
                issue.code,
                issue.message
            )?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        if !self.emitted_any_region {
            writeln!(self.out, "No executable sections found.")?;
        }
        self.out.flush()?;
        Ok(())
    }
}

// ───────────────────────── NDJSON line sink ─────────────────────────

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum Line<'a> {
    Header {
        schema_version: u32,
        container: &'a ReportContainerIdentity,
        request: &'a DisassemblyReportRequest,
    },
    Slice {
        identity: &'a ReportSliceIdentity,
        container_offset: u64,
        slice_size: u64,
    },
    Region {
        segment: &'a str,
        section: &'a str,
        selection_source: SelectionSource,
        range_source: Option<SymbolSource>,
        end_source: Option<RangeEndSource>,
        start_va: u64,
        requested_end_va: Option<u64>,
        requested_instruction_count: Option<u64>,
        instruction_flags: InstructionFlags,
    },
    Record {
        record: &'a DisassemblyRecord,
    },
    Label {
        label: &'a DisassemblyLabel,
    },
    RegionEnd {
        emitted_instruction_count: u64,
        examined_end_va: u64,
        next_unexamined_va: Option<u64>,
    },
    SliceEnd {
        status: DisassemblyStatus,
        decoded_bytes: u64,
        decoded_bytes_truncated: bool,
        symbol_ranges_truncated: bool,
    },
    Issue {
        issue: &'a DisassemblyIssue,
    },
}

struct NdjsonSink<'a> {
    out: &'a mut dyn Write,
    container: Option<ReportContainerIdentity>,
    request: Option<DisassemblyReportRequest>,
    header_emitted: bool,
}

impl<'a> NdjsonSink<'a> {
    fn new(out: &'a mut dyn Write) -> Self {
        Self {
            out,
            container: None,
            request: None,
            header_emitted: false,
        }
    }

    fn write_line(
        &mut self,
        line: &Line<'_>,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        serde_json::to_writer(&mut *self.out, line).map_err(std::io::Error::other)?;
        self.out.write_all(b"\n")?;
        Ok(())
    }

    /// Emit the container/request header exactly once, before the first slice.
    /// Deferring it keeps stdout empty when a pre-decode error aborts the run.
    fn ensure_header(&mut self) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        if self.header_emitted {
            return Ok(());
        }
        self.header_emitted = true;
        let container = self.container.take().expect("begin() runs before slices");
        let request = self.request.take().expect("begin() runs before slices");
        let line = Line::Header {
            schema_version: 1,
            container: &container,
            request: &request,
        };
        self.write_line(&line)?;
        self.container = Some(container);
        self.request = Some(request);
        Ok(())
    }
}

impl DisassemblySink for NdjsonSink<'_> {
    fn begin(
        &mut self,
        container: &ReportContainerIdentity,
        request: &DisassemblyReportRequest,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.container = Some(container.clone());
        self.request = Some(request.clone());
        Ok(())
    }

    fn slice_start(
        &mut self,
        header: SliceHeader,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.ensure_header()?;
        self.write_line(&Line::Slice {
            identity: &header.identity,
            container_offset: header.container_offset,
            slice_size: header.slice_size,
        })
    }

    fn region_start(
        &mut self,
        header: RegionHeader,
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.write_line(&Line::Region {
            segment: &header.segment,
            section: &header.section,
            selection_source: header.selection_source,
            range_source: header.range_source,
            end_source: header.end_source,
            start_va: header.start_va,
            requested_end_va: header.requested_end_va,
            requested_instruction_count: header.requested_instruction_count,
            instruction_flags: header.instruction_flags,
        })
    }

    fn record(
        &mut self,
        record: &DisassemblyRecord,
        _labels: &[DisassemblyLabel],
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.write_line(&Line::Record { record })
    }

    fn region_end(
        &mut self,
        summary: RegionSummary,
        labels: &[DisassemblyLabel],
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        for label in labels {
            self.write_line(&Line::Label { label })?;
        }
        self.write_line(&Line::RegionEnd {
            emitted_instruction_count: summary.emitted_instruction_count,
            examined_end_va: summary.examined_end_va,
            next_unexamined_va: summary.next_unexamined_va,
        })
    }

    fn slice_end(
        &mut self,
        summary: SliceSummary,
        issues: &[DisassemblyIssue],
    ) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.write_line(&Line::SliceEnd {
            status: summary.status,
            decoded_bytes: summary.decoded_bytes,
            decoded_bytes_truncated: summary.decoded_bytes_truncated,
            symbol_ranges_truncated: summary.symbol_ranges_truncated,
        })?;
        for issue in issues {
            self.write_line(&Line::Issue { issue })?;
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), macho::analysis::disassembly::DisassemblyError> {
        self.out.flush()?;
        Ok(())
    }
}

// ───────────────────────── argument parsing ─────────────────────────

fn architecture_name(architecture: Architecture) -> String {
    macho::model::header::ArchSpec {
        cpu_type: macho::model::header::CpuType(architecture.cpu_type),
        cpu_subtype: macho::model::header::CpuSubtype(architecture.cpu_subtype),
    }
    .name()
}

fn parse_section(value: &str) -> Result<SectionSelector, String> {
    let mut parts = value.split(',');
    let segment = parts.next().unwrap_or_default();
    let section = parts.next().unwrap_or_default();
    if segment.is_empty() || section.is_empty() || parts.next().is_some() {
        return Err("expected exactly SEGMENT,SECTION with non-empty names".to_owned());
    }
    SectionSelector::new(segment, section).map_err(|error| error.to_string())
}

fn parse_va(value: &str) -> Result<u64, String> {
    let digits = value.strip_prefix("0x").unwrap_or(value);
    (!digits.is_empty())
        .then(|| u64::from_str_radix(digits, 16))
        .ok_or_else(|| "expected a hexadecimal virtual address".to_owned())?
        .map_err(|_| "expected a hexadecimal virtual address".to_owned())
}

fn parse_nonzero_length(value: &str) -> Result<NonZeroUsize, String> {
    let parsed = if let Some(digits) = value.strip_prefix("0x") {
        usize::from_str_radix(digits, 16)
    } else {
        value.parse()
    }
    .map_err(|_| "expected a non-zero decimal or 0x-prefixed hexadecimal length".to_owned())?;
    NonZeroUsize::new(parsed).ok_or_else(|| "value must be greater than zero".to_owned())
}

fn parse_nonzero_decimal(value: &str) -> Result<NonZeroUsize, String> {
    let parsed = value
        .parse()
        .map_err(|_| "expected a non-zero decimal integer".to_owned())?;
    NonZeroUsize::new(parsed).ok_or_else(|| "value must be greater than zero".to_owned())
}

fn parse_raw_arch(value: &str) -> Option<Architecture> {
    let (cpu, subtype) = value.split_once(':')?;
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
