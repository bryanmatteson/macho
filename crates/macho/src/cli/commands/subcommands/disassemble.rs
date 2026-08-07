use std::fmt::Write as _;
use std::io::{BufWriter, Write};
use std::num::NonZeroUsize;

use crate::analysis::disassembly::{
    AddressExtent, DecodeMode, DisassemblyError, DisassemblyRequest, DisassemblySelection,
    DisassemblySink, NonEmpty, RegionHeader, RegionSummary, SectionSelector, SliceHeader,
    SliceSelection, SliceSummary, disassemble_streaming, resolve_slice_selection,
};
use crate::analysis::report::disassembly::{
    DirectTarget, DisassemblyIssue, DisassemblyLabel, DisassemblyRecord, DisassemblyReportRequest,
    InstructionEncoding, InstructionKind,
};
use crate::analysis::report::{Architecture, ReportContainerIdentity};
use anyhow::Result;
use serde::Serialize;

use termosaic::Span;

use crate::cli::commands::args::{ArchitectureArgs, InputArgs};
use crate::cli::commands::output::{ADDRESS_TOKEN, Format, Options, RAW_BYTES_TOKEN, asm};
use crate::cli::commands::subcommands::common::map_input;
use crate::cli::commands::usage_message;

const STREAM_BUFFER_CAPACITY: usize = 64 * 1024;
const INSTRUCTION_STREAM_SCHEMA_VERSION: u32 = 1;

fn with_stream_buffer<T>(
    out: &mut dyn Write,
    stream: impl FnOnce(&mut dyn Write) -> Result<T, DisassemblyError>,
) -> Result<T, DisassemblyError> {
    let mut buffered = BufWriter::with_capacity(STREAM_BUFFER_CAPACITY, out);
    let stream_result = stream(&mut buffered);
    let flush_result = buffered.flush().map_err(DisassemblyError::from);
    match stream_result {
        Err(error) => Err(error),
        Ok(value) => {
            flush_result?;
            Ok(value)
        }
    }
}

fn append_sanitized(output: &mut String, text: &str) {
    for character in text.chars() {
        if matches!(
            character,
            '\u{0000}'..='\u{001f}'
                | '\u{007f}'..='\u{009f}'
                | '\u{202a}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
        ) {
            output.push('\u{fffd}');
        } else {
            output.push(character);
        }
    }
}

#[derive(Debug, clap::Args)]
#[command(
    after_help = "Output streams with constant memory: pretty text by default, or exactly one self-contained instruction object per line with --format json (NDJSON). JSON instruction metadata includes its section, labels, and resolved direct target when available; headers, trailers, gaps, and issues are never written to stdout. SARIF output is supported only by the audit command.\n\nExamples:\n  macho disassemble app\n  macho disassemble app --arch arm64e --symbol _main\n  macho disassemble app --address 0x100003f50 --count 8\n  macho disassemble app --address 0x100003f50 --end-address 0x100003f80\n  macho disassemble app --symbol _main --no-addresses --no-bytes\n  macho disassemble app --section __TEXT,__text --no-labels --no-targets\n  macho disassemble app --section __TEXT,__text --format json"
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

    /// Select bytes from --address up to this exclusive virtual address
    /// (hexadecimal, with optional 0x prefix).
    #[arg(long, value_parser = parse_va, requires = "address", conflicts_with_all = ["length", "count"])]
    end_address: Option<u64>,

    /// Demangle retained symbol labels while preserving their raw names.
    #[arg(long)]
    demangle: bool,

    /// Omit the virtual-address column from text output.
    #[arg(long)]
    no_addresses: bool,

    /// Omit the raw-bytes column from text output.
    #[arg(long)]
    no_bytes: bool,

    /// Omit symbol-label lines from text output.
    #[arg(long)]
    no_labels: bool,

    /// Omit resolved direct-target annotations from text output.
    #[arg(long)]
    no_targets: bool,

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

/// Execute the disassembly command, streaming directly to `out` with
/// output-side memory constant in the instruction count. Text is the default;
/// `--format json` emits one instruction object per line as NDJSON.
pub fn run_streaming(args: DisassembleArgs, output: Options, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = crate::parse(&mmap)?;
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
            resolve_slice_selection(&container, selector)?
        }
        None => SliceSelection::All,
    };
    if args.address.is_some()
        && container.is_fat()
        && !matches!(&arches, SliceSelection::One { .. })
    {
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
        let extent = match (args.length, args.count, args.end_address) {
            (Some(length), None, None) => AddressExtent::ByteLength(length),
            (None, Some(count), None) => AddressExtent::InstructionCount(count),
            (None, None, Some(end)) => {
                let length = end
                    .checked_sub(start)
                    .and_then(|length| usize::try_from(length).ok())
                    .and_then(NonZeroUsize::new)
                    .ok_or_else(|| usage_message("--end-address must be greater than --address"))?;
                AddressExtent::ByteLength(length)
            }
            (None, None, None) => {
                AddressExtent::InstructionCount(NonZeroUsize::new(1).expect("one is non-zero"))
            }
            _ => unreachable!("Clap rejects conflicting extents"),
        };
        DisassemblySelection::Address {
            start: crate::model::addr::Va(start),
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
    with_stream_buffer(out, |out| match output.format() {
        Format::Json => {
            let mut sink = NdjsonSink::new(out);
            disassemble_streaming(&container, &request, &mut sink)
        }
        Format::Text => {
            let mut sink = TextLineSink::new(
                output,
                args.no_addresses,
                args.no_bytes,
                args.no_labels,
                args.no_targets,
                out,
            );
            disassemble_streaming(&container, &request, &mut sink)
        }
        Format::Sarif => unreachable!("central output policy rejects disassembly SARIF"),
    })?;
    Ok(())
}

// ───────────────────────── text line sink ─────────────────────────

struct TextLineSink<'a> {
    out: &'a mut dyn Write,
    options: Options,
    no_addresses: bool,
    no_bytes: bool,
    no_labels: bool,
    no_targets: bool,
    multiple: bool,
    raw_width: usize,
    pending_titles: Vec<String>,
    emitted_any_region: bool,
    /// Reused across records so tokenizing a streamed instruction does not
    /// allocate per line.
    spans: Vec<termosaic::Span>,
    /// Reused for each directly assembled line when ANSI styling is disabled.
    plain_line: String,
}

impl<'a> TextLineSink<'a> {
    fn new(
        options: Options,
        no_addresses: bool,
        no_bytes: bool,
        no_labels: bool,
        no_targets: bool,
        out: &'a mut dyn Write,
    ) -> Self {
        Self {
            out,
            options,
            no_addresses,
            no_bytes,
            no_labels,
            no_targets,
            multiple: false,
            raw_width: 8,
            pending_titles: Vec::new(),
            emitted_any_region: false,
            spans: Vec::new(),
            plain_line: String::new(),
        }
    }
}

impl DisassemblySink for TextLineSink<'_> {
    fn begin(
        &mut self,
        container: &ReportContainerIdentity,
        _request: &DisassemblyReportRequest,
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        self.multiple = container.slice_count > 1;
        Ok(())
    }

    fn slice_start(
        &mut self,
        header: SliceHeader,
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
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
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        if !self.emitted_any_region {
            for title in std::mem::take(&mut self.pending_titles) {
                writeln!(self.out, "{title}")?;
            }
            self.emitted_any_region = true;
        }
        let style = self.options.style();
        if !style.enabled() {
            self.plain_line.clear();
            append_sanitized(&mut self.plain_line, &header.segment);
            self.plain_line.push(',');
            append_sanitized(&mut self.plain_line, &header.section);
            write!(self.plain_line, "  {:#018x}", header.start_va)
                .expect("writing to a String cannot fail");
            match header.requested_end_va {
                Some(end) => {
                    write!(self.plain_line, "..{end:#018x}")
                        .expect("writing to a String cannot fail");
                }
                None => {
                    write!(
                        self.plain_line,
                        " ({} instructions)",
                        header.requested_instruction_count.unwrap_or(0)
                    )
                    .expect("writing to a String cannot fail");
                }
            }
            self.plain_line.push('\n');
            self.out.write_all(self.plain_line.as_bytes())?;
            return Ok(());
        }
        self.spans.clear();
        self.spans.push(Span::new(
            termosaic::tokens::TEXT_SUBHEADING,
            format!("{},{}", header.segment, header.section),
        ));
        self.spans.push(asm::literal("  "));
        self.spans.push(Span::new(
            ADDRESS_TOKEN,
            format!("{:#018x}", header.start_va),
        ));
        match header.requested_end_va {
            Some(end) => {
                self.spans
                    .push(Span::new(termosaic::tokens::SYNTAX_PUNCTUATION, ".."));
                self.spans
                    .push(Span::new(ADDRESS_TOKEN, format!("{end:#018x}")));
            }
            None => {
                self.spans.push(asm::literal(" "));
                self.spans.push(Span::new(
                    termosaic::tokens::TEXT_MUTED,
                    format!(
                        "({} instructions)",
                        header.requested_instruction_count.unwrap_or(0)
                    ),
                ));
            }
        }
        writeln!(self.out, "{}", style.render_spans(&self.spans))?;
        Ok(())
    }

    fn record(
        &mut self,
        record: &DisassemblyRecord,
        labels: &[DisassemblyLabel],
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        let style = self.options.style();
        if !style.enabled() {
            if !self.no_labels {
                for label in labels {
                    self.plain_line.clear();
                    append_sanitized(&mut self.plain_line, &label.display_name);
                    self.plain_line.push_str(":\n");
                    self.out.write_all(self.plain_line.as_bytes())?;
                }
            }

            self.plain_line.clear();
            self.plain_line.push_str("  ");
            let (va, bytes) = match record {
                DisassemblyRecord::Instruction { va, bytes, .. }
                | DisassemblyRecord::Gap { va, bytes, .. } => (*va, bytes.as_str()),
            };
            if !self.no_addresses {
                write!(self.plain_line, "{va:#018x}  ").expect("writing to a String cannot fail");
            }
            if !self.no_bytes {
                let padding = self.raw_width.saturating_sub(bytes.len());
                self.plain_line.push_str(bytes);
                self.plain_line
                    .extend(std::iter::repeat_n(' ', padding + 2));
            }
            match record {
                DisassemblyRecord::Instruction {
                    text,
                    direct_target,
                    ..
                } => {
                    append_sanitized(&mut self.plain_line, text);
                    if !self.no_targets
                        && let Some(target) = direct_target
                    {
                        self.plain_line.push_str("  ; ");
                        if let Some(name) = &target.display_symbol {
                            append_sanitized(&mut self.plain_line, name);
                            let offset = target.offset.unwrap_or(0);
                            if offset != 0 {
                                write!(self.plain_line, "+{offset:#x}")
                                    .expect("writing to a String cannot fail");
                            }
                        } else {
                            write!(self.plain_line, "{:#x}", target.va)
                                .expect("writing to a String cannot fail");
                        }
                    }
                }
                DisassemblyRecord::Gap { code, message, .. } => {
                    self.plain_line.push('<');
                    append_sanitized(&mut self.plain_line, code);
                    self.plain_line.push_str("> ");
                    append_sanitized(&mut self.plain_line, message);
                }
            }
            self.plain_line.push('\n');
            self.out.write_all(self.plain_line.as_bytes())?;
            return Ok(());
        }
        if !self.no_labels {
            for label in labels {
                writeln!(
                    self.out,
                    "{}",
                    style.accent(&format!("{}:", label.display_name))
                )?;
            }
        }
        // The record line is assembled as one semantic span stream and rendered
        // once, so every column resolves through the same theme.
        self.spans.clear();
        self.spans.push(asm::literal("  "));
        let (va, bytes) = match record {
            DisassemblyRecord::Instruction { va, bytes, .. }
            | DisassemblyRecord::Gap { va, bytes, .. } => (*va, bytes.as_str()),
        };
        if !self.no_addresses {
            self.spans
                .push(Span::new(ADDRESS_TOKEN, format!("{va:#018x}")));
            self.spans.push(asm::literal("  "));
        }
        if !self.no_bytes {
            // Pad from the unstyled width so the instruction column stays
            // aligned whether or not ANSI sequences were emitted.
            let padding = self.raw_width.saturating_sub(bytes.len());
            self.spans.push(Span::new(RAW_BYTES_TOKEN, bytes));
            self.spans.push(asm::literal(" ".repeat(padding + 2)));
        }
        match record {
            DisassemblyRecord::Instruction {
                text,
                direct_target,
                ..
            } => {
                asm::instruction_spans_into(text, &mut self.spans);
                let annotation = if self.no_targets {
                    None
                } else {
                    direct_target.as_ref().map(|target| {
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
                    })
                };
                if let Some(annotation) = annotation {
                    self.spans.push(asm::literal("  "));
                    self.spans
                        .push(Span::new(termosaic::tokens::SYNTAX_COMMENT, annotation));
                }
            }
            DisassemblyRecord::Gap { code, message, .. } => {
                self.spans.push(Span::new(
                    termosaic::tokens::DIAGNOSTIC_WARNING,
                    format!("<{code}>"),
                ));
                self.spans.push(asm::literal(" "));
                self.spans
                    .push(Span::new(termosaic::tokens::TEXT_MUTED, message));
            }
        }
        writeln!(self.out, "{}", style.render_spans(&self.spans))?;
        Ok(())
    }

    fn region_end(
        &mut self,
        summary: RegionSummary,
        _labels: &[DisassemblyLabel],
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
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
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
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

    fn finish(&mut self) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        if !self.emitted_any_region {
            writeln!(self.out, "No executable sections found.")?;
        }
        Ok(())
    }
}

// ───────────────────────── NDJSON instruction sink ─────────────────────────

/// One self-contained machine-readable instruction. Stream framing, slice
/// headers, region trailers, gaps, and issues never appear on stdout.
#[derive(Serialize)]
struct InstructionLine<'a> {
    schema_version: u32,
    architecture: &'a InstructionArchitecture,
    slice_index: u32,
    va: u64,
    thin_file_offset: u64,
    container_file_offset: u64,
    size: u64,
    bytes: &'a str,
    mnemonic: String,
    operands: Vec<&'a str>,
    kind: InstructionKind,
    metadata: InstructionMetadata<'a>,
}

#[derive(Serialize)]
struct InstructionArchitecture {
    name: String,
    cpu_type: i32,
    cpu_subtype: i32,
}

#[derive(Serialize)]
struct InstructionMetadata<'a> {
    segment: &'a str,
    section: &'a str,
    #[serde(skip_serializing_if = "<[DisassemblyLabel]>::is_empty")]
    labels: &'a [DisassemblyLabel],
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<&'a DirectTarget>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encoding: Option<&'a InstructionEncoding>,
}

/// Split the decoder's canonical assembly spelling into its mnemonic and
/// logical top-level operands. Commas inside memory references, register
/// lists, or parenthesized expressions do not create additional operands.
fn instruction_syntax(text: &str) -> (String, Vec<&str>) {
    let text = text.trim();
    let mnemonic_end = text.find(char::is_whitespace).unwrap_or(text.len());
    let mnemonic = text[..mnemonic_end].to_ascii_lowercase();
    let tail = text[mnemonic_end..].trim();
    if tail.is_empty() {
        return (mnemonic, Vec::new());
    }

    let mut operands = Vec::new();
    let mut start = 0usize;
    let mut square_depth = 0u32;
    let mut brace_depth = 0u32;
    let mut paren_depth = 0u32;
    for (index, character) in tail.char_indices() {
        match character {
            '[' => square_depth += 1,
            ']' => square_depth = square_depth.saturating_sub(1),
            '{' => brace_depth += 1,
            '}' => brace_depth = brace_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            ',' if square_depth == 0 && brace_depth == 0 && paren_depth == 0 => {
                let operand = tail[start..index].trim();
                if !operand.is_empty() {
                    operands.push(operand);
                }
                start = index + character.len_utf8();
            }
            _ => {}
        }
    }
    let operand = tail[start..].trim();
    if !operand.is_empty() {
        operands.push(operand);
    }
    (mnemonic, operands)
}

struct NdjsonSink<'a> {
    out: &'a mut dyn Write,
    architecture: Option<InstructionArchitecture>,
    slice_index: u32,
    segment: Option<String>,
    section: Option<String>,
}

impl<'a> NdjsonSink<'a> {
    fn new(out: &'a mut dyn Write) -> Self {
        Self {
            out,
            architecture: None,
            slice_index: 0,
            segment: None,
            section: None,
        }
    }
}

impl DisassemblySink for NdjsonSink<'_> {
    fn begin(
        &mut self,
        _container: &ReportContainerIdentity,
        _request: &DisassemblyReportRequest,
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        Ok(())
    }

    fn slice_start(
        &mut self,
        header: SliceHeader,
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        let architecture = header.identity.image.architecture;
        self.architecture = Some(InstructionArchitecture {
            name: architecture_name(architecture),
            cpu_type: architecture.cpu_type,
            cpu_subtype: architecture.cpu_subtype,
        });
        self.slice_index = header.identity.image.slice_index;
        Ok(())
    }

    fn region_start(
        &mut self,
        header: RegionHeader,
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        self.segment = Some(header.segment);
        self.section = Some(header.section);
        Ok(())
    }

    fn record(
        &mut self,
        record: &DisassemblyRecord,
        labels: &[DisassemblyLabel],
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        let DisassemblyRecord::Instruction {
            va,
            thin_file_offset,
            container_file_offset,
            size,
            bytes,
            text,
            kind,
            direct_target,
            encoding,
        } = record
        else {
            // Recovering gaps are not instructions and therefore are not part
            // of the machine stream. Strict mode still fails through stderr.
            return Ok(());
        };
        let (mnemonic, operands) = instruction_syntax(text);
        let architecture = self
            .architecture
            .as_ref()
            .expect("slice_start() runs before record()");
        let segment = self
            .segment
            .as_deref()
            .expect("region_start() runs before record()");
        let section = self
            .section
            .as_deref()
            .expect("region_start() runs before record()");
        let line = InstructionLine {
            schema_version: INSTRUCTION_STREAM_SCHEMA_VERSION,
            architecture,
            slice_index: self.slice_index,
            va: *va,
            thin_file_offset: *thin_file_offset,
            container_file_offset: *container_file_offset,
            size: *size,
            bytes: bytes.as_str(),
            mnemonic,
            operands,
            kind: *kind,
            metadata: InstructionMetadata {
                segment,
                section,
                labels,
                target: direct_target.as_ref(),
                encoding: encoding.as_ref(),
            },
        };
        serde_json::to_writer(&mut *self.out, &line).map_err(std::io::Error::other)?;
        self.out.write_all(b"\n")?;
        Ok(())
    }

    fn region_end(
        &mut self,
        _summary: RegionSummary,
        _labels: &[DisassemblyLabel],
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        self.segment = None;
        self.section = None;
        Ok(())
    }

    fn slice_end(
        &mut self,
        _summary: SliceSummary,
        _issues: &[DisassemblyIssue],
    ) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        self.architecture = None;
        Ok(())
    }

    fn finish(&mut self) -> Result<(), crate::analysis::disassembly::DisassemblyError> {
        Ok(())
    }
}

// ───────────────────────── argument parsing ─────────────────────────

fn architecture_name(architecture: Architecture) -> String {
    crate::model::header::ArchSpec {
        cpu_type: crate::model::header::CpuType(architecture.cpu_type),
        cpu_subtype: crate::model::header::CpuSubtype(architecture.cpu_subtype),
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

#[cfg(test)]
mod tests {
    use super::{STREAM_BUFFER_CAPACITY, append_sanitized, instruction_syntax, with_stream_buffer};
    use std::io::{self, Write};

    #[derive(Default)]
    struct RecordingWriter {
        bytes: Vec<u8>,
        write_sizes: Vec<usize>,
        flushes: usize,
        fail_write_once: bool,
        fail_flush: bool,
    }

    impl Write for RecordingWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.write_sizes.push(bytes.len());
            if self.fail_write_once {
                self.fail_write_once = false;
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "stream write failed",
                ));
            }
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            if self.fail_flush {
                return Err(io::Error::other("outer flush failed"));
            }
            Ok(())
        }
    }

    #[test]
    fn stream_buffer_preserves_exact_output() {
        let mut writer = RecordingWriter::default();
        with_stream_buffer(&mut writer, |out| {
            out.write_all(b"alpha")?;
            out.write_all(b"\0beta\n")?;
            Ok(())
        })
        .expect("buffered writes should succeed");

        assert_eq!(writer.bytes, b"alpha\0beta\n");
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn stream_buffer_coalesces_many_logical_writes() {
        const LOGICAL_WRITES: usize = 4096;
        const CHUNK: &[u8] = &[b'x'; 64];
        let mut writer = RecordingWriter::default();
        with_stream_buffer(&mut writer, |out| {
            for _ in 0..LOGICAL_WRITES {
                out.write_all(CHUNK)?;
            }
            Ok(())
        })
        .expect("buffered writes should succeed");

        assert_eq!(writer.bytes.len(), LOGICAL_WRITES * CHUNK.len());
        assert!(writer.write_sizes.len() < LOGICAL_WRITES / 100);
        assert!(
            writer
                .write_sizes
                .iter()
                .all(|&size| size <= STREAM_BUFFER_CAPACITY)
        );
    }

    #[test]
    fn stream_buffer_returns_flush_failure() {
        let mut writer = RecordingWriter {
            fail_flush: true,
            ..RecordingWriter::default()
        };
        let error = with_stream_buffer(&mut writer, |out| {
            out.write_all(b"complete")?;
            Ok(())
        })
        .expect_err("the explicit flush should fail");

        assert!(error.message().contains("outer flush failed"));
        assert_eq!(writer.bytes, b"complete");
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn stream_buffer_prefers_mid_stream_write_failure() {
        let mut writer = RecordingWriter {
            fail_write_once: true,
            fail_flush: true,
            ..RecordingWriter::default()
        };
        let error = with_stream_buffer(&mut writer, |out| {
            for _ in 0..=STREAM_BUFFER_CAPACITY / 64 {
                out.write_all(&[b'x'; 64])?;
            }
            Ok(())
        })
        .expect_err("the buffered stream write should fail");

        assert!(error.message().contains("stream write failed"));
        assert_eq!(writer.flushes, 1);
    }

    #[test]
    fn sanitized_append_replaces_unsafe_ranges_and_preserves_neighbors() {
        let source = concat!(
            "A", "\u{0000}", "\u{001f}", " ", "~", "\u{007f}", "\u{009f}", "\u{00a0}", "\u{2029}",
            "\u{202a}", "\u{202e}", "\u{202f}", "\u{2065}", "\u{2066}", "\u{2069}", "\u{206a}",
            "Z"
        );
        let mut output = String::from("prefix:");
        append_sanitized(&mut output, source);

        assert_eq!(
            output,
            concat!(
                "prefix:A", "\u{fffd}", "\u{fffd}", " ", "~", "\u{fffd}", "\u{fffd}", "\u{00a0}",
                "\u{2029}", "\u{fffd}", "\u{fffd}", "\u{202f}", "\u{2065}", "\u{fffd}", "\u{fffd}",
                "\u{206a}", "Z"
            )
        );
    }

    #[test]
    fn instruction_syntax_preserves_nested_operand_commas() {
        let (mnemonic, operands) = instruction_syntax("STP x29, x30, [sp, #-0x10]!  ");
        assert_eq!(mnemonic, "stp");
        assert_eq!(operands, ["x29", "x30", "[sp, #-0x10]!"]);

        let (mnemonic, operands) = instruction_syntax("nop");
        assert_eq!(mnemonic, "nop");
        assert!(operands.is_empty());
    }
}
