use std::collections::BTreeMap;
use std::io::Write;
use std::num::NonZeroUsize;

use anyhow::Result;
use macho::analysis::disassembly::{
    AddressExtent, DecodeMode, DisassemblyRequest, DisassemblySelection, NonEmpty, SectionSelector,
    SliceSelection, disassemble, resolve_architecture_selector,
};
use macho::analysis::report::Architecture;

use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::output::{Format, Options, columns};
use crate::commands::subcommands::common::map_input;
use crate::commands::usage_message;

#[derive(Debug, clap::Args)]
#[command(
    after_help = "SARIF output is supported only by the audit command.\n\nExamples:\n  macho disassemble app\n  macho disassemble app --arch arm64e --symbol _main\n  macho disassemble app --address 0x100003f50 --count 8\n  macho disassemble app --section __TEXT,__text --format json"
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

/// Execute the disassembly command and render its typed report.
pub fn run(args: DisassembleArgs, output: Options, out: &mut dyn Write) -> Result<()> {
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
    let report = disassemble(&container, &request)?;
    match output.format() {
        Format::Json => crate::commands::output::json::write_pretty(out, &report)?,
        Format::Text => render_text(&report, output, out)?,
        Format::Sarif => unreachable!("central output policy rejects disassembly SARIF"),
    }
    Ok(())
}

fn render_text(
    report: &macho::analysis::report::disassembly::DisassemblyReport,
    output: Options,
    out: &mut dyn Write,
) -> Result<()> {
    let style = output.style();
    if report.slices.iter().all(|slice| slice.regions.is_empty()) {
        writeln!(out, "No executable sections found.")?;
        return Ok(());
    }
    let multiple = report.slices.len() > 1;
    for slice in &report.slices {
        let raw_width = if slice.identity.image.architecture.cpu_type == 0x0100_0007 {
            30
        } else {
            8
        };
        if multiple {
            let architecture = slice.identity.image.architecture;
            writeln!(
                out,
                "{}",
                style.title(&format!(
                    "=== {} [slice {}, 0x{:08x}:0x{:08x}] ===",
                    architecture_name(architecture),
                    slice.identity.image.slice_index + 1,
                    architecture.cpu_type as u32,
                    architecture.cpu_subtype as u32
                ))
            )?;
        }
        for region in &slice.regions {
            let extent = region
                .requested_end_va
                .map(|end| format!("{:#018x}..{end:#018x}", region.start_va))
                .unwrap_or_else(|| {
                    format!(
                        "{:#018x} ({} instructions)",
                        region.start_va,
                        region.requested_instruction_count.unwrap_or(0)
                    )
                });
            writeln!(
                out,
                "{}  {}",
                style.heading(&format!("{},{}", region.segment, region.section)),
                extent
            )?;
            let labels: BTreeMap<u64, Vec<_>> =
                region
                    .labels
                    .iter()
                    .fold(BTreeMap::new(), |mut labels, label| {
                        labels.entry(label.va).or_default().push(label);
                        labels
                    });
            let mut rows = Vec::new();
            for record in &region.records {
                let va = record.va();
                if let Some(labels) = labels.get(&va) {
                    for label in labels {
                        rows.push(vec![format!("{}:", label.display_name)]);
                    }
                }
                match record {
                    macho::analysis::report::disassembly::DisassemblyRecord::Instruction {
                        va,
                        bytes,
                        text,
                        direct_target,
                        ..
                    } => {
                        let annotation =
                            direct_target.as_ref().map_or_else(String::new, |target| {
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
                        rows.push(vec![
                            format!("{va:#018x}"),
                            format!("{:<raw_width$}", bytes.as_str()),
                            format!("{text}{annotation}"),
                        ]);
                    }
                    macho::analysis::report::disassembly::DisassemblyRecord::Gap {
                        va,
                        bytes,
                        code,
                        message,
                        ..
                    } => rows.push(vec![
                        format!("{va:#018x}"),
                        format!("{:<raw_width$}", bytes.as_str()),
                        format!("<{code}> {message}"),
                    ]),
                }
            }
            for mut line in columns::align(&rows) {
                if line.starts_with("0x") {
                    if let Some(end) = line.find("  ") {
                        let address = style.address(&line[..end]);
                        line.replace_range(..end, &address);
                    }
                    writeln!(out, "  {line}")?;
                } else {
                    writeln!(out, "{}", style.accent(&line))?;
                }
            }
            if region.next_unexamined_va.is_some() {
                writeln!(
                    out,
                    "  {} decoded-byte limit reached; next VA {:#x}",
                    style.warning("Partial:"),
                    region.next_unexamined_va.unwrap_or(region.examined_end_va)
                )?;
            }
        }
        if slice.symbol_ranges_truncated {
            writeln!(
                out,
                "{} symbol range limit reached",
                style.warning("Partial:")
            )?;
        }
        for issue in &slice.issues {
            writeln!(
                out,
                "{} [{}] {}",
                style.warning("Warning:"),
                issue.code,
                issue.message
            )?;
        }
    }
    Ok(())
}

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
