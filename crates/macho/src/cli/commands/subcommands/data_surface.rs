use std::io::Write;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::cli::analysis::strings::FoundString;
use crate::cli::analysis::vtables::{SlotTarget, VtableEntry};
use crate::cli::analysis::xref::ranges::{CodeEntity, RangeEntry, RangeSource};
use crate::cli::analysis::xref::refs::{Xref, XrefKind, XrefTarget};
use crate::cli::analysis::{AnalysisDomain, AnalysisLimits};
use crate::cli::commands::OutputFormat;
use crate::cli::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use crate::cli::commands::output::layout::{self, Cell};
use crate::cli::commands::output::{Options as OutputOptions, Style};
use crate::cli::commands::subcommands::common::read_input as read_input_bytes;
use crate::cli::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::cli::model::addr::Va;
use crate::cli::symbols::demangle::demangle_symbol;

#[derive(clap::Args)]
/// Arguments for bounded string analysis.
pub struct StringsArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Search for strings containing this query.
    #[arg(long)]
    search: Option<String>,
    /// Match --search exactly instead of by substring.
    #[arg(long, requires = "search")]
    exact: bool,
    /// Retain only strings with at least this many characters.
    #[arg(long, default_value = "1")]
    min_length: std::num::NonZeroUsize,
    /// Show file offsets alongside virtual addresses in text output.
    #[arg(long)]
    offsets: bool,
    /// Also scan plausible untyped text sections.
    #[arg(long)]
    heuristic: bool,
}

#[derive(clap::Args)]
/// Arguments for bounded C++ virtual-table analysis.
pub struct VtablesArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Filter by class name.
    #[arg(long = "class", alias = "class-filter", name = "class")]
    class_filter: Option<String>,
    /// Demangle class and slot symbol names in text output.
    #[arg(long)]
    demangle: bool,
}

#[derive(clap::Args)]
/// Arguments for bounded symbol-range analysis.
pub struct RangesArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Look up the owner of a virtual address (hexadecimal).
    #[arg(long)]
    lookup: Option<String>,
    /// Retain only entities whose name contains this text (raw or demangled).
    #[arg(long)]
    name: Option<String>,
    /// Retain only ranges from this evidence source (repeatable).
    #[arg(long, value_enum, action = clap::ArgAction::Append)]
    source: Vec<RangeSourceArg>,
    /// Demangle symbol names.
    #[arg(long)]
    demangle: bool,
}

/// Command-line spelling of one symbol-range evidence source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum RangeSourceArg {
    /// Defined nlist symbols.
    Nlist,
    /// Export-trie entries.
    Export,
    /// Objective-C metadata.
    Objc,
    /// Boundary-inferred ranges.
    Inferred,
}

impl RangeSourceArg {
    fn matches(self, source: RangeSource) -> bool {
        matches!(
            (self, source),
            (Self::Nlist, RangeSource::Nlist)
                | (Self::Export, RangeSource::ExportTrie)
                | (Self::Objc, RangeSource::ObjCMetadata)
                | (Self::Inferred, RangeSource::Inferred)
        )
    }
}

#[derive(clap::Args)]
/// Arguments for bounded cross-reference analysis.
pub struct XrefsArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: XrefAnalysisLimitArgs,
    /// Show references originating from this virtual address.
    #[arg(long)]
    from: Option<String>,
    /// Show references targeting this virtual address.
    #[arg(long)]
    to: Option<String>,
    /// Show references targeting imports whose name contains this text.
    #[arg(long, conflicts_with = "to")]
    import: Option<String>,
    /// Retain only references of this kind (repeatable).
    #[arg(long, value_enum, action = clap::ArgAction::Append)]
    kind: Vec<XrefKindArg>,
    /// Demangle import names in text output.
    #[arg(long)]
    demangle: bool,
}

const XREF_DEFAULT_MAX_REFS: usize = 10_000;
const XREF_DEFAULT_MAX_FUNCTIONS: usize = 25_000;
const XREF_DEFAULT_MAX_DECODED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, clap::Args)]
struct XrefAnalysisLimitArgs {
    /// Maximum strings retained per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_strings_per_slice)]
    max_strings: usize,
    /// Maximum cross-references retained per selected slice.
    #[arg(long, default_value_t = XREF_DEFAULT_MAX_REFS)]
    max_xrefs: usize,
    /// Maximum recovered function ranges retained per selected slice.
    #[arg(long, default_value_t = XREF_DEFAULT_MAX_FUNCTIONS)]
    max_ranges: usize,
    /// Maximum virtual tables retained per selected slice.
    #[arg(long, default_value_t = AnalysisLimits::default().max_vtables_per_slice)]
    max_vtables: usize,
    /// Maximum decoded bytes inspected per selected slice.
    #[arg(long, default_value_t = XREF_DEFAULT_MAX_DECODED_BYTES)]
    max_decoded_bytes: usize,
    /// Maximum issues retained for one domain.
    #[arg(long, default_value_t = AnalysisLimits::default().max_issues_per_domain)]
    max_issues: usize,
}

impl From<&XrefAnalysisLimitArgs> for AnalysisLimits {
    fn from(args: &XrefAnalysisLimitArgs) -> Self {
        Self {
            max_strings_per_slice: args.max_strings,
            max_xrefs_per_slice: args.max_xrefs,
            max_ranges_per_slice: args.max_ranges,
            max_vtables_per_slice: args.max_vtables,
            max_decoded_bytes_per_slice: args.max_decoded_bytes,
            max_issues_per_domain: args.max_issues,
        }
    }
}

/// Command-line spelling of one cross-reference kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum XrefKindArg {
    /// Stub-island references.
    Stub,
    /// Chained-fixup bind references.
    ChainedBind,
    /// Chained-fixup rebase references.
    ChainedRebase,
    /// Legacy dyld-info bind references.
    LegacyBind,
    /// Relocation-backed references.
    Relocation,
    /// Direct branch instructions.
    Branch,
    /// Non-branch instruction data references.
    Data,
}

impl XrefKindArg {
    fn matches(self, kind: XrefKind) -> bool {
        matches!(
            (self, kind),
            (Self::Stub, XrefKind::Stub)
                | (Self::ChainedBind, XrefKind::ChainedBind)
                | (Self::ChainedRebase, XrefKind::ChainedRebase)
                | (Self::LegacyBind, XrefKind::LegacyBind)
                | (Self::Relocation, XrefKind::Relocation)
                | (Self::Branch, XrefKind::DirectBranch)
                | (Self::Data, XrefKind::Data)
        )
    }
}

/// Analyze and render strings through an explicit [`crate::cli::analysis::AnalysisPlan`].
pub fn run_strings(args: StringsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = crate::parse(&bytes)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let mut values = analyze_typed::<Vec<FoundString>>(
        &container,
        args.selection.arch.as_deref(),
        AnalysisDomain::Strings,
        (&args.limits).into(),
        args.heuristic,
    )?;
    let min_length = args.min_length.get();
    for (_, strings) in &mut values {
        if min_length > 1 {
            strings.retain(|value| value.value.chars().count() >= min_length);
        }
        if let Some(query) = &args.search {
            if args.exact {
                strings.retain(|value| value.value == *query);
            } else {
                strings.retain(|value| value.value.contains(query));
            }
        }
    }
    if format == OutputFormat::Json {
        return write_typed_json(values, out);
    }
    let multi = values.len() > 1;
    for (arch, strings) in values {
        write_arch_header(out, &arch, multi);
        if strings.is_empty() {
            writeln!(out, "No strings found.")?;
        } else {
            writeln!(out, "Strings: {} found", strings.len())?;
            for value in strings {
                if args.offsets {
                    writeln!(
                        out,
                        "  {:#018x}  {:#010x}  {}",
                        value.va.0, value.file_offset.0, value.value
                    )?;
                } else {
                    writeln!(out, "  {:#018x}  {}", value.va.0, value.value)?;
                }
            }
        }
    }
    Ok(())
}

/// Analyze and render virtual tables through an explicit analysis plan.
pub fn run_vtables(args: VtablesArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = crate::parse(&bytes)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let mut values = analyze_typed::<Vec<VtableEntry>>(
        &container,
        args.selection.arch.as_deref(),
        AnalysisDomain::Vtables,
        (&args.limits).into(),
        true,
    )?;
    if let Some(class_name) = &args.class_filter {
        for (_, vtables) in &mut values {
            vtables.retain(|vtable| {
                vtable
                    .name
                    .as_ref()
                    .is_some_and(|name| name.contains(class_name))
            });
        }
    }
    if format == OutputFormat::Json {
        return write_typed_json(values, out);
    }
    let multi = values.len() > 1;
    for (arch, vtables) in values {
        write_arch_header(out, &arch, multi);
        if vtables.is_empty() {
            writeln!(out, "No C++ vtables found.")?;
            continue;
        }
        writeln!(out, "C++ vtables: {} found", vtables.len())?;
        for vtable in vtables {
            let name = match (&vtable.name, &vtable.mangled_name) {
                (Some(name), _) => name.clone(),
                (None, Some(mangled)) if args.demangle => {
                    demangle_symbol(mangled).unwrap_or_else(|| mangled.clone())
                }
                (None, Some(mangled)) => mangled.clone(),
                (None, None) => "<unknown>".to_owned(),
            };
            writeln!(
                out,
                "\n  {} @ {:#018x} ({} slots, {:#x} bytes)",
                name,
                vtable.va.0,
                vtable.slots.len(),
                vtable.size
            )?;
            for slot in vtable.slots {
                writeln!(
                    out,
                    "    +{:#06x}  {:#018x}  {}",
                    slot.offset,
                    slot.va.0,
                    format_slot_target(&slot.target, args.demangle)
                )?;
            }
        }
    }
    Ok(())
}

/// Analyze and render symbol ranges through an explicit analysis plan.
pub fn run_ranges(args: RangesArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    let format = output.format();
    let style = output.style();
    let bytes = read_input(&args.input.path)?;
    let container = crate::parse(&bytes)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let lookup = args.lookup.as_deref().map(parse_hex_va).transpose()?;
    let mut values = analyze_typed::<Vec<RangeEntry>>(
        &container,
        args.selection.arch.as_deref(),
        AnalysisDomain::Ranges,
        (&args.limits).into(),
        true,
    )?;
    if let Some(va) = lookup {
        for (_, ranges) in &mut values {
            ranges.retain(|range| range.start.0 <= va.0 && va.0 < range.end.0);
            ranges.truncate(1);
        }
    }
    for (_, ranges) in &mut values {
        if let Some(query) = &args.name {
            ranges.retain(|range| entity_matches(&range.entity, query));
        }
        if !args.source.is_empty() {
            ranges.retain(|range| {
                args.source
                    .iter()
                    .any(|source| source.matches(range.source))
            });
        }
    }
    if format == OutputFormat::Json {
        return write_typed_json(values, out);
    }
    let multi = values.len() > 1;
    for (arch, ranges) in values {
        if multi {
            writeln!(out, "{}", style.title(&format!("=== {arch} ===")))?;
        }
        if ranges.is_empty() {
            if let Some(va) = lookup {
                writeln!(out, "No owner found for {:#x}", va.0)?;
            } else {
                writeln!(out, "No symbol ranges found.")?;
            }
            continue;
        }
        if lookup.is_none() {
            let title = format!("Symbol ranges: {} entries", ranges.len());
            writeln!(out, "{}", style.heading(&title))?;
        }
        let rows = ranges
            .into_iter()
            .map(|range| format_range_row(&range, args.demangle, style))
            .collect::<Vec<_>>();
        for line in layout::align(&rows, style) {
            writeln!(out, "{line}")?;
        }
    }
    Ok(())
}

fn format_range_row(range: &RangeEntry, demangle: bool, style: Style) -> Vec<Cell> {
    let span = layout::join_cells([
        layout::plain_cell("  "),
        style.address_cell(&format!("{:#018x}", range.start.0)),
        layout::plain_cell(".."),
        style.address_cell(&format!("{:#018x}", range.end.0)),
    ]);
    let size = style.muted_cell(&format!("{:#x}", range.end.0 - range.start.0));
    let text = format!("[{}]", format_source(range.source));
    let source = match range.source {
        RangeSource::Nlist => style.info_cell(&text),
        RangeSource::ExportTrie => style.success_cell(&text),
        RangeSource::ObjCMetadata => style.accent_cell(&text),
        RangeSource::Inferred => style.warning_cell(&text),
        _ => style.muted_cell(&text),
    };
    vec![
        span,
        size,
        source,
        layout::plain_cell(&format_entity(&range.entity, demangle)),
    ]
}

/// Analyze and render cross-references through an explicit analysis plan.
pub fn run_xrefs(args: XrefsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = crate::parse(&bytes)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let from = args.from.as_deref().map(parse_hex_va).transpose()?;
    let to = args.to.as_deref().map(parse_hex_va).transpose()?;
    let mut values = analyze_typed::<Vec<Xref>>(
        &container,
        args.selection.arch.as_deref(),
        AnalysisDomain::Xrefs,
        (&args.limits).into(),
        true,
    )?;
    for (_, references) in &mut values {
        if let Some(va) = from {
            references.retain(|xref| xref.source == va);
        }
        if let Some(va) = to {
            references.retain(
                |xref| matches!(xref.target, XrefTarget::Internal { va: target } if target == va),
            );
        }
        if let Some(query) = &args.import {
            references.retain(
                |xref| matches!(&xref.target, XrefTarget::Import { name, .. } if name.contains(query)),
            );
        }
        if !args.kind.is_empty() {
            references.retain(|xref| args.kind.iter().any(|kind| kind.matches(xref.kind)));
        }
    }
    if format == OutputFormat::Json {
        return write_typed_json(values, out);
    }
    let multi = values.len() > 1;
    for (arch, references) in values {
        write_arch_header(out, &arch, multi);
        if references.is_empty() {
            writeln!(out, "No cross-references found.")?;
            continue;
        }
        writeln!(out, "Cross-references: {} entries", references.len())?;
        for xref in references {
            writeln!(
                out,
                "  {:#018x} -> {}  [{}]",
                xref.source.0,
                format_target(&xref.target, args.demangle),
                format_kind(xref.kind)
            )?;
        }
    }
    Ok(())
}

fn read_input(path: &std::path::Path) -> Result<Vec<u8>> {
    read_input_bytes(path)
}

fn analyze_typed<T: DeserializeOwned>(
    container: &crate::cli::model::container::MachoContainer<'_>,
    arch: Option<&str>,
    domain: AnalysisDomain,
    limits: AnalysisLimits,
    heuristic_strings: bool,
) -> Result<Vec<(String, T)>> {
    analyze_selected_domain(container, arch, domain, limits, heuristic_strings)?
        .into_iter()
        .map(|(arch, value)| {
            serde_json::from_value(value)
                .with_context(|| format!("decode {} report for {arch}", domain.as_str()))
                .map(|value| (arch, value))
        })
        .collect()
}

fn write_typed_json<T: serde::Serialize>(
    values: Vec<(String, T)>,
    out: &mut dyn Write,
) -> Result<()> {
    let values = values
        .into_iter()
        .map(|(arch, value)| Ok((arch, serde_json::to_value(value)?)))
        .collect::<Result<Vec<(String, Value)>>>()?;
    write_selected_json(values, out)
}

fn write_arch_header(out: &mut dyn Write, arch: &str, multi: bool) {
    if multi {
        let _ = writeln!(out, "=== {arch} ===");
    }
}

fn format_slot_target(target: &SlotTarget, demangle: bool) -> String {
    match target {
        SlotTarget::Function { name, va } => {
            let name = if demangle {
                demangle_symbol(name).unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            format!("-> {name} ({:#x})", va.0)
        }
        SlotTarget::PureVirtual => "-> [pure virtual]".to_owned(),
        SlotTarget::TypeInfo { va } => format!("-> [typeinfo] ({:#x})", va.0),
        SlotTarget::OffsetToTop { value } => format!("-> [offset-to-top: {value}]"),
        SlotTarget::Unknown { value } => format!("-> {value:#018x}"),
        _ => "-> [unknown]".to_owned(),
    }
}

/// Whether a range entity's raw or demangled name contains `query`.
fn entity_matches(entity: &CodeEntity, query: &str) -> bool {
    let name_matches = |name: &str| {
        name.contains(query)
            || demangle_symbol(name).is_some_and(|demangled| demangled.contains(query))
    };
    match entity {
        CodeEntity::Symbol { name, .. } | CodeEntity::Export { name } => name_matches(name),
        CodeEntity::ObjCMethod {
            class_name,
            selector,
            ..
        } => class_name.contains(query) || selector.contains(query),
        CodeEntity::Anonymous { section_name } => section_name.contains(query),
        _ => false,
    }
}

fn format_entity(entity: &CodeEntity, demangle: bool) -> String {
    match entity {
        CodeEntity::Symbol { name, external } => {
            let name = if demangle {
                demangle_symbol(name).unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            if *external {
                format!("{name} [ext]")
            } else {
                name
            }
        }
        CodeEntity::ObjCMethod {
            class_name,
            selector,
            is_class_method,
        } => format!(
            "{}[{class_name} {selector}]",
            if *is_class_method { '+' } else { '-' }
        ),
        CodeEntity::Export { name } => {
            let name = if demangle {
                demangle_symbol(name).unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            format!("{name} [export]")
        }
        CodeEntity::Anonymous { section_name } => format!("<anonymous in {section_name}>"),
        _ => "<unknown entity>".to_owned(),
    }
}

fn format_source(source: RangeSource) -> &'static str {
    match source {
        RangeSource::Nlist => "nlist",
        RangeSource::ExportTrie => "export",
        RangeSource::ObjCMetadata => "objc",
        RangeSource::Inferred => "inferred",
        _ => "unknown",
    }
}

fn format_target(target: &XrefTarget, demangle: bool) -> String {
    match target {
        XrefTarget::Internal { va } => format!("{:#018x}", va.0),
        XrefTarget::Import { name, ordinal } => {
            let name = if demangle {
                demangle_symbol(name).unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            format!("{name} (ordinal {ordinal})")
        }
        _ => "<unknown target>".to_owned(),
    }
}

fn format_kind(kind: XrefKind) -> &'static str {
    match kind {
        XrefKind::Stub => "stub",
        XrefKind::ChainedBind => "chained-bind",
        XrefKind::ChainedRebase => "chained-rebase",
        XrefKind::LegacyBind => "legacy-bind",
        XrefKind::Relocation => "relocation",
        XrefKind::DirectBranch => "branch",
        XrefKind::Data => "data",
        _ => "unknown",
    }
}

fn parse_hex_va(value: &str) -> Result<Va> {
    let digits = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    u64::from_str_radix(digits, 16)
        .with_context(|| format!("invalid hex address: {value}"))
        .map(Va)
}
