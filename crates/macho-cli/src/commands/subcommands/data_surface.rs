use std::io::Write;

use anyhow::{Context, Result};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::analysis::strings::FoundString;
use crate::analysis::vtables::{SlotTarget, VtableEntry};
use crate::analysis::xref::ranges::{CodeEntity, RangeEntry, RangeSource};
use crate::analysis::xref::refs::{Xref, XrefKind, XrefTarget};
use crate::analysis::{AnalysisDomain, AnalysisLimits};
use crate::commands::OutputFormat;
use crate::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::read_input as read_input_bytes;
use crate::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::model::addr::Va;
use crate::symbols::demangle::demangle_symbol;

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
    #[arg(long, name = "class")]
    class_filter: Option<String>,
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
    /// Demangle symbol names.
    #[arg(long)]
    demangle: bool,
}

#[derive(clap::Args)]
/// Arguments for bounded cross-reference analysis.
pub struct XrefsArgs {
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Show references originating from this virtual address.
    #[arg(long)]
    from: Option<String>,
    /// Show references targeting this virtual address.
    #[arg(long)]
    to: Option<String>,
}

/// Analyze and render strings through an explicit [`crate::analysis::AnalysisPlan`].
pub fn run_strings(args: StringsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = macho::parse(&bytes)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let mut values = analyze_typed::<Vec<FoundString>>(
        &container,
        args.selection.arch.as_deref(),
        AnalysisDomain::Strings,
        (&args.limits).into(),
        args.heuristic,
    )?;
    if let Some(query) = &args.search {
        for (_, strings) in &mut values {
            strings.retain(|value| value.value.contains(query));
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
                writeln!(out, "  {:#018x}  {}", value.va.0, value.value)?;
            }
        }
    }
    Ok(())
}

/// Analyze and render virtual tables through an explicit analysis plan.
pub fn run_vtables(args: VtablesArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = macho::parse(&bytes)
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
            let name = vtable
                .name
                .as_deref()
                .or(vtable.mangled_name.as_deref())
                .unwrap_or("<unknown>");
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
                    format_slot_target(&slot.target)
                )?;
            }
        }
    }
    Ok(())
}

/// Analyze and render symbol ranges through an explicit analysis plan.
pub fn run_ranges(args: RangesArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = macho::parse(&bytes)
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
    if format == OutputFormat::Json {
        return write_typed_json(values, out);
    }
    let multi = values.len() > 1;
    for (arch, ranges) in values {
        write_arch_header(out, &arch, multi);
        if ranges.is_empty() {
            if let Some(va) = lookup {
                writeln!(out, "No owner found for {:#x}", va.0)?;
            } else {
                writeln!(out, "No symbol ranges found.")?;
            }
            continue;
        }
        if lookup.is_none() {
            writeln!(out, "Symbol ranges: {} entries", ranges.len())?;
        }
        for range in ranges {
            writeln!(
                out,
                "  {:#018x}..{:#018x}  {:#x}  [{}]  {}",
                range.start.0,
                range.end.0,
                range.end.0 - range.start.0,
                format_source(range.source),
                format_entity(&range.entity, args.demangle)
            )?;
        }
    }
    Ok(())
}

/// Analyze and render cross-references through an explicit analysis plan.
pub fn run_xrefs(args: XrefsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let bytes = read_input(&args.input.path)?;
    let container = macho::parse(&bytes)
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
        } else if let Some(va) = to {
            references.retain(
                |xref| matches!(xref.target, XrefTarget::Internal { va: target } if target == va),
            );
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
                format_target(&xref.target),
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
    container: &crate::model::container::MachoContainer<'_>,
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

fn format_slot_target(target: &SlotTarget) -> String {
    match target {
        SlotTarget::Function { name, va } => format!("-> {name} ({:#x})", va.0),
        SlotTarget::PureVirtual => "-> [pure virtual]".to_owned(),
        SlotTarget::TypeInfo { va } => format!("-> [typeinfo] ({:#x})", va.0),
        SlotTarget::OffsetToTop { value } => format!("-> [offset-to-top: {value}]"),
        SlotTarget::Unknown { value } => format!("-> {value:#018x}"),
        _ => "-> [unknown]".to_owned(),
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

fn format_target(target: &XrefTarget) -> String {
    match target {
        XrefTarget::Internal { va } => format!("{:#018x}", va.0),
        XrefTarget::Import { name, ordinal } => format!("{name} (ordinal {ordinal})"),
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
