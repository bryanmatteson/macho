use crate::analysis::strings::StringRegions;
use crate::analysis::xref::ranges::{CodeEntity, SymbolRangeIndex};
use crate::analysis::xref::refs::{XrefIndex, XrefKind, XrefTarget};
use crate::model::addr::Va;
use crate::model::mach_file::MachFile;
use crate::recovery::vtables::SlotTarget;
use crate::recovery::vtables::VtableIndex;
use crate::symbols::demangle::demangle_symbol;
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::cli::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct StringsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Search for strings containing this query
    #[arg(long)]
    search: Option<String>,
    /// Also scan heuristic string regions
    #[arg(long)]
    heuristic: bool,
}

#[derive(clap::Args)]
pub struct VtablesArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Filter by class name
    #[arg(long, name = "class")]
    class_filter: Option<String>,
}

pub fn run_strings(args: StringsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |mach, arch_name, _| {
            let regions = if args.heuristic {
                StringRegions::with_heuristic(mach)
            } else {
                StringRegions::discover(mach)
            };

            let value = if let Some(ref query) = args.search {
                serde_json::to_value(regions.search(mach, query))?
            } else {
                serde_json::to_value(&regions)?
            };

            result.insert(arch_name.to_string(), value);
            Ok(())
        })?;

        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(
            &container,
            args.arch.as_deref(),
            |mach, arch_name, show_header| {
                if show_header {
                    println!("=== {arch_name} ===");
                }
                print_strings_text(mach, &args);
                if show_header {
                    println!();
                }
                Ok(())
            },
        )?;
    }

    Ok(())
}

fn print_strings_text(mach: &MachFile<'_>, args: &StringsArgs) {
    let regions = if args.heuristic {
        StringRegions::with_heuristic(mach)
    } else {
        StringRegions::discover(mach)
    };

    if regions.regions.is_empty() {
        println!("No string regions discovered.");
        return;
    }

    if let Some(ref query) = args.search {
        let matches = regions.search(mach, query);
        println!(
            "Found {} matches for \"{}\" across {} regions:",
            matches.len(),
            query,
            regions.regions.len(),
        );
        for m in &matches {
            let region = &regions.regions[m.region_index];
            println!(
                "  {:#018x}  [{},{}]  {}",
                m.va.0, region.section_segment, region.section_name, m.value,
            );
        }
    } else {
        println!("String regions: {} discovered", regions.regions.len(),);
        for (i, region) in regions.regions.iter().enumerate() {
            let strings = regions.strings_in_region(mach, region);
            println!(
                "  [{i}] {},{} ({:?}) - {} strings, {:#x} bytes @ {:#018x}",
                region.section_segment,
                region.section_name,
                region.kind,
                strings.len(),
                region.size,
                region.start.0,
            );
        }
    }
}

pub fn run_vtables(args: VtablesArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |mach, arch_name, _| {
            let index = VtableIndex::build(mach)?;

            let value = if let Some(ref class_name) = args.class_filter {
                let filtered: Vec<_> = index
                    .vtables
                    .iter()
                    .filter(|v| v.name.as_ref().is_some_and(|n| n.contains(class_name)))
                    .collect();
                serde_json::to_value(&filtered)?
            } else {
                serde_json::to_value(&index)?
            };

            result.insert(arch_name.to_string(), value);
            Ok(())
        })?;

        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(
            &container,
            args.arch.as_deref(),
            |mach, arch_name, show_header| {
                if show_header {
                    println!("=== {arch_name} ===");
                }
                print_vtables_text(mach, &args)?;
                if show_header {
                    println!();
                }
                Ok(())
            },
        )?;
    }

    Ok(())
}

fn print_vtables_text(mach: &MachFile<'_>, args: &VtablesArgs) -> Result<()> {
    let index = VtableIndex::build(mach)?;

    if index.vtables.is_empty() {
        println!("No C++ vtables found.");
        return Ok(());
    }

    let filtered: Vec<_> = if let Some(ref class_name) = args.class_filter {
        index
            .vtables
            .iter()
            .filter(|v| v.name.as_ref().is_some_and(|n| n.contains(class_name)))
            .collect()
    } else {
        index.vtables.iter().collect()
    };

    println!("C++ vtables: {} found", filtered.len());

    for vtable in &filtered {
        let name = vtable
            .name
            .as_deref()
            .or(vtable.mangled_name.as_deref())
            .unwrap_or("<unknown>");
        println!(
            "\n  {} @ {:#018x} ({} slots, {:#x} bytes)",
            name,
            vtable.va.0,
            vtable.slots.len(),
            vtable.size,
        );

        for slot in &vtable.slots {
            let target_str = match &slot.target {
                SlotTarget::Function { name, va } => {
                    format!("-> {} ({:#x})", name, va.0)
                }
                SlotTarget::PureVirtual => "-> [pure virtual]".to_string(),
                SlotTarget::TypeInfo { va } => {
                    format!("-> [typeinfo] ({:#x})", va.0)
                }
                SlotTarget::OffsetToTop { value } => {
                    if *value == 0 {
                        "-> [offset-to-top: 0]".to_string()
                    } else {
                        format!("-> [offset-to-top: {value}]")
                    }
                }
                SlotTarget::Unknown { value } => {
                    format!("-> {value:#018x}")
                }
            };

            println!(
                "    +{:#06x}  {:#018x}  {target_str}",
                slot.offset, slot.va.0,
            );
        }
    }

    Ok(())
}

// ── Ranges command ──────────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct RangesArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Look up the owner of a specific virtual address (hex, e.g. 0x100003f00)
    #[arg(long)]
    lookup: Option<String>,
    /// Demangle symbol names
    #[arg(long)]
    demangle: bool,
}

pub fn run_ranges(args: RangesArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    let lookup_va = args.lookup.as_ref().map(|s| parse_hex_va(s)).transpose()?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |mach, arch_name, _| {
            let index = SymbolRangeIndex::build(mach)?;
            let value = if let Some(va) = lookup_va {
                serde_json::to_value(index.lookup_va(va))?
            } else {
                serde_json::to_value(&index)?
            };
            result.insert(arch_name.to_string(), value);
            Ok(())
        })?;

        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(
            &container,
            args.arch.as_deref(),
            |mach, arch_name, show_header| {
                if show_header {
                    println!("=== {arch_name} ===");
                }
                print_ranges_text(mach, &args, lookup_va)?;
                if show_header {
                    println!();
                }
                Ok(())
            },
        )?;
    }

    Ok(())
}

fn print_ranges_text(mach: &MachFile<'_>, args: &RangesArgs, lookup_va: Option<Va>) -> Result<()> {
    let index = SymbolRangeIndex::build(mach)?;

    if let Some(va) = lookup_va {
        match index.lookup_va(va) {
            Some(entry) => {
                let name = format_entity(&entry.entity, args.demangle);
                println!(
                    "{:#018x}..{:#018x}  {:#x}  [{}]  {}",
                    entry.start.0,
                    entry.end.0,
                    entry.end.0 - entry.start.0,
                    format_source(entry.source),
                    name,
                );
            }
            None => println!("No owner found for {:#x}", va.0),
        }
        return Ok(());
    }

    if index.is_empty() {
        println!("No symbol ranges found.");
        return Ok(());
    }

    println!("Symbol ranges: {} entries", index.len());
    for entry in index.entries() {
        let name = format_entity(&entry.entity, args.demangle);
        println!(
            "  {:#018x}..{:#018x}  {:#x}  [{}]  {}",
            entry.start.0,
            entry.end.0,
            entry.end.0 - entry.start.0,
            format_source(entry.source),
            name,
        );
    }

    Ok(())
}

fn format_entity(entity: &CodeEntity, do_demangle: bool) -> String {
    match entity {
        CodeEntity::Symbol { name, external } => {
            let display = if do_demangle {
                demangle_symbol(name).unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            if *external {
                format!("{display} [ext]")
            } else {
                display
            }
        }
        CodeEntity::ObjCMethod {
            class_name,
            selector,
            is_class_method,
        } => {
            let prefix = if *is_class_method { '+' } else { '-' };
            format!("{prefix}[{class_name} {selector}]")
        }
        CodeEntity::Export { name } => {
            let display = if do_demangle {
                demangle_symbol(name).unwrap_or_else(|| name.clone())
            } else {
                name.clone()
            };
            format!("{display} [export]")
        }
        CodeEntity::Anonymous { section_name } => {
            format!("<anonymous in {section_name}>")
        }
    }
}

fn format_source(source: crate::analysis::xref::ranges::RangeSource) -> &'static str {
    match source {
        crate::analysis::xref::ranges::RangeSource::Nlist => "nlist",
        crate::analysis::xref::ranges::RangeSource::ExportTrie => "export",
        crate::analysis::xref::ranges::RangeSource::ObjCMetadata => "objc",
        crate::analysis::xref::ranges::RangeSource::Inferred => "inferred",
    }
}

// ── Xrefs command ───────────────────────────────────────────────────────

#[derive(clap::Args)]
pub struct XrefsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Show xrefs originating from this virtual address (hex)
    #[arg(long)]
    from: Option<String>,
    /// Show xrefs targeting this virtual address (hex)
    #[arg(long)]
    to: Option<String>,
}

pub fn run_xrefs(args: XrefsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    let from_va = args.from.as_ref().map(|s| parse_hex_va(s)).transpose()?;
    let to_va = args.to.as_ref().map(|s| parse_hex_va(s)).transpose()?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |mach, arch_name, _| {
            let index = XrefIndex::build(mach)?;
            let value = if let Some(va) = from_va {
                let refs: Vec<_> = index.refs_from(va).collect();
                serde_json::to_value(&refs)?
            } else if let Some(va) = to_va {
                let refs: Vec<_> = index.refs_to(va).collect();
                serde_json::to_value(&refs)?
            } else {
                serde_json::to_value(&index)?
            };
            result.insert(arch_name.to_string(), value);
            Ok(())
        })?;

        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(
            &container,
            args.arch.as_deref(),
            |mach, arch_name, show_header| {
                if show_header {
                    println!("=== {arch_name} ===");
                }
                print_xrefs_text(mach, from_va, to_va)?;
                if show_header {
                    println!();
                }
                Ok(())
            },
        )?;
    }

    Ok(())
}

fn print_xrefs_text(mach: &MachFile<'_>, from_va: Option<Va>, to_va: Option<Va>) -> Result<()> {
    let index = XrefIndex::build(mach)?;

    if let Some(va) = from_va {
        let refs: Vec<_> = index.refs_from(va).collect();
        println!("Xrefs from {:#018x}: {} found", va.0, refs.len());
        for xref in &refs {
            println!(
                "  -> {}  [{}]",
                format_target(&xref.target),
                format_kind(xref.kind),
            );
        }
        return Ok(());
    }

    if let Some(va) = to_va {
        let refs: Vec<_> = index.refs_to(va).collect();
        println!("Xrefs to {:#018x}: {} found", va.0, refs.len());
        for xref in &refs {
            println!("  {:#018x}  [{}]", xref.source.0, format_kind(xref.kind));
        }
        return Ok(());
    }

    if index.is_empty() {
        println!("No cross-references found.");
        return Ok(());
    }

    println!("Cross-references: {} entries", index.len());
    for xref in index.all_refs() {
        println!(
            "  {:#018x} -> {}  [{}]",
            xref.source.0,
            format_target(&xref.target),
            format_kind(xref.kind),
        );
    }

    Ok(())
}

fn format_target(target: &XrefTarget) -> String {
    match target {
        XrefTarget::Internal { va } => format!("{:#018x}", va.0),
        XrefTarget::Import { name, ordinal } => format!("{name} (ordinal {ordinal})"),
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
    }
}

fn parse_hex_va(s: &str) -> Result<Va> {
    let s = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    let val = u64::from_str_radix(s, 16).with_context(|| format!("invalid hex address: {s}"))?;
    Ok(Va(val))
}
