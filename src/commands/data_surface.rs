use anyhow::{Context, Result};
use macho::data_surface::strings::StringRegions;
use macho::data_surface::vtable::VtableIndex;
use macho::model::mach::MachFile;
use std::path::PathBuf;

use crate::commands::common::for_each_selected_mach;

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
        println!(
            "String regions: {} discovered",
            regions.regions.len(),
        );
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
                    .filter(|v| {
                        v.name
                            .as_ref()
                            .is_some_and(|n| n.contains(class_name))
                    })
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
            .filter(|v| {
                v.name
                    .as_ref()
                    .is_some_and(|n| n.contains(class_name))
            })
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
                macho::data_surface::vtable::SlotTarget::Function { name, va } => {
                    format!("-> {} ({:#x})", name, va.0)
                }
                macho::data_surface::vtable::SlotTarget::PureVirtual => {
                    "-> [pure virtual]".to_string()
                }
                macho::data_surface::vtable::SlotTarget::TypeInfo { va } => {
                    format!("-> [typeinfo] ({:#x})", va.0)
                }
                macho::data_surface::vtable::SlotTarget::OffsetToTop { value } => {
                    if *value == 0 {
                        "-> [offset-to-top: 0]".to_string()
                    } else {
                        format!("-> [offset-to-top: {}]", value)
                    }
                }
                macho::data_surface::vtable::SlotTarget::Unknown { value } => {
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
