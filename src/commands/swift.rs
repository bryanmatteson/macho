use anyhow::{Context, Result};
use macho::model::mach::MachFile;
use macho::swift::SwiftTypeIndex;
use std::path::PathBuf;

use crate::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct SwiftArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Filter by type kind (class, struct, enum, protocol)
    #[arg(long)]
    kind: Option<String>,
}

pub fn run(args: SwiftArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        // Collect all slices into a single JSON object keyed by arch
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |mach, arch_name, _| {
            let index = SwiftTypeIndex::build(mach);
            result.insert(arch_name.to_string(), serde_json::to_value(&index)?);
            Ok(())
        })?;
        if result.len() == 1 {
            // Single arch — emit the index directly
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
                print_swift_text(mach, &args);
                if show_header {
                    println!();
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

fn print_swift_text(mach: &MachFile<'_>, args: &SwiftArgs) {
    let index = SwiftTypeIndex::build(mach);

    if index.types.is_empty() {
        println!("No Swift types discovered.");
        return;
    }

    let filtered: Vec<_> = if let Some(ref kind) = args.kind {
        index
            .types
            .iter()
            .filter(|t| t.kind.to_string() == *kind)
            .collect()
    } else {
        index.types.iter().collect()
    };

    let classes = filtered
        .iter()
        .filter(|t| t.kind == macho::swift::types::SwiftTypeKind::Class)
        .count();
    let structs = filtered
        .iter()
        .filter(|t| t.kind == macho::swift::types::SwiftTypeKind::Struct)
        .count();
    let enums = filtered
        .iter()
        .filter(|t| t.kind == macho::swift::types::SwiftTypeKind::Enum)
        .count();
    let protos = filtered
        .iter()
        .filter(|t| t.kind == macho::swift::types::SwiftTypeKind::Protocol)
        .count();

    println!(
        "Swift types: {} total ({} classes, {} structs, {} enums, {} protocols)",
        filtered.len(),
        classes,
        structs,
        enums,
        protos,
    );

    for t in &filtered {
        let addr = t.address.map(|a| format!(" {a:#x}")).unwrap_or_default();
        let source = match t.source {
            macho::swift::types::SwiftTypeSource::DemangledSymbol => "",
            macho::swift::types::SwiftTypeSource::ObjCMetadata => " [objc]",
        };
        println!("  {:>8} {}{addr}{source}", t.kind, t.name);
    }
}
