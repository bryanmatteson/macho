use anyhow::{Context, Result};
use macho::api::ImageInspector;
use macho::metadata::swift::SwiftTypeIndex;
use std::path::PathBuf;

use crate::cli::commands::common::for_each_selected_mach;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

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
    let kind_filter = match args.kind.as_deref() {
        Some(kind) => Some(parse_kind_filter(kind)?),
        None => None,
    };

    if args.json {
        // Collect all slices into a single JSON object keyed by arch
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |macho, arch_name, _| {
            let inspector = ImageInspector::new(macho);
            let index = inspector.parse_swift_types()?;
            let value = if let Some(kind) = kind_filter {
                let filtered = SwiftTypeIndex {
                    types: index
                        .types
                        .iter()
                        .filter(|t| t.kind == kind)
                        .cloned()
                        .collect(),
                };
                serde_json::to_value(&filtered)?
            } else {
                serde_json::to_value(index)?
            };
            result.insert(arch_name.to_string(), value);
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
            |macho, arch_name, show_header| {
                let inspector = ImageInspector::new(macho);
                let index = inspector.parse_swift_types()?;
                if show_header {
                    println!("=== {arch_name} ===");
                }
                print_swift_text(index, kind_filter);
                if show_header {
                    println!();
                }
                Ok(())
            },
        )?;
    }
    Ok(())
}

fn parse_kind_filter(kind: &str) -> Result<macho::metadata::swift::types::SwiftTypeKind> {
    match kind {
        "class" => Ok(macho::metadata::swift::types::SwiftTypeKind::Class),
        "struct" => Ok(macho::metadata::swift::types::SwiftTypeKind::Struct),
        "enum" => Ok(macho::metadata::swift::types::SwiftTypeKind::Enum),
        "protocol" => Ok(macho::metadata::swift::types::SwiftTypeKind::Protocol),
        "unknown" => Ok(macho::metadata::swift::types::SwiftTypeKind::Unknown),
        _ => anyhow::bail!(
            "invalid kind '{kind}', expected one of: class, struct, enum, protocol, unknown"
        ),
    }
}

fn print_swift_text(
    index: &SwiftTypeIndex,
    kind_filter: Option<macho::metadata::swift::types::SwiftTypeKind>,
) {
    if index.types.is_empty() {
        println!("No Swift types discovered.");
        return;
    }

    let filtered: Vec<_> = if let Some(kind) = kind_filter {
        index.types.iter().filter(|t| t.kind == kind).collect()
    } else {
        index.types.iter().collect()
    };

    let high_confidence = filtered.iter().filter(|t| t.confidence.is_high()).count();
    let partial = filtered.len().saturating_sub(high_confidence);
    let classes = filtered
        .iter()
        .filter(|t| t.kind == macho::metadata::swift::types::SwiftTypeKind::Class)
        .count();
    let structs = filtered
        .iter()
        .filter(|t| t.kind == macho::metadata::swift::types::SwiftTypeKind::Struct)
        .count();
    let enums = filtered
        .iter()
        .filter(|t| t.kind == macho::metadata::swift::types::SwiftTypeKind::Enum)
        .count();
    let protos = filtered
        .iter()
        .filter(|t| t.kind == macho::metadata::swift::types::SwiftTypeKind::Protocol)
        .count();

    println!(
        "Swift types: {} total ({} high-confidence, {} partial; {} classes, {} structs, {} enums, {} protocols)",
        filtered.len(),
        high_confidence,
        partial,
        classes,
        structs,
        enums,
        protos,
    );

    for t in &filtered {
        let addr = t.address.map(|a| format!(" {a:#x}")).unwrap_or_default();
        let source = match t.source {
            macho::metadata::swift::types::SwiftTypeSource::DemangledSymbol => "",
            macho::metadata::swift::types::SwiftTypeSource::ObjCMetadata => " [objc]",
        };
        let confidence = if t.confidence.is_high() {
            ""
        } else {
            " [partial]"
        };
        println!("  {:>8} {}{addr}{source}{confidence}", t.kind, t.name);
    }
}
