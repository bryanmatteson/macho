use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::{OutputFormat, usage_message};
use anyhow::{Context, Result};
use macho::metadata::swift::SwiftTypeIndex;
use std::io::Write;

use crate::commands::subcommands::common::{for_each_selected_mach, map_input};

#[derive(clap::Args)]
/// The SwiftArgs type.
pub struct SwiftArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Filter by type kind (class, struct, enum, protocol)
    #[arg(long)]
    kind: Option<String>,
}

/// Performs run.
pub fn run(args: SwiftArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let kind_filter = match args.kind.as_deref() {
        Some(kind) => Some(parse_kind_filter(kind)?),
        None => None,
    };

    if format == OutputFormat::Json {
        // Collect all slices into a single JSON object keyed by arch
        let mut result = serde_json::Map::new();
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |macho, arch_name, _| {
                let index = macho.ext::<macho::swift::SwiftTypeIndex>()?;
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
                    serde_json::to_value(&index)?
                };
                result.insert(arch_name.to_string(), value);
                Ok(())
            },
        )?;
        if result.len() == 1 {
            // Single arch — emit the index directly
            let (_, val) = result.into_iter().next().unwrap();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&val)?);
        } else {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(
            &container,
            args.selection.arch.as_deref(),
            |macho, arch_name, show_header| {
                let index = macho.ext::<macho::swift::SwiftTypeIndex>()?;
                if show_header {
                    let _ = writeln!(out, "=== {arch_name} ===");
                }
                print_swift_text(&index, kind_filter, out);
                if show_header {
                    let _ = writeln!(out,);
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
        _ => Err(usage_message(format!(
            "invalid kind '{kind}', expected one of: class, struct, enum, protocol, unknown"
        ))),
    }
}

fn print_swift_text(
    index: &SwiftTypeIndex,
    kind_filter: Option<macho::metadata::swift::types::SwiftTypeKind>,
    out: &mut dyn Write,
) {
    if index.types.is_empty() {
        let _ = writeln!(out, "No Swift types discovered.");
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

    let _ = writeln!(
        out,
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
            _ => " [unknown]",
        };
        let confidence = if t.confidence.is_high() {
            ""
        } else {
            " [partial]"
        };
        let _ = writeln!(out, "  {:>8} {}{addr}{source}{confidence}", t.kind, t.name);
    }
}
