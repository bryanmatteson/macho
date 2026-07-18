use std::collections::BTreeSet;
use std::io::Write;

use anyhow::{Context, Result};
use macho::analysis::report::{
    SwiftEntity, SwiftEntityState, SwiftReport, SwiftTypeKind, SwiftValue, recover_swift_container,
};

use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::output::{Options as OutputOptions, Style, columns};
use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, usage_message};

#[derive(clap::Args)]
/// Evidence-accountable Swift metadata recovery.
pub struct SwiftArgs {
    /// Path to Mach-O binary.
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture.
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Filter by type kind.
    #[arg(long)]
    kind: Option<String>,
}

/// Runs Swift recovery.
pub fn run(args: SwiftArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    if output.format() == OutputFormat::Sarif {
        return Err(usage_message("Swift recovery supports only text and JSON"));
    }
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;
    let mut report = recover_swift_container(&container, args.selection.arch.as_deref())?;
    let kind_filter = args.kind.as_deref().map(parse_kind_filter).transpose()?;
    apply_filter(&mut report, kind_filter);

    match output.format() {
        OutputFormat::Json => crate::commands::output::json::write_pretty(out, &report)?,
        OutputFormat::Text => print_swift_text(&report, output.style(), out),
        OutputFormat::Sarif => unreachable!("rejected above"),
    }
    Ok(())
}

fn parse_kind_filter(kind: &str) -> Result<SwiftTypeKind> {
    match kind {
        "class" => Ok(SwiftTypeKind::Class),
        "struct" => Ok(SwiftTypeKind::Struct),
        "enum" => Ok(SwiftTypeKind::Enum),
        "protocol" => Ok(SwiftTypeKind::Protocol),
        "type-alias" => Ok(SwiftTypeKind::TypeAlias),
        "opaque" => Ok(SwiftTypeKind::Opaque),
        "unknown" => Ok(SwiftTypeKind::Unknown),
        _ => Err(usage_message(format!(
            "invalid kind '{kind}', expected one of: class, struct, enum, protocol, type-alias, opaque, unknown"
        ))),
    }
}

fn apply_filter(report: &mut SwiftReport, kind_filter: Option<SwiftTypeKind>) {
    for slice in report.slices.as_mut_slice() {
        slice.selection.selected_entity_ids = slice
            .entities
            .iter()
            .filter(|entity| kind_filter.is_none_or(|kind| entity_kind(entity) == kind))
            .map(|entity| entity.id.clone())
            .collect();
    }
}

fn print_swift_text(report: &SwiftReport, style: Style, out: &mut dyn Write) {
    let _ = writeln!(out, "{}", style.title("Swift recovery"));
    for slice in report.slices.as_slice() {
        let selected_ids = slice
            .selection
            .selected_entity_ids
            .iter()
            .map(|id| id.as_str())
            .collect::<BTreeSet<_>>();
        let selected = slice
            .entities
            .iter()
            .filter(|entity| selected_ids.contains(entity.id.as_str()))
            .collect::<Vec<_>>();
        let totals = &slice.selection.totals;
        let _ = writeln!(
            out,
            "  {}  {}  {}  {}  {}  {}  {}",
            style.enum_property("arch", &architecture_name(slice.architecture)),
            style.property("metadata-defined", &totals.metadata_defined.to_string()),
            style.property("referenced", &totals.referenced.to_string()),
            style.property("symbol-only", &totals.symbol_only.to_string()),
            style.property("partial", &totals.partial.to_string()),
            style.property("unknown", &totals.unknown.to_string()),
            style.property("selected", &selected.len().to_string()),
        );
        if selected.is_empty() {
            let _ = writeln!(
                out,
                "  {}",
                style.muted("No Swift entities matched the selection.")
            );
            continue;
        }
        for state in [
            SwiftEntityState::MetadataDefined,
            SwiftEntityState::Referenced,
            SwiftEntityState::SymbolOnly,
            SwiftEntityState::Partial,
            SwiftEntityState::Unknown,
        ] {
            let entities = selected
                .iter()
                .copied()
                .filter(|entity| entity.state == state)
                .collect::<Vec<_>>();
            if entities.is_empty() {
                continue;
            }
            let _ = writeln!(out, "  {}", style.heading(state_heading(state)));
            let rows = entities
                .into_iter()
                .map(|entity| {
                    vec![
                        style.enum_value(kind_name(entity_kind(entity))),
                        style.accent(&entity_name(entity)),
                        entity_address(entity)
                            .map(|address| style.address(&format!("0x{address:016x}")))
                            .unwrap_or_else(|| style.muted("-")),
                        style.property("fields", &entity_field_count(entity).to_string()),
                        style.property("gaps", &entity.gaps.len().to_string()),
                    ]
                })
                .collect::<Vec<_>>();
            for row in columns::align(&rows) {
                let _ = writeln!(out, "    {row}");
            }
        }
        for diagnostic in &slice.diagnostics {
            let _ = writeln!(
                out,
                "  {}  {}",
                style.warning(&format!("{:?}", diagnostic.code).to_lowercase()),
                diagnostic.message
            );
        }
    }
}

fn entity_kind(entity: &SwiftEntity) -> SwiftTypeKind {
    match &entity.kind {
        SwiftValue::Known { value, .. } => *value,
        _ => SwiftTypeKind::Unknown,
    }
}

fn entity_name(entity: &SwiftEntity) -> String {
    match &entity.qualified_name {
        SwiftValue::Known { value, .. } => value.path.as_slice().join("."),
        _ => "<unknown>".to_owned(),
    }
}

fn entity_address(entity: &SwiftEntity) -> Option<u64> {
    match &entity.descriptor {
        SwiftValue::Known { value, .. } => Some(value.virtual_address),
        _ => None,
    }
}

fn entity_field_count(entity: &SwiftEntity) -> usize {
    match &entity.fields_or_cases {
        SwiftValue::Known { value, .. } => value.len(),
        _ => 0,
    }
}

fn state_heading(state: SwiftEntityState) -> &'static str {
    match state {
        SwiftEntityState::MetadataDefined => "Metadata-defined",
        SwiftEntityState::Referenced => "Referenced",
        SwiftEntityState::SymbolOnly => "Symbol-only",
        SwiftEntityState::Partial => "Partial",
        SwiftEntityState::Unknown => "Unknown",
    }
}

fn kind_name(kind: SwiftTypeKind) -> &'static str {
    match kind {
        SwiftTypeKind::Class => "class",
        SwiftTypeKind::Struct => "struct",
        SwiftTypeKind::Enum => "enum",
        SwiftTypeKind::Protocol => "protocol",
        SwiftTypeKind::TypeAlias => "type-alias",
        SwiftTypeKind::Opaque => "opaque",
        SwiftTypeKind::Unknown => "unknown",
    }
}

fn architecture_name(architecture: macho::analysis::report::Architecture) -> String {
    let cpu = macho::core::model::header::CpuType(architecture.cpu_type);
    let subtype = macho::core::model::header::CpuSubtype(architecture.cpu_subtype);
    format!("{} ({})", cpu.name(), subtype.name(cpu))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kind_filter_is_closed() {
        assert_eq!(parse_kind_filter("class").unwrap(), SwiftTypeKind::Class);
        assert!(parse_kind_filter("actorish").is_err());
    }
}
