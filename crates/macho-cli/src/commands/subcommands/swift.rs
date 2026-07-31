use std::collections::BTreeSet;
use std::io::Write;

use anyhow::{Context, Result};
use macho::analysis::report::{
    SwiftEntity, SwiftEntityState, SwiftField, SwiftReport, SwiftTypeKind, SwiftUnavailableReason,
    SwiftValue, project_swift_headers, recover_swift_container,
};

use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::output::layout;
use crate::commands::output::{Options as OutputOptions, Style};
use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, usage_message};

#[derive(clap::Args)]
#[command(
    after_help = "Examples:\n  macho swift app --kind class --state metadata-defined\n  macho swift app --name Module.Type --exact\n  macho swift app --arch arm64 --name Module.Type --exact --headers\n  macho swift app --kind struct --kind enum --format json"
)]
/// Evidence-accountable Swift metadata recovery.
pub struct SwiftArgs {
    /// Path to Mach-O binary.
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture.
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Retain one or more type kinds (repeatable).
    #[arg(long = "kind", value_name = "KIND", value_enum, action = clap::ArgAction::Append)]
    kinds: Vec<SwiftTypeKindArg>,
    /// Retain one or more recovery states (repeatable).
    #[arg(long = "state", value_name = "STATE", value_enum, action = clap::ArgAction::Append)]
    states: Vec<SwiftEntityStateArg>,
    /// Retain entities whose qualified or raw linkage name contains this text.
    #[arg(long)]
    name: Option<String>,
    /// Match --name exactly instead of by substring.
    #[arg(long, requires = "name")]
    exact: bool,
    /// Render the validated Swift declaration projection.
    #[arg(long, visible_alias = "declarations")]
    headers: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SwiftTypeKindArg {
    Class,
    Struct,
    Enum,
    Protocol,
    TypeAlias,
    Opaque,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SwiftEntityStateArg {
    MetadataDefined,
    Referenced,
    SymbolOnly,
    Partial,
    Unknown,
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
    apply_filter(
        &mut report,
        &args.kinds,
        &args.states,
        args.name.as_deref(),
        args.exact,
    );

    if args.headers {
        if report.slices.as_slice().len() > 1 && args.selection.arch.is_none() {
            return Err(usage_message(
                "fat Swift declaration output requires --arch",
            ));
        }
        project_swift_headers(&mut report)?;
    }

    match output.format() {
        OutputFormat::Json => crate::commands::output::json::write_pretty(out, &report)?,
        OutputFormat::Text if args.headers => {
            for slice in report.slices.as_slice() {
                let header = slice
                    .header
                    .as_ref()
                    .expect("header projection requested for every selected slice");
                out.write_all(header.source.as_bytes())?;
                if header.declarations.is_empty() {
                    // The banner alone leaves "no Swift metadata here" looking
                    // like a truncated run, so the empty result is stated.
                    writeln!(
                        out,
                        "// No Swift declarations projected for {}.",
                        architecture_name(slice.architecture)
                    )?;
                }
                if !header.unresolved.is_empty() {
                    // The ledger records member gaps as well as whole
                    // declarations, so report the two separately rather than
                    // calling every entry a declaration.
                    let declarations = header
                        .unresolved
                        .iter()
                        .filter(|gap| gap.member.is_none())
                        .count();
                    let members = header.unresolved.len() - declarations;
                    writeln!(
                        out,
                        "// {declarations} declaration(s) and {members} member(s) unresolved; inspect --format json for the ledger."
                    )?;
                }
            }
        }
        OutputFormat::Text => {
            print_swift_text(&report, args.selection_is_filtered(), output.style(), out)
        }
        OutputFormat::Sarif => unreachable!("rejected above"),
    }
    Ok(())
}

impl SwiftArgs {
    /// Whether the caller narrowed the selection.
    ///
    /// Answered from the arguments rather than inferred by comparing a selected
    /// count against a total, which cannot tell "no filter" apart from "a filter
    /// that retained everything".
    fn selection_is_filtered(&self) -> bool {
        !self.kinds.is_empty() || !self.states.is_empty() || self.name.is_some()
    }
}

impl SwiftTypeKindArg {
    fn matches(self, kind: SwiftTypeKind) -> bool {
        matches!(
            (self, kind),
            (Self::Class, SwiftTypeKind::Class)
                | (Self::Struct, SwiftTypeKind::Struct)
                | (Self::Enum, SwiftTypeKind::Enum)
                | (Self::Protocol, SwiftTypeKind::Protocol)
                | (Self::TypeAlias, SwiftTypeKind::TypeAlias)
                | (Self::Opaque, SwiftTypeKind::Opaque)
                | (Self::Unknown, SwiftTypeKind::Unknown)
        )
    }
}

impl SwiftEntityStateArg {
    fn matches(self, state: SwiftEntityState) -> bool {
        matches!(
            (self, state),
            (Self::MetadataDefined, SwiftEntityState::MetadataDefined)
                | (Self::Referenced, SwiftEntityState::Referenced)
                | (Self::SymbolOnly, SwiftEntityState::SymbolOnly)
                | (Self::Partial, SwiftEntityState::Partial)
                | (Self::Unknown, SwiftEntityState::Unknown)
        )
    }
}

fn apply_filter(
    report: &mut SwiftReport,
    kinds: &[SwiftTypeKindArg],
    states: &[SwiftEntityStateArg],
    name: Option<&str>,
    exact: bool,
) {
    for slice in report.slices.as_mut_slice() {
        let entities = &slice.entities;
        slice.selection.selected_entity_ids.retain(|id| {
            entities
                .iter()
                .find(|entity| entity.id == *id)
                .is_some_and(|entity| {
                    (kinds.is_empty() || kinds.iter().any(|kind| kind.matches(entity_kind(entity))))
                        && (states.is_empty()
                            || states.iter().any(|state| state.matches(entity.state)))
                        && name.is_none_or(|query| entity_matches_name(entity, query, exact))
                })
        });
    }
}

fn entity_matches_name(entity: &SwiftEntity, query: &str, exact: bool) -> bool {
    let matches = |candidate: &str| {
        if exact {
            candidate == query
        } else {
            candidate.contains(query)
        }
    };
    known_swift(&entity.qualified_name).is_some_and(|name| matches(&name.path.as_slice().join(".")))
        || entity.raw_linkages.iter().any(|name| matches(name))
}

fn known_swift<T>(value: &SwiftValue<T>) -> Option<&T> {
    match value {
        SwiftValue::Known { value, .. } => Some(value),
        SwiftValue::Conflicted { .. } | SwiftValue::Unavailable { .. } => None,
    }
}

fn print_swift_text(
    report: &SwiftReport,
    selection_is_filtered: bool,
    style: Style,
    out: &mut dyn Write,
) {
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
                .iter()
                .map(|entity| {
                    vec![
                        style.enum_value_cell(kind_name(entity_kind(entity))),
                        style.accent_cell(&entity_name(entity)),
                        entity_address(entity)
                            .map(|address| style.address_cell(&format!("0x{address:016x}")))
                            .unwrap_or_else(|| style.muted_cell("-")),
                        style.property_cell(
                            "fields",
                            &entity_field_summary(&entity.fields_or_cases),
                        ),
                        style.property_cell("gaps", &entity.gaps.len().to_string()),
                    ]
                })
                .collect::<Vec<_>>();
            for (entity, row) in entities.into_iter().zip(layout::align(&rows, style)) {
                let _ = writeln!(out, "    {row}");
                print_swift_fields(entity, style, out);
            }
        }
        for diagnostic in &slice.diagnostics {
            // A diagnostic with no entity describes a record that never decoded
            // into one, so it belongs to the image rather than to any selection
            // and a filter cannot make it irrelevant.
            let diagnostic_is_selected = match &diagnostic.entity_id {
                None => true,
                Some(entity_id) => selected_ids.contains(entity_id.as_str()),
            };
            if selection_is_filtered && !diagnostic_is_selected {
                continue;
            }
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

fn entity_field_summary(fields: &SwiftValue<Vec<SwiftField>>) -> String {
    match fields {
        SwiftValue::Known { value, .. } => value.len().to_string(),
        SwiftValue::Conflicted { .. } => "conflicted".to_owned(),
        SwiftValue::Unavailable { reason } => {
            format!("unavailable:{}", unavailable_reason_name(*reason))
        }
    }
}

fn print_swift_fields(entity: &SwiftEntity, style: Style, out: &mut dyn Write) {
    let SwiftValue::Known { value: fields, .. } = &entity.fields_or_cases else {
        return;
    };
    let rows = fields
        .iter()
        .map(|field| {
            let name = field.name.as_deref().unwrap_or("<unknown>");
            let type_name = match (field_type_text(field), field.type_name.is_some()) {
                (Some(value), true) => style.accent_cell(value),
                (Some(value), false) => {
                    layout::join_cells([style.muted_cell("mangled="), style.raw_bytes_cell(value)])
                }
                (None, _) => style.muted_cell("<type unavailable>"),
            };
            vec![
                style.enum_value_cell("field"),
                style.accent_cell(name),
                type_name,
            ]
        })
        .collect::<Vec<_>>();
    for row in layout::align(&rows, style) {
        let _ = writeln!(out, "      {row}");
    }
}

fn field_type_text(field: &SwiftField) -> Option<&str> {
    field
        .type_name
        .as_deref()
        .or_else(|| field.mangled_type.as_ref().map(|value| value.as_str()))
}

fn unavailable_reason_name(reason: SwiftUnavailableReason) -> &'static str {
    match reason {
        SwiftUnavailableReason::NotEncoded => "not-encoded",
        SwiftUnavailableReason::MalformedDescriptor => "malformed-descriptor",
        SwiftUnavailableReason::UnsupportedDescriptor => "unsupported-descriptor",
        SwiftUnavailableReason::UnsupportedMangling => "unsupported-mangling",
        SwiftUnavailableReason::UnresolvedReference => "unresolved-reference",
        SwiftUnavailableReason::AmbiguousIdentity => "ambiguous-identity",
        SwiftUnavailableReason::CollectorFailed => "collector-failed",
        SwiftUnavailableReason::Truncated => "truncated",
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
    use macho::analysis::report::{HexBytes, NonEmpty, SwiftEvidenceId};

    #[test]
    fn kind_filter_is_closed() {
        assert!(SwiftTypeKindArg::Class.matches(SwiftTypeKind::Class));
        assert!(!SwiftTypeKindArg::Class.matches(SwiftTypeKind::Protocol));
        assert!(SwiftEntityStateArg::SymbolOnly.matches(SwiftEntityState::SymbolOnly));
    }

    #[test]
    fn field_summary_distinguishes_empty_from_unavailable() {
        let evidence = NonEmpty::new(vec![
            SwiftEvidenceId::new("0".repeat(64)).expect("valid evidence ID"),
        ])
        .expect("one evidence ID");
        assert_eq!(
            entity_field_summary(&SwiftValue::Known {
                value: Vec::new(),
                evidence,
            }),
            "0"
        );
        assert_eq!(
            entity_field_summary(&SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            }),
            "unavailable:not-encoded"
        );
    }

    #[test]
    fn field_rows_prefer_resolved_types_and_preserve_raw_manglings() {
        let resolved = SwiftField {
            name: Some("store".to_owned()),
            mangled_type: Some(HexBytes::from_bytes(b"ignored")),
            type_name: Some("Passwords.Store".to_owned()),
            flags: 0,
        };
        let raw = SwiftField {
            name: Some("body".to_owned()),
            mangled_type: Some(HexBytes::from_bytes(b"raw")),
            type_name: None,
            flags: 0,
        };
        assert_eq!(field_type_text(&resolved), Some("Passwords.Store"));
        assert_eq!(field_type_text(&raw), Some("726177"));
    }
}
