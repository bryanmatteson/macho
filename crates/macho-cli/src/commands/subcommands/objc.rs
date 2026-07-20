use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

mod filters;
mod model;

use filters::*;
use model::*;

use anyhow::{Context, Result};
use macho::analysis::report::{
    ObjCEntity, ObjCEntityId, ObjCGraphEdge, ObjCMethod, ObjCMethodKind, ObjCPresence, ObjCReport,
    ObjCSliceReport, project_objc_headers, recover_objc_container,
};
use macho::core::model::symbol::{SymbolTable, SymbolType};
use serde::Serialize;

use crate::commands::args::{ArchitectureArgs, InputArgs, OptionalInputArgs};
use crate::commands::output::{Options as OutputOptions, Style, columns};
use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, usage_message};

#[derive(clap::Args)]
#[command(
    after_help = "Examples:\n  macho objc app --kind class --presence defined\n  macho objc app --name Controller --selector viewDidLoad\n  macho objc graph app --kind protocol\n  macho objc xrefs app --class AppDelegate"
)]
/// Evidence-accountable Objective-C runtime recovery.
pub struct ObjCArgs {
    #[command(subcommand)]
    action: Option<ObjCAction>,
    #[command(flatten)]
    input: OptionalInputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    filters: ObjCFilterArgs,
    /// Render the validated typed header projection.
    #[arg(long)]
    headers: bool,
}

#[derive(clap::Subcommand)]
enum ObjCAction {
    /// Show the canonical entity graph and category-folding state.
    Graph {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
        #[command(flatten)]
        filters: ObjCFilterArgs,
    },
    /// Show selector ownership, origins, implementations, and ambiguity.
    Selectors {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
        /// Select an exact selector spelling.
        #[arg(long)]
        name: Option<String>,
    },
    /// Join method implementations to symbols only by exact virtual address.
    Xrefs {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
        #[command(flatten)]
        filters: ObjCFilterArgs,
    },
}

/// Runs Objective-C recovery.
pub fn run(args: ObjCArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    if output.format() == OutputFormat::Sarif {
        return Err(usage_message(
            "Objective-C recovery supports only text and JSON",
        ));
    }
    match args.action {
        Some(ObjCAction::Graph {
            input,
            selection,
            filters,
        }) => run_graph(&input, &selection, &filters, output, out),
        Some(ObjCAction::Selectors {
            input,
            selection,
            name,
        }) => run_selectors(&input, &selection, name.as_deref(), output, out),
        Some(ObjCAction::Xrefs {
            input,
            selection,
            filters,
        }) => run_xrefs(&input, &selection, &filters, output, out),
        None => {
            let path = args
                .input
                .path
                .ok_or_else(|| usage_message("path is required"))?;
            let input = InputArgs { path };
            run_surface(
                &input,
                &args.selection,
                args.headers,
                &args.filters,
                output,
                out,
            )
        }
    }
}

fn recover(input: &InputArgs, selection: &ArchitectureArgs) -> Result<(memmap2::Mmap, ObjCReport)> {
    let mmap = map_input(&input.path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", input.path.display()))?;
    let report = recover_objc_container(&container, selection.arch.as_deref())?;
    drop(container);
    Ok((mmap, report))
}

fn run_surface(
    input: &InputArgs,
    selection: &ArchitectureArgs,
    headers: bool,
    filters: &ObjCFilterArgs,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    let (_mmap, mut report) = recover(input, selection)?;
    apply_filters(&mut report, filters);
    if headers {
        if report.slices.as_slice().len() > 1 && selection.arch.is_none() {
            return Err(usage_message(
                "fat Objective-C header output requires --arch",
            ));
        }
        project_objc_headers(&mut report)?;
    }
    match output.format() {
        OutputFormat::Json => crate::commands::output::json::write_pretty(out, &report)?,
        OutputFormat::Text if headers => {
            for slice in report.slices.as_slice() {
                let header = slice
                    .header
                    .as_ref()
                    .expect("header projection requested for every selected slice");
                out.write_all(header.source.as_bytes())?;
                if !header.unresolved.is_empty() {
                    writeln!(
                        out,
                        "/* {} declaration(s) omitted; inspect --format json for the unresolved ledger. */",
                        header.unresolved.len()
                    )?;
                }
            }
        }
        OutputFormat::Text => print_surface(&report, output.style(), out),
        OutputFormat::Sarif => unreachable!("rejected above"),
    }
    Ok(())
}

fn print_surface(report: &ObjCReport, style: Style, out: &mut dyn Write) {
    let _ = writeln!(out, "{}", style.title("Objective-C runtime recovery"));
    for slice in report.slices.as_slice() {
        let selected = slice
            .selection
            .selected_entity_ids
            .iter()
            .map(|id| id.as_str())
            .collect::<BTreeSet<_>>();
        let totals = &slice.selection.totals;
        let _ = writeln!(
            out,
            "  {}  {}  {}  {}  {}  {}  {}",
            style.enum_property("arch", &architecture_name(slice)),
            style.property("defined", &totals.defined_entities.to_string()),
            style.property("referenced", &totals.referenced_entities.to_string()),
            style.property("partial", &totals.partial_entities.to_string()),
            style.property("malformed", &totals.malformed_observations.to_string()),
            style.property("excluded", &totals.excluded_observations.to_string()),
            style.property("selected", &selected.len().to_string()),
        );
        for presence in [
            ObjCPresence::Defined,
            ObjCPresence::Referenced,
            ObjCPresence::Partial,
        ] {
            let entities = slice
                .entities
                .iter()
                .filter(|entity| entity.common().presence == presence)
                .filter(|entity| selected.contains(entity.common().id.as_str()))
                .collect::<Vec<_>>();
            if entities.is_empty() {
                continue;
            }
            let _ = writeln!(out, "  {}", style.heading(presence_heading(presence)));
            let rows = entities
                .iter()
                .map(|entity| entity_row(entity, style))
                .collect::<Vec<_>>();
            for row in columns::align(&rows) {
                let _ = writeln!(out, "    {row}");
            }
            for entity in entities {
                print_members(entity, style, out);
            }
        }
        if selected.is_empty() {
            let _ = writeln!(
                out,
                "  {}",
                style.muted("No entities matched the selection.")
            );
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

fn entity_row(entity: &ObjCEntity, style: Style) -> Vec<String> {
    let common = entity.common();
    let name = known(&common.name)
        .map(|name| macho::symbols::demangle::demangle_swift_symbol(name).unwrap_or(name.clone()))
        .unwrap_or_else(|| "<unknown>".to_owned());
    let (kind, members, detail) = match entity {
        ObjCEntity::Class(value) => (
            "class",
            value.ivars.len()
                + value.properties.len()
                + value.instance_methods.len()
                + value.class_methods.len(),
            known(&value.superclass)
                .and_then(Option::as_ref)
                .map(|value| format!("super={}", value.name))
                .unwrap_or_else(|| "super=-".to_owned()),
        ),
        ObjCEntity::Category(value) => (
            "category",
            value.properties.len() + value.instance_methods.len() + value.class_methods.len(),
            known(&value.extended_class)
                .map(|value| format!("extends={}", value.name))
                .unwrap_or_else(|| "extends=?".to_owned()),
        ),
        ObjCEntity::Protocol(value) => (
            "protocol",
            value.properties.len()
                + value.required_instance_methods.len()
                + value.required_class_methods.len()
                + value.optional_instance_methods.len()
                + value.optional_class_methods.len(),
            format!("adopts={}", value.adopted_protocols.len()),
        ),
    };
    vec![
        style.enum_value(kind),
        style.accent(&name),
        style.enum_property("presence", presence_name(common.presence)),
        style.property("members", &members.to_string()),
        detail
            .split_once('=')
            .map(|(key, value)| style.property(key, value))
            .unwrap_or_else(|| style.muted(&detail)),
        style.muted(&format!("id={}", &common.id.as_str()[..12])),
    ]
}

fn print_members(entity: &ObjCEntity, style: Style, out: &mut dyn Write) {
    let mut rows = Vec::new();
    match entity {
        ObjCEntity::Class(value) => {
            rows.extend(value.ivars.iter().map(|ivar| {
                vec![
                    style.enum_value("ivar"),
                    style.accent(known(&ivar.name).map_or("<unknown>", String::as_str)),
                    style.property("offset", &value_u64(&ivar.offset)),
                    style.enum_property("type", value_state(&ivar.parsed_type)),
                ]
            }));
            rows.extend(
                value
                    .properties
                    .iter()
                    .map(|value| property_row(value, style)),
            );
            rows.extend(
                value
                    .instance_methods
                    .iter()
                    .map(|value| method_row(value, style)),
            );
            rows.extend(
                value
                    .class_methods
                    .iter()
                    .map(|value| method_row(value, style)),
            );
        }
        ObjCEntity::Category(value) => {
            rows.extend(
                value
                    .properties
                    .iter()
                    .map(|value| property_row(value, style)),
            );
            rows.extend(
                value
                    .instance_methods
                    .iter()
                    .map(|value| method_row(value, style)),
            );
            rows.extend(
                value
                    .class_methods
                    .iter()
                    .map(|value| method_row(value, style)),
            );
        }
        ObjCEntity::Protocol(value) => {
            rows.extend(
                value
                    .properties
                    .iter()
                    .map(|value| property_row(value, style)),
            );
            rows.extend(
                value
                    .required_instance_methods
                    .iter()
                    .chain(&value.required_class_methods)
                    .map(|value| method_row(value, style)),
            );
            rows.extend(
                value
                    .optional_instance_methods
                    .iter()
                    .chain(&value.optional_class_methods)
                    .map(|value| method_row(value, style)),
            );
        }
    }
    for row in columns::align(&rows) {
        let _ = writeln!(out, "      {row}");
    }
}

fn method_row(value: &ObjCMethod, style: Style) -> Vec<String> {
    let selector = known(&value.selector)
        .map(|value| value.spelling.as_str())
        .unwrap_or("<unknown>");
    let implementation = known(&value.implementation)
        .and_then(Option::as_ref)
        .map(|value| format!("0x{:016x}", value.virtual_address))
        .unwrap_or_else(|| "-".to_owned());
    vec![
        style.enum_value(match value.kind {
            ObjCMethodKind::Instance => "method -",
            ObjCMethodKind::Class => "method +",
        }),
        style.accent(selector),
        style.enum_property("signature", value_state(&value.signature)),
        style.property("imp", &implementation),
    ]
}

fn property_row(value: &macho::analysis::report::ObjCProperty, style: Style) -> Vec<String> {
    vec![
        style.enum_value("property"),
        style.accent(known(&value.name).map_or("<unknown>", String::as_str)),
        style.enum_property("attributes", value_state(&value.parsed_attributes)),
    ]
}

fn run_graph(
    input: &InputArgs,
    selection: &ArchitectureArgs,
    filters: &ObjCFilterArgs,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    let (_mmap, mut report) = recover(input, selection)?;
    apply_filters(&mut report, filters);
    let views = report
        .slices
        .as_slice()
        .iter()
        .map(graph_view)
        .collect::<Vec<_>>();
    if output.format() == OutputFormat::Json {
        return crate::commands::output::json::write_pretty(out, &views).map_err(Into::into);
    }
    for view in views {
        writeln!(
            out,
            "{}",
            output.style().title(&format!("ObjC graph — {}", view.arch))
        )?;
        writeln!(
            out,
            "  {}  {}  {}  {}",
            output
                .style()
                .property("nodes", &view.nodes.len().to_string()),
            output
                .style()
                .property("inheritance", &view.inheritance.len().to_string()),
            output
                .style()
                .property("conformances", &view.conformances.len().to_string()),
            output
                .style()
                .property("categories", &view.categories.len().to_string()),
        )?;
        for node in &view.nodes {
            writeln!(
                out,
                "  {}  {}  {}",
                output.style().enum_value(node.kind),
                output.style().accent(&node.name),
                output
                    .style()
                    .enum_property("presence", presence_name(node.presence)),
            )?;
        }
        for edge in view
            .inheritance
            .iter()
            .chain(&view.conformances)
            .chain(&view.categories)
        {
            writeln!(
                out,
                "    {}  {} -> {}",
                output
                    .style()
                    .enum_value(&format!("{:?}", edge.kind).to_lowercase()),
                &edge.from.as_str()[..12],
                &edge.to.as_str()[..12],
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct GraphView<'a> {
    arch: String,
    nodes: Vec<GraphNodeView>,
    inheritance: Vec<&'a ObjCGraphEdge>,
    conformances: Vec<&'a ObjCGraphEdge>,
    categories: Vec<&'a ObjCGraphEdge>,
    selector_owners: Vec<&'a macho::analysis::report::ObjCSelectorOwner>,
}

#[derive(Serialize)]
struct GraphNodeView {
    entity_id: ObjCEntityId,
    kind: &'static str,
    name: String,
    presence: ObjCPresence,
}

fn graph_view(slice: &ObjCSliceReport) -> GraphView<'_> {
    let selected = slice
        .selection
        .selected_entity_ids
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let incident = slice
        .graph
        .inheritance
        .iter()
        .chain(&slice.graph.conformances)
        .chain(&slice.graph.categories)
        .filter(|edge| selected.contains(edge.from.as_str()) || selected.contains(edge.to.as_str()))
        .flat_map(|edge| [edge.from.as_str(), edge.to.as_str()])
        .collect::<BTreeSet<_>>();
    let nodes = slice
        .entities
        .iter()
        .filter(|entity| {
            selected.contains(entity.common().id.as_str())
                || incident.contains(entity.common().id.as_str())
        })
        .map(|entity| GraphNodeView {
            entity_id: entity.common().id.clone(),
            kind: entity_kind(entity),
            name: known(&entity.common().name)
                .cloned()
                .unwrap_or_else(|| "<unknown>".to_owned()),
            presence: entity.common().presence,
        })
        .collect();
    let edge_selected = |edge: &&ObjCGraphEdge| {
        selected.contains(edge.from.as_str()) || selected.contains(edge.to.as_str())
    };
    GraphView {
        arch: architecture_name(slice),
        nodes,
        inheritance: slice
            .graph
            .inheritance
            .iter()
            .filter(edge_selected)
            .collect(),
        conformances: slice
            .graph
            .conformances
            .iter()
            .filter(edge_selected)
            .collect(),
        categories: slice
            .graph
            .categories
            .iter()
            .filter(edge_selected)
            .collect(),
        selector_owners: slice
            .graph
            .selector_owners
            .iter()
            .filter(|owner| {
                owner
                    .effective_owner
                    .as_ref()
                    .is_some_and(|id| selected.contains(id.as_str()))
                    || owner.candidates.iter().any(|candidate| {
                        find_method(slice, candidate)
                            .is_some_and(|method| selected.contains(method.origin.as_str()))
                    })
            })
            .collect(),
    }
}

fn run_selectors(
    input: &InputArgs,
    selection: &ArchitectureArgs,
    name: Option<&str>,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    let (_mmap, report) = recover(input, selection)?;
    let views = selector_views(&report, name);
    if output.format() == OutputFormat::Json {
        return crate::commands::output::json::write_pretty(out, &views).map_err(Into::into);
    }
    let rows = views
        .iter()
        .map(|view| {
            vec![
                output.style().enum_value(&view.method_kind),
                output.style().accent(&view.selector),
                output.style().property(
                    "owner",
                    view.effective_owner.as_deref().unwrap_or("ambiguous"),
                ),
                output
                    .style()
                    .property("candidates", &view.candidates.len().to_string()),
                output.style().enum_property("arch", &view.arch),
            ]
        })
        .collect::<Vec<_>>();
    for row in columns::align(&rows) {
        writeln!(out, "  {row}")?;
    }
    for view in &views {
        if view.candidates.len() < 2 {
            continue;
        }
        for candidate in &view.candidates {
            writeln!(
                out,
                "    {}  {}  {}",
                output.style().enum_value("candidate"),
                output.style().accent(&candidate.origin),
                candidate
                    .implementation
                    .map(|address| output.style().address(&format!("0x{address:016x}")))
                    .unwrap_or_else(|| output.style().muted("-")),
            )?;
        }
    }
    Ok(())
}

#[derive(Serialize)]
struct SelectorView {
    arch: String,
    selector: String,
    method_kind: String,
    effective_owner_id: Option<ObjCEntityId>,
    effective_owner: Option<String>,
    candidates: Vec<SelectorCandidate>,
}

#[derive(Serialize)]
struct SelectorCandidate {
    member_id: String,
    origin_id: ObjCEntityId,
    origin: String,
    implementation: Option<u64>,
}

fn selector_views(report: &ObjCReport, name: Option<&str>) -> Vec<SelectorView> {
    let mut result = Vec::new();
    for slice in report.slices.as_slice() {
        for owner in &slice.graph.selector_owners {
            if name.is_some_and(|name| name != owner.selector.spelling) {
                continue;
            }
            result.push(SelectorView {
                arch: architecture_name(slice),
                selector: owner.selector.spelling.clone(),
                method_kind: method_kind_name(owner.method_kind).to_owned(),
                effective_owner_id: owner.effective_owner.clone(),
                effective_owner: owner
                    .effective_owner
                    .as_ref()
                    .and_then(|id| entity_name_by_id(slice, id)),
                candidates: owner
                    .candidates
                    .iter()
                    .filter_map(|id| find_method(slice, id))
                    .map(|method| SelectorCandidate {
                        member_id: method.id.to_string(),
                        origin_id: method.origin.clone(),
                        origin: entity_name_by_id(slice, &method.origin)
                            .unwrap_or_else(|| "<unknown>".to_owned()),
                        implementation: known(&method.implementation)
                            .and_then(Option::as_ref)
                            .map(|value| value.virtual_address),
                    })
                    .collect(),
            });
        }
    }
    result
}

fn run_xrefs(
    input: &InputArgs,
    selection: &ArchitectureArgs,
    filters: &ObjCFilterArgs,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(&input.path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", input.path.display()))?;
    let mut report = recover_objc_container(&container, selection.arch.as_deref())?;
    apply_filters(&mut report, filters);
    let machos = container
        .macho_files()
        .filter(|macho| {
            selection
                .arch
                .as_deref()
                .is_none_or(|arch| arch == macho.header().cpu_type().name())
        })
        .collect::<Vec<_>>();
    let mut views = Vec::new();
    for (slice, macho) in report.slices.as_slice().iter().zip(machos) {
        views.extend(xref_views(slice, macho));
    }
    if output.format() == OutputFormat::Json {
        return crate::commands::output::json::write_pretty(out, &views).map_err(Into::into);
    }
    let rows = views
        .iter()
        .map(|view| {
            vec![
                output.style().enum_value(&view.status),
                output.style().enum_value(&view.method_kind),
                output
                    .style()
                    .accent(&format!("[{} {}]", view.origin, view.selector)),
                output
                    .style()
                    .address(&format!("0x{:016x}", view.implementation)),
                output.style().property("symbols", &view.symbols.join(",")),
                output
                    .style()
                    .property("callers", &view.references.len().to_string()),
            ]
        })
        .collect::<Vec<_>>();
    for row in columns::align(&rows) {
        writeln!(out, "  {row}")?;
    }
    Ok(())
}

#[derive(Serialize)]
struct XrefView {
    arch: String,
    member_id: String,
    origin_id: ObjCEntityId,
    origin: String,
    selector: String,
    method_kind: String,
    implementation: u64,
    status: String,
    symbols: Vec<String>,
    references: Vec<macho::analysis::xref::Xref>,
}

fn xref_views(
    slice: &ObjCSliceReport,
    macho: &macho::core::model::macho_file::MachoFile<'_>,
) -> Vec<XrefView> {
    let selected = slice
        .selection
        .selected_entity_ids
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut symbols = BTreeMap::<u64, Vec<String>>::new();
    if let Ok(table) = macho.ext::<SymbolTable<'_>>() {
        for symbol in table.symbols() {
            if symbol.sym_type == SymbolType::Section && symbol.value != 0 {
                symbols
                    .entry(symbol.value)
                    .or_default()
                    .push(symbol.name.to_owned());
            }
        }
    }
    let xrefs = macho::analysis::xref::XrefIndex::build(macho).ok();
    let mut result = Vec::new();
    for entity in &slice.entities {
        if !selected.contains(entity.common().id.as_str()) {
            continue;
        }
        for method in entity_methods(entity) {
            let Some(implementation) = known(&method.implementation).and_then(Option::as_ref)
            else {
                continue;
            };
            let names = symbols
                .get(&implementation.virtual_address)
                .cloned()
                .unwrap_or_default();
            let status = match names.len() {
                0 => "unresolved",
                1 => "resolved",
                _ => "ambiguous",
            };
            result.push(XrefView {
                arch: architecture_name(slice),
                member_id: method.id.to_string(),
                origin_id: method.origin.clone(),
                origin: entity_name_by_id(slice, &method.origin)
                    .unwrap_or_else(|| "<unknown>".to_owned()),
                selector: known(&method.selector)
                    .map(|value| value.spelling.clone())
                    .unwrap_or_else(|| "<unknown>".to_owned()),
                method_kind: method_kind_name(method.kind).to_owned(),
                implementation: implementation.virtual_address,
                status: status.to_owned(),
                symbols: names,
                references: xrefs
                    .as_ref()
                    .map(|index| {
                        index
                            .refs_to(macho::core::model::addr::Va(implementation.virtual_address))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
    }
    result
}
