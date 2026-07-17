use anyhow::{Context, Result};
use macho::analysis::reconstruct::objc::graph::{MethodKind, ObjCGraph};
use macho::analysis::reconstruct::objc::{ObjcReconstructionPlan, reconstruct};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

use crate::analysis::{AnalysisDomain, AnalysisLimits};
use crate::commands::args::{ArchitectureArgs, InputArgs, OptionalInputArgs};
use crate::commands::subcommands::common::{analyze_selected_domain, write_selected_json};
use crate::commands::subcommands::common::{for_each_selected_mach, map_input};
use crate::commands::{OutputFormat, usage_message};

#[derive(clap::Args)]
/// The ObjCArgs type.
pub struct ObjCArgs {
    #[command(subcommand)]
    action: Option<ObjCAction>,

    #[command(flatten)]
    input: OptionalInputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,

    /// Show full class-dump-style headers
    #[arg(long)]
    headers: bool,

    /// Filter to a specific class name
    #[arg(long)]
    class: Option<String>,
}

#[derive(clap::Subcommand)]
enum ObjCAction {
    /// Show ObjC class/category/protocol graph with category folding
    Graph {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
        /// Show only a specific class
        #[arg(long)]
        class: Option<String>,
    },
    /// Look up selector ownership across all classes
    Selectors {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
        /// Filter to a specific selector name
        #[arg(long)]
        name: Option<String>,
    },
    /// Show cross-references between ObjC methods and symbols
    Xrefs {
        #[command(flatten)]
        input: InputArgs,
        #[command(flatten)]
        selection: ArchitectureArgs,
        /// Filter to a specific class
        #[arg(long)]
        class: Option<String>,
    },
}

/// Performs run.
pub fn run(args: ObjCArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let json = format == OutputFormat::Json;
    match args.action {
        Some(ObjCAction::Graph {
            input,
            selection,
            class,
        }) => run_graph(
            &input.path,
            selection.arch.as_deref(),
            json,
            class.as_deref(),
            out,
        ),
        Some(ObjCAction::Selectors {
            input,
            selection,
            name,
        }) => run_selectors(
            &input.path,
            selection.arch.as_deref(),
            name.as_deref(),
            json,
            out,
        ),
        Some(ObjCAction::Xrefs {
            input,
            selection,
            class,
        }) => run_xrefs(
            &input.path,
            selection.arch.as_deref(),
            class.as_deref(),
            json,
            out,
        ),
        None => {
            let path = args
                .input
                .path
                .ok_or_else(|| usage_message("path is required"))?;
            run_list(
                &path,
                &args.selection.arch,
                args.headers,
                args.class.as_deref(),
                format,
                out,
            )
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ObjCXref {
    class_name: String,
    selector: String,
    kind: MethodKind,
    origin: macho::analysis::reconstruct::objc::graph::MethodOrigin,
    imp: u64,
    imp_symbol: String,
}

fn has_objc_graph_data(graph: &ObjCGraph) -> bool {
    !(graph.classes.is_empty() && graph.protocols.is_empty() && graph.selectors.is_empty())
}

fn run_list(
    path: &Path,
    arch_filter: &Option<String>,
    headers: bool,
    class_filter: Option<&str>,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if format == OutputFormat::Json {
        let domain = if headers {
            AnalysisDomain::ObjcHeaders
        } else {
            AnalysisDomain::Objc
        };
        let mut values = analyze_selected_domain(
            &container,
            arch_filter.as_deref(),
            domain,
            AnalysisLimits::default(),
            true,
        )?;
        if let Some(class_name) = class_filter
            && !headers
        {
            for (_, value) in &mut values {
                if let Some(object) = value.as_object_mut()
                    && let Some(classes) = object
                        .get_mut("classes")
                        .and_then(serde_json::Value::as_array_mut)
                {
                    classes.retain(|class| {
                        class.get("name").and_then(serde_json::Value::as_str) == Some(class_name)
                    });
                }
            }
        }
        return write_selected_json(values, out);
    }

    for_each_selected_mach(
        &container,
        arch_filter.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                let _ = writeln!(out, "=== {arch_name} ===");
            }
            if headers {
                print_objc_headers(macho, class_filter, out);
            } else {
                print_objc_summary(macho, class_filter, out);
            }
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn run_graph(
    path: &Path,
    arch: Option<&str>,
    json: bool,
    class: Option<&str>,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |macho, arch_name, _| {
            let graph = match macho.ext::<ObjCGraph>() {
                Ok(graph) => graph,
                Err(_) => {
                    result.insert(arch_name.to_string(), serde_json::Value::Null);
                    return Ok(());
                }
            };
            if !has_objc_graph_data(&graph) {
                result.insert(arch_name.to_string(), serde_json::Value::Null);
                return Ok(());
            }
            let val = if let Some(cls) = class {
                graph
                    .class(cls)
                    .map(serde_json::to_value)
                    .transpose()?
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::to_value(graph)?
            };
            result.insert(arch_name.to_string(), val);
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&val)?);
        } else {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(&container, arch, |macho, arch_name, show_header| {
            if show_header {
                let _ = writeln!(out, "=== {arch_name} ===");
            }
            let graph = match macho.ext::<ObjCGraph>() {
                Ok(graph) => graph,
                Err(e) => {
                    let _ = writeln!(out, "[{arch_name}] No ObjC metadata: {e}");
                    if show_header {
                        let _ = writeln!(out,);
                    }
                    return Ok(());
                }
            };
            if !has_objc_graph_data(&graph) {
                let _ = writeln!(out, "[{arch_name}] No ObjC metadata found.");
                if show_header {
                    let _ = writeln!(out,);
                }
                return Ok(());
            }

            if let Some(cls) = class {
                if let Some(node) = graph.class(cls) {
                    print_class_node(node, &graph, out);
                } else {
                    let _ = writeln!(out, "Class {cls} not found");
                }
            } else {
                let _ = writeln!(
                    out,
                    "[{arch_name}] ObjC graph: {} classes, {} protocols, {} selectors",
                    graph.classes.len(),
                    graph.protocols.len(),
                    graph.selectors.len()
                );
                for node in graph.classes.values() {
                    let cats = if node.categories.is_empty() {
                        String::new()
                    } else {
                        format!(" +{} categories", node.categories.len())
                    };
                    let _ = writeln!(
                        out,
                        "  {} : {} ({} methods{cats})",
                        node.name,
                        node.superclass.as_deref().unwrap_or("?"),
                        node.effective_instance_methods.len() + node.effective_class_methods.len(),
                    );
                }
            }
            if show_header {
                let _ = writeln!(out,);
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn print_class_node(
    node: &macho::analysis::reconstruct::objc::graph::ClassNode,
    graph: &ObjCGraph,
    out: &mut dyn Write,
) {
    let super_str = node.superclass.as_deref().unwrap_or("(root)");
    let swift_tag = if node.is_swift { " [swift]" } else { "" };
    let _ = writeln!(out, "{}{swift_tag} : {super_str}", node.name);

    let chain = graph.superclass_chain(&node.name);
    if !chain.is_empty() {
        let _ = writeln!(out, "  hierarchy: {} -> {}", node.name, chain.join(" -> "));
    }

    if !node.categories.is_empty() {
        let _ = writeln!(out, "  categories: {}", node.categories.join(", "));
    }
    if !node.protocols.is_empty() {
        let _ = writeln!(out, "  protocols: {}", node.protocols.join(", "));
    }

    let _ = writeln!(
        out,
        "  instance methods ({}):",
        node.effective_instance_methods.len()
    );
    for m in &node.effective_instance_methods {
        let origin = match &m.origin {
            macho::analysis::reconstruct::objc::graph::MethodOrigin::Class => String::new(),
            macho::analysis::reconstruct::objc::graph::MethodOrigin::Category(cat) => {
                format!(" [from {cat}]")
            }
            _ => " [from unknown source]".to_owned(),
        };
        let _ = writeln!(out, "    -{} {:#x}{origin}", m.selector, m.imp);
    }

    if !node.effective_class_methods.is_empty() {
        let _ = writeln!(
            out,
            "  class methods ({}):",
            node.effective_class_methods.len()
        );
        for m in &node.effective_class_methods {
            let origin = match &m.origin {
                macho::analysis::reconstruct::objc::graph::MethodOrigin::Class => String::new(),
                macho::analysis::reconstruct::objc::graph::MethodOrigin::Category(cat) => {
                    format!(" [from {cat}]")
                }
                _ => " [from unknown source]".to_owned(),
            };
            let _ = writeln!(out, "    +{} {:#x}{origin}", m.selector, m.imp);
        }
    }
}

fn run_selectors(
    path: &Path,
    arch: Option<&str>,
    name: Option<&str>,
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |macho, arch_name, _| {
            let graph = match macho.ext::<ObjCGraph>() {
                Ok(graph) => graph,
                Err(_) => {
                    result.insert(arch_name.to_string(), serde_json::Value::Null);
                    return Ok(());
                }
            };
            if !has_objc_graph_data(&graph) {
                result.insert(arch_name.to_string(), serde_json::Value::Null);
                return Ok(());
            }

            let value = if let Some(sel_name) = name {
                serde_json::json!({
                    "selector": sel_name,
                    "owners": graph.implementations_of(sel_name, MethodKind::Instance)
                        .into_iter()
                        .chain(graph.implementations_of(sel_name, MethodKind::Class))
                        .collect::<Vec<_>>(),
                })
            } else {
                serde_json::to_value(&graph.selectors)?
            };
            result.insert(arch_name.to_string(), value);
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&val)?);
        } else {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(&container, arch, |macho, arch_name, show_header| {
        if show_header {
            let _ = writeln!(out, "=== {arch_name} ===");
        }
        let graph = match macho.ext::<ObjCGraph>() {
            Ok(graph) => graph,
            Err(e) => {
                let _ = writeln!(out, "[{arch_name}] No ObjC metadata: {e}");
                if show_header {
                    let _ = writeln!(out,);
                }
                return Ok(());
            }
        };
        if !has_objc_graph_data(&graph) {
            let _ = writeln!(out, "[{arch_name}] No ObjC metadata found.");
            if show_header {
                let _ = writeln!(out,);
            }
            return Ok(());
        }

        if let Some(sel_name) = name {
            let owners = graph.selector_owners(sel_name);
            if owners.is_empty() {
                let _ = writeln!(out, "[{arch_name}] selector '{sel_name}' not found");
            } else {
                let _ = writeln!(
                    out,
                    "[{arch_name}] selector '{sel_name}' ({} implementations):",
                    owners.len()
                );
                for owner in owners {
                    let origin = match &owner.origin {
                        macho::analysis::reconstruct::objc::graph::MethodOrigin::Class => {
                            String::new()
                        }
                        macho::analysis::reconstruct::objc::graph::MethodOrigin::Category(cat) => {
                            format!(" [from {cat}]")
                        }
                        _ => " [from unknown source]".to_owned(),
                    };
                    let _ = writeln!(
                        out,
                        "  {}[{} {sel_name}] {:#x}{origin}",
                        owner.kind.prefix(),
                        owner.class_name,
                        owner.imp
                    );
                }
            }
        } else {
            let _ = writeln!(
                out,
                "[{arch_name}] {} unique selectors",
                graph.selectors.len()
            );
            for (sel, owners) in &graph.selectors {
                let classes: Vec<&str> = owners
                    .iter()
                    .map(
                        |owner: &macho::analysis::reconstruct::objc::SelectorOwner| {
                            owner.class_name.as_str()
                        },
                    )
                    .collect();
                let _ = writeln!(out, "  {sel} -> {}", classes.join(", "));
            }
        }
        if show_header {
            let _ = writeln!(out,);
        }
        Ok(())
    })?;
    Ok(())
}

fn print_objc_headers(
    macho: &macho::core::model::macho_file::MachoFile<'_>,
    class_filter: Option<&str>,
    out: &mut dyn Write,
) {
    let report = match reconstruct(
        macho,
        &ObjcReconstructionPlan {
            class_filter: class_filter.map(str::to_owned),
        },
    ) {
        Ok(report) => report,
        Err(e) => {
            let _ = writeln!(out, "No ObjC metadata: {e}");
            return;
        }
    };
    if report.classes == 0 && report.categories == 0 && report.protocols == 0 {
        let _ = writeln!(out, "No ObjC classes, categories, or protocols found.");
        return;
    }
    let _ = write!(out, "{}", report.header);
}

fn print_objc_summary(
    macho: &macho::core::model::macho_file::MachoFile<'_>,
    class_filter: Option<&str>,
    out: &mut dyn Write,
) {
    let graph = match macho.ext::<ObjCGraph>() {
        Ok(graph) => graph,
        Err(e) => {
            let _ = writeln!(out, "No ObjC metadata: {e}");
            return;
        }
    };
    if !has_objc_graph_data(&graph) {
        let _ = writeln!(out, "No ObjC classes, categories, or protocols found.");
        return;
    }

    let classes: Vec<_> = graph
        .classes
        .values()
        .filter(|c| class_filter.is_none_or(|f| c.name == f))
        .collect();

    let _ = writeln!(out, "Classes ({}):", classes.len());
    for class in &classes {
        let super_str = class.superclass.as_deref().unwrap_or("?");
        let swift_str = if class.is_swift { " [swift]" } else { "" };
        let categories = if class.categories.is_empty() {
            String::new()
        } else {
            format!(" +{} categories", class.categories.len())
        };
        let _ = writeln!(
            out,
            "  {} : {} ({} effective methods, {} ivars, {} props){categories}{swift_str}",
            class.name,
            super_str,
            class.effective_instance_methods.len() + class.effective_class_methods.len(),
            class.ivars.len(),
            class.properties.len(),
        );
    }

    if class_filter.is_none() && !graph.protocols.is_empty() {
        let _ = writeln!(out, "\nProtocols ({}):", graph.protocols.len());
        for proto in graph.protocols.values() {
            let _ = writeln!(
                out,
                "  {} — {} methods, {} conforming classes",
                proto.name,
                proto.instance_methods.len()
                    + proto.class_methods.len()
                    + proto.optional_instance_methods.len()
                    + proto.optional_class_methods.len(),
                proto.conforming_classes.len(),
            );
        }
    }
}

fn run_xrefs(
    path: &Path,
    arch: Option<&str>,
    class: Option<&str>,
    json: bool,
    out: &mut dyn Write,
) -> Result<()> {
    let mmap = map_input(path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |macho, arch_name, _| {
            let graph = match macho.ext::<ObjCGraph>() {
                Ok(graph) => graph,
                Err(_) => {
                    result.insert(arch_name.to_string(), serde_json::Value::Null);
                    return Ok(());
                }
            };
            if !has_objc_graph_data(&graph) {
                result.insert(arch_name.to_string(), serde_json::Value::Null);
                return Ok(());
            }
            result.insert(
                arch_name.to_string(),
                serde_json::to_value(collect_xrefs(&graph, class))?,
            );
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&val)?);
        } else {
            let _ = writeln!(out, "{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(&container, arch, |macho, arch_name, show_header| {
        if show_header {
            let _ = writeln!(out, "=== {arch_name} ===");
        }
        let graph = match macho.ext::<ObjCGraph>() {
            Ok(graph) => graph,
            Err(e) => {
                let _ = writeln!(out, "[{arch_name}] No ObjC metadata: {e}");
                return Ok(());
            }
        };
        if !has_objc_graph_data(&graph) {
            let _ = writeln!(out, "[{arch_name}] No ObjC metadata found.");
            if show_header {
                let _ = writeln!(out,);
            }
            return Ok(());
        }
        let xrefs = collect_xrefs(&graph, class);
        for xref in &xrefs {
            let _ = writeln!(
                out,
                "  {}[{} {}] {:#x} -> {}",
                xref.kind.prefix(),
                xref.class_name,
                xref.selector,
                xref.imp,
                xref.imp_symbol
            );
        }
        let _ = writeln!(out, "({} cross-references)", xrefs.len());
        if show_header {
            let _ = writeln!(out,);
        }
        Ok(())
    })?;
    Ok(())
}

fn collect_xrefs(graph: &ObjCGraph, class: Option<&str>) -> Vec<ObjCXref> {
    let classes: Vec<_> = if let Some(cls) = class {
        graph.class(cls).into_iter().collect()
    } else {
        graph.classes.values().collect()
    };

    let mut xrefs = Vec::new();
    for node in &classes {
        for method in &node.effective_instance_methods {
            if let Some(sym) = &method.imp_symbol {
                xrefs.push(ObjCXref {
                    class_name: node.name.clone(),
                    selector: method.selector.clone(),
                    kind: MethodKind::Instance,
                    origin: method.origin.clone(),
                    imp: method.imp,
                    imp_symbol: sym.clone(),
                });
            }
        }
        for method in &node.effective_class_methods {
            if let Some(sym) = &method.imp_symbol {
                xrefs.push(ObjCXref {
                    class_name: node.name.clone(),
                    selector: method.selector.clone(),
                    kind: MethodKind::Class,
                    origin: method.origin.clone(),
                    imp: method.imp,
                    imp_symbol: sym.clone(),
                });
            }
        }
    }
    xrefs
}
