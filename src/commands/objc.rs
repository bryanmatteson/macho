use anyhow::{Context, Result};
use macho::inspect::ImageInspector;
use macho::objc::graph::{MethodKind, ObjCGraph};
use macho::objc::render;
use serde::Serialize;
use std::path::{Path, PathBuf};

use crate::commands::common::for_each_selected_mach;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(clap::Args)]
pub struct ObjCArgs {
    #[command(subcommand)]
    action: Option<ObjCAction>,

    /// Path to Mach-O binary
    path: Option<PathBuf>,

    #[arg(long)]
    arch: Option<String>,

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
        path: PathBuf,
        #[arg(long)]
        arch: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
        /// Show only a specific class
        #[arg(long)]
        class: Option<String>,
    },
    /// Look up selector ownership across all classes
    Selectors {
        path: PathBuf,
        #[arg(long)]
        arch: Option<String>,
        /// Filter to a specific selector name
        #[arg(long)]
        name: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show cross-references between ObjC methods and symbols
    Xrefs {
        path: PathBuf,
        #[arg(long)]
        arch: Option<String>,
        /// Filter to a specific class
        #[arg(long)]
        class: Option<String>,
        /// Output as JSON
        #[arg(long)]
        json: bool,
    },
}

pub fn run(args: ObjCArgs) -> Result<()> {
    match args.action {
        Some(ObjCAction::Graph {
            path,
            arch,
            json,
            class,
        }) => run_graph(&path, arch.as_deref(), json, class.as_deref()),
        Some(ObjCAction::Selectors {
            path,
            arch,
            name,
            json,
        }) => run_selectors(&path, arch.as_deref(), name.as_deref(), json),
        Some(ObjCAction::Xrefs {
            path,
            arch,
            class,
            json,
        }) => run_xrefs(&path, arch.as_deref(), class.as_deref(), json),
        None => {
            let path = args
                .path
                .ok_or_else(|| anyhow::anyhow!("path is required"))?;
            run_list(&path, &args.arch, args.headers, args.class.as_deref())
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct ObjCXref {
    class_name: String,
    selector: String,
    kind: MethodKind,
    origin: macho::objc::graph::MethodOrigin,
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
) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    for_each_selected_mach(
        &container,
        arch_filter.as_deref(),
        |mach, arch_name, show_header| {
            let inspector = ImageInspector::new(mach);
            if show_header {
                println!("=== {arch_name} ===");
            }
            if headers {
                print_objc_headers(&inspector, class_filter);
            } else {
                print_objc_summary(&inspector, class_filter);
            }
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn run_graph(path: &Path, arch: Option<&str>, json: bool, class: Option<&str>) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |mach, arch_name, _| {
            let inspector = ImageInspector::new(mach);
            let graph = match inspector.objc_graph() {
                Ok(graph) => graph,
                Err(_) => {
                    result.insert(arch_name.to_string(), serde_json::Value::Null);
                    return Ok(());
                }
            };
            if !has_objc_graph_data(graph) {
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
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
    } else {
        for_each_selected_mach(&container, arch, |mach, arch_name, show_header| {
            let inspector = ImageInspector::new(mach);
            if show_header {
                println!("=== {arch_name} ===");
            }
            let graph = match inspector.objc_graph() {
                Ok(graph) => graph,
                Err(e) => {
                    println!("[{arch_name}] No ObjC metadata: {e}");
                    if show_header {
                        println!();
                    }
                    return Ok(());
                }
            };
            if !has_objc_graph_data(graph) {
                println!("[{arch_name}] No ObjC metadata found.");
                if show_header {
                    println!();
                }
                return Ok(());
            }

            if let Some(cls) = class {
                if let Some(node) = graph.class(cls) {
                    print_class_node(node, graph);
                } else {
                    println!("Class {cls} not found");
                }
            } else {
                println!(
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
                    println!(
                        "  {} : {} ({} methods{cats})",
                        node.name,
                        node.superclass.as_deref().unwrap_or("?"),
                        node.effective_instance_methods.len() + node.effective_class_methods.len(),
                    );
                }
            }
            if show_header {
                println!();
            }
            Ok(())
        })?;
    }
    Ok(())
}

fn print_class_node(node: &macho::objc::graph::ClassNode, graph: &ObjCGraph) {
    let super_str = node.superclass.as_deref().unwrap_or("(root)");
    let swift_tag = if node.is_swift { " [swift]" } else { "" };
    println!("{}{swift_tag} : {super_str}", node.name);

    let chain = graph.superclass_chain(&node.name);
    if !chain.is_empty() {
        println!("  hierarchy: {} -> {}", node.name, chain.join(" -> "));
    }

    if !node.categories.is_empty() {
        println!("  categories: {}", node.categories.join(", "));
    }
    if !node.protocols.is_empty() {
        println!("  protocols: {}", node.protocols.join(", "));
    }

    println!(
        "  instance methods ({}):",
        node.effective_instance_methods.len()
    );
    for m in &node.effective_instance_methods {
        let origin = match &m.origin {
            macho::objc::graph::MethodOrigin::Class => String::new(),
            macho::objc::graph::MethodOrigin::Category(cat) => format!(" [from {cat}]"),
        };
        println!("    -{} {:#x}{origin}", m.selector, m.imp);
    }

    if !node.effective_class_methods.is_empty() {
        println!("  class methods ({}):", node.effective_class_methods.len());
        for m in &node.effective_class_methods {
            let origin = match &m.origin {
                macho::objc::graph::MethodOrigin::Class => String::new(),
                macho::objc::graph::MethodOrigin::Category(cat) => format!(" [from {cat}]"),
            };
            println!("    +{} {:#x}{origin}", m.selector, m.imp);
        }
    }
}

fn run_selectors(path: &Path, arch: Option<&str>, name: Option<&str>, json: bool) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |mach, arch_name, _| {
            let inspector = ImageInspector::new(mach);
            let graph = match inspector.objc_graph() {
                Ok(graph) => graph,
                Err(_) => {
                    result.insert(arch_name.to_string(), serde_json::Value::Null);
                    return Ok(());
                }
            };
            if !has_objc_graph_data(graph) {
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
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(&container, arch, |mach, arch_name, show_header| {
        let inspector = ImageInspector::new(mach);
        if show_header {
            println!("=== {arch_name} ===");
        }
        let graph = match inspector.objc_graph() {
            Ok(graph) => graph,
            Err(e) => {
                println!("[{arch_name}] No ObjC metadata: {e}");
                if show_header {
                    println!();
                }
                return Ok(());
            }
        };
        if !has_objc_graph_data(graph) {
            println!("[{arch_name}] No ObjC metadata found.");
            if show_header {
                println!();
            }
            return Ok(());
        }

        if let Some(sel_name) = name {
            let owners = graph.selector_owners(sel_name);
            if owners.is_empty() {
                println!("[{arch_name}] selector '{sel_name}' not found");
            } else {
                println!(
                    "[{arch_name}] selector '{sel_name}' ({} implementations):",
                    owners.len()
                );
                for owner in owners {
                    let origin = match &owner.origin {
                        macho::objc::graph::MethodOrigin::Class => String::new(),
                        macho::objc::graph::MethodOrigin::Category(cat) => format!(" [from {cat}]"),
                    };
                    println!(
                        "  {}[{} {sel_name}] {:#x}{origin}",
                        owner.kind.prefix(),
                        owner.class_name,
                        owner.imp
                    );
                }
            }
        } else {
            println!("[{arch_name}] {} unique selectors", graph.selectors.len());
            for (sel, owners) in &graph.selectors {
                let classes: Vec<&str> = owners.iter().map(|o| o.class_name.as_str()).collect();
                println!("  {sel} -> {}", classes.join(", "));
            }
        }
        if show_header {
            println!();
        }
        Ok(())
    })?;
    Ok(())
}

fn print_objc_headers(inspector: &ImageInspector<'_>, class_filter: Option<&str>) {
    let metadata = match inspector.objc_metadata() {
        Ok(m) => m,
        Err(e) => {
            println!("No ObjC metadata: {e}");
            return;
        }
    };

    if metadata.classes.is_empty()
        && metadata.categories.is_empty()
        && metadata.protocols.is_empty()
    {
        println!("No ObjC classes, categories, or protocols found.");
        return;
    }

    for class in &metadata.classes {
        if let Some(filter) = class_filter {
            if class.name != filter {
                continue;
            }
        }
        println!("{}", render::render_class_header(class));
    }
    // When filtering by class, only show categories/protocols for that class
    for cat in &metadata.categories {
        if let Some(filter) = class_filter {
            if cat.class_name != filter {
                continue;
            }
        }
        println!("{}", render::render_category_header(cat));
    }

    if class_filter.is_none() {
        for proto in &metadata.protocols {
            println!("{}", render::render_protocol_header(proto));
        }
    }
}

fn print_objc_summary(inspector: &ImageInspector<'_>, class_filter: Option<&str>) {
    let graph = match inspector.objc_graph() {
        Ok(graph) => graph,
        Err(e) => {
            println!("No ObjC metadata: {e}");
            return;
        }
    };
    if !has_objc_graph_data(graph) {
        println!("No ObjC classes, categories, or protocols found.");
        return;
    }

    let classes: Vec<_> = graph
        .classes
        .values()
        .filter(|c| class_filter.is_none_or(|f| c.name == f))
        .collect();

    println!("Classes ({}):", classes.len());
    for class in &classes {
        let super_str = class.superclass.as_deref().unwrap_or("?");
        let swift_str = if class.is_swift { " [swift]" } else { "" };
        let categories = if class.categories.is_empty() {
            String::new()
        } else {
            format!(" +{} categories", class.categories.len())
        };
        println!(
            "  {} : {} ({} effective methods, {} ivars, {} props){categories}{swift_str}",
            class.name,
            super_str,
            class.effective_instance_methods.len() + class.effective_class_methods.len(),
            class.ivars.len(),
            class.properties.len(),
        );
    }

    if class_filter.is_none() && !graph.protocols.is_empty() {
        println!("\nProtocols ({}):", graph.protocols.len());
        for proto in graph.protocols.values() {
            println!(
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

fn run_xrefs(path: &Path, arch: Option<&str>, class: Option<&str>, json: bool) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    if json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, arch, |mach, arch_name, _| {
            let inspector = ImageInspector::new(mach);
            let graph = match inspector.objc_graph() {
                Ok(graph) => graph,
                Err(_) => {
                    result.insert(arch_name.to_string(), serde_json::Value::Null);
                    return Ok(());
                }
            };
            if !has_objc_graph_data(graph) {
                result.insert(arch_name.to_string(), serde_json::Value::Null);
                return Ok(());
            }
            result.insert(
                arch_name.to_string(),
                serde_json::to_value(collect_xrefs(graph, class))?,
            );
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, val) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&val)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(&container, arch, |mach, arch_name, show_header| {
        let inspector = ImageInspector::new(mach);
        if show_header {
            println!("=== {arch_name} ===");
        }
        let graph = match inspector.objc_graph() {
            Ok(graph) => graph,
            Err(e) => {
                println!("[{arch_name}] No ObjC metadata: {e}");
                return Ok(());
            }
        };
        if !has_objc_graph_data(graph) {
            println!("[{arch_name}] No ObjC metadata found.");
            if show_header {
                println!();
            }
            return Ok(());
        }
        let xrefs = collect_xrefs(graph, class);
        for xref in &xrefs {
            println!(
                "  {}[{} {}] {:#x} -> {}",
                xref.kind.prefix(),
                xref.class_name,
                xref.selector,
                xref.imp,
                xref.imp_symbol
            );
        }
        println!("({} cross-references)", xrefs.len());
        if show_header {
            println!();
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
