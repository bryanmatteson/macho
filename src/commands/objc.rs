use anyhow::{Context, Result};
use macho::model::mach::MachFile;
use macho::objc::graph::ObjCGraph;
use macho::objc::{self, render};
use std::path::{Path, PathBuf};

use crate::commands::common::for_each_selected_mach;

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
    },
    /// Show cross-references between ObjC methods and symbols
    Xrefs {
        path: PathBuf,
        #[arg(long)]
        arch: Option<String>,
        /// Filter to a specific class
        #[arg(long)]
        class: Option<String>,
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
        Some(ObjCAction::Selectors { path, arch, name }) => {
            run_selectors(&path, arch.as_deref(), name.as_deref())
        }
        Some(ObjCAction::Xrefs { path, arch, class }) => {
            run_xrefs(&path, arch.as_deref(), class.as_deref())
        }
        None => {
            let path = args
                .path
                .ok_or_else(|| anyhow::anyhow!("path is required"))?;
            run_list(&path, &args.arch, args.headers, args.class.as_deref())
        }
    }
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
            if show_header {
                println!("=== {arch_name} ===");
            }
            print_objc(mach, headers, class_filter);
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
            let metadata = match objc::parse_objc_metadata(mach) {
                Ok(m) => m,
                Err(_) => return Ok(()),
            };
            let graph = ObjCGraph::build_from_mach(&metadata, mach);
            let val = if let Some(cls) = class {
                graph
                    .class(cls)
                    .map(serde_json::to_value)
                    .transpose()?
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::to_value(&graph)?
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
            if show_header {
                println!("=== {arch_name} ===");
            }
            let metadata = match objc::parse_objc_metadata(mach) {
                Ok(m) => m,
                Err(e) => {
                    println!("[{arch_name}] No ObjC metadata: {e}");
                    if show_header {
                        println!();
                    }
                    return Ok(());
                }
            };
            let graph = ObjCGraph::build_from_mach(&metadata, mach);

            if let Some(cls) = class {
                if let Some(node) = graph.class(cls) {
                    print_class_node(node, &graph);
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
                        node.instance_methods.len() + node.class_methods.len(),
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

    println!("  instance methods ({}):", node.instance_methods.len());
    for m in &node.instance_methods {
        let origin = match &m.origin {
            macho::objc::graph::MethodOrigin::Class => String::new(),
            macho::objc::graph::MethodOrigin::Category(cat) => format!(" [from {cat}]"),
        };
        println!("    -{} {:#x}{origin}", m.selector, m.imp);
    }

    if !node.class_methods.is_empty() {
        println!("  class methods ({}):", node.class_methods.len());
        for m in &node.class_methods {
            let origin = match &m.origin {
                macho::objc::graph::MethodOrigin::Class => String::new(),
                macho::objc::graph::MethodOrigin::Category(cat) => format!(" [from {cat}]"),
            };
            println!("    +{} {:#x}{origin}", m.selector, m.imp);
        }
    }
}

fn run_selectors(path: &Path, arch: Option<&str>, name: Option<&str>) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    for_each_selected_mach(&container, arch, |mach, arch_name, show_header| {
        if show_header {
            println!("=== {arch_name} ===");
        }
        let metadata = match objc::parse_objc_metadata(mach) {
            Ok(m) => m,
            Err(e) => {
                println!("[{arch_name}] No ObjC metadata: {e}");
                if show_header {
                    println!();
                }
                return Ok(());
            }
        };
        let graph = ObjCGraph::build_from_mach(&metadata, mach);

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
                    let prefix = if owner.is_class_method { "+" } else { "-" };
                    let origin = match &owner.origin {
                        macho::objc::graph::MethodOrigin::Class => String::new(),
                        macho::objc::graph::MethodOrigin::Category(cat) => format!(" [from {cat}]"),
                    };
                    println!(
                        "  {prefix}[{} {sel_name}] {:#x}{origin}",
                        owner.class_name, owner.imp
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

fn print_objc(mach: &MachFile<'_>, headers: bool, class_filter: Option<&str>) {
    let metadata = match objc::parse_objc_metadata(mach) {
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

    if headers {
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
    } else {
        let classes: Vec<_> = metadata
            .classes
            .iter()
            .filter(|c| class_filter.is_none_or(|f| c.name == f))
            .collect();

        println!("Classes ({}):", classes.len());
        for class in &classes {
            let super_str = class.superclass_name.as_deref().unwrap_or("?");
            let swift_str = if class.is_swift { " [swift]" } else { "" };
            println!(
                "  {} : {} ({} methods, {} ivars, {} props){swift_str}",
                class.name,
                super_str,
                class.instance_methods.len() + class.class_methods.len(),
                class.ivars.len(),
                class.properties.len(),
            );
        }

        let categories: Vec<_> = metadata
            .categories
            .iter()
            .filter(|c| class_filter.is_none_or(|f| c.class_name == f))
            .collect();

        if !categories.is_empty() {
            println!("\nCategories ({}):", categories.len());
            for cat in &categories {
                println!(
                    "  {} ({}) — {} methods",
                    cat.class_name,
                    cat.name,
                    cat.instance_methods.len() + cat.class_methods.len(),
                );
            }
        }

        if class_filter.is_none() && !metadata.protocols.is_empty() {
            println!("\nProtocols ({}):", metadata.protocols.len());
            for proto in &metadata.protocols {
                println!(
                    "  {} — {} methods",
                    proto.name,
                    proto.instance_methods.len()
                        + proto.class_methods.len()
                        + proto.optional_instance_methods.len()
                        + proto.optional_class_methods.len(),
                );
            }
        }
    }
}

fn run_xrefs(path: &Path, arch: Option<&str>, class: Option<&str>) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    for_each_selected_mach(&container, arch, |mach, arch_name, show_header| {
        if show_header {
            println!("=== {arch_name} ===");
        }
        let metadata = match objc::parse_objc_metadata(mach) {
            Ok(m) => m,
            Err(e) => {
                println!("[{arch_name}] No ObjC metadata: {e}");
                return Ok(());
            }
        };
        let graph = ObjCGraph::build_from_mach(&metadata, mach);

        let classes: Vec<_> = if let Some(cls) = class {
            graph.class(cls).into_iter().collect()
        } else {
            graph.classes.values().collect()
        };

        let mut xref_count = 0;
        for node in &classes {
            for m in &node.instance_methods {
                if let Some(ref sym) = m.imp_symbol {
                    println!("  -[{} {}] {:#x} -> {}", node.name, m.selector, m.imp, sym);
                    xref_count += 1;
                }
            }
            for m in &node.class_methods {
                if let Some(ref sym) = m.imp_symbol {
                    println!("  +[{} {}] {:#x} -> {}", node.name, m.selector, m.imp, sym);
                    xref_count += 1;
                }
            }
        }
        println!("({xref_count} cross-references)");
        if show_header {
            println!();
        }
        Ok(())
    })?;
    Ok(())
}
