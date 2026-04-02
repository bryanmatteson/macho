use crate::analysis::reconstruct::cpp::{
    CppImageIndex, build_headers_for_mach, build_image_index, default_header_unit, render_header,
    unify_images,
};
use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::commands::subcommands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct CppArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    /// Filter to a specific architecture
    #[arg(long)]
    arch: Option<String>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
    /// Render a recovered header
    #[arg(long)]
    headers: bool,
    /// Filter to a specific class name
    #[arg(long, name = "class")]
    class_filter: Option<String>,
}

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

pub fn run(args: CppArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.json {
        let mut result = serde_json::Map::new();
        for_each_selected_mach(&container, args.arch.as_deref(), |macho, arch_name, _| {
            let mut index = build_image_index(macho)?;
            if let Some(class_name) = &args.class_filter {
                index.classes.retain(|name, _| name == class_name);
            }
            result.insert(arch_name.to_string(), serde_json::to_value(&index)?);
            Ok(())
        })?;
        if result.len() == 1 {
            let (_, value) = result.into_iter().next().unwrap();
            println!("{}", serde_json::to_string_pretty(&value)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        return Ok(());
    }

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |macho, arch_name, show_header| {
            if show_header {
                println!("=== {arch_name} ===");
            }

            if args.headers {
                if let Some(class_name) = &args.class_filter {
                    let mut index = build_image_index(macho)?;
                    index.classes.retain(|name, _| name == class_name);
                    let unified = unify_images(&[index]);
                    let unit = default_header_unit(&unified);
                    println!("{}", render_header(&unit));
                } else {
                    println!("{}", build_headers_for_mach(macho)?);
                }
            } else {
                let mut index = build_image_index(macho)?;
                if let Some(class_name) = &args.class_filter {
                    index.classes.retain(|name, _| name == class_name);
                }
                print_cpp_summary(&index);
            }

            if show_header {
                println!();
            }
            Ok(())
        },
    )?;

    Ok(())
}

fn print_cpp_summary(index: &CppImageIndex) {
    println!(
        "C++ recovery: {} classes, {} typeinfos, {} free functions, {} symbols",
        index.classes.len(),
        index.typeinfos.len(),
        index.free_functions.len(),
        index.symbols.len(),
    );

    for class in index.classes.values() {
        println!(
            "  {}: {} bases, {} methods, {} vtables",
            class.name,
            class.bases.len(),
            class.methods.len(),
            class.vtables.len(),
        );
    }
}
