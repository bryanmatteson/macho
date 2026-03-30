use anyhow::{Context, Result};
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use macho::objc::{self, render};
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct ObjCArgs {
    /// Path to Mach-O binary
    path: PathBuf,

    #[arg(long)]
    arch: Option<String>,

    /// Show full class-dump-style headers
    #[arg(long)]
    headers: bool,

    /// Filter to a specific class name
    #[arg(long)]
    class: Option<String>,
}

pub fn run(args: ObjCArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachContainer::Thin(mach) => print_objc(mach, &args),
        MachContainer::Fat(fat) => {
            for arch in fat.arches() {
                let name = arch.spec.name();
                if let Some(ref f) = args.arch {
                    if !name.eq_ignore_ascii_case(f) {
                        continue;
                    }
                }
                if fat.arches().len() > 1 {
                    println!("=== {name} ===");
                }
                print_objc(&arch.mach, &args);
                println!();
            }
        }
    }
    Ok(())
}

fn print_objc(mach: &MachFile<'_>, args: &ObjCArgs) {
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

    if args.headers {
        for class in &metadata.classes {
            if let Some(ref filter) = args.class {
                if class.name != *filter {
                    continue;
                }
            }
            println!("{}", render::render_class_header(class));
        }
        for cat in &metadata.categories {
            println!("{}", render::render_category_header(cat));
        }
        for proto in &metadata.protocols {
            println!("{}", render::render_protocol_header(proto));
        }
    } else {
        println!("Classes ({}):", metadata.classes.len());
        for class in &metadata.classes {
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

        if !metadata.categories.is_empty() {
            println!("\nCategories ({}):", metadata.categories.len());
            for cat in &metadata.categories {
                println!(
                    "  {} ({}) — {} methods",
                    cat.class_name,
                    cat.name,
                    cat.instance_methods.len() + cat.class_methods.len(),
                );
            }
        }

        if !metadata.protocols.is_empty() {
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
