pub mod c;
pub mod cpp;
pub mod dwarf;
pub mod header_infer;
pub mod objc;
pub mod swift;

use anyhow::{Context, Result};
use std::path::PathBuf;

use crate::commands::subcommands::codesign;
use crate::commands::subcommands::common::for_each_selected_mach;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(clap::Args)]
pub struct ExtractArgs {
    #[command(subcommand)]
    action: ExtractAction,
}

#[derive(clap::Subcommand)]
enum ExtractAction {
    Objc(self::objc::ObjCArgs),
    Swift(self::swift::SwiftArgs),
    Rtti(self::cpp::CppArgs),
    Dwarf(self::dwarf::ExtractDwarfArgs),
    Section(SectionArgs),
    #[command(name = "code-signature", visible_alias = "codesign")]
    CodeSignature(codesign::CodesignArgs),
}

#[derive(clap::Args)]
struct SectionArgs {
    path: PathBuf,
    segment: String,
    section: String,
    #[arg(long)]
    arch: Option<String>,
    #[arg(long)]
    output: Option<PathBuf>,
    #[arg(long)]
    output_dir: Option<PathBuf>,
}

pub fn run(args: ExtractArgs) -> Result<()> {
    match args.action {
        ExtractAction::Objc(args) => self::objc::run(args),
        ExtractAction::Swift(args) => self::swift::run(args),
        ExtractAction::Rtti(args) => self::cpp::run(args),
        ExtractAction::Dwarf(args) => self::dwarf::run_extract(args),
        ExtractAction::Section(args) => run_section(args),
        ExtractAction::CodeSignature(args) => codesign::run(args),
    }
}

fn run_section(args: SectionArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    if args.output.is_none() && args.output_dir.is_none() {
        anyhow::bail!("specify --output for one slice or --output-dir for multiple slices");
    }

    let mut wrote = 0usize;
    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |macho, arch_name, show_header| {
            let bytes = macho.section_bytes(&args.segment, &args.section)?;
            if let Some(path) = args.output.as_ref() {
                if show_header {
                    anyhow::bail!("--output requires selecting a single architecture with --arch");
                }
                std::fs::write(path, bytes)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            } else if let Some(dir) = args.output_dir.as_ref() {
                std::fs::create_dir_all(dir)
                    .with_context(|| format!("failed to create {}", dir.display()))?;
                let path = dir.join(format!(
                    "{}-{}-{}.bin",
                    arch_name,
                    args.segment.trim_start_matches('_'),
                    args.section.trim_start_matches('_')
                ));
                std::fs::write(&path, bytes)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }
            wrote += 1;
            Ok(())
        },
    )?;

    if wrote == 0 {
        anyhow::bail!(
            "section {},{} was not found in the selected slices",
            args.segment,
            args.section
        );
    }

    if let Some(path) = args.output.as_ref() {
        println!(
            "Extracted {},{} to {}",
            args.segment,
            args.section,
            path.display()
        );
    } else if let Some(dir) = args.output_dir.as_ref() {
        println!(
            "Extracted {},{} for {wrote} slice{} to {}",
            args.segment,
            args.section,
            if wrote == 1 { "" } else { "s" },
            dir.display()
        );
    }

    Ok(())
}
