use anyhow::{Context, Result};
use macho::dyld::chained::parse_chained_fixups;
use macho::dyld::types::FixupKind;
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct FixupsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    /// Show only bind fixups
    #[arg(long)]
    binds_only: bool,
    /// Show only rebase fixups
    #[arg(long)]
    rebases_only: bool,
}

pub fn run(args: FixupsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    match &container {
        MachContainer::Thin(mach) => print_fixups(mach, &args),
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
                print_fixups(&arch.mach, &args);
                println!();
            }
        }
    }
    Ok(())
}

fn print_fixups(mach: &MachFile<'_>, args: &FixupsArgs) {
    match parse_chained_fixups(mach) {
        Ok(fixups) => {
            let mut bind_count = 0usize;
            let mut rebase_count = 0usize;

            for f in &fixups.fixups {
                let is_bind = matches!(f.kind, FixupKind::Bind { .. } | FixupKind::AuthBind { .. });
                let is_rebase = !is_bind;

                if args.binds_only && !is_bind {
                    continue;
                }
                if args.rebases_only && !is_rebase {
                    continue;
                }

                if is_bind {
                    bind_count += 1;
                } else {
                    rebase_count += 1;
                }

                let kind_str = match &f.kind {
                    FixupKind::Rebase { target } => format!("rebase  -> {target:#x}"),
                    FixupKind::Bind {
                        import_index,
                        addend,
                    } => {
                        let name = fixups
                            .imports
                            .get(*import_index as usize)
                            .map(|i| i.name)
                            .unwrap_or("?");
                        if *addend != 0 {
                            format!("bind    -> {name} + {addend}")
                        } else {
                            format!("bind    -> {name}")
                        }
                    }
                    FixupKind::AuthRebase {
                        target,
                        key,
                        diversity,
                        ..
                    } => {
                        format!("auth-rb -> {target:#x} key={key} div={diversity}")
                    }
                    FixupKind::AuthBind {
                        import_index,
                        key,
                        diversity,
                        ..
                    } => {
                        let name = fixups
                            .imports
                            .get(*import_index as usize)
                            .map(|i| i.name)
                            .unwrap_or("?");
                        format!("auth-bd -> {name} key={key} div={diversity}")
                    }
                };

                println!(
                    "  seg[{}]+{:#010x}  {kind_str}",
                    f.segment_index, f.segment_offset,
                );
            }

            println!("({bind_count} binds, {rebase_count} rebases)");
        }
        Err(e) => println!("No chained fixups: {e}"),
    }
}
