use anyhow::{Context, Result};
use macho::demangle::SymbolDemangler;
use macho::dyld::chained::parse_chained_fixups;
use macho::dyld::types::FixupKind;
use macho::model::mach::MachFile;
use std::path::PathBuf;

use crate::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct FixupsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    /// Show only bind fixups
    #[arg(long, conflicts_with = "rebases_only")]
    binds_only: bool,
    /// Show only rebase fixups
    #[arg(long, conflicts_with = "binds_only")]
    rebases_only: bool,
    /// Demangle Rust and C++ symbol names when possible
    #[arg(long)]
    demangle: bool,
}

pub fn run(args: FixupsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    for_each_selected_mach(
        &container,
        args.arch.as_deref(),
        |mach, arch_name, show_header| {
            if show_header {
                println!("=== {arch_name} ===");
            }
            print_fixups(mach, &args);
            if show_header {
                println!();
            }
            Ok(())
        },
    )?;
    Ok(())
}

fn print_fixups(mach: &MachFile<'_>, args: &FixupsArgs) {
    match parse_chained_fixups(mach) {
        Ok(fixups) => {
            let mut bind_count = 0usize;
            let mut rebase_count = 0usize;
            let mut demangler = SymbolDemangler::new(args.demangle);

            demangler.precompute(fixups.imports.iter().map(|import| import.name));

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
                        let name = demangler.format(name);
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
                        let name = demangler.format(name);
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
