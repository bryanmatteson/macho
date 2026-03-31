use anyhow::{Context, Result};
use macho::container_analysis::ContainerReport;
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::commands::common::for_each_selected_mach;

#[derive(clap::Args)]
pub struct FilesetArgs {
    #[command(subcommand)]
    action: FilesetAction,
}

#[derive(clap::Subcommand)]
enum FilesetAction {
    /// List fileset entries in the binary
    List {
        path: PathBuf,
        #[arg(long)]
        arch: Option<String>,
    },
    /// Inspect a specific fileset entry by ID
    Inspect {
        path: PathBuf,
        /// The entry_id to inspect
        entry_id: String,
        #[arg(long)]
        arch: Option<String>,
    },
}

pub fn run(args: FilesetArgs) -> Result<()> {
    match args.action {
        FilesetAction::List { path, arch } => run_list(&path, arch.as_deref()),
        FilesetAction::Inspect {
            path,
            entry_id,
            arch,
        } => run_inspect(&path, &entry_id, arch.as_deref()),
    }
}

fn run_list(path: &std::path::Path, arch: Option<&str>) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    let snapshot = container.snapshot();
    let report = ContainerReport::from_snapshot(&snapshot);

    let mut found = false;
    if let Some(fileset) = report.fileset.as_ref() {
        let mut entries_by_arch: BTreeMap<&str, Vec<_>> = BTreeMap::new();
        for entry in &fileset.entries {
            if let Some(filter) = arch {
                if !entry.arch.eq_ignore_ascii_case(filter) {
                    continue;
                }
            }
            entries_by_arch
                .entry(entry.arch.as_str())
                .or_default()
                .push(entry);
        }

        for (arch_name, entries) in entries_by_arch {
            found = true;
            println!("[{}] {} fileset entries:", arch_name, entries.len());
            for entry in entries {
                println!(
                    "  {} vm={:#x} fileoff={:#x}",
                    entry.entry_id, entry.vm_addr, entry.file_offset
                );
            }
        }
    }

    if !found {
        if let Some(filter) = arch {
            if report.fileset.is_some() {
                println!("No fileset entries matched architecture '{filter}'.");
            } else {
                println!("No fileset entries found (binary is not MH_FILESET).");
            }
        } else {
            println!("No fileset entries found (binary is not MH_FILESET).");
        }
    }

    Ok(())
}

fn run_inspect(path: &std::path::Path, entry_id: &str, arch: Option<&str>) -> Result<()> {
    let file =
        std::fs::File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", path.display()))?;

    for_each_selected_mach(&container, arch, |mach, arch_name, show_header| {
        if show_header {
            println!("=== {arch_name} ===");
        }

        let entry = mach.load_commands().iter().find_map(|lc| {
            if let macho::model::load_command::LoadCommand::FilesetEntry(data) = &lc.kind {
                if data.entry_id == entry_id {
                    Some(data)
                } else {
                    None
                }
            } else {
                None
            }
        });

        match entry {
            Some(data) => {
                println!("Fileset Entry: {}", data.entry_id);
                println!("  VM address:   {:#x}", data.vm_addr);
                println!("  File offset:  {:#x}", data.file_offset);

                // Try to parse the member as a Mach-O at the specified offset
                let offset = data.file_offset as usize;
                if offset < mach.bytes().len() {
                    let remaining = &mach.bytes()[offset..];
                    match macho::parse(remaining) {
                        Ok(member) => {
                            let member_mach = member.first_mach();
                            println!("  File type:    {}", member_mach.header().file_type.name());
                            println!("  CPU:          {}", member_mach.header().cpu_type);
                            println!("  Load cmds:    {}", member_mach.load_commands().len());
                            println!("  Segments:     {}", member_mach.segments().len());
                        }
                        Err(_) => {
                            println!("  (could not parse member as Mach-O)");
                        }
                    }
                }
            }
            None => {
                println!("Fileset entry '{entry_id}' not found");
            }
        }

        if show_header {
            println!();
        }
        Ok(())
    })?;
    Ok(())
}
