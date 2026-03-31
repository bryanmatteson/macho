use anyhow::{Context, Result};
use macho::container_analysis::ContainerReport;
use std::collections::BTreeMap;
use std::path::PathBuf;

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

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

    let all_matches = container.inspect_fileset_entry(entry_id);
    let matches: Vec<_> = all_matches
        .iter()
        .filter(|inspection| arch.is_none_or(|filter| inspection.arch.eq_ignore_ascii_case(filter)))
        .collect();

    if matches.is_empty() {
        if let Some(filter) = arch {
            if all_matches.is_empty() {
                println!("Fileset entry '{entry_id}' not found");
            } else {
                println!("Fileset entry '{entry_id}' not found for architecture '{filter}'");
            }
        } else {
            println!("Fileset entry '{entry_id}' not found");
        }
        return Ok(());
    }

    let show_headers = matches.len() > 1;
    for (index, inspection) in matches.iter().enumerate() {
        if show_headers {
            if index > 0 {
                println!();
            }
            println!("=== {} ===", inspection.arch);
        }

        println!("Fileset Entry: {}", inspection.entry_id);
        println!("  VM address:   {:#x}", inspection.vm_addr);
        println!("  File offset:  {:#x}", inspection.file_offset);
        if let Some(member) = &inspection.member {
            println!("  File type:    {}", member.file_type);
            println!("  CPU:          {}", member.cpu);
            println!("  Load cmds:    {}", member.load_commands);
            println!("  Segments:     {}", member.segments);
        } else if let Some(err) = &inspection.parse_error {
            println!("  (could not parse member as Mach-O: {err})");
        }
    }
    Ok(())
}
