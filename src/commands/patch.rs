use anyhow::{Context, Result};
use macho::edit::resign::ResignPlan;
use macho::edit::transaction::{PatchOp, PatchTransaction};
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use macho::model::owned::OwnedFatBinary;
use std::path::{Path, PathBuf};

use crate::commands::common::arch_name_for_mach;

#[derive(clap::Args)]
pub struct PatchArgs {
    #[command(subcommand)]
    action: PatchAction,
}

#[derive(clap::Subcommand)]
enum PatchAction {
    /// Add an LC_RPATH to the binary
    AddRpath {
        path: PathBuf,
        /// The rpath value to add
        rpath: String,
        #[command(flatten)]
        target: TargetOpts,
        #[command(flatten)]
        output: OutputOpts,
    },
    /// Remove an LC_RPATH from the binary
    RemoveRpath {
        path: PathBuf,
        /// The rpath value to remove
        rpath: String,
        #[command(flatten)]
        target: TargetOpts,
        #[command(flatten)]
        output: OutputOpts,
    },
    /// Add an LC_LOAD_DYLIB to the binary
    AddDylib {
        path: PathBuf,
        /// The dylib install name
        dylib: String,
        #[command(flatten)]
        target: TargetOpts,
        #[command(flatten)]
        output: OutputOpts,
    },
    /// Remove LC_CODE_SIGNATURE from the binary
    StripSignature {
        path: PathBuf,
        #[command(flatten)]
        target: TargetOpts,
        #[command(flatten)]
        output: OutputOpts,
    },
    /// Overwrite raw bytes at a file offset
    PatchBytes {
        path: PathBuf,
        /// File offset to patch (for fat binaries, use --arch and provide a slice-relative offset)
        #[arg(long)]
        offset: String,
        /// Hex-encoded bytes to write (e.g., "90909090" for NOP sled)
        #[arg(long)]
        hex: String,
        #[command(flatten)]
        target: TargetOpts,
        #[command(flatten)]
        output: OutputOpts,
    },
}

#[derive(clap::Args)]
struct TargetOpts {
    /// Filter to a specific architecture (e.g., arm64, x86_64, arm64e)
    #[arg(long)]
    arch: Option<String>,
}

#[derive(clap::Args)]
struct OutputOpts {
    /// Output path (required unless --in-place)
    #[arg(long, short)]
    output: Option<PathBuf>,
    /// Modify the binary in place
    #[arg(long, conflicts_with = "output")]
    in_place: bool,
    /// Create a backup before in-place modification
    #[arg(long, requires = "in_place")]
    backup: bool,
    /// Preview changes without writing
    #[arg(long)]
    dry_run: bool,
    /// Skip validation checks
    #[arg(long)]
    force: bool,
}

pub fn run(args: PatchArgs) -> Result<()> {
    match args.action {
        PatchAction::AddRpath {
            path,
            rpath,
            target,
            output,
        } => run_patch(
            &path,
            target.arch.as_deref(),
            &output,
            vec![PatchOp::AddRpath(rpath)],
        ),
        PatchAction::RemoveRpath {
            path,
            rpath,
            target,
            output,
        } => run_patch(
            &path,
            target.arch.as_deref(),
            &output,
            vec![PatchOp::RemoveRpath(rpath)],
        ),
        PatchAction::AddDylib {
            path,
            dylib,
            target,
            output,
        } => {
            run_patch(
                &path,
                target.arch.as_deref(),
                &output,
                vec![PatchOp::AddDylib {
                    name: dylib,
                    compat_version: 0x10000, // 1.0.0
                    current_version: 0x10000,
                }],
            )
        }
        PatchAction::StripSignature {
            path,
            target,
            output,
        } => run_patch(
            &path,
            target.arch.as_deref(),
            &output,
            vec![PatchOp::RemoveCodeSignature],
        ),
        PatchAction::PatchBytes {
            path,
            offset,
            hex,
            target,
            output,
        } => {
            let offset = parse_offset(&offset)?;
            let bytes = parse_hex_bytes(&hex)?;
            run_patch(
                &path,
                target.arch.as_deref(),
                &output,
                vec![PatchOp::PatchBytes { offset, bytes }],
            )
        }
    }
}

fn run_patch(
    input: &Path,
    arch_filter: Option<&str>,
    opts: &OutputOpts,
    ops: Vec<PatchOp>,
) -> Result<()> {
    let file = std::fs::File::open(input)
        .with_context(|| format!("failed to open {}", input.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", input.display()))?;

    let output_bytes = match &container {
        MachContainer::Thin(mach) => {
            if let Some(filter) = arch_filter {
                let arch_name = arch_name_for_mach(mach);
                if !arch_name.eq_ignore_ascii_case(filter) {
                    anyhow::bail!(
                        "no architecture matching '{filter}' found (available: {arch_name})"
                    );
                }
            }

            let prepared = prepare_patch(mach, &ops, opts.force)?;
            let arch_name = arch_name_for_mach(mach);
            emit_preview(&[(&arch_name, &prepared)], opts.dry_run);
            prepared.bytes
        }
        MachContainer::Fat(fat) => {
            if arch_filter.is_none() && has_raw_byte_patch(&ops) {
                anyhow::bail!(
                    "raw byte patching a fat binary requires --arch because offsets are slice-relative"
                );
            }

            let selected = select_fat_arch_indices(fat, arch_filter)?;
            let prepared: Vec<(usize, String, PreparedPatch)> = selected
                .into_iter()
                .map(|index| {
                    let arch = &fat.arches()[index];
                    Ok((
                        index,
                        arch.spec.name(),
                        prepare_patch(&arch.mach, &ops, opts.force)?,
                    ))
                })
                .collect::<Result<_>>()?;

            let preview_items: Vec<(&str, &PreparedPatch)> = prepared
                .iter()
                .map(|(_, arch_name, prepared)| (arch_name.as_str(), prepared))
                .collect();
            emit_preview(&preview_items, opts.dry_run);

            let mut owned = OwnedFatBinary::from_fat(fat, &mmap);
            for (index, _, prepared) in &prepared {
                owned.replace_arch(*index, prepared.bytes.clone())?;
            }
            let rebuilt = owned.rebuild_bytes()?;
            let reparsed = macho::parse(&rebuilt).with_context(|| {
                format!("failed to re-parse rebuilt fat binary {}", input.display())
            })?;
            if !matches!(reparsed, MachContainer::Fat(_)) {
                anyhow::bail!("rebuilt output is no longer a fat binary");
            }
            rebuilt
        }
    };

    if opts.dry_run {
        return Ok(());
    }

    let output_path = if opts.in_place {
        if opts.backup {
            let backup = input.with_extension("bak");
            std::fs::copy(input, &backup)
                .with_context(|| format!("failed to create backup at {}", backup.display()))?;
            eprintln!("Backup saved to {}", backup.display());
        }
        input.to_path_buf()
    } else if let Some(ref out) = opts.output {
        out.clone()
    } else {
        anyhow::bail!("specify --output <path> or --in-place");
    };

    // Drop the mmap before writing (in case of in-place)
    drop(mmap);
    drop(file);

    std::fs::write(&output_path, &output_bytes)
        .with_context(|| format!("failed to write {}", output_path.display()))?;

    println!(
        "Wrote {} bytes to {}",
        output_bytes.len(),
        output_path.display()
    );

    Ok(())
}

fn parse_offset(s: &str) -> Result<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).with_context(|| format!("invalid hex offset: {s}"))
    } else {
        s.parse::<u64>()
            .with_context(|| format!("invalid offset: {s}"))
    }
}

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if hex.len() % 2 != 0 {
        anyhow::bail!("hex string must have even length, got {}", hex.len());
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .with_context(|| format!("invalid hex byte at position {i}: {:?}", &hex[i..i + 2]))
        })
        .collect()
}

struct PreparedPatch {
    preview: macho::edit::transaction::PatchPreview,
    resign_plan: ResignPlan,
    bytes: Vec<u8>,
}

fn prepare_patch(mach: &MachFile<'_>, ops: &[PatchOp], force: bool) -> Result<PreparedPatch> {
    let resign_plan = ResignPlan::from_mach(mach);

    let mut txn = PatchTransaction::new(mach);
    for op in ops {
        txn.add_op(op.clone());
    }

    let preview = txn.preview()?;
    if !preview.validation_errors.is_empty() && !force {
        let details = preview.validation_errors.join("\n  ");
        anyhow::bail!(
            "candidate binary has validation errors (use --force to override):\n  {details}"
        );
    }

    let bytes = if force {
        txn.build_unchecked()?
    } else {
        txn.commit()?
    };

    Ok(PreparedPatch {
        preview,
        resign_plan,
        bytes,
    })
}

fn emit_preview(items: &[(&str, &PreparedPatch)], dry_run: bool) {
    if dry_run {
        println!("Dry run — changes that would be applied:");
    }

    for (index, (arch_name, prepared)) in items.iter().enumerate() {
        if items.len() > 1 {
            if index > 0 {
                println!();
            }
            println!("=== {arch_name} ===");
        }

        for op in &prepared.preview.operations {
            println!("  {op}");
        }
        println!(
            "Load commands: {} -> {}",
            prepared.preview.old_command_count, prepared.preview.new_command_count
        );
        if !prepared.preview.validation_errors.is_empty() {
            println!("Validation errors:");
            for e in &prepared.preview.validation_errors {
                println!("  {e}");
            }
        }
        if !prepared.preview.validation_warnings.is_empty() {
            println!("Validation warnings:");
            for w in &prepared.preview.validation_warnings {
                println!("  {w}");
            }
        }
        if prepared.preview.signature_invalidated {
            println!("\nWarning: code signature will be invalidated.");
            print!("{}", prepared.resign_plan);
        }
    }
}

fn has_raw_byte_patch(ops: &[PatchOp]) -> bool {
    ops.iter()
        .any(|op| matches!(op, PatchOp::PatchBytes { .. }))
}

fn select_fat_arch_indices(
    fat: &macho::model::container::FatBinary<'_>,
    arch_filter: Option<&str>,
) -> Result<Vec<usize>> {
    let selected: Vec<usize> = fat
        .arches()
        .iter()
        .enumerate()
        .filter_map(|(index, arch)| {
            let arch_name = arch.spec.name();
            match arch_filter {
                Some(filter) if !arch_name.eq_ignore_ascii_case(filter) => None,
                _ => Some(index),
            }
        })
        .collect();

    if selected.is_empty() {
        if let Some(filter) = arch_filter {
            let available: Vec<String> = fat.arches().iter().map(|arch| arch.spec.name()).collect();
            anyhow::bail!(
                "no architecture matching '{filter}' found (available: {})",
                available.join(", ")
            );
        }
    }

    Ok(selected)
}
