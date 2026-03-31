use anyhow::{Context, Result};
use macho::edit::transaction::{PatchOp, PatchTransaction, PreparedPatch, SignatureOutcome};
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use macho::model::owned::OwnedFatBinary;
use macho::validate;
use std::fs::Permissions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
    let template_permissions = file
        .metadata()
        .with_context(|| format!("failed to read metadata for {}", input.display()))?
        .permissions();
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

            let prepared = prepare_patch(mach, &ops)?;
            let arch_name = arch_name_for_mach(mach);
            emit_preview(&[(&arch_name, &prepared)], opts.dry_run);
            if !opts.force && !prepared.preview.validation_errors.is_empty() {
                let details = prepared.preview.validation_errors.join("\n  ");
                anyhow::bail!(
                    "candidate binary has validation errors (use --force to override):\n  {details}"
                );
            }
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
                .iter()
                .copied()
                .map(|index| {
                    let arch = &fat.arches()[index];
                    Ok((index, arch.spec.name(), prepare_patch(&arch.mach, &ops)?))
                })
                .collect::<Result<_>>()?;

            let preview_items: Vec<(&str, &PreparedPatch)> = prepared
                .iter()
                .map(|(_, arch_name, prepared)| (arch_name.as_str(), prepared))
                .collect();
            emit_preview(&preview_items, opts.dry_run);
            if !opts.force
                && prepared
                    .iter()
                    .any(|(_, _, prepared)| !prepared.preview.validation_errors.is_empty())
            {
                let details: Vec<String> = prepared
                    .iter()
                    .flat_map(|(_, arch_name, prepared)| {
                        prepared
                            .preview
                            .validation_errors
                            .iter()
                            .map(move |err| format!("{arch_name}: {err}"))
                    })
                    .collect();
                anyhow::bail!(
                    "candidate binary has validation errors (use --force to override):\n  {}",
                    details.join("\n  ")
                );
            }

            let mut owned = OwnedFatBinary::from_fat(fat, &mmap);
            for (index, _, prepared) in &prepared {
                owned.replace_arch(*index, prepared.bytes.clone())?;
            }
            let rebuilt = owned.rebuild_bytes()?;
            let reparsed = macho::parse(&rebuilt).with_context(|| {
                format!("failed to re-parse rebuilt fat binary {}", input.display())
            })?;
            let MachContainer::Fat(rebuilt_fat) = reparsed else {
                anyhow::bail!("rebuilt output is no longer a fat binary");
            };
            if !opts.force {
                let mut errors = Vec::new();
                for index in &selected {
                    let arch = &rebuilt_fat.arches()[*index];
                    errors.extend(
                        validation_errors_for_mach(&arch.mach)
                            .into_iter()
                            .map(|err| format!("{}: {err}", arch.spec.name())),
                    );
                }
                if !errors.is_empty() {
                    anyhow::bail!(
                        "rebuilt fat binary has validation errors (use --force to override):\n  {}",
                        errors.join("\n  ")
                    );
                }
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

    atomic_write(&output_path, &output_bytes, template_permissions)?;

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

fn atomic_write(path: &Path, bytes: &[u8], permissions: Permissions) -> Result<()> {
    let tmp_path = temp_path_for(path);
    {
        let mut file = std::fs::File::create(&tmp_path)
            .with_context(|| format!("failed to create temporary file {}", tmp_path.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write temporary file {}", tmp_path.display()))?;
        file.set_permissions(permissions).with_context(|| {
            format!("failed to preserve permissions for {}", tmp_path.display())
        })?;
        file.sync_all()
            .with_context(|| format!("failed to flush temporary file {}", tmp_path.display()))?;
    }

    if let Err(err) = std::fs::rename(&tmp_path, path) {
        let _ = std::fs::remove_file(&tmp_path);
        return Err(err).context(format!("failed to replace {}", path.display()));
    }

    Ok(())
}

fn temp_path_for(path: &Path) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path.file_name().and_then(|s| s.to_str()).unwrap_or("macho");
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let pid = std::process::id();
    parent.join(format!(".{stem}.{pid}.{nanos}.tmp"))
}

fn prepare_patch(mach: &MachFile<'_>, ops: &[PatchOp]) -> Result<PreparedPatch> {
    let mut txn = PatchTransaction::new(mach);
    for op in ops {
        txn.add_op(op.clone());
    }

    txn.prepare().map_err(Into::into)
}

fn emit_preview(items: &[(&str, &PreparedPatch)], dry_run: bool) {
    print!("{}", format_preview(items, dry_run));
}

fn format_preview(items: &[(&str, &PreparedPatch)], dry_run: bool) -> String {
    let mut output = String::new();
    if dry_run {
        output.push_str("Dry run - changes that would be applied:\n");
    }

    for (index, (arch_name, prepared)) in items.iter().enumerate() {
        if items.len() > 1 {
            if index > 0 {
                output.push('\n');
            }
            output.push_str(&format!("=== {arch_name} ===\n"));
        }

        for op in &prepared.preview.operations {
            output.push_str(&format!("  {op}\n"));
        }
        output.push_str(&format!(
            "Load commands: {} -> {}\n",
            prepared.preview.old_command_count, prepared.preview.new_command_count
        ));
        if !prepared.preview.semantic_diff.findings.is_empty() {
            output.push_str("Semantic changes:\n");
            for finding in &prepared.preview.semantic_diff.findings {
                output.push_str(&format!(
                    "  [{}:{}] {}",
                    finding.severity, finding.domain, finding.message
                ));
                output.push('\n');
            }
        }
        if !prepared.preview.validation_errors.is_empty() {
            output.push_str("Validation errors:\n");
            for e in &prepared.preview.validation_errors {
                output.push_str(&format!("  {e}\n"));
            }
        }
        if !prepared.preview.validation_warnings.is_empty() {
            output.push_str("Validation warnings:\n");
            for w in &prepared.preview.validation_warnings {
                output.push_str(&format!("  {w}\n"));
            }
        }
        match prepared.preview.signature_outcome {
            SignatureOutcome::Unchanged => {}
            SignatureOutcome::Invalidated => {
                output.push_str("\nWarning: code signature will be invalidated.\n");
                if let Some(plan) = &prepared.preview.resign_plan {
                    output.push_str(&plan.to_string());
                }
            }
            SignatureOutcome::Removed => {
                output.push_str("\nCode signature will be removed; output will be unsigned.\n");
                if let Some(plan) = &prepared.preview.resign_plan {
                    output.push_str(&plan.to_string());
                }
            }
        }
    }

    output
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

fn validation_errors_for_mach(mach: &MachFile<'_>) -> Vec<String> {
    validate::validate(mach)
        .into_iter()
        .filter(|diag| diag.severity == validate::Severity::Error)
        .map(|diag| format!("{}: {}", diag.code.0, diag.message))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use macho::diff::{ChangeSeverity, DiffDomain, DiffFinding, DiffReport};
    use macho::edit::transaction::PatchPreview;

    fn prepared_patch(
        operations: Vec<&str>,
        findings: Vec<DiffFinding>,
        signature_outcome: SignatureOutcome,
    ) -> PreparedPatch {
        PreparedPatch {
            preview: PatchPreview {
                operations: operations.into_iter().map(str::to_owned).collect(),
                old_command_count: 10,
                new_command_count: 11,
                validation_errors: Vec::new(),
                validation_warnings: Vec::new(),
                semantic_diff: DiffReport { findings },
                signature_outcome,
                resign_plan: None,
            },
            bytes: Vec::new(),
        }
    }

    #[test]
    fn format_preview_surfaces_semantic_diff_and_signature_invalidation() {
        let prepared = prepared_patch(
            vec!["add rpath: /tmp/test"],
            vec![DiffFinding {
                domain: DiffDomain::LoadCommands,
                severity: ChangeSeverity::Info,
                arch: Some("arm64e".to_string()),
                message: "load command added: LC_RPATH".to_string(),
            }],
            SignatureOutcome::Invalidated,
        );

        let output = format_preview(&[("arm64e", &prepared)], true);

        assert!(output.contains("Dry run - changes that would be applied:"));
        assert!(output.contains("Semantic changes:"));
        assert!(output.contains("load command added: LC_RPATH"));
        assert!(output.contains("Warning: code signature will be invalidated."));
    }

    #[test]
    fn format_preview_reports_unsigned_output_when_signature_removed() {
        let prepared = prepared_patch(
            vec!["remove code signature"],
            vec![DiffFinding {
                domain: DiffDomain::Codesign,
                severity: ChangeSeverity::Warning,
                arch: Some("arm64e".to_string()),
                message: "code signature removed".to_string(),
            }],
            SignatureOutcome::Removed,
        );

        let output = format_preview(&[("arm64e", &prepared)], true);

        assert!(output.contains("Semantic changes:"));
        assert!(output.contains("code signature removed"));
        assert!(output.contains("Code signature will be removed; output will be unsigned."));
    }
}
