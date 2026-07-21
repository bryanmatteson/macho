use crate::analysis::{AnalysisDomain, AnalysisPlan};
use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::model::container::MachoContainer;
use crate::model::macho_file::MachoFile;
use crate::model::validate;
use crate::mutate::owned::OwnedFatBinary;
use crate::mutate::patch::PatchOp;
use crate::mutate::preview::{SignatureOutcome, StructuralPatchPreview};
use crate::mutate::transaction::{PatchPlan, PreparedPatch};
use crate::mutate::{
    InProcessSignatureProvider, SignatureKind, SignatureProvider, SignatureRequest,
};
use crate::workflow::WorkflowSigning;
use anyhow::{Context, Result};
use clap::ArgAction;
use std::fs::Permissions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::commands::subcommands::common::arch_name_for_mach;
use crate::commands::{OutputFormat, input_message, input_result, usage_message};

#[derive(clap::Args)]
/// The PatchArgs type.
pub struct PatchArgs {
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture (e.g., arm64, x86_64, arm64e)
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Add an LC_RPATH to the binary
    #[arg(long = "add-rpath", action = ArgAction::Append)]
    add_rpath: Vec<String>,
    /// Remove an LC_RPATH from the binary
    #[arg(long = "remove-rpath", action = ArgAction::Append)]
    remove_rpath: Vec<String>,
    /// Add an LC_LOAD_DYLIB to the binary
    #[arg(long = "add-dylib", action = ArgAction::Append)]
    add_dylib: Vec<String>,
    /// Remove LC_CODE_SIGNATURE from the binary
    #[arg(long = "strip-signature")]
    strip_signature: bool,
    /// Overwrite raw bytes at a file offset using OFFSET:HEX
    #[arg(long = "bytes", action = ArgAction::Append)]
    patch_bytes: Vec<String>,
    #[command(flatten)]
    signing: SigningOpts,
    #[command(flatten)]
    output: OutputOpts,
}

#[derive(clap::Args, Default)]
struct SigningOpts {
    /// Sign the candidate in process with an ad-hoc signature
    #[arg(long, conflicts_with_all = ["sign_p12", "strip_signature"])]
    sign_adhoc: bool,
    /// Sign the candidate in process with a PKCS#12/PFX identity
    #[arg(
        long,
        value_name = "PATH",
        conflicts_with_all = ["sign_adhoc", "strip_signature"]
    )]
    sign_p12: Option<PathBuf>,
    /// Read the PKCS#12 password from PATH (one terminal line ending is removed)
    #[arg(long, value_name = "PATH", requires = "sign_p12")]
    p12_password_file: Option<PathBuf>,
    /// Override the signature identifier
    #[arg(long, value_name = "VALUE")]
    identifier: Option<String>,
    /// Override XML property-list entitlements from PATH
    #[arg(long, value_name = "PATH")]
    entitlements: Option<PathBuf>,
}

struct SigningConfig {
    provider: InProcessSignatureProvider,
    request: SignatureRequest,
}

impl SigningConfig {
    fn kind(&self) -> SignatureKind {
        self.provider.kind()
    }
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
}

/// Performs run.
pub fn run(args: PatchArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let signing = load_signing_config(&args.signing)?;
    let mut ops = Vec::new();
    for rpath in args.add_rpath {
        ops.push(PatchOp::AddRpath(rpath));
    }
    for rpath in args.remove_rpath {
        ops.push(PatchOp::RemoveRpath(rpath));
    }
    for dylib in args.add_dylib {
        ops.push(PatchOp::AddDylib {
            name: dylib,
            compat_version: 0x10000,
            current_version: 0x10000,
        });
    }
    if args.strip_signature {
        ops.push(PatchOp::RemoveCodeSignature);
    }
    for spec in args.patch_bytes {
        let (offset, bytes) = parse_patch_bytes_spec(&spec)?;
        ops.push(PatchOp::PatchBytes { offset, bytes });
    }
    if ops.is_empty() && signing.is_none() {
        return Err(usage_message("no patch operations specified"));
    }

    run_patch(
        &args.input.path,
        args.selection.arch.as_deref(),
        &args.output,
        ops,
        signing.as_ref(),
        format,
        out,
    )
}

fn run_patch(
    input: &Path,
    arch_filter: Option<&str>,
    opts: &OutputOpts,
    ops: Vec<PatchOp>,
    signing: Option<&SigningConfig>,
    format: OutputFormat,
    out: &mut dyn Write,
) -> Result<()> {
    let file = input_result(
        std::fs::File::open(input),
        format!("failed to open {}", input.display()),
    )?;
    let template_permissions = input_result(
        file.metadata(),
        format!("failed to read metadata for {}", input.display()),
    )?
    .permissions();
    let mmap = input_result(
        // SAFETY: the mapping is read-only and remains valid while the input
        // file is retained for the duration of the patch preparation phase.
        unsafe { memmap2::Mmap::map(&file) },
        format!("failed to map {}", input.display()),
    )?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", input.display()))?;

    let (output_bytes, previews) = match &container {
        MachoContainer::Thin(macho) => {
            if let Some(filter) = arch_filter {
                let arch_name = arch_name_for_mach(macho);
                if !arch_name.eq_ignore_ascii_case(filter) {
                    return Err(input_message(format!(
                        "no architecture matching '{filter}' found (available: {arch_name})"
                    )));
                }
            }

            let prepared = prepare_patch(macho, &ops, signing)?;
            let arch_name = arch_name_for_mach(macho);
            if format == OutputFormat::Text {
                emit_preview(&[(&arch_name, &prepared)], opts.dry_run, out);
            }
            if !prepared.preview.validation_errors.is_empty() {
                let details = prepared.preview.validation_errors.join("\n  ");
                anyhow::bail!("candidate binary has validation errors:\n  {details}");
            }
            (prepared.bytes, vec![(arch_name, prepared.preview)])
        }
        MachoContainer::Fat(fat) => {
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
                    Ok((
                        index,
                        arch.spec().name(),
                        prepare_patch(arch.macho(), &ops, signing)?,
                    ))
                })
                .collect::<Result<_>>()?;

            let preview_items: Vec<(&str, &PreparedPatch)> = prepared
                .iter()
                .map(|(_, arch_name, prepared)| (arch_name.as_str(), prepared))
                .collect();
            if format == OutputFormat::Text {
                emit_preview(&preview_items, opts.dry_run, out);
            }
            if prepared
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
                    "candidate binary has validation errors:\n  {}",
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
            let MachoContainer::Fat(rebuilt_fat) = reparsed else {
                anyhow::bail!("rebuilt output is no longer a fat binary");
            };
            let mut errors = Vec::new();
            for index in &selected {
                let arch = &rebuilt_fat.arches()[*index];
                errors.extend(
                    validation_errors_for_mach(arch.macho())
                        .into_iter()
                        .map(|err| format!("{}: {err}", arch.spec().name())),
                );
            }
            if !errors.is_empty() {
                anyhow::bail!(
                    "rebuilt fat binary has validation errors:\n  {}",
                    errors.join("\n  ")
                );
            }
            (
                rebuilt,
                prepared
                    .into_iter()
                    .map(|(_, arch, prepared)| (arch, prepared.preview))
                    .collect(),
            )
        }
    };

    if opts.dry_run {
        if format == OutputFormat::Json {
            crate::commands::output::json::write_pretty(
                out,
                &serde_json::json!({
                    "dry_run": true,
                    "written": false,
                    "output": null,
                    "bytes": output_bytes.len(),
                    "signing": signing_report(signing),
                    "previews": preview_report(&previews),
                }),
            )?;
        }
        return Ok(());
    }

    let mut backup_path = None;
    let output_path = if opts.in_place {
        if opts.backup {
            let backup = input.with_extension("bak");
            std::fs::copy(input, &backup)
                .with_context(|| format!("failed to create backup at {}", backup.display()))?;
            if format == OutputFormat::Text {
                let _ = writeln!(out, "Backup saved to {}", backup.display());
            }
            backup_path = Some(backup);
        }
        input.to_path_buf()
    } else if let Some(ref out) = opts.output {
        out.clone()
    } else {
        return Err(usage_message("specify --output <path> or --in-place"));
    };

    // Drop the mmap before writing (in case of in-place)
    drop(mmap);
    drop(file);

    atomic_write(&output_path, &output_bytes, template_permissions)?;

    if format == OutputFormat::Json {
        crate::commands::output::json::write_pretty(
            out,
            &serde_json::json!({
                "dry_run": false,
                "written": true,
                "output": output_path,
                "backup": backup_path,
                "bytes": output_bytes.len(),
                "signing": signing_report(signing),
                "previews": preview_report(&previews),
            }),
        )?;
    } else {
        let _ = writeln!(
            out,
            "Wrote {} bytes to {}",
            output_bytes.len(),
            output_path.display()
        );
    }

    Ok(())
}

fn preview_report(previews: &[(String, StructuralPatchPreview)]) -> Vec<serde_json::Value> {
    previews
        .iter()
        .map(|(arch, preview)| serde_json::json!({ "arch": arch, "preview": preview }))
        .collect()
}

fn signing_report(signing: Option<&SigningConfig>) -> serde_json::Value {
    match signing {
        Some(config) => serde_json::json!({
            "requested": true,
            "mode": match config.kind() {
                SignatureKind::AdHoc => "ad_hoc",
                SignatureKind::Certificate => "certificate",
                _ => "opaque",
            },
            "verified": true,
        }),
        None => serde_json::json!({
            "requested": false,
            "mode": null,
            "verified": false,
        }),
    }
}

fn load_signing_config(opts: &SigningOpts) -> Result<Option<SigningConfig>> {
    let signing_requested = opts.sign_adhoc || opts.sign_p12.is_some();
    if !signing_requested {
        if opts.identifier.is_some() || opts.entitlements.is_some() {
            return Err(usage_message(
                "--identifier and --entitlements require --sign-adhoc or --sign-p12",
            ));
        }
        return Ok(None);
    }

    let entitlements_xml = opts
        .entitlements
        .as_ref()
        .map(|path| {
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read entitlements {}", path.display()))
        })
        .transpose()?;
    let request = SignatureRequest {
        identifier: opts.identifier.clone(),
        entitlements_xml,
    };

    let provider = if let Some(path) = &opts.sign_p12 {
        let pkcs12 = std::fs::read(path)
            .with_context(|| format!("failed to read PKCS#12 identity {}", path.display()))?;
        let password = match &opts.p12_password_file {
            Some(password_path) => {
                let password = std::fs::read_to_string(password_path).with_context(|| {
                    format!(
                        "failed to read PKCS#12 password file {}",
                        password_path.display()
                    )
                })?;
                strip_one_line_ending(password)
            }
            None => String::new(),
        };
        InProcessSignatureProvider::from_pkcs12(&pkcs12, &password)?
    } else {
        InProcessSignatureProvider::adhoc()
    };
    provider.validate_request(&request)?;

    Ok(Some(SigningConfig { provider, request }))
}

fn strip_one_line_ending(mut value: String) -> String {
    if value.ends_with('\n') {
        value.pop();
        if value.ends_with('\r') {
            value.pop();
        }
    }
    value
}

fn parse_offset(s: &str) -> Result<u64> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16)
            .map_err(|error| usage_message(format!("invalid hex offset {s}: {error}")))
    } else {
        s.parse::<u64>()
            .map_err(|error| usage_message(format!("invalid offset {s}: {error}")))
    }
}

fn parse_hex_bytes(hex: &str) -> Result<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return Err(usage_message(format!(
            "hex string must have even length, got {}",
            hex.len()
        )));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16).map_err(|error| {
                usage_message(format!(
                    "invalid hex byte at position {i} ({:?}): {error}",
                    &hex[i..i + 2]
                ))
            })
        })
        .collect()
}

fn parse_patch_bytes_spec(spec: &str) -> Result<(u64, Vec<u8>)> {
    let Some((offset, hex)) = spec.split_once(':') else {
        return Err(usage_message(format!(
            "invalid patch-bytes spec '{spec}', expected OFFSET:HEX"
        )));
    };
    Ok((parse_offset(offset)?, parse_hex_bytes(hex)?))
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

fn prepare_patch(
    macho: &MachoFile<'_>,
    ops: &[PatchOp],
    signing: Option<&SigningConfig>,
) -> Result<PreparedPatch> {
    let analysis = AnalysisPlan::new([
        AnalysisDomain::Header,
        AnalysisDomain::LoadCommands,
        AnalysisDomain::Segments,
        AnalysisDomain::Codesign,
    ]);
    let workflow_signing = signing.map(|config| WorkflowSigning {
        provider: &config.provider,
        request: &config.request,
    });
    let result = macho::workflow::execute(
        macho.bytes(),
        &PatchPlan::new(ops.to_vec()),
        &analysis,
        workflow_signing,
    )?;
    Ok(PreparedPatch {
        preview: result.preview.structural,
        bytes: result.bytes,
    })
}

fn emit_preview(items: &[(&str, &PreparedPatch)], dry_run: bool, out: &mut dyn Write) {
    let _ = write!(out, "{}", format_preview(items, dry_run));
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
            SignatureOutcome::SignedAdHoc => {
                output.push_str("\nCode signature: verified ad-hoc signature applied.\n");
            }
            SignatureOutcome::SignedCertificate => {
                output.push_str("\nCode signature: verified certificate signature applied.\n");
            }
            SignatureOutcome::SignedOpaque => {
                output.push_str("\nCode signature: opaque provider signature applied.\n");
            }
            _ => output.push_str("\nWarning: signature outcome is unknown.\n"),
        }
    }

    output
}

fn has_raw_byte_patch(ops: &[PatchOp]) -> bool {
    ops.iter()
        .any(|op| matches!(op, PatchOp::PatchBytes { .. }))
}

fn select_fat_arch_indices(
    fat: &crate::model::container::FatBinary<'_>,
    arch_filter: Option<&str>,
) -> Result<Vec<usize>> {
    let selected: Vec<usize> = fat
        .arches()
        .iter()
        .enumerate()
        .filter_map(|(index, arch)| {
            let arch_name = arch.spec().name();
            match arch_filter {
                Some(filter) if !arch_name.eq_ignore_ascii_case(filter) => None,
                _ => Some(index),
            }
        })
        .collect();

    if selected.is_empty()
        && let Some(filter) = arch_filter
    {
        let available: Vec<String> = fat.arches().iter().map(|arch| arch.spec().name()).collect();
        return Err(input_message(format!(
            "no architecture matching '{filter}' found (available: {})",
            available.join(", ")
        )));
    }

    Ok(selected)
}

fn validation_errors_for_mach(macho: &MachoFile<'_>) -> Vec<String> {
    validate::validate(macho)
        .into_iter()
        .filter(|diag| diag.severity == validate::Severity::Error)
        .map(|diag| format!("{}: {}", diag.code.0, diag.message))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mutate::preview::StructuralPatchPreview;

    fn prepared_patch(operations: Vec<&str>, signature_outcome: SignatureOutcome) -> PreparedPatch {
        PreparedPatch {
            preview: StructuralPatchPreview {
                operations: operations.into_iter().map(str::to_owned).collect(),
                old_command_count: 10,
                new_command_count: 11,
                validation_errors: Vec::new(),
                validation_warnings: Vec::new(),
                signature_outcome,
                resign_plan: None,
            },
            bytes: Vec::new(),
        }
    }

    #[test]
    fn format_preview_surfaces_structure_and_signature_invalidation() {
        let prepared = prepared_patch(vec!["add rpath: /tmp/test"], SignatureOutcome::Invalidated);

        let output = format_preview(&[("arm64e", &prepared)], true);

        assert!(output.contains("Dry run - changes that would be applied:"));
        assert!(output.contains("add rpath: /tmp/test"));
        assert!(output.contains("Warning: code signature will be invalidated."));
    }

    #[test]
    fn format_preview_reports_unsigned_output_when_signature_removed() {
        let prepared = prepared_patch(vec!["remove code signature"], SignatureOutcome::Removed);

        let output = format_preview(&[("arm64e", &prepared)], true);

        assert!(output.contains("remove code signature"));
        assert!(output.contains("Code signature will be removed; output will be unsigned."));
    }

    #[test]
    fn failed_atomic_replace_preserves_destination_and_removes_temporary_file() {
        let root = std::env::temp_dir().join(format!(
            "macho-atomic-write-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let destination = root.join("destination");
        std::fs::create_dir_all(&destination).expect("create destination directory");
        let permissions = std::fs::metadata(&destination)
            .expect("destination metadata")
            .permissions();

        atomic_write(&destination, b"candidate", permissions)
            .expect_err("a file cannot atomically replace a directory");
        assert!(destination.is_dir());
        let entries = std::fs::read_dir(&root)
            .expect("read temporary root")
            .collect::<std::io::Result<Vec<_>>>()
            .expect("directory entries");
        assert_eq!(entries.len(), 1, "temporary file was not cleaned up");
        assert_eq!(entries[0].path(), destination);

        std::fs::remove_dir_all(root).expect("remove temporary root");
    }

    #[test]
    fn password_file_removes_only_one_terminal_line_ending() {
        assert_eq!(strip_one_line_ending("secret\n".into()), "secret");
        assert_eq!(strip_one_line_ending("secret\r\n".into()), "secret");
        assert_eq!(strip_one_line_ending("secret\n\n".into()), "secret\n");
        assert_eq!(strip_one_line_ending(" secret ".into()), " secret ");
    }
}
