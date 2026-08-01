use crate::analysis::{AnalysisDomain, AnalysisPlan};
use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::model::container::MachoContainer;
use crate::model::macho_file::MachoFile;
use crate::model::validate;
use crate::mutate::AddSection;
use crate::mutate::PatchOp;
use crate::mutate::owned::OwnedFatBinary;
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

mod executable;
mod spec;
use executable::*;
use spec::*;

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
    /// Overwrite bytes using OFFSET,EXPECTED_HEX,REPLACEMENT_HEX
    #[arg(long = "bytes", action = ArgAction::Append)]
    patch_bytes: Vec<String>,
    /// Add file-backed section SEGMENT,SECTION,ALIGN_EXPONENT,PATH
    #[arg(long = "add-section", action = ArgAction::Append, value_name = "SPEC")]
    add_section: Vec<String>,
    /// Add zero-fill section SEGMENT,SECTION,ALIGN_EXPONENT,SIZE
    #[arg(long = "add-zerofill-section", action = ArgAction::Append, value_name = "SPEC")]
    add_zerofill_section: Vec<String>,
    /// Patch a function entry with a branch: ENTRY_VA,DESTINATION_VA,OVERWRITE_LEN
    #[arg(long = "detour", action = ArgAction::Append, value_name = "SPEC")]
    detour: Vec<String>,
    #[command(flatten)]
    signing: SigningOpts,
    #[command(flatten)]
    output: OutputOpts,
}

struct SlicePrepared {
    prepared: PreparedPatch,
    details: Vec<OperationDetail>,
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
    let mut requests = Vec::new();
    for rpath in args.add_rpath {
        requests.push(PatchRequest::Operation(PatchOp::AddRpath(rpath)));
    }
    for rpath in args.remove_rpath {
        requests.push(PatchRequest::Operation(PatchOp::RemoveRpath(rpath)));
    }
    for dylib in args.add_dylib {
        requests.push(PatchRequest::Operation(PatchOp::AddDylib {
            name: dylib,
            compat_version: 0x10000,
            current_version: 0x10000,
        }));
    }
    if args.strip_signature {
        requests.push(PatchRequest::Operation(PatchOp::RemoveCodeSignature));
    }
    for spec in args.patch_bytes {
        let (offset, expected, replacement) = parse_patch_bytes_spec(&spec)?;
        requests.push(PatchRequest::RawBytes {
            offset,
            expected,
            replacement,
        });
    }
    for spec in args.add_section {
        let (segment, section, alignment, path) = parse_file_section_spec(&spec)?;
        let payload = input_result(
            std::fs::read(&path),
            format!("failed to read section payload {}", path.display()),
        )?;
        requests.push(PatchRequest::FileSection {
            segment,
            section,
            alignment,
            path,
            payload,
        });
    }
    for spec in args.add_zerofill_section {
        let (segment, section, alignment, size) = parse_zerofill_section_spec(&spec)?;
        requests.push(PatchRequest::ZeroFillSection {
            segment,
            section,
            alignment,
            size,
        });
    }
    for spec in args.detour {
        let (entry_va, destination_va, overwrite_len) = parse_detour_spec(&spec)?;
        requests.push(PatchRequest::Detour {
            entry_va,
            destination_va,
            overwrite_len,
        });
    }
    if requests.is_empty() && signing.is_none() {
        return Err(usage_message("no patch operations specified"));
    }

    run_patch(
        &args.input.path,
        args.selection.arch.as_deref(),
        &args.output,
        &requests,
        signing.as_ref(),
        format,
        out,
    )
}

fn run_patch(
    input: &Path,
    arch_filter: Option<&str>,
    opts: &OutputOpts,
    requests: &[PatchRequest],
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
                if !macho.header().arch_spec().matches_selector(filter) {
                    return Err(input_message(format!(
                        "no architecture matching '{filter}' found (available: {arch_name})"
                    )));
                }
            }

            let prepared = prepare_patch(macho, requests, signing)?;
            let arch_name = arch_name_for_mach(macho);
            if format == OutputFormat::Text {
                emit_preview(&[(&arch_name, &prepared)], opts.dry_run, out);
            }
            if !prepared.prepared.preview.validation_errors.is_empty() {
                let details = prepared.prepared.preview.validation_errors.join("\n  ");
                anyhow::bail!("candidate binary has validation errors:\n  {details}");
            }
            (
                prepared.prepared.bytes,
                vec![(arch_name, prepared.prepared.preview, prepared.details)],
            )
        }
        MachoContainer::Fat(fat) => {
            if arch_filter.is_none() && has_slice_local_patch(requests) {
                anyhow::bail!(
                    "raw byte or executable patching a fat binary requires --arch with one explicit exact architecture because offsets and addresses are slice-relative"
                );
            }

            let selected = select_fat_arch_indices(fat, arch_filter)?;
            if has_slice_local_patch(requests) {
                let filter = arch_filter.expect("slice-local fat operation requires an arch");
                if selected.len() != 1
                    || !fat.arches()[selected[0]]
                        .spec()
                        .name()
                        .eq_ignore_ascii_case(filter)
                {
                    let matched = selected
                        .iter()
                        .map(|index| fat.arches()[*index].spec().name())
                        .collect::<Vec<_>>()
                        .join(", ");
                    anyhow::bail!(
                        "slice-local raw byte and executable patching requires one exact --arch value; '{filter}' resolved to: {matched}"
                    );
                }
            }
            let prepared: Vec<(usize, String, SlicePrepared)> = selected
                .iter()
                .copied()
                .map(|index| {
                    let arch = &fat.arches()[index];
                    Ok((
                        index,
                        arch.spec().name(),
                        prepare_patch(arch.macho(), requests, signing)?,
                    ))
                })
                .collect::<Result<_>>()?;

            let preview_items: Vec<(&str, &SlicePrepared)> = prepared
                .iter()
                .map(|(_, arch_name, prepared)| (arch_name.as_str(), prepared))
                .collect();
            if format == OutputFormat::Text {
                emit_preview(&preview_items, opts.dry_run, out);
            }
            if prepared
                .iter()
                .any(|(_, _, prepared)| !prepared.prepared.preview.validation_errors.is_empty())
            {
                let details: Vec<String> = prepared
                    .iter()
                    .flat_map(|(_, arch_name, prepared)| {
                        prepared
                            .prepared
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
                owned.replace_arch(*index, prepared.prepared.bytes.clone())?;
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
                    .map(|(_, arch, prepared)| (arch, prepared.prepared.preview, prepared.details))
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

fn preview_report(
    previews: &[(String, StructuralPatchPreview, Vec<OperationDetail>)],
) -> Vec<serde_json::Value> {
    previews
        .iter()
        .map(|(arch, preview, details)| {
            serde_json::json!({
                "arch": arch,
                "preview": preview,
                "operation_details": details,
            })
        })
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
    let mut request = SignatureRequest::new();
    if let Some(identifier) = &opts.identifier {
        request = request.with_identifier(identifier);
    }
    if let Some(entitlements_xml) = entitlements_xml {
        request = request.with_entitlements_xml(entitlements_xml);
    }

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
    requests: &[PatchRequest],
    signing: Option<&SigningConfig>,
) -> Result<SlicePrepared> {
    let mut ops = Vec::new();
    let mut expected = Vec::new();
    let mut details = Vec::new();
    let mut section_requests = Vec::new();

    for request in requests {
        match request {
            PatchRequest::Operation(op) => ops.push(op.clone()),
            PatchRequest::RawBytes {
                offset,
                expected: original,
                replacement,
            } => {
                ops.push(PatchOp::PatchBytes {
                    offset: *offset,
                    bytes: replacement.clone(),
                });
                expected.push((*offset, original.clone()));
                details.push(Some(OperationDetail::RawBytes {
                    offset: *offset,
                    expected_bytes: encode_hex(original),
                    replacement_bytes: encode_hex(replacement),
                }));
            }
            PatchRequest::FileSection {
                segment,
                section,
                alignment,
                path,
                payload,
            } => {
                let add = AddSection::new(segment, section, payload)
                    .and_then(|request| request.with_alignment(*alignment))?;
                ops.push(PatchOp::AddSection(add));
                let detail_index = details.len();
                details.push(None);
                section_requests.push((
                    detail_index,
                    segment.as_str(),
                    section.as_str(),
                    "file_backed",
                    Some(path.clone()),
                ));
            }
            PatchRequest::ZeroFillSection {
                segment,
                section,
                alignment,
                size,
            } => {
                let add = AddSection::zero_fill(segment, section, *size)
                    .and_then(|request| request.with_alignment(*alignment))?;
                ops.push(PatchOp::AddSection(add));
                let detail_index = details.len();
                details.push(None);
                section_requests.push((
                    detail_index,
                    segment.as_str(),
                    section.as_str(),
                    "zero_fill",
                    None,
                ));
            }
            PatchRequest::Detour {
                entry_va,
                destination_va,
                overwrite_len,
            } => {
                let (plan, instruction_count) =
                    plan_detour(macho, *entry_va, *destination_va, *overwrite_len)?;
                let offset = u64::try_from(plan.entry_offset)
                    .map_err(|_| usage_message("detour file offset exceeds u64"))?;
                ops.push(PatchOp::PatchBytes {
                    offset,
                    bytes: plan.patch_bytes.clone(),
                });
                expected.push((offset, plan.original_bytes.clone()));
                details.push(Some(detour_detail(&plan, instruction_count)));
            }
        }
    }

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
    let mut patch_plan = PatchPlan::new(ops);
    for (offset, bytes) in expected {
        patch_plan = patch_plan.expect_bytes(offset, bytes);
    }
    let result = macho::workflow::execute(macho.bytes(), &patch_plan, &analysis, workflow_signing)?;
    let prepared = PreparedPatch {
        preview: result.preview.structural,
        bytes: result.bytes,
    };
    let reparsed = macho::parse(&prepared.bytes).context("failed to reparse prepared slice")?;
    let candidate = reparsed
        .first_macho()
        .ok_or_else(|| input_message("prepared slice contains no Mach-O image"))?;
    for (index, segment, section, content, source) in section_requests {
        details[index] = Some(section_detail(
            candidate, segment, section, content, source,
        )?);
    }
    let details = details
        .into_iter()
        .map(|detail| detail.expect("every deferred operation detail is filled"))
        .collect();
    Ok(SlicePrepared { prepared, details })
}

fn section_detail(
    macho: &MachoFile<'_>,
    segment_name: &str,
    section_name: &str,
    content: &'static str,
    source: Option<PathBuf>,
) -> Result<OperationDetail> {
    let segments = macho
        .segments()
        .iter()
        .filter(|segment| segment.name() == segment_name)
        .collect::<Vec<_>>();
    let [segment] = segments.as_slice() else {
        anyhow::bail!(
            "prepared candidate does not contain one unambiguous segment named {segment_name}"
        );
    };
    let sections = segment
        .sections()
        .iter()
        .filter(|section| section.section_name() == section_name)
        .collect::<Vec<_>>();
    let [section] = sections.as_slice() else {
        anyhow::bail!(
            "prepared candidate does not contain one unambiguous section {segment_name},{section_name}"
        );
    };
    Ok(OperationDetail::Section {
        segment: segment_name.to_owned(),
        section: section_name.to_owned(),
        content,
        source,
        address: section.addr().0,
        file_offset: if section.section_type().is_zerofill() {
            None
        } else {
            Some(section.offset().0)
        },
        size: section.size(),
        section_type: section.section_type().name().to_owned(),
        alignment_exponent: section.align(),
    })
}

fn emit_preview(items: &[(&str, &SlicePrepared)], dry_run: bool, out: &mut dyn Write) {
    let _ = write!(out, "{}", format_preview(items, dry_run));
}

fn format_preview(items: &[(&str, &SlicePrepared)], dry_run: bool) -> String {
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

        for op in &prepared.prepared.preview.operations {
            output.push_str(&format!("  {op}\n"));
        }
        for detail in &prepared.details {
            output.push_str(&format_operation_detail(detail));
        }
        output.push_str(&format!(
            "Load commands: {} -> {}\n",
            prepared.prepared.preview.old_command_count,
            prepared.prepared.preview.new_command_count
        ));
        if !prepared.prepared.preview.validation_errors.is_empty() {
            output.push_str("Validation errors:\n");
            for e in &prepared.prepared.preview.validation_errors {
                output.push_str(&format!("  {e}\n"));
            }
        }
        if !prepared.prepared.preview.validation_warnings.is_empty() {
            output.push_str("Validation warnings:\n");
            for w in &prepared.prepared.preview.validation_warnings {
                output.push_str(&format!("  {w}\n"));
            }
        }
        match prepared.prepared.preview.signature_outcome {
            SignatureOutcome::Unchanged => {}
            SignatureOutcome::Invalidated => {
                output.push_str("\nWarning: code signature will be invalidated.\n");
                if let Some(plan) = &prepared.prepared.preview.resign_plan {
                    output.push_str(&plan.to_string());
                }
            }
            SignatureOutcome::Removed => {
                output.push_str("\nCode signature will be removed; output will be unsigned.\n");
                if let Some(plan) = &prepared.prepared.preview.resign_plan {
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

fn has_slice_local_patch(requests: &[PatchRequest]) -> bool {
    requests.iter().any(|request| {
        matches!(
            request,
            PatchRequest::RawBytes { .. } | PatchRequest::Detour { .. }
        )
    })
}

fn select_fat_arch_indices(
    fat: &crate::model::container::FatBinary<'_>,
    arch_filter: Option<&str>,
) -> Result<Vec<usize>> {
    let selected: Vec<usize> = fat
        .arches()
        .iter()
        .enumerate()
        .filter_map(|(index, arch)| match arch_filter {
            Some(filter) if !arch.spec().matches_selector(filter) => None,
            _ => Some(index),
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

    fn prepared_patch(operations: Vec<&str>, signature_outcome: SignatureOutcome) -> SlicePrepared {
        SlicePrepared {
            prepared: PreparedPatch {
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
            },
            details: Vec::new(),
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

    #[test]
    fn raw_bytes_require_exact_equal_length_precondition() {
        assert_eq!(
            parse_patch_bytes_spec("0x20,0011,aabb").expect("valid"),
            (0x20, vec![0, 0x11], vec![0xaa, 0xbb])
        );
        assert!(parse_patch_bytes_spec("0x20,aabb").is_err());
        assert!(parse_patch_bytes_spec("0x20,00,aabb").is_err());
        assert!(parse_patch_bytes_spec("0x20,,").is_err());
    }

    #[test]
    fn section_specs_are_explicit_and_validate_alignment_later() {
        let parsed = parse_file_section_spec("__LINKEDIT,__meta,3,/tmp/a,b").expect("valid");
        assert_eq!(parsed.0, "__LINKEDIT");
        assert_eq!(parsed.1, "__meta");
        assert_eq!(parsed.2, 3);
        assert_eq!(parsed.3, PathBuf::from("/tmp/a,b"));
        assert!(parse_file_section_spec("__DATA,__x,/tmp/data").is_err());

        let parsed = parse_zerofill_section_spec("__DATA,__scratch,4,0x20").expect("valid");
        assert_eq!(parsed.3, 0x20);
        assert!(parse_zerofill_section_spec("__DATA,__scratch,4,0").is_err());
    }
}
