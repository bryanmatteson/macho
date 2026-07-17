use anyhow::{Context, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::adapters::XcrunClangValidator;
use crate::analysis::reconstruct::{
    BundleValidationReport, EvidenceBundle, HeaderInferenceSession, ModelOutput, PromptSet,
    ValidationReport, validate_bundle,
};
use crate::commands::OutputFormat;
use crate::commands::subcommands::common::read_input_string;
use crate::commands::{input_message, input_result};

#[derive(clap::Args)]
/// The HeaderInferArgs type.
pub struct HeaderInferArgs {
    #[command(subcommand)]
    action: HeaderInferAction,
}

#[derive(clap::Subcommand)]
enum HeaderInferAction {
    /// Inspect an evidence bundle
    Inspect { bundle: PathBuf },
    /// Validate an evidence bundle before prompting a model
    CheckBundle { bundle: PathBuf },
    /// Emit the prompt set for a bundle
    Prompt { bundle: PathBuf },
    /// Validate a model response against a bundle
    Validate { bundle: PathBuf, response: PathBuf },
    /// Apply a model response and emit header plus sidecar
    Apply {
        bundle: PathBuf,
        response: PathBuf,
        #[arg(long)]
        header_out: Option<PathBuf>,
        #[arg(long)]
        sidecar_out: Option<PathBuf>,
    },
}

/// Performs run.
pub fn run(args: HeaderInferArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let json = format == OutputFormat::Json;
    match args.action {
        HeaderInferAction::Inspect { bundle } => {
            let bundle = read_bundle(&bundle)?;
            if json {
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&bundle)?);
            } else {
                print_bundle_summary(&bundle, out);
            }
        }
        HeaderInferAction::CheckBundle { bundle } => {
            let bundle = read_bundle(&bundle)?;
            let report = validate_bundle(&bundle);
            if json {
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_bundle_validation_report(&report, out);
            }
            fail_if_invalid_bundle(&report)?;
        }
        HeaderInferAction::Prompt { bundle } => {
            let session = HeaderInferenceSession::new(read_bundle(&bundle)?);
            let prompt = session.prompt()?;
            if json {
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&prompt)?);
            } else {
                print_prompt(&prompt, out);
            }
        }
        HeaderInferAction::Validate { bundle, response } => {
            let session = HeaderInferenceSession::new(read_bundle(&bundle)?);
            let output = read_model_output(&session, &response)?;
            let validators = validators();
            let report = session.validate(&output, &validators)?;
            if json {
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_validation_report(&report, out);
            }
            fail_if_invalid_validation(&report)?;
        }
        HeaderInferAction::Apply {
            bundle,
            response,
            header_out,
            sidecar_out,
        } => {
            let session = HeaderInferenceSession::new(read_bundle(&bundle)?);
            let output = read_model_output(&session, &response)?;
            let validators = validators();
            let sidecar = session.apply(output, &validators)?;

            if let Some(path) = header_out.as_ref() {
                std::fs::write(path, &sidecar.generated_header)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }

            if let Some(path) = sidecar_out.as_ref() {
                let encoded = serde_json::to_vec_pretty(&sidecar)?;
                std::fs::write(path, encoded)
                    .with_context(|| format!("failed to write {}", path.display()))?;
            }

            if json {
                let _ = writeln!(out, "{}", serde_json::to_string_pretty(&sidecar)?);
            } else {
                print_validation_report(&sidecar.validation, out);
                let _ = writeln!(out, "Header: {}", sidecar.header_name);
                let _ = writeln!(out, "Valid: {}", sidecar.valid);
                if header_out.is_none() {
                    let _ = writeln!(out,);
                    let _ = writeln!(out, "{}", sidecar.generated_header);
                }
            }
            fail_if_invalid_validation(&sidecar.validation)?;
        }
    }

    Ok(())
}

fn read_bundle(path: &Path) -> Result<EvidenceBundle> {
    let data = read_input_string(path)?;
    let bundle: EvidenceBundle = input_result(
        serde_json::from_str(&data),
        format!("failed to parse {}", path.display()),
    )?;
    Ok(bundle)
}

fn read_model_output(session: &HeaderInferenceSession, path: &Path) -> Result<ModelOutput> {
    let data = read_input_string(path)?;
    let output = input_result(
        session.parse_model_output(&data),
        format!("failed to parse {}", path.display()),
    )?;
    Ok(output)
}

fn validators() -> [&'static dyn crate::analysis::reconstruct::ModelOutputValidator; 1] {
    static CLANG: XcrunClangValidator = XcrunClangValidator;
    [&CLANG]
}

fn print_bundle_summary(bundle: &EvidenceBundle, out: &mut dyn Write) {
    let report = validate_bundle(bundle);
    let _ = writeln!(
        out,
        "Bundle {} ({})",
        bundle.header_unit.name,
        bundle.header_unit.language.prompt_name()
    );
    let _ = writeln!(out, "  target ABI: {}", bundle.header_unit.target_abi);
    if let Some(module) = &bundle.header_unit.module {
        let _ = writeln!(out, "  module: {module}");
    }
    let _ = writeln!(out, "  entities: {}", bundle.entities.len());
    let _ = writeln!(out, "  unresolved gaps: {}", bundle.unresolved.len());
    let _ = writeln!(
        out,
        "  validation targets: {}",
        bundle.validation_targets.len()
    );
    let _ = writeln!(out, "  bundle valid: {}", report.valid);
}

fn print_bundle_validation_report(
    report: &crate::analysis::reconstruct::BundleValidationReport,
    out: &mut dyn Write,
) {
    let _ = writeln!(out, "valid: {}", report.valid);
    if report.issues.is_empty() {
        let _ = writeln!(out, "issues: none");
        return;
    }
    let _ = writeln!(out, "issues:");
    for issue in &report.issues {
        let _ = writeln!(out, "  - {} {}", issue.code, issue.message);
    }
}

fn fail_if_invalid_bundle(report: &BundleValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    Err(input_message("evidence bundle validation failed"))
}

fn fail_if_invalid_validation(report: &ValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    Err(input_message("header inference validation failed"))
}

fn print_prompt(prompt: &PromptSet, out: &mut dyn Write) {
    let _ = writeln!(out, "== system ==");
    let _ = writeln!(out, "{}", prompt.system);
    let _ = writeln!(out,);
    let _ = writeln!(out, "== user ==");
    let _ = writeln!(out, "{}", prompt.user);
}

fn print_validation_report(
    report: &crate::analysis::reconstruct::ValidationReport,
    out: &mut dyn Write,
) {
    let _ = writeln!(out, "valid: {}", report.valid);
    let _ = writeln!(out, "syntax checked: {}", report.syntax_checked);
    let _ = writeln!(out, "syntax ok: {}", report.syntax_ok);
    if report.issues.is_empty() {
        let _ = writeln!(out, "issues: none");
        return;
    }
    let _ = writeln!(out, "issues:");
    for issue in &report.issues {
        if let Some(entity_id) = &issue.entity_id {
            let _ = writeln!(
                out,
                "  - [{:?}] {} {} ({entity_id})",
                issue.severity, issue.code, issue.message
            );
        } else {
            let _ = writeln!(
                out,
                "  - [{:?}] {} {}",
                issue.severity, issue.code, issue.message
            );
        }
    }
}
