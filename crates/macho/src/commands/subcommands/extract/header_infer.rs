use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;

use crate::extract::headers::{
    BundleValidationReport, ClangSyntaxValidator, EvidenceBundle, HeaderInferenceSession,
    ModelOutput, PromptSet, ValidationReport, validate_bundle,
};

macro_rules! println {
    ($($arg:tt)*) => {
        crate::outln!($($arg)*)
    };
}

#[derive(clap::Args)]
pub struct HeaderInferArgs {
    #[command(subcommand)]
    action: HeaderInferAction,
}

#[derive(clap::Subcommand)]
enum HeaderInferAction {
    /// Inspect an evidence bundle
    Inspect {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate an evidence bundle before prompting a model
    CheckBundle {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Emit the prompt set for a bundle
    Prompt {
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Validate a model response against a bundle
    Validate {
        bundle: PathBuf,
        response: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Apply a model response and emit header plus sidecar
    Apply {
        bundle: PathBuf,
        response: PathBuf,
        #[arg(long)]
        header_out: Option<PathBuf>,
        #[arg(long)]
        sidecar_out: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

pub fn run(args: HeaderInferArgs) -> Result<()> {
    match args.action {
        HeaderInferAction::Inspect { bundle, json } => {
            let bundle = read_bundle(&bundle)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&bundle)?);
            } else {
                print_bundle_summary(&bundle);
            }
        }
        HeaderInferAction::CheckBundle { bundle, json } => {
            let bundle = read_bundle(&bundle)?;
            let report = validate_bundle(&bundle);
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_bundle_validation_report(&report);
            }
            fail_if_invalid_bundle(&report)?;
        }
        HeaderInferAction::Prompt { bundle, json } => {
            let session = HeaderInferenceSession::new(read_bundle(&bundle)?);
            let prompt = session.prompt()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&prompt)?);
            } else {
                print_prompt(&prompt);
            }
        }
        HeaderInferAction::Validate {
            bundle,
            response,
            json,
        } => {
            let session = HeaderInferenceSession::new(read_bundle(&bundle)?);
            let output = read_model_output(&session, &response)?;
            let validators = validators();
            let report = session.validate(&output, &validators)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print_validation_report(&report);
            }
            fail_if_invalid_validation(&report)?;
        }
        HeaderInferAction::Apply {
            bundle,
            response,
            header_out,
            sidecar_out,
            json,
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
                println!("{}", serde_json::to_string_pretty(&sidecar)?);
            } else {
                print_validation_report(&sidecar.validation);
                println!("Header: {}", sidecar.header_name);
                println!("Valid: {}", sidecar.valid);
                if header_out.is_none() {
                    println!();
                    println!("{}", sidecar.generated_header);
                }
            }
            fail_if_invalid_validation(&sidecar.validation)?;
        }
    }

    Ok(())
}

fn read_bundle(path: &PathBuf) -> Result<EvidenceBundle> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let bundle: EvidenceBundle = serde_json::from_str(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    Ok(bundle)
}

fn read_model_output(session: &HeaderInferenceSession, path: &PathBuf) -> Result<ModelOutput> {
    let data = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let output = session.parse_model_output(&data)?;
    Ok(output)
}

fn validators() -> [&'static dyn crate::extract::headers::ModelOutputValidator; 1] {
    static CLANG: ClangSyntaxValidator = ClangSyntaxValidator;
    [&CLANG]
}

fn print_bundle_summary(bundle: &EvidenceBundle) {
    let report = validate_bundle(bundle);
    println!(
        "Bundle {} ({})",
        bundle.header_unit.name,
        bundle.header_unit.language.prompt_name()
    );
    println!("  target ABI: {}", bundle.header_unit.target_abi);
    if let Some(module) = &bundle.header_unit.module {
        println!("  module: {module}");
    }
    println!("  entities: {}", bundle.entities.len());
    println!("  unresolved gaps: {}", bundle.unresolved.len());
    println!("  validation targets: {}", bundle.validation_targets.len());
    println!("  bundle valid: {}", report.valid);
}

fn print_bundle_validation_report(report: &crate::extract::headers::BundleValidationReport) {
    println!("valid: {}", report.valid);
    if report.issues.is_empty() {
        println!("issues: none");
        return;
    }
    println!("issues:");
    for issue in &report.issues {
        println!("  - {} {}", issue.code, issue.message);
    }
}

fn fail_if_invalid_bundle(report: &BundleValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    std::io::stdout().flush()?;
    anyhow::bail!("evidence bundle validation failed");
}

fn fail_if_invalid_validation(report: &ValidationReport) -> Result<()> {
    if report.valid {
        return Ok(());
    }
    std::io::stdout().flush()?;
    anyhow::bail!("header inference validation failed");
}

fn print_prompt(prompt: &PromptSet) {
    println!("== system ==");
    println!("{}", prompt.system);
    println!();
    println!("== user ==");
    println!("{}", prompt.user);
}

fn print_validation_report(report: &crate::extract::headers::ValidationReport) {
    println!("valid: {}", report.valid);
    println!("syntax checked: {}", report.syntax_checked);
    println!("syntax ok: {}", report.syntax_ok);
    if report.issues.is_empty() {
        println!("issues: none");
        return;
    }
    println!("issues:");
    for issue in &report.issues {
        if let Some(entity_id) = &issue.entity_id {
            println!(
                "  - [{:?}] {} {} ({entity_id})",
                issue.severity, issue.code, issue.message
            );
        } else {
            println!(
                "  - [{:?}] {} {}",
                issue.severity, issue.code, issue.message
            );
        }
    }
}
