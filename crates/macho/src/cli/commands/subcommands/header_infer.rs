//! Offline header-hypothesis artifact exchange.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::analysis::report::{Architecture, RecoveryGapId, RecoveryReport, RecoverySchemaVersion};
use crate::header_infer::{
    HypothesisBundle, HypothesisDisposition, HypothesisLimits, HypothesisReport, ModelResponse,
    build_prompt, export_bundle, validate_response,
};
use anyhow::{Context, Result, bail};

use crate::cli::commands::output::layout;
use crate::cli::commands::output::{ColorChoice, Format, Options as OutputOptions};
use crate::cli::commands::subcommands::common::read_input_string;
use crate::cli::commands::{input_message, input_result, usage_message};

#[derive(clap::Args)]
/// Export, inspect, prompt, validate, and apply offline hypothesis artifacts.
pub struct HeaderInferArgs {
    #[command(subcommand)]
    action: HeaderInferAction,
}

#[derive(clap::Subcommand)]
enum HeaderInferAction {
    /// Export explicit recovery gaps into one bounded offline bundle.
    Export {
        /// Common JSON envelope produced by `macho c` or `macho cpp`.
        recovery_json: PathBuf,
        /// Exact architecture name from the recovery report.
        #[arg(long)]
        arch: String,
        /// Explicit gap ID; repeat for each requested gap.
        #[arg(long, required = true)]
        gap: Vec<String>,
        /// Destination bundle path.
        #[arg(long)]
        output: PathBuf,
    },
    /// Inspect bounded targets, facts, evidence, constraints, and limits.
    Inspect {
        /// Hypothesis bundle path.
        bundle: PathBuf,
    },
    /// Validate bundle schema, digest, bounds, and references.
    CheckBundle {
        /// Hypothesis bundle path.
        bundle: PathBuf,
    },
    /// Emit a deterministic provider-neutral prompt.
    Prompt {
        /// Hypothesis bundle path.
        bundle: PathBuf,
        /// Optional prompt destination; stdout when omitted.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Validate one strict response against one exact bundle.
    Validate {
        /// Hypothesis bundle path.
        bundle: PathBuf,
        /// ModelResponse JSON path.
        response: PathBuf,
    },
    /// Revalidate and emit hypothesis-assisted header source and optional sidecar.
    Apply {
        /// Hypothesis bundle path.
        bundle: PathBuf,
        /// ModelResponse JSON path.
        response: PathBuf,
        /// Optional header destination; stdout when omitted.
        #[arg(long)]
        header_out: Option<PathBuf>,
        /// Optional immutable HypothesisReport sidecar destination.
        #[arg(long)]
        sidecar_out: Option<PathBuf>,
    },
}

/// Runs the offline artifact workflow.
pub fn run(args: HeaderInferArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    if output.format() == Format::Sarif {
        return Err(usage_message(
            "header-infer supports text and JSON only for inspect, check-bundle, and validate",
        ));
    }
    match args.action {
        HeaderInferAction::Export {
            recovery_json,
            arch,
            gap,
            output: destination,
        } => {
            require_artifact_output(output, "export")?;
            let report = read_recovery(&recovery_json)?;
            let architecture = architecture_by_name(&report, &arch)?;
            let gaps = gap
                .into_iter()
                .map(|value| {
                    RecoveryGapId::new(value)
                        .map_err(|error| input_message(format!("invalid --gap ID: {error}")))
                })
                .collect::<Result<Vec<_>>>()?;
            let bundle = export_bundle(&report, architecture, &gaps, HypothesisLimits::default())?;
            atomic_write(&destination, &bundle.canonical_bytes()?)?;
        }
        HeaderInferAction::Inspect { bundle } => {
            let bundle = read_bundle(&bundle)?;
            match output.format() {
                Format::Json => crate::cli::commands::output::json::write_pretty(out, &bundle)?,
                Format::Text => print_bundle(&bundle, output, out)?,
                Format::Sarif => unreachable!(),
            }
        }
        HeaderInferAction::CheckBundle { bundle } => {
            let bundle = read_bundle(&bundle)?;
            bundle.validate()?;
            match output.format() {
                Format::Json => crate::cli::commands::output::json::write_pretty(
                    out,
                    &serde_json::json!({
                        "valid": true,
                        "bundle_digest": bundle.bundle_digest(),
                    }),
                )?,
                Format::Text => writeln!(
                    out,
                    "{}  {}",
                    output.style().enum_value("valid"),
                    output
                        .style()
                        .property("bundle", bundle.bundle_digest().as_str()),
                )?,
                Format::Sarif => unreachable!(),
            }
        }
        HeaderInferAction::Prompt {
            bundle,
            output: destination,
        } => {
            require_artifact_output(output, "prompt")?;
            let prompt = build_prompt(&read_bundle(&bundle)?)?;
            if let Some(path) = destination {
                atomic_write(&path, prompt.as_bytes())?;
            } else {
                out.write_all(prompt.as_bytes())?;
            }
        }
        HeaderInferAction::Validate { bundle, response } => {
            let bundle = read_bundle(&bundle)?;
            let response = read_response(&response, bundle.limits())?;
            let report = validate_response(&bundle, &response)?;
            match output.format() {
                Format::Json => crate::cli::commands::output::json::write_pretty(out, &report)?,
                Format::Text => print_report(&report, output, out)?,
                Format::Sarif => unreachable!(),
            }
        }
        HeaderInferAction::Apply {
            bundle,
            response,
            header_out,
            sidecar_out,
        } => {
            require_artifact_output(output, "apply")?;
            let bundle = read_bundle(&bundle)?;
            let response = read_response(&response, bundle.limits())?;
            let report = validate_response(&bundle, &response)?;
            let header = report
                .projected_header
                .as_ref()
                .map(|projection| projection.source.as_str())
                .unwrap_or("/* hypothesis-assisted; no declarations accepted */\n");
            if let Some(path) = header_out {
                atomic_write(&path, header.as_bytes())?;
            } else {
                out.write_all(header.as_bytes())?;
            }
            if let Some(path) = sidecar_out {
                let bytes = crate::analysis::report::canonical_json(&report)?;
                atomic_write(&path, &bytes)?;
            }
        }
    }
    Ok(())
}

fn require_artifact_output(output: OutputOptions, command: &str) -> Result<()> {
    if output.format() != Format::Text {
        return Err(usage_message(format!(
            "header-infer {command} emits a fixed artifact format and does not accept --format"
        )));
    }
    if output.color() == ColorChoice::Always {
        return Err(usage_message(format!(
            "header-infer {command} does not accept --color always"
        )));
    }
    Ok(())
}

fn read_recovery(path: &Path) -> Result<RecoveryReport> {
    let text = read_input_string(path)?;
    let value: serde_json::Value = input_result(
        serde_json::from_str(&text),
        format!("failed to parse {}", path.display()),
    )?;
    let data = value
        .get("data")
        .cloned()
        .ok_or_else(|| input_message("recovery input is not a common JSON envelope"))?;
    let report: RecoveryReport = input_result(
        serde_json::from_value(data),
        format!("invalid recovery report in {}", path.display()),
    )?;
    if report.schema_version != RecoverySchemaVersion::CURRENT {
        bail!("unsupported recovery report schema");
    }
    report
        .validate()
        .map_err(|error| input_message(format!("invalid recovery report: {error}")))?;
    Ok(report)
}

fn read_bundle(path: &Path) -> Result<HypothesisBundle> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    HypothesisBundle::from_json(&bytes)
        .map_err(|error| input_message(format!("invalid bundle {}: {error}", path.display())))
}

fn read_response(path: &Path, limits: HypothesisLimits) -> Result<ModelResponse> {
    let bytes =
        std::fs::read(path).with_context(|| format!("failed to read {}", path.display()))?;
    ModelResponse::from_json(&bytes, limits)
        .map_err(|error| input_message(format!("invalid response {}: {error}", path.display())))
}

fn architecture_by_name(report: &RecoveryReport, name: &str) -> Result<Architecture> {
    report
        .slices
        .as_slice()
        .iter()
        .map(|slice| slice.architecture)
        .find(|architecture| architecture_name(*architecture) == name)
        .ok_or_else(|| input_message(format!("architecture `{name}` is absent from recovery")))
}

fn architecture_name(architecture: Architecture) -> String {
    crate::core::model::header::ArchSpec {
        cpu_type: crate::core::model::header::CpuType(architecture.cpu_type),
        cpu_subtype: crate::core::model::header::CpuSubtype(architecture.cpu_subtype),
    }
    .name()
}

fn print_bundle(
    bundle: &HypothesisBundle,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    writeln!(out, "{}", output.style().title("Header hypothesis bundle"))?;
    writeln!(
        out,
        "  {}  {}  {}  {}  {}",
        output
            .style()
            .enum_property("arch", &architecture_name(bundle.architecture())),
        output
            .style()
            .property("targets", &bundle.targets().len().to_string()),
        output
            .style()
            .property("facts", &bundle.facts().len().to_string()),
        output
            .style()
            .property("evidence", &bundle.evidence().len().to_string()),
        output
            .style()
            .property("digest", bundle.bundle_digest().as_str()),
    )?;
    let rows = bundle
        .targets()
        .iter()
        .flat_map(|target| {
            target.gap_ids.as_slice().iter().map(|gap| {
                vec![
                    output.style().enum_value_cell("target"),
                    output.style().accent_cell(&target.entity_id.as_str()[..12]),
                    output.style().property_cell("gap", &gap.as_str()[..12]),
                    output.style().property_cell(
                        "operations",
                        &target
                            .allowed_operations
                            .as_slice()
                            .iter()
                            .map(|operation| format!("{operation:?}").to_ascii_lowercase())
                            .collect::<Vec<_>>()
                            .join(","),
                    ),
                ]
            })
        })
        .collect::<Vec<_>>();
    for row in layout::align(&rows, output.style()) {
        writeln!(out, "  {row}")?;
    }
    Ok(())
}

fn print_report(
    report: &HypothesisReport,
    output: OutputOptions,
    out: &mut dyn Write,
) -> Result<()> {
    let rows = report
        .results
        .iter()
        .map(|result| {
            vec![
                output.style().enum_value_cell(match result.disposition {
                    HypothesisDisposition::Accepted => "accepted",
                    HypothesisDisposition::Rejected => "rejected",
                    HypothesisDisposition::Unresolved => "unresolved",
                }),
                output
                    .style()
                    .accent_cell(&result.hypothesis_id.as_str()[..12]),
                output
                    .style()
                    .property_cell("entity", &result.entity_id.as_str()[..12]),
                output
                    .style()
                    .property_cell("gap", &result.gap_id.as_str()[..12]),
                output
                    .style()
                    .property_cell("diagnostics", &result.diagnostics.len().to_string()),
            ]
        })
        .collect::<Vec<_>>();
    for row in layout::align(&rows, output.style()) {
        writeln!(out, "  {row}")?;
    }
    writeln!(
        out,
        "  {}  {}",
        output
            .style()
            .property("unresolved", &report.unresolved_gap_ids.len().to_string()),
        output.style().property(
            "header",
            if report.projected_header.is_some() {
                "projected"
            } else {
                "none"
            },
        ),
    )?;
    Ok(())
}

fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temporary = parent.join(format!(".{stem}.macho-{}-{nonce}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(bytes)
            .with_context(|| format!("failed to write {}", temporary.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to flush {}", temporary.display()))?;
        std::fs::rename(&temporary, path)
            .with_context(|| format!("failed to replace {}", path.display()))
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
