use crate::analysis::container::ContainerDocumentReport;
use crate::analysis::{AnalysisDomain, Analyzer, ContainerPlan};
use crate::commands::args::{AnalysisLimitArgs, ArchitectureArgs, InputArgs};
use anyhow::{Context, Result};
use std::io::Write;

use crate::commands::subcommands::common::map_input;
use crate::commands::{OutputFormat, usage_message};

#[derive(clap::Args)]
/// The ContainerArgs type.
pub struct ContainerArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    /// Filter to a specific architecture
    #[command(flatten)]
    selection: ArchitectureArgs,
    #[command(flatten)]
    limits: AnalysisLimitArgs,
    /// Show cross-image symbol resolution
    #[arg(long)]
    resolve: bool,
    /// Limit parity checks to a specific domain (repeatable: exports, imports, segments, codesign, objc)
    #[arg(long = "parity-domain")]
    parity_domains: Vec<String>,
}

/// Performs run.
pub fn run(args: ContainerArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    let mut parity_domains = parse_parity_domains(&args.parity_domains)?;
    if parity_domains.is_empty() {
        parity_domains = vec![
            AnalysisDomain::Exports,
            AnalysisDomain::Imports,
            AnalysisDomain::Segments,
            AnalysisDomain::Codesign,
            AnalysisDomain::Objc,
        ];
    }
    let requested = parity_domains
        .iter()
        .copied()
        .chain(args.resolve.then_some(AnalysisDomain::Imports))
        .chain(args.resolve.then_some(AnalysisDomain::Exports));
    let plan = ContainerPlan::new(requested).with_limits((&args.limits).into());
    let plan = if let Some(ref arch) = args.selection.arch {
        plan.with_slices([arch.clone()])
    } else {
        plan
    };
    let compiled = plan.compile();
    let document = Analyzer.run(&container, &compiled)?;
    let report = ContainerDocumentReport::from_document(&document, &parity_domains, args.resolve);

    if format == OutputFormat::Json {
        crate::commands::output::json::write_pretty(out, &report)?;
        return Ok(());
    }

    // Text output
    let _ = writeln!(out, "Container: {}", report.format);
    let _ = writeln!(out, "Architectures: {}", report.arches.join(", "));

    let divergences = report.parity.divergences.len();
    if divergences == 0 {
        let _ = writeln!(out, "\nParity: all arches in agreement");
    } else {
        let _ = writeln!(out, "\nParity divergences ({divergences}):");
        for domain in &report.parity.divergences {
            let _ = writeln!(out, "  [{}] domain states differ", domain.domain.as_str());
            for (arch, state) in &domain.per_arch {
                let _ = writeln!(out, "    {arch}: {state}");
            }
        }
    }
    if args.resolve
        && let Some(inputs) = &report.resolution_inputs
    {
        let _ = writeln!(
            out,
            "\nResolution inputs captured for {} architecture(s)",
            inputs.len()
        );
    }

    Ok(())
}

fn parse_parity_domains(raw: &[String]) -> Result<Vec<AnalysisDomain>> {
    raw.iter()
        .map(|domain| match domain.as_str() {
            "exports" => Ok(AnalysisDomain::Exports),
            "imports" => Ok(AnalysisDomain::Imports),
            "segments" => Ok(AnalysisDomain::Segments),
            "codesign" => Ok(AnalysisDomain::Codesign),
            "objc" => Ok(AnalysisDomain::Objc),
            other => Err(usage_message(format!(
                "unknown parity domain: {other} (use exports, imports, segments, codesign, or objc)"
            ))),
        })
        .collect()
}
