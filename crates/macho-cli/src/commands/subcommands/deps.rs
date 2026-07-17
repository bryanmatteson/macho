use crate::analysis::deps::compat::{CompatReport, CompatSeverity};
use crate::analysis::deps::graph::{DepGraph, ImportProvider};
use crate::commands::OutputFormat;
use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::map_input;
use crate::metadata::image::DylibLinkKind;
use crate::model::container::MachoContainer;
use crate::model::macho_file::MachoFile;
use anyhow::{Context, Result};
use std::io::Write;
use std::path::PathBuf;

#[derive(clap::Args)]
/// The DepsArgs type.
pub struct DepsArgs {
    /// Path to Mach-O binary
    #[command(flatten)]
    input: InputArgs,
    #[command(flatten)]
    selection: ArchitectureArgs,
    /// Check compatibility against a provider binary
    #[arg(long = "check-compat")]
    check_compat: Option<PathBuf>,
}

/// Performs run.
pub fn run(args: DepsArgs, format: OutputFormat, out: &mut dyn Write) -> Result<()> {
    let json = format == OutputFormat::Json;
    let mmap = map_input(&args.input.path)?;
    let container = macho::parse(&mmap)
        .with_context(|| format!("failed to parse {}", args.input.path.display()))?;

    let provider_mmap;
    let provider_container;
    let provider = if let Some(ref prov_path) = args.check_compat {
        provider_mmap = map_input(prov_path)?;
        provider_container = macho::parse(&provider_mmap)
            .with_context(|| format!("failed to parse provider {}", prov_path.display()))?;
        Some(&provider_container)
    } else {
        None
    };

    let mut has_incompatible = false;

    match &container {
        MachoContainer::Thin(macho) => {
            let prov_mach = provider.and_then(|container| container.first_macho());
            has_incompatible |= print_deps(
                macho,
                &args.input.path.display().to_string(),
                prov_mach,
                args.check_compat
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .as_deref(),
                json,
                out,
            )?;
        }
        MachoContainer::Fat(fat) => {
            for arch in fat.arches() {
                let name = arch.spec().name();
                if let Some(ref f) = args.selection.arch {
                    if !name.eq_ignore_ascii_case(f) {
                        continue;
                    }
                }
                if !json && fat.arches().len() > 1 {
                    let _ = writeln!(out, "=== {name} ===");
                }
                let prov_mach = provider.and_then(|c| {
                    c.find_arch(arch.macho().header().cpu_type())
                        .or_else(|| c.first_macho())
                });
                has_incompatible |= print_deps(
                    arch.macho(),
                    &args.input.path.display().to_string(),
                    prov_mach,
                    args.check_compat
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .as_deref(),
                    json,
                    out,
                )?;
                if !json {
                    let _ = writeln!(out,);
                }
            }
        }
    }

    if has_incompatible {
        anyhow::bail!("dependency compatibility check found incompatible imports");
    }

    Ok(())
}

/// Returns true if incompatibilities were found.
fn print_deps(
    macho: &MachoFile<'_>,
    target_path: &str,
    provider: Option<&MachoFile<'_>>,
    provider_path: Option<&str>,
    json: bool,
    out: &mut dyn Write,
) -> Result<bool> {
    let graph = DepGraph::build(macho).with_context(|| "failed to build dependency graph")?;

    let compat_report = if provider.is_some() {
        Some(
            CompatReport::check(macho, target_path, provider, provider_path)
                .with_context(|| "compatibility check failed")?,
        )
    } else {
        None
    };

    if json {
        let output = serde_json::json!({
            "install_name": graph.install_name,
            "dylibs": graph.dylibs.iter().map(|d| serde_json::json!({
                "name": d.name,
                "ordinal": d.ordinal,
                "kind": d.kind.to_string(),
                "current_version": d.current_version,
                "compat_version": d.compat_version,
                "import_count": graph.imports_from(d.ordinal).len(),
            })).collect::<Vec<_>>(),
            "import_count": graph.imports.len(),
            "export_count": graph.exports.len(),
            "reexport_count": graph.reexports().len(),
            "validation_issues": graph.validate().iter().map(|i| serde_json::json!({
                "severity": i.severity.to_string(),
                "message": i.message,
            })).collect::<Vec<_>>(),
            "compat_report": compat_report.as_ref().map(|r| serde_json::to_value(r).ok()),
        });
        let _ = writeln!(out, "{}", serde_json::to_string_pretty(&output)?);
        return Ok(compat_report.as_ref().is_some_and(|r| r.has_incompatible()));
    }

    if let Some(ref install_name) = graph.install_name {
        let _ = writeln!(out, "install name: {install_name}");
    }

    let _ = writeln!(out, "linked dylibs ({}):", graph.dylibs.len());
    for dylib in &graph.dylibs {
        let kind_tag = match dylib.kind {
            DylibLinkKind::Required => "",
            DylibLinkKind::Weak => " [weak]",
            DylibLinkKind::Reexport => " [reexport]",
            DylibLinkKind::Lazy => " [lazy]",
            DylibLinkKind::Upward => " [upward]",
            _ => " [unknown]",
        };
        let import_count = graph.imports_from(dylib.ordinal).len();
        let _ = writeln!(
            out,
            "  [{:>2}] {}{} (compat: {}, current: {}) -- {} imports",
            dylib.ordinal,
            dylib.name,
            kind_tag,
            dylib.compat_version,
            dylib.current_version,
            import_count,
        );
    }

    // Count imports by provider category
    let mut self_count = 0usize;
    let mut main_count = 0usize;
    let mut dynamic_count = 0usize;
    let mut weak_lookup_count = 0usize;
    for imp in &graph.imports {
        match &imp.provider {
            ImportProvider::SelfImage => self_count += 1,
            ImportProvider::MainExecutable => main_count += 1,
            ImportProvider::DynamicLookup => dynamic_count += 1,
            ImportProvider::WeakLookup => weak_lookup_count += 1,
            _ => {}
        }
    }

    let _ = writeln!(
        out,
        "imports: {} total, {} exports, {} reexports",
        graph.imports.len(),
        graph.exports.len(),
        graph.reexports().len(),
    );

    if self_count > 0 {
        let _ = writeln!(out, "  self-image: {self_count}");
    }
    if main_count > 0 {
        let _ = writeln!(out, "  main-executable: {main_count}");
    }
    if dynamic_count > 0 {
        let _ = writeln!(out, "  dynamic-lookup: {dynamic_count}");
    }
    if weak_lookup_count > 0 {
        let _ = writeln!(out, "  weak-lookup: {weak_lookup_count}");
    }

    let issues = graph.validate();
    if !issues.is_empty() {
        let _ = writeln!(out, "validation issues ({}):", issues.len());
        for issue in &issues {
            let _ = writeln!(out, "  [{}] {}", issue.severity, issue.message);
        }
    }

    if let Some(report) = &compat_report {
        let _ = writeln!(out,);
        let _ = writeln!(out, "--- compatibility check ---");

        for finding in &report.findings {
            let icon = match finding.severity {
                CompatSeverity::Incompatible => "FAIL",
                CompatSeverity::Warning => "WARN",
                CompatSeverity::Info => "INFO",
                _ => "WARN",
            };
            let _ = writeln!(out, "  [{icon}] [{}] {}", finding.category, finding.message);
        }

        if report.has_incompatible() {
            let _ = writeln!(out, "result: INCOMPATIBLE");
        } else {
            let _ = writeln!(out, "result: compatible");
        }
    }

    Ok(compat_report.as_ref().is_some_and(|r| r.has_incompatible()))
}
