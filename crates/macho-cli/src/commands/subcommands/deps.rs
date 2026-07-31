use crate::analysis::deps::compat::{CompatReport, CompatSeverity};
use crate::analysis::deps::graph::{DepGraph, ImportProvider};
use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::output::layout;
use crate::commands::output::{Options as OutputOptions, Style};
use crate::commands::subcommands::common::map_input;
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
pub fn run(args: DepsArgs, output: OutputOptions, out: &mut dyn Write) -> Result<()> {
    let json = output.format() == crate::commands::OutputFormat::Json;
    let style = output.style();
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
                style,
                out,
            )?;
        }
        MachoContainer::Fat(fat) => {
            for arch in fat.arches() {
                let name = arch.spec().name();
                if let Some(ref f) = args.selection.arch
                    && !name.eq_ignore_ascii_case(f)
                {
                    continue;
                }
                if !json && fat.arches().len() > 1 {
                    let _ = writeln!(out, "{}", style.title(&format!("=== {name} ===")));
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
                    style,
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
    style: Style,
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
        crate::commands::output::json::write_pretty(out, &output)?;
        return Ok(compat_report.as_ref().is_some_and(|r| r.has_incompatible()));
    }

    if let Some(ref install_name) = graph.install_name {
        let _ = writeln!(
            out,
            "{} {}",
            style.muted("install name:"),
            style.info(install_name)
        );
    }

    let _ = writeln!(
        out,
        "{}",
        style.heading(&format!("Linked dylibs ({}):", graph.dylibs.len()))
    );
    for line in linked_dylib_lines(&graph, style) {
        let _ = writeln!(out, "{line}");
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

    let _ = writeln!(out, "{}", style.heading("Imports:"));
    let _ = writeln!(
        out,
        "  {}  {}  {}",
        style.property("total", &graph.imports.len().to_string()),
        style.property("exports", &graph.exports.len().to_string()),
        style.property("reexports", &graph.reexports().len().to_string()),
    );

    if self_count > 0 {
        let _ = writeln!(
            out,
            "  {}",
            style.property("self-image", &self_count.to_string())
        );
    }
    if main_count > 0 {
        let _ = writeln!(
            out,
            "  {}",
            style.property("main-executable", &main_count.to_string())
        );
    }
    if dynamic_count > 0 {
        let _ = writeln!(
            out,
            "  {}",
            style.property("dynamic-lookup", &dynamic_count.to_string())
        );
    }
    if weak_lookup_count > 0 {
        let _ = writeln!(
            out,
            "  {}",
            style.property("weak-lookup", &weak_lookup_count.to_string())
        );
    }

    let issues = graph.validate();
    if !issues.is_empty() {
        let _ = writeln!(
            out,
            "{}",
            style.heading(&format!("Validation issues ({}):", issues.len()))
        );
        for issue in &issues {
            let severity = issue.severity.to_string();
            let severity = if severity == "error" {
                style.error(&severity)
            } else {
                style.warning(&severity)
            };
            let _ = writeln!(out, "  {severity}  {}", issue.message);
        }
    }

    if let Some(report) = &compat_report {
        let _ = writeln!(out,);
        let _ = writeln!(out, "{}", style.heading("Compatibility check:"));

        for finding in &report.findings {
            let label = match finding.severity {
                CompatSeverity::Incompatible => style.error("FAIL"),
                CompatSeverity::Warning => style.warning("WARN"),
                CompatSeverity::Info => style.info("INFO"),
                _ => style.warning("WARN"),
            };
            let _ = writeln!(
                out,
                "  {label}  {}  {}",
                style.enum_value(&finding.category.to_string()),
                finding.message
            );
        }

        if report.has_incompatible() {
            let _ = writeln!(
                out,
                "{} {}",
                style.muted("result:"),
                style.error("INCOMPATIBLE")
            );
        } else {
            let _ = writeln!(
                out,
                "{} {}",
                style.muted("result:"),
                style.success("compatible")
            );
        }
    }

    Ok(compat_report.as_ref().is_some_and(|r| r.has_incompatible()))
}

fn linked_dylib_lines(graph: &DepGraph, style: Style) -> Vec<String> {
    let ordinal_width = graph
        .dylibs
        .iter()
        .map(|dylib| dylib.ordinal.to_string().len())
        .max()
        .unwrap_or(1)
        .max(2);
    let rows = graph
        .dylibs
        .iter()
        .map(|dylib| {
            vec![
                style.muted_cell(&format!("  {:>ordinal_width$}", dylib.ordinal)),
                style.info_cell(&dylib.name),
                style.enum_value_cell(&dylib.kind.to_string()),
                style.property_cell("compat", &dylib.compat_version),
                style.property_cell("current", &dylib.current_version),
                style.property_cell(
                    "imports",
                    &graph.imports_from(dylib.ordinal).len().to_string(),
                ),
            ]
        })
        .collect::<Vec<_>>();
    layout::align(&rows, style)
}

#[cfg(test)]
mod tests {
    use super::linked_dylib_lines;
    use crate::analysis::deps::graph::{DepGraph, NormalizedDylib};
    use crate::commands::output::Style;
    use crate::metadata::image::DylibLinkKind;

    #[test]
    fn linked_dylib_ordinals_are_bare_and_right_aligned() {
        let graph = DepGraph {
            install_name: None,
            dylibs: vec![
                NormalizedDylib {
                    name: "/usr/lib/libShort.dylib".to_owned(),
                    ordinal: 1,
                    current_version: "1.0.0".to_owned(),
                    compat_version: "1.0.0".to_owned(),
                    kind: DylibLinkKind::Required,
                },
                NormalizedDylib {
                    name: "/System/Library/Frameworks/Long.framework/Long".to_owned(),
                    ordinal: 12,
                    current_version: "12.3.0".to_owned(),
                    compat_version: "2.0.0".to_owned(),
                    kind: DylibLinkKind::Weak,
                },
            ],
            imports: Vec::new(),
            exports: Vec::new(),
        };

        let lines = linked_dylib_lines(&graph, Style::new(false));
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("   1  "));
        assert!(lines[1].starts_with("  12  "));
        assert!(lines.iter().all(|line| !line.contains('[')));
        let compat_offsets = lines
            .iter()
            .map(|line| line.find("compat=").expect("compat property"))
            .collect::<Vec<_>>();
        assert_eq!(compat_offsets[0], compat_offsets[1]);
    }
}
