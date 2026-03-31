use anyhow::{Context, Result};
use macho::depgraph::compat::{CompatReport, CompatSeverity};
use macho::depgraph::graph::{DepGraph, ImportProvider};
use macho::inspect::DylibLinkKind;
use macho::model::container::MachContainer;
use macho::model::mach::MachFile;
use std::path::PathBuf;

#[derive(clap::Args)]
pub struct DepsArgs {
    /// Path to Mach-O binary
    path: PathBuf,
    #[arg(long)]
    arch: Option<String>,
    /// Check compatibility against a provider binary
    #[arg(long = "check-compat")]
    check_compat: Option<PathBuf>,
    /// Output as JSON
    #[arg(long)]
    json: bool,
}

pub fn run(args: DepsArgs) -> Result<()> {
    let file = std::fs::File::open(&args.path)
        .with_context(|| format!("failed to open {}", args.path.display()))?;
    let mmap = unsafe { memmap2::Mmap::map(&file)? };
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", args.path.display()))?;

    let provider_mmap;
    let provider_container;
    let provider = if let Some(ref prov_path) = args.check_compat {
        let pf = std::fs::File::open(prov_path)
            .with_context(|| format!("failed to open provider {}", prov_path.display()))?;
        provider_mmap = unsafe { memmap2::Mmap::map(&pf)? };
        provider_container = macho::parse(&provider_mmap)
            .with_context(|| format!("failed to parse provider {}", prov_path.display()))?;
        Some(&provider_container)
    } else {
        None
    };

    let mut has_incompatible = false;

    match &container {
        MachContainer::Thin(mach) => {
            let prov_mach = provider.map(|c| c.first_mach());
            has_incompatible |= print_deps(
                mach,
                &args.path.display().to_string(),
                prov_mach,
                args.check_compat
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .as_deref(),
                args.json,
            )?;
        }
        MachContainer::Fat(fat) => {
            for arch in fat.arches() {
                let name = arch.spec.name();
                if let Some(ref f) = args.arch {
                    if !name.eq_ignore_ascii_case(f) {
                        continue;
                    }
                }
                if !args.json && fat.arches().len() > 1 {
                    println!("=== {name} ===");
                }
                let prov_mach = provider.map(|c| {
                    c.find_arch(arch.mach.header().cpu_type)
                        .unwrap_or_else(|| c.first_mach())
                });
                has_incompatible |= print_deps(
                    &arch.mach,
                    &args.path.display().to_string(),
                    prov_mach,
                    args.check_compat
                        .as_ref()
                        .map(|p| p.display().to_string())
                        .as_deref(),
                    args.json,
                )?;
                if !args.json {
                    println!();
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
    mach: &MachFile<'_>,
    target_path: &str,
    provider: Option<&MachFile<'_>>,
    provider_path: Option<&str>,
    json: bool,
) -> Result<bool> {
    let graph = DepGraph::build(mach).with_context(|| "failed to build dependency graph")?;

    let compat_report = if provider.is_some() {
        Some(
            CompatReport::check(mach, target_path, provider, provider_path)
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
        println!("{}", serde_json::to_string_pretty(&output)?);
        return Ok(compat_report.as_ref().is_some_and(|r| r.has_incompatible()));
    }

    if let Some(ref install_name) = graph.install_name {
        println!("install name: {install_name}");
    }

    println!("linked dylibs ({}):", graph.dylibs.len());
    for dylib in &graph.dylibs {
        let kind_tag = match dylib.kind {
            DylibLinkKind::Required => "",
            DylibLinkKind::Weak => " [weak]",
            DylibLinkKind::Reexport => " [reexport]",
            DylibLinkKind::Lazy => " [lazy]",
            DylibLinkKind::Upward => " [upward]",
        };
        let import_count = graph.imports_from(dylib.ordinal).len();
        println!(
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

    println!(
        "imports: {} total, {} exports, {} reexports",
        graph.imports.len(),
        graph.exports.len(),
        graph.reexports().len(),
    );

    if self_count > 0 {
        println!("  self-image: {self_count}");
    }
    if main_count > 0 {
        println!("  main-executable: {main_count}");
    }
    if dynamic_count > 0 {
        println!("  dynamic-lookup: {dynamic_count}");
    }
    if weak_lookup_count > 0 {
        println!("  weak-lookup: {weak_lookup_count}");
    }

    let issues = graph.validate();
    if !issues.is_empty() {
        println!("validation issues ({}):", issues.len());
        for issue in &issues {
            println!("  [{}] {}", issue.severity, issue.message);
        }
    }

    if let Some(report) = &compat_report {
        println!();
        println!("--- compatibility check ---");

        for finding in &report.findings {
            let icon = match finding.severity {
                CompatSeverity::Incompatible => "FAIL",
                CompatSeverity::Warning => "WARN",
                CompatSeverity::Info => "INFO",
            };
            println!("  [{icon}] [{}] {}", finding.category, finding.message);
        }

        if report.has_incompatible() {
            println!("result: INCOMPATIBLE");
        } else {
            println!("result: compatible");
        }
    }

    Ok(compat_report.as_ref().is_some_and(|r| r.has_incompatible()))
}
