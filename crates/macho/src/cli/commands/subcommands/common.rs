use crate::cli::model::container::MachoContainer;
use crate::cli::model::macho_file::MachoFile;
use std::path::Path;

use crate::analysis::{AnalysisDomain, AnalysisLimits, AnalysisPlan, Analyzer, DomainState};
use anyhow::{Result, bail};
use memmap2::Mmap;
use serde_json::Value;

use crate::cli::commands::{input_message, input_result};

/// Open and memory-map a caller-provided input while retaining typed CLI
/// input-failure classification.
pub fn map_input(path: &Path) -> Result<Mmap> {
    let file = input_result(
        std::fs::File::open(path),
        format!("failed to open {}", path.display()),
    )?;
    input_result(
        // SAFETY: the mapping is read-only and `memmap2` retains the mapping
        // after the file descriptor is closed.
        unsafe { Mmap::map(&file) },
        format!("failed to map {}", path.display()),
    )
}

/// Read caller-provided bytes with typed CLI input-failure classification.
pub fn read_input(path: &Path) -> Result<Vec<u8>> {
    input_result(
        std::fs::read(path),
        format!("failed to read {}", path.display()),
    )
}

/// Read caller-provided UTF-8 text with typed CLI input-failure classification.
pub fn read_input_string(path: &Path) -> Result<String> {
    input_result(
        std::fs::read_to_string(path),
        format!("failed to read {}", path.display()),
    )
}

/// Performs arch_name_for_mach.
pub fn arch_name_for_mach(macho: &MachoFile<'_>) -> String {
    macho.header().arch_spec().name()
}

/// Performs for_each_selected_mach.
pub fn for_each_selected_mach(
    container: &MachoContainer<'_>,
    arch_filter: Option<&str>,
    mut f: impl FnMut(&MachoFile<'_>, &str, bool) -> Result<()>,
) -> Result<()> {
    match container {
        MachoContainer::Thin(macho) => {
            let arch_name = arch_name_for_mach(macho);
            if let Some(filter) = arch_filter
                && !macho.header().arch_spec().matches_selector(filter)
            {
                return Err(input_message(format!(
                    "no architecture matching '{filter}' found (available: {arch_name})"
                )));
            }
            f(macho, &arch_name, false)?;
        }
        MachoContainer::Fat(fat) => {
            let mut matched = false;
            let show_headers = fat.arches().len() > 1;

            for arch in fat.arches() {
                let arch_name = arch.spec().name();
                if let Some(filter) = arch_filter
                    && !arch.spec().matches_selector(filter)
                {
                    continue;
                }

                matched = true;
                f(arch.macho(), &arch_name, show_headers)?;
            }

            if !matched && let Some(filter) = arch_filter {
                let available: Vec<String> =
                    fat.arches().iter().map(|arch| arch.spec().name()).collect();
                return Err(input_message(format!(
                    "no architecture matching '{filter}' found (available: {})",
                    available.join(", ")
                )));
            }
        }
    }

    Ok(())
}

/// Execute one selected analysis domain and return its per-slice typed values.
pub fn analyze_selected_domain(
    container: &MachoContainer<'_>,
    arch_filter: Option<&str>,
    domain: AnalysisDomain,
    limits: AnalysisLimits,
    heuristic_strings: bool,
) -> Result<Vec<(String, Value)>> {
    let mut plan = AnalysisPlan::new([domain])
        .with_limits(limits)
        .with_heuristic_strings(heuristic_strings);
    if let Some(arch) = arch_filter {
        plan = plan.with_slices([arch.to_owned()]);
    }
    let document = Analyzer.run(container, &plan)?;
    document
        .slices
        .into_iter()
        .map(|slice| {
            let state = slice
                .domains
                .get(&domain)
                .expect("all schema-v3 domains have a state");
            let value = match state {
                DomainState::Complete { value, .. } => value.value().clone(),
                DomainState::Failed { error, .. } => {
                    bail!("{}: {}", error.code, error.message)
                }
                DomainState::Unsupported { reason } => {
                    bail!("{}: {}", reason.code, reason.message)
                }
                DomainState::NotRequested => {
                    bail!("selected domain {} did not execute", domain.as_str())
                }
                _ => bail!(
                    "selected domain {} returned an unknown state",
                    domain.as_str()
                ),
            };
            Ok((slice.identity.arch, value))
        })
        .collect()
}

/// Serialize a per-slice report, unwrapping the common one-slice case.
pub fn write_selected_json(
    values: Vec<(String, Value)>,
    out: &mut dyn std::io::Write,
) -> Result<()> {
    crate::cli::commands::output::json::write_selected(values, out)?;
    Ok(())
}
