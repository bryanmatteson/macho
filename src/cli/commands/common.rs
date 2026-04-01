use crate::model::container::MachoContainer;
use crate::model::header::ArchSpec;
use crate::model::macho_file::MachoFile;
use anyhow::{Result, bail};
use macho::analysis::snapshot::ContainerSnapshot;
use std::path::Path;

pub fn arch_name_for_mach(macho: &MachoFile<'_>) -> String {
    let spec = ArchSpec {
        cpu_type: macho.header().cpu_type,
        cpu_subtype: macho.header().cpu_subtype,
    };
    spec.name()
}

pub fn filter_snapshot_by_arch(
    snapshot: &mut ContainerSnapshot,
    filter: &str,
    path: &Path,
) -> Result<()> {
    let available = snapshot.available_arches();
    snapshot
        .slices
        .retain(|slice| slice.arch.eq_ignore_ascii_case(filter));

    if snapshot.slices.is_empty() {
        bail!(
            "no architecture matching '{filter}' found in {} (available: {})",
            path.display(),
            available.join(", ")
        );
    }

    Ok(())
}

pub fn for_each_selected_mach(
    container: &MachoContainer<'_>,
    arch_filter: Option<&str>,
    mut f: impl FnMut(&MachoFile<'_>, &str, bool) -> Result<()>,
) -> Result<()> {
    match container {
        MachoContainer::Thin(macho) => {
            let arch_name = arch_name_for_mach(macho);
            if let Some(filter) = arch_filter {
                if !arch_name.eq_ignore_ascii_case(filter) {
                    bail!("no architecture matching '{filter}' found (available: {arch_name})");
                }
            }
            f(macho, &arch_name, false)?;
        }
        MachoContainer::Fat(fat) => {
            let mut matched = false;
            let show_headers = fat.arches().len() > 1;

            for arch in fat.arches() {
                let arch_name = arch.spec.name();
                if let Some(filter) = arch_filter {
                    if !arch_name.eq_ignore_ascii_case(filter) {
                        continue;
                    }
                }

                matched = true;
                f(&arch.macho, &arch_name, show_headers)?;
            }

            if !matched {
                if let Some(filter) = arch_filter {
                    let available: Vec<String> =
                        fat.arches().iter().map(|arch| arch.spec.name()).collect();
                    bail!(
                        "no architecture matching '{filter}' found (available: {})",
                        available.join(", ")
                    );
                }
            }
        }
    }

    Ok(())
}
