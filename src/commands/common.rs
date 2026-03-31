use anyhow::{Result, bail};
use macho::analysis::snapshot::ContainerSnapshot;
use macho::model::container::MachContainer;
use macho::model::fat::ArchSpec;
use macho::model::mach::MachFile;
use std::path::Path;

pub fn arch_name_for_mach(mach: &MachFile<'_>) -> String {
    let spec = ArchSpec {
        cpu_type: mach.header().cpu_type,
        cpu_subtype: mach.header().cpu_subtype,
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
    container: &MachContainer<'_>,
    arch_filter: Option<&str>,
    mut f: impl FnMut(&MachFile<'_>, &str, bool) -> Result<()>,
) -> Result<()> {
    match container {
        MachContainer::Thin(mach) => {
            let arch_name = arch_name_for_mach(mach);
            if let Some(filter) = arch_filter {
                if !arch_name.eq_ignore_ascii_case(filter) {
                    bail!("no architecture matching '{filter}' found (available: {arch_name})");
                }
            }
            f(mach, &arch_name, false)?;
        }
        MachContainer::Fat(fat) => {
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
                f(&arch.mach, &arch_name, show_headers)?;
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
