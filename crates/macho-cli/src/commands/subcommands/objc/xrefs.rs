use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result};
use macho::analysis::report::{
    Architecture, ObjCEntityId, ObjCSliceReport, recover_objc_container,
};
use macho::core::model::header::ArchSpec;
use macho::core::model::symbol::{SymbolTable, SymbolType};
use serde::Serialize;

use super::{
    ObjCFilterArgs, apply_filters, architecture_name, entity_methods, entity_name_by_id, known,
    method_kind_name,
};
use crate::commands::args::{ArchitectureArgs, InputArgs};
use crate::commands::subcommands::common::map_input;

/// Recover method-to-symbol and caller joins for exactly the report's selected
/// slices. The second selection over parsed images deliberately uses the same
/// core matcher as report recovery so a qualified selector cannot silently
/// collapse a valid report into an empty xref result.
pub(super) fn recover_views(
    input: &InputArgs,
    selection: &ArchitectureArgs,
    filters: &ObjCFilterArgs,
) -> Result<Vec<XrefView>> {
    let mmap = map_input(&input.path)?;
    let container =
        macho::parse(&mmap).with_context(|| format!("failed to parse {}", input.path.display()))?;
    let mut report = recover_objc_container(&container, selection.arch.as_deref())?;
    apply_filters(&mut report, filters);
    let machos = container
        .macho_files()
        .filter(|macho| {
            selection
                .arch
                .as_deref()
                .is_none_or(|arch| macho.header().arch_spec().matches_selector(arch))
        })
        .collect::<Vec<_>>();
    let reported_architectures = report
        .slices
        .as_slice()
        .iter()
        .map(|slice| slice.architecture)
        .collect::<Vec<_>>();
    let parsed_architectures = machos
        .iter()
        .map(|macho| macho.header().arch_spec())
        .collect::<Vec<_>>();
    anyhow::ensure!(
        architecture_sequences_match(&reported_architectures, &parsed_architectures),
        "Objective-C xref slice selection diverged from recovery selection"
    );
    let mut views = Vec::new();
    for (slice, macho) in report.slices.as_slice().iter().zip(machos) {
        views.extend(xref_views(slice, macho));
    }
    Ok(views)
}

fn architecture_sequences_match(reported: &[Architecture], parsed: &[ArchSpec]) -> bool {
    reported.len() == parsed.len()
        && reported.iter().zip(parsed).all(|(reported, parsed)| {
            // Recovery records the raw subtype, including capability bits.
            // Selector matching may mask those bits, but this identity join
            // must preserve them so equal-length reordered slices fail closed.
            reported.cpu_type == parsed.cpu_type.0 && reported.cpu_subtype == parsed.cpu_subtype.0
        })
}

#[derive(Serialize)]
pub(super) struct XrefView {
    pub(super) arch: String,
    member_id: String,
    origin_id: ObjCEntityId,
    pub(super) origin: String,
    pub(super) selector: String,
    pub(super) method_kind: String,
    pub(super) implementation: u64,
    pub(super) status: String,
    pub(super) symbols: Vec<String>,
    pub(super) references: Vec<macho::analysis::xref::Xref>,
}

fn xref_views(
    slice: &ObjCSliceReport,
    macho: &macho::core::model::macho_file::MachoFile<'_>,
) -> Vec<XrefView> {
    let selected = slice
        .selection
        .selected_entity_ids
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut symbols = BTreeMap::<u64, Vec<String>>::new();
    if let Ok(table) = macho.ext::<SymbolTable<'_>>() {
        for symbol in table.symbols() {
            if symbol.sym_type == SymbolType::Section && symbol.value != 0 {
                symbols
                    .entry(symbol.value)
                    .or_default()
                    .push(symbol.name.to_owned());
            }
        }
    }
    let xrefs = macho::analysis::xref::XrefIndex::build(macho).ok();
    let mut result = Vec::new();
    for entity in &slice.entities {
        if !selected.contains(entity.common().id.as_str()) {
            continue;
        }
        for method in entity_methods(entity) {
            let Some(implementation) = known(&method.implementation).and_then(Option::as_ref)
            else {
                continue;
            };
            let names = symbols
                .get(&implementation.virtual_address)
                .cloned()
                .unwrap_or_default();
            let status = match names.len() {
                0 => "unresolved",
                1 => "resolved",
                _ => "ambiguous",
            };
            result.push(XrefView {
                arch: architecture_name(slice),
                member_id: method.id.to_string(),
                origin_id: method.origin.clone(),
                origin: entity_name_by_id(slice, &method.origin)
                    .unwrap_or_else(|| "<unknown>".to_owned()),
                selector: known(&method.selector)
                    .map(|value| value.spelling.clone())
                    .unwrap_or_else(|| "<unknown>".to_owned()),
                method_kind: method_kind_name(method.kind).to_owned(),
                implementation: implementation.virtual_address,
                status: status.to_owned(),
                symbols: names,
                references: xrefs
                    .as_ref()
                    .map(|index| {
                        index
                            .refs_to(macho::core::model::addr::Va(implementation.virtual_address))
                            .cloned()
                            .collect()
                    })
                    .unwrap_or_default(),
            });
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use macho::core::format::constants::{
        CPU_SUBTYPE_ARM64_ALL, CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64,
    };
    use macho::core::model::header::{CpuSubtype, CpuType};

    fn architecture(cpu_subtype: i32) -> Architecture {
        Architecture {
            cpu_type: CPU_TYPE_ARM64,
            cpu_subtype,
        }
    }

    fn arch_spec(cpu_subtype: i32) -> ArchSpec {
        ArchSpec {
            cpu_type: CpuType(CPU_TYPE_ARM64),
            cpu_subtype: CpuSubtype(cpu_subtype),
        }
    }

    #[test]
    fn equal_length_reordered_architectures_fail_the_xref_join() {
        let reported = [
            architecture(CPU_SUBTYPE_ARM64_ALL),
            architecture(CPU_SUBTYPE_ARM64E),
        ];
        let reordered = [
            arch_spec(CPU_SUBTYPE_ARM64E),
            arch_spec(CPU_SUBTYPE_ARM64_ALL),
        ];

        assert!(!architecture_sequences_match(&reported, &reordered));
    }

    #[test]
    fn xref_join_preserves_raw_subtype_capability_bits() {
        let arm64e_with_capability = i32::from_ne_bytes(0x8000_0002_u32.to_ne_bytes());

        assert!(architecture_sequences_match(
            &[architecture(arm64e_with_capability)],
            &[arch_spec(arm64e_with_capability)],
        ));
        assert!(
            !architecture_sequences_match(
                &[architecture(CPU_SUBTYPE_ARM64E)],
                &[arch_spec(arm64e_with_capability)],
            ),
            "masked-equal subtypes are not the same raw report identity"
        );
    }
}
