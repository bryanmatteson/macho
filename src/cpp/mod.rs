pub mod abi;
pub mod correlate;
pub mod render;
pub mod rtti;
pub mod symbol;
pub mod types;
pub mod unify;

use std::collections::BTreeMap;

use crate::cpp::abi::analyze_symbol_body;
use crate::cpp::rtti::build_typeinfo_index;
use crate::cpp::symbol::parse_symbol;
use crate::data_surface::vtable::{SlotTarget, VtableIndex};
use crate::model::mach::MachFile;
use crate::parse::parse_symbol_table;
use crate::{Error, Result};

pub use correlate::{ExternalHeaderIndex, HeaderCandidate, correlate_functions};
pub use render::{default_header_unit, render_header};
pub use types::*;
pub use unify::unify_images;

pub fn build_image_index(mach: &MachFile<'_>) -> Result<types::CppImageIndex> {
    let symtab = parse_symbol_table(mach)?;
    let typeinfos = build_typeinfo_index(mach)?;
    let vtables = VtableIndex::build(mach)?;

    let mut symbols = Vec::new();
    let mut classes: BTreeMap<String, types::CppClass> = BTreeMap::new();
    let mut free_functions = Vec::new();

    for symbol in symtab.symbols() {
        let Some(mut record) = parse_symbol(symbol.name, Some(symbol.value)) else {
            continue;
        };

        if let types::CppSymbolKind::Function { ref mut decl } = record.kind {
            decl.body_analysis = analyze_symbol_body(mach, &symtab, symbol);
            if let Some(class_name) = decl
                .name
                .parent()
                .and_then(|parent| parent.leaf().map(str::to_string))
            {
                classes
                    .entry(class_name.clone())
                    .or_insert_with(|| seed_class(&class_name, typeinfos.get(&class_name)))
                    .methods
                    .push(decl.clone());
            } else {
                free_functions.push(decl.clone());
            }
        }

        symbols.push(record);
    }

    for vtable in vtables.vtables() {
        let Some(name) = vtable
            .name
            .as_deref()
            .and_then(|text| text.strip_prefix("vtable for "))
        else {
            continue;
        };
        let class = classes
            .entry(name.to_string())
            .or_insert_with(|| seed_class(name, typeinfos.get(name)));
        class.vtables.push(convert_vtable(vtable));
        class.evidence.push(types::CppEvidence {
            kind: types::CppEvidenceKind::Vtable,
            confidence: types::CppConfidence::High,
            detail: format!("{} @ {:#x}", name, vtable.va.0),
        });
        mark_virtual_methods(class);
    }

    for (name, typeinfo) in &typeinfos {
        classes
            .entry(name.clone())
            .and_modify(|class| {
                class.bases = typeinfo.bases.clone();
                class.evidence.extend(typeinfo.evidence.clone());
            })
            .or_insert_with(|| seed_class(name, Some(typeinfo)));
    }

    Ok(types::CppImageIndex {
        image: types::CppImageInfo {
            arch: mach.header().cpu_type.name().to_string(),
            uuid: mach.uuid().map(crate::model::load_command::format_uuid),
            install_name: mach
                .load_commands()
                .iter()
                .find_map(|lc| lc.kind.as_dylib().map(|data| data.name.to_string())),
        },
        symbols,
        typeinfos,
        classes,
        free_functions,
        header_matches: Vec::new(),
    })
}

fn seed_class(name: &str, typeinfo: Option<&types::CppTypeInfoNode>) -> types::CppClass {
    types::CppClass {
        name: name.to_string(),
        bases: typeinfo.map(|node| node.bases.clone()).unwrap_or_default(),
        methods: Vec::new(),
        vtables: Vec::new(),
        evidence: typeinfo
            .map(|node| node.evidence.clone())
            .unwrap_or_else(Vec::new),
    }
}

fn convert_vtable(vtable: &crate::data_surface::vtable::VtableEntry) -> types::CppVtableGroup {
    types::CppVtableGroup {
        name: vtable
            .name
            .clone()
            .unwrap_or_else(|| "<unknown>".to_string()),
        mangled_name: vtable.mangled_name.clone(),
        address: vtable.va.0,
        size: vtable.size,
        slots: vtable
            .slots
            .iter()
            .enumerate()
            .map(|(index, slot)| types::CppVtableSlot {
                index,
                offset: slot.offset,
                kind: match &slot.target {
                    SlotTarget::OffsetToTop { .. } => types::CppVtableSlotKind::OffsetToTop,
                    SlotTarget::TypeInfo { .. } => types::CppVtableSlotKind::TypeInfo,
                    SlotTarget::Function { .. } => types::CppVtableSlotKind::Method,
                    SlotTarget::PureVirtual => types::CppVtableSlotKind::PureVirtual,
                    SlotTarget::Unknown { .. } => types::CppVtableSlotKind::Unknown,
                },
                target_name: match &slot.target {
                    SlotTarget::Function { name, .. } => Some(name.clone()),
                    _ => None,
                },
                target_va: match &slot.target {
                    SlotTarget::Function { va, .. } => Some(va.0),
                    SlotTarget::TypeInfo { va } => Some(va.0),
                    _ => None,
                },
            })
            .collect(),
        evidence: vec![types::CppEvidence {
            kind: types::CppEvidenceKind::Vtable,
            confidence: types::CppConfidence::High,
            detail: format!("{} slots", vtable.slots.len()),
        }],
    }
}

fn mark_virtual_methods(class: &mut types::CppClass) {
    let mut method_names = std::collections::BTreeSet::new();
    for vtable in &class.vtables {
        for slot in &vtable.slots {
            if let Some(target_name) = &slot.target_name {
                method_names.insert(target_name.clone());
            }
        }
    }
    for method in &mut class.methods {
        if method_names.contains(&method.demangled_name) {
            method.is_virtual = true;
        }
    }
}

pub fn build_headers_for_mach(mach: &MachFile<'_>) -> Result<String> {
    let index = build_image_index(mach)?;
    let unified = unify::unify_images(&[index]);
    let unit = render::default_header_unit(&unified);
    Ok(render::render_header(&unit))
}

pub fn validate_header_syntax(path: &std::path::Path) -> Result<()> {
    let output = std::process::Command::new("xcrun")
        .arg("clang++")
        .arg("-std=c++17")
        .arg("-x")
        .arg("c++-header")
        .arg("-fsyntax-only")
        .arg(path)
        .output()
        .map_err(|err| Error::Validation(format!("failed to invoke clang++: {err}")))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(Error::Validation(
            String::from_utf8_lossy(&output.stderr).trim().to_string(),
        ))
    }
}
