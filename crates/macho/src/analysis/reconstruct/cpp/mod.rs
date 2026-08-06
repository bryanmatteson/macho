pub use crate::metadata::cpp::abi;
/// The correlate module.
pub mod correlate;
/// The render module.
pub mod render;
/// The rtti module.
pub mod rtti;
/// The symbol module.
pub mod symbol;
/// The types module.
pub mod types;
/// The unify module.
pub mod unify;

use serde::Serialize;
use std::collections::BTreeMap;

use crate::analysis::Result;
use crate::analysis::core::{MachoFile, SymbolTable};
use crate::analysis::dwarf::DwarfFunctionIndex;
use crate::analysis::vtables::{SlotTarget, VtableIndex};
use abi::analyze_symbol_body;
use rtti::build_typeinfo_index;
use symbol::parse_symbol;

pub use correlate::{ExternalHeaderIndex, HeaderCandidate, correlate_functions};
pub use render::{default_header_unit, render_header};
pub use types::*;
pub use unify::unify_images;

/// Explicit configuration for one C++ reconstruction run.
#[derive(Debug, Clone, Default)]
pub struct CppReconstructionPlan {
    /// Optional exact class-name selection applied before rendering.
    pub class_filter: Option<String>,
    /// Whether to include a rendered recovered header.
    pub render_header: bool,
}

/// Typed result of a planned C++ reconstruction run.
#[derive(Debug, Clone, Serialize)]
pub struct CppReconstructionReport {
    /// Recovered image model after plan filtering.
    pub index: CppImageIndex,
    /// Optional recovered header requested by the plan.
    pub header: Option<String>,
}

/// Execute C++ reconstruction according to an explicit plan.
pub fn reconstruct(
    macho: &MachoFile<'_>,
    plan: &CppReconstructionPlan,
) -> Result<CppReconstructionReport> {
    let mut index = build_image_index(macho)?;
    if let Some(class_name) = &plan.class_filter {
        index.classes.retain(|name, _| name == class_name);
    }
    let header = plan.render_header.then(|| {
        let unified = unify_images(&[index.clone()]);
        render_header(&default_header_unit(&unified))
    });
    Ok(CppReconstructionReport { index, header })
}

/// Performs build_image_index.
pub fn build_image_index(macho: &MachoFile<'_>) -> Result<types::CppImageIndex> {
    let symtab = macho.ext::<SymbolTable<'_>>()?;
    let typeinfos = build_typeinfo_index(macho)?;
    let vtables = VtableIndex::build(macho)?;
    let dwarf_index = DwarfFunctionIndex::build(macho).ok();

    let mut symbols = Vec::new();
    let mut classes: BTreeMap<String, types::CppClass> = BTreeMap::new();
    let mut pending_functions = Vec::new();
    let mut probable_classes: std::collections::BTreeSet<String> =
        typeinfos.keys().cloned().collect();

    for vtable in vtables.vtables() {
        if let Some(name) = vtable
            .name
            .as_deref()
            .and_then(|text| text.strip_prefix("vtable for "))
        {
            probable_classes.insert(name.to_string());
        }
    }

    for symbol in symtab.symbols() {
        let Some(mut record) = parse_symbol(symbol.name, Some(symbol.value), dwarf_index.as_ref())
        else {
            continue;
        };

        if let types::CppSymbolKind::Function { ref mut decl } = record.kind {
            decl.body_analysis = analyze_symbol_body(macho, &symtab, symbol, Some(&vtables));
            if let Some(parent) = decl.name.parent() {
                if decl.is_constructor || decl.is_destructor {
                    probable_classes.insert(parent.as_string());
                }
            }
            pending_functions.push(decl.as_ref().clone());
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
    }

    let mut free_functions = Vec::new();
    for mut function in pending_functions {
        if let Some(parent) = function.name.parent() {
            let owner = parent.as_string();
            if probable_classes.contains(&owner) {
                function.is_method = true;
                classes
                    .entry(owner.clone())
                    .or_insert_with(|| seed_class(&owner, typeinfos.get(&owner)))
                    .methods
                    .push(function);
                continue;
            }
        }
        function.is_method = false;
        free_functions.push(function);
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

    for class in classes.values_mut() {
        mark_virtual_methods(class);
    }

    Ok(types::CppImageIndex {
        image: types::CppImageInfo {
            arch: macho.header().arch_spec().name(),
            uuid: macho.uuid().map(crate::analysis::core::format_uuid),
            install_name: macho.load_commands().iter().find_map(|lc| match lc.kind() {
                crate::analysis::core::LoadCommand::IdDylib(data) => Some(data.name.to_string()),
                _ => None,
            }),
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
            .unwrap_or_default(),
    }
}

fn convert_vtable(vtable: &crate::analysis::vtables::VtableEntry) -> types::CppVtableGroup {
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
                    _ => types::CppVtableSlotKind::Unknown,
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

pub(crate) fn mark_virtual_methods(class: &mut types::CppClass) {
    let mut method_names = std::collections::BTreeSet::new();
    for vtable in &class.vtables {
        for slot in &vtable.slots {
            if let Some(target_name) = &slot.target_name {
                method_names.insert(target_name.clone());
                if let Some(without_return) = strip_leading_return_type(target_name) {
                    method_names.insert(without_return.to_string());
                }
            }
        }
    }
    for method in &mut class.methods {
        if method_names.contains(&method.demangled_name)
            || method_names.contains(&method.name.as_string())
            || method_names.contains(&method.signature_key())
        {
            method.is_virtual = true;
        }
    }
}

fn strip_leading_return_type(text: &str) -> Option<&str> {
    let open = text.find('(')?;
    let prefix = &text[..open];
    let split = prefix.rfind(' ')?;
    Some(text[split + 1..].trim_start())
}

/// Performs build_headers_for_mach.
pub fn build_headers_for_mach(macho: &MachoFile<'_>) -> Result<String> {
    let index = build_image_index(macho)?;
    let unified = unify::unify_images(&[index]);
    let unit = render::default_header_unit(&unified);
    Ok(render::render_header(&unit))
}
