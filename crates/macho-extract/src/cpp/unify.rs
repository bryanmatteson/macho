use std::collections::BTreeMap;

use crate::cpp::mark_virtual_methods;
use crate::cpp::types::{
    CppClass, CppConfidence, CppFunctionDecl, CppHeaderMatch, CppImageIndex, CppUnifiedIndex,
};

pub fn unify_images(images: &[CppImageIndex]) -> CppUnifiedIndex {
    let mut classes: BTreeMap<String, CppClass> = BTreeMap::new();
    let mut functions: BTreeMap<String, CppFunctionDecl> = BTreeMap::new();
    let mut header_matches = Vec::new();

    for image in images {
        header_matches.extend(image.header_matches.clone());

        for (name, class) in &image.classes {
            classes
                .entry(name.clone())
                .and_modify(|existing| merge_class(existing, class))
                .or_insert_with(|| class.clone());
        }

        for function in &image.free_functions {
            functions
                .entry(function_key(function))
                .and_modify(|existing| merge_function(existing, function))
                .or_insert_with(|| function.clone());
        }
    }

    for class in classes.values_mut() {
        mark_virtual_methods(class);
    }

    CppUnifiedIndex {
        images: images.iter().map(|image| image.image.clone()).collect(),
        classes,
        free_functions: functions.into_values().collect(),
        header_matches,
    }
}

fn merge_class(existing: &mut CppClass, incoming: &CppClass) {
    for base in &incoming.bases {
        if !existing
            .bases
            .iter()
            .any(|candidate| candidate.name == base.name)
        {
            existing.bases.push(base.clone());
        }
    }
    for method in &incoming.methods {
        if let Some(current) = existing
            .methods
            .iter_mut()
            .find(|candidate| function_key(candidate) == function_key(method))
        {
            merge_function(current, method);
        } else {
            existing.methods.push(method.clone());
        }
    }
    for vtable in &incoming.vtables {
        if !existing
            .vtables
            .iter()
            .any(|candidate| candidate.address == vtable.address)
        {
            existing.vtables.push(vtable.clone());
        }
    }
    existing.evidence.extend(incoming.evidence.clone());
}

fn merge_function(existing: &mut CppFunctionDecl, incoming: &CppFunctionDecl) {
    if existing.signature.return_type.is_none() && incoming.signature.return_type.is_some() {
        existing.signature.return_type = incoming.signature.return_type.clone();
    }
    existing.is_virtual |= incoming.is_virtual;
    existing.is_thunk |= incoming.is_thunk;
    if existing.body_analysis.is_none() {
        existing.body_analysis = incoming.body_analysis.clone();
    }
    existing.evidence.extend(incoming.evidence.clone());
}

fn function_key(function: &CppFunctionDecl) -> String {
    function.overload_key()
}

pub fn correlation_stub(header: &str, declaration: &str) -> CppHeaderMatch {
    CppHeaderMatch {
        declaration: declaration.to_string(),
        header: header.to_string(),
        confidence: CppConfidence::Hook,
    }
}
