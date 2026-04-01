use crate::cpp::types::{
    CppClass, CppFunctionDecl, CppHeaderUnit, CppRefQualifier, CppUnifiedIndex,
};
use std::collections::BTreeMap;

pub fn render_header(unit: &CppHeaderUnit) -> String {
    let mut out = String::new();
    let ordered_classes = order_classes(&unit.classes);
    out.push_str("#pragma once\n\n");
    out.push_str("namespace __macho {\n");
    out.push_str("using unknown_return = void*;\n");
    out.push_str(
        "template <unsigned long N> struct unknown_aggregate { unsigned char bytes[N]; };\n",
    );
    out.push_str("}\n\n");

    for include in &unit.includes {
        out.push_str(&format!("#include {include}\n"));
    }
    if !unit.includes.is_empty() {
        out.push('\n');
    }

    for helper in &unit.helpers {
        out.push_str(helper);
        out.push('\n');
    }

    if !ordered_classes.is_empty() {
        for class in &ordered_classes {
            out.push_str(&format!("class {};\n", class.name));
        }
        out.push('\n');
    }

    for class in &ordered_classes {
        out.push_str(&render_class(class));
        out.push('\n');
    }

    for function in dedup_functions(&unit.free_functions)
        .into_iter()
        .filter(|function| !is_runtime_operator(function))
    {
        out.push_str(&render_function(function, true));
        out.push('\n');
    }

    out
}

fn order_classes<'a>(classes: &'a [CppClass]) -> Vec<&'a CppClass> {
    let mut remaining: BTreeMap<String, &CppClass> = classes
        .iter()
        .map(|class| (class.name.clone(), class))
        .collect();
    let mut ordered = Vec::new();

    while !remaining.is_empty() {
        let ready = remaining
            .iter()
            .find(|(_, class)| {
                class
                    .bases
                    .iter()
                    .all(|base| !remaining.contains_key(&base.name))
            })
            .map(|(name, _)| name.clone());

        let Some(next_name) = ready.or_else(|| remaining.keys().next().cloned()) else {
            break;
        };
        let class = remaining.remove(&next_name).expect("class should exist");
        ordered.push(class);
    }

    ordered
}

pub fn default_header_unit(index: &CppUnifiedIndex) -> CppHeaderUnit {
    CppHeaderUnit {
        name: "recovered.hpp".to_string(),
        includes: Vec::new(),
        helpers: Vec::new(),
        classes: index.classes.values().cloned().collect(),
        free_functions: index.free_functions.clone(),
        unresolved: Vec::new(),
    }
}

fn render_class(class: &CppClass) -> String {
    let mut out = String::new();
    out.push_str("class ");
    out.push_str(&class.name);
    if !class.bases.is_empty() {
        let bases = class
            .bases
            .iter()
            .map(|base| {
                let access = if base.is_public {
                    "public "
                } else {
                    "protected "
                };
                format!("{access}{}", base.name)
            })
            .collect::<Vec<_>>()
            .join(", ");
        out.push_str(" : ");
        out.push_str(&bases);
    }
    out.push_str(" {\npublic:\n");

    for method in dedup_functions(&class.methods) {
        out.push_str("    ");
        out.push_str(&render_function(method, false));
        out.push('\n');
    }
    out.push_str("};\n");
    out
}

fn dedup_functions<'a>(functions: &'a [CppFunctionDecl]) -> Vec<&'a CppFunctionDecl> {
    let mut ordered: BTreeMap<String, &CppFunctionDecl> = BTreeMap::new();
    for function in functions {
        let key = format!(
            "{}|{}|{}|{}",
            function.name.leaf().unwrap_or_default(),
            function
                .signature
                .params
                .iter()
                .map(|param| param.ty.render())
                .collect::<Vec<_>>()
                .join(","),
            function.is_constructor,
            function.is_destructor
        );
        ordered.entry(key).or_insert(function);
    }
    ordered.into_values().collect()
}

fn is_runtime_operator(function: &CppFunctionDecl) -> bool {
    matches!(
        function.name.leaf(),
        Some("operator new")
            | Some("operator new[]")
            | Some("operator delete")
            | Some("operator delete[]")
    )
}

fn render_function(function: &CppFunctionDecl, terminate: bool) -> String {
    let mut out = String::new();
    if function.is_virtual {
        out.push_str("virtual ");
    }
    if !function.is_constructor && !function.is_destructor {
        out.push_str(
            &function
                .signature
                .return_type
                .as_ref()
                .map(|ty| ty.render())
                .unwrap_or_else(|| "__macho::unknown_return".to_string()),
        );
        out.push(' ');
    }
    out.push_str(function.name.leaf().unwrap_or_default());
    out.push('(');
    out.push_str(
        &function
            .signature
            .params
            .iter()
            .map(|param| format!("{} {}", param.ty.render(), param.name))
            .collect::<Vec<_>>()
            .join(", "),
    );
    out.push(')');
    if function.signature.is_const {
        out.push_str(" const");
    }
    if function.signature.is_volatile {
        out.push_str(" volatile");
    }
    if let Some(ref_qualifier) = &function.signature.ref_qualifier {
        match ref_qualifier {
            CppRefQualifier::Lvalue => out.push_str(" &"),
            CppRefQualifier::Rvalue => out.push_str(" &&"),
        }
    }
    if function.signature.noexcept {
        out.push_str(" noexcept");
    }
    if terminate {
        out.push(';');
    } else {
        out.push(';');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{default_header_unit, render_header};
    use crate::cpp::types::{CppImageInfo, CppUnifiedIndex};
    use std::collections::BTreeMap;

    #[test]
    fn header_emitter_produces_pragmas() {
        let unit = default_header_unit(&CppUnifiedIndex {
            images: vec![CppImageInfo {
                arch: "x86_64".to_string(),
                uuid: None,
                install_name: None,
            }],
            classes: BTreeMap::new(),
            free_functions: Vec::new(),
            header_matches: Vec::new(),
        });
        let text = render_header(&unit);
        assert!(text.contains("#pragma once"));
        assert!(text.contains("namespace __macho"));
    }
}
