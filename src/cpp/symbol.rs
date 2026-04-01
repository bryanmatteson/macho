use cpp_demangle::DemangleOptions;

use crate::cpp::types::{
    CppConfidence, CppEvidence, CppEvidenceKind, CppFunctionDecl, CppFunctionSignature,
    CppParameter, CppRefQualifier, CppSpecialSymbol, CppSymbolKind, CppSymbolRecord, CppThunkKind,
    CppType, QualifiedName,
};
use crate::demangle::{demangle_cpp_symbol_with_options, demangle_symbol};

pub fn parse_symbol(mangled_name: &str, address: Option<u64>) -> Option<CppSymbolRecord> {
    let demangled_name = demangle_symbol(mangled_name)?;

    if let Some(detail) = parse_special_symbol(&demangled_name) {
        return Some(CppSymbolRecord {
            mangled_name: mangled_name.to_string(),
            demangled_name: Some(demangled_name),
            address,
            kind: CppSymbolKind::Special { detail },
            confidence: CppConfidence::High,
        });
    }

    if !demangled_name.contains('(') {
        return Some(CppSymbolRecord {
            mangled_name: mangled_name.to_string(),
            demangled_name: Some(demangled_name.clone()),
            address,
            kind: CppSymbolKind::Data {
                name: QualifiedName::from_text(&demangled_name),
            },
            confidence: CppConfidence::High,
        });
    }

    parse_function(mangled_name, &demangled_name, address).map(|decl| CppSymbolRecord {
        mangled_name: mangled_name.to_string(),
        demangled_name: Some(demangled_name),
        address,
        kind: CppSymbolKind::Function { decl },
        confidence: CppConfidence::High,
    })
}

fn parse_special_symbol(text: &str) -> Option<CppSpecialSymbol> {
    if let Some(class_name) = text.strip_prefix("vtable for ") {
        return Some(CppSpecialSymbol::VirtualTable {
            class_name: class_name.trim().to_string(),
        });
    }
    if let Some(class_name) = text.strip_prefix("typeinfo for ") {
        return Some(CppSpecialSymbol::TypeInfo {
            class_name: class_name.trim().to_string(),
        });
    }
    if let Some(class_name) = text.strip_prefix("typeinfo name for ") {
        return Some(CppSpecialSymbol::TypeInfoName {
            class_name: class_name.trim().to_string(),
        });
    }
    if let Some(target) = text.strip_prefix("virtual thunk to ") {
        return Some(CppSpecialSymbol::Thunk {
            kind: CppThunkKind::Virtual,
            target: target.trim().to_string(),
            adjustment: None,
        });
    }
    if let Some(target) = text.strip_prefix("non-virtual thunk to ") {
        return Some(CppSpecialSymbol::Thunk {
            kind: CppThunkKind::NonVirtual,
            target: target.trim().to_string(),
            adjustment: None,
        });
    }
    if let Some(rest) = text.strip_prefix("virtual override thunk ") {
        let (adjustment, target) = if let Some(target) = rest.split("] ").nth(1) {
            let adj = rest
                .strip_prefix("[offset ")
                .and_then(|part| part.split(']').next())
                .and_then(|part| part.trim().parse::<i64>().ok());
            (adj, target.to_string())
        } else {
            (None, rest.to_string())
        };
        return Some(CppSpecialSymbol::Thunk {
            kind: CppThunkKind::Override,
            target: target.trim().to_string(),
            adjustment,
        });
    }
    None
}

fn parse_function(
    mangled_name: &str,
    demangled_name: &str,
    address: Option<u64>,
) -> Option<CppFunctionDecl> {
    let no_return =
        demangle_cpp_symbol_with_options(mangled_name, DemangleOptions::default().no_return_type())
            .unwrap_or_else(|| demangled_name.to_string());
    let full = demangle_cpp_symbol_with_options(mangled_name, DemangleOptions::default())
        .unwrap_or_else(|| demangled_name.to_string());

    let (name_text, args_text, suffix) = split_signature(&no_return)?;
    let return_type = extract_return_type(&full, &no_return).map(|ty| parse_type(&ty));
    let name = QualifiedName::from_text(name_text);
    let leaf = name.leaf().unwrap_or_default().to_string();
    let class_leaf = name
        .parent()
        .and_then(|parent| parent.leaf().map(str::to_string));
    let is_constructor = class_leaf.as_deref() == Some(leaf.as_str());
    let is_destructor = class_leaf
        .as_deref()
        .is_some_and(|class_name| leaf == format!("~{class_name}"));
    let is_operator = leaf.starts_with("operator");
    let (is_const, is_volatile, ref_qualifier, noexcept) = parse_suffix_qualifiers(suffix);
    let params = split_top_level_args(args_text)
        .into_iter()
        .enumerate()
        .map(|(index, arg)| CppParameter {
            name: format!("arg{index}"),
            ty: parse_type(&arg),
        })
        .collect();

    Some(CppFunctionDecl {
        mangled_name: mangled_name.to_string(),
        demangled_name: demangled_name.to_string(),
        name: name.clone(),
        signature: CppFunctionSignature {
            return_type,
            params,
            is_const,
            is_volatile,
            ref_qualifier,
            noexcept,
        },
        address,
        is_method: false,
        is_constructor,
        is_destructor,
        is_operator,
        is_virtual: false,
        is_thunk: demangled_name.contains("thunk"),
        evidence: vec![
            CppEvidence {
                kind: CppEvidenceKind::MangledSymbol,
                confidence: CppConfidence::Exact,
                detail: mangled_name.to_string(),
            },
            CppEvidence {
                kind: CppEvidenceKind::DemangledSymbol,
                confidence: CppConfidence::High,
                detail: demangled_name.to_string(),
            },
        ],
        body_analysis: None,
    })
}

fn extract_return_type(full: &str, no_return: &str) -> Option<String> {
    if full == no_return {
        return None;
    }
    let suffix = format!(" {no_return}");
    full.strip_suffix(&suffix)
        .map(str::trim)
        .and_then(|prefix| {
            if prefix.is_empty() {
                None
            } else {
                Some(prefix.to_string())
            }
        })
}

fn split_signature(text: &str) -> Option<(&str, &str, &str)> {
    let open = text.find('(')?;
    let close = find_matching_paren(text, open)?;
    Some((
        &text[..open],
        &text[open + 1..close],
        text[close + 1..].trim(),
    ))
}

fn find_matching_paren(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (index, ch) in text.char_indices().skip(open) {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn parse_suffix_qualifiers(suffix: &str) -> (bool, bool, Option<CppRefQualifier>, bool) {
    let mut is_const = false;
    let mut is_volatile = false;
    let mut ref_qualifier = None;
    let mut noexcept = false;
    for token in suffix.split_whitespace() {
        match token {
            "const" => is_const = true,
            "volatile" => is_volatile = true,
            "&" => ref_qualifier = Some(CppRefQualifier::Lvalue),
            "&&" => ref_qualifier = Some(CppRefQualifier::Rvalue),
            "noexcept" => noexcept = true,
            _ => {}
        }
    }
    (is_const, is_volatile, ref_qualifier, noexcept)
}

fn split_top_level_args(args: &str) -> Vec<String> {
    if args.trim().is_empty() || args.trim() == "void" {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut start = 0usize;
    let mut angle_depth = 0usize;
    let mut paren_depth = 0usize;
    let mut bracket_depth = 0usize;
    for (index, ch) in args.char_indices() {
        match ch {
            '<' => angle_depth += 1,
            '>' => angle_depth = angle_depth.saturating_sub(1),
            '(' => paren_depth += 1,
            ')' => paren_depth = paren_depth.saturating_sub(1),
            '[' => bracket_depth += 1,
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if angle_depth == 0 && paren_depth == 0 && bracket_depth == 0 => {
                out.push(args[start..index].trim().to_string());
                start = index + 1;
            }
            _ => {}
        }
    }
    out.push(args[start..].trim().to_string());
    out
}

pub fn parse_type(text: &str) -> CppType {
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return CppType::Unknown {
            label: "__macho::unknown_type".to_string(),
        };
    }

    if let Some(rest) = trimmed.strip_suffix("&&") {
        return CppType::RvalueRef {
            inner: Box::new(parse_type(rest)),
        };
    }
    if let Some(rest) = trimmed.strip_suffix('&') {
        return CppType::LvalueRef {
            inner: Box::new(parse_type(rest)),
        };
    }
    if let Some(rest) = trimmed.strip_suffix('*') {
        return CppType::Pointer {
            inner: Box::new(parse_type(rest)),
        };
    }

    let mut is_const = false;
    let mut is_volatile = false;
    let mut base = trimmed;
    loop {
        if let Some(rest) = base.strip_suffix(" const") {
            is_const = true;
            base = rest.trim_end();
            continue;
        }
        if let Some(rest) = base.strip_suffix(" volatile") {
            is_volatile = true;
            base = rest.trim_end();
            continue;
        }
        break;
    }

    let base_ty = if let Some((name, args)) = split_template_instance(base) {
        CppType::TemplateInstance {
            base: QualifiedName::from_text(name),
            args: split_top_level_args(args)
                .into_iter()
                .map(|arg| parse_type(&arg))
                .collect(),
        }
    } else if is_builtin_type(base) {
        CppType::Builtin {
            spelling: base.to_string(),
        }
    } else if base.contains("(*)(") && base.ends_with(')') {
        parse_function_pointer(base)
    } else if base.contains("::") || base.chars().all(is_identifierish) {
        CppType::Named {
            name: QualifiedName::from_text(base),
        }
    } else {
        CppType::Spelled {
            spelling: base.to_string(),
        }
    };

    if is_const || is_volatile {
        CppType::Qualified {
            is_const,
            is_volatile,
            inner: Box::new(base_ty),
        }
    } else {
        base_ty
    }
}

fn parse_function_pointer(text: &str) -> CppType {
    let Some((ret, tail)) = text.split_once("(*)(") else {
        return CppType::Spelled {
            spelling: text.to_string(),
        };
    };
    let Some(args) = tail.strip_suffix(')') else {
        return CppType::Spelled {
            spelling: text.to_string(),
        };
    };
    CppType::FunctionPointer {
        result: Box::new(parse_type(ret)),
        params: split_top_level_args(args)
            .into_iter()
            .map(|arg| parse_type(&arg))
            .collect(),
    }
}

fn split_template_instance(text: &str) -> Option<(&str, &str)> {
    let start = text.find('<')?;
    let end = text.rfind('>')?;
    if end <= start {
        return None;
    }
    Some((text[..start].trim(), &text[start + 1..end]))
}

fn is_builtin_type(text: &str) -> bool {
    matches!(
        text,
        "void"
            | "bool"
            | "char"
            | "signed char"
            | "unsigned char"
            | "short"
            | "unsigned short"
            | "int"
            | "unsigned int"
            | "long"
            | "unsigned long"
            | "long long"
            | "unsigned long long"
            | "float"
            | "double"
            | "long double"
            | "wchar_t"
            | "char16_t"
            | "char32_t"
            | "size_t"
    )
}

fn is_identifierish(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | ':' | '~')
}

#[cfg(test)]
mod tests {
    use super::{parse_symbol, parse_type};
    use crate::cpp::types::{CppSymbolKind, CppType};

    #[test]
    fn parses_simple_function_symbol() {
        let record = parse_symbol("__ZN5space3fooEii", Some(0x1000)).expect("record");
        match record.kind {
            CppSymbolKind::Function { decl } => {
                assert_eq!(decl.name.as_string(), "space::foo");
                assert_eq!(decl.signature.params.len(), 2);
            }
            other => panic!("expected function, got {other:?}"),
        }
    }

    #[test]
    fn parses_special_symbols() {
        let record = parse_symbol("__ZTVN10__cxxabiv117__class_type_infoE", None)
            .expect("vtable special symbol");
        match record.kind {
            CppSymbolKind::Special { .. } => {}
            other => panic!("expected special, got {other:?}"),
        }
    }

    #[test]
    fn parses_template_and_reference_types() {
        let ty = parse_type("std::vector<int> const&");
        match ty {
            CppType::LvalueRef { .. } => {}
            other => panic!("expected lvalue ref, got {other:?}"),
        }
    }
}
