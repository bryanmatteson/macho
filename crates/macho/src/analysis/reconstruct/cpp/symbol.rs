use super::types::{
    CppConfidence, CppEvidence, CppEvidenceKind, CppFunctionDecl, CppFunctionSignature,
    CppParameter, CppRefQualifier, CppSpecialSymbol, CppSymbolKind, CppSymbolRecord, CppThunkKind,
    CppType, QualifiedName,
};
use crate::analysis::dwarf::DwarfFunctionIndex;
use crate::analysis::dwarf::types::{DwarfFunctionInfo, DwarfType};
use crate::analysis::symbols::demangle::{
    demangle_cpp_symbol, demangle_cpp_symbol_without_return_type, demangle_symbol,
};

/// Performs parse_symbol.
pub fn parse_symbol(
    mangled_name: &str,
    address: Option<u64>,
    dwarf_index: Option<&DwarfFunctionIndex>,
) -> Option<CppSymbolRecord> {
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

    let dwarf_func = dwarf_index.and_then(|idx| idx.find_by_linkage_name(mangled_name));
    parse_function(mangled_name, &demangled_name, address, dwarf_func).map(|decl| CppSymbolRecord {
        mangled_name: mangled_name.to_string(),
        demangled_name: Some(demangled_name),
        address,
        kind: CppSymbolKind::Function {
            decl: Box::new(decl),
        },
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
    dwarf_func: Option<&DwarfFunctionInfo>,
) -> Option<CppFunctionDecl> {
    let no_return = demangle_cpp_symbol_without_return_type(mangled_name)
        .unwrap_or_else(|| demangled_name.to_string());
    let full = demangle_cpp_symbol(mangled_name).unwrap_or_else(|| demangled_name.to_string());

    let (name_text, args_text, suffix) = split_signature(&no_return)?;
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

    // Build parameters and return type.
    // When DWARF is available, use it for exact names and types; fall back to
    // demangled-string parsing otherwise.
    let (return_type, params, evidence) = if let Some(df) = dwarf_func {
        let rt = dwarf_type_to_cpp(&df.return_type);
        let ps: Vec<CppParameter> = df
            .parameters
            .iter()
            .filter(|p| !p.is_artificial)
            .enumerate()
            .map(|(i, dp)| CppParameter {
                name: dp.name.clone().unwrap_or_else(|| format!("arg{i}")),
                ty: dwarf_type_to_cpp(&dp.ty),
            })
            .collect();
        let ev = vec![
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
            CppEvidence {
                kind: CppEvidenceKind::BodyAnalysis, // closest variant for "DWARF"
                confidence: CppConfidence::Exact,
                detail: "DWARF debug info".to_string(),
            },
        ];
        (Some(rt), ps, ev)
    } else {
        let rt = extract_return_type(&full, &no_return).map(|ty| parse_type(&ty));
        let ps = split_top_level_args(args_text)
            .into_iter()
            .enumerate()
            .map(|(index, arg)| CppParameter {
                name: format!("arg{index}"),
                ty: parse_type(&arg),
            })
            .collect();
        let ev = vec![
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
        ];
        (rt, ps, ev)
    };

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
        evidence,
        body_analysis: None,
    })
}

/// Convert a DWARF type to the C++ type representation.
fn dwarf_type_to_cpp(dt: &DwarfType) -> CppType {
    match dt {
        DwarfType::Void => CppType::Builtin {
            spelling: "void".to_string(),
        },
        DwarfType::Base { name, .. } => CppType::Builtin {
            spelling: name.clone(),
        },
        DwarfType::Pointer { pointee, .. } => CppType::Pointer {
            inner: Box::new(dwarf_type_to_cpp(pointee)),
        },
        DwarfType::Reference { referent } => CppType::LvalueRef {
            inner: Box::new(dwarf_type_to_cpp(referent)),
        },
        DwarfType::RvalueReference { referent } => CppType::RvalueRef {
            inner: Box::new(dwarf_type_to_cpp(referent)),
        },
        DwarfType::Const(inner) => CppType::Qualified {
            is_const: true,
            is_volatile: false,
            inner: Box::new(dwarf_type_to_cpp(inner)),
        },
        DwarfType::Volatile(inner) => CppType::Qualified {
            is_const: false,
            is_volatile: true,
            inner: Box::new(dwarf_type_to_cpp(inner)),
        },
        DwarfType::Restrict(inner) => dwarf_type_to_cpp(inner),
        DwarfType::Typedef { name, .. } => CppType::Named {
            name: QualifiedName::from_text(name),
        },
        DwarfType::Structure { name, .. } => CppType::Named {
            name: QualifiedName::from_text(name.as_deref().unwrap_or("<anon>")),
        },
        DwarfType::Union { name, .. } => CppType::Named {
            name: QualifiedName::from_text(name.as_deref().unwrap_or("<anon>")),
        },
        DwarfType::Enumeration { name, .. } => CppType::Named {
            name: QualifiedName::from_text(name.as_deref().unwrap_or("<anon>")),
        },
        DwarfType::Array { .. } => CppType::Spelled {
            spelling: format!("{dt}"),
        },
        DwarfType::Subroutine {
            return_type,
            params,
        } => CppType::FunctionPointer {
            result: Box::new(dwarf_type_to_cpp(return_type)),
            params: params.iter().map(dwarf_type_to_cpp).collect(),
        },
        DwarfType::Unresolved => CppType::Unknown {
            label: "<unresolved>".to_string(),
        },
        _ => CppType::Unknown {
            label: "<unsupported DWARF type>".to_string(),
        },
    }
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

/// Performs parse_type.
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
    use crate::analysis::reconstruct::cpp::types::{CppSymbolKind, CppType};

    #[test]
    fn parses_simple_function_symbol() {
        let record = parse_symbol("__ZN5space3fooEii", Some(0x1000), None).expect("record");
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
        let record = parse_symbol("__ZTVN10__cxxabiv117__class_type_infoE", None, None)
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

    // ── DWARF type conversion tests ──

    use super::dwarf_type_to_cpp;
    use crate::analysis::dwarf::types::{BaseTypeEncoding, DwarfType};

    #[test]
    fn dwarf_void_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Void);
        assert!(matches!(ty, CppType::Builtin { spelling } if spelling == "void"));
    }

    #[test]
    fn dwarf_base_int_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Base {
            name: "int".to_string(),
            byte_size: 4,
            encoding: BaseTypeEncoding::Signed,
        });
        assert!(matches!(ty, CppType::Builtin { spelling } if spelling == "int"));
    }

    #[test]
    fn dwarf_base_float_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Base {
            name: "double".to_string(),
            byte_size: 8,
            encoding: BaseTypeEncoding::Float,
        });
        assert!(matches!(ty, CppType::Builtin { spelling } if spelling == "double"));
    }

    #[test]
    fn dwarf_pointer_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Pointer {
            pointee: Box::new(DwarfType::Base {
                name: "char".to_string(),
                byte_size: 1,
                encoding: BaseTypeEncoding::Char,
            }),
            byte_size: 8,
        });
        match ty {
            CppType::Pointer { inner } => {
                assert!(matches!(*inner, CppType::Builtin { spelling } if spelling == "char"));
            }
            other => panic!("expected Pointer, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_reference_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Reference {
            referent: Box::new(DwarfType::Base {
                name: "int".to_string(),
                byte_size: 4,
                encoding: BaseTypeEncoding::Signed,
            }),
        });
        assert!(matches!(ty, CppType::LvalueRef { .. }));
    }

    #[test]
    fn dwarf_rvalue_reference_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::RvalueReference {
            referent: Box::new(DwarfType::Void),
        });
        assert!(matches!(ty, CppType::RvalueRef { .. }));
    }

    #[test]
    fn dwarf_const_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Const(Box::new(DwarfType::Base {
            name: "int".to_string(),
            byte_size: 4,
            encoding: BaseTypeEncoding::Signed,
        })));
        match ty {
            CppType::Qualified {
                is_const,
                is_volatile,
                ..
            } => {
                assert!(is_const);
                assert!(!is_volatile);
            }
            other => panic!("expected Qualified, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_volatile_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Volatile(Box::new(DwarfType::Void)));
        match ty {
            CppType::Qualified {
                is_const,
                is_volatile,
                ..
            } => {
                assert!(!is_const);
                assert!(is_volatile);
            }
            other => panic!("expected Qualified, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_typedef_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Typedef {
            name: "size_t".to_string(),
            underlying: Box::new(DwarfType::Base {
                name: "unsigned long".to_string(),
                byte_size: 8,
                encoding: BaseTypeEncoding::Unsigned,
            }),
        });
        match ty {
            CppType::Named { name } => assert_eq!(name.as_string(), "size_t"),
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_structure_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Structure {
            name: Some("MyClass".to_string()),
            byte_size: Some(16),
        });
        match ty {
            CppType::Named { name } => assert_eq!(name.as_string(), "MyClass"),
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_anonymous_struct_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Structure {
            name: None,
            byte_size: Some(8),
        });
        match ty {
            CppType::Named { name } => assert_eq!(name.as_string(), "<anon>"),
            other => panic!("expected Named for anon struct, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_union_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Union {
            name: Some("MyUnion".to_string()),
            byte_size: Some(8),
        });
        match ty {
            CppType::Named { name } => assert_eq!(name.as_string(), "MyUnion"),
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_enum_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Enumeration {
            name: Some("Color".to_string()),
            byte_size: Some(4),
        });
        match ty {
            CppType::Named { name } => assert_eq!(name.as_string(), "Color"),
            other => panic!("expected Named, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_array_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Array {
            element: Box::new(DwarfType::Base {
                name: "int".to_string(),
                byte_size: 4,
                encoding: BaseTypeEncoding::Signed,
            }),
            count: Some(10),
        });
        match ty {
            CppType::Spelled { spelling } => assert!(spelling.contains("[10]"), "got: {spelling}"),
            other => panic!("expected Spelled array, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_subroutine_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Subroutine {
            return_type: Box::new(DwarfType::Void),
            params: vec![DwarfType::Base {
                name: "int".to_string(),
                byte_size: 4,
                encoding: BaseTypeEncoding::Signed,
            }],
        });
        match ty {
            CppType::FunctionPointer { result, params } => {
                assert!(matches!(*result, CppType::Builtin { spelling } if spelling == "void"));
                assert_eq!(params.len(), 1);
            }
            other => panic!("expected FunctionPointer, got {other:?}"),
        }
    }

    #[test]
    fn dwarf_unresolved_to_cpp() {
        let ty = dwarf_type_to_cpp(&DwarfType::Unresolved);
        assert!(matches!(ty, CppType::Unknown { .. }));
    }

    #[test]
    fn dwarf_restrict_to_cpp() {
        // restrict is dropped (not representable in C++ types), inner preserved
        let ty = dwarf_type_to_cpp(&DwarfType::Restrict(Box::new(DwarfType::Pointer {
            pointee: Box::new(DwarfType::Void),
            byte_size: 8,
        })));
        assert!(matches!(ty, CppType::Pointer { .. }));
    }

    #[test]
    fn dwarf_nested_const_pointer_to_cpp() {
        // const char* → Pointer { inner: Qualified { const, Builtin "char" } }
        let ty = dwarf_type_to_cpp(&DwarfType::Pointer {
            pointee: Box::new(DwarfType::Const(Box::new(DwarfType::Base {
                name: "char".to_string(),
                byte_size: 1,
                encoding: BaseTypeEncoding::Char,
            }))),
            byte_size: 8,
        });
        match ty {
            CppType::Pointer { inner } => {
                assert!(matches!(*inner, CppType::Qualified { is_const: true, .. }));
            }
            other => panic!("expected Pointer to Qualified, got {other:?}"),
        }
    }
}
