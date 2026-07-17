/// Performs render_header.
pub fn render_header(analysis: &CAnalysis) -> String {
    let mut out = String::new();
    for unit in &analysis.header_units {
        if analysis.header_units.len() > 1 {
            out.push_str(&format!("/* {} */\n", unit.name));
        }
        for decl in &unit.declarations {
            out.push_str(decl);
            if !decl.ends_with('\n') {
                out.push('\n');
            }
            out.push('\n');
        }
    }
    out
}

fn build_header_units(analysis: &CAnalysis) -> Vec<CHeaderUnit> {
    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let header_name = |source: &SourceLocation| {
        source
            .file
            .as_deref()
            .and_then(|file| Path::new(file).file_name())
            .and_then(|name| name.to_str())
            .map(str::to_owned)
            .unwrap_or_else(|| "recovered.h".to_string())
    };

    for record in &analysis.records {
        grouped
            .entry(header_name(&record.source))
            .or_default()
            .push(render_record(record));
    }
    for enumeration in &analysis.enums {
        grouped
            .entry(header_name(&enumeration.source))
            .or_default()
            .push(render_enum(enumeration));
    }
    for typedef in &analysis.typedefs {
        grouped
            .entry(header_name(&typedef.source))
            .or_default()
            .push(render_typedef(typedef));
    }
    for global in analysis
        .globals
        .iter()
        .filter(|global| should_emit_global(global))
    {
        grouped
            .entry(header_name(&global.source))
            .or_default()
            .push(render_global(global));
    }
    for function in analysis
        .functions
        .iter()
        .filter(|function| should_emit_function(function))
    {
        grouped
            .entry(header_name(&function.source))
            .or_default()
            .push(render_function(function));
    }

    grouped
        .into_iter()
        .map(|(name, declarations)| CHeaderUnit { name, declarations })
        .collect()
}

fn render_record(record: &CRecordDecl) -> String {
    let keyword = match record.kind {
        CTagKind::Struct => "struct",
        CTagKind::Union => "union",
        CTagKind::Enum => unreachable!(),
    };
    if !record.complete {
        return format!("{keyword} {};", record.name);
    }

    let mut out = format!("{keyword} {} {{\n", record.name);
    for field in &record.fields {
        out.push_str("    ");
        out.push_str(&render_type_with_name(&field.ty, &field.name));
        if let Some(bit_size) = field.bit_size {
            out.push_str(&format!(" : {bit_size}"));
        }
        out.push_str(";\n");
    }
    out.push_str("};");
    out
}

fn render_enum(enumeration: &CEnumDecl) -> String {
    let mut out = format!("enum {} {{\n", enumeration.name);
    for (index, variant) in enumeration.variants.iter().enumerate() {
        let suffix = if index + 1 == enumeration.variants.len() {
            ""
        } else {
            ","
        };
        out.push_str(&format!(
            "    {} = {}{suffix}\n",
            variant.name, variant.value
        ));
    }
    out.push_str("};");
    out
}

fn render_typedef(typedef: &CTypedefDecl) -> String {
    match &typedef.target {
        CType::Named {
            name,
            tag: Some(tag),
        } => {
            let keyword = match tag {
                CTagKind::Struct => "struct",
                CTagKind::Union => "union",
                CTagKind::Enum => "enum",
            };
            format!("typedef {keyword} {name} {};", typedef.name)
        }
        other => format!("typedef {};", render_type_with_name(other, &typedef.name)),
    }
}

fn render_function(function: &CFunctionDecl) -> String {
    let params = if function.params.is_empty() && !function.variadic {
        "void".to_string()
    } else {
        let mut rendered: Vec<String> = function
            .params
            .iter()
            .enumerate()
            .map(|(index, param)| {
                let name = param.name.clone().unwrap_or_else(|| format!("arg{index}"));
                render_type_with_name(&param.ty, &name)
            })
            .collect();
        if function.variadic {
            rendered.push("...".to_string());
        }
        rendered.join(", ")
    };

    format!(
        "{}({params});",
        render_function_signature(&function.return_type, &function.name)
    )
}

fn render_global(global: &CGlobalDecl) -> String {
    format!(
        "extern {};",
        render_type_with_name(&global.ty, &global.name)
    )
}

fn render_function_signature(return_type: &CType, name: &str) -> String {
    match return_type {
        CType::FunctionPointer { .. } => render_type_with_name(return_type, name),
        _ => format!("{} {name}", render_type(return_type)),
    }
}

fn render_type(ty: &CType) -> String {
    render_type_with_name(ty, "").trim().to_string()
}

fn render_type_with_name(ty: &CType, name: &str) -> String {
    match ty {
        CType::Void => render_named("void", name),
        CType::Builtin { name: builtin } => render_named(builtin, name),
        CType::Named {
            name: named,
            tag: Some(tag),
        } => {
            let keyword = match tag {
                CTagKind::Struct => "struct",
                CTagKind::Union => "union",
                CTagKind::Enum => "enum",
            };
            render_named(&format!("{keyword} {named}"), name)
        }
        CType::Named {
            name: named,
            tag: None,
        } => render_named(named, name),
        CType::Pointer { to } => {
            let decorated = if name.is_empty() {
                "*".to_string()
            } else {
                format!("*{name}")
            };
            match &**to {
                CType::Array { .. } | CType::FunctionPointer { .. } => {
                    render_type_with_name(to, &format!("({decorated})"))
                }
                _ => render_type_with_name(to, &decorated),
            }
        }
        CType::Array { element, count } => {
            let suffix = count.map(|count| count.to_string()).unwrap_or_default();
            render_type_with_name(element, &format!("{name}[{suffix}]"))
        }
        CType::Const { inner } => match &**inner {
            CType::Pointer { .. } | CType::Array { .. } | CType::FunctionPointer { .. } => {
                render_type_with_name(inner, &format!("const {name}"))
            }
            _ => render_named(&format!("const {}", render_type(inner)), name),
        },
        CType::Volatile { inner } => {
            render_named(&format!("volatile {}", render_type(inner)), name)
        }
        CType::Restrict { inner } => {
            render_named(&format!("restrict {}", render_type(inner)), name)
        }
        CType::FunctionPointer {
            return_type,
            params,
            variadic,
        } => {
            let mut rendered: Vec<String> = params
                .iter()
                .enumerate()
                .map(|(index, param)| {
                    let param_name = param.name.clone().unwrap_or_else(|| format!("arg{index}"));
                    render_type_with_name(&param.ty, &param_name)
                })
                .collect();
            if *variadic {
                rendered.push("...".to_string());
            }
            let params = if rendered.is_empty() {
                "void".to_string()
            } else {
                rendered.join(", ")
            };
            render_type_with_name(return_type, &format!("(*{name})({params})"))
        }
        CType::Unknown { display } => render_named(display, name),
    }
}

fn render_named(base: &str, name: &str) -> String {
    if name.is_empty() {
        base.to_string()
    } else {
        format!("{base} {name}")
    }
}
