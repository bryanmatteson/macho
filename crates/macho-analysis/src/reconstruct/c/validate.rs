fn find_symbol<'a>(symtab: &'a SymbolTable<'_>, name: &str) -> Option<&'a Symbol<'a>> {
    let prefixed = format!("_{name}");
    symtab
        .find_by_name(name)
        .or_else(|| symtab.find_by_name(&prefixed))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SymbolClassification {
    Function,
    Global,
    Skip,
}

fn classify_symbol(macho: &MachoFile<'_>, symbol: &Symbol<'_>) -> SymbolClassification {
    if symbol.is_stab() {
        return SymbolClassification::Skip;
    }
    let Some(section) = section_for_symbol(macho, symbol) else {
        return SymbolClassification::Skip;
    };
    if section.section_name() == "__text" {
        SymbolClassification::Function
    } else {
        SymbolClassification::Global
    }
}

fn section_for_symbol<'a>(macho: &'a MachoFile<'_>, symbol: &Symbol<'_>) -> Option<&'a Section> {
    let section_index = usize::from(symbol.section_index);
    if section_index == 0 {
        return None;
    }
    macho.all_sections().nth(section_index - 1)
}

fn normalize_c_symbol_name(name: &str) -> Option<String> {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    if stripped.is_empty() {
        return None;
    }
    let first = stripped.chars().next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if stripped
        .chars()
        .any(|ch| !(ch == '_' || ch.is_ascii_alphanumeric()))
    {
        return None;
    }
    Some(stripped.to_string())
}

fn is_probable_c_symbol(name: &str) -> bool {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    !stripped.starts_with("ltmp")
        && !stripped.starts_with("OBJC_")
        && !stripped.starts_with("_OBJC_")
        && !stripped.starts_with("$s")
        && !stripped.starts_with("swift")
        && !stripped.starts_with("Z")
        && !stripped.starts_with("_Z")
        && !stripped.starts_with("___")
}

fn synthetic_tag_name(kind: CTagKind, offset: u64) -> String {
    match kind {
        CTagKind::Struct => format!("__anon_struct_{offset:x}"),
        CTagKind::Union => format!("__anon_union_{offset:x}"),
        CTagKind::Enum => format!("__anon_enum_{offset:x}"),
    }
}

fn should_emit_function(function: &CFunctionDecl) -> bool {
    function.external
}

fn should_emit_global(global: &CGlobalDecl) -> bool {
    global.external
}

fn upsert_function(map: &mut BTreeMap<String, CFunctionDecl>, decl: CFunctionDecl) {
    match map.get_mut(&decl.name) {
        Some(existing) => merge_function(existing, decl),
        None => {
            map.insert(decl.name.clone(), decl);
        }
    }
}

fn merge_function(existing: &mut CFunctionDecl, incoming: CFunctionDecl) {
    if existing.confidence <= incoming.confidence {
        let mut merged = incoming;
        merged.external |= existing.external;
        if merged.address.is_none() {
            merged.address = existing.address;
        }
        if merged.source.file.is_none() {
            merged.source.file = existing.source.file.clone();
        }
        if merged.source.line.is_none() {
            merged.source.line = existing.source.line;
        }
        if merged.params.is_empty() {
            merged.params = existing.params.clone();
        }
        merged.variadic |= existing.variadic;
        merged.evidence.extend(existing.evidence.clone());
        *existing = merged;
    } else {
        existing.external |= incoming.external;
        if existing.address.is_none() {
            existing.address = incoming.address;
        }
        if existing.source.file.is_none() {
            existing.source.file = incoming.source.file;
        }
        if existing.source.line.is_none() {
            existing.source.line = incoming.source.line;
        }
        if existing.params.is_empty() && !incoming.params.is_empty() {
            existing.params = incoming.params;
        }
        existing.variadic |= incoming.variadic;
        existing.evidence.extend(incoming.evidence);
    }
}

fn upsert_global(map: &mut BTreeMap<String, CGlobalDecl>, decl: CGlobalDecl) {
    match map.get_mut(&decl.name) {
        Some(existing) => merge_global(existing, decl),
        None => {
            map.insert(decl.name.clone(), decl);
        }
    }
}

fn merge_global(existing: &mut CGlobalDecl, incoming: CGlobalDecl) {
    if existing.confidence <= incoming.confidence {
        let mut merged = incoming;
        merged.external |= existing.external;
        if merged.address.is_none() {
            merged.address = existing.address;
        }
        if merged.source.file.is_none() {
            merged.source.file = existing.source.file.clone();
        }
        if merged.source.line.is_none() {
            merged.source.line = existing.source.line;
        }
        merged.evidence.extend(existing.evidence.clone());
        *existing = merged;
    } else {
        existing.external |= incoming.external;
        if existing.address.is_none() {
            existing.address = incoming.address;
        }
        if existing.source.file.is_none() {
            existing.source.file = incoming.source.file;
        }
        if existing.source.line.is_none() {
            existing.source.line = incoming.source.line;
        }
        existing.evidence.extend(incoming.evidence);
    }
}

fn upsert_record(map: &mut BTreeMap<String, CRecordDecl>, decl: CRecordDecl) {
    match map.get_mut(&decl.name) {
        Some(existing) => merge_record(existing, decl),
        None => {
            map.insert(decl.name.clone(), decl);
        }
    }
}

fn merge_record(existing: &mut CRecordDecl, incoming: CRecordDecl) {
    if !existing.complete && incoming.complete {
        let mut merged = incoming;
        merged.evidence.extend(existing.evidence.clone());
        *existing = merged;
        return;
    }
    if existing.size.is_none() {
        existing.size = incoming.size;
    }
    if existing.source.file.is_none() {
        existing.source.file = incoming.source.file;
    }
    if existing.source.line.is_none() {
        existing.source.line = incoming.source.line;
    }
    if existing.fields.is_empty() && !incoming.fields.is_empty() {
        existing.fields = incoming.fields;
    }
    existing.evidence.extend(incoming.evidence);
}
fn upsert_enum(map: &mut BTreeMap<String, CEnumDecl>, decl: CEnumDecl) {
    match map.get_mut(&decl.name) {
        Some(existing) => merge_enum(existing, decl),
        None => {
            map.insert(decl.name.clone(), decl);
        }
    }
}

fn merge_enum(existing: &mut CEnumDecl, incoming: CEnumDecl) {
    if !existing.complete && incoming.complete {
        let mut merged = incoming;
        merged.evidence.extend(existing.evidence.clone());
        *existing = merged;
        return;
    }
    if existing.source.file.is_none() {
        existing.source.file = incoming.source.file;
    }
    if existing.source.line.is_none() {
        existing.source.line = incoming.source.line;
    }
    if existing.variants.is_empty() && !incoming.variants.is_empty() {
        existing.variants = incoming.variants;
    }
    existing.evidence.extend(incoming.evidence);
}
