pub mod types;

pub use types::SwiftTypeIndex;

use crate::ext::MachoExt;
use crate::metadata::objc::ObjCMetadata;
use crate::model::macho_file::MachoFile;
use crate::model::symbol::SymbolTable;
use crate::symbols::demangle::demangle_symbol;
use std::collections::btree_map::Entry;

impl<'data> MachoExt<'data> for SwiftTypeIndex {
    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> crate::Result<Self>
    where
        'data: 'mf,
    {
        Ok(Self::build(macho))
    }
}

impl SwiftTypeIndex {
    pub fn build(macho: &MachoFile<'_>) -> Self {
        let mut types = std::collections::BTreeMap::new();

        // 1. From demangled symbols — process descriptors first (they carry
        //    accurate kind info), then metadata accessors for anything not yet
        //    covered.
        if let Ok(symtab) = macho.ext::<SymbolTable<'_>>() {
            // First pass: descriptors (high-confidence kind)
            for sym in symtab.symbols() {
                if !is_swift_mangled(sym.name) {
                    continue;
                }
                if let Some(demangled) = demangle_symbol(sym.name) {
                    if !demangled.contains("descriptor") {
                        continue;
                    }
                    if let Some(swift_type) = extract_swift_type(&demangled, sym.name, sym.value) {
                        insert_swift_type(&mut types, swift_type);
                    }
                }
            }
            // Second pass: metadata accessors (fills in types not covered by descriptors)
            for sym in symtab.symbols() {
                if !is_swift_mangled(sym.name) {
                    continue;
                }
                if let Some(demangled) = demangle_symbol(sym.name) {
                    if demangled.contains("descriptor") {
                        continue;
                    }
                    if let Some(swift_type) = extract_swift_type(&demangled, sym.name, sym.value) {
                        insert_swift_type(&mut types, swift_type);
                    }
                }
            }
        }

        // 2. From ObjC classes marked as Swift
        if let Ok(meta) = macho.ext::<ObjCMetadata>() {
            for cls in &meta.classes {
                if cls.is_swift {
                    insert_swift_type(
                        &mut types,
                        types::SwiftType {
                            name: cls.name.clone(),
                            kind: types::SwiftTypeKind::Class,
                            mangled_name: None,
                            address: None,
                            source: types::SwiftTypeSource::ObjCMetadata,
                            confidence: types::SwiftTypeConfidence::High,
                        },
                    );
                }
            }
        }

        SwiftTypeIndex {
            types: types.into_values().collect(),
        }
    }
}

fn is_swift_mangled(name: &str) -> bool {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    stripped.starts_with("$s") || stripped.starts_with("$S") || stripped.starts_with("$e")
}

fn extract_swift_type(demangled: &str, mangled: &str, address: u64) -> Option<types::SwiftType> {
    // Prioritize descriptors (they give accurate kind) over metadata accessors.
    // Protocol conformance descriptors describe a type's conformance, not a
    // protocol definition — skip them (the type is found via its own descriptor).
    if demangled.contains("protocol conformance descriptor") {
        return None;
    }

    let kind = if demangled.contains("protocol descriptor") {
        types::SwiftTypeKind::Protocol
    } else if demangled.contains("class descriptor") {
        types::SwiftTypeKind::Class
    } else if demangled.contains("enum descriptor") {
        types::SwiftTypeKind::Enum
    } else if demangled.contains("struct descriptor")
        || demangled.contains("nominal type descriptor")
    {
        types::SwiftTypeKind::Struct
    } else if demangled.contains("type metadata accessor") {
        // Metadata accessors exist for all types; we cannot determine the
        // concrete kind from this symbol alone. Mark as Unknown — if a
        // descriptor for the same type was found in the first pass, the
        // seen-guard will have already excluded this symbol, so Unknown is
        // only assigned when no descriptor is available.
        types::SwiftTypeKind::Unknown
    } else {
        return None;
    };

    let name = extract_type_name(demangled)?;

    Some(types::SwiftType {
        name,
        kind,
        mangled_name: Some(mangled.to_string()),
        address: Some(address),
        source: types::SwiftTypeSource::DemangledSymbol,
        confidence: if kind == types::SwiftTypeKind::Unknown {
            types::SwiftTypeConfidence::Partial
        } else {
            types::SwiftTypeConfidence::High
        },
    })
}

fn extract_type_name(demangled: &str) -> Option<String> {
    // Descriptors: "protocol descriptor for Module.Type"
    // Metadata accessors: "type metadata accessor for Module.Type"
    // Extensions: "type metadata accessor for (extension in $hex):Module.Type"
    let descriptor_prefixes = [
        "nominal type descriptor for ",
        "protocol descriptor for ",
        "class descriptor for ",
        "enum descriptor for ",
        "struct descriptor for ",
        "type metadata accessor for ",
    ];

    for prefix in &descriptor_prefixes {
        if let Some(rest) = demangled.strip_prefix(prefix) {
            return Some(clean_type_name(rest));
        }
    }

    None
}

/// Clean a raw demangled type name, handling extension syntax and extra
/// trailing tokens.
///
/// Examples:
///   "Foundation.URL" -> "Foundation.URL"
///   "(extension in $hex):Module.Type" -> "Module.Type"
///   "(extension in $hex):__C.NSNumber" -> "__C.NSNumber"
fn clean_type_name(raw: &str) -> String {
    let cleaned = if raw.starts_with('(') {
        // Extension form: "(extension in $something):ActualModule.Type"
        // Skip past the "):" to get the real name.
        if let Some(colon_pos) = raw.find("):") {
            &raw[colon_pos + 2..]
        } else {
            raw
        }
    } else {
        raw
    };

    // The type name may be followed by additional descriptors or nesting.
    // Take only the fully-qualified name (allows dots but not spaces).
    // e.g. "Swift.Int" from "Swift.Int, Swift.Int"
    let name = cleaned
        .split(|c: char| c.is_whitespace() || c == ',')
        .next()
        .unwrap_or(cleaned);

    // Strip generic parameters: "Swift.Repeated<A>" -> "Swift.Repeated"
    let name = match name.find('<') {
        Some(pos) => &name[..pos],
        None => name,
    };

    if name.is_empty() {
        return name.to_string();
    }

    name.to_string()
}

fn insert_swift_type(
    types: &mut std::collections::BTreeMap<String, types::SwiftType>,
    candidate: types::SwiftType,
) {
    match types.entry(candidate.name.clone()) {
        Entry::Vacant(entry) => {
            entry.insert(candidate);
        }
        Entry::Occupied(mut entry) => {
            let merged = merge_swift_types(entry.get(), candidate);
            if merged.confidence != entry.get().confidence
                || merged.kind != entry.get().kind
                || merged.mangled_name != entry.get().mangled_name
                || merged.address != entry.get().address
                || merged.source != entry.get().source
            {
                entry.insert(merged);
            }
        }
    }
}

fn confidence_rank(confidence: types::SwiftTypeConfidence) -> u8 {
    match confidence {
        types::SwiftTypeConfidence::High => 1,
        types::SwiftTypeConfidence::Partial => 0,
    }
}

fn merge_swift_types(existing: &types::SwiftType, candidate: types::SwiftType) -> types::SwiftType {
    let existing_rank = confidence_rank(existing.confidence);
    let candidate_rank = confidence_rank(candidate.confidence);
    let mut preferred = if candidate_rank > existing_rank
        || (candidate_rank == existing_rank
            && existing.kind == types::SwiftTypeKind::Unknown
            && candidate.kind != types::SwiftTypeKind::Unknown)
        || (candidate_rank == existing_rank
            && (existing.mangled_name.is_none() && candidate.mangled_name.is_some()
                || existing.address.is_none() && candidate.address.is_some()))
    {
        candidate
    } else {
        existing.clone()
    };

    if preferred.mangled_name.is_none() {
        preferred.mangled_name = existing.mangled_name.clone();
    }
    if preferred.address.is_none() {
        preferred.address = existing.address;
    }
    preferred
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefers_high_confidence_over_partial() {
        let mut types = std::collections::BTreeMap::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Unknown,
                mangled_name: Some("$s4Demo6WidgetC".into()),
                address: Some(0x1000),
                source: types::SwiftTypeSource::DemangledSymbol,
                confidence: types::SwiftTypeConfidence::Partial,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: None,
                source: types::SwiftTypeSource::ObjCMetadata,
                confidence: types::SwiftTypeConfidence::High,
            },
        );

        let ty = types.get("Demo.Widget").expect("type should be present");
        assert_eq!(ty.kind, types::SwiftTypeKind::Class);
        assert_eq!(ty.source, types::SwiftTypeSource::ObjCMetadata);
        assert_eq!(ty.confidence, types::SwiftTypeConfidence::High);
        assert_eq!(ty.mangled_name.as_deref(), Some("$s4Demo6WidgetC"));
        assert_eq!(ty.address, Some(0x1000));
    }

    #[test]
    fn preserves_symbol_details_when_replacing_partial_metadata() {
        let mut types = std::collections::BTreeMap::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Unknown,
                mangled_name: Some("$s4Demo6WidgetC".into()),
                address: Some(0x2000),
                source: types::SwiftTypeSource::DemangledSymbol,
                confidence: types::SwiftTypeConfidence::Partial,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: None,
                source: types::SwiftTypeSource::ObjCMetadata,
                confidence: types::SwiftTypeConfidence::High,
            },
        );

        let ty = types.get("Demo.Widget").expect("type should be present");
        assert_eq!(ty.kind, types::SwiftTypeKind::Class);
        assert_eq!(ty.source, types::SwiftTypeSource::ObjCMetadata);
        assert_eq!(ty.confidence, types::SwiftTypeConfidence::High);
        assert_eq!(ty.mangled_name.as_deref(), Some("$s4Demo6WidgetC"));
        assert_eq!(ty.address, Some(0x2000));
    }

    #[test]
    fn equal_confidence_merge_keeps_richer_symbol_details() {
        let mut types = std::collections::BTreeMap::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: None,
                source: types::SwiftTypeSource::ObjCMetadata,
                confidence: types::SwiftTypeConfidence::High,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: Some("$s4Demo6WidgetC".into()),
                address: Some(0x3000),
                source: types::SwiftTypeSource::DemangledSymbol,
                confidence: types::SwiftTypeConfidence::High,
            },
        );

        let ty = types.get("Demo.Widget").expect("type should be present");
        assert_eq!(ty.source, types::SwiftTypeSource::DemangledSymbol);
        assert_eq!(ty.mangled_name.as_deref(), Some("$s4Demo6WidgetC"));
        assert_eq!(ty.address, Some(0x3000));
    }
}
