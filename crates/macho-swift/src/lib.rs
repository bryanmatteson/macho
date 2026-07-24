#![deny(missing_docs)]
//! Swift metadata indexing with injectable demangling.
//!
//! Depend on this crate directly for Swift type indexes without the `macho`
//! façade: build a [`SwiftTypeIndex`] from a [`macho_core::MachoFile`] or a
//! borrowed byte source.

pub use macho_core::{ext, model};

/// The error module.
pub mod error;
pub use error::{Result, SwiftError, SwiftErrorKind};
mod context_descriptors;
/// The types module.
pub mod types;

pub use types::SwiftTypeIndex;
#[cfg(feature = "strict-rtti")]
pub mod strict;

use crate::ext::MachoExt;
use crate::model::macho_file::MachoFile;
use crate::model::symbol::SymbolTable;
use macho_demangle::demangle_swift_symbol;

/// Injectable Swift symbol demangler.
pub trait SwiftDemangler: Send + Sync {
    /// Return a demangled name, `None` for a non-Swift symbol, or a typed
    /// capability/format failure.
    fn demangle(&self, symbol: &str) -> Result<Option<String>>;
}

/// Process-free Swift demangler backed directly by the Swift demangling library.
#[derive(Debug, Default, Clone, Copy)]
pub struct PureSwiftDemangler;

impl SwiftDemangler for PureSwiftDemangler {
    fn demangle(&self, symbol: &str) -> Result<Option<String>> {
        Ok(demangle_swift_symbol(symbol))
    }
}

impl<'data> MachoExt<'data> for SwiftTypeIndex {
    type Error = SwiftError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> crate::Result<Self>
    where
        'data: 'mf,
    {
        Ok(Self::build(macho))
    }
}

impl SwiftTypeIndex {
    /// Performs build.
    pub fn build(macho: &MachoFile<'_>) -> Self {
        Self::build_with_demangler(macho, &PureSwiftDemangler).unwrap_or_else(|_| Self {
            types: Vec::new(),
            parents: Vec::new(),
            conformances: Vec::new(),
            associated_types: Vec::new(),
        })
    }

    /// Build an index from one borrowed thin Mach-O byte source.
    ///
    /// The source is not copied and may be a byte slice, vector, or
    /// caller-owned read-only memory map. Universal binaries are rejected so
    /// callers select an architecture explicitly through [`macho_core::parse`].
    pub fn build_from_source<S>(source: &S) -> Result<Self>
    where
        S: AsRef<[u8]> + ?Sized,
    {
        let macho = parse_source(source)?;
        Ok(Self::build(&macho))
    }

    /// Build the index with an injected demangler and retain typed failures.
    pub fn build_with_demangler(
        macho: &MachoFile<'_>,
        demangler: &dyn SwiftDemangler,
    ) -> Result<Self> {
        let mut types = Vec::new();

        // 1. Native Swift context descriptors. These are the authoritative
        //    source for nominal kinds and include types that are neither
        //    Objective-C-visible nor represented by exported symbols.
        for swift_type in context_descriptors::discover(macho, demangler) {
            insert_swift_type(&mut types, swift_type);
        }

        // 2. From demangled symbols — process descriptors first (they carry
        //    accurate kind info), then metadata accessors for anything not yet
        //    covered.
        if let Ok(symtab) = macho.ext::<SymbolTable<'_>>() {
            // First pass: descriptors (high-confidence kind)
            for sym in symtab.symbols().iter().filter(|symbol| symbol.is_defined()) {
                if !is_swift_mangled(sym.name) {
                    continue;
                }
                if let Some(demangled) = demangler.demangle(sym.name)? {
                    if !demangled.contains("descriptor") {
                        continue;
                    }
                    if let Some(swift_type) = extract_swift_type(&demangled, sym.name, sym.value) {
                        insert_swift_type(&mut types, swift_type);
                    }
                }
            }
            // Second pass: metadata accessors (fills in types not covered by descriptors)
            for sym in symtab.symbols().iter().filter(|symbol| symbol.is_defined()) {
                if !is_swift_mangled(sym.name) {
                    continue;
                }
                if let Some(demangled) = demangler.demangle(sym.name)? {
                    if demangled.contains("descriptor") {
                        continue;
                    }
                    if let Some(swift_type) = extract_swift_type(&demangled, sym.name, sym.value) {
                        insert_swift_type(&mut types, swift_type);
                    }
                }
            }
        }

        sort_types(&mut types);
        let parents = context_descriptors::discover_parents(macho, &types);
        let conformances = context_descriptors::discover_conformances(macho);
        let associated_types = context_descriptors::discover_associated_types(macho, demangler);
        Ok(SwiftTypeIndex {
            types,
            parents,
            conformances,
            associated_types,
        })
    }

    /// Build from one borrowed thin Mach-O source with an injected demangler.
    ///
    /// This has the same zero-copy source and universal-binary behavior as
    /// [`Self::build_from_source`].
    pub fn build_from_source_with_demangler<S>(
        source: &S,
        demangler: &dyn SwiftDemangler,
    ) -> Result<Self>
    where
        S: AsRef<[u8]> + ?Sized,
    {
        let macho = parse_source(source)?;
        Self::build_with_demangler(&macho, demangler)
    }

    /// Compose Objective-C runtime names into this Swift index without making
    /// the Swift parser depend on an Objective-C parser.
    pub fn enrich_objc_runtime_types<I>(
        &mut self,
        runtime_types: I,
        demangler: &dyn SwiftDemangler,
    ) -> Result<()>
    where
        I: IntoIterator<Item = (String, types::SwiftTypeKind)>,
    {
        for (runtime_name, kind) in runtime_types {
            insert_swift_type(
                &mut self.types,
                swift_type_from_objc_runtime_name(&runtime_name, kind, demangler)?,
            );
        }
        sort_types(&mut self.types);
        Ok(())
    }
}

fn parse_source<'data, S>(source: &'data S) -> Result<MachoFile<'data>>
where
    S: AsRef<[u8]> + ?Sized,
{
    match macho_core::parse(source.as_ref())? {
        macho_core::model::container::MachoContainer::Thin(macho) => Ok(macho),
        macho_core::model::container::MachoContainer::Fat(_) => Err(SwiftError::unsupported(
            "borrowed source contains a universal Mach-O; select an architecture explicitly",
        )),
    }
}

fn swift_type_from_objc_runtime_name(
    runtime_name: &str,
    kind: types::SwiftTypeKind,
    demangler: &dyn SwiftDemangler,
) -> Result<types::SwiftType> {
    let demangled = demangler.demangle(runtime_name)?;
    Ok(types::SwiftType {
        name: demangled.unwrap_or_else(|| runtime_name.to_owned()),
        kind,
        mangled_name: runtime_name
            .starts_with("_Tt")
            .then(|| runtime_name.to_owned()),
        address: None,
        metadata_address: None,
        source: types::SwiftTypeSource::ObjCMetadata,
        confidence: types::SwiftTypeConfidence::High,
        fields: None,
    })
}

fn is_swift_mangled(name: &str) -> bool {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    stripped.starts_with("$s") || stripped.starts_with("$S") || stripped.starts_with("$e")
}

fn sort_types(types: &mut [types::SwiftType]) {
    types.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.address.cmp(&right.address))
            .then_with(|| source_rank(right.source).cmp(&source_rank(left.source)))
            .then_with(|| left.mangled_name.cmp(&right.mangled_name))
    });
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
    } else if demangled.contains("type metadata for ") {
        types::SwiftTypeKind::Unknown
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
    let metadata_address = demangled
        .starts_with("type metadata for ")
        .then_some(address);

    Some(types::SwiftType {
        name,
        kind,
        mangled_name: Some(mangled.to_string()),
        address: metadata_address.is_none().then_some(address),
        metadata_address,
        source: types::SwiftTypeSource::DemangledSymbol,
        confidence: if kind == types::SwiftTypeKind::Unknown {
            types::SwiftTypeConfidence::Partial
        } else {
            types::SwiftTypeConfidence::High
        },
        fields: None,
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
        "type metadata for ",
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

fn insert_swift_type(types: &mut Vec<types::SwiftType>, candidate: types::SwiftType) {
    let matches = types
        .iter()
        .enumerate()
        .filter(|(_, existing)| same_swift_identity(existing, &candidate))
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if let [index] = matches.as_slice() {
        types[*index] = merge_swift_types(&types[*index], candidate);
    } else {
        // Zero matches is a new occurrence. Multiple matches are ambiguous and
        // must also remain a distinct occurrence rather than name-deduplicating
        // descriptors or symbols that happen to share a spelling.
        types.push(candidate);
    }
}

fn same_swift_identity(existing: &types::SwiftType, candidate: &types::SwiftType) -> bool {
    if (existing.metadata_address.is_some() || candidate.metadata_address.is_some())
        && existing.name == candidate.name
    {
        return true;
    }
    if existing.address.is_some() && existing.address == candidate.address {
        return true;
    }
    let descriptor_and_symbol = matches!(
        (existing.source, candidate.source),
        (
            types::SwiftTypeSource::SwiftMetadata,
            types::SwiftTypeSource::DemangledSymbol
        ) | (
            types::SwiftTypeSource::DemangledSymbol,
            types::SwiftTypeSource::SwiftMetadata
        )
    );
    descriptor_and_symbol
        && existing.name == candidate.name
        && (existing.kind == candidate.kind
            || existing.kind == types::SwiftTypeKind::Unknown
            || candidate.kind == types::SwiftTypeKind::Unknown)
}

fn confidence_rank(confidence: types::SwiftTypeConfidence) -> u8 {
    match confidence {
        types::SwiftTypeConfidence::High => 1,
        types::SwiftTypeConfidence::Partial => 0,
    }
}

fn source_rank(source: types::SwiftTypeSource) -> u8 {
    match source {
        types::SwiftTypeSource::SwiftMetadata => 2,
        types::SwiftTypeSource::DemangledSymbol => 1,
        types::SwiftTypeSource::ObjCMetadata => 0,
    }
}

fn merge_swift_types(existing: &types::SwiftType, candidate: types::SwiftType) -> types::SwiftType {
    let existing_rank = confidence_rank(existing.confidence);
    let candidate_rank = confidence_rank(candidate.confidence);
    let mangled_name = existing
        .mangled_name
        .clone()
        .or_else(|| candidate.mangled_name.clone());
    let address = existing.address.or(candidate.address);
    let metadata_address = existing.metadata_address.or(candidate.metadata_address);
    let fields = existing.fields.clone().or_else(|| candidate.fields.clone());
    let mut preferred = if candidate_rank > existing_rank
        || (candidate_rank == existing_rank
            && existing.kind == types::SwiftTypeKind::Unknown
            && candidate.kind != types::SwiftTypeKind::Unknown)
        || (candidate_rank == existing_rank
            && existing.kind == candidate.kind
            && source_rank(candidate.source) > source_rank(existing.source))
    {
        candidate
    } else {
        existing.clone()
    };

    preferred.mangled_name = mangled_name;
    preferred.address = address;
    preferred.metadata_address = metadata_address;
    preferred.fields = fields;
    preferred
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    struct RuntimeNameDemangler;

    impl SwiftDemangler for RuntimeNameDemangler {
        fn demangle(&self, symbol: &str) -> Result<Option<String>> {
            Ok(match symbol {
                "_TtC4Demo6Widget" => Some("Demo.Widget".to_owned()),
                "_TtP4Demo8Drawable_" => Some("Demo.Drawable".to_owned()),
                _ => None,
            })
        }
    }

    #[test]
    fn objc_runtime_names_become_swift_names_and_retain_identity() {
        let ty = swift_type_from_objc_runtime_name(
            "_TtC4Demo6Widget",
            types::SwiftTypeKind::Class,
            &RuntimeNameDemangler,
        )
        .expect("runtime name demangles");
        assert_eq!(ty.name, "Demo.Widget");
        assert_eq!(ty.mangled_name.as_deref(), Some("_TtC4Demo6Widget"));
        assert_eq!(ty.kind, types::SwiftTypeKind::Class);

        let protocol = swift_type_from_objc_runtime_name(
            "_TtP4Demo8Drawable_",
            types::SwiftTypeKind::Protocol,
            &RuntimeNameDemangler,
        )
        .expect("protocol name demangles");
        assert_eq!(protocol.name, "Demo.Drawable");
        assert_eq!(protocol.kind, types::SwiftTypeKind::Protocol);
    }

    #[test]
    fn prefers_high_confidence_over_partial() {
        let mut types = Vec::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Unknown,
                mangled_name: Some("$s4Demo6WidgetC".into()),
                address: Some(0x1000),
                metadata_address: None,
                source: types::SwiftTypeSource::DemangledSymbol,
                confidence: types::SwiftTypeConfidence::Partial,
                fields: None,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: None,
                metadata_address: None,
                source: types::SwiftTypeSource::SwiftMetadata,
                confidence: types::SwiftTypeConfidence::High,
                fields: None,
            },
        );

        let ty = types
            .iter()
            .find(|value| value.name == "Demo.Widget")
            .unwrap();
        assert_eq!(ty.kind, types::SwiftTypeKind::Class);
        assert_eq!(ty.source, types::SwiftTypeSource::SwiftMetadata);
        assert_eq!(ty.confidence, types::SwiftTypeConfidence::High);
        assert_eq!(ty.mangled_name.as_deref(), Some("$s4Demo6WidgetC"));
        assert_eq!(ty.address, Some(0x1000));
    }

    #[test]
    fn preserves_symbol_details_when_replacing_partial_metadata() {
        let mut types = Vec::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Unknown,
                mangled_name: Some("$s4Demo6WidgetC".into()),
                address: Some(0x2000),
                metadata_address: None,
                source: types::SwiftTypeSource::DemangledSymbol,
                confidence: types::SwiftTypeConfidence::Partial,
                fields: None,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: None,
                metadata_address: None,
                source: types::SwiftTypeSource::SwiftMetadata,
                confidence: types::SwiftTypeConfidence::High,
                fields: None,
            },
        );

        let ty = types
            .iter()
            .find(|value| value.name == "Demo.Widget")
            .unwrap();
        assert_eq!(ty.kind, types::SwiftTypeKind::Class);
        assert_eq!(ty.source, types::SwiftTypeSource::SwiftMetadata);
        assert_eq!(ty.confidence, types::SwiftTypeConfidence::High);
        assert_eq!(ty.mangled_name.as_deref(), Some("$s4Demo6WidgetC"));
        assert_eq!(ty.address, Some(0x2000));
    }

    #[test]
    fn equal_confidence_merge_keeps_richer_symbol_details() {
        let mut types = Vec::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: None,
                metadata_address: None,
                source: types::SwiftTypeSource::SwiftMetadata,
                confidence: types::SwiftTypeConfidence::High,
                fields: None,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: Some("$s4Demo6WidgetC".into()),
                address: Some(0x3000),
                metadata_address: None,
                source: types::SwiftTypeSource::DemangledSymbol,
                confidence: types::SwiftTypeConfidence::High,
                fields: None,
            },
        );

        let ty = types
            .iter()
            .find(|value| value.name == "Demo.Widget")
            .unwrap();
        assert_eq!(ty.source, types::SwiftTypeSource::SwiftMetadata);
        assert_eq!(ty.mangled_name.as_deref(), Some("$s4Demo6WidgetC"));
        assert_eq!(ty.address, Some(0x3000));
    }

    #[test]
    fn native_metadata_remains_authoritative_when_objc_adds_a_runtime_name() {
        let mut types = Vec::new();
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: None,
                address: Some(0x4000),
                metadata_address: None,
                source: types::SwiftTypeSource::SwiftMetadata,
                confidence: types::SwiftTypeConfidence::High,
                fields: None,
            },
        );
        insert_swift_type(
            &mut types,
            types::SwiftType {
                name: "Demo.Widget".into(),
                kind: types::SwiftTypeKind::Class,
                mangled_name: Some("_TtC4Demo6Widget".into()),
                address: None,
                metadata_address: None,
                source: types::SwiftTypeSource::ObjCMetadata,
                confidence: types::SwiftTypeConfidence::High,
                fields: None,
            },
        );

        let native = types
            .iter()
            .find(|value| value.source == types::SwiftTypeSource::SwiftMetadata)
            .unwrap();
        assert_eq!(types.len(), 2, "name-only ObjC evidence must not merge");
        let ty = native;
        assert_eq!(ty.source, types::SwiftTypeSource::SwiftMetadata);
        assert_eq!(ty.mangled_name, None);
        assert_eq!(ty.address, Some(0x4000));
    }

    #[test]
    fn duplicate_descriptor_names_at_distinct_addresses_remain_occurrences() {
        let mut types = Vec::new();
        for address in [0x1000, 0x2000] {
            insert_swift_type(
                &mut types,
                types::SwiftType {
                    name: "Demo.Widget".into(),
                    kind: types::SwiftTypeKind::Struct,
                    mangled_name: None,
                    address: Some(address),
                    metadata_address: None,
                    source: types::SwiftTypeSource::SwiftMetadata,
                    confidence: types::SwiftTypeConfidence::High,
                    fields: None,
                },
            );
        }
        assert_eq!(types.len(), 2);
    }

    #[test]
    fn emitted_metadata_is_retained_without_treating_an_accessor_as_an_instance() {
        let descriptor = extract_swift_type(
            "nominal type descriptor for Demo.Value",
            "_$s4Demo5ValueVMn",
            0x1000,
        )
        .expect("descriptor");
        let metadata =
            extract_swift_type("type metadata for Demo.Value", "_$s4Demo5ValueVN", 0x2000)
                .expect("metadata");
        let accessor = extract_swift_type(
            "type metadata accessor for Demo.Value",
            "_$s4Demo5ValueVMa",
            0x3000,
        )
        .expect("accessor");

        let mut types = Vec::new();
        insert_swift_type(&mut types, descriptor);
        insert_swift_type(&mut types, metadata);
        insert_swift_type(&mut types, accessor);

        assert_eq!(types.len(), 1);
        assert_eq!(types[0].address, Some(0x1000));
        assert_eq!(types[0].metadata_address, Some(0x2000));
        assert_ne!(types[0].metadata_address, Some(0x3000));
    }
}
