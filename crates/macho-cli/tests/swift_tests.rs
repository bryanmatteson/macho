//! Swift metadata corpus checks against Apple system binaries.
#![cfg(target_os = "macos")]

use macho::metadata::swift::SwiftTypeIndex;
use macho::metadata::swift::types::{
    SwiftType, SwiftTypeConfidence, SwiftTypeKind, SwiftTypeSource,
};
use macho::model::container::MachoContainer;

fn swift_index_for(path: &str) -> SwiftTypeIndex {
    let data = std::fs::read(path).expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };
    macho.ext::<SwiftTypeIndex>().expect("swift ext")
}

#[test]
fn swift_type_names_are_clean() {
    let index = swift_index_for("/usr/bin/plutil");
    for t in &index.types {
        assert!(
            !t.name.starts_with('('),
            "type name should not start with '(' (broken extension parsing): '{}'",
            t.name
        );
        assert!(!t.name.is_empty(), "type name should not be empty");
        assert!(
            !t.name.contains(' '),
            "type name should not contain spaces: '{}'",
            t.name
        );
    }
}

#[test]
fn swift_type_kind_filter() {
    let index = swift_index_for("/usr/bin/plutil");
    let classes = index.classes();
    let structs = index.structs();
    let protos = index.protocols();
    let unknown = index.by_kind(SwiftTypeKind::Unknown);

    // The union of all known kinds plus Unknown must equal the full type list.
    let total = classes.len() + structs.len() + protos.len() + index.enums().len() + unknown.len();
    assert_eq!(total, index.types.len());
}

#[test]
fn swift_find_by_name() {
    let index = swift_index_for("/usr/bin/plutil");
    // Try to find a common Foundation type
    if let Some(t) = index.find("Foundation.URL") {
        assert!(
            t.kind == SwiftTypeKind::Struct || t.kind == SwiftTypeKind::Class,
            "Foundation.URL should be a struct, got: {:?}",
            t.kind
        );
    }
}

#[test]
fn swift_types_sorted() {
    let index = swift_index_for("/usr/bin/plutil");
    for window in index.types.windows(2) {
        assert!(
            window[0].name <= window[1].name,
            "types should be sorted: '{}' > '{}'",
            window[0].name,
            window[1].name
        );
    }
}

#[test]
fn swift_empty_for_c_binary() {
    // /usr/bin/true is a minimal C binary with no Swift
    let index = swift_index_for("/usr/bin/true");
    // Might have some due to ObjC-marked classes; but should have no demangled symbols
    let from_symbols: Vec<_> = index
        .types
        .iter()
        .filter(|t| t.source == SwiftTypeSource::DemangledSymbol)
        .collect();
    assert!(
        from_symbols.is_empty(),
        "/usr/bin/true should have no Swift demangled symbols"
    );
}

#[test]
fn swift_type_index_serializes() {
    let index = SwiftTypeIndex {
        types: vec![SwiftType {
            name: "Demo.Widget".into(),
            kind: SwiftTypeKind::Class,
            mangled_name: Some("$s4Demo6WidgetC".into()),
            address: Some(0x1000),
            metadata_address: None,
            source: SwiftTypeSource::DemangledSymbol,
            confidence: SwiftTypeConfidence::High,
            fields: None,
            superclass: None,
        }],
        parents: Vec::new(),
        conformances: Vec::new(),
        associated_types: Vec::new(),
    };
    let json = serde_json::to_string(&index).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed["types"].is_array());
    assert!(parsed["types"][0]["confidence"].is_string());
}

#[test]
fn swift_confidence_helpers_are_consistent() {
    let index = swift_index_for("/usr/bin/plutil");
    let high = index.high_confidence();
    let partial = index.partial();
    assert_eq!(high.len() + partial.len(), index.types.len());
}

#[test]
fn swift_type_confidence_serializes() {
    let ty = SwiftType {
        name: "Demo.Widget".into(),
        kind: SwiftTypeKind::Class,
        mangled_name: Some("$s4Demo6WidgetC".into()),
        address: Some(0x1000),
        metadata_address: None,
        source: SwiftTypeSource::DemangledSymbol,
        confidence: SwiftTypeConfidence::High,
        fields: None,
        superclass: None,
    };
    let json = serde_json::to_value(&ty).expect("serialize");
    assert_eq!(json["confidence"], "high");
}

#[test]
fn swift_type_json_uses_machine_readable_kind_and_source_names() {
    let ty = SwiftType {
        name: "Demo.Widget".into(),
        kind: SwiftTypeKind::Class,
        mangled_name: Some("$s4Demo6WidgetC".into()),
        address: Some(0x1000),
        metadata_address: None,
        source: SwiftTypeSource::DemangledSymbol,
        confidence: SwiftTypeConfidence::High,
        fields: None,
        superclass: None,
    };
    let json = serde_json::to_value(&ty).expect("serialize");
    assert_eq!(json["kind"], "class");
    assert_eq!(json["source"], "demangled_symbol");
}
