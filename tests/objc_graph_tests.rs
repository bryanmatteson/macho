use std::collections::BTreeMap;

use macho::addr::ThinFileOffset;
use macho::model::container::MachContainer;
use macho::objc::graph::{
    ClassNode, MethodEntry, MethodKind, MethodOrigin, ObjCGraph, ProtocolNode, SelectorOwner,
};
use macho::objc::parse_objc_metadata;

fn graph_for(path: &str) -> Option<ObjCGraph> {
    let data = std::fs::read(path).expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };
    let meta = parse_objc_metadata(mach).ok()?;
    Some(ObjCGraph::build(&meta))
}

#[test]
fn graph_classes_from_plutil() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    assert!(!graph.classes.is_empty(), "plutil should have ObjC classes");
}

#[test]
fn graph_class_lookup() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    // PLUContext is a known class in plutil
    let node = graph.class("PLUContext");
    assert!(node.is_some(), "PLUContext should exist in plutil graph");

    let node = node.unwrap();
    assert_eq!(node.name, "PLUContext");
    assert!(!node.instance_methods.is_empty());
}

#[test]
fn graph_superclass_chain() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    let chain = graph.superclass_chain("PLUContext");
    // PLUContext should inherit from NSObject
    assert!(
        chain.contains(&"NSObject"),
        "PLUContext should descend from NSObject, got: {:?}",
        chain
    );
}

#[test]
fn graph_selector_index() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    assert!(!graph.selectors.is_empty(), "should have indexed selectors");
}

#[test]
fn graph_selector_lookup_existing() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    // Find any selector from PLUContext
    if let Some(node) = graph.class("PLUContext") {
        if let Some(method) = node.instance_methods.first() {
            let owners = graph.selector_owners(&method.selector);
            assert!(
                !owners.is_empty(),
                "selector '{}' should have at least one owner",
                method.selector
            );
        }
    }
}

#[test]
fn graph_selector_lookup_nonexistent() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    let owners = graph.selector_owners("__totally_nonexistent_selector__");
    assert!(owners.is_empty());
}

#[test]
fn graph_effective_methods_includes_all() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    if let Some(node) = graph.class("PLUContext") {
        let effective = graph.effective_instance_methods("PLUContext");
        // Effective methods should include at least all class-declared methods
        assert!(
            effective.len()
                >= node
                    .instance_methods
                    .iter()
                    .filter(|m| { matches!(m.origin, macho::objc::graph::MethodOrigin::Class) })
                    .count()
        );

        assert_eq!(
            effective.len(),
            node.effective_instance_methods.len(),
            "effective helper should match the canonical class snapshot"
        );
    }
}

#[test]
fn graph_serializes_to_json() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    let json = serde_json::to_string(&graph).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed["classes"].is_object());
    assert!(parsed["protocols"].is_object());
    assert!(parsed["selectors"].is_object());
    let any_owner = parsed["selectors"]
        .as_object()
        .and_then(|selectors| selectors.values().next())
        .and_then(|owners| owners.as_array())
        .and_then(|owners| owners.first())
        .expect("expected selector owners");
    assert!(any_owner["kind"].is_string());
}

#[test]
fn graph_protocol_conforming_classes() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    for (_, proto) in &graph.protocols {
        for cls_name in &proto.conforming_classes {
            assert!(
                graph.classes.contains_key(cls_name),
                "conforming class '{}' for protocol '{}' should exist in classes map",
                cls_name,
                proto.name
            );
        }
    }
}

#[test]
fn graph_method_resolution_follows_inheritance() {
    let superclass = ClassNode {
        name: "BaseWidget".into(),
        superclass: None,
        is_swift: false,
        instance_methods: vec![MethodEntry {
            selector: "draw".into(),
            origin: MethodOrigin::Class,
            imp: 0x1000,
            imp_symbol: None,
        }],
        class_methods: vec![],
        effective_instance_methods: vec![MethodEntry {
            selector: "draw".into(),
            origin: MethodOrigin::Class,
            imp: 0x1000,
            imp_symbol: None,
        }],
        effective_class_methods: vec![],
        properties: vec![],
        ivars: vec![],
        protocols: vec![],
        categories: vec![],
    };
    let subclass = ClassNode {
        name: "ChildWidget".into(),
        superclass: Some("BaseWidget".into()),
        is_swift: false,
        instance_methods: vec![MethodEntry {
            selector: "paint".into(),
            origin: MethodOrigin::Class,
            imp: 0x2000,
            imp_symbol: None,
        }],
        class_methods: vec![],
        effective_instance_methods: vec![MethodEntry {
            selector: "paint".into(),
            origin: MethodOrigin::Class,
            imp: 0x2000,
            imp_symbol: None,
        }],
        effective_class_methods: vec![],
        properties: vec![],
        ivars: vec![],
        protocols: vec![],
        categories: vec![],
    };

    let graph = ObjCGraph {
        classes: BTreeMap::from([
            (superclass.name.clone(), superclass),
            (subclass.name.clone(), subclass),
        ]),
        protocols: BTreeMap::<String, ProtocolNode>::new(),
        selectors: BTreeMap::from([(
            "draw".into(),
            vec![SelectorOwner {
                class_name: "BaseWidget".into(),
                kind: MethodKind::Instance,
                origin: MethodOrigin::Class,
                imp: 0x1000,
                imp_symbol: None,
            }],
        )]),
    };

    assert!(
        graph
            .find_method("ChildWidget", "draw", MethodKind::Instance)
            .is_none(),
        "inherited selector should not be found as a direct implementation"
    );
    assert!(
        graph.responds_to("ChildWidget", "draw", MethodKind::Instance),
        "inherited selector should still be reported as handled"
    );

    let resolved = graph
        .resolve_inherited("ChildWidget", "draw", MethodKind::Instance)
        .expect("should resolve inherited implementation");
    assert_eq!(resolved.class_name, "BaseWidget");
    assert!(matches!(
        resolved.resolution,
        macho::objc::graph::MethodResolution::Inherited { .. }
    ));
}

#[test]
fn graph_all_methods_matches_effective_lists() {
    let graph = graph_for("/usr/bin/plutil").expect("should have ObjC metadata");
    let (all_methods, node) = graph
        .classes
        .values()
        .find_map(|class| {
            graph
                .all_methods(&class.name)
                .map(|all_methods| (all_methods, class))
        })
        .expect("expected a class with methods");
    assert_eq!(
        all_methods.instance.len(),
        node.effective_instance_methods.len()
    );
    assert_eq!(all_methods.class.len(), node.effective_class_methods.len());
}

#[test]
fn graph_method_impl_helpers_report_va_and_offset() {
    let data = std::fs::read("/usr/bin/plutil").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };
    let meta = parse_objc_metadata(mach).expect("should have ObjC metadata");
    let graph = ObjCGraph::build_from_mach(&meta, mach);
    let (class_name, method) = graph
        .classes
        .values()
        .find_map(|class| {
            class
                .effective_instance_methods
                .iter()
                .find(|method| method.imp != 0)
                .map(|method| (class.name.as_str(), method))
        })
        .expect("expected a class method with an implementation");

    let method_va = graph
        .method_impl_va(class_name, &method.selector, MethodKind::Instance)
        .expect("expected method VA");
    assert_eq!(method_va, method.imp);

    let method_offset = graph
        .method_impl_offset(mach, class_name, &method.selector, MethodKind::Instance)
        .expect("expected method file offset");
    let expected_offset = mach
        .address_map()
        .va_to_thin_offset(macho::addr::Va(method.imp))
        .expect("expected address-map translation");
    assert_eq!(method_offset, expected_offset);
    assert!(matches!(method_offset, ThinFileOffset(_)));
}

#[test]
fn no_objc_graph_for_minimal_binary() {
    // /usr/bin/true has no ObjC metadata
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let mach = match &container {
        MachContainer::Fat(fat) => &fat.arches()[0].mach,
        MachContainer::Thin(mach) => mach,
    };
    // parse_objc_metadata might succeed with empty data or fail — both are fine
    if let Ok(meta) = parse_objc_metadata(mach) {
        let graph = ObjCGraph::build(&meta);
        // Should just be empty
        assert!(graph.classes.is_empty());
    }
}
