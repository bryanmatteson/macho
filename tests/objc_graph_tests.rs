use macho::model::container::MachContainer;
use macho::objc::graph::ObjCGraph;
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
