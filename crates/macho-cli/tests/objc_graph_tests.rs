use std::collections::BTreeMap;

use macho::analysis::reconstruct::objc::graph::{
    ClassNode, MethodEntry, MethodKind, MethodOrigin, ObjCGraph, PropertyEntry, ProtocolNode,
    SelectorOwner,
};
use macho::metadata::objc::{
    ObjCCategory, ObjCClass, ObjCMetadata, ObjCMethod, ObjCProperty, ObjCProtocol,
    parse_objc_metadata,
};
use macho::model::addr::ThinFileOffset;
use macho::model::addr::Va;
use macho::model::container::MachoContainer;

fn graph_for(path: &str) -> Option<ObjCGraph> {
    let data = std::fs::read(path).expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };
    let meta = parse_objc_metadata(macho).ok()?;
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
    if let Some(node) = graph.class("PLUContext")
        && let Some(method) = node.instance_methods.first()
    {
        let owners = graph.selector_owners(&method.selector);
        assert!(
            !owners.is_empty(),
            "selector '{}' should have at least one owner",
            method.selector
        );
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
                    .filter(|m| {
                        matches!(
                            m.origin,
                            macho::analysis::reconstruct::objc::graph::MethodOrigin::Class
                        )
                    })
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
    for proto in graph.protocols.values() {
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
        macho::analysis::reconstruct::objc::graph::MethodResolution::Inherited { .. }
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
fn graph_all_methods_includes_inherited_methods_without_overriding_direct_ones() {
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
        selectors: BTreeMap::new(),
    };

    let methods = graph
        .all_methods("ChildWidget")
        .expect("expected child class methods");
    let selectors: Vec<_> = methods
        .instance
        .iter()
        .map(|method| method.selector.as_str())
        .collect();

    assert!(selectors.contains(&"paint"));
    assert!(selectors.contains(&"draw"));
    assert_eq!(methods.instance.len(), 2);
}

#[test]
fn graph_all_methods_tolerates_unresolved_superclass() {
    let subclass = ClassNode {
        name: "Widget".into(),
        superclass: Some("NSObject".into()),
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

    let graph = ObjCGraph {
        classes: BTreeMap::from([(subclass.name.clone(), subclass)]),
        protocols: BTreeMap::<String, ProtocolNode>::new(),
        selectors: BTreeMap::new(),
    };

    let methods = graph
        .all_methods("Widget")
        .expect("expected methods even when superclass metadata is absent");
    assert_eq!(methods.instance.len(), 1);
    assert_eq!(methods.instance[0].selector, "draw");
    assert!(methods.class.is_empty());
}

#[test]
fn graph_method_origin_json_is_tagged_and_machine_readable() {
    let class_json =
        serde_json::to_value(MethodOrigin::Class).expect("serialize class method origin");
    assert_eq!(class_json, serde_json::json!({ "kind": "class" }));

    let category_json = serde_json::to_value(MethodOrigin::Category("Debug".into()))
        .expect("serialize category method origin");
    assert_eq!(
        category_json,
        serde_json::json!({ "kind": "category", "category": "Debug" })
    );
}

#[test]
fn graph_folds_category_protocols_into_class_and_protocol_views() {
    let metadata = ObjCMetadata {
        classes: vec![ObjCClass {
            name: "Widget".into(),
            superclass_name: Some("NSObject".into()),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            ivars: Vec::new(),
            properties: vec![ObjCProperty {
                name: "title".into(),
                attributes: "T@\"NSString\",&,N,V_title".into(),
                is_class: false,
            }],
            protocols: vec!["WidgetBase".into()],
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        }],
        categories: vec![ObjCCategory {
            name: "Debug".into(),
            class_name: "Widget".into(),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            properties: Vec::new(),
            protocols: vec!["Debuggable".into()],
        }],
        protocols: vec![
            ObjCProtocol {
                name: "WidgetBase".into(),
                instance_methods: Vec::new(),
                class_methods: Vec::new(),
                optional_instance_methods: Vec::new(),
                optional_class_methods: Vec::new(),
                properties: Vec::new(),
                adopted_protocols: Vec::new(),
            },
            ObjCProtocol {
                name: "Debuggable".into(),
                instance_methods: Vec::new(),
                class_methods: Vec::new(),
                optional_instance_methods: Vec::new(),
                optional_class_methods: Vec::new(),
                properties: Vec::new(),
                adopted_protocols: Vec::new(),
            },
        ],
    };

    let graph = ObjCGraph::build(&metadata);
    let class = graph.class("Widget").expect("expected Widget class");
    assert!(class.protocols.contains(&"Debuggable".to_string()));
    assert!(class.properties.contains(&PropertyEntry {
        name: "title".into(),
        is_class: false,
    }));

    let protocol = graph
        .protocol("Debuggable")
        .expect("expected Debuggable protocol");
    assert!(protocol.conforming_classes.contains(&"Widget".to_string()));
}

#[test]
fn graph_method_impl_helpers_report_va_and_offset() {
    let data = std::fs::read("/usr/bin/plutil").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };
    let meta = parse_objc_metadata(macho).expect("should have ObjC metadata");
    let graph = ObjCGraph::build_from_mach(&meta, macho);
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
        .method_impl_offset(macho, class_name, &method.selector, MethodKind::Instance)
        .expect("expected method file offset");
    let expected_offset = macho
        .address_map()
        .va_to_thin_offset(macho::model::addr::Va(method.imp))
        .expect("expected address-map translation");
    assert_eq!(method_offset, expected_offset);
    assert!(matches!(method_offset, ThinFileOffset(_)));
}

#[test]
fn no_objc_graph_for_minimal_binary() {
    // /usr/bin/true has no ObjC metadata
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };
    // parse_objc_metadata might succeed with empty data or fail — both are fine
    if let Ok(meta) = parse_objc_metadata(macho) {
        let graph = ObjCGraph::build(&meta);
        // Should just be empty
        assert!(graph.classes.is_empty());
    }
}

#[test]
fn objc_graph_via_ext_matches_direct_build() {
    let data = std::fs::read("/usr/bin/plutil").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };

    let meta = parse_objc_metadata(macho).expect("should have ObjC metadata");
    let direct = ObjCGraph::build_from_mach(&meta, macho);
    let via_ext: ObjCGraph = macho.ext().expect("objc graph ext");

    assert_eq!(via_ext.classes.len(), direct.classes.len());
    assert_eq!(via_ext.protocols.len(), direct.protocols.len());
}

#[test]
fn graph_category_folding_uses_metadata_order_for_overrides() {
    let metadata = ObjCMetadata {
        classes: vec![ObjCClass {
            name: "Widget".into(),
            superclass_name: None,
            instance_methods: vec![ObjCMethod {
                name: "draw".into(),
                type_encoding: "v@:".into(),
                imp: Va(0x1000),
            }],
            class_methods: vec![],
            ivars: vec![],
            properties: vec![],
            protocols: vec![],
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        }],
        categories: vec![
            ObjCCategory {
                name: "Debug".into(),
                class_name: "Widget".into(),
                instance_methods: vec![ObjCMethod {
                    name: "draw".into(),
                    type_encoding: "v@:".into(),
                    imp: Va(0x2000),
                }],
                class_methods: vec![],
                properties: vec![],
                protocols: vec![],
            },
            ObjCCategory {
                name: "Release".into(),
                class_name: "Widget".into(),
                instance_methods: vec![ObjCMethod {
                    name: "draw".into(),
                    type_encoding: "v@:".into(),
                    imp: Va(0x3000),
                }],
                class_methods: vec![],
                properties: vec![],
                protocols: vec![],
            },
        ],
        protocols: vec![],
    };

    let graph = ObjCGraph::build(&metadata);
    let method = graph
        .find_method("Widget", "draw", MethodKind::Instance)
        .expect("folded selector should resolve");

    assert_eq!(method.imp, 0x3000);
    assert_eq!(method.origin, MethodOrigin::Category("Release".into()));

    let owners = graph.implementations_of("draw", MethodKind::Instance);
    assert_eq!(owners.len(), 3);
}

#[test]
fn graph_preserves_class_property_kind_and_protocol_properties() {
    let metadata = ObjCMetadata {
        classes: vec![ObjCClass {
            name: "Widget".into(),
            superclass_name: None,
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            ivars: Vec::new(),
            properties: vec![
                ObjCProperty {
                    name: "title".into(),
                    attributes: "T@\"NSString\",&,N".into(),
                    is_class: false,
                },
                ObjCProperty {
                    name: "sharedWidget".into(),
                    attributes: "T@\"Widget\",&,N".into(),
                    is_class: true,
                },
            ],
            protocols: vec!["WidgetProtocol".into()],
            instance_size: 0,
            is_meta: false,
            is_swift: false,
        }],
        categories: Vec::new(),
        protocols: vec![ObjCProtocol {
            name: "WidgetProtocol".into(),
            instance_methods: Vec::new(),
            class_methods: Vec::new(),
            optional_instance_methods: Vec::new(),
            optional_class_methods: Vec::new(),
            properties: vec![ObjCProperty {
                name: "delegate".into(),
                attributes: "T@\"NSObject\",W".into(),
                is_class: false,
            }],
            adopted_protocols: Vec::new(),
        }],
    };

    let graph = ObjCGraph::build(&metadata);
    let class = graph.class("Widget").expect("expected Widget class");
    assert!(class.properties.contains(&PropertyEntry {
        name: "title".into(),
        is_class: false,
    }));
    assert!(class.properties.contains(&PropertyEntry {
        name: "sharedWidget".into(),
        is_class: true,
    }));

    let proto = graph.protocol("WidgetProtocol").expect("expected protocol");
    assert!(proto.properties.contains(&PropertyEntry {
        name: "delegate".into(),
        is_class: false,
    }));
}
