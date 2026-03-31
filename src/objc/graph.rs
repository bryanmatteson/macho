use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::ObjCMetadata;
use super::types::ObjCCategory;
use crate::model::mach::MachFile;
use crate::parse::parse_symbol_table;

#[derive(Debug, Clone, Serialize)]
pub struct ObjCGraph {
    pub classes: BTreeMap<String, ClassNode>,
    pub protocols: BTreeMap<String, ProtocolNode>,
    pub selectors: BTreeMap<String, Vec<SelectorOwner>>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ClassNode {
    pub name: String,
    pub superclass: Option<String>,
    pub is_swift: bool,
    pub instance_methods: Vec<MethodEntry>,
    pub class_methods: Vec<MethodEntry>,
    pub properties: Vec<String>,
    pub ivars: Vec<String>,
    pub protocols: Vec<String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodEntry {
    pub selector: String,
    pub origin: MethodOrigin,
    pub imp: u64,
    pub imp_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum MethodOrigin {
    Class,
    Category(String),
}

#[derive(Debug, Clone, Serialize)]
pub struct ProtocolNode {
    pub name: String,
    pub instance_methods: Vec<String>,
    pub class_methods: Vec<String>,
    pub optional_instance_methods: Vec<String>,
    pub optional_class_methods: Vec<String>,
    pub adopted_protocols: Vec<String>,
    pub conforming_classes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SelectorOwner {
    pub class_name: String,
    pub is_class_method: bool,
    pub origin: MethodOrigin,
    pub imp: u64,
    pub imp_symbol: Option<String>,
}

impl ObjCGraph {
    /// Build from metadata alone (no symbol cross-references).
    pub fn build(metadata: &ObjCMetadata) -> Self {
        Self::build_with_symbols(metadata, &BTreeMap::new())
    }

    /// Build from metadata with symbol cross-references from the binary.
    pub fn build_from_mach(metadata: &ObjCMetadata, mach: &MachFile<'_>) -> Self {
        let addr_to_sym = build_address_symbol_map(mach);
        Self::build_with_symbols(metadata, &addr_to_sym)
    }

    fn build_with_symbols(metadata: &ObjCMetadata, addr_to_sym: &BTreeMap<u64, String>) -> Self {
        let mut classes = BTreeMap::new();
        let mut protocols = BTreeMap::new();
        let mut selectors: BTreeMap<String, Vec<SelectorOwner>> = BTreeMap::new();

        // Build class nodes
        for cls in &metadata.classes {
            let node = ClassNode {
                name: cls.name.clone(),
                superclass: cls.superclass_name.clone(),
                is_swift: cls.is_swift,
                instance_methods: cls
                    .instance_methods
                    .iter()
                    .map(|m| MethodEntry {
                        selector: m.name.clone(),
                        origin: MethodOrigin::Class,
                        imp: m.imp.0,
                        imp_symbol: addr_to_sym.get(&m.imp.0).cloned(),
                    })
                    .collect(),
                class_methods: cls
                    .class_methods
                    .iter()
                    .map(|m| MethodEntry {
                        selector: m.name.clone(),
                        origin: MethodOrigin::Class,
                        imp: m.imp.0,
                        imp_symbol: addr_to_sym.get(&m.imp.0).cloned(),
                    })
                    .collect(),
                properties: cls.properties.iter().map(|p| p.name.clone()).collect(),
                ivars: cls.ivars.iter().map(|iv| iv.name.clone()).collect(),
                protocols: cls.protocols.clone(),
                categories: Vec::new(),
            };

            // Index selectors
            for m in &cls.instance_methods {
                index_selector(
                    &mut selectors,
                    &m.name,
                    &cls.name,
                    false,
                    MethodOrigin::Class,
                    m.imp.0,
                    addr_to_sym.get(&m.imp.0).cloned(),
                );
            }
            for m in &cls.class_methods {
                index_selector(
                    &mut selectors,
                    &m.name,
                    &cls.name,
                    true,
                    MethodOrigin::Class,
                    m.imp.0,
                    addr_to_sym.get(&m.imp.0).cloned(),
                );
            }

            classes.insert(cls.name.clone(), node);
        }

        // Fold categories
        for cat in &metadata.categories {
            if let Some(node) = classes.get_mut(&cat.class_name) {
                node.categories.push(cat.name.clone());
                fold_category_methods(node, cat, &mut selectors, addr_to_sym);
            }
        }

        // Build protocol nodes
        for proto in &metadata.protocols {
            let conforming: Vec<String> = classes
                .values()
                .filter(|c| c.protocols.contains(&proto.name))
                .map(|c| c.name.clone())
                .collect();

            protocols.insert(
                proto.name.clone(),
                ProtocolNode {
                    name: proto.name.clone(),
                    instance_methods: proto
                        .instance_methods
                        .iter()
                        .map(|m| m.name.clone())
                        .collect(),
                    class_methods: proto.class_methods.iter().map(|m| m.name.clone()).collect(),
                    optional_instance_methods: proto
                        .optional_instance_methods
                        .iter()
                        .map(|m| m.name.clone())
                        .collect(),
                    optional_class_methods: proto
                        .optional_class_methods
                        .iter()
                        .map(|m| m.name.clone())
                        .collect(),
                    adopted_protocols: proto.adopted_protocols.clone(),
                    conforming_classes: conforming,
                },
            );
        }

        Self {
            classes,
            protocols,
            selectors,
        }
    }

    pub fn class(&self, name: &str) -> Option<&ClassNode> {
        self.classes.get(name)
    }

    pub fn protocol(&self, name: &str) -> Option<&ProtocolNode> {
        self.protocols.get(name)
    }

    pub fn selector_owners(&self, selector: &str) -> &[SelectorOwner] {
        self.selectors
            .get(selector)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn superclass_chain(&self, class_name: &str) -> Vec<&str> {
        let mut chain = Vec::new();
        let mut current = class_name;
        let mut seen = BTreeSet::new();
        while let Some(node) = self.classes.get(current) {
            if let Some(ref sup) = node.superclass {
                if !seen.insert(sup.as_str()) {
                    break; // cycle guard
                }
                chain.push(sup.as_str());
                current = sup;
            } else {
                break;
            }
        }
        chain
    }

    pub fn effective_instance_methods(&self, class_name: &str) -> Vec<&MethodEntry> {
        let mut methods = Vec::new();
        let mut seen = BTreeSet::new();

        // Own methods (categories override class methods for same selector)
        if let Some(node) = self.classes.get(class_name) {
            // Category methods first (last category wins in ObjC runtime)
            for m in node.instance_methods.iter().rev() {
                if seen.insert(&m.selector) {
                    methods.push(m);
                }
            }
        }
        methods.reverse();
        methods
    }
}

fn fold_category_methods(
    node: &mut ClassNode,
    cat: &ObjCCategory,
    selectors: &mut BTreeMap<String, Vec<SelectorOwner>>,
    addr_to_sym: &BTreeMap<u64, String>,
) {
    let origin = MethodOrigin::Category(cat.name.clone());

    for m in &cat.instance_methods {
        let sym = addr_to_sym.get(&m.imp.0).cloned();
        node.instance_methods.push(MethodEntry {
            selector: m.name.clone(),
            origin: origin.clone(),
            imp: m.imp.0,
            imp_symbol: sym.clone(),
        });
        index_selector(
            selectors,
            &m.name,
            &cat.class_name,
            false,
            origin.clone(),
            m.imp.0,
            sym,
        );
    }
    for m in &cat.class_methods {
        let sym = addr_to_sym.get(&m.imp.0).cloned();
        node.class_methods.push(MethodEntry {
            selector: m.name.clone(),
            origin: origin.clone(),
            imp: m.imp.0,
            imp_symbol: sym.clone(),
        });
        index_selector(
            selectors,
            &m.name,
            &cat.class_name,
            true,
            origin.clone(),
            m.imp.0,
            sym,
        );
    }
}

fn index_selector(
    selectors: &mut BTreeMap<String, Vec<SelectorOwner>>,
    selector: &str,
    class_name: &str,
    is_class_method: bool,
    origin: MethodOrigin,
    imp: u64,
    imp_symbol: Option<String>,
) {
    selectors
        .entry(selector.to_string())
        .or_default()
        .push(SelectorOwner {
            class_name: class_name.to_string(),
            is_class_method,
            origin,
            imp,
            imp_symbol,
        });
}

fn build_address_symbol_map(mach: &MachFile<'_>) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    if let Ok(symtab) = parse_symbol_table(mach) {
        for sym in symtab.symbols() {
            if sym.is_defined() && sym.value != 0 {
                map.insert(sym.value, sym.name.to_string());
            }
        }
    }
    map
}
