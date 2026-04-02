use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use macho_core::ext::MachoExt;
use macho_core::model::addr::ThinFileOffset;
use macho_core::model::macho_file::MachoFile;
use macho_core::model::symbol::SymbolTable;
use macho_core::objc::ObjCMetadata;
use macho_core::objc::types::ObjCCategory;

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
    pub effective_instance_methods: Vec<MethodEntry>,
    pub effective_class_methods: Vec<MethodEntry>,
    pub properties: Vec<PropertyEntry>,
    pub ivars: Vec<String>,
    pub protocols: Vec<String>,
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct AllMethods {
    pub instance: Vec<MethodEntry>,
    pub class: Vec<MethodEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MethodEntry {
    pub selector: String,
    pub origin: MethodOrigin,
    pub imp: u64,
    pub imp_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "category", rename_all = "snake_case")]
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
    pub properties: Vec<PropertyEntry>,
    pub adopted_protocols: Vec<String>,
    pub conforming_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct PropertyEntry {
    pub name: String,
    pub is_class: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MethodKind {
    Instance,
    Class,
}

impl MethodKind {
    pub fn prefix(self) -> char {
        match self {
            Self::Instance => '-',
            Self::Class => '+',
        }
    }

    pub fn is_class(self) -> bool {
        matches!(self, Self::Class)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct SelectorOwner {
    pub class_name: String,
    pub kind: MethodKind,
    pub origin: MethodOrigin,
    pub imp: u64,
    pub imp_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ResolvedMethod {
    pub class_name: String,
    pub selector: String,
    pub kind: MethodKind,
    pub origin: MethodOrigin,
    pub imp: u64,
    pub imp_symbol: Option<String>,
    pub resolution: MethodResolution,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
pub enum MethodResolution {
    Direct,
    Inherited { from: String },
}

impl ObjCGraph {
    /// Build from metadata alone (no symbol cross-references).
    pub fn build(metadata: &ObjCMetadata) -> Self {
        Self::build_with_symbols(metadata, &BTreeMap::new())
    }

    /// Build from metadata with symbol cross-references from the binary.
    pub fn build_from_mach(metadata: &ObjCMetadata, macho: &MachoFile<'_>) -> Self {
        let addr_to_sym = build_address_symbol_map(macho);
        Self::build_with_symbols(metadata, &addr_to_sym)
    }

    fn build_with_symbols(metadata: &ObjCMetadata, addr_to_sym: &BTreeMap<u64, String>) -> Self {
        let mut classes = BTreeMap::new();
        let mut protocols = BTreeMap::new();
        let mut selectors: BTreeMap<String, Vec<SelectorOwner>> = BTreeMap::new();

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
                effective_instance_methods: Vec::new(),
                effective_class_methods: Vec::new(),
                properties: cls
                    .properties
                    .iter()
                    .map(|p| PropertyEntry {
                        name: p.name.clone(),
                        is_class: p.is_class,
                    })
                    .collect(),
                ivars: cls.ivars.iter().map(|iv| iv.name.clone()).collect(),
                protocols: cls.protocols.clone(),
                categories: Vec::new(),
            };

            for m in &cls.instance_methods {
                index_selector(
                    &mut selectors,
                    &m.name,
                    &cls.name,
                    MethodKind::Instance,
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
                    MethodKind::Class,
                    MethodOrigin::Class,
                    m.imp.0,
                    addr_to_sym.get(&m.imp.0).cloned(),
                );
            }

            classes.insert(cls.name.clone(), node);
        }

        for cat in &metadata.categories {
            if let Some(node) = classes.get_mut(&cat.class_name) {
                node.categories.push(cat.name.clone());
                node.protocols.extend(cat.protocols.iter().cloned());
                node.properties
                    .extend(cat.properties.iter().map(|prop| PropertyEntry {
                        name: prop.name.clone(),
                        is_class: prop.is_class,
                    }));
                fold_category_methods(node, cat, &mut selectors, addr_to_sym);
            }
        }

        for node in classes.values_mut() {
            finalize_class_node(node);
        }

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
                    instance_methods: sorted_unique(
                        proto
                            .instance_methods
                            .iter()
                            .map(|m| m.name.clone())
                            .collect(),
                    ),
                    class_methods: sorted_unique(
                        proto.class_methods.iter().map(|m| m.name.clone()).collect(),
                    ),
                    optional_instance_methods: sorted_unique(
                        proto
                            .optional_instance_methods
                            .iter()
                            .map(|m| m.name.clone())
                            .collect(),
                    ),
                    optional_class_methods: sorted_unique(
                        proto
                            .optional_class_methods
                            .iter()
                            .map(|m| m.name.clone())
                            .collect(),
                    ),
                    properties: sorted_unique_properties(
                        proto
                            .properties
                            .iter()
                            .map(|property| PropertyEntry {
                                name: property.name.clone(),
                                is_class: property.is_class,
                            })
                            .collect(),
                    ),
                    adopted_protocols: sorted_unique(proto.adopted_protocols.clone()),
                    conforming_classes: sorted_unique(conforming),
                },
            );
        }

        for owners in selectors.values_mut() {
            owners.sort_by(selector_owner_sort_key);
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

    pub fn implementations_of(&self, selector: &str, kind: MethodKind) -> Vec<SelectorOwner> {
        self.selector_owners(selector)
            .iter()
            .filter(|owner| owner.kind == kind)
            .cloned()
            .collect()
    }

    pub fn superclass_chain(&self, class_name: &str) -> Vec<&str> {
        let mut chain = Vec::new();
        let mut current = class_name;
        let mut seen = BTreeSet::new();
        while let Some(node) = self.classes.get(current) {
            if let Some(ref sup) = node.superclass {
                if !seen.insert(sup.as_str()) {
                    break;
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
        self.classes
            .get(class_name)
            .map(|node| node.effective_instance_methods.iter().collect())
            .unwrap_or_default()
    }

    pub fn effective_class_methods(&self, class_name: &str) -> Vec<&MethodEntry> {
        self.classes
            .get(class_name)
            .map(|node| node.effective_class_methods.iter().collect())
            .unwrap_or_default()
    }

    pub fn all_methods(&self, class_name: &str) -> Option<AllMethods> {
        Some(AllMethods {
            instance: self.collect_all_methods(class_name, MethodKind::Instance)?,
            class: self.collect_all_methods(class_name, MethodKind::Class)?,
        })
    }

    pub fn find_method(
        &self,
        class_name: &str,
        selector: &str,
        kind: MethodKind,
    ) -> Option<&MethodEntry> {
        let node = self.classes.get(class_name)?;
        match kind {
            MethodKind::Instance => node
                .effective_instance_methods
                .iter()
                .find(|m| m.selector == selector),
            MethodKind::Class => node
                .effective_class_methods
                .iter()
                .find(|m| m.selector == selector),
        }
    }

    pub fn resolve_inherited(
        &self,
        class_name: &str,
        selector: &str,
        kind: MethodKind,
    ) -> Option<ResolvedMethod> {
        let node = self.classes.get(class_name)?;

        if let Some(method) = self.find_method(class_name, selector, kind) {
            return Some(ResolvedMethod {
                class_name: class_name.to_string(),
                selector: selector.to_string(),
                kind,
                origin: method.origin.clone(),
                imp: method.imp,
                imp_symbol: method.imp_symbol.clone(),
                resolution: MethodResolution::Direct,
            });
        }

        for ancestor in self.superclass_chain(&node.name) {
            if let Some(method) = self.find_method(ancestor, selector, kind) {
                return Some(ResolvedMethod {
                    class_name: ancestor.to_string(),
                    selector: selector.to_string(),
                    kind,
                    origin: method.origin.clone(),
                    imp: method.imp,
                    imp_symbol: method.imp_symbol.clone(),
                    resolution: MethodResolution::Inherited {
                        from: ancestor.to_string(),
                    },
                });
            }
        }

        None
    }

    pub fn method_impl_va(
        &self,
        class_name: &str,
        selector: &str,
        kind: MethodKind,
    ) -> Option<u64> {
        self.resolve_inherited(class_name, selector, kind)
            .map(|resolved| resolved.imp)
    }

    pub fn method_impl_offset(
        &self,
        macho: &MachoFile<'_>,
        class_name: &str,
        selector: &str,
        kind: MethodKind,
    ) -> Option<ThinFileOffset> {
        let va = self.method_impl_va(class_name, selector, kind)?;
        macho
            .address_map()
            .va_to_thin_offset(macho_core::model::addr::Va(va))
            .ok()
    }

    pub fn responds_to(&self, class_name: &str, selector: &str, kind: MethodKind) -> bool {
        self.resolve_inherited(class_name, selector, kind).is_some()
    }

    fn collect_all_methods(&self, class_name: &str, kind: MethodKind) -> Option<Vec<MethodEntry>> {
        let mut current = Some(class_name);
        let mut seen = BTreeSet::new();
        let mut methods = BTreeMap::new();
        let mut saw_class = false;

        while let Some(name) = current {
            if !seen.insert(name) {
                break;
            }

            let Some(node) = self.classes.get(name) else {
                return if saw_class {
                    Some(methods.into_values().collect())
                } else {
                    None
                };
            };
            saw_class = true;
            let candidates = match kind {
                MethodKind::Instance => &node.effective_instance_methods,
                MethodKind::Class => &node.effective_class_methods,
            };

            for method in candidates {
                methods
                    .entry(method.selector.clone())
                    .or_insert_with(|| method.clone());
            }

            current = node.superclass.as_deref();
        }

        let mut methods: Vec<MethodEntry> = methods.into_values().collect();
        methods.sort_by(method_entry_sort_key);
        Some(methods)
    }
}

impl<'data> MachoExt<'data> for ObjCGraph {
    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> macho_core::Result<Self>
    where
        'data: 'mf,
    {
        let meta = macho.ext::<ObjCMetadata>()?;
        Ok(Self::build_from_mach(&meta, macho))
    }
}

fn finalize_class_node(node: &mut ClassNode) {
    let instance_methods = std::mem::take(&mut node.instance_methods);
    let class_methods = std::mem::take(&mut node.class_methods);

    node.effective_instance_methods = build_effective_methods(&instance_methods);
    node.effective_class_methods = build_effective_methods(&class_methods);

    node.instance_methods = sort_method_entries(instance_methods);
    node.class_methods = sort_method_entries(class_methods);
    node.properties = sorted_unique_properties(std::mem::take(&mut node.properties));
    node.ivars = sorted_unique(std::mem::take(&mut node.ivars));
    node.protocols = sorted_unique(std::mem::take(&mut node.protocols));
    node.categories = sorted_unique(std::mem::take(&mut node.categories));
}

fn build_effective_methods(entries: &[MethodEntry]) -> Vec<MethodEntry> {
    let mut map = BTreeMap::new();
    for entry in entries {
        // Static category folding is intentionally deterministic: class methods
        // are inserted first, then category methods are appended in metadata
        // traversal order, and the last definition for a selector wins.
        map.insert(entry.selector.clone(), entry.clone());
    }
    map.into_values().collect()
}

fn sort_method_entries(mut entries: Vec<MethodEntry>) -> Vec<MethodEntry> {
    entries.sort_by(method_entry_sort_key);
    entries
}

fn method_entry_sort_key(left: &MethodEntry, right: &MethodEntry) -> std::cmp::Ordering {
    left.selector
        .cmp(&right.selector)
        .then(method_origin_sort_key(&left.origin).cmp(&method_origin_sort_key(&right.origin)))
        .then(left.imp.cmp(&right.imp))
        .then(left.imp_symbol.cmp(&right.imp_symbol))
}

fn method_origin_sort_key(origin: &MethodOrigin) -> (u8, &str) {
    match origin {
        MethodOrigin::Class => (0, ""),
        MethodOrigin::Category(name) => (1, name.as_str()),
    }
}

fn sorted_unique(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values.dedup();
    values
}

fn sorted_unique_properties(mut values: Vec<PropertyEntry>) -> Vec<PropertyEntry> {
    values.sort();
    values.dedup();
    values
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
            MethodKind::Instance,
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
            MethodKind::Class,
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
    kind: MethodKind,
    origin: MethodOrigin,
    imp: u64,
    imp_symbol: Option<String>,
) {
    selectors
        .entry(selector.to_string())
        .or_default()
        .push(SelectorOwner {
            class_name: class_name.to_string(),
            kind,
            origin,
            imp,
            imp_symbol,
        });
}

fn selector_owner_sort_key(left: &SelectorOwner, right: &SelectorOwner) -> std::cmp::Ordering {
    left.class_name
        .cmp(&right.class_name)
        .then(left.kind.prefix().cmp(&right.kind.prefix()))
        .then(method_origin_sort_key(&left.origin).cmp(&method_origin_sort_key(&right.origin)))
        .then(left.imp.cmp(&right.imp))
        .then(left.imp_symbol.cmp(&right.imp_symbol))
}

fn build_address_symbol_map(macho: &MachoFile<'_>) -> BTreeMap<u64, String> {
    let mut map = BTreeMap::new();
    if let Ok(symtab) = macho.ext::<SymbolTable<'_>>() {
        for sym in symtab.symbols() {
            if sym.is_defined() && sym.value != 0 {
                map.insert(sym.value, sym.name.to_string());
            }
        }
    }
    map
}
