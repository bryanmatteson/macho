use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use macho_core::ext::MachoExt;
use macho_core::model::addr::ThinFileOffset;
use macho_core::model::macho_file::MachoFile;
use macho_core::model::symbol::SymbolTable;
use macho_objc::ObjCMetadata;
use macho_objc::types::ObjCCategory;

#[derive(Debug, Clone, Serialize)]
/// The ObjCGraph type.
pub struct ObjCGraph {
    /// The classes field.
    pub classes: BTreeMap<String, ClassNode>,
    /// The protocols field.
    pub protocols: BTreeMap<String, ProtocolNode>,
    /// The selectors field.
    pub selectors: BTreeMap<String, Vec<SelectorOwner>>,
}

#[derive(Debug, Clone, Serialize)]
/// The ClassNode type.
pub struct ClassNode {
    /// The name field.
    pub name: String,
    /// The superclass field.
    pub superclass: Option<String>,
    /// The is_swift field.
    pub is_swift: bool,
    /// The instance_methods field.
    pub instance_methods: Vec<MethodEntry>,
    /// The class_methods field.
    pub class_methods: Vec<MethodEntry>,
    /// The effective_instance_methods field.
    pub effective_instance_methods: Vec<MethodEntry>,
    /// The effective_class_methods field.
    pub effective_class_methods: Vec<MethodEntry>,
    /// The properties field.
    pub properties: Vec<PropertyEntry>,
    /// The ivars field.
    pub ivars: Vec<String>,
    /// The protocols field.
    pub protocols: Vec<String>,
    /// The categories field.
    pub categories: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
/// The AllMethods type.
pub struct AllMethods {
    /// The instance field.
    pub instance: Vec<MethodEntry>,
    /// The class field.
    pub class: Vec<MethodEntry>,
}

#[derive(Debug, Clone, Serialize)]
/// The MethodEntry type.
pub struct MethodEntry {
    /// The selector field.
    pub selector: String,
    /// The origin field.
    pub origin: MethodOrigin,
    /// The imp field.
    pub imp: u64,
    /// The imp_symbol field.
    pub imp_symbol: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "category", rename_all = "snake_case")]
/// The MethodOrigin type.
#[non_exhaustive]
pub enum MethodOrigin {
    /// The Class variant.
    Class,
    /// The Category variant.
    Category(String),
}

#[derive(Debug, Clone, Serialize)]
/// The ProtocolNode type.
pub struct ProtocolNode {
    /// The name field.
    pub name: String,
    /// The instance_methods field.
    pub instance_methods: Vec<String>,
    /// The class_methods field.
    pub class_methods: Vec<String>,
    /// The optional_instance_methods field.
    pub optional_instance_methods: Vec<String>,
    /// The optional_class_methods field.
    pub optional_class_methods: Vec<String>,
    /// The properties field.
    pub properties: Vec<PropertyEntry>,
    /// The adopted_protocols field.
    pub adopted_protocols: Vec<String>,
    /// The conforming_classes field.
    pub conforming_classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
/// The PropertyEntry type.
pub struct PropertyEntry {
    /// The name field.
    pub name: String,
    /// The is_class field.
    pub is_class: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
/// The MethodKind type.
#[non_exhaustive]
pub enum MethodKind {
    /// The Instance variant.
    Instance,
    /// The Class variant.
    Class,
}

impl MethodKind {
    /// Performs prefix.
    pub fn prefix(self) -> char {
        match self {
            Self::Instance => '-',
            Self::Class => '+',
        }
    }

    /// Performs is_class.
    pub fn is_class(self) -> bool {
        matches!(self, Self::Class)
    }
}

#[derive(Debug, Clone, Serialize)]
/// The SelectorOwner type.
pub struct SelectorOwner {
    /// The class_name field.
    pub class_name: String,
    /// The kind field.
    pub kind: MethodKind,
    /// The origin field.
    pub origin: MethodOrigin,
    /// The imp field.
    pub imp: u64,
    /// The imp_symbol field.
    pub imp_symbol: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
/// The ResolvedMethod type.
pub struct ResolvedMethod {
    /// The class_name field.
    pub class_name: String,
    /// The selector field.
    pub selector: String,
    /// The kind field.
    pub kind: MethodKind,
    /// The origin field.
    pub origin: MethodOrigin,
    /// The imp field.
    pub imp: u64,
    /// The imp_symbol field.
    pub imp_symbol: Option<String>,
    /// The resolution field.
    pub resolution: MethodResolution,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "resolution", rename_all = "snake_case")]
/// The MethodResolution type.
#[non_exhaustive]
pub enum MethodResolution {
    /// The Direct variant.
    Direct,
    /// The Inherited variant.
    Inherited {
        #[doc = "The from field."]
        from: String,
    },
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

    /// Performs class.
    pub fn class(&self, name: &str) -> Option<&ClassNode> {
        self.classes.get(name)
    }

    /// Performs protocol.
    pub fn protocol(&self, name: &str) -> Option<&ProtocolNode> {
        self.protocols.get(name)
    }

    /// Performs selector_owners.
    pub fn selector_owners(&self, selector: &str) -> &[SelectorOwner] {
        self.selectors
            .get(selector)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Performs implementations_of.
    pub fn implementations_of(&self, selector: &str, kind: MethodKind) -> Vec<SelectorOwner> {
        self.selector_owners(selector)
            .iter()
            .filter(|owner| owner.kind == kind)
            .cloned()
            .collect()
    }

    /// Performs superclass_chain.
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

    /// Performs effective_instance_methods.
    pub fn effective_instance_methods(&self, class_name: &str) -> Vec<&MethodEntry> {
        self.classes
            .get(class_name)
            .map(|node| node.effective_instance_methods.iter().collect())
            .unwrap_or_default()
    }

    /// Performs effective_class_methods.
    pub fn effective_class_methods(&self, class_name: &str) -> Vec<&MethodEntry> {
        self.classes
            .get(class_name)
            .map(|node| node.effective_class_methods.iter().collect())
            .unwrap_or_default()
    }

    /// Performs all_methods.
    pub fn all_methods(&self, class_name: &str) -> Option<AllMethods> {
        Some(AllMethods {
            instance: self.collect_all_methods(class_name, MethodKind::Instance)?,
            class: self.collect_all_methods(class_name, MethodKind::Class)?,
        })
    }

    /// Performs find_method.
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

    /// Performs resolve_inherited.
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

    /// Performs method_impl_va.
    pub fn method_impl_va(
        &self,
        class_name: &str,
        selector: &str,
        kind: MethodKind,
    ) -> Option<u64> {
        self.resolve_inherited(class_name, selector, kind)
            .map(|resolved| resolved.imp)
    }

    /// Performs method_impl_offset.
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

    /// Performs responds_to.
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
    type Error = crate::objc::ObjcError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> crate::objc::Result<Self>
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
        // Static category folding is deterministic: class methods are inserted
        // first, then category methods are appended in metadata traversal
        // order, and the last definition for a selector wins.
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
