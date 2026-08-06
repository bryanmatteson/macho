use std::collections::{BTreeMap, BTreeSet};

use super::super::{ObjCDiagnosticId, ObjCEntityId, ObjCMemberId, Selector, Severity, sha256_hex};
use super::types::*;

pub(super) fn build_graph(entities: &[ObjCEntity]) -> ObjCGraph {
    let mut inheritance = Vec::new();
    let mut conformances = Vec::new();
    let mut categories = Vec::new();
    let mut selectors =
        BTreeMap::<(Selector, ObjCMethodKind), Vec<(ObjCEntityId, ObjCMemberId)>>::new();
    for entity in entities {
        let id = entity.common().id.clone();
        match entity {
            ObjCEntity::Class(value) => {
                if let ObjCValue::Known {
                    value: Some(target),
                    ..
                } = &value.superclass
                    && let Some(to) = &target.entity_id
                {
                    inheritance.push(edge(&id, to, ObjCGraphEdgeKind::Superclass));
                }
                add_conformances(&mut conformances, &id, &value.adopted_protocols);
                add_methods(
                    &mut selectors,
                    &id,
                    value.instance_methods.iter().chain(&value.class_methods),
                );
            }
            ObjCEntity::Category(value) => {
                if let ObjCValue::Known { value: target, .. } = &value.extended_class
                    && let Some(to) = &target.entity_id
                {
                    categories.push(edge(&id, to, ObjCGraphEdgeKind::ExtendsClass));
                }
                add_conformances(&mut conformances, &id, &value.adopted_protocols);
                add_methods(
                    &mut selectors,
                    &id,
                    value.instance_methods.iter().chain(&value.class_methods),
                );
            }
            ObjCEntity::Protocol(value) => {
                add_conformances(&mut conformances, &id, &value.adopted_protocols);
                add_methods(
                    &mut selectors,
                    &id,
                    value
                        .required_instance_methods
                        .iter()
                        .chain(&value.required_class_methods)
                        .chain(&value.optional_instance_methods)
                        .chain(&value.optional_class_methods),
                );
            }
        }
    }
    inheritance.sort();
    conformances.sort();
    categories.sort();
    ObjCGraph {
        nodes: entities
            .iter()
            .map(|entity| ObjCGraphNode {
                entity_id: entity.common().id.clone(),
                presence: entity.common().presence,
            })
            .collect(),
        inheritance,
        conformances,
        categories,
        selector_owners: selectors
            .into_iter()
            .map(|((selector, method_kind), values)| ObjCSelectorOwner {
                selector,
                method_kind,
                effective_owner: (values.len() == 1).then(|| values[0].0.clone()),
                candidates: values.into_iter().map(|(_, member)| member).collect(),
            })
            .collect(),
    }
}

fn add_conformances(edges: &mut Vec<ObjCGraphEdge>, owner: &ObjCEntityId, targets: &[ObjCTypeRef]) {
    for target in targets {
        if let Some(to) = &target.entity_id {
            edges.push(edge(owner, to, ObjCGraphEdgeKind::AdoptsProtocol));
        }
    }
}

fn add_methods<'a>(
    map: &mut BTreeMap<(Selector, ObjCMethodKind), Vec<(ObjCEntityId, ObjCMemberId)>>,
    owner: &ObjCEntityId,
    methods: impl Iterator<Item = &'a ObjCMethod>,
) {
    for method in methods {
        if let ObjCValue::Known {
            value: selector, ..
        } = &method.selector
        {
            map.entry((selector.clone(), method.kind))
                .or_default()
                .push((owner.clone(), method.id.clone()));
        }
    }
}

fn edge(from: &ObjCEntityId, to: &ObjCEntityId, kind: ObjCGraphEdgeKind) -> ObjCGraphEdge {
    ObjCGraphEdge {
        from: from.clone(),
        to: to.clone(),
        kind,
    }
}

pub(super) fn add_cycle_diagnostics(graph: &ObjCGraph, diagnostics: &mut Vec<ObjCDiagnostic>) {
    let parents = graph
        .inheritance
        .iter()
        .map(|edge| (edge.from.as_str(), edge.to.as_str()))
        .collect::<BTreeMap<_, _>>();
    for start in parents.keys() {
        let mut seen = BTreeSet::new();
        let mut current = *start;
        while let Some(next) = parents.get(current) {
            if !seen.insert(current) {
                diagnostics.push(ObjCDiagnostic {
                    id: ObjCDiagnosticId::new(sha256_hex(
                        format!("graph-cycle|{start}").as_bytes(),
                    ))
                    .expect("SHA-256 diagnostic ID"),
                    code: ObjCDiagnosticCode::GraphCycle,
                    severity: Severity::Warning,
                    message: format!("Objective-C superclass cycle includes {start}"),
                    observation_id: None,
                    entity_id: ObjCEntityId::new((*start).to_owned()).ok(),
                    evidence_ids: Vec::new(),
                });
                break;
            }
            current = next;
        }
    }
}
