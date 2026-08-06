//! Report-level Swift declaration projection.
//!
//! The projection restates what the recovery report already established: it
//! never demangles, resolves, or infers anything the collectors did not. A
//! member whose type the report could not resolve becomes an entry in
//! [`SwiftHeaderProjection::unresolved`] rather than a plausible Swift type.

use crate::analysis::reconstruct::swift::{
    declaration_selection, is_identifier, render_declarations,
};
use crate::analysis::report::{
    SwiftDecl, SwiftDeclBinding, SwiftDeclMember, SwiftEntity, SwiftField, SwiftHeaderGap,
    SwiftHeaderProjection, SwiftReport, SwiftSliceReport, SwiftTypeKind, SwiftUnavailableReason,
    SwiftValue,
};

/// ABI field-record flags, mirroring `crate::analysis::reconstruct::swift`.
const FIELD_IS_INDIRECT_CASE: u32 = 0x1;
const FIELD_IS_VAR: u32 = 0x2;
const FIELD_IS_ARTIFICIAL: u32 = 0x4;

/// Attach a Swift declaration projection to every slice in `report`.
///
/// Only selected entities are projected, so a filtered report projects exactly
/// what its filter retained.
pub fn project_swift_headers(report: &mut SwiftReport) -> crate::analysis::Result<()> {
    for slice in report.slices.as_mut_slice() {
        let projection = project_slice(slice);
        slice.header = Some(projection);
    }
    Ok(())
}

fn project_slice(slice: &SwiftSliceReport) -> SwiftHeaderProjection {
    let mut declarations = Vec::new();
    let mut unresolved = Vec::new();
    let selection = declaration_selection(slice);
    // The same entity set the rendered source declares, so `declarations` and
    // `source` describe the same types.
    for entity in selection.declared {
        match project_entity(entity, &mut unresolved) {
            Some(declaration) => declarations.push(declaration),
            None => continue,
        }
    }
    // A displaced observation is normally an empty Objective-C shadow of a type
    // the winner already describes, and repeating it would bury the ledger. One
    // holding conflicting evidence is different: the conflict exists nowhere in
    // the projection once its observation is dropped, so it is recorded here.
    for entity in selection.suppressed {
        if holds_conflict(entity) {
            unresolved.push(gap(entity, None, SwiftUnavailableReason::AmbiguousIdentity));
        }
    }
    SwiftHeaderProjection {
        declarations,
        unresolved,
        // The rendered text and the structured declarations describe the same
        // slice, so both come from the same selection.
        source: render_declarations(slice),
    }
}

fn project_entity(entity: &SwiftEntity, unresolved: &mut Vec<SwiftHeaderGap>) -> Option<SwiftDecl> {
    let kind = match &entity.kind {
        SwiftValue::Known { value, .. } => *value,
        SwiftValue::Conflicted { .. } => {
            unresolved.push(gap(entity, None, SwiftUnavailableReason::AmbiguousIdentity));
            return None;
        }
        SwiftValue::Unavailable { reason } => {
            unresolved.push(gap(entity, None, *reason));
            return None;
        }
    };
    if !matches!(
        kind,
        SwiftTypeKind::Class
            | SwiftTypeKind::Struct
            | SwiftTypeKind::Enum
            | SwiftTypeKind::Protocol
    ) {
        unresolved.push(gap(
            entity,
            None,
            SwiftUnavailableReason::UnsupportedDescriptor,
        ));
        return None;
    }

    let Some((name, nominal)) = qualified_name(entity) else {
        unresolved.push(gap(
            entity,
            None,
            SwiftUnavailableReason::UnresolvedReference,
        ));
        return None;
    };
    if !is_identifier(&nominal) {
        // Swift private-discriminator names such as `(Inner in _ABC123)` are
        // recovered intact but cannot be spelled as a declaration, so the
        // rendered source omits them and the ledger records the omission.
        unresolved.push(gap(
            entity,
            None,
            SwiftUnavailableReason::UnsupportedDescriptor,
        ));
    }

    let conformances = match &entity.conformances {
        SwiftValue::Known { value, .. } => value
            .iter()
            .filter_map(|conformance| {
                conformance
                    .protocol
                    .qualified_name
                    .as_ref()
                    .map(|name| name.path.as_slice().join("."))
            })
            .collect(),
        SwiftValue::Conflicted { .. } => {
            unresolved.push(gap(entity, None, SwiftUnavailableReason::AmbiguousIdentity));
            Vec::new()
        }
        SwiftValue::Unavailable { reason } => {
            unresolved.push(gap(entity, None, *reason));
            Vec::new()
        }
    };

    // Protocol requirements are not carried by nominal field metadata, so a
    // protocol projects its identity and conformances and no members.
    let members = if kind == SwiftTypeKind::Protocol {
        Vec::new()
    } else {
        project_members(entity, kind, unresolved)
    };

    // A null superclass reference and a kind that has no such field are both
    // reported as unavailable upstream, so an absent superclass is a complete
    // fact about a root class rather than a gap in the ledger.
    let superclass = match &entity.superclass {
        SwiftValue::Known { value, .. } => Some(value.clone()),
        SwiftValue::Unavailable { .. } => None,
        SwiftValue::Conflicted { .. } => {
            unresolved.push(gap(entity, None, SwiftUnavailableReason::AmbiguousIdentity));
            None
        }
    };

    Some(SwiftDecl {
        entity_id: entity.id.clone(),
        kind,
        state: entity.state,
        name,
        superclass,
        conformances,
        members,
    })
}

fn project_members(
    entity: &SwiftEntity,
    kind: SwiftTypeKind,
    unresolved: &mut Vec<SwiftHeaderGap>,
) -> Vec<SwiftDeclMember> {
    let fields = match &entity.fields_or_cases {
        SwiftValue::Known { value, .. } => value,
        SwiftValue::Conflicted { .. } => {
            unresolved.push(gap(entity, None, SwiftUnavailableReason::AmbiguousIdentity));
            return Vec::new();
        }
        SwiftValue::Unavailable { reason } => {
            unresolved.push(gap(entity, None, *reason));
            return Vec::new();
        }
    };
    fields
        .iter()
        .filter_map(|field| project_member(entity, kind, field, unresolved))
        .collect()
}

fn project_member(
    entity: &SwiftEntity,
    kind: SwiftTypeKind,
    field: &SwiftField,
    unresolved: &mut Vec<SwiftHeaderGap>,
) -> Option<SwiftDeclMember> {
    let Some(name) = field.name.clone() else {
        unresolved.push(gap(
            entity,
            None,
            SwiftUnavailableReason::UnresolvedReference,
        ));
        return None;
    };
    let binding = if kind == SwiftTypeKind::Enum {
        if field.flags & FIELD_IS_INDIRECT_CASE != 0 {
            SwiftDeclBinding::IndirectCase
        } else {
            SwiftDeclBinding::Case
        }
    } else if field.flags & FIELD_IS_VAR != 0 {
        SwiftDeclBinding::Var
    } else {
        SwiftDeclBinding::Let
    };

    // A case with neither a resolved type nor mangled bytes carries no payload;
    // that is a complete fact, not a gap.
    let has_mangled = field
        .mangled_type
        .as_ref()
        .is_some_and(|value| !value.as_str().is_empty());
    if field.type_name.is_none() && (kind != SwiftTypeKind::Enum || has_mangled) {
        unresolved.push(gap(
            entity,
            Some(name.clone()),
            SwiftUnavailableReason::UnsupportedMangling,
        ));
    } else if !is_identifier(&name) {
        // The type resolved, but the rendered source cannot spell this name
        // (Swift's `$__lazy_storage_$_*` backing fields, for example), so it is
        // omitted there and must be accounted for here.
        unresolved.push(gap(
            entity,
            Some(name.clone()),
            SwiftUnavailableReason::UnsupportedDescriptor,
        ));
    }

    Some(SwiftDeclMember {
        name,
        binding,
        type_name: field.type_name.clone(),
        artificial: field.flags & FIELD_IS_ARTIFICIAL != 0,
    })
}

/// Whether any of an observation's projected values conflicts across evidence.
fn holds_conflict(entity: &SwiftEntity) -> bool {
    matches!(&entity.kind, SwiftValue::Conflicted { .. })
        || matches!(&entity.qualified_name, SwiftValue::Conflicted { .. })
        || matches!(&entity.fields_or_cases, SwiftValue::Conflicted { .. })
        || matches!(&entity.conformances, SwiftValue::Conflicted { .. })
}

/// The fully qualified name paired with its nominal (last) path component.
fn qualified_name(entity: &SwiftEntity) -> Option<(String, String)> {
    match &entity.qualified_name {
        SwiftValue::Known { value, .. } => {
            let path = value.path.as_slice();
            Some((path.join("."), path.last()?.clone()))
        }
        SwiftValue::Conflicted { .. } | SwiftValue::Unavailable { .. } => None,
    }
}

fn gap(
    entity: &SwiftEntity,
    member: Option<String>,
    reason: SwiftUnavailableReason,
) -> SwiftHeaderGap {
    SwiftHeaderGap {
        entity_id: entity.id.clone(),
        member,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::report::{
        AtLeastTwo, IdentityStability, NonEmpty, SwiftCandidate, SwiftEntityId, SwiftEntityState,
        SwiftEvidenceId, SwiftObservationId, SwiftQualifiedName,
    };

    fn evidence() -> NonEmpty<SwiftEvidenceId> {
        NonEmpty::new(vec![
            SwiftEvidenceId::new("0".repeat(64)).expect("valid evidence ID"),
        ])
        .expect("one evidence ID")
    }

    fn known<T>(value: T) -> SwiftValue<T> {
        SwiftValue::Known {
            value,
            evidence: evidence(),
        }
    }

    fn field(name: &str, type_name: Option<&str>, flags: u32) -> SwiftField {
        SwiftField {
            name: Some(name.to_owned()),
            mangled_type: None,
            type_name: type_name.map(str::to_owned),
            flags,
        }
    }

    fn entity(kind: SwiftTypeKind, path: &[&str], fields: Vec<SwiftField>) -> SwiftEntity {
        SwiftEntity {
            id: SwiftEntityId::new("1".repeat(64)).expect("valid entity ID"),
            identity_stability: IdentityStability::CrossBuild,
            state: SwiftEntityState::MetadataDefined,
            kind: known(kind),
            qualified_name: known(SwiftQualifiedName {
                module: Some(path[0].to_owned()),
                path: NonEmpty::new(path.iter().map(|value| (*value).to_owned()).collect())
                    .expect("non-empty path"),
            }),
            descriptor: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            parent: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            fields_or_cases: known(fields),
            conformances: known(Vec::new()),
            superclass: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            raw_linkages: Vec::new(),
            observation_ids: NonEmpty::new(vec![
                SwiftObservationId::new("2".repeat(64)).expect("valid observation ID"),
            ])
            .expect("one observation ID"),
            gaps: Vec::new(),
        }
    }

    #[test]
    fn stored_properties_carry_their_binding_and_type() {
        let value = entity(
            SwiftTypeKind::Class,
            &["Module", "Store"],
            vec![
                field("mutable", Some("Swift.Int"), FIELD_IS_VAR),
                field("constant", Some("Swift.String"), 0),
                field(
                    "generated",
                    Some("Swift.Bool"),
                    FIELD_IS_VAR | FIELD_IS_ARTIFICIAL,
                ),
            ],
        );
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        assert!(unresolved.is_empty());
        assert_eq!(declaration.name, "Module.Store");
        assert_eq!(declaration.kind, SwiftTypeKind::Class);
        let bindings = declaration
            .members
            .iter()
            .map(|member| (member.name.as_str(), member.binding, member.artificial))
            .collect::<Vec<_>>();
        assert_eq!(
            bindings,
            vec![
                ("mutable", SwiftDeclBinding::Var, false),
                ("constant", SwiftDeclBinding::Let, false),
                ("generated", SwiftDeclBinding::Var, true),
            ]
        );
        assert_eq!(
            declaration.members[0].type_name.as_deref(),
            Some("Swift.Int")
        );
    }

    #[test]
    fn enum_cases_without_payload_are_complete_rather_than_unresolved() {
        let value = entity(
            SwiftTypeKind::Enum,
            &["Module", "Choice"],
            vec![
                field("plain", None, 0),
                field("boxed", None, FIELD_IS_INDIRECT_CASE),
            ],
        );
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        // A payload-free case has no type by construction, so it is not a gap.
        assert!(unresolved.is_empty(), "unexpected gaps: {unresolved:?}");
        assert_eq!(declaration.members[0].binding, SwiftDeclBinding::Case);
        assert_eq!(
            declaration.members[1].binding,
            SwiftDeclBinding::IndirectCase
        );
    }

    #[test]
    fn a_case_with_mangled_but_unresolved_payload_is_a_gap() {
        let mut payload = field("wrapped", None, 0);
        payload.mangled_type = Some(crate::analysis::report::HexBytes::from_bytes(b"raw"));
        let value = entity(SwiftTypeKind::Enum, &["Module", "Choice"], vec![payload]);
        let mut unresolved = Vec::new();
        project_entity(&value, &mut unresolved).expect("declaration");

        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].member.as_deref(), Some("wrapped"));
        assert_eq!(
            unresolved[0].reason,
            SwiftUnavailableReason::UnsupportedMangling
        );
    }

    #[test]
    fn a_superclass_reaches_the_structured_declaration_without_becoming_a_gap() {
        let mut value = entity(SwiftTypeKind::Class, &["Module", "Derived"], Vec::new());
        value.superclass = known("Module.Base".to_owned());
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        assert_eq!(declaration.superclass.as_deref(), Some("Module.Base"));
        assert!(unresolved.is_empty(), "unexpected gaps: {unresolved:?}");
    }

    #[test]
    fn a_root_class_reports_no_superclass_and_no_gap() {
        // The descriptor was read and its superclass reference was null. That is
        // a complete fact about a root class, so it owes the ledger nothing.
        let value = entity(SwiftTypeKind::Class, &["Module", "Root"], Vec::new());
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        assert!(declaration.superclass.is_none());
        assert!(unresolved.is_empty(), "unexpected gaps: {unresolved:?}");
    }

    #[test]
    fn protocols_project_no_members() {
        let value = entity(
            SwiftTypeKind::Protocol,
            &["Module", "Drawable"],
            vec![field("ignored", Some("Swift.Int"), FIELD_IS_VAR)],
        );
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        // Requirements are not carried by nominal field metadata.
        assert!(declaration.members.is_empty());
        assert!(unresolved.is_empty());
    }

    #[test]
    fn unavailable_members_and_conformances_are_recorded_against_the_declaration() {
        let mut value = entity(SwiftTypeKind::Struct, &["Module", "Opaque"], Vec::new());
        value.fields_or_cases = SwiftValue::Unavailable {
            reason: SwiftUnavailableReason::NotEncoded,
        };
        value.conformances = SwiftValue::Unavailable {
            reason: SwiftUnavailableReason::UnresolvedReference,
        };
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        assert!(declaration.members.is_empty());
        assert_eq!(unresolved.len(), 2);
        assert!(unresolved.iter().all(|gap| gap.member.is_none()));
        let reasons = unresolved.iter().map(|gap| gap.reason).collect::<Vec<_>>();
        assert!(reasons.contains(&SwiftUnavailableReason::UnresolvedReference));
        assert!(reasons.contains(&SwiftUnavailableReason::NotEncoded));
    }

    #[test]
    fn a_resolved_field_the_source_cannot_spell_is_still_recorded() {
        // Swift lazy-var backing storage: the type resolves, but `$` cannot be
        // written as a Swift identifier, so the rendered source omits it.
        let value = entity(
            SwiftTypeKind::Class,
            &["Module", "View"],
            vec![field(
                "$__lazy_storage_$_button",
                Some("Swift.Optional<Button>"),
                FIELD_IS_VAR,
            )],
        );
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        assert_eq!(unresolved.len(), 1);
        assert_eq!(
            unresolved[0].member.as_deref(),
            Some("$__lazy_storage_$_button")
        );
        assert_eq!(
            unresolved[0].reason,
            SwiftUnavailableReason::UnsupportedDescriptor
        );
        // The structured projection keeps the fact the source had to drop.
        assert_eq!(
            declaration.members[0].type_name.as_deref(),
            Some("Swift.Optional<Button>")
        );
    }

    #[test]
    fn a_private_discriminator_name_is_projected_but_recorded_as_unspellable() {
        let value = entity(
            SwiftTypeKind::Class,
            &["Module", "(Inner in _ABC123)"],
            Vec::new(),
        );
        let mut unresolved = Vec::new();
        let declaration = project_entity(&value, &mut unresolved).expect("declaration");

        assert_eq!(declaration.name, "Module.(Inner in _ABC123)");
        assert_eq!(unresolved.len(), 1);
        assert!(unresolved[0].member.is_none());
        assert_eq!(
            unresolved[0].reason,
            SwiftUnavailableReason::UnsupportedDescriptor
        );
    }

    #[test]
    fn a_conflict_counts_wherever_it_sits_on_the_observation() {
        let plain = entity(SwiftTypeKind::Class, &["Module", "Store"], Vec::new());
        assert!(!holds_conflict(&plain));

        let mut conflicted = plain.clone();
        conflicted.fields_or_cases = SwiftValue::Conflicted {
            candidates: AtLeastTwo::new(vec![
                SwiftCandidate {
                    value: vec![field("a", Some("Swift.Int"), 0)],
                    evidence: evidence(),
                },
                SwiftCandidate {
                    value: vec![field("b", Some("Swift.Int"), 0)],
                    evidence: evidence(),
                },
            ])
            .expect("two candidates"),
        };
        assert!(
            holds_conflict(&conflicted),
            "a conflict the winner does not carry must be recordable"
        );
    }

    #[test]
    fn non_nominal_kinds_do_not_project_a_declaration() {
        for kind in [
            SwiftTypeKind::TypeAlias,
            SwiftTypeKind::Opaque,
            SwiftTypeKind::Unknown,
        ] {
            let value = entity(kind, &["Module", "Alias"], Vec::new());
            let mut unresolved = Vec::new();
            assert!(project_entity(&value, &mut unresolved).is_none());
            assert_eq!(
                unresolved[0].reason,
                SwiftUnavailableReason::UnsupportedDescriptor
            );
        }
    }

    #[test]
    fn an_unavailable_kind_or_name_blocks_the_declaration() {
        let mut value = entity(SwiftTypeKind::Class, &["Module", "Type"], Vec::new());
        value.kind = SwiftValue::Unavailable {
            reason: SwiftUnavailableReason::MalformedDescriptor,
        };
        let mut unresolved = Vec::new();
        assert!(project_entity(&value, &mut unresolved).is_none());
        assert_eq!(
            unresolved[0].reason,
            SwiftUnavailableReason::MalformedDescriptor
        );

        let mut value = entity(SwiftTypeKind::Class, &["Module", "Type"], Vec::new());
        value.qualified_name = SwiftValue::Unavailable {
            reason: SwiftUnavailableReason::NotEncoded,
        };
        let mut unresolved = Vec::new();
        assert!(project_entity(&value, &mut unresolved).is_none());
        assert_eq!(
            unresolved[0].reason,
            SwiftUnavailableReason::UnresolvedReference
        );
    }
}
