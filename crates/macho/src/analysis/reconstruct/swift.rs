//! Evidence-honest Swift source declaration projection.

use std::collections::BTreeSet;
use std::fmt::Write;

use crate::analysis::report::{
    SwiftEntity, SwiftEntityState, SwiftField, SwiftSliceReport, SwiftTypeKind,
    SwiftUnavailableReason, SwiftValue,
};

const FIELD_IS_INDIRECT_CASE: u32 = 0x1;
const FIELD_IS_VAR: u32 = 0x2;
const FIELD_IS_ARTIFICIAL: u32 = 0x4;

/// Render the selected entities in one Swift report slice as source-like declarations.
///
/// The projection emits only facts represented by the recovery report. Unknown field
/// types, conformances, and unsupported declarations remain explicit comments rather
/// than being replaced by invented Swift types.
pub fn render_declarations(slice: &SwiftSliceReport) -> String {
    let mut output = String::from(
        "// Recovered Swift declarations.\n\
         // Unavailable metadata is preserved as comments; this is not original source.\n\n",
    );
    for entity in declarable_entities(slice) {
        render_entity(&mut output, entity);
        output.push('\n');
    }
    output
}

/// The selected entities to declare, at most one per nominal type.
///
/// A Swift type exposed to Objective-C is observed twice — once as a Swift
/// context descriptor and once as Objective-C metadata — and the report keeps
/// both, because they are genuinely separate evidence. A source projection
/// declares each type once, so the observation carrying the most recovered
/// content wins and the other is dropped from the declaration list.
///
/// Entities keep their report order, and ties resolve to the first observed, so
/// the result is deterministic for a given report.
pub(crate) fn declarable_entities(slice: &SwiftSliceReport) -> Vec<&SwiftEntity> {
    declaration_selection(slice).declared
}

/// The entities a source projection declares, and the observations it set aside.
pub(crate) struct DeclarationSelection<'a> {
    /// One entity per nominal type, richest observation first.
    pub declared: Vec<&'a SwiftEntity>,
    /// Observations displaced by a richer one for the same type.
    pub suppressed: Vec<&'a SwiftEntity>,
}

/// Choose one observation per nominal type, keeping what was displaced.
///
/// The displaced list exists so a caller can account for evidence the rendered
/// source drops: a losing observation may hold a conflict the winner does not.
pub(crate) fn declaration_selection(slice: &SwiftSliceReport) -> DeclarationSelection<'_> {
    let selected = slice
        .selection
        .selected_entity_ids
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut chosen: Vec<&SwiftEntity> = Vec::new();
    let mut suppressed: Vec<&SwiftEntity> = Vec::new();
    let mut position_by_name = std::collections::BTreeMap::<String, usize>::new();
    for entity in &slice.entities {
        if !selected.contains(entity.id.as_str()) {
            continue;
        }
        if is_imported_objc_entity(entity) {
            // `__C` is the Swift runtime's synthetic module for imported
            // Objective-C declarations. Its entities are useful recovery
            // references, but they are not declarations owned by this image.
            continue;
        }
        let Some(name) = known(&entity.qualified_name).map(|name| name.path.as_slice().join("."))
        else {
            // Without a name there is nothing to collapse on; keep the entity so
            // its declaration still reports why it could not be projected.
            chosen.push(entity);
            continue;
        };
        match position_by_name.get(&name) {
            Some(position) if declaration_rank(entity) <= declaration_rank(chosen[*position]) => {
                suppressed.push(entity);
            }
            Some(position) => {
                suppressed.push(std::mem::replace(&mut chosen[*position], entity));
            }
            None => {
                position_by_name.insert(name, chosen.len());
                chosen.push(entity);
            }
        }
    }
    DeclarationSelection {
        declared: chosen,
        suppressed,
    }
}

fn is_imported_objc_entity(entity: &SwiftEntity) -> bool {
    known(&entity.qualified_name).is_some_and(|name| {
        name.module.as_deref() == Some("__C")
            || name
                .path
                .as_slice()
                .first()
                .is_some_and(|value| value == "__C")
    })
}

/// How much declarable content an observation carries; higher wins.
fn declaration_rank(entity: &SwiftEntity) -> (usize, usize, usize) {
    let members = match &entity.fields_or_cases {
        SwiftValue::Known { value, .. } => 2 + value.len(),
        SwiftValue::Conflicted { .. } => 1,
        SwiftValue::Unavailable { .. } => 0,
    };
    let conformances = usize::from(matches!(&entity.conformances, SwiftValue::Known { .. }));
    let defined = usize::from(entity.state == SwiftEntityState::MetadataDefined);
    (members, conformances, defined)
}

fn render_entity(output: &mut String, entity: &SwiftEntity) {
    let qualified_name = known(&entity.qualified_name)
        .map(|name| name.path.as_slice().join("."))
        .unwrap_or_else(|| "<unknown>".to_owned());
    let declaration_name = known(&entity.qualified_name)
        .and_then(|name| name.path.as_slice().last())
        .filter(|name| is_identifier(name))
        .map(|name| escaped_identifier(name));
    let kind = known(&entity.kind)
        .copied()
        .unwrap_or(SwiftTypeKind::Unknown);

    let _ = writeln!(output, "// {qualified_name}");
    if entity.state != SwiftEntityState::MetadataDefined {
        let _ = writeln!(output, "// Recovery state: {}.", state_name(entity.state));
    }
    let Some(declaration_name) = declaration_name else {
        output.push_str("// Declaration omitted: nominal identifier is unavailable or invalid.\n");
        return;
    };

    let Some(keyword) = declaration_keyword(kind) else {
        let _ = writeln!(
            output,
            "// Unsupported {} declaration: {declaration_name}.",
            kind_name(kind)
        );
        return;
    };

    // Swift spells inheritance and conformance in one clause, superclass first.
    let inherited = known(&entity.superclass)
        .cloned()
        .into_iter()
        .chain(
            known(&entity.conformances)
                .into_iter()
                .flatten()
                .filter_map(|conformance| {
                    conformance
                        .protocol
                        .qualified_name
                        .as_ref()
                        .map(|name| name.path.as_slice().join("."))
                }),
        )
        .collect::<Vec<_>>();
    let conformance_clause = if inherited.is_empty() {
        String::new()
    } else {
        format!(": {}", inherited.join(", "))
    };
    let generic_clause = generic_parameter_clause(entity);
    let _ = writeln!(
        output,
        "{keyword} {declaration_name}{generic_clause}{conformance_clause} {{"
    );

    if !matches!(&entity.conformances, SwiftValue::Known { .. }) {
        render_unavailable_value_comment(output, "Conformances", &entity.conformances);
    }

    match kind {
        SwiftTypeKind::Class | SwiftTypeKind::Struct => {
            render_stored_fields(output, &entity.fields_or_cases)
        }
        SwiftTypeKind::Enum => render_enum_cases(output, &entity.fields_or_cases),
        SwiftTypeKind::Protocol => {
            output.push_str("    // Requirements are not encoded by nominal field metadata.\n");
        }
        SwiftTypeKind::TypeAlias | SwiftTypeKind::Opaque | SwiftTypeKind::Unknown => {
            unreachable!("unsupported kinds returned above")
        }
    }
    output.push_str("}\n");
}

fn generic_parameter_clause(entity: &SwiftEntity) -> String {
    let Some(fields) = known(&entity.fields_or_cases) else {
        return String::new();
    };
    let parameters = fields
        .iter()
        .filter_map(|field| field.type_name.as_deref())
        .flat_map(generic_parameters_in)
        .collect::<BTreeSet<_>>();
    if parameters.is_empty() {
        String::new()
    } else {
        format!(
            "<{}>",
            parameters.into_iter().collect::<Vec<_>>().join(", ")
        )
    }
}

/// The generic placeholders a demangled type name mentions.
///
/// Placeholders are rendered bare (`A`), so the rule is positional: a lone
/// uppercase letter names a placeholder when it is a whole segment
/// (`Swift.Optional<A>`) or the *root* of a dotted path, which is how a
/// dependent member type spells one (`A.Swift.Collection.Index`). A qualified
/// name whose later component happens to be one letter, such as `Module.A`, is
/// a real type and is not mistaken for a placeholder.
///
/// A segment followed by a colon is a tuple label rather than a type, so
/// `(A: Swift.Int)` contributes nothing.
fn generic_parameters_in(type_name: &str) -> impl Iterator<Item = &str> {
    let mut parameters = Vec::new();
    let mut start = None;
    for (index, character) in type_name.char_indices() {
        let inside_segment = character.is_alphanumeric() || character == '_' || character == '.';
        match (inside_segment, start) {
            (true, None) => start = Some(index),
            (false, Some(begin)) => {
                push_placeholder(&mut parameters, type_name, begin, index);
                start = None;
            }
            _ => {}
        }
    }
    if let Some(begin) = start {
        push_placeholder(&mut parameters, type_name, begin, type_name.len());
    }
    parameters.into_iter()
}

fn push_placeholder<'a>(parameters: &mut Vec<&'a str>, text: &'a str, begin: usize, end: usize) {
    let segment = &text[begin..end];
    let root_len = segment.find('.').unwrap_or(segment.len());
    let root = &segment[..root_len];
    if root.len() != 1 || !root.as_bytes()[0].is_ascii_uppercase() {
        return;
    }
    // A whole-segment placeholder can be a tuple label; a dotted path cannot,
    // so the colon only disqualifies the undotted form.
    if root_len == segment.len() && text[end..].starts_with(':') {
        return;
    }
    parameters.push(root);
}

fn render_stored_fields(output: &mut String, fields: &SwiftValue<Vec<SwiftField>>) {
    match fields {
        SwiftValue::Known { value, .. } if value.is_empty() => {
            output.push_str("    // No stored fields encoded.\n");
        }
        SwiftValue::Known { value, .. } => {
            for field in value {
                render_stored_field(output, field);
            }
        }
        SwiftValue::Unavailable { reason } => {
            let _ = writeln!(
                output,
                "    // Stored fields unavailable: {}.",
                unavailable_reason_name(*reason)
            );
        }
        SwiftValue::Conflicted { .. } => {
            output.push_str("    // Stored fields conflicted across evidence.\n");
        }
    }
}

fn render_stored_field(output: &mut String, field: &SwiftField) {
    let Some(name) = field.name.as_deref() else {
        render_unresolved_field(output, "<unknown>", field);
        return;
    };
    let Some(type_name) = field.type_name.as_deref() else {
        render_unresolved_field(output, name, field);
        return;
    };
    if !is_identifier(name) {
        render_unresolved_field(output, name, field);
        return;
    }
    let binding = if field.flags & FIELD_IS_VAR != 0 {
        "var"
    } else {
        "let"
    };
    let artificial = if field.flags & FIELD_IS_ARTIFICIAL != 0 {
        " // compiler-generated"
    } else {
        ""
    };
    let _ = writeln!(
        output,
        "    {binding} {}: {type_name}{artificial}",
        escaped_identifier(name)
    );
}

fn render_unresolved_field(output: &mut String, name: &str, field: &SwiftField) {
    let mangled = field
        .mangled_type
        .as_ref()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(|value| format!("; mangled={value}"))
        .unwrap_or_default();
    let _ = writeln!(
        output,
        "    // Stored field {name:?} has an unresolved type{mangled}."
    );
}

fn render_enum_cases(output: &mut String, fields: &SwiftValue<Vec<SwiftField>>) {
    match fields {
        SwiftValue::Known { value, .. } if value.is_empty() => {
            output.push_str("    // No cases encoded.\n");
        }
        SwiftValue::Known { value, .. } => {
            for field in value {
                render_enum_case(output, field);
            }
        }
        SwiftValue::Unavailable { reason } => {
            let _ = writeln!(
                output,
                "    // Cases unavailable: {}.",
                unavailable_reason_name(*reason)
            );
        }
        SwiftValue::Conflicted { .. } => {
            output.push_str("    // Cases conflicted across evidence.\n");
        }
    }
}

fn render_enum_case(output: &mut String, field: &SwiftField) {
    let Some(name) = field.name.as_deref().filter(|name| is_identifier(name)) else {
        render_unresolved_case(output, field);
        return;
    };
    let indirect = if field.flags & FIELD_IS_INDIRECT_CASE != 0 {
        "indirect "
    } else {
        ""
    };
    match (
        field.type_name.as_deref(),
        field.mangled_type.as_ref().map(|value| value.as_str()),
    ) {
        (Some(type_name), _) => {
            let _ = writeln!(
                output,
                "    {indirect}case {}({type_name})",
                escaped_identifier(name)
            );
        }
        (None, None | Some("")) => {
            let _ = writeln!(output, "    {indirect}case {}", escaped_identifier(name));
        }
        (None, Some(_)) => render_unresolved_case(output, field),
    }
}

fn render_unresolved_case(output: &mut String, field: &SwiftField) {
    let name = field.name.as_deref().unwrap_or("<unknown>");
    let mangled = field
        .mangled_type
        .as_ref()
        .map(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(|value| format!("; mangled={value}"))
        .unwrap_or_default();
    let _ = writeln!(
        output,
        "    // Enum case {name:?} has an unresolved payload type{mangled}."
    );
}

fn render_unavailable_value_comment<T>(output: &mut String, label: &str, value: &SwiftValue<T>) {
    match value {
        SwiftValue::Unavailable { reason } => {
            let _ = writeln!(
                output,
                "    // {label} unavailable: {}.",
                unavailable_reason_name(*reason)
            );
        }
        SwiftValue::Conflicted { .. } => {
            let _ = writeln!(output, "    // {label} conflicted across evidence.");
        }
        SwiftValue::Known { .. } => {}
    }
}

fn known<T>(value: &SwiftValue<T>) -> Option<&T> {
    match value {
        SwiftValue::Known { value, .. } => Some(value),
        SwiftValue::Conflicted { .. } | SwiftValue::Unavailable { .. } => None,
    }
}

fn declaration_keyword(kind: SwiftTypeKind) -> Option<&'static str> {
    match kind {
        SwiftTypeKind::Class => Some("class"),
        SwiftTypeKind::Struct => Some("struct"),
        SwiftTypeKind::Enum => Some("enum"),
        SwiftTypeKind::Protocol => Some("protocol"),
        SwiftTypeKind::TypeAlias | SwiftTypeKind::Opaque | SwiftTypeKind::Unknown => None,
    }
}

fn kind_name(kind: SwiftTypeKind) -> &'static str {
    match kind {
        SwiftTypeKind::Class => "class",
        SwiftTypeKind::Struct => "struct",
        SwiftTypeKind::Enum => "enum",
        SwiftTypeKind::Protocol => "protocol",
        SwiftTypeKind::TypeAlias => "type-alias",
        SwiftTypeKind::Opaque => "opaque",
        SwiftTypeKind::Unknown => "unknown",
    }
}

fn state_name(state: SwiftEntityState) -> &'static str {
    match state {
        SwiftEntityState::MetadataDefined => "metadata-defined",
        SwiftEntityState::Referenced => "referenced",
        SwiftEntityState::SymbolOnly => "symbol-only",
        SwiftEntityState::Partial => "partial",
        SwiftEntityState::Unknown => "unknown",
    }
}

fn unavailable_reason_name(reason: SwiftUnavailableReason) -> &'static str {
    match reason {
        SwiftUnavailableReason::NotEncoded => "not encoded",
        SwiftUnavailableReason::MalformedDescriptor => "malformed descriptor",
        SwiftUnavailableReason::UnsupportedDescriptor => "unsupported descriptor",
        SwiftUnavailableReason::UnsupportedMangling => "unsupported mangling",
        SwiftUnavailableReason::UnresolvedReference => "unresolved reference",
        SwiftUnavailableReason::AmbiguousIdentity => "ambiguous identity",
        SwiftUnavailableReason::CollectorFailed => "collector failed",
        SwiftUnavailableReason::Truncated => "truncated",
    }
}

fn escaped_identifier(value: &str) -> String {
    if is_keyword(value) {
        format!("`{value}`")
    } else {
        value.to_owned()
    }
}

/// Report whether `value` can be emitted as a Swift identifier.
///
/// The header projection shares this rule so its unresolved ledger accounts for
/// exactly the names this renderer cannot spell.
pub(crate) fn is_identifier(value: &str) -> bool {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_alphabetic())
        && chars.all(|character| character == '_' || character.is_alphanumeric())
}

/// Swift's reserved words: every name that must be backtick-escaped to appear
/// in declaration position. Statement and expression keywords are included
/// because member names sit in both positions — an enum whose cases are named
/// `true` and `false` is legal Swift only as `` case `true` ``.
fn is_keyword(value: &str) -> bool {
    matches!(
        value,
        "Any"
            | "Self"
            | "as"
            | "associatedtype"
            | "await"
            | "borrowing"
            | "break"
            | "case"
            | "catch"
            | "class"
            | "consuming"
            | "continue"
            | "default"
            | "defer"
            | "deinit"
            | "do"
            | "else"
            | "enum"
            | "extension"
            | "fallthrough"
            | "false"
            | "fileprivate"
            | "for"
            | "func"
            | "guard"
            | "if"
            | "import"
            | "in"
            | "init"
            | "inout"
            | "internal"
            | "is"
            | "let"
            | "macro"
            | "nil"
            | "nonisolated"
            | "open"
            | "operator"
            | "precedencegroup"
            | "private"
            | "protocol"
            | "public"
            | "repeat"
            | "rethrows"
            | "return"
            | "self"
            | "static"
            | "struct"
            | "subscript"
            | "super"
            | "switch"
            | "throw"
            | "throws"
            | "true"
            | "try"
            | "typealias"
            | "var"
            | "where"
            | "while"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::report::{
        HexBytes, IdentityStability, NonEmpty, SwiftEntityId, SwiftEvidenceId, SwiftObservationId,
        SwiftQualifiedName,
    };

    fn evidence() -> NonEmpty<SwiftEvidenceId> {
        NonEmpty::new(vec![
            SwiftEvidenceId::new("1".repeat(64)).expect("valid evidence ID"),
        ])
        .expect("one evidence ID")
    }

    fn entity(kind: SwiftTypeKind, fields: Vec<SwiftField>) -> SwiftEntity {
        SwiftEntity {
            id: SwiftEntityId::new("0".repeat(64)).expect("valid entity ID"),
            identity_stability: IdentityStability::CrossBuild,
            state: SwiftEntityState::Partial,
            kind: SwiftValue::Known {
                value: kind,
                evidence: evidence(),
            },
            qualified_name: SwiftValue::Known {
                value: SwiftQualifiedName {
                    module: Some("Example".to_owned()),
                    path: NonEmpty::new(vec!["Example".to_owned(), "Record".to_owned()])
                        .expect("qualified name"),
                },
                evidence: evidence(),
            },
            descriptor: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            parent: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            fields_or_cases: SwiftValue::Known {
                value: fields,
                evidence: evidence(),
            },
            conformances: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::UnresolvedReference,
            },
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
    fn a_superclass_opens_the_inheritance_clause_ahead_of_conformances() {
        use crate::analysis::report::{SwiftConformanceRef, SwiftEntityRef};

        let mut record = entity(SwiftTypeKind::Class, Vec::new());
        record.superclass = SwiftValue::Known {
            value: "Example.Base".to_owned(),
            evidence: evidence(),
        };
        record.conformances = SwiftValue::Known {
            value: vec![SwiftConformanceRef {
                protocol: SwiftEntityRef {
                    entity_id: None,
                    qualified_name: Some(SwiftQualifiedName {
                        module: Some("Swift".to_owned()),
                        path: NonEmpty::new(vec!["Swift".to_owned(), "Equatable".to_owned()])
                            .expect("qualified name"),
                    }),
                },
                r#type: None,
                descriptor: None,
            }],
            evidence: evidence(),
        };
        let mut output = String::new();

        render_entity(&mut output, &record);

        // Swift requires the superclass first in the inheritance clause.
        assert!(
            output.contains("class Record: Example.Base, Swift.Equatable {"),
            "unexpected inheritance clause: {output}"
        );
    }

    #[test]
    fn a_root_class_declares_no_inheritance_clause() {
        let record = entity(SwiftTypeKind::Class, Vec::new());
        let mut output = String::new();

        render_entity(&mut output, &record);

        // A native Swift class inherits from nothing unless declared, so an
        // absent superclass must not become an invented base type.
        assert!(
            output.contains("class Record {"),
            "a root class must declare no base: {output}"
        );
        assert!(!output.contains("class Record:"));
    }

    #[test]
    fn struct_projection_never_invents_an_unresolved_type() {
        let record = entity(
            SwiftTypeKind::Struct,
            vec![
                SwiftField {
                    name: Some("title".to_owned()),
                    mangled_type: Some(HexBytes::from_bytes(b"SS")),
                    type_name: Some("Swift.String".to_owned()),
                    flags: FIELD_IS_VAR,
                },
                SwiftField {
                    name: Some("_store".to_owned()),
                    mangled_type: Some(HexBytes::from_bytes(&[2, 1, 0, 0, 0])),
                    type_name: None,
                    flags: FIELD_IS_VAR,
                },
            ],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(output.contains("struct Record {"));
        assert!(output.contains("var title: Swift.String"));
        assert!(output.contains("Stored field \"_store\" has an unresolved type"));
        assert!(!output.contains("var _store: Any"));
    }

    #[test]
    fn enum_projection_preserves_payload_and_payloadless_cases() {
        let record = entity(
            SwiftTypeKind::Enum,
            vec![
                SwiftField {
                    name: Some("empty".to_owned()),
                    mangled_type: None,
                    type_name: None,
                    flags: 0,
                },
                SwiftField {
                    name: Some("value".to_owned()),
                    mangled_type: Some(HexBytes::from_bytes(b"Si")),
                    type_name: Some("Swift.Int".to_owned()),
                    flags: FIELD_IS_INDIRECT_CASE,
                },
            ],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(output.contains("enum Record {"));
        assert!(output.contains("case empty"));
        assert!(output.contains("indirect case value(Swift.Int)"));
    }

    #[test]
    fn generic_placeholders_recovered_from_payloads_reach_the_header() {
        let record = entity(
            SwiftTypeKind::Enum,
            vec![
                SwiftField {
                    name: Some("left".to_owned()),
                    mangled_type: Some(HexBytes::from_bytes(b"x")),
                    type_name: Some("A".to_owned()),
                    flags: 0,
                },
                SwiftField {
                    name: Some("right".to_owned()),
                    mangled_type: Some(HexBytes::from_bytes(b"q_")),
                    type_name: Some("B".to_owned()),
                    flags: 0,
                },
            ],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(output.contains("enum Record<A, B> {"));
        assert!(output.contains("case left(A)"));
        assert!(output.contains("case right(B)"));
    }

    #[test]
    fn reserved_words_are_escaped_wherever_a_name_can_sit() {
        // /usr/bin/plutil ships an enum whose cases are named `true` and
        // `false`; bare keywords render as invalid Swift.
        let record = entity(
            SwiftTypeKind::Enum,
            vec![
                SwiftField {
                    name: Some("true".to_owned()),
                    mangled_type: None,
                    type_name: None,
                    flags: 0,
                },
                SwiftField {
                    name: Some("default".to_owned()),
                    mangled_type: Some(HexBytes::from_bytes(b"Si")),
                    type_name: Some("Swift.Int".to_owned()),
                    flags: 0,
                },
            ],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(
            output.contains("case `true`"),
            "keyword case unescaped: {output}"
        );
        assert!(
            output.contains("case `default`(Swift.Int)"),
            "payload keyword case unescaped: {output}"
        );

        let record = entity(
            SwiftTypeKind::Struct,
            vec![SwiftField {
                name: Some("self".to_owned()),
                mangled_type: None,
                type_name: Some("Swift.String".to_owned()),
                flags: FIELD_IS_VAR,
            }],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(
            output.contains("var `self`: Swift.String"),
            "keyword stored field unescaped: {output}"
        );
    }

    fn slice_of(entities: Vec<SwiftEntity>) -> SwiftSliceReport {
        use crate::analysis::report::{
            Architecture, ContainerKind, ContentHash, ImageIdentity, SwiftCollectorExecution,
            SwiftCollectorId, SwiftCollectorOutcome, SwiftPartitionCounts, SwiftSelectionResult,
        };
        let architecture = Architecture {
            cpu_type: 0x0100_000c,
            cpu_subtype: 0,
        };
        SwiftSliceReport {
            architecture,
            image: ImageIdentity {
                content_sha256: ContentHash::new("3".repeat(64)).expect("valid content hash"),
                byte_len: 0,
                container: ContainerKind::Thin,
                slice_index: 0,
                architecture,
                uuid: None,
            },
            observations: Vec::new(),
            evidence: Vec::new(),
            selection: SwiftSelectionResult {
                selected_entity_ids: entities.iter().map(|entity| entity.id.clone()).collect(),
                totals: SwiftPartitionCounts {
                    metadata_defined: 0,
                    referenced: 0,
                    symbol_only: 0,
                    partial: 0,
                    unknown: 0,
                    excluded_observations: 0,
                },
            },
            entities,
            header: None,
            diagnostics: Vec::new(),
            executions: NonEmpty::new(vec![SwiftCollectorExecution {
                collector: SwiftCollectorId::MetadataDescriptors,
                outcome: SwiftCollectorOutcome::Complete,
                input_records: 0,
                output_records: 0,
            }])
            .expect("one execution"),
        }
    }

    #[test]
    fn one_type_observed_twice_declares_only_its_richest_observation() {
        // A Swift class exposed to Objective-C is observed as both a context
        // descriptor and Objective-C metadata; the source declares it once.
        let mut shadow = entity(SwiftTypeKind::Class, Vec::new());
        shadow.id = SwiftEntityId::new("a".repeat(64)).expect("valid entity ID");
        shadow.fields_or_cases = SwiftValue::Unavailable {
            reason: SwiftUnavailableReason::NotEncoded,
        };
        let mut defined = entity(
            SwiftTypeKind::Class,
            vec![SwiftField {
                name: Some("stored".to_owned()),
                mangled_type: None,
                type_name: Some("Swift.Int".to_owned()),
                flags: FIELD_IS_VAR,
            }],
        );
        defined.id = SwiftEntityId::new("b".repeat(64)).expect("valid entity ID");
        defined.state = SwiftEntityState::MetadataDefined;

        for order in [
            vec![shadow.clone(), defined.clone()],
            vec![defined.clone(), shadow.clone()],
        ] {
            let slice = slice_of(order);
            let chosen = declarable_entities(&slice);
            assert_eq!(chosen.len(), 1, "one declaration per nominal type");
            assert_eq!(chosen[0].id, defined.id, "the richest observation wins");

            let source = render_declarations(&slice);
            assert_eq!(source.matches("class Record").count(), 1);
            assert!(source.contains("var stored: Swift.Int"));
            assert!(!source.contains("Stored fields unavailable"));
        }
    }

    #[test]
    fn the_displaced_observation_is_kept_for_the_caller() {
        let mut shadow = entity(SwiftTypeKind::Class, Vec::new());
        shadow.id = SwiftEntityId::new("e".repeat(64)).expect("valid entity ID");
        shadow.fields_or_cases = SwiftValue::Unavailable {
            reason: SwiftUnavailableReason::NotEncoded,
        };
        let mut defined = entity(
            SwiftTypeKind::Class,
            vec![SwiftField {
                name: Some("stored".to_owned()),
                mangled_type: None,
                type_name: Some("Swift.Int".to_owned()),
                flags: FIELD_IS_VAR,
            }],
        );
        defined.id = SwiftEntityId::new("f".repeat(64)).expect("valid entity ID");
        defined.state = SwiftEntityState::MetadataDefined;

        // Whichever order the report lists them in, the richer observation is
        // declared and the other is handed back rather than dropped silently.
        for order in [
            vec![shadow.clone(), defined.clone()],
            vec![defined.clone(), shadow.clone()],
        ] {
            let slice = slice_of(order);
            let selection = declaration_selection(&slice);
            assert_eq!(selection.declared.len(), 1);
            assert_eq!(selection.declared[0].id, defined.id);
            assert_eq!(selection.suppressed.len(), 1);
            assert_eq!(selection.suppressed[0].id, shadow.id);
        }
    }

    #[test]
    fn distinct_types_are_never_collapsed() {
        let mut first = entity(SwiftTypeKind::Class, Vec::new());
        first.id = SwiftEntityId::new("c".repeat(64)).expect("valid entity ID");
        let mut second = entity(SwiftTypeKind::Class, Vec::new());
        second.id = SwiftEntityId::new("d".repeat(64)).expect("valid entity ID");
        second.qualified_name = SwiftValue::Known {
            value: SwiftQualifiedName {
                module: Some("Example".to_owned()),
                path: NonEmpty::new(vec!["Example".to_owned(), "Other".to_owned()])
                    .expect("qualified name"),
            },
            evidence: evidence(),
        };

        let slice = slice_of(vec![first, second]);
        assert_eq!(declarable_entities(&slice).len(), 2);
    }

    #[test]
    fn unselected_entities_are_never_declared() {
        let mut slice = slice_of(vec![entity(SwiftTypeKind::Class, Vec::new())]);
        slice.selection.selected_entity_ids.clear();
        assert!(declarable_entities(&slice).is_empty());
    }

    #[test]
    fn imported_objc_types_are_references_not_local_swift_declarations() {
        let mut imported = entity(SwiftTypeKind::Class, Vec::new());
        imported.qualified_name = SwiftValue::Known {
            value: SwiftQualifiedName {
                module: Some("__C".to_owned()),
                path: NonEmpty::new(vec!["__C".to_owned(), "CFString".to_owned()])
                    .expect("qualified name"),
            },
            evidence: evidence(),
        };
        let slice = slice_of(vec![imported]);

        assert!(declarable_entities(&slice).is_empty());
        assert!(!render_declarations(&slice).contains("class CFString"));
    }

    #[test]
    fn generic_placeholders_are_found_inside_type_arguments() {
        assert_eq!(generic_parameters_in("A").collect::<Vec<_>>(), vec!["A"]);
        assert_eq!(
            generic_parameters_in("Swift.Optional<A>").collect::<Vec<_>>(),
            vec!["A"]
        );
        assert_eq!(
            generic_parameters_in("Swift.Dictionary<A, B>").collect::<Vec<_>>(),
            vec!["A", "B"]
        );
        assert!(
            generic_parameters_in("Swift.Array<__C.NSControl>")
                .next()
                .is_none()
        );
        assert!(generic_parameters_in("Swift.String").next().is_none());
        // A qualified name whose final component is one letter is a real type,
        // not a placeholder, so it stays a single segment.
        assert!(generic_parameters_in("Module.A").next().is_none());
        // A dependent member type is rooted at the placeholder it constrains,
        // so the root is the placeholder and the trailing path is not.
        assert_eq!(
            generic_parameters_in("A.Swift.Collection.Index").collect::<Vec<_>>(),
            vec!["A"]
        );
        assert_eq!(
            generic_parameters_in("Swift.Range<A.Swift.Collection.Index>").collect::<Vec<_>>(),
            vec!["A"]
        );
        assert_eq!(
            generic_parameters_in("(A.Swift.Sequence.Element) -> B").collect::<Vec<_>>(),
            vec!["A", "B"]
        );
        // A one-letter tuple label names a field, not a type parameter.
        assert!(
            generic_parameters_in("(A: Swift.Int, B: Swift.Int)")
                .next()
                .is_none()
        );
        // A placeholder beside a label is still a placeholder.
        assert_eq!(
            generic_parameters_in("(key: Swift.String, value: A)").collect::<Vec<_>>(),
            vec!["A"]
        );
    }

    #[test]
    fn a_placeholder_reached_only_through_a_dependent_member_type_is_declared() {
        // `Algorithms.ChunkedByCollection.Index` in libswiftCreateML declares no
        // parameter of its own; its one field is `Swift.Range<A...Index>`. Without
        // the dotted-root rule the rendered struct referenced an undeclared `A`.
        let record = entity(
            SwiftTypeKind::Struct,
            vec![SwiftField {
                name: Some("baseRange".to_owned()),
                mangled_type: None,
                type_name: Some("Swift.Range<A.Swift.Collection.Index>".to_owned()),
                flags: FIELD_IS_VAR,
            }],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(
            output.contains("struct Record<A> {"),
            "a placeholder behind a dependent member type must be declared: {output}"
        );
    }

    #[test]
    fn a_placeholder_behind_optional_still_reaches_the_declaration() {
        let record = entity(
            SwiftTypeKind::Class,
            vec![SwiftField {
                name: Some("value".to_owned()),
                mangled_type: None,
                type_name: Some("Swift.Optional<A>".to_owned()),
                flags: FIELD_IS_VAR,
            }],
        );
        let mut output = String::new();

        render_entity(&mut output, &record);

        assert!(
            output.contains("class Record<A> {"),
            "expected a generic parameter clause: {output}"
        );
    }
}
