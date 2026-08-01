use macho::analysis::report::{
    ObjCEncodedType, ObjCEntity, ObjCEntityId, ObjCMemberId, ObjCMethod, ObjCMethodKind,
    ObjCMethodSignature, ObjCOwnership, ObjCPresence, ObjCPrimitive, ObjCPropertyAttributes,
    ObjCQualifier, ObjCSliceReport, ObjCUnavailableReason, ObjCValue, RecordKind,
};

pub(super) fn entity_methods(entity: &ObjCEntity) -> Box<dyn Iterator<Item = &ObjCMethod> + '_> {
    match entity {
        ObjCEntity::Class(value) => {
            Box::new(value.instance_methods.iter().chain(&value.class_methods))
        }
        ObjCEntity::Category(value) => {
            Box::new(value.instance_methods.iter().chain(&value.class_methods))
        }
        ObjCEntity::Protocol(value) => Box::new(
            value
                .required_instance_methods
                .iter()
                .chain(&value.required_class_methods)
                .chain(&value.optional_instance_methods)
                .chain(&value.optional_class_methods),
        ),
    }
}

pub(super) fn find_method<'a>(
    slice: &'a ObjCSliceReport,
    id: &ObjCMemberId,
) -> Option<&'a ObjCMethod> {
    slice
        .entities
        .iter()
        .flat_map(entity_methods)
        .find(|method| method.id == *id)
}

pub(super) fn entity_name_by_id(slice: &ObjCSliceReport, id: &ObjCEntityId) -> Option<String> {
    slice
        .entities
        .iter()
        .find(|entity| entity.common().id == *id)
        .and_then(|entity| known(&entity.common().name).cloned())
}

pub(super) fn known<T>(value: &ObjCValue<T>) -> Option<&T> {
    match value {
        ObjCValue::Known { value, .. } => Some(value),
        ObjCValue::Conflicted { .. } | ObjCValue::Unavailable { .. } => None,
    }
}

pub(super) fn value_state<T>(value: &ObjCValue<T>) -> &'static str {
    match value {
        ObjCValue::Known { .. } => "known",
        ObjCValue::Conflicted { .. } => "conflicted",
        ObjCValue::Unavailable { .. } => "unavailable",
    }
}

pub(super) fn value_u64(value: &ObjCValue<u64>) -> String {
    known(value)
        .map(ToString::to_string)
        .unwrap_or_else(|| value_state(value).to_owned())
}

/// A member value prepared for display.
///
/// The two cases stay distinct so a caller cannot style an absent value as a
/// decoded one: recovery that never established a type must not read like a
/// type it recovered.
pub(super) enum ValueDisplay {
    /// A decoded value, rendered as text.
    Known(String),
    /// A bracketed marker naming why no decoded value exists.
    Absent(String),
}

/// Render a recovered value, or a marker naming why it is absent.
///
/// The `PartialEq` bound is what `AtLeastTwo` requires to report how many
/// candidates a conflict holds.
pub(super) fn value_display<T: PartialEq>(
    value: &ObjCValue<T>,
    render: impl FnOnce(&T) -> String,
) -> ValueDisplay {
    match value {
        ObjCValue::Known { value, .. } => ValueDisplay::Known(render(value)),
        ObjCValue::Conflicted { candidates } => {
            ValueDisplay::Absent(format!("<conflicted:{}>", candidates.as_slice().len()))
        }
        ObjCValue::Unavailable { reason } => ValueDisplay::Absent(format!(
            "<unavailable:{}>",
            unavailable_reason_name(*reason)
        )),
    }
}

pub(super) fn unavailable_reason_name(value: ObjCUnavailableReason) -> &'static str {
    match value {
        ObjCUnavailableReason::NotEncoded => "not-encoded",
        ObjCUnavailableReason::MalformedEncoding => "malformed-encoding",
        ObjCUnavailableReason::UnresolvedReference => "unresolved-reference",
        ObjCUnavailableReason::AmbiguousOwner => "ambiguous-owner",
        ObjCUnavailableReason::ConflictingMetadata => "conflicting-metadata",
        ObjCUnavailableReason::Truncated => "truncated",
        ObjCUnavailableReason::UnsupportedEncoding => "unsupported-encoding",
        ObjCUnavailableReason::SemanticValidationFailed => "semantic-validation-failed",
    }
}

/// Spell a decoded type on one line.
///
/// This is the surface listing's compact spelling, not the validated header
/// projection: it never fails, and it reports an encoding it could not classify
/// as such instead of substituting a plausible type.
pub(super) fn encoded_type_text(value: &ObjCEncodedType) -> String {
    match value {
        ObjCEncodedType::Primitive { value, qualifiers } => {
            qualify(qualifiers, primitive_text(*value).to_owned())
        }
        ObjCEncodedType::Object {
            name,
            protocols,
            qualifiers,
        } => {
            let mut text = name.clone().unwrap_or_else(|| "id".to_owned());
            if !protocols.is_empty() {
                text.push('<');
                text.push_str(&protocols.join(", "));
                text.push('>');
            }
            if name.is_some() {
                text.push_str(" *");
            }
            qualify(qualifiers, text)
        }
        ObjCEncodedType::Class => "Class".to_owned(),
        ObjCEncodedType::Selector => "SEL".to_owned(),
        // The `@?` encoding carries no signature, so an unsigned block is named
        // rather than given invented parameter types.
        ObjCEncodedType::Block { signature: None } => "^block".to_owned(),
        ObjCEncodedType::Block {
            signature: Some(signature),
        } => format!(
            "{} (^)({})",
            encoded_type_text(&signature.return_type),
            parameter_text(&signature.parameters)
        ),
        ObjCEncodedType::Pointer { pointee } => {
            let pointee = encoded_type_text(pointee);
            if pointee.ends_with('*') {
                format!("{pointee}*")
            } else {
                format!("{pointee} *")
            }
        }
        ObjCEncodedType::Array { count, element } => {
            format!("{}[{count}]", encoded_type_text(element))
        }
        ObjCEncodedType::Record {
            record_kind, name, ..
        } => format!(
            "{} {}",
            record_kind_text(*record_kind),
            name.as_deref().unwrap_or("<anonymous>")
        ),
        ObjCEncodedType::Bitfield { width } => format!("unsigned int : {width}"),
        ObjCEncodedType::Unknown { raw } => format!("<unparsed:{}>", raw.as_str()),
    }
}

/// Spell a method signature as its return type over its parameter types.
///
/// `parameters` holds only the selector's own arguments; the implicit `self`
/// and `_cmd` are separate fields upstream and never appear here.
pub(super) fn method_signature_text(value: &ObjCMethodSignature) -> String {
    format!(
        "{} ({})",
        encoded_type_text(&value.return_type),
        parameter_text(&value.parameters)
    )
}

pub(super) fn property_attributes_text(value: &ObjCPropertyAttributes) -> String {
    let mut parts = vec![
        if value.readonly {
            "readonly"
        } else {
            "readwrite"
        }
        .to_owned(),
    ];
    if let Some(ownership) = ownership_text(value.ownership) {
        parts.push(ownership.to_owned());
    }
    parts.push(
        if value.nonatomic {
            "nonatomic"
        } else {
            "atomic"
        }
        .to_owned(),
    );
    if value.dynamic {
        parts.push("dynamic".to_owned());
    }
    if let Some(getter) = &value.getter {
        parts.push(format!("getter={}", getter.spelling));
    }
    if let Some(setter) = &value.setter {
        parts.push(format!("setter={}", setter.spelling));
    }
    if let Some(ivar) = &value.ivar {
        parts.push(format!("ivar={ivar}"));
    }
    parts.join(",")
}

fn parameter_text(values: &[ObjCEncodedType]) -> String {
    if values.is_empty() {
        return "void".to_owned();
    }
    values
        .iter()
        .map(encoded_type_text)
        .collect::<Vec<_>>()
        .join(", ")
}

fn qualify(qualifiers: &[ObjCQualifier], text: String) -> String {
    if qualifiers.is_empty() {
        return text;
    }
    let prefix = qualifiers
        .iter()
        .map(|value| qualifier_text(*value))
        .collect::<Vec<_>>()
        .join(" ");
    format!("{prefix} {text}")
}

fn qualifier_text(value: ObjCQualifier) -> &'static str {
    match value {
        ObjCQualifier::Const => "const",
        ObjCQualifier::In => "in",
        ObjCQualifier::Inout => "inout",
        ObjCQualifier::Out => "out",
        ObjCQualifier::Bycopy => "bycopy",
        ObjCQualifier::Byref => "byref",
        ObjCQualifier::Oneway => "oneway",
        ObjCQualifier::Atomic => "_Atomic",
    }
}

fn primitive_text(value: ObjCPrimitive) -> &'static str {
    match value {
        ObjCPrimitive::Void => "void",
        ObjCPrimitive::Char => "char",
        ObjCPrimitive::UnsignedChar => "unsigned char",
        ObjCPrimitive::Short => "short",
        ObjCPrimitive::UnsignedShort => "unsigned short",
        ObjCPrimitive::Int => "int",
        ObjCPrimitive::UnsignedInt => "unsigned int",
        ObjCPrimitive::Long => "long",
        ObjCPrimitive::UnsignedLong => "unsigned long",
        ObjCPrimitive::LongLong => "long long",
        ObjCPrimitive::UnsignedLongLong => "unsigned long long",
        ObjCPrimitive::Int128 => "__int128",
        ObjCPrimitive::UnsignedInt128 => "unsigned __int128",
        ObjCPrimitive::Float => "float",
        ObjCPrimitive::Double => "double",
        ObjCPrimitive::LongDouble => "long double",
        ObjCPrimitive::Bool => "bool",
        ObjCPrimitive::Cstring => "char *",
        ObjCPrimitive::UnknownObject => "id",
    }
}

fn ownership_text(value: ObjCOwnership) -> Option<&'static str> {
    match value {
        ObjCOwnership::Assign => Some("assign"),
        ObjCOwnership::Copy => Some("copy"),
        ObjCOwnership::Retain => Some("retain"),
        ObjCOwnership::Strong => Some("strong"),
        ObjCOwnership::Weak => Some("weak"),
        ObjCOwnership::UnsafeUnretained => Some("unsafe_unretained"),
        ObjCOwnership::Unspecified => None,
    }
}

fn record_kind_text(value: RecordKind) -> &'static str {
    match value {
        RecordKind::Struct => "struct",
        RecordKind::Union => "union",
        RecordKind::Class => "class",
        RecordKind::Enum => "enum",
    }
}

pub(super) fn architecture_name(slice: &ObjCSliceReport) -> String {
    macho::core::model::header::ArchSpec {
        cpu_type: macho::core::model::header::CpuType(slice.architecture.cpu_type),
        cpu_subtype: macho::core::model::header::CpuSubtype(slice.architecture.cpu_subtype),
    }
    .name()
}

pub(super) fn entity_kind(entity: &ObjCEntity) -> &'static str {
    match entity {
        ObjCEntity::Class(_) => "class",
        ObjCEntity::Category(_) => "category",
        ObjCEntity::Protocol(_) => "protocol",
    }
}

pub(super) fn presence_heading(value: ObjCPresence) -> &'static str {
    match value {
        ObjCPresence::Defined => "Defined entities",
        ObjCPresence::Referenced => "Referenced entities",
        ObjCPresence::Partial => "Partial entities",
    }
}

pub(super) fn presence_name(value: ObjCPresence) -> &'static str {
    match value {
        ObjCPresence::Defined => "defined",
        ObjCPresence::Referenced => "referenced",
        ObjCPresence::Partial => "partial",
    }
}

pub(super) fn method_kind_name(value: ObjCMethodKind) -> &'static str {
    match value {
        ObjCMethodKind::Instance => "instance",
        ObjCMethodKind::Class => "class",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macho::analysis::report::{
        AtLeastTwo, HexBytes, NonEmpty, ObjCCandidate, ObjCEvidenceId, Selector,
    };

    fn evidence(byte: char) -> NonEmpty<ObjCEvidenceId> {
        NonEmpty::new(vec![
            ObjCEvidenceId::new(byte.to_string().repeat(64)).expect("valid evidence ID"),
        ])
        .expect("one evidence ID")
    }

    fn primitive(value: ObjCPrimitive) -> ObjCEncodedType {
        ObjCEncodedType::Primitive {
            value,
            qualifiers: Vec::new(),
        }
    }

    fn object(name: Option<&str>) -> ObjCEncodedType {
        ObjCEncodedType::Object {
            name: name.map(str::to_owned),
            protocols: Vec::new(),
            qualifiers: Vec::new(),
        }
    }

    fn text(value: &ObjCValue<ObjCEncodedType>) -> String {
        match value_display(value, encoded_type_text) {
            ValueDisplay::Known(text) | ValueDisplay::Absent(text) => text,
        }
    }

    #[test]
    fn primitives_and_objects_spell_their_c_types() {
        assert_eq!(encoded_type_text(&primitive(ObjCPrimitive::Void)), "void");
        assert_eq!(encoded_type_text(&primitive(ObjCPrimitive::Bool)), "bool");
        assert_eq!(
            encoded_type_text(&primitive(ObjCPrimitive::UnsignedLongLong)),
            "unsigned long long"
        );
        assert_eq!(
            encoded_type_text(&primitive(ObjCPrimitive::Cstring)),
            "char *"
        );
        // A bare `@` names no class, so it is `id` rather than a guessed type.
        assert_eq!(
            encoded_type_text(&primitive(ObjCPrimitive::UnknownObject)),
            "id"
        );
        assert_eq!(encoded_type_text(&object(None)), "id");
        assert_eq!(encoded_type_text(&object(Some("NSString"))), "NSString *");
        assert_eq!(encoded_type_text(&ObjCEncodedType::Class), "Class");
        assert_eq!(encoded_type_text(&ObjCEncodedType::Selector), "SEL");
    }

    #[test]
    fn protocol_lists_attach_to_their_base_type() {
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Object {
                name: None,
                protocols: vec!["NSCopying".to_owned(), "NSCoding".to_owned()],
                qualifiers: Vec::new(),
            }),
            "id<NSCopying, NSCoding>"
        );
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Object {
                name: Some("NSArray".to_owned()),
                protocols: vec!["NSCopying".to_owned()],
                qualifiers: Vec::new(),
            }),
            "NSArray<NSCopying> *"
        );
    }

    #[test]
    fn nested_pointers_collapse_their_stars() {
        let single = ObjCEncodedType::Pointer {
            pointee: Box::new(primitive(ObjCPrimitive::Char)),
        };
        assert_eq!(encoded_type_text(&single), "char *");
        let double = ObjCEncodedType::Pointer {
            pointee: Box::new(single),
        };
        assert_eq!(encoded_type_text(&double), "char **");
    }

    #[test]
    fn aggregates_and_bitfields_spell_their_shape() {
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Array {
                count: 4,
                element: Box::new(primitive(ObjCPrimitive::Int)),
            }),
            "int[4]"
        );
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Record {
                record_kind: RecordKind::Struct,
                name: Some("CGRect".to_owned()),
                fields: Vec::new(),
            }),
            "struct CGRect"
        );
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Record {
                record_kind: RecordKind::Union,
                name: None,
                fields: Vec::new(),
            }),
            "union <anonymous>"
        );
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Bitfield { width: 3 }),
            "unsigned int : 3"
        );
    }

    #[test]
    fn qualifiers_prefix_the_type_they_qualify() {
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Primitive {
                value: ObjCPrimitive::Int,
                qualifiers: vec![ObjCQualifier::Const, ObjCQualifier::Inout],
            }),
            "const inout int"
        );
    }

    #[test]
    fn unsigned_blocks_are_named_rather_than_given_invented_parameters() {
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Block { signature: None }),
            "^block"
        );
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Block {
                signature: Some(Box::new(ObjCMethodSignature {
                    return_type: primitive(ObjCPrimitive::Void),
                    parameters: vec![object(Some("NSError"))],
                    frame_size: None,
                    argument_offsets: Vec::new(),
                })),
            }),
            "void (^)(NSError *)"
        );
    }

    #[test]
    fn unclassified_encodings_report_their_bytes_instead_of_a_plausible_type() {
        assert_eq!(
            encoded_type_text(&ObjCEncodedType::Unknown {
                raw: HexBytes::from_bytes(b"?"),
            }),
            "<unparsed:3f>"
        );
    }

    #[test]
    fn signatures_render_an_empty_parameter_list_as_void() {
        let signature = ObjCMethodSignature {
            return_type: object(None),
            parameters: Vec::new(),
            frame_size: None,
            argument_offsets: Vec::new(),
        };
        assert_eq!(method_signature_text(&signature), "id (void)");
    }

    #[test]
    fn signatures_render_only_the_selectors_own_arguments() {
        // `self` and `_cmd` live in separate upstream fields, so a two-colon
        // selector must render exactly two parameters.
        let signature = ObjCMethodSignature {
            return_type: primitive(ObjCPrimitive::Void),
            parameters: vec![object(Some("NSString")), primitive(ObjCPrimitive::Bool)],
            frame_size: None,
            argument_offsets: Vec::new(),
        };
        assert_eq!(method_signature_text(&signature), "void (NSString *, bool)");
    }

    #[test]
    fn property_attributes_list_only_what_the_encoding_carried() {
        let attributes = ObjCPropertyAttributes {
            r#type: object(Some("NSString")),
            readonly: true,
            ownership: ObjCOwnership::Copy,
            nonatomic: true,
            dynamic: false,
            getter: Some(Selector::new("title")),
            setter: None,
            ivar: Some("_title".to_owned()),
            unknown: Vec::new(),
        };
        assert_eq!(
            property_attributes_text(&attributes),
            "readonly,copy,nonatomic,getter=title,ivar=_title"
        );
    }

    #[test]
    fn unspecified_ownership_is_omitted_rather_than_defaulted_to_assign() {
        // The header projection substitutes `assign` because emitted source must
        // state something; a surface listing must not assert what was absent.
        let attributes = ObjCPropertyAttributes {
            r#type: primitive(ObjCPrimitive::Bool),
            readonly: false,
            ownership: ObjCOwnership::Unspecified,
            nonatomic: false,
            dynamic: true,
            getter: None,
            setter: None,
            ivar: None,
            unknown: Vec::new(),
        };
        assert_eq!(
            property_attributes_text(&attributes),
            "readwrite,atomic,dynamic"
        );
    }

    #[test]
    fn absent_values_never_render_as_a_recovered_type() {
        let unavailable = ObjCValue::<ObjCEncodedType>::Unavailable {
            reason: ObjCUnavailableReason::MalformedEncoding,
        };
        assert!(matches!(
            value_display(&unavailable, encoded_type_text),
            ValueDisplay::Absent(_)
        ));
        assert_eq!(text(&unavailable), "<unavailable:malformed-encoding>");

        let conflicted = ObjCValue::Conflicted {
            candidates: AtLeastTwo::new(vec![
                ObjCCandidate {
                    value: object(Some("NSString")),
                    evidence: evidence('0'),
                },
                ObjCCandidate {
                    value: object(Some("NSNumber")),
                    evidence: evidence('1'),
                },
            ])
            .expect("two candidates"),
        };
        assert!(matches!(
            value_display(&conflicted, encoded_type_text),
            ValueDisplay::Absent(_)
        ));
        assert_eq!(text(&conflicted), "<conflicted:2>");

        let recovered = ObjCValue::Known {
            value: object(Some("NSString")),
            evidence: evidence('2'),
        };
        assert!(matches!(
            value_display(&recovered, encoded_type_text),
            ValueDisplay::Known(_)
        ));
        assert_eq!(text(&recovered), "NSString *");
    }

    #[test]
    fn every_unavailable_reason_has_a_distinct_name() {
        let reasons = [
            ObjCUnavailableReason::NotEncoded,
            ObjCUnavailableReason::MalformedEncoding,
            ObjCUnavailableReason::UnresolvedReference,
            ObjCUnavailableReason::AmbiguousOwner,
            ObjCUnavailableReason::ConflictingMetadata,
            ObjCUnavailableReason::Truncated,
            ObjCUnavailableReason::UnsupportedEncoding,
            ObjCUnavailableReason::SemanticValidationFailed,
        ];
        let names = reasons
            .iter()
            .map(|reason| unavailable_reason_name(*reason))
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(names.len(), reasons.len());
    }
}
