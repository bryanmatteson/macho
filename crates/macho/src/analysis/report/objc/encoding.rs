use crate::core::MachoFile;
use crate::metadata::objc::encoding::{ObjCQualifiedType, ObjCType, TypeQualifier};

use super::super::{
    HexBytes, NonEmpty, ObjCDiagnosticId, ObjCEntityId, ObjCEvidenceId, ObjCMemberId, RecordKind,
    Selector, Severity, sha256_hex,
};
use super::types::*;

pub(super) struct MethodContext<'a, 'data> {
    pub macho: &'a MachoFile<'data>,
    pub origin: &'a ObjCEntityId,
    pub evidence_id: &'a ObjCEvidenceId,
    pub diagnostics: &'a mut Vec<ObjCDiagnostic>,
}

pub(super) fn method(
    value: &crate::metadata::objc::ObjCMethod,
    kind: ObjCMethodKind,
    identity_scope: &str,
    ordinal: usize,
    context: &mut MethodContext<'_, '_>,
) -> ObjCMethod {
    let MethodContext {
        macho,
        origin,
        evidence_id,
        diagnostics,
    } = context;
    let member_id = member_id(&format!(
        "method|{origin}|{identity_scope}|{kind:?}|{}|{}|{ordinal}",
        value.name, value.imp.0,
    ));
    let selector = Selector::new(value.name.clone());
    let signature = match value.parsed_signature() {
        Some(parsed) if parsed.arguments.len() as u32 == selector.colon_count => ObjCValue::Known {
            value: method_signature(&parsed),
            evidence: evidence(evidence_id),
        },
        Some(_) => {
            diagnostics.push(diagnostic(
                origin,
                evidence_id,
                ObjCDiagnosticCode::SelectorArityMismatch,
                format!(
                    "selector `{}` does not match encoded explicit argument count",
                    value.name
                ),
            ));
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::MalformedEncoding,
            }
        }
        None => {
            diagnostics.push(diagnostic(
                origin,
                evidence_id,
                ObjCDiagnosticCode::MalformedEncoding,
                format!(
                    "malformed Objective-C method encoding `{}`",
                    value.type_encoding
                ),
            ));
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::MalformedEncoding,
            }
        }
    };
    ObjCMethod {
        id: member_id,
        selector: ObjCValue::Known {
            value: selector,
            evidence: evidence(evidence_id),
        },
        kind,
        raw_encoding: HexBytes::from_bytes(value.type_encoding.as_bytes()),
        signature,
        implementation: ObjCValue::Known {
            value: Some(ImplementationLocation {
                virtual_address: value.imp.0,
                file_offset: macho
                    .address_map()
                    .va_to_thin_offset(value.imp)
                    .ok()
                    .map(|offset| offset.0),
            }),
            evidence: evidence(evidence_id),
        },
        origin: origin.clone(),
    }
}

pub(super) fn property(
    value: &crate::metadata::objc::ObjCProperty,
    ordinal: usize,
    origin: &ObjCEntityId,
    evidence_id: &ObjCEvidenceId,
) -> ObjCProperty {
    let id = member_id(&format!("property|{origin}|{}|{ordinal}", value.name));
    let parsed = value.parsed_attributes();
    let parsed_attributes = parsed.effective_type().map_or(
        ObjCValue::Unavailable {
            reason: ObjCUnavailableReason::MalformedEncoding,
        },
        |ty| ObjCValue::Known {
            value: ObjCPropertyAttributes {
                r#type: qualified_type(&ty),
                readonly: parsed.readonly,
                ownership: if parsed.copy {
                    ObjCOwnership::Copy
                } else if parsed.strong {
                    ObjCOwnership::Strong
                } else if parsed.weak {
                    ObjCOwnership::Weak
                } else {
                    ObjCOwnership::Unspecified
                },
                nonatomic: parsed.nonatomic,
                dynamic: parsed.dynamic,
                getter: parsed.getter.map(Selector::new),
                setter: parsed.setter.map(Selector::new),
                ivar: parsed.ivar,
                unknown: parsed.unknown_flags,
            },
            evidence: evidence(evidence_id),
        },
    );
    ObjCProperty {
        id,
        name: ObjCValue::Known {
            value: value.name.clone(),
            evidence: evidence(evidence_id),
        },
        raw_attributes: HexBytes::from_bytes(value.attributes.as_bytes()),
        parsed_attributes,
        origin: origin.clone(),
    }
}

pub(super) fn ivar(
    value: &crate::metadata::objc::ObjCIvar,
    ordinal: usize,
    origin: &ObjCEntityId,
    evidence_id: &ObjCEvidenceId,
) -> ObjCIvar {
    let id = member_id(&format!(
        "ivar|{origin}|{}|{:?}|{ordinal}",
        value.name, value.offset
    ));
    let known = || evidence(evidence_id);
    ObjCIvar {
        id,
        name: ObjCValue::Known {
            value: value.name.clone(),
            evidence: known(),
        },
        raw_encoding: HexBytes::from_bytes(
            value
                .type_encoding
                .as_deref()
                .unwrap_or_default()
                .as_bytes(),
        ),
        // Only an encoding that exists and fails to parse is malformed. An
        // absent one was never written, and an unreadable pointer is an
        // unresolved reference; reporting either as malformed would blame the
        // metadata for a fact it never claimed.
        parsed_type: match value.type_encoding.as_deref() {
            None => ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::UnresolvedReference,
            },
            Some("") => ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::NotEncoded,
            },
            Some(_) => value.parsed_type().map_or(
                ObjCValue::Unavailable {
                    reason: ObjCUnavailableReason::MalformedEncoding,
                },
                |ty| ObjCValue::Known {
                    value: qualified_type(&ty),
                    evidence: known(),
                },
            ),
        },
        offset: value.offset.map_or(
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::UnresolvedReference,
            },
            |offset| ObjCValue::Known {
                value: offset as u64,
                evidence: known(),
            },
        ),
        size: ObjCValue::Known {
            value: value.size as u64,
            evidence: known(),
        },
        alignment: ObjCValue::Known {
            value: value.alignment as u64,
            evidence: known(),
        },
    }
}

fn method_signature(
    value: &crate::metadata::objc::encoding::ObjCMethodSignature,
) -> ObjCMethodSignature {
    ObjCMethodSignature {
        return_type: qualified_type(&value.return_type),
        parameters: value
            .arguments
            .iter()
            .map(|argument| qualified_type(&argument.ty))
            .collect(),
        frame_size: value.return_offset.map(|value| value as u64),
        argument_offsets: value
            .arguments
            .iter()
            .filter_map(|argument| argument.stack_offset.map(|value| value as i64))
            .collect(),
    }
}

fn qualified_type(value: &ObjCQualifiedType) -> ObjCEncodedType {
    let qualifiers = value.qualifiers.iter().copied().map(qualifier).collect();
    match &value.ty {
        ObjCType::Void => primitive(ObjCPrimitive::Void, qualifiers),
        ObjCType::Bool => primitive(ObjCPrimitive::Bool, qualifiers),
        ObjCType::Char => primitive(ObjCPrimitive::Char, qualifiers),
        ObjCType::UnsignedChar => primitive(ObjCPrimitive::UnsignedChar, qualifiers),
        ObjCType::Short => primitive(ObjCPrimitive::Short, qualifiers),
        ObjCType::UnsignedShort => primitive(ObjCPrimitive::UnsignedShort, qualifiers),
        ObjCType::Int => primitive(ObjCPrimitive::Int, qualifiers),
        ObjCType::UnsignedInt => primitive(ObjCPrimitive::UnsignedInt, qualifiers),
        ObjCType::Long => primitive(ObjCPrimitive::Long, qualifiers),
        ObjCType::UnsignedLong => primitive(ObjCPrimitive::UnsignedLong, qualifiers),
        ObjCType::LongLong => primitive(ObjCPrimitive::LongLong, qualifiers),
        ObjCType::UnsignedLongLong => primitive(ObjCPrimitive::UnsignedLongLong, qualifiers),
        ObjCType::Float => primitive(ObjCPrimitive::Float, qualifiers),
        ObjCType::Double => primitive(ObjCPrimitive::Double, qualifiers),
        ObjCType::CharPtr | ObjCType::CString => primitive(ObjCPrimitive::Cstring, qualifiers),
        ObjCType::Selector => ObjCEncodedType::Selector,
        ObjCType::Class => ObjCEncodedType::Class,
        ObjCType::Object { is_block: true, .. } => ObjCEncodedType::Block { signature: None },
        ObjCType::Object {
            class_name,
            protocols,
            is_block: false,
        } => ObjCEncodedType::Object {
            name: class_name.clone(),
            protocols: protocols.clone(),
            qualifiers,
        },
        ObjCType::Pointer(pointee) => ObjCEncodedType::Pointer {
            pointee: Box::new(qualified_type(pointee)),
        },
        ObjCType::Array { len, element } => ObjCEncodedType::Array {
            count: *len as u64,
            element: Box::new(qualified_type(element)),
        },
        ObjCType::Struct { name, fields } => ObjCEncodedType::Record {
            record_kind: RecordKind::Struct,
            name: named_record(name),
            fields: fields.iter().map(qualified_type).collect(),
        },
        ObjCType::Union { name, fields } => ObjCEncodedType::Record {
            record_kind: RecordKind::Union,
            name: named_record(name),
            fields: fields.iter().map(qualified_type).collect(),
        },
        ObjCType::BitField(width) => ObjCEncodedType::Bitfield {
            width: *width as u32,
        },
        ObjCType::Unknown(code) => ObjCEncodedType::Unknown {
            raw: HexBytes::from_bytes(code.to_string().as_bytes()),
        },
        _ => ObjCEncodedType::Unknown {
            raw: HexBytes::from_bytes(b"?"),
        },
    }
}

fn primitive(value: ObjCPrimitive, qualifiers: Vec<ObjCQualifier>) -> ObjCEncodedType {
    ObjCEncodedType::Primitive { value, qualifiers }
}

fn qualifier(value: TypeQualifier) -> ObjCQualifier {
    match value {
        TypeQualifier::Const => ObjCQualifier::Const,
        TypeQualifier::In => ObjCQualifier::In,
        TypeQualifier::InOut => ObjCQualifier::Inout,
        TypeQualifier::Out => ObjCQualifier::Out,
        TypeQualifier::ByCopy => ObjCQualifier::Bycopy,
        TypeQualifier::ByRef => ObjCQualifier::Byref,
        TypeQualifier::OneWay => ObjCQualifier::Oneway,
        TypeQualifier::Atomic => ObjCQualifier::Atomic,
        _ => ObjCQualifier::Atomic,
    }
}

fn named_record(value: &str) -> Option<String> {
    (!value.is_empty() && value != "?").then(|| value.to_owned())
}

fn member_id(seed: &str) -> ObjCMemberId {
    ObjCMemberId::new(sha256_hex(seed.as_bytes())).expect("SHA-256 member ID")
}

fn evidence(value: &ObjCEvidenceId) -> NonEmpty<ObjCEvidenceId> {
    NonEmpty::new(vec![value.clone()]).unwrap()
}

fn diagnostic(
    entity_id: &ObjCEntityId,
    evidence_id: &ObjCEvidenceId,
    code: ObjCDiagnosticCode,
    message: String,
) -> ObjCDiagnostic {
    ObjCDiagnostic {
        id: ObjCDiagnosticId::new(sha256_hex(
            format!("objc-diagnostic|{entity_id}|{code:?}|{message}").as_bytes(),
        ))
        .expect("SHA-256 diagnostic ID"),
        code,
        severity: Severity::Warning,
        message,
        observation_id: None,
        entity_id: Some(entity_id.clone()),
        evidence_ids: vec![evidence_id.clone()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unresolved_ivar_offsets_are_not_reported_as_zero() {
        let origin = ObjCEntityId::new("0".repeat(64)).expect("valid entity ID");
        let evidence_id = ObjCEvidenceId::new("1".repeat(64)).expect("valid evidence ID");
        let value = crate::metadata::objc::ObjCIvar {
            name: "_value".to_owned(),
            type_encoding: Some("i".to_owned()),
            offset: None,
            size: 4,
            alignment: 4,
        };

        let recovered = ivar(&value, 0, &origin, &evidence_id);

        assert_eq!(
            recovered.offset,
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::UnresolvedReference,
            }
        );
    }

    fn ivar_with_encoding(type_encoding: Option<&str>) -> ObjCIvar {
        let origin = ObjCEntityId::new("0".repeat(64)).expect("valid entity ID");
        let evidence_id = ObjCEvidenceId::new("1".repeat(64)).expect("valid evidence ID");
        let value = crate::metadata::objc::ObjCIvar {
            name: "_value".to_owned(),
            type_encoding: type_encoding.map(str::to_owned),
            offset: Some(8),
            size: 8,
            alignment: 8,
        };
        ivar(&value, 0, &origin, &evidence_id)
    }

    #[test]
    fn an_absent_type_encoding_is_not_reported_as_malformed() {
        // Swift stored properties surface as Objective-C ivars carrying no type
        // encoding at all. Calling that malformed blames the metadata for a
        // claim it never made.
        assert_eq!(
            ivar_with_encoding(Some("")).parsed_type,
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::NotEncoded,
            }
        );
    }

    #[test]
    fn an_unreadable_type_pointer_is_an_unresolved_reference() {
        assert_eq!(
            ivar_with_encoding(None).parsed_type,
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::UnresolvedReference,
            }
        );
    }

    #[test]
    fn an_encoding_that_exists_but_does_not_parse_is_malformed() {
        assert_eq!(
            ivar_with_encoding(Some("\u{7f}not-an-encoding")).parsed_type,
            ObjCValue::Unavailable {
                reason: ObjCUnavailableReason::MalformedEncoding,
            }
        );
    }

    #[test]
    fn a_well_formed_encoding_still_decodes() {
        assert!(matches!(
            ivar_with_encoding(Some("i")).parsed_type,
            ObjCValue::Known { .. }
        ));
    }
}
