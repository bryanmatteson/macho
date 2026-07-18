use std::collections::BTreeSet;

use macho_header_syntax as syntax;
use syntax::HeaderParser;

use super::super::*;
use super::types::*;
use super::validate::validate_objc_slice;

/// Adds a validated, process-free header projection to every report slice.
pub fn project_objc_headers(report: &mut ObjCReport) -> crate::Result<()> {
    for slice in report.slices.as_mut_slice() {
        project_slice(slice)?;
        validate_objc_slice(slice)?;
    }
    Ok(())
}

fn project_slice(slice: &mut ObjCSliceReport) -> crate::Result<()> {
    let selected = slice
        .selection
        .selected_entity_ids
        .iter()
        .map(|id| id.as_str())
        .collect::<BTreeSet<_>>();
    let mut context = ProjectionContext::default();

    for entity in &slice.entities {
        if selected.contains(entity.common().id.as_str())
            && entity.common().presence != ObjCPresence::Referenced
        {
            context.project_entity(entity);
        }
    }
    context.prepend_forwards();

    let unit = syntax::TranslationUnit {
        language: syntax::Language::ObjectiveC,
        declarations: context.syntax_declarations,
        declaration_spans: Vec::new(),
    };
    let source = syntax::render(&unit).map_err(|error| {
        crate::AnalysisError::validation(format!("render ObjC header: {error}"))
    })?;
    let reparsed = syntax::TreeSitterHeaderParser
        .parse(syntax::Language::ObjectiveC, &source)
        .map_err(|error| {
            crate::AnalysisError::validation(format!(
                "reparse rendered ObjC header: {error}\n{source}"
            ))
        })?;
    let validation =
        syntax::validate(&reparsed, syntax::ValidationLimits::default()).map_err(|error| {
            crate::AnalysisError::validation(format!("validate ObjC header: {error}"))
        })?;
    if !validation.syntax_valid || !validation.semantic_valid {
        return Err(crate::AnalysisError::validation(format!(
            "rendered ObjC header failed semantic validation: {:?}",
            validation.diagnostics
        )));
    }

    let output_records = context.wire_declarations.len() as u64;
    slice.header = Some(ObjCHeaderProjection {
        declarations: context.wire_declarations,
        unresolved: context.unresolved,
        source,
        validation: HeaderValidationReport::from(&validation),
    });
    slice.executions.push(ObjCCollectorExecution {
        collector: ObjCCollectorId::HeaderProjection,
        outcome: ObjCCollectorOutcome::Complete,
        input_records: selected.len() as u64,
        output_records,
    });
    Ok(())
}

#[derive(Default)]
struct ProjectionContext {
    wire_declarations: Vec<HeaderDecl>,
    syntax_declarations: Vec<syntax::Decl>,
    unresolved: Vec<ObjCHeaderGap>,
    class_forwards: BTreeSet<String>,
    protocol_forwards: BTreeSet<String>,
    record_forwards: BTreeSet<(RecordKind, String)>,
}

impl ProjectionContext {
    fn project_entity(&mut self, entity: &ObjCEntity) {
        match entity {
            ObjCEntity::Class(value) => self.project_class(value),
            ObjCEntity::Category(value) => self.project_category(value),
            ObjCEntity::Protocol(value) => self.project_protocol(value),
        }
    }

    fn project_class(&mut self, value: &ObjCClassEntity) {
        let entity_id = &value.common.id;
        let Some((name, syntax_name)) = identifier(known(&value.common.name)) else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnsupportedEncoding);
            self.gap_all_class_members(value, ObjCUnavailableReason::UnresolvedReference);
            return;
        };
        let superclass = match known(&value.superclass) {
            Some(Some(reference)) => match self.reference_identifier(reference, false) {
                Some((wire, syntax)) => Some((wire, syntax)),
                None => {
                    self.entity_gap(entity_id, ObjCUnavailableReason::UnresolvedReference);
                    return;
                }
            },
            Some(None) => None,
            None => {
                self.entity_gap(entity_id, value_reason(&value.superclass));
                return;
            }
        };
        let Some((protocols, syntax_protocols)) = self.protocols(&value.adopted_protocols) else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnresolvedReference);
            return;
        };
        let mut wire_ivars = Vec::new();
        let mut syntax_ivars = Vec::new();
        for ivar in &value.ivars {
            match self.project_ivar(ivar) {
                Ok((wire, syntax)) => {
                    wire_ivars.push(wire);
                    syntax_ivars.push(syntax);
                }
                Err(reason) => self.member_gap(entity_id, &ivar.id, reason),
            }
        }
        let (wire_members, syntax_methods, syntax_properties) = self.project_members(
            entity_id,
            value
                .instance_methods
                .iter()
                .map(|method| (method, None))
                .chain(value.class_methods.iter().map(|method| (method, None))),
            &value.properties,
        );
        self.wire_declarations.push(HeaderDecl::ObjcInterface {
            id: entity_id.clone(),
            name,
            superclass: superclass.as_ref().map(|(wire, _)| wire.clone()),
            protocols,
            ivars: wire_ivars,
            members: wire_members,
        });
        self.syntax_declarations
            .push(syntax::Decl::ObjectiveCInterface {
                name: syntax_name,
                superclass: superclass.map(|(_, syntax)| syntax),
                protocols: syntax_protocols,
                ivars: syntax_ivars,
                methods: syntax_methods,
                properties: syntax_properties,
            });
    }

    fn project_category(&mut self, value: &ObjCCategoryEntity) {
        let entity_id = &value.common.id;
        let Some((name, syntax_name)) = identifier(known(&value.common.name)) else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnsupportedEncoding);
            return;
        };
        let Some(reference) = known(&value.extended_class) else {
            self.entity_gap(entity_id, value_reason(&value.extended_class));
            return;
        };
        let Some((extended_class, syntax_extended_class)) =
            self.reference_identifier(reference, false)
        else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnresolvedReference);
            return;
        };
        let Some((protocols, syntax_protocols)) = self.protocols(&value.adopted_protocols) else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnresolvedReference);
            return;
        };
        let (wire_members, syntax_methods, syntax_properties) = self.project_members(
            entity_id,
            value
                .instance_methods
                .iter()
                .map(|method| (method, None))
                .chain(value.class_methods.iter().map(|method| (method, None))),
            &value.properties,
        );
        self.wire_declarations.push(HeaderDecl::ObjcCategory {
            id: entity_id.clone(),
            name,
            extended_class,
            protocols,
            members: wire_members,
        });
        self.syntax_declarations
            .push(syntax::Decl::ObjectiveCCategory {
                name: syntax_name,
                extended_class: syntax_extended_class,
                protocols: syntax_protocols,
                methods: syntax_methods,
                properties: syntax_properties,
            });
    }

    fn project_protocol(&mut self, value: &ObjCProtocolEntity) {
        let entity_id = &value.common.id;
        let Some((name, syntax_name)) = identifier(known(&value.common.name)) else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnsupportedEncoding);
            return;
        };
        let Some((protocols, syntax_protocols)) = self.protocols(&value.adopted_protocols) else {
            self.entity_gap(entity_id, ObjCUnavailableReason::UnresolvedReference);
            return;
        };
        let methods = value
            .required_instance_methods
            .iter()
            .chain(&value.required_class_methods)
            .map(|method| (method, Some(true)))
            .chain(
                value
                    .optional_instance_methods
                    .iter()
                    .chain(&value.optional_class_methods)
                    .map(|method| (method, Some(false))),
            );
        let (wire_members, syntax_methods, syntax_properties) =
            self.project_members(entity_id, methods, &value.properties);
        self.wire_declarations.push(HeaderDecl::ObjcProtocol {
            id: entity_id.clone(),
            name,
            protocols,
            members: wire_members,
        });
        self.syntax_declarations
            .push(syntax::Decl::ObjectiveCProtocol {
                name: syntax_name,
                protocols: syntax_protocols,
                methods: syntax_methods,
                properties: syntax_properties,
            });
    }

    fn project_members<'a>(
        &mut self,
        entity_id: &ObjCEntityId,
        methods: impl Iterator<Item = (&'a ObjCMethod, Option<bool>)>,
        properties: &[ObjCProperty],
    ) -> (
        Vec<ObjCHeaderMember>,
        Vec<syntax::ObjectiveCMethod>,
        Vec<syntax::ObjectiveCProperty>,
    ) {
        let mut wire = Vec::new();
        let mut syntax_methods = Vec::new();
        let mut syntax_properties = Vec::new();
        let mut identities = BTreeSet::new();
        for (method, required) in methods {
            match self.project_method(method, required) {
                Ok((wire_method, syntax_method, identity))
                    if identities.insert(identity.clone()) =>
                {
                    wire.push(wire_method);
                    syntax_methods.push(syntax_method);
                }
                Ok(_) => self.member_gap(
                    entity_id,
                    &method.id,
                    ObjCUnavailableReason::ConflictingMetadata,
                ),
                Err(reason) => self.member_gap(entity_id, &method.id, reason),
            }
        }
        for property in properties {
            match self.project_property(property) {
                Ok((wire_property, syntax_property, identity))
                    if identities.insert(identity.clone()) =>
                {
                    wire.push(wire_property);
                    syntax_properties.push(syntax_property);
                }
                Ok(_) => self.member_gap(
                    entity_id,
                    &property.id,
                    ObjCUnavailableReason::ConflictingMetadata,
                ),
                Err(reason) => self.member_gap(entity_id, &property.id, reason),
            }
        }
        (wire, syntax_methods, syntax_properties)
    }

    fn project_method(
        &mut self,
        value: &ObjCMethod,
        required: Option<bool>,
    ) -> Result<(ObjCHeaderMember, syntax::ObjectiveCMethod, String), ObjCUnavailableReason> {
        let selector = known(&value.selector).ok_or_else(|| value_reason(&value.selector))?;
        let signature = known(&value.signature).ok_or_else(|| value_reason(&value.signature))?;
        if !selector_is_header_safe(&selector.spelling) {
            return Err(ObjCUnavailableReason::UnsupportedEncoding);
        }
        if selector.colon_count as usize != signature.parameters.len() {
            return Err(ObjCUnavailableReason::ConflictingMetadata);
        }
        let return_type = self.project_type(&signature.return_type)?;
        let mut wire_parameters = Vec::new();
        let mut syntax_parameters = Vec::new();
        for (index, ty) in signature.parameters.iter().enumerate() {
            let ty = self.project_type(ty)?;
            let name = Identifier::new(format!("arg{}", index + 1))
                .expect("generated Objective-C argument name is valid");
            let syntax_name = syntax::Identifier::new(name.as_str())
                .expect("wire identifier is valid syntax identifier");
            wire_parameters.push(HeaderParameter { name, ty: ty.wire });
            syntax_parameters.push(syntax::Parameter {
                name: syntax_name,
                ty: ty.syntax,
            });
        }
        let method_kind = match value.kind {
            ObjCMethodKind::Instance => MethodKind::Instance,
            ObjCMethodKind::Class => MethodKind::Class,
        };
        let syntax_kind = match value.kind {
            ObjCMethodKind::Instance => syntax::MethodKind::Instance,
            ObjCMethodKind::Class => syntax::MethodKind::Class,
        };
        let identity = format!("method:{:?}:{}", value.kind, selector.spelling);
        Ok((
            ObjCHeaderMember::Method {
                id: value.id.clone(),
                method_kind,
                selector: selector.clone(),
                return_type: return_type.wire,
                parameters: wire_parameters,
                required,
            },
            syntax::ObjectiveCMethod {
                kind: syntax_kind,
                selector: selector.spelling.clone(),
                return_type: return_type.syntax,
                parameters: syntax_parameters,
                required,
            },
            identity,
        ))
    }

    fn project_property(
        &mut self,
        value: &ObjCProperty,
    ) -> Result<(ObjCHeaderMember, syntax::ObjectiveCProperty, String), ObjCUnavailableReason> {
        let name = known(&value.name).ok_or_else(|| value_reason(&value.name))?;
        let (wire_name, syntax_name) =
            identifier(Some(name)).ok_or(ObjCUnavailableReason::UnsupportedEncoding)?;
        let attributes = known(&value.parsed_attributes)
            .ok_or_else(|| value_reason(&value.parsed_attributes))?;
        if !attributes.unknown.is_empty()
            || attributes.getter.is_some()
            || attributes.setter.is_some()
        {
            return Err(ObjCUnavailableReason::UnsupportedEncoding);
        }
        let ty = self.project_type(&attributes.r#type)?;
        let mut wire_attributes = vec![if attributes.readonly {
            ObjCPropertyAttribute::Readonly
        } else {
            ObjCPropertyAttribute::Readwrite
        }];
        wire_attributes.push(match attributes.ownership {
            ObjCOwnership::Assign | ObjCOwnership::Unspecified => ObjCPropertyAttribute::Assign,
            ObjCOwnership::Copy => ObjCPropertyAttribute::Copy,
            ObjCOwnership::Retain => ObjCPropertyAttribute::Retain,
            ObjCOwnership::Strong => ObjCPropertyAttribute::Strong,
            ObjCOwnership::Weak => ObjCPropertyAttribute::Weak,
            ObjCOwnership::UnsafeUnretained => ObjCPropertyAttribute::Assign,
        });
        wire_attributes.push(if attributes.nonatomic {
            ObjCPropertyAttribute::Nonatomic
        } else {
            ObjCPropertyAttribute::Atomic
        });
        if attributes.dynamic {
            wire_attributes.push(ObjCPropertyAttribute::Dynamic);
        }
        let syntax_attributes = wire_attributes
            .iter()
            .copied()
            .map(syntax_property_attribute)
            .collect();
        Ok((
            ObjCHeaderMember::Property {
                id: value.id.clone(),
                name: wire_name,
                ty: ty.wire,
                attributes: wire_attributes,
            },
            syntax::ObjectiveCProperty {
                name: syntax_name,
                ty: ty.syntax,
                attributes: syntax_attributes,
            },
            format!("property:{name}"),
        ))
    }

    fn project_ivar(
        &mut self,
        value: &ObjCIvar,
    ) -> Result<(ObjCHeaderIvar, syntax::ObjectiveCIvar), ObjCUnavailableReason> {
        let name = known(&value.name).ok_or_else(|| value_reason(&value.name))?;
        let (wire_name, syntax_name) =
            identifier(Some(name)).ok_or(ObjCUnavailableReason::UnsupportedEncoding)?;
        let encoded = known(&value.parsed_type).ok_or_else(|| value_reason(&value.parsed_type))?;
        let ty = self.project_type(encoded)?;
        Ok((
            ObjCHeaderIvar {
                id: value.id.clone(),
                name: wire_name,
                ty: ty.wire,
                access: ObjCAccess::Protected,
            },
            syntax::ObjectiveCIvar {
                name: syntax_name,
                ty: ty.syntax,
                access: syntax::ObjectiveCAccess::Protected,
            },
        ))
    }

    fn project_type(
        &mut self,
        value: &ObjCEncodedType,
    ) -> Result<ProjectedType, ObjCUnavailableReason> {
        match value {
            ObjCEncodedType::Primitive { value, qualifiers } => {
                if qualifiers
                    .iter()
                    .any(|value| *value != ObjCQualifier::Const)
                {
                    return Err(ObjCUnavailableReason::UnsupportedEncoding);
                }
                let is_const = qualifiers.contains(&ObjCQualifier::Const);
                let builtin = primitive(*value)?;
                if *value == ObjCPrimitive::Cstring {
                    let pointee =
                        ProjectedType::builtin(BuiltinType::Char, syntax::BuiltinType::Char);
                    Ok(ProjectedType::pointer(pointee, is_const))
                } else if *value == ObjCPrimitive::UnknownObject {
                    Ok(ProjectedType::objc_object(None, Vec::new(), is_const))
                } else {
                    Ok(ProjectedType::builtin(builtin.0, builtin.1))
                }
            }
            ObjCEncodedType::Object {
                name,
                protocols,
                qualifiers,
            } => {
                if qualifiers
                    .iter()
                    .any(|value| *value != ObjCQualifier::Const)
                {
                    return Err(ObjCUnavailableReason::UnsupportedEncoding);
                }
                let name = name.as_deref().map(valid_identifiers).transpose()?;
                if let Some((wire, _)) = &name {
                    self.class_forwards.insert(wire.as_str().to_owned());
                }
                let protocols = protocols
                    .iter()
                    .map(|value| {
                        let pair = valid_identifiers(value)?;
                        self.protocol_forwards.insert(pair.0.as_str().to_owned());
                        Ok(pair)
                    })
                    .collect::<Result<Vec<_>, ObjCUnavailableReason>>()?;
                Ok(ProjectedType::objc_object(
                    name,
                    protocols,
                    qualifiers.contains(&ObjCQualifier::Const),
                ))
            }
            ObjCEncodedType::Class => ProjectedType::named_typedef("Class"),
            ObjCEncodedType::Selector => ProjectedType::named_typedef("SEL"),
            ObjCEncodedType::Block { .. } => Err(ObjCUnavailableReason::UnsupportedEncoding),
            ObjCEncodedType::Pointer { pointee } => {
                Ok(ProjectedType::pointer(self.project_type(pointee)?, false))
            }
            ObjCEncodedType::Array { .. } | ObjCEncodedType::Bitfield { .. } => {
                Err(ObjCUnavailableReason::UnsupportedEncoding)
            }
            ObjCEncodedType::Record {
                record_kind,
                name: Some(name),
                ..
            } => {
                let (wire, syntax_name) = valid_identifiers(name)?;
                self.record_forwards
                    .insert((*record_kind, wire.as_str().to_owned()));
                Ok(ProjectedType {
                    wire: HeaderType::Named {
                        tag: match record_kind {
                            RecordKind::Struct => NamedTypeTag::Struct,
                            RecordKind::Union => NamedTypeTag::Union,
                            RecordKind::Class => NamedTypeTag::Class,
                            RecordKind::Enum => NamedTypeTag::Enum,
                        },
                        path: NonEmpty::new(vec![wire]).unwrap(),
                        template_arguments: Vec::new(),
                    },
                    syntax: syntax::Type::Named {
                        tag: match record_kind {
                            RecordKind::Struct => syntax::NamedTypeTag::Struct,
                            RecordKind::Union => syntax::NamedTypeTag::Union,
                            RecordKind::Class => syntax::NamedTypeTag::Class,
                            RecordKind::Enum => syntax::NamedTypeTag::Enum,
                        },
                        path: syntax::IdentifierPath::new(vec![syntax_name]).unwrap(),
                        template_arguments: Vec::new(),
                    },
                })
            }
            ObjCEncodedType::Record { name: None, .. } | ObjCEncodedType::Unknown { .. } => {
                Err(ObjCUnavailableReason::UnsupportedEncoding)
            }
        }
    }

    fn protocols(
        &mut self,
        values: &[ObjCTypeRef],
    ) -> Option<(Vec<Identifier>, Vec<syntax::Identifier>)> {
        let mut wire = Vec::new();
        let mut syntax = Vec::new();
        for value in values {
            let (wire_name, syntax_name) = self.reference_identifier(value, true)?;
            wire.push(wire_name);
            syntax.push(syntax_name);
        }
        Some((wire, syntax))
    }

    fn reference_identifier(
        &mut self,
        value: &ObjCTypeRef,
        protocol: bool,
    ) -> Option<(Identifier, syntax::Identifier)> {
        let pair = valid_identifiers(&value.name).ok()?;
        if protocol {
            self.protocol_forwards.insert(value.name.clone());
        } else {
            self.class_forwards.insert(value.name.clone());
        }
        Some(pair)
    }

    fn prepend_forwards(&mut self) {
        let mut wire = Vec::new();
        let mut syntax_declarations = Vec::new();
        if let Some((wire_names, syntax_names)) = forward_names(&self.class_forwards) {
            wire.push(HeaderDecl::ObjcForward {
                entity_kind: ObjCForwardKind::Class,
                names: NonEmpty::new(wire_names).unwrap(),
            });
            syntax_declarations.push(syntax::Decl::ObjectiveCForward {
                kind: syntax::ObjectiveCForwardKind::Class,
                names: syntax_names,
            });
        }
        if let Some((wire_names, syntax_names)) = forward_names(&self.protocol_forwards) {
            wire.push(HeaderDecl::ObjcForward {
                entity_kind: ObjCForwardKind::Protocol,
                names: NonEmpty::new(wire_names).unwrap(),
            });
            syntax_declarations.push(syntax::Decl::ObjectiveCForward {
                kind: syntax::ObjectiveCForwardKind::Protocol,
                names: syntax_names,
            });
        }
        for (kind, name) in &self.record_forwards {
            let Ok((wire_name, syntax_name)) = valid_identifiers(name) else {
                continue;
            };
            wire.push(HeaderDecl::Forward {
                id: EntityId::new(sha256_hex(
                    format!("objc-record|{kind:?}|{name}").as_bytes(),
                ))
                .expect("SHA-256 entity ID"),
                record_kind: *kind,
                path: NonEmpty::new(vec![wire_name]).unwrap(),
            });
            syntax_declarations.push(syntax::Decl::Forward {
                kind: match kind {
                    RecordKind::Struct => syntax::RecordKind::Struct,
                    RecordKind::Union => syntax::RecordKind::Union,
                    RecordKind::Class => syntax::RecordKind::Class,
                    RecordKind::Enum => syntax::RecordKind::Enum,
                },
                path: syntax::IdentifierPath::new(vec![syntax_name]).unwrap(),
            });
        }
        wire.append(&mut self.wire_declarations);
        syntax_declarations.append(&mut self.syntax_declarations);
        self.wire_declarations = wire;
        self.syntax_declarations = syntax_declarations;
    }

    fn entity_gap(&mut self, entity_id: &ObjCEntityId, reason: ObjCUnavailableReason) {
        self.unresolved.push(ObjCHeaderGap {
            entity_id: entity_id.clone(),
            member_id: None,
            reason,
            diagnostic_ids: Vec::new(),
        });
    }

    fn member_gap(
        &mut self,
        entity_id: &ObjCEntityId,
        member_id: &ObjCMemberId,
        reason: ObjCUnavailableReason,
    ) {
        self.unresolved.push(ObjCHeaderGap {
            entity_id: entity_id.clone(),
            member_id: Some(member_id.clone()),
            reason,
            diagnostic_ids: Vec::new(),
        });
    }

    fn gap_all_class_members(&mut self, value: &ObjCClassEntity, reason: ObjCUnavailableReason) {
        for id in value
            .ivars
            .iter()
            .map(|value| &value.id)
            .chain(value.properties.iter().map(|value| &value.id))
            .chain(value.instance_methods.iter().map(|value| &value.id))
            .chain(value.class_methods.iter().map(|value| &value.id))
        {
            self.member_gap(&value.common.id, id, reason);
        }
    }
}

struct ProjectedType {
    wire: HeaderType,
    syntax: syntax::Type,
}

impl ProjectedType {
    fn builtin(wire: BuiltinType, syntax: syntax::BuiltinType) -> Self {
        Self {
            wire: HeaderType::Builtin { name: wire },
            syntax: syntax::Type::Builtin(syntax),
        }
    }

    fn pointer(pointee: Self, is_const: bool) -> Self {
        Self {
            wire: HeaderType::Pointer {
                pointee: Box::new(pointee.wire),
                qualifiers: TypeQualifiers {
                    is_const,
                    ..TypeQualifiers::default()
                },
            },
            syntax: syntax::Type::Pointer {
                pointee: Box::new(pointee.syntax),
                qualifiers: syntax::TypeQualifiers {
                    is_const,
                    ..syntax::TypeQualifiers::default()
                },
            },
        }
    }

    fn named_typedef(name: &str) -> Result<Self, ObjCUnavailableReason> {
        let (wire, syntax_name) = valid_identifiers(name)?;
        Ok(Self {
            wire: HeaderType::Named {
                tag: NamedTypeTag::Typedef,
                path: NonEmpty::new(vec![wire]).unwrap(),
                template_arguments: Vec::new(),
            },
            syntax: syntax::Type::Named {
                tag: syntax::NamedTypeTag::Typedef,
                path: syntax::IdentifierPath::new(vec![syntax_name]).unwrap(),
                template_arguments: Vec::new(),
            },
        })
    }

    fn objc_object(
        name: Option<(Identifier, syntax::Identifier)>,
        protocols: Vec<(Identifier, syntax::Identifier)>,
        is_const: bool,
    ) -> Self {
        let (wire_name, syntax_name) = name.unzip();
        let (wire_protocols, syntax_protocols) = protocols.into_iter().unzip();
        Self {
            wire: HeaderType::ObjcObject {
                name: wire_name,
                protocols: wire_protocols,
                qualifiers: TypeQualifiers {
                    is_const,
                    ..TypeQualifiers::default()
                },
            },
            syntax: syntax::Type::ObjectiveCObject {
                name: syntax_name,
                protocols: syntax_protocols,
                qualifiers: syntax::TypeQualifiers {
                    is_const,
                    ..syntax::TypeQualifiers::default()
                },
            },
        }
    }
}

fn known<T>(value: &ObjCValue<T>) -> Option<&T> {
    match value {
        ObjCValue::Known { value, .. } => Some(value),
        ObjCValue::Conflicted { .. } | ObjCValue::Unavailable { .. } => None,
    }
}

fn value_reason<T>(value: &ObjCValue<T>) -> ObjCUnavailableReason {
    match value {
        ObjCValue::Conflicted { .. } => ObjCUnavailableReason::ConflictingMetadata,
        ObjCValue::Unavailable { reason } => *reason,
        ObjCValue::Known { .. } => ObjCUnavailableReason::NotEncoded,
    }
}

fn identifier(value: Option<&String>) -> Option<(Identifier, syntax::Identifier)> {
    valid_identifiers(value?).ok()
}

fn valid_identifiers(
    value: &str,
) -> Result<(Identifier, syntax::Identifier), ObjCUnavailableReason> {
    let wire = Identifier::new(value.to_owned())
        .map_err(|_| ObjCUnavailableReason::UnsupportedEncoding)?;
    let syntax =
        syntax::Identifier::new(value).ok_or(ObjCUnavailableReason::UnsupportedEncoding)?;
    Ok((wire, syntax))
}

fn selector_is_header_safe(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if value.contains(':') {
        value
            .split_terminator(':')
            .all(|piece| syntax::Identifier::new(piece).is_some())
            && value.ends_with(':')
    } else {
        syntax::Identifier::new(value).is_some()
    }
}

fn forward_names(values: &BTreeSet<String>) -> Option<(Vec<Identifier>, Vec<syntax::Identifier>)> {
    let values = values
        .iter()
        .filter_map(|value| valid_identifiers(value).ok())
        .collect::<Vec<_>>();
    (!values.is_empty()).then(|| values.into_iter().unzip())
}

fn primitive(
    value: ObjCPrimitive,
) -> Result<(BuiltinType, syntax::BuiltinType), ObjCUnavailableReason> {
    use ObjCPrimitive as Source;
    Ok(match value {
        Source::Void => (BuiltinType::Void, syntax::BuiltinType::Void),
        Source::Char => (BuiltinType::Char, syntax::BuiltinType::Char),
        Source::UnsignedChar => (BuiltinType::UnsignedChar, syntax::BuiltinType::UnsignedChar),
        Source::Short => (BuiltinType::Short, syntax::BuiltinType::Short),
        Source::UnsignedShort => (
            BuiltinType::UnsignedShort,
            syntax::BuiltinType::UnsignedShort,
        ),
        Source::Int => (BuiltinType::Int, syntax::BuiltinType::Int),
        Source::UnsignedInt => (BuiltinType::UnsignedInt, syntax::BuiltinType::UnsignedInt),
        Source::Long => (BuiltinType::Long, syntax::BuiltinType::Long),
        Source::UnsignedLong => (BuiltinType::UnsignedLong, syntax::BuiltinType::UnsignedLong),
        Source::LongLong => (BuiltinType::LongLong, syntax::BuiltinType::LongLong),
        Source::UnsignedLongLong => (
            BuiltinType::UnsignedLongLong,
            syntax::BuiltinType::UnsignedLongLong,
        ),
        Source::Int128 => (BuiltinType::Int128, syntax::BuiltinType::Int128),
        Source::UnsignedInt128 => (
            BuiltinType::UnsignedInt128,
            syntax::BuiltinType::UnsignedInt128,
        ),
        Source::Float => (BuiltinType::Float, syntax::BuiltinType::Float),
        Source::Double => (BuiltinType::Double, syntax::BuiltinType::Double),
        Source::LongDouble => (BuiltinType::LongDouble, syntax::BuiltinType::LongDouble),
        Source::Bool => (BuiltinType::Bool, syntax::BuiltinType::Bool),
        Source::Cstring | Source::UnknownObject => {
            return Err(ObjCUnavailableReason::UnsupportedEncoding);
        }
    })
}

fn syntax_property_attribute(value: ObjCPropertyAttribute) -> syntax::ObjectiveCPropertyAttribute {
    use ObjCPropertyAttribute as Source;
    match value {
        Source::Readonly => syntax::ObjectiveCPropertyAttribute::Readonly,
        Source::Readwrite => syntax::ObjectiveCPropertyAttribute::Readwrite,
        Source::Copy => syntax::ObjectiveCPropertyAttribute::Copy,
        Source::Retain => syntax::ObjectiveCPropertyAttribute::Retain,
        Source::Strong => syntax::ObjectiveCPropertyAttribute::Strong,
        Source::Weak => syntax::ObjectiveCPropertyAttribute::Weak,
        Source::Assign => syntax::ObjectiveCPropertyAttribute::Assign,
        Source::Atomic => syntax::ObjectiveCPropertyAttribute::Atomic,
        Source::Nonatomic => syntax::ObjectiveCPropertyAttribute::Nonatomic,
        Source::Dynamic => syntax::ObjectiveCPropertyAttribute::Dynamic,
        Source::Class => syntax::ObjectiveCPropertyAttribute::Class,
    }
}
