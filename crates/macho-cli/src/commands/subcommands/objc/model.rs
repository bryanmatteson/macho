use macho::analysis::report::{
    ObjCEntity, ObjCEntityId, ObjCMemberId, ObjCMethod, ObjCMethodKind, ObjCPresence,
    ObjCSliceReport, ObjCValue,
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

pub(super) fn architecture_name(slice: &ObjCSliceReport) -> String {
    let cpu = macho::core::model::header::CpuType(slice.architecture.cpu_type);
    let subtype = macho::core::model::header::CpuSubtype(slice.architecture.cpu_subtype);
    format!("{} ({})", cpu.name(), subtype.name(cpu))
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
