use crate::error::Result;
use crate::objc::class::{resolve_class_name_from_va, resolve_class_ref_name};
use crate::objc::method::parse_method_list;
use crate::objc::property::{parse_property_list, parse_property_list_with_kind};
use crate::objc::protocol::parse_protocol_name_list;
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::ObjCCategory;
use crate::model::addr::Va;

pub fn parse_category(resolver: &ObjCResolver<'_>, cat_va: Va) -> Result<ObjCCategory> {
    let offset = resolver.va_to_offset(cat_va)?;

    let name_ptr_offset = offset.as_usize() as u64;
    let name = match resolver.read_pointer_at_offset(name_ptr_offset)? {
        Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>").to_string(),
        None => "<null>".to_string(),
    };

    // Read class pointer — may be a bind (external) or rebase (internal)
    let cls_offset = offset.as_usize() as u64 + 8;
    let class_name = resolve_class_ref_name(resolver, cls_offset).unwrap_or_else(|| {
        if let Ok(Some(cls_va)) = resolver.read_pointer_at_offset(cls_offset) {
            resolve_class_name_from_va(resolver, cls_va).unwrap_or_else(|| "<class>".to_string())
        } else {
            "<null>".to_string()
        }
    });

    let inst_methods_offset = offset.as_usize() as u64 + 16;
    let instance_methods = match resolver.read_pointer_at_offset(inst_methods_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let cls_methods_offset = offset.as_usize() as u64 + 24;
    let class_methods = match resolver.read_pointer_at_offset(cls_methods_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let protos_offset = offset.as_usize() as u64 + 32;
    let protocols = match resolver.read_pointer_at_offset(protos_offset)? {
        Some(va) if va.0 != 0 => parse_protocol_name_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    // Modern category_t appends instance properties at +40.
    let props_offset = offset.as_usize() as u64 + 40;
    let properties = match resolver.read_pointer_at_offset(props_offset) {
        Ok(Some(va)) if va.0 != 0 => parse_property_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let class_props_offset = offset.as_usize() as u64 + 48;
    let class_properties = match resolver.read_pointer_at_offset(class_props_offset) {
        Ok(Some(va)) if va.0 != 0 => {
            parse_property_list_with_kind(resolver, va, true).unwrap_or_default()
        }
        _ => Vec::new(),
    };

    let mut properties = properties;
    properties.extend(class_properties);

    Ok(ObjCCategory {
        name,
        class_name,
        instance_methods,
        class_methods,
        properties,
        protocols,
    })
}
