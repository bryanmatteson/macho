use crate::addr::Va;
use crate::error::Result;
use crate::objc::method::parse_method_list;
use crate::objc::protocol::parse_protocol_name_list;
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::ObjCCategory;

pub fn parse_category(resolver: &ObjCResolver<'_>, cat_va: Va) -> Result<ObjCCategory> {
    let offset = resolver.va_to_offset(cat_va)?;

    let name_ptr_offset = offset.as_usize() as u64;
    let name = match resolver.read_pointer_at_offset(name_ptr_offset)? {
        Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>").to_string(),
        None => "<null>".to_string(),
    };

    // Read class pointer — may be a bind (external) or rebase (internal)
    let cls_offset = offset.as_usize() as u64 + 8;
    let class_name = if let Some(bind_name) = resolver.bind_name_at_offset(cls_offset) {
        bind_name
            .strip_prefix("_OBJC_CLASS_$_")
            .unwrap_or(bind_name)
            .to_string()
    } else if let Ok(Some(cls_va)) = resolver.read_pointer_at_offset(cls_offset) {
        // Internal class — resolve the class name by reading class -> data -> name
        resolve_class_name(resolver, cls_va).unwrap_or_else(|| "<class>".to_string())
    } else {
        "<null>".to_string()
    };

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

    Ok(ObjCCategory {
        name,
        class_name,
        instance_methods,
        class_methods,
        protocols,
    })
}

/// Follow objc_class -> data -> class_ro_t.name to get the class name.
fn resolve_class_name(resolver: &ObjCResolver<'_>, cls_va: Va) -> Option<String> {
    let cls_offset = resolver.va_to_offset(cls_va).ok()?;

    // data field is at +32 in objc_class
    let data_ptr_offset = cls_offset.as_usize() as u64 + 32;
    let data_va = resolver.read_pointer_at_offset(data_ptr_offset).ok()??;
    let data_va = Va(data_va.0 & !1); // clear swift bit

    let ro_offset = resolver.va_to_offset(data_va).ok()?;

    // name field is at +24 in class_ro_t
    let name_ptr_offset = ro_offset.as_usize() as u64 + 24;
    let name_va = resolver.read_pointer_at_offset(name_ptr_offset).ok()??;
    resolver.read_cstring(name_va).ok().map(|s| s.to_string())
}
