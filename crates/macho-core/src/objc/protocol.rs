use crate::addr::Va;
use crate::error::Result;
use crate::io::pod;
use crate::objc::method::parse_method_list;
use crate::objc::property::parse_property_list;
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::ObjCProtocol;

pub fn parse_protocol(resolver: &ObjCResolver<'_>, proto_va: Va) -> Result<ObjCProtocol> {
    let offset = resolver.va_to_offset(proto_va)?;
    let name_ptr_offset = offset.as_usize() as u64 + 8;
    let name = match resolver.read_pointer_at_offset(name_ptr_offset)? {
        Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>").to_string(),
        None => "<null>".to_string(),
    };

    let inst_methods_offset = offset.as_usize() as u64 + 24;
    let instance_methods = match resolver.read_pointer_at_offset(inst_methods_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let cls_methods_offset = offset.as_usize() as u64 + 32;
    let class_methods = match resolver.read_pointer_at_offset(cls_methods_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let opt_inst_offset = offset.as_usize() as u64 + 40;
    let optional_instance_methods = match resolver.read_pointer_at_offset(opt_inst_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let opt_cls_offset = offset.as_usize() as u64 + 48;
    let optional_class_methods = match resolver.read_pointer_at_offset(opt_cls_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let props_offset = offset.as_usize() as u64 + 56;
    let properties = match resolver.read_pointer_at_offset(props_offset)? {
        Some(va) if va.0 != 0 => parse_property_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    let protos_offset = offset.as_usize() as u64 + 16;
    let adopted_protocols = match resolver.read_pointer_at_offset(protos_offset)? {
        Some(va) if va.0 != 0 => parse_protocol_name_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    Ok(ObjCProtocol {
        name,
        instance_methods,
        class_methods,
        optional_instance_methods,
        optional_class_methods,
        properties,
        adopted_protocols,
    })
}

/// Parse a protocol_list_t and return just the protocol names.
pub fn parse_protocol_name_list(resolver: &ObjCResolver<'_>, va: Va) -> Result<Vec<String>> {
    let offset = resolver.va_to_offset(va)?;
    let data = resolver.mach().bytes();
    let endian = resolver.endian();

    // protocol_list_t: first 8 bytes is count (as u64)
    let count = endian.interpret_u64(pod::read_pod::<u64>(data, offset.as_usize())?) as usize;
    if count > 10_000 {
        return Ok(Vec::new());
    }

    let mut names = Vec::with_capacity(count);
    for i in 0..count {
        let ptr_offset = offset.as_usize() as u64 + 8 + i as u64 * 8;
        if let Ok(Some(proto_va)) = resolver.read_pointer_at_offset(ptr_offset) {
            if proto_va.0 != 0 {
                // Read the protocol's name field (at offset +8 in protocol_t)
                let name_ptr_offset = match resolver.va_to_offset(proto_va) {
                    Ok(off) => off.as_usize() as u64 + 8,
                    Err(_) => continue,
                };
                if let Ok(Some(name_va)) = resolver.read_pointer_at_offset(name_ptr_offset) {
                    if let Ok(name) = resolver.read_cstring(name_va) {
                        names.push(name.to_string());
                    }
                }
            }
        }
    }

    Ok(names)
}
