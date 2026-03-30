use crate::addr::Va;
use crate::error::Result;
use crate::io::pod::{self, RawClassRoT64};
use crate::objc::ivar::parse_ivar_list;
use crate::objc::method::parse_method_list;
use crate::objc::property::parse_property_list;
use crate::objc::protocol::parse_protocol_name_list;
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::{ObjCClass, RO_META};

pub fn parse_class(resolver: &ObjCResolver<'_>, class_va: Va) -> Result<ObjCClass> {
    let class_offset = resolver.va_to_offset(class_va)?;
    let data = resolver.mach().bytes();
    let endian = resolver.endian();

    // Read the data pointer (class_ro_t). Low bit is the Swift class flag.
    let data_ptr_offset = class_offset.as_usize() as u64 + 32; // offset of 'data' field
    let raw_data_ptr = match resolver.read_pointer_at_offset(data_ptr_offset)? {
        Some(va) => va,
        None => {
            return Err(crate::error::Error::Format(
                "null class_ro_t pointer".into(),
            ));
        }
    };
    let is_swift = raw_data_ptr.0 & 1 != 0;
    let data_va = Va(raw_data_ptr.0 & !1); // clear low bit

    // Parse class_ro_t
    let ro_offset = resolver.va_to_offset(data_va)?;
    let ro: RawClassRoT64 = pod::read_pod(data, ro_offset.as_usize())?;
    let flags = endian.interpret_u32(ro.flags);
    let instance_size = endian.interpret_u32(ro.instance_size);
    let is_meta = flags & RO_META != 0;

    // Read class name
    let name_ptr_offset = ro_offset.as_usize() as u64 + 24; // offset of 'name' field in class_ro_t
    let name = match resolver.read_pointer_at_offset(name_ptr_offset)? {
        Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>").to_string(),
        None => "<null>".to_string(),
    };

    // Read superclass name from bind (if available)
    let superclass_offset = class_offset.as_usize() as u64 + 8;
    let superclass_name = resolver.bind_name_at_offset(superclass_offset).map(|s| {
        // Strip _OBJC_CLASS_$_ prefix if present
        s.strip_prefix("_OBJC_CLASS_$_").unwrap_or(s).to_string()
    });

    // Parse methods
    let methods_ptr_offset = ro_offset.as_usize() as u64 + 32;
    let instance_methods = match resolver.read_pointer_at_offset(methods_ptr_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    // Parse protocols
    let protos_ptr_offset = ro_offset.as_usize() as u64 + 40;
    let protocols = match resolver.read_pointer_at_offset(protos_ptr_offset)? {
        Some(va) if va.0 != 0 => parse_protocol_name_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    // Parse ivars
    let ivars_ptr_offset = ro_offset.as_usize() as u64 + 48;
    let ivars = match resolver.read_pointer_at_offset(ivars_ptr_offset)? {
        Some(va) if va.0 != 0 => parse_ivar_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    // Parse properties
    let props_ptr_offset = ro_offset.as_usize() as u64 + 64;
    let properties = match resolver.read_pointer_at_offset(props_ptr_offset)? {
        Some(va) if va.0 != 0 => parse_property_list(resolver, va).unwrap_or_default(),
        _ => Vec::new(),
    };

    // Parse metaclass for class methods
    let meta_offset = class_offset.as_usize() as u64; // isa field
    let class_methods = match resolver.read_pointer_at_offset(meta_offset)? {
        Some(meta_va) => parse_metaclass_methods(resolver, meta_va).unwrap_or_default(),
        None => Vec::new(),
    };

    Ok(ObjCClass {
        name,
        superclass_name,
        instance_methods,
        class_methods,
        ivars,
        properties,
        protocols,
        instance_size,
        is_meta,
        is_swift,
    })
}

fn parse_metaclass_methods(
    resolver: &ObjCResolver<'_>,
    meta_va: Va,
) -> Result<Vec<crate::objc::types::ObjCMethod>> {
    let meta_offset = resolver.va_to_offset(meta_va)?;

    let data_ptr_offset = meta_offset.as_usize() as u64 + 32;
    let data_va = match resolver.read_pointer_at_offset(data_ptr_offset)? {
        Some(va) => Va(va.0 & !1),
        None => return Ok(Vec::new()),
    };

    let ro_offset = resolver.va_to_offset(data_va)?;

    let methods_ptr_offset = ro_offset.as_usize() as u64 + 32;
    match resolver.read_pointer_at_offset(methods_ptr_offset)? {
        Some(va) if va.0 != 0 => parse_method_list(resolver, va),
        _ => Ok(Vec::new()),
    }
}
