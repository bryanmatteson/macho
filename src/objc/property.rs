use crate::addr::Va;
use crate::error::Result;
use crate::io::pod::{self, RawMethodListHeader, RawPropertyT};
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::{METHOD_LIST_ENTSIZE_MASK, ObjCProperty};

pub fn parse_property_list(resolver: &ObjCResolver<'_>, va: Va) -> Result<Vec<ObjCProperty>> {
    parse_property_list_with_kind(resolver, va, false)
}

pub fn parse_property_list_with_kind(
    resolver: &ObjCResolver<'_>,
    va: Va,
    is_class: bool,
) -> Result<Vec<ObjCProperty>> {
    let offset = resolver.va_to_offset(va)?;
    let data = resolver.mach().bytes();
    let endian = resolver.endian();

    let header: RawMethodListHeader = pod::read_pod(data, offset.as_usize())?;
    let entsize_and_flags = endian.interpret_u32(header.entsize_and_flags);
    let count = endian.interpret_u32(header.count) as usize;
    let header_size = size_of::<RawMethodListHeader>();

    let entsize = (entsize_and_flags & METHOD_LIST_ENTSIZE_MASK) as usize;
    let entry_size = if entsize > 0 {
        entsize
    } else {
        size_of::<RawPropertyT>()
    };

    let mut props = Vec::with_capacity(count.min(1000));

    for i in 0..count {
        let entry_offset = offset.as_usize() + header_size + i * entry_size;

        let name_ptr = resolver.read_pointer_at_offset(entry_offset as u64)?;
        let attr_ptr = resolver.read_pointer_at_offset(entry_offset as u64 + 8)?;

        let name = match name_ptr {
            Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>"),
            None => "<null>",
        };
        let attributes = match attr_ptr {
            Some(va) => resolver.read_cstring(va).unwrap_or(""),
            None => "",
        };

        props.push(ObjCProperty {
            name: name.to_string(),
            attributes: attributes.to_string(),
            is_class,
        });
    }

    Ok(props)
}
