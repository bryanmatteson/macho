use crate::addr::Va;
use crate::error::Result;
use crate::io::pod::{self, RawIvarT64, RawMethodListHeader};
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::{METHOD_LIST_ENTSIZE_MASK, ObjCIvar};

pub fn parse_ivar_list(resolver: &ObjCResolver<'_>, va: Va) -> Result<Vec<ObjCIvar>> {
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
        size_of::<RawIvarT64>()
    };

    let mut ivars = Vec::with_capacity(count.min(1000));

    for i in 0..count {
        let entry_offset = offset.as_usize() + header_size + i * entry_size;

        let name_ptr = resolver.read_pointer_at_offset(entry_offset as u64 + 8)?;
        let type_ptr = resolver.read_pointer_at_offset(entry_offset as u64 + 16)?;

        // Read alignment and size from the raw struct
        let raw: RawIvarT64 = pod::read_pod(data, entry_offset)?;
        let alignment = endian.interpret_u32(raw.alignment);
        let size = endian.interpret_u32(raw.size);

        // Read the ivar offset value (offset_ptr points to a u32)
        let ivar_offset = match resolver.read_pointer_at_offset(entry_offset as u64) {
            Ok(Some(va)) => match resolver.va_to_offset(va) {
                Ok(off) => pod::read_pod::<u32>(data, off.as_usize())
                    .map(|v| endian.interpret_u32(v))
                    .unwrap_or(0),
                Err(_) => 0,
            },
            _ => 0,
        };

        let name = match name_ptr {
            Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>"),
            None => "<null>",
        };
        let type_encoding = match type_ptr {
            Some(va) => resolver.read_cstring(va).unwrap_or(""),
            None => "",
        };

        ivars.push(ObjCIvar {
            name: name.to_string(),
            type_encoding: type_encoding.to_string(),
            offset: ivar_offset,
            size,
            alignment: 1u32.wrapping_shl(alignment),
        });
    }

    Ok(ivars)
}
