use crate::metadata::objc::error::Result;
use crate::metadata::objc::format::io::pod::{self, RawIvarT64, RawMethodListHeader};
use crate::metadata::objc::model::addr::Va;
use crate::metadata::objc::resolve::ObjCResolver;
use crate::metadata::objc::types::{METHOD_LIST_ENTSIZE_MASK, ObjCIvar};

/// Performs parse_ivar_list.
pub fn parse_ivar_list(resolver: &ObjCResolver<'_>, va: Va) -> Result<Vec<ObjCIvar>> {
    let offset = resolver.va_to_offset(va)?;
    let data = resolver.macho().bytes();
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
        let ivar_offset = resolver
            .read_pointer_at_offset(entry_offset as u64)
            .ok()
            .flatten()
            .and_then(|va| resolver.va_to_offset(va).ok())
            .and_then(|offset| pod::read_pod::<u32>(data, offset.as_usize()).ok())
            .map(|value| endian.interpret_u32(value));

        let name = match name_ptr {
            Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>"),
            None => "<null>",
        };
        // `read_pointer_at_offset` reports a null slot and a bind it cannot
        // resolve identically, so the raw slot decides between them: a zero slot
        // means the ivar carries no type encoding, which is how a Swift stored
        // property appears, while a non-zero slot that did not resolve is a
        // reference this image cannot follow. Reporting either as a malformed
        // encoding would blame the metadata for a claim it never made.
        let type_slot = pod::read_pod::<u64>(data, entry_offset + 16)
            .map(|value| endian.interpret_u64(value))
            .unwrap_or(0);
        let type_encoding = match type_ptr {
            Some(va) => resolver.read_cstring(va).ok().map(str::to_owned),
            None if type_slot == 0 => Some(String::new()),
            None => None,
        };

        ivars.push(ObjCIvar {
            name: name.to_string(),
            type_encoding,
            offset: ivar_offset,
            size,
            alignment: 1u32.wrapping_shl(alignment),
        });
    }

    Ok(ivars)
}
