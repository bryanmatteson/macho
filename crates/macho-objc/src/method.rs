use crate::error::Result;
use crate::format::io::pod::{self, RawMethodListHeader, RawMethodT, RawRelativeMethodT};
use crate::model::addr::{ThinFileOffset, Va};
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::{
    METHOD_LIST_ENTSIZE_MASK, METHOD_LIST_USES_DIRECT_SELECTOR_OFFSETS,
    METHOD_LIST_USES_RELATIVE_OFFSETS, ObjCMethod,
};

/// Performs parse_method_list.
pub fn parse_method_list(resolver: &ObjCResolver<'_>, va: Va) -> Result<Vec<ObjCMethod>> {
    let offset = resolver.va_to_offset(va)?;
    let data = resolver.macho().bytes();
    let endian = resolver.endian();

    let header: RawMethodListHeader = pod::read_pod(data, offset.as_usize())?;
    let entsize_and_flags = endian.interpret_u32(header.entsize_and_flags);
    let count = endian.interpret_u32(header.count) as usize;
    let uses_relative = entsize_and_flags & METHOD_LIST_USES_RELATIVE_OFFSETS != 0;
    let uses_direct_selectors = entsize_and_flags & METHOD_LIST_USES_DIRECT_SELECTOR_OFFSETS != 0;

    let header_size = size_of::<RawMethodListHeader>();
    let mut methods = Vec::with_capacity(count.min(10_000));

    if uses_relative {
        let entsize = (entsize_and_flags & METHOD_LIST_ENTSIZE_MASK) as usize;
        if entsize < size_of::<RawRelativeMethodT>() {
            return Err(crate::error::Error::format(format!(
                "relative method entry size {entsize} is smaller than {}",
                size_of::<RawRelativeMethodT>()
            )));
        }
        let entry_size = entsize;

        for i in 0..count {
            let entry_offset = offset
                .as_usize()
                .checked_add(header_size)
                .and_then(|v| v.checked_add(i.checked_mul(entry_size)?))
                .ok_or_else(|| {
                    crate::error::Error::format(format!("relative method[{i}] offset overflows"))
                })?;
            let raw: RawRelativeMethodT = pod::read_pod(data, entry_offset)?;
            let name_rel = endian.interpret_i32(raw.name_offset) as isize;
            let types_rel = endian.interpret_i32(raw.types_offset) as isize;
            let imp_rel = endian.interpret_i32(raw.imp_offset) as i64;

            // Each offset is relative to its own field address.
            let name_field_addr = entry_offset; // field 0
            let types_field_addr = entry_offset
                .checked_add(4)
                .ok_or_else(|| crate::error::Error::address("method type field overflows"))?;
            let imp_field_addr = entry_offset
                .checked_add(8)
                .ok_or_else(|| crate::error::Error::address("method IMP field overflows"))?;

            // The name offset points to a selector reference (a pointer in
            // __objc_selrefs), not directly to the string. Follow the
            // indirection: read the pointer at the sel ref, then read the
            // string at that address.
            let selector_offset = name_field_addr
                .checked_add_signed(name_rel)
                .ok_or_else(|| crate::error::Error::address("method selector offset overflows"))?;
            let name = if uses_direct_selectors {
                read_cstring_at_file_offset(data, selector_offset)?
            } else {
                let string_va = resolver
                    .read_pointer_at_offset(selector_offset as u64)?
                    .ok_or_else(|| {
                        crate::error::Error::address(
                            "relative method selector reference is unresolved",
                        )
                    })?;
                resolver.read_cstring(string_va)?
            };

            let types_file_offset =
                types_field_addr
                    .checked_add_signed(types_rel)
                    .ok_or_else(|| {
                        crate::error::Error::address("method type-encoding offset overflows")
                    })?;
            let type_encoding = read_cstring_at_file_offset(data, types_file_offset)?;

            // Relative IMP offsets use the runtime address of their own field
            // as the basis, not the field's file offset.
            let imp_field_va = resolver
                .macho()
                .address_map()
                .thin_offset_to_va(ThinFileOffset(imp_field_addr as u64))?;
            let imp_addr = imp_field_va
                .0
                .checked_add_signed(imp_rel)
                .filter(|address| *address != 0)
                .ok_or_else(|| {
                    crate::error::Error::address("relative method IMP address is invalid")
                })?;

            methods.push(ObjCMethod {
                name: name.to_string(),
                type_encoding: type_encoding.to_string(),
                imp: Va(imp_addr),
            });
        }
    } else {
        // Absolute method list
        let entsize = (entsize_and_flags & METHOD_LIST_ENTSIZE_MASK) as usize;
        if entsize < size_of::<RawMethodT>() {
            return Err(crate::error::Error::format(format!(
                "absolute method entry size {entsize} is smaller than {}",
                size_of::<RawMethodT>()
            )));
        }
        let entry_size = entsize;

        for i in 0..count {
            let entry_offset = offset
                .as_usize()
                .checked_add(header_size)
                .and_then(|v| v.checked_add(i.checked_mul(entry_size)?))
                .ok_or_else(|| {
                    crate::error::Error::format(format!("absolute method[{i}] offset overflows"))
                })?;

            // All fields are pointers that may be chained fixups
            let name_ptr = resolver
                .read_pointer_at_offset(entry_offset as u64)?
                .ok_or_else(|| crate::error::Error::address("method name pointer is unresolved"))?;
            let types_ptr = resolver
                .read_pointer_at_offset(entry_offset as u64 + 8)?
                .ok_or_else(|| {
                    crate::error::Error::address("method type-encoding pointer is unresolved")
                })?;
            let imp = resolver
                .read_pointer_at_offset(entry_offset as u64 + 16)?
                .filter(|value| value.0 != 0)
                .ok_or_else(|| crate::error::Error::address("method IMP pointer is unresolved"))?;
            let name = resolver.read_cstring(name_ptr)?;
            let type_encoding = resolver.read_cstring(types_ptr)?;

            methods.push(ObjCMethod {
                name: name.to_string(),
                type_encoding: type_encoding.to_string(),
                imp,
            });
        }
    }

    Ok(methods)
}

fn read_cstring_at_file_offset(data: &[u8], offset: usize) -> Result<&str> {
    let slice = data
        .get(offset..)
        .ok_or_else(|| crate::error::Error::bounds(offset as u64, 1, data.len() as u64))?;
    let end = slice.iter().position(|&b| b == 0).ok_or_else(|| {
        crate::error::Error::format(format!("unterminated string at file offset {offset:#x}"))
    })?;
    std::str::from_utf8(&slice[..end])
        .map_err(|e| crate::error::Error::format(format!("invalid UTF-8 at offset {offset}: {e}")))
}
