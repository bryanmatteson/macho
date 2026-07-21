use crate::error::Result;
use crate::format::io::pod::{self, RawMethodListHeader, RawMethodT, RawRelativeMethodT};
use crate::model::addr::Va;
use crate::objc::resolve::ObjCResolver;
use crate::objc::types::{METHOD_LIST_ENTSIZE_MASK, METHOD_LIST_USES_RELATIVE_OFFSETS, ObjCMethod};

/// Performs parse_method_list.
pub fn parse_method_list(resolver: &ObjCResolver<'_>, va: Va) -> Result<Vec<ObjCMethod>> {
    let offset = resolver.va_to_offset(va)?;
    let data = resolver.macho().bytes();
    let endian = resolver.endian();

    let header: RawMethodListHeader = pod::read_pod(data, offset.as_usize())?;
    let entsize_and_flags = endian.interpret_u32(header.entsize_and_flags);
    let count = endian.interpret_u32(header.count) as usize;
    let uses_relative = entsize_and_flags & METHOD_LIST_USES_RELATIVE_OFFSETS != 0;

    let header_size = size_of::<RawMethodListHeader>();
    let mut methods = Vec::with_capacity(count.min(10_000));

    if uses_relative {
        // Use entsize from header, or fall back to struct size
        let entsize = (entsize_and_flags & METHOD_LIST_ENTSIZE_MASK) as usize;
        let entry_size = if entsize > 0 {
            entsize
        } else {
            size_of::<RawRelativeMethodT>()
        };

        for i in 0..count {
            let entry_offset = offset
                .as_usize()
                .checked_add(header_size)
                .and_then(|v| v.checked_add(i.checked_mul(entry_size)?))
                .ok_or_else(|| {
                    crate::error::Error::format(format!("relative method[{i}] offset overflows"))
                })?;
            let raw: RawRelativeMethodT = pod::read_pod(data, entry_offset)?;
            let name_rel = endian.interpret_i32(raw.name_offset) as i64;
            let types_rel = endian.interpret_i32(raw.types_offset) as i64;
            let imp_rel = endian.interpret_i32(raw.imp_offset) as i64;

            // Each offset is relative to its own field address.
            let name_field_addr = entry_offset; // field 0
            let types_field_addr = entry_offset + 4; // field 1
            let imp_field_addr = entry_offset + 8; // field 2

            // The name offset points to a selector reference (a pointer in
            // __objc_selrefs), not directly to the string. Follow the
            // indirection: read the pointer at the sel ref, then read the
            // string at that address.
            let sel_ref_file_offset = (name_field_addr as i64 + name_rel) as u64;
            let name = match resolver.read_pointer_at_offset(sel_ref_file_offset) {
                Ok(Some(string_va)) => resolver.read_cstring(string_va).unwrap_or("<invalid>"),
                _ => {
                    // Fallback: try reading as direct string
                    read_cstring_at_file_offset(data, sel_ref_file_offset as usize)
                        .unwrap_or("<invalid>")
                }
            };

            let types_file_offset = (types_field_addr as i64 + types_rel) as usize;
            let type_encoding = read_cstring_at_file_offset(data, types_file_offset).unwrap_or("");

            // Relative IMP offsets use the runtime address of their own field
            // as the basis, not the field's file offset.
            let imp_field_va = resolver
                .macho()
                .address_map()
                .thin_offset_to_va(crate::model::addr::ThinFileOffset(
                    imp_field_addr as u64,
                ))?;
            let imp_addr = imp_field_va
                .0
                .checked_add_signed(imp_rel)
                .ok_or_else(|| crate::error::Error::address("relative method IMP overflows"))?;

            methods.push(ObjCMethod {
                name: name.to_string(),
                type_encoding: type_encoding.to_string(),
                imp: Va(imp_addr),
            });
        }
    } else {
        // Absolute method list
        let entsize = (entsize_and_flags & METHOD_LIST_ENTSIZE_MASK) as usize;
        let entry_size = if entsize > 0 {
            entsize
        } else {
            size_of::<RawMethodT>()
        };

        for i in 0..count {
            let entry_offset = offset
                .as_usize()
                .checked_add(header_size)
                .and_then(|v| v.checked_add(i.checked_mul(entry_size)?))
                .ok_or_else(|| {
                    crate::error::Error::format(format!("absolute method[{i}] offset overflows"))
                })?;

            // All fields are pointers that may be chained fixups
            let name_ptr = resolver.read_pointer_at_offset(entry_offset as u64)?;
            let types_ptr = resolver.read_pointer_at_offset(entry_offset as u64 + 8)?;
            let imp_ptr = resolver.read_pointer_at_offset(entry_offset as u64 + 16)?;

            let name = match name_ptr {
                Some(va) => resolver.read_cstring(va).unwrap_or("<invalid>"),
                None => "<null>",
            };
            let type_encoding = match types_ptr {
                Some(va) => resolver.read_cstring(va).unwrap_or(""),
                None => "",
            };
            let imp = match imp_ptr {
                Some(va) => va,
                None => Va(0),
            };

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
    if offset >= data.len() {
        return Ok("<out of bounds>");
    }
    let slice = &data[offset..];
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end])
        .map_err(|e| crate::error::Error::format(format!("invalid UTF-8 at offset {offset}: {e}")))
}
