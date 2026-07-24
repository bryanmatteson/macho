use crate::SwiftDemangler;
use crate::model::addr::Va;
use crate::model::macho_file::MachoFile;
use crate::types::{
    SwiftAssociatedTypeInfo, SwiftAssociatedTypeRecordInfo, SwiftConformanceInfo, SwiftFieldInfo,
    SwiftParentInfo, SwiftType, SwiftTypeConfidence, SwiftTypeKind, SwiftTypeSource,
};

const CONTEXT_KIND_MASK: u32 = 0x1f;
const MODULE_CONTEXT: u32 = 0;
const EXTENSION_CONTEXT: u32 = 1;
const ANONYMOUS_CONTEXT: u32 = 2;
const PROTOCOL_CONTEXT: u32 = 3;
const CLASS_CONTEXT: u32 = 16;
const STRUCT_CONTEXT: u32 = 17;
const ENUM_CONTEXT: u32 = 18;
const MAX_CONTEXT_DEPTH: usize = 64;
const MAX_IDENTIFIER_LENGTH: usize = 4096;
const MAX_FIELD_RECORDS: usize = 1_000_000;
const MAX_ASSOCIATED_TYPE_RECORDS: usize = 1_000_000;
const FIELD_DESCRIPTOR_HEADER_SIZE: u64 = 16;
const MIN_FIELD_RECORD_SIZE: usize = 12;

pub(crate) fn discover(macho: &MachoFile<'_>, demangler: &dyn SwiftDemangler) -> Vec<SwiftType> {
    let mut types = discover_section(macho, "__swift5_types", None, demangler);
    types.extend(discover_section(
        macho,
        "__swift5_protos",
        Some(SwiftTypeKind::Protocol),
        demangler,
    ));
    types
}

pub(crate) fn discover_parents(macho: &MachoFile<'_>, types: &[SwiftType]) -> Vec<SwiftParentInfo> {
    types
        .iter()
        .filter_map(|swift_type| {
            let descriptor = Va(swift_type.address?);
            let parent_field = add_unsigned(descriptor, 4)?;
            let relative = read_i32(macho, parent_field)?;
            let parent = resolve_relative_pointer(macho, parent_field, relative)?;
            let kind = read_u32(macho, parent)? & CONTEXT_KIND_MASK;
            if !matches!(
                kind,
                PROTOCOL_CONTEXT | CLASS_CONTEXT | STRUCT_CONTEXT | ENUM_CONTEXT
            ) {
                return None;
            }
            Some(SwiftParentInfo {
                descriptor_address: descriptor.0,
                parent_descriptor_address: parent.0,
                parent_name: context_path(macho, parent, 0)?.join("."),
            })
        })
        .collect()
}

pub(crate) fn discover_conformances(macho: &MachoFile<'_>) -> Vec<SwiftConformanceInfo> {
    let Some(section) = macho
        .all_sections()
        .find(|section| section.section_name() == "__swift5_proto")
    else {
        return Vec::new();
    };
    let Ok(bytes) = macho.read_bytes_at(section.offset(), section.size() as usize) else {
        return Vec::new();
    };
    bytes
        .chunks_exact(4)
        .enumerate()
        .filter_map(|(index, chunk)| {
            let relative = macho.endian().read_i32(chunk.try_into().ok()?);
            let entry = add_unsigned(section.addr(), (index * 4) as u64)?;
            let descriptor = resolve_relative_pointer(macho, entry, relative)?;
            let protocol_field = descriptor;
            let protocol_address = read_i32(macho, protocol_field)
                .and_then(|value| resolve_relative_pointer(macho, protocol_field, value));
            let protocol = protocol_address
                .and_then(|address| context_path(macho, address, 0))
                .map(|path| path.join("."));
            let type_field = add_unsigned(descriptor, 4)?;
            let type_reference = read_i32(macho, type_field)
                .and_then(|value| resolve_type_reference(macho, type_field, value));
            Some(SwiftConformanceInfo {
                address: descriptor.0,
                byte_len: 16,
                protocol_address: protocol_address.map(|value| value.0),
                protocol_name: protocol,
                conforming_type_address: type_reference.as_ref().and_then(|value| value.1),
                conforming_type_name: type_reference.map(|value| value.0),
            })
        })
        .collect()
}

pub(crate) fn discover_associated_types(
    macho: &MachoFile<'_>,
    demangler: &dyn SwiftDemangler,
) -> Vec<SwiftAssociatedTypeInfo> {
    let Some(section) = macho
        .all_sections()
        .find(|section| section.section_name() == "__swift5_assocty")
    else {
        return Vec::new();
    };
    let Some(end) = section.addr().0.checked_add(section.size()) else {
        return Vec::new();
    };
    let mut cursor = section.addr();
    let mut descriptors = Vec::new();
    while cursor.0.checked_add(16).is_some_and(|value| value <= end) {
        let Some(type_field) = add_unsigned(cursor, 4) else {
            break;
        };
        let Some(count) = add_unsigned(cursor, 8).and_then(|address| read_u32(macho, address))
        else {
            break;
        };
        let Some(record_size) =
            add_unsigned(cursor, 12).and_then(|address| read_u32(macho, address))
        else {
            break;
        };
        let count = count as usize;
        let record_size = record_size as usize;
        if count > MAX_ASSOCIATED_TYPE_RECORDS || record_size < 8 {
            break;
        }
        let Ok(record_size_u32) = u32::try_from(record_size) else {
            break;
        };
        let Some(records_bytes) = count.checked_mul(record_size) else {
            break;
        };
        let Some(descriptor_size) = 16usize.checked_add(records_bytes) else {
            break;
        };
        if cursor
            .0
            .checked_add(descriptor_size as u64)
            .is_none_or(|value| value > end)
        {
            break;
        }
        let protocol_type_name = read_i32(macho, type_field)
            .filter(|value| *value != 0)
            .and_then(|value| add_signed(type_field, value))
            .and_then(|address| read_mangled_bytes(macho, address));
        let conforming_type_address = read_i32(macho, cursor)
            .filter(|value| *value != 0)
            .and_then(|value| add_signed(cursor, value));
        let conforming_type_name =
            conforming_type_address.and_then(|address| read_mangled_bytes(macho, address));
        let resolved_conforming_type = conforming_type_address
            .and_then(|address| resolve_mangled_nominal_identity(macho, address, demangler));
        let mut records = Vec::with_capacity(count);
        let Some(records_start) = add_unsigned(cursor, 16) else {
            break;
        };
        for index in 0..count {
            let Some(record) = add_unsigned(records_start, (index * record_size) as u64) else {
                break;
            };
            let name = read_i32(macho, record)
                .filter(|value| *value != 0)
                .and_then(|value| add_signed(record, value))
                .and_then(|address| read_c_string(macho, address));
            let substituted_field = add_unsigned(record, 4);
            let substituted_type_name = substituted_field
                .and_then(|field| read_i32(macho, field).map(|value| (field, value)))
                .filter(|(_, value)| *value != 0)
                .and_then(|(field, value)| add_signed(field, value))
                .and_then(|address| read_mangled_bytes(macho, address));
            records.push(SwiftAssociatedTypeRecordInfo {
                record_address: record.0,
                record_size: record_size_u32,
                name,
                substituted_type_name,
            });
        }
        descriptors.push(SwiftAssociatedTypeInfo {
            address: cursor.0,
            byte_len: descriptor_size as u32,
            conforming_type_name,
            resolved_conforming_type_name: resolved_conforming_type
                .as_ref()
                .map(|(name, _)| name.clone()),
            resolved_conforming_type_descriptor_address: resolved_conforming_type
                .and_then(|(_, descriptor)| descriptor),
            protocol_type_name,
            records,
        });
        let Some(next) = add_unsigned(cursor, descriptor_size as u64) else {
            break;
        };
        cursor = next;
    }
    descriptors
}

fn discover_section(
    macho: &MachoFile<'_>,
    section_name: &str,
    expected_kind: Option<SwiftTypeKind>,
    demangler: &dyn SwiftDemangler,
) -> Vec<SwiftType> {
    let Some(section) = macho
        .all_sections()
        .find(|section| section.section_name() == section_name)
    else {
        return Vec::new();
    };
    let Ok(bytes) = macho.read_bytes_at(section.offset(), section.size() as usize) else {
        return Vec::new();
    };

    bytes
        .chunks_exact(4)
        .enumerate()
        .filter_map(|(index, chunk)| {
            let relative = macho.endian().read_i32(chunk.try_into().ok()?);
            let entry_address = add_unsigned(section.addr(), (index * 4) as u64)?;
            let descriptor = resolve_relative_pointer(macho, entry_address, relative)?;
            parse_type_descriptor(macho, descriptor, expected_kind, demangler)
        })
        .collect()
}

fn parse_type_descriptor(
    macho: &MachoFile<'_>,
    descriptor: Va,
    expected_kind: Option<SwiftTypeKind>,
    demangler: &dyn SwiftDemangler,
) -> Option<SwiftType> {
    let flags = read_u32(macho, descriptor)?;
    let kind = swift_type_kind(flags & CONTEXT_KIND_MASK)?;
    if expected_kind.is_some_and(|expected| expected != kind) {
        return None;
    }
    let name = context_path(macho, descriptor, 0)?.join(".");
    if name.is_empty() {
        return None;
    }

    Some(SwiftType {
        name,
        kind,
        mangled_name: None,
        address: Some(descriptor.0),
        metadata_address: None,
        source: SwiftTypeSource::SwiftMetadata,
        confidence: SwiftTypeConfidence::High,
        fields: parse_fields(macho, descriptor, demangler),
    })
}

fn parse_fields(
    macho: &MachoFile<'_>,
    descriptor: Va,
    demangler: &dyn SwiftDemangler,
) -> Option<Vec<SwiftFieldInfo>> {
    let field_pointer = add_unsigned(descriptor, 16)?;
    let relative = read_i32(macho, field_pointer)?;
    if relative == 0 {
        return Some(Vec::new());
    }
    let field_descriptor = add_signed(field_pointer, relative)?;
    let record_size = read_u16(macho, add_unsigned(field_descriptor, 10)?)? as usize;
    let count = read_u32(macho, add_unsigned(field_descriptor, 12)?)? as usize;
    if record_size < MIN_FIELD_RECORD_SIZE || count > MAX_FIELD_RECORDS {
        return None;
    }
    let records_start = add_unsigned(field_descriptor, FIELD_DESCRIPTOR_HEADER_SIZE)?;
    let mut fields = Vec::with_capacity(count);
    for index in 0..count {
        let offset = index.checked_mul(record_size)? as u64;
        let record = add_unsigned(records_start, offset)?;
        let flags = read_u32(macho, record)?;
        let type_field = add_unsigned(record, 4)?;
        let name_field = add_unsigned(record, 8)?;
        let mangled_type = read_i32(macho, type_field)
            .filter(|relative| *relative != 0)
            .and_then(|relative| add_signed(type_field, relative))
            .and_then(|address| read_mangled_bytes(macho, address));
        let type_name = read_i32(macho, type_field)
            .filter(|relative| *relative != 0)
            .and_then(|relative| add_signed(type_field, relative))
            .and_then(|address| resolve_mangled_nominal(macho, address, demangler));
        let name = read_i32(macho, name_field)
            .filter(|relative| *relative != 0)
            .and_then(|relative| add_signed(name_field, relative))
            .and_then(|address| read_c_string(macho, address));
        fields.push(SwiftFieldInfo {
            record_address: record.0,
            record_size: u32::try_from(record_size).ok()?,
            name,
            mangled_type,
            type_name,
            flags,
        });
    }
    Some(fields)
}

fn context_path(macho: &MachoFile<'_>, descriptor: Va, depth: usize) -> Option<Vec<String>> {
    if depth >= MAX_CONTEXT_DEPTH {
        return None;
    }

    let flags = read_u32(macho, descriptor)?;
    let context_kind = flags & CONTEXT_KIND_MASK;
    let parent_field = add_unsigned(descriptor, 4)?;
    let parent = read_i32(macho, parent_field)
        .filter(|relative| *relative != 0)
        .and_then(|relative| resolve_relative_pointer(macho, parent_field, relative));
    let mut path = parent
        .and_then(|parent| context_path(macho, parent, depth + 1))
        .unwrap_or_default();

    if matches!(context_kind, EXTENSION_CONTEXT | ANONYMOUS_CONTEXT) {
        return Some(path);
    }
    if !matches!(
        context_kind,
        MODULE_CONTEXT | PROTOCOL_CONTEXT | CLASS_CONTEXT | STRUCT_CONTEXT | ENUM_CONTEXT
    ) {
        return None;
    }

    let name_field = add_unsigned(descriptor, 8)?;
    let relative_name = read_i32(macho, name_field)?;
    let name_address = add_signed(name_field, relative_name)?;
    let name = read_c_string(macho, name_address)?;
    if path.last() != Some(&name) {
        path.push(name);
    }
    Some(path)
}

fn swift_type_kind(context_kind: u32) -> Option<SwiftTypeKind> {
    match context_kind {
        CLASS_CONTEXT => Some(SwiftTypeKind::Class),
        STRUCT_CONTEXT => Some(SwiftTypeKind::Struct),
        ENUM_CONTEXT => Some(SwiftTypeKind::Enum),
        PROTOCOL_CONTEXT => Some(SwiftTypeKind::Protocol),
        _ => None,
    }
}

fn resolve_relative_pointer(macho: &MachoFile<'_>, field: Va, relative: i32) -> Option<Va> {
    if relative == 0 {
        return None;
    }
    let indirect = relative & 1 != 0;
    let relative = relative & !1;
    let target = add_signed(field, relative)?;
    if !indirect {
        return Some(target);
    }

    if macho.is_64bit() {
        read_u64(macho, target).map(Va)
    } else {
        read_u32(macho, target).map(|address| Va(address as u64))
    }
}

fn resolve_type_reference(
    macho: &MachoFile<'_>,
    field: Va,
    relative: i32,
) -> Option<(String, Option<u64>)> {
    let tag = (relative as u32) & 3;
    let offset = ((relative as u32) & !3) as i32;
    let target = add_signed(field, offset)?;
    match tag {
        0 => context_path(macho, target, 0).map(|path| (path.join("."), Some(target.0))),
        1 => read_pointer(macho, target).and_then(|address| {
            context_path(macho, address, 0).map(|path| (path.join("."), Some(address.0)))
        }),
        2 => read_c_string(macho, target).map(|name| (name, None)),
        3 => read_pointer(macho, target)
            .and_then(|address| read_c_string(macho, address))
            .map(|name| (name, None)),
        _ => None,
    }
}

fn read_pointer(macho: &MachoFile<'_>, address: Va) -> Option<Va> {
    if macho.is_64bit() {
        read_u64(macho, address).map(Va)
    } else {
        read_u32(macho, address).map(|value| Va(value as u64))
    }
}

fn read_c_string(macho: &MachoFile<'_>, address: Va) -> Option<String> {
    let bytes = read_c_bytes(macho, address)?;
    std::str::from_utf8(&bytes)
        .ok()
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
}

fn read_c_bytes(macho: &MachoFile<'_>, address: Va) -> Option<Vec<u8>> {
    let offset = macho
        .address_map()
        .va_to_thin_offset(address)
        .ok()?
        .as_usize();
    let bytes = macho.bytes().get(offset..)?;
    let length = bytes
        .iter()
        .take(MAX_IDENTIFIER_LENGTH)
        .position(|byte| *byte == 0)?;
    Some(bytes[..length].to_vec())
}

fn read_mangled_bytes(macho: &MachoFile<'_>, address: Va) -> Option<Vec<u8>> {
    let offset = macho
        .address_map()
        .va_to_thin_offset(address)
        .ok()?
        .as_usize();
    let bytes = macho.bytes().get(offset..)?;
    let mut length = 0usize;
    while length < bytes.len() && length < MAX_IDENTIFIER_LENGTH {
        match bytes[length] {
            0 => return Some(bytes[..length].to_vec()),
            0x01..=0x0c => length = length.checked_add(5)?,
            _ => length += 1,
        }
    }
    None
}

fn resolve_mangled_nominal(
    macho: &MachoFile<'_>,
    address: Va,
    demangler: &dyn SwiftDemangler,
) -> Option<String> {
    resolve_mangled_nominal_identity(macho, address, demangler).map(|(name, _)| name)
}

fn resolve_mangled_nominal_identity(
    macho: &MachoFile<'_>,
    address: Va,
    demangler: &dyn SwiftDemangler,
) -> Option<(String, Option<u64>)> {
    let first = *macho.read_bytes_at_va(address, 1).ok()?.first()?;
    if matches!(first, 0x01 | 0x02) {
        let relative_field = add_unsigned(address, 1)?;
        let relative = read_i32(macho, relative_field)?;
        let direct = add_signed(relative_field, relative)?;
        let descriptor = if first == 0x01 {
            direct
        } else {
            read_pointer(macho, direct)?
        };
        return context_path(macho, descriptor, 0).map(|path| (path.join("."), Some(descriptor.0)));
    }
    let bytes = read_mangled_bytes(macho, address)?;
    let raw = std::str::from_utf8(&bytes).ok()?;
    let name = demangler
        .demangle(raw)
        .ok()
        .flatten()
        .or_else(|| demangler.demangle(&format!("$s{raw}")).ok().flatten())?;
    Some((name, None))
}

fn read_i32(macho: &MachoFile<'_>, address: Va) -> Option<i32> {
    macho
        .read_bytes_at_va(address, 4)
        .ok()?
        .try_into()
        .ok()
        .map(|bytes| macho.endian().read_i32(bytes))
}

fn read_u32(macho: &MachoFile<'_>, address: Va) -> Option<u32> {
    macho
        .read_bytes_at_va(address, 4)
        .ok()?
        .try_into()
        .ok()
        .map(|bytes| macho.endian().read_u32(bytes))
}

fn read_u16(macho: &MachoFile<'_>, address: Va) -> Option<u16> {
    macho
        .read_bytes_at_va(address, 2)
        .ok()?
        .try_into()
        .ok()
        .map(|bytes| macho.endian().read_u16(bytes))
}

fn read_u64(macho: &MachoFile<'_>, address: Va) -> Option<u64> {
    macho
        .read_bytes_at_va(address, 8)
        .ok()?
        .try_into()
        .ok()
        .map(|bytes| macho.endian().read_u64(bytes))
}

fn add_unsigned(address: Va, offset: u64) -> Option<Va> {
    address.0.checked_add(offset).map(Va)
}

fn add_signed(address: Va, offset: i32) -> Option<Va> {
    if offset >= 0 {
        address.0.checked_add(offset as u64).map(Va)
    } else {
        address.0.checked_sub(offset.unsigned_abs() as u64).map(Va)
    }
}

#[cfg(test)]
mod tests {
    use super::{Va, add_signed, swift_type_kind};
    use crate::types::SwiftTypeKind;

    #[test]
    fn context_kinds_map_to_swift_kinds() {
        assert_eq!(swift_type_kind(16), Some(SwiftTypeKind::Class));
        assert_eq!(swift_type_kind(17), Some(SwiftTypeKind::Struct));
        assert_eq!(swift_type_kind(18), Some(SwiftTypeKind::Enum));
        assert_eq!(swift_type_kind(3), Some(SwiftTypeKind::Protocol));
        assert_eq!(swift_type_kind(0), None);
    }

    #[test]
    fn signed_relative_addresses_are_checked() {
        assert_eq!(add_signed(Va(0x1000), 0x20), Some(Va(0x1020)));
        assert_eq!(add_signed(Va(0x1000), -0x20), Some(Va(0x0fe0)));
        assert_eq!(add_signed(Va(0), -1), None);
    }
}
