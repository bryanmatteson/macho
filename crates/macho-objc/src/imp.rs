use macho_core::format::io::pod::{
    self, RawClassRoT64, RawMethodListHeader, RawMethodT, RawRelativeMethodT,
};
use macho_core::model::addr::{ThinFileOffset, Va};
use macho_core::model::macho_file::MachoFile;
use macho_core::model::section::Section;

use crate::error::{Error, Result};
use crate::resolve::ObjCResolver;
use crate::types::{METHOD_LIST_ENTSIZE_MASK, METHOD_LIST_USES_RELATIVE_OFFSETS};

/// Objective-C method dispatch kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjCMethodKind {
    /// Instance method (`-`).
    Instance,
    /// Class method (`+`).
    Class,
}

/// One parsed Objective-C implementation entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjCMethodImp {
    /// Owning class name.
    pub class_name: String,
    /// Owning category name, when the method comes from a category.
    pub category_name: Option<String>,
    /// Selector spelling.
    pub method_name: String,
    /// Instance or class dispatch kind.
    pub kind: ObjCMethodKind,
    /// Implementation virtual address.
    pub imp: Va,
}

/// Fold class and category method implementations into caller-owned state.
///
/// Runtime pointer lists and method lists are traversed directly; no complete
/// Objective-C graph or method vector is materialized. The state is returned
/// only after every nested pointer, name, method entry, and implementation
/// address parses successfully. A malformed suffix therefore drops the partial
/// accumulator and returns only the typed parse error.
pub fn fold_method_imps<State>(
    macho: &MachoFile<'_>,
    mut state: State,
    mut folder: impl FnMut(&mut State, ObjCMethodImp) -> Result<()>,
) -> Result<State> {
    if !macho.is_64bit() {
        return Err(Error::unsupported(
            "ObjC method implementation parsing is only supported for 64-bit binaries",
        ));
    }
    let resolver = ObjCResolver::new(macho);
    let (class_list, category_list) = runtime_lists(macho);
    if let Some(section) = class_list {
        fold_pointer_list(macho, &resolver, section, |class_va| {
            fold_class(&resolver, class_va, &mut state, &mut folder)
        })?;
    }
    if let Some(section) = category_list {
        fold_pointer_list(macho, &resolver, section, |category_va| {
            fold_category(&resolver, category_va, &mut state, &mut folder)
        })?;
    }
    Ok(state)
}

/// Fold method implementations from one borrowed thin Mach-O byte source.
///
/// The source is not copied and may be a byte slice, vector, or caller-owned
/// read-only memory map. Universal binaries require explicit architecture
/// selection through [`macho_core::parse`] and [`fold_method_imps`].
pub fn fold_method_imps_from_source<S, State>(
    source: &S,
    state: State,
    folder: impl FnMut(&mut State, ObjCMethodImp) -> Result<()>,
) -> Result<State>
where
    S: AsRef<[u8]> + ?Sized,
{
    let macho = crate::parse_source(source)?;
    fold_method_imps(&macho, state, folder)
}

fn runtime_lists<'macho>(
    macho: &'macho MachoFile<'_>,
) -> (Option<&'macho Section>, Option<&'macho Section>) {
    let mut classes = None;
    let mut categories = None;
    for section in macho.all_sections() {
        if section.section_name() == "__objc_classlist" && classes.is_none() {
            classes = Some(section);
        } else if section.section_name() == "__objc_catlist" && categories.is_none() {
            categories = Some(section);
        }
    }
    (classes, categories)
}

fn fold_pointer_list(
    macho: &MachoFile<'_>,
    resolver: &ObjCResolver<'_>,
    section: &Section,
    mut visitor: impl FnMut(Va) -> Result<()>,
) -> Result<()> {
    let offset = section.offset().0;
    let size = section.size();
    if size % 8 != 0 {
        return Err(Error::format(format!(
            "section {} size {size:#x} is not pointer-aligned",
            section.section_name()
        )));
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| Error::address("Objective-C pointer-list range overflows"))?;
    if end > macho.file_size() as u64 {
        return Err(Error::bounds(offset, size, macho.file_size() as u64));
    }
    for ordinal in 0..size / 8 {
        let pointer_offset = offset
            .checked_add(ordinal * 8)
            .ok_or_else(|| Error::address("Objective-C pointer offset overflows"))?;
        let runtime_va = resolver
            .read_pointer_at_offset(pointer_offset)?
            .filter(|va| va.0 != 0)
            .ok_or_else(|| {
                Error::format(format!(
                    "{}[{ordinal}] has a null or unresolved runtime pointer",
                    section.section_name()
                ))
            })?;
        visitor(runtime_va)?;
    }
    Ok(())
}

fn fold_class<State>(
    resolver: &ObjCResolver<'_>,
    class_va: Va,
    state: &mut State,
    folder: &mut impl FnMut(&mut State, ObjCMethodImp) -> Result<()>,
) -> Result<()> {
    let class_offset = resolver.va_to_offset(class_va)?.0;
    let data_va = required_pointer(
        resolver,
        checked_field_offset(class_offset, 32, "class data")?,
        "class data",
    )?;
    let ro_offset = resolver.va_to_offset(Va(data_va.0 & !1))?.0;
    let _: RawClassRoT64 = pod::read_pod(resolver.macho().bytes(), ro_offset as usize)?;
    let class_name = required_cstring_pointer(
        resolver,
        checked_field_offset(ro_offset, 24, "class name")?,
        "class name",
    )?;

    fold_optional_method_list(
        resolver,
        checked_field_offset(ro_offset, 32, "class methods")?,
        &class_name,
        None,
        ObjCMethodKind::Instance,
        state,
        folder,
    )?;
    if let Some(meta_va) = resolver.read_pointer_at_offset(class_offset)? {
        let meta_offset = resolver.va_to_offset(meta_va)?.0;
        let meta_data = required_pointer(
            resolver,
            checked_field_offset(meta_offset, 32, "metaclass data")?,
            "metaclass data",
        )?;
        let meta_ro_offset = resolver.va_to_offset(Va(meta_data.0 & !1))?.0;
        let _: RawClassRoT64 = pod::read_pod(resolver.macho().bytes(), meta_ro_offset as usize)?;
        fold_optional_method_list(
            resolver,
            checked_field_offset(meta_ro_offset, 32, "metaclass methods")?,
            &class_name,
            None,
            ObjCMethodKind::Class,
            state,
            folder,
        )?;
    }
    Ok(())
}

fn fold_category<State>(
    resolver: &ObjCResolver<'_>,
    category_va: Va,
    state: &mut State,
    folder: &mut impl FnMut(&mut State, ObjCMethodImp) -> Result<()>,
) -> Result<()> {
    let offset = resolver.va_to_offset(category_va)?.0;
    let category_name = required_cstring_pointer(resolver, offset, "category name")?;
    let class_name =
        strict_class_ref_name(resolver, checked_field_offset(offset, 8, "category class")?)?;
    fold_optional_method_list(
        resolver,
        checked_field_offset(offset, 16, "category instance methods")?,
        &class_name,
        Some(&category_name),
        ObjCMethodKind::Instance,
        state,
        folder,
    )?;
    fold_optional_method_list(
        resolver,
        checked_field_offset(offset, 24, "category class methods")?,
        &class_name,
        Some(&category_name),
        ObjCMethodKind::Class,
        state,
        folder,
    )
}

#[allow(clippy::too_many_arguments)]
fn fold_optional_method_list<State>(
    resolver: &ObjCResolver<'_>,
    pointer_offset: u64,
    class_name: &str,
    category_name: Option<&str>,
    kind: ObjCMethodKind,
    state: &mut State,
    folder: &mut impl FnMut(&mut State, ObjCMethodImp) -> Result<()>,
) -> Result<()> {
    let Some(list_va) = resolver.read_pointer_at_offset(pointer_offset)? else {
        return Ok(());
    };
    if list_va.0 == 0 {
        return Ok(());
    }
    fold_method_list(resolver, list_va, |method_name, imp| {
        folder(
            state,
            ObjCMethodImp {
                class_name: class_name.to_owned(),
                category_name: category_name.map(str::to_owned),
                method_name,
                kind,
                imp,
            },
        )
    })
}

fn fold_method_list(
    resolver: &ObjCResolver<'_>,
    list_va: Va,
    mut visitor: impl FnMut(String, Va) -> Result<()>,
) -> Result<()> {
    let offset = resolver.va_to_offset(list_va)?.as_usize();
    let data = resolver.macho().bytes();
    let endian = resolver.endian();
    let header: RawMethodListHeader = pod::read_pod(data, offset)?;
    let flags = endian.interpret_u32(header.entsize_and_flags);
    let count = endian.interpret_u32(header.count) as usize;
    let relative = flags & METHOD_LIST_USES_RELATIVE_OFFSETS != 0;
    let minimum = if relative {
        size_of::<RawRelativeMethodT>()
    } else {
        size_of::<RawMethodT>()
    };
    let encoded_size = (flags & METHOD_LIST_ENTSIZE_MASK) as usize;
    let entry_size = if encoded_size == 0 {
        minimum
    } else {
        encoded_size
    };
    if entry_size < minimum {
        return Err(Error::format(format!(
            "method entry size {entry_size} is smaller than {minimum}"
        )));
    }
    let entries_start = offset
        .checked_add(size_of::<RawMethodListHeader>())
        .ok_or_else(|| Error::address("method-list header range overflows"))?;
    let entries_size = count
        .checked_mul(entry_size)
        .ok_or_else(|| Error::address("method-list entry range overflows"))?;
    let entries_end = entries_start
        .checked_add(entries_size)
        .ok_or_else(|| Error::address("method-list end overflows"))?;
    if entries_end > data.len() {
        return Err(Error::bounds(
            entries_start as u64,
            entries_size as u64,
            data.len() as u64,
        ));
    }

    for ordinal in 0..count {
        let entry_offset = entries_start + ordinal * entry_size;
        let (name, imp) = if relative {
            parse_relative_method(resolver, entry_offset)?
        } else {
            parse_absolute_method(resolver, entry_offset)?
        };
        visitor(name, imp)?;
    }
    Ok(())
}

fn parse_relative_method(resolver: &ObjCResolver<'_>, entry_offset: usize) -> Result<(String, Va)> {
    let data = resolver.macho().bytes();
    let endian = resolver.endian();
    let raw: RawRelativeMethodT = pod::read_pod(data, entry_offset)?;
    let name_relative = endian.interpret_i32(raw.name_offset) as isize;
    let imp_relative = endian.interpret_i32(raw.imp_offset) as i64;
    let selector_offset = entry_offset
        .checked_add_signed(name_relative)
        .ok_or_else(|| Error::address("relative method selector offset overflows"))?;
    let name = match resolver.read_pointer_at_offset(selector_offset as u64)? {
        Some(string_va) => resolver.read_cstring(string_va)?.to_owned(),
        None => read_cstring_at_file_offset(data, selector_offset)?.to_owned(),
    };
    let imp_field_offset = entry_offset
        .checked_add(8)
        .ok_or_else(|| Error::address("relative method IMP field overflows"))?;
    let imp_field_va = resolver
        .macho()
        .address_map()
        .thin_offset_to_va(ThinFileOffset(imp_field_offset as u64))?;
    let imp = imp_field_va
        .0
        .checked_add_signed(imp_relative)
        .filter(|value| *value != 0)
        .map(Va)
        .ok_or_else(|| Error::address("relative method IMP address is invalid"))?;
    Ok((name, imp))
}

fn parse_absolute_method(resolver: &ObjCResolver<'_>, entry_offset: usize) -> Result<(String, Va)> {
    let name = required_cstring_pointer(resolver, entry_offset as u64, "method name")?;
    let imp = required_pointer(
        resolver,
        checked_field_offset(entry_offset as u64, 16, "method IMP")?,
        "method IMP",
    )?;
    if imp.0 == 0 {
        return Err(Error::address("method IMP is null"));
    }
    Ok((name, imp))
}

fn strict_class_ref_name(resolver: &ObjCResolver<'_>, pointer_offset: u64) -> Result<String> {
    if let Some(bind_name) = resolver.bind_name_at_offset(pointer_offset) {
        return Ok(bind_name
            .strip_prefix("_OBJC_CLASS_$_")
            .unwrap_or(bind_name)
            .to_owned());
    }
    let class_va = required_pointer(resolver, pointer_offset, "category class")?;
    let class_offset = resolver.va_to_offset(class_va)?.0;
    let data_va = required_pointer(
        resolver,
        checked_field_offset(class_offset, 32, "category class data")?,
        "category class data",
    )?;
    let ro_offset = resolver.va_to_offset(Va(data_va.0 & !1))?.0;
    required_cstring_pointer(
        resolver,
        checked_field_offset(ro_offset, 24, "category class name")?,
        "category class name",
    )
}

fn checked_field_offset(base: u64, delta: u64, field: &str) -> Result<u64> {
    base.checked_add(delta)
        .ok_or_else(|| Error::address(format!("{field} offset overflows")))
}

fn required_pointer(resolver: &ObjCResolver<'_>, offset: u64, field: &str) -> Result<Va> {
    resolver
        .read_pointer_at_offset(offset)?
        .filter(|va| va.0 != 0)
        .ok_or_else(|| Error::format(format!("{field} pointer is null or unresolved")))
}

fn required_cstring_pointer(
    resolver: &ObjCResolver<'_>,
    offset: u64,
    field: &str,
) -> Result<String> {
    let va = required_pointer(resolver, offset, field)?;
    resolver.read_cstring(va).map(str::to_owned)
}

fn read_cstring_at_file_offset(data: &[u8], offset: usize) -> Result<&str> {
    let slice = data
        .get(offset..)
        .ok_or_else(|| Error::bounds(offset as u64, 1, data.len() as u64))?;
    let end = slice
        .iter()
        .position(|byte| *byte == 0)
        .ok_or_else(|| Error::format(format!("unterminated string at file offset {offset:#x}")))?;
    std::str::from_utf8(&slice[..end])
        .map_err(|error| Error::format(format!("invalid UTF-8 at offset {offset:#x}: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thin(bytes: &[u8]) -> &MachoFile<'_> {
        let container = Box::leak(Box::new(macho_core::parse(bytes).unwrap()));
        match container {
            macho_core::model::container::MachoContainer::Thin(macho) => macho,
            macho_core::model::container::MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    #[test]
    fn folds_class_and_category_method_imps_without_collecting_a_graph() {
        let class_bytes = macho_test_support::disassembly_objc_boundary();
        let class_imps = fold_method_imps(thin(&class_bytes), Vec::new(), |items, item| {
            items.push(item);
            Ok(())
        })
        .unwrap();
        assert!(
            class_imps.iter().any(|item| {
                item.class_name == "Fixture"
                    && item.category_name.is_none()
                    && item.method_name == "next"
                    && item.kind == ObjCMethodKind::Instance
            }),
            "{class_imps:?}"
        );

        let category_bytes = macho_test_support::disassembly_objc_category_labels();
        let category_imps = fold_method_imps(thin(&category_bytes), Vec::new(), |items, item| {
            items.push(item);
            Ok(())
        })
        .unwrap();
        assert!(
            category_imps
                .iter()
                .any(|item| item.category_name.as_deref() == Some("Fixture")
                    && item.kind == ObjCMethodKind::Instance)
        );
        assert!(
            category_imps
                .iter()
                .any(|item| item.category_name.as_deref() == Some("Fixture")
                    && item.kind == ObjCMethodKind::Class)
        );
    }

    #[test]
    fn malformed_suffix_drops_an_accumulator_after_a_valid_imp() {
        let mut bytes = macho_test_support::disassembly_objc_boundary();
        // Extend __objc_classlist over the class object's isa word. The first
        // class method list is valid and invokes the folder; its malformed isa
        // then fails before the accumulator can be returned.
        bytes[224..232].copy_from_slice(&16u64.to_le_bytes());
        bytes[0x248..0x250].copy_from_slice(&u64::MAX.to_le_bytes());
        let callback_count = std::cell::Cell::new(0usize);
        let result = fold_method_imps(thin(&bytes), 0usize, |count, _| {
            *count += 1;
            callback_count.set(callback_count.get() + 1);
            Ok(())
        });
        assert_eq!(callback_count.get(), 1);
        assert!(result.is_err());
    }
}
