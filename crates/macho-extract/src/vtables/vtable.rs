use serde::Serialize;

use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::SymbolTable;
use crate::core::symbols::demangle::demangle_symbol;
use crate::{Error, Result};

#[derive(Debug, Clone, Serialize)]
pub struct VtableIndex {
    pub vtables: Vec<VtableEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VtableEntry {
    pub name: Option<String>,
    pub mangled_name: Option<String>,
    pub va: Va,
    pub size: u64,
    pub slots: Vec<VtableSlot>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VtableSlot {
    pub offset: u64,
    pub va: Va,
    pub target: SlotTarget,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SlotTarget {
    Function { name: String, va: Va },
    PureVirtual,
    TypeInfo { va: Va },
    OffsetToTop { value: i64 },
    Unknown { value: u64 },
}

/// Resolved value at a vtable slot after decoding chained fixups.
#[derive(Debug)]
enum ResolvedSlotValue {
    /// A rebase target: this is the resolved VA the pointer refers to.
    Address(u64),
    /// A bind (import): the pointer refers to an imported symbol.
    Import { name: String },
    /// No fixup data available; use the raw value directly.
    Raw(u64),
}

impl VtableIndex {
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        let symtab = macho.ext::<SymbolTable<'_>>()?;
        let symbols = symtab.symbols();

        let ptr_size: u64 = if macho.is_64bit() { 8 } else { 4 };
        let image_base = macho.image_base().0;

        // Build a map of VA -> symbol name for resolving slot targets
        let mut va_to_name: std::collections::HashMap<u64, &str> = std::collections::HashMap::new();
        for sym in symbols {
            if sym.is_defined() && sym.value != 0 {
                va_to_name.insert(sym.value, sym.name);
            }
        }

        // Build a fixup map for resolving chained fixup pointers.
        // On modern arm64/x86_64 binaries, pointer values in __DATA_CONST
        // are encoded chained fixup entries, not actual VAs.
        let fixup_map = build_vtable_fixup_map(macho);

        // Find typeinfo symbol VAs (symbols starting with __ZTI)
        let typeinfo_vas: std::collections::HashSet<u64> = symbols
            .iter()
            .filter(|s| s.name.starts_with("__ZTI") || s.name.starts_with("_ZTI"))
            .filter(|s| s.is_defined() && s.value != 0)
            .map(|s| s.value)
            .collect();

        // Collect vtable symbols sorted by VA
        let mut vtable_syms: Vec<_> = symbols
            .iter()
            .filter(|s| {
                s.is_defined()
                    && s.value != 0
                    && (s.name.starts_with("__ZTV") || s.name.starts_with("_ZTV"))
            })
            .collect();
        vtable_syms.sort_by_key(|s| s.value);

        // Find the next defined symbol after each vtable to determine size bounds
        let mut all_defined_vas: Vec<u64> = symbols
            .iter()
            .filter(|s| s.is_defined() && s.value != 0)
            .map(|s| s.value)
            .collect();
        all_defined_vas.sort();
        all_defined_vas.dedup();

        let mut vtables = Vec::new();

        for vtable_sym in &vtable_syms {
            let vtable_va = vtable_sym.value;

            // Determine max size: distance to next symbol
            let max_size = match all_defined_vas.binary_search(&vtable_va) {
                Ok(idx) => {
                    if idx + 1 < all_defined_vas.len() {
                        all_defined_vas[idx + 1] - vtable_va
                    } else {
                        // Last symbol - use a reasonable cap
                        256 * ptr_size
                    }
                }
                Err(_) => 1024 * ptr_size,
            };

            // Read vtable slots
            let ctx = VtableScanContext {
                image_base,
                va_to_name: &va_to_name,
                typeinfo_vas: &typeinfo_vas,
                fixup_map: &fixup_map,
            };

            let slots = match read_vtable_slots(macho, Va(vtable_va), ptr_size, max_size, &ctx) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if slots.is_empty() {
                continue;
            }

            let size = slots.last().map(|s| s.offset + ptr_size).unwrap_or(0);

            // Demangle the vtable name
            let demangled = demangle_symbol(vtable_sym.name);

            vtables.push(VtableEntry {
                name: demangled,
                mangled_name: Some(vtable_sym.name.to_owned()),
                va: Va(vtable_va),
                size,
                slots,
            });
        }

        Ok(Self { vtables })
    }

    pub fn find_by_class(&self, class_name: &str) -> Option<&VtableEntry> {
        self.vtables
            .iter()
            .find(|v| v.name.as_ref().is_some_and(|n| n.contains(class_name)))
    }

    pub fn find_by_va(&self, va: Va) -> Option<&VtableEntry> {
        self.vtables.iter().find(|v| v.va == va)
    }

    pub fn slot_at(&self, va: Va) -> Option<(&VtableEntry, &VtableSlot)> {
        for vtable in &self.vtables {
            for slot in &vtable.slots {
                if slot.va == va {
                    return Some((vtable, slot));
                }
            }
        }
        None
    }

    /// Find all vtable slots whose target points to the given function VA.
    pub fn slots_targeting_va(&self, target_va: Va) -> Vec<(&VtableEntry, &VtableSlot)> {
        let mut results = Vec::new();
        for vtable in &self.vtables {
            for slot in &vtable.slots {
                if let SlotTarget::Function { va, .. } = &slot.target {
                    if *va == target_va {
                        results.push((vtable, slot));
                    }
                }
            }
        }
        results
    }

    pub fn vtables(&self) -> &[VtableEntry] {
        &self.vtables
    }
}

/// Resolved fixup at a file offset.
#[derive(Debug, Clone)]
enum VtableFixup {
    /// Rebase: the pointer targets image_base + target.
    Rebase(u64),
    /// Bind: the pointer targets an imported symbol.
    Bind { import_name: String },
}

/// Build a map from file_offset -> resolved fixup, using chained fixups
/// if available, otherwise legacy bind/rebase opcodes.
fn build_vtable_fixup_map(macho: &MachoFile<'_>) -> std::collections::HashMap<u64, VtableFixup> {
    use macho_metadata::metadata::dyld::chained::parse_chained_fixups;
    use macho_metadata::metadata::dyld::types::FixupKind;

    let mut map = std::collections::HashMap::new();

    match parse_chained_fixups(macho) {
        Ok(fixups) => {
            for fixup in &fixups.fixups {
                let seg = match macho.segments().get(fixup.segment_index) {
                    Some(s) => s,
                    None => continue,
                };
                let file_offset = seg.file_offset.0 + fixup.segment_offset;

                match &fixup.kind {
                    FixupKind::Rebase { target } | FixupKind::AuthRebase { target, .. } => {
                        map.insert(file_offset, VtableFixup::Rebase(*target));
                    }
                    FixupKind::Bind { import_index, .. }
                    | FixupKind::AuthBind { import_index, .. } => {
                        let name = fixups
                            .imports
                            .get(*import_index as usize)
                            .map(|i| i.name.to_string())
                            .unwrap_or_default();
                        map.insert(file_offset, VtableFixup::Bind { import_name: name });
                    }
                }
            }
        }
        Err(_) => {
            // Try legacy bind/rebase opcodes
            if let Ok((regular, weak, lazy)) =
                macho_metadata::metadata::dyld::bind::parse_bind_entries(macho)
            {
                for entry in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
                    if let Some(seg) = macho.segments().get(entry.segment_index) {
                        let file_offset = seg.file_offset.0 + entry.segment_offset;
                        map.insert(
                            file_offset,
                            VtableFixup::Bind {
                                import_name: entry.symbol_name.to_string(),
                            },
                        );
                    }
                }
            }

            if let Ok(rebases) = macho_metadata::metadata::dyld::rebase::parse_rebase_entries(macho) {
                for entry in &rebases {
                    if let Some(seg) = macho.segments().get(entry.segment_index) {
                        let file_offset = seg.file_offset.0 + entry.segment_offset;
                        map.entry(file_offset).or_insert(VtableFixup::Rebase(0));
                    }
                }
            }
        }
    }

    map
}

/// Resolve the pointer value at a given file offset using the fixup map.
fn resolve_slot_value(
    raw_value: u64,
    file_offset: u64,
    image_base: u64,
    fixup_map: &std::collections::HashMap<u64, VtableFixup>,
    macho: &MachoFile<'_>,
    endian: crate::core::format::io::endian::Endian,
) -> ResolvedSlotValue {
    if let Some(fixup) = fixup_map.get(&file_offset) {
        match fixup {
            VtableFixup::Rebase(target) if *target != 0 => {
                ResolvedSlotValue::Address(image_base + target)
            }
            VtableFixup::Rebase(_) => {
                // Legacy rebase sentinel -- read the raw pointer directly
                // (the linker wrote the correct un-slid VA)
                let raw = crate::core::format::io::pod::read_pod::<u64>(
                    macho.bytes(),
                    file_offset as usize,
                )
                .map(|v| endian.interpret_u64(v))
                .unwrap_or(raw_value);
                ResolvedSlotValue::Address(raw)
            }
            VtableFixup::Bind { import_name } => ResolvedSlotValue::Import {
                name: import_name.clone(),
            },
        }
    } else {
        // No fixup -- use raw value as-is (non-fixup binaries or
        // the slot was not covered by any fixup chain)
        ResolvedSlotValue::Raw(raw_value)
    }
}

struct VtableScanContext<'a> {
    image_base: u64,
    va_to_name: &'a std::collections::HashMap<u64, &'a str>,
    typeinfo_vas: &'a std::collections::HashSet<u64>,
    fixup_map: &'a std::collections::HashMap<u64, VtableFixup>,
}

fn read_vtable_slots(
    macho: &MachoFile<'_>,
    vtable_va: Va,
    ptr_size: u64,
    max_size: u64,
    ctx: &VtableScanContext<'_>,
) -> Result<Vec<VtableSlot>> {
    let endian = macho.endian();
    let max_slots = max_size / ptr_size;
    let has_fixups = !ctx.fixup_map.is_empty();
    let mut slots = Vec::new();

    for i in 0..max_slots {
        let slot_offset = i * ptr_size;
        let slot_va = Va(vtable_va.0 + slot_offset);

        let bytes = match macho.read_bytes_at_va(slot_va, ptr_size as usize) {
            Ok(b) => b,
            Err(_) => break,
        };

        let raw_value = if ptr_size == 8 {
            let arr: [u8; 8] = bytes
                .try_into()
                .map_err(|_| Error::Format("failed to read 8 bytes for vtable slot".into()))?;
            endian.read_u64(arr)
        } else {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| Error::Format("failed to read 4 bytes for vtable slot".into()))?;
            endian.read_u32(arr) as u64
        };

        // Resolve the pointer value through the fixup map
        let file_offset = macho
            .address_map()
            .va_to_thin_offset(slot_va)
            .map(|o| o.0)
            .unwrap_or(0);

        let resolved = resolve_slot_value(
            raw_value,
            file_offset,
            ctx.image_base,
            ctx.fixup_map,
            macho,
            endian,
        );

        let target = classify_slot(
            &resolved,
            raw_value,
            i,
            ctx.va_to_name,
            ctx.typeinfo_vas,
            has_fixups,
        );

        // Stop if we've read past the structural header (offset-to-top +
        // typeinfo) and hit a clearly invalid entry (zero after the
        // function pointer region).
        if i > 2 {
            match &resolved {
                ResolvedSlotValue::Address(0) | ResolvedSlotValue::Raw(0) => break,
                _ => {}
            }
        }

        slots.push(VtableSlot {
            offset: slot_offset,
            va: slot_va,
            target,
        });
    }

    Ok(slots)
}

fn classify_slot(
    resolved: &ResolvedSlotValue,
    _raw_value: u64,
    slot_index: u64,
    va_to_name: &std::collections::HashMap<u64, &str>,
    typeinfo_vas: &std::collections::HashSet<u64>,
    has_fixups: bool,
) -> SlotTarget {
    // First slot is the offset-to-top value (typically 0 for primary vtables,
    // or a negative offset for secondary base vtables).
    if slot_index == 0 {
        // The offset-to-top is a signed integer, not a pointer.
        // In non-fixup binaries the raw value is the actual offset-to-top.
        // In fixup binaries, if this slot has no fixup entry, the raw value
        // is the offset-to-top. If it does have a fixup, the resolved address
        // minus image_base is the offset-to-top.
        let value = match resolved {
            ResolvedSlotValue::Raw(v) => *v as i64,
            ResolvedSlotValue::Address(v) => *v as i64,
            ResolvedSlotValue::Import { .. } => 0,
        };
        return SlotTarget::OffsetToTop { value };
    }

    // Second slot is the typeinfo pointer.
    if slot_index == 1 {
        match resolved {
            ResolvedSlotValue::Address(va) if typeinfo_vas.contains(va) => {
                return SlotTarget::TypeInfo { va: Va(*va) };
            }
            ResolvedSlotValue::Address(va) if *va != 0 => {
                // Even if we don't recognize this as a typeinfo symbol,
                // slot 1 is structurally the typeinfo pointer.
                return SlotTarget::TypeInfo { va: Va(*va) };
            }
            ResolvedSlotValue::Import { .. } => {
                // Typeinfo bound to an external symbol -- still typeinfo
                return SlotTarget::TypeInfo { va: Va(0) };
            }
            ResolvedSlotValue::Raw(v) if !has_fixups => {
                if typeinfo_vas.contains(v) || *v != 0 {
                    return SlotTarget::TypeInfo { va: Va(*v) };
                }
                return SlotTarget::TypeInfo { va: Va(0) };
            }
            _ => {
                return SlotTarget::TypeInfo { va: Va(0) };
            }
        }
    }

    // For slots beyond the header, resolve the target and classify.
    let effective_va = match resolved {
        ResolvedSlotValue::Address(va) => *va,
        ResolvedSlotValue::Import { name } => {
            // Check if this is a pure virtual or deleted virtual import
            if is_pure_virtual_name(name) {
                return SlotTarget::PureVirtual;
            }
            // Other imports -- report as function with the import name
            let demangled = demangle_symbol(name).unwrap_or_else(|| name.clone());
            return SlotTarget::Function {
                name: demangled,
                va: Va(0),
            };
        }
        ResolvedSlotValue::Raw(v) => *v,
    };

    // Check for known function symbol
    if let Some(name) = va_to_name.get(&effective_va) {
        // Check if this symbol is actually pure virtual
        if is_pure_virtual_name(name) {
            return SlotTarget::PureVirtual;
        }
        let demangled = demangle_symbol(name).unwrap_or_else(|| (*name).to_owned());
        return SlotTarget::Function {
            name: demangled,
            va: Va(effective_va),
        };
    }

    // If the value looks like a reasonable VA (non-zero), treat as unknown pointer
    SlotTarget::Unknown {
        value: effective_va,
    }
}

/// Check if a symbol name refers to __cxa_pure_virtual or __cxa_deleted_virtual.
///
/// Mach-O prepends one underscore to C names, so the standard library symbols
/// appear as `___cxa_pure_virtual` (3 underscores) in the symbol table. We
/// strip one leading underscore and match the C-level name with its own leading
/// double-underscore.
fn is_pure_virtual_name(name: &str) -> bool {
    let stripped = name.strip_prefix('_').unwrap_or(name);
    matches!(stripped, "__cxa_pure_virtual" | "__cxa_deleted_virtual")
}
