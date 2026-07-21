use serde::{Deserialize, Serialize};

use crate::model::addr::Va;
use crate::model::macho_file::MachoFile;
use crate::model::symbol::SymbolTable;
use crate::symbols::demangle::demangle_symbol;
use crate::{Error, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The VtableIndex type.
pub struct VtableIndex {
    /// The vtables field.
    pub vtables: Vec<VtableEntry>,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The VtableEntry type.
pub struct VtableEntry {
    /// The name field.
    pub name: Option<String>,
    /// The mangled_name field.
    pub mangled_name: Option<String>,
    #[serde(with = "va_serde")]
    /// The va field.
    pub va: Va,
    /// The size field.
    pub size: u64,
    /// The slots field.
    pub slots: Vec<VtableSlot>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The VtableSlot type.
pub struct VtableSlot {
    /// The offset field.
    pub offset: u64,
    #[serde(with = "va_serde")]
    /// The va field.
    pub va: Va,
    /// The target field.
    pub target: SlotTarget,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// The SlotTarget type.
#[non_exhaustive]
pub enum SlotTarget {
    /// The Function variant.
    Function {
        /// The String field.
        name: String,
        #[serde(with = "va_serde")]
        /// The Va field.
        va: Va,
    },
    /// The PureVirtual variant.
    PureVirtual,
    /// The TypeInfo variant.
    TypeInfo {
        #[serde(with = "va_serde")]
        /// The Va field.
        va: Va,
    },
    /// The OffsetToTop variant.
    OffsetToTop {
        /// The i64 field.
        value: i64,
    },
    /// The Unknown variant.
    Unknown {
        /// The u64 field.
        value: u64,
    },
}

mod va_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    use crate::model::addr::Va;

    pub fn serialize<S>(value: &Va, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_u64(value.0)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Va, D::Error>
    where
        D: Deserializer<'de>,
    {
        u64::deserialize(deserializer).map(Va)
    }
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
    /// Performs build.
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        Self::build_limited(macho, usize::MAX)
    }

    /// Build from one borrowed thin Mach-O byte source.
    ///
    /// The source is not copied and may be a byte slice, vector, or
    /// caller-owned read-only memory map. Universal binaries are rejected so
    /// callers select an architecture explicitly.
    pub fn build_from_source<S>(source: &S) -> Result<Self>
    where
        S: AsRef<[u8]> + ?Sized,
    {
        Self::build_limited_from_source(source, usize::MAX)
    }

    /// Builds at most `max_vtables` decoded vtables.
    ///
    /// The search stops once the output limit is reached. Use
    /// [`Self::was_truncated`] to distinguish a complete result from a bounded
    /// one.
    pub fn build_limited(macho: &MachoFile<'_>, max_vtables: usize) -> Result<Self> {
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
            .take(max_vtables.saturating_add(1))
            .collect();
        vtable_syms.sort_by_key(|s| s.value);
        let truncated = vtable_syms.len() > max_vtables;
        vtable_syms.truncate(max_vtables);

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

        Ok(Self { vtables, truncated })
    }

    /// Build at most `max_vtables` entries from a borrowed thin Mach-O source.
    ///
    /// This has the same zero-copy source and universal-binary behavior as
    /// [`Self::build_from_source`].
    pub fn build_limited_from_source<S>(source: &S, max_vtables: usize) -> Result<Self>
    where
        S: AsRef<[u8]> + ?Sized,
    {
        let macho = crate::parse_source(source)?;
        Self::build_limited(&macho, max_vtables)
    }

    /// Performs find_by_class.
    pub fn find_by_class(&self, class_name: &str) -> Option<&VtableEntry> {
        self.vtables
            .iter()
            .find(|v| v.name.as_ref().is_some_and(|n| n.contains(class_name)))
    }

    /// Performs find_by_va.
    pub fn find_by_va(&self, va: Va) -> Option<&VtableEntry> {
        self.vtables.iter().find(|v| v.va == va)
    }

    /// Performs slot_at.
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

    /// Performs vtables.
    pub fn vtables(&self) -> &[VtableEntry] {
        &self.vtables
    }

    /// Returns whether additional vtable candidates were skipped at the
    /// configured collection bound.
    pub fn was_truncated(&self) -> bool {
        self.truncated
    }

    /// Find a vtable function slot by class name and method name.
    ///
    /// The method name is matched against the demangled target function name
    /// of each slot. The match is substring-based: `"check"` matches a slot
    /// targeting `"Foo::check()"`.
    ///
    /// Returns the vtable entry, the matching slot, and its function-slot
    /// index (0-based, excluding the header slots).
    pub fn find_slot_by_method(
        &self,
        class_name: &str,
        method_name: &str,
    ) -> Option<(&VtableEntry, &VtableSlot, usize)> {
        let entry = self.find_by_class(class_name)?;
        entry
            .find_slot_by_name(method_name)
            .map(|(slot, idx)| (entry, slot, idx))
    }
}

impl VtableEntry {
    /// Return only the function slots (excluding offset-to-top and typeinfo header slots).
    pub fn function_slots(&self) -> impl Iterator<Item = (usize, &VtableSlot)> {
        self.slots
            .iter()
            .filter(|s| {
                matches!(
                    s.target,
                    SlotTarget::Function { .. } | SlotTarget::PureVirtual
                )
            })
            .enumerate()
    }

    /// Number of function slots (excluding header slots).
    pub fn function_slot_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|s| {
                matches!(
                    s.target,
                    SlotTarget::Function { .. } | SlotTarget::PureVirtual
                )
            })
            .count()
    }

    /// Find a function slot by matching the demangled target name.
    ///
    /// Returns the slot and its function-slot index (0-based, excluding header slots).
    /// The match checks whether the demangled function name contains `method_name`.
    pub fn find_slot_by_name(&self, method_name: &str) -> Option<(&VtableSlot, usize)> {
        for (func_idx, slot) in self.function_slots() {
            if let SlotTarget::Function { name, .. } = &slot.target {
                // Try exact leaf match first, then substring.
                if extract_method_leaf(name) == method_name || name.contains(method_name) {
                    return Some((slot, func_idx));
                }
            }
        }
        None
    }

    /// Get a function slot by its 0-based function-slot index
    /// (excluding header slots like offset-to-top and typeinfo).
    pub fn function_slot_at(&self, index: usize) -> Option<&VtableSlot> {
        self.function_slots()
            .find(|(i, _)| *i == index)
            .map(|(_, slot)| slot)
    }
}

/// Extract the leaf method name from a demangled C++ name.
///
/// `"Foo::Bar::check(int)"` → `"check"`
/// `"check"` → `"check"`
fn extract_method_leaf(demangled: &str) -> &str {
    // Strip everything from '(' onward (parameters).
    let base = demangled.split('(').next().unwrap_or(demangled);
    // Take the part after the last "::".
    base.rsplit("::").next().unwrap_or(base)
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
    use crate::dyld::chained::parse_chained_fixups;
    use crate::dyld::types::FixupKind;

    let mut map = std::collections::HashMap::new();

    match parse_chained_fixups(macho) {
        Ok(fixups) => {
            for fixup in &fixups.fixups {
                let seg = match macho.segments().get(fixup.segment_index) {
                    Some(s) => s,
                    None => continue,
                };
                let file_offset = seg.file_offset().0 + fixup.segment_offset;

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
                    _ => continue,
                }
            }
        }
        Err(_) => {
            // Try legacy bind/rebase opcodes
            if let Ok((regular, weak, lazy)) = crate::dyld::bind::parse_bind_entries(macho) {
                for entry in regular.iter().chain(weak.iter()).chain(lazy.iter()) {
                    if let Some(seg) = macho.segments().get(entry.segment_index) {
                        let file_offset = seg.file_offset().0 + entry.segment_offset;
                        map.insert(
                            file_offset,
                            VtableFixup::Bind {
                                import_name: entry.symbol_name.to_string(),
                            },
                        );
                    }
                }
            }

            if let Ok(rebases) = crate::dyld::rebase::parse_rebase_entries(macho) {
                for entry in &rebases {
                    if let Some(seg) = macho.segments().get(entry.segment_index) {
                        let file_offset = seg.file_offset().0 + entry.segment_offset;
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
    endian: crate::format::io::endian::Endian,
) -> ResolvedSlotValue {
    if let Some(fixup) = fixup_map.get(&file_offset) {
        match fixup {
            VtableFixup::Rebase(target) if *target != 0 => {
                ResolvedSlotValue::Address(image_base + target)
            }
            VtableFixup::Rebase(_) => {
                // Legacy rebase sentinel -- read the raw pointer directly
                // (the linker wrote the correct un-slid VA)
                let raw =
                    crate::format::io::pod::read_pod::<u64>(macho.bytes(), file_offset as usize)
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
                .map_err(|_| Error::format("failed to read 8 bytes for vtable slot"))?;
            endian.read_u64(arr)
        } else {
            let arr: [u8; 4] = bytes
                .try_into()
                .map_err(|_| Error::format("failed to read 4 bytes for vtable slot"))?;
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
