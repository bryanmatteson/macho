use serde::Serialize;

use crate::addr::Va;
use crate::demangle::demangle_symbol;
use crate::model::mach::MachFile;
use crate::parse::parse_symbol_table;
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
pub enum SlotTarget {
    Function { name: String, va: Va },
    PureVirtual,
    TypeInfo { va: Va },
    AddressPoint,
    Unknown { value: u64 },
}

impl VtableIndex {
    pub fn build(mach: &MachFile<'_>) -> Result<Self> {
        let symtab = parse_symbol_table(mach)?;
        let symbols = symtab.symbols();

        let ptr_size: u64 = if mach.is_64bit() { 8 } else { 4 };

        // Build a map of VA -> symbol name for resolving slot targets
        let mut va_to_name: std::collections::HashMap<u64, &str> = std::collections::HashMap::new();
        for sym in symbols {
            if sym.is_defined() && sym.value != 0 {
                va_to_name.insert(sym.value, sym.name);
            }
        }

        // Find pure virtual symbol VA
        let pure_virtual_va = symbols
            .iter()
            .find(|s| {
                s.name == "___cxa_pure_virtual"
                    || s.name == "__cxa_pure_virtual"
                    || s.name == "___cxa_deleted_virtual"
            })
            .map(|s| s.value);

        // Find typeinfo symbol VAs (symbols starting with __ZTI)
        let typeinfo_vas: std::collections::HashSet<u64> = symbols
            .iter()
            .filter(|s| {
                s.name.starts_with("__ZTI") || s.name.starts_with("_ZTI")
            })
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
                        1024 * ptr_size
                    }
                }
                Err(_) => 1024 * ptr_size,
            };

            // Read vtable slots
            let slots = match read_vtable_slots(
                mach,
                Va(vtable_va),
                ptr_size,
                max_size,
                &va_to_name,
                pure_virtual_va,
                &typeinfo_vas,
            ) {
                Ok(s) => s,
                Err(_) => continue,
            };

            if slots.is_empty() {
                continue;
            }

            let size = slots
                .last()
                .map(|s| s.offset + ptr_size)
                .unwrap_or(0);

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
        self.vtables.iter().find(|v| {
            v.name
                .as_ref()
                .is_some_and(|n| n.contains(class_name))
        })
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

    pub fn vtables(&self) -> &[VtableEntry] {
        &self.vtables
    }
}

fn read_vtable_slots(
    mach: &MachFile<'_>,
    vtable_va: Va,
    ptr_size: u64,
    max_size: u64,
    va_to_name: &std::collections::HashMap<u64, &str>,
    pure_virtual_va: Option<u64>,
    typeinfo_vas: &std::collections::HashSet<u64>,
) -> Result<Vec<VtableSlot>> {
    let endian = mach.endian();
    let max_slots = max_size / ptr_size;
    let mut slots = Vec::new();

    for i in 0..max_slots {
        let slot_offset = i * ptr_size;
        let slot_va = Va(vtable_va.0 + slot_offset);

        let bytes = match mach.read_bytes_at_va(slot_va, ptr_size as usize) {
            Ok(b) => b,
            Err(_) => break,
        };

        let value = if ptr_size == 8 {
            let arr: [u8; 8] = bytes.try_into().map_err(|_| {
                Error::Format("failed to read 8 bytes for vtable slot".into())
            })?;
            endian.read_u64(arr)
        } else {
            let arr: [u8; 4] = bytes.try_into().map_err(|_| {
                Error::Format("failed to read 4 bytes for vtable slot".into())
            })?;
            endian.read_u32(arr) as u64
        };

        let target = classify_slot(
            value,
            i,
            va_to_name,
            pure_virtual_va,
            typeinfo_vas,
        );

        // Stop if we've read past the address point and hit a clearly
        // invalid entry (zero after the function pointer region).
        // The vtable structure is: offset-to-top, typeinfo, then function pointers.
        // After the function pointers we should stop.
        if i > 2 && value == 0 {
            break;
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
    value: u64,
    slot_index: u64,
    va_to_name: &std::collections::HashMap<u64, &str>,
    pure_virtual_va: Option<u64>,
    typeinfo_vas: &std::collections::HashSet<u64>,
) -> SlotTarget {
    // First slot is typically offset-to-top (usually 0)
    if slot_index == 0 && value == 0 {
        return SlotTarget::AddressPoint;
    }

    // Second slot is typically typeinfo pointer
    if slot_index == 1 && typeinfo_vas.contains(&value) {
        return SlotTarget::TypeInfo { va: Va(value) };
    }

    // Check for pure virtual
    if let Some(pv_va) = pure_virtual_va {
        if value == pv_va {
            return SlotTarget::PureVirtual;
        }
    }

    // Check for known function symbol
    if let Some(name) = va_to_name.get(&value) {
        let demangled = demangle_symbol(name).unwrap_or_else(|| (*name).to_owned());
        return SlotTarget::Function {
            name: demangled,
            va: Va(value),
        };
    }

    // If the value looks like a reasonable VA (non-zero in code regions),
    // treat it as an unknown pointer
    SlotTarget::Unknown { value }
}
