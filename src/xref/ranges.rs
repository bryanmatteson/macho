use std::collections::HashSet;

use serde::Serialize;

use crate::addr::map::AddressMap;
use crate::addr::types::{ThinFileOffset, Va};
use crate::dyld::exports::parse_exports;
use crate::dyld::types::ExportKind;
use crate::error::Result;
use crate::model::mach::MachFile;
use crate::model::symbol::SymbolType;
use crate::objc::parse_objc_metadata;
use crate::parse::parse_symbol_table;

#[derive(Debug, Clone, Serialize)]
pub struct SymbolRangeIndex {
    entries: Vec<RangeEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RangeEntry {
    pub start: Va,
    pub end: Va,
    pub entity: CodeEntity,
    pub source: RangeSource,
    pub is_alt_entry: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CodeEntity {
    Symbol {
        name: String,
        external: bool,
    },
    ObjCMethod {
        class_name: String,
        selector: String,
        is_class_method: bool,
    },
    Export {
        name: String,
    },
    Anonymous {
        section_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RangeSource {
    Nlist,
    ExportTrie,
    ObjCMetadata,
    Inferred,
}

struct RawEntry {
    va: Va,
    entity: CodeEntity,
    source: RangeSource,
    is_alt_entry: bool,
}

impl SymbolRangeIndex {
    pub fn build(mach: &MachFile<'_>) -> Result<Self> {
        let mut raw: Vec<RawEntry> = Vec::new();

        // Track nlist VAs in a HashSet for O(1) dedup checks instead of O(n)
        // linear scans per entry.
        let mut nlist_vas: HashSet<u64> = HashSet::new();

        // Collect defined nlist symbols
        if let Ok(symtab) = parse_symbol_table(mach) {
            for sym in symtab.symbols() {
                if sym.sym_type == SymbolType::Section && sym.value != 0 {
                    nlist_vas.insert(sym.value);
                    raw.push(RawEntry {
                        va: Va(sym.value),
                        entity: CodeEntity::Symbol {
                            name: sym.name.to_string(),
                            external: sym.external,
                        },
                        source: RangeSource::Nlist,
                        is_alt_entry: sym.is_alt_entry(),
                    });
                }
            }
        }

        // Collect exports with addresses (only add if not already covered by nlist).
        // Skip Absolute exports — they are linker-defined constants not backed
        // by any file section, so they have no meaningful ownership range.
        if let Ok(exports) = parse_exports(mach) {
            for exp in &exports {
                let addr = match &exp.kind {
                    ExportKind::Regular { address } => *address,
                    ExportKind::ThreadLocal { address } => *address,
                    ExportKind::Absolute { .. } => continue,
                    _ => continue,
                };
                if addr == 0 {
                    continue;
                }
                // O(1) check instead of O(n) linear scan
                if nlist_vas.contains(&addr) {
                    continue;
                }
                raw.push(RawEntry {
                    va: Va(addr),
                    entity: CodeEntity::Export {
                        name: exp.name.clone(),
                    },
                    source: RangeSource::ExportTrie,
                    is_alt_entry: false,
                });
            }
        }

        // Collect ObjC method implementations
        if let Ok(objc) = parse_objc_metadata(mach) {
            for class in &objc.classes {
                for method in &class.instance_methods {
                    if method.imp.0 != 0 && !nlist_vas.contains(&method.imp.0) {
                        raw.push(RawEntry {
                            va: method.imp,
                            entity: CodeEntity::ObjCMethod {
                                class_name: class.name.clone(),
                                selector: method.name.clone(),
                                is_class_method: false,
                            },
                            source: RangeSource::ObjCMetadata,
                            is_alt_entry: false,
                        });
                    }
                }
                for method in &class.class_methods {
                    if method.imp.0 != 0 && !nlist_vas.contains(&method.imp.0) {
                        raw.push(RawEntry {
                            va: method.imp,
                            entity: CodeEntity::ObjCMethod {
                                class_name: class.name.clone(),
                                selector: method.name.clone(),
                                is_class_method: true,
                            },
                            source: RangeSource::ObjCMetadata,
                            is_alt_entry: false,
                        });
                    }
                }
            }
            for cat in &objc.categories {
                for method in &cat.instance_methods {
                    if method.imp.0 != 0 && !nlist_vas.contains(&method.imp.0) {
                        raw.push(RawEntry {
                            va: method.imp,
                            entity: CodeEntity::ObjCMethod {
                                class_name: cat.class_name.clone(),
                                selector: method.name.clone(),
                                is_class_method: false,
                            },
                            source: RangeSource::ObjCMetadata,
                            is_alt_entry: false,
                        });
                    }
                }
                for method in &cat.class_methods {
                    if method.imp.0 != 0 && !nlist_vas.contains(&method.imp.0) {
                        raw.push(RawEntry {
                            va: method.imp,
                            entity: CodeEntity::ObjCMethod {
                                class_name: cat.class_name.clone(),
                                selector: method.name.clone(),
                                is_class_method: true,
                            },
                            source: RangeSource::ObjCMetadata,
                            is_alt_entry: false,
                        });
                    }
                }
            }
        }

        // Sort by VA
        raw.sort_by_key(|e| e.va);

        // Deduplicate entries at the same VA (prefer Nlist > ExportTrie > ObjCMetadata)
        raw.dedup_by(|b, a| a.va == b.va);

        // Build section boundaries for sizing the last entry in each section
        let mut section_ends: Vec<(Va, Va)> = Vec::new(); // (start, end)
        for seg in mach.segments() {
            for sect in &seg.sections {
                if sect.size > 0 {
                    section_ends.push((sect.addr, Va(sect.addr.0 + sect.size)));
                }
            }
        }
        section_ends.sort_by_key(|&(start, _)| start);

        // Size each entry by gap to next entry, clamped to section end
        let len = raw.len();
        let mut entries = Vec::with_capacity(len);
        for i in 0..len {
            let start = raw[i].va;
            let end = if i + 1 < len {
                // Next entry's start, but don't cross section boundary
                let next_start = raw[i + 1].va;
                let section_end = find_section_end(&section_ends, start);
                match section_end {
                    Some(se) if se < next_start => se,
                    _ => next_start,
                }
            } else {
                // Last entry: use section end
                find_section_end(&section_ends, start).unwrap_or(Va(start.0 + 1))
            };

            entries.push(RangeEntry {
                start,
                end,
                entity: std::mem::replace(
                    &mut raw[i].entity,
                    CodeEntity::Anonymous {
                        section_name: String::new(),
                    },
                ),
                source: raw[i].source,
                is_alt_entry: raw[i].is_alt_entry,
            });
        }

        Ok(Self { entries })
    }

    pub fn lookup_va(&self, va: Va) -> Option<&RangeEntry> {
        // Binary search for the entry containing this VA
        let idx = self.entries.partition_point(|e| e.start <= va);
        if idx == 0 {
            return None;
        }
        let entry = &self.entries[idx - 1];
        if va >= entry.start && va < entry.end {
            Some(entry)
        } else {
            None
        }
    }

    pub fn lookup_file_offset(
        &self,
        offset: ThinFileOffset,
        address_map: &AddressMap,
    ) -> Option<&RangeEntry> {
        let va = address_map.thin_offset_to_va(offset).ok()?;
        self.lookup_va(va)
    }

    pub fn entries(&self) -> &[RangeEntry] {
        &self.entries
    }

    pub fn entries_in_range(&self, start: Va, end: Va) -> &[RangeEntry] {
        let lo = self.entries.partition_point(|e| e.start < start);
        let hi = self.entries.partition_point(|e| e.start < end);
        &self.entries[lo..hi]
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn find_section_end(section_ends: &[(Va, Va)], va: Va) -> Option<Va> {
    // Binary search for the section containing this VA. The array is sorted
    // by section start address. We find the last section whose start <= va,
    // then verify va < end.
    let idx = section_ends.partition_point(|&(start, _)| start <= va);
    if idx == 0 {
        return None;
    }
    let (start, end) = section_ends[idx - 1];
    if va >= start && va < end {
        Some(end)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_section_end_empty() {
        assert_eq!(find_section_end(&[], Va(0x1000)), None);
    }

    #[test]
    fn find_section_end_before_all_sections() {
        let sections = vec![(Va(0x2000), Va(0x3000))];
        assert_eq!(find_section_end(&sections, Va(0x1000)), None);
    }

    #[test]
    fn find_section_end_at_section_start() {
        let sections = vec![(Va(0x2000), Va(0x3000))];
        assert_eq!(find_section_end(&sections, Va(0x2000)), Some(Va(0x3000)));
    }

    #[test]
    fn find_section_end_in_middle_of_section() {
        let sections = vec![(Va(0x2000), Va(0x3000))];
        assert_eq!(find_section_end(&sections, Va(0x2800)), Some(Va(0x3000)));
    }

    #[test]
    fn find_section_end_at_last_byte() {
        let sections = vec![(Va(0x2000), Va(0x3000))];
        // VA 0x2FFF is the last byte in the section [0x2000, 0x3000)
        assert_eq!(find_section_end(&sections, Va(0x2FFF)), Some(Va(0x3000)));
    }

    #[test]
    fn find_section_end_at_section_end_returns_none() {
        let sections = vec![(Va(0x2000), Va(0x3000))];
        // VA 0x3000 is past the section end
        assert_eq!(find_section_end(&sections, Va(0x3000)), None);
    }

    #[test]
    fn find_section_end_gap_between_sections() {
        let sections = vec![(Va(0x1000), Va(0x2000)), (Va(0x3000), Va(0x4000))];
        // VA 0x2500 is in the gap between sections
        assert_eq!(find_section_end(&sections, Va(0x2500)), None);
    }

    #[test]
    fn find_section_end_multiple_sections() {
        let sections = vec![
            (Va(0x1000), Va(0x2000)),
            (Va(0x2000), Va(0x3000)),
            (Va(0x4000), Va(0x5000)),
        ];
        assert_eq!(find_section_end(&sections, Va(0x1500)), Some(Va(0x2000)));
        assert_eq!(find_section_end(&sections, Va(0x2000)), Some(Va(0x3000)));
        assert_eq!(find_section_end(&sections, Va(0x4800)), Some(Va(0x5000)));
    }
}
