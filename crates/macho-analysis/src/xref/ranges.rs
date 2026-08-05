use std::collections::HashSet;

use serde::{Deserialize, Serialize};

use crate::Result;
use crate::dyld::exports::parse_exports;
use crate::dyld::types::ExportKind;
use crate::ext::MachoExt;
use crate::functions::{
    FunctionCollectorStatus, FunctionEvidenceSource, FunctionIdentity, FunctionIndex,
};
use crate::model::addr::map::AddressMap;
use crate::model::addr::types::{ThinFileOffset, Va};
use crate::model::macho_file::MachoFile;
use crate::model::symbol::SymbolTable;
use crate::model::symbol::SymbolType;
use crate::objc::ObjCMetadata;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The SymbolRangeIndex type.
pub struct SymbolRangeIndex {
    entries: Vec<RangeEntry>,
    truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The RangeEntry type.
pub struct RangeEntry {
    #[serde(
        serialize_with = "crate::serde_addr::va",
        deserialize_with = "crate::serde_addr::va_from"
    )]
    /// The start field.
    pub start: Va,
    #[serde(
        serialize_with = "crate::serde_addr::va",
        deserialize_with = "crate::serde_addr::va_from"
    )]
    /// The end field.
    pub end: Va,
    /// The entity field.
    pub entity: CodeEntity,
    /// The source field.
    pub source: RangeSource,
    /// The is_alt_entry field.
    pub is_alt_entry: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
/// The CodeEntity type.
#[non_exhaustive]
pub enum CodeEntity {
    /// The Symbol variant.
    Symbol {
        /// The String field.
        name: String,
        /// The bool field.
        external: bool,
    },
    /// The ObjCMethod variant.
    ObjCMethod {
        /// The String field.
        class_name: String,
        /// The String field.
        selector: String,
        /// The bool field.
        is_class_method: bool,
    },
    /// The Export variant.
    Export {
        /// The String field.
        name: String,
    },
    /// The Anonymous variant.
    Anonymous {
        /// The String field.
        section_name: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The RangeSource type.
#[non_exhaustive]
pub enum RangeSource {
    /// The Nlist variant.
    Nlist,
    /// The ExportTrie variant.
    ExportTrie,
    /// The ObjCMetadata variant.
    ObjCMetadata,
    /// The Inferred variant.
    Inferred,
}

struct RawEntry {
    va: Va,
    entity: CodeEntity,
    source: RangeSource,
    is_alt_entry: bool,
}

impl SymbolRangeIndex {
    /// Performs build.
    pub fn build(macho: &MachoFile<'_>) -> Result<Self> {
        Self::build_limited(macho, usize::MAX)
    }

    /// Builds at most `max_ranges` symbol ranges.
    ///
    /// [`Self::was_truncated`] reports whether additional input-derived ranges
    /// were discarded after the bound was reached.
    pub fn build_limited(macho: &MachoFile<'_>, max_ranges: usize) -> Result<Self> {
        let mut raw: Vec<RawEntry> = Vec::new();
        let mut truncated = false;

        // Track nlist VAs in a HashSet for O(1) dedup checks instead of O(n)
        // linear scans per entry.
        let mut nlist_vas: HashSet<u64> = HashSet::new();

        // Collect defined nlist symbols
        if let Ok(symtab) = macho.ext::<SymbolTable<'_>>() {
            for sym in symtab.symbols() {
                if sym.sym_type == SymbolType::Section && sym.value != 0 {
                    if raw.len() >= max_ranges {
                        truncated = true;
                        continue;
                    }
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
        if let Ok(exports) = parse_exports(macho) {
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
                if raw.len() >= max_ranges {
                    truncated = true;
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
        if let Ok(objc) = macho.ext::<ObjCMetadata>() {
            for class in &objc.classes {
                for method in &class.instance_methods {
                    if method.imp.0 != 0 && !nlist_vas.contains(&method.imp.0) {
                        if raw.len() >= max_ranges {
                            truncated = true;
                            continue;
                        }
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
                        if raw.len() >= max_ranges {
                            truncated = true;
                            continue;
                        }
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
                        if raw.len() >= max_ranges {
                            truncated = true;
                            continue;
                        }
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
                        if raw.len() >= max_ranges {
                            truncated = true;
                            continue;
                        }
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
        for seg in macho.segments() {
            for sect in seg.sections() {
                if sect.size() > 0 {
                    section_ends.push((sect.addr(), Va(sect.addr().0 + sect.size())));
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

        Ok(Self { entries, truncated })
    }

    /// Project the Macho-owned function inventory into the legacy range wire
    /// model without deriving new boundaries from adjacent symbols.
    pub fn from_function_index_limited(
        macho: &MachoFile<'_>,
        functions: &FunctionIndex,
        max_ranges: usize,
    ) -> Self {
        let truncated = functions.truncated_function_count() != 0
            || functions.functions().len() > max_ranges
            || functions
                .receipts()
                .iter()
                .any(|receipt| receipt.status == FunctionCollectorStatus::Truncated);
        let entries = functions
            .functions()
            .iter()
            .take(max_ranges)
            .map(|function| {
                let source = if function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source == FunctionEvidenceSource::Nlist)
                {
                    RangeSource::Nlist
                } else if function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source == FunctionEvidenceSource::ExportTrie)
                {
                    RangeSource::ExportTrie
                } else if function
                    .evidence
                    .iter()
                    .any(|evidence| evidence.source == FunctionEvidenceSource::ObjectiveC)
                {
                    RangeSource::ObjCMetadata
                } else {
                    RangeSource::Inferred
                };
                let entity = match &function.identity {
                    FunctionIdentity::Named { primary, .. }
                        if source == RangeSource::ObjCMetadata =>
                    {
                        objc_entity(primary).unwrap_or_else(|| CodeEntity::Symbol {
                            name: primary.clone(),
                            external: false,
                        })
                    }
                    FunctionIdentity::Named { primary, .. } => CodeEntity::Symbol {
                        name: primary.clone(),
                        external: false,
                    },
                    FunctionIdentity::Anonymous { .. } => CodeEntity::Anonymous {
                        section_name: macho
                            .all_sections()
                            .find(|section| {
                                section.addr().0 <= function.entry
                                    && function.entry
                                        < section.addr().0.saturating_add(section.size())
                            })
                            .map_or_else(String::new, |section| section.section_name().to_string()),
                    },
                };
                RangeEntry {
                    start: Va(function.entry),
                    end: Va(function.extent.map_or_else(
                        || function.entry.saturating_add(1),
                        |extent| extent.end_exclusive,
                    )),
                    entity,
                    source,
                    is_alt_entry: function
                        .evidence
                        .iter()
                        .any(|evidence| evidence.detail == "nlist_alt_entry"),
                }
            })
            .collect();
        Self { entries, truncated }
    }

    /// Performs lookup_va.
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

    /// Performs lookup_file_offset.
    pub fn lookup_file_offset(
        &self,
        offset: ThinFileOffset,
        address_map: &AddressMap,
    ) -> Option<&RangeEntry> {
        let va = address_map.thin_offset_to_va(offset).ok()?;
        self.lookup_va(va)
    }

    /// Performs entries.
    pub fn entries(&self) -> &[RangeEntry] {
        &self.entries
    }

    /// Performs entries_in_range.
    pub fn entries_in_range(&self, start: Va, end: Va) -> &[RangeEntry] {
        let lo = self.entries.partition_point(|e| e.start < start);
        let hi = self.entries.partition_point(|e| e.start < end);
        &self.entries[lo..hi]
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns whether input-derived ranges were discarded at the configured
    /// collection bound.
    pub fn was_truncated(&self) -> bool {
        self.truncated
    }
}

fn objc_entity(name: &str) -> Option<CodeEntity> {
    let is_class_method = name.starts_with("+[");
    if !is_class_method && !name.starts_with("-[") {
        return None;
    }
    let body = name.get(2..name.len().checked_sub(1)?)?;
    let (class, selector) = body.split_once(' ')?;
    let class_name = class.split_once('(').map_or(class, |(class, _)| class);
    Some(CodeEntity::ObjCMethod {
        class_name: class_name.to_owned(),
        selector: selector.to_owned(),
        is_class_method,
    })
}

impl<'data> MachoExt<'data> for SymbolRangeIndex {
    type Error = crate::AnalysisError;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        Self::build(macho)
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
    use crate::functions::FunctionRecoveryLimits;

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

    #[test]
    fn legacy_ranges_project_function_index_extents_without_rederiving_adjacency() {
        let bytes = macho_test_support::disassembly_x86_64();
        let container = macho_core::parse(&bytes).unwrap();
        let macho = container.first_macho().unwrap();
        let functions = FunctionIndex::recover(macho, FunctionRecoveryLimits::default()).unwrap();
        let ranges = SymbolRangeIndex::from_function_index_limited(macho, &functions, usize::MAX);
        assert_eq!(ranges.entries().len(), functions.functions().len());
        for (range, function) in ranges.entries().iter().zip(functions.functions()) {
            assert_eq!(range.start.0, function.entry);
            assert_eq!(
                range.end.0,
                function.extent.map_or_else(
                    || function.entry.saturating_add(1),
                    |extent| extent.end_exclusive
                )
            );
        }
    }
}
