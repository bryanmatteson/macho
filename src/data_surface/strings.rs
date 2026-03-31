use serde::Serialize;

use crate::addr::{ThinFileOffset, Va};
use crate::model::mach::MachFile;
use crate::model::section::SectionType;

#[derive(Debug, Clone, Serialize)]
pub struct StringRegions {
    pub regions: Vec<StringRegion>,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringRegion {
    pub section_segment: String,
    pub section_name: String,
    pub start: Va,
    pub size: u64,
    pub file_offset: ThinFileOffset,
    pub kind: StringRegionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum StringRegionKind {
    CString,
    ObjCString,
    SwiftReflection,
    CFString,
    Heuristic,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringMatch {
    pub value: String,
    pub va: Va,
    pub file_offset: ThinFileOffset,
    pub region_index: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FoundString {
    pub value: String,
    pub va: Va,
    pub file_offset: ThinFileOffset,
}

impl StringRegions {
    pub fn discover(mach: &MachFile<'_>) -> Self {
        let mut regions = Vec::new();

        for section in mach.all_sections() {
            let seg = section.segment_name.as_str_lossy();
            let sect = section.section_name.as_str_lossy();

            // Check name-based classification first so ObjC/Swift sections
            // with S_CSTRING_LITERALS type get the more specific kind.
            let kind = if sect == "__objc_methnames"
                || sect == "__objc_methname"
                || sect == "__objc_classname"
                || sect == "__objc_methtype"
            {
                Some(StringRegionKind::ObjCString)
            } else if sect == "__swift5_reflstr" {
                Some(StringRegionKind::SwiftReflection)
            } else if sect == "__cfstring" {
                Some(StringRegionKind::CFString)
            } else if section.section_type == SectionType::CStringLiterals {
                Some(StringRegionKind::CString)
            } else {
                None
            };

            if let Some(kind) = kind {
                regions.push(StringRegion {
                    section_segment: seg.into_owned(),
                    section_name: sect.into_owned(),
                    start: section.addr,
                    size: section.size,
                    file_offset: section.offset,
                    kind,
                });
            }
        }

        Self { regions }
    }

    pub fn with_heuristic(mach: &MachFile<'_>) -> Self {
        let mut result = Self::discover(mach);

        for section in mach.all_sections() {
            if section.section_type != SectionType::Regular {
                continue;
            }

            let seg = section.segment_name.as_str_lossy();
            if seg != "__TEXT" && seg != "__RODATA" {
                continue;
            }

            let sect = section.section_name.as_str_lossy();

            // Skip sections we already classified
            let already_present = result
                .regions
                .iter()
                .any(|r| r.section_segment == seg.as_ref() && r.section_name == sect.as_ref());
            if already_present {
                continue;
            }

            if section.size == 0 {
                continue;
            }

            let bytes = match mach.read_bytes_at(section.offset, section.size as usize) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if is_heuristic_string_section(bytes) {
                result.regions.push(StringRegion {
                    section_segment: seg.into_owned(),
                    section_name: sect.into_owned(),
                    start: section.addr,
                    size: section.size,
                    file_offset: section.offset,
                    kind: StringRegionKind::Heuristic,
                });
            }
        }

        result
    }

    pub fn search(&self, mach: &MachFile<'_>, query: &str) -> Vec<StringMatch> {
        let mut matches = Vec::new();

        for (region_index, region) in self.regions.iter().enumerate() {
            // CFString sections contain struct data (pointers + length),
            // not raw null-terminated C strings. Skip them for C-string search.
            if region.kind == StringRegionKind::CFString {
                continue;
            }

            let bytes = match mach.read_bytes_at(region.file_offset, region.size as usize) {
                Ok(b) => b,
                Err(_) => continue,
            };

            for (value, offset_in_region) in extract_cstrings(bytes) {
                if value.contains(query) {
                    let file_offset =
                        ThinFileOffset(region.file_offset.0 + offset_in_region as u64);
                    let va = Va(region.start.0 + offset_in_region as u64);
                    matches.push(StringMatch {
                        value,
                        va,
                        file_offset,
                        region_index,
                    });
                }
            }
        }

        matches
    }

    pub fn search_exact(&self, mach: &MachFile<'_>, query: &str) -> Vec<StringMatch> {
        let mut matches = Vec::new();

        for (region_index, region) in self.regions.iter().enumerate() {
            if region.kind == StringRegionKind::CFString {
                continue;
            }

            let bytes = match mach.read_bytes_at(region.file_offset, region.size as usize) {
                Ok(b) => b,
                Err(_) => continue,
            };

            for (value, offset_in_region) in extract_cstrings(bytes) {
                if value == query {
                    let file_offset =
                        ThinFileOffset(region.file_offset.0 + offset_in_region as u64);
                    let va = Va(region.start.0 + offset_in_region as u64);
                    matches.push(StringMatch {
                        value,
                        va,
                        file_offset,
                        region_index,
                    });
                }
            }
        }

        matches
    }

    pub fn strings_in_region(
        &self,
        mach: &MachFile<'_>,
        region: &StringRegion,
    ) -> Vec<FoundString> {
        // CFString sections contain struct data, not raw C strings.
        if region.kind == StringRegionKind::CFString {
            return Vec::new();
        }

        let bytes = match mach.read_bytes_at(region.file_offset, region.size as usize) {
            Ok(b) => b,
            Err(_) => return Vec::new(),
        };

        extract_cstrings(bytes)
            .into_iter()
            .map(|(value, offset_in_region)| {
                let file_offset = ThinFileOffset(region.file_offset.0 + offset_in_region as u64);
                let va = Va(region.start.0 + offset_in_region as u64);
                FoundString {
                    value,
                    va,
                    file_offset,
                }
            })
            .collect()
    }

    pub fn all_strings(&self, mach: &MachFile<'_>) -> Vec<FoundString> {
        let mut all = Vec::new();
        for region in &self.regions {
            all.extend(self.strings_in_region(mach, region));
        }
        all
    }

    pub fn regions(&self) -> &[StringRegion] {
        &self.regions
    }
}

fn extract_cstrings(bytes: &[u8]) -> Vec<(String, usize)> {
    let mut results = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        // Skip leading nulls
        if bytes[start] == 0 {
            start += 1;
            continue;
        }

        // Find the null terminator
        let end = bytes[start..]
            .iter()
            .position(|&b| b == 0)
            .map(|pos| start + pos)
            .unwrap_or(bytes.len());

        let slice = &bytes[start..end];
        if let Ok(s) = std::str::from_utf8(slice) {
            if !s.is_empty() {
                results.push((s.to_owned(), start));
            }
        }

        start = end + 1;
    }

    results
}

fn is_heuristic_string_section(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return false;
    }

    let printable_or_null = bytes
        .iter()
        .filter(|&&b| b.is_ascii_graphic() || b.is_ascii_whitespace() || b == 0)
        .count();

    let ratio = printable_or_null as f64 / bytes.len() as f64;
    ratio >= 0.80
}
