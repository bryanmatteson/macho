use serde::{Deserialize, Serialize};

use crate::analysis::model::addr::{ThinFileOffset, Va};
use crate::analysis::model::macho_file::MachoFile;
use crate::analysis::model::section::SectionType;

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The StringRegions type.
pub struct StringRegions {
    /// The regions field.
    pub regions: Vec<StringRegion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The StringRegion type.
pub struct StringRegion {
    /// The section_segment field.
    pub section_segment: String,
    /// The section_name field.
    pub section_name: String,
    #[serde(
        serialize_with = "crate::analysis::serde_addr::va",
        deserialize_with = "crate::analysis::serde_addr::va_from"
    )]
    /// The start field.
    pub start: Va,
    /// The size field.
    pub size: u64,
    #[serde(
        serialize_with = "crate::analysis::serde_addr::thin_file_offset",
        deserialize_with = "crate::analysis::serde_addr::thin_file_offset_from"
    )]
    /// The file_offset field.
    pub file_offset: ThinFileOffset,
    /// The kind field.
    pub kind: StringRegionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// The StringRegionKind type.
#[non_exhaustive]
pub enum StringRegionKind {
    /// The CString variant.
    CString,
    /// The ObjCString variant.
    ObjCString,
    /// The SwiftReflection variant.
    SwiftReflection,
    /// The CFString variant.
    CFString,
    /// The Heuristic variant.
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The StringMatch type.
pub struct StringMatch {
    /// The value field.
    pub value: String,
    #[serde(
        serialize_with = "crate::analysis::serde_addr::va",
        deserialize_with = "crate::analysis::serde_addr::va_from"
    )]
    /// The va field.
    pub va: Va,
    #[serde(
        serialize_with = "crate::analysis::serde_addr::thin_file_offset",
        deserialize_with = "crate::analysis::serde_addr::thin_file_offset_from"
    )]
    /// The file_offset field.
    pub file_offset: ThinFileOffset,
    /// The region_index field.
    pub region_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
/// The FoundString type.
pub struct FoundString {
    /// The value field.
    pub value: String,
    #[serde(
        serialize_with = "crate::analysis::serde_addr::va",
        deserialize_with = "crate::analysis::serde_addr::va_from"
    )]
    /// The va field.
    pub va: Va,
    #[serde(
        serialize_with = "crate::analysis::serde_addr::thin_file_offset",
        deserialize_with = "crate::analysis::serde_addr::thin_file_offset_from"
    )]
    /// The file_offset field.
    pub file_offset: ThinFileOffset,
}

impl StringRegions {
    /// Performs discover.
    pub fn discover(macho: &MachoFile<'_>) -> Self {
        let mut regions = Vec::new();

        for section in macho.all_sections() {
            let seg = section.segment_name().as_str_lossy();
            let sect = section.section_name().as_str_lossy();

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
            } else if section.section_type() == SectionType::CStringLiterals {
                Some(StringRegionKind::CString)
            } else {
                None
            };

            if let Some(kind) = kind {
                regions.push(StringRegion {
                    section_segment: seg.into_owned(),
                    section_name: sect.into_owned(),
                    start: section.addr(),
                    size: section.size(),
                    file_offset: section.offset(),
                    kind,
                });
            }
        }

        Self { regions }
    }

    /// Performs with_heuristic.
    pub fn with_heuristic(macho: &MachoFile<'_>) -> Self {
        let mut result = Self::discover(macho);

        for section in macho.all_sections() {
            if section.section_type() != SectionType::Regular {
                continue;
            }

            let seg = section.segment_name().as_str_lossy();
            if seg != "__TEXT" && seg != "__RODATA" {
                continue;
            }

            let sect = section.section_name().as_str_lossy();

            // Skip sections we already classified
            let already_present = result
                .regions
                .iter()
                .any(|r| r.section_segment == seg.as_ref() && r.section_name == sect.as_ref());
            if already_present {
                continue;
            }

            if section.size() == 0 {
                continue;
            }

            let bytes = match macho.read_bytes_at(section.offset(), section.size() as usize) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if is_heuristic_string_section(bytes) {
                result.regions.push(StringRegion {
                    section_segment: seg.into_owned(),
                    section_name: sect.into_owned(),
                    start: section.addr(),
                    size: section.size(),
                    file_offset: section.offset(),
                    kind: StringRegionKind::Heuristic,
                });
            }
        }

        result
    }

    /// Performs search.
    pub fn search(&self, macho: &MachoFile<'_>, query: &str) -> Vec<StringMatch> {
        let mut matches = Vec::new();

        for (region_index, region) in self.regions.iter().enumerate() {
            // CFString sections contain struct data (pointers + length),
            // not raw null-terminated C strings. Skip them for C-string search.
            if region.kind == StringRegionKind::CFString {
                continue;
            }

            let bytes = match macho.read_bytes_at(region.file_offset, region.size as usize) {
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

    /// Performs search_exact.
    pub fn search_exact(&self, macho: &MachoFile<'_>, query: &str) -> Vec<StringMatch> {
        let mut matches = Vec::new();

        for (region_index, region) in self.regions.iter().enumerate() {
            if region.kind == StringRegionKind::CFString {
                continue;
            }

            let bytes = match macho.read_bytes_at(region.file_offset, region.size as usize) {
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

    /// Performs strings_in_region.
    pub fn strings_in_region(
        &self,
        macho: &MachoFile<'_>,
        region: &StringRegion,
    ) -> Vec<FoundString> {
        // CFString sections contain struct data, not raw C strings.
        if region.kind == StringRegionKind::CFString {
            return Vec::new();
        }

        let bytes = match macho.read_bytes_at(region.file_offset, region.size as usize) {
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

    /// Performs all_strings.
    pub fn all_strings(&self, macho: &MachoFile<'_>) -> Vec<FoundString> {
        self.all_strings_limited(macho, usize::MAX).0
    }

    /// Collect at most `limit` strings and report whether additional input was skipped.
    pub fn all_strings_limited(
        &self,
        macho: &MachoFile<'_>,
        limit: usize,
    ) -> (Vec<FoundString>, bool) {
        let mut all = Vec::new();
        for region in &self.regions {
            if all.len() == limit {
                return (all, true);
            }
            if region.kind == StringRegionKind::CFString {
                continue;
            }
            let bytes = match macho.read_bytes_at(region.file_offset, region.size as usize) {
                Ok(bytes) => bytes,
                Err(_) => continue,
            };
            let remaining = limit - all.len();
            let (values, truncated) = extract_cstrings_limited(bytes, remaining);
            all.extend(
                values
                    .into_iter()
                    .map(|(value, offset_in_region)| FoundString {
                        value,
                        va: Va(region.start.0 + offset_in_region as u64),
                        file_offset: ThinFileOffset(region.file_offset.0 + offset_in_region as u64),
                    }),
            );
            if truncated {
                return (all, true);
            }
        }
        (all, false)
    }

    /// Performs regions.
    pub fn regions(&self) -> &[StringRegion] {
        &self.regions
    }
}

fn extract_cstrings(bytes: &[u8]) -> Vec<(String, usize)> {
    extract_cstrings_limited(bytes, usize::MAX).0
}

fn extract_cstrings_limited(bytes: &[u8], limit: usize) -> (Vec<(String, usize)>, bool) {
    let mut results = Vec::new();
    let mut start = 0;

    while start < bytes.len() {
        if results.len() == limit {
            return (results, true);
        }
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

    (results, false)
}

pub(crate) fn is_heuristic_string_section(bytes: &[u8]) -> bool {
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
