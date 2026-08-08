//! Image-bound string inventory and address queries for disassembly annotation.

use crate::core::model::addr::ThinFileOffset;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::section::SectionType;
use crate::metadata::dyld::resolve::{PointerResolver, PointerTarget};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;
use crate::analysis::strings::{
    StringRegion, StringRegionKind, StringRegions, is_heuristic_string_section,
};

/// Explicit limits for one string inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringRecoveryLimits {
    /// Maximum total bytes scanned across admitted regions.
    pub max_scanned_bytes: usize,
    /// Maximum strings retained.
    pub max_strings: usize,
    /// Maximum bytes retained in one UTF-8 string.
    pub max_string_bytes: usize,
    /// Whether regular text/rodata sections passing the heuristic are admitted.
    pub include_heuristic_regions: bool,
}

impl Default for StringRecoveryLimits {
    fn default() -> Self {
        Self {
            max_scanned_bytes: 256 * 1024 * 1024,
            max_strings: 4_000_000,
            max_string_bytes: 1_048_576,
            include_heuristic_regions: false,
        }
    }
}

impl StringRecoveryLimits {
    /// Reject zero-valued numeric limits.
    pub fn validate(self) -> Result<Self, StringRecoveryError> {
        if self.max_scanned_bytes == 0 || self.max_strings == 0 || self.max_string_bytes == 0 {
            return Err(StringRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing string recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StringRecoveryError {
    /// At least one numeric limit is zero.
    #[error("string recovery limits must be non-zero")]
    InvalidLimits,
}

/// Completion state for the string inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StringIndexStatus {
    /// Every admitted region was read and every valid string retained.
    Complete,
    /// At least one admitted region could not be read.
    Partial,
    /// An explicit byte, count, or per-string limit omitted evidence.
    Truncated,
}

/// One owned UTF-8 string and its exact image location.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredString {
    /// Exact decoded UTF-8 contents.
    pub value: String,
    /// Address of the first byte.
    pub address: u64,
    /// Thin-image file offset of the first byte.
    pub file_offset: u64,
    /// Segment containing the bytes.
    pub segment: String,
    /// Section containing the bytes.
    pub section: String,
    /// Region classification.
    pub kind: StringRegionKind,
    /// Address of a referenceable constant object wrapping these bytes.
    ///
    /// This is present for `__cfstring` records and absent for direct string
    /// literals.
    pub object_address: Option<u64>,
    /// Thin-image file offset of the wrapping constant object.
    pub object_file_offset: Option<u64>,
}

/// Completeness and work receipt for string recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StringIndexCompleteness {
    /// Overall status.
    pub status: StringIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Number of admitted regions.
    pub region_count: u64,
    /// Bytes actually scanned.
    pub scanned_bytes: u64,
    /// Valid UTF-8 strings observed, including omitted strings.
    pub observed_strings: u64,
    /// Strings omitted by explicit limits.
    pub omitted_strings: u64,
}

/// Deterministic string inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringIndex {
    image: FunctionImageIdentity,
    limits: StringRecoveryLimits,
    strings: Vec<RecoveredString>,
    by_reference: Vec<usize>,
    completeness: StringIndexCompleteness,
}

impl StringIndex {
    /// Recover strings from typed sections and optionally heuristic regions.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: StringRecoveryLimits,
    ) -> Result<Self, StringRecoveryError> {
        let limits = limits.validate()?;
        let typed_regions = StringRegions::discover(macho).regions;
        let mut state = StringRecoveryState {
            region_count: typed_regions.len() as u64,
            ..StringRecoveryState::default()
        };
        for region in &typed_regions {
            if region.kind == StringRegionKind::CFString {
                state.scan_cfstrings(macho, region, limits);
                continue;
            }
            let remaining = limits.max_scanned_bytes.saturating_sub(state.scanned_bytes);
            if remaining == 0 {
                state.budget_exhausted = true;
                break;
            }
            let region_size = usize::try_from(region.size).unwrap_or(usize::MAX);
            let admitted = region_size.min(remaining);
            let Ok(bytes) = macho.read_bytes_at(region.file_offset, admitted) else {
                state.unreadable = true;
                continue;
            };
            state.scanned_bytes = state.scanned_bytes.saturating_add(bytes.len());
            let clipped = admitted < region_size;
            state.scan_region(region, bytes, limits, clipped);
            if clipped {
                state.budget_exhausted = true;
                break;
            }
        }
        if limits.include_heuristic_regions && !state.budget_exhausted {
            for section in macho.all_sections() {
                if section.section_type() != SectionType::Regular || section.size() == 0 {
                    continue;
                }
                let segment = section.segment_name().as_str_lossy();
                if segment != "__TEXT" && segment != "__RODATA" {
                    continue;
                }
                let section_name = section.section_name().as_str_lossy();
                if typed_regions.iter().any(|region| {
                    region.section_segment == segment.as_ref()
                        && region.section_name == section_name.as_ref()
                }) {
                    continue;
                }
                let remaining = limits.max_scanned_bytes.saturating_sub(state.scanned_bytes);
                let Ok(region_size) = usize::try_from(section.size()) else {
                    state.budget_exhausted = true;
                    break;
                };
                if region_size > remaining {
                    state.budget_exhausted = true;
                    break;
                }
                let Ok(bytes) = macho.read_bytes_at(section.offset(), region_size) else {
                    state.unreadable = true;
                    continue;
                };
                state.scanned_bytes = state.scanned_bytes.saturating_add(bytes.len());
                if !is_heuristic_string_section(bytes) {
                    continue;
                }
                state.region_count = state.region_count.saturating_add(1);
                let region = StringRegion {
                    section_segment: segment.into_owned(),
                    section_name: section_name.into_owned(),
                    start: section.addr(),
                    size: section.size(),
                    file_offset: section.offset(),
                    kind: StringRegionKind::Heuristic,
                };
                state.scan_region(&region, bytes, limits, false);
            }
        }
        state.strings.sort_by_key(|value| value.address);
        let mut by_reference = (0..state.strings.len()).collect::<Vec<_>>();
        by_reference.sort_by_key(|index| {
            let value = &state.strings[*index];
            (value.object_address.unwrap_or(value.address), value.address)
        });
        let status = if state.budget_exhausted || state.omitted_strings != 0 {
            StringIndexStatus::Truncated
        } else if state.unreadable || state.malformed_cfstrings || state.malformed_region {
            StringIndexStatus::Partial
        } else {
            StringIndexStatus::Complete
        };
        let mut reasons = Vec::new();
        if state.budget_exhausted {
            reasons.push("strings.scan_budget".to_owned());
        }
        if state.omitted_strings != 0 {
            reasons.push("strings.retention_budget".to_owned());
        }
        if state.unreadable {
            reasons.push("strings.unreadable_region".to_owned());
        }
        if state.malformed_cfstrings {
            reasons.push("strings.cfstring_malformed".to_owned());
        }
        if state.malformed_region {
            reasons.push("strings.unterminated_region".to_owned());
        }
        Ok(Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            strings: state.strings,
            by_reference,
            completeness: StringIndexCompleteness {
                status,
                reasons,
                region_count: state.region_count,
                scanned_bytes: state.scanned_bytes as u64,
                observed_strings: state.observed_strings,
                omitted_strings: state.omitted_strings,
            },
        })
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact recovery limits.
    pub const fn limits(&self) -> StringRecoveryLimits {
        self.limits
    }

    /// Strings sorted by starting address.
    pub fn strings(&self) -> &[RecoveredString] {
        &self.strings
    }

    /// Completeness and work receipt.
    pub fn completeness(&self) -> &StringIndexCompleteness {
        &self.completeness
    }

    /// Overall string-inventory status.
    pub const fn status(&self) -> StringIndexStatus {
        self.completeness.status
    }

    /// Find a string beginning at an exact address.
    pub fn by_address(&self, address: u64) -> Option<&RecoveredString> {
        self.strings
            .binary_search_by_key(&address, |value| value.address)
            .ok()
            .map(|index| &self.strings[index])
    }

    /// Resolve an address used by code to reference a literal.
    ///
    /// Direct strings resolve at their first byte; constant CFStrings resolve
    /// at the `__cfstring` object address as well as at their backing bytes.
    pub fn referenced_at(&self, address: u64) -> Option<&RecoveredString> {
        self.by_address(address).or_else(|| {
            let position = self.by_reference.binary_search_by_key(&address, |index| {
                self.strings[*index]
                    .object_address
                    .unwrap_or(self.strings[*index].address)
            });
            position
                .ok()
                .map(|index| &self.strings[self.by_reference[index]])
        })
    }

    /// Find the retained string whose bytes contain an address.
    pub fn containing(&self, address: u64) -> Option<&RecoveredString> {
        let index = self
            .strings
            .partition_point(|value| value.address <= address);
        index.checked_sub(1).and_then(|index| {
            let value = &self.strings[index];
            let end = value
                .address
                .saturating_add(value.value.len() as u64)
                .saturating_add(1);
            (address < end).then_some(value)
        })
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        let strings_are_sorted = self
            .strings
            .windows(2)
            .all(|pair| pair[0].address <= pair[1].address);
        let mut expected_by_reference = (0..self.strings.len()).collect::<Vec<_>>();
        expected_by_reference.sort_by_key(|index| {
            let value = &self.strings[*index];
            (value.object_address.unwrap_or(value.address), value.address)
        });
        let strings_are_well_formed = self.strings.iter().all(|value| {
            value.value.len() <= self.limits.max_string_bytes
                && value
                    .address
                    .checked_add(value.value.len() as u64)
                    .is_some()
                && value
                    .file_offset
                    .checked_add(value.value.len() as u64)
                    .is_some_and(|end| end <= self.image.byte_len)
                && value.object_address.is_some() == value.object_file_offset.is_some()
                && value
                    .object_file_offset
                    .is_none_or(|offset| offset < self.image.byte_len)
        });
        let has_reason = |expected: &str| {
            self.completeness
                .reasons
                .iter()
                .any(|reason| reason == expected)
        };
        let reasons_are_known = self.completeness.reasons.iter().all(|reason| {
            matches!(
                reason.as_str(),
                "strings.scan_budget"
                    | "strings.retention_budget"
                    | "strings.unreadable_region"
                    | "strings.cfstring_malformed"
                    | "strings.unterminated_region"
            )
        });
        let reasons_are_unique = self
            .completeness
            .reasons
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == self.completeness.reasons.len();
        let expected_status =
            if has_reason("strings.scan_budget") || self.completeness.omitted_strings != 0 {
                StringIndexStatus::Truncated
            } else if has_reason("strings.unreadable_region")
                || has_reason("strings.cfstring_malformed")
                || has_reason("strings.unterminated_region")
            {
                StringIndexStatus::Partial
            } else {
                StringIndexStatus::Complete
            };
        self.limits.validate().is_ok()
            && self.strings.len() <= self.limits.max_strings
            && self.completeness.scanned_bytes <= self.limits.max_scanned_bytes as u64
            && self.completeness.observed_strings
                >= (self.strings.len() as u64).saturating_add(self.completeness.omitted_strings)
            && strings_are_sorted
            && strings_are_well_formed
            && self.by_reference == expected_by_reference
            && reasons_are_known
            && reasons_are_unique
            && has_reason("strings.retention_budget") == (self.completeness.omitted_strings != 0)
            && self.completeness.status == expected_status
    }

    /// Return the exact typed file offset for a retained string.
    pub fn typed_file_offset(value: &RecoveredString) -> ThinFileOffset {
        ThinFileOffset(value.file_offset)
    }
}

#[derive(Default)]
struct StringRecoveryState {
    strings: Vec<RecoveredString>,
    region_count: u64,
    scanned_bytes: usize,
    observed_strings: u64,
    omitted_strings: u64,
    unreadable: bool,
    malformed_cfstrings: bool,
    malformed_region: bool,
    budget_exhausted: bool,
}

impl StringRecoveryState {
    fn scan_cfstrings(
        &mut self,
        macho: &MachoFile<'_>,
        region: &StringRegion,
        limits: StringRecoveryLimits,
    ) {
        let (record_size, pointer_offset, length_offset) = if macho.is_64bit() {
            (32_usize, 16_u64, 24_usize)
        } else {
            (16_usize, 8_u64, 12_usize)
        };
        let Ok(region_size) = usize::try_from(region.size) else {
            self.budget_exhausted = true;
            return;
        };
        if region_size % record_size != 0 {
            self.malformed_cfstrings = true;
        }
        let admitted = region_size.min(limits.max_scanned_bytes.saturating_sub(self.scanned_bytes));
        let complete_records = admitted / record_size;
        if complete_records < region_size / record_size {
            self.budget_exhausted = true;
        }
        let Ok(resolver) = PointerResolver::new(macho) else {
            self.malformed_cfstrings = true;
            return;
        };
        for ordinal in 0..complete_records {
            let relative = ordinal.saturating_mul(record_size);
            let Some(record_offset) = region.file_offset.0.checked_add(relative as u64) else {
                self.malformed_cfstrings = true;
                break;
            };
            let Ok(record) = macho.read_bytes_at(ThinFileOffset(record_offset), record_size) else {
                self.unreadable = true;
                continue;
            };
            self.scanned_bytes = self.scanned_bytes.saturating_add(record.len());
            let length = if macho.is_64bit() {
                macho.endian().read_u64(
                    record[length_offset..length_offset + 8]
                        .try_into()
                        .expect("validated 64-bit CFString record"),
                )
            } else {
                u64::from(
                    macho.endian().read_u32(
                        record[length_offset..length_offset + 4]
                            .try_into()
                            .expect("validated 32-bit CFString record"),
                    ),
                )
            };
            self.observed_strings = self.observed_strings.saturating_add(1);
            let Ok(length) = usize::try_from(length) else {
                self.omitted_strings = self.omitted_strings.saturating_add(1);
                continue;
            };
            if length > limits.max_string_bytes
                || self.strings.len() >= limits.max_strings
                || length > limits.max_scanned_bytes.saturating_sub(self.scanned_bytes)
            {
                self.omitted_strings = self.omitted_strings.saturating_add(1);
                if length > limits.max_scanned_bytes.saturating_sub(self.scanned_bytes) {
                    self.budget_exhausted = true;
                }
                continue;
            }
            let Some(pointer_file_offset) = record_offset.checked_add(pointer_offset) else {
                self.malformed_cfstrings = true;
                continue;
            };
            let target = match resolver.observe_at_offset(ThinFileOffset(pointer_file_offset)) {
                Ok(observation) => match observation.target {
                    PointerTarget::Address(address) => address,
                    PointerTarget::Null | PointerTarget::Import { .. } => {
                        self.malformed_cfstrings = true;
                        continue;
                    }
                },
                Err(_) => {
                    self.malformed_cfstrings = true;
                    continue;
                }
            };
            let Ok(content_offset) = macho.address_map().va_to_thin_offset(target) else {
                self.malformed_cfstrings = true;
                continue;
            };
            let Ok(bytes) = macho.read_bytes_at(content_offset, length) else {
                self.unreadable = true;
                continue;
            };
            self.scanned_bytes = self.scanned_bytes.saturating_add(bytes.len());
            let Ok(value) = std::str::from_utf8(bytes) else {
                self.malformed_cfstrings = true;
                continue;
            };
            let Some(object_address) = region.start.0.checked_add(relative as u64) else {
                self.malformed_cfstrings = true;
                continue;
            };
            self.strings.push(RecoveredString {
                value: value.to_owned(),
                address: target.0,
                file_offset: content_offset.0,
                segment: region.section_segment.clone(),
                section: region.section_name.clone(),
                kind: StringRegionKind::CFString,
                object_address: Some(object_address),
                object_file_offset: Some(record_offset),
            });
        }
    }

    fn scan_region(
        &mut self,
        region: &StringRegion,
        bytes: &[u8],
        limits: StringRecoveryLimits,
        clipped: bool,
    ) {
        let mut start = 0_usize;
        while start < bytes.len() {
            if bytes[start] == 0 {
                start += 1;
                continue;
            }
            let Some(relative_end) = bytes[start..].iter().position(|byte| *byte == 0) else {
                if !clipped {
                    self.malformed_region = true;
                }
                return;
            };
            let end = start + relative_end;
            let value = &bytes[start..end];
            if let Ok(value) = std::str::from_utf8(value)
                && !value.is_empty()
            {
                self.observed_strings = self.observed_strings.saturating_add(1);
                if self.strings.len() >= limits.max_strings || value.len() > limits.max_string_bytes
                {
                    self.omitted_strings = self.omitted_strings.saturating_add(1);
                } else if let (Some(address), Some(file_offset)) = (
                    region.start.0.checked_add(start as u64),
                    region.file_offset.0.checked_add(start as u64),
                ) {
                    self.strings.push(RecoveredString {
                        value: value.to_owned(),
                        address,
                        file_offset,
                        segment: region.section_segment.clone(),
                        section: region.section_name.clone(),
                        kind: region.kind.clone(),
                        object_address: None,
                        object_file_offset: None,
                    });
                } else {
                    self.malformed_region = true;
                }
            }
            start = end.saturating_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::core::model::container::MachoContainer;

    use super::*;

    fn image(bytes: &[u8]) -> MachoFile<'_> {
        match crate::core::parse(bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        }
    }

    #[test]
    fn heuristic_classification_obeys_the_total_scan_budget() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0xa8..0xac].copy_from_slice(&0_u32.to_le_bytes());
        let index = StringIndex::recover(
            &image(&bytes),
            StringRecoveryLimits {
                max_scanned_bytes: 8,
                include_heuristic_regions: true,
                ..StringRecoveryLimits::default()
            },
        )
        .unwrap();
        assert!(index.durable_invariants_hold());
        assert_eq!(index.status(), StringIndexStatus::Truncated);
        assert!(index.completeness().scanned_bytes <= 8);
        assert!(
            index
                .completeness()
                .reasons
                .contains(&"strings.scan_budget".to_owned())
        );
    }

    #[test]
    fn constant_cfstrings_resolve_at_object_and_backing_addresses() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0x68..0x78].fill(0);
        bytes[0x68..0x72].copy_from_slice(b"__cfstring");
        bytes[0x90..0x98].copy_from_slice(&32_u64.to_le_bytes());
        bytes[0x100..0x140].fill(0);
        bytes[0x110..0x118].copy_from_slice(&0x1_0000_0130_u64.to_le_bytes());
        bytes[0x118..0x120].copy_from_slice(&5_u64.to_le_bytes());
        bytes[0x130..0x135].copy_from_slice(b"hello");

        let index = StringIndex::recover(&image(&bytes), StringRecoveryLimits::default()).unwrap();
        assert!(index.durable_invariants_hold());
        let value = index
            .referenced_at(0x1_0000_0100)
            .expect("CFString object is referenceable");
        assert_eq!(value.value, "hello");
        assert_eq!(value.address, 0x1_0000_0130);
        assert_eq!(value.object_address, Some(0x1_0000_0100));
        assert_eq!(
            index
                .referenced_at(0x1_0000_0130)
                .map(|value| value.value.as_str()),
            Some("hello")
        );
        assert_eq!(index.status(), StringIndexStatus::Complete);
    }

    #[test]
    fn unterminated_typed_region_is_partial_not_complete() {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[0xa8..0xac].copy_from_slice(&2_u32.to_le_bytes());
        bytes[0x100..0x140].fill(b'a');
        let index = StringIndex::recover(&image(&bytes), StringRecoveryLimits::default()).unwrap();
        assert!(index.durable_invariants_hold());
        assert_eq!(index.status(), StringIndexStatus::Partial);
        assert!(
            index
                .completeness()
                .reasons
                .contains(&"strings.unterminated_region".to_owned())
        );
    }
}
