//! Indexed segment, section, and address-translation facts for one image.

use crate::core::model::macho_file::MachoFile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;

/// Explicit retention limits for image layout facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageLayoutLimits {
    /// Maximum segments retained.
    pub max_segments: usize,
    /// Maximum sections retained.
    pub max_sections: usize,
}

impl Default for ImageLayoutLimits {
    fn default() -> Self {
        Self {
            max_segments: 1_000_000,
            max_sections: 4_000_000,
        }
    }
}

impl ImageLayoutLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, ImageLayoutError> {
        if self.max_segments == 0 || self.max_sections == 0 {
            return Err(ImageLayoutError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing layout indexing from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ImageLayoutError {
    /// At least one limit is zero.
    #[error("image layout limits must be non-zero")]
    InvalidLimits,
}

/// One normalized segment range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSegment {
    /// Load-command ordinal.
    pub ordinal: u64,
    /// Segment name.
    pub name: String,
    /// Virtual start address.
    pub address: u64,
    /// Virtual size.
    pub size: u64,
    /// Thin-image file offset.
    pub file_offset: u64,
    /// File-backed size.
    pub file_size: u64,
    /// Initial virtual-memory protection as `rwx` text.
    pub protection: String,
    /// Raw segment flags.
    pub flags: u32,
}

/// One normalized section range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageSection {
    /// Global section ordinal in segment/load-command order.
    pub ordinal: u64,
    /// Containing segment name.
    pub segment: String,
    /// Section name.
    pub name: String,
    /// Virtual start address.
    pub address: u64,
    /// Virtual size.
    pub size: u64,
    /// Thin-image file offset.
    pub file_offset: u64,
    /// Whether the section has readable file-backed contents.
    pub file_backed: bool,
    /// Base-two alignment exponent.
    pub alignment: u32,
    /// Mach-O section type spelling.
    pub section_type: String,
    /// Raw section attribute flags.
    pub attributes: u32,
}

/// Completeness receipt for retained layout facts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImageLayoutCompleteness {
    /// Whether every segment and section was retained.
    pub complete: bool,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Segments observed before retention limits.
    pub observed_segments: u64,
    /// Sections observed before retention limits.
    pub observed_sections: u64,
}

/// Deterministic address-layout index for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageLayoutIndex {
    image: FunctionImageIdentity,
    limits: ImageLayoutLimits,
    segments: Vec<ImageSegment>,
    sections: Vec<ImageSection>,
    completeness: ImageLayoutCompleteness,
}

impl ImageLayoutIndex {
    /// Retain normalized layout facts with explicit count limits.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: ImageLayoutLimits,
    ) -> Result<Self, ImageLayoutError> {
        let limits = limits.validate()?;
        let observed_segments = macho.segments().len();
        let observed_sections = macho.all_sections().count();
        let mut segments = macho
            .segments()
            .iter()
            .take(limits.max_segments)
            .enumerate()
            .map(|(ordinal, segment)| ImageSegment {
                ordinal: ordinal as u64,
                name: segment.name().to_string(),
                address: segment.vm_addr().0,
                size: segment.vm_size(),
                file_offset: segment.file_offset().0,
                file_size: segment.file_size(),
                protection: segment.init_prot().rwx_string(),
                flags: segment.flags().bits(),
            })
            .collect::<Vec<_>>();
        let mut sections = macho
            .all_sections()
            .take(limits.max_sections)
            .enumerate()
            .map(|(ordinal, section)| ImageSection {
                ordinal: ordinal as u64,
                segment: section.segment_name().to_string(),
                name: section.section_name().to_string(),
                address: section.addr().0,
                size: section.size(),
                file_offset: section.offset().0,
                file_backed: !section.section_type().is_zerofill()
                    && section
                        .offset()
                        .0
                        .checked_add(section.size())
                        .is_some_and(|end| end <= macho.file_size() as u64),
                alignment: section.align(),
                section_type: section.section_type().name().to_owned(),
                attributes: section.attributes().bits(),
            })
            .collect::<Vec<_>>();
        segments.sort_by_key(|segment| (segment.address, segment.ordinal));
        sections.sort_by_key(|section| (section.address, section.ordinal));
        let mut reasons = Vec::new();
        if observed_segments > segments.len() {
            reasons.push("layout.segment_budget".to_owned());
        }
        if observed_sections > sections.len() {
            reasons.push("layout.section_budget".to_owned());
        }
        Ok(Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            segments,
            sections,
            completeness: ImageLayoutCompleteness {
                complete: reasons.is_empty(),
                reasons,
                observed_segments: observed_segments as u64,
                observed_sections: observed_sections as u64,
            },
        })
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact retention limits.
    pub const fn limits(&self) -> ImageLayoutLimits {
        self.limits
    }

    /// Segments sorted by virtual address.
    pub fn segments(&self) -> &[ImageSegment] {
        &self.segments
    }

    /// Sections sorted by virtual address.
    pub fn sections(&self) -> &[ImageSection] {
        &self.sections
    }

    /// Completeness and retention receipt.
    pub const fn completeness(&self) -> &ImageLayoutCompleteness {
        &self.completeness
    }

    /// Find the retained segment containing an address.
    pub fn segment_containing(&self, address: u64) -> Option<&ImageSegment> {
        let end = self
            .segments
            .partition_point(|segment| segment.address <= address);
        self.segments[..end].iter().rev().find(|segment| {
            segment
                .address
                .checked_add(segment.size)
                .is_some_and(|limit| address < limit)
        })
    }

    /// Find the retained section containing an address.
    pub fn section_containing(&self, address: u64) -> Option<&ImageSection> {
        let end = self
            .sections
            .partition_point(|section| section.address <= address);
        self.sections[..end].iter().rev().find(|section| {
            section
                .address
                .checked_add(section.size)
                .is_some_and(|limit| address < limit)
        })
    }

    /// Translate one virtual address into a thin-image file offset.
    pub fn file_offset_for_address(&self, address: u64) -> Option<u64> {
        let segment = self.segment_containing(address)?;
        let relative = address.checked_sub(segment.address)?;
        (relative < segment.file_size).then(|| segment.file_offset + relative)
    }

    /// Translate one thin-image file offset into a virtual address.
    pub fn address_for_file_offset(&self, file_offset: u64) -> Option<u64> {
        self.segments.iter().find_map(|segment| {
            let relative = file_offset.checked_sub(segment.file_offset)?;
            (relative < segment.file_size).then(|| segment.address + relative)
        })
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        let segments_are_sorted = self
            .segments
            .windows(2)
            .all(|pair| (pair[0].address, pair[0].ordinal) < (pair[1].address, pair[1].ordinal));
        let sections_are_sorted = self
            .sections
            .windows(2)
            .all(|pair| (pair[0].address, pair[0].ordinal) < (pair[1].address, pair[1].ordinal));
        let segments_are_well_formed = self.segments.iter().all(|segment| {
            segment.file_size <= segment.size
                && segment.address.checked_add(segment.size).is_some()
                && segment
                    .file_offset
                    .checked_add(segment.file_size)
                    .is_some_and(|end| end <= self.image.byte_len)
        });
        let sections_are_well_formed = self.sections.iter().all(|section| {
            section.address.checked_add(section.size).is_some()
                && (!section.file_backed
                    || section
                        .file_offset
                        .checked_add(section.size)
                        .is_some_and(|end| end <= self.image.byte_len))
        });
        let observed_segments = self.completeness.observed_segments;
        let observed_sections = self.completeness.observed_sections;
        let mut expected_reasons = Vec::new();
        if observed_segments > self.segments.len() as u64 {
            expected_reasons.push("layout.segment_budget".to_owned());
        }
        if observed_sections > self.sections.len() as u64 {
            expected_reasons.push("layout.section_budget".to_owned());
        }
        self.limits.validate().is_ok()
            && self.segments.len() <= self.limits.max_segments
            && self.sections.len() <= self.limits.max_sections
            && observed_segments >= self.segments.len() as u64
            && observed_sections >= self.sections.len() as u64
            && segments_are_sorted
            && sections_are_sorted
            && segments_are_well_formed
            && sections_are_well_formed
            && self.completeness.complete == expected_reasons.is_empty()
            && self.completeness.reasons == expected_reasons
    }
}
