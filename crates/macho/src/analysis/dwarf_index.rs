//! Bounded image-bound DWARF traversal and source-address recovery.

use crate::core::model::macho_file::MachoFile;
use crate::metadata::dwarf::{DwarfTraversal, DwarfTraversalLimits, traverse_dwarf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;

/// Explicit limits for one DWARF inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwarfRecoveryLimits {
    /// Maximum combined uncompressed section bytes.
    pub max_section_bytes: u64,
    /// Maximum compilation or type units.
    pub max_units: u64,
    /// Maximum retained DIEs.
    pub max_entries: u64,
    /// Maximum retained attributes.
    pub max_attributes: u64,
    /// Maximum retained physical line rows.
    pub max_line_rows: u64,
    /// Maximum retained raw range-list entries.
    pub max_range_entries: u64,
}

impl Default for DwarfRecoveryLimits {
    fn default() -> Self {
        let limits = DwarfTraversalLimits::default();
        Self {
            max_section_bytes: limits.max_section_bytes,
            max_units: limits.max_units,
            max_entries: limits.max_entries,
            max_attributes: limits.max_attributes,
            max_line_rows: limits.max_line_rows,
            max_range_entries: limits.max_range_entries,
        }
    }
}

impl DwarfRecoveryLimits {
    /// Reject zero-valued limits.
    pub fn validate(self) -> Result<Self, DwarfRecoveryError> {
        if self.max_section_bytes == 0
            || self.max_units == 0
            || self.max_entries == 0
            || self.max_attributes == 0
            || self.max_line_rows == 0
            || self.max_range_entries == 0
        {
            return Err(DwarfRecoveryError::InvalidLimits);
        }
        Ok(self)
    }

    const fn traversal(self) -> DwarfTraversalLimits {
        DwarfTraversalLimits {
            max_section_bytes: self.max_section_bytes,
            max_units: self.max_units,
            max_entries: self.max_entries,
            max_attributes: self.max_attributes,
            max_line_rows: self.max_line_rows,
            max_range_entries: self.max_range_entries,
        }
    }
}

/// Failure preventing DWARF recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum DwarfRecoveryError {
    /// At least one limit is zero.
    #[error("DWARF recovery limits must be non-zero")]
    InvalidLimits,
}

/// DWARF inventory completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DwarfIndexStatus {
    /// No supported in-image DWARF sections exist.
    Absent,
    /// Every supported unit, entry, attribute, line row, and range was traversed.
    Complete,
    /// DWARF exists but malformed, external, or unsupported evidence prevented traversal.
    Partial,
    /// An explicit structural limit prevented traversal.
    Truncated,
}

/// Addressable source-line annotation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwarfLineAnnotation {
    /// Image virtual address.
    pub address: u64,
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// Address-sequence ordinal.
    pub sequence: u64,
    /// Source file index within the unit line table.
    pub file_index: u64,
    /// One-based source line.
    pub line: Option<u64>,
    /// One-based source column.
    pub column: Option<u64>,
    /// Whether this row terminates the address sequence.
    pub end_sequence: bool,
}

/// Completeness and work receipt for DWARF recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DwarfIndexCompleteness {
    /// Overall status.
    pub status: DwarfIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Supported DWARF sections retained.
    pub sections: u64,
    /// Compilation or type units retained.
    pub units: u64,
    /// DIEs retained.
    pub entries: u64,
    /// Attributes retained.
    pub attributes: u64,
    /// Physical line rows retained.
    pub line_rows: u64,
    /// Raw range-list entries retained.
    pub range_entries: u64,
}

/// Deterministic bounded DWARF inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DwarfIndex {
    image: FunctionImageIdentity,
    limits: DwarfRecoveryLimits,
    lines: Vec<DwarfLineAnnotation>,
    completeness: DwarfIndexCompleteness,
    diagnostic: Option<String>,
    traversal: Option<DwarfTraversal>,
}

impl DwarfIndex {
    /// Traverse every supported in-image DWARF source with explicit limits.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: DwarfRecoveryLimits,
    ) -> Result<Self, DwarfRecoveryError> {
        let limits = limits.validate()?;
        let (traversal, diagnostic, mut completeness) =
            match traverse_dwarf(macho, limits.traversal()) {
                Ok(None) => (None, None, empty_completeness(DwarfIndexStatus::Absent)),
                Ok(Some(traversal)) => {
                    let partial_ranges = traversal
                        .range_lists
                        .iter()
                        .any(|range| range.coverage != "complete")
                        || traversal
                            .range_entries
                            .iter()
                            .any(|range| range.limitation.is_some());
                    let status = if partial_ranges {
                        DwarfIndexStatus::Partial
                    } else {
                        DwarfIndexStatus::Complete
                    };
                    let mut completeness = traversal_completeness(&traversal, status);
                    if partial_ranges {
                        completeness.reasons.push("dwarf.range_partial".to_owned());
                    }
                    (Some(traversal), None, completeness)
                }
                Err(error) => {
                    let diagnostic = error.to_string();
                    let truncated = diagnostic.contains("limit")
                        || diagnostic.contains("maximum")
                        || diagnostic.contains("exceed");
                    let status = if truncated {
                        DwarfIndexStatus::Truncated
                    } else {
                        DwarfIndexStatus::Partial
                    };
                    let mut completeness = empty_completeness(status);
                    completeness.reasons.push(if truncated {
                        "dwarf.structural_limit".to_owned()
                    } else {
                        "dwarf.traversal_rejected".to_owned()
                    });
                    (None, Some(diagnostic), completeness)
                }
            };
        completeness.reasons.sort();
        completeness.reasons.dedup();
        let mut lines = traversal
            .as_ref()
            .into_iter()
            .flat_map(|traversal| &traversal.line_rows)
            .map(|row| DwarfLineAnnotation {
                address: row.address,
                unit_ordinal: row.unit_ordinal,
                sequence: row.sequence,
                file_index: row.file_index,
                line: row.line,
                column: row.column,
                end_sequence: row.end_sequence,
            })
            .collect::<Vec<_>>();
        lines.sort_by_key(|line| (line.address, line.unit_ordinal, line.sequence));
        let index = Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            lines,
            completeness,
            diagnostic,
            traversal,
        };
        debug_assert!(index.durable_invariants_hold());
        Ok(index)
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact recovery limits.
    pub const fn limits(&self) -> DwarfRecoveryLimits {
        self.limits
    }

    /// Complete bounded physical traversal, when it could be retained.
    pub const fn traversal(&self) -> Option<&DwarfTraversal> {
        self.traversal.as_ref()
    }

    /// Source rows sorted by image address.
    pub fn lines(&self) -> &[DwarfLineAnnotation] {
        &self.lines
    }

    /// Diagnostic for rejected traversal, bounded to one typed parser message.
    pub fn diagnostic(&self) -> Option<&str> {
        self.diagnostic.as_deref()
    }

    /// Overall completion state.
    pub const fn status(&self) -> DwarfIndexStatus {
        self.completeness.status
    }

    /// Completeness and work receipt.
    pub const fn completeness(&self) -> &DwarfIndexCompleteness {
        &self.completeness
    }

    /// Find every physical source row beginning at an exact address.
    pub fn lines_at(&self, address: u64) -> impl Iterator<Item = &DwarfLineAnnotation> {
        let start = self.lines.partition_point(|line| line.address < address);
        let end = self.lines.partition_point(|line| line.address <= address);
        self.lines[start..end].iter()
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err() {
            return false;
        }
        let lines_are_canonical = self.lines.windows(2).all(|pair| {
            (pair[0].address, pair[0].unit_ordinal, pair[0].sequence)
                <= (pair[1].address, pair[1].unit_ordinal, pair[1].sequence)
        });
        if !lines_are_canonical {
            return false;
        }

        let Some(traversal) = &self.traversal else {
            if !self.lines.is_empty() {
                return false;
            }
            return match (self.completeness.status, self.diagnostic.as_deref()) {
                (DwarfIndexStatus::Absent, None) => {
                    self.completeness == empty_completeness(DwarfIndexStatus::Absent)
                }
                (DwarfIndexStatus::Partial | DwarfIndexStatus::Truncated, Some(diagnostic)) => {
                    let truncated = diagnostic.contains("limit")
                        || diagnostic.contains("maximum")
                        || diagnostic.contains("exceed");
                    let status = if truncated {
                        DwarfIndexStatus::Truncated
                    } else {
                        DwarfIndexStatus::Partial
                    };
                    let mut expected = empty_completeness(status);
                    expected.reasons.push(if truncated {
                        "dwarf.structural_limit".to_owned()
                    } else {
                        "dwarf.traversal_rejected".to_owned()
                    });
                    self.completeness == expected
                }
                _ => false,
            };
        };
        if self.diagnostic.is_some()
            || !dwarf_traversal_durable_invariants_hold(traversal, self.limits, self.image.byte_len)
        {
            return false;
        }
        let partial_ranges = traversal
            .range_lists
            .iter()
            .any(|range| range.coverage != "complete")
            || traversal
                .range_entries
                .iter()
                .any(|range| range.limitation.is_some());
        let status = if partial_ranges {
            DwarfIndexStatus::Partial
        } else {
            DwarfIndexStatus::Complete
        };
        let mut expected_completeness = traversal_completeness(traversal, status);
        if partial_ranges {
            expected_completeness
                .reasons
                .push("dwarf.range_partial".to_owned());
        }
        let mut expected_lines = traversal
            .line_rows
            .iter()
            .map(|row| DwarfLineAnnotation {
                address: row.address,
                unit_ordinal: row.unit_ordinal,
                sequence: row.sequence,
                file_index: row.file_index,
                line: row.line,
                column: row.column,
                end_sequence: row.end_sequence,
            })
            .collect::<Vec<_>>();
        expected_lines.sort_by_key(|line| (line.address, line.unit_ordinal, line.sequence));
        self.completeness == expected_completeness && self.lines == expected_lines
    }
}

fn dwarf_traversal_durable_invariants_hold(
    traversal: &DwarfTraversal,
    limits: DwarfRecoveryLimits,
    image_byte_len: u64,
) -> bool {
    let section_bytes = traversal.sections.iter().try_fold(0_u64, |total, section| {
        total.checked_add(section.bytes.len() as u64)
    });
    let sections_are_canonical = traversal
        .sections
        .windows(2)
        .all(|pair| pair[0].section_id < pair[1].section_id);
    let sections_are_bounded = traversal.sections.iter().all(|section| {
        section
            .file_offset
            .checked_add(section.bytes.len() as u64)
            .is_some_and(|end| end <= image_byte_len)
    });
    let units_are_canonical = traversal
        .units
        .iter()
        .enumerate()
        .all(|(ordinal, unit)| unit.ordinal == ordinal as u64 && unit.length != 0);
    let entries_are_canonical = traversal.entries.windows(2).all(|pair| {
        (pair[0].unit_ordinal, pair[0].ordinal) < (pair[1].unit_ordinal, pair[1].ordinal)
    }) && traversal.entries.iter().all(|entry| {
        entry.unit_ordinal < traversal.units.len() as u64
            && entry
                .parent_offset
                .is_none_or(|parent| parent != entry.offset)
    });
    let attributes_are_canonical = traversal.attributes.windows(2).all(|pair| {
        (pair[0].unit_ordinal, pair[0].entry_offset, pair[0].ordinal)
            < (pair[1].unit_ordinal, pair[1].entry_offset, pair[1].ordinal)
    });
    let source_files_are_canonical = traversal.source_files.windows(2).all(|pair| {
        (pair[0].unit_ordinal, pair[0].file_index) < (pair[1].unit_ordinal, pair[1].file_index)
    });
    let line_rows_are_canonical = traversal.line_rows.windows(2).all(|pair| {
        (pair[0].unit_ordinal, pair[0].sequence, pair[0].ordinal)
            < (pair[1].unit_ordinal, pair[1].sequence, pair[1].ordinal)
    });
    let range_lists_are_canonical = traversal.range_lists.windows(2).all(|pair| {
        (
            pair[0].unit_ordinal,
            pair[0].entry_offset,
            pair[0].attribute_ordinal,
        ) < (
            pair[1].unit_ordinal,
            pair[1].entry_offset,
            pair[1].attribute_ordinal,
        )
    });
    let range_entries_are_canonical = traversal.range_entries.windows(2).all(|pair| {
        (
            pair[0].unit_ordinal,
            pair[0].entry_offset,
            pair[0].attribute_ordinal,
            pair[0].ordinal,
        ) < (
            pair[1].unit_ordinal,
            pair[1].entry_offset,
            pair[1].attribute_ordinal,
            pair[1].ordinal,
        )
    }) && traversal.range_entries.iter().all(|entry| {
        entry.start.is_some() == entry.end.is_some()
            && entry
                .start
                .zip(entry.end)
                .is_none_or(|(start, end)| start < end)
    });

    section_bytes.is_some_and(|count| count <= limits.max_section_bytes)
        && sections_are_canonical
        && sections_are_bounded
        && !traversal.units.is_empty()
        && traversal.units.len() as u64 <= limits.max_units
        && traversal.entries.len() as u64 <= limits.max_entries
        && traversal.attributes.len() as u64 <= limits.max_attributes
        && traversal.line_rows.len() as u64 <= limits.max_line_rows
        && traversal.range_entries.len() as u64 <= limits.max_range_entries
        && units_are_canonical
        && entries_are_canonical
        && attributes_are_canonical
        && source_files_are_canonical
        && line_rows_are_canonical
        && range_lists_are_canonical
        && range_entries_are_canonical
}

fn empty_completeness(status: DwarfIndexStatus) -> DwarfIndexCompleteness {
    DwarfIndexCompleteness {
        status,
        reasons: Vec::new(),
        sections: 0,
        units: 0,
        entries: 0,
        attributes: 0,
        line_rows: 0,
        range_entries: 0,
    }
}

fn traversal_completeness(
    traversal: &DwarfTraversal,
    status: DwarfIndexStatus,
) -> DwarfIndexCompleteness {
    DwarfIndexCompleteness {
        status,
        reasons: Vec::new(),
        sections: traversal.sections.len() as u64,
        units: traversal.units.len() as u64,
        entries: traversal.entries.len() as u64,
        attributes: traversal.attributes.len() as u64,
        line_rows: traversal.line_rows.len() as u64,
        range_entries: traversal.range_entries.len() as u64,
    }
}
