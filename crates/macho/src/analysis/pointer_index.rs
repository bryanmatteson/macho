//! Format-level pointer, fixup, bind, stub, and relocation recovery.

use std::collections::BTreeMap;

use crate::core::model::macho_file::MachoFile;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;
use crate::analysis::xref::{XrefIndex, XrefIndexStatus, XrefKind, XrefTarget};

/// Explicit limits for one pointer inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerRecoveryLimits {
    /// Maximum retained pointer and format-reference records.
    pub max_records: usize,
}

impl Default for PointerRecoveryLimits {
    fn default() -> Self {
        Self {
            max_records: 16_000_000,
        }
    }
}

impl PointerRecoveryLimits {
    /// Reject a zero record limit.
    pub fn validate(self) -> Result<Self, PointerRecoveryError> {
        if self.max_records == 0 {
            return Err(PointerRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing pointer recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PointerRecoveryError {
    /// The record limit is zero.
    #[error("pointer recovery record limit must be non-zero")]
    InvalidLimits,
    /// Format-reference collection failed before producing receipts.
    #[error("pointer format recovery failed: {0}")]
    Recovery(String),
}

/// Pointer record source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PointerRecordKind {
    /// Indirect-symbol stub or pointer slot.
    Stub,
    /// Dyld chained bind.
    ChainedBind,
    /// Dyld chained rebase.
    ChainedRebase,
    /// Legacy dyld rebase.
    LegacyRebase,
    /// Legacy dyld bind.
    LegacyBind,
    /// Mach-O relocation.
    Relocation,
}

/// Arm64e chained-pointer authentication metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerAuthentication {
    /// Pointer-authentication key selector.
    pub key: u8,
    /// Encoded diversity value.
    pub diversity: u16,
    /// Whether the pointer address contributes to authentication.
    pub address_diversity: bool,
}

/// One pointer-bearing format record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredPointer {
    /// Address of the slot, stub, or relocation source.
    pub address: u64,
    /// Resolved internal or imported target.
    pub target: XrefTarget,
    /// Format source kind.
    pub kind: PointerRecordKind,
    /// Authentication metadata, when encoded by an arm64e chained pointer.
    pub authentication: Option<PointerAuthentication>,
}

/// Completeness receipt for pointer recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerIndexCompleteness {
    /// Whether format sources completed without rejection or omission.
    pub complete: bool,
    /// Whether an explicit record limit omitted evidence.
    pub truncated: bool,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Retained pointer records.
    pub retained: u64,
}

/// Deterministic pointer and fixup inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerIndex {
    image: FunctionImageIdentity,
    limits: PointerRecoveryLimits,
    pointers: Vec<RecoveredPointer>,
    completeness: PointerIndexCompleteness,
    format: XrefIndex,
}

impl PointerIndex {
    /// Recover format-level pointer evidence without decoding instructions.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: PointerRecoveryLimits,
    ) -> Result<Self, PointerRecoveryError> {
        let evidence = crate::evidence::SelectedImageEvidence::new(macho)
            .map_err(|error| PointerRecoveryError::Recovery(error.to_string()))?;
        Self::recover_with_evidence(&evidence, limits)
    }

    /// Recover through the shared selected-image evidence session.
    pub fn recover_with_evidence(
        evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
        limits: PointerRecoveryLimits,
    ) -> Result<Self, PointerRecoveryError> {
        let limits = limits.validate()?;
        let format = XrefIndex::recover_format_with_evidence(evidence, limits.max_records)
            .map_err(|error| PointerRecoveryError::Recovery(error.to_string()))?;
        let authentication = evidence_chained_authentication(evidence, &format)?;
        Self::from_format(evidence.image(), limits, format, authentication)
    }

    fn from_format(
        macho: &MachoFile<'_>,
        limits: PointerRecoveryLimits,
        format: XrefIndex,
        authentication: BTreeMap<u64, PointerAuthentication>,
    ) -> Result<Self, PointerRecoveryError> {
        let mut pointers = format
            .all_refs()
            .iter()
            .filter_map(|reference| {
                let kind = pointer_kind_for_xref(reference.kind)?;
                Some(RecoveredPointer {
                    address: reference.source.0,
                    target: reference.target.clone(),
                    kind,
                    authentication: record_authentication(
                        kind,
                        reference.source.0,
                        &authentication,
                    ),
                })
            })
            .collect::<Vec<_>>();
        pointers.sort_by_key(|pointer| (pointer.address, pointer.kind as u8));
        let truncated = format.status() == XrefIndexStatus::Truncated;
        let complete = format.status() == XrefIndexStatus::Complete;
        Ok(Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            completeness: PointerIndexCompleteness {
                complete,
                truncated,
                reasons: format.completeness().reasons.clone(),
                retained: pointers.len() as u64,
            },
            pointers,
            format,
        })
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact recovery limits.
    pub const fn limits(&self) -> PointerRecoveryLimits {
        self.limits
    }

    /// Pointer records sorted by source address.
    pub fn pointers(&self) -> &[RecoveredPointer] {
        &self.pointers
    }

    /// Completeness and retention receipt.
    pub const fn completeness(&self) -> &PointerIndexCompleteness {
        &self.completeness
    }

    /// Iterate pointer records beginning at an exact address.
    pub fn at_address(&self, address: u64) -> impl Iterator<Item = &RecoveredPointer> {
        let start = self
            .pointers
            .partition_point(|pointer| pointer.address < address);
        let end = self
            .pointers
            .partition_point(|pointer| pointer.address <= address);
        self.pointers[start..end].iter()
    }

    pub(crate) const fn format_index(&self) -> &XrefIndex {
        &self.format
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        let pointers_are_sorted = self
            .pointers
            .windows(2)
            .all(|pair| pointer_sort_key(&pair[0]) <= pointer_sort_key(&pair[1]));
        let mut expected = Vec::with_capacity(self.format.all_refs().len());
        for reference in self.format.all_refs() {
            let Some(kind) = pointer_kind_for_xref(reference.kind) else {
                return false;
            };
            expected.push((reference.source.0, kind, &reference.target));
        }
        expected.sort_by_key(|(address, kind, _)| (*address, *kind as u8));
        let pointers_match_format = expected.len() == self.pointers.len()
            && expected
                .iter()
                .zip(&self.pointers)
                .all(|((address, kind, target), pointer)| {
                    *address == pointer.address
                        && *kind == pointer.kind
                        && *target == &pointer.target
                        && pointer.authentication.is_none_or(|authentication| {
                            matches!(
                                pointer.kind,
                                PointerRecordKind::ChainedBind | PointerRecordKind::ChainedRebase
                            ) && authentication.key <= 3
                        })
                });
        let format_status = self.format.status();
        self.limits.validate().is_ok()
            && self.image == *self.format.image()
            && self.format.limits().max_refs == self.limits.max_records
            && self.pointers.len() <= self.limits.max_records
            && pointers_are_sorted
            && pointers_match_format
            && self.completeness.retained == self.pointers.len() as u64
            && self.completeness.complete == (format_status == XrefIndexStatus::Complete)
            && self.completeness.truncated == (format_status == XrefIndexStatus::Truncated)
            && self.completeness.reasons == self.format.completeness().reasons
            && self.format.durable_invariants_hold()
    }
}

const fn pointer_kind_for_xref(kind: XrefKind) -> Option<PointerRecordKind> {
    match kind {
        XrefKind::Stub => Some(PointerRecordKind::Stub),
        XrefKind::ChainedBind => Some(PointerRecordKind::ChainedBind),
        XrefKind::ChainedRebase => Some(PointerRecordKind::ChainedRebase),
        XrefKind::LegacyRebase => Some(PointerRecordKind::LegacyRebase),
        XrefKind::LegacyBind => Some(PointerRecordKind::LegacyBind),
        XrefKind::Relocation => Some(PointerRecordKind::Relocation),
        XrefKind::DirectBranch | XrefKind::Data => None,
    }
}

const fn pointer_sort_key(pointer: &RecoveredPointer) -> (u64, u8) {
    (pointer.address, pointer.kind as u8)
}

fn record_authentication(
    kind: PointerRecordKind,
    address: u64,
    authentication: &BTreeMap<u64, PointerAuthentication>,
) -> Option<PointerAuthentication> {
    if matches!(
        kind,
        PointerRecordKind::ChainedBind | PointerRecordKind::ChainedRebase
    ) {
        authentication.get(&address).copied()
    } else {
        None
    }
}

fn evidence_chained_authentication(
    evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
    format: &XrefIndex,
) -> Result<BTreeMap<u64, PointerAuthentication>, PointerRecoveryError> {
    let mut authentication = BTreeMap::new();
    for reference in format.all_refs().iter().filter(|reference| {
        matches!(
            reference.kind,
            XrefKind::ChainedBind | XrefKind::ChainedRebase
        )
    }) {
        let observation = evidence
            .pointers()
            .observe_at_va(reference.source)
            .map_err(|error| PointerRecoveryError::Recovery(error.to_string()))?;
        if let Some(value) = observation.authentication {
            authentication.insert(
                reference.source.0,
                PointerAuthentication {
                    key: value.key,
                    diversity: value.diversity,
                    address_diversity: value.address_diversity,
                },
            );
        }
    }
    Ok(authentication)
}

#[cfg(test)]
mod tests {
    use super::{BTreeMap, PointerAuthentication, PointerRecordKind, record_authentication};

    #[test]
    fn authentication_belongs_only_to_chained_records_at_an_address() {
        let authentication = PointerAuthentication {
            key: 2,
            diversity: 0x1234,
            address_diversity: true,
        };
        let by_address = BTreeMap::from([(0x1000, authentication)]);

        assert_eq!(
            record_authentication(PointerRecordKind::ChainedBind, 0x1000, &by_address),
            Some(authentication)
        );
        assert_eq!(
            record_authentication(PointerRecordKind::ChainedRebase, 0x1000, &by_address),
            Some(authentication)
        );
        assert_eq!(
            record_authentication(PointerRecordKind::Stub, 0x1000, &by_address),
            None
        );
        assert_eq!(
            record_authentication(PointerRecordKind::LegacyBind, 0x1000, &by_address),
            None
        );
    }
}
