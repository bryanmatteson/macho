//! Format-level pointer, fixup, bind, stub, and relocation recovery.

use std::collections::BTreeMap;

use crate::core::model::macho_file::MachoFile;
use crate::metadata::dyld::{FixupKind, parse_chained_fixups};
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PointerIndex {
    image: FunctionImageIdentity,
    limits: PointerRecoveryLimits,
    pointers: Vec<RecoveredPointer>,
    completeness: PointerIndexCompleteness,
    #[serde(skip)]
    format: XrefIndex,
}

impl PointerIndex {
    /// Recover format-level pointer evidence without decoding instructions.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: PointerRecoveryLimits,
    ) -> Result<Self, PointerRecoveryError> {
        let limits = limits.validate()?;
        let format = XrefIndex::recover_format(macho, limits.max_records)
            .map_err(|error| PointerRecoveryError::Recovery(error.to_string()))?;
        let authentication = chained_authentication(macho);
        let mut pointers = format
            .all_refs()
            .iter()
            .filter_map(|reference| {
                let kind = match reference.kind {
                    XrefKind::Stub => PointerRecordKind::Stub,
                    XrefKind::ChainedBind => PointerRecordKind::ChainedBind,
                    XrefKind::ChainedRebase => PointerRecordKind::ChainedRebase,
                    XrefKind::LegacyBind => PointerRecordKind::LegacyBind,
                    XrefKind::Relocation => PointerRecordKind::Relocation,
                    XrefKind::DirectBranch | XrefKind::Data => return None,
                };
                Some(RecoveredPointer {
                    address: reference.source.0,
                    target: reference.target.clone(),
                    kind,
                    authentication: authentication.get(&reference.source.0).copied(),
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
}

fn chained_authentication(macho: &MachoFile<'_>) -> BTreeMap<u64, PointerAuthentication> {
    let Ok(fixups) = parse_chained_fixups(macho) else {
        return BTreeMap::new();
    };
    fixups
        .fixups
        .iter()
        .filter_map(|fixup| {
            let segment = macho.segments().get(fixup.segment_index)?;
            let address = segment.vm_addr().0.checked_add(fixup.segment_offset)?;
            let (diversity, key, address_diversity) = match fixup.kind {
                FixupKind::AuthRebase {
                    diversity,
                    key,
                    addr_div,
                    ..
                }
                | FixupKind::AuthBind {
                    diversity,
                    key,
                    addr_div,
                    ..
                } => (diversity, key, addr_div),
                _ => return None,
            };
            Some((
                address,
                PointerAuthentication {
                    key,
                    diversity,
                    address_diversity,
                },
            ))
        })
        .collect()
}
