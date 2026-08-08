//! Bounded image-bound Swift ABI metadata recovery.

use crate::core::model::macho_file::MachoFile;
use crate::metadata::swift::evidence::{
    MachoSwiftClassOverrideRecordV1, MachoSwiftClassVtableEntryV1, MachoSwiftRecordV1,
    SwiftDecodeBatchV1, SwiftDecodeOutcomeV1, SwiftEvidenceLimits, decode_swift_strict,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;

/// Explicit limits for one Swift ABI evidence inventory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwiftRecoveryLimits {
    /// Maximum bytes admitted for one identifier.
    pub max_identifier_bytes: u64,
    /// Maximum bytes admitted for one mangling.
    pub max_mangling_bytes: u64,
    /// Maximum nominal descriptors.
    pub max_nominal_descriptors: u64,
    /// Maximum protocol requirements.
    pub max_protocol_requirements: u64,
    /// Maximum conformances.
    pub max_conformances: u64,
    /// Maximum dispatch slots.
    pub max_dispatch_slots: u64,
    /// Maximum total observations.
    pub max_observations: u64,
}

impl Default for SwiftRecoveryLimits {
    fn default() -> Self {
        let limits = SwiftEvidenceLimits::default();
        Self {
            max_identifier_bytes: limits.max_identifier_bytes,
            max_mangling_bytes: limits.max_mangling_bytes,
            max_nominal_descriptors: limits.max_nominal_descriptors,
            max_protocol_requirements: limits.max_protocol_requirements,
            max_conformances: limits.max_conformances,
            max_dispatch_slots: limits.max_dispatch_slots,
            max_observations: limits.max_observations,
        }
    }
}

impl SwiftRecoveryLimits {
    /// Validate every caller-selected limit against the strict decoder contract.
    pub fn validate(self) -> Result<Self, SwiftRecoveryError> {
        self.evidence()
            .validate()
            .map_err(SwiftRecoveryError::InvalidLimits)?;
        Ok(self)
    }

    const fn evidence(self) -> SwiftEvidenceLimits {
        SwiftEvidenceLimits {
            max_identifier_bytes: self.max_identifier_bytes,
            max_mangling_bytes: self.max_mangling_bytes,
            max_nominal_descriptors: self.max_nominal_descriptors,
            max_protocol_requirements: self.max_protocol_requirements,
            max_conformances: self.max_conformances,
            max_dispatch_slots: self.max_dispatch_slots,
            max_observations: self.max_observations,
        }
    }
}

/// Failure preventing Swift recovery from beginning.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SwiftRecoveryError {
    /// One strict evidence limit is zero or above its hard maximum.
    #[error("invalid Swift recovery limits: {0}")]
    InvalidLimits(String),
}

/// Swift inventory completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftIndexStatus {
    /// No supported Swift metadata surface exists.
    Absent,
    /// Every admitted Swift observation was conserved.
    Complete,
    /// Swift metadata exists but structural evidence was rejected.
    Partial,
    /// A structural limit prevented complete recovery.
    Truncated,
}

/// Completeness and conservation receipt for Swift recovery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SwiftIndexCompleteness {
    /// Overall status.
    pub status: SwiftIndexStatus,
    /// Stable reason codes.
    pub reasons: Vec<String>,
    /// Source observations attempted.
    pub attempted: u64,
    /// Source observations included.
    pub included: u64,
    /// Source observations unresolved.
    pub unknown: u64,
    /// Source observations deliberately excluded.
    pub excluded: u64,
}

/// Deterministic strict Swift ABI inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftIndex {
    image: FunctionImageIdentity,
    limits: SwiftRecoveryLimits,
    batch: SwiftDecodeBatchV1,
    completeness: SwiftIndexCompleteness,
}

impl SwiftIndex {
    /// Recover strict Swift ABI evidence exactly once.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: SwiftRecoveryLimits,
    ) -> Result<Self, SwiftRecoveryError> {
        let limits = limits.validate()?;
        let batch = decode_swift_strict(macho, &limits.evidence());
        Ok(Self::from_batch(macho, limits, batch))
    }

    /// Recover from the selected-image evidence session used by program recovery.
    pub fn recover_with_evidence(
        evidence: &crate::evidence::SelectedImageEvidence<'_, '_>,
        limits: SwiftRecoveryLimits,
    ) -> Result<Self, SwiftRecoveryError> {
        let limits = limits.validate()?;
        Ok(Self::from_batch(
            evidence.image(),
            limits,
            evidence.swift(&limits.evidence()),
        ))
    }

    fn from_batch(
        macho: &MachoFile<'_>,
        limits: SwiftRecoveryLimits,
        batch: SwiftDecodeBatchV1,
    ) -> Self {
        let completeness = batch_completeness(&batch);
        let index = Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            batch,
            completeness,
        };
        debug_assert!(index.durable_invariants_hold());
        index
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact recovery limits.
    pub const fn limits(&self) -> SwiftRecoveryLimits {
        self.limits
    }

    /// Complete strict decoder batch and collector receipts.
    pub const fn batch(&self) -> &SwiftDecodeBatchV1 {
        &self.batch
    }

    /// Nominal records sorted in strict decoder order.
    pub fn records(&self) -> &[MachoSwiftRecordV1] {
        &self.batch.records
    }

    /// Class vtable implementation records.
    pub fn class_vtable_entries(&self) -> &[MachoSwiftClassVtableEntryV1] {
        &self.batch.class_vtable_entries
    }

    /// Class override implementation records.
    pub fn class_overrides(&self) -> &[MachoSwiftClassOverrideRecordV1] {
        &self.batch.class_overrides
    }

    /// Overall completion state.
    pub const fn status(&self) -> SwiftIndexStatus {
        self.completeness.status
    }

    /// Completeness and conservation receipt.
    pub const fn completeness(&self) -> &SwiftIndexCompleteness {
        &self.completeness
    }

    /// Find one exact nominal descriptor address.
    pub fn record_by_descriptor(&self, address: u64) -> Option<&MachoSwiftRecordV1> {
        self.batch
            .records
            .iter()
            .find(|record| record.descriptor_va == address)
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err()
            || self.batch.validate().is_err()
            || self.completeness != batch_completeness(&self.batch)
            || self.batch.records.len() as u64 > self.limits.max_nominal_descriptors
            || self.batch.conformances.len() as u64 > self.limits.max_conformances
            || self.batch.protocol_requirements.len() as u64 > self.limits.max_protocol_requirements
            || (self.batch.class_vtable_entries.len() as u64)
                .checked_add(self.batch.class_overrides.len() as u64)
                .is_none_or(|count| count > self.limits.max_dispatch_slots)
        {
            return false;
        }

        let records_are_canonical = self
            .batch
            .records
            .windows(2)
            .all(|pair| pair[0].descriptor_va < pair[1].descriptor_va);
        let conformances_are_canonical = self
            .batch
            .conformances
            .windows(2)
            .all(|pair| pair[0].descriptor_va < pair[1].descriptor_va);
        let associated_types_are_canonical = self
            .batch
            .associated_types
            .windows(2)
            .all(|pair| pair[0].descriptor_va < pair[1].descriptor_va);
        let requirements_are_canonical = self.batch.protocol_requirements.windows(2).all(|pair| {
            (pair[0].protocol_descriptor_va, pair[0].requirement_index)
                < (pair[1].protocol_descriptor_va, pair[1].requirement_index)
        });
        let vtables_are_canonical = self.batch.class_vtable_entries.windows(2).all(|pair| {
            (pair[0].class_descriptor_va, pair[0].slot_index)
                < (pair[1].class_descriptor_va, pair[1].slot_index)
        });
        let overrides_are_canonical = self.batch.class_overrides.windows(2).all(|pair| {
            (pair[0].class_descriptor_va, pair[0].override_index)
                < (pair[1].class_descriptor_va, pair[1].override_index)
        });
        let nested_ordinals_are_canonical =
            self.batch.records.iter().all(|record| {
                record
                    .fields
                    .iter()
                    .enumerate()
                    .all(|(ordinal, field)| usize::try_from(field.ordinal) == Ok(ordinal))
            }) && self.batch.conformances.iter().all(|conformance| {
                conformance.conditional_requirements.iter().enumerate().all(
                    |(ordinal, requirement)| {
                        usize::try_from(requirement.requirement_index) == Ok(ordinal)
                    },
                )
            });
        let reasons_are_canonical = self
            .completeness
            .reasons
            .windows(2)
            .all(|pair| pair[0] < pair[1]);

        records_are_canonical
            && conformances_are_canonical
            && associated_types_are_canonical
            && requirements_are_canonical
            && vtables_are_canonical
            && overrides_are_canonical
            && nested_ordinals_are_canonical
            && reasons_are_canonical
    }
}

fn batch_completeness(batch: &SwiftDecodeBatchV1) -> SwiftIndexCompleteness {
    let mut reasons = batch
        .gaps
        .iter()
        .map(|gap| gap.code.clone())
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    let truncated = reasons.iter().any(|reason| {
        reason.contains("limit") || reason.contains("budget") || reason.contains("overflow")
    });
    let status = match batch.outcome {
        SwiftDecodeOutcomeV1::Absent => SwiftIndexStatus::Absent,
        SwiftDecodeOutcomeV1::Complete => SwiftIndexStatus::Complete,
        SwiftDecodeOutcomeV1::Rejected if truncated => SwiftIndexStatus::Truncated,
        SwiftDecodeOutcomeV1::Rejected => SwiftIndexStatus::Partial,
    };
    SwiftIndexCompleteness {
        status,
        reasons,
        attempted: batch.conservation.attempted,
        included: batch.conservation.included,
        unknown: batch.conservation.unknown,
        excluded: batch.conservation.excluded,
    }
}
