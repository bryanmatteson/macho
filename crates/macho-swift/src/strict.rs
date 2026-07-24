//! Strict, effect-free collection of emitted Swift metadata identities.
//!
//! This module observes only metadata objects already named by the selected
//! image. It never calls a metadata accessor, executes target code, or treats
//! an accessor symbol as proof that an instance exists. Fixup resolution and
//! ABI-specific value-witness decoding remain in the dyld-owning composition
//! layer rather than creating a forbidden Swift-to-dyld dependency.

use serde::Serialize;

use crate::error::{Result, SwiftError};
use crate::types::SwiftTypeIndex;

/// One already-materialized metadata object emitted in the selected image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SwiftStaticMetadata {
    /// Fully-qualified type name.
    pub type_name: String,
    /// Unslid metadata address point.
    pub metadata_address: u64,
    /// Descriptor occurrence associated with the type, when present.
    pub descriptor_address: Option<u64>,
}

/// Conserved strict result for emitted metadata instances.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SwiftStaticMetadataIndex {
    /// Number of emitted metadata symbols considered.
    pub attempted: u64,
    /// Number of records retained.
    pub included: u64,
    /// Strict collection never silently classifies a record as unknown.
    pub unknown: u64,
    /// Strict collection never silently excludes a record.
    pub excluded: u64,
    /// Canonically ordered metadata records.
    pub records: Vec<SwiftStaticMetadata>,
}

impl SwiftTypeIndex {
    /// Retain every emitted, already-materialized metadata identity in this
    /// index. Metadata accessors are excluded by construction because they do
    /// not populate `metadata_address`.
    pub fn strict_static_metadata(&self) -> Result<SwiftStaticMetadataIndex> {
        let mut records = self
            .types
            .iter()
            .filter_map(|ty| {
                ty.metadata_address
                    .map(|metadata_address| SwiftStaticMetadata {
                        type_name: ty.name.clone(),
                        metadata_address,
                        descriptor_address: ty.address,
                    })
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.type_name
                .cmp(&right.type_name)
                .then_with(|| left.metadata_address.cmp(&right.metadata_address))
        });
        if records.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(SwiftError::format(
                "duplicate emitted Swift metadata identity",
            ));
        }
        let included = u64::try_from(records.len())
            .map_err(|_| SwiftError::format("Swift metadata count exceeds u64"))?;
        Ok(SwiftStaticMetadataIndex {
            attempted: included,
            included,
            unknown: 0,
            excluded: 0,
            records,
        })
    }
}
