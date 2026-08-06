//! Strict, effect-free collection of emitted Swift metadata identities.
//!
//! This module observes only metadata objects already named by the selected
//! image. It never calls a metadata accessor, executes target code, or treats
//! an accessor symbol as proof that an instance exists. Fixup resolution and
//! ABI-specific value-witness decoding remain in the dyld-owning composition
//! layer rather than creating a forbidden Swift-to-dyld dependency.

use serde::Serialize;

use crate::core::MachoFile;
use crate::core::model::addr::Va;
use crate::metadata::dyld::resolve::{
    PointerAuthentication, PointerEncoding, PointerResolver, PointerTarget,
};
use crate::metadata::swift::error::{Result, SwiftError};
use crate::metadata::swift::types::{SwiftTypeIndex, SwiftTypeKind};

/// One already-materialized metadata object emitted in the selected image.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SwiftStaticMetadata {
    /// Fully-qualified type name.
    pub type_name: String,
    /// Nominal metadata kind.
    pub kind: SwiftTypeKind,
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
                        kind: ty.kind,
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

/// Protocol requirement identity needed to decode one witness-pattern slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StrictWitnessRequirement {
    /// Stable zero-based requirement index.
    pub requirement_index: u32,
}

/// Target retained for one witness-pattern pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictWitnessPointerTarget {
    /// Address within the selected image.
    Address(u64),
    /// Imported symbol.
    Import(String),
}

/// On-disk provenance retained for one witness-pattern pointer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum StrictWitnessPointerProvenance {
    /// Ordinary pointer bytes.
    Direct,
    /// Chained rebase.
    ChainedRebase,
    /// Authenticated chained rebase.
    ChainedAuthRebase(PointerAuthentication),
    /// Chained bind.
    ChainedBind,
    /// Authenticated chained bind.
    ChainedAuthBind(PointerAuthentication),
    /// Legacy rebase.
    LegacyRebase,
    /// Legacy bind.
    LegacyBind,
}

/// One decoded witness-pattern entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictWitnessPatternEntry {
    /// Protocol requirement index.
    pub requirement_index: u32,
    /// Address of the pointer slot.
    pub slot_va: u64,
    /// Resolved target.
    pub target: StrictWitnessPointerTarget,
    /// Retained pointer provenance.
    pub provenance: StrictWitnessPointerProvenance,
    /// Exact raw pointer bytes.
    pub raw: Vec<u8>,
}

/// Complete recorded witness-table pattern.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrictWitnessTablePattern {
    /// Address of the pattern.
    pub pattern_va: u64,
    /// Provenance of the conformance-descriptor back-pointer.
    pub conformance_pointer_provenance: StrictWitnessPointerProvenance,
    /// Requirement entries in strictly increasing requirement order.
    pub entries: Vec<StrictWitnessPatternEntry>,
}

/// Decode one recorded witness-table pattern without executing target code.
pub fn decode_witness_table_pattern(
    image: &MachoFile<'_>,
    conformance_descriptor_va: u64,
    pattern_va: u64,
    requirements: &[StrictWitnessRequirement],
    max_dispatch_slots: u64,
) -> Result<StrictWitnessTablePattern> {
    if !image.is_64bit() {
        return Err(SwiftError::unsupported(
            "recorded Swift witness patterns require a 64-bit layout",
        ));
    }
    if requirements.len() as u64 > max_dispatch_slots {
        return Err(SwiftError::unsupported(
            "recorded Swift witness pattern exceeds the dispatch-slot limit",
        ));
    }
    if requirements
        .windows(2)
        .any(|pair| pair[0].requirement_index >= pair[1].requirement_index)
    {
        return Err(SwiftError::format(
            "Swift protocol requirements are not strictly ordered",
        ));
    }
    let resolver = PointerResolver::new(image)
        .map_err(|error| SwiftError::format(format!("Swift pointer resolution failed: {error}")))?;
    let conformance = observe_witness_pointer(&resolver, pattern_va)?;
    if conformance.target != (StrictWitnessPointerTarget::Address(conformance_descriptor_va)) {
        return Err(SwiftError::format(
            "witness-table pattern does not point back to its conformance descriptor",
        ));
    }
    let mut entries = Vec::with_capacity(requirements.len());
    for (ordinal, requirement) in requirements.iter().enumerate() {
        let slot_offset = u64::try_from(ordinal)
            .ok()
            .and_then(|value| value.checked_add(1))
            .and_then(|value| value.checked_mul(8))
            .ok_or_else(|| SwiftError::address("witness-pattern slot offset overflows"))?;
        let slot_va = pattern_va
            .checked_add(slot_offset)
            .ok_or_else(|| SwiftError::address("witness-pattern slot address overflows"))?;
        let pointer = observe_witness_pointer(&resolver, slot_va)?;
        entries.push(StrictWitnessPatternEntry {
            requirement_index: requirement.requirement_index,
            slot_va,
            target: pointer.target,
            provenance: pointer.provenance,
            raw: pointer.raw,
        });
    }
    Ok(StrictWitnessTablePattern {
        pattern_va,
        conformance_pointer_provenance: conformance.provenance,
        entries,
    })
}

struct WitnessPointer {
    target: StrictWitnessPointerTarget,
    provenance: StrictWitnessPointerProvenance,
    raw: Vec<u8>,
}

fn observe_witness_pointer(
    resolver: &PointerResolver<'_, '_>,
    slot_va: u64,
) -> Result<WitnessPointer> {
    let observation = resolver
        .observe_at_va(Va(slot_va))
        .map_err(|error| SwiftError::format(format!("Swift pointer decode failed: {error}")))?;
    let target = match observation.target {
        PointerTarget::Address(address) => StrictWitnessPointerTarget::Address(address.0),
        PointerTarget::Import { name, .. } => StrictWitnessPointerTarget::Import(name),
        PointerTarget::Null => {
            return Err(SwiftError::format(
                "Swift witness pattern contains a null pointer",
            ));
        }
    };
    let provenance = match (observation.encoding, observation.authentication) {
        (PointerEncoding::Direct, None) => StrictWitnessPointerProvenance::Direct,
        (PointerEncoding::ChainedRebase, None) => StrictWitnessPointerProvenance::ChainedRebase,
        (PointerEncoding::ChainedRebase, Some(authentication)) => {
            StrictWitnessPointerProvenance::ChainedAuthRebase(authentication)
        }
        (PointerEncoding::ChainedBind, None) => StrictWitnessPointerProvenance::ChainedBind,
        (PointerEncoding::ChainedBind, Some(authentication)) => {
            StrictWitnessPointerProvenance::ChainedAuthBind(authentication)
        }
        (PointerEncoding::LegacyRebase, None) => StrictWitnessPointerProvenance::LegacyRebase,
        (PointerEncoding::LegacyBind, None) => StrictWitnessPointerProvenance::LegacyBind,
        _ => {
            return Err(SwiftError::format(
                "pointer authentication appears on an invalid encoding",
            ));
        }
    };
    Ok(WitnessPointer {
        target,
        provenance,
        raw: observation.raw,
    })
}
