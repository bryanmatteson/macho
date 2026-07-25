//! Strict, effect-free Swift ABI evidence for one selected Mach-O image.
//!
//! This module owns byte interpretation, pointer provenance, lossless
//! conservation, and bounded rejection. Consumers retain ownership of semantic
//! identities, capability policy, graph construction, and user-facing reports.

use std::collections::BTreeMap;
use std::fmt;

use crate::types::{SwiftTypeKind, SwiftTypeSource};
use macho_core::model::addr::Va;
use macho_core::model::container::MachoContainer;
use macho_core::model::macho_file::MachoFile;
use macho_dyld::resolve::{PointerResolver, PointerTarget};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
struct ValidatedDescriptor {
    section: String,
    index: u64,
    address: u64,
    raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug)]
struct ValidatedConformance {
    section: String,
    index: u64,
    address: u64,
    flags: u32,
    conditional_requirement_count: u8,
    conditional_requirements: Vec<MachoSwiftConditionalRequirementV1>,
    witness_table_pattern_va: Option<u64>,
    raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug)]
struct ValidatedAssociatedType {
    address: u64,
    byte_len: u32,
    conforming_type_mangling: Vec<u8>,
    protocol_type_mangling: Vec<u8>,
    records: Vec<MachoSwiftAssociatedTypeRecordV1>,
    raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug)]
struct AssociatedTypeValidationError {
    attempted: u64,
    gap: SwiftDecodeGapV1,
}

#[derive(Clone, Debug)]
struct ProtocolRequirementValidationError {
    attempted: u64,
    gap: SwiftDecodeGapV1,
}

#[derive(Clone, Debug)]
struct ClassDispatchValidationError {
    attempted: u64,
    gap: SwiftDecodeGapV1,
}

mod associated;
mod conformance;
mod decode;
mod descriptors;
mod dispatch;
mod model_core;
mod model_graph;
mod outcome;
mod static_metadata;

pub use decode::{decode_swift_strict, decode_swift_strict_file};
pub use model_core::*;
pub use model_graph::*;
pub use static_metadata::{
    decode_swift_static_metadata, decode_swift_static_metadata_file,
    decode_swift_static_metadata_with_resolver,
};

use associated::validate_associated_types;
use conformance::validate_conformance_list;
use descriptors::{
    add_signed, decode_evidence_witness_table_pattern, gap, read_bounded_mangled_name,
    resolve_relative_indirect, validate_bounded_c_string, validate_conforming_type_reference,
    validate_name, validate_nominal_lists,
};
use dispatch::{
    swift_conformance_list_entry_count, swift_nominal_list_entry_count, validate_class_dispatch,
    validate_protocol_requirements,
};
use outcome::{collector, rejected, validated};
use static_metadata::NoSymbolDemangler;
