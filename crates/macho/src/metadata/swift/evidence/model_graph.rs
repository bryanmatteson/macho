use super::*;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Conditional Requirement V1 evidence.
pub struct MachoSwiftConditionalRequirementV1 {
    /// requirement index.
    pub requirement_index: u32,
    /// descriptor va.
    pub descriptor_va: u64,
    /// flags.
    pub flags: u32,
    /// kind.
    pub kind: MachoSwiftGenericRequirementKindV1,
    /// parameter mangling va.
    pub parameter_mangling_va: u64,
    /// parameter mangling.
    pub parameter_mangling: Vec<u8>,
    /// constraint.
    pub constraint: MachoSwiftGenericRequirementConstraintV1,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Conformance Record V1 evidence.
pub struct MachoSwiftConformanceRecordV1 {
    /// descriptor va.
    pub descriptor_va: u64,
    /// flags.
    pub flags: u32,
    /// conditional requirement count.
    pub conditional_requirement_count: u8,
    /// conditional requirements.
    pub conditional_requirements: Vec<MachoSwiftConditionalRequirementV1>,
    /// protocol descriptor va.
    pub protocol_descriptor_va: Option<u64>,
    /// protocol name.
    pub protocol_name: Option<String>,
    /// conforming type descriptor va.
    pub conforming_type_descriptor_va: Option<u64>,
    /// conforming type name.
    pub conforming_type_name: Option<String>,
    /// witness table pattern va.
    pub witness_table_pattern_va: Option<u64>,
    /// witness table pattern.
    pub witness_table_pattern: Option<MachoSwiftWitnessTablePatternV1>,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Associated Type Record V1 evidence.
pub struct MachoSwiftAssociatedTypeRecordV1 {
    /// record va.
    pub record_va: u64,
    /// record size.
    pub record_size: u32,
    /// name.
    pub name: String,
    /// substituted type mangling.
    pub substituted_type_mangling: Vec<u8>,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Associated Type Descriptor V1 evidence.
pub struct MachoSwiftAssociatedTypeDescriptorV1 {
    /// descriptor va.
    pub descriptor_va: u64,
    /// byte len.
    pub byte_len: u32,
    /// conforming type mangling.
    pub conforming_type_mangling: Vec<u8>,
    /// resolved conforming type name.
    pub resolved_conforming_type_name: Option<String>,
    /// resolved conforming type descriptor va.
    pub resolved_conforming_type_descriptor_va: Option<u64>,
    /// protocol type mangling.
    pub protocol_type_mangling: Vec<u8>,
    /// records.
    pub records: Vec<MachoSwiftAssociatedTypeRecordV1>,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Macho Swift Protocol Requirement Kind V1 evidence.
pub enum MachoSwiftProtocolRequirementKindV1 {
    /// Base Protocol.
    BaseProtocol,
    /// Method.
    Method,
    /// Initializer.
    Initializer,
    /// Getter.
    Getter,
    /// Setter.
    Setter,
    /// Read Coroutine.
    ReadCoroutine,
    /// Modify Coroutine.
    ModifyCoroutine,
    /// Associated Type Access.
    AssociatedTypeAccess,
    /// Associated Conformance Access.
    AssociatedConformanceAccess,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Protocol Requirement Record V1 evidence.
pub struct MachoSwiftProtocolRequirementRecordV1 {
    /// protocol descriptor va.
    pub protocol_descriptor_va: u64,
    /// requirement index.
    pub requirement_index: u32,
    /// descriptor va.
    pub descriptor_va: u64,
    /// flags.
    pub flags: u32,
    /// kind.
    pub kind: MachoSwiftProtocolRequirementKindV1,
    /// default implementation va.
    pub default_implementation_va: Option<u64>,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

/// One generic signature requirement preceding a protocol's dispatch
/// requirements. Relative operands remain raw ABI evidence until their full
/// constraint kind is admitted by the semantic layer.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachoSwiftProtocolSignatureRequirementRecordV1 {
    /// Owning protocol descriptor.
    pub protocol_descriptor_va: u64,
    /// Signature-local requirement index.
    pub requirement_index: u32,
    /// Generic requirement descriptor address.
    pub descriptor_va: u64,
    /// ABI generic requirement flags.
    pub flags: u32,
    /// Raw relative parameter mangling pointer.
    pub parameter_relative: i32,
    /// Raw relative constraint pointer or layout payload.
    pub constraint_relative: i32,
    /// Digest of the exact 12-byte descriptor.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Macho Swift Class Method Kind V1 evidence.
pub enum MachoSwiftClassMethodKindV1 {
    /// Method.
    Method,
    /// Initializer.
    Initializer,
    /// Getter.
    Getter,
    /// Setter.
    Setter,
    /// Modify Coroutine.
    ModifyCoroutine,
    /// Read Coroutine.
    ReadCoroutine,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Class Vtable Entry V1 evidence.
pub struct MachoSwiftClassVtableEntryV1 {
    /// class descriptor va.
    pub class_descriptor_va: u64,
    /// vtable offset.
    pub vtable_offset: u32,
    /// slot index.
    pub slot_index: u32,
    /// descriptor va.
    pub descriptor_va: u64,
    /// flags.
    pub flags: u32,
    /// kind.
    pub kind: MachoSwiftClassMethodKindV1,
    /// implementation va.
    pub implementation_va: u64,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Class Override Record V1 evidence.
pub struct MachoSwiftClassOverrideRecordV1 {
    /// class descriptor va.
    pub class_descriptor_va: u64,
    /// override index.
    pub override_index: u32,
    /// descriptor va.
    pub descriptor_va: u64,
    /// overridden class descriptor va.
    pub overridden_class_descriptor_va: u64,
    /// overridden method descriptor va.
    pub overridden_method_descriptor_va: u64,
    /// implementation va.
    pub implementation_va: u64,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

/// Generic-context portion of a Swift class trailing descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachoSwiftGenericContextLayoutV1 {
    /// Generic-context descriptor address.
    pub descriptor_va: u64,
    /// Relative pointer to the generic metadata instantiation cache.
    pub instantiation_cache_relative: i32,
    /// Relative pointer to the default generic metadata instantiation pattern.
    pub default_instantiation_pattern_relative: i32,
    /// Number of generic parameters.
    pub parameter_count: u16,
    /// Number of generic requirements.
    pub requirement_count: u16,
    /// Number of key arguments used to form metadata identity.
    pub key_argument_count: u16,
    /// Swift 5.8-and-newer generic-context flags. This field occupied the
    /// now-retired extra-argument count in older runtimes, where it was zero.
    pub flags: u16,
    /// Number of pack-shape descriptors, when the type-pack flag is set.
    pub pack_count: u16,
    /// Number of equivalence classes in the same-shape relation.
    pub shape_class_count: u16,
    /// Raw set of conditionally inverted protocols.
    pub conditional_inverted_protocol_bits: u16,
    /// Cumulative generic-requirement counts for the set bits above.
    pub conditional_inverted_protocol_requirement_counts: Vec<u16>,
    /// Number of generic value descriptors, when the value flag is set.
    pub value_count: u32,
    /// Complete generic-context descriptor byte length.
    pub byte_len: u32,
}

/// Metadata-initialization portion of a Swift class trailing descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum MachoSwiftMetadataInitializationLayoutV1 {
    /// The descriptor has no metadata-initialization record.
    None,
    /// Singleton initialization with cache, incomplete-metadata, and completion pointers.
    Singleton {
        /// Initialization record address.
        descriptor_va: u64,
        /// Cache relative pointer as encoded.
        cache_relative: i32,
        /// Incomplete-metadata relative pointer as encoded.
        incomplete_metadata_relative: i32,
        /// Completion-function relative pointer as encoded.
        completion_function_relative: i32,
    },
    /// Foreign initialization with a completion-function pointer.
    Foreign {
        /// Initialization record address.
        descriptor_va: u64,
        /// Completion-function relative pointer as encoded.
        completion_function_relative: i32,
    },
}

/// Typed trailing-layout evidence for one Swift class descriptor.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MachoSwiftClassTrailingLayoutV1 {
    /// Owning class descriptor address.
    pub class_descriptor_va: u64,
    /// Raw context descriptor flags selecting this layout.
    pub flags: u32,
    /// Generic-context layout, when the class is generic.
    pub generic_context: Option<MachoSwiftGenericContextLayoutV1>,
    /// Address of the resilient-superclass record, when present.
    pub resilient_superclass_descriptor_va: Option<u64>,
    /// Raw resilient-superclass type-reference relative pointer.
    pub resilient_superclass_type_reference_relative: Option<i32>,
    /// Metadata-initialization layout.
    pub metadata_initialization: MachoSwiftMetadataInitializationLayoutV1,
    /// Address immediately following all admitted layout prefixes.
    pub dispatch_descriptor_va: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Swift Decode Gap V1 evidence.
pub struct SwiftDecodeGapV1 {
    /// code.
    pub code: String,
    /// section.
    pub section: Option<String>,
    /// record index.
    pub record_index: Option<u64>,
    /// safe detail.
    pub safe_detail: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Swift Collector Status V1 evidence.
pub enum SwiftCollectorStatusV1 {
    /// Complete.
    Complete,
    /// Absent.
    Absent,
    /// Rejected.
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Swift Collector Outcome V1 evidence.
pub struct SwiftCollectorOutcomeV1 {
    /// collector.
    pub collector: String,
    /// status.
    pub status: SwiftCollectorStatusV1,
    /// attempted.
    pub attempted: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Swift Observation Conservation V1 evidence.
pub struct SwiftObservationConservationV1 {
    /// attempted.
    pub attempted: u64,
    /// included.
    pub included: u64,
    /// unknown.
    pub unknown: u64,
    /// excluded.
    pub excluded: u64,
}

impl SwiftObservationConservationV1 {
    /// Validate conservation and outcome invariants.
    pub fn validate(self) -> Result<(), String> {
        let conserved = self
            .included
            .checked_add(self.unknown)
            .and_then(|value| value.checked_add(self.excluded))
            .ok_or_else(|| "Swift observation conservation overflowed".to_string())?;
        if conserved != self.attempted {
            return Err("Swift observation conservation does not balance".into());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Swift Decode Batch V1 evidence.
pub struct SwiftDecodeBatchV1 {
    /// outcome.
    pub outcome: SwiftDecodeOutcomeV1,
    /// records.
    pub records: Vec<MachoSwiftRecordV1>,
    /// conformances.
    pub conformances: Vec<MachoSwiftConformanceRecordV1>,
    /// associated types.
    pub associated_types: Vec<MachoSwiftAssociatedTypeDescriptorV1>,
    /// protocol requirements.
    pub protocol_requirements: Vec<MachoSwiftProtocolRequirementRecordV1>,
    /// Protocol generic signature requirements.
    #[serde(default)]
    pub protocol_signature_requirements: Vec<MachoSwiftProtocolSignatureRequirementRecordV1>,
    /// Class trailing layouts used to locate dispatch records.
    #[serde(default)]
    pub class_trailing_layouts: Vec<MachoSwiftClassTrailingLayoutV1>,
    /// class vtable entries.
    pub class_vtable_entries: Vec<MachoSwiftClassVtableEntryV1>,
    /// class overrides.
    pub class_overrides: Vec<MachoSwiftClassOverrideRecordV1>,
    /// gaps.
    pub gaps: Vec<SwiftDecodeGapV1>,
    /// collector outcomes.
    pub collector_outcomes: Vec<SwiftCollectorOutcomeV1>,
    /// conservation.
    pub conservation: SwiftObservationConservationV1,
}

impl SwiftDecodeBatchV1 {
    /// Validate conservation and outcome invariants.
    pub fn validate(&self) -> Result<(), String> {
        self.conservation.validate()?;
        let retained = self
            .records
            .len()
            .checked_add(
                self.records
                    .iter()
                    .try_fold(0_usize, |count, record| {
                        count.checked_add(record.fields.len())
                    })
                    .ok_or_else(|| "Swift retained field count overflowed".to_string())?,
            )
            .and_then(|value| value.checked_add(self.conformances.len()))
            .and_then(|value| value.checked_add(self.associated_types.len()))
            .and_then(|value| value.checked_add(self.protocol_requirements.len()))
            .and_then(|value| value.checked_add(self.protocol_signature_requirements.len()))
            .and_then(|value| value.checked_add(self.class_trailing_layouts.len()))
            .and_then(|value| value.checked_add(self.class_vtable_entries.len()))
            .and_then(|value| value.checked_add(self.class_overrides.len()))
            .and_then(|value| {
                self.conformances
                    .iter()
                    .try_fold(value, |count, conformance| {
                        count.checked_add(conformance.conditional_requirements.len())
                    })
            })
            .and_then(|value| {
                self.conformances
                    .iter()
                    .try_fold(value, |count, conformance| {
                        if let Some(pattern) = &conformance.witness_table_pattern {
                            count
                                .checked_add(1)
                                .and_then(|value| value.checked_add(pattern.entries.len()))
                        } else {
                            Some(count)
                        }
                    })
            })
            .and_then(|value| {
                self.associated_types
                    .iter()
                    .try_fold(value, |count, descriptor| {
                        count.checked_add(descriptor.records.len())
                    })
            })
            .ok_or_else(|| "Swift retained observation count overflowed".to_string())?;
        if retained as u64 != self.conservation.included {
            return Err("Swift included count differs from retained records".into());
        }
        match self.outcome {
            SwiftDecodeOutcomeV1::Absent
                if self.conservation.attempted == 0
                    && self.records.is_empty()
                    && self.conformances.is_empty()
                    && self.associated_types.is_empty()
                    && self.protocol_requirements.is_empty()
                    && self.protocol_signature_requirements.is_empty()
                    && self.class_trailing_layouts.is_empty()
                    && self.class_vtable_entries.is_empty()
                    && self.class_overrides.is_empty()
                    && self.gaps.is_empty() => {}
            SwiftDecodeOutcomeV1::Complete
                if self.conservation.unknown == 0
                    && self.collector_outcomes.iter().all(|collector| {
                        matches!(
                            collector.status,
                            SwiftCollectorStatusV1::Complete | SwiftCollectorStatusV1::Absent
                        )
                    }) => {}
            SwiftDecodeOutcomeV1::Rejected
                if !self.gaps.is_empty()
                    && self.collector_outcomes.iter().any(|collector| {
                        matches!(collector.status, SwiftCollectorStatusV1::Rejected)
                    }) => {}
            _ => return Err("Swift decode outcome and evidence disagree".into()),
        }
        Ok(())
    }
}
