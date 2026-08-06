use super::*;

/// SHA-256 digest of exact evidence bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
/// Evidence Digest evidence.
pub struct EvidenceDigest([u8; 32]);

impl EvidenceDigest {
    /// Hash exact evidence bytes.
    #[must_use]
    pub fn of(bytes: impl AsRef<[u8]>) -> Self {
        Self(Sha256::digest(bytes.as_ref()).into())
    }

    /// Return the digest bytes.
    #[must_use]
    pub const fn into_bytes(self) -> [u8; 32] {
        self.0
    }

    /// Render canonical lowercase hexadecimal.
    #[must_use]
    pub fn to_hex(self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut rendered = String::with_capacity(64);
        for byte in self.0 {
            rendered.push(char::from(HEX[usize::from(byte >> 4)]));
            rendered.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        rendered
    }
}

impl fmt::Display for EvidenceDigest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.to_hex())
    }
}

impl Serialize for EvidenceDigest {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for EvidenceDigest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(serde::de::Error::custom(
                "Swift evidence digest must contain 64 hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; 32];
        for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
            let high = hex_nibble(pair[0]).ok_or_else(|| {
                serde::de::Error::custom("Swift evidence digest contains invalid hexadecimal")
            })?;
            let low = hex_nibble(pair[1]).ok_or_else(|| {
                serde::de::Error::custom("Swift evidence digest contains invalid hexadecimal")
            })?;
            bytes[index] = (high << 4) | low;
        }
        Ok(Self(bytes))
    }
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Resource limits enforced while decoding Swift ABI evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
/// Swift Evidence Limits evidence.
pub struct SwiftEvidenceLimits {
    /// Maximum bytes admitted for one identifier.
    /// max identifier bytes.
    pub max_identifier_bytes: u64,
    /// Maximum bytes admitted for one mangling.
    /// max mangling bytes.
    pub max_mangling_bytes: u64,
    /// Maximum nominal descriptors.
    /// max nominal descriptors.
    pub max_nominal_descriptors: u64,
    /// Maximum protocol requirements.
    /// max protocol requirements.
    pub max_protocol_requirements: u64,
    /// Maximum conformances.
    /// max conformances.
    pub max_conformances: u64,
    /// Maximum dispatch slots.
    /// max dispatch slots.
    pub max_dispatch_slots: u64,
    /// Maximum total observations.
    /// max observations.
    pub max_observations: u64,
}

impl SwiftEvidenceLimits {
    /// Reject zero limits and values above the decoder's hard safety bounds.
    /// Validate conservation and outcome invariants.
    pub fn validate(&self) -> Result<(), String> {
        let selected = [
            self.max_identifier_bytes,
            self.max_mangling_bytes,
            self.max_nominal_descriptors,
            self.max_protocol_requirements,
            self.max_conformances,
            self.max_dispatch_slots,
            self.max_observations,
        ];
        let hard = [
            65_536_u64, 262_144, 4_000_000, 4_000_000, 4_000_000, 8_000_000, 32_000_000,
        ];
        if selected
            .into_iter()
            .zip(hard)
            .any(|(value, maximum)| value == 0 || value > maximum)
        {
            return Err("Swift evidence limit is zero or exceeds its hard maximum".into());
        }
        Ok(())
    }
}

impl Default for SwiftEvidenceLimits {
    fn default() -> Self {
        Self {
            max_identifier_bytes: 4_096,
            max_mangling_bytes: 16_384,
            max_nominal_descriptors: 1_000_000,
            max_protocol_requirements: 1_000_000,
            max_conformances: 1_000_000,
            max_dispatch_slots: 2_000_000,
            max_observations: 8_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Swift Decode Outcome V1 evidence.
pub enum SwiftDecodeOutcomeV1 {
    /// Absent.
    Absent,
    /// Complete.
    Complete,
    /// Rejected.
    Rejected,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Macho Swift Nominal Kind V1 evidence.
pub enum MachoSwiftNominalKindV1 {
    /// Class.
    Class,
    /// Struct.
    Struct,
    /// Enum.
    Enum,
    /// Protocol.
    Protocol,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Record V1 evidence.
pub struct MachoSwiftRecordV1 {
    /// descriptor va.
    pub descriptor_va: u64,
    /// parent descriptor va.
    pub parent_descriptor_va: Option<u64>,
    /// kind.
    pub kind: MachoSwiftNominalKindV1,
    /// qualified name.
    pub qualified_name: String,
    /// fields.
    pub fields: Vec<MachoSwiftFieldRecordV1>,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Field Record V1 evidence.
pub struct MachoSwiftFieldRecordV1 {
    /// record va.
    pub record_va: u64,
    /// record size.
    pub record_size: u32,
    /// ordinal.
    pub ordinal: u32,
    /// name.
    pub name: Option<String>,
    /// mangled type.
    pub mangled_type: Option<Vec<u8>>,
    /// resolved type name.
    pub resolved_type_name: Option<String>,
    /// flags.
    pub flags: u32,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Macho Swift Static Pointer Target V1 evidence.
pub enum MachoSwiftStaticPointerTargetV1 {
    /// Local.
    Local {
        /// va.
        va: u64,
    },
    /// External.
    External {
        /// symbol.
        symbol: String,
        /// library ordinal.
        library_ordinal: i32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Value Witness Layout V1 evidence.
pub struct MachoSwiftValueWitnessLayoutV1 {
    /// table va.
    pub table_va: u64,
    /// size.
    pub size: u64,
    /// stride.
    pub stride: u64,
    /// alignment.
    pub alignment: u64,
    /// extra inhabitant count.
    pub extra_inhabitant_count: u32,
    /// flags.
    pub flags: u32,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Static Metadata V1 evidence.
pub struct MachoSwiftStaticMetadataV1 {
    /// qualified name.
    pub qualified_name: String,
    /// kind.
    pub kind: MachoSwiftNominalKindV1,
    /// metadata va.
    pub metadata_va: u64,
    /// descriptor.
    pub descriptor: MachoSwiftStaticPointerTargetV1,
    /// value witness table.
    pub value_witness_table: Option<MachoSwiftStaticPointerTargetV1>,
    /// evidence va.
    pub evidence_va: u64,
    /// evidence length.
    pub evidence_length: u64,
    /// layout.
    pub layout: Option<MachoSwiftValueWitnessLayoutV1>,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

/// Conserved, bounded result of decoding already-materialized Swift metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftStaticMetadataBatchV1 {
    /// Overall decode outcome.
    pub outcome: SwiftDecodeOutcomeV1,
    /// Complete retained metadata records.
    pub records: Vec<MachoSwiftStaticMetadataV1>,
    /// Typed reasons why the complete candidate set could not be retained.
    pub gaps: Vec<SwiftDecodeGapV1>,
    /// Candidate accounting for this leaf.
    pub conservation: SwiftObservationConservationV1,
}

impl SwiftStaticMetadataBatchV1 {
    /// Validate fail-closed outcome and conservation invariants.
    pub fn validate(&self) -> Result<(), String> {
        self.conservation.validate()?;
        let retained = u64::try_from(self.records.len())
            .map_err(|_| "Swift static metadata record count exceeds u64".to_string())?;
        if retained != self.conservation.included {
            return Err(
                "Swift static metadata included count differs from retained records".into(),
            );
        }
        match self.outcome {
            SwiftDecodeOutcomeV1::Absent
                if self.conservation.attempted == 0
                    && self.records.is_empty()
                    && self.gaps.is_empty() => {}
            SwiftDecodeOutcomeV1::Complete
                if self.conservation.attempted == self.conservation.included
                    && self.conservation.unknown == 0
                    && self.conservation.excluded == 0
                    && self.gaps.is_empty() => {}
            SwiftDecodeOutcomeV1::Rejected
                if self.records.is_empty()
                    && self.conservation.included == 0
                    && self.conservation.unknown == self.conservation.attempted
                    && self.conservation.excluded == 0
                    && !self.gaps.is_empty() => {}
            _ => return Err("Swift static metadata outcome and evidence disagree".into()),
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Macho Swift Witness Pointer Provenance V1 evidence.
pub enum MachoSwiftWitnessPointerProvenanceV1 {
    /// Direct.
    Direct,
    /// Chained Rebase.
    ChainedRebase,
    /// Chained Auth Rebase.
    ChainedAuthRebase {
        /// diversity.
        diversity: u16,
        /// key.
        key: u8,
        /// address diversity.
        address_diversity: bool,
    },
    /// Chained Bind.
    ChainedBind,
    /// Chained Auth Bind.
    ChainedAuthBind {
        /// diversity.
        diversity: u16,
        /// key.
        key: u8,
        /// address diversity.
        address_diversity: bool,
    },
    /// Legacy Rebase.
    LegacyRebase,
    /// Legacy Bind.
    LegacyBind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Macho Swift Witness Pointer Target V1 evidence.
pub enum MachoSwiftWitnessPointerTargetV1 {
    /// Resolved.
    Resolved {
        /// Resolved in-image address.
        va: u64,
    },
    /// External.
    External {
        /// Imported symbol name.
        symbol: String,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Witness Pattern Entry V1 evidence.
pub struct MachoSwiftWitnessPatternEntryV1 {
    /// requirement index.
    pub requirement_index: u32,
    /// slot va.
    pub slot_va: u64,
    /// target.
    pub target: MachoSwiftWitnessPointerTargetV1,
    /// provenance.
    pub provenance: MachoSwiftWitnessPointerProvenanceV1,
    /// raw sha256.
    pub raw_sha256: EvidenceDigest,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
/// Macho Swift Witness Table Pattern V1 evidence.
pub struct MachoSwiftWitnessTablePatternV1 {
    /// pattern va.
    pub pattern_va: u64,
    /// conformance slot va.
    pub conformance_slot_va: u64,
    /// conformance pointer provenance.
    pub conformance_pointer_provenance: MachoSwiftWitnessPointerProvenanceV1,
    /// entries.
    pub entries: Vec<MachoSwiftWitnessPatternEntryV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
/// Macho Swift Generic Requirement Kind V1 evidence.
pub enum MachoSwiftGenericRequirementKindV1 {
    /// Protocol.
    Protocol,
    /// Same Type.
    SameType,
    /// Base Class.
    BaseClass,
    /// Same Conformance.
    SameConformance,
    /// Layout.
    Layout,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
/// Macho Swift Generic Requirement Constraint V1 evidence.
pub enum MachoSwiftGenericRequirementConstraintV1 {
    /// Protocol.
    Protocol {
        /// descriptor va.
        descriptor_va: u64,
    },
    /// Same Type.
    SameType {
        /// type mangling va.
        type_mangling_va: u64,
        /// type mangling.
        type_mangling: Vec<u8>,
    },
    /// Base Class.
    BaseClass {
        /// type mangling va.
        type_mangling_va: u64,
        /// type mangling.
        type_mangling: Vec<u8>,
    },
    /// Same Conformance.
    SameConformance {
        /// descriptor va.
        descriptor_va: u64,
    },
    /// Layout.
    Layout {
        /// layout kind.
        layout_kind: u32,
    },
}
