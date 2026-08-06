//! Strict, bounded Itanium C++ RTTI leaf records.

use serde::{Deserialize, Deserializer, Serialize};

use crate::metadata::cpp::{Error, Result};

#[path = "strict_rtti_decoder.rs"]
pub(crate) mod decoder;
pub use decoder::{decode_strict_rtti, decode_strict_rtti_from_source};

const HARD_RECORDS: u64 = 4_000_000;
const HARD_SYMBOLS: u64 = 16_000_000;
const HARD_BASES: u64 = 8_000_000;
const HARD_NAME_BYTES: u64 = 65_536;
const HARD_EVIDENCE_BYTES: u64 = 1 << 31;
const HARD_INPUT_BYTES: u64 = 1 << 34;

/// Structural limits for one strict Itanium RTTI decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictRttiLimits {
    /// Maximum selected thin-image byte length.
    pub max_input_bytes: u64,
    /// Maximum symbols admitted before RTTI candidate discovery.
    pub max_symbols: u64,
    /// Maximum defined and external `_ZTI` records admitted from the symbol table.
    pub max_records: u64,
    /// Maximum direct bases admitted across all VMI records.
    pub max_bases: u64,
    /// Maximum bytes, excluding the terminator, in one type-name object.
    pub max_name_bytes: u64,
    /// Maximum total bytes covered by retained observations.
    pub max_evidence_bytes: u64,
}

impl Default for StrictRttiLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1 << 30,
            max_symbols: 4_000_000,
            max_records: 1_000_000,
            max_bases: 2_000_000,
            max_name_bytes: 4_096,
            max_evidence_bytes: 1 << 29,
        }
    }
}

impl StrictRttiLimits {
    /// Reject zero limits and values above the implementation hard maxima.
    pub fn validate(self) -> Result<()> {
        for (value, hard, name) in [
            (self.max_input_bytes, HARD_INPUT_BYTES, "RTTI input-byte"),
            (self.max_symbols, HARD_SYMBOLS, "RTTI symbol"),
            (self.max_records, HARD_RECORDS, "RTTI record"),
            (self.max_bases, HARD_BASES, "RTTI base"),
            (self.max_name_bytes, HARD_NAME_BYTES, "RTTI name-byte"),
            (
                self.max_evidence_bytes,
                HARD_EVIDENCE_BYTES,
                "RTTI evidence-byte",
            ),
        ] {
            if value == 0 || value > hard {
                return Err(Error::format(format!(
                    "{name} limit is zero or exceeds its hard maximum"
                )));
            }
        }
        Ok(())
    }
}

/// Terminal state of a strict RTTI batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictRttiOutcome {
    /// No defined or external Itanium typeinfo symbols exist.
    Absent,
    /// Every candidate was decoded and conserved.
    Complete,
    /// At least one candidate or required field failed strict decoding.
    Rejected,
}

/// Exact conservation ledger for symbol-table RTTI candidates.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictRttiConservation {
    /// Total `_ZTI` candidates attempted.
    pub attempted: u64,
    /// Candidates represented by complete records.
    pub included: u64,
    /// Candidates retained as typed gaps.
    pub unknown: u64,
    /// Candidates excluded by a structural budget before decoding.
    pub excluded: u64,
}

impl StrictRttiConservation {
    pub(crate) fn validate(self) -> Result<()> {
        let balanced = self
            .included
            .checked_add(self.unknown)
            .and_then(|value| value.checked_add(self.excluded));
        if balanced != Some(self.attempted) {
            return Err(Error::format("strict RTTI conservation does not balance"));
        }
        Ok(())
    }
}

/// Closed strict-decoder gap registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictRttiGapCode {
    /// A structural count or evidence budget was exceeded.
    StructuralLimitExceeded,
    /// A required pointer could not be decoded or resolved.
    PointerUnresolved,
    /// A required record field was malformed or out of bounds.
    RecordMalformed,
    /// The runtime typeinfo implementation family is not admitted.
    FamilyUnsupported,
    /// A type-name object was unterminated, oversized, or not UTF-8.
    TypeNameInvalid,
}

/// One failed candidate or batch-wide structural rejection.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictRttiGap {
    /// Candidate symbol, or `None` for a batch-wide limit failure.
    pub symbol: Option<String>,
    /// Exact field or registry subject that failed.
    pub field: String,
    /// Stable machine-readable failure code.
    pub code: StrictRttiGapCode,
    /// Source error code when one exists.
    pub source_code: Option<String>,
}

/// Kind of byte range retained as strict evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StrictRttiObservationKind {
    /// Pointer-sized field.
    Pointer,
    /// Fixed-width integer field.
    Integer,
    /// NUL-terminated type-name bytes including the terminator.
    TypeName,
}

/// One exact file-backed observation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictRttiObservation {
    /// Canonical zero-based ordinal in this batch.
    pub ordinal: u64,
    /// Candidate symbol that owns the field.
    pub symbol: String,
    /// ABI field name.
    pub field: String,
    /// Virtual address of the observed bytes.
    pub va: u64,
    /// Thin-image file offset of the observed bytes.
    pub file_offset: u64,
    /// Exact byte length.
    pub length: u64,
    /// Observation interpretation.
    pub kind: StrictRttiObservationKind,
}

/// Pointer encoding or fixup mechanism used by one field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrictPointerEncoding {
    /// Ordinary pointer bytes with no covering fixup record.
    Direct,
    /// Chained rebase.
    ChainedRebase,
    /// Chained import bind.
    ChainedBind {
        /// Import addend retained from the chained-import table.
        addend: i64,
        /// Whether the import is weak.
        weak: bool,
    },
    /// Legacy dyld rebase opcode.
    LegacyRebase,
    /// Legacy dyld bind opcode.
    LegacyBind {
        /// Bind addend.
        addend: i64,
        /// Whether the bind is weak.
        weak: bool,
        /// Whether the bind is lazy.
        lazy: bool,
    },
}

/// Pointer-authentication state retained independently from target resolution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrictPointerAuthentication {
    /// The pointer format is not authenticated.
    NotApplicable,
    /// The chained fixup carries authenticated-pointer metadata.
    Authenticated {
        /// ABI key selector.
        key: u8,
        /// Diversity discriminator.
        diversity: u16,
        /// Whether the storage address participates in diversification.
        address_diversity: bool,
    },
}

/// Resolved target of one pointer-valued RTTI field.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrictPointerTarget {
    /// Null pointer.
    Null,
    /// Address within the selected image.
    Local {
        /// Unslid virtual address.
        va: u64,
    },
    /// Imported symbol outside the selected image.
    External {
        /// Exact symbol spelling.
        symbol: String,
        /// Mach-O library ordinal.
        library_ordinal: i32,
    },
}

/// Full pointer observation including raw storage and resolution provenance.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictPointerObservation {
    /// Ordinal of the corresponding byte observation.
    pub observation_ordinal: u64,
    /// Raw pointer-sized value as stored in the file.
    pub raw_value: u64,
    /// Pointer width in bytes.
    pub width: u8,
    /// Encoding or fixup mechanism.
    pub encoding: StrictPointerEncoding,
    /// Pointer-authentication state.
    pub authentication: StrictPointerAuthentication,
    /// Resolved local, external, or null target.
    pub target: StrictPointerTarget,
}

/// Complete admitted Itanium `type_info` implementation family.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItaniumTypeInfoFamily {
    /// `__fundamental_type_info`.
    Fundamental,
    /// `__array_type_info`.
    Array,
    /// `__function_type_info`.
    Function,
    /// `__enum_type_info`.
    Enum,
    /// `__class_type_info`.
    Class,
    /// `__si_class_type_info`.
    SingleInheritanceClass,
    /// `__vmi_class_type_info`.
    VirtualMultipleInheritanceClass,
    /// `__pointer_type_info`.
    Pointer,
    /// `__pointer_to_member_type_info`.
    PointerToMember,
    /// Qualified pbase variant retained from its flags.
    Qualified,
}

/// One direct base entry in ABI declaration order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumBaseRecord {
    /// Zero-based direct-base ordinal.
    pub ordinal: u64,
    /// Exact base typeinfo pointer.
    pub typeinfo: StrictPointerObservation,
    /// Raw `offset_flags` word.
    pub offset_flags: u64,
    /// Signed non-virtual offset or signed vbase-slot displacement.
    pub signed_offset: i64,
    /// Virtual-base flag.
    pub is_virtual: bool,
    /// Public-base flag.
    pub is_public: bool,
}

/// Pointee and optional member-owner links for pbase families.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumPointeeRecord {
    /// Raw ABI qualifier/incomplete flags.
    pub flags: u32,
    /// Pointee typeinfo pointer.
    pub pointee: StrictPointerObservation,
    /// Containing-class typeinfo for pointer-to-member records.
    pub member_of: Option<StrictPointerObservation>,
}

/// Strict file-backed typeinfo object.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumTypeInfoRecord {
    /// Exact `_ZTI` symbol spelling.
    pub symbol: String,
    /// Typeinfo object virtual address.
    pub va: u64,
    /// Typeinfo object thin-image file offset.
    pub file_offset: u64,
    /// Runtime implementation family selected from the vptr target.
    pub family: ItaniumTypeInfoFamily,
    /// Exact encoded type-name bytes interpreted as UTF-8.
    pub type_name: String,
    /// Darwin's high-bit type-name tag marks this RTTI identity non-unique.
    pub type_name_non_unique: bool,
    /// Runtime-family vptr observation.
    pub runtime_vtable: StrictPointerObservation,
    /// Type-name pointer observation.
    pub type_name_pointer: StrictPointerObservation,
    /// VMI class flags, zero for non-VMI records.
    pub class_flags: u32,
    /// Direct bases in ABI order.
    pub bases: Vec<ItaniumBaseRecord>,
    /// Pointee details for pointer families.
    pub pointee: Option<ItaniumPointeeRecord>,
    /// Whether the defining symbol is weak.
    pub weak_definition: bool,
}

/// One included strict RTTI record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrictRttiRecord {
    /// Complete file-backed typeinfo object.
    TypeInfo {
        /// Decoded object.
        record: Box<ItaniumTypeInfoRecord>,
    },
    /// Undefined external `_ZTI` symbol retained rather than dropped.
    ExternalTypeInfo {
        /// Exact symbol spelling.
        symbol: String,
        /// Library ordinal from `n_desc`.
        library_ordinal: i32,
        /// Weak-reference bit.
        weak: bool,
    },
}

/// Closed strict RTTI decode batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrictRttiBatch {
    /// Terminal batch outcome.
    pub outcome: StrictRttiOutcome,
    /// Included records in canonical symbol/address order.
    pub records: Vec<StrictRttiRecord>,
    /// Exact byte-range evidence in decode order.
    pub observations: Vec<StrictRttiObservation>,
    /// Typed failures; nonempty exactly when `outcome` is rejected.
    pub gaps: Vec<StrictRttiGap>,
    /// Candidate conservation ledger.
    pub conservation: StrictRttiConservation,
}

impl StrictRttiBatch {
    fn validate(&self, limits: StrictRttiLimits) -> Result<()> {
        limits.validate()?;
        self.conservation.validate()?;
        if self.observations.iter().enumerate().any(|(index, value)| {
            value.ordinal != u64::try_from(index).unwrap_or(u64::MAX) || value.length == 0
        }) {
            return Err(Error::format(
                "strict RTTI observations are not canonical and nonempty",
            ));
        }
        let evidence_bytes = self.observations.iter().try_fold(0_u64, |total, value| {
            total
                .checked_add(value.length)
                .ok_or_else(|| Error::format("strict RTTI evidence bytes overflow"))
        })?;
        if evidence_bytes > limits.max_evidence_bytes {
            return Err(Error::format("strict RTTI evidence exceeds its limit"));
        }
        if u64::try_from(self.records.len()).ok() != Some(self.conservation.included) {
            return Err(Error::format(
                "strict RTTI included count differs from its record count",
            ));
        }
        let preflight_gap = u64::from(
            self.outcome == StrictRttiOutcome::Rejected && self.conservation.attempted == 0,
        );
        let expected_gaps = self
            .conservation
            .unknown
            .checked_add(u64::from(self.conservation.excluded > 0))
            .and_then(|value| value.checked_add(preflight_gap))
            .ok_or_else(|| Error::format("strict RTTI expected gap count overflows"))?;
        if u64::try_from(self.gaps.len()).ok() != Some(expected_gaps)
            || self
                .gaps
                .iter()
                .any(|gap| gap.field.is_empty() || gap.field.chars().any(char::is_control))
        {
            return Err(Error::format(
                "strict RTTI gaps do not reconstruct unknown and excluded candidates",
            ));
        }
        let mut prior_key: Option<(String, u64)> = None;
        let mut base_count = 0_u64;
        for record in &self.records {
            let key = match record {
                StrictRttiRecord::TypeInfo { record } => {
                    self.validate_typeinfo(record, limits, &mut base_count)?;
                    (record.symbol.clone(), record.va)
                }
                StrictRttiRecord::ExternalTypeInfo { symbol, .. } => {
                    if symbol.is_empty() || !decoder::is_typeinfo_symbol(symbol) {
                        return Err(Error::format(
                            "strict external RTTI record has an invalid symbol",
                        ));
                    }
                    (symbol.clone(), 0)
                }
            };
            if prior_key.as_ref().is_some_and(|prior| prior >= &key) {
                return Err(Error::format(
                    "strict RTTI records are not canonical and unique",
                ));
            }
            prior_key = Some(key);
        }
        match self.outcome {
            StrictRttiOutcome::Absent
                if self.conservation.attempted == 0
                    && self.records.is_empty()
                    && self.gaps.is_empty() => {}
            StrictRttiOutcome::Complete
                if self.conservation.attempted > 0
                    && self.conservation.included == self.conservation.attempted
                    && self.gaps.is_empty() => {}
            StrictRttiOutcome::Rejected if !self.gaps.is_empty() => {}
            _ => {
                return Err(Error::format(
                    "strict RTTI outcome, gaps, and conservation disagree",
                ));
            }
        }
        Ok(())
    }

    fn validate_typeinfo(
        &self,
        record: &ItaniumTypeInfoRecord,
        limits: StrictRttiLimits,
        base_count: &mut u64,
    ) -> Result<()> {
        if record.symbol.is_empty()
            || !decoder::is_typeinfo_symbol(&record.symbol)
            || record.type_name.is_empty()
            || u64::try_from(record.type_name.len())
                .ok()
                .is_none_or(|length| length > limits.max_name_bytes)
        {
            return Err(Error::format(
                "strict RTTI record identity or name is invalid",
            ));
        }
        self.validate_pointer(&record.symbol, &record.runtime_vtable)?;
        self.validate_pointer(&record.symbol, &record.type_name_pointer)?;
        *base_count = base_count
            .checked_add(
                u64::try_from(record.bases.len())
                    .map_err(|_| Error::format("strict RTTI base count exceeds UInt64"))?,
            )
            .ok_or_else(|| Error::format("strict RTTI base count overflows"))?;
        if *base_count > limits.max_bases
            || record
                .bases
                .iter()
                .enumerate()
                .any(|(index, base)| base.ordinal != index as u64)
        {
            return Err(Error::format(
                "strict RTTI bases exceed limits or are not canonical",
            ));
        }
        for base in &record.bases {
            self.validate_pointer(&record.symbol, &base.typeinfo)?;
            if base.signed_offset != (base.offset_flags as i64) >> 8
                || base.is_virtual != (base.offset_flags & 1 != 0)
                || base.is_public != (base.offset_flags & 2 != 0)
            {
                return Err(Error::format(
                    "strict RTTI base semantics disagree with offset_flags",
                ));
            }
        }
        if let Some(pointee) = &record.pointee {
            self.validate_pointer(&record.symbol, &pointee.pointee)?;
            if let Some(member_of) = &pointee.member_of {
                self.validate_pointer(&record.symbol, member_of)?;
            }
        }
        let shape_matches = match record.family {
            ItaniumTypeInfoFamily::SingleInheritanceClass => {
                record.bases.len() == 1 && record.pointee.is_none() && record.class_flags == 0
            }
            ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass => record.pointee.is_none(),
            ItaniumTypeInfoFamily::Pointer => {
                record
                    .pointee
                    .as_ref()
                    .is_some_and(|pointee| pointee.member_of.is_none())
                    && record.bases.is_empty()
                    && record.class_flags == 0
            }
            ItaniumTypeInfoFamily::PointerToMember => {
                record
                    .pointee
                    .as_ref()
                    .is_some_and(|pointee| pointee.member_of.is_some())
                    && record.bases.is_empty()
                    && record.class_flags == 0
            }
            _ => record.bases.is_empty() && record.pointee.is_none() && record.class_flags == 0,
        };
        if !shape_matches {
            return Err(Error::format(
                "strict RTTI family disagrees with its family-specific fields",
            ));
        }
        Ok(())
    }

    fn validate_pointer(&self, symbol: &str, pointer: &StrictPointerObservation) -> Result<()> {
        let observation = usize::try_from(pointer.observation_ordinal)
            .ok()
            .and_then(|index| self.observations.get(index))
            .ok_or_else(|| Error::format("strict RTTI pointer observation is absent"))?;
        if observation.symbol != symbol
            || observation.kind != StrictRttiObservationKind::Pointer
            || observation.length != u64::from(pointer.width)
            || !matches!(pointer.width, 4 | 8)
        {
            return Err(Error::format(
                "strict RTTI pointer disagrees with its byte observation",
            ));
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictRttiBatchWire {
    outcome: StrictRttiOutcome,
    records: Vec<StrictRttiRecord>,
    observations: Vec<StrictRttiObservation>,
    gaps: Vec<StrictRttiGap>,
    conservation: StrictRttiConservation,
}

impl<'de> Deserialize<'de> for StrictRttiBatch {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StrictRttiBatchWire::deserialize(deserializer)?;
        let value = Self {
            outcome: wire.outcome,
            records: wire.records,
            observations: wire.observations,
            gaps: wire.gaps,
            conservation: wire.conservation,
        };
        value
            .validate(StrictRttiLimits::default())
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}
