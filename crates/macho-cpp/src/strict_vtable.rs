//! Strict, bounded Itanium virtual-table and VTT leaf records.

use serde::{Deserialize, Deserializer, Serialize};

use crate::strict_rtti::{
    StrictPointerObservation, StrictRttiConservation, StrictRttiGap, StrictRttiLimits,
    StrictRttiObservation, StrictRttiObservationKind, StrictRttiOutcome,
};
use crate::{Error, Result};

#[path = "strict_vtable_decoder.rs"]
mod decoder;
pub use decoder::{decode_strict_vtables, decode_strict_vtables_from_source};

const HARD_RECORDS: u64 = 4_000_000;
const HARD_WORDS: u64 = 64_000_000;
const HARD_EVIDENCE_BYTES: u64 = 1 << 31;
const HARD_INPUT_BYTES: u64 = 1 << 34;
const HARD_SYMBOLS: u64 = 16_000_000;

/// Structural limits for one strict Itanium virtual-table decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StrictVtableLimits {
    /// Maximum selected thin-image byte length.
    pub max_input_bytes: u64,
    /// Maximum symbols admitted before candidate discovery.
    pub max_symbols: u64,
    /// Maximum `_ZTV`, `_ZTC`, and `_ZTT` candidates.
    pub max_records: u64,
    /// Maximum pointer-width words across all defined candidates.
    pub max_words: u64,
    /// Maximum total bytes covered by observations.
    pub max_evidence_bytes: u64,
}

impl Default for StrictVtableLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1 << 30,
            max_symbols: 4_000_000,
            max_records: 1_000_000,
            max_words: 8_000_000,
            max_evidence_bytes: 1 << 29,
        }
    }
}

impl StrictVtableLimits {
    /// Reject zero limits and values above implementation hard maxima.
    pub fn validate(self) -> Result<()> {
        for (value, hard, name) in [
            (self.max_input_bytes, HARD_INPUT_BYTES, "vtable input-byte"),
            (self.max_symbols, HARD_SYMBOLS, "vtable symbol"),
            (self.max_records, HARD_RECORDS, "vtable record"),
            (self.max_words, HARD_WORDS, "vtable word"),
            (
                self.max_evidence_bytes,
                HARD_EVIDENCE_BYTES,
                "vtable evidence-byte",
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

    pub(crate) fn reader_limits(self) -> StrictRttiLimits {
        StrictRttiLimits {
            max_input_bytes: self.max_input_bytes,
            max_symbols: self.max_symbols,
            max_records: self.max_records,
            max_evidence_bytes: self.max_evidence_bytes,
            ..StrictRttiLimits::default()
        }
    }
}

/// ABI role of one special-name symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItaniumVtableSymbolKind {
    /// Complete-object virtual table group (`_ZTV`).
    CompleteGroup,
    /// Construction virtual table group (`_ZTC`).
    ConstructionGroup,
    /// Virtual table table (`_ZTT`).
    Vtt,
}

/// Authority used to bound a Mach-O symbol that has no encoded size.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItaniumVtableExtentSource {
    /// The next defined symbol in the same section.
    NextDefinedSymbol,
    /// The end of the containing file-backed section.
    SectionEnd,
}

/// Best leaf-level role for a pre-address-point offset component.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItaniumVtableOffsetRole {
    /// The leaf image cannot distinguish vcall from vbase without graph context.
    VcallOrVbase,
}

/// Structural authority that located one address-point header.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItaniumVtableAddressPointSource {
    /// The typeinfo word resolves to an exact `_ZTI` symbol.
    TypeinfoSymbol,
    /// No `_ZTI` target exists and a null typeinfo word follows symbol word zero.
    NullTypeinfoAtSymbolStart,
}

/// One encoded thunk adjustment.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ItaniumThunkAdjustment {
    /// Fixed adjustment to a non-virtual base.
    NonVirtual {
        /// Signed byte displacement.
        offset: i64,
    },
    /// Fixed adjustment followed by a vtable-loaded virtual adjustment.
    Virtual {
        /// Signed displacement to the nearest virtual base.
        offset: i64,
        /// Signed byte displacement of the vcall/vbase offset entry.
        virtual_offset: i64,
    },
}

/// Function-slot semantic role proven by its exact target symbol.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItaniumVtableSlotRole {
    /// Ordinary function or an exact function symbol without a narrower role.
    Function,
    /// `__cxa_pure_virtual`.
    PureVirtual,
    /// `__cxa_deleted_virtual`.
    DeletedVirtual,
    /// D0 deleting destructor.
    DeletingDestructor,
    /// D1 complete-object destructor.
    CompleteDestructor,
    /// D2 base-object destructor.
    BaseDestructor,
    /// `Th` non-virtual override thunk.
    NonVirtualThunk,
    /// `Tv` virtual override thunk.
    VirtualThunk,
    /// `Tc` covariant-return thunk.
    CovariantThunk,
    /// Null virtual entry.
    Null,
    /// A resolved target with no exact symbol role.
    Unknown,
}

/// One word before an address-point header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVtableOffsetRecord {
    /// Absolute word ordinal in the containing symbol.
    pub word_ordinal: u64,
    /// Observation containing the pointer-width signed integer.
    pub observation_ordinal: u64,
    /// Raw unsigned storage value.
    pub raw_value: u64,
    /// Sign-extended ABI value.
    pub signed_value: i64,
    /// Leaf-level offset role.
    pub role: ItaniumVtableOffsetRole,
}

/// One function-entry candidate after an address point.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVtableSlotRecord {
    /// Zero-based slot ordinal within this address point.
    pub ordinal: u64,
    /// Absolute word ordinal in the containing symbol.
    pub word_ordinal: u64,
    /// Full pointer and fixup provenance.
    pub pointer: StrictPointerObservation,
    /// Exact target symbol when one is present.
    pub target_symbol: Option<String>,
    /// Function, destructor, thunk, pure/deleted, null, or unknown role.
    pub role: ItaniumVtableSlotRole,
    /// `this` adjustment encoded by a thunk name.
    pub this_adjustment: Option<ItaniumThunkAdjustment>,
    /// Return adjustment encoded by a covariant thunk name.
    pub return_adjustment: Option<ItaniumThunkAdjustment>,
}

/// One ABI address point and its structural header.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVtableAddressPointRecord {
    /// Zero-based address-point ordinal in the group.
    pub ordinal: u64,
    /// Address-point virtual address, immediately after the typeinfo pointer.
    pub va: u64,
    /// Structural authority used to locate this header.
    pub source: ItaniumVtableAddressPointSource,
    /// Word ordinal of the offset-to-top field.
    pub offset_to_top_word: u64,
    /// Offset components preceding the header when their ownership is exact.
    pub prefix_offsets: Vec<ItaniumVtableOffsetRecord>,
    /// Observation containing offset-to-top.
    pub offset_to_top_observation_ordinal: u64,
    /// Signed offset from this subobject to the complete object.
    pub offset_to_top: i64,
    /// Typeinfo pointer, including a distinct null state for `-fno-rtti`.
    pub typeinfo: StrictPointerObservation,
    /// Slots owned unambiguously by this address point.
    pub slots: Vec<ItaniumVtableSlotRecord>,
}

/// Words between address points whose slot/offset ownership requires graph context.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVtableAmbiguousWordRecord {
    /// Absolute word ordinal in the containing symbol.
    pub word_ordinal: u64,
    /// Observation containing the raw word.
    pub observation_ordinal: u64,
    /// Raw unsigned storage value.
    pub raw_value: u64,
}

/// Strict complete or construction virtual-table group.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVtableGroupRecord {
    /// Exact `_ZTV` or `_ZTC` symbol spelling.
    pub symbol: String,
    /// Complete-object or construction-table kind.
    pub kind: ItaniumVtableSymbolKind,
    /// Symbol virtual address.
    pub va: u64,
    /// Symbol thin-image file offset.
    pub file_offset: u64,
    /// Exact bounded extent in bytes.
    pub byte_length: u64,
    /// Mach-O authority used for the extent.
    pub extent_source: ItaniumVtableExtentSource,
    /// Pointer width in bytes; relative-vtable encodings are rejected.
    pub pointer_width: u8,
    /// Structurally proven address points.
    pub address_points: Vec<ItaniumVtableAddressPointRecord>,
    /// Conserved inter-address-point words whose role is not leaf-decidable.
    pub ambiguous_words: Vec<ItaniumVtableAmbiguousWordRecord>,
    /// Whether the definition is weak.
    pub weak_definition: bool,
}

/// One pointer entry in a VTT array.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVttEntryRecord {
    /// Zero-based VTT ordinal. Nested VTT roles are assigned by graph context.
    pub ordinal: u64,
    /// Pointer to an address point in a complete or construction table.
    pub address_point: StrictPointerObservation,
}

/// Strict VTT array.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ItaniumVttRecord {
    /// Exact `_ZTT` symbol spelling.
    pub symbol: String,
    /// Symbol virtual address.
    pub va: u64,
    /// Symbol thin-image file offset.
    pub file_offset: u64,
    /// Exact bounded extent in bytes.
    pub byte_length: u64,
    /// Mach-O authority used for the extent.
    pub extent_source: ItaniumVtableExtentSource,
    /// Entries in ABI array order.
    pub entries: Vec<ItaniumVttEntryRecord>,
    /// Whether the definition is weak.
    pub weak_definition: bool,
}

/// One included strict virtual-table record.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StrictVtableRecord {
    /// Complete or construction vtable group.
    Group {
        /// Decoded group.
        record: Box<ItaniumVtableGroupRecord>,
    },
    /// VTT array.
    Vtt {
        /// Decoded VTT.
        record: Box<ItaniumVttRecord>,
    },
    /// Undefined special-name symbol retained rather than dropped.
    External {
        /// Special-name family.
        symbol_kind: ItaniumVtableSymbolKind,
        /// Exact symbol spelling.
        symbol: String,
        /// Mach-O library ordinal.
        library_ordinal: i32,
        /// Weak-reference bit.
        weak: bool,
    },
}

/// Closed strict vtable/VTT decode batch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StrictVtableBatch {
    /// Terminal outcome.
    pub outcome: StrictRttiOutcome,
    /// Included records in canonical symbol/address order.
    pub records: Vec<StrictVtableRecord>,
    /// Exact byte observations in decode order.
    pub observations: Vec<StrictRttiObservation>,
    /// Typed failures.
    pub gaps: Vec<StrictRttiGap>,
    /// Candidate conservation ledger.
    pub conservation: StrictRttiConservation,
}

impl StrictVtableBatch {
    pub(crate) fn validate(&self, limits: StrictVtableLimits) -> Result<()> {
        limits.validate()?;
        self.conservation.validate()?;
        if self.observations.iter().enumerate().any(|(index, value)| {
            value.ordinal != u64::try_from(index).unwrap_or(u64::MAX) || value.length == 0
        }) {
            return Err(Error::format(
                "strict vtable observations are not canonical",
            ));
        }
        let evidence = self.observations.iter().try_fold(0_u64, |total, value| {
            total
                .checked_add(value.length)
                .ok_or_else(|| Error::format("strict vtable evidence overflows"))
        })?;
        if evidence > limits.max_evidence_bytes
            || u64::try_from(self.records.len()).ok() != Some(self.conservation.included)
        {
            return Err(Error::format(
                "strict vtable counts exceed limits or disagree",
            ));
        }
        let expected_gaps = self
            .conservation
            .unknown
            .checked_add(u64::from(self.conservation.excluded > 0))
            .and_then(|value| {
                value.checked_add(u64::from(
                    self.outcome == StrictRttiOutcome::Rejected && self.conservation.attempted == 0,
                ))
            })
            .ok_or_else(|| Error::format("strict vtable gap count overflows"))?;
        if u64::try_from(self.gaps.len()).ok() != Some(expected_gaps) {
            return Err(Error::format(
                "strict vtable gaps do not reconstruct conservation",
            ));
        }
        let mut prior: Option<(String, u64)> = None;
        let mut words = 0_u64;
        for record in &self.records {
            let (symbol, va, record_words) = match record {
                StrictVtableRecord::Group { record } => {
                    self.validate_group(record)?;
                    (
                        &record.symbol,
                        record.va,
                        record.byte_length / u64::from(record.pointer_width),
                    )
                }
                StrictVtableRecord::Vtt { record } => {
                    self.validate_vtt(record)?;
                    (
                        &record.symbol,
                        record.va,
                        u64::try_from(record.entries.len()).unwrap_or(u64::MAX),
                    )
                }
                StrictVtableRecord::External {
                    symbol_kind,
                    symbol,
                    ..
                } => {
                    if decoder::classify_symbol(symbol) != Some(*symbol_kind) {
                        return Err(Error::format("strict external vtable symbol is invalid"));
                    }
                    (symbol, 0, 0)
                }
            };
            let key = (symbol.clone(), va);
            if prior.as_ref().is_some_and(|value| value >= &key) {
                return Err(Error::format(
                    "strict vtable records are not canonical and unique",
                ));
            }
            prior = Some(key);
            words = words
                .checked_add(record_words)
                .ok_or_else(|| Error::format("strict vtable word count overflows"))?;
        }
        if words > limits.max_words {
            return Err(Error::format("strict vtable word limit exceeded"));
        }
        match self.outcome {
            StrictRttiOutcome::Absent
                if self.conservation.attempted == 0 && self.gaps.is_empty() => {}
            StrictRttiOutcome::Complete
                if self.conservation.attempted > 0
                    && self.gaps.is_empty()
                    && self.conservation.included == self.conservation.attempted => {}
            StrictRttiOutcome::Rejected if !self.gaps.is_empty() => {}
            _ => {
                return Err(Error::format(
                    "strict vtable outcome and conservation disagree",
                ));
            }
        }
        Ok(())
    }

    fn validate_group(&self, record: &ItaniumVtableGroupRecord) -> Result<()> {
        if !matches!(
            record.kind,
            ItaniumVtableSymbolKind::CompleteGroup | ItaniumVtableSymbolKind::ConstructionGroup
        ) || decoder::classify_symbol(&record.symbol) != Some(record.kind)
            || !matches!(record.pointer_width, 4 | 8)
            || record.byte_length == 0
            || record.byte_length % u64::from(record.pointer_width) != 0
            || record.address_points.is_empty()
        {
            return Err(Error::format("strict vtable group shape is invalid"));
        }
        let mut used = std::collections::BTreeSet::new();
        for (index, point) in record.address_points.iter().enumerate() {
            if point.ordinal != index as u64
                || point.va
                    != record.va + (point.offset_to_top_word + 2) * u64::from(record.pointer_width)
            {
                return Err(Error::format(
                    "strict vtable address point is not canonical",
                ));
            }
            let source_matches = match point.source {
                ItaniumVtableAddressPointSource::TypeinfoSymbol => !matches!(
                    point.typeinfo.target,
                    crate::strict_rtti::StrictPointerTarget::Null
                ),
                ItaniumVtableAddressPointSource::NullTypeinfoAtSymbolStart => {
                    index == 0
                        && point.offset_to_top_word == 0
                        && matches!(
                            point.typeinfo.target,
                            crate::strict_rtti::StrictPointerTarget::Null
                        )
                }
            };
            if !source_matches {
                return Err(Error::format(
                    "strict vtable address-point source disagrees with its header",
                ));
            }
            self.validate_integer(
                &record.symbol,
                point.offset_to_top_observation_ordinal,
                record.pointer_width,
                &mut used,
            )?;
            self.validate_pointer(&record.symbol, &point.typeinfo, &mut used)?;
            for offset in &point.prefix_offsets {
                self.validate_integer(
                    &record.symbol,
                    offset.observation_ordinal,
                    record.pointer_width,
                    &mut used,
                )?;
                if offset.signed_value != sign_extend(offset.raw_value, record.pointer_width) {
                    return Err(Error::format(
                        "strict vtable offset sign extension disagrees",
                    ));
                }
            }
            for (slot_index, slot) in point.slots.iter().enumerate() {
                if slot.ordinal != slot_index as u64 {
                    return Err(Error::format("strict vtable slots are not canonical"));
                }
                self.validate_pointer(&record.symbol, &slot.pointer, &mut used)?;
                decoder::validate_slot_semantics(slot)?;
            }
        }
        for word in &record.ambiguous_words {
            self.validate_integer(
                &record.symbol,
                word.observation_ordinal,
                record.pointer_width,
                &mut used,
            )?;
        }
        let expected = record.byte_length / u64::from(record.pointer_width);
        if u64::try_from(used.len()).ok() != Some(expected) {
            return Err(Error::format(
                "strict vtable group does not conserve every word exactly once",
            ));
        }
        Ok(())
    }

    fn validate_vtt(&self, record: &ItaniumVttRecord) -> Result<()> {
        if decoder::classify_symbol(&record.symbol) != Some(ItaniumVtableSymbolKind::Vtt)
            || record.byte_length == 0
            || record.entries.is_empty()
        {
            return Err(Error::format("strict VTT shape is invalid"));
        }
        let mut used = std::collections::BTreeSet::new();
        for (index, entry) in record.entries.iter().enumerate() {
            if entry.ordinal != index as u64 {
                return Err(Error::format("strict VTT entries are not canonical"));
            }
            self.validate_pointer(&record.symbol, &entry.address_point, &mut used)?;
        }
        if record.byte_length
            != record.entries.len() as u64 * u64::from(record.entries[0].address_point.width)
        {
            return Err(Error::format("strict VTT extent differs from its entries"));
        }
        Ok(())
    }

    fn validate_pointer(
        &self,
        symbol: &str,
        pointer: &StrictPointerObservation,
        used: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        let observation = self
            .observations
            .get(pointer.observation_ordinal as usize)
            .ok_or_else(|| Error::format("strict vtable pointer observation is absent"))?;
        if observation.symbol != symbol
            || observation.kind != StrictRttiObservationKind::Pointer
            || observation.length != u64::from(pointer.width)
            || !used.insert(pointer.observation_ordinal)
        {
            return Err(Error::format(
                "strict vtable pointer observation disagrees or aliases",
            ));
        }
        Ok(())
    }

    fn validate_integer(
        &self,
        symbol: &str,
        ordinal: u64,
        width: u8,
        used: &mut std::collections::BTreeSet<u64>,
    ) -> Result<()> {
        let observation = self
            .observations
            .get(ordinal as usize)
            .ok_or_else(|| Error::format("strict vtable integer observation is absent"))?;
        if observation.symbol != symbol
            || observation.kind != StrictRttiObservationKind::Integer
            || observation.length != u64::from(width)
            || !used.insert(ordinal)
        {
            return Err(Error::format(
                "strict vtable integer observation disagrees or aliases",
            ));
        }
        Ok(())
    }
}

pub(crate) fn sign_extend(value: u64, width: u8) -> i64 {
    if width == 4 {
        i64::from(value as u32 as i32)
    } else {
        value as i64
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictVtableBatchWire {
    outcome: StrictRttiOutcome,
    records: Vec<StrictVtableRecord>,
    observations: Vec<StrictRttiObservation>,
    gaps: Vec<StrictRttiGap>,
    conservation: StrictRttiConservation,
}

impl<'de> Deserialize<'de> for StrictVtableBatch {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = StrictVtableBatchWire::deserialize(deserializer)?;
        let value = Self {
            outcome: wire.outcome,
            records: wire.records,
            observations: wire.observations,
            gaps: wire.gaps,
            conservation: wire.conservation,
        };
        value
            .validate(StrictVtableLimits::default())
            .map_err(serde::de::Error::custom)?;
        Ok(value)
    }
}
