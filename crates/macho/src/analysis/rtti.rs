//! Image-bound Itanium RTTI, vtable, and type-relationship recovery.

use std::collections::{BTreeMap, BTreeSet};

use crate::core::format::constants::SectionAttributes;
use crate::core::model::addr::Va;
use crate::core::model::load_command::LoadCommand;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::section::{Section, SectionType};
use crate::core::model::symbol::SymbolTable;
use crate::metadata::cpp::{
    ItaniumTypeInfoFamily, ItaniumTypeInfoRecord, ItaniumVtableGroupRecord, StrictPointerTarget,
    StrictRttiBatch, StrictRttiConservation, StrictRttiLimits, StrictRttiOutcome, StrictRttiRecord,
    StrictVtableBatch, StrictVtableLimits, StrictVtableRecord, decode_strict_rtti,
    decode_strict_vtables,
};
use crate::metadata::dyld::ExportKind;
use crate::metadata::dyld::resolve::{
    PointerAuthentication, PointerEncoding, PointerObservation, PointerResolver, PointerTarget,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::functions::FunctionImageIdentity;

/// Explicit strict and structural limits for one RTTI recovery operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct RttiRecoveryLimits {
    /// Itanium type-info limits.
    pub type_info: StrictRttiLimits,
    /// Itanium vtable and VTT limits.
    pub vtables: StrictVtableLimits,
}

impl RttiRecoveryLimits {
    /// Validate both strict decoder limit sets.
    pub fn validate(self) -> Result<Self, RttiRecoveryError> {
        self.type_info
            .validate()
            .map_err(|error| RttiRecoveryError::InvalidLimits(error.to_string()))?;
        self.vtables
            .validate()
            .map_err(|error| RttiRecoveryError::InvalidLimits(error.to_string()))?;
        Ok(self)
    }
}

/// Failure preventing the strict RTTI stage from producing a closed batch.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RttiRecoveryError {
    /// A strict structural limit is invalid.
    #[error("invalid RTTI limits: {0}")]
    InvalidLimits(String),
    /// Type-info decoding failed before a conservation batch could be built.
    #[error("strict type-info decoding failed: {0}")]
    TypeInfo(String),
    /// Vtable decoding failed before a conservation batch could be built.
    #[error("strict vtable decoding failed: {0}")]
    Vtables(String),
    /// Structural pointer evidence could not be indexed.
    #[error("structural RTTI recovery failed: {0}")]
    Structural(String),
}

/// Strict RTTI subcollector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RttiCollector {
    /// Itanium `_ZTI` type-info records.
    TypeInfo,
    /// Itanium `_ZTV`, `_ZTC`, and `_ZTT` records.
    Vtables,
    /// ABI-structural type-info records that do not require `_ZTI` symbols.
    StructuralTypeInfo,
    /// ABI-structural vtable address points that do not require `_ZTV` symbols.
    StructuralVtables,
    /// ABI-structural VTT arrays independent of `_ZTT` symbols.
    StructuralVtts,
}

/// Whole-stage completion state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RttiIndexStatus {
    /// Both strict decoders conserved every candidate, including the absent case.
    Complete,
    /// At least one non-budget structural candidate was rejected.
    Partial,
    /// At least one strict structural budget excluded a candidate.
    Truncated,
}

/// Conservation receipt for one strict RTTI subcollector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttiCollectorReceipt {
    /// Subcollector.
    pub collector: RttiCollector,
    /// Strict decoder outcome.
    pub outcome: StrictRttiOutcome,
    /// Exact candidate conservation.
    pub conservation: StrictRttiConservation,
    /// Stable reason codes derived from typed gaps.
    pub reasons: Vec<String>,
}

/// One direct Itanium base-type relationship.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttiBaseRelation {
    /// Derived type-info object address.
    pub derived_typeinfo: u64,
    /// Derived `_ZTI` symbol.
    pub derived_symbol: String,
    /// Zero-based direct-base ordinal.
    pub ordinal: u64,
    /// Resolved local, external, or null base target.
    pub base: StrictPointerTarget,
    /// Signed non-virtual offset or virtual-base slot displacement.
    pub signed_offset: i64,
    /// Whether the base is virtual.
    pub is_virtual: bool,
    /// Whether the base is public.
    pub is_public: bool,
}

/// Ownership link from one vtable address point to its type-info target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VtableTypeRelation {
    /// `_ZTV` or `_ZTC` symbol.
    pub vtable_symbol: String,
    /// Vtable group address.
    pub vtable: u64,
    /// Address-point ordinal within the group.
    pub address_point_ordinal: u64,
    /// Address-point virtual address.
    pub address_point: u64,
    /// Resolved local, external, or null type-info target.
    pub typeinfo: StrictPointerTarget,
}

/// A disagreement between symbol-backed and structural RTTI evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RttiConflict {
    /// Type-info object address shared by both observations.
    pub address: u64,
    /// Stable ABI field name that disagreed.
    pub field: String,
    /// Symbol-backed value.
    pub strict_value: String,
    /// Structurally decoded value.
    pub structural_value: String,
}

/// Provenance for one structurally decoded pointer field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralPointerEncoding {
    /// Ordinary pointer bytes.
    Direct,
    /// Chained-fixup rebase.
    ChainedRebase,
    /// Chained-fixup bind.
    ChainedBind,
    /// Legacy rebase opcode.
    LegacyRebase,
    /// Legacy bind opcode.
    LegacyBind,
    /// Signed 32-bit offset relative to the field address.
    RelativeSigned32,
}

/// Authentication metadata retained from an authenticated pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralPointerAuthentication {
    /// Pointer-auth diversity.
    pub diversity: u16,
    /// Pointer-auth key selector.
    pub key: u8,
    /// Whether the storage address participates in diversity.
    pub address_diversity: bool,
}

/// One structurally recovered pointer with its exact source and encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralPointer {
    /// Address of the pointer field.
    pub source_address: u64,
    /// Exact stored word before semantic resolution.
    pub raw_value: u64,
    /// On-disk pointer mechanism.
    pub encoding: StructuralPointerEncoding,
    /// Pointer-authentication metadata, when present.
    pub authentication: Option<StructuralPointerAuthentication>,
    /// Resolved local, imported, or null target.
    pub target: StrictPointerTarget,
}

/// One direct base decoded from an anonymous or stripped type-info object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralRttiBase {
    /// Zero-based direct-base ordinal.
    pub ordinal: u64,
    /// Base type-info pointer.
    pub typeinfo: StructuralPointer,
    /// Raw ABI offset-and-flags word.
    pub offset_flags: u64,
    /// Signed non-virtual offset or virtual-base slot displacement.
    pub signed_offset: i64,
    /// Whether this is a virtual base.
    pub is_virtual: bool,
    /// Whether this is a public base.
    pub is_public: bool,
}

/// Pointee relationships for the Itanium pointer RTTI families.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralRttiPointee {
    /// Raw qualifier and incomplete-type flags.
    pub flags: u32,
    /// Pointee type-info pointer.
    pub pointee: StructuralPointer,
    /// Containing-class type-info for pointer-to-member records.
    pub member_of: Option<StructuralPointer>,
}

/// A complete ABI-structural type-info record, independent of symbol names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralTypeInfoRecord {
    /// Type-info object virtual address.
    pub address: u64,
    /// Thin-image file offset.
    pub file_offset: u64,
    /// Runtime implementation family proven by its vptr.
    pub family: ItaniumTypeInfoFamily,
    /// Authority used to select the runtime implementation family.
    pub family_authority: StructuralRttiFamilyAuthority,
    /// Exact ABI-encoded type name.
    pub type_name: String,
    /// Darwin high-bit non-unique-name tag.
    pub type_name_non_unique: bool,
    /// Runtime-family vtable pointer.
    pub runtime_vtable: StructuralPointer,
    /// Type-name pointer.
    pub type_name_pointer: StructuralPointer,
    /// VMI flags, or zero for non-VMI records.
    pub class_flags: u32,
    /// Direct bases in ABI order.
    pub bases: Vec<StructuralRttiBase>,
    /// Pointer-family pointee information.
    pub pointee: Option<StructuralRttiPointee>,
}

/// Authority selecting a structural RTTI implementation family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralRttiFamilyAuthority {
    /// Exact runtime-family vtable symbol or import.
    RuntimeVtableAnchor,
    /// Anchor-free encoded-name and relationship/layout proof.
    EncodedNameAndLayout,
    /// Class-like identity is certain while enum/class leaf family is not.
    ConservativeClassLike,
}

/// Pointer representation used by a structural virtual table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralVtableEncoding {
    /// Pointer-width absolute fields and slots.
    AbsolutePointers,
    /// Signed 32-bit fields relative to their own storage address.
    RelativeSigned32,
}

/// Structural role of a vtable group after VTT cross-linking.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralVtableKind {
    /// No VTT relationship distinguishes complete and construction roles.
    CompleteOrConstruction,
    /// A recovered VTT references this address point, proving construction use.
    ConstructionReferenced,
}

/// A stripped adjustment thunk recognized from bounded entry instructions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralAdjustmentThunk {
    /// Signed adjustment applied to the `this` argument.
    pub this_adjustment: i64,
    /// Direct tail target after the adjustment.
    pub target: u64,
}

/// Confidence of a structural vtable extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StructuralVtableExtentConfidence {
    /// Bounded by another proven ABI object or a non-code pointer word.
    Derived,
    /// Bounded only by the containing section.
    Candidate,
}

/// One function slot following a structurally proven vtable address point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralVtableSlot {
    /// Zero-based slot ordinal.
    pub ordinal: u64,
    /// Slot virtual address.
    pub address: u64,
    /// Resolved slot pointer.
    pub pointer: StructuralPointer,
    /// Stripped compiler thunk idiom, when independently decoded.
    pub adjustment_thunk: Option<StructuralAdjustmentThunk>,
}

/// One structurally proven vtable header and its conservatively bounded slots.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralVtableRecord {
    /// Address of the offset-to-top header word.
    pub start: u64,
    /// Address point immediately following the type-info pointer.
    pub address_point: u64,
    /// Absolute-pointer or relative-32 representation.
    pub encoding: StructuralVtableEncoding,
    /// Complete/construction role established by structural cross-links.
    pub kind: StructuralVtableKind,
    /// Exclusive derived or candidate extent.
    pub end_exclusive: u64,
    /// Signed Itanium offset-to-top value.
    pub offset_to_top: i64,
    /// Pointer to the owning type-info object.
    pub typeinfo: StructuralPointer,
    /// Function entries retained until the first structural boundary.
    pub slots: Vec<StructuralVtableSlot>,
    /// Honesty marker for the non-symbol extent.
    pub extent_confidence: StructuralVtableExtentConfidence,
    /// Whether every slot up to the selected structural boundary was retained.
    pub complete: bool,
    /// Stable truncation reason when [`Self::complete`] is false.
    pub truncation_reason: Option<String>,
}

/// One structurally recovered VTT entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralVttEntry {
    /// Zero-based array ordinal.
    pub ordinal: u64,
    /// Entry storage address.
    pub address: u64,
    /// Pointer to a recovered vtable address point.
    pub address_point: StructuralPointer,
}

/// A stripped VTT array proven by two or more address-point references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuralVttRecord {
    /// First VTT entry address.
    pub start: u64,
    /// Exclusive array end.
    pub end_exclusive: u64,
    /// Entries in ABI order.
    pub entries: Vec<StructuralVttEntry>,
}

/// Borrowed named or structural type-info identity.
#[derive(Debug, Clone, Copy)]
pub enum RecoveredTypeInfo<'index> {
    /// Symbol-backed strict record.
    Strict(&'index ItaniumTypeInfoRecord),
    /// ABI-structural record, potentially anonymous after stripping.
    Structural(&'index StructuralTypeInfoRecord),
}

/// Borrowed named or structural vtable identity.
#[derive(Debug, Clone, Copy)]
pub enum RecoveredVtable<'index> {
    /// Symbol-backed strict vtable group.
    Strict(&'index ItaniumVtableGroupRecord),
    /// ABI-structural address point.
    Structural(&'index StructuralVtableRecord),
}

/// Symbol-backed and structural RTTI inventory for one exact image.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RttiIndex {
    image: FunctionImageIdentity,
    limits: RttiRecoveryLimits,
    type_info: StrictRttiBatch,
    vtables: StrictVtableBatch,
    structural_type_info: Vec<StructuralTypeInfoRecord>,
    structural_vtables: Vec<StructuralVtableRecord>,
    structural_vtts: Vec<StructuralVttRecord>,
    conflicts: Vec<RttiConflict>,
    base_relations: Vec<RttiBaseRelation>,
    vtable_type_relations: Vec<VtableTypeRelation>,
    receipts: Vec<RttiCollectorReceipt>,
    status: RttiIndexStatus,
}

impl RttiIndex {
    /// Recover named and structural type-info, vtables, VTTs, and relationships.
    pub fn recover(
        macho: &MachoFile<'_>,
        limits: RttiRecoveryLimits,
    ) -> Result<Self, RttiRecoveryError> {
        let limits = limits.validate()?;
        let has_symtab = macho
            .load_commands()
            .iter()
            .any(|command| matches!(command.kind(), LoadCommand::Symtab(_)));
        let (type_info, vtables) = if has_symtab {
            (
                decode_strict_rtti(macho, limits.type_info)
                    .map_err(|error| RttiRecoveryError::TypeInfo(error.to_string()))?,
                decode_strict_vtables(macho, limits.vtables)
                    .map_err(|error| RttiRecoveryError::Vtables(error.to_string()))?,
            )
        } else {
            (absent_type_info(), absent_vtables())
        };
        let mut structural = recover_structural_rtti(macho, limits)?;
        let conflicts = collect_rtti_conflicts(&type_info, &structural.type_info);
        if !conflicts.is_empty() {
            structural
                .type_info_receipt
                .reasons
                .push("rtti.evidence_conflict".to_owned());
        }
        let base_relations = collect_base_relations(&type_info);
        let vtable_type_relations = collect_vtable_relations(&vtables);
        let mut receipts = vec![
            receipt(RttiCollector::TypeInfo, &type_info),
            vtable_receipt(&vtables),
            structural.type_info_receipt,
            structural.vtable_receipt,
            structural.vtt_receipt,
        ];
        if !has_symtab {
            for receipt in receipts.iter_mut().take(2) {
                receipt.reasons.push("rtti.symbol_table_absent".to_owned());
            }
        }
        for receipt in receipts.iter_mut().take(2) {
            if receipt.outcome == StrictRttiOutcome::Absent {
                receipt
                    .reasons
                    .push("rtti.symbol_candidates_absent".to_owned());
            }
            receipt.reasons.sort();
            receipt.reasons.dedup();
        }
        let status = if receipts.iter().any(|receipt| {
            receipt
                .reasons
                .iter()
                .any(|reason| reason == "rtti.structural_limit")
        }) {
            RttiIndexStatus::Truncated
        } else if !conflicts.is_empty()
            || receipts.iter().any(|receipt| {
                matches!(
                    receipt.collector,
                    RttiCollector::StructuralTypeInfo
                        | RttiCollector::StructuralVtables
                        | RttiCollector::StructuralVtts
                ) && receipt.outcome == StrictRttiOutcome::Rejected
            })
            || !collector_covered(
                &receipts,
                RttiCollector::TypeInfo,
                RttiCollector::StructuralTypeInfo,
            )
            || !collector_covered(
                &receipts,
                RttiCollector::Vtables,
                RttiCollector::StructuralVtables,
            )
        {
            RttiIndexStatus::Partial
        } else {
            RttiIndexStatus::Complete
        };
        Ok(Self {
            image: FunctionImageIdentity::from_macho(macho),
            limits,
            type_info,
            vtables,
            structural_type_info: structural.type_info,
            structural_vtables: structural.vtables,
            structural_vtts: structural.vtts,
            conflicts,
            base_relations,
            vtable_type_relations,
            receipts,
            status,
        })
    }

    /// Exact selected-image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }

    /// Exact strict decoder limits.
    pub const fn limits(&self) -> RttiRecoveryLimits {
        self.limits
    }

    /// Strict type-info conservation batch.
    pub fn type_info(&self) -> &StrictRttiBatch {
        &self.type_info
    }

    /// Strict vtable and VTT conservation batch.
    pub fn vtables(&self) -> &StrictVtableBatch {
        &self.vtables
    }

    /// ABI-structural type-info records, including records recovered after stripping.
    pub fn structural_type_info(&self) -> &[StructuralTypeInfoRecord] {
        &self.structural_type_info
    }

    /// ABI-structural vtable address points, including anonymous stripped tables.
    pub fn structural_vtables(&self) -> &[StructuralVtableRecord] {
        &self.structural_vtables
    }

    /// ABI-structural VTT arrays, including stripped definitions.
    pub fn structural_vtts(&self) -> &[StructuralVttRecord] {
        &self.structural_vtts
    }

    /// Cross-source RTTI disagreements retained without choosing a false winner.
    pub fn conflicts(&self) -> &[RttiConflict] {
        &self.conflicts
    }

    /// Direct base-type relationships in derived-record and ABI base order.
    pub fn base_relations(&self) -> &[RttiBaseRelation] {
        &self.base_relations
    }

    /// Vtable-address-point ownership links.
    pub fn vtable_type_relations(&self) -> &[VtableTypeRelation] {
        &self.vtable_type_relations
    }

    /// Per-decoder conservation receipts.
    pub fn receipts(&self) -> &[RttiCollectorReceipt] {
        &self.receipts
    }

    /// Overall strict RTTI stage status.
    pub const fn status(&self) -> RttiIndexStatus {
        self.status
    }

    /// Find one exact local type-info object address.
    pub fn type_info_by_address(&self, address: u64) -> Option<&ItaniumTypeInfoRecord> {
        self.type_info
            .records
            .iter()
            .find_map(|record| match record {
                StrictRttiRecord::TypeInfo { record } if record.va == address => {
                    Some(record.as_ref())
                }
                _ => None,
            })
    }

    /// Find a type-info identity regardless of whether symbols survived stripping.
    pub fn recovered_type_info_by_address(&self, address: u64) -> Option<RecoveredTypeInfo<'_>> {
        self.type_info_by_address(address)
            .map(RecoveredTypeInfo::Strict)
            .or_else(|| {
                self.structural_type_info
                    .iter()
                    .find(|record| record.address == address)
                    .map(RecoveredTypeInfo::Structural)
            })
    }

    /// Find one exact `_ZTI` symbol, including external records.
    pub fn type_info_by_symbol(&self, symbol: &str) -> Option<&StrictRttiRecord> {
        self.type_info.records.iter().find(|record| match record {
            StrictRttiRecord::TypeInfo { record } => record.symbol == symbol,
            StrictRttiRecord::ExternalTypeInfo { symbol: value, .. } => value == symbol,
        })
    }

    /// Iterate local type-info objects with an exact encoded type name.
    pub fn type_info_by_name<'index>(
        &'index self,
        type_name: &'index str,
    ) -> impl Iterator<Item = &'index ItaniumTypeInfoRecord> + 'index {
        self.type_info
            .records
            .iter()
            .filter_map(move |record| match record {
                StrictRttiRecord::TypeInfo { record } if record.type_name == type_name => {
                    Some(record.as_ref())
                }
                _ => None,
            })
    }

    /// Find one exact local vtable-group symbol.
    pub fn vtable_by_symbol(&self, symbol: &str) -> Option<&ItaniumVtableGroupRecord> {
        self.vtables.records.iter().find_map(|record| match record {
            StrictVtableRecord::Group { record } if record.symbol == symbol => {
                Some(record.as_ref())
            }
            _ => None,
        })
    }

    /// Find the strict vtable group whose exact symbol extent contains an address.
    pub fn vtable_containing(&self, address: u64) -> Option<&ItaniumVtableGroupRecord> {
        self.vtables.records.iter().find_map(|record| match record {
            StrictVtableRecord::Group { record }
                if record.va <= address
                    && address < record.va.saturating_add(record.byte_length) =>
            {
                Some(record.as_ref())
            }
            _ => None,
        })
    }

    /// Find a vtable identity containing an address, named or structurally recovered.
    pub fn recovered_vtable_containing(&self, address: u64) -> Option<RecoveredVtable<'_>> {
        self.vtable_containing(address)
            .map(RecoveredVtable::Strict)
            .or_else(|| {
                self.structural_vtables
                    .iter()
                    .find(|record| record.start <= address && address < record.end_exclusive)
                    .map(RecoveredVtable::Structural)
            })
    }

    /// Iterate direct bases of one local derived type-info address.
    pub fn bases_of(&self, derived_typeinfo: u64) -> impl Iterator<Item = &RttiBaseRelation> {
        self.base_relations
            .iter()
            .filter(move |relation| relation.derived_typeinfo == derived_typeinfo)
    }

    /// Iterate vtable address points owned by one local type-info address.
    pub fn vtables_for_typeinfo(&self, typeinfo: u64) -> impl Iterator<Item = &VtableTypeRelation> {
        self.vtable_type_relations.iter().filter(move |relation| {
            relation.typeinfo == StrictPointerTarget::Local { va: typeinfo }
        })
    }
}

struct StructuralRecovery {
    type_info: Vec<StructuralTypeInfoRecord>,
    vtables: Vec<StructuralVtableRecord>,
    vtts: Vec<StructuralVttRecord>,
    type_info_receipt: RttiCollectorReceipt,
    vtable_receipt: RttiCollectorReceipt,
    vtt_receipt: RttiCollectorReceipt,
}

#[derive(Default)]
struct StructuralLedger {
    attempted: u64,
    included: u64,
    unknown: u64,
    excluded: u64,
    reasons: BTreeSet<String>,
}

impl StructuralLedger {
    fn receipt(self, collector: RttiCollector, authority_present: bool) -> RttiCollectorReceipt {
        let outcome = if self.excluded != 0 || self.unknown != 0 {
            StrictRttiOutcome::Rejected
        } else if self.included != 0 {
            StrictRttiOutcome::Complete
        } else if authority_present {
            StrictRttiOutcome::Absent
        } else {
            StrictRttiOutcome::Rejected
        };
        let mut reasons = self.reasons.into_iter().collect::<Vec<_>>();
        if !authority_present {
            reasons.push("rtti.runtime_family_anchors_absent".to_owned());
        }
        RttiCollectorReceipt {
            collector,
            outcome,
            conservation: StrictRttiConservation {
                attempted: self.attempted,
                included: self.included,
                unknown: self.unknown,
                excluded: self.excluded,
            },
            reasons,
        }
    }
}

fn recover_structural_rtti(
    macho: &MachoFile<'_>,
    limits: RttiRecoveryLimits,
) -> Result<StructuralRecovery, RttiRecoveryError> {
    let input_limit = limits
        .type_info
        .max_input_bytes
        .min(limits.vtables.max_input_bytes);
    if macho.file_size() as u64 > input_limit {
        let ledger = StructuralLedger {
            attempted: 1,
            excluded: 1,
            reasons: BTreeSet::from(["rtti.structural_limit".to_owned()]),
            ..StructuralLedger::default()
        };
        let type_info_receipt = ledger.receipt(RttiCollector::StructuralTypeInfo, false);
        let vtable_receipt = StructuralLedger {
            attempted: 1,
            excluded: 1,
            reasons: BTreeSet::from(["rtti.structural_limit".to_owned()]),
            ..StructuralLedger::default()
        }
        .receipt(RttiCollector::StructuralVtables, false);
        return Ok(StructuralRecovery {
            type_info: Vec::new(),
            vtables: Vec::new(),
            vtts: Vec::new(),
            type_info_receipt,
            vtable_receipt,
            vtt_receipt: StructuralLedger {
                attempted: 1,
                excluded: 1,
                reasons: BTreeSet::from(["rtti.structural_limit".to_owned()]),
                ..StructuralLedger::default()
            }
            .receipt(RttiCollector::StructuralVtts, false),
        });
    }
    let resolver = PointerResolver::new(macho)
        .map_err(|error| RttiRecoveryError::Structural(error.to_string()))?;
    let pointer_width = if macho.is_64bit() { 8_u64 } else { 4_u64 };
    let (runtime_anchors, local_targets, symbol_authority_complete) =
        local_symbol_authority(macho, pointer_width, limits.type_info.max_symbols);
    let mut type_ledger = StructuralLedger::default();
    if !symbol_authority_complete {
        type_ledger
            .reasons
            .insert("rtti.symbol_authority_partial".to_owned());
    }
    let mut type_info = Vec::new();
    let mut total_bases = 0_u64;
    let mut evidence_bytes = 0_u64;
    for section in structural_sections(macho) {
        let Some(section_end) = section.addr().0.checked_add(section.size()) else {
            type_ledger.unknown = type_ledger.unknown.saturating_add(1);
            type_ledger.attempted = type_ledger.attempted.saturating_add(1);
            type_ledger
                .reasons
                .insert("rtti.section_extent_overflow".to_owned());
            continue;
        };
        let mut address = align_up(section.addr().0, pointer_width);
        while address
            .checked_add(pointer_width.saturating_mul(2))
            .is_some_and(|end| end <= section_end)
        {
            let Ok(runtime_observation) = resolver.observe_at_va(Va(address)) else {
                address = address.saturating_add(pointer_width);
                continue;
            };
            let runtime_pointer =
                structural_pointer(macho, runtime_observation, u64::MAX, &local_targets);
            let family = family_for_target(&runtime_pointer.target, &runtime_anchors);
            let Some(family) = family else {
                address = address.saturating_add(pointer_width);
                continue;
            };
            type_ledger.attempted = type_ledger.attempted.saturating_add(1);
            if type_ledger.included >= limits.type_info.max_records {
                type_ledger.excluded = type_ledger.excluded.saturating_add(1);
                type_ledger
                    .reasons
                    .insert("rtti.structural_limit".to_owned());
                address = address.saturating_add(pointer_width);
                continue;
            }
            match decode_structural_type_info(
                macho,
                &resolver,
                address,
                family,
                StructuralRttiFamilyAuthority::RuntimeVtableAnchor,
                pointer_width,
                limits.type_info,
                &local_targets,
                &mut total_bases,
                &mut evidence_bytes,
            ) {
                Ok(record) => {
                    type_ledger.included = type_ledger.included.saturating_add(1);
                    type_info.push(record);
                }
                Err(StructuralDecodeFailure::Limit) => {
                    type_ledger.excluded = type_ledger.excluded.saturating_add(1);
                    type_ledger
                        .reasons
                        .insert("rtti.structural_limit".to_owned());
                }
                Err(StructuralDecodeFailure::Malformed(reason)) => {
                    type_ledger.unknown = type_ledger.unknown.saturating_add(1);
                    type_ledger.reasons.insert(reason.to_owned());
                }
            }
            address = address.saturating_add(pointer_width);
        }
    }
    let anchored_addresses = type_info
        .iter()
        .map(|record| record.address)
        .collect::<BTreeSet<_>>();
    recover_anchor_free_type_info(
        macho,
        &resolver,
        pointer_width,
        limits.type_info,
        &local_targets,
        &anchored_addresses,
        &mut type_info,
        &mut type_ledger,
        &mut total_bases,
        &mut evidence_bytes,
    );
    // A complete bounded scan is itself authority for absence; runtime-family
    // names are useful classification evidence, not a prerequisite.
    let authority_present = true;
    type_info.sort_by_key(|record| record.address);
    type_info.dedup_by_key(|record| record.address);
    let type_addresses = type_info
        .iter()
        .map(|record| record.address)
        .collect::<BTreeSet<_>>();
    let (mut vtables, vtable_ledger) = recover_structural_vtables(
        macho,
        &resolver,
        pointer_width,
        &type_addresses,
        &local_targets,
        limits.vtables,
        authority_present,
    );
    let (vtts, vtt_ledger) = recover_structural_vtts(
        macho,
        &resolver,
        pointer_width,
        &vtables,
        &local_targets,
        limits.vtables,
        authority_present,
    );
    let construction_points = vtts
        .iter()
        .flat_map(|vtt| vtt.entries.iter())
        .filter_map(|entry| match entry.address_point.target {
            StrictPointerTarget::Local { va } => Some(va),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    for vtable in &mut vtables {
        if construction_points.contains(&vtable.address_point) {
            vtable.kind = StructuralVtableKind::ConstructionReferenced;
        }
    }
    Ok(StructuralRecovery {
        type_info,
        vtables,
        vtts,
        type_info_receipt: type_ledger
            .receipt(RttiCollector::StructuralTypeInfo, authority_present),
        vtable_receipt: vtable_ledger.receipt(RttiCollector::StructuralVtables, authority_present),
        vtt_receipt: vtt_ledger.receipt(RttiCollector::StructuralVtts, authority_present),
    })
}

#[derive(Debug)]
struct AnchorFreeTypeSeed {
    address: u64,
    runtime: StructuralPointer,
    type_name: String,
}

#[allow(clippy::too_many_arguments)]
fn recover_anchor_free_type_info(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    pointer_width: u64,
    limits: StrictRttiLimits,
    local_targets: &BTreeMap<String, u64>,
    anchored: &BTreeSet<u64>,
    records: &mut Vec<StructuralTypeInfoRecord>,
    ledger: &mut StructuralLedger,
    total_bases: &mut u64,
    evidence_bytes: &mut u64,
) {
    let tag = 1_u64 << (pointer_width * 8 - 1);
    let mut seeds = Vec::new();
    for section in structural_sections(macho) {
        let Some(end) = section.addr().0.checked_add(section.size()) else {
            continue;
        };
        let mut address = align_up(section.addr().0, pointer_width);
        while address
            .checked_add(pointer_width.saturating_mul(2))
            .is_some_and(|finish| finish <= end)
        {
            if anchored.contains(&address) {
                address = address.saturating_add(pointer_width);
                continue;
            }
            let Ok(runtime_observation) = resolver.observe_at_va(Va(address)) else {
                address = address.saturating_add(pointer_width);
                continue;
            };
            let runtime = structural_pointer(macho, runtime_observation, u64::MAX, local_targets);
            if matches!(runtime.target, StrictPointerTarget::Null) {
                address = address.saturating_add(pointer_width);
                continue;
            }
            let Ok(name) = observe_structural_pointer(
                macho,
                resolver,
                address.saturating_add(pointer_width),
                !tag,
                local_targets,
            ) else {
                address = address.saturating_add(pointer_width);
                continue;
            };
            let StrictPointerTarget::Local { va } = name.target else {
                address = address.saturating_add(pointer_width);
                continue;
            };
            let Ok((type_name, _)) = read_type_name(macho, va, limits.max_name_bytes) else {
                address = address.saturating_add(pointer_width);
                continue;
            };
            if valid_itanium_type_name(&type_name) {
                seeds.push(AnchorFreeTypeSeed {
                    address,
                    runtime,
                    type_name,
                });
            }
            address = address.saturating_add(pointer_width);
        }
    }
    seeds.sort_by_key(|seed| seed.address);
    seeds.dedup_by_key(|seed| seed.address);
    let candidates = seeds
        .iter()
        .map(|seed| seed.address)
        .chain(anchored.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut runtime_counts = BTreeMap::<String, usize>::new();
    for seed in &seeds {
        *runtime_counts
            .entry(pointer_target_key(&seed.runtime.target))
            .or_default() += 1;
    }
    let referenced =
        anchor_free_vtable_references(macho, resolver, pointer_width, &candidates, local_targets);
    for seed in seeds {
        let linked = referenced.contains(&seed.address)
            || runtime_counts
                .get(&pointer_target_key(&seed.runtime.target))
                .copied()
                .unwrap_or(0)
                >= 2;
        if !linked {
            continue;
        }
        ledger.attempted = ledger.attempted.saturating_add(1);
        if ledger.included >= limits.max_records {
            ledger.excluded = ledger.excluded.saturating_add(1);
            ledger.reasons.insert("rtti.structural_limit".to_owned());
            continue;
        }
        let (family, authority) = infer_anchor_free_family(
            macho,
            resolver,
            seed.address,
            &seed.type_name,
            pointer_width,
            &candidates,
            local_targets,
        );
        match decode_structural_type_info(
            macho,
            resolver,
            seed.address,
            family,
            authority,
            pointer_width,
            limits,
            local_targets,
            total_bases,
            evidence_bytes,
        ) {
            Ok(record) => {
                ledger.included = ledger.included.saturating_add(1);
                records.push(record);
            }
            Err(StructuralDecodeFailure::Limit) => {
                ledger.excluded = ledger.excluded.saturating_add(1);
                ledger.reasons.insert("rtti.structural_limit".to_owned());
            }
            Err(StructuralDecodeFailure::Malformed(reason)) => {
                ledger.unknown = ledger.unknown.saturating_add(1);
                ledger.reasons.insert(reason.to_owned());
            }
        }
    }
}

fn pointer_target_key(target: &StrictPointerTarget) -> String {
    match target {
        StrictPointerTarget::Null => "null".to_owned(),
        StrictPointerTarget::Local { va } => format!("local:{va:016x}"),
        StrictPointerTarget::External {
            symbol,
            library_ordinal,
        } => format!("external:{library_ordinal}:{symbol}"),
    }
}

fn valid_itanium_type_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let symbol = format!("_ZTS{name}");
    cpp_demangle::Symbol::new(&symbol)
        .ok()
        .and_then(|symbol| symbol.demangle().ok())
        .is_some()
}

fn anchor_free_vtable_references(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    pointer_width: u64,
    candidates: &BTreeSet<u64>,
    local_targets: &BTreeMap<String, u64>,
) -> BTreeSet<u64> {
    let executable = executable_ranges(macho);
    let mut references = BTreeSet::new();
    for section in structural_sections(macho) {
        let Some(end) = section.addr().0.checked_add(section.size()) else {
            continue;
        };
        let mut field = align_up(
            section.addr().0.saturating_add(pointer_width),
            pointer_width,
        );
        while field
            .checked_add(pointer_width.saturating_mul(2))
            .is_some_and(|finish| finish <= end)
        {
            let typeinfo =
                observe_structural_pointer(macho, resolver, field, u64::MAX, local_targets);
            let slot = observe_structural_pointer(
                macho,
                resolver,
                field.saturating_add(pointer_width),
                u64::MAX,
                local_targets,
            );
            if let (Ok(typeinfo), Ok(slot)) = (typeinfo, slot)
                && is_vtable_slot_target(&slot.target, &executable)
                && let StrictPointerTarget::Local { va } = typeinfo.target
                && candidates.contains(&va)
            {
                references.insert(va);
            }
            field = field.saturating_add(pointer_width);
        }
    }
    references
}

fn infer_anchor_free_family(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    address: u64,
    name: &str,
    pointer_width: u64,
    candidates: &BTreeSet<u64>,
    local_targets: &BTreeMap<String, u64>,
) -> (ItaniumTypeInfoFamily, StructuralRttiFamilyAuthority) {
    let unqualified = name.trim_start_matches(['K', 'V', 'r']);
    if unqualified.starts_with('P') {
        return (
            if unqualified.len() == name.len() {
                ItaniumTypeInfoFamily::Pointer
            } else {
                ItaniumTypeInfoFamily::Qualified
            },
            StructuralRttiFamilyAuthority::EncodedNameAndLayout,
        );
    }
    if unqualified.starts_with('M') {
        return (
            ItaniumTypeInfoFamily::PointerToMember,
            StructuralRttiFamilyAuthority::EncodedNameAndLayout,
        );
    }
    if unqualified.starts_with('A') {
        return (
            ItaniumTypeInfoFamily::Array,
            StructuralRttiFamilyAuthority::EncodedNameAndLayout,
        );
    }
    if unqualified.starts_with('F') {
        return (
            ItaniumTypeInfoFamily::Function,
            StructuralRttiFamilyAuthority::EncodedNameAndLayout,
        );
    }
    if unqualified.len() == 1 && unqualified.as_bytes()[0].is_ascii_alphabetic() {
        return (
            ItaniumTypeInfoFamily::Fundamental,
            StructuralRttiFamilyAuthority::EncodedNameAndLayout,
        );
    }
    let header = address.saturating_add(pointer_width.saturating_mul(2));
    if let (Ok(flags), Ok(count)) = (read_u32_va(macho, header), read_u32_va(macho, header + 4))
        && flags <= 3
        && count > 0
        && count <= 4096
    {
        let entries = header.saturating_add(8);
        let all_bases = (0..u64::from(count)).all(|ordinal| {
            let entry = entries.saturating_add(ordinal.saturating_mul(pointer_width * 2));
            observe_structural_pointer(macho, resolver, entry, u64::MAX, local_targets)
                .is_ok_and(|pointer| {
                    matches!(pointer.target, StrictPointerTarget::Local { va } if candidates.contains(&va))
                })
                && read_word_va(macho, entry.saturating_add(pointer_width)).is_ok()
        });
        if all_bases {
            return (
                ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass,
                StructuralRttiFamilyAuthority::EncodedNameAndLayout,
            );
        }
    }
    if observe_structural_pointer(macho, resolver, header, u64::MAX, local_targets).is_ok_and(
        |pointer| matches!(pointer.target, StrictPointerTarget::Local { va } if candidates.contains(&va)),
    ) {
        return (
            ItaniumTypeInfoFamily::SingleInheritanceClass,
            StructuralRttiFamilyAuthority::EncodedNameAndLayout,
        );
    }
    (
        ItaniumTypeInfoFamily::Class,
        StructuralRttiFamilyAuthority::ConservativeClassLike,
    )
}

#[derive(Debug)]
enum StructuralDecodeFailure {
    Limit,
    Malformed(&'static str),
}

#[allow(clippy::too_many_arguments)]
fn decode_structural_type_info(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    address: u64,
    family: ItaniumTypeInfoFamily,
    family_authority: StructuralRttiFamilyAuthority,
    pointer_width: u64,
    limits: StrictRttiLimits,
    local_targets: &BTreeMap<String, u64>,
    total_bases: &mut u64,
    evidence_bytes: &mut u64,
) -> Result<StructuralTypeInfoRecord, StructuralDecodeFailure> {
    let runtime_vtable =
        observe_structural_pointer(macho, resolver, address, u64::MAX, local_targets)?;
    let name_address =
        address
            .checked_add(pointer_width)
            .ok_or(StructuralDecodeFailure::Malformed(
                "rtti.record_address_overflow",
            ))?;
    let tag = 1_u64 << (pointer_width * 8 - 1);
    let type_name_pointer =
        observe_structural_pointer(macho, resolver, name_address, !tag, local_targets)?;
    let (type_name, name_size) = match &type_name_pointer.target {
        StrictPointerTarget::Local { va } => read_type_name(macho, *va, limits.max_name_bytes)?,
        StrictPointerTarget::External { symbol, .. } => {
            let Some(&local_name_va) = local_targets.get(symbol) else {
                return Err(StructuralDecodeFailure::Malformed(
                    "rtti.type_name_pointer_unresolved",
                ));
            };
            let (name, size) = read_type_name(macho, local_name_va, limits.max_name_bytes)?;
            if symbol.strip_prefix("__ZTS") != Some(name.as_str()) {
                return Err(StructuralDecodeFailure::Malformed(
                    "rtti.type_name_pointer_unresolved",
                ));
            }
            (name, size)
        }
        StrictPointerTarget::Null => {
            return Err(StructuralDecodeFailure::Malformed(
                "rtti.type_name_pointer_unresolved",
            ));
        }
    };
    let mut object_size = pointer_width.saturating_mul(2);
    let mut class_flags = 0;
    let mut bases = Vec::new();
    let mut pointee = None;
    match family {
        ItaniumTypeInfoFamily::SingleInheritanceClass => {
            if *total_bases >= limits.max_bases {
                return Err(StructuralDecodeFailure::Limit);
            }
            let base_address = address.checked_add(pointer_width.saturating_mul(2)).ok_or(
                StructuralDecodeFailure::Malformed("rtti.record_address_overflow"),
            )?;
            bases.push(StructuralRttiBase {
                ordinal: 0,
                typeinfo: observe_structural_pointer(
                    macho,
                    resolver,
                    base_address,
                    u64::MAX,
                    local_targets,
                )?,
                offset_flags: 2,
                signed_offset: 0,
                is_virtual: false,
                is_public: true,
            });
            *total_bases = total_bases.saturating_add(1);
            object_size = object_size.saturating_add(pointer_width);
        }
        ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass => {
            let header = address.checked_add(pointer_width.saturating_mul(2)).ok_or(
                StructuralDecodeFailure::Malformed("rtti.record_address_overflow"),
            )?;
            class_flags = read_u32_va(macho, header)?;
            let count = u64::from(read_u32_va(macho, header.saturating_add(4))?);
            if total_bases.saturating_add(count) > limits.max_bases {
                return Err(StructuralDecodeFailure::Limit);
            }
            let entry_size = pointer_width.saturating_mul(2);
            let start = header.saturating_add(8);
            for ordinal in 0..count {
                let entry = start
                    .checked_add(ordinal.saturating_mul(entry_size))
                    .ok_or(StructuralDecodeFailure::Malformed(
                        "rtti.record_address_overflow",
                    ))?;
                let offset_flags = read_word_va(macho, entry.saturating_add(pointer_width))?;
                bases.push(StructuralRttiBase {
                    ordinal,
                    typeinfo: observe_structural_pointer(
                        macho,
                        resolver,
                        entry,
                        u64::MAX,
                        local_targets,
                    )?,
                    offset_flags,
                    signed_offset: sign_extend_word(offset_flags, pointer_width) >> 8,
                    is_virtual: offset_flags & 1 != 0,
                    is_public: offset_flags & 2 != 0,
                });
            }
            *total_bases = total_bases.saturating_add(count);
            object_size = object_size
                .saturating_add(8)
                .saturating_add(count.saturating_mul(entry_size));
        }
        ItaniumTypeInfoFamily::Pointer
        | ItaniumTypeInfoFamily::PointerToMember
        | ItaniumTypeInfoFamily::Qualified => {
            let flags_address = address.checked_add(pointer_width.saturating_mul(2)).ok_or(
                StructuralDecodeFailure::Malformed("rtti.record_address_overflow"),
            )?;
            let flags = read_u32_va(macho, flags_address)?;
            let pointee_address = align_up(flags_address.saturating_add(4), pointer_width);
            let member_of = if family == ItaniumTypeInfoFamily::PointerToMember {
                Some(observe_structural_pointer(
                    macho,
                    resolver,
                    pointee_address.saturating_add(pointer_width),
                    u64::MAX,
                    local_targets,
                )?)
            } else {
                None
            };
            pointee = Some(StructuralRttiPointee {
                flags,
                pointee: observe_structural_pointer(
                    macho,
                    resolver,
                    pointee_address,
                    u64::MAX,
                    local_targets,
                )?,
                member_of,
            });
            object_size = pointee_address
                .saturating_sub(address)
                .saturating_add(pointer_width)
                .saturating_add(
                    (family == ItaniumTypeInfoFamily::PointerToMember) as u64 * pointer_width,
                );
        }
        _ => {}
    }
    let evidence = object_size.saturating_add(name_size);
    if evidence_bytes.saturating_add(evidence) > limits.max_evidence_bytes {
        return Err(StructuralDecodeFailure::Limit);
    }
    *evidence_bytes = evidence_bytes.saturating_add(evidence);
    let file_offset = macho
        .address_map()
        .va_to_thin_offset(Va(address))
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.record_unmapped"))?
        .0;
    Ok(StructuralTypeInfoRecord {
        address,
        file_offset,
        family,
        family_authority,
        type_name,
        type_name_non_unique: type_name_pointer.raw_value & tag != 0,
        runtime_vtable,
        type_name_pointer,
        class_flags,
        bases,
        pointee,
    })
}

fn recover_structural_vtables(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    pointer_width: u64,
    type_addresses: &BTreeSet<u64>,
    local_targets: &BTreeMap<String, u64>,
    limits: StrictVtableLimits,
    authority_present: bool,
) -> (Vec<StructuralVtableRecord>, StructuralLedger) {
    let mut ledger = StructuralLedger::default();
    if type_addresses.is_empty() {
        return (Vec::new(), ledger);
    }
    let executable = executable_ranges(macho);
    let mut headers = Vec::new();
    for section in structural_sections(macho) {
        let Some(end) = section.addr().0.checked_add(section.size()) else {
            continue;
        };
        let mut address = align_up(section.addr().0, pointer_width);
        while address
            .checked_add(pointer_width.saturating_mul(2))
            .is_some_and(|value| value <= end)
        {
            let type_field = address.saturating_add(pointer_width);
            if let Ok(pointer) =
                observe_structural_pointer(macho, resolver, type_field, u64::MAX, local_targets)
                && matches!(pointer.target, StrictPointerTarget::Local { va } if type_addresses.contains(&va))
            {
                headers.push((address, end, pointer));
            }
            address = address.saturating_add(pointer_width);
        }
    }
    headers.sort_by_key(|header| header.0);
    let boundaries = headers
        .iter()
        .map(|header| header.0)
        .chain(type_addresses.iter().copied())
        .collect::<BTreeSet<_>>();
    let mut records = Vec::new();
    let mut total_words = 0_u64;
    let mut evidence_bytes = 0_u64;
    for (start, section_end, typeinfo) in headers {
        ledger.attempted = ledger.attempted.saturating_add(1);
        if ledger.included >= limits.max_records {
            ledger.excluded = ledger.excluded.saturating_add(1);
            ledger.reasons.insert("rtti.structural_limit".to_owned());
            continue;
        }
        let address_point = start.saturating_add(pointer_width.saturating_mul(2));
        let structural_boundary = boundaries
            .range(address_point..)
            .next()
            .copied()
            .unwrap_or(section_end)
            .min(section_end);
        let offset_to_top = match read_word_va(macho, start) {
            Ok(value) => sign_extend_word(value, pointer_width),
            Err(_) => {
                ledger.unknown = ledger.unknown.saturating_add(1);
                ledger
                    .reasons
                    .insert("rtti.vtable_header_unreadable".to_owned());
                continue;
            }
        };
        let mut slots = Vec::new();
        let mut cursor = address_point;
        let mut bounded_by_content = false;
        let mut complete = true;
        let mut truncation_reason = None;
        while cursor.saturating_add(pointer_width) <= structural_boundary {
            if total_words >= limits.max_words
                || evidence_bytes.saturating_add(pointer_width) > limits.max_evidence_bytes
            {
                complete = false;
                truncation_reason = Some("rtti.structural_limit".to_owned());
                ledger.reasons.insert("rtti.structural_limit".to_owned());
                break;
            }
            let Ok(pointer) =
                observe_structural_pointer(macho, resolver, cursor, u64::MAX, local_targets)
            else {
                bounded_by_content = true;
                break;
            };
            if !is_vtable_slot_target(&pointer.target, &executable) {
                bounded_by_content = true;
                break;
            }
            let ordinal = slots.len() as u64;
            slots.push(StructuralVtableSlot {
                ordinal,
                address: cursor,
                adjustment_thunk: adjustment_thunk(macho, &pointer.target),
                pointer,
            });
            total_words = total_words.saturating_add(1);
            evidence_bytes = evidence_bytes.saturating_add(pointer_width);
            cursor = cursor.saturating_add(pointer_width);
        }
        if complete {
            ledger.included = ledger.included.saturating_add(1);
        } else {
            ledger.unknown = ledger.unknown.saturating_add(1);
        }
        records.push(StructuralVtableRecord {
            start,
            address_point,
            encoding: StructuralVtableEncoding::AbsolutePointers,
            kind: StructuralVtableKind::CompleteOrConstruction,
            end_exclusive: cursor,
            offset_to_top,
            typeinfo,
            slots,
            extent_confidence: if bounded_by_content || structural_boundary < section_end {
                StructuralVtableExtentConfidence::Derived
            } else {
                StructuralVtableExtentConfidence::Candidate
            },
            complete,
            truncation_reason,
        });
    }
    if pointer_width == 8 {
        let mut relative_headers = Vec::new();
        for section in structural_sections(macho) {
            let Some(end) = section.addr().0.checked_add(section.size()) else {
                continue;
            };
            let mut start = align_up(section.addr().0, 4);
            while start.checked_add(8).is_some_and(|value| value <= end) {
                let type_field = start.saturating_add(4);
                if let Ok(relative) = read_i32_va(macho, type_field) {
                    let target = type_field.wrapping_add_signed(i64::from(relative));
                    if type_addresses.contains(&target) {
                        relative_headers.push((start, end, target));
                    }
                }
                start = start.saturating_add(4);
            }
        }
        relative_headers.sort_unstable();
        let relative_boundaries = relative_headers
            .iter()
            .map(|header| header.0)
            .chain(type_addresses.iter().copied())
            .collect::<BTreeSet<_>>();
        for (start, section_end, typeinfo_target) in relative_headers {
            ledger.attempted = ledger.attempted.saturating_add(1);
            if ledger.included >= limits.max_records {
                ledger.excluded = ledger.excluded.saturating_add(1);
                ledger.reasons.insert("rtti.structural_limit".to_owned());
                continue;
            }
            let address_point = start.saturating_add(8);
            let boundary = relative_boundaries
                .range(address_point..)
                .next()
                .copied()
                .unwrap_or(section_end)
                .min(section_end);
            let Ok(offset_to_top) = read_i32_va(macho, start) else {
                ledger.unknown = ledger.unknown.saturating_add(1);
                ledger
                    .reasons
                    .insert("rtti.vtable_header_unreadable".to_owned());
                continue;
            };
            let typeinfo = relative_structural_pointer(
                start.saturating_add(4),
                i64::from(read_i32_va(macho, start.saturating_add(4)).unwrap_or(0)),
            );
            debug_assert_eq!(
                typeinfo.target,
                StrictPointerTarget::Local {
                    va: typeinfo_target
                }
            );
            let mut cursor = address_point;
            let mut slots = Vec::new();
            let mut complete = true;
            let mut truncation_reason = None;
            let mut bounded_by_content = false;
            while cursor.saturating_add(4) <= boundary {
                if total_words >= limits.max_words
                    || evidence_bytes.saturating_add(4) > limits.max_evidence_bytes
                {
                    complete = false;
                    truncation_reason = Some("rtti.structural_limit".to_owned());
                    ledger.reasons.insert("rtti.structural_limit".to_owned());
                    break;
                }
                let Ok(relative) = read_i32_va(macho, cursor) else {
                    bounded_by_content = true;
                    break;
                };
                let pointer = relative_structural_pointer(cursor, i64::from(relative));
                if !is_vtable_slot_target(&pointer.target, &executable) {
                    bounded_by_content = true;
                    break;
                }
                slots.push(StructuralVtableSlot {
                    ordinal: slots.len() as u64,
                    address: cursor,
                    adjustment_thunk: adjustment_thunk(macho, &pointer.target),
                    pointer,
                });
                total_words = total_words.saturating_add(1);
                evidence_bytes = evidence_bytes.saturating_add(4);
                cursor = cursor.saturating_add(4);
            }
            if complete {
                ledger.included = ledger.included.saturating_add(1);
            } else {
                ledger.unknown = ledger.unknown.saturating_add(1);
            }
            records.push(StructuralVtableRecord {
                start,
                address_point,
                encoding: StructuralVtableEncoding::RelativeSigned32,
                kind: StructuralVtableKind::CompleteOrConstruction,
                end_exclusive: cursor,
                offset_to_top: i64::from(offset_to_top),
                typeinfo,
                slots,
                extent_confidence: if bounded_by_content || boundary < section_end {
                    StructuralVtableExtentConfidence::Derived
                } else {
                    StructuralVtableExtentConfidence::Candidate
                },
                complete,
                truncation_reason,
            });
        }
    }
    records.sort_by_key(|record| (record.start, record.address_point));
    records.dedup_by_key(|record| (record.start, record.address_point));
    if !authority_present {
        ledger
            .reasons
            .insert("rtti.runtime_family_anchors_absent".to_owned());
    }
    (records, ledger)
}

fn recover_structural_vtts(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    pointer_width: u64,
    vtables: &[StructuralVtableRecord],
    local_targets: &BTreeMap<String, u64>,
    limits: StrictVtableLimits,
    authority_present: bool,
) -> (Vec<StructuralVttRecord>, StructuralLedger) {
    let points = vtables
        .iter()
        .map(|record| record.address_point)
        .collect::<BTreeSet<_>>();
    let occupied = vtables
        .iter()
        .map(|record| (record.start, record.end_exclusive))
        .collect::<Vec<_>>();
    let mut ledger = StructuralLedger::default();
    if points.is_empty() {
        return (Vec::new(), ledger);
    }
    let mut records = Vec::new();
    let mut total_words = 0_u64;
    let mut evidence_bytes = 0_u64;
    for section in structural_sections(macho) {
        let Some(end) = section.addr().0.checked_add(section.size()) else {
            continue;
        };
        let mut cursor = align_up(section.addr().0, pointer_width);
        while cursor.saturating_add(pointer_width) <= end {
            if occupied
                .iter()
                .any(|&(start, finish)| start <= cursor && cursor < finish)
            {
                cursor = cursor.saturating_add(pointer_width);
                continue;
            }
            let start = cursor;
            let mut entries = Vec::new();
            while cursor.saturating_add(pointer_width) <= end {
                let Ok(pointer) =
                    observe_structural_pointer(macho, resolver, cursor, u64::MAX, local_targets)
                else {
                    break;
                };
                if !matches!(pointer.target, StrictPointerTarget::Local { va } if points.contains(&va))
                {
                    break;
                }
                entries.push(StructuralVttEntry {
                    ordinal: entries.len() as u64,
                    address: cursor,
                    address_point: pointer,
                });
                cursor = cursor.saturating_add(pointer_width);
            }
            if entries.len() >= 2 {
                ledger.attempted = ledger.attempted.saturating_add(1);
                let words = entries.len() as u64;
                let bytes = words.saturating_mul(pointer_width);
                if ledger.included >= limits.max_records
                    || total_words.saturating_add(words) > limits.max_words
                    || evidence_bytes.saturating_add(bytes) > limits.max_evidence_bytes
                {
                    ledger.excluded = ledger.excluded.saturating_add(1);
                    ledger.reasons.insert("rtti.structural_limit".to_owned());
                } else {
                    total_words = total_words.saturating_add(words);
                    evidence_bytes = evidence_bytes.saturating_add(bytes);
                    ledger.included = ledger.included.saturating_add(1);
                    records.push(StructuralVttRecord {
                        start,
                        end_exclusive: cursor,
                        entries,
                    });
                }
            } else {
                cursor = start.saturating_add(pointer_width);
            }
        }
    }
    if !authority_present {
        ledger
            .reasons
            .insert("rtti.runtime_family_anchors_absent".to_owned());
    }
    (records, ledger)
}

fn structural_sections<'image, 'data>(
    macho: &'image MachoFile<'data>,
) -> impl Iterator<Item = &'image Section> {
    macho.all_sections().filter(|section| {
        let name = section.section_name().as_str_lossy();
        matches!(
            section.section_type(),
            SectionType::Regular | SectionType::Coalesced
        ) && name != "__cfstring"
            && !name.starts_with("__objc_")
            && !name.starts_with("__swift")
            && !section.attributes().intersects(
                SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS,
            )
    })
}

fn executable_ranges(macho: &MachoFile<'_>) -> Vec<(u64, u64)> {
    macho
        .segments()
        .iter()
        .flat_map(|segment| {
            segment.sections().iter().filter_map(move |section| {
                let executable = segment
                    .init_prot()
                    .contains(crate::core::format::constants::VmProtection::EXECUTE)
                    && (section.attributes().intersects(
                        SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS,
                    ) || section.section_name() == "__text");
                executable.then(|| {
                    (
                        section.addr().0,
                        section.addr().0.saturating_add(section.size()),
                    )
                })
            })
        })
        .collect()
}

fn is_vtable_slot_target(target: &StrictPointerTarget, executable: &[(u64, u64)]) -> bool {
    match target {
        StrictPointerTarget::Null | StrictPointerTarget::External { .. } => true,
        StrictPointerTarget::Local { va } => executable
            .iter()
            .any(|&(start, end)| start <= *va && *va < end),
    }
}

fn local_symbol_authority(
    macho: &MachoFile<'_>,
    pointer_width: u64,
    max_symbols: u64,
) -> (
    BTreeMap<u64, ItaniumTypeInfoFamily>,
    BTreeMap<String, u64>,
    bool,
) {
    let mut anchors = BTreeMap::new();
    let mut targets = BTreeMap::new();
    let mut complete = true;
    let has_symtab = macho
        .load_commands()
        .iter()
        .any(|command| matches!(command.kind(), LoadCommand::Symtab(_)));
    match macho.ext::<SymbolTable<'_>>() {
        Ok(symbols) => {
            for symbol in symbols
                .symbols()
                .iter()
                .filter(|symbol| symbol.is_defined())
                .take(max_symbols.saturating_add(1) as usize)
            {
                if targets.len() as u64 == max_symbols {
                    complete = false;
                    break;
                }
                targets.insert(symbol.name.to_owned(), symbol.value);
            }
        }
        Err(_) if has_symtab => complete = false,
        Err(_) => {}
    }
    let image_base = macho.image_base().0;
    let mut export_count = 0_u64;
    let exports = crate::metadata::dyld::fold_exports(macho, (), |_, export| {
        export_count = export_count.saturating_add(1);
        if export_count > max_symbols {
            complete = false;
            return Ok(());
        }
        let address = match export.kind {
            ExportKind::Regular { address } | ExportKind::ThreadLocal { address } => {
                image_base.checked_add(address)
            }
            ExportKind::Absolute { address } => Some(address),
            ExportKind::StubAndResolver { stub_offset, .. } => image_base.checked_add(stub_offset),
            _ => None,
        };
        if let Some(address) = address {
            targets.entry(export.name).or_insert(address);
        }
        Ok(())
    });
    if exports.is_err() {
        complete = false;
    }
    for (name, &address) in &targets {
        let Some(family) = classify_family(name) else {
            continue;
        };
        for delta in [0, pointer_width, pointer_width.saturating_mul(2)] {
            if let Some(anchor) = address.checked_add(delta) {
                anchors.insert(anchor, family);
            }
        }
    }
    (anchors, targets, complete)
}

fn family_for_target(
    target: &StrictPointerTarget,
    anchors: &BTreeMap<u64, ItaniumTypeInfoFamily>,
) -> Option<ItaniumTypeInfoFamily> {
    match target {
        StrictPointerTarget::External { symbol, .. } => classify_family(symbol),
        StrictPointerTarget::Local { va } => anchors.get(va).copied(),
        StrictPointerTarget::Null => None,
    }
}

fn classify_family(name: &str) -> Option<ItaniumTypeInfoFamily> {
    [
        (
            "__fundamental_type_info",
            ItaniumTypeInfoFamily::Fundamental,
        ),
        ("__array_type_info", ItaniumTypeInfoFamily::Array),
        ("__function_type_info", ItaniumTypeInfoFamily::Function),
        ("__enum_type_info", ItaniumTypeInfoFamily::Enum),
        (
            "__si_class_type_info",
            ItaniumTypeInfoFamily::SingleInheritanceClass,
        ),
        (
            "__vmi_class_type_info",
            ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass,
        ),
        ("__class_type_info", ItaniumTypeInfoFamily::Class),
        ("__pointer_type_info", ItaniumTypeInfoFamily::Pointer),
        (
            "__pointer_to_member_type_info",
            ItaniumTypeInfoFamily::PointerToMember,
        ),
        ("__qualified_type_info", ItaniumTypeInfoFamily::Qualified),
    ]
    .into_iter()
    .find_map(|(needle, family)| name.contains(needle).then_some(family))
}

fn observe_structural_pointer(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    address: u64,
    address_mask: u64,
    local_targets: &BTreeMap<String, u64>,
) -> Result<StructuralPointer, StructuralDecodeFailure> {
    resolver
        .observe_at_va(Va(address))
        .map(|observation| structural_pointer(macho, observation, address_mask, local_targets))
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.pointer_unresolved"))
}

fn structural_pointer(
    macho: &MachoFile<'_>,
    observation: PointerObservation,
    address_mask: u64,
    local_targets: &BTreeMap<String, u64>,
) -> StructuralPointer {
    let self_bind_address = match (&observation.target, observation.encoding) {
        (
            PointerTarget::Import {
                name,
                library_ordinal: Some(0),
            },
            encoding,
        ) => local_targets.get(name).copied().or_else(|| {
            (encoding == PointerEncoding::LegacyBind)
                .then_some(observation.stored_value & address_mask)
                .filter(|candidate| {
                    macho
                        .address_map()
                        .va_to_thin_offset(Va(*candidate))
                        .is_ok()
                })
        }),
        _ => None,
    };
    let target = match observation.target {
        PointerTarget::Null => StrictPointerTarget::Null,
        PointerTarget::Address(address) => StrictPointerTarget::Local {
            va: address.0 & address_mask,
        },
        PointerTarget::Import {
            name,
            library_ordinal,
        } => self_bind_address.map_or_else(
            || StrictPointerTarget::External {
                symbol: name,
                library_ordinal: library_ordinal.unwrap_or(0),
            },
            |va| StrictPointerTarget::Local { va },
        ),
    };
    StructuralPointer {
        source_address: observation.source_va.0,
        raw_value: observation.stored_value,
        encoding: match observation.encoding {
            PointerEncoding::Direct => StructuralPointerEncoding::Direct,
            PointerEncoding::ChainedRebase => StructuralPointerEncoding::ChainedRebase,
            PointerEncoding::ChainedBind => StructuralPointerEncoding::ChainedBind,
            PointerEncoding::LegacyRebase => StructuralPointerEncoding::LegacyRebase,
            PointerEncoding::LegacyBind => StructuralPointerEncoding::LegacyBind,
        },
        authentication: observation.authentication.map(
            |PointerAuthentication {
                 diversity,
                 key,
                 address_diversity,
             }| StructuralPointerAuthentication {
                diversity,
                key,
                address_diversity,
            },
        ),
        target,
    }
}

fn relative_structural_pointer(source_address: u64, relative: i64) -> StructuralPointer {
    StructuralPointer {
        source_address,
        raw_value: relative as u32 as u64,
        encoding: StructuralPointerEncoding::RelativeSigned32,
        authentication: None,
        target: StrictPointerTarget::Local {
            va: source_address.wrapping_add_signed(relative),
        },
    }
}

fn adjustment_thunk(
    macho: &MachoFile<'_>,
    target: &StrictPointerTarget,
) -> Option<StructuralAdjustmentThunk> {
    let StrictPointerTarget::Local { va } = *target else {
        return None;
    };
    let bytes = macho.read_bytes_at_va(Va(va), 12).ok()?;
    if matches!(
        macho.header().cpu_type().0,
        crate::core::format::constants::CPU_TYPE_X86_64
    ) {
        let (adjustment, branch_offset) = match bytes {
            [0x48, 0x83, 0xC7, immediate, ..] => (i64::from(*immediate as i8), 4_usize),
            [0x48, 0x83, 0xEF, immediate, ..] => (-i64::from(*immediate), 4_usize),
            [0x48, 0x81, 0xC7, immediate @ ..] if immediate.len() >= 9 => {
                let value = i32::from_le_bytes(immediate[..4].try_into().ok()?);
                (i64::from(value), 7)
            }
            [0x48, 0x81, 0xEF, immediate @ ..] if immediate.len() >= 9 => {
                let value = i32::from_le_bytes(immediate[..4].try_into().ok()?);
                (-i64::from(value), 7)
            }
            _ => return None,
        };
        let branch = bytes.get(branch_offset..)?;
        let target = match branch {
            [0xE9, displacement @ ..] if displacement.len() >= 4 => {
                let displacement = i32::from_le_bytes(displacement[..4].try_into().ok()?);
                va.saturating_add(branch_offset as u64 + 5)
                    .wrapping_add_signed(i64::from(displacement))
            }
            [0xEB, displacement, ..] => va
                .saturating_add(branch_offset as u64 + 2)
                .wrapping_add_signed(i64::from(*displacement as i8)),
            _ => return None,
        };
        return Some(StructuralAdjustmentThunk {
            this_adjustment: adjustment,
            target,
        });
    }
    if macho.header().cpu_type().0 == crate::core::format::constants::CPU_TYPE_ARM64 {
        let first = u32::from_le_bytes(bytes[..4].try_into().ok()?);
        let branch = u32::from_le_bytes(bytes[4..8].try_into().ok()?);
        if first & 0xFFC0_03FF != 0x9100_0000 && first & 0xFFC0_03FF != 0xD100_0000 {
            return None;
        }
        if branch & 0x7C00_0000 != 0x1400_0000 {
            return None;
        }
        let immediate =
            i64::from((first >> 10) & 0xFFF) << if first & (1 << 22) != 0 { 12 } else { 0 };
        let adjustment = if first & 0x4000_0000 != 0 {
            -immediate
        } else {
            immediate
        };
        let displacement = (((branch & 0x03FF_FFFF) << 6) as i32 >> 4) as i64;
        return Some(StructuralAdjustmentThunk {
            this_adjustment: adjustment,
            target: va.saturating_add(4).wrapping_add_signed(displacement),
        });
    }
    None
}

fn read_type_name(
    macho: &MachoFile<'_>,
    address: u64,
    max_bytes: u64,
) -> Result<(String, u64), StructuralDecodeFailure> {
    let offset = macho
        .address_map()
        .va_to_thin_offset(Va(address))
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.type_name_unmapped"))?;
    let start = usize::try_from(offset.0)
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.type_name_unmapped"))?;
    let maximum = usize::try_from(max_bytes).map_err(|_| StructuralDecodeFailure::Limit)?;
    let available = macho
        .bytes()
        .get(start..)
        .ok_or(StructuralDecodeFailure::Malformed(
            "rtti.type_name_unmapped",
        ))?;
    let bounded = &available[..available.len().min(maximum.saturating_add(1))];
    let length = bounded
        .iter()
        .position(|byte| *byte == 0)
        .ok_or(StructuralDecodeFailure::Limit)?;
    if length == 0 {
        return Err(StructuralDecodeFailure::Malformed("rtti.type_name_invalid"));
    }
    let name = std::str::from_utf8(&bounded[..length])
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.type_name_invalid"))?;
    Ok((name.to_owned(), length.saturating_add(1) as u64))
}

fn read_u32_va(macho: &MachoFile<'_>, address: u64) -> Result<u32, StructuralDecodeFailure> {
    let bytes = macho
        .read_bytes_at_va(Va(address), 4)
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.record_unreadable"))?;
    Ok(macho
        .endian()
        .read_u32(bytes.try_into().expect("validated four-byte read")))
}

fn read_i32_va(macho: &MachoFile<'_>, address: u64) -> Result<i32, StructuralDecodeFailure> {
    read_u32_va(macho, address).map(|value| value as i32)
}

fn read_word_va(macho: &MachoFile<'_>, address: u64) -> Result<u64, StructuralDecodeFailure> {
    let width = if macho.is_64bit() { 8 } else { 4 };
    let bytes = macho
        .read_bytes_at_va(Va(address), width)
        .map_err(|_| StructuralDecodeFailure::Malformed("rtti.record_unreadable"))?;
    Ok(if macho.is_64bit() {
        macho
            .endian()
            .read_u64(bytes.try_into().expect("validated eight-byte read"))
    } else {
        u64::from(
            macho
                .endian()
                .read_u32(bytes.try_into().expect("validated four-byte read")),
        )
    })
}

fn sign_extend_word(value: u64, pointer_width: u64) -> i64 {
    if pointer_width == 4 {
        i64::from(value as u32 as i32)
    } else {
        value as i64
    }
}

fn align_up(value: u64, alignment: u64) -> u64 {
    value
        .checked_add(alignment.saturating_sub(1))
        .map(|value| value & !alignment.saturating_sub(1))
        .unwrap_or(u64::MAX)
}

fn collector_covered(
    receipts: &[RttiCollectorReceipt],
    strict: RttiCollector,
    structural: RttiCollector,
) -> bool {
    receipts.iter().any(|receipt| {
        receipt.collector == strict && receipt.outcome == StrictRttiOutcome::Complete
    }) || receipts.iter().any(|receipt| {
        receipt.collector == structural
            && matches!(
                receipt.outcome,
                StrictRttiOutcome::Complete | StrictRttiOutcome::Absent
            )
    })
}

fn collect_rtti_conflicts(
    strict: &StrictRttiBatch,
    structural: &[StructuralTypeInfoRecord],
) -> Vec<RttiConflict> {
    let strict = strict
        .records
        .iter()
        .filter_map(|record| match record {
            StrictRttiRecord::TypeInfo { record } => Some((record.va, record.as_ref())),
            StrictRttiRecord::ExternalTypeInfo { .. } => None,
        })
        .collect::<BTreeMap<_, _>>();
    let mut conflicts = Vec::new();
    for record in structural {
        let Some(exact) = strict.get(&record.address) else {
            continue;
        };
        for (field, strict_value, structural_value) in [
            (
                "family",
                format!("{:?}", exact.family),
                format!("{:?}", record.family),
            ),
            (
                "type_name",
                exact.type_name.clone(),
                record.type_name.clone(),
            ),
            (
                "type_name_non_unique",
                exact.type_name_non_unique.to_string(),
                record.type_name_non_unique.to_string(),
            ),
            (
                "class_flags",
                exact.class_flags.to_string(),
                record.class_flags.to_string(),
            ),
            (
                "base_count",
                exact.bases.len().to_string(),
                record.bases.len().to_string(),
            ),
        ] {
            if strict_value != structural_value {
                conflicts.push(RttiConflict {
                    address: record.address,
                    field: field.to_owned(),
                    strict_value,
                    structural_value,
                });
            }
        }
    }
    conflicts.sort_by(|left, right| {
        (left.address, left.field.as_str()).cmp(&(right.address, right.field.as_str()))
    });
    conflicts
}

fn collect_base_relations(batch: &StrictRttiBatch) -> Vec<RttiBaseRelation> {
    let mut relations = Vec::new();
    for record in &batch.records {
        let StrictRttiRecord::TypeInfo { record } = record else {
            continue;
        };
        for base in &record.bases {
            relations.push(RttiBaseRelation {
                derived_typeinfo: record.va,
                derived_symbol: record.symbol.clone(),
                ordinal: base.ordinal,
                base: base.typeinfo.target.clone(),
                signed_offset: base.signed_offset,
                is_virtual: base.is_virtual,
                is_public: base.is_public,
            });
        }
    }
    relations
}

fn collect_vtable_relations(batch: &StrictVtableBatch) -> Vec<VtableTypeRelation> {
    let mut relations = Vec::new();
    for record in &batch.records {
        let StrictVtableRecord::Group { record } = record else {
            continue;
        };
        for point in &record.address_points {
            relations.push(VtableTypeRelation {
                vtable_symbol: record.symbol.clone(),
                vtable: record.va,
                address_point_ordinal: point.ordinal,
                address_point: point.va,
                typeinfo: point.typeinfo.target.clone(),
            });
        }
    }
    relations.sort_by_key(|relation| (relation.vtable, relation.address_point_ordinal));
    relations
}

fn receipt(collector: RttiCollector, batch: &StrictRttiBatch) -> RttiCollectorReceipt {
    RttiCollectorReceipt {
        collector,
        outcome: batch.outcome,
        conservation: batch.conservation,
        reasons: gap_reasons(batch.gaps.iter().map(|gap| gap.code)),
    }
}

fn vtable_receipt(batch: &StrictVtableBatch) -> RttiCollectorReceipt {
    RttiCollectorReceipt {
        collector: RttiCollector::Vtables,
        outcome: batch.outcome,
        conservation: batch.conservation,
        reasons: gap_reasons(batch.gaps.iter().map(|gap| gap.code)),
    }
}

fn gap_reasons(
    codes: impl Iterator<Item = crate::metadata::cpp::StrictRttiGapCode>,
) -> Vec<String> {
    let mut reasons = codes
        .map(|code| match code {
            crate::metadata::cpp::StrictRttiGapCode::StructuralLimitExceeded => {
                "rtti.structural_limit"
            }
            crate::metadata::cpp::StrictRttiGapCode::PointerUnresolved => "rtti.pointer_unresolved",
            crate::metadata::cpp::StrictRttiGapCode::RecordMalformed => "rtti.record_malformed",
            crate::metadata::cpp::StrictRttiGapCode::FamilyUnsupported => "rtti.family_unsupported",
            crate::metadata::cpp::StrictRttiGapCode::TypeNameInvalid => "rtti.type_name_invalid",
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    reasons.sort();
    reasons.dedup();
    reasons
}

fn absent_type_info() -> StrictRttiBatch {
    StrictRttiBatch {
        outcome: StrictRttiOutcome::Absent,
        records: Vec::new(),
        observations: Vec::new(),
        gaps: Vec::new(),
        conservation: StrictRttiConservation {
            attempted: 0,
            included: 0,
            unknown: 0,
            excluded: 0,
        },
    }
}

fn absent_vtables() -> StrictVtableBatch {
    StrictVtableBatch {
        outcome: StrictRttiOutcome::Absent,
        records: Vec::new(),
        observations: Vec::new(),
        gaps: Vec::new(),
        conservation: StrictRttiConservation {
            attempted: 0,
            included: 0,
            unknown: 0,
            excluded: 0,
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::core::model::container::MachoContainer;

    use super::*;

    #[test]
    fn anchor_free_type_names_require_a_complete_itanium_parse() {
        for name in ["1A", "N3foo3barE", "P1A", "i"] {
            assert!(valid_itanium_type_name(name), "rejected {name}");
        }
        for name in ["rules", "rules2", "requirement", "1Atrailing"] {
            assert!(!valid_itanium_type_name(name), "accepted {name}");
        }
    }

    fn structural_rtti_fixture(strip_application_names: bool) -> Vec<u8> {
        let runtime = "__ZTVN10__cxxabiv117__class_type_infoE";
        let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
            macho_test_support::SymbolFixture {
                name: runtime,
                external: true,
                defined: true,
            },
            macho_test_support::SymbolFixture {
                name: "__ZTI1A",
                external: false,
                defined: true,
            },
            macho_test_support::SymbolFixture {
                name: "__ZTV1A",
                external: false,
                defined: true,
            },
        ]);
        let symbol_offset = 0x140;
        for (index, value) in [0x1_0000_0100_u64, 0x1_0000_0118, 0x1_0000_0128]
            .into_iter()
            .enumerate()
        {
            let offset = symbol_offset + index * 16 + 8;
            bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        }
        bytes[0x100..0x140].fill(0);
        bytes[0x118..0x120].copy_from_slice(&0x1_0000_0110_u64.to_le_bytes());
        bytes[0x120..0x128].copy_from_slice(&0x1_0000_0138_u64.to_le_bytes());
        bytes[0x130..0x138].copy_from_slice(&0x1_0000_0118_u64.to_le_bytes());
        bytes[0x138..0x13b].copy_from_slice(b"1A\0");
        if strip_application_names {
            for (from, to) in [
                (b"__ZTI1A".as_slice(), b"_local1".as_slice()),
                (b"__ZTV1A".as_slice(), b"_local2".as_slice()),
            ] {
                let offset = bytes
                    .windows(from.len())
                    .position(|window| window == from)
                    .expect("fixture symbol name");
                bytes[offset..offset + to.len()].copy_from_slice(to);
            }
        }
        bytes
    }

    #[test]
    fn structural_rtti_preserves_identity_after_application_symbols_are_stripped() {
        let recover = |bytes: &[u8]| {
            let macho = match crate::core::parse(bytes).unwrap() {
                MachoContainer::Thin(macho) => macho,
                MachoContainer::Fat(_) => panic!("fixture must be thin"),
            };
            RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap()
        };
        let rich = recover(&structural_rtti_fixture(false));
        let stripped = recover(&structural_rtti_fixture(true));
        assert_eq!(rich.status(), RttiIndexStatus::Complete);
        assert_eq!(stripped.status(), RttiIndexStatus::Complete);
        assert_eq!(rich.structural_type_info(), stripped.structural_type_info());
        assert_eq!(rich.structural_vtables(), stripped.structural_vtables());
        assert!(matches!(
            stripped.recovered_type_info_by_address(0x1_0000_0118),
            Some(RecoveredTypeInfo::Structural(record)) if record.type_name == "1A"
        ));
        assert!(matches!(
            stripped.recovered_vtable_containing(0x1_0000_0128),
            Some(RecoveredVtable::Structural(record))
                if record.address_point == 0x1_0000_0138
        ));
    }

    #[test]
    fn anchor_free_cluster_is_independent_rtti_authority() {
        let mut bytes = structural_rtti_fixture(true);
        let runtime_name = b"__ZTVN10__cxxabiv117__class_type_infoE";
        let offset = bytes
            .windows(runtime_name.len())
            .position(|window| window == runtime_name)
            .expect("runtime anchor symbol name");
        bytes[offset..offset + runtime_name.len()].fill(b'x');
        bytes[offset + runtime_name.len()] = 0;
        // A second valid type-info-shaped object sharing the same local vptr
        // establishes the runtime family cluster without any symbol spelling.
        bytes[0x100..0x108].copy_from_slice(&0x1_0000_0110_u64.to_le_bytes());
        bytes[0x108..0x110].copy_from_slice(&0x1_0000_013b_u64.to_le_bytes());
        bytes[0x13b..0x13e].copy_from_slice(b"1B\0");
        let macho = match crate::core::parse(&bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
        assert_eq!(index.status(), RttiIndexStatus::Complete);
        let record = index
            .structural_type_info()
            .iter()
            .find(|record| record.address == 0x1_0000_0118)
            .expect("application RTTI survives removal of every runtime-family name");
        assert_eq!(
            record.family_authority,
            StructuralRttiFamilyAuthority::ConservativeClassLike
        );
        assert!(index.receipts().iter().all(|receipt| {
            !receipt
                .reasons
                .contains(&"rtti.runtime_family_anchors_absent".to_owned())
        }));
    }

    #[test]
    fn relative_vtable_headers_and_stripped_adjustment_thunks_are_structural() {
        let mut bytes = structural_rtti_fixture(false);
        bytes[0x100..0x104].copy_from_slice(&0_i32.to_le_bytes());
        bytes[0x104..0x108].copy_from_slice(&0x14_i32.to_le_bytes());
        bytes[0x108..0x10c].copy_from_slice(&0_i32.to_le_bytes());
        let macho = match crate::core::parse(&bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
        assert!(index.structural_vtables().iter().any(|record| {
            record.start == 0x1_0000_0100
                && record.encoding == StructuralVtableEncoding::RelativeSigned32
                && record.typeinfo.target == StrictPointerTarget::Local { va: 0x1_0000_0118 }
        }));

        let mut thunk_bytes = macho_test_support::disassembly_x86_64();
        thunk_bytes[0x100..0x109].copy_from_slice(&[0x48, 0x83, 0xc7, 0x08, 0xe9, 0x07, 0, 0, 0]);
        let thunk_macho = match crate::core::parse(&thunk_bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        assert_eq!(
            adjustment_thunk(
                &thunk_macho,
                &StrictPointerTarget::Local { va: 0x1_0000_0100 },
            ),
            Some(StructuralAdjustmentThunk {
                this_adjustment: 8,
                target: 0x1_0000_0110,
            })
        );
    }

    #[test]
    fn checked_in_arm64_and_x86_corpus_has_complete_structural_parity() {
        for bytes in [
            include_bytes!("../../tests/fixtures/arm64-darwin-tagged-rtti.dylib").as_slice(),
            include_bytes!("../../tests/fixtures/x86_64-darwin-tagged-rtti.dylib").as_slice(),
        ] {
            let macho = match crate::core::parse(bytes).unwrap() {
                MachoContainer::Thin(macho) => macho,
                MachoContainer::Fat(_) => panic!("fixture must be thin"),
            };
            let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
            let strict_types = index
                .type_info()
                .records
                .iter()
                .filter(|record| matches!(record, StrictRttiRecord::TypeInfo { .. }))
                .count();
            assert_eq!(index.status(), RttiIndexStatus::Complete);
            assert_eq!(index.structural_type_info().len(), strict_types);
            assert!(
                index
                    .receipts()
                    .iter()
                    .all(|receipt| receipt.outcome == StrictRttiOutcome::Complete)
            );
        }
    }

    #[test]
    fn bounded_anchor_free_scan_proves_absent_rtti() {
        let bytes = macho_test_support::disassembly_x86_64();
        let macho = match crate::core::parse(&bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
        assert_eq!(index.status(), RttiIndexStatus::Complete);
        assert_eq!(index.type_info().outcome, StrictRttiOutcome::Absent);
        assert_eq!(index.vtables().outcome, StrictRttiOutcome::Absent);
    }

    #[test]
    fn external_typeinfo_is_retained_and_queryable() {
        let bytes =
            macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
                name: "__ZTI1A",
                external: true,
                defined: false,
            }]);
        let macho = match crate::core::parse(&bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
        assert_eq!(index.status(), RttiIndexStatus::Complete);
        assert!(matches!(
            index.type_info_by_symbol("__ZTI1A"),
            Some(StrictRttiRecord::ExternalTypeInfo { symbol, .. }) if symbol == "__ZTI1A"
        ));
    }

    #[test]
    fn missing_symbol_table_is_covered_by_structural_absence_authority() {
        let bytes = macho_test_support::thin64_x86_64(2);
        let macho = match crate::core::parse(&bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
        assert_eq!(index.status(), RttiIndexStatus::Complete);
        assert!(
            index
                .receipts()
                .iter()
                .filter(|receipt| matches!(
                    receipt.collector,
                    RttiCollector::TypeInfo | RttiCollector::Vtables
                ))
                .all(|receipt| receipt
                    .reasons
                    .contains(&"rtti.symbol_table_absent".to_owned()))
        );
    }

    #[test]
    fn stripping_external_rtti_names_falls_back_to_structural_absence() {
        let mut bytes =
            macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
                name: "__ZTI1A",
                external: true,
                defined: false,
            }]);
        let string_range = {
            let macho = match crate::core::parse(&bytes).unwrap() {
                MachoContainer::Thin(macho) => macho,
                MachoContainer::Fat(_) => panic!("fixture must be thin"),
            };
            macho
                .load_commands()
                .iter()
                .find_map(|command| match command.kind() {
                    LoadCommand::Symtab(symtab) => Some(
                        symtab.str_offset as usize
                            ..symtab.str_offset as usize + symtab.str_size as usize,
                    ),
                    _ => None,
                })
                .unwrap()
        };
        bytes[string_range].fill(0);
        let macho = match crate::core::parse(&bytes).unwrap() {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("fixture must be thin"),
        };
        let index = RttiIndex::recover(&macho, RttiRecoveryLimits::default()).unwrap();
        assert_eq!(index.status(), RttiIndexStatus::Complete);
        assert!(
            index
                .receipts()
                .iter()
                .filter(|receipt| matches!(
                    receipt.collector,
                    RttiCollector::TypeInfo | RttiCollector::Vtables
                ))
                .all(|receipt| receipt
                    .reasons
                    .contains(&"rtti.symbol_candidates_absent".to_owned()))
        );
    }
}
