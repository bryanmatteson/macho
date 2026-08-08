//! Bounded data-object, signature, stack-frame, and local-variable recovery.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::analysis::dwarf_index::{DwarfIndex, DwarfIndexStatus};
use crate::analysis::exception_index::{
    ExceptionCfaRule, ExceptionIndex, ExceptionIndexStatus, ExceptionRegisterRule,
};
use crate::analysis::functions::{FunctionImageIdentity, FunctionIndex};
use crate::analysis::image_layout::ImageLayoutIndex;
use crate::analysis::objc_index::{ObjcIndex, ObjcIndexStatus};
use crate::analysis::pointer_index::PointerIndex;
use crate::analysis::rtti::{RttiIndex, RttiIndexStatus};
use crate::analysis::string_index::{StringIndex, StringIndexStatus};
use crate::analysis::swift_index::{SwiftIndex, SwiftIndexStatus};
use crate::analysis::symbol_inventory::{
    NlistSymbolKind, RecoveredSymbolKind, SymbolInventory, SymbolInventoryStatus,
};

/// Explicit bounds for semantic recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRecoveryLimits {
    /// Maximum global/static data identities retained.
    pub max_data_objects: usize,
    /// Maximum function signatures retained.
    pub max_signatures: usize,
    /// Maximum stack-frame records retained.
    pub max_frames: usize,
    /// Maximum local-variable and parameter records retained.
    pub max_locals: usize,
}

impl Default for SemanticRecoveryLimits {
    fn default() -> Self {
        Self {
            max_data_objects: 8_000_000,
            max_signatures: 2_000_000,
            max_frames: 2_000_000,
            max_locals: 8_000_000,
        }
    }
}

impl SemanticRecoveryLimits {
    /// Reject zero bounds.
    pub fn validate(self) -> Result<Self, SemanticRecoveryError> {
        if self.max_data_objects == 0
            || self.max_signatures == 0
            || self.max_frames == 0
            || self.max_locals == 0
        {
            return Err(SemanticRecoveryError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Failure preventing semantic recovery.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SemanticRecoveryError {
    /// At least one bound is zero.
    #[error("semantic recovery limits must be non-zero")]
    InvalidLimits,
    /// Input indexes describe different images.
    #[error("semantic recovery inputs describe different image bytes")]
    ImageMismatch,
}

/// Supported global/static object class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataObjectKind {
    /// Typed string bytes.
    String,
    /// Constant object wrapping string bytes.
    ConstantStringObject,
    /// Pointer, relocation, fixup, or stub slot.
    PointerSlot,
    /// One fixed-width element of a pointer-array section.
    PointerArrayElement,
    /// One fixed-width compiler literal.
    Literal,
    /// A thread-local storage region or descriptor.
    ThreadLocal,
    /// Section-backed named global.
    NamedGlobal,
    /// Objective-C runtime record.
    ObjectiveCMetadata,
    /// Swift descriptor or field record.
    SwiftMetadata,
    /// Itanium type-info object.
    CppTypeInfo,
    /// Itanium vtable address-point group.
    CppVtable,
    /// Itanium virtual-table table (VTT) array.
    CppVtt,
}

/// Confidence of an object extent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataExtentConfidence {
    /// Both object boundaries are exact.
    Exact,
    /// Boundaries follow supported structural evidence.
    Derived,
    /// At least one boundary remains candidate-only.
    Candidate,
    /// No supported end boundary is known.
    Unknown,
}

/// One addressable data identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredDataObject {
    /// Stable image-local identifier.
    pub id: String,
    /// First object byte.
    pub address: u64,
    /// Exclusive end when bounded.
    pub end_exclusive: Option<u64>,
    /// Semantic object class.
    pub kind: DataObjectKind,
    /// Best known name.
    pub name: Option<String>,
    /// Strength of the retained extent.
    pub extent_confidence: DataExtentConfidence,
    /// Stable evidence sources.
    pub evidence: Vec<String>,
}

/// Evidence source for a function signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureEvidenceSource {
    /// DWARF DIEs and attributes.
    Dwarf,
    /// Objective-C runtime type encoding.
    ObjectiveCEncoding,
    /// Symbol spelling and linkage role.
    SymbolRole,
    /// Swift ABI metadata or mangling.
    SwiftMetadata,
    /// Itanium C++ mangled spelling.
    CppMangledName,
}

/// Best-known function signature without inventing register-derived types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredFunctionSignature {
    /// Recovered function identity.
    pub function_entry: u64,
    /// Best available display spelling.
    pub display: Option<String>,
    /// Return type when an authoritative source supplies one.
    pub return_type: Option<String>,
    /// Ordered argument type/name spellings supplied by metadata.
    pub arguments: Vec<String>,
    /// Whether a source proves variadic calling semantics.
    pub variadic: Option<bool>,
    /// Hidden receiver or ABI parameters.
    pub hidden_parameters: Vec<String>,
    /// Evidence contributing to this record.
    pub evidence: Vec<SignatureEvidenceSource>,
    /// Stable unresolved/conflict reasons.
    pub reasons: Vec<String>,
}

/// One recovered stack-frame summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredStackFrame {
    /// Function entry.
    pub function_entry: u64,
    /// Maximum positive CFA displacement observed, when register-based CFI exists.
    pub cfa_extent: Option<u64>,
    /// Registers saved in CFA-relative slots.
    pub saved_registers: Vec<(u16, i64)>,
    /// Whether all retained CFI rows use supported register-and-offset rules.
    pub complete: bool,
    /// Stable limitations.
    pub reasons: Vec<String>,
}

/// DWARF local or formal parameter retained without speculative semantics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecoveredLocalVariable {
    /// Owning function when a containing subprogram has an address.
    pub function_entry: Option<u64>,
    /// Physical DIE offset.
    pub die_offset: u64,
    /// Variable or formal parameter.
    pub parameter: bool,
    /// Source name.
    pub name: Option<String>,
    /// Referenced type DIE offset.
    pub type_reference: Option<u64>,
    /// Exact DWARF location expression bytes.
    pub location_expression: Option<Vec<u8>>,
    /// Whether supported metadata establishes a stable location expression.
    pub location_complete: bool,
}

/// Status shared by semantic sub-inventories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticIndexStatus {
    /// All supported inputs and records were conserved.
    Complete,
    /// A source or semantic field remains explicitly unresolved.
    Partial,
    /// An explicit record bound omitted evidence.
    Truncated,
}

/// Conservation and continuation receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticIndexCompleteness {
    /// Overall status.
    pub status: SemanticIndexStatus,
    /// Stable reasons.
    pub reasons: Vec<String>,
    /// Candidate records observed before retention limits.
    pub observed: u64,
    /// Records retained.
    pub retained: u64,
    /// First omitted stable coordinate.
    pub continuation: Option<String>,
}

/// Unified image-bound semantic inventory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SemanticIndex {
    image: FunctionImageIdentity,
    limits: SemanticRecoveryLimits,
    data_objects: Vec<RecoveredDataObject>,
    signatures: Vec<RecoveredFunctionSignature>,
    frames: Vec<RecoveredStackFrame>,
    locals: Vec<RecoveredLocalVariable>,
    completeness: SemanticIndexCompleteness,
}

/// Required evidence inputs for semantic recovery.
#[derive(Debug, Clone, Copy)]
pub struct SemanticRecoveryInputs<'a> {
    /// Selected image segments and sections.
    pub image_layout: &'a ImageLayoutIndex,
    /// Format pointer records.
    pub pointers: &'a PointerIndex,
    /// Symbol inventory.
    pub symbols: &'a SymbolInventory,
    /// String inventory.
    pub strings: &'a StringIndex,
    /// Objective-C metadata.
    pub objc: &'a ObjcIndex,
    /// Swift metadata.
    pub swift: &'a SwiftIndex,
    /// RTTI and vtables.
    pub rtti: &'a RttiIndex,
    /// DWARF traversal.
    pub dwarf: &'a DwarfIndex,
    /// Exception CFI rows.
    pub exceptions: &'a ExceptionIndex,
    /// Function identities.
    pub functions: &'a FunctionIndex,
}

impl SemanticIndex {
    /// Recover supported data, signature, frame, and local-variable semantics.
    pub fn recover(
        inputs: SemanticRecoveryInputs<'_>,
        limits: SemanticRecoveryLimits,
    ) -> Result<Self, SemanticRecoveryError> {
        let limits = limits.validate()?;
        let image = inputs.functions.image().clone();
        if [
            inputs.image_layout.image(),
            inputs.pointers.image(),
            inputs.symbols.image(),
            inputs.strings.image(),
            inputs.objc.image(),
            inputs.swift.image(),
            inputs.rtti.image(),
            inputs.dwarf.image(),
            inputs.exceptions.image(),
        ]
        .into_iter()
        .any(|candidate| candidate != &image)
        {
            return Err(SemanticRecoveryError::ImageMismatch);
        }
        let mut data_objects = collect_data_objects(inputs);
        let mut signatures = collect_signatures(inputs);
        let mut frames = collect_frames(inputs);
        let mut locals = collect_locals(inputs.dwarf);
        data_objects.sort_by(|a, b| (a.address, a.kind, &a.id).cmp(&(b.address, b.kind, &b.id)));
        data_objects
            .dedup_by(|a, b| a.address == b.address && a.kind == b.kind && a.name == b.name);
        signatures.sort_by_key(|record| record.function_entry);
        frames.sort_by_key(|record| record.function_entry);
        locals.sort_by_key(|record| (record.function_entry, record.die_offset));
        let observed = data_objects.len() as u64
            + signatures.len() as u64
            + frames.len() as u64
            + locals.len() as u64;
        let mut continuation = None;
        if data_objects.len() > limits.max_data_objects {
            continuation = Some(format!("data_object:{}", limits.max_data_objects));
            data_objects.truncate(limits.max_data_objects);
        }
        if continuation.is_none() && signatures.len() > limits.max_signatures {
            continuation = Some(format!("signature:{}", limits.max_signatures));
        }
        signatures.truncate(limits.max_signatures);
        if continuation.is_none() && frames.len() > limits.max_frames {
            continuation = Some(format!("frame:{}", limits.max_frames));
        }
        frames.truncate(limits.max_frames);
        if continuation.is_none() && locals.len() > limits.max_locals {
            continuation = Some(format!("local:{}", limits.max_locals));
        }
        locals.truncate(limits.max_locals);
        let retained = data_objects.len() as u64
            + signatures.len() as u64
            + frames.len() as u64
            + locals.len() as u64;
        let mut reasons = source_reasons(inputs);
        if continuation.is_some() {
            reasons.insert("semantics.record_budget".into());
        }
        let status = if continuation.is_some() {
            SemanticIndexStatus::Truncated
        } else if reasons.is_empty() {
            SemanticIndexStatus::Complete
        } else {
            SemanticIndexStatus::Partial
        };
        let index = Self {
            image,
            limits,
            data_objects,
            signatures,
            frames,
            locals,
            completeness: SemanticIndexCompleteness {
                status,
                reasons: reasons.into_iter().collect(),
                observed,
                retained,
                continuation,
            },
        };
        debug_assert!(index.durable_invariants_hold());
        Ok(index)
    }

    /// Exact image identity.
    pub fn image(&self) -> &FunctionImageIdentity {
        &self.image
    }
    /// Exact recovery limits.
    pub const fn limits(&self) -> SemanticRecoveryLimits {
        self.limits
    }
    /// Recovered addressable data identities.
    pub fn data_objects(&self) -> &[RecoveredDataObject] {
        &self.data_objects
    }
    /// Recovered best-known signatures.
    pub fn signatures(&self) -> &[RecoveredFunctionSignature] {
        &self.signatures
    }
    /// Recovered CFI-derived frames.
    pub fn frames(&self) -> &[RecoveredStackFrame] {
        &self.frames
    }
    /// Recovered DWARF locals and formal parameters.
    pub fn locals(&self) -> &[RecoveredLocalVariable] {
        &self.locals
    }
    /// Completeness and continuation receipt.
    pub fn completeness(&self) -> &SemanticIndexCompleteness {
        &self.completeness
    }
    /// Find a data object that owns or begins at an address.
    pub fn data_containing(&self, address: u64) -> Option<&RecoveredDataObject> {
        self.data_objects
            .iter()
            .filter(|object| {
                object.address == address
                    || (object.address < address
                        && object.end_exclusive.is_some_and(|end| address < end))
            })
            .min_by_key(|object| object.end_exclusive.unwrap_or(u64::MAX) - object.address)
    }
    /// Best-known signature for a recovered function.
    pub fn signature(&self, entry: u64) -> Option<&RecoveredFunctionSignature> {
        self.signatures
            .binary_search_by_key(&entry, |item| item.function_entry)
            .ok()
            .map(|index| &self.signatures[index])
    }
    /// Frame summary for a recovered function.
    pub fn frame(&self, entry: u64) -> Option<&RecoveredStackFrame> {
        self.frames
            .binary_search_by_key(&entry, |item| item.function_entry)
            .ok()
            .map(|index| &self.frames[index])
    }

    pub(crate) fn durable_invariants_hold(&self) -> bool {
        if self.limits.validate().is_err()
            || self.data_objects.len() > self.limits.max_data_objects
            || self.signatures.len() > self.limits.max_signatures
            || self.frames.len() > self.limits.max_frames
            || self.locals.len() > self.limits.max_locals
        {
            return false;
        }
        let data_are_canonical = self.data_objects.windows(2).all(|pair| {
            (pair[0].address, pair[0].kind, &pair[0].id)
                <= (pair[1].address, pair[1].kind, &pair[1].id)
        }) && self.data_objects.iter().all(|object| {
            !object.id.is_empty()
                && !object.evidence.is_empty()
                && object.end_exclusive.is_none_or(|end| object.address < end)
        });
        let signatures_are_canonical = self
            .signatures
            .windows(2)
            .all(|pair| pair[0].function_entry < pair[1].function_entry)
            && self.signatures.iter().all(|signature| {
                signature.evidence.windows(2).all(|pair| pair[0] < pair[1])
                    && signature.reasons.windows(2).all(|pair| pair[0] < pair[1])
            });
        let frames_are_canonical = self
            .frames
            .windows(2)
            .all(|pair| pair[0].function_entry < pair[1].function_entry)
            && self.frames.iter().all(|frame| {
                frame
                    .saved_registers
                    .windows(2)
                    .all(|pair| pair[0] < pair[1])
                    && frame.reasons.windows(2).all(|pair| pair[0] < pair[1])
            });
        let locals_are_canonical = self.locals.windows(2).all(|pair| {
            (pair[0].function_entry, pair[0].die_offset)
                <= (pair[1].function_entry, pair[1].die_offset)
        });
        let reasons_are_canonical = self
            .completeness
            .reasons
            .windows(2)
            .all(|pair| pair[0] < pair[1]);
        let retained = self
            .data_objects
            .len()
            .checked_add(self.signatures.len())
            .and_then(|count| count.checked_add(self.frames.len()))
            .and_then(|count| count.checked_add(self.locals.len()))
            .and_then(|count| u64::try_from(count).ok());
        let continuation_is_valid = self
            .completeness
            .continuation
            .as_deref()
            .is_none_or(|value| {
                [
                    ("data_object", self.limits.max_data_objects),
                    ("signature", self.limits.max_signatures),
                    ("frame", self.limits.max_frames),
                    ("local", self.limits.max_locals),
                ]
                .into_iter()
                .any(|(kind, limit)| value == format!("{kind}:{limit}"))
            });
        let status_is_derived = match self.completeness.status {
            SemanticIndexStatus::Complete => {
                self.completeness.continuation.is_none()
                    && self.completeness.reasons.is_empty()
                    && self.completeness.observed == self.completeness.retained
            }
            SemanticIndexStatus::Partial => {
                self.completeness.continuation.is_none()
                    && !self.completeness.reasons.is_empty()
                    && self.completeness.observed == self.completeness.retained
            }
            SemanticIndexStatus::Truncated => {
                self.completeness.continuation.is_some()
                    && self
                        .completeness
                        .reasons
                        .binary_search_by(|reason| reason.as_str().cmp("semantics.record_budget"))
                        .is_ok()
                    && self.completeness.observed > self.completeness.retained
            }
        };

        data_are_canonical
            && signatures_are_canonical
            && frames_are_canonical
            && locals_are_canonical
            && reasons_are_canonical
            && retained == Some(self.completeness.retained)
            && self.completeness.observed >= self.completeness.retained
            && continuation_is_valid
            && status_is_derived
    }
}

fn object(
    address: u64,
    end: Option<u64>,
    kind: DataObjectKind,
    name: Option<String>,
    confidence: DataExtentConfidence,
    evidence: &str,
) -> RecoveredDataObject {
    RecoveredDataObject {
        id: format!("data:{address:016x}:{kind:?}"),
        address,
        end_exclusive: end,
        kind,
        name,
        extent_confidence: confidence,
        evidence: vec![evidence.into()],
    }
}

fn collect_data_objects(inputs: SemanticRecoveryInputs<'_>) -> Vec<RecoveredDataObject> {
    let mut result = Vec::new();
    collect_section_objects(inputs.image_layout, &mut result);
    for string in inputs.strings.strings() {
        let end = string.address.checked_add(string.value.len() as u64 + 1);
        result.push(object(
            string.address,
            end,
            DataObjectKind::String,
            None,
            DataExtentConfidence::Exact,
            "typed_string_region",
        ));
        if let Some(address) = string.object_address {
            result.push(object(
                address,
                address.checked_add(32),
                DataObjectKind::ConstantStringObject,
                None,
                DataExtentConfidence::Exact,
                "cfstring_record",
            ));
        }
    }
    for pointer in inputs.pointers.pointers() {
        result.push(object(
            pointer.address,
            pointer.address.checked_add(8),
            DataObjectKind::PointerSlot,
            None,
            DataExtentConfidence::Exact,
            "format_pointer",
        ));
    }
    for symbol in inputs.symbols.symbols() {
        if let (
            Some(address),
            RecoveredSymbolKind::Nlist {
                symbol_type: NlistSymbolKind::Section,
                ..
            },
        ) = (symbol.address, &symbol.kind)
            && inputs.functions.by_entry(address).is_none()
        {
            result.push(object(
                address,
                None,
                DataObjectKind::NamedGlobal,
                Some(symbol.name.clone()),
                DataExtentConfidence::Unknown,
                "section_symbol",
            ));
        }
    }
    bound_named_globals(inputs.image_layout, &mut result);
    for entity in inputs.objc.entities() {
        result.push(object(
            entity.address,
            None,
            DataObjectKind::ObjectiveCMetadata,
            Some(entity.name.clone()),
            DataExtentConfidence::Unknown,
            "objc_runtime_record",
        ));
    }
    for record in inputs.swift.records() {
        result.push(object(
            record.descriptor_va,
            None,
            DataObjectKind::SwiftMetadata,
            Some(record.qualified_name.clone()),
            DataExtentConfidence::Unknown,
            "swift_nominal_descriptor",
        ));
        for field in &record.fields {
            result.push(object(
                field.record_va,
                field.record_va.checked_add(u64::from(field.record_size)),
                DataObjectKind::SwiftMetadata,
                field.name.clone(),
                DataExtentConfidence::Exact,
                "swift_field_record",
            ));
        }
    }
    for record in inputs.rtti.structural_type_info() {
        result.push(object(
            record.address,
            None,
            DataObjectKind::CppTypeInfo,
            Some(record.type_name.clone()),
            DataExtentConfidence::Derived,
            "itanium_typeinfo",
        ));
    }
    for record in inputs.rtti.structural_vtables() {
        result.push(object(
            record.start,
            Some(record.end_exclusive),
            DataObjectKind::CppVtable,
            None,
            match record.extent_confidence {
                crate::analysis::rtti::StructuralVtableExtentConfidence::Derived => {
                    DataExtentConfidence::Derived
                }
                crate::analysis::rtti::StructuralVtableExtentConfidence::Candidate => {
                    DataExtentConfidence::Candidate
                }
            },
            "itanium_vtable",
        ));
    }
    for record in inputs.rtti.structural_vtts() {
        result.push(object(
            record.start,
            Some(record.end_exclusive),
            DataObjectKind::CppVtt,
            None,
            DataExtentConfidence::Derived,
            "itanium_vtt",
        ));
    }
    result
}

fn collect_section_objects(layout: &ImageLayoutIndex, result: &mut Vec<RecoveredDataObject>) {
    for section in layout.sections() {
        let (kind, width, evidence) = match section.section_type.as_str() {
            "S_4BYTE_LITERALS" => (DataObjectKind::Literal, 4_u64, "literal_section"),
            "S_8BYTE_LITERALS" => (DataObjectKind::Literal, 8_u64, "literal_section"),
            "S_16BYTE_LITERALS" => (DataObjectKind::Literal, 16_u64, "literal_section"),
            "S_LITERAL_POINTERS"
            | "S_NON_LAZY_SYMBOL_POINTERS"
            | "S_LAZY_SYMBOL_POINTERS"
            | "S_LAZY_DYLIB_SYMBOL_POINTERS"
            | "S_MOD_INIT_FUNC_POINTERS"
            | "S_MOD_TERM_FUNC_POINTERS" => (
                DataObjectKind::PointerArrayElement,
                8_u64,
                "pointer_array_section",
            ),
            "S_THREAD_LOCAL_VARIABLES"
            | "S_THREAD_LOCAL_VARIABLE_POINTERS"
            | "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS" => {
                (DataObjectKind::ThreadLocal, 8_u64, "thread_local_section")
            }
            "S_THREAD_LOCAL_REGULAR" | "S_THREAD_LOCAL_ZEROFILL" => {
                if section.size != 0 {
                    result.push(object(
                        section.address,
                        section.address.checked_add(section.size),
                        DataObjectKind::ThreadLocal,
                        Some(format!("{},{}", section.segment, section.name)),
                        DataExtentConfidence::Exact,
                        "thread_local_storage_section",
                    ));
                }
                continue;
            }
            _ => continue,
        };
        let mut offset = 0_u64;
        while offset < section.size {
            let address = section.address.saturating_add(offset);
            let remaining = section.size - offset;
            let retained_width = remaining.min(width);
            result.push(object(
                address,
                address.checked_add(retained_width),
                kind,
                None,
                if retained_width == width {
                    DataExtentConfidence::Exact
                } else {
                    DataExtentConfidence::Candidate
                },
                evidence,
            ));
            offset = offset.saturating_add(retained_width);
        }
    }
}

fn bound_named_globals(layout: &ImageLayoutIndex, objects: &mut [RecoveredDataObject]) {
    let starts = objects
        .iter()
        .filter(|object| object.kind == DataObjectKind::NamedGlobal)
        .map(|object| object.address)
        .collect::<BTreeSet<_>>();
    for object in objects
        .iter_mut()
        .filter(|object| object.kind == DataObjectKind::NamedGlobal)
    {
        let Some(section) = layout.section_containing(object.address) else {
            continue;
        };
        let section_end = section.address.saturating_add(section.size);
        let next = starts
            .range(object.address.saturating_add(1)..section_end)
            .next()
            .copied()
            .unwrap_or(section_end);
        if next > object.address {
            object.end_exclusive = Some(next);
            object.extent_confidence = DataExtentConfidence::Candidate;
            object
                .evidence
                .push("next_global_or_section_boundary".into());
        }
    }
}

fn collect_signatures(inputs: SemanticRecoveryInputs<'_>) -> Vec<RecoveredFunctionSignature> {
    let mut records = inputs
        .functions
        .functions()
        .iter()
        .map(|function| {
            (
                function.entry,
                RecoveredFunctionSignature {
                    function_entry: function.entry,
                    display: None,
                    return_type: None,
                    arguments: Vec::new(),
                    variadic: None,
                    hidden_parameters: Vec::new(),
                    evidence: Vec::new(),
                    reasons: vec!["signature.type_unresolved".into()],
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    for method in inputs.objc.methods() {
        if let Some(record) = records.get_mut(&method.implementation) {
            record.display = Some(format!(
                "{}[{} {}] {}",
                if method.class_method { "+" } else { "-" },
                method.class_name,
                method.selector,
                method.type_encoding
            ));
            record.arguments = vec!["self".into(), "_cmd".into()];
            record.hidden_parameters = record.arguments.clone();
            record
                .evidence
                .push(SignatureEvidenceSource::ObjectiveCEncoding);
            record
                .reasons
                .retain(|reason| reason != "signature.type_unresolved");
        }
    }
    for symbol in inputs.symbols.symbols() {
        let Some(address) = symbol.address else {
            continue;
        };
        let Some(record) = records.get_mut(&address) else {
            continue;
        };
        if record.display.is_none() {
            record.display = Some(symbol.name.clone());
        }
        record.evidence.push(
            if symbol.name.starts_with("__Z") || symbol.name.starts_with("_Z") {
                SignatureEvidenceSource::CppMangledName
            } else if symbol.name.starts_with("_$s") {
                SignatureEvidenceSource::SwiftMetadata
            } else {
                SignatureEvidenceSource::SymbolRole
            },
        );
    }
    if let Some(traversal) = inputs.dwarf.traversal() {
        let attrs = attributes_by_entry(traversal);
        for entry in traversal
            .entries
            .iter()
            .filter(|entry| entry.tag == gimli::DW_TAG_subprogram.0)
        {
            let Some(address) = attr_unsigned(
                attrs.get(&(entry.unit_ordinal, entry.offset)),
                gimli::DW_AT_low_pc.0,
            ) else {
                continue;
            };
            let Some(record) = records.get_mut(&address) else {
                continue;
            };
            if let Some(name) = attr_text(
                attrs.get(&(entry.unit_ordinal, entry.offset)),
                gimli::DW_AT_name.0,
            ) {
                record.display = Some(name);
            }
            record.evidence.push(SignatureEvidenceSource::Dwarf);
        }
    }
    for record in records.values_mut() {
        record.evidence.sort();
        record.evidence.dedup();
    }
    records.into_values().collect()
}

fn collect_frames(inputs: SemanticRecoveryInputs<'_>) -> Vec<RecoveredStackFrame> {
    let mut grouped = BTreeMap::<u64, Vec<_>>::new();
    for row in inputs.exceptions.cfi_rows() {
        grouped.entry(row.function_entry).or_default().push(row);
    }
    grouped
        .into_iter()
        .map(|(function_entry, rows)| {
            let mut cfa_extent = None::<u64>;
            let mut saved = BTreeSet::new();
            let mut complete = true;
            for row in rows {
                match row.cfa {
                    ExceptionCfaRule::RegisterAndOffset { offset, .. } if offset >= 0 => {
                        cfa_extent = Some(cfa_extent.unwrap_or(0).max(offset as u64))
                    }
                    ExceptionCfaRule::RegisterAndOffset { .. } | ExceptionCfaRule::Expression => {
                        complete = false
                    }
                }
                for register in &row.registers {
                    if let ExceptionRegisterRule::Offset { offset } = register.rule {
                        saved.insert((register.register, offset));
                    }
                }
            }
            RecoveredStackFrame {
                function_entry,
                cfa_extent,
                saved_registers: saved.into_iter().collect(),
                complete,
                reasons: (!complete)
                    .then_some("frame.cfi_expression_or_negative_cfa".into())
                    .into_iter()
                    .collect(),
            }
        })
        .collect()
}

type AttrMap<'a> = BTreeMap<(u64, u64), Vec<&'a crate::metadata::dwarf::DwarfAttributeRecord>>;
fn attributes_by_entry(traversal: &crate::metadata::dwarf::DwarfTraversal) -> AttrMap<'_> {
    let mut result = BTreeMap::new();
    for attr in &traversal.attributes {
        result
            .entry((attr.unit_ordinal, attr.entry_offset))
            .or_insert_with(Vec::new)
            .push(attr);
    }
    result
}
fn attr_unsigned(
    attrs: Option<&Vec<&crate::metadata::dwarf::DwarfAttributeRecord>>,
    name: u16,
) -> Option<u64> {
    attrs?
        .iter()
        .find(|attr| attr.name == name)
        .and_then(|attr| attr.unsigned)
}
fn attr_text(
    attrs: Option<&Vec<&crate::metadata::dwarf::DwarfAttributeRecord>>,
    name: u16,
) -> Option<String> {
    attrs?
        .iter()
        .find(|attr| attr.name == name)
        .and_then(|attr| attr.text.as_ref())
        .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
}

fn collect_locals(dwarf: &DwarfIndex) -> Vec<RecoveredLocalVariable> {
    let Some(traversal) = dwarf.traversal() else {
        return Vec::new();
    };
    let attrs = attributes_by_entry(traversal);
    let entries = traversal
        .entries
        .iter()
        .map(|entry| ((entry.unit_ordinal, entry.offset), entry))
        .collect::<BTreeMap<_, _>>();
    let mut result = Vec::new();
    for entry in traversal.entries.iter().filter(|entry| {
        entry.tag == gimli::DW_TAG_variable.0 || entry.tag == gimli::DW_TAG_formal_parameter.0
    }) {
        let own_attrs = attrs.get(&(entry.unit_ordinal, entry.offset));
        let mut parent = entry.parent_offset;
        let mut function_entry = None;
        while let Some(offset) = parent {
            let Some(owner) = entries.get(&(entry.unit_ordinal, offset)) else {
                break;
            };
            if owner.tag == gimli::DW_TAG_subprogram.0 {
                function_entry = attr_unsigned(
                    attrs.get(&(owner.unit_ordinal, owner.offset)),
                    gimli::DW_AT_low_pc.0,
                );
                break;
            }
            parent = owner.parent_offset;
        }
        let location = own_attrs
            .and_then(|items| {
                items
                    .iter()
                    .find(|attr| attr.name == gimli::DW_AT_location.0)
            })
            .and_then(|attr| attr.block.clone());
        result.push(RecoveredLocalVariable {
            function_entry,
            die_offset: entry.debug_info_offset,
            parameter: entry.tag == gimli::DW_TAG_formal_parameter.0,
            name: attr_text(own_attrs, gimli::DW_AT_name.0),
            type_reference: own_attrs
                .and_then(|items| items.iter().find(|attr| attr.name == gimli::DW_AT_type.0))
                .and_then(|attr| attr.debug_info_reference.or(attr.unit_reference)),
            location_complete: location.is_some(),
            location_expression: location,
        });
    }
    result
}

fn source_reasons(inputs: SemanticRecoveryInputs<'_>) -> BTreeSet<String> {
    let mut reasons = BTreeSet::new();
    if inputs.symbols.status() != SymbolInventoryStatus::Complete {
        reasons.insert("semantics.symbols_incomplete".into());
    }
    if inputs.strings.status() != StringIndexStatus::Complete {
        reasons.insert("semantics.strings_incomplete".into());
    }
    if inputs.objc.status() == ObjcIndexStatus::Partial
        || inputs.objc.status() == ObjcIndexStatus::Truncated
    {
        reasons.insert("semantics.objc_incomplete".into());
    }
    if inputs.swift.status() == SwiftIndexStatus::Partial
        || inputs.swift.status() == SwiftIndexStatus::Truncated
    {
        reasons.insert("semantics.swift_incomplete".into());
    }
    if inputs.rtti.status() != RttiIndexStatus::Complete {
        reasons.insert("semantics.rtti_incomplete".into());
    }
    if inputs.dwarf.status() == DwarfIndexStatus::Partial
        || inputs.dwarf.status() == DwarfIndexStatus::Truncated
    {
        reasons.insert("semantics.dwarf_incomplete".into());
    }
    if inputs.exceptions.status() == ExceptionIndexStatus::Partial
        || inputs.exceptions.status() == ExceptionIndexStatus::Truncated
    {
        reasons.insert("semantics.exceptions_incomplete".into());
    }
    reasons
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semantic_limits_reject_zero() {
        assert_eq!(
            SemanticRecoveryLimits {
                max_data_objects: 0,
                ..SemanticRecoveryLimits::default()
            }
            .validate(),
            Err(SemanticRecoveryError::InvalidLimits)
        );
    }
}
