//! Strict, lossless Objective-C runtime metadata collection.

use std::collections::BTreeSet;

use crate::format::io::pod::{self, RawClassRoT64, RawProtocolT64};
use crate::model::addr::{ThinFileOffset, Va};
use crate::model::macho_file::MachoFile;
use crate::resolve::ObjCResolver;
use crate::{
    Error, ObjCMetadata, ObjCMethodRecord, ObjCMethodRecordEncoding, ObjCPointerProvenance,
    ObjCRecordKind, ObjCRecordObservation, ObjCRelativeSelectorEncoding, Result,
    fold_method_records, scan_objc_metadata,
};

/// Resource limits for strict Objective-C collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictObjCLimits {
    /// Maximum runtime-list observations.
    pub max_observations: usize,
    /// Maximum decoded class, category, and protocol entities.
    pub max_entities: usize,
    /// Maximum retained method records.
    pub max_methods: usize,
    /// Maximum entries in any nested protocol list or superclass walk.
    pub max_nested_records: usize,
}

/// Stable reason that strict decoding could not claim completeness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictObjCGap {
    /// Stable machine-oriented reason code.
    pub code: &'static str,
    /// Human-readable bounded detail.
    pub detail: String,
}

/// Conservation accounting for one strict decode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StrictObjCConservation {
    /// Source records considered.
    pub attempted: u64,
    /// Records retained in a complete batch.
    pub included: u64,
    /// Records whose meaning could not be established.
    pub unknown: u64,
    /// Records deliberately excluded by the contract.
    pub excluded: u64,
}

/// Complete Objective-C metadata and its conserved source records.
#[derive(Debug)]
pub struct StrictObjCBatch {
    /// Successfully decoded class, category, and protocol metadata.
    pub metadata: ObjCMetadata,
    /// Every admitted runtime-list observation.
    pub observations: Vec<ObjCRecordObservation>,
    /// Every strict method record with exact encoding and storage provenance.
    pub method_records: Vec<ObjCMethodRecord>,
    /// Lossless record accounting.
    pub conservation: StrictObjCConservation,
}

/// Rejected strict decode. No partial semantic metadata is exposed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictObjCRejection {
    /// Lossless record accounting at the point of rejection.
    pub conservation: StrictObjCConservation,
    /// Canonically ordered reasons for rejection.
    pub gaps: Vec<StrictObjCGap>,
}

/// Strict decode state for one selected image.
#[derive(Debug)]
pub enum StrictObjCOutcome {
    /// No Objective-C runtime-list surface exists.
    Absent,
    /// All admitted source records were decoded and conserved.
    Complete(StrictObjCBatch),
    /// Objective-C data exists but completeness could not be established.
    Rejected(StrictObjCRejection),
}

/// Exact referenced Objective-C runtime record and its source pointer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictObjCRecordReference {
    /// Thin-file offset of the source pointer.
    pub pointer_file_offset: ThinFileOffset,
    /// On-disk pointer provenance.
    pub pointer_provenance: ObjCPointerProvenance,
    /// Resolved runtime address.
    pub runtime_address: Va,
    /// Thin-file offset of the referenced record.
    pub record_file_offset: ThinFileOffset,
    /// Exact bounded record bytes.
    pub raw: Vec<u8>,
}

/// Exact storage coordinates for one Objective-C selector observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrictObjCSelectorStorage {
    /// Thin-file offset of the selector field in the method record.
    pub selector_field_file_offset: ThinFileOffset,
    /// Encoded selector-field width.
    pub selector_field_size: u64,
    /// Thin-file offset of the pointer that reaches the cstring.
    pub selector_pointer_file_offset: ThinFileOffset,
    /// Thin-file offset of the selector cstring.
    pub selector_string_file_offset: ThinFileOffset,
    /// Method-record selector provenance.
    pub record_provenance: ObjCPointerProvenance,
    /// Selector-reference pointer provenance.
    pub string_provenance: ObjCPointerProvenance,
}

/// Resolve the metaclass record referenced by one class record.
pub fn class_metaclass_reference(
    macho: &MachoFile<'_>,
    class_va: Va,
) -> Result<StrictObjCRecordReference> {
    let resolver = ObjCResolver::new(macho)?;
    let class_offset = resolver.va_to_offset(class_va)?;
    let runtime_address = required_pointer(&resolver, class_offset.0)?;
    let record_file_offset = resolver.va_to_offset(runtime_address)?;
    let raw = macho
        .read_bytes_at(record_file_offset, 40)
        .map(ToOwned::to_owned)?;
    Ok(StrictObjCRecordReference {
        pointer_file_offset: class_offset,
        pointer_provenance: resolver.pointer_provenance_at_offset(class_offset.0),
        runtime_address,
        record_file_offset,
        raw,
    })
}

/// Resolve the in-image class target referenced by one category record.
pub fn category_class_target(macho: &MachoFile<'_>, category_va: Va) -> Result<Option<Va>> {
    let resolver = ObjCResolver::new(macho)?;
    let category_offset = resolver.va_to_offset(category_va)?;
    resolver.read_pointer_at_offset(checked_offset(
        category_offset.0,
        8,
        "category class pointer",
    )?)
}

/// Resolve exact selector storage for one already-decoded method record.
pub fn method_selector_storage(
    macho: &MachoFile<'_>,
    method: &ObjCMethodRecord,
) -> Result<StrictObjCSelectorStorage> {
    let resolver = ObjCResolver::new(macho)?;
    let record_offset = method.provenance.record_file_offset;
    match &method.provenance.encoding {
        ObjCMethodRecordEncoding::Absolute {
            selector_pointer, ..
        } => {
            let selector_va = required_pointer(&resolver, record_offset.0)?;
            let selector_string_file_offset = resolver.va_to_offset(selector_va)?;
            Ok(StrictObjCSelectorStorage {
                selector_field_file_offset: record_offset,
                selector_field_size: 8,
                selector_pointer_file_offset: record_offset,
                selector_string_file_offset,
                record_provenance: selector_pointer.clone(),
                string_provenance: selector_pointer.clone(),
            })
        }
        ObjCMethodRecordEncoding::Relative { selector, .. } => match selector {
            ObjCRelativeSelectorEncoding::DirectString {
                selector_string_file_offset,
            } => Ok(StrictObjCSelectorStorage {
                selector_field_file_offset: record_offset,
                selector_field_size: 4,
                selector_pointer_file_offset: record_offset,
                selector_string_file_offset: *selector_string_file_offset,
                record_provenance: ObjCPointerProvenance::Direct,
                string_provenance: ObjCPointerProvenance::Direct,
            }),
            ObjCRelativeSelectorEncoding::IndirectReference {
                selector_reference_file_offset,
                selector_reference_pointer,
            } => {
                let selector_va = required_pointer(&resolver, selector_reference_file_offset.0)?;
                let selector_string_file_offset = resolver.va_to_offset(selector_va)?;
                Ok(StrictObjCSelectorStorage {
                    selector_field_file_offset: record_offset,
                    selector_field_size: 4,
                    selector_pointer_file_offset: *selector_reference_file_offset,
                    selector_string_file_offset,
                    record_provenance: ObjCPointerProvenance::Direct,
                    string_provenance: selector_reference_pointer.clone(),
                })
            }
        },
    }
}

/// Collect strict Objective-C metadata from one selected thin image.
///
/// Invalid caller limits return `Err`. Damaged or unsupported image content is
/// represented as [`StrictObjCOutcome::Rejected`] so consumers cannot confuse a
/// parser failure with absence or accidentally consume partial semantic data.
pub fn decode_strict_objc(
    macho: &MachoFile<'_>,
    limits: StrictObjCLimits,
) -> Result<StrictObjCOutcome> {
    if limits.max_observations == 0
        || limits.max_entities == 0
        || limits.max_methods == 0
        || limits.max_nested_records == 0
    {
        return Err(Error::unsupported(
            "strict Objective-C limits must all be nonzero",
        ));
    }
    let has_surface = macho.all_sections().any(|section| {
        matches!(
            section.section_name().trimmed_bytes(),
            b"__objc_classlist" | b"__objc_catlist" | b"__objc_protolist"
        )
    });
    if !has_surface {
        return Ok(StrictObjCOutcome::Absent);
    }
    let scan = match scan_objc_metadata(macho) {
        Ok(scan) => scan,
        Err(error) => {
            return Ok(rejected(1, "objc_metadata_malformed", error.to_string()));
        }
    };
    let attempted_observations = u64::try_from(scan.observations.len()).unwrap_or(u64::MAX);
    if scan.observations.len() > limits.max_observations {
        return Ok(rejected(
            attempted_observations,
            "objc_observation_limit_exceeded",
            format!(
                "{} Objective-C observations exceed limit {}",
                scan.observations.len(),
                limits.max_observations
            ),
        ));
    }
    if let Some(observation) = scan.observations.iter().find(|observation| {
        observation.runtime_address.is_none()
            || observation.parsed_name.is_none()
            || observation.error.is_some()
    }) {
        return Ok(rejected(
            attempted_observations,
            "objc_observation_incomplete",
            format!(
                "{:?} observation {} is incomplete: {}",
                observation.kind,
                observation.ordinal,
                observation
                    .error
                    .as_deref()
                    .unwrap_or("missing decoded identity")
            ),
        ));
    }
    let resolver = match ObjCResolver::new(macho) {
        Ok(resolver) => resolver,
        Err(error) => {
            return Ok(rejected(
                attempted_observations,
                "objc_pointer_evidence_rejected",
                error.to_string(),
            ));
        }
    };
    if let Err(error) =
        validate_nested_sources(&resolver, &scan.observations, limits.max_nested_records)
    {
        return Ok(rejected(
            attempted_observations,
            "objc_nested_metadata_rejected",
            error.to_string(),
        ));
    }
    if let Err(error) =
        validate_superclass_chains(&resolver, &scan.observations, limits.max_nested_records)
    {
        return Ok(rejected(
            attempted_observations,
            "objc_superclass_graph_rejected",
            error.to_string(),
        ));
    }
    let entity_count = scan
        .metadata
        .classes
        .len()
        .checked_add(scan.metadata.categories.len())
        .and_then(|count| count.checked_add(scan.metadata.protocols.len()));
    let Some(entity_count) = entity_count else {
        return Ok(rejected(
            attempted_observations,
            "objc_entity_count_overflow",
            "Objective-C entity count exceeds host limits",
        ));
    };
    if entity_count > limits.max_entities {
        return Ok(rejected(
            attempted_observations,
            "objc_entity_limit_exceeded",
            format!(
                "{entity_count} Objective-C entities exceed limit {}",
                limits.max_entities
            ),
        ));
    }
    let method_records = match fold_method_records(macho, Vec::new(), |records, record| {
        if records.len() == limits.max_methods {
            return Err(Error::unsupported(
                "strict Objective-C method limit exceeded",
            ));
        }
        records.push(record);
        Ok(())
    }) {
        Ok(records) => records,
        Err(error) => {
            return Ok(rejected(
                attempted_observations,
                "objc_method_decode_rejected",
                error.to_string(),
            ));
        }
    };
    let attempted = scan
        .observations
        .len()
        .checked_add(method_records.len())
        .and_then(|value| u64::try_from(value).ok())
        .unwrap_or(u64::MAX);
    Ok(StrictObjCOutcome::Complete(StrictObjCBatch {
        metadata: scan.metadata,
        observations: scan.observations,
        method_records,
        conservation: StrictObjCConservation {
            attempted,
            included: attempted,
            unknown: 0,
            excluded: 0,
        },
    }))
}

fn rejected(attempted: u64, code: &'static str, detail: impl Into<String>) -> StrictObjCOutcome {
    StrictObjCOutcome::Rejected(StrictObjCRejection {
        conservation: StrictObjCConservation {
            attempted,
            included: 0,
            unknown: attempted,
            excluded: 0,
        },
        gaps: vec![StrictObjCGap {
            code,
            detail: detail.into(),
        }],
    })
}

fn validate_nested_sources(
    resolver: &ObjCResolver<'_>,
    observations: &[ObjCRecordObservation],
    nested_record_limit: usize,
) -> Result<()> {
    for observation in observations {
        let runtime_address = observation.runtime_address.ok_or_else(|| {
            Error::format(format!(
                "Objective-C {:?} observation {} has no runtime address",
                observation.kind, observation.ordinal
            ))
        })?;
        match observation.kind {
            ObjCRecordKind::Class => {
                validate_class_sources(resolver, runtime_address, nested_record_limit)?;
            }
            ObjCRecordKind::Category => {
                validate_category_sources(resolver, runtime_address, nested_record_limit)?;
            }
            ObjCRecordKind::Protocol => {
                validate_protocol_sources(resolver, runtime_address, nested_record_limit)?;
            }
        }
    }
    Ok(())
}

fn validate_class_sources(
    resolver: &ObjCResolver<'_>,
    runtime_address: u64,
    nested_record_limit: usize,
) -> Result<()> {
    let class_offset = resolver.va_to_offset(Va(runtime_address))?.0;
    let data = required_pointer(resolver, checked_offset(class_offset, 32, "class data")?)?;
    let ro_offset = resolver.va_to_offset(objc_class_ro_pointer(data))?.0;
    let _: RawClassRoT64 = pod::read_pod(resolver.macho().bytes(), ro_offset as usize)?;
    validate_optional_method_list(resolver, checked_offset(ro_offset, 32, "class methods")?)?;
    validate_optional_protocol_list(
        resolver,
        checked_offset(ro_offset, 40, "class protocols")?,
        nested_record_limit,
    )?;
    validate_optional_ivar_list(resolver, checked_offset(ro_offset, 48, "class ivars")?)?;
    validate_optional_property_list(
        resolver,
        checked_offset(ro_offset, 64, "class properties")?,
        false,
    )?;

    if let Some(meta) = resolver.read_pointer_at_offset(class_offset)?
        && meta.0 != 0
    {
        let meta_offset = resolver.va_to_offset(meta)?.0;
        let meta_data =
            required_pointer(resolver, checked_offset(meta_offset, 32, "metaclass data")?)?;
        let meta_ro_offset = resolver.va_to_offset(objc_class_ro_pointer(meta_data))?.0;
        let _: RawClassRoT64 = pod::read_pod(resolver.macho().bytes(), meta_ro_offset as usize)?;
        validate_optional_method_list(
            resolver,
            checked_offset(meta_ro_offset, 32, "metaclass methods")?,
        )?;
        validate_optional_property_list(
            resolver,
            checked_offset(meta_ro_offset, 64, "metaclass properties")?,
            true,
        )?;
    }
    Ok(())
}

fn validate_category_sources(
    resolver: &ObjCResolver<'_>,
    runtime_address: u64,
    nested_record_limit: usize,
) -> Result<()> {
    let offset = resolver.va_to_offset(Va(runtime_address))?.0;
    validate_optional_method_list(
        resolver,
        checked_offset(offset, 16, "category instance methods")?,
    )?;
    validate_optional_method_list(
        resolver,
        checked_offset(offset, 24, "category class methods")?,
    )?;
    validate_optional_protocol_list(
        resolver,
        checked_offset(offset, 32, "category protocols")?,
        nested_record_limit,
    )?;
    validate_optional_property_list(
        resolver,
        checked_offset(offset, 40, "category properties")?,
        false,
    )
}

fn validate_protocol_sources(
    resolver: &ObjCResolver<'_>,
    runtime_address: u64,
    nested_record_limit: usize,
) -> Result<()> {
    let offset = resolver.va_to_offset(Va(runtime_address))?.0;
    let raw: RawProtocolT64 = pod::read_pod(resolver.macho().bytes(), offset as usize)?;
    let protocol_size = resolver.endian().interpret_u32(raw.size) as usize;
    validate_optional_protocol_list(
        resolver,
        checked_offset(offset, 16, "adopted protocols")?,
        nested_record_limit,
    )?;
    for (delta, field) in [
        (24, "required instance methods"),
        (32, "required class methods"),
        (40, "optional instance methods"),
        (48, "optional class methods"),
    ] {
        validate_optional_method_list(resolver, checked_offset(offset, delta, field)?)?;
    }
    validate_optional_property_list(
        resolver,
        checked_offset(offset, 56, "protocol properties")?,
        false,
    )?;
    if protocol_size >= 96 {
        validate_optional_property_list(
            resolver,
            checked_offset(offset, 88, "protocol class properties")?,
            true,
        )?;
    }
    Ok(())
}

fn validate_optional_method_list(resolver: &ObjCResolver<'_>, pointer_offset: u64) -> Result<()> {
    if let Some(value) = resolver.read_pointer_at_offset(pointer_offset)?
        && value.0 != 0
    {
        crate::method::parse_method_list(resolver, value)?;
    }
    Ok(())
}

fn validate_optional_ivar_list(resolver: &ObjCResolver<'_>, pointer_offset: u64) -> Result<()> {
    if let Some(value) = resolver.read_pointer_at_offset(pointer_offset)?
        && value.0 != 0
    {
        crate::ivar::parse_ivar_list(resolver, value)?;
    }
    Ok(())
}

fn validate_optional_property_list(
    resolver: &ObjCResolver<'_>,
    pointer_offset: u64,
    is_class: bool,
) -> Result<()> {
    if let Some(value) = resolver.read_pointer_at_offset(pointer_offset)?
        && value.0 != 0
    {
        crate::property::parse_property_list_with_kind(resolver, value, is_class)?;
    }
    Ok(())
}

fn validate_optional_protocol_list(
    resolver: &ObjCResolver<'_>,
    pointer_offset: u64,
    nested_record_limit: usize,
) -> Result<()> {
    let Some(value) = resolver.read_pointer_at_offset(pointer_offset)? else {
        return Ok(());
    };
    if value.0 == 0 {
        return Ok(());
    }
    let offset = resolver.va_to_offset(value)?.0;
    let count = resolver.endian().interpret_u64(pod::read_pod::<u64>(
        resolver.macho().bytes(),
        offset as usize,
    )?) as usize;
    if count > nested_record_limit {
        return Err(Error::format(format!(
            "Objective-C protocol-list count {count} exceeds {nested_record_limit}"
        )));
    }
    let names = crate::protocol::parse_protocol_name_list(resolver, value)?;
    if names.len() != count {
        return Err(Error::format(format!(
            "Objective-C protocol list retained {} of {count} entries",
            names.len()
        )));
    }
    Ok(())
}

fn validate_superclass_chains(
    resolver: &ObjCResolver<'_>,
    observations: &[ObjCRecordObservation],
    entity_limit: usize,
) -> Result<()> {
    for observation in observations
        .iter()
        .filter(|observation| observation.kind == ObjCRecordKind::Class)
    {
        let Some(mut class_va) = observation.runtime_address else {
            continue;
        };
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert(class_va) {
                return Err(Error::format(format!(
                    "Objective-C superclass cycle reaches {class_va:#x}"
                )));
            }
            if visited.len() > entity_limit {
                return Err(Error::unsupported(format!(
                    "Objective-C superclass chain exceeds {entity_limit}"
                )));
            }
            let class_offset = resolver.va_to_offset(Va(class_va))?.0;
            let superclass_offset = checked_offset(class_offset, 8, "superclass field")?;
            let Some(superclass) = resolver
                .read_pointer_at_offset(superclass_offset)?
                .filter(|value| value.0 != 0)
            else {
                break;
            };
            class_va = superclass.0;
        }
    }
    Ok(())
}

const fn objc_class_ro_pointer(value: Va) -> Va {
    Va(value.0 & crate::types::CLASS_DATA_POINTER_MASK)
}

fn required_pointer(resolver: &ObjCResolver<'_>, pointer_offset: u64) -> Result<Va> {
    resolver
        .read_pointer_at_offset(pointer_offset)?
        .filter(|value| value.0 != 0)
        .ok_or_else(|| Error::format("required Objective-C pointer is absent"))
}

fn checked_offset(base: u64, delta: u64, field: &str) -> Result<u64> {
    base.checked_add(delta)
        .ok_or_else(|| Error::address(format!("{field} offset overflows")))
}
