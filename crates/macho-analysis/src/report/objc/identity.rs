use std::collections::BTreeMap;

use macho_core::{MachoFile, Section};
use macho_objc::{ObjCMetadataScan, ObjCRecordKind};

use super::super::*;
use super::types::*;

pub(super) fn record_entity_ids(
    scan: &ObjCMetadataScan,
    class_counts: &BTreeMap<String, usize>,
    category_counts: &BTreeMap<(String, String), usize>,
    protocol_counts: &BTreeMap<String, usize>,
) -> Vec<Option<ObjCEntityId>> {
    let mut class_index = 0usize;
    let mut category_index = 0usize;
    let mut protocol_index = 0usize;
    scan.observations
        .iter()
        .map(|record| {
            record.parsed_name.as_ref()?;
            Some(match record.kind {
                ObjCRecordKind::Class => {
                    let value = &scan.metadata.classes[class_index];
                    let id = occurrence_entity_id(
                        "class",
                        &value.name,
                        class_counts[&value.name],
                        record.runtime_address,
                        record.ordinal,
                    );
                    class_index += 1;
                    id
                }
                ObjCRecordKind::Category => {
                    let value = &scan.metadata.categories[category_index];
                    let id = category_id(value, category_index, category_counts, scan);
                    category_index += 1;
                    id
                }
                ObjCRecordKind::Protocol => {
                    let value = &scan.metadata.protocols[protocol_index];
                    let id = occurrence_entity_id(
                        "protocol",
                        &value.name,
                        protocol_counts[&value.name],
                        record.runtime_address,
                        record.ordinal,
                    );
                    protocol_index += 1;
                    id
                }
            })
        })
        .collect()
}

pub(super) fn name_counts<'a>(values: impl Iterator<Item = &'a str>) -> BTreeMap<String, usize> {
    let mut counts = BTreeMap::new();
    for value in values {
        *counts.entry(value.to_owned()).or_default() += 1;
    }
    counts
}

fn occurrence_entity_id(
    kind: &str,
    name: &str,
    count: usize,
    runtime_address: Option<u64>,
    ordinal: usize,
) -> ObjCEntityId {
    if count == 1 {
        entity_id(&format!("{kind}|{name}"))
    } else {
        entity_id(&format!(
            "{kind}|{name}|{}",
            runtime_address.unwrap_or(ordinal as u64)
        ))
    }
}

pub(super) fn record_ids_for(
    scan: &ObjCMetadataScan,
    ids: &[Option<ObjCEntityId>],
    kind: ObjCRecordKind,
) -> Vec<ObjCEntityId> {
    scan.observations
        .iter()
        .zip(ids)
        .filter(|(record, _)| record.kind == kind && record.parsed_name.is_some())
        .map(|(_, id)| id.clone().expect("parsed runtime record has an entity ID"))
        .collect()
}

pub(super) fn unique_defined_ids<'a>(
    names: impl Iterator<Item = &'a str>,
    ids: &[ObjCEntityId],
    counts: &BTreeMap<String, usize>,
) -> BTreeMap<String, ObjCEntityId> {
    names
        .zip(ids)
        .filter(|(name, _)| counts[*name] == 1)
        .map(|(name, id)| (name.to_owned(), id.clone()))
        .collect()
}

pub(super) fn category_counts(scan: &ObjCMetadataScan) -> BTreeMap<(String, String), usize> {
    let mut counts = BTreeMap::new();
    for value in &scan.metadata.categories {
        *counts
            .entry((value.class_name.clone(), value.name.clone()))
            .or_default() += 1;
    }
    counts
}

pub(super) fn category_id(
    value: &macho_objc::ObjCCategory,
    ordinal: usize,
    counts: &BTreeMap<(String, String), usize>,
    scan: &ObjCMetadataScan,
) -> ObjCEntityId {
    let key = (value.class_name.clone(), value.name.clone());
    let occurrence = if counts[&key] == 1 {
        String::new()
    } else {
        format!(
            "|{}",
            scan.observations
                .iter()
                .filter(|record| {
                    record.kind == ObjCRecordKind::Category && record.parsed_name.is_some()
                })
                .nth(ordinal)
                .and_then(|record| record.runtime_address)
                .unwrap_or(ordinal as u64)
        )
    };
    entity_id(&format!(
        "category|{}|{}{}",
        value.class_name, value.name, occurrence
    ))
}

pub(super) fn record_location(
    macho: &MachoFile<'_>,
    sections: &[&Section],
    record: &macho_objc::ObjCRecordObservation,
) -> ObjCMetadataLocation {
    let address = record.runtime_address.unwrap_or(0);
    ObjCMetadataLocation {
        virtual_address: address,
        file_offset: record.runtime_address.and_then(|value| {
            macho
                .address_map()
                .va_to_thin_offset(macho_core::model::addr::Va(value))
                .ok()
                .map(|offset| offset.0)
        }),
        section: record
            .runtime_address
            .and_then(|value| section_at(value, sections))
            .map(|(ordinal, section)| section_identity(ordinal, section)),
    }
}

fn section_at<'a>(address: u64, sections: &'a [&Section]) -> Option<(usize, &'a Section)> {
    sections.iter().enumerate().find_map(|(index, section)| {
        let end = section.addr().0.checked_add(section.size())?;
        (address >= section.addr().0 && address < end).then_some((index + 1, *section))
    })
}

fn section_identity(ordinal: usize, section: &Section) -> SectionIdentity {
    SectionIdentity {
        segment: MachName::new(section.segment_name().as_str_lossy().into_owned()).unwrap(),
        section: MachName::new(section.section_name().as_str_lossy().into_owned()).unwrap(),
        ordinal: ordinal as u32,
    }
}

pub(super) fn observation_source(kind: ObjCRecordKind) -> ObjCObservationSource {
    match kind {
        ObjCRecordKind::Class => ObjCObservationSource::ClassList,
        ObjCRecordKind::Category => ObjCObservationSource::CategoryList,
        ObjCRecordKind::Protocol => ObjCObservationSource::ProtocolList,
    }
}

pub(super) fn evidence_kind(kind: ObjCRecordKind) -> ObjCEvidenceKind {
    match kind {
        ObjCRecordKind::Class => ObjCEvidenceKind::ClassRo,
        ObjCRecordKind::Category => ObjCEvidenceKind::Category,
        ObjCRecordKind::Protocol => ObjCEvidenceKind::Protocol,
    }
}

pub(super) fn entity_id(seed: &str) -> ObjCEntityId {
    ObjCEntityId::new(sha256_hex(seed.as_bytes())).unwrap()
}

pub(super) fn observation_id(seed: &str) -> ObjCObservationId {
    ObjCObservationId::new(sha256_hex(seed.as_bytes())).unwrap()
}

pub(super) fn evidence_id(seed: &str) -> ObjCEvidenceId {
    ObjCEvidenceId::new(sha256_hex(seed.as_bytes())).unwrap()
}

pub(super) fn diagnostic_id(seed: &str) -> ObjCDiagnosticId {
    ObjCDiagnosticId::new(sha256_hex(seed.as_bytes())).unwrap()
}

pub(super) fn partition_counts(
    entities: &[ObjCEntity],
    malformed_observations: u64,
) -> ObjCPartitionCounts {
    ObjCPartitionCounts {
        defined_entities: entities
            .iter()
            .filter(|value| value.common().presence == ObjCPresence::Defined)
            .count() as u64,
        referenced_entities: entities
            .iter()
            .filter(|value| value.common().presence == ObjCPresence::Referenced)
            .count() as u64,
        partial_entities: entities
            .iter()
            .filter(|value| value.common().presence == ObjCPresence::Partial)
            .count() as u64,
        malformed_observations,
        excluded_observations: 0,
    }
}
