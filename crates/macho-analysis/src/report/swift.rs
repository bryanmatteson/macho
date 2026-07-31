//! Canonical descriptor-first Swift recovery report.

#![allow(missing_docs)]

mod enrich;
mod header;
mod validate;

pub use header::project_swift_headers;

use macho_core::model::container::MachoContainer;
use macho_core::{MachoFile, Section};
use serde::{Deserialize, Serialize};

use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftEntityState {
    MetadataDefined,
    Referenced,
    SymbolOnly,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftTypeKind {
    Class,
    Struct,
    Enum,
    Protocol,
    TypeAlias,
    Opaque,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftCollectorId {
    MetadataDescriptors,
    ReflectionMetadata,
    SymbolDemangling,
    Reconciliation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftEvidenceKind {
    ContextDescriptor,
    FieldDescriptor,
    ProtocolDescriptor,
    ConformanceDescriptor,
    AssociatedTypeDescriptor,
    ReflectionString,
    DemangledSymbol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftObservationSource {
    TypeMetadata,
    Protocols,
    Conformances,
    Fields,
    AssociatedTypes,
    ReflectionStrings,
    Nlist,
    ExportTrie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftExclusionReason {
    NotSwift,
    UnselectedKind,
    DuplicateAlias,
    UnsupportedRecordKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftUnavailableReason {
    NotEncoded,
    MalformedDescriptor,
    UnsupportedDescriptor,
    UnsupportedMangling,
    UnresolvedReference,
    AmbiguousIdentity,
    CollectorFailed,
    Truncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftDiagnosticCode {
    MalformedDescriptor,
    UnsupportedDescriptor,
    MalformedMangling,
    UnsupportedMangling,
    UnresolvedReference,
    AmbiguousIdentity,
    ConflictingMetadata,
    CollectorFailed,
    CollectorTruncated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftFieldName {
    Kind,
    QualifiedName,
    Descriptor,
    Parent,
    FieldsOrCases,
    Conformances,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftCandidate<T> {
    pub value: T,
    pub evidence: NonEmpty<SwiftEvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[serde(bound(deserialize = "T: Deserialize<'de> + PartialEq"))]
pub enum SwiftValue<T> {
    Known {
        value: T,
        evidence: NonEmpty<SwiftEvidenceId>,
    },
    Conflicted {
        candidates: AtLeastTwo<SwiftCandidate<T>>,
    },
    Unavailable {
        reason: SwiftUnavailableReason,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftQualifiedName {
    pub module: Option<String>,
    pub path: NonEmpty<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftDescriptorLocation {
    pub virtual_address: u64,
    pub file_offset: Option<u64>,
    pub section: SectionIdentity,
    pub relative_offset: Option<i64>,
}

pub type SwiftMetadataLocation = SwiftDescriptorLocation;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftEntityRef {
    pub entity_id: Option<SwiftEntityId>,
    pub qualified_name: Option<SwiftQualifiedName>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftField {
    pub name: Option<String>,
    pub mangled_type: Option<HexBytes>,
    pub type_name: Option<String>,
    pub flags: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftConformanceRef {
    pub protocol: SwiftEntityRef,
    pub r#type: Option<SwiftEntityRef>,
    pub descriptor: Option<SwiftDescriptorLocation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftGap {
    pub id: SwiftGapId,
    pub field: SwiftFieldName,
    pub reason: SwiftUnavailableReason,
    pub evidence_ids: Vec<SwiftEvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftEvidence {
    pub id: SwiftEvidenceId,
    pub observation_ids: NonEmpty<SwiftObservationId>,
    pub kind: SwiftEvidenceKind,
    pub location: Option<SwiftMetadataLocation>,
    pub raw: HexBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SwiftObservationDisposition {
    Included { entity_ids: NonEmpty<SwiftEntityId> },
    Unknown { diagnostic_id: SwiftDiagnosticId },
    Excluded { reason: SwiftExclusionReason },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftObservation {
    pub id: SwiftObservationId,
    pub source: SwiftObservationSource,
    pub raw: HexBytes,
    pub location: Option<SwiftMetadataLocation>,
    pub disposition: SwiftObservationDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftEntity {
    pub id: SwiftEntityId,
    pub identity_stability: IdentityStability,
    pub state: SwiftEntityState,
    pub kind: SwiftValue<SwiftTypeKind>,
    pub qualified_name: SwiftValue<SwiftQualifiedName>,
    pub descriptor: SwiftValue<SwiftDescriptorLocation>,
    pub parent: SwiftValue<SwiftEntityRef>,
    pub fields_or_cases: SwiftValue<Vec<SwiftField>>,
    pub conformances: SwiftValue<Vec<SwiftConformanceRef>>,
    /// The resolved superclass name.
    ///
    /// `Unavailable { NotEncoded }` covers both a kind that carries no such
    /// field and a class whose superclass reference is null — a root class.
    /// Only a class descriptor encodes one.
    pub superclass: SwiftValue<String>,
    pub raw_linkages: Vec<String>,
    pub observation_ids: NonEmpty<SwiftObservationId>,
    pub gaps: Vec<SwiftGap>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftPartitionCounts {
    pub metadata_defined: u64,
    pub referenced: u64,
    pub symbol_only: u64,
    pub partial: u64,
    pub unknown: u64,
    pub excluded_observations: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftSelectionResult {
    pub selected_entity_ids: Vec<SwiftEntityId>,
    pub totals: SwiftPartitionCounts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SwiftCollectorOutcome {
    Complete,
    Unsupported { reason: UnsupportedReasonCode },
    Failed { diagnostic_id: SwiftDiagnosticId },
    Truncated { omitted_lower_bound: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftCollectorExecution {
    pub collector: SwiftCollectorId,
    pub outcome: SwiftCollectorOutcome,
    pub input_records: u64,
    pub output_records: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftDiagnostic {
    pub id: SwiftDiagnosticId,
    pub code: SwiftDiagnosticCode,
    pub severity: Severity,
    pub message: String,
    pub observation_id: Option<SwiftObservationId>,
    pub entity_id: Option<SwiftEntityId>,
    pub evidence_ids: Vec<SwiftEvidenceId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftSliceReport {
    pub architecture: Architecture,
    pub image: ImageIdentity,
    pub observations: Vec<SwiftObservation>,
    pub evidence: Vec<SwiftEvidence>,
    pub entities: Vec<SwiftEntity>,
    pub selection: SwiftSelectionResult,
    pub header: Option<SwiftHeaderProjection>,
    pub diagnostics: Vec<SwiftDiagnostic>,
    pub executions: NonEmpty<SwiftCollectorExecution>,
}

/// How a projected member binds its name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwiftDeclBinding {
    Var,
    Let,
    Case,
    IndirectCase,
}

/// One stored property or enum case in a projected declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftDeclMember {
    pub name: String,
    pub binding: SwiftDeclBinding,
    /// The resolved Swift type, or `None` when the report could not resolve one.
    pub type_name: Option<String>,
    pub artificial: bool,
}

/// One projected nominal declaration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftDecl {
    pub entity_id: SwiftEntityId,
    pub kind: SwiftTypeKind,
    pub state: SwiftEntityState,
    pub name: String,
    /// The superclass, when the class descriptor named one. Absent for a root
    /// class and for every non-class kind.
    pub superclass: Option<String>,
    pub conformances: Vec<String>,
    pub members: Vec<SwiftDeclMember>,
}

/// A declaration or member the projection could not state completely.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftHeaderGap {
    pub entity_id: SwiftEntityId,
    /// The member name, or `None` when the gap concerns the declaration itself.
    pub member: Option<String>,
    pub reason: SwiftUnavailableReason,
}

/// The Swift declaration projection for one slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftHeaderProjection {
    pub declarations: Vec<SwiftDecl>,
    pub unresolved: Vec<SwiftHeaderGap>,
    pub source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SwiftReport {
    pub schema_version: SwiftReportVersion,
    pub slices: NonEmpty<SwiftSliceReport>,
}

pub fn recover_swift_container(
    container: &MachoContainer<'_>,
    selected_architecture: Option<&str>,
) -> crate::Result<SwiftReport> {
    let container_kind = match container {
        MachoContainer::Thin(_) => ContainerKind::Thin,
        MachoContainer::Fat(_) => ContainerKind::Fat,
    };
    let mut slices = Vec::new();
    for (index, macho) in container.macho_files().enumerate() {
        if selected_architecture
            .is_some_and(|selected| !slice_matches_architecture(macho, selected))
        {
            continue;
        }
        let mut slice = recover_swift_surface(macho)?.slices.into_vec().remove(0);
        slice.image.container = container_kind;
        slice.image.slice_index = index as u32;
        slices.push(slice);
    }
    if slices.is_empty() {
        return Err(crate::AnalysisError::invalid(match selected_architecture {
            Some(arch) => format!("no architecture matching `{arch}` found"),
            None => "no selected Mach-O slices".to_owned(),
        }));
    }
    let report = SwiftReport {
        schema_version: SwiftReportVersion::CURRENT,
        slices: NonEmpty::new(slices).expect("checked non-empty Swift slices"),
    };
    report.validate()?;
    Ok(report)
}

pub fn recover_swift_surface(macho: &MachoFile<'_>) -> crate::Result<SwiftReport> {
    let architecture = Architecture {
        cpu_type: macho.header().cpu_type().0,
        cpu_subtype: macho.header().cpu_subtype().0,
    };
    let image = super::symbol_recovery::image_identity(macho, architecture)?;
    let mut index = macho.ext::<macho_swift::SwiftTypeIndex>()?;
    if let Ok(metadata) = macho.ext::<macho_objc::ObjCMetadata>() {
        let runtime_types = metadata
            .classes
            .iter()
            .filter(|class| class.is_swift)
            .map(|class| (class.name.clone(), macho_swift::types::SwiftTypeKind::Class))
            .chain(
                metadata
                    .protocols
                    .iter()
                    .filter(|protocol| protocol.name.starts_with("_TtP"))
                    .map(|protocol| {
                        (
                            protocol.name.clone(),
                            macho_swift::types::SwiftTypeKind::Protocol,
                        )
                    }),
            );
        index.enrich_objc_runtime_types(runtime_types, &macho_swift::PureSwiftDemangler)?;
    }
    let sections = macho.all_sections().collect::<Vec<_>>();
    let mut observations = Vec::new();
    let mut evidence = Vec::new();
    let mut entities = Vec::new();
    let mut diagnostics = Vec::new();
    let identity_counts = index.types.iter().fold(
        std::collections::BTreeMap::<String, usize>::new(),
        |mut counts, value| {
            *counts.entry(swift_identity_key(value)).or_default() += 1;
            counts
        },
    );

    for (ordinal, swift_type) in index.types.iter().enumerate() {
        let raw = swift_type
            .mangled_name
            .as_deref()
            .unwrap_or(&swift_type.name);
        let observation_id = SwiftObservationId::new(sha256_hex(
            format!(
                "swift-observation|{ordinal}|{}|{:?}",
                raw, swift_type.source
            )
            .as_bytes(),
        ))
        .expect("SHA-256 observation ID");
        let identity_key = swift_identity_key(swift_type);
        let unique = identity_counts.get(&identity_key) == Some(&1);
        let (entity_seed, identity_stability) = if unique {
            match swift_type.source {
                macho_swift::types::SwiftTypeSource::SwiftMetadata => (
                    format!("swift-descriptor|{:?}|{}", swift_type.kind, swift_type.name),
                    IdentityStability::CrossBuild,
                ),
                _ if swift_type.mangled_name.is_some() => (
                    format!(
                        "swift-linkage|{}",
                        swift_type.mangled_name.as_deref().unwrap_or_default()
                    ),
                    IdentityStability::CrossBuild,
                ),
                _ => (
                    format!("swift-runtime|{:?}|{}", swift_type.kind, swift_type.name),
                    IdentityStability::CrossBuild,
                ),
            }
        } else {
            (
                format!(
                    "swift-occurrence|{ordinal}|{:?}|{}|{:?}",
                    swift_type.source, swift_type.name, swift_type.address
                ),
                IdentityStability::SliceOnly,
            )
        };
        let entity_id =
            SwiftEntityId::new(sha256_hex(entity_seed.as_bytes())).expect("SHA-256 entity ID");
        let evidence_id = SwiftEvidenceId::new(sha256_hex(
            format!("swift-evidence|{observation_id}").as_bytes(),
        ))
        .expect("SHA-256 evidence ID");
        let section = swift_type
            .address
            .and_then(|address| section_at(address, &sections));
        let section_identity = section.map(|(ordinal, section)| section_identity(ordinal, section));
        let descriptor = match (
            swift_type.source,
            swift_type.address,
            section_identity.clone(),
        ) {
            (macho_swift::types::SwiftTypeSource::SwiftMetadata, Some(address), Some(section)) => {
                SwiftValue::Known {
                    value: SwiftDescriptorLocation {
                        virtual_address: address,
                        file_offset: macho
                            .address_map()
                            .va_to_thin_offset(macho_core::model::addr::Va(address))
                            .ok()
                            .map(|offset| offset.0),
                        section,
                        relative_offset: None,
                    },
                    evidence: NonEmpty::new(vec![evidence_id.clone()]).unwrap(),
                }
            }
            _ => SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
        };
        let state = swift_state(swift_type);
        let kind = map_kind(swift_type.kind);
        let qualified_name = qualified_name(&swift_type.name);
        let source = match swift_type.source {
            macho_swift::types::SwiftTypeSource::SwiftMetadata => {
                if kind == SwiftTypeKind::Protocol {
                    SwiftObservationSource::Protocols
                } else {
                    SwiftObservationSource::TypeMetadata
                }
            }
            macho_swift::types::SwiftTypeSource::DemangledSymbol => SwiftObservationSource::Nlist,
            macho_swift::types::SwiftTypeSource::ObjCMetadata => {
                SwiftObservationSource::TypeMetadata
            }
            _ => SwiftObservationSource::Nlist,
        };
        let evidence_kind = match swift_type.source {
            macho_swift::types::SwiftTypeSource::SwiftMetadata
                if kind == SwiftTypeKind::Protocol =>
            {
                SwiftEvidenceKind::ProtocolDescriptor
            }
            macho_swift::types::SwiftTypeSource::SwiftMetadata => {
                SwiftEvidenceKind::ContextDescriptor
            }
            macho_swift::types::SwiftTypeSource::DemangledSymbol => {
                SwiftEvidenceKind::DemangledSymbol
            }
            macho_swift::types::SwiftTypeSource::ObjCMetadata => {
                SwiftEvidenceKind::ContextDescriptor
            }
            _ => SwiftEvidenceKind::DemangledSymbol,
        };
        let observation_location = swift_type.address.and_then(|virtual_address| {
            section_identity
                .clone()
                .map(|section| SwiftDescriptorLocation {
                    virtual_address,
                    file_offset: macho
                        .address_map()
                        .va_to_thin_offset(macho_core::model::addr::Va(virtual_address))
                        .ok()
                        .map(|offset| offset.0),
                    section,
                    relative_offset: None,
                })
        });
        let raw_evidence =
            if swift_type.source == macho_swift::types::SwiftTypeSource::SwiftMetadata {
                swift_type
                    .address
                    .and_then(|address| {
                        macho
                            .read_bytes_at_va(macho_core::model::addr::Va(address), 20)
                            .ok()
                    })
                    .map_or_else(|| raw.as_bytes().to_vec(), <[u8]>::to_vec)
            } else {
                raw.as_bytes().to_vec()
            };
        observations.push(SwiftObservation {
            id: observation_id.clone(),
            source,
            raw: HexBytes::from_bytes(&raw_evidence),
            location: observation_location,
            disposition: SwiftObservationDisposition::Included {
                entity_ids: NonEmpty::new(vec![entity_id.clone()]).unwrap(),
            },
        });
        evidence.push(SwiftEvidence {
            id: evidence_id.clone(),
            observation_ids: NonEmpty::new(vec![observation_id.clone()]).unwrap(),
            kind: evidence_kind,
            location: match &descriptor {
                SwiftValue::Known { value, .. } => Some(value.clone()),
                _ => None,
            },
            raw: HexBytes::from_bytes(&raw_evidence),
        });
        let fields_or_cases = match &swift_type.fields {
            Some(fields) => SwiftValue::Known {
                value: fields
                    .iter()
                    .map(|field| SwiftField {
                        name: field.name.clone(),
                        mangled_type: field.mangled_type.as_deref().map(HexBytes::from_bytes),
                        type_name: field.type_name.clone().or_else(|| {
                            field.mangled_type.as_deref().and_then(|bytes| {
                                std::str::from_utf8(bytes)
                                    .ok()
                                    .and_then(macho_symbols::demangle::demangle_symbol)
                            })
                        }),
                        flags: field.flags,
                    })
                    .collect(),
                evidence: NonEmpty::new(vec![evidence_id.clone()]).unwrap(),
            },
            None => SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
        };
        let mut gaps = vec![
            gap(&entity_id, SwiftFieldName::Parent, &evidence_id),
            gap(&entity_id, SwiftFieldName::Conformances, &evidence_id),
        ];
        if swift_type.fields.is_none() {
            gaps.push(gap(&entity_id, SwiftFieldName::FieldsOrCases, &evidence_id));
        }
        if !matches!(descriptor, SwiftValue::Known { .. }) {
            gaps.push(gap(&entity_id, SwiftFieldName::Descriptor, &evidence_id));
        }
        entities.push(SwiftEntity {
            id: entity_id,
            identity_stability,
            state,
            kind: SwiftValue::Known {
                value: kind,
                evidence: NonEmpty::new(vec![evidence_id.clone()]).unwrap(),
            },
            qualified_name: SwiftValue::Known {
                value: qualified_name,
                evidence: NonEmpty::new(vec![evidence_id.clone()]).unwrap(),
            },
            descriptor,
            parent: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            fields_or_cases,
            conformances: SwiftValue::Unavailable {
                reason: SwiftUnavailableReason::NotEncoded,
            },
            superclass: match &swift_type.superclass {
                Some(name) => SwiftValue::Known {
                    value: name.clone(),
                    evidence: NonEmpty::new(vec![evidence_id.clone()]).unwrap(),
                },
                None => SwiftValue::Unavailable {
                    reason: SwiftUnavailableReason::NotEncoded,
                },
            },
            raw_linkages: swift_type.mangled_name.iter().cloned().collect(),
            observation_ids: NonEmpty::new(vec![observation_id]).unwrap(),
            gaps,
        });
    }

    let supplemental_reflection_records = enrich::enrich_reflection(
        macho,
        &index,
        &sections,
        &mut observations,
        &mut evidence,
        &mut entities,
        &mut diagnostics,
    );
    let totals = partition_counts(&entities, 0);
    let selected_entity_ids = entities.iter().map(|entity| entity.id.clone()).collect();
    let metadata_count = entities
        .iter()
        .filter(|entity| {
            matches!(
                entity.state,
                SwiftEntityState::MetadataDefined | SwiftEntityState::Referenced
            )
        })
        .count() as u64;
    let symbol_count = entities
        .iter()
        .filter(|entity| entity.state == SwiftEntityState::SymbolOnly)
        .count() as u64;
    let reflection_records = entities
        .iter()
        .filter_map(|entity| match &entity.fields_or_cases {
            SwiftValue::Known { value, .. } => Some(value.len() as u64),
            _ => None,
        })
        .sum::<u64>()
        .saturating_add(supplemental_reflection_records);
    let has_reflection_sections = macho.all_sections().any(|section| {
        matches!(
            section.section_name().as_str_lossy().as_ref(),
            "__swift5_fieldmd"
                | "__swift5_assocty"
                | "__swift5_proto"
                | "__swift5_reflstr"
                | "__swift5_typeref"
        )
    });
    let slice = SwiftSliceReport {
        architecture,
        image,
        observations,
        evidence,
        entities,
        selection: SwiftSelectionResult {
            selected_entity_ids,
            totals,
        },
        header: None,
        diagnostics,
        executions: NonEmpty::new(vec![
            SwiftCollectorExecution {
                collector: SwiftCollectorId::MetadataDescriptors,
                outcome: SwiftCollectorOutcome::Complete,
                input_records: metadata_count,
                output_records: metadata_count,
            },
            SwiftCollectorExecution {
                collector: SwiftCollectorId::ReflectionMetadata,
                outcome: if has_reflection_sections {
                    SwiftCollectorOutcome::Complete
                } else {
                    SwiftCollectorOutcome::Unsupported {
                        reason: UnsupportedReasonCode::MissingSection,
                    }
                },
                input_records: reflection_records,
                output_records: reflection_records,
            },
            SwiftCollectorExecution {
                collector: SwiftCollectorId::SymbolDemangling,
                outcome: SwiftCollectorOutcome::Complete,
                input_records: symbol_count,
                output_records: symbol_count,
            },
            SwiftCollectorExecution {
                collector: SwiftCollectorId::Reconciliation,
                outcome: SwiftCollectorOutcome::Complete,
                input_records: index.types.len() as u64,
                output_records: index.types.len() as u64,
            },
        ])
        .unwrap(),
    };
    let report = SwiftReport {
        schema_version: SwiftReportVersion::CURRENT,
        slices: NonEmpty::new(vec![slice]).unwrap(),
    };
    report.validate()?;
    Ok(report)
}

fn swift_identity_key(value: &macho_swift::types::SwiftType) -> String {
    format!("{:?}|{:?}|{}", value.source, value.kind, value.name)
}

fn swift_state(value: &macho_swift::types::SwiftType) -> SwiftEntityState {
    match value.source {
        macho_swift::types::SwiftTypeSource::SwiftMetadata if value.name.starts_with("__C.") => {
            SwiftEntityState::Referenced
        }
        macho_swift::types::SwiftTypeSource::SwiftMetadata => SwiftEntityState::MetadataDefined,
        macho_swift::types::SwiftTypeSource::DemangledSymbol => SwiftEntityState::SymbolOnly,
        macho_swift::types::SwiftTypeSource::ObjCMetadata => SwiftEntityState::Partial,
        _ => SwiftEntityState::Unknown,
    }
}

fn map_kind(value: macho_swift::types::SwiftTypeKind) -> SwiftTypeKind {
    match value {
        macho_swift::types::SwiftTypeKind::Class => SwiftTypeKind::Class,
        macho_swift::types::SwiftTypeKind::Struct => SwiftTypeKind::Struct,
        macho_swift::types::SwiftTypeKind::Enum => SwiftTypeKind::Enum,
        macho_swift::types::SwiftTypeKind::Protocol => SwiftTypeKind::Protocol,
        macho_swift::types::SwiftTypeKind::Unknown => SwiftTypeKind::Unknown,
        _ => SwiftTypeKind::Unknown,
    }
}

fn qualified_name(value: &str) -> SwiftQualifiedName {
    let components = value.split('.').map(str::to_owned).collect::<Vec<_>>();
    let module = (components.len() > 1).then(|| components[0].clone());
    SwiftQualifiedName {
        module,
        path: NonEmpty::new(components).expect("Swift type names are non-empty"),
    }
}

fn gap(entity: &SwiftEntityId, field: SwiftFieldName, evidence: &SwiftEvidenceId) -> SwiftGap {
    SwiftGap {
        id: SwiftGapId::new(sha256_hex(
            format!("swift-gap|{entity}|{field:?}").as_bytes(),
        ))
        .expect("SHA-256 gap ID"),
        field,
        reason: SwiftUnavailableReason::NotEncoded,
        evidence_ids: vec![evidence.clone()],
    }
}

fn section_at<'a>(address: u64, sections: &'a [&Section]) -> Option<(usize, &'a Section)> {
    sections.iter().enumerate().find_map(|(index, section)| {
        let start = section.addr().0;
        let end = start.checked_add(section.size())?;
        (address >= start && address < end).then_some((index + 1, *section))
    })
}

fn section_identity(ordinal: usize, section: &Section) -> SectionIdentity {
    SectionIdentity {
        segment: MachName::new(section.segment_name().as_str_lossy().into_owned()).unwrap(),
        section: MachName::new(section.section_name().as_str_lossy().into_owned()).unwrap(),
        ordinal: ordinal as u32,
    }
}

fn partition_counts(entities: &[SwiftEntity], excluded_observations: u64) -> SwiftPartitionCounts {
    SwiftPartitionCounts {
        metadata_defined: entities
            .iter()
            .filter(|entity| entity.state == SwiftEntityState::MetadataDefined)
            .count() as u64,
        referenced: entities
            .iter()
            .filter(|entity| entity.state == SwiftEntityState::Referenced)
            .count() as u64,
        symbol_only: entities
            .iter()
            .filter(|entity| entity.state == SwiftEntityState::SymbolOnly)
            .count() as u64,
        partial: entities
            .iter()
            .filter(|entity| entity.state == SwiftEntityState::Partial)
            .count() as u64,
        unknown: entities
            .iter()
            .filter(|entity| entity.state == SwiftEntityState::Unknown)
            .count() as u64,
        excluded_observations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_swift_wire_rejects_unknown_keys() {
        let value = serde_json::json!({"schema_version": 1, "slices": [], "invented": true});
        assert!(serde_json::from_value::<SwiftReport>(value).is_err());
    }
}
