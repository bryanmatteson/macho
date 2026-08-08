//! Conservative, useful symbol-only recovery with no optional collectors.

mod cpp_types;

use std::collections::BTreeMap;

use crate::core::model::SectionType;
use crate::core::model::container::MachoContainer;
use crate::core::{MachoFile, Section, SymbolTable};

use super::*;

/// Builds one canonical symbols-only report for the selected container slices.
pub fn recover_symbol_container(
    container: &MachoContainer<'_>,
    language: RecoveryLanguage,
    selected_architecture: Option<&str>,
) -> crate::analysis::Result<RecoveryReport> {
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
        let report = recover_symbol_surface(macho, language)?;
        let mut slice = report.slices.into_vec().remove(0);
        slice.image.container = container_kind;
        slice.image.slice_index = index as u32;
        slice.inputs.image = slice.image.clone();
        slices.push(slice);
    }
    if slices.is_empty() {
        return Err(crate::analysis::AnalysisError::invalid(
            match selected_architecture {
                Some(arch) => format!("no architecture matching `{arch}` found"),
                None => "container contains no Mach-O slices".to_owned(),
            },
        ));
    }
    let architectures = match (selected_architecture, slices.as_slice()) {
        (None, _) => ArchitectureSelection::All,
        (Some(_), [slice]) => ArchitectureSelection::One {
            architecture: slice.architecture,
        },
        (Some(_), slices) => ArchitectureSelection::Many {
            architectures: NonEmpty::new(slices.iter().map(|slice| slice.architecture).collect())
                .expect("selected recovery slices are non-empty"),
        },
    };
    let request = recovery_request(language, architectures);
    let request_digest = request_digest(&request)?;
    for slice in &mut slices {
        slice.resolved_plan.request_digest = request_digest.clone();
        for execution in slice.executions.as_mut_slice() {
            execution.request_digest = request_digest.clone();
        }
    }
    let report = RecoveryReport {
        schema_version: RecoverySchemaVersion::CURRENT,
        language,
        request,
        slices: NonEmpty::new(slices).expect("checked non-empty slices"),
    };
    report
        .validate()
        .map_err(|error| crate::analysis::AnalysisError::validation(error.to_string()))?;
    Ok(report)
}

/// Builds a canonical C or C++ report from the nlist symbol table only.
///
/// The function never executes DWARF, ranges, RTTI, vtable, body-analysis,
/// Objective-C, Swift, or header collectors. Facts not encoded in nlist remain
/// explicitly unavailable.
pub fn recover_symbol_surface(
    macho: &MachoFile<'_>,
    language: RecoveryLanguage,
) -> crate::analysis::Result<RecoveryReport> {
    let architecture = Architecture {
        cpu_type: macho.header().cpu_type().0,
        cpu_subtype: macho.header().cpu_subtype().0,
    };
    let image = image_identity(macho, architecture)?;
    let limits = RecoveryLimits::default();
    let request = recovery_request(language, ArchitectureSelection::One { architecture });
    let request_digest = request_digest(&request)?;

    let symbols = macho.ext::<SymbolTable<'_>>()?;
    let sections = macho.all_sections().collect::<Vec<_>>();
    let name_counts = symbols
        .symbols()
        .iter()
        .filter(|symbol| !symbol.is_stab() && !symbol.name.is_empty())
        .map(|symbol| normalize_name(symbol.name))
        .fold(BTreeMap::<String, usize>::new(), |mut counts, name| {
            *counts.entry(name).or_default() += 1;
            counts
        });

    let mut observations = Vec::with_capacity(symbols.len());
    let mut entities = Vec::new();
    let mut diagnostics = Vec::new();
    for symbol in symbols.symbols() {
        let section = symbol_section(symbol, &sections);
        let section_identity = section.map(|section| SectionIdentity {
            segment: MachName::new(section.segment_name().as_str_lossy().into_owned())
                .expect("Mach-O segment names satisfy the wire constraints"),
            section: MachName::new(section.section_name().as_str_lossy().into_owned())
                .expect("Mach-O section names satisfy the wire constraints"),
            ordinal: symbol.section_index as u32,
        });
        let observation_id = id::<ObservationId>(&format!(
            "observation|nlist|{}|{}|{}",
            symbol.index, symbol.value, symbol.name
        ));
        let presence = symbol_presence(symbol);
        let disposition = if symbol.is_stab() {
            ObservationDisposition::Excluded {
                reason: ExclusionReason::DebugOnly,
            }
        } else if symbol.name.is_empty() {
            ObservationDisposition::Excluded {
                reason: ExclusionReason::SyntheticNonEntity,
            }
        } else {
            match classify_linkage(symbol.name) {
                LinkageClassification::MalformedKnown => {
                    let diagnostic_id = id::<DiagnosticId>(&format!(
                        "diagnostic|malformed|{}|{}",
                        symbol.index, symbol.name
                    ));
                    diagnostics.push(RecoveryDiagnostic {
                        id: diagnostic_id,
                        code: RecoveryDiagnosticCode::MalformedKnownEncoding,
                        severity: Severity::Warning,
                        message: format!("malformed known linkage encoding `{}`", symbol.name),
                        observation_id: Some(observation_id.clone()),
                        entity_id: None,
                        evidence_ids: Vec::new(),
                    });
                    ObservationDisposition::Unknown {
                        reason: UnknownReason::MalformedEncoding,
                    }
                }
                classification if !classification.belongs_to(language) => {
                    ObservationDisposition::Excluded {
                        reason: ExclusionReason::WrongLanguage,
                    }
                }
                classification => {
                    let normalized = normalize_name(symbol.name);
                    let stability = if name_counts.get(&normalized) == Some(&1) {
                        IdentityStability::CrossBuild
                    } else {
                        IdentityStability::SliceOnly
                    };
                    let entity_seed = if stability == IdentityStability::CrossBuild {
                        format!("entity|{:?}|{normalized}", language)
                    } else {
                        format!(
                            "entity|{:?}|{}|{}|{normalized}",
                            language, symbol.index, symbol.value
                        )
                    };
                    let entity_id = id::<EntityId>(&entity_seed);
                    let evidence_id = id::<EvidenceId>(&format!("evidence|{entity_seed}|nlist"));
                    entities.push(build_entity(
                        symbol,
                        EntityBuildInput {
                            classification,
                            normalized,
                            stability,
                            entity_id: entity_id.clone(),
                            observation_id: observation_id.clone(),
                            evidence_id,
                            section: section_identity.clone(),
                            role: classify_role(symbol, classification, section),
                        },
                    ));
                    ObservationDisposition::Included {
                        entity_ids: NonEmpty::new(vec![entity_id])
                            .expect("one entity ID is non-empty"),
                    }
                }
            }
        };
        observations.push(SymbolObservation {
            id: observation_id,
            source: ObservationSource::Nlist,
            ordinal: symbol.index as u64,
            raw_name: symbol.name.to_owned(),
            presence,
            address: symbol.is_defined().then_some(symbol.value),
            section: section_identity,
            disposition,
        });
    }

    if language == RecoveryLanguage::Cpp {
        cpp_types::materialize_cpp_types(&mut observations, &mut entities);
    }

    let selected_entity_ids = entities.iter().map(|entity| entity.id.clone()).collect();
    let execution = CollectorExecution {
        collector: CollectorId::SymbolDiscovery,
        request_digest: request_digest.clone(),
        target_entity_ids: Vec::new(),
        outcome: CollectorOutcome::Complete,
        counts: CollectorCounts {
            input_records: observations.len() as u64,
            output_records: entities.len() as u64,
            selected_targets: entities.len() as u64,
        },
    };
    let slice = SliceRecovery {
        architecture,
        image: image.clone(),
        inputs: RecoveryInputs {
            image,
            selected_architecture: architecture,
            header_roots: Vec::new(),
        },
        resolved_plan: ResolvedRecoveryPlan {
            request_digest,
            discovery: vec![ResolvedCollectorSpec {
                collector: CollectorId::SymbolDiscovery,
                target_entity_ids: Vec::new(),
                required: true,
                limits: CollectorLimits {
                    max_records: limits.max_observations,
                    max_bytes: limits.max_serialized_bytes,
                    max_diagnostics: limits.max_diagnostics,
                },
            }],
            selected_entity_ids,
            targeted: Vec::new(),
            projection: None,
        },
        executions: NonEmpty::new(vec![execution]).expect("one execution is non-empty"),
        observations,
        entities,
        header: None,
        diagnostics,
        truncations: Vec::new(),
    };
    let report = RecoveryReport {
        schema_version: RecoverySchemaVersion::CURRENT,
        language,
        request,
        slices: NonEmpty::new(vec![slice]).expect("one slice is non-empty"),
    };
    report
        .validate()
        .map_err(|error| crate::analysis::AnalysisError::validation(error.to_string()))?;
    Ok(report)
}

fn recovery_request(
    language: RecoveryLanguage,
    architectures: ArchitectureSelection,
) -> RecoveryRequestSummary {
    RecoveryRequestSummary {
        language,
        architectures,
        view: RecoveryView::Surface,
        selection: EntitySelection {
            scope: RecoveryScope::All,
            kinds: vec![
                EntityKind::Function,
                EntityKind::Data,
                EntityKind::Tls,
                EntityKind::RuntimeArtifact,
                EntityKind::Method,
                EntityKind::Type,
                EntityKind::Vtable,
                EntityKind::Typeinfo,
                EntityKind::Thunk,
                EntityKind::Guard,
                EntityKind::Unknown,
            ],
            name_globs: Vec::new(),
        },
        analysis: AnalysisLevel::Sources,
        header_roots: Vec::new(),
        hypothesis_selection_policy: Default::default(),
        limits: RecoveryLimits::default(),
    }
}

fn request_digest(request: &RecoveryRequestSummary) -> crate::analysis::Result<RequestDigest> {
    Ok(
        RequestDigest::new(digest_bytes(&canonical_json(request).map_err(|error| {
            crate::analysis::AnalysisError::validation(error.to_string())
        })?))
        .expect("SHA-256 is a valid request digest"),
    )
}

struct EntityBuildInput {
    classification: LinkageClassification,
    normalized: String,
    stability: IdentityStability,
    entity_id: EntityId,
    observation_id: ObservationId,
    evidence_id: EvidenceId,
    section: Option<SectionIdentity>,
    role: (EntityRole, EvidenceStrength),
}

fn build_entity(symbol: &crate::core::Symbol<'_>, input: EntityBuildInput) -> RecoveredEntity {
    let EntityBuildInput {
        classification,
        normalized,
        stability,
        entity_id,
        observation_id,
        evidence_id,
        section,
        role,
    } = input;
    let entity_seed = entity_id.to_string();
    let evidence_ids =
        || NonEmpty::new(vec![evidence_id.clone()]).expect("one evidence ID is non-empty");
    let presence = symbol_presence(symbol);
    let weakness = if symbol.is_weak_def() {
        Weakness::WeakDefinition
    } else if symbol.is_weak_ref() {
        Weakness::WeakReference
    } else {
        Weakness::Strong
    };
    let visibility = if symbol.private_external {
        Visibility::PrivateExtern
    } else {
        Visibility::Default
    };
    let location = EntityLocation {
        address: symbol.is_defined().then_some(symbol.value),
        section: section.clone(),
        range: None,
    };
    let evidence = EvidenceRecord {
        id: evidence_id.clone(),
        collector: CollectorId::SymbolDiscovery,
        observation_ids: vec![observation_id.clone()],
        strength: EvidenceStrength::Exact,
        payload: EvidencePayload::Symbol {
            value: SymbolEvidence {
                raw_name: symbol.name.to_owned(),
                normalized_linkage: normalized.clone(),
                source: ObservationSource::Nlist,
                ordinal: symbol.index as u64,
                presence,
                address: symbol.is_defined().then_some(symbol.value),
                section,
            },
        },
    };
    let gap = |field: RecoveryField, reason: UnavailableReason| RecoveryGap {
        id: id::<RecoveryGapId>(&format!("gap|{entity_seed}|{field:?}")),
        field,
        reason: RecoveryGapReason::Unavailable { reason },
        evidence_ids: vec![evidence_id.clone()],
    };
    let not_encoded = UnavailableReason::NotEncoded;
    let role_value = role.0;
    let value_type_reason = if matches!(
        role_value,
        EntityRole::Data | EntityRole::Tls | EntityRole::CppStaticData
    ) {
        UnavailableReason::NotEncoded
    } else {
        UnavailableReason::NotApplicable
    };
    RecoveredEntity {
        id: entity_id,
        identity_stability: stability,
        observation_ids: NonEmpty::new(vec![observation_id])
            .expect("one observation ID is non-empty"),
        linkage: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|linkage")),
            value: LinkageEncoding {
                raw: symbol.name.to_owned(),
                normalized: normalized.clone(),
                family: classification.family(),
            },
            strength: EvidenceStrength::Exact,
            evidence_ids: evidence_ids(),
        },
        display_name: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|display_name")),
            value: normalized,
            strength: EvidenceStrength::Exact,
            evidence_ids: evidence_ids(),
        },
        role: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|role")),
            value: role_value,
            strength: role.1,
            evidence_ids: evidence_ids(),
        },
        presence: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|presence")),
            value: presence,
            strength: EvidenceStrength::Exact,
            evidence_ids: evidence_ids(),
        },
        visibility: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|visibility")),
            value: visibility,
            strength: EvidenceStrength::Exact,
            evidence_ids: evidence_ids(),
        },
        weakness: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|weakness")),
            value: weakness,
            strength: EvidenceStrength::Exact,
            evidence_ids: evidence_ids(),
        },
        location: Fact::Known {
            id: id::<FactId>(&format!("fact|{entity_seed}|location")),
            value: location,
            strength: EvidenceStrength::Exact,
            evidence_ids: evidence_ids(),
        },
        owner: unavailable_fact(&entity_seed, "owner", not_encoded, &evidence_id),
        value_type: unavailable_fact(&entity_seed, "value_type", value_type_reason, &evidence_id),
        signature: RecoveredSignature {
            return_type: unavailable_fact(&entity_seed, "return_type", not_encoded, &evidence_id),
            parameters: unavailable_fact(&entity_seed, "parameters", not_encoded, &evidence_id),
            variadic: unavailable_fact(&entity_seed, "variadic", not_encoded, &evidence_id),
            calling_convention: Fact::Known {
                id: id::<FactId>(&format!("fact|{entity_seed}|calling_convention")),
                value: CallingConvention::C,
                strength: EvidenceStrength::Inferred,
                evidence_ids: evidence_ids(),
            },
            qualifiers: unavailable_fact(&entity_seed, "qualifiers", not_encoded, &evidence_id),
        },
        layout: RecoveredLayout {
            size: unavailable_fact(&entity_seed, "layout_size", not_encoded, &evidence_id),
            alignment: unavailable_fact(
                &entity_seed,
                "layout_alignment",
                not_encoded,
                &evidence_id,
            ),
            fields: unavailable_fact(&entity_seed, "layout_fields", not_encoded, &evidence_id),
            completeness: unavailable_fact(
                &entity_seed,
                "layout_completeness",
                not_encoded,
                &evidence_id,
            ),
        },
        hierarchy: RecoveredHierarchy {
            bases: unavailable_fact(&entity_seed, "bases", not_encoded, &evidence_id),
            virtual_surface: unavailable_fact(
                &entity_seed,
                "virtual_surface",
                not_encoded,
                &evidence_id,
            ),
        },
        evidence: vec![evidence],
        gaps: [
            RecoveryField::Owner,
            RecoveryField::ReturnType,
            RecoveryField::Parameters,
            RecoveryField::Variadic,
            RecoveryField::Qualifiers,
            RecoveryField::LayoutSize,
            RecoveryField::LayoutAlignment,
            RecoveryField::LayoutFields,
            RecoveryField::LayoutCompleteness,
            RecoveryField::Bases,
            RecoveryField::VirtualSurface,
        ]
        .into_iter()
        .map(|field| gap(field, not_encoded))
        .chain(
            matches!(
                role_value,
                EntityRole::Data | EntityRole::Tls | EntityRole::CppStaticData
            )
            .then(|| gap(RecoveryField::ValueType, not_encoded)),
        )
        .collect(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LinkageClassification {
    Plain,
    ItaniumCpp,
    RustV0,
    RustLegacy,
    Swift,
    Objc,
    MalformedKnown,
}

impl LinkageClassification {
    fn belongs_to(self, language: RecoveryLanguage) -> bool {
        match language {
            RecoveryLanguage::CAbi => matches!(self, Self::Plain),
            RecoveryLanguage::Cpp => matches!(self, Self::ItaniumCpp),
        }
    }

    fn family(self) -> LinkageFamily {
        match self {
            Self::Plain => LinkageFamily::Plain,
            Self::ItaniumCpp => LinkageFamily::ItaniumCpp,
            Self::RustV0 => LinkageFamily::RustV0,
            Self::RustLegacy => LinkageFamily::RustLegacy,
            Self::Swift => LinkageFamily::Swift,
            Self::Objc => LinkageFamily::Objc,
            Self::MalformedKnown => LinkageFamily::Unknown,
        }
    }
}

fn symbol_section<'a>(
    symbol: &crate::core::Symbol<'_>,
    sections: &'a [&Section],
) -> Option<&'a Section> {
    symbol
        .section_index
        .checked_sub(1)
        .and_then(|index| sections.get(index as usize).copied())
}

fn classify_role(
    symbol: &crate::core::Symbol<'_>,
    classification: LinkageClassification,
    section: Option<&Section>,
) -> (EntityRole, EvidenceStrength) {
    use crate::core::format::constants::SectionAttributes;

    if classification == LinkageClassification::Plain && is_runtime_artifact(symbol.name) {
        return (EntityRole::RuntimeArtifact, EvidenceStrength::Exact);
    }
    if section.is_some_and(|section| {
        matches!(
            section.section_type(),
            SectionType::ThreadLocalRegular
                | SectionType::ThreadLocalZeroFill
                | SectionType::ThreadLocalVariables
                | SectionType::ThreadLocalVariablePointers
                | SectionType::ThreadLocalInitFunctionPointers
        )
    }) {
        return (EntityRole::Tls, EvidenceStrength::Exact);
    }
    if classification == LinkageClassification::ItaniumCpp {
        let candidate = symbol.name.strip_prefix('_').unwrap_or(symbol.name);
        return if candidate.starts_with("_ZTV") {
            (EntityRole::Vtable, EvidenceStrength::Exact)
        } else if candidate.starts_with("_ZTI") || candidate.starts_with("_ZTS") {
            (EntityRole::Typeinfo, EvidenceStrength::Exact)
        } else if candidate.starts_with("_ZTT") {
            (EntityRole::Vtt, EvidenceStrength::Exact)
        } else if candidate.starts_with("_ZTh")
            || candidate.starts_with("_ZTv")
            || candidate.starts_with("_ZTc")
        {
            (EntityRole::Thunk, EvidenceStrength::Exact)
        } else if candidate.starts_with("_ZGV") {
            (EntityRole::Guard, EvidenceStrength::Exact)
        } else if crate::analysis::reconstruct::cpp::symbol::parse_symbol(symbol.name, None, None)
            .is_some_and(|record| {
                matches!(
                    record.kind,
                    crate::analysis::reconstruct::cpp::CppSymbolKind::Data { .. }
                )
            })
        {
            (EntityRole::CppStaticData, EvidenceStrength::Exact)
        } else if symbol.is_defined()
            && section.is_some_and(|section| {
                section.attributes().intersects(
                    SectionAttributes::PURE_INSTRUCTIONS | SectionAttributes::SOME_INSTRUCTIONS,
                )
            })
        {
            // A qualified Itanium name alone cannot prove class ownership, but an
            // executable section does prove a callable entity.
            (EntityRole::Function, EvidenceStrength::Correlated)
        } else if symbol.is_defined() {
            // Itanium local names may contain the enclosing function signature
            // even when the symbol itself is a function-local data object.
            // Non-executable placement is therefore part of the role evidence.
            (EntityRole::CppStaticData, EvidenceStrength::Correlated)
        } else {
            (EntityRole::Unknown, EvidenceStrength::Inferred)
        };
    }
    if classification == LinkageClassification::Plain && symbol.is_defined() {
        return if section.is_some_and(|section| {
            section.section_name() == "__text"
                || section.section_name() == "__stubs"
                || section.section_name() == "__stub_helper"
        }) {
            (EntityRole::Function, EvidenceStrength::Correlated)
        } else {
            (EntityRole::Data, EvidenceStrength::Correlated)
        };
    }
    (EntityRole::Unknown, EvidenceStrength::Inferred)
}

fn is_runtime_artifact(name: &str) -> bool {
    let undecorated = name.trim_start_matches('_');
    matches!(
        undecorated,
        "mh_execute_header" | "mh_dylib_header" | "mh_bundle_header" | "mh_object_header"
    ) || undecorated.starts_with("section$start$")
        || undecorated.starts_with("section$end$")
        || undecorated.starts_with("segment$start$")
        || undecorated.starts_with("segment$end$")
}

fn classify_linkage(name: &str) -> LinkageClassification {
    let candidate = name.strip_prefix('_').unwrap_or(name);
    if candidate.starts_with("_Z") {
        if crate::metadata::symbols::demangle::demangle_cpp_symbol(name).is_some() {
            LinkageClassification::ItaniumCpp
        } else {
            LinkageClassification::MalformedKnown
        }
    } else if candidate.starts_with("_R") {
        LinkageClassification::RustV0
    } else if candidate.starts_with("_ZN") {
        LinkageClassification::RustLegacy
    } else if candidate.starts_with("$s")
        || candidate.starts_with("_$s")
        || candidate.starts_with("_Tt")
    {
        LinkageClassification::Swift
    } else if candidate.starts_with("OBJC_") || candidate.starts_with("_OBJC_") {
        LinkageClassification::Objc
    } else {
        LinkageClassification::Plain
    }
}

fn normalize_name(name: &str) -> String {
    crate::metadata::symbols::demangle::demangle_symbol(name).unwrap_or_else(|| {
        name.strip_prefix('_')
            .filter(|stripped| !stripped.starts_with('_'))
            .unwrap_or(name)
            .to_owned()
    })
}

fn symbol_presence(symbol: &crate::core::Symbol<'_>) -> Presence {
    if symbol.is_defined() {
        Presence::Defined
    } else if symbol.is_undefined() {
        Presence::Imported
    } else {
        Presence::Unknown
    }
}

fn unavailable_fact<T>(
    entity_seed: &str,
    field: &str,
    reason: UnavailableReason,
    evidence_id: &EvidenceId,
) -> Fact<T> {
    Fact::Unavailable {
        id: id::<FactId>(&format!("fact|{entity_seed}|{field}")),
        reason,
        evidence_ids: vec![evidence_id.clone()],
    }
}

pub(super) fn image_identity(
    macho: &MachoFile<'_>,
    architecture: Architecture,
) -> crate::analysis::Result<ImageIdentity> {
    let uuid = macho
        .uuid()
        .map(|bytes| {
            let hex = bytes
                .iter()
                .map(|byte| format!("{byte:02X}"))
                .collect::<String>();
            CanonicalUuid::new(format!(
                "{}-{}-{}-{}-{}",
                &hex[0..8],
                &hex[8..12],
                &hex[12..16],
                &hex[16..20],
                &hex[20..32]
            ))
        })
        .transpose()
        .map_err(|error| crate::analysis::AnalysisError::validation(error.to_string()))?;
    Ok(ImageIdentity {
        content_sha256: ContentHash::new(digest_bytes(macho.bytes()))
            .expect("SHA-256 is a valid content hash"),
        byte_len: macho.bytes().len() as u64,
        container: ContainerKind::Thin,
        slice_index: 0,
        architecture,
        uuid,
    })
}

trait StableDigestId: Sized {
    fn from_digest(value: String) -> Self;
}

macro_rules! stable_digest_id {
    ($($ty:ty),+ $(,)?) => {$(
        impl StableDigestId for $ty {
            fn from_digest(value: String) -> Self {
                <$ty>::new(value).expect("SHA-256 is a valid stable ID")
            }
        }
    )+};
}

stable_digest_id!(
    ObservationId,
    EntityId,
    FactId,
    EvidenceId,
    DiagnosticId,
    RecoveryGapId,
);

fn id<T: StableDigestId>(seed: &str) -> T {
    T::from_digest(digest_bytes(seed.as_bytes()))
}

fn digest_bytes(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_only_report_conserves_every_observation() {
        let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
            macho_test_support::SymbolFixture {
                name: "_plain",
                external: true,
                defined: true,
            },
            macho_test_support::SymbolFixture {
                name: "__Z3foov",
                external: true,
                defined: true,
            },
        ]);
        let container = crate::core::parse(&bytes).unwrap();
        let macho = container.first_macho().unwrap();
        let report = recover_symbol_surface(macho, RecoveryLanguage::CAbi).unwrap();
        let slice = &report.slices.as_slice()[0];
        assert_eq!(slice.observations.len(), 2);
        assert_eq!(slice.entities.len(), 1);
        assert!(matches!(
            slice.observations[1].disposition,
            ObservationDisposition::Excluded {
                reason: ExclusionReason::WrongLanguage
            }
        ));
        report.validate().unwrap();
    }

    #[test]
    fn recognized_image_header_overrides_executable_section_heuristic() {
        let bytes =
            macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
                name: "_mh_execute_header",
                external: true,
                defined: true,
            }]);
        let container = crate::core::parse(&bytes).unwrap();
        let report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::CAbi)
                .unwrap();
        assert!(matches!(
            report.slices.as_slice()[0].entities[0].role,
            Fact::Known {
                value: EntityRole::RuntimeArtifact,
                strength: EvidenceStrength::Exact,
                ..
            }
        ));
    }

    #[test]
    fn thread_local_section_produces_explicit_tls_role() {
        let bytes = macho_test_support::thin64_x86_64_with_tls_symbols(&[
            macho_test_support::SymbolFixture {
                name: "_tls_value",
                external: true,
                defined: true,
            },
        ]);
        let container = crate::core::parse(&bytes).unwrap();
        let report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::CAbi)
                .unwrap();
        let entity = &report.slices.as_slice()[0].entities[0];
        assert!(matches!(
            entity.role,
            Fact::Known {
                value: EntityRole::Tls,
                strength: EvidenceStrength::Exact,
                ..
            }
        ));
        assert!(
            entity
                .gaps
                .iter()
                .any(|gap| gap.field == RecoveryField::ValueType)
        );
    }

    #[test]
    fn itanium_function_local_static_in_data_is_not_classified_as_a_function() {
        let bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
            macho_test_support::SymbolFixture {
                name: "__ZZN6Base646encodeERKNSt3__112basic_stringIcNS0_11char_traitsIcEENS0_9allocatorIcEEEEE12sBase64Table",
                external: false,
                defined: true,
            },
        ]);
        let container = crate::core::parse(&bytes).unwrap();
        let report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::Cpp)
                .unwrap();
        let entity = &report.slices.as_slice()[0].entities[0];
        assert!(matches!(
            entity.role,
            Fact::Known {
                value: EntityRole::CppStaticData,
                strength: EvidenceStrength::Correlated,
                ..
            }
        ));
        report.validate().unwrap();
    }

    #[test]
    fn positive_cpp_anchors_create_occurrence_linked_type_entities() {
        let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
            macho_test_support::SymbolFixture {
                name: "__ZN3FooC1Ev",
                external: true,
                defined: true,
            },
            macho_test_support::SymbolFixture {
                name: "__ZN3BarC1Ev",
                external: true,
                defined: false,
            },
        ]);
        let container = crate::core::parse(&bytes).unwrap();
        let report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::Cpp)
                .unwrap();
        let slice = &report.slices.as_slice()[0];
        let type_entity = |name: &str| {
            slice
                .entities
                .iter()
                .find(|entity| {
                    matches!(
                        entity.role,
                        Fact::Known {
                            value: EntityRole::Type,
                            ..
                        }
                    ) && matches!(&entity.display_name, Fact::Known { value, .. } if value == name)
                })
                .unwrap()
        };
        assert!(matches!(
            type_entity("Foo").presence,
            Fact::Known {
                value: Presence::Defined,
                ..
            }
        ));
        assert!(matches!(
            type_entity("Bar").presence,
            Fact::Known {
                value: Presence::Imported,
                ..
            }
        ));
        assert!(slice.observations.iter().all(|observation| matches!(
            &observation.disposition,
            ObservationDisposition::Included { entity_ids } if entity_ids.as_slice().len() == 2
        )));
        report.validate().unwrap();
    }

    #[test]
    fn v2_rejects_pre_amendment_entity_shape() {
        let bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
            macho_test_support::SymbolFixture {
                name: "_global",
                external: true,
                defined: true,
            },
        ]);
        let container = crate::core::parse(&bytes).unwrap();
        let report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::CAbi)
                .unwrap();
        let mut value = serde_json::to_value(report).unwrap();
        value["slices"][0]["entities"][0]
            .as_object_mut()
            .unwrap()
            .remove("value_type");
        let error = serde_json::from_value::<RecoveryReport>(value).unwrap_err();
        assert!(error.to_string().contains("value_type"), "{error}");
    }

    #[test]
    fn v2_rejects_v1_and_false_architecture_provenance() {
        let bytes = macho_test_support::thin64_x86_64_with_symbols(&[]);
        let container = crate::core::parse(&bytes).unwrap();
        let report =
            recover_symbol_surface(container.first_macho().unwrap(), RecoveryLanguage::CAbi)
                .unwrap();

        let mut v1 = serde_json::to_value(&report).unwrap();
        v1["schema_version"] = serde_json::json!(1);
        assert!(serde_json::from_value::<RecoveryReport>(v1).is_err());

        let mut wrong_architecture = serde_json::to_value(report).unwrap();
        wrong_architecture["request"]["architectures"] = serde_json::json!({
            "kind": "one",
            "architecture": { "cpu_type": 0, "cpu_subtype": 0 }
        });
        let wrong_architecture =
            serde_json::from_value::<RecoveryReport>(wrong_architecture).unwrap();
        assert!(matches!(
            wrong_architecture.validate(),
            Err(RecoveryValidationError::ArchitectureSelection)
        ));
    }
}
