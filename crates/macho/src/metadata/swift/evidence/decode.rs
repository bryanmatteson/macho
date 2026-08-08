use super::*;

/// Decode one already-selected thin Mach-O byte view. Universal selection,
/// file I/O, host tools, live memory, and target runtime calls remain outside
/// this function.
#[must_use]
pub fn decode_swift_strict_file(source: &[u8], limits: &SwiftEvidenceLimits) -> SwiftDecodeBatchV1 {
    if let Err(error) = limits.validate() {
        return rejected(
            1,
            "swift_structural_budget_exceeded",
            None,
            error.to_string(),
        );
    }
    let macho = match crate::core::parse(source) {
        Ok(MachoContainer::Thin(macho)) => macho,
        Ok(MachoContainer::Fat(_)) => {
            return rejected(
                1,
                "swift_selection_required",
                None,
                "strict Swift decoding requires one preselected thin Mach-O",
            );
        }
        Err(error) => {
            return rejected(
                1,
                "swift_metadata_malformed",
                None,
                format!("selected Mach-O parse failed: {error}"),
            );
        }
    };
    decode_swift_strict(&macho, limits)
}

/// Decode strict Swift ABI evidence from a parsed selected image.
#[must_use]
pub fn decode_swift_strict(
    macho: &MachoFile<'_>,
    limits: &SwiftEvidenceLimits,
) -> SwiftDecodeBatchV1 {
    if let Err(error) = limits.validate() {
        return rejected(
            1,
            "swift_structural_budget_exceeded",
            None,
            error.to_string(),
        );
    }
    let nominal_entries = swift_nominal_list_entry_count(macho);
    let conformance_entries = swift_conformance_list_entry_count(macho);
    let validated_associated_types = match validate_associated_types(macho, limits) {
        Ok(descriptors) => descriptors,
        Err(error) => {
            let attempted = nominal_entries
                .checked_add(conformance_entries)
                .and_then(|value| value.checked_add(error.attempted))
                .unwrap_or(u64::MAX);
            return validated(SwiftDecodeBatchV1 {
                outcome: SwiftDecodeOutcomeV1::Rejected,
                records: Vec::new(),
                conformances: Vec::new(),
                associated_types: Vec::new(),
                protocol_requirements: Vec::new(),
                protocol_signature_requirements: Vec::new(),
                class_vtable_entries: Vec::new(),
                class_overrides: Vec::new(),
                gaps: vec![error.gap],
                collector_outcomes: vec![
                    collector(
                        "nominal_descriptors",
                        if nominal_entries == 0 {
                            SwiftCollectorStatusV1::Absent
                        } else {
                            SwiftCollectorStatusV1::Complete
                        },
                        nominal_entries,
                    ),
                    collector(
                        "conformances",
                        if conformance_entries == 0 {
                            SwiftCollectorStatusV1::Absent
                        } else {
                            SwiftCollectorStatusV1::Complete
                        },
                        conformance_entries,
                    ),
                    collector(
                        "associated_types",
                        SwiftCollectorStatusV1::Rejected,
                        error.attempted,
                    ),
                ],
                conservation: SwiftObservationConservationV1 {
                    attempted,
                    included: 0,
                    unknown: attempted,
                    excluded: 0,
                },
            });
        }
    };
    let associated_type_entries =
        match validated_associated_types
            .iter()
            .try_fold(0_u64, |count, descriptor| {
                count
                    .checked_add(1)
                    .and_then(|value| value.checked_add(descriptor.records.len() as u64))
            }) {
            Some(count) => count,
            None => {
                return rejected(
                    u64::MAX,
                    "swift_structural_budget_exceeded",
                    Some("__swift5_assocty".into()),
                    "Swift associated-type observation count overflowed",
                );
            }
        };
    let total_entries = match nominal_entries
        .checked_add(conformance_entries)
        .and_then(|value| value.checked_add(associated_type_entries))
    {
        Some(total) => total,
        None => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                None,
                "Swift descriptor observation count overflowed",
            );
        }
    };
    if total_entries == 0 {
        return validated(SwiftDecodeBatchV1 {
            outcome: SwiftDecodeOutcomeV1::Absent,
            records: Vec::new(),
            conformances: Vec::new(),
            associated_types: Vec::new(),
            protocol_requirements: Vec::new(),
            protocol_signature_requirements: Vec::new(),
            class_vtable_entries: Vec::new(),
            class_overrides: Vec::new(),
            gaps: Vec::new(),
            collector_outcomes: vec![
                collector("nominal_descriptors", SwiftCollectorStatusV1::Absent, 0),
                collector("conformances", SwiftCollectorStatusV1::Absent, 0),
                collector("associated_types", SwiftCollectorStatusV1::Absent, 0),
                collector("protocol_requirements", SwiftCollectorStatusV1::Absent, 0),
                collector("witness_patterns", SwiftCollectorStatusV1::Absent, 0),
                collector("class_dispatch", SwiftCollectorStatusV1::Absent, 0),
            ],
            conservation: SwiftObservationConservationV1 {
                attempted: 0,
                included: 0,
                unknown: 0,
                excluded: 0,
            },
        });
    }
    if nominal_entries > limits.max_nominal_descriptors
        || conformance_entries > limits.max_conformances
        || total_entries > limits.max_observations
    {
        return rejected(
            total_entries,
            "swift_structural_budget_exceeded",
            None,
            "Swift descriptor count exceeds the selected limit",
        );
    }

    let descriptors = match validate_nominal_lists(macho, limits) {
        Ok(descriptors) => descriptors,
        Err(gap) => {
            return validated(SwiftDecodeBatchV1 {
                outcome: SwiftDecodeOutcomeV1::Rejected,
                records: Vec::new(),
                conformances: Vec::new(),
                associated_types: Vec::new(),
                protocol_requirements: Vec::new(),
                protocol_signature_requirements: Vec::new(),
                class_vtable_entries: Vec::new(),
                class_overrides: Vec::new(),
                gaps: vec![gap],
                collector_outcomes: vec![SwiftCollectorOutcomeV1 {
                    collector: "nominal_descriptors".into(),
                    status: SwiftCollectorStatusV1::Rejected,
                    attempted: total_entries,
                }],
                conservation: SwiftObservationConservationV1 {
                    attempted: total_entries,
                    included: 0,
                    unknown: total_entries,
                    excluded: 0,
                },
            });
        }
    };
    let mut structural_gaps = Vec::new();
    let mut structural_unknown = 0_u64;
    let mut protocol_requirements = Vec::new();
    let mut protocol_signature_requirements = Vec::new();
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.section == "__swift5_protos")
    {
        match validate_protocol_requirements(macho, std::slice::from_ref(descriptor), limits) {
            Ok((mut signatures, mut requirements)) => {
                protocol_signature_requirements.append(&mut signatures);
                protocol_requirements.append(&mut requirements);
            }
            Err(error) => {
                structural_unknown = structural_unknown.saturating_add(error.attempted);
                structural_gaps.push(error.gap);
            }
        }
    }
    let protocol_requirement_attempted = (protocol_requirements.len() as u64)
        .saturating_add(protocol_signature_requirements.len() as u64)
        .saturating_add(structural_unknown);
    let total_entries = match total_entries.checked_add(protocol_requirement_attempted) {
        Some(total) if total <= limits.max_observations => total,
        _ => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_protos".into()),
                "Swift protocol-requirement observations exceed the selected limit",
            );
        }
    };
    let mut class_vtable_entries = Vec::new();
    let mut class_overrides = Vec::new();
    let mut class_dispatch_attempted = 0_u64;
    let mut class_dispatch_rejected = 0_u64;
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.section == "__swift5_types")
    {
        match validate_class_dispatch(macho, std::slice::from_ref(descriptor), limits) {
            Ok((mut entries, mut overrides)) => {
                class_dispatch_attempted = class_dispatch_attempted
                    .saturating_add(entries.len() as u64)
                    .saturating_add(overrides.len() as u64);
                class_vtable_entries.append(&mut entries);
                class_overrides.append(&mut overrides);
            }
            Err(error) => {
                let retained = (error.retained_vtable_entries.len() as u64)
                    .saturating_add(error.retained_overrides.len() as u64);
                class_dispatch_attempted = class_dispatch_attempted.saturating_add(error.attempted);
                class_dispatch_rejected = class_dispatch_rejected
                    .saturating_add(error.attempted.saturating_sub(retained));
                class_vtable_entries.extend(error.retained_vtable_entries);
                class_overrides.extend(error.retained_overrides);
                structural_gaps.push(*error.gap);
            }
        }
    }
    let class_dispatch_entries = Some(class_dispatch_attempted);
    let total_entries =
        match class_dispatch_entries.and_then(|count| total_entries.checked_add(count)) {
            Some(total) if total <= limits.max_observations => total,
            _ => {
                return rejected(
                    u64::MAX,
                    "swift_structural_budget_exceeded",
                    Some("__swift5_types".into()),
                    "Swift class-dispatch observations exceed the selected limit",
                );
            }
        };
    let (validated_conformances, conformance_rejection) =
        match validate_conformance_list(macho, limits) {
            Ok(conformances) => (conformances, None),
            Err(gap) => (Vec::new(), Some(gap)),
        };
    let conditional_requirement_entries = match validated_conformances
        .iter()
        .try_fold(0_u64, |count, conformance| {
            count.checked_add(conformance.conditional_requirements.len() as u64)
        }) {
        Some(count) => count,
        None => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_proto".into()),
                "Swift conditional requirement observation count overflowed",
            );
        }
    };
    let total_entries = match total_entries.checked_add(conditional_requirement_entries) {
        Some(total) if total <= limits.max_observations => total,
        _ => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_proto".into()),
                "Swift conditional requirement observations exceed the selected limit",
            );
        }
    };

    let index = match crate::metadata::swift::SwiftTypeIndex::build_with_demangler(
        macho,
        &NoSymbolDemangler,
    ) {
        Ok(index) => index,
        Err(error) => {
            return rejected(
                total_entries,
                "swift_metadata_malformed",
                None,
                format!("revision-pinned Swift decoder rejected the selected image: {error}"),
            );
        }
    };
    let field_entries = match index.types.iter().try_fold(0_u64, |count, swift_type| {
        count.checked_add(
            swift_type
                .fields
                .as_ref()
                .map_or(0, |fields| fields.len() as u64),
        )
    }) {
        Some(count) => count,
        None => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_fieldmd".into()),
                "Swift field observation count overflowed",
            );
        }
    };
    let total_entries = match total_entries.checked_add(field_entries) {
        Some(total) if total <= limits.max_observations => total,
        _ => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_fieldmd".into()),
                "Swift field observations exceed the selected limit",
            );
        }
    };
    let mut decoded = BTreeMap::new();
    for swift_type in &index.types {
        if !matches!(swift_type.source, SwiftTypeSource::SwiftMetadata) {
            continue;
        }
        let Some(address) = swift_type.address else {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                None,
                "metadata-defined Swift type has no descriptor coordinate",
            );
        };
        if decoded.insert(address, swift_type).is_some() {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                None,
                "revision-pinned decoder merged duplicate descriptor coordinates",
            );
        }
    }
    if decoded.len() as u64 != nominal_entries {
        return rejected(
            total_entries,
            "swift_decoder_record_lost",
            None,
            "validated descriptor count differs from revision-pinned decoder output",
        );
    }

    let mut decoded_conformances = BTreeMap::new();
    for conformance in &index.conformances {
        if decoded_conformances
            .insert(conformance.address, conformance)
            .is_some()
        {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                Some("__swift5_proto".into()),
                "revision-pinned decoder merged duplicate conformance coordinates",
            );
        }
    }
    if conformance_rejection.is_none() && decoded_conformances.len() as u64 != conformance_entries {
        return rejected(
            total_entries,
            "swift_decoder_record_lost",
            Some("__swift5_proto".into()),
            "validated conformance count differs from revision-pinned decoder output",
        );
    }

    let mut decoded_associated_types = BTreeMap::new();
    for associated_type in &index.associated_types {
        if decoded_associated_types
            .insert(associated_type.address, associated_type)
            .is_some()
        {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                Some("__swift5_assocty".into()),
                "revision-pinned decoder merged duplicate associated-type coordinates",
            );
        }
    }
    if decoded_associated_types.len() != validated_associated_types.len() {
        return rejected(
            total_entries,
            "swift_decoder_record_lost",
            Some("__swift5_assocty".into()),
            "validated associated-type count differs from revision-pinned decoder output",
        );
    }

    let parents = index
        .parents
        .iter()
        .map(|parent| (parent.descriptor_address, parent.parent_descriptor_address))
        .collect::<BTreeMap<_, _>>();
    let mut records = Vec::with_capacity(descriptors.len());
    for descriptor in descriptors {
        let Some(swift_type) = decoded.remove(&descriptor.address) else {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                Some(descriptor.section),
                format!(
                    "validated record {} disappeared during decoding",
                    descriptor.index
                ),
            );
        };
        let kind = match swift_type.kind {
            SwiftTypeKind::Class => MachoSwiftNominalKindV1::Class,
            SwiftTypeKind::Struct => MachoSwiftNominalKindV1::Struct,
            SwiftTypeKind::Enum => MachoSwiftNominalKindV1::Enum,
            SwiftTypeKind::Protocol => MachoSwiftNominalKindV1::Protocol,
            _ => {
                return rejected(
                    total_entries,
                    "swift_metadata_unsupported",
                    Some(descriptor.section),
                    format!(
                        "record {} has an unsupported nominal kind",
                        descriptor.index
                    ),
                );
            }
        };
        let fields = swift_type
            .fields
            .as_deref()
            .unwrap_or_default()
            .iter()
            .enumerate()
            .map(|(ordinal, field)| {
                let raw = macho
                    .read_bytes_at_va(
                        Va(field.record_address),
                        usize::try_from(field.record_size).map_err(|_| {
                            "Swift field record size exceeds the host address space".to_owned()
                        })?,
                    )
                    .map_err(|error| {
                        format!("Swift field record is outside the selected image: {error}")
                    })?;
                Ok(MachoSwiftFieldRecordV1 {
                    record_va: field.record_address,
                    record_size: field.record_size,
                    ordinal: u32::try_from(ordinal)
                        .map_err(|_| "Swift field ordinal exceeds UInt32".to_owned())?,
                    name: field.name.clone(),
                    mangled_type: field.mangled_type.clone(),
                    resolved_type_name: field.type_name.clone(),
                    flags: field.flags,
                    raw_sha256: EvidenceDigest::of(raw),
                })
            })
            .collect::<Result<Vec<_>, String>>();
        let fields = match fields {
            Ok(fields) => fields,
            Err(error) => {
                return rejected(
                    total_entries,
                    "swift_metadata_malformed",
                    Some(descriptor.section),
                    error,
                );
            }
        };
        records.push(MachoSwiftRecordV1 {
            descriptor_va: descriptor.address,
            parent_descriptor_va: parents.get(&descriptor.address).copied(),
            kind,
            qualified_name: swift_type.name.clone(),
            fields,
            raw_sha256: descriptor.raw_sha256,
        });
    }
    records.sort_by_key(|record| record.descriptor_va);
    let mut conformances = Vec::with_capacity(validated_conformances.len());
    for validated_conformance in validated_conformances {
        let Some(conformance) = decoded_conformances.remove(&validated_conformance.address) else {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                Some(validated_conformance.section),
                format!(
                    "validated conformance {} disappeared during decoding",
                    validated_conformance.index
                ),
            );
        };
        let witness_table_pattern = if let Some(pattern_va) =
            validated_conformance.witness_table_pattern_va
        {
            let Some(protocol_descriptor_va) = conformance.protocol_address else {
                return rejected(
                    total_entries,
                    "swift_metadata_malformed",
                    Some("__swift5_proto".into()),
                    "Swift witness-table pattern has no resolved protocol owner",
                );
            };
            let requirements = protocol_requirements
                .iter()
                .filter(|requirement| requirement.protocol_descriptor_va == protocol_descriptor_va)
                .collect::<Vec<_>>();
            match decode_evidence_witness_table_pattern(
                macho,
                validated_conformance.address,
                pattern_va,
                &requirements,
                limits,
            ) {
                Ok(pattern) => Some(pattern),
                Err(error) => {
                    let attempted = total_entries
                        .saturating_add(1)
                        .saturating_add(requirements.len() as u64);
                    return rejected(
                        attempted,
                        "swift_metadata_malformed",
                        Some("__swift5_proto".into()),
                        format!("Swift witness-table pattern is invalid: {error}"),
                    );
                }
            }
        } else {
            None
        };
        conformances.push(MachoSwiftConformanceRecordV1 {
            descriptor_va: validated_conformance.address,
            flags: validated_conformance.flags,
            conditional_requirement_count: validated_conformance.conditional_requirement_count,
            conditional_requirements: validated_conformance.conditional_requirements,
            protocol_descriptor_va: conformance.protocol_address,
            protocol_name: conformance.protocol_name.clone(),
            conforming_type_descriptor_va: conformance.conforming_type_address,
            conforming_type_name: conformance.conforming_type_name.clone(),
            witness_table_pattern_va: validated_conformance.witness_table_pattern_va,
            witness_table_pattern,
            raw_sha256: validated_conformance.raw_sha256,
        });
    }
    conformances.sort_by_key(|record| record.descriptor_va);
    let witness_pattern_entries = match conformances.iter().try_fold(0_u64, |count, conformance| {
        if let Some(pattern) = &conformance.witness_table_pattern {
            count
                .checked_add(1)
                .and_then(|value| value.checked_add(pattern.entries.len() as u64))
        } else {
            Some(count)
        }
    }) {
        Some(count) => count,
        None => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_proto".into()),
                "Swift witness-pattern observation count overflowed",
            );
        }
    };
    let total_entries = match total_entries.checked_add(witness_pattern_entries) {
        Some(total) if total <= limits.max_observations => total,
        _ => {
            return rejected(
                u64::MAX,
                "swift_structural_budget_exceeded",
                Some("__swift5_proto".into()),
                "Swift witness-pattern observations exceed the selected limit",
            );
        }
    };
    let mut associated_types = Vec::with_capacity(validated_associated_types.len());
    for validated_associated_type in validated_associated_types {
        let Some(associated_type) =
            decoded_associated_types.remove(&validated_associated_type.address)
        else {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                Some("__swift5_assocty".into()),
                "validated associated-type descriptor disappeared during decoding",
            );
        };
        if associated_type.byte_len != validated_associated_type.byte_len
            || associated_type.conforming_type_name.as_deref()
                != Some(
                    validated_associated_type
                        .conforming_type_mangling
                        .as_slice(),
                )
            || associated_type.protocol_type_name.as_deref()
                != Some(validated_associated_type.protocol_type_mangling.as_slice())
            || associated_type.records.len() != validated_associated_type.records.len()
            || associated_type
                .records
                .iter()
                .zip(&validated_associated_type.records)
                .any(|(decoded, validated)| {
                    decoded.record_address != validated.record_va
                        || decoded.record_size != validated.record_size
                        || decoded.name.as_deref() != Some(validated.name.as_str())
                        || decoded.substituted_type_name.as_deref()
                            != Some(validated.substituted_type_mangling.as_slice())
                })
        {
            return rejected(
                total_entries,
                "swift_decoder_record_lost",
                Some("__swift5_assocty".into()),
                "revision-pinned decoder changed associated-type descriptor evidence",
            );
        }
        associated_types.push(MachoSwiftAssociatedTypeDescriptorV1 {
            descriptor_va: validated_associated_type.address,
            byte_len: validated_associated_type.byte_len,
            conforming_type_mangling: validated_associated_type.conforming_type_mangling,
            resolved_conforming_type_name: associated_type.resolved_conforming_type_name.clone(),
            resolved_conforming_type_descriptor_va: associated_type
                .resolved_conforming_type_descriptor_address,
            protocol_type_mangling: validated_associated_type.protocol_type_mangling,
            records: validated_associated_type.records,
            raw_sha256: validated_associated_type.raw_sha256,
        });
    }
    associated_types.sort_by_key(|record| record.descriptor_va);
    let mut gaps = structural_gaps;
    let mut unknown = structural_unknown.saturating_add(class_dispatch_rejected);
    let conformance_status = if let Some(gap) = conformance_rejection {
        gaps.push(gap);
        unknown = unknown.saturating_add(conformance_entries);
        SwiftCollectorStatusV1::Rejected
    } else if conformance_entries == 0 && conditional_requirement_entries == 0 {
        SwiftCollectorStatusV1::Absent
    } else {
        SwiftCollectorStatusV1::Complete
    };
    let class_dispatch_status = if class_dispatch_rejected != 0 {
        SwiftCollectorStatusV1::Rejected
    } else if class_dispatch_entries == Some(0) {
        SwiftCollectorStatusV1::Absent
    } else {
        SwiftCollectorStatusV1::Complete
    };
    let outcome = if gaps.is_empty() {
        SwiftDecodeOutcomeV1::Complete
    } else {
        SwiftDecodeOutcomeV1::Rejected
    };
    let protocol_requirements_empty =
        protocol_requirements.is_empty() && protocol_signature_requirements.is_empty();
    validated(SwiftDecodeBatchV1 {
        outcome,
        conservation: SwiftObservationConservationV1 {
            attempted: total_entries,
            included: total_entries.saturating_sub(unknown),
            unknown,
            excluded: 0,
        },
        records,
        conformances,
        associated_types,
        protocol_requirements,
        protocol_signature_requirements,
        class_vtable_entries,
        class_overrides,
        gaps,
        collector_outcomes: vec![
            collector(
                "nominal_descriptors",
                if nominal_entries == 0 {
                    SwiftCollectorStatusV1::Absent
                } else {
                    SwiftCollectorStatusV1::Complete
                },
                nominal_entries,
            ),
            collector(
                "conformances",
                conformance_status,
                conformance_entries.saturating_add(conditional_requirement_entries),
            ),
            collector(
                "associated_types",
                if associated_type_entries == 0 {
                    SwiftCollectorStatusV1::Absent
                } else {
                    SwiftCollectorStatusV1::Complete
                },
                associated_type_entries,
            ),
            collector(
                "protocol_requirements",
                if structural_unknown != 0 {
                    SwiftCollectorStatusV1::Rejected
                } else if protocol_requirements_empty {
                    SwiftCollectorStatusV1::Absent
                } else {
                    SwiftCollectorStatusV1::Complete
                },
                protocol_requirement_attempted,
            ),
            collector(
                "witness_patterns",
                if witness_pattern_entries == 0 {
                    SwiftCollectorStatusV1::Absent
                } else {
                    SwiftCollectorStatusV1::Complete
                },
                witness_pattern_entries,
            ),
            collector(
                "class_dispatch",
                class_dispatch_status,
                class_dispatch_entries.unwrap_or(u64::MAX),
            ),
        ],
    })
}
