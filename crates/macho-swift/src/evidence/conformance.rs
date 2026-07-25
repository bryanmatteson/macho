use super::*;

pub(super) fn validate_conformance_list(
    macho: &MachoFile<'_>,
    limits: &SwiftEvidenceLimits,
) -> Result<Vec<ValidatedConformance>, SwiftDecodeGapV1> {
    let mut conformances = Vec::new();
    for section in macho
        .all_sections()
        .filter(|section| section.section_name().as_str_lossy() == "__swift5_proto")
    {
        let section_name = section.section_name().as_str_lossy().into_owned();
        if section.size() % 4 != 0 {
            return Err(gap(
                "swift_metadata_malformed",
                &section_name,
                None,
                "Swift conformance list has a truncated relative pointer",
            ));
        }
        let bytes = macho
            .read_bytes_at(section.offset(), section.size() as usize)
            .map_err(|error| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    None,
                    format!("Swift conformance list is unreadable: {error}"),
                )
            })?;
        for (index, chunk) in bytes.chunks_exact(4).enumerate() {
            if conformances.len() as u64 >= limits.max_conformances {
                return Err(gap(
                    "swift_structural_budget_exceeded",
                    &section_name,
                    Some(index as u64),
                    "Swift conformance count exceeds the selected limit",
                ));
            }
            let relative = macho.endian().read_i32(chunk.try_into().map_err(|_| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    "Swift conformance pointer has the wrong width",
                )
            })?);
            let entry = section
                .addr()
                .0
                .checked_add((index as u64).checked_mul(4).ok_or_else(|| {
                    gap(
                        "swift_structural_budget_exceeded",
                        &section_name,
                        Some(index as u64),
                        "Swift conformance-list coordinate overflowed",
                    )
                })?)
                .ok_or_else(|| {
                    gap(
                        "swift_metadata_malformed",
                        &section_name,
                        Some(index as u64),
                        "Swift conformance-list coordinate overflowed",
                    )
                })?;
            let address = resolve_relative_indirect(macho, entry, relative).ok_or_else(|| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    "Swift conformance descriptor pointer is invalid",
                )
            })?;
            let descriptor = macho.read_bytes_at_va(Va(address), 16).map_err(|error| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    format!("Swift conformance descriptor is unreadable: {error}"),
                )
            })?;
            validate_conformance_protocol_reference(
                macho,
                address,
                descriptor,
                limits,
                &section_name,
                index as u64,
            )?;
            validate_conforming_type_reference(
                macho,
                address,
                descriptor,
                limits,
                &section_name,
                index as u64,
            )?;
            let flags = macho.endian().read_u32(
                descriptor[12..16]
                    .try_into()
                    .expect("Swift conformance flags"),
            );
            let conditional_requirement_count = ((flags >> 8) & 0xff) as u8;
            let conditional_requirements = validate_conditional_requirements(
                macho,
                address,
                conditional_requirement_count,
                limits,
                &section_name,
                index as u64,
            )?;
            let witness_relative = macho.endian().read_i32(
                descriptor[8..12]
                    .try_into()
                    .expect("Swift witness-table pattern pointer"),
            );
            let witness_table_pattern_va = if witness_relative == 0 {
                None
            } else {
                let field = address.checked_add(8).ok_or_else(|| {
                    gap(
                        "swift_metadata_malformed",
                        &section_name,
                        Some(index as u64),
                        "Swift witness-table pattern field coordinate overflowed",
                    )
                })?;
                let pattern = add_signed(field, witness_relative).ok_or_else(|| {
                    gap(
                        "swift_metadata_malformed",
                        &section_name,
                        Some(index as u64),
                        "Swift witness-table pattern pointer overflowed",
                    )
                })?;
                let pointer_width = if macho.is_64bit() { 8 } else { 4 };
                macho
                    .read_bytes_at_va(Va(pattern), pointer_width)
                    .map_err(|error| {
                        gap(
                            "swift_metadata_malformed",
                            &section_name,
                            Some(index as u64),
                            format!("Swift witness-table pattern is unmapped: {error}"),
                        )
                    })?;
                Some(pattern)
            };
            conformances.push(ValidatedConformance {
                section: section_name.clone(),
                index: index as u64,
                address,
                flags,
                conditional_requirement_count,
                conditional_requirements,
                witness_table_pattern_va,
                raw_sha256: EvidenceDigest::of(descriptor),
            });
        }
    }
    Ok(conformances)
}

fn validate_conformance_protocol_reference(
    macho: &MachoFile<'_>,
    descriptor_address: u64,
    descriptor: &[u8],
    limits: &SwiftEvidenceLimits,
    section: &str,
    index: u64,
) -> Result<(), SwiftDecodeGapV1> {
    let relative = macho.endian().read_i32(
        descriptor[0..4]
            .try_into()
            .expect("protocol relative pointer"),
    );
    let protocol =
        resolve_relative_indirect(macho, descriptor_address, relative).ok_or_else(|| {
            gap(
                "swift_metadata_malformed",
                section,
                Some(index),
                "Swift conformance protocol reference is invalid",
            )
        })?;
    let protocol_descriptor = macho.read_bytes_at_va(Va(protocol), 20).map_err(|error| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            format!("Swift conformance protocol descriptor is unreadable: {error}"),
        )
    })?;
    let flags = macho.endian().read_u32(
        protocol_descriptor[0..4]
            .try_into()
            .expect("protocol descriptor flags"),
    );
    if flags & 0x1f != 3 {
        return Err(gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift conformance protocol reference does not name a protocol descriptor",
        ));
    }
    validate_name(macho, protocol, protocol_descriptor, limits, section, index)
}

fn validate_conditional_requirements(
    macho: &MachoFile<'_>,
    conformance_address: u64,
    count: u8,
    limits: &SwiftEvidenceLimits,
    section: &str,
    conformance_index: u64,
) -> Result<Vec<MachoSwiftConditionalRequirementV1>, SwiftDecodeGapV1> {
    if u64::from(count) > limits.max_observations {
        return Err(gap(
            "swift_structural_budget_exceeded",
            section,
            Some(conformance_index),
            "Swift conditional requirements exceed the observation limit",
        ));
    }
    let first = conformance_address.checked_add(16).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(conformance_index),
            "Swift conditional requirement coordinate overflowed",
        )
    })?;
    let mut requirements = Vec::with_capacity(usize::from(count));
    for requirement_index in 0..u32::from(count) {
        let descriptor_va = first
            .checked_add(
                u64::from(requirement_index)
                    .checked_mul(12)
                    .ok_or_else(|| {
                        gap(
                            "swift_structural_budget_exceeded",
                            section,
                            Some(conformance_index),
                            "Swift conditional requirement offset overflowed",
                        )
                    })?,
            )
            .ok_or_else(|| {
                gap(
                    "swift_metadata_malformed",
                    section,
                    Some(conformance_index),
                    "Swift conditional requirement address overflowed",
                )
            })?;
        let raw = macho
            .read_bytes_at_va(Va(descriptor_va), 12)
            .map_err(|error| {
                gap(
                    "swift_metadata_malformed",
                    section,
                    Some(conformance_index),
                    format!("Swift conditional requirement is unreadable: {error}"),
                )
            })?;
        let flags = macho
            .endian()
            .read_u32(raw[0..4].try_into().expect("generic requirement flags"));
        let kind = match flags & 0x1f {
            0 => MachoSwiftGenericRequirementKindV1::Protocol,
            1 => MachoSwiftGenericRequirementKindV1::SameType,
            2 => MachoSwiftGenericRequirementKindV1::BaseClass,
            3 => MachoSwiftGenericRequirementKindV1::SameConformance,
            0x1f => MachoSwiftGenericRequirementKindV1::Layout,
            value => {
                return Err(gap(
                    "swift_metadata_unsupported",
                    section,
                    Some(conformance_index),
                    format!("Swift conditional requirement kind {value:#x} is unsupported"),
                ));
            }
        };
        let parameter_field = descriptor_va.checked_add(4).ok_or_else(|| {
            gap(
                "swift_metadata_malformed",
                section,
                Some(conformance_index),
                "Swift conditional parameter field overflowed",
            )
        })?;
        let parameter_relative = macho.endian().read_i32(
            raw[4..8]
                .try_into()
                .expect("generic requirement parameter pointer"),
        );
        if parameter_relative == 0 {
            return Err(gap(
                "swift_metadata_malformed",
                section,
                Some(conformance_index),
                "Swift conditional parameter pointer is null",
            ));
        }
        let parameter_mangling_va =
            add_signed(parameter_field, parameter_relative).ok_or_else(|| {
                gap(
                    "swift_metadata_malformed",
                    section,
                    Some(conformance_index),
                    "Swift conditional parameter pointer overflowed",
                )
            })?;
        let parameter_mangling = read_bounded_mangled_name(
            macho,
            parameter_mangling_va,
            limits,
            section,
            conformance_index,
        )?;
        let constraint_field = descriptor_va.checked_add(8).ok_or_else(|| {
            gap(
                "swift_metadata_malformed",
                section,
                Some(conformance_index),
                "Swift conditional constraint field overflowed",
            )
        })?;
        let constraint_relative = macho.endian().read_i32(
            raw[8..12]
                .try_into()
                .expect("generic requirement constraint"),
        );
        let direct_constraint = || {
            if constraint_relative == 0 {
                return Err(gap(
                    "swift_metadata_malformed",
                    section,
                    Some(conformance_index),
                    "Swift conditional constraint pointer is null",
                ));
            }
            add_signed(constraint_field, constraint_relative).ok_or_else(|| {
                gap(
                    "swift_metadata_malformed",
                    section,
                    Some(conformance_index),
                    "Swift conditional constraint pointer overflowed",
                )
            })
        };
        let constraint = match kind {
            MachoSwiftGenericRequirementKindV1::Protocol => {
                let descriptor_va =
                    resolve_relative_indirect(macho, constraint_field, constraint_relative)
                        .ok_or_else(|| {
                            gap(
                                "swift_metadata_malformed",
                                section,
                                Some(conformance_index),
                                "Swift conditional protocol constraint is invalid",
                            )
                        })?;
                let descriptor =
                    macho
                        .read_bytes_at_va(Va(descriptor_va), 20)
                        .map_err(|error| {
                            gap(
                                "swift_metadata_malformed",
                                section,
                                Some(conformance_index),
                                format!("Swift conditional protocol is unreadable: {error}"),
                            )
                        })?;
                let descriptor_flags = macho.endian().read_u32(
                    descriptor[0..4]
                        .try_into()
                        .expect("conditional protocol descriptor flags"),
                );
                if descriptor_flags & 0x1f != 3 {
                    return Err(gap(
                        "swift_metadata_malformed",
                        section,
                        Some(conformance_index),
                        "Swift conditional protocol constraint has the wrong descriptor kind",
                    ));
                }
                MachoSwiftGenericRequirementConstraintV1::Protocol { descriptor_va }
            }
            MachoSwiftGenericRequirementKindV1::SameType => {
                let type_mangling_va = direct_constraint()?;
                MachoSwiftGenericRequirementConstraintV1::SameType {
                    type_mangling_va,
                    type_mangling: read_bounded_mangled_name(
                        macho,
                        type_mangling_va,
                        limits,
                        section,
                        conformance_index,
                    )?,
                }
            }
            MachoSwiftGenericRequirementKindV1::BaseClass => {
                let type_mangling_va = direct_constraint()?;
                MachoSwiftGenericRequirementConstraintV1::BaseClass {
                    type_mangling_va,
                    type_mangling: read_bounded_mangled_name(
                        macho,
                        type_mangling_va,
                        limits,
                        section,
                        conformance_index,
                    )?,
                }
            }
            MachoSwiftGenericRequirementKindV1::SameConformance => {
                let descriptor_va = direct_constraint()?;
                macho
                    .read_bytes_at_va(Va(descriptor_va), 16)
                    .map_err(|error| {
                        gap(
                            "swift_metadata_malformed",
                            section,
                            Some(conformance_index),
                            format!("Swift same-conformance descriptor is unreadable: {error}"),
                        )
                    })?;
                MachoSwiftGenericRequirementConstraintV1::SameConformance { descriptor_va }
            }
            MachoSwiftGenericRequirementKindV1::Layout => {
                MachoSwiftGenericRequirementConstraintV1::Layout {
                    layout_kind: macho.endian().read_u32(
                        raw[8..12]
                            .try_into()
                            .expect("generic requirement layout kind"),
                    ),
                }
            }
        };
        requirements.push(MachoSwiftConditionalRequirementV1 {
            requirement_index,
            descriptor_va,
            flags,
            kind,
            parameter_mangling_va,
            parameter_mangling,
            constraint,
            raw_sha256: EvidenceDigest::of(raw),
        });
    }
    Ok(requirements)
}
