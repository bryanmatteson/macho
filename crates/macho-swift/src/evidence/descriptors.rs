use super::*;

pub(super) fn read_bounded_mangled_name(
    macho: &MachoFile<'_>,
    address: u64,
    limits: &SwiftEvidenceLimits,
    section: &str,
    index: u64,
) -> Result<Vec<u8>, SwiftDecodeGapV1> {
    let maximum = usize::try_from(limits.max_mangling_bytes).map_err(|_| {
        gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift mangling limit does not fit the host",
        )
    })?;
    let offset = macho
        .address_map()
        .va_to_thin_offset(Va(address))
        .map_err(|error| {
            gap(
                "swift_metadata_malformed",
                section,
                Some(index),
                format!("Swift mangling address is unmapped: {error}"),
            )
        })?
        .as_usize();
    let bytes = macho.bytes().get(offset..).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift mangling address is outside the selected image",
        )
    })?;
    let Some(length) = bytes.iter().take(maximum).position(|byte| *byte == 0) else {
        return Err(gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift mangling is unterminated or exceeds the selected limit",
        ));
    };
    if length == 0 {
        return Err(gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift mangling is empty",
        ));
    }
    Ok(bytes[..length].to_vec())
}

pub(super) fn validate_conforming_type_reference(
    macho: &MachoFile<'_>,
    descriptor_address: u64,
    descriptor: &[u8],
    limits: &SwiftEvidenceLimits,
    section: &str,
    index: u64,
) -> Result<(), SwiftDecodeGapV1> {
    let relative = macho
        .endian()
        .read_i32(descriptor[4..8].try_into().expect("type relative pointer"));
    let field = descriptor_address.checked_add(4).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift conforming-type field coordinate overflowed",
        )
    })?;
    let tagged = relative as u32;
    let target = add_signed(field, (tagged & !3) as i32).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift conforming-type relative reference overflowed",
        )
    })?;
    match tagged & 3 {
        0 | 1 => {
            let descriptor_address = if tagged & 3 == 1 {
                read_pointer_at(macho, target).ok_or_else(|| {
                    gap(
                        "swift_metadata_malformed",
                        section,
                        Some(index),
                        "Swift indirect conforming-type pointer is unreadable",
                    )
                })?
            } else {
                target
            };
            let nominal = macho
                .read_bytes_at_va(Va(descriptor_address), 20)
                .map_err(|error| {
                    gap(
                        "swift_metadata_malformed",
                        section,
                        Some(index),
                        format!("Swift conforming nominal descriptor is unreadable: {error}"),
                    )
                })?;
            let kind = macho.endian().read_u32(
                nominal[0..4]
                    .try_into()
                    .expect("conforming nominal descriptor flags"),
            ) & 0x1f;
            if !matches!(kind, 16..=18) {
                return Err(gap(
                    "swift_metadata_malformed",
                    section,
                    Some(index),
                    "Swift conformance type reference does not name a nominal descriptor",
                ));
            }
            validate_name(macho, descriptor_address, nominal, limits, section, index)
        }
        2 => validate_bounded_c_string(macho, target, limits, section, index),
        3 => {
            let name = read_pointer_at(macho, target).ok_or_else(|| {
                gap(
                    "swift_metadata_malformed",
                    section,
                    Some(index),
                    "Swift indirect conforming-type name pointer is unreadable",
                )
            })?;
            validate_bounded_c_string(macho, name, limits, section, index)
        }
        _ => unreachable!("two-bit conformance type tag"),
    }
}

pub(super) fn validate_bounded_c_string(
    macho: &MachoFile<'_>,
    address: u64,
    limits: &SwiftEvidenceLimits,
    section: &str,
    index: u64,
) -> Result<(), SwiftDecodeGapV1> {
    let maximum = usize::try_from(limits.max_identifier_bytes).map_err(|_| {
        gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift identifier limit does not fit the host",
        )
    })?;
    let offset = macho
        .address_map()
        .va_to_thin_offset(Va(address))
        .map_err(|error| {
            gap(
                "swift_metadata_malformed",
                section,
                Some(index),
                format!("Swift name address is unmapped: {error}"),
            )
        })?
        .as_usize();
    let bytes = macho.bytes().get(offset..).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift name address is outside the selected image",
        )
    })?;
    let Some(length) = bytes.iter().take(maximum).position(|byte| *byte == 0) else {
        return Err(gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift name is unterminated or exceeds the selected limit",
        ));
    };
    if length == 0 || std::str::from_utf8(&bytes[..length]).is_err() {
        return Err(gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift name is empty or invalid UTF-8",
        ));
    }
    Ok(())
}

pub(super) fn resolve_relative_indirect(
    macho: &MachoFile<'_>,
    field: u64,
    relative: i32,
) -> Option<u64> {
    if relative == 0 {
        return None;
    }
    let tagged = relative as u32;
    let target = add_signed(field, (tagged & !1) as i32)?;
    if tagged & 1 == 0 {
        Some(target)
    } else {
        read_pointer_at(macho, target)
    }
}

fn read_pointer_at(macho: &MachoFile<'_>, address: u64) -> Option<u64> {
    if macho.is_64bit() {
        macho
            .read_bytes_at_va(Va(address), 8)
            .ok()?
            .try_into()
            .ok()
            .map(|bytes| macho.endian().read_u64(bytes))
    } else {
        macho
            .read_bytes_at_va(Va(address), 4)
            .ok()?
            .try_into()
            .ok()
            .map(|bytes| u64::from(macho.endian().read_u32(bytes)))
    }
}

pub(super) fn validate_nominal_lists(
    macho: &MachoFile<'_>,
    limits: &SwiftEvidenceLimits,
) -> Result<Vec<ValidatedDescriptor>, SwiftDecodeGapV1> {
    let mut descriptors = Vec::new();
    for section in macho.all_sections().filter(|section| {
        matches!(
            section.section_name().as_str_lossy().as_ref(),
            "__swift5_types" | "__swift5_protos"
        )
    }) {
        let section_name = section.section_name().as_str_lossy().into_owned();
        if section.size() % 4 != 0 {
            return Err(gap(
                "swift_metadata_malformed",
                &section_name,
                None,
                "Swift descriptor list has a truncated relative pointer",
            ));
        }
        let bytes = macho
            .read_bytes_at(section.offset(), section.size() as usize)
            .map_err(|error| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    None,
                    format!("Swift descriptor list is unreadable: {error}"),
                )
            })?;
        for (index, chunk) in bytes.chunks_exact(4).enumerate() {
            let raw: [u8; 4] = chunk.try_into().map_err(|_| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    "Swift relative pointer has the wrong width",
                )
            })?;
            let relative = macho.endian().read_i32(raw);
            let entry = section
                .addr()
                .0
                .checked_add((index as u64).checked_mul(4).ok_or_else(|| {
                    gap(
                        "swift_structural_budget_exceeded",
                        &section_name,
                        Some(index as u64),
                        "Swift descriptor-list coordinate overflowed",
                    )
                })?)
                .ok_or_else(|| {
                    gap(
                        "swift_metadata_malformed",
                        &section_name,
                        Some(index as u64),
                        "Swift descriptor-list coordinate overflowed",
                    )
                })?;
            let address = add_signed(entry, relative).ok_or_else(|| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    "Swift descriptor relative pointer overflowed",
                )
            })?;
            let descriptor = macho.read_bytes_at_va(Va(address), 20).map_err(|error| {
                gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    format!("Swift descriptor header is unreadable: {error}"),
                )
            })?;
            let flags = macho.endian().read_u32(
                descriptor[0..4]
                    .try_into()
                    .expect("four-byte descriptor flags"),
            );
            let kind = flags & 0x1f;
            let expected_protocol = section_name == "__swift5_protos";
            if (expected_protocol && kind != 3) || (!expected_protocol && !matches!(kind, 16..=18))
            {
                return Err(gap(
                    "swift_metadata_malformed",
                    &section_name,
                    Some(index as u64),
                    "Swift descriptor kind disagrees with its list section",
                ));
            }
            validate_name(
                macho,
                address,
                descriptor,
                limits,
                &section_name,
                index as u64,
            )?;
            validate_field_descriptor(
                macho,
                address,
                descriptor,
                limits,
                &section_name,
                index as u64,
            )?;
            descriptors.push(ValidatedDescriptor {
                section: section_name.clone(),
                index: index as u64,
                address,
                raw_sha256: EvidenceDigest::of(descriptor),
            });
        }
    }
    Ok(descriptors)
}

pub(super) fn validate_name(
    macho: &MachoFile<'_>,
    descriptor_address: u64,
    descriptor: &[u8],
    limits: &SwiftEvidenceLimits,
    section: &str,
    index: u64,
) -> Result<(), SwiftDecodeGapV1> {
    let relative = macho.endian().read_i32(
        descriptor[8..12]
            .try_into()
            .expect("four-byte name pointer"),
    );
    let field = descriptor_address.checked_add(8).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift name field coordinate overflowed",
        )
    })?;
    let address = add_signed(field, relative).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift name relative pointer overflowed",
        )
    })?;
    let maximum = usize::try_from(limits.max_identifier_bytes).map_err(|_| {
        gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift identifier limit does not fit the host",
        )
    })?;
    let bytes = macho.read_bytes_at_va(Va(address), maximum).or_else(|_| {
        let remaining = macho
            .address_map()
            .va_to_thin_offset(Va(address))
            .ok()
            .and_then(|offset| macho.file_size().checked_sub(offset.as_usize()))
            .unwrap_or(0)
            .min(maximum);
        macho.read_bytes_at_va(Va(address), remaining)
    });
    let bytes = bytes.map_err(|error| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            format!("Swift descriptor name is unreadable: {error}"),
        )
    })?;
    let Some(end) = bytes.iter().position(|byte| *byte == 0) else {
        return Err(gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift descriptor name exceeds its bound or is unterminated",
        ));
    };
    if end == 0 || std::str::from_utf8(&bytes[..end]).is_err() {
        return Err(gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift descriptor name is empty or invalid UTF-8",
        ));
    }
    Ok(())
}

fn validate_field_descriptor(
    macho: &MachoFile<'_>,
    descriptor_address: u64,
    descriptor: &[u8],
    limits: &SwiftEvidenceLimits,
    section: &str,
    index: u64,
) -> Result<(), SwiftDecodeGapV1> {
    if section == "__swift5_protos" {
        return Ok(());
    }
    let relative = macho.endian().read_i32(
        descriptor[16..20]
            .try_into()
            .expect("four-byte field pointer"),
    );
    if relative == 0 {
        return Ok(());
    }
    let field = descriptor_address.checked_add(16).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift field-descriptor coordinate overflowed",
        )
    })?;
    let address = add_signed(field, relative).ok_or_else(|| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift field-descriptor relative pointer overflowed",
        )
    })?;
    let header = macho.read_bytes_at_va(Va(address), 16).map_err(|error| {
        gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            format!("Swift field descriptor is unreadable: {error}"),
        )
    })?;
    let record_size = match macho.endian() {
        macho_core::format::io::Endian::Little => u16::from_le_bytes([header[10], header[11]]),
        macho_core::format::io::Endian::Big => u16::from_be_bytes([header[10], header[11]]),
    } as u64;
    let count = macho
        .endian()
        .read_u32(header[12..16].try_into().expect("four-byte field count")) as u64;
    if record_size < 12 || count > limits.max_observations {
        return Err(gap(
            "swift_metadata_malformed",
            section,
            Some(index),
            "Swift field descriptor has an invalid record size or count",
        ));
    }
    let byte_length = count
        .checked_mul(record_size)
        .and_then(|value| value.checked_add(16))
        .ok_or_else(|| {
            gap(
                "swift_structural_budget_exceeded",
                section,
                Some(index),
                "Swift field descriptor byte length overflowed",
            )
        })?;
    let byte_length = usize::try_from(byte_length).map_err(|_| {
        gap(
            "swift_structural_budget_exceeded",
            section,
            Some(index),
            "Swift field descriptor byte length does not fit the host",
        )
    })?;
    macho
        .read_bytes_at_va(Va(address), byte_length)
        .map_err(|error| {
            gap(
                "swift_metadata_malformed",
                section,
                Some(index),
                format!("Swift field records are truncated: {error}"),
            )
        })?;
    Ok(())
}

pub(super) fn add_signed(base: u64, relative: i32) -> Option<u64> {
    let value = i128::from(base).checked_add(i128::from(relative))?;
    u64::try_from(value).ok()
}

pub(super) fn decode_evidence_witness_table_pattern(
    macho: &MachoFile<'_>,
    conformance_descriptor_va: u64,
    pattern_va: u64,
    requirements: &[&MachoSwiftProtocolRequirementRecordV1],
    limits: &SwiftEvidenceLimits,
) -> Result<MachoSwiftWitnessTablePatternV1, String> {
    use crate::strict::{
        StrictWitnessPointerTarget, StrictWitnessRequirement, decode_witness_table_pattern,
    };

    let requirements = requirements
        .iter()
        .map(|requirement| StrictWitnessRequirement {
            requirement_index: requirement.requirement_index,
        })
        .collect::<Vec<_>>();
    let pattern = decode_witness_table_pattern(
        macho,
        conformance_descriptor_va,
        pattern_va,
        &requirements,
        limits.max_dispatch_slots,
    )
    .map_err(|error| error.to_string())?;
    Ok(MachoSwiftWitnessTablePatternV1 {
        pattern_va: pattern.pattern_va,
        conformance_slot_va: pattern.pattern_va,
        conformance_pointer_provenance: evidence_witness_provenance(
            pattern.conformance_pointer_provenance,
        ),
        entries: pattern
            .entries
            .into_iter()
            .map(|entry| MachoSwiftWitnessPatternEntryV1 {
                requirement_index: entry.requirement_index,
                slot_va: entry.slot_va,
                target: match entry.target {
                    StrictWitnessPointerTarget::Address(va) => {
                        MachoSwiftWitnessPointerTargetV1::Resolved { va }
                    }
                    StrictWitnessPointerTarget::Import(symbol) => {
                        MachoSwiftWitnessPointerTargetV1::External { symbol }
                    }
                },
                provenance: evidence_witness_provenance(entry.provenance),
                raw_sha256: EvidenceDigest::of(&entry.raw),
            })
            .collect(),
    })
}

fn evidence_witness_provenance(
    value: crate::strict::StrictWitnessPointerProvenance,
) -> MachoSwiftWitnessPointerProvenanceV1 {
    use crate::strict::StrictWitnessPointerProvenance;

    match value {
        StrictWitnessPointerProvenance::Direct => MachoSwiftWitnessPointerProvenanceV1::Direct,
        StrictWitnessPointerProvenance::ChainedRebase => {
            MachoSwiftWitnessPointerProvenanceV1::ChainedRebase
        }
        StrictWitnessPointerProvenance::ChainedAuthRebase(authentication) => {
            MachoSwiftWitnessPointerProvenanceV1::ChainedAuthRebase {
                diversity: authentication.diversity,
                key: authentication.key,
                address_diversity: authentication.address_diversity,
            }
        }
        StrictWitnessPointerProvenance::ChainedBind => {
            MachoSwiftWitnessPointerProvenanceV1::ChainedBind
        }
        StrictWitnessPointerProvenance::ChainedAuthBind(authentication) => {
            MachoSwiftWitnessPointerProvenanceV1::ChainedAuthBind {
                diversity: authentication.diversity,
                key: authentication.key,
                address_diversity: authentication.address_diversity,
            }
        }
        StrictWitnessPointerProvenance::LegacyRebase => {
            MachoSwiftWitnessPointerProvenanceV1::LegacyRebase
        }
        StrictWitnessPointerProvenance::LegacyBind => {
            MachoSwiftWitnessPointerProvenanceV1::LegacyBind
        }
    }
}

pub(super) fn gap(
    code: &str,
    section: &str,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> SwiftDecodeGapV1 {
    SwiftDecodeGapV1 {
        code: code.into(),
        section: Some(section.into()),
        record_index,
        safe_detail: safe_detail.into(),
    }
}
