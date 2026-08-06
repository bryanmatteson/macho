use super::*;

pub(super) fn validate_associated_types(
    macho: &MachoFile<'_>,
    limits: &SwiftEvidenceLimits,
) -> Result<Vec<ValidatedAssociatedType>, AssociatedTypeValidationError> {
    let mut descriptors = Vec::new();
    let mut attempted = 0_u64;
    for section in macho
        .all_sections()
        .filter(|section| section.section_name().as_str_lossy() == "__swift5_assocty")
    {
        let section_bytes = macho
            .read_bytes_at(section.offset(), section.size() as usize)
            .map_err(|error| {
                associated_error(
                    attempted.saturating_add(1),
                    None,
                    format!("Swift associated-type section is unreadable: {error}"),
                )
            })?;
        let mut cursor = 0_usize;
        let mut descriptor_index = 0_u64;
        while cursor < section_bytes.len() {
            attempted = attempted.checked_add(1).ok_or_else(|| {
                associated_error(
                    u64::MAX,
                    Some(descriptor_index),
                    "Swift associated-type observation count overflowed",
                )
            })?;
            let header_end = cursor.checked_add(16).ok_or_else(|| {
                associated_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type header coordinate overflowed",
                )
            })?;
            let header = section_bytes.get(cursor..header_end).ok_or_else(|| {
                associated_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type descriptor header is truncated",
                )
            })?;
            let count = u64::from(
                macho.endian().read_u32(
                    header[8..12]
                        .try_into()
                        .expect("associated-type record count"),
                ),
            );
            let record_size = u64::from(
                macho.endian().read_u32(
                    header[12..16]
                        .try_into()
                        .expect("associated-type record size"),
                ),
            );
            if record_size < 8 {
                return Err(associated_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type descriptor has an invalid record size",
                ));
            }
            if count > limits.max_protocol_requirements {
                return Err(associated_budget_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type record count exceeds the selected limit",
                ));
            }
            let records_bytes = count.checked_mul(record_size).ok_or_else(|| {
                associated_budget_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type record byte length overflowed",
                )
            })?;
            let descriptor_len = 16_u64.checked_add(records_bytes).ok_or_else(|| {
                associated_budget_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type descriptor byte length overflowed",
                )
            })?;
            let descriptor_len_usize = usize::try_from(descriptor_len).map_err(|_| {
                associated_budget_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type descriptor length does not fit the host",
                )
            })?;
            let descriptor_end = cursor.checked_add(descriptor_len_usize).ok_or_else(|| {
                associated_budget_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type descriptor coordinate overflowed",
                )
            })?;
            let descriptor = section_bytes.get(cursor..descriptor_end).ok_or_else(|| {
                associated_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type records are truncated",
                )
            })?;
            let address = section.addr().0.checked_add(cursor as u64).ok_or_else(|| {
                associated_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type descriptor address overflowed",
                )
            })?;
            let conforming_type_mangling = read_relative_bounded_bytes(
                macho,
                address,
                &header[0..4],
                limits.max_mangling_bytes,
                true,
                attempted,
                descriptor_index,
                "conforming type",
            )?;
            let protocol_field = address.checked_add(4).ok_or_else(|| {
                associated_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type protocol field address overflowed",
                )
            })?;
            let protocol_type_mangling = read_relative_bounded_bytes(
                macho,
                protocol_field,
                &header[4..8],
                limits.max_mangling_bytes,
                true,
                attempted,
                descriptor_index,
                "protocol type",
            )?;
            let mut records = Vec::with_capacity(usize::try_from(count).map_err(|_| {
                associated_budget_error(
                    attempted,
                    Some(descriptor_index),
                    "Swift associated-type record count does not fit the host",
                )
            })?);
            for record_index in 0..count {
                attempted = attempted.checked_add(1).ok_or_else(|| {
                    associated_budget_error(
                        u64::MAX,
                        Some(descriptor_index),
                        "Swift associated-type observation count overflowed",
                    )
                })?;
                if attempted > limits.max_observations {
                    return Err(associated_budget_error(
                        attempted,
                        Some(descriptor_index),
                        "Swift associated-type observations exceed the selected limit",
                    ));
                }
                let record_offset = 16_u64
                    .checked_add(record_index.checked_mul(record_size).ok_or_else(|| {
                        associated_budget_error(
                            attempted,
                            Some(descriptor_index),
                            "Swift associated-type record coordinate overflowed",
                        )
                    })?)
                    .ok_or_else(|| {
                        associated_budget_error(
                            attempted,
                            Some(descriptor_index),
                            "Swift associated-type record coordinate overflowed",
                        )
                    })?;
                let record_offset_usize = usize::try_from(record_offset).map_err(|_| {
                    associated_budget_error(
                        attempted,
                        Some(descriptor_index),
                        "Swift associated-type record coordinate does not fit the host",
                    )
                })?;
                let record = descriptor
                    .get(record_offset_usize..record_offset_usize + 8)
                    .ok_or_else(|| {
                        associated_error(
                            attempted,
                            Some(descriptor_index),
                            "Swift associated-type record is truncated",
                        )
                    })?;
                let record_address = address.checked_add(record_offset).ok_or_else(|| {
                    associated_error(
                        attempted,
                        Some(descriptor_index),
                        "Swift associated-type record address overflowed",
                    )
                })?;
                let name_bytes = read_relative_bounded_bytes(
                    macho,
                    record_address,
                    &record[0..4],
                    limits.max_identifier_bytes,
                    false,
                    attempted,
                    descriptor_index,
                    "requirement name",
                )?;
                let name = String::from_utf8(name_bytes).map_err(|_| {
                    associated_error(
                        attempted,
                        Some(descriptor_index),
                        "Swift associated-type requirement name is not UTF-8",
                    )
                })?;
                let substituted_field = record_address.checked_add(4).ok_or_else(|| {
                    associated_error(
                        attempted,
                        Some(descriptor_index),
                        "Swift associated-type substitution field address overflowed",
                    )
                })?;
                let substituted_type_mangling = read_relative_bounded_bytes(
                    macho,
                    substituted_field,
                    &record[4..8],
                    limits.max_mangling_bytes,
                    true,
                    attempted,
                    descriptor_index,
                    "substituted type",
                )?;
                records.push(MachoSwiftAssociatedTypeRecordV1 {
                    record_va: record_address,
                    record_size: u32::try_from(record_size).map_err(|_| {
                        associated_budget_error(
                            attempted,
                            Some(descriptor_index),
                            "Swift associated-type record size exceeds u32",
                        )
                    })?,
                    name,
                    substituted_type_mangling,
                    raw_sha256: EvidenceDigest::of(
                        descriptor
                            .get(
                                record_offset_usize
                                    ..record_offset_usize
                                        + usize::try_from(record_size).map_err(|_| {
                                            associated_budget_error(
                                                attempted,
                                                Some(descriptor_index),
                                                "Swift associated-type record size does not fit the host",
                                            )
                                        })?,
                            )
                            .ok_or_else(|| {
                                associated_error(
                                    attempted,
                                    Some(descriptor_index),
                                    "Swift associated-type record extent is truncated",
                                )
                            })?,
                    ),
                });
            }
            descriptors.push(ValidatedAssociatedType {
                address,
                byte_len: u32::try_from(descriptor_len).map_err(|_| {
                    associated_budget_error(
                        attempted,
                        Some(descriptor_index),
                        "Swift associated-type descriptor length exceeds u32",
                    )
                })?,
                conforming_type_mangling,
                protocol_type_mangling,
                records,
                raw_sha256: EvidenceDigest::of(descriptor),
            });
            cursor = descriptor_end;
            descriptor_index = descriptor_index.checked_add(1).ok_or_else(|| {
                associated_budget_error(
                    attempted,
                    None,
                    "Swift associated-type descriptor index overflowed",
                )
            })?;
        }
    }
    Ok(descriptors)
}

#[allow(clippy::too_many_arguments)]
fn read_relative_bounded_bytes(
    macho: &MachoFile<'_>,
    field: u64,
    relative_bytes: &[u8],
    maximum: u64,
    allow_symbolic_references: bool,
    attempted: u64,
    descriptor_index: u64,
    role: &str,
) -> Result<Vec<u8>, AssociatedTypeValidationError> {
    let relative = macho.endian().read_i32(
        relative_bytes
            .try_into()
            .expect("four-byte associated-type relative pointer"),
    );
    if relative == 0 {
        return Err(associated_error(
            attempted,
            Some(descriptor_index),
            format!("Swift associated-type {role} pointer is null"),
        ));
    }
    let address = add_signed(field, relative).ok_or_else(|| {
        associated_error(
            attempted,
            Some(descriptor_index),
            format!("Swift associated-type {role} pointer overflowed"),
        )
    })?;
    let maximum = usize::try_from(maximum).map_err(|_| {
        associated_budget_error(
            attempted,
            Some(descriptor_index),
            format!("Swift associated-type {role} limit does not fit the host"),
        )
    })?;
    let offset = macho
        .address_map()
        .va_to_thin_offset(Va(address))
        .map_err(|error| {
            associated_error(
                attempted,
                Some(descriptor_index),
                format!("Swift associated-type {role} address is unmapped: {error}"),
            )
        })?
        .as_usize();
    let bytes = macho.bytes().get(offset..).ok_or_else(|| {
        associated_error(
            attempted,
            Some(descriptor_index),
            format!("Swift associated-type {role} address is outside the selected image"),
        )
    })?;
    let mut end = 0_usize;
    loop {
        if end >= bytes.len() || end >= maximum {
            return Err(associated_budget_error(
                attempted,
                Some(descriptor_index),
                format!("Swift associated-type {role} exceeds its bound or is unterminated"),
            ));
        }
        match bytes[end] {
            0 => break,
            0x01..=0x0c if allow_symbolic_references => {
                end = end.checked_add(5).ok_or_else(|| {
                    associated_budget_error(
                        attempted,
                        Some(descriptor_index),
                        format!("Swift associated-type {role} length overflowed"),
                    )
                })?;
            }
            _ => end += 1,
        }
    }
    if end == 0 {
        return Err(associated_error(
            attempted,
            Some(descriptor_index),
            format!("Swift associated-type {role} is empty"),
        ));
    }
    Ok(bytes[..end].to_vec())
}

fn associated_error(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> AssociatedTypeValidationError {
    AssociatedTypeValidationError {
        attempted,
        gap: gap(
            "swift_metadata_malformed",
            "__swift5_assocty",
            record_index,
            safe_detail,
        ),
    }
}

fn associated_budget_error(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> AssociatedTypeValidationError {
    AssociatedTypeValidationError {
        attempted,
        gap: gap(
            "swift_structural_budget_exceeded",
            "__swift5_assocty",
            record_index,
            safe_detail,
        ),
    }
}
