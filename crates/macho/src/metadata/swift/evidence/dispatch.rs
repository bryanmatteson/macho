use super::*;

pub(super) fn swift_nominal_list_entry_count(macho: &MachoFile<'_>) -> u64 {
    macho
        .all_sections()
        .filter(|section| {
            matches!(
                section.section_name().as_str_lossy().as_ref(),
                "__swift5_types" | "__swift5_protos"
            )
        })
        .fold(0_u64, |count, section| {
            count.saturating_add(section.size().div_ceil(4))
        })
}

pub(super) fn swift_conformance_list_entry_count(macho: &MachoFile<'_>) -> u64 {
    macho
        .all_sections()
        .filter(|section| section.section_name().as_str_lossy() == "__swift5_proto")
        .fold(0_u64, |count, section| {
            count.saturating_add(section.size().div_ceil(4))
        })
}

pub(super) fn validate_class_dispatch(
    macho: &MachoFile<'_>,
    descriptors: &[ValidatedDescriptor],
    limits: &SwiftEvidenceLimits,
) -> Result<
    (
        Vec<MachoSwiftClassVtableEntryV1>,
        Vec<MachoSwiftClassOverrideRecordV1>,
    ),
    ClassDispatchValidationError,
> {
    const HAS_VTABLE: u32 = 0x8000_0000;
    const HAS_OVERRIDE_TABLE: u32 = 0x4000_0000;
    const HAS_RESILIENT_SUPERCLASS: u32 = 0x2000_0000;
    const METADATA_INITIALIZATION_MASK: u32 = 0x0003_0000;
    const IS_GENERIC: u32 = 0x80;

    let mut vtable_entries = Vec::new();
    let mut overrides = Vec::new();
    let mut attempted = 0_u64;
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.section == "__swift5_types")
    {
        let header = macho
            .read_bytes_at_va(Va(descriptor.address), 44)
            .map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    format!("Swift class descriptor is truncated: {error}"),
                )
            })?;
        let flags = macho.endian().read_u32(
            header[0..4]
                .try_into()
                .expect("Swift context descriptor flags"),
        );
        if flags & 0x1f != 16 {
            continue;
        }
        if flags & (IS_GENERIC | HAS_RESILIENT_SUPERCLASS | METADATA_INITIALIZATION_MASK) != 0 {
            if flags & (HAS_VTABLE | HAS_OVERRIDE_TABLE) == 0 {
                // These flags change the trailing class layout, but there is
                // no dispatch payload to locate when both dispatch-presence
                // bits are clear.
                continue;
            }
            let mut error = class_dispatch_unsupported(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "generic, resilient-superclass, or metadata-initialized class layout is not yet admitted",
            );
            error.retained_vtable_entries = vtable_entries;
            error.retained_overrides = overrides;
            return Err(error);
        }
        let mut cursor = descriptor.address.checked_add(44).ok_or_else(|| {
            class_dispatch_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift class trailing-descriptor address overflowed",
            )
        })?;
        if flags & HAS_VTABLE != 0 {
            let vtable_header = macho.read_bytes_at_va(Va(cursor), 8).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    format!("Swift class vtable header is truncated: {error}"),
                )
            })?;
            let vtable_offset = macho.endian().read_u32(
                vtable_header[0..4]
                    .try_into()
                    .expect("Swift class vtable offset"),
            );
            let vtable_size = u64::from(
                macho.endian().read_u32(
                    vtable_header[4..8]
                        .try_into()
                        .expect("Swift class vtable size"),
                ),
            );
            if vtable_size > limits.max_dispatch_slots
                || vtable_entries.len() as u64 > limits.max_dispatch_slots - vtable_size
            {
                return Err(class_dispatch_budget_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    "Swift class vtable exceeds the dispatch-slot limit",
                ));
            }
            cursor = cursor.checked_add(8).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    "Swift class vtable record address overflowed",
                )
            })?;
            for slot_index in 0..vtable_size {
                attempted = attempted.checked_add(1).ok_or_else(|| {
                    class_dispatch_budget_error(
                        u64::MAX,
                        Some(descriptor.index),
                        "Swift class vtable observation count overflowed",
                    )
                })?;
                let slot_offset = slot_index.checked_mul(8).ok_or_else(|| {
                    class_dispatch_budget_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class vtable slot coordinate overflowed",
                    )
                })?;
                let method_va = cursor.checked_add(slot_offset).ok_or_else(|| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class method descriptor address overflowed",
                    )
                })?;
                let raw = macho.read_bytes_at_va(Va(method_va), 8).map_err(|error| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        format!("Swift class method descriptor is truncated: {error}"),
                    )
                })?;
                let method_flags = macho
                    .endian()
                    .read_u32(raw[0..4].try_into().expect("Swift class method flags"));
                let kind = class_method_kind(method_flags, attempted, descriptor.index)?;
                let implementation_relative = macho.endian().read_i32(
                    raw[4..8]
                        .try_into()
                        .expect("Swift class method implementation pointer"),
                );
                let implementation_field = method_va.checked_add(4).ok_or_else(|| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class method implementation field overflowed",
                    )
                })?;
                let implementation_va = resolve_required_class_relative(
                    macho,
                    implementation_field,
                    implementation_relative,
                    attempted,
                    descriptor.index,
                    "method implementation",
                    1,
                )?;
                vtable_entries.push(MachoSwiftClassVtableEntryV1 {
                    class_descriptor_va: descriptor.address,
                    vtable_offset,
                    slot_index: u32::try_from(slot_index).map_err(|_| {
                        class_dispatch_budget_error(
                            attempted,
                            Some(descriptor.index),
                            "Swift class vtable slot index exceeds u32",
                        )
                    })?,
                    descriptor_va: method_va,
                    flags: method_flags,
                    kind,
                    implementation_va,
                    raw_sha256: EvidenceDigest::of(raw),
                });
            }
            cursor = cursor
                .checked_add(vtable_size.checked_mul(8).ok_or_else(|| {
                    class_dispatch_budget_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class vtable byte length overflowed",
                    )
                })?)
                .ok_or_else(|| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class vtable end address overflowed",
                    )
                })?;
        }
        if flags & HAS_OVERRIDE_TABLE != 0 {
            let override_header = macho.read_bytes_at_va(Va(cursor), 4).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    format!("Swift class override header is truncated: {error}"),
                )
            })?;
            let override_count = u64::from(
                macho.endian().read_u32(
                    override_header
                        .try_into()
                        .expect("Swift class override count"),
                ),
            );
            if override_count > limits.max_dispatch_slots
                || overrides.len() as u64 > limits.max_dispatch_slots - override_count
            {
                return Err(class_dispatch_budget_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    "Swift class override table exceeds the dispatch-slot limit",
                ));
            }
            cursor = cursor.checked_add(4).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    "Swift class override record address overflowed",
                )
            })?;
            for override_index in 0..override_count {
                attempted = attempted.checked_add(1).ok_or_else(|| {
                    class_dispatch_budget_error(
                        u64::MAX,
                        Some(descriptor.index),
                        "Swift class override observation count overflowed",
                    )
                })?;
                let offset = override_index.checked_mul(12).ok_or_else(|| {
                    class_dispatch_budget_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class override coordinate overflowed",
                    )
                })?;
                let override_va = cursor.checked_add(offset).ok_or_else(|| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift class override address overflowed",
                    )
                })?;
                let raw = macho
                    .read_bytes_at_va(Va(override_va), 12)
                    .map_err(|error| {
                        class_dispatch_error(
                            attempted,
                            Some(descriptor.index),
                            format!("Swift class override descriptor is truncated: {error}"),
                        )
                    })?;
                let overridden_class_descriptor_va = resolve_required_class_relative(
                    macho,
                    override_va,
                    macho.endian().read_i32(
                        raw[0..4]
                            .try_into()
                            .expect("Swift overridden class pointer"),
                    ),
                    attempted,
                    descriptor.index,
                    "overridden class descriptor",
                    44,
                )?;
                let overridden_method_field = override_va.checked_add(4).ok_or_else(|| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift overridden method field overflowed",
                    )
                })?;
                let overridden_method_descriptor_va = resolve_required_class_relative(
                    macho,
                    overridden_method_field,
                    macho.endian().read_i32(
                        raw[4..8]
                            .try_into()
                            .expect("Swift overridden method pointer"),
                    ),
                    attempted,
                    descriptor.index,
                    "overridden method descriptor",
                    8,
                )?;
                let implementation_field = override_va.checked_add(8).ok_or_else(|| {
                    class_dispatch_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift override implementation field overflowed",
                    )
                })?;
                let implementation_va = resolve_required_class_relative(
                    macho,
                    implementation_field,
                    macho.endian().read_i32(
                        raw[8..12]
                            .try_into()
                            .expect("Swift override implementation pointer"),
                    ),
                    attempted,
                    descriptor.index,
                    "override implementation",
                    1,
                )?;
                overrides.push(MachoSwiftClassOverrideRecordV1 {
                    class_descriptor_va: descriptor.address,
                    override_index: u32::try_from(override_index).map_err(|_| {
                        class_dispatch_budget_error(
                            attempted,
                            Some(descriptor.index),
                            "Swift class override index exceeds u32",
                        )
                    })?,
                    descriptor_va: override_va,
                    overridden_class_descriptor_va,
                    overridden_method_descriptor_va,
                    implementation_va,
                    raw_sha256: EvidenceDigest::of(raw),
                });
            }
        }
    }
    Ok((vtable_entries, overrides))
}

fn class_method_kind(
    flags: u32,
    attempted: u64,
    record_index: u64,
) -> Result<MachoSwiftClassMethodKindV1, ClassDispatchValidationError> {
    match flags & 0x0f {
        0 => Ok(MachoSwiftClassMethodKindV1::Method),
        1 => Ok(MachoSwiftClassMethodKindV1::Initializer),
        2 => Ok(MachoSwiftClassMethodKindV1::Getter),
        3 => Ok(MachoSwiftClassMethodKindV1::Setter),
        4 => Ok(MachoSwiftClassMethodKindV1::ModifyCoroutine),
        5 => Ok(MachoSwiftClassMethodKindV1::ReadCoroutine),
        _ => Err(class_dispatch_unsupported(
            attempted,
            Some(record_index),
            "Swift class method kind is not admitted",
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_required_class_relative(
    macho: &MachoFile<'_>,
    field: u64,
    relative: i32,
    attempted: u64,
    record_index: u64,
    role: &str,
    byte_len: usize,
) -> Result<u64, ClassDispatchValidationError> {
    if relative == 0 {
        return Err(class_dispatch_error(
            attempted,
            Some(record_index),
            format!("Swift class {role} pointer is null"),
        ));
    }
    let address = add_signed(field, relative).ok_or_else(|| {
        class_dispatch_error(
            attempted,
            Some(record_index),
            format!("Swift class {role} pointer overflowed"),
        )
    })?;
    macho
        .read_bytes_at_va(Va(address), byte_len)
        .map_err(|error| {
            class_dispatch_error(
                attempted,
                Some(record_index),
                format!("Swift class {role} is unmapped: {error}"),
            )
        })?;
    Ok(address)
}

fn class_dispatch_error(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> ClassDispatchValidationError {
    ClassDispatchValidationError {
        attempted,
        gap: Box::new(gap(
            "swift_metadata_malformed",
            "__swift5_types",
            record_index,
            safe_detail,
        )),
        retained_vtable_entries: Vec::new(),
        retained_overrides: Vec::new(),
    }
}

fn class_dispatch_budget_error(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> ClassDispatchValidationError {
    ClassDispatchValidationError {
        attempted,
        gap: Box::new(gap(
            "swift_structural_budget_exceeded",
            "__swift5_types",
            record_index,
            safe_detail,
        )),
        retained_vtable_entries: Vec::new(),
        retained_overrides: Vec::new(),
    }
}

fn class_dispatch_unsupported(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> ClassDispatchValidationError {
    ClassDispatchValidationError {
        attempted,
        gap: Box::new(gap(
            "swift_metadata_unsupported",
            "__swift5_types",
            record_index,
            safe_detail,
        )),
        retained_vtable_entries: Vec::new(),
        retained_overrides: Vec::new(),
    }
}

pub(super) fn validate_protocol_requirements(
    macho: &MachoFile<'_>,
    descriptors: &[ValidatedDescriptor],
    limits: &SwiftEvidenceLimits,
) -> Result<Vec<MachoSwiftProtocolRequirementRecordV1>, ProtocolRequirementValidationError> {
    let mut requirements = Vec::new();
    let mut attempted = 0_u64;
    for descriptor in descriptors
        .iter()
        .filter(|descriptor| descriptor.section == "__swift5_protos")
    {
        let header = macho
            .read_bytes_at_va(Va(descriptor.address), 24)
            .map_err(|error| {
                protocol_requirement_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    format!("Swift protocol descriptor is truncated: {error}"),
                )
            })?;
        let signature_count = u64::from(
            macho.endian().read_u32(
                header[12..16]
                    .try_into()
                    .expect("protocol signature-requirement count"),
            ),
        );
        let requirement_count = u64::from(
            macho.endian().read_u32(
                header[16..20]
                    .try_into()
                    .expect("protocol requirement count"),
            ),
        );
        if signature_count != 0 {
            return Err(protocol_requirement_unsupported(
                signature_count,
                Some(descriptor.index),
                "generic protocol requirement signatures are retained as unsupported",
            ));
        }
        if requirement_count > limits.max_protocol_requirements
            || requirements.len() as u64 > limits.max_protocol_requirements - requirement_count
        {
            return Err(protocol_requirement_budget_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift protocol requirement count exceeds the selected limit",
            ));
        }
        let associated_names_relative = macho.endian().read_i32(
            header[20..24]
                .try_into()
                .expect("protocol associated-type names pointer"),
        );
        if associated_names_relative != 0 {
            let names_field = descriptor.address.checked_add(20).ok_or_else(|| {
                protocol_requirement_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    "Swift protocol associated-type names field overflowed",
                )
            })?;
            let names = add_signed(names_field, associated_names_relative).ok_or_else(|| {
                protocol_requirement_error(
                    attempted.saturating_add(1),
                    Some(descriptor.index),
                    "Swift protocol associated-type names pointer overflowed",
                )
            })?;
            validate_bounded_c_string(macho, names, limits, "__swift5_protos", descriptor.index)
                .map_err(|gap| ProtocolRequirementValidationError {
                    attempted: attempted.saturating_add(1),
                    gap,
                })?;
        }
        let requirements_start = descriptor.address.checked_add(24).ok_or_else(|| {
            protocol_requirement_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift protocol requirement array address overflowed",
            )
        })?;
        for requirement_index in 0..requirement_count {
            attempted = attempted.checked_add(1).ok_or_else(|| {
                protocol_requirement_budget_error(
                    u64::MAX,
                    Some(descriptor.index),
                    "Swift protocol requirement observation count overflowed",
                )
            })?;
            let offset = requirement_index.checked_mul(8).ok_or_else(|| {
                protocol_requirement_budget_error(
                    attempted,
                    Some(descriptor.index),
                    "Swift protocol requirement coordinate overflowed",
                )
            })?;
            let requirement_address = requirements_start.checked_add(offset).ok_or_else(|| {
                protocol_requirement_error(
                    attempted,
                    Some(descriptor.index),
                    "Swift protocol requirement address overflowed",
                )
            })?;
            let raw = macho
                .read_bytes_at_va(Va(requirement_address), 8)
                .map_err(|error| {
                    protocol_requirement_error(
                        attempted,
                        Some(descriptor.index),
                        format!("Swift protocol requirement is truncated: {error}"),
                    )
                })?;
            let flags = macho
                .endian()
                .read_u32(raw[0..4].try_into().expect("protocol requirement flags"));
            let kind = match flags & 0x0f {
                0 => MachoSwiftProtocolRequirementKindV1::BaseProtocol,
                1 => MachoSwiftProtocolRequirementKindV1::Method,
                2 => MachoSwiftProtocolRequirementKindV1::Initializer,
                3 => MachoSwiftProtocolRequirementKindV1::Getter,
                4 => MachoSwiftProtocolRequirementKindV1::Setter,
                5 => MachoSwiftProtocolRequirementKindV1::ReadCoroutine,
                6 => MachoSwiftProtocolRequirementKindV1::ModifyCoroutine,
                7 => MachoSwiftProtocolRequirementKindV1::AssociatedTypeAccess,
                8 => MachoSwiftProtocolRequirementKindV1::AssociatedConformanceAccess,
                _ => {
                    return Err(protocol_requirement_unsupported(
                        attempted,
                        Some(descriptor.index),
                        "Swift protocol requirement kind is not admitted",
                    ));
                }
            };
            let default_relative = macho.endian().read_i32(
                raw[4..8]
                    .try_into()
                    .expect("protocol default implementation pointer"),
            );
            let default_implementation_va = if default_relative == 0 {
                None
            } else {
                let field = requirement_address.checked_add(4).ok_or_else(|| {
                    protocol_requirement_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift default implementation field address overflowed",
                    )
                })?;
                let address = add_signed(field, default_relative).ok_or_else(|| {
                    protocol_requirement_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift default implementation pointer overflowed",
                    )
                })?;
                macho.read_bytes_at_va(Va(address), 1).map_err(|error| {
                    protocol_requirement_error(
                        attempted,
                        Some(descriptor.index),
                        format!("Swift default implementation is unmapped: {error}"),
                    )
                })?;
                Some(address)
            };
            requirements.push(MachoSwiftProtocolRequirementRecordV1 {
                protocol_descriptor_va: descriptor.address,
                requirement_index: u32::try_from(requirement_index).map_err(|_| {
                    protocol_requirement_budget_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift protocol requirement index exceeds u32",
                    )
                })?,
                descriptor_va: requirement_address,
                flags,
                kind,
                default_implementation_va,
                raw_sha256: EvidenceDigest::of(raw),
            });
        }
    }
    Ok(requirements)
}

fn protocol_requirement_error(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> ProtocolRequirementValidationError {
    ProtocolRequirementValidationError {
        attempted,
        gap: gap(
            "swift_metadata_malformed",
            "__swift5_protos",
            record_index,
            safe_detail,
        ),
    }
}

fn protocol_requirement_budget_error(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> ProtocolRequirementValidationError {
    ProtocolRequirementValidationError {
        attempted,
        gap: gap(
            "swift_structural_budget_exceeded",
            "__swift5_protos",
            record_index,
            safe_detail,
        ),
    }
}

fn protocol_requirement_unsupported(
    attempted: u64,
    record_index: Option<u64>,
    safe_detail: impl Into<String>,
) -> ProtocolRequirementValidationError {
    ProtocolRequirementValidationError {
        attempted,
        gap: gap(
            "swift_metadata_unsupported",
            "__swift5_protos",
            record_index,
            safe_detail,
        ),
    }
}
