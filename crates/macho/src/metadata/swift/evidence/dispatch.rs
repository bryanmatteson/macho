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

pub(super) struct ClassDispatchEvidence {
    pub(super) layouts: Vec<MachoSwiftClassTrailingLayoutV1>,
    pub(super) vtable_entries: Vec<MachoSwiftClassVtableEntryV1>,
    pub(super) overrides: Vec<MachoSwiftClassOverrideRecordV1>,
}

pub(super) fn validate_class_dispatch(
    macho: &MachoFile<'_>,
    descriptors: &[ValidatedDescriptor],
    limits: &SwiftEvidenceLimits,
) -> Result<ClassDispatchEvidence, ClassDispatchValidationError> {
    const HAS_VTABLE: u32 = 0x8000_0000;
    const HAS_OVERRIDE_TABLE: u32 = 0x4000_0000;
    const HAS_RESILIENT_SUPERCLASS: u32 = 0x2000_0000;
    const METADATA_INITIALIZATION_MASK: u32 = 0x0003_0000;
    const IS_GENERIC: u32 = 0x80;

    let mut layouts = Vec::new();
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
        let cursor = descriptor.address.checked_add(44).ok_or_else(|| {
            class_dispatch_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift class trailing-descriptor address overflowed",
            )
        })?;
        let (mut cursor, layout) = decode_class_trailing_layout(
            macho,
            descriptor.address,
            descriptor.index,
            flags,
            cursor,
            attempted,
            IS_GENERIC,
            HAS_RESILIENT_SUPERCLASS,
            METADATA_INITIALIZATION_MASK,
            limits,
        )?;
        layouts.push(layout);
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
    Ok(ClassDispatchEvidence {
        layouts,
        vtable_entries,
        overrides,
    })
}

#[allow(clippy::too_many_arguments)]
fn decode_class_trailing_layout(
    macho: &MachoFile<'_>,
    class_descriptor_va: u64,
    descriptor_index: u64,
    flags: u32,
    mut cursor: u64,
    attempted: u64,
    is_generic: u32,
    has_resilient_superclass: u32,
    metadata_initialization_mask: u32,
    limits: &SwiftEvidenceLimits,
) -> Result<(u64, MachoSwiftClassTrailingLayoutV1), ClassDispatchValidationError> {
    let generic_context = if flags & is_generic != 0 {
        let descriptor_va = cursor;
        let header = macho.read_bytes_at_va(Va(cursor), 16).map_err(|error| {
            class_dispatch_error(
                attempted.saturating_add(1),
                Some(descriptor_index),
                format!("Swift type-generic context header is truncated: {error}"),
            )
        })?;
        let instantiation_cache_relative = macho
            .endian()
            .read_i32(header[0..4].try_into().expect("generic instantiation cache"));
        let default_instantiation_pattern_relative = macho.endian().read_i32(
            header[4..8]
                .try_into()
                .expect("generic instantiation pattern"),
        );
        let parameter_count = macho
            .endian()
            .read_u16(header[8..10].try_into().expect("generic parameter count"));
        let requirement_count = macho
            .endian()
            .read_u16(header[10..12].try_into().expect("generic requirement count"));
        let key_argument_count = macho
            .endian()
            .read_u16(header[12..14].try_into().expect("generic key argument count"));
        let generic_flags = macho.endian().read_u16(
            header[14..16]
                .try_into()
                .expect("generic context flags"),
        );
        if generic_flags & !0x7 != 0 {
            return Err(class_dispatch_unsupported(
                attempted.saturating_add(1),
                Some(descriptor_index),
                "Swift generic context uses unknown trailing-layout flags",
            ));
        }
        let parameter_bytes = u64::from(parameter_count)
            .checked_add(3)
            .map(|value| value & !3)
            .ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic parameter descriptor length overflowed",
                )
            })?;
        let requirement_bytes = u64::from(requirement_count)
            .checked_mul(12)
            .ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic requirement descriptor length overflowed",
                )
            })?;
        let base_length = 16_u64
            .checked_add(parameter_bytes)
            .and_then(|value| value.checked_add(requirement_bytes))
            .ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic context length overflowed",
                )
            })?;
        macho.read_bytes_at_va(
            Va(cursor),
            usize::try_from(base_length).map_err(|_| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic context exceeds host limits",
                )
            })?,
        )
        .map_err(|error| {
            class_dispatch_error(
                attempted.saturating_add(1),
                Some(descriptor_index),
                format!("Swift generic context is truncated: {error}"),
            )
        })?;
        cursor = cursor.checked_add(base_length).ok_or_else(|| {
            class_dispatch_error(
                attempted.saturating_add(1),
                Some(descriptor_index),
                "Swift generic context end overflowed",
            )
        })?;

        let (pack_count, shape_class_count) = if generic_flags & 0x1 != 0 {
            let pack_header = macho.read_bytes_at_va(Va(cursor), 4).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift generic pack-shape header is truncated: {error}"),
                )
            })?;
            let pack_count = macho
                .endian()
                .read_u16(pack_header[0..2].try_into().expect("generic pack count"));
            let shape_class_count = macho.endian().read_u16(
                pack_header[2..4]
                    .try_into()
                    .expect("generic shape-class count"),
            );
            if u64::from(pack_count) > limits.max_observations {
                return Err(class_dispatch_budget_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic pack-shape count exceeds the observation limit",
                ));
            }
            let pack_length = u64::from(pack_count)
                .checked_mul(8)
                .and_then(|value| value.checked_add(4))
                .ok_or_else(|| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift generic pack-shape length overflowed",
                    )
                })?;
            macho.read_bytes_at_va(
                Va(cursor),
                usize::try_from(pack_length).map_err(|_| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift generic pack-shape layout exceeds host limits",
                    )
                })?,
            )
            .map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift generic pack-shape layout is truncated: {error}"),
                )
            })?;
            cursor = cursor.checked_add(pack_length).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic pack-shape end overflowed",
                )
            })?;
            (pack_count, shape_class_count)
        } else {
            (0, 0)
        };

        let mut conditional_inverted_protocol_bits = 0_u16;
        let mut conditional_inverted_protocol_requirement_counts = Vec::new();
        if generic_flags & 0x2 != 0 {
            let set = macho.read_bytes_at_va(Va(cursor), 2).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift conditional-inverted-protocol set is truncated: {error}"),
                )
            })?;
            conditional_inverted_protocol_bits =
                macho.endian().read_u16(set.try_into().expect("invertible protocol set"));
            let count_len = u64::from(conditional_inverted_protocol_bits.count_ones())
                .checked_mul(2)
                .ok_or_else(|| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift conditional-inverted-protocol count length overflowed",
                    )
                })?;
            let counts_va = cursor.checked_add(2).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift conditional-inverted-protocol count address overflowed",
                )
            })?;
            let counts = macho
                .read_bytes_at_va(
                    Va(counts_va),
                    usize::try_from(count_len).map_err(|_| {
                        class_dispatch_error(
                            attempted.saturating_add(1),
                            Some(descriptor_index),
                            "Swift conditional-inverted-protocol counts exceed host limits",
                        )
                    })?,
                )
                .map_err(|error| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        format!(
                            "Swift conditional-inverted-protocol counts are truncated: {error}"
                        ),
                    )
                })?;
            conditional_inverted_protocol_requirement_counts = counts
                .chunks_exact(2)
                .map(|raw| macho.endian().read_u16(raw.try_into().unwrap()))
                .collect();
            if !conditional_inverted_protocol_requirement_counts
                .windows(2)
                .all(|window| window[0] <= window[1])
            {
                return Err(class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift conditional-inverted-protocol counts are not cumulative",
                ));
            }
            let conditional_requirement_count = conditional_inverted_protocol_requirement_counts
                .last()
                .copied()
                .unwrap_or(0);
            if u64::from(conditional_requirement_count) > limits.max_observations {
                return Err(class_dispatch_budget_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift conditional-inverted-protocol requirements exceed the observation limit",
                ));
            }
            let counts_end = counts_va.checked_add(count_len).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift conditional-inverted-protocol counts overflowed",
                )
            })?;
            let requirements_va = counts_end.checked_add(3).map(|value| value & !3).ok_or_else(
                || {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift conditional-inverted-protocol alignment overflowed",
                    )
                },
            )?;
            let requirements_len = u64::from(conditional_requirement_count)
                .checked_mul(12)
                .ok_or_else(|| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift conditional-inverted-protocol requirement length overflowed",
                    )
                })?;
            macho.read_bytes_at_va(
                Va(requirements_va),
                usize::try_from(requirements_len).map_err(|_| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift conditional-inverted-protocol requirements exceed host limits",
                    )
                })?,
            )
            .map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!(
                        "Swift conditional-inverted-protocol requirements are truncated: {error}"
                    ),
                )
            })?;
            cursor = requirements_va
                .checked_add(requirements_len)
                .ok_or_else(|| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift conditional-inverted-protocol layout overflowed",
                    )
                })?;
        }

        let value_count = if generic_flags & 0x4 != 0 {
            let value_header = macho.read_bytes_at_va(Va(cursor), 4).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift generic-value header is truncated: {error}"),
                )
            })?;
            let value_count = macho
                .endian()
                .read_u32(value_header.try_into().expect("generic value count"));
            if u64::from(value_count) > limits.max_observations {
                return Err(class_dispatch_budget_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic-value count exceeds the observation limit",
                ));
            }
            let value_length = u64::from(value_count)
                .checked_mul(4)
                .and_then(|value| value.checked_add(4))
                .ok_or_else(|| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift generic-value layout length overflowed",
                    )
                })?;
            macho.read_bytes_at_va(
                Va(cursor),
                usize::try_from(value_length).map_err(|_| {
                    class_dispatch_error(
                        attempted.saturating_add(1),
                        Some(descriptor_index),
                        "Swift generic-value layout exceeds host limits",
                    )
                })?,
            )
            .map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift generic-value layout is truncated: {error}"),
                )
            })?;
            cursor = cursor.checked_add(value_length).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic-value layout end overflowed",
                )
            })?;
            value_count
        } else {
            0
        };

        let length = cursor.checked_sub(descriptor_va).ok_or_else(|| {
            class_dispatch_error(
                attempted.saturating_add(1),
                Some(descriptor_index),
                "Swift generic context length underflowed",
            )
        })?;
        Some(MachoSwiftGenericContextLayoutV1 {
            descriptor_va,
            instantiation_cache_relative,
            default_instantiation_pattern_relative,
            parameter_count,
            requirement_count,
            key_argument_count,
            flags: generic_flags,
            pack_count,
            shape_class_count,
            conditional_inverted_protocol_bits,
            conditional_inverted_protocol_requirement_counts,
            value_count,
            byte_len: u32::try_from(length).map_err(|_| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift generic context length exceeds the public record",
                )
            })?,
        })
    } else {
        None
    };
    let (resilient_superclass_descriptor_va, resilient_superclass_type_reference_relative) =
        if flags & has_resilient_superclass != 0 {
            let descriptor_va = cursor;
            let raw = macho.read_bytes_at_va(Va(cursor), 4).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift resilient-superclass record is truncated: {error}"),
                )
            })?;
            let relative = macho.endian().read_i32(
                raw.try_into()
                    .expect("Swift resilient-superclass relative pointer"),
            );
            cursor = cursor.checked_add(4).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift resilient-superclass trailing record overflowed",
                )
            })?;
            (Some(descriptor_va), Some(relative))
        } else {
            (None, None)
        };
    let metadata_initialization = match flags & metadata_initialization_mask {
        0 => MachoSwiftMetadataInitializationLayoutV1::None,
        0x0001_0000 => {
            let descriptor_va = cursor;
            let raw = macho.read_bytes_at_va(Va(cursor), 12).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift singleton metadata-initialization record is truncated: {error}"),
                )
            })?;
            cursor = cursor.checked_add(12).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift singleton metadata-initialization record overflowed",
                )
            })?;
            MachoSwiftMetadataInitializationLayoutV1::Singleton {
                descriptor_va,
                cache_relative: macho.endian().read_i32(raw[0..4].try_into().unwrap()),
                incomplete_metadata_relative: macho
                    .endian()
                    .read_i32(raw[4..8].try_into().unwrap()),
                completion_function_relative: macho
                    .endian()
                    .read_i32(raw[8..12].try_into().unwrap()),
            }
        }
        0x0002_0000 => {
            let descriptor_va = cursor;
            let raw = macho.read_bytes_at_va(Va(cursor), 4).map_err(|error| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    format!("Swift foreign metadata-initialization record is truncated: {error}"),
                )
            })?;
            cursor = cursor.checked_add(4).ok_or_else(|| {
                class_dispatch_error(
                    attempted.saturating_add(1),
                    Some(descriptor_index),
                    "Swift foreign metadata-initialization record overflowed",
                )
            })?;
            MachoSwiftMetadataInitializationLayoutV1::Foreign {
                descriptor_va,
                completion_function_relative: macho.endian().read_i32(raw.try_into().unwrap()),
            }
        }
        _ => {
            return Err(class_dispatch_unsupported(
                attempted.saturating_add(1),
                Some(descriptor_index),
                "Swift class metadata-initialization trailing record is unsupported",
            ));
        }
    };
    Ok((
        cursor,
        MachoSwiftClassTrailingLayoutV1 {
            class_descriptor_va,
            flags,
            generic_context,
            resilient_superclass_descriptor_va,
            resilient_superclass_type_reference_relative,
            metadata_initialization,
            dispatch_descriptor_va: cursor,
        },
    ))
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
) -> Result<
    (
        Vec<MachoSwiftProtocolSignatureRequirementRecordV1>,
        Vec<MachoSwiftProtocolRequirementRecordV1>,
    ),
    ProtocolRequirementValidationError,
> {
    let mut signature_requirements = Vec::new();
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
        if signature_count > limits.max_protocol_requirements
            || signature_requirements.len() as u64
                > limits.max_protocol_requirements - signature_count
        {
            return Err(protocol_requirement_budget_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift protocol signature requirements exceed the selected limit",
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
        let signature_start = descriptor.address.checked_add(24).ok_or_else(|| {
            protocol_requirement_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift protocol signature-requirement array address overflowed",
            )
        })?;
        for requirement_index in 0..signature_count {
            attempted = attempted.checked_add(1).ok_or_else(|| {
                protocol_requirement_budget_error(
                    u64::MAX,
                    Some(descriptor.index),
                    "Swift protocol signature-requirement count overflowed",
                )
            })?;
            let descriptor_va = signature_start
                .checked_add(requirement_index.checked_mul(12).ok_or_else(|| {
                    protocol_requirement_budget_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift protocol signature-requirement coordinate overflowed",
                    )
                })?)
                .ok_or_else(|| {
                    protocol_requirement_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift protocol signature-requirement address overflowed",
                    )
                })?;
            let raw = macho
                .read_bytes_at_va(Va(descriptor_va), 12)
                .map_err(|error| {
                    protocol_requirement_error(
                        attempted,
                        Some(descriptor.index),
                        format!("Swift protocol signature requirement is truncated: {error}"),
                    )
                })?;
            signature_requirements.push(MachoSwiftProtocolSignatureRequirementRecordV1 {
                protocol_descriptor_va: descriptor.address,
                requirement_index: u32::try_from(requirement_index).map_err(|_| {
                    protocol_requirement_budget_error(
                        attempted,
                        Some(descriptor.index),
                        "Swift protocol signature-requirement index exceeds u32",
                    )
                })?,
                descriptor_va,
                flags: macho
                    .endian()
                    .read_u32(raw[0..4].try_into().expect("generic requirement flags")),
                parameter_relative: macho
                    .endian()
                    .read_i32(raw[4..8].try_into().expect("generic requirement parameter")),
                constraint_relative: macho.endian().read_i32(
                    raw[8..12]
                        .try_into()
                        .expect("generic requirement constraint"),
                ),
                raw_sha256: EvidenceDigest::of(raw),
            });
        }
        // Generic signature requirements precede ordinary protocol
        // requirements and use the ABI's 12-byte generic-requirement record.
        // Their raw constraints remain represented by the protocol descriptor;
        // advancing over them preserves exact ordinary requirement coordinates.
        let signature_bytes = signature_count.checked_mul(12).ok_or_else(|| {
            protocol_requirement_budget_error(
                attempted.saturating_add(1),
                Some(descriptor.index),
                "Swift protocol signature-requirement length overflowed",
            )
        })?;
        let requirements_start = descriptor
            .address
            .checked_add(24)
            .and_then(|address| address.checked_add(signature_bytes))
            .ok_or_else(|| {
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
    Ok((signature_requirements, requirements))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn image(bytes: &[u8]) -> MachoFile<'_> {
        match crate::core::parse(bytes).expect("fixture parses") {
            MachoContainer::Thin(macho) => macho,
            MachoContainer::Fat(_) => panic!("expected thin image"),
        }
    }

    #[test]
    fn generic_resilient_and_metadata_initialization_layouts_are_typed() {
        const BASE: usize = 0x130;
        const VA: u64 = 0x1_0000_0130;
        const GENERIC: u32 = 0x80;
        const RESILIENT: u32 = 0x2000_0000;
        const SINGLETON: u32 = 0x0001_0000;
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[BASE..BASE + 4].copy_from_slice(&11_i32.to_le_bytes());
        bytes[BASE + 4..BASE + 8].copy_from_slice(&12_i32.to_le_bytes());
        bytes[BASE + 8..BASE + 16].copy_from_slice(&[2, 0, 1, 0, 3, 0, 0, 0]);
        bytes[BASE + 32..BASE + 36].copy_from_slice(&17_i32.to_le_bytes());
        bytes[BASE + 36..BASE + 40].copy_from_slice(&1_i32.to_le_bytes());
        bytes[BASE + 40..BASE + 44].copy_from_slice(&2_i32.to_le_bytes());
        bytes[BASE + 44..BASE + 48].copy_from_slice(&3_i32.to_le_bytes());
        let macho = image(&bytes);
        let (end, layout) = decode_class_trailing_layout(
            &macho,
            0x1_0000_0100,
            0,
            GENERIC | RESILIENT | SINGLETON,
            VA,
            0,
            GENERIC,
            RESILIENT,
            0x0003_0000,
            &SwiftEvidenceLimits::default(),
        )
        .unwrap();
        assert_eq!(end, VA + 48);
        assert_eq!(layout.dispatch_descriptor_va, end);
        assert_eq!(
            layout.generic_context,
            Some(MachoSwiftGenericContextLayoutV1 {
                descriptor_va: VA,
                instantiation_cache_relative: 11,
                default_instantiation_pattern_relative: 12,
                parameter_count: 2,
                requirement_count: 1,
                key_argument_count: 3,
                flags: 0,
                pack_count: 0,
                shape_class_count: 0,
                conditional_inverted_protocol_bits: 0,
                conditional_inverted_protocol_requirement_counts: Vec::new(),
                value_count: 0,
                byte_len: 32,
            })
        );
        assert_eq!(layout.resilient_superclass_descriptor_va, Some(VA + 32));
        assert_eq!(
            layout.resilient_superclass_type_reference_relative,
            Some(17)
        );
        assert!(matches!(
            layout.metadata_initialization,
            MachoSwiftMetadataInitializationLayoutV1::Singleton {
                descriptor_va,
                cache_relative: 1,
                incomplete_metadata_relative: 2,
                completion_function_relative: 3,
            } if descriptor_va == VA + 36
        ));

        bytes[BASE + 48..BASE + 52].copy_from_slice(&29_i32.to_le_bytes());
        let macho = image(&bytes);
        let (foreign_end, foreign) = decode_class_trailing_layout(
            &macho,
            0x1_0000_0100,
            0,
            0x0002_0000,
            VA + 48,
            0,
            GENERIC,
            RESILIENT,
            0x0003_0000,
            &SwiftEvidenceLimits::default(),
        )
        .unwrap();
        assert_eq!(foreign_end, VA + 52);
        assert!(matches!(
            foreign.metadata_initialization,
            MachoSwiftMetadataInitializationLayoutV1::Foreign {
                descriptor_va,
                completion_function_relative: 29,
            } if descriptor_va == VA + 48
        ));
    }

    #[test]
    fn modern_generic_trailing_shapes_advance_to_the_dispatch_layout() {
        const BASE: usize = 0x130;
        const VA: u64 = 0x1_0000_0130;
        const GENERIC: u32 = 0x80;
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[BASE..BASE + 4].copy_from_slice(&11_i32.to_le_bytes());
        bytes[BASE + 4..BASE + 8].copy_from_slice(&12_i32.to_le_bytes());
        bytes[BASE + 8..BASE + 16].copy_from_slice(&[0, 0, 0, 0, 0, 0, 7, 0]);
        bytes[BASE + 16..BASE + 20].copy_from_slice(&[1, 0, 1, 0]);
        bytes[BASE + 28..BASE + 30].copy_from_slice(&3_u16.to_le_bytes());
        bytes[BASE + 30..BASE + 32].copy_from_slice(&1_u16.to_le_bytes());
        bytes[BASE + 32..BASE + 34].copy_from_slice(&2_u16.to_le_bytes());
        bytes[BASE + 60..BASE + 64].copy_from_slice(&2_u32.to_le_bytes());
        let macho = image(&bytes);

        let (end, layout) = decode_class_trailing_layout(
            &macho,
            0x1_0000_0100,
            0,
            GENERIC,
            VA,
            0,
            GENERIC,
            0x2000_0000,
            0x0003_0000,
            &SwiftEvidenceLimits::default(),
        )
        .unwrap();

        assert_eq!(end, VA + 72);
        let generic = layout.generic_context.unwrap();
        assert_eq!(generic.flags, 7);
        assert_eq!((generic.pack_count, generic.shape_class_count), (1, 1));
        assert_eq!(generic.conditional_inverted_protocol_bits, 3);
        assert_eq!(
            generic.conditional_inverted_protocol_requirement_counts,
            vec![1, 2]
        );
        assert_eq!(generic.value_count, 2);
        assert_eq!(generic.byte_len, 72);
        assert_eq!(layout.dispatch_descriptor_va, VA + 72);
    }
}
