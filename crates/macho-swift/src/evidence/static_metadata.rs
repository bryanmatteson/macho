use super::*;

use macho_core::format::symbols::fold_symbols;
use macho_demangle::{
    SwiftNominalMetadataKind, SwiftTypeMetadataIdentity, SwiftTypeMetadataSymbolEvidence,
    classify_swift_type_metadata_symbol,
};

pub(super) struct NoSymbolDemangler;

impl crate::SwiftDemangler for NoSymbolDemangler {
    fn demangle(&self, _symbol: &str) -> crate::Result<Option<String>> {
        Ok(None)
    }
}

struct StaticMetadataCandidate {
    identity: SwiftTypeMetadataIdentity,
    metadata_va: u64,
}

struct StaticMetadataCandidates {
    attempted: u64,
    records: Vec<StaticMetadataCandidate>,
    gap: Option<SwiftDecodeGapV1>,
}

/// Decode already-emitted value metadata and local value-witness layouts.
///
/// Metadata accessors are not invoked and accessor symbols are not admitted as
/// instances. A thin image must be selected before this leaf can decode.
#[must_use]
pub fn decode_swift_static_metadata_file(
    source: &[u8],
    limits: &SwiftEvidenceLimits,
) -> SwiftStaticMetadataBatchV1 {
    let macho = match macho_core::parse(source) {
        Ok(MachoContainer::Thin(macho)) => macho,
        Ok(MachoContainer::Fat(_)) => {
            return rejected_static_metadata(
                0,
                "swift.static_metadata.selected_image_required",
                "static Swift metadata requires one selected thin Mach-O",
            );
        }
        Err(error) => {
            return rejected_static_metadata(
                0,
                "swift.static_metadata.image_malformed",
                format!("selected Mach-O parse failed: {error}"),
            );
        }
    };
    decode_swift_static_metadata(&macho, limits)
}

/// Decode already-emitted value metadata from a parsed selected image.
#[must_use]
pub fn decode_swift_static_metadata(
    macho: &MachoFile<'_>,
    limits: &SwiftEvidenceLimits,
) -> SwiftStaticMetadataBatchV1 {
    if let Err(error) = limits.validate() {
        return rejected_static_metadata(0, "swift.static_metadata.invalid_limits", error);
    }
    if !macho.is_64bit() {
        return rejected_static_metadata(
            0,
            "swift.static_metadata.unsupported_abi",
            "static Swift metadata requires a 64-bit ABI",
        );
    }
    let resolver = match PointerResolver::new(macho) {
        Ok(resolver) => resolver,
        Err(error) => {
            return rejected_static_metadata(
                0,
                "swift.static_metadata.pointer_index_rejected",
                format!("Swift pointer-evidence indexing failed: {error}"),
            );
        }
    };
    decode_swift_static_metadata_with_resolver(macho, &resolver, limits)
}

/// Decode already-emitted value metadata while reusing a selected-image
/// pointer/fixup index.
#[must_use]
pub fn decode_swift_static_metadata_with_resolver(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    limits: &SwiftEvidenceLimits,
) -> SwiftStaticMetadataBatchV1 {
    if let Err(error) = limits.validate() {
        return rejected_static_metadata(0, "swift.static_metadata.invalid_limits", error);
    }
    if !macho.is_64bit() {
        return rejected_static_metadata(
            0,
            "swift.static_metadata.unsupported_abi",
            "static Swift metadata requires a 64-bit ABI",
        );
    }
    if macho
        .find_load_command(|command| command.as_symtab().is_some())
        .is_none()
    {
        return absent_static_metadata();
    }

    let candidates = match fold_symbols(
        macho,
        StaticMetadataCandidates {
            attempted: 0,
            records: Vec::new(),
            gap: None,
        },
        |state, symbol| {
            if !symbol.is_defined()
                || symbol.value == 0
                || !is_emitted_metadata_candidate(symbol.name)
            {
                return Ok(());
            }
            let Some(attempted) = state.attempted.checked_add(1) else {
                state.gap = Some(gap(
                    "swift.static_metadata.observation_overflow",
                    "Swift static metadata candidate count overflowed",
                ));
                return Ok(());
            };
            state.attempted = attempted;
            if state.gap.is_some() {
                return Ok(());
            }
            if state.attempted > limits.max_observations {
                state.gap = Some(gap(
                    "swift.static_metadata.observation_limit",
                    "Swift static metadata candidates exceed max_observations",
                ));
                return Ok(());
            }
            if state.attempted > limits.max_nominal_descriptors {
                state.gap = Some(gap(
                    "swift.static_metadata.nominal_limit",
                    "Swift static metadata candidates exceed max_nominal_descriptors",
                ));
                return Ok(());
            }
            if symbol.name.len() as u64 > limits.max_mangling_bytes {
                state.gap = Some(gap(
                    "swift.static_metadata.mangling_limit",
                    "Swift static metadata mangling exceeds max_mangling_bytes",
                ));
                return Ok(());
            }
            match classify_swift_type_metadata_symbol(symbol.name) {
                SwiftTypeMetadataSymbolEvidence::Metadata(identity) => {
                    if identity
                        .name
                        .split('.')
                        .any(|component| component.len() as u64 > limits.max_identifier_bytes)
                    {
                        state.gap = Some(gap(
                            "swift.static_metadata.identifier_limit",
                            "Swift static metadata identity exceeds max_identifier_bytes",
                        ));
                    } else {
                        state.records.push(StaticMetadataCandidate {
                            identity,
                            metadata_va: symbol.value,
                        });
                    }
                }
                SwiftTypeMetadataSymbolEvidence::NotTypeMetadata => {
                    state.gap = Some(gap(
                        "swift.static_metadata.classification_inconsistent",
                        "Swift emitted-metadata candidate was not classified as metadata",
                    ));
                }
                SwiftTypeMetadataSymbolEvidence::Unsupported { detail } => {
                    state.gap = Some(gap("swift.static_metadata.unsupported_symbol", detail));
                }
                SwiftTypeMetadataSymbolEvidence::Malformed { detail } => {
                    state.gap = Some(gap("swift.static_metadata.malformed_symbol", detail));
                }
            }
            Ok(())
        },
    ) {
        Ok(candidates) => candidates,
        Err(error) => {
            return rejected_static_metadata(
                0,
                "swift.static_metadata.symbol_table_malformed",
                format!("Swift static metadata symbol-table traversal failed: {error}"),
            );
        }
    };

    if let Some(gap) = candidates.gap {
        return rejected_static_metadata_gap(candidates.attempted, gap);
    }
    if candidates.attempted == 0 {
        return absent_static_metadata();
    }

    let mut records = Vec::with_capacity(candidates.records.len());
    for candidate in candidates.records {
        let record = match decode_static_metadata_record(macho, resolver, candidate) {
            Ok(record) => record,
            Err(error) => {
                return rejected_static_metadata(
                    candidates.attempted,
                    "swift.static_metadata.record_rejected",
                    error,
                );
            }
        };
        records.push(record);
    }
    records.sort_by(|left, right| {
        left.qualified_name
            .cmp(&right.qualified_name)
            .then_with(|| left.metadata_va.cmp(&right.metadata_va))
    });
    if records
        .windows(2)
        .any(|pair| pair[0].qualified_name == pair[1].qualified_name)
    {
        return rejected_static_metadata(
            candidates.attempted,
            "swift.static_metadata.ambiguous_identity",
            "Swift static metadata identity is ambiguous",
        );
    }

    validated_static_metadata(SwiftStaticMetadataBatchV1 {
        outcome: SwiftDecodeOutcomeV1::Complete,
        conservation: SwiftObservationConservationV1 {
            attempted: candidates.attempted,
            included: candidates.attempted,
            unknown: 0,
            excluded: 0,
        },
        records,
        gaps: Vec::new(),
    })
}

fn decode_static_metadata_record(
    macho: &MachoFile<'_>,
    resolver: &PointerResolver<'_, '_>,
    candidate: StaticMetadataCandidate,
) -> Result<MachoSwiftStaticMetadataV1, String> {
    let kind = match candidate.identity.kind {
        SwiftNominalMetadataKind::Class => MachoSwiftNominalKindV1::Class,
        SwiftNominalMetadataKind::Struct => MachoSwiftNominalKindV1::Struct,
        SwiftNominalMetadataKind::Enum => MachoSwiftNominalKindV1::Enum,
    };
    let qualified_name = candidate.identity.name;
    let metadata_va = candidate.metadata_va;
    let (value_witness_slot, descriptor_slot, evidence_va, evidence_length) = match kind {
        MachoSwiftNominalKindV1::Class => (
            None,
            metadata_va
                .checked_add(64)
                .ok_or_else(|| "Swift class metadata descriptor slot overflows".to_string())?,
            metadata_va,
            72,
        ),
        MachoSwiftNominalKindV1::Struct | MachoSwiftNominalKindV1::Enum => (
            Some(
                metadata_va
                    .checked_sub(8)
                    .ok_or_else(|| "Swift metadata address underflows".to_string())?,
            ),
            metadata_va
                .checked_add(8)
                .ok_or_else(|| "Swift metadata descriptor slot overflows".to_string())?,
            metadata_va
                .checked_sub(8)
                .ok_or_else(|| "Swift metadata evidence underflows".to_string())?,
            24,
        ),
        MachoSwiftNominalKindV1::Protocol => {
            return Err("Swift protocol metadata cannot be a type instance".into());
        }
    };
    let value_witness_table = value_witness_slot
        .map(|slot| resolve_static_pointer(resolver, Va(slot)))
        .transpose()?;
    let descriptor = resolve_static_pointer(resolver, Va(descriptor_slot))?;
    let layout = match value_witness_table.as_ref() {
        Some(MachoSwiftStaticPointerTargetV1::Local { va }) => {
            Some(read_value_witness_layout(macho, *va)?)
        }
        Some(MachoSwiftStaticPointerTargetV1::External { .. }) | None => None,
    };
    let raw = macho
        .read_bytes_at_va(
            Va(evidence_va),
            usize::try_from(evidence_length)
                .map_err(|_| "Swift metadata evidence length exceeds host".to_string())?,
        )
        .map_err(|error| format!("Swift metadata record is truncated: {error}"))?;
    Ok(MachoSwiftStaticMetadataV1 {
        qualified_name,
        kind,
        metadata_va,
        descriptor,
        value_witness_table,
        evidence_va,
        evidence_length,
        layout,
        raw_sha256: EvidenceDigest::of(raw),
    })
}

fn is_emitted_metadata_candidate(name: &str) -> bool {
    let candidate = name.strip_prefix('_').unwrap_or(name);
    (candidate.starts_with("$s") || candidate.starts_with("$S") || candidate.starts_with("$e"))
        && candidate.ends_with('N')
}

fn gap(code: &str, safe_detail: impl Into<String>) -> SwiftDecodeGapV1 {
    SwiftDecodeGapV1 {
        code: code.into(),
        section: None,
        record_index: None,
        safe_detail: safe_detail.into(),
    }
}

fn absent_static_metadata() -> SwiftStaticMetadataBatchV1 {
    validated_static_metadata(SwiftStaticMetadataBatchV1 {
        outcome: SwiftDecodeOutcomeV1::Absent,
        records: Vec::new(),
        gaps: Vec::new(),
        conservation: SwiftObservationConservationV1 {
            attempted: 0,
            included: 0,
            unknown: 0,
            excluded: 0,
        },
    })
}

fn rejected_static_metadata(
    attempted: u64,
    code: &str,
    safe_detail: impl Into<String>,
) -> SwiftStaticMetadataBatchV1 {
    rejected_static_metadata_gap(attempted, gap(code, safe_detail))
}

fn rejected_static_metadata_gap(
    attempted: u64,
    gap: SwiftDecodeGapV1,
) -> SwiftStaticMetadataBatchV1 {
    validated_static_metadata(SwiftStaticMetadataBatchV1 {
        outcome: SwiftDecodeOutcomeV1::Rejected,
        records: Vec::new(),
        gaps: vec![gap],
        conservation: SwiftObservationConservationV1 {
            attempted,
            included: 0,
            unknown: attempted,
            excluded: 0,
        },
    })
}

fn validated_static_metadata(batch: SwiftStaticMetadataBatchV1) -> SwiftStaticMetadataBatchV1 {
    debug_assert!(batch.validate().is_ok());
    batch
}

fn resolve_static_pointer(
    resolver: &PointerResolver<'_, '_>,
    slot: Va,
) -> Result<MachoSwiftStaticPointerTargetV1, String> {
    match resolver
        .observe_at_va(slot)
        .map_err(|error| format!("Swift static pointer resolution failed: {error}"))?
        .target
    {
        PointerTarget::Null => Err("Swift static pointer is null".into()),
        PointerTarget::Address(address) => {
            Ok(MachoSwiftStaticPointerTargetV1::Local { va: address.0 })
        }
        PointerTarget::Import {
            name,
            library_ordinal,
        } => Ok(MachoSwiftStaticPointerTargetV1::External {
            symbol: name,
            library_ordinal: library_ordinal.ok_or_else(|| {
                "Swift imported pointer lacks a dynamic-library ordinal".to_string()
            })?,
        }),
    }
}

fn read_value_witness_layout(
    macho: &MachoFile<'_>,
    table_va: u64,
) -> Result<MachoSwiftValueWitnessLayoutV1, String> {
    let scalars_va = table_va
        .checked_add(64)
        .ok_or_else(|| "Swift value-witness scalar address overflows".to_string())?;
    let raw = macho
        .read_bytes_at_va(Va(scalars_va), 24)
        .map_err(|error| format!("Swift value-witness layout is truncated: {error}"))?;
    let endian = macho.endian();
    let size = endian.interpret_u64(u64::from_ne_bytes(
        raw[0..8].try_into().expect("eight-byte checked slice"),
    ));
    let stride = endian.interpret_u64(u64::from_ne_bytes(
        raw[8..16].try_into().expect("eight-byte checked slice"),
    ));
    let flags = endian.interpret_u32(u32::from_ne_bytes(
        raw[16..20].try_into().expect("four-byte checked slice"),
    ));
    let extra_inhabitant_count = endian.interpret_u32(u32::from_ne_bytes(
        raw[20..24].try_into().expect("four-byte checked slice"),
    ));
    let alignment = u64::from(flags & 0xff)
        .checked_add(1)
        .ok_or_else(|| "Swift value-witness alignment overflows".to_string())?;
    if !alignment.is_power_of_two() || stride < size {
        return Err("Swift value-witness layout violates ABI invariants".into());
    }
    Ok(MachoSwiftValueWitnessLayoutV1 {
        table_va,
        size,
        stride,
        alignment,
        extra_inhabitant_count,
        flags,
        raw_sha256: EvidenceDigest::of(raw),
    })
}
