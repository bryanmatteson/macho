use std::num::NonZeroUsize;

use crate::report::disassembly::{
    DisassemblyRecord, DisassemblyStatus, RangeEndSource, SelectionSource, SymbolSource,
};

use super::*;

fn request(selection: DisassemblySelection) -> DisassemblyRequest {
    DisassemblyRequest {
        selection,
        ..DisassemblyRequest::default()
    }
}

#[test]
fn public_selector_constructors_reject_empty_or_malformed_states() {
    assert!(NonEmpty::<String>::try_from_vec(Vec::new()).is_err());
    assert!(SectionSelector::new("", "__text").is_err());
    assert!(SectionSelector::new("__TEXT", "bad,name").is_err());
    let empty_name =
        DisassemblySelection::Symbols(NonEmpty::try_from_vec(vec![String::new()]).unwrap());
    assert!(
        DisassemblyRequest::new(
            SliceSelection::All,
            empty_name,
            DecodeMode::Recovering,
            false,
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        )
        .is_err()
    );
}

#[test]
fn request_constructor_applies_the_symbol_limit_after_deduplication() {
    let repeated = symbols(&["_main", "_main"]);
    assert!(
        DisassemblyRequest::new(
            SliceSelection::All,
            repeated,
            DecodeMode::Recovering,
            false,
            NonZeroUsize::new(1).unwrap(),
            NonZeroUsize::new(1).unwrap(),
        )
        .is_ok()
    );

    let over_limit = symbols(&["_main", "_main", "_helper"]);
    let error = DisassemblyRequest::new(
        SliceSelection::All,
        over_limit,
        DecodeMode::Recovering,
        false,
        NonZeroUsize::new(1).unwrap(),
        NonZeroUsize::new(1).unwrap(),
    )
    .unwrap_err();
    assert_eq!(error.code(), REQUEST_INVALID_CODE);
}

fn symbols(names: &[&str]) -> DisassemblySelection {
    DisassemblySelection::Symbols(
        NonEmpty::try_from_vec(names.iter().map(|name| (*name).to_owned()).collect()).unwrap(),
    )
}

fn sections(values: &[(&str, &str)]) -> DisassemblySelection {
    DisassemblySelection::Sections(
        NonEmpty::try_from_vec(
            values
                .iter()
                .map(|(segment, section)| SectionSelector::new(*segment, *section).unwrap())
                .collect(),
        )
        .unwrap(),
    )
}

#[test]
fn x86_recovery_accounts_for_every_selected_byte() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    let slice = &report.slices[0];
    assert_eq!(slice.decoded_bytes, 0x40);
    assert_eq!(slice.status, DisassemblyStatus::Partial);
    assert!(matches!(
        slice.regions[0].records.last(),
        Some(DisassemblyRecord::Gap { code, .. }) if code == "insn.decode.invalid"
    ));
    let encoded = serde_json::to_vec(&report).unwrap();
    let decoded: crate::report::disassembly::DisassemblyReport =
        serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, report);
}

#[test]
fn default_selection_accepts_either_instruction_flag() {
    for flags in [0x8000_0000u32, 0x0000_0400] {
        let mut bytes = macho_test_support::disassembly_x86_64();
        bytes[168..172].copy_from_slice(&flags.to_le_bytes());
        let container = macho_core::parse(&bytes).unwrap();
        let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
        assert_eq!(report.slices[0].regions.len(), 1);
    }
    let mut bytes = macho_test_support::disassembly_x86_64();
    bytes[168..172].copy_from_slice(&0u32.to_le_bytes());
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    assert!(report.slices[0].regions.is_empty());
}

#[test]
fn explicit_sections_deduplicate_decode_unflagged_and_reject_missing() {
    let mut bytes = macho_test_support::disassembly_x86_64();
    bytes[168..172].copy_from_slice(&0u32.to_le_bytes());
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(
        &container,
        &request(sections(&[("__TEXT", "__text"), ("__TEXT", "__text")])),
    )
    .unwrap();
    assert_eq!(report.slices[0].regions.len(), 1);
    assert_eq!(
        report.slices[0].regions[0].selection_source,
        SelectionSource::ExplicitSection
    );
    assert!(
        !report.slices[0].regions[0]
            .instruction_flags
            .pure_instructions
    );
    assert!(
        !report.slices[0].regions[0]
            .instruction_flags
            .some_instructions
    );

    let error =
        disassemble(&container, &request(sections(&[("__TEXT", "__missing")]))).unwrap_err();
    assert_eq!(error.code(), SECTION_MISSING_CODE);
}

#[test]
fn address_count_and_structured_target_are_exact() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(2).unwrap()),
        }),
    )
    .unwrap();
    let region = &report.slices[0].regions[0];
    assert_eq!(region.emitted_instruction_count, 2);
    assert_eq!(region.records.len(), 2);
    assert!(matches!(
        &region.records[0],
        DisassemblyRecord::Instruction {
            kind: crate::report::disassembly::InstructionKind::Branch,
            direct_target: Some(_),
            ..
        }
    ));
}

#[test]
fn target_symbolication_requires_proven_range_ownership() {
    let mut bytes = macho_test_support::disassembly_x86_64();
    bytes[0x101] = 3;
    let container = macho_core::parse(&bytes).unwrap();
    let selection = DisassemblySelection::Address {
        start: Va(0x1_0000_0100),
        extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
    };
    let full = disassemble(&container, &request(selection.clone())).unwrap();
    let DisassemblyRecord::Instruction {
        direct_target: Some(target),
        ..
    } = &full.slices[0].regions[0].records[0]
    else {
        panic!("expected direct target")
    };
    assert_eq!(target.raw_symbol.as_deref(), Some("_helper"));
    assert_eq!(target.offset, Some(1));

    let mut bounded = request(selection);
    bounded.max_symbol_ranges_per_slice = NonZeroUsize::new(1).unwrap();
    let bounded = disassemble(&container, &bounded).unwrap();
    let DisassemblyRecord::Instruction {
        direct_target: Some(target),
        ..
    } = &bounded.slices[0].regions[0].records[0]
    else {
        panic!("expected direct target")
    };
    assert_eq!(target.va, 0x1_0000_0105);
    assert!(target.raw_symbol.is_none());
    assert!(target.offset.is_none());
}

#[test]
fn address_default_length_mapping_and_count_boundaries_are_exact() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let one = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
        }),
    )
    .unwrap();
    assert_eq!(one.slices[0].regions[0].emitted_instruction_count, 1);

    let length = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::ByteLength(NonZeroUsize::new(4).unwrap()),
        }),
    )
    .unwrap();
    assert_eq!(length.slices[0].decoded_bytes, 4);
    assert_eq!(length.slices[0].regions[0].examined_end_va, 0x1_0000_0104);

    let unmapped = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_1000),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
        }),
    )
    .unwrap_err();
    assert_eq!(unmapped.code(), ADDRESS_UNMAPPED_CODE);

    let cross = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_013f),
            extent: AddressExtent::ByteLength(NonZeroUsize::new(2).unwrap()),
        }),
    )
    .unwrap_err();
    assert_eq!(cross.code(), ADDRESS_CROSS_SECTION_CODE);

    let unsatisfied = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_013f),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(2).unwrap()),
        }),
    )
    .unwrap_err();
    assert_eq!(unsatisfied.code(), COUNT_UNSATISFIED_CODE);
}

#[test]
fn supported_architecture_records_and_targets_are_complete() {
    for (bytes, cpu_type, cpu_subtype, size, raw) in [
        (
            macho_test_support::disassembly_x86_64(),
            CPU_TYPE_X86_64,
            3,
            2,
            "eb02",
        ),
        (
            macho_test_support::disassembly_arm64(),
            CPU_TYPE_ARM64,
            0,
            4,
            "01000014",
        ),
        (
            macho_test_support::disassembly_arm64e(),
            CPU_TYPE_ARM64,
            CPU_SUBTYPE_ARM64E,
            4,
            "01000014",
        ),
    ] {
        let container = macho_core::parse(&bytes).unwrap();
        let report = disassemble(
            &container,
            &request(DisassemblySelection::Address {
                start: Va(0x1_0000_0100),
                extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
            }),
        )
        .unwrap();
        let slice = &report.slices[0];
        assert_eq!(slice.identity.image.architecture.cpu_type, cpu_type);
        assert_eq!(slice.identity.image.architecture.cpu_subtype, cpu_subtype);
        match &slice.regions[0].records[0] {
            DisassemblyRecord::Instruction {
                va,
                thin_file_offset,
                container_file_offset,
                size: actual_size,
                bytes,
                text,
                kind,
                direct_target,
            } => {
                assert_eq!(*va, 0x1_0000_0100);
                assert_eq!(*thin_file_offset, 0x100);
                assert_eq!(*container_file_offset, 0x100);
                assert_eq!(*actual_size, size);
                assert_eq!(bytes.as_str(), raw);
                assert!(!text.is_empty());
                assert_eq!(*kind, crate::report::disassembly::InstructionKind::Branch);
                let target = direct_target.as_ref().unwrap();
                assert_eq!(target.va, 0x1_0000_0104);
                assert_eq!(target.raw_symbol.as_deref(), Some("_helper"));
                assert_eq!(target.display_symbol.as_deref(), Some("_helper"));
                assert_eq!(target.offset, Some(0));
            }
            record => panic!("expected instruction, got {record:?}"),
        }
    }
}

#[test]
fn unsupported_cpu_is_never_silently_skipped() {
    let bytes = macho_test_support::thin64_unknown_cpu(2);
    let container = macho_core::parse(&bytes).unwrap();
    let error = disassemble(&container, &DisassemblyRequest::default()).unwrap_err();
    assert_eq!(error.code(), ARCH_UNSUPPORTED_CODE);
    assert!(error.message().contains("0x01007fff"));
}

#[test]
fn exact_unknown_and_mixed_fat_unsupported_slices_fail_closed() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let request = DisassemblyRequest {
        arches: SliceSelection::Exact(Architecture {
            cpu_type: macho_test_support::CPU_TYPE_UNKNOWN_64 as i32,
            cpu_subtype: 0,
        }),
        ..DisassemblyRequest::default()
    };
    assert_eq!(
        disassemble(&container, &request).unwrap_err().code(),
        ARCH_UNSUPPORTED_CODE
    );

    let mixed = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_X86_64,
            3,
            macho_test_support::disassembly_x86_64(),
        ),
        (
            macho_test_support::CPU_TYPE_UNKNOWN_64,
            0,
            macho_test_support::thin64_unknown_cpu(2),
        ),
    ]);
    let container = macho_core::parse(&mixed).unwrap();
    assert_eq!(
        disassemble(&container, &DisassemblyRequest::default())
            .unwrap_err()
            .code(),
        ARCH_UNSUPPORTED_CODE
    );
}

#[test]
fn strict_decode_is_fail_closed() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let request = DisassemblyRequest {
        mode: DecodeMode::Strict,
        ..DisassemblyRequest::default()
    };
    let error = disassemble(&container, &request).unwrap_err();
    assert_eq!(error.code(), "insn.decode.invalid");
}

#[test]
fn x86_recovery_units_are_atomic_at_decoded_byte_limits() {
    let mut bytes = macho_test_support::disassembly_x86_64();
    bytes[0x13e] = 0x0f;
    bytes[0x13f] = 0xff;
    let container = macho_core::parse(&bytes).unwrap();
    let selection = DisassemblySelection::Address {
        start: Va(0x1_0000_013d),
        extent: AddressExtent::ByteLength(NonZeroUsize::new(3).unwrap()),
    };

    let mut inside = request(selection.clone());
    inside.max_decoded_bytes_per_slice = NonZeroUsize::new(2).unwrap();
    let inside = disassemble(&container, &inside).unwrap();
    let region = &inside.slices[0].regions[0];
    assert_eq!(inside.slices[0].decoded_bytes, 1);
    assert_eq!(region.records.len(), 1);
    assert_eq!(region.next_unexamined_va, Some(0x1_0000_013e));

    let mut exact = request(selection);
    exact.max_decoded_bytes_per_slice = NonZeroUsize::new(3).unwrap();
    let exact = disassemble(&container, &exact).unwrap();
    let region = &exact.slices[0].regions[0];
    assert_eq!(exact.slices[0].decoded_bytes, 3);
    assert!(matches!(
        &region.records[1],
        DisassemblyRecord::Gap { bytes, .. } if bytes.as_str() == "0fff"
    ));
}

#[test]
fn clipped_instructions_and_arm_alignment_are_uniform() {
    let x86 = macho_test_support::disassembly_x86_64();
    let x86_container = macho_core::parse(&x86).unwrap();
    let clipped = DisassemblySelection::Address {
        start: Va(0x1_0000_0100),
        extent: AddressExtent::ByteLength(NonZeroUsize::new(1).unwrap()),
    };
    let recovering = disassemble(&x86_container, &request(clipped.clone())).unwrap();
    assert!(matches!(
        &recovering.slices[0].regions[0].records[0],
        DisassemblyRecord::Gap { code, .. } if code == PARTIAL_INSTRUCTION_CODE
    ));
    let mut strict = request(clipped);
    strict.mode = DecodeMode::Strict;
    assert_eq!(
        disassemble(&x86_container, &strict).unwrap_err().code(),
        PARTIAL_INSTRUCTION_CODE
    );

    let arm = macho_test_support::disassembly_arm64();
    let arm_container = macho_core::parse(&arm).unwrap();
    let mut strict_arm = request(DisassemblySelection::Address {
        start: Va(0x1_0000_0100),
        extent: AddressExtent::ByteLength(NonZeroUsize::new(2).unwrap()),
    });
    strict_arm.mode = DecodeMode::Strict;
    assert_eq!(
        disassemble(&arm_container, &strict_arm).unwrap_err().code(),
        PARTIAL_INSTRUCTION_CODE
    );

    let address = request(DisassemblySelection::Address {
        start: Va(0x1_0000_0101),
        extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
    });
    assert_eq!(
        disassemble(&arm_container, &address).unwrap_err().code(),
        ADDRESS_UNALIGNED_CODE
    );

    for selection in [
        DisassemblySelection::ExecutableSections,
        sections(&[("__TEXT", "__text")]),
    ] {
        let mut unaligned = arm.clone();
        unaligned[136..144].copy_from_slice(&0x1_0000_0101u64.to_le_bytes());
        let container = macho_core::parse(&unaligned).unwrap();
        assert_eq!(
            disassemble(&container, &request(selection))
                .unwrap_err()
                .code(),
            ADDRESS_UNALIGNED_CODE
        );
    }

    let mut unaligned_symbol = arm;
    unaligned_symbol[0x148..0x150].copy_from_slice(&0x1_0000_0101u64.to_le_bytes());
    let container = macho_core::parse(&unaligned_symbol).unwrap();
    assert_eq!(
        disassemble(&container, &request(symbols(&["_main"])))
            .unwrap_err()
            .code(),
        ADDRESS_UNALIGNED_CODE
    );
}

#[test]
fn exact_symbol_uses_next_code_owner() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &request(symbols(&["_main"]))).unwrap();
    let region = &report.slices[0].regions[0];
    assert_eq!(region.selection_source, SelectionSource::Symbol);
    assert_eq!(region.requested_end_va, Some(0x1_0000_0104));
    assert_eq!(region.end_source, Some(RangeEndSource::Nlist));
}

#[test]
fn demangling_changes_display_names_without_changing_exact_matching() {
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "__ZN3foo3barEv",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_helper",
            external: true,
            defined: true,
        },
    ]);
    let container = macho_core::parse(&bytes).unwrap();
    let mut request = request(symbols(&["__ZN3foo3barEv"]));
    request.demangle = true;
    let report = disassemble(&container, &request).unwrap();
    let label = &report.slices[0].regions[0].labels[0];
    assert_eq!(label.raw_name, "__ZN3foo3barEv");
    assert_ne!(label.display_name, label.raw_name);
    assert!(label.display_name.contains("foo"));
}

#[test]
fn exact_symbols_reject_missing_ambiguous_and_non_code_inputs() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    assert_eq!(
        disassemble(&container, &request(symbols(&["_missing"])))
            .unwrap_err()
            .code(),
        SYMBOL_MISSING_CODE
    );

    let ambiguous = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_same",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_same",
            external: true,
            defined: true,
        },
    ]);
    let container = macho_core::parse(&ambiguous).unwrap();
    let error = disassemble(&container, &request(symbols(&["_same"]))).unwrap_err();
    assert_eq!(error.code(), SYMBOL_AMBIGUOUS_CODE);
    assert!(error.message().contains("select --address"));

    let data =
        macho_test_support::thin64_x86_64_with_data_symbols(&[macho_test_support::SymbolFixture {
            name: "_data",
            external: true,
            defined: true,
        }]);
    let container = macho_core::parse(&data).unwrap();
    assert_eq!(
        disassemble(&container, &request(symbols(&["_data"])))
            .unwrap_err()
            .code(),
        SYMBOL_NON_CODE_CODE
    );
}

#[test]
fn export_trie_symbols_use_image_relative_addresses_and_exact_extents() {
    let bytes = macho_test_support::disassembly_export_symbol();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &request(symbols(&["_exported"]))).unwrap();
    let region = &report.slices[0].regions[0];
    assert_eq!(region.start_va, 0x1_0000_0100);
    assert_eq!(region.requested_end_va, Some(0x1_0000_0104));
    assert_eq!(region.range_source, Some(SymbolSource::ExportTrie));
    assert_eq!(region.end_source, Some(RangeEndSource::Nlist));

    let bytes = macho_test_support::disassembly_zero_export();
    let container = macho_core::parse(&bytes).unwrap();
    let error = disassemble(&container, &request(symbols(&["_zero"]))).unwrap_err();
    assert_eq!(error.code(), SYMBOL_NON_CODE_CODE);
}

#[test]
fn requested_symbol_extent_survives_a_one_alias_budget() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let mut request = request(symbols(&["_main"]));
    request.max_symbol_ranges_per_slice = NonZeroUsize::new(1).unwrap();
    let report = disassemble(&container, &request).unwrap();
    let region = &report.slices[0].regions[0];
    assert_eq!(region.requested_end_va, Some(0x1_0000_0104));
    assert!(report.slices[0].symbol_ranges_truncated);
}

#[test]
fn requested_extent_keeps_a_prior_stream_boundary_after_eviction() {
    let mut bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_later",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        },
    ]);
    bytes[0x148..0x150].copy_from_slice(&0x1_0000_0104u64.to_le_bytes());
    bytes[0x158..0x160].copy_from_slice(&0x1_0000_0100u64.to_le_bytes());
    let container = macho_core::parse(&bytes).unwrap();
    let mut request = request(symbols(&["_main"]));
    request.max_symbol_ranges_per_slice = NonZeroUsize::new(1).unwrap();
    let report = disassemble(&container, &request).unwrap();
    let region = &report.slices[0].regions[0];
    assert_eq!(region.requested_end_va, Some(0x1_0000_0104));
    assert_eq!(region.end_source, Some(RangeEndSource::Nlist));
    assert!(report.slices[0].symbol_ranges_truncated);
}

#[test]
fn objc_imp_is_a_symbol_range_end_authority() {
    let bytes = macho_test_support::disassembly_objc_boundary();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &request(symbols(&["_main"]))).unwrap();
    let region = &report.slices[0].regions[0];
    assert_eq!(region.end_source, Some(RangeEndSource::ObjcMetadata));
    assert_eq!(region.requested_end_va, Some(0x1_0000_0204));
    assert_eq!(region.examined_end_va, 0x1_0000_0204);
    assert_eq!(
        region
            .records
            .iter()
            .map(DisassemblyRecord::byte_len)
            .sum::<u64>(),
        4
    );
}

#[test]
fn objc_category_instance_and_class_labels_keep_distinct_method_kinds() {
    let bytes = macho_test_support::disassembly_objc_category_labels();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    let labels = &report.slices[0].regions[0].labels;
    assert!(labels.iter().any(|label| {
        label.va == 0x1_0000_0204
            && label.raw_name.starts_with("-[")
            && label.raw_name.contains("(Fixture) next]")
    }));
    assert!(labels.iter().any(|label| {
        label.va == 0x1_0000_0208
            && label.raw_name.starts_with("+[")
            && label.raw_name.contains("(Fixture) next]")
    }));
}

#[test]
fn objc_display_label_is_not_an_exact_symbol_selector() {
    let bytes = macho_test_support::disassembly_objc_boundary();
    let container = macho_core::parse(&bytes).unwrap();
    let error = disassemble(&container, &request(symbols(&["-[Fixture next]"]))).unwrap_err();
    assert_eq!(error.code(), SYMBOL_MISSING_CODE);
}

#[test]
fn malformed_objc_metadata_is_fatal_only_for_symbol_selection() {
    let bytes = macho_test_support::disassembly_malformed_objc();
    let container = macho_core::parse(&bytes).unwrap();
    let error = disassemble(&container, &request(symbols(&["_main"]))).unwrap_err();
    assert_eq!(error.code(), SYMBOL_METADATA_INVALID_CODE);

    let report = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
        }),
    )
    .unwrap();
    assert_eq!(report.slices[0].status, DisassemblyStatus::Partial);
    assert!(
        report.slices[0]
            .issues
            .iter()
            .any(|issue| issue.code == SYMBOL_METADATA_INVALID_CODE)
    );
    assert!(!report.slices[0].regions[0].records.is_empty());
}

#[test]
fn malformed_nested_objc_imp_ownership_never_preserves_a_successful_prefix() {
    let mut bytes = macho_test_support::disassembly_objc_boundary();
    bytes[224..232].copy_from_slice(&16u64.to_le_bytes());
    bytes[0x248..0x250].copy_from_slice(&u64::MAX.to_le_bytes());
    let container = macho_core::parse(&bytes).unwrap();

    let error = disassemble(&container, &request(symbols(&["_main"]))).unwrap_err();
    assert_eq!(error.code(), SYMBOL_METADATA_INVALID_CODE);

    let report = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0200),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
        }),
    )
    .unwrap();
    assert_eq!(report.slices[0].status, DisassemblyStatus::Partial);
    assert!(report.slices[0].regions[0].labels.is_empty());
    assert!(
        report.slices[0]
            .issues
            .iter()
            .any(|issue| issue.code == SYMBOL_METADATA_INVALID_CODE)
    );
}

#[test]
fn malformed_nlist_and_export_metadata_are_fatal_only_for_symbol_selection() {
    for (bytes, lenient) in [
        (macho_test_support::disassembly_malformed_nlist(), true),
        (macho_test_support::disassembly_malformed_export(), false),
    ] {
        let container = if lenient {
            macho_core::parse_with_options(
                &bytes,
                &macho_core::ParseOptions {
                    mode: macho_core::ParseMode::Forensic,
                    limits: macho_core::ParseLimits::default(),
                },
            )
            .unwrap()
            .container
        } else {
            macho_core::parse(&bytes).unwrap()
        };
        let error = disassemble(&container, &request(symbols(&["_main"]))).unwrap_err();
        assert_eq!(error.code(), SYMBOL_METADATA_INVALID_CODE);

        let report = disassemble(
            &container,
            &request(DisassemblySelection::Address {
                start: Va(0x1_0000_0100),
                extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
            }),
        )
        .unwrap();
        assert_eq!(report.slices[0].status, DisassemblyStatus::Partial);
        assert!(
            report.slices[0]
                .issues
                .iter()
                .any(|issue| issue.code == SYMBOL_METADATA_INVALID_CODE)
        );
        assert_eq!(report.slices[0].regions[0].emitted_instruction_count, 1);
    }
}

#[test]
fn same_va_aliases_each_consume_one_budget_unit() {
    let bytes = macho_test_support::disassembly_x86_64_aliases(30);
    let container = macho_core::parse(&bytes).unwrap();
    let mut request = request(symbols(&["_alias0000"]));
    request.max_symbol_ranges_per_slice = NonZeroUsize::new(3).unwrap();
    let report = disassemble(&container, &request).unwrap();
    let slice = &report.slices[0];
    assert!(slice.symbol_ranges_truncated);
    assert_eq!(slice.regions[0].labels.len(), 3);
    assert!(
        slice.regions[0]
            .labels
            .windows(2)
            .all(|pair| pair[0].raw_name < pair[1].raw_name)
    );
}

#[test]
fn direct_target_uses_the_lowest_retained_equal_va_alias() {
    let mut bytes = macho_test_support::disassembly_x86_64_aliases(5);
    bytes[0x100..0x102].copy_from_slice(&[0xeb, 0x00]);
    let container = macho_core::parse(&bytes).unwrap();
    let mut request = request(DisassemblySelection::Address {
        start: Va(0x1_0000_0100),
        extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
    });
    request.max_symbol_ranges_per_slice = NonZeroUsize::new(3).unwrap();
    let report = disassemble(&container, &request).unwrap();
    let DisassemblyRecord::Instruction {
        direct_target: Some(target),
        ..
    } = &report.slices[0].regions[0].records[0]
    else {
        panic!("expected direct target")
    };
    assert_eq!(target.va, 0x1_0000_0102);
    assert!(target.raw_symbol.is_none());

    bytes[0x100..0x102].copy_from_slice(&[0xeb, 0xfe]);
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &request).unwrap();
    let DisassemblyRecord::Instruction {
        direct_target: Some(target),
        ..
    } = &report.slices[0].regions[0].records[0]
    else {
        panic!("expected direct target")
    };
    assert_eq!(target.va, 0x1_0000_0100);
    assert_eq!(target.raw_symbol.as_deref(), Some("_alias0000"));
    assert_eq!(target.offset, Some(0));
}

#[test]
fn requested_names_are_reserved_ahead_of_auxiliary_labels() {
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_aux",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_requested_a",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "_requested_b",
            external: true,
            defined: true,
        },
    ]);
    let container = macho_core::parse(&bytes).unwrap();
    let mut request = request(symbols(&["_requested_a", "_requested_b"]));
    request.max_symbol_ranges_per_slice = NonZeroUsize::new(2).unwrap();
    let report = disassemble(&container, &request).unwrap();
    let retained = report.slices[0]
        .regions
        .iter()
        .flat_map(|region| region.labels.iter())
        .map(|label| label.raw_name.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(retained.len(), 2);
    assert!(retained.contains("_requested_a"));
    assert!(retained.contains("_requested_b"));
    assert!(!retained.contains("_aux"));
}

#[test]
fn caller_clipped_arm_word_is_not_reported_as_corrupt() {
    let bytes = macho_test_support::disassembly_arm64e();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::ByteLength(NonZeroUsize::new(2).unwrap()),
        }),
    )
    .unwrap();
    assert!(matches!(
        &report.slices[0].regions[0].records[0],
        DisassemblyRecord::Gap { code, .. }
            if code == "analysis.disassembly.selection.partial_instruction"
    ));
}

#[test]
fn fat_order_and_raw_subtype_selection_are_stable() {
    let bytes = macho_test_support::disassembly_fat();
    let container = macho_core::parse(&bytes).unwrap();
    let all = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    assert_eq!(all.slices.len(), 2);
    assert_eq!(
        all.slices[0].identity.image.architecture.cpu_type,
        CPU_TYPE_X86_64
    );
    assert_eq!(
        all.slices[1].identity.image.architecture.cpu_subtype,
        CPU_SUBTYPE_ARM64E
    );
    let selected = resolve_architecture_selector(&container, "arm64e").unwrap();
    assert_eq!(selected.cpu_subtype, CPU_SUBTYPE_ARM64E);
}

#[test]
fn thin_and_fat_identity_offsets_use_both_coordinate_systems() {
    let thin_bytes = macho_test_support::disassembly_x86_64();
    let thin_container = macho_core::parse(&thin_bytes).unwrap();
    let thin = disassemble(
        &thin_container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
        }),
    )
    .unwrap();
    let DisassemblyRecord::Instruction {
        thin_file_offset,
        container_file_offset,
        ..
    } = &thin.slices[0].regions[0].records[0]
    else {
        panic!("expected instruction")
    };
    assert_eq!(thin_file_offset, container_file_offset);
    assert_eq!(thin.slices[0].container_offset, 0);
    assert_eq!(thin.slices[0].slice_size, thin_bytes.len() as u64);

    let fat_bytes = macho_test_support::disassembly_fat();
    let fat_container = macho_core::parse(&fat_bytes).unwrap();
    let architecture = resolve_architecture_selector(&fat_container, "x86_64").unwrap();
    let fat = disassemble(
        &fat_container,
        &DisassemblyRequest {
            arches: SliceSelection::Exact(architecture),
            selection: DisassemblySelection::Address {
                start: Va(0x1_0000_0100),
                extent: AddressExtent::InstructionCount(NonZeroUsize::new(1).unwrap()),
            },
            ..DisassemblyRequest::default()
        },
    )
    .unwrap();
    let DisassemblyRecord::Instruction {
        thin_file_offset,
        container_file_offset,
        ..
    } = &fat.slices[0].regions[0].records[0]
    else {
        panic!("expected instruction")
    };
    assert_eq!(
        *container_file_offset,
        fat.slices[0].container_offset + *thin_file_offset
    );
    assert_ne!(thin_file_offset, container_file_offset);
    assert_eq!(fat.slices[0].identity.image.slice_index, 0);
    assert_eq!(fat.slices[0].slice_size, thin_bytes.len() as u64);
}

#[test]
fn duplicate_display_architectures_require_a_raw_tuple() {
    let bytes = macho_test_support::disassembly_fat_x86_subtypes();
    let container = macho_core::parse(&bytes).unwrap();
    let error = resolve_architecture_selector(&container, "x86_64").unwrap_err();
    assert_eq!(error.code(), ARCH_AMBIGUOUS_CODE);
    assert!(error.message().contains("0x01000007:0x00000003"));
    assert!(error.message().contains("0x01000007:0x00000008"));
    let exact = resolve_architecture_selector(&container, "0x01000007:0x00000008").unwrap();
    assert_eq!(exact.cpu_subtype, 8);
}

#[test]
fn report_deserialization_rejects_unknown_fields_and_bad_version() {
    let bytes = macho_test_support::disassembly_arm64();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    let mut value = serde_json::to_value(report).unwrap();
    value["unknown"] = serde_json::json!(true);
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(value).is_err()
    );

    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    let mut value = serde_json::to_value(report).unwrap();
    value["schema_version"] = serde_json::json!(2);
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(value).is_err()
    );
}

#[test]
fn valid_empty_report_round_trips_through_the_typed_schema() {
    let mut bytes = macho_test_support::disassembly_x86_64();
    bytes[168..172].copy_from_slice(&0u32.to_le_bytes());
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    assert_eq!(report.slices.len(), 1);
    assert!(report.slices[0].regions.is_empty());
    report.validate().unwrap();

    let encoded = serde_json::to_vec(&report).unwrap();
    let decoded: crate::report::disassembly::DisassemblyReport =
        serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, report);
}

#[test]
fn report_validator_rejects_inconsistent_wire_evidence() {
    let bytes = macho_test_support::disassembly_arm64();
    let container = macho_core::parse(&bytes).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    let base = serde_json::to_value(report).unwrap();
    let rejects = |mutate: fn(&mut serde_json::Value)| {
        let mut value = base.clone();
        mutate(&mut value);
        assert!(
            serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(value).is_err()
        );
    };
    rejects(|value| value["container"]["content_sha256"] = serde_json::json!("ABC"));
    rejects(|value| value["container"]["slice_count"] = serde_json::json!(2));
    rejects(|value| value["slices"][0]["identity"]["image"]["byte_len"] = serde_json::json!(1));
    rejects(|value| value["slices"][0]["container_offset"] = serde_json::json!(1));
    rejects(|value| value["slices"][0]["decoded_bytes"] = serde_json::json!(1));
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][0]["bytes"] = serde_json::json!("0")
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][0]["kind"] = serde_json::json!("invalid")
    });
    rejects(|value| value["slices"][0]["regions"][0]["records"][0]["size"] = serde_json::json!(8));
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][1]["va"] = serde_json::json!(0x1_0000_010c_u64)
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][1]["va"] = serde_json::json!(0x1_0000_0100_u64)
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][1]["thin_file_offset"] =
            serde_json::json!(0x108_u64)
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][0]["direct_target"]["raw_symbol"] =
            serde_json::Value::Null
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][0]["kind"] = serde_json::json!("nop")
    });
    rejects(|value| {
        value["request"]["selection"] = serde_json::json!({
            "kind": "symbols",
            "names": ["_main"]
        })
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["selection_source"] = serde_json::json!("address")
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["requested_instruction_count"] = serde_json::json!(1)
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["examined_end_va"] = serde_json::json!(0x1_0000_013c_u64)
    });
    rejects(|value| {
        value["slices"][0]["regions"][0]["next_unexamined_va"] =
            serde_json::json!(0x1_0000_0140_u64)
    });
    rejects(|value| value["slices"][0]["decoded_bytes_truncated"] = serde_json::json!(true));
    rejects(|value| value["slices"][0]["status"] = serde_json::json!("partial"));
    rejects(|value| {
        value["slices"][0]["regions"][0]["records"][0]["unknown"] = serde_json::json!(true)
    });

    let fat_bytes = macho_test_support::disassembly_fat();
    let fat_container = macho_core::parse(&fat_bytes).unwrap();
    let fat = disassemble(&fat_container, &DisassemblyRequest::default()).unwrap();
    let mut duplicate = serde_json::to_value(&fat).unwrap();
    duplicate["slices"][1]["identity"]["image"]["slice_index"] =
        duplicate["slices"][0]["identity"]["image"]["slice_index"].clone();
    duplicate["slices"][1]["identity"]["image"]["architecture"] =
        duplicate["slices"][0]["identity"]["image"]["architecture"].clone();
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(duplicate).is_err()
    );

    let mut bad_fat_offset = serde_json::to_value(&fat).unwrap();
    bad_fat_offset["slices"][0]["regions"][0]["records"][0]["container_file_offset"] =
        serde_json::json!(0);
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(bad_fat_offset)
            .is_err()
    );

    let x86 = macho_test_support::disassembly_x86_64();
    let x86_container = macho_core::parse(&x86).unwrap();
    let recovering = disassemble(&x86_container, &DisassemblyRequest::default()).unwrap();
    let mut unknown_gap = recovering.clone();
    let gap_code = unknown_gap.slices[0].regions[0]
        .records
        .iter_mut()
        .find_map(|record| match record {
            DisassemblyRecord::Gap { code, .. } => Some(code),
            DisassemblyRecord::Instruction { .. } => None,
        })
        .expect("x86 recovery fixture contains a gap");
    *gap_code = "analysis.disassembly.gap.unknown".to_owned();
    assert!(unknown_gap.validate().is_err());
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(
            serde_json::to_value(unknown_gap).unwrap()
        )
        .is_err()
    );

    let mut strict_with_gap = serde_json::to_value(recovering).unwrap();
    strict_with_gap["request"]["mode"] = serde_json::json!("strict");
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(strict_with_gap)
            .is_err()
    );

    let objc = macho_test_support::disassembly_objc_boundary();
    let objc_container = macho_core::parse(&objc).unwrap();
    let symbol_report = disassemble(&objc_container, &request(symbols(&["_main"]))).unwrap();
    let mut objc_range_source = serde_json::to_value(symbol_report).unwrap();
    objc_range_source["slices"][0]["regions"][0]["range_source"] =
        serde_json::json!("objc_metadata");
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(objc_range_source)
            .is_err()
    );
}

#[test]
fn report_validator_rejects_false_truncation_after_fully_examined_extents() {
    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();

    let byte_report = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::ByteLength(NonZeroUsize::new(4).unwrap()),
        }),
    )
    .unwrap();
    let mut false_byte_truncation = serde_json::to_value(byte_report).unwrap();
    let byte_examined_end =
        false_byte_truncation["slices"][0]["regions"][0]["examined_end_va"].clone();
    assert_eq!(
        byte_examined_end,
        false_byte_truncation["slices"][0]["regions"][0]["requested_end_va"]
    );
    false_byte_truncation["slices"][0]["regions"][0]["next_unexamined_va"] = byte_examined_end;
    false_byte_truncation["slices"][0]["decoded_bytes_truncated"] = serde_json::json!(true);
    false_byte_truncation["slices"][0]["status"] = serde_json::json!("partial");
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(
            false_byte_truncation
        )
        .is_err()
    );

    let count_report = disassemble(
        &container,
        &request(DisassemblySelection::Address {
            start: Va(0x1_0000_0100),
            extent: AddressExtent::InstructionCount(NonZeroUsize::new(2).unwrap()),
        }),
    )
    .unwrap();
    let mut false_count_truncation = serde_json::to_value(count_report).unwrap();
    assert_eq!(
        false_count_truncation["slices"][0]["regions"][0]["emitted_instruction_count"],
        false_count_truncation["slices"][0]["regions"][0]["requested_instruction_count"]
    );
    let count_examined_end =
        false_count_truncation["slices"][0]["regions"][0]["examined_end_va"].clone();
    false_count_truncation["slices"][0]["regions"][0]["next_unexamined_va"] = count_examined_end;
    false_count_truncation["slices"][0]["decoded_bytes_truncated"] = serde_json::json!(true);
    false_count_truncation["slices"][0]["status"] = serde_json::json!("partial");
    assert!(
        serde_json::from_value::<crate::report::disassembly::DisassemblyReport>(
            false_count_truncation
        )
        .is_err()
    );
}

#[test]
fn disassembly_work_bounds() {
    fn assert_decode_bounds(stats: &WorkStats, decoder_window: u64) {
        assert!(
            stats.decode_attempts <= 2 * stats.examined_bytes + stats.unexamined_lookahead_bytes,
            "decode attempts must be covered by retained bytes or charged lookahead: {stats:?}"
        );
        assert!(
            stats.unexamined_lookahead_bytes <= stats.decode_eligible_bytes,
            "unexamined lookahead must remain inside decode-eligible bytes: {stats:?}"
        );
        assert!(
            stats.decoder_input_bytes <= decoder_window * stats.decode_attempts,
            "every decoder invocation must use one bounded architecture window: {stats:?}"
        );
    }

    fn assert_index_bounds(stats: &WorkStats) {
        assert!(
            stats.section_index_entries <= stats.sections_visited * 5,
            "two ownership span sets plus the name map must remain bounded: {stats:?}"
        );
        assert!(stats.metadata_traversals.iter().all(|count| *count <= 2));
    }

    let bytes = macho_test_support::disassembly_x86_64();
    let container = macho_core::parse(&bytes).unwrap();
    let run = |limit| {
        let request = DisassemblyRequest {
            max_decoded_bytes_per_slice: NonZeroUsize::new(limit).unwrap(),
            ..DisassemblyRequest::default()
        };
        disassemble_with_work_stats(&container, &request).unwrap()
    };
    let (n, n_stats) = run(16);
    let (two_n, two_n_stats) = run(32);
    assert_eq!(n.slices[0].decoded_bytes, 16);
    assert_eq!(two_n.slices[0].decoded_bytes, 32);
    let n_records: usize = n.slices[0]
        .regions
        .iter()
        .map(|region| region.records.len())
        .sum();
    let two_n_records: usize = two_n.slices[0]
        .regions
        .iter()
        .map(|region| region.records.len())
        .sum();
    assert!(two_n_records <= n_records * 2 + 1);
    assert!(two_n.slices[0].decoded_bytes <= n.slices[0].decoded_bytes * 2);
    assert_decode_bounds(&n_stats, 15);
    assert_decode_bounds(&two_n_stats, 15);
    assert_index_bounds(&n_stats);
    assert_index_bounds(&two_n_stats);
    assert!(two_n_stats.decode_attempts <= n_stats.decode_attempts * 2 + 2);
    assert!(two_n_stats.decoder_input_bytes <= n_stats.decoder_input_bytes * 2 + 16);
    assert!(two_n_stats.unexamined_lookahead_bytes <= n_stats.unexamined_lookahead_bytes * 2 + 1);
    assert!(two_n_stats.decode_eligible_bytes <= n_stats.decode_eligible_bytes * 2);
    assert!(two_n_stats.records_retained <= two_n_stats.examined_bytes);
    assert!(n_stats.records_retained <= n_stats.examined_bytes);
    assert_eq!(n_stats.raw_bytes_retained, n_stats.examined_bytes);
    assert_eq!(two_n_stats.raw_bytes_retained, two_n_stats.examined_bytes);
    assert_eq!(n_stats.container_bytes_hashed, bytes.len() as u64);
    assert_eq!(n_stats.slice_bytes_hashed, 0);
    assert!(n_stats.container_bytes_hashed + n_stats.slice_bytes_hashed <= bytes.len() as u64 * 2);
    assert!(two_n_stats.container_bytes_hashed <= n_stats.container_bytes_hashed * 2);
    assert!(two_n_stats.slice_bytes_hashed <= n_stats.slice_bytes_hashed * 2);
    for source in 0..3 {
        assert_eq!(
            two_n_stats.metadata_observations_visited[source],
            n_stats.metadata_observations_visited[source]
        );
        assert_eq!(
            two_n_stats.metadata_name_bytes_visited[source],
            n_stats.metadata_name_bytes_visited[source]
        );
    }
    assert_eq!(n_stats.metadata_observations_visited, [2, 0, 0]);
    assert_eq!(n_stats.metadata_name_bytes_visited, [12, 0, 0]);
    assert_eq!(n_stats.metadata_traversals, [1, 1, 0]);
    assert_eq!(two_n_stats.metadata_traversals, [1, 1, 0]);
    assert_eq!(n_stats.sections_visited, 1);
    assert_eq!(two_n_stats.sections_visited, 1);
    assert_eq!(n_stats.section_index_entries, 3);
    assert_eq!(two_n_stats.section_index_entries, 3);
    assert_eq!(n_stats.boundary_queries, 0);
    assert_eq!(two_n_stats.boundary_queries, 0);
    assert_eq!(n_stats.label_range_queries, 1);
    assert_eq!(two_n_stats.label_range_queries, 1);
    assert_eq!(
        two_n_stats.section_index_queries,
        n_stats.section_index_queries
    );
    assert_eq!(
        two_n_stats.target_owner_queries,
        n_stats.target_owner_queries
    );
    assert_eq!(two_n_stats.aliases_retained, n_stats.aliases_retained);
    assert!(two_n_stats.examined_bytes <= n_stats.examined_bytes * 2);
    assert!(two_n_stats.raw_bytes_retained <= n_stats.raw_bytes_retained * 2);
    assert!(two_n_stats.records_retained <= n_stats.records_retained * 2 + 1);
    assert!(n_stats.serialized_bytes > 0 && n_stats.owned_report_bytes > 0);
    assert_ne!(n_stats.serialized_bytes, n_stats.owned_report_bytes);
    let retained_name_bytes = n_stats.metadata_name_bytes_visited.iter().sum::<u64>();
    assert!(n_stats.owned_report_bytes <= n_stats.serialized_bytes + retained_name_bytes + 2048);
    assert!(two_n_stats.owned_report_bytes <= n_stats.owned_report_bytes * 2 + 2048);
    assert!(two_n_stats.serialized_bytes <= n_stats.serialized_bytes * 2 + 2048);

    let alias_bytes = macho_test_support::disassembly_x86_64_aliases(30);
    let alias_container = macho_core::parse(&alias_bytes).unwrap();
    let mut alias_request = request(symbols(&["_alias0000"]));
    alias_request.max_symbol_ranges_per_slice = NonZeroUsize::new(3).unwrap();
    let (alias_report, alias_stats) =
        disassemble_with_work_stats(&alias_container, &alias_request).unwrap();
    assert!(alias_report.slices[0].symbol_ranges_truncated);
    assert_eq!(alias_stats.aliases_retained, 3);
    assert_eq!(alias_stats.metadata_observations_visited[0], 60);
    assert_eq!(
        alias_stats.metadata_name_bytes_visited[0],
        60 * "_alias0000".len() as u64
    );
    assert_eq!(alias_stats.raw_bytes_retained, alias_stats.examined_bytes);
    assert_eq!(alias_stats.metadata_traversals, [2, 2, 0]);
    assert_decode_bounds(&alias_stats, 15);
    assert_index_bounds(&alias_stats);

    let alias_two_n_bytes = macho_test_support::disassembly_x86_64_aliases(60);
    let alias_two_n_container = macho_core::parse(&alias_two_n_bytes).unwrap();
    let (alias_two_n_report, alias_two_n_stats) =
        disassemble_with_work_stats(&alias_two_n_container, &alias_request).unwrap();
    assert!(alias_two_n_report.slices[0].symbol_ranges_truncated);
    assert_eq!(alias_two_n_stats.aliases_retained, 3);
    assert_eq!(alias_two_n_stats.metadata_traversals, [2, 2, 0]);
    assert_eq!(
        alias_two_n_stats.metadata_observations_visited[0],
        alias_stats.metadata_observations_visited[0] * 2
    );
    assert_eq!(
        alias_two_n_stats.metadata_name_bytes_visited[0],
        alias_stats.metadata_name_bytes_visited[0] * 2
    );
    assert!(alias_two_n_stats.section_index_queries <= alias_stats.section_index_queries * 2);
    assert_index_bounds(&alias_two_n_stats);

    let objc_bytes = macho_test_support::disassembly_objc_boundary();
    let objc_container = macho_core::parse(&objc_bytes).unwrap();
    let (_, objc_stats) =
        disassemble_with_work_stats(&objc_container, &request(symbols(&["_main"]))).unwrap();
    assert_eq!(objc_stats.metadata_traversals, [2, 2, 1]);
    assert_eq!(objc_stats.metadata_observations_visited[2], 1);
    assert_eq!(
        objc_stats.metadata_name_bytes_visited[2],
        "-[Fixture next]".len() as u64
    );
    assert_index_bounds(&objc_stats);

    let region_symbols = (0..8)
        .map(|index| format!("_region{index:02}"))
        .collect::<Vec<_>>();
    let region_fixtures = region_symbols
        .iter()
        .map(|name| macho_test_support::SymbolFixture {
            name,
            external: true,
            defined: true,
        })
        .collect::<Vec<_>>();
    let region_bytes = macho_test_support::thin64_x86_64_with_symbols(&region_fixtures);
    let region_container = macho_core::parse(&region_bytes).unwrap();
    let run_regions = |count: usize| {
        let selection = symbols(
            &region_symbols[..count]
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let mut request = request(selection);
        request.max_symbol_ranges_per_slice = NonZeroUsize::new(8).unwrap();
        disassemble_with_work_stats(&region_container, &request).unwrap()
    };
    let (region_n, region_n_stats) = run_regions(4);
    let (region_two_n, region_two_n_stats) = run_regions(8);
    assert_eq!(region_n.slices[0].regions.len(), 4);
    assert_eq!(region_two_n.slices[0].regions.len(), 8);
    assert_eq!(region_n_stats.boundary_queries, 4);
    assert_eq!(region_two_n_stats.boundary_queries, 8);
    assert_eq!(region_n_stats.label_range_queries, 4);
    assert_eq!(region_two_n_stats.label_range_queries, 8);
    assert!(region_two_n_stats.section_index_queries <= region_n_stats.section_index_queries * 2);
    assert_index_bounds(&region_n_stats);
    assert_index_bounds(&region_two_n_stats);

    let run_sections = |count| {
        let bytes = macho_test_support::disassembly_x86_64_sections(count);
        let container = macho_core::parse(&bytes).unwrap();
        disassemble_with_work_stats(&container, &DisassemblyRequest::default()).unwrap()
    };
    let (section_n, section_n_stats) = run_sections(4);
    let (section_two_n, section_two_n_stats) = run_sections(8);
    assert_eq!(section_n.slices[0].regions.len(), 4);
    assert_eq!(section_two_n.slices[0].regions.len(), 8);
    assert_eq!(section_n_stats.sections_visited, 4);
    assert_eq!(section_two_n_stats.sections_visited, 8);
    assert_eq!(section_n_stats.section_index_entries, 12);
    assert_eq!(section_two_n_stats.section_index_entries, 24);
    assert_eq!(section_n_stats.label_range_queries, 4);
    assert_eq!(section_two_n_stats.label_range_queries, 8);
    assert!(
        section_two_n_stats.section_index_queries <= section_n_stats.section_index_queries * 2 + 1
    );
    assert_index_bounds(&section_n_stats);
    assert_index_bounds(&section_two_n_stats);

    let mut atomic_bytes = macho_test_support::disassembly_x86_64();
    atomic_bytes[0x13e] = 0x0f;
    atomic_bytes[0x13f] = 0xff;
    let atomic_container = macho_core::parse(&atomic_bytes).unwrap();
    let mut atomic_request = request(DisassemblySelection::Address {
        start: Va(0x1_0000_013d),
        extent: AddressExtent::ByteLength(NonZeroUsize::new(3).unwrap()),
    });
    atomic_request.max_decoded_bytes_per_slice = NonZeroUsize::new(2).unwrap();
    let (atomic_report, atomic_stats) =
        disassemble_with_work_stats(&atomic_container, &atomic_request).unwrap();
    assert_eq!(atomic_report.slices[0].decoded_bytes, 1);
    assert_eq!(
        atomic_report.slices[0].regions[0].next_unexamined_va,
        Some(0x1_0000_013e)
    );
    assert!(atomic_stats.unexamined_lookahead_bytes > 0);
    assert_decode_bounds(&atomic_stats, 15);

    let malformed = macho_test_support::disassembly_malformed_export();
    let malformed_container = macho_core::parse(&malformed).unwrap();
    let malformed_request = request(symbols(&["_main"]));
    let error = disassemble_with_work_stats(&malformed_container, &malformed_request).unwrap_err();
    assert_eq!(error.code(), SYMBOL_METADATA_INVALID_CODE);
}

#[test]
fn disassemble_survives_section_va_near_sign_boundary() {
    // A crafted-but-parseable image whose executable section sits near the i64
    // sign boundary must not panic the decoder. Before the wrapping-subtraction
    // fix in macho-insn, the branch/RIP/ADRP displacement math overflowed under
    // the overflow checks that test and debug builds enable, turning a crafted
    // Mach-O into a denial-of-service through the public disassemble() path.
    // Only the segment/section VM-address fields are patched; the file layout
    // and instruction bytes are the stock fixtures.
    let mut x86 = macho_test_support::disassembly_x86_64();
    x86[56..64].copy_from_slice(&0x7FFF_FFFF_FFFF_0000u64.to_le_bytes()); // segment vmaddr
    x86[136..144].copy_from_slice(&0x7FFF_FFFF_FFFF_FFFEu64.to_le_bytes()); // section addr
    let container = macho_core::parse(&x86).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    assert!(!report.slices[0].regions.is_empty());

    let mut arm = macho_test_support::disassembly_arm64();
    arm[56..64].copy_from_slice(&0x7FFF_FFFF_FFFF_0000u64.to_le_bytes());
    arm[136..144].copy_from_slice(&0x7FFF_FFFF_FFFF_F000u64.to_le_bytes());
    arm[0x100..0x104].copy_from_slice(&0xF07F_FFE0u32.to_le_bytes()); // ADRP, max +imm21
    let container = macho_core::parse(&arm).unwrap();
    let report = disassemble(&container, &DisassemblyRequest::default()).unwrap();
    assert!(!report.slices[0].regions.is_empty());
}

/// F3: the streaming path retains a constant number of records regardless of
/// instruction count, while the materialized report grows with it. A sink that
/// releases each record before the next arrives — the constant-memory contract
/// the CLI line sinks honor — never holds more than one record at a time, even
/// as the decoded instruction count scales from 1_000 to 50_000.
#[test]
fn streaming_output_retention_is_constant_in_instruction_count() {
    use crate::report::ReportContainerIdentity;
    use crate::report::disassembly::{
        DisassemblyIssue, DisassemblyLabel, DisassemblyReportRequest,
    };

    /// Models constant-memory output: holds the current record only for the
    /// duration of `record`, releasing it before the next. `peak_retained` is
    /// the greatest number of records held simultaneously, which stays at one
    /// for a non-accumulating streaming sink no matter how long the stream is.
    #[derive(Default)]
    struct PeakSink {
        held: Option<DisassemblyRecord>,
        peak_retained: usize,
        total_records: u64,
    }

    impl DisassemblySink for PeakSink {
        fn begin(
            &mut self,
            _container: &ReportContainerIdentity,
            _request: &DisassemblyReportRequest,
        ) -> Result<(), DisassemblyError> {
            Ok(())
        }

        fn slice_start(&mut self, _header: SliceHeader) -> Result<(), DisassemblyError> {
            Ok(())
        }

        fn region_start(&mut self, _header: RegionHeader) -> Result<(), DisassemblyError> {
            Ok(())
        }

        fn record(
            &mut self,
            record: &DisassemblyRecord,
            _labels: &[DisassemblyLabel],
        ) -> Result<(), DisassemblyError> {
            self.held = Some(record.clone());
            self.peak_retained = self.peak_retained.max(self.held.iter().count());
            self.total_records += 1;
            self.held = None;
            Ok(())
        }

        fn region_end(
            &mut self,
            _summary: RegionSummary,
            _labels: &[DisassemblyLabel],
        ) -> Result<(), DisassemblyError> {
            Ok(())
        }

        fn slice_end(
            &mut self,
            _summary: SliceSummary,
            _issues: &[DisassemblyIssue],
        ) -> Result<(), DisassemblyError> {
            Ok(())
        }
    }

    let counts = [1_000usize, 10_000, 50_000];
    let mut previous_peak: Option<usize> = None;
    let mut previous_report_records: Option<u64> = None;
    for &count in &counts {
        let bytes = macho_test_support::disassembly_x86_64_dense(count);
        let container = macho_core::parse(&bytes).unwrap();
        let request = DisassemblyRequest::default();

        let mut sink = PeakSink::default();
        disassemble_streaming(&container, &request, &mut sink).unwrap();

        // The sink observed every decoded instruction ...
        assert_eq!(
            sink.total_records, count as u64,
            "the streaming sink must observe every decoded instruction at n={count}"
        );
        // ... yet never retained more than a single record at any moment.
        assert!(
            sink.peak_retained <= 1,
            "streaming retention must be constant; held {} records at n={count}",
            sink.peak_retained
        );

        // The materialized report, by contrast, retains every record.
        let report = disassemble(&container, &request).unwrap();
        let report_records: u64 = report
            .slices
            .iter()
            .flat_map(|slice| slice.regions.iter())
            .map(|region| region.records.len() as u64)
            .sum();
        assert_eq!(
            report_records, count as u64,
            "the materialized report must retain every decoded instruction at n={count}"
        );

        // Peak streamed retention is flat across n; the report's record count grows.
        if let Some(previous) = previous_peak {
            assert_eq!(
                sink.peak_retained, previous,
                "peak streamed retention must not grow with the instruction count"
            );
        }
        if let Some(previous) = previous_report_records {
            assert!(
                report_records > previous,
                "the materialized record count must grow with the instruction count"
            );
        }
        previous_peak = Some(sink.peak_retained);
        previous_report_records = Some(report_records);
    }
}
