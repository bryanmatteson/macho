#![cfg(feature = "itanium-rtti")]

use macho_cpp::{
    ItaniumThunkAdjustment, ItaniumVtableSlotRole, ItaniumVtableSymbolKind, StrictPointerTarget,
    StrictRttiGapCode, StrictRttiOutcome, StrictVtableLimits, StrictVtableRecord,
    decode_strict_vtables_from_source,
};
use macho_test_support::SymbolFixture;

const IMAGE: u64 = 0x1_0000_0000;
const DATA_OFFSET: usize = 0x100;
const SYMBOL_OFFSET: usize = 0x140;

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn set_symbol_value(bytes: &mut [u8], index: usize, value: u64) {
    write_u64(bytes, SYMBOL_OFFSET + index * 16 + 8, value);
}

fn group_fixture(kind: &'static str) -> Vec<u8> {
    let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
        SymbolFixture {
            name: kind,
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTI7Derived",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZN7DerivedD0Ev",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZThn16_N7Derived1fEv",
            external: true,
            defined: true,
        },
    ]);
    let group = IMAGE + 0x120;
    let typeinfo = IMAGE + 0x100;
    let deleting_destructor = IMAGE + 0x108;
    let thunk = IMAGE + 0x110;
    set_symbol_value(&mut bytes, 0, group);
    set_symbol_value(&mut bytes, 1, typeinfo);
    set_symbol_value(&mut bytes, 2, deleting_destructor);
    set_symbol_value(&mut bytes, 3, thunk);
    write_u64(&mut bytes, DATA_OFFSET + 0x20, 0);
    write_u64(&mut bytes, DATA_OFFSET + 0x28, typeinfo);
    write_u64(&mut bytes, DATA_OFFSET + 0x30, deleting_destructor);
    write_u64(&mut bytes, DATA_OFFSET + 0x38, thunk);
    bytes
}

fn vtt_fixture() -> Vec<u8> {
    let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
        SymbolFixture {
            name: "__ZTT7Derived",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "_extent_marker",
            external: false,
            defined: true,
        },
    ]);
    set_symbol_value(&mut bytes, 0, IMAGE + 0x100);
    set_symbol_value(&mut bytes, 1, IMAGE + 0x120);
    for (index, target) in [IMAGE + 0x110, IMAGE + 0x118, IMAGE + 0x128, IMAGE + 0x130]
        .into_iter()
        .enumerate()
    {
        write_u64(&mut bytes, DATA_OFFSET + index * 8, target);
    }
    bytes
}

fn multiple_address_point_fixture() -> Vec<u8> {
    let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
        SymbolFixture {
            name: "__ZTV7Diamond",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTI7Diamond",
            external: true,
            defined: true,
        },
    ]);
    for index in 0..2 {
        set_symbol_value(&mut bytes, index, IMAGE + 0x100);
    }
    for (index, value) in [
        (-24_i64) as u64,
        0,
        IMAGE + 0x100,
        0,
        0x20,
        (-16_i64) as u64,
        IMAGE + 0x100,
        0,
    ]
    .into_iter()
    .enumerate()
    {
        write_u64(&mut bytes, DATA_OFFSET + index * 8, value);
    }
    bytes
}

#[test]
fn strict_vtable_leaf_preserves_header_destructor_and_thunk_roles() {
    let batch = decode_strict_vtables_from_source(
        &group_fixture("__ZTV7Derived"),
        StrictVtableLimits::default(),
    )
    .expect("strict vtable group");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete, "{batch:#?}");
    assert_eq!(batch.conservation.attempted, 1);
    let group = match &batch.records[0] {
        StrictVtableRecord::Group { record } => record,
        _ => panic!("group record"),
    };
    assert_eq!(group.kind, ItaniumVtableSymbolKind::CompleteGroup);
    assert_eq!(group.address_points.len(), 1);
    let point = &group.address_points[0];
    assert_eq!(point.va, IMAGE + 0x130);
    assert_eq!(point.offset_to_top, 0);
    assert_eq!(
        point.typeinfo.target,
        StrictPointerTarget::Local { va: IMAGE + 0x100 }
    );
    assert_eq!(point.slots.len(), 2);
    assert_eq!(
        point.slots[0].role,
        ItaniumVtableSlotRole::DeletingDestructor
    );
    assert_eq!(point.slots[1].role, ItaniumVtableSlotRole::NonVirtualThunk);
    assert_eq!(
        point.slots[1].this_adjustment,
        Some(ItaniumThunkAdjustment::NonVirtual { offset: -16 })
    );
    assert!(group.ambiguous_words.is_empty());

    let mut forged = serde_json::to_value(&batch).expect("batch JSON");
    forged["records"][0]["record"]["address_points"][0]["slots"][0]["role"] =
        serde_json::json!("function");
    assert!(serde_json::from_value::<macho_cpp::StrictVtableBatch>(forged).is_err());
}

#[test]
fn strict_vtable_leaf_distinguishes_construction_groups_and_vtts() {
    let construction = decode_strict_vtables_from_source(
        &group_fixture("__ZTC7Derived0_4Base"),
        StrictVtableLimits::default(),
    )
    .expect("construction group");
    let group = match &construction.records[0] {
        StrictVtableRecord::Group { record } => record,
        _ => panic!("construction group"),
    };
    assert_eq!(group.kind, ItaniumVtableSymbolKind::ConstructionGroup);

    let vtt = decode_strict_vtables_from_source(&vtt_fixture(), StrictVtableLimits::default())
        .expect("VTT fixture");
    let record = match &vtt.records[0] {
        StrictVtableRecord::Vtt { record } => record,
        _ => panic!("VTT record"),
    };
    assert_eq!(record.entries.len(), 4);
    assert_eq!(record.entries[0].ordinal, 0);
    assert_eq!(
        record.entries[3].address_point.target,
        StrictPointerTarget::Local { va: IMAGE + 0x130 }
    );
}

#[test]
fn strict_vtable_leaf_conserves_multiple_address_points_without_guessing() {
    let batch = decode_strict_vtables_from_source(
        &multiple_address_point_fixture(),
        StrictVtableLimits::default(),
    )
    .expect("multiple address points");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete, "{batch:#?}");
    let group = match &batch.records[0] {
        StrictVtableRecord::Group { record } => record,
        _ => panic!("group"),
    };
    assert_eq!(group.address_points.len(), 2);
    assert_eq!(group.address_points[0].prefix_offsets.len(), 1);
    assert_eq!(group.address_points[0].prefix_offsets[0].signed_value, -24);
    assert_eq!(group.address_points[0].slots.len(), 1);
    assert_eq!(group.ambiguous_words.len(), 1);
    assert_eq!(group.ambiguous_words[0].word_ordinal, 4);
    assert_eq!(group.address_points[1].offset_to_top, -16);
    assert_eq!(group.address_points[1].slots.len(), 1);
    assert_eq!(batch.observations.len(), 8);
}

#[test]
fn strict_vtable_leaf_retains_fno_rtti_and_external_candidates() {
    let mut no_rtti = group_fixture("__ZTV7Derived");
    write_u64(&mut no_rtti, DATA_OFFSET + 0x28, 0);
    let batch = decode_strict_vtables_from_source(&no_rtti, StrictVtableLimits::default())
        .expect("null RTTI remains distinct");
    let point = match &batch.records[0] {
        StrictVtableRecord::Group { record } => &record.address_points[0],
        _ => panic!("group"),
    };
    assert_eq!(point.typeinfo.target, StrictPointerTarget::Null);

    let external = macho_test_support::thin64_x86_64_with_data_symbols(&[SymbolFixture {
        name: "__ZTV7Missing",
        external: true,
        defined: false,
    }]);
    let batch = decode_strict_vtables_from_source(&external, StrictVtableLimits::default())
        .expect("external vtable");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete);
    assert!(matches!(
        batch.records[0],
        StrictVtableRecord::External { .. }
    ));
}

#[test]
fn strict_vtable_leaf_rejects_structural_limits_without_truncation() {
    let bytes = group_fixture("__ZTV7Derived");
    let batch = decode_strict_vtables_from_source(
        &bytes,
        StrictVtableLimits {
            max_words: 2,
            ..StrictVtableLimits::default()
        },
    )
    .expect("word limit is typed");
    assert_eq!(batch.outcome, StrictRttiOutcome::Rejected);
    assert!(batch.records.is_empty());
    assert_eq!(batch.conservation.unknown, 1);
    assert_eq!(
        batch.gaps[0].code,
        StrictRttiGapCode::StructuralLimitExceeded
    );
}
