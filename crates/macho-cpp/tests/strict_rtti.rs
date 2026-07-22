#![cfg(feature = "itanium-rtti")]

use macho_cpp::{
    ItaniumTypeInfoFamily, StrictPointerTarget, StrictRttiGapCode, StrictRttiLimits,
    StrictRttiOutcome, StrictRttiRecord, decode_strict_rtti_from_source,
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

fn single_inheritance_fixture() -> Vec<u8> {
    let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
        SymbolFixture {
            name: "__ZTI7Derived",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTI4Base",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTVN10__cxxabiv120__si_class_type_infoE",
            external: false,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTVN10__cxxabiv117__class_type_infoE",
            external: false,
            defined: true,
        },
    ]);
    let derived = IMAGE + 0x100;
    let base = IMAGE + 0x118;
    let derived_name = IMAGE + 0x128;
    let base_name = IMAGE + 0x131;
    let si_vtable = IMAGE + 0x138;
    let class_vtable = IMAGE + 0x13c;

    write_u64(&mut bytes, DATA_OFFSET, si_vtable);
    write_u64(&mut bytes, DATA_OFFSET + 8, derived_name);
    write_u64(&mut bytes, DATA_OFFSET + 16, base);
    write_u64(&mut bytes, DATA_OFFSET + 24, class_vtable);
    write_u64(&mut bytes, DATA_OFFSET + 32, base_name);
    bytes[DATA_OFFSET + 40..DATA_OFFSET + 49].copy_from_slice(b"7Derived\0");
    bytes[DATA_OFFSET + 49..DATA_OFFSET + 55].copy_from_slice(b"4Base\0");

    set_symbol_value(&mut bytes, 0, derived);
    set_symbol_value(&mut bytes, 1, base);
    set_symbol_value(&mut bytes, 2, si_vtable);
    set_symbol_value(&mut bytes, 3, class_vtable);
    bytes
}

fn vmi_fixture() -> Vec<u8> {
    let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
        SymbolFixture {
            name: "__ZTI7Diamond",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTVN10__cxxabiv121__vmi_class_type_infoE",
            external: false,
            defined: true,
        },
    ]);
    let record = IMAGE + 0x100;
    let base = IMAGE + 0x138;
    let name = IMAGE + 0x130;
    let runtime_vtable = IMAGE + 0x13c;
    write_u64(&mut bytes, DATA_OFFSET, runtime_vtable);
    write_u64(&mut bytes, DATA_OFFSET + 8, name);
    bytes[DATA_OFFSET + 16..DATA_OFFSET + 20].copy_from_slice(&2u32.to_le_bytes());
    bytes[DATA_OFFSET + 20..DATA_OFFSET + 24].copy_from_slice(&1u32.to_le_bytes());
    write_u64(&mut bytes, DATA_OFFSET + 24, base);
    let offset_flags = ((-24_i64 << 8) as u64) | 3;
    write_u64(&mut bytes, DATA_OFFSET + 32, offset_flags);
    bytes[DATA_OFFSET + 48..DATA_OFFSET + 57].copy_from_slice(b"7Diamond\0");
    set_symbol_value(&mut bytes, 0, record);
    set_symbol_value(&mut bytes, 1, runtime_vtable);
    bytes
}

fn pointer_to_member_fixture() -> Vec<u8> {
    let mut bytes = macho_test_support::thin64_x86_64_with_data_symbols(&[
        SymbolFixture {
            name: "__ZTIM7DerivedFvvE",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTVN10__cxxabiv129__pointer_to_member_type_infoE",
            external: false,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTSFvvE",
            external: false,
            defined: true,
        },
        SymbolFixture {
            name: "__ZTS7Derived",
            external: false,
            defined: true,
        },
    ]);
    let record = IMAGE + 0x100;
    let name = IMAGE + 0x128;
    let pointee = IMAGE + 0x134;
    let member_of = IMAGE + 0x138;
    let runtime_vtable = IMAGE + 0x13c;
    write_u64(&mut bytes, DATA_OFFSET, runtime_vtable);
    write_u64(&mut bytes, DATA_OFFSET + 8, name);
    bytes[DATA_OFFSET + 16..DATA_OFFSET + 20].copy_from_slice(&3u32.to_le_bytes());
    write_u64(&mut bytes, DATA_OFFSET + 24, pointee);
    write_u64(&mut bytes, DATA_OFFSET + 32, member_of);
    bytes[DATA_OFFSET + 40..DATA_OFFSET + 54].copy_from_slice(b"M7DerivedFvvE\0");
    set_symbol_value(&mut bytes, 0, record);
    set_symbol_value(&mut bytes, 1, runtime_vtable);
    set_symbol_value(&mut bytes, 2, pointee);
    set_symbol_value(&mut bytes, 3, member_of);
    bytes
}

#[test]
fn strict_itanium_leaf_conserves_exact_single_inheritance_records() {
    let bytes = single_inheritance_fixture();
    let batch = decode_strict_rtti_from_source(&bytes, StrictRttiLimits::default())
        .expect("strict RTTI fixture decodes");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete);
    assert_eq!(batch.conservation.attempted, 2);
    assert_eq!(batch.conservation.included, 2);
    assert_eq!(batch.conservation.unknown, 0);
    assert!(batch.gaps.is_empty());
    assert!(
        batch
            .observations
            .iter()
            .enumerate()
            .all(|(index, value)| value.ordinal == index as u64)
    );

    let derived = batch
        .records
        .iter()
        .find_map(|record| match record {
            StrictRttiRecord::TypeInfo { record } if record.symbol == "__ZTI7Derived" => {
                Some(record)
            }
            _ => None,
        })
        .expect("derived record");
    assert_eq!(
        derived.family,
        ItaniumTypeInfoFamily::SingleInheritanceClass
    );
    assert_eq!(derived.type_name, "7Derived");
    assert_eq!(derived.bases.len(), 1);
    assert_eq!(derived.bases[0].ordinal, 0);
    assert!(derived.bases[0].is_public);
    assert!(!derived.bases[0].is_virtual);
    assert_eq!(
        derived.bases[0].typeinfo.target,
        StrictPointerTarget::Local { va: IMAGE + 0x118 }
    );

    let json = serde_json::to_value(&batch).expect("strict batch JSON");
    let mut hostile = json;
    hostile["future"] = serde_json::json!(true);
    assert!(serde_json::from_value::<macho_cpp::StrictRttiBatch>(hostile).is_err());

    let mut forged = serde_json::to_value(&batch).expect("strict batch JSON");
    forged["records"][1]["record"]["runtime_vtable"]["observation_ordinal"] =
        serde_json::json!(999);
    assert!(serde_json::from_value::<macho_cpp::StrictRttiBatch>(forged).is_err());
}

#[test]
fn strict_itanium_leaf_rejects_limits_without_usable_truncation() {
    let bytes = single_inheritance_fixture();
    let input = decode_strict_rtti_from_source(
        &bytes,
        StrictRttiLimits {
            max_input_bytes: 1,
            ..StrictRttiLimits::default()
        },
    )
    .expect("input limit rejection is a typed batch");
    assert_eq!(input.outcome, StrictRttiOutcome::Rejected);
    assert_eq!(input.conservation.attempted, 0);
    assert_eq!(input.gaps[0].field, "input_bytes");

    let batch = decode_strict_rtti_from_source(
        &bytes,
        StrictRttiLimits {
            max_records: 1,
            ..StrictRttiLimits::default()
        },
    )
    .expect("limit rejection is a typed batch");
    assert_eq!(batch.outcome, StrictRttiOutcome::Rejected);
    assert!(batch.records.is_empty());
    assert!(batch.observations.is_empty());
    assert_eq!(batch.conservation.attempted, 2);
    assert_eq!(batch.conservation.excluded, 2);
    assert_eq!(
        batch.gaps[0].code,
        StrictRttiGapCode::StructuralLimitExceeded
    );

    let evidence = decode_strict_rtti_from_source(
        &bytes,
        StrictRttiLimits {
            max_evidence_bytes: 8,
            ..StrictRttiLimits::default()
        },
    )
    .expect("evidence limit rejection is a typed batch");
    assert_eq!(evidence.outcome, StrictRttiOutcome::Rejected);
    assert!(
        evidence
            .gaps
            .iter()
            .all(|gap| gap.code == StrictRttiGapCode::StructuralLimitExceeded)
    );
    assert_eq!(
        evidence
            .observations
            .iter()
            .map(|value| value.length)
            .sum::<u64>(),
        8
    );
}

#[test]
fn strict_itanium_leaf_rejects_unmapped_base_and_oversized_names() {
    let mut bad_base = single_inheritance_fixture();
    write_u64(&mut bad_base, DATA_OFFSET + 16, 0xdead_beef);
    let batch = decode_strict_rtti_from_source(&bad_base, StrictRttiLimits::default())
        .expect("malformed base is a typed batch");
    assert_eq!(batch.outcome, StrictRttiOutcome::Rejected);
    assert!(batch.gaps.iter().any(|gap| {
        gap.symbol.as_deref() == Some("__ZTI7Derived")
            && gap.code == StrictRttiGapCode::PointerUnresolved
    }));
    assert_eq!(
        batch.conservation.included + batch.conservation.unknown,
        batch.conservation.attempted
    );

    let names = decode_strict_rtti_from_source(
        &single_inheritance_fixture(),
        StrictRttiLimits {
            max_name_bytes: 1,
            ..StrictRttiLimits::default()
        },
    )
    .expect("oversized names are typed gaps");
    assert_eq!(names.outcome, StrictRttiOutcome::Rejected);
    assert!(
        names
            .gaps
            .iter()
            .all(|gap| gap.code == StrictRttiGapCode::TypeNameInvalid)
    );
}

#[test]
fn strict_itanium_leaf_distinguishes_absent_and_external_typeinfo() {
    let absent = macho_test_support::thin64_x86_64_with_symbols(&[SymbolFixture {
        name: "_main",
        external: true,
        defined: true,
    }]);
    let batch = decode_strict_rtti_from_source(&absent, StrictRttiLimits::default())
        .expect("no RTTI is absence");
    assert_eq!(batch.outcome, StrictRttiOutcome::Absent);

    let external = macho_test_support::thin64_x86_64_with_symbols(&[SymbolFixture {
        name: "__ZTI8External",
        external: true,
        defined: false,
    }]);
    let batch = decode_strict_rtti_from_source(&external, StrictRttiLimits::default())
        .expect("external RTTI is conserved");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete);
    assert!(matches!(
        &batch.records[0],
        StrictRttiRecord::ExternalTypeInfo { symbol, .. } if symbol == "__ZTI8External"
    ));
}

#[test]
fn strict_itanium_leaf_preserves_vmi_flags_order_and_signed_offsets() {
    let batch = decode_strict_rtti_from_source(&vmi_fixture(), StrictRttiLimits::default())
        .expect("VMI fixture decodes");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete);
    let record = match &batch.records[0] {
        StrictRttiRecord::TypeInfo { record } => record,
        other => panic!("unexpected VMI record: {other:?}"),
    };
    assert_eq!(
        record.family,
        ItaniumTypeInfoFamily::VirtualMultipleInheritanceClass
    );
    assert_eq!(record.class_flags, 2);
    assert_eq!(record.bases.len(), 1);
    assert_eq!(record.bases[0].ordinal, 0);
    assert_eq!(record.bases[0].signed_offset, -24);
    assert!(record.bases[0].is_virtual);
    assert!(record.bases[0].is_public);
}

#[test]
fn strict_itanium_leaf_preserves_pointer_to_member_qualifiers_and_owner() {
    let batch =
        decode_strict_rtti_from_source(&pointer_to_member_fixture(), StrictRttiLimits::default())
            .expect("pointer-to-member fixture decodes");
    assert_eq!(batch.outcome, StrictRttiOutcome::Complete);
    let record = match &batch.records[0] {
        StrictRttiRecord::TypeInfo { record } => record,
        other => panic!("unexpected pointer-to-member record: {other:?}"),
    };
    assert_eq!(record.family, ItaniumTypeInfoFamily::PointerToMember);
    let pointee = record.pointee.as_ref().expect("pbase details");
    assert_eq!(pointee.flags, 3);
    assert_eq!(
        pointee.pointee.target,
        StrictPointerTarget::Local { va: IMAGE + 0x134 }
    );
    assert_eq!(
        pointee.member_of.as_ref().expect("member owner").target,
        StrictPointerTarget::Local { va: IMAGE + 0x138 }
    );
}
