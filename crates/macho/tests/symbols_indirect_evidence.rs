use macho::metadata::symbols::{
    IndirectBindingKind, IndirectBindingsOutcome, IndirectSymbolTarget, decode_indirect_bindings,
};

const BASE: u64 = 0x1_0000_0000;
const SEGMENT: usize = 32;
const SYMTAB: usize = SEGMENT + 152;
const DYSYMTAB: usize = SYMTAB + 24;

fn fixture(raw_indices: &[u32]) -> Vec<u8> {
    let mut bytes = vec![0_u8; 0x300];
    bytes[..4].copy_from_slice(&0xfeed_facf_u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x0100_0007_u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&3_u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&2_u32.to_le_bytes());
    bytes[16..20].copy_from_slice(&3_u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&256_u32.to_le_bytes());

    bytes[SEGMENT..SEGMENT + 4].copy_from_slice(&0x19_u32.to_le_bytes());
    bytes[SEGMENT + 4..SEGMENT + 8].copy_from_slice(&152_u32.to_le_bytes());
    bytes[SEGMENT + 8..SEGMENT + 14].copy_from_slice(b"__TEXT");
    bytes[SEGMENT + 24..SEGMENT + 32].copy_from_slice(&BASE.to_le_bytes());
    bytes[SEGMENT + 32..SEGMENT + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[SEGMENT + 48..SEGMENT + 56].copy_from_slice(&0x300_u64.to_le_bytes());
    bytes[SEGMENT + 64..SEGMENT + 68].copy_from_slice(&1_u32.to_le_bytes());
    let section = SEGMENT + 72;
    bytes[section..section + 7].copy_from_slice(b"__stubs");
    bytes[section + 16..section + 22].copy_from_slice(b"__TEXT");
    bytes[section + 32..section + 40].copy_from_slice(&(BASE + 0x200).to_le_bytes());
    bytes[section + 40..section + 48]
        .copy_from_slice(&((raw_indices.len() * 8) as u64).to_le_bytes());
    bytes[section + 48..section + 52].copy_from_slice(&0x200_u32.to_le_bytes());
    bytes[section + 64..section + 68].copy_from_slice(&8_u32.to_le_bytes());
    bytes[section + 72..section + 76].copy_from_slice(&8_u32.to_le_bytes());

    bytes[SYMTAB..SYMTAB + 4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[SYMTAB + 4..SYMTAB + 8].copy_from_slice(&24_u32.to_le_bytes());
    bytes[SYMTAB + 8..SYMTAB + 12].copy_from_slice(&0x260_u32.to_le_bytes());
    bytes[SYMTAB + 12..SYMTAB + 16].copy_from_slice(&1_u32.to_le_bytes());
    bytes[SYMTAB + 16..SYMTAB + 20].copy_from_slice(&0x270_u32.to_le_bytes());
    bytes[SYMTAB + 20..SYMTAB + 24].copy_from_slice(&6_u32.to_le_bytes());

    bytes[DYSYMTAB..DYSYMTAB + 4].copy_from_slice(&0xb_u32.to_le_bytes());
    bytes[DYSYMTAB + 4..DYSYMTAB + 8].copy_from_slice(&80_u32.to_le_bytes());
    bytes[DYSYMTAB + 56..DYSYMTAB + 60].copy_from_slice(&0x240_u32.to_le_bytes());
    bytes[DYSYMTAB + 60..DYSYMTAB + 64].copy_from_slice(&(raw_indices.len() as u32).to_le_bytes());

    for (index, raw) in raw_indices.iter().enumerate() {
        bytes[0x240 + index * 4..0x244 + index * 4].copy_from_slice(&raw.to_le_bytes());
    }
    bytes[0x260..0x264].copy_from_slice(&1_u32.to_le_bytes());
    bytes[0x264] = 1;
    bytes[0x270..0x276].copy_from_slice(b"\0_imp\0");
    bytes
}

#[test]
fn complete_inventory_retains_symbols_and_every_special_entry() {
    let bytes = fixture(&[0, 0x8000_0000, 0x4000_0000, 0xc000_0000]);
    let macho = macho::core::format::parse_macho_file(&bytes).unwrap();
    let IndirectBindingsOutcome::Complete(rows) = decode_indirect_bindings(&macho, 8).unwrap()
    else {
        panic!()
    };
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0].address.0, BASE + 0x200);
    assert_eq!(rows[0].file_offset.0, 0x200);
    assert_eq!(rows[0].size, 8);
    let IndirectSymbolTarget::Symbol(symbol) = &rows[0].target else {
        panic!()
    };
    assert_eq!(symbol.index, 0);
    assert_eq!(symbol.name, "_imp");
    assert!(symbol.is_undefined());
    assert_eq!(symbol.library_ordinal(), 0);
    assert_eq!(rows[1].target, IndirectSymbolTarget::Local);
    assert_eq!(rows[2].target, IndirectSymbolTarget::Absolute);
    assert_eq!(rows[3].target, IndirectSymbolTarget::LocalAbsolute);
}

#[test]
fn finite_limit_has_exact_continuation_and_zero_refuses() {
    let bytes = fixture(&[0, 0x8000_0000, 0x4000_0000]);
    let macho = macho::core::format::parse_macho_file(&bytes).unwrap();
    let IndirectBindingsOutcome::Truncated {
        bindings,
        available,
        continuation,
    } = decode_indirect_bindings(&macho, 2).unwrap()
    else {
        panic!()
    };
    assert_eq!(bindings.len(), 2);
    assert_eq!(available, 3);
    assert_eq!(continuation.next.entry_index, 2);
    assert_eq!(continuation.next.target, IndirectSymbolTarget::Absolute);
    assert!(decode_indirect_bindings(&macho, 0).is_err());
}

#[test]
fn malformed_stride_table_symbol_and_utf8_reject_without_partial_results() {
    let mut stride = fixture(&[0]);
    stride[SEGMENT + 72 + 72..SEGMENT + 72 + 76].copy_from_slice(&0_u32.to_le_bytes());
    assert!(
        decode_indirect_bindings(&macho::core::format::parse_macho_file(&stride).unwrap(), 8)
            .is_err()
    );

    let absent_symbol = fixture(&[9]);
    assert!(
        decode_indirect_bindings(
            &macho::core::format::parse_macho_file(&absent_symbol).unwrap(),
            8
        )
        .is_err()
    );

    let mut utf8 = fixture(&[0]);
    utf8[0x271] = 0xff;
    assert!(
        decode_indirect_bindings(&macho::core::format::parse_macho_file(&utf8).unwrap(), 8)
            .is_err()
    );

    let mut table = fixture(&[0]);
    table[DYSYMTAB + 56..DYSYMTAB + 60].copy_from_slice(&0x2ff_u32.to_le_bytes());
    assert!(
        decode_indirect_bindings(&macho::core::format::parse_macho_file(&table).unwrap(), 8)
            .is_err()
    );

    let mut host_overflow = fixture(&[0]);
    host_overflow[DYSYMTAB + 56..DYSYMTAB + 60].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        decode_indirect_bindings(
            &macho::core::format::parse_macho_file(&host_overflow).unwrap(),
            8
        )
        .is_err()
    );
}

#[test]
fn no_dysymtab_is_explicitly_absent() {
    let mut bytes = fixture(&[0]);
    bytes[16..20].copy_from_slice(&2_u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&176_u32.to_le_bytes());
    let macho = macho::core::format::parse_macho_file(&bytes).unwrap();
    assert_eq!(
        decode_indirect_bindings(&macho, 8).unwrap(),
        IndirectBindingsOutcome::Absent
    );
}

#[test]
fn lazy_and_nonlazy_pointer_slots_have_typed_kinds() {
    for (section_type, expected) in [
        (6_u32, IndirectBindingKind::NonLazyPointer),
        (7_u32, IndirectBindingKind::LazyPointer),
    ] {
        let mut bytes = fixture(&[0]);
        bytes[SEGMENT + 72 + 64..SEGMENT + 72 + 68].copy_from_slice(&section_type.to_le_bytes());
        let macho = macho::core::format::parse_macho_file(&bytes).unwrap();
        let IndirectBindingsOutcome::Complete(rows) = decode_indirect_bindings(&macho, 8).unwrap()
        else {
            panic!()
        };
        assert_eq!(rows[0].kind, expected);
        assert_eq!(rows[0].size, 8);
    }
}
