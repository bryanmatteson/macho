use macho_core::model::container::{MachoContainer, SelectionKey};
use macho_core::model::header::ArchSpec;
use macho_dyld::resolve::{
    InventoryPointerTarget, PointerEncoding, PointerInventory, PointerResolver,
};
use macho_dyld::{
    ChainedImportLookup, FunctionStartsOutcome, decode_function_starts, lookup_chained_import,
};

const BASE: u64 = 0x1_0000_0000;

fn header(commands: u32, command_bytes: u32) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&0xfeed_facf_u32.to_le_bytes());
    bytes.extend_from_slice(&0x0100_0007_u32.to_le_bytes());
    bytes.extend_from_slice(&3_u32.to_le_bytes());
    bytes.extend_from_slice(&2_u32.to_le_bytes());
    bytes.extend_from_slice(&commands.to_le_bytes());
    bytes.extend_from_slice(&command_bytes.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes.extend_from_slice(&0_u32.to_le_bytes());
    bytes
}

fn function_starts(encoded: &[u8]) -> Vec<u8> {
    let mut bytes = header(2, 88);
    bytes.resize(0x200, 0);
    let segment = 32;
    bytes[segment..segment + 4].copy_from_slice(&0x19_u32.to_le_bytes());
    bytes[segment + 4..segment + 8].copy_from_slice(&72_u32.to_le_bytes());
    bytes[segment + 8..segment + 14].copy_from_slice(b"__TEXT");
    bytes[segment + 24..segment + 32].copy_from_slice(&BASE.to_le_bytes());
    bytes[segment + 32..segment + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[segment + 48..segment + 56].copy_from_slice(&0x200_u64.to_le_bytes());
    let command = segment + 72;
    bytes[command..command + 4].copy_from_slice(&0x26_u32.to_le_bytes());
    bytes[command + 4..command + 8].copy_from_slice(&16_u32.to_le_bytes());
    bytes[command + 8..command + 12].copy_from_slice(&0x180_u32.to_le_bytes());
    bytes[command + 12..command + 16].copy_from_slice(&(encoded.len() as u32).to_le_bytes());
    bytes[0x180..0x180 + encoded.len()].copy_from_slice(encoded);
    bytes
}

fn chained_imports(format: u32, rows: &[(u64, i64)], symbols: &[u8]) -> Vec<u8> {
    let width = match format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => 4,
    };
    let imports_offset = 28_usize;
    let symbols_offset = imports_offset + rows.len() * width;
    let mut blob = vec![0_u8; symbols_offset + symbols.len()];
    blob[4..8].copy_from_slice(&28_u32.to_le_bytes());
    blob[8..12].copy_from_slice(&(imports_offset as u32).to_le_bytes());
    blob[12..16].copy_from_slice(&(symbols_offset as u32).to_le_bytes());
    blob[16..20].copy_from_slice(&(rows.len() as u32).to_le_bytes());
    blob[20..24].copy_from_slice(&format.to_le_bytes());
    for (index, (packed, addend)) in rows.iter().enumerate() {
        let at = imports_offset + index * width;
        if format == 3 {
            blob[at..at + 8].copy_from_slice(&packed.to_le_bytes());
            blob[at + 8..at + 16].copy_from_slice(&(*addend as u64).to_le_bytes());
        } else {
            blob[at..at + 4].copy_from_slice(&(*packed as u32).to_le_bytes());
            if format == 2 {
                blob[at + 4..at + 8].copy_from_slice(&(*addend as i32).to_le_bytes());
            }
        }
    }
    blob[symbols_offset..].copy_from_slice(symbols);

    let mut bytes = header(1, 16);
    bytes.resize(0x100 + blob.len(), 0);
    bytes[32..36].copy_from_slice(&0x8000_0034_u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&16_u32.to_le_bytes());
    bytes[40..44].copy_from_slice(&0x100_u32.to_le_bytes());
    bytes[44..48].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    bytes[0x100..].copy_from_slice(&blob);
    bytes
}

fn legacy_streams(bind: &[u8], weak: &[u8], lazy: &[u8]) -> Vec<u8> {
    let mut bytes = header(2, 120);
    bytes.resize(0x220, 0);
    let segment = 32;
    bytes[segment..segment + 4].copy_from_slice(&0x19_u32.to_le_bytes());
    bytes[segment + 4..segment + 8].copy_from_slice(&72_u32.to_le_bytes());
    bytes[segment + 8..segment + 14].copy_from_slice(b"__TEXT");
    bytes[segment + 24..segment + 32].copy_from_slice(&BASE.to_le_bytes());
    bytes[segment + 32..segment + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[segment + 48..segment + 56].copy_from_slice(&0x220_u64.to_le_bytes());
    let dyld = segment + 72;
    bytes[dyld..dyld + 4].copy_from_slice(&0x8000_0022_u32.to_le_bytes());
    bytes[dyld + 4..dyld + 8].copy_from_slice(&48_u32.to_le_bytes());
    bytes[dyld + 16..dyld + 20].copy_from_slice(&0x180_u32.to_le_bytes());
    bytes[dyld + 20..dyld + 24].copy_from_slice(&(bind.len() as u32).to_le_bytes());
    bytes[dyld + 24..dyld + 28].copy_from_slice(&0x1c0_u32.to_le_bytes());
    bytes[dyld + 28..dyld + 32].copy_from_slice(&(weak.len() as u32).to_le_bytes());
    bytes[dyld + 32..dyld + 36].copy_from_slice(&0x1e0_u32.to_le_bytes());
    bytes[dyld + 36..dyld + 40].copy_from_slice(&(lazy.len() as u32).to_le_bytes());
    bytes[0x180..0x180 + bind.len()].copy_from_slice(bind);
    bytes[0x1c0..0x1c0 + weak.len()].copy_from_slice(weak);
    bytes[0x1e0..0x1e0 + lazy.len()].copy_from_slice(lazy);
    bytes
}

fn legacy_binds(bind: &[u8]) -> Vec<u8> {
    legacy_streams(bind, &[], &[])
}

fn chained_pointer() -> Vec<u8> {
    let mut bytes = header(2, 88);
    bytes.resize(0x300, 0);
    let segment = 32;
    bytes[segment..segment + 4].copy_from_slice(&0x19_u32.to_le_bytes());
    bytes[segment + 4..segment + 8].copy_from_slice(&72_u32.to_le_bytes());
    bytes[segment + 8..segment + 14].copy_from_slice(b"__TEXT");
    bytes[segment + 24..segment + 32].copy_from_slice(&BASE.to_le_bytes());
    bytes[segment + 32..segment + 40].copy_from_slice(&0x1000_u64.to_le_bytes());
    bytes[segment + 48..segment + 56].copy_from_slice(&0x300_u64.to_le_bytes());
    let command = segment + 72;
    bytes[command..command + 4].copy_from_slice(&0x8000_0034_u32.to_le_bytes());
    bytes[command + 4..command + 8].copy_from_slice(&16_u32.to_le_bytes());
    bytes[command + 8..command + 12].copy_from_slice(&0x180_u32.to_le_bytes());

    let mut blob = vec![0_u8; 75];
    blob[4..8].copy_from_slice(&28_u32.to_le_bytes());
    blob[8..12].copy_from_slice(&64_u32.to_le_bytes());
    blob[12..16].copy_from_slice(&68_u32.to_le_bytes());
    blob[16..20].copy_from_slice(&1_u32.to_le_bytes());
    blob[20..24].copy_from_slice(&1_u32.to_le_bytes());
    blob[28..32].copy_from_slice(&1_u32.to_le_bytes());
    blob[32..36].copy_from_slice(&8_u32.to_le_bytes());
    blob[36..40].copy_from_slice(&28_u32.to_le_bytes());
    blob[40..42].copy_from_slice(&0x100_u16.to_le_bytes());
    blob[42..44].copy_from_slice(&6_u16.to_le_bytes());
    blob[56..58].copy_from_slice(&3_u16.to_le_bytes());
    blob[58..60].copy_from_slice(&0xffff_u16.to_le_bytes());
    blob[60..62].copy_from_slice(&0_u16.to_le_bytes());
    blob[62..64].copy_from_slice(&0xffff_u16.to_le_bytes());
    blob[64..68].copy_from_slice(&1_u32.to_le_bytes());
    blob[68..75].copy_from_slice(b"_chain\0");
    bytes[command + 12..command + 16].copy_from_slice(&(blob.len() as u32).to_le_bytes());
    bytes[0x180..0x180 + blob.len()].copy_from_slice(&blob);
    bytes[0x100..0x108].copy_from_slice(&(1_u64 << 63 | 0xff_u64 << 24).to_le_bytes());
    bytes
}

#[test]
fn function_starts_are_strict_bounded_and_source_retaining() {
    let bytes = function_starts(&[0x80, 0x02, 0x10, 0x08, 0]);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    let outcome = decode_function_starts(&macho, 2).unwrap();
    let FunctionStartsOutcome::Truncated {
        starts,
        continuation,
    } = outcome
    else {
        panic!()
    };
    assert_eq!(
        starts.iter().map(|row| row.address.0).collect::<Vec<_>>(),
        [BASE + 0x100, BASE + 0x110]
    );
    assert_eq!(starts[0].encoded_offset.0, 0x180);
    assert_eq!(continuation.next.address.0, BASE + 0x118);
    assert!(decode_function_starts(&macho, 0).is_err());
    assert!(
        decode_function_starts(
            &macho_core::format::parse_macho_file(&function_starts(&[1])).unwrap(),
            4
        )
        .is_err()
    );
    let overflowing = function_starts(&[
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0,
    ]);
    assert!(
        decode_function_starts(
            &macho_core::format::parse_macho_file(&overflowing).unwrap(),
            4
        )
        .is_err()
    );
    let trailing = function_starts(&[1, 0, 1]);
    assert!(
        decode_function_starts(&macho_core::format::parse_macho_file(&trailing).unwrap(), 4)
            .is_err()
    );

    let absent_bytes = header(0, 0);
    let absent = macho_core::format::parse_macho_file(&absent_bytes).unwrap();
    assert_eq!(
        decode_function_starts(&absent, 4).unwrap(),
        FunctionStartsOutcome::Absent
    );

    let mut duplicate = function_starts(&[1, 0]);
    duplicate[16..20].copy_from_slice(&3_u32.to_le_bytes());
    duplicate[20..24].copy_from_slice(&104_u32.to_le_bytes());
    duplicate.copy_within(104..120, 120);
    let duplicate = macho_core::format::parse_macho_file(&duplicate).unwrap();
    assert!(decode_function_starts(&duplicate, 4).is_err());
}

#[test]
fn exact_selected_fat_slice_controls_function_starts() {
    let x86 = function_starts(&[1, 0]);
    let mut arm = function_starts(&[2, 0]);
    arm[4..8].copy_from_slice(&0x0100_000c_u32.to_le_bytes());
    arm[8..12].copy_from_slice(&0_u32.to_le_bytes());
    let mut fat = vec![0_u8; 0x2000 + arm.len()];
    fat[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
    fat[4..8].copy_from_slice(&2_u32.to_be_bytes());
    for (row, cpu, subtype, offset, size) in [
        (8, 0x0100_0007_u32, 3_u32, 0x1000, x86.len()),
        (28, 0x0100_000c, 0, 0x2000, arm.len()),
    ] {
        fat[row..row + 4].copy_from_slice(&cpu.to_be_bytes());
        fat[row + 4..row + 8].copy_from_slice(&subtype.to_be_bytes());
        fat[row + 8..row + 12].copy_from_slice(&(offset as u32).to_be_bytes());
        fat[row + 12..row + 16].copy_from_slice(&(size as u32).to_be_bytes());
        fat[row + 16..row + 20].copy_from_slice(&12_u32.to_be_bytes());
    }
    fat[0x1000..0x1000 + x86.len()].copy_from_slice(&x86);
    fat[0x2000..].copy_from_slice(&arm);
    let container = macho_core::parse(&fat).unwrap();
    let MachoContainer::Fat(parsed) = &container else {
        panic!()
    };
    let key = SelectionKey {
        container_index: 1,
        architecture: parsed.arches()[1].spec(),
    };
    let selected = container.select_exact(key).unwrap();
    let FunctionStartsOutcome::Complete(starts) =
        decode_function_starts(selected.image, 4).unwrap()
    else {
        panic!()
    };
    assert_eq!(starts[0].address.0, BASE + 2);
    let stale = SelectionKey {
        container_index: 0,
        architecture: ArchSpec {
            cpu_type: selected.key.architecture.cpu_type,
            cpu_subtype: selected.key.architecture.cpu_subtype,
        },
    };
    assert!(container.select_exact(stale).is_err());
}

#[test]
fn chained_lookup_supports_all_formats_and_ambiguity() {
    for (format, packed, addend) in [
        (1, 1_u64, 0),
        (2, 1_u64, -7),
        (3, 0xffff_u64 | (1_u64 << 16), i64::MAX),
    ] {
        let bytes = chained_imports(format, &[(packed, addend)], b"_target\0");
        let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
        let ChainedImportLookup::Unique(record) = lookup_chained_import(&macho, "_target").unwrap()
        else {
            panic!()
        };
        assert_eq!(record.ordinal, 0);
        assert_eq!(record.addend, addend);
    }
    let bytes = chained_imports(1, &[(1, 0), (1, 0)], b"_same\0");
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    let ChainedImportLookup::Ambiguous(rows) = lookup_chained_import(&macho, "_same").unwrap()
    else {
        panic!()
    };
    assert_eq!(
        rows.iter().map(|row| row.ordinal).collect::<Vec<_>>(),
        [0, 1]
    );
}

#[test]
fn chained_lookup_rejects_malformed_names_and_distinguishes_absence() {
    let absent_bytes = header(0, 0);
    let absent = macho_core::format::parse_macho_file(&absent_bytes).unwrap();
    assert_eq!(
        lookup_chained_import(&absent, "x").unwrap(),
        ChainedImportLookup::Absent
    );
    let bytes = chained_imports(1, &[(1, 0)], &[0xff, 0]);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    assert!(lookup_chained_import(&macho, "x").is_err());
}

#[test]
fn chained_inventory_retains_format_ordinals_and_both_addends() {
    let bytes = chained_pointer();
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    let PointerInventory::Complete(rows) =
        PointerResolver::new(&macho).unwrap().inventory(4).unwrap()
    else {
        panic!()
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].file_offset.0, 0x100);
    assert_eq!(rows[0].chained_pointer_format, Some(6));
    assert_eq!(rows[0].encoding, PointerEncoding::ChainedBind);
    assert!(matches!(&rows[0].target, InventoryPointerTarget::Import {
        import_ordinal: Some(0), name, library_ordinal: Some(1), weak: Some(false),
        import_addend: 0, pointer_addend: -1,
    } if name == "_chain"));
}

#[test]
fn unsupported_chained_multi_start_rejects_instead_of_dropping_a_page() {
    let mut bytes = chained_pointer();
    bytes[0x180 + 60..0x180 + 62].copy_from_slice(&0x8000_u16.to_le_bytes());
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    assert!(PointerResolver::new(&macho).is_err());
}

#[test]
fn legacy_inventory_is_deterministic_bounded_and_semantic() {
    let bind = [
        0x11, 0x40, b'_', b'a', 0, 0x51, 0x70, 0x80, 0x02, 0x90, 0x40, b'_', b'b', 0, 0x90, 0,
    ];
    let bytes = legacy_binds(&bind);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    let resolver = PointerResolver::new(&macho).unwrap();
    let PointerInventory::Truncated {
        pointers,
        available,
        continuation,
    } = resolver.inventory(1).unwrap()
    else {
        panic!()
    };
    assert_eq!(available, 2);
    assert_eq!(pointers[0].file_offset.0, 0x100);
    assert_eq!(pointers[0].source_va.0, BASE + 0x100);
    assert_eq!(pointers[0].width, 8);
    assert_eq!(pointers[0].encoding, PointerEncoding::LegacyBind);
    assert!(
        matches!(&pointers[0].target, InventoryPointerTarget::Import { name, library_ordinal: Some(1), .. } if name == "_a")
    );
    assert_eq!(continuation.next_file_offset.0, 0x108);
    assert!(resolver.inventory(0).is_err());
}

#[test]
fn duplicate_legacy_rows_deduplicate_but_conflicts_reject() {
    let duplicate = [
        0x11, 0x40, b'_', b'a', 0, 0x51, 0x70, 0x80, 0x02, 0x90, 0x70, 0x80, 0x02, 0x90, 0,
    ];
    let bytes = legacy_binds(&duplicate);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    assert!(
        matches!(PointerResolver::new(&macho).unwrap().inventory(4).unwrap(), PointerInventory::Complete(rows) if rows.len() == 1)
    );

    let conflict = [
        0x11, 0x40, b'_', b'a', 0, 0x51, 0x70, 0x80, 0x02, 0x90, 0x40, b'_', b'b', 0, 0x70, 0x80,
        0x02, 0x90, 0,
    ];
    let bytes = legacy_binds(&conflict);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    assert!(
        PointerResolver::new(&macho)
            .err()
            .unwrap()
            .to_string()
            .contains("conflicting")
    );
}

#[test]
fn regular_and_weak_repetitions_retain_both_stream_facts() {
    use macho_dyld::resolve::{LegacyBindStream, PointerTarget};

    let regular = [
        0x11, 0x40, b'_', b's', b'a', b'm', b'e', 0, 0x51, 0x70, 0x80, 0x02, 0x90, 0,
    ];
    let weak = [
        0x10, 0x41, b'_', b's', b'a', b'm', b'e', 0, 0x51, 0x70, 0x80, 0x02, 0x90, 0,
    ];
    let bytes = legacy_streams(&regular, &weak, &[]);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    let resolver = PointerResolver::new(&macho).unwrap();
    let PointerInventory::Complete(rows) = resolver.inventory(4).unwrap() else {
        panic!()
    };
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].legacy_bind_occurrences.len(), 2);
    assert_eq!(
        rows[0]
            .legacy_bind_occurrences
            .iter()
            .map(|source| source.stream)
            .collect::<Vec<_>>(),
        [LegacyBindStream::Regular, LegacyBindStream::Weak]
    );
    assert_eq!(rows[0].legacy_bind_occurrences[0].library_ordinal, 1);
    assert_eq!(rows[0].legacy_bind_occurrences[1].library_ordinal, 0);
    assert!(!rows[0].legacy_bind_occurrences[0].weak);
    assert!(rows[0].legacy_bind_occurrences[1].weak);
    assert_eq!(rows[0].legacy_bind_occurrences[0].symbol_flags, 0);
    assert_eq!(rows[0].legacy_bind_occurrences[1].symbol_flags, 1);
    assert!(matches!(
        &rows[0].target,
        InventoryPointerTarget::Import {
            name,
            library_ordinal: None,
            weak: None,
            pointer_addend: 0,
            ..
        } if name == "_same"
    ));
    assert!(matches!(
        resolver
            .observe_at_offset(rows[0].file_offset)
            .unwrap()
            .target,
        PointerTarget::Import {
            name,
            library_ordinal: None
        } if name == "_same"
    ));

    let conflicting_addend = [
        0x10, 0x41, b'_', b's', b'a', b'm', b'e', 0, 0x51, 0x60, 0x01, 0x70, 0x80, 0x02, 0x90, 0,
    ];
    let bytes = legacy_streams(&regular, &conflicting_addend, &[]);
    let macho = macho_core::format::parse_macho_file(&bytes).unwrap();
    assert!(PointerResolver::new(&macho).is_err());
}
