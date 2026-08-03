#[test]
fn dwarf_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_arm64(0);
    let container = macho_core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    assert!(!macho_dwarf::has_dwarf_sections(image));
    assert!(
        macho_dwarf::load_dwarf(image)
            .expect("absence is not failure")
            .is_none()
    );
}

#[test]
fn bounded_traversal_retains_units_dies_forms_and_physical_lines() {
    let bytes = dwarf4_macho_fixture();
    let container = macho_core::parse(&bytes).expect("DWARF fixture parses as Mach-O");
    let image = container.first_macho().expect("thin image");
    let traversal =
        macho_dwarf::traverse_dwarf(image, macho_dwarf::DwarfTraversalLimits::default())
            .expect("supported DWARF traverses")
            .expect("fixture has DWARF");

    assert_eq!(traversal.units.len(), 1);
    assert_eq!(traversal.units[0].version, 4);
    assert_eq!(
        traversal.units[0].producer.as_deref(),
        Some("macho-dwarf-test")
    );
    assert_eq!(traversal.entries.len(), 4);
    assert_eq!(
        traversal.entries[3].parent_offset,
        Some(traversal.entries[2].offset)
    );
    assert!(traversal.attributes.iter().any(|attribute| {
        attribute.name == gimli::DW_AT_data_member_location.0 && attribute.unsigned == Some(0)
    }));
    let type_reference = traversal
        .attributes
        .iter()
        .find(|attribute| attribute.name == gimli::DW_AT_type.0)
        .expect("member type reference");
    assert!(type_reference.unsigned.is_some());
    assert_eq!(
        type_reference.unit_reference,
        Some(traversal.entries[1].debug_info_offset)
    );
    assert_eq!(traversal.source_files.len(), 2);
    assert_eq!(traversal.source_files[0].file_index, 0);
    assert_eq!(traversal.source_files[1].file_index, 1);
    assert_eq!(traversal.source_files[1].file_name, b"fixture.c");
    assert_eq!(traversal.line_rows.len(), 3);
    assert_eq!(traversal.line_rows[0].address, 0x1000);
    assert_eq!(traversal.line_rows[1].line, Some(10));
    assert!(traversal.line_rows[2].end_sequence);
}

#[test]
fn malformed_unit_and_tight_budget_fail_closed() {
    let mut bytes = dwarf4_macho_fixture();
    let debug_info_offset = section_offset(&bytes, "__debug_info");
    bytes[debug_info_offset..debug_info_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    let container = macho_core::parse(&bytes).expect("envelope remains valid");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("truncated unit rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let bytes = dwarf4_macho_fixture();
    let container = macho_core::parse(&bytes).expect("fixture parses");
    let limits = macho_dwarf::DwarfTraversalLimits {
        max_entries: 1,
        ..macho_dwarf::DwarfTraversalLimits::default()
    };
    let error = macho_dwarf::traverse_dwarf(container.first_macho().expect("thin image"), limits)
        .expect_err("entry ceiling rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::Unsupported);
}

#[test]
fn legacy_range_lists_retain_raw_order_bases_and_exact_intervals() {
    let bytes = dwarf4_ranges_fixture(true);
    let container = macho_core::parse(&bytes).expect("range fixture parses");
    let traversal = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect("range traversal succeeds")
    .expect("DWARF exists");

    assert_eq!(traversal.range_lists.len(), 1);
    assert_eq!(
        traversal.range_lists[0].attribute_form,
        gimli::DW_FORM_sec_offset.0
    );
    assert_eq!(traversal.range_lists[0].list_offset, 0);
    assert_eq!(traversal.range_lists[0].initial_base_address, 0x1000);
    assert_eq!(traversal.range_lists[0].coverage, "complete");
    assert_eq!(traversal.range_entries.len(), 3);
    assert_eq!(traversal.range_entries[0].kind, "address_or_offset_pair");
    assert_eq!(traversal.range_entries[0].raw_operand0, Some(0));
    assert_eq!(traversal.range_entries[0].start, Some(0x1000));
    assert_eq!(traversal.range_entries[0].end, Some(0x1010));
    assert_eq!(traversal.range_entries[1].start, Some(0x1020));
    assert_eq!(traversal.range_entries[1].end, Some(0x1028));
    assert_eq!(traversal.range_entries[2].kind, "base_address");
    assert_eq!(traversal.range_entries[2].raw_operand0, Some(0x3000));
    assert_eq!(traversal.range_entries[2].active_base_address, 0x3000);
    assert_eq!(traversal.range_entries[2].disposition, "base");
}

#[test]
fn dwarf5_rnglistx_retains_index_and_closed_rle_records() {
    let bytes = dwarf5_rnglistx_fixture(0x00, true);
    let container = macho_core::parse(&bytes).expect("DWARF5 fixture parses");
    let traversal = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect("DWARF5 range traversal succeeds")
    .expect("DWARF exists");

    let list = traversal.range_lists.first().expect("one range list");
    assert_eq!(list.attribute_form, gimli::DW_FORM_rnglistx.0);
    assert_eq!(list.attribute_value, 0);
    assert_eq!(list.list_offset, 16);
    assert_eq!(list.initial_base_address, 0x2000);
    assert_eq!(list.coverage, "complete");
    assert_eq!(traversal.range_entries.len(), 3);
    assert_eq!(traversal.range_entries[0].kind, "base_address");
    assert_eq!(traversal.range_entries[0].active_base_address, 0x4000);
    assert_eq!(traversal.range_entries[1].kind, "offset_pair");
    assert_eq!(traversal.range_entries[1].start, Some(0x4004));
    assert_eq!(traversal.range_entries[1].end, Some(0x4010));
    assert_eq!(traversal.range_entries[2].kind, "start_end");
    assert_eq!(traversal.range_entries[2].start, Some(0x5000));
    assert_eq!(traversal.range_entries[2].end, Some(0x5008));
}

#[test]
fn range_lists_reject_missing_terminators_unknown_opcodes_and_tight_budgets() {
    let missing_terminator = dwarf4_ranges_fixture(false);
    let container = macho_core::parse(&missing_terminator).expect("envelope parses");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("missing range terminator rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let missing_dwarf5_terminator = dwarf5_rnglistx_fixture(0x00, false);
    let container = macho_core::parse(&missing_dwarf5_terminator).expect("envelope parses");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("missing DWARF5 range terminator rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let truncated_operand = dwarf5_rnglistx_body(vec![0x06, 1, 2, 3, 4]);
    let container = macho_core::parse(&truncated_operand).expect("envelope parses");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("truncated DWARF5 range operand rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let mut overflowing_uleb = vec![0x04];
    overflowing_uleb.extend_from_slice(&[0xff; 10]);
    let overflowing_uleb = dwarf5_rnglistx_body(overflowing_uleb);
    let container = macho_core::parse(&overflowing_uleb).expect("envelope parses");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("overflowing DWARF5 ULEB rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let unresolved_address_index = dwarf5_rnglistx_fixture(0x01, true);
    let container = macho_core::parse(&unresolved_address_index).expect("envelope parses");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("missing .debug_addr index rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let unknown_opcode = dwarf5_rnglistx_fixture(0xff, true);
    let container = macho_core::parse(&unknown_opcode).expect("envelope parses");
    let error = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect_err("unknown RLE opcode rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::InvalidFormat);

    let bytes = dwarf4_ranges_fixture(true);
    let container = macho_core::parse(&bytes).expect("fixture parses");
    let limits = macho_dwarf::DwarfTraversalLimits {
        max_range_entries: 1,
        ..macho_dwarf::DwarfTraversalLimits::default()
    };
    let error = macho_dwarf::traverse_dwarf(container.first_macho().expect("thin image"), limits)
        .expect_err("range ceiling rejects");
    assert_eq!(error.kind, macho_dwarf::DwarfErrorKind::Unsupported);
}

#[test]
fn legacy_32_bit_address_width_resolves_without_64_bit_reads() {
    let bytes = dwarf4_ranges_fixture_with_address_size(true, 4);
    let container = macho_core::parse(&bytes).expect("32-bit-address DWARF envelope parses");
    let traversal = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect("32-bit-address DWARF traverses")
    .expect("DWARF exists");
    assert_eq!(traversal.units[0].address_size, 4);
    assert_eq!(traversal.range_entries.len(), 3);
    assert_eq!(traversal.range_entries[0].raw_operand1, Some(0x10));
    assert_eq!(traversal.range_entries[0].start, Some(0x1000));
    assert_eq!(traversal.range_entries[1].end, Some(0x1028));
    assert_eq!(traversal.range_entries[2].raw_operand0, Some(0x3000));
}

#[test]
fn suppressed_raw_ranges_are_retained_as_partial_not_absent() {
    let mut bytes = dwarf4_ranges_fixture(true);
    let ranges = section_offset(&bytes, "__debug_ranges");
    bytes[ranges..ranges + 8].copy_from_slice(&0x10_u64.to_le_bytes());
    bytes[ranges + 8..ranges + 16].copy_from_slice(&0x10_u64.to_le_bytes());
    let container = macho_core::parse(&bytes).expect("envelope parses");
    let traversal = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect("suppressed range remains traversable")
    .expect("DWARF exists");
    assert_eq!(traversal.range_lists[0].coverage, "partial");
    assert_eq!(traversal.range_entries[0].disposition, "suppressed");
    assert_eq!(
        traversal.range_entries[0].limitation.as_deref(),
        Some("dwarf.range_entry_suppressed")
    );
    assert!(traversal.range_entries[0].start.is_none());
    assert!(traversal.range_entries[0].end.is_none());
    assert_eq!(traversal.range_entries[1].start, Some(0x1020));
}

#[cfg(target_os = "macos")]
#[test]
fn dwarf5_indexed_strings_are_resolved_to_exact_attribute_bytes() {
    let temporary = tempfile::tempdir().expect("tempdir");
    let source = temporary.path().join("indexed-strings.c");
    let object = temporary.path().join("indexed-strings.o");
    std::fs::write(
        &source,
        "int authorize(int code, long token) { return code == 7 && token == 11; }\n",
    )
    .expect("write source");
    let output = std::process::Command::new("clang")
        .args(["-gdwarf-5", "-O0", "-c"])
        .arg(&source)
        .arg("-o")
        .arg(&object)
        .output()
        .expect("spawn clang");
    assert!(
        output.status.success(),
        "clang failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let bytes = std::fs::read(object).expect("read object");
    let container = macho_core::parse(&bytes).expect("object parses");
    let traversal = macho_dwarf::traverse_dwarf(
        container.first_macho().expect("thin image"),
        macho_dwarf::DwarfTraversalLimits::default(),
    )
    .expect("DWARF traverses")
    .expect("DWARF exists");
    let names = traversal
        .attributes
        .iter()
        .filter(|attribute| attribute.name == gimli::DW_AT_name.0)
        .filter_map(|attribute| attribute.text.as_deref())
        .collect::<Vec<_>>();
    for expected in [
        b"authorize".as_slice(),
        b"code".as_slice(),
        b"token".as_slice(),
        b"int".as_slice(),
        b"long".as_slice(),
    ] {
        assert!(
            names.contains(&expected),
            "missing exact indexed string {:?} from {names:?}",
            String::from_utf8_lossy(expected)
        );
    }
    assert!(traversal.attributes.iter().any(|attribute| {
        attribute.form == gimli::DW_FORM_strx1.0
            && attribute.value_kind == "text"
            && attribute.text.is_some()
            && attribute.unsigned.is_some()
    }));
}

fn dwarf4_macho_fixture() -> Vec<u8> {
    let debug_abbrev = vec![
        1, 0x11, 1, 0x03, 0x08, 0x13, 0x05, 0x25, 0x08, 0x1b, 0x08, 0x10, 0x17, 0, 0, 2, 0x24, 0,
        0x03, 0x08, 0x0b, 0x0b, 0x3e, 0x0b, 0, 0, 3, 0x13, 1, 0x03, 0x08, 0x0b, 0x0b, 0, 0, 4,
        0x0d, 0, 0x03, 0x08, 0x49, 0x13, 0x38, 0x0b, 0, 0, 0,
    ];
    let mut entries = Vec::new();
    entries.push(1);
    entries.extend_from_slice(b"fixture.c\0");
    entries.extend_from_slice(&0x0002u16.to_le_bytes());
    entries.extend_from_slice(b"macho-dwarf-test\0");
    entries.extend_from_slice(b"/src\0");
    entries.extend_from_slice(&0u32.to_le_bytes());
    entries.push(2);
    entries.extend_from_slice(b"int\0");
    entries.push(4);
    entries.push(0x05);
    let int_die_offset = entries.len() + 4;
    entries.push(3);
    entries.extend_from_slice(b"Point\0");
    entries.push(4);
    entries.push(4);
    entries.extend_from_slice(b"x\0");
    entries.extend_from_slice(&(int_die_offset as u32).to_le_bytes());
    entries.push(0);
    entries.push(0);
    entries.push(0);
    let mut debug_info = Vec::new();
    debug_info.extend_from_slice(&((7 + entries.len()) as u32).to_le_bytes());
    debug_info.extend_from_slice(&4u16.to_le_bytes());
    debug_info.extend_from_slice(&0u32.to_le_bytes());
    debug_info.push(8);
    debug_info.extend_from_slice(&entries);

    let mut line_header = vec![1, 1, 1, 0xfb, 14, 13];
    line_header.extend_from_slice(&[0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]);
    line_header.extend_from_slice(b"src\0\0fixture.c\0");
    line_header.extend_from_slice(&[1, 0, 0, 0]);
    let mut line_ops = vec![0, 9, 2];
    line_ops.extend_from_slice(&0x1000u64.to_le_bytes());
    line_ops.extend_from_slice(&[1, 3, 9, 2, 4, 1, 0, 1, 1]);
    let mut debug_line = Vec::new();
    debug_line
        .extend_from_slice(&((2 + 4 + line_header.len() + line_ops.len()) as u32).to_le_bytes());
    debug_line.extend_from_slice(&4u16.to_le_bytes());
    debug_line.extend_from_slice(&(line_header.len() as u32).to_le_bytes());
    debug_line.extend_from_slice(&line_header);
    debug_line.extend_from_slice(&line_ops);

    macho_with_sections(&[
        ("__debug_abbrev", debug_abbrev),
        ("__debug_info", debug_info),
        ("__debug_line", debug_line),
    ])
}

fn dwarf4_ranges_fixture(terminated: bool) -> Vec<u8> {
    dwarf4_ranges_fixture_with_address_size(terminated, 8)
}

fn dwarf4_ranges_fixture_with_address_size(terminated: bool, address_size: u8) -> Vec<u8> {
    let mut debug_abbrev = Vec::new();
    push_uleb(&mut debug_abbrev, 1);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_TAG_compile_unit.0));
    debug_abbrev.push(1);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_AT_low_pc.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_FORM_addr.0));
    debug_abbrev.extend_from_slice(&[0, 0]);
    push_uleb(&mut debug_abbrev, 2);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_TAG_subprogram.0));
    debug_abbrev.push(0);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_AT_name.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_FORM_string.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_AT_ranges.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_FORM_sec_offset.0));
    debug_abbrev.extend_from_slice(&[0, 0, 0]);

    let mut entries = vec![1];
    match address_size {
        4 => entries.extend_from_slice(&0x1000_u32.to_le_bytes()),
        8 => entries.extend_from_slice(&0x1000_u64.to_le_bytes()),
        _ => panic!("test fixture address width must be 4 or 8"),
    }
    entries.push(2);
    entries.extend_from_slice(b"authorize\0");
    entries.extend_from_slice(&0_u32.to_le_bytes());
    entries.push(0);
    let mut debug_info = Vec::new();
    debug_info.extend_from_slice(&((7 + entries.len()) as u32).to_le_bytes());
    debug_info.extend_from_slice(&4_u16.to_le_bytes());
    debug_info.extend_from_slice(&0_u32.to_le_bytes());
    debug_info.push(address_size);
    debug_info.extend_from_slice(&entries);

    let mut debug_ranges = Vec::new();
    let maximum = if address_size == 4 {
        u64::from(u32::MAX)
    } else {
        u64::MAX
    };
    for value in [0_u64, 0x10, 0x20, 0x28, maximum, 0x3000] {
        match address_size {
            4 => debug_ranges.extend_from_slice(&(value as u32).to_le_bytes()),
            8 => debug_ranges.extend_from_slice(&value.to_le_bytes()),
            _ => unreachable!(),
        }
    }
    if terminated {
        debug_ranges.resize(debug_ranges.len() + usize::from(address_size) * 2, 0);
    }
    macho_with_sections(&[
        ("__debug_abbrev", debug_abbrev),
        ("__debug_info", debug_info),
        ("__debug_ranges", debug_ranges),
    ])
}

fn dwarf5_rnglistx_fixture(first_list_opcode: u8, terminated: bool) -> Vec<u8> {
    let mut range_body = Vec::new();
    range_body.push(if first_list_opcode == 0 {
        0x05
    } else {
        first_list_opcode
    });
    if range_body[0] == 0x05 {
        range_body.extend_from_slice(&0x4000_u64.to_le_bytes());
        range_body.extend_from_slice(&[0x04, 0x04, 0x10, 0x06]);
        range_body.extend_from_slice(&0x5000_u64.to_le_bytes());
        range_body.extend_from_slice(&0x5008_u64.to_le_bytes());
    } else if range_body[0] == 0x01 {
        range_body.push(0);
    }
    if terminated {
        range_body.push(0);
    }
    dwarf5_rnglistx_body(range_body)
}

fn dwarf5_rnglistx_body(range_body: Vec<u8>) -> Vec<u8> {
    let mut debug_abbrev = Vec::new();
    push_uleb(&mut debug_abbrev, 1);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_TAG_compile_unit.0));
    debug_abbrev.push(1);
    for (name, form) in [
        (gimli::DW_AT_low_pc.0, gimli::DW_FORM_addr.0),
        (gimli::DW_AT_rnglists_base.0, gimli::DW_FORM_sec_offset.0),
    ] {
        push_uleb(&mut debug_abbrev, u64::from(name));
        push_uleb(&mut debug_abbrev, u64::from(form));
    }
    debug_abbrev.extend_from_slice(&[0, 0]);
    push_uleb(&mut debug_abbrev, 2);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_TAG_subprogram.0));
    debug_abbrev.push(0);
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_AT_name.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_FORM_string.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_AT_ranges.0));
    push_uleb(&mut debug_abbrev, u64::from(gimli::DW_FORM_rnglistx.0));
    debug_abbrev.extend_from_slice(&[0, 0, 0]);

    let mut entries = vec![1];
    entries.extend_from_slice(&0x2000_u64.to_le_bytes());
    entries.extend_from_slice(&12_u32.to_le_bytes());
    entries.push(2);
    entries.extend_from_slice(b"authorize\0");
    entries.push(0);
    entries.push(0);
    let mut debug_info = Vec::new();
    debug_info.extend_from_slice(&((8 + entries.len()) as u32).to_le_bytes());
    debug_info.extend_from_slice(&5_u16.to_le_bytes());
    debug_info.push(gimli::DW_UT_compile.0);
    debug_info.push(8);
    debug_info.extend_from_slice(&0_u32.to_le_bytes());
    debug_info.extend_from_slice(&entries);

    let mut debug_rnglists = Vec::new();
    debug_rnglists.extend_from_slice(&((8 + 4 + range_body.len()) as u32).to_le_bytes());
    debug_rnglists.extend_from_slice(&5_u16.to_le_bytes());
    debug_rnglists.push(8);
    debug_rnglists.push(0);
    debug_rnglists.extend_from_slice(&1_u32.to_le_bytes());
    debug_rnglists.extend_from_slice(&4_u32.to_le_bytes());
    debug_rnglists.extend_from_slice(&range_body);

    macho_with_sections(&[
        ("__debug_abbrev", debug_abbrev),
        ("__debug_info", debug_info),
        ("__debug_rnglists", debug_rnglists),
    ])
}

fn push_uleb(bytes: &mut Vec<u8>, mut value: u64) {
    loop {
        let mut byte = (value & 0x7f) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        bytes.push(byte);
        if value == 0 {
            return;
        }
    }
}

fn macho_with_sections(sections: &[(&str, Vec<u8>)]) -> Vec<u8> {
    const HEADER_SIZE: usize = 32;
    const SEGMENT_SIZE: usize = 72;
    const SECTION_SIZE: usize = 80;
    const DATA_OFFSET: usize = 0x200;
    let command_size = SEGMENT_SIZE + SECTION_SIZE * sections.len();
    let data_size: usize = sections.iter().map(|(_, bytes)| bytes.len()).sum();
    let mut bytes = Vec::with_capacity(DATA_OFFSET + data_size);
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&0x0100_0007u32.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(command_size as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    assert_eq!(bytes.len(), HEADER_SIZE);
    bytes.extend_from_slice(&0x19u32.to_le_bytes());
    bytes.extend_from_slice(&(command_size as u32).to_le_bytes());
    push_name(&mut bytes, "__DWARF");
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&(data_size as u64).to_le_bytes());
    bytes.extend_from_slice(&(DATA_OFFSET as u64).to_le_bytes());
    bytes.extend_from_slice(&(data_size as u64).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(sections.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    let mut offset = DATA_OFFSET;
    for (name, data) in sections {
        push_name(&mut bytes, name);
        push_name(&mut bytes, "__DWARF");
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(&(data.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        offset += data.len();
    }
    bytes.resize(DATA_OFFSET, 0);
    for (_, data) in sections {
        bytes.extend_from_slice(data);
    }
    bytes
}

fn push_name(bytes: &mut Vec<u8>, name: &str) {
    let mut field = [0u8; 16];
    field[..name.len()].copy_from_slice(name.as_bytes());
    bytes.extend_from_slice(&field);
}

fn section_offset(bytes: &[u8], name: &str) -> usize {
    let needle = name.as_bytes();
    let name_offset = bytes
        .windows(needle.len())
        .position(|window| window == needle)
        .expect("section name exists");
    let offset_field = name_offset + 16 + 16 + 8 + 8;
    u32::from_le_bytes(bytes[offset_field..offset_field + 4].try_into().unwrap()) as usize
}
