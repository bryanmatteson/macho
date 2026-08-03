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
