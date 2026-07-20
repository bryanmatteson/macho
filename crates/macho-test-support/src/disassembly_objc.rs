use super::{CPU_TYPE_X86_64, push_fixed_name};

/// Build an x86-64 image whose parsed Objective-C method IMP is the next code
/// owner after `_main`.
pub fn disassembly_objc_boundary() -> Vec<u8> {
    const HEADER_SIZE: usize = 32;
    const SEGMENT_COMMAND_SIZE: usize = 72 + 2 * 80;
    const SYMTAB_COMMAND_SIZE: usize = 24;
    const TEXT_OFFSET: usize = 0x200;
    const TEXT_SIZE: usize = 0x40;
    const CLASS_LIST_OFFSET: usize = 0x240;
    const CLASS_OFFSET: usize = 0x248;
    const CLASS_RO_OFFSET: usize = 0x270;
    const METHOD_LIST_OFFSET: usize = 0x2c0;
    const CLASS_NAME_OFFSET: usize = 0x2e0;
    const METHOD_NAME_OFFSET: usize = 0x2e8;
    const METHOD_TYPES_OFFSET: usize = 0x2f0;
    const SYMBOL_OFFSET: usize = 0x300;
    const STRING_OFFSET: usize = 0x310;

    let image_base = 0x1_0000_0000u64;
    let file_size = STRING_OFFSET + 7;
    let mut bytes = Vec::with_capacity(file_size);
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&((SEGMENT_COMMAND_SIZE + SYMTAB_COMMAND_SIZE) as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(bytes.len(), HEADER_SIZE);

    bytes.extend_from_slice(&0x19u32.to_le_bytes());
    bytes.extend_from_slice(&(SEGMENT_COMMAND_SIZE as u32).to_le_bytes());
    push_fixed_name(&mut bytes, "__TEXT");
    bytes.extend_from_slice(&image_base.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&(file_size as u64).to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    push_fixed_name(&mut bytes, "__text");
    push_fixed_name(&mut bytes, "__TEXT");
    bytes.extend_from_slice(&(image_base + TEXT_OFFSET as u64).to_le_bytes());
    bytes.extend_from_slice(&(TEXT_SIZE as u64).to_le_bytes());
    bytes.extend_from_slice(&(TEXT_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0x8000_0400u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    push_fixed_name(&mut bytes, "__objc_classlist");
    push_fixed_name(&mut bytes, "__TEXT");
    bytes.extend_from_slice(&(image_base + CLASS_LIST_OFFSET as u64).to_le_bytes());
    bytes.extend_from_slice(&8u64.to_le_bytes());
    bytes.extend_from_slice(&(CLASS_LIST_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    bytes.extend_from_slice(&0x02u32.to_le_bytes());
    bytes.extend_from_slice(&(SYMTAB_COMMAND_SIZE as u32).to_le_bytes());
    bytes.extend_from_slice(&(SYMBOL_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(STRING_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(&7u32.to_le_bytes());
    bytes.resize(TEXT_OFFSET, 0);

    for chunk in (0..TEXT_SIZE).step_by(4) {
        bytes.extend_from_slice(if chunk == 0 {
            &[0xeb, 0x02, 0x90, 0xc3]
        } else {
            &[0x90, 0x90, 0x90, 0xc3]
        });
    }
    debug_assert_eq!(bytes.len(), CLASS_LIST_OFFSET);
    bytes.extend_from_slice(&(image_base + CLASS_OFFSET as u64).to_le_bytes());
    bytes.resize(CLASS_OFFSET + 32, 0);
    bytes.extend_from_slice(&(image_base + CLASS_RO_OFFSET as u64).to_le_bytes());
    bytes.resize(CLASS_RO_OFFSET + 24, 0);
    bytes.extend_from_slice(&(image_base + CLASS_NAME_OFFSET as u64).to_le_bytes());
    bytes.extend_from_slice(&(image_base + METHOD_LIST_OFFSET as u64).to_le_bytes());
    bytes.resize(METHOD_LIST_OFFSET, 0);
    bytes.extend_from_slice(&24u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(image_base + METHOD_NAME_OFFSET as u64).to_le_bytes());
    bytes.extend_from_slice(&(image_base + METHOD_TYPES_OFFSET as u64).to_le_bytes());
    bytes.extend_from_slice(&(image_base + TEXT_OFFSET as u64 + 4).to_le_bytes());
    bytes.resize(CLASS_NAME_OFFSET, 0);
    bytes.extend_from_slice(b"Fixture\0");
    bytes.resize(METHOD_NAME_OFFSET, 0);
    bytes.extend_from_slice(b"next\0");
    bytes.resize(METHOD_TYPES_OFFSET, 0);
    bytes.extend_from_slice(b"v@:\0");
    bytes.resize(SYMBOL_OFFSET, 0);
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(0x0f);
    bytes.push(1);
    bytes.extend_from_slice(&0u16.to_le_bytes());
    bytes.extend_from_slice(&(image_base + TEXT_OFFSET as u64).to_le_bytes());
    bytes.resize(STRING_OFFSET, 0);
    bytes.extend_from_slice(b"\0_main\0");
    bytes
}

/// Build an x86-64 image whose `__objc_classlist` lists the same class pointer
/// twice. Both entries resolve to one class object at the same runtime address,
/// producing two same-address class observations — the shape that made real
/// binaries fail entity-identity validation before duplicate entities were
/// collapsed.
pub fn disassembly_objc_duplicate_class() -> Vec<u8> {
    // Class object built by [`disassembly_objc_boundary`].
    const CLASS_OFFSET: u64 = 0x248;
    // File offset of the second (`__objc_classlist`) section header: 32-byte
    // Mach header + 72-byte segment command body + one 80-byte section header.
    const CLASSLIST_SECTION_HEADER: usize = 184;
    // `filesize` field within the single segment command body.
    const SEGMENT_FILESIZE_FIELD: usize = 80;
    let image_base = 0x1_0000_0000u64;

    let mut bytes = disassembly_objc_boundary();
    while bytes.len() % 8 != 0 {
        bytes.push(0);
    }
    let table_offset = bytes.len() as u64;
    let class_pointer = image_base + CLASS_OFFSET;
    bytes.extend_from_slice(&class_pointer.to_le_bytes());
    bytes.extend_from_slice(&class_pointer.to_le_bytes());
    let end = bytes.len() as u64;

    // Repoint `__objc_classlist` at the two-entry table: addr(+32), size(+40),
    // offset(+48) within the section header.
    bytes[CLASSLIST_SECTION_HEADER + 32..CLASSLIST_SECTION_HEADER + 40]
        .copy_from_slice(&(image_base + table_offset).to_le_bytes());
    bytes[CLASSLIST_SECTION_HEADER + 40..CLASSLIST_SECTION_HEADER + 48]
        .copy_from_slice(&16u64.to_le_bytes());
    bytes[CLASSLIST_SECTION_HEADER + 48..CLASSLIST_SECTION_HEADER + 52]
        .copy_from_slice(&(table_offset as u32).to_le_bytes());

    // Extend the segment's file coverage so the appended table is mapped.
    bytes[SEGMENT_FILESIZE_FIELD..SEGMENT_FILESIZE_FIELD + 8].copy_from_slice(&end.to_le_bytes());
    bytes
}

/// Build an x86-64 image with parsed Objective-C category instance and class
/// methods so disassembly labels can prove their `-`/`+` distinction.
pub fn disassembly_objc_category_labels() -> Vec<u8> {
    const CATEGORY_OFFSET: usize = 0x248;
    const CLASS_METHOD_LIST_OFFSET: usize = 0x290;
    const INSTANCE_METHOD_LIST_OFFSET: usize = 0x2c0;
    const CATEGORY_NAME_OFFSET: usize = 0x2e0;
    const METHOD_NAME_OFFSET: usize = 0x2e8;
    const METHOD_TYPES_OFFSET: usize = 0x2f0;
    const OWNER_CLASS_OFFSET: usize = 0x320;
    const OWNER_CLASS_RO_OFFSET: usize = 0x348;
    const OWNER_CLASS_NAME_OFFSET: usize = 0x390;
    let image_base = 0x1_0000_0000u64;

    let mut bytes = disassembly_objc_boundary();
    bytes[184..200].fill(0);
    bytes[184..184 + "__objc_catlist".len()].copy_from_slice(b"__objc_catlist");

    bytes[CATEGORY_OFFSET..CATEGORY_OFFSET + 56].fill(0);
    bytes[CATEGORY_OFFSET..CATEGORY_OFFSET + 8]
        .copy_from_slice(&(image_base + CATEGORY_NAME_OFFSET as u64).to_le_bytes());
    bytes[CATEGORY_OFFSET + 8..CATEGORY_OFFSET + 16]
        .copy_from_slice(&(image_base + OWNER_CLASS_OFFSET as u64).to_le_bytes());
    bytes[CATEGORY_OFFSET + 16..CATEGORY_OFFSET + 24]
        .copy_from_slice(&(image_base + INSTANCE_METHOD_LIST_OFFSET as u64).to_le_bytes());
    bytes[CATEGORY_OFFSET + 24..CATEGORY_OFFSET + 32]
        .copy_from_slice(&(image_base + CLASS_METHOD_LIST_OFFSET as u64).to_le_bytes());

    bytes[CLASS_METHOD_LIST_OFFSET..CLASS_METHOD_LIST_OFFSET + 32].fill(0);
    bytes[CLASS_METHOD_LIST_OFFSET..CLASS_METHOD_LIST_OFFSET + 4]
        .copy_from_slice(&24u32.to_le_bytes());
    bytes[CLASS_METHOD_LIST_OFFSET + 4..CLASS_METHOD_LIST_OFFSET + 8]
        .copy_from_slice(&1u32.to_le_bytes());
    bytes[CLASS_METHOD_LIST_OFFSET + 8..CLASS_METHOD_LIST_OFFSET + 16]
        .copy_from_slice(&(image_base + METHOD_NAME_OFFSET as u64).to_le_bytes());
    bytes[CLASS_METHOD_LIST_OFFSET + 16..CLASS_METHOD_LIST_OFFSET + 24]
        .copy_from_slice(&(image_base + METHOD_TYPES_OFFSET as u64).to_le_bytes());
    bytes[CLASS_METHOD_LIST_OFFSET + 24..CLASS_METHOD_LIST_OFFSET + 32]
        .copy_from_slice(&(image_base + 0x208).to_le_bytes());
    bytes.resize(OWNER_CLASS_OFFSET + 32, 0);
    bytes.extend_from_slice(&(image_base + OWNER_CLASS_RO_OFFSET as u64).to_le_bytes());
    bytes.resize(OWNER_CLASS_RO_OFFSET + 24, 0);
    bytes.extend_from_slice(&(image_base + OWNER_CLASS_NAME_OFFSET as u64).to_le_bytes());
    bytes.resize(OWNER_CLASS_NAME_OFFSET, 0);
    bytes.extend_from_slice(b"FixtureOwner\0");
    let file_size = bytes.len() as u64;
    bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    bytes
}
