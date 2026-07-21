use super::{CPU_TYPE_X86_64, push_fixed_name, push_segment64};

/// Build a signable x86-64 image whose `__DATA` segment has a bounded file gap
/// before final `__LINKEDIT`, suitable for non-relocating section insertion.
pub fn signable_thin64_x86_64_with_data_gap(file_type: u32) -> Vec<u8> {
    const HEADER_SIZE: usize = 32;
    const SECTION_SEGMENT_COMMAND_SIZE: usize = 72 + 80;
    const LINKEDIT_SEGMENT_COMMAND_SIZE: usize = 72;
    const DATA_OFFSET: usize = 0x1000;
    const DATA_SIZE: usize = 0x100;
    const LINKEDIT_OFFSET: usize = 0x1200;
    const LINKEDIT_SIZE: usize = 0x10;

    let mut bytes = Vec::with_capacity(LINKEDIT_OFFSET + LINKEDIT_SIZE);
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&file_type.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(
        &((SECTION_SEGMENT_COMMAND_SIZE * 2 + LINKEDIT_SEGMENT_COMMAND_SIZE) as u32).to_le_bytes(),
    );
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(bytes.len(), HEADER_SIZE);

    push_segment64(
        &mut bytes,
        "__TEXT",
        0x1_0000_0000,
        DATA_OFFSET as u64,
        0,
        DATA_OFFSET as u64,
        5,
        5,
        1,
    );
    push_fixed_name(&mut bytes, "__text");
    push_fixed_name(&mut bytes, "__TEXT");
    bytes.extend_from_slice(&0x1_0000_0400u64.to_le_bytes());
    bytes.extend_from_slice(&4u64.to_le_bytes());
    bytes.extend_from_slice(&0x400u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0x8000_0400u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    push_segment64(
        &mut bytes,
        "__DATA",
        0x1_0000_1000,
        0x1000,
        DATA_OFFSET as u64,
        DATA_SIZE as u64,
        3,
        3,
        1,
    );
    push_fixed_name(&mut bytes, "__data");
    push_fixed_name(&mut bytes, "__DATA");
    bytes.extend_from_slice(&0x1_0000_1000u64.to_le_bytes());
    bytes.extend_from_slice(&(DATA_SIZE as u64).to_le_bytes());
    bytes.extend_from_slice(&(DATA_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    push_segment64(
        &mut bytes,
        "__LINKEDIT",
        0x1_0000_2000,
        0x1000,
        LINKEDIT_OFFSET as u64,
        LINKEDIT_SIZE as u64,
        1,
        1,
        0,
    );
    bytes.resize(LINKEDIT_OFFSET + LINKEDIT_SIZE, 0);
    bytes[0x400..0x404].copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    bytes
}
