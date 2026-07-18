const CPU_TYPE_X86_64: u32 = 0x0100_0007;
const LC_SEGMENT_64: u32 = 0x19;
const SECTION_SIZE: usize = 4;

/// Build an x86-64 image containing `count` disjoint executable sections.
///
/// This fixture exists to make section-index and region-range scaling
/// assertions deterministic without relying on elapsed wall time.
pub fn disassembly_x86_64_sections(count: usize) -> Vec<u8> {
    assert!((1..=9_999).contains(&count));
    let command_size = 72usize
        .checked_add(count.checked_mul(80).expect("bounded section table"))
        .expect("bounded segment command");
    let data_offset = (32 + command_size).next_multiple_of(16);
    let file_size = data_offset
        .checked_add(count * SECTION_SIZE)
        .expect("bounded fixture size");
    let image_base = 0x1_0000_0000u64;

    let mut bytes = Vec::with_capacity(file_size);
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
    bytes.extend_from_slice(&3u32.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&(command_size as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    bytes.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    bytes.extend_from_slice(&(command_size as u32).to_le_bytes());
    push_fixed_name(&mut bytes, "__TEXT");
    bytes.extend_from_slice(&image_base.to_le_bytes());
    bytes.extend_from_slice(&(file_size as u64).to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&(file_size as u64).to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&(count as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    for index in 0..count {
        push_fixed_name(&mut bytes, &format!("__s{index:04}"));
        push_fixed_name(&mut bytes, "__TEXT");
        let offset = data_offset + index * SECTION_SIZE;
        bytes.extend_from_slice(&(image_base + offset as u64).to_le_bytes());
        bytes.extend_from_slice(&(SECTION_SIZE as u64).to_le_bytes());
        bytes.extend_from_slice(&(offset as u32).to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0x8000_0400u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
    }
    bytes.resize(data_offset, 0);
    for _ in 0..count {
        bytes.extend_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    }
    bytes
}

fn push_fixed_name(bytes: &mut Vec<u8>, name: &str) {
    assert!(name.len() <= 16);
    let mut fixed = [0u8; 16];
    fixed[..name.len()].copy_from_slice(name.as_bytes());
    bytes.extend_from_slice(&fixed);
}
