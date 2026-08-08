use super::*;
use crate::dyld_cache::parse::{
    IMAGE_INFO_SIZE, IMAGE_TEXT_INFO_SIZE, MAPPING_AND_SLIDE_INFO_SIZE, MAPPING_INFO_SIZE,
};

const FAMILY_BASE: u64 = 0x1_0000_0000;
const IMAGE_VA: u64 = FAMILY_BASE + 0x1400;

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32_be(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_u64_be(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_name(bytes: &mut [u8], offset: usize, name: &str) {
    bytes[offset..offset + name.len()].copy_from_slice(name.as_bytes());
}

fn cache_magic(bytes: &mut [u8], arch: &str) {
    let magic = format!("dyld_v1  {arch}");
    bytes[..magic.len().min(16)].copy_from_slice(&magic.as_bytes()[..magic.len().min(16)]);
}

fn make_family() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let primary_uuid = [0x11; 16];
    let first_uuid = [0x22; 16];
    let second_uuid = [0x33; 16];
    let mut primary = vec![0_u8; 0x400];
    cache_magic(&mut primary, "arm64e");
    put_u32(&mut primary, 16, 0x260);
    put_u32(&mut primary, 20, 1);
    primary[0x58..0x68].copy_from_slice(&primary_uuid);
    put_u32(&mut primary, 0x188, 0x280);
    put_u32(&mut primary, 0x18c, 2);
    put_u32(&mut primary, 0x1c0, 0x300);
    put_u32(&mut primary, 0x1c4, 1);
    put_u64(&mut primary, 0x260, FAMILY_BASE);
    put_u64(&mut primary, 0x268, 0x400);
    put_u64(&mut primary, 0x270, 0);
    put_u32(&mut primary, 0x278, 5);
    put_u32(&mut primary, 0x27c, 5);
    primary[0x280..0x290].copy_from_slice(&first_uuid);
    put_u64(&mut primary, 0x290, 0x1000);
    put_name(&mut primary, 0x298, ".01");
    primary[0x2b8..0x2c8].copy_from_slice(&second_uuid);
    put_u64(&mut primary, 0x2c8, 0x4000);
    put_name(&mut primary, 0x2d0, ".02.dyldlinkedit");
    put_u64(&mut primary, 0x300, IMAGE_VA);
    put_u32(&mut primary, 0x318, 0x320);
    put_name(&mut primary, 0x320, "/usr/lib/libFixture.dylib");

    let mut first = make_member(first_uuid, FAMILY_BASE + 0x1000, 0x3000, "arm64e");
    let mut second = make_member(second_uuid, FAMILY_BASE + 0x4000, 0x3000, "arm64e");
    let macho_offset = 0x800;
    let ncmds = 4_u32;
    let sizeofcmds = 72 * 2 + 24 + 16;
    put_u32(&mut first, macho_offset, 0xfeed_facf);
    put_u32(&mut first, macho_offset + 4, 0x0100_000c);
    put_u32(&mut first, macho_offset + 8, 2);
    put_u32(&mut first, macho_offset + 12, 6);
    put_u32(&mut first, macho_offset + 16, ncmds);
    put_u32(&mut first, macho_offset + 20, sizeofcmds);
    put_u32(&mut first, macho_offset + 24, 0x8000_0085);
    let text = macho_offset + 32;
    put_u32(&mut first, text, 0x19);
    put_u32(&mut first, text + 4, 72);
    put_name(&mut first, text + 8, "__TEXT");
    put_u64(&mut first, text + 24, IMAGE_VA);
    put_u64(&mut first, text + 32, 0x3c00);
    put_u64(&mut first, text + 40, 0);
    put_u64(&mut first, text + 48, 0x3c00);
    put_u32(&mut first, text + 56, 7);
    put_u32(&mut first, text + 60, 5);
    let linkedit = text + 72;
    put_u32(&mut first, linkedit, 0x19);
    put_u32(&mut first, linkedit + 4, 72);
    put_name(&mut first, linkedit + 8, "__LINKEDIT");
    put_u64(&mut first, linkedit + 24, FAMILY_BASE + 0x5000);
    put_u64(&mut first, linkedit + 32, 0x1000);
    put_u64(&mut first, linkedit + 40, 0x1400);
    put_u64(&mut first, linkedit + 48, 0x1000);
    put_u32(&mut first, linkedit + 56, 7);
    put_u32(&mut first, linkedit + 60, 1);
    let symtab = linkedit + 72;
    put_u32(&mut first, symtab, 0x2);
    put_u32(&mut first, symtab + 4, 24);
    put_u32(&mut first, symtab + 8, 0x1500);
    put_u32(&mut first, symtab + 12, 1);
    put_u32(&mut first, symtab + 16, 0x1510);
    put_u32(&mut first, symtab + 20, 0x800);
    let exports = symtab + 24;
    put_u32(&mut first, exports, 0x8000_0033);
    put_u32(&mut first, exports + 4, 16);
    put_u32(&mut first, exports + 8, 0x1700);
    let trie = synthetic_export_trie();
    put_u32(&mut first, exports + 12, trie.len() as u32);

    // The __TEXT segment crosses from .01 into .02.
    for byte in &mut first[macho_offset + sizeofcmds as usize + 32..0x3400] {
        *byte = 0x41;
    }
    for byte in &mut second[0x400..0x1400] {
        *byte = 0x42;
    }
    put_u32(&mut second, 0x1500, 0x100);
    second[0x1504] = 0x0f;
    second[0x1505] = 1;
    put_u64(&mut second, 0x1508, IMAGE_VA);
    put_name(&mut second, 0x1610, "_symbol");
    second[0x1617] = 0;
    second[0x1700..0x1700 + trie.len()].copy_from_slice(&trie);
    (primary, first, second)
}

fn make_member(uuid: [u8; 16], address: u64, size: u64, arch: &str) -> Vec<u8> {
    let mut data = vec![0_u8; 0x400 + size as usize];
    cache_magic(&mut data, arch);
    put_u32(&mut data, 16, 0x260);
    put_u32(&mut data, 20, 1);
    data[0x58..0x68].copy_from_slice(&uuid);
    put_u64(&mut data, 0x260, address);
    put_u64(&mut data, 0x268, size);
    put_u64(&mut data, 0x270, 0x400);
    put_u32(&mut data, 0x278, 7);
    put_u32(&mut data, 0x27c, 5);
    data
}

fn make_v1_cache_with_local_symbols() -> Vec<u8> {
    let mut data = vec![0_u8; 0x700];
    cache_magic(&mut data, "arm64e");
    put_u32(&mut data, 16, 0x1c8);
    put_u32(&mut data, 20, 1);
    data[0x58..0x68].copy_from_slice(&[0x44; 16]);
    put_u64(&mut data, 0x48, 0x500);
    put_u64(&mut data, 0x50, 0x40);
    put_u32(&mut data, 0x188, 0x200);
    put_u32(&mut data, 0x18c, 2);

    put_u64(&mut data, 0x1c8, FAMILY_BASE);
    put_u64(&mut data, 0x1d0, 0x100);
    put_u64(&mut data, 0x1d8, 0x400);
    put_u32(&mut data, 0x1e0, 5);
    put_u32(&mut data, 0x1e4, 5);
    data[0x200..0x210].copy_from_slice(&[0x55; 16]);
    put_u64(&mut data, 0x210, 0x1000);
    data[0x218..0x228].copy_from_slice(&[0x66; 16]);
    put_u64(&mut data, 0x228, 0x2000);

    put_u32(&mut data, 0x500, 24);
    put_u32(&mut data, 0x504, 1);
    put_u32(&mut data, 0x508, 40);
    put_u32(&mut data, 0x50c, 8);
    put_u32(&mut data, 0x510, 48);
    put_u32(&mut data, 0x514, 1);
    put_u32(&mut data, 0x518, 1);
    put_name(&mut data, 0x528, "\0local\0");
    put_u64(&mut data, 0x530, 0x1400);
    put_u32(&mut data, 0x538, 0);
    put_u32(&mut data, 0x53c, 1);
    data
}

fn make_symbols_member(uuid: [u8; 16]) -> Vec<u8> {
    let mut data = vec![0_u8; 0x380];
    cache_magic(&mut data, "arm64e");
    put_u32(&mut data, 16, 0x260);
    data[0x58..0x68].copy_from_slice(&uuid);
    put_u64(&mut data, 0x48, 0x300);
    put_u64(&mut data, 0x50, 0x40);
    put_u32(&mut data, 0x300, 24);
    put_u32(&mut data, 0x304, 1);
    put_u32(&mut data, 0x308, 40);
    put_u32(&mut data, 0x30c, 8);
    put_u32(&mut data, 0x310, 48);
    put_u32(&mut data, 0x314, 1);
    put_u32(&mut data, 0x318, 1);
    put_name(&mut data, 0x328, "\0local\0");
    put_u64(&mut data, 0x330, 0x1400);
    put_u32(&mut data, 0x338, 0);
    put_u32(&mut data, 0x33c, 1);
    data
}

fn synthetic_export_trie() -> Vec<u8> {
    let mut trie = vec![0, 1, b'_', 0, 6, 0, 0, 1];
    trie.extend_from_slice(b"main");
    trie.extend_from_slice(&[0, 14]);
    while trie.len() < 14 {
        trie.push(0);
    }
    trie.extend_from_slice(&[3, 0, 0x80, 0x20, 0]);
    trie
}

fn parse_family<'a>(primary: &'a [u8], first: &'a [u8], second: &'a [u8]) -> DyldCacheFamily<'a> {
    DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: second,
            },
        ],
    )
    .expect("valid cache family")
}

fn make_minimal_cache(arch: &str) -> Vec<u8> {
    // Build a minimal old-format dyld cache with 1 mapping and 1 image
    let mut magic = [0u8; 16];
    let prefix = format!("dyld_v1  {arch}");
    let bytes = prefix.as_bytes();
    let len = bytes.len().min(15);
    magic[..len].copy_from_slice(&bytes[..len]);

    let mapping_offset: u32 = 32; // right after header
    let mapping_count: u32 = 1;
    let images_offset: u32 = mapping_offset + MAPPING_INFO_SIZE as u32;
    let images_count: u32 = 1;

    let image_va: u64 = 0x1_0000_0000;
    let image_file_offset: u64 = 4096;

    // Path will be placed after the image info
    let path_offset: u32 = images_offset + IMAGE_INFO_SIZE as u32;
    let path = b"/usr/lib/libSystem.B.dylib\0";

    let total_size = path_offset as usize + path.len() + image_file_offset as usize + 4096;
    let mut data = vec![0u8; total_size];

    // Header
    data[..16].copy_from_slice(&magic);
    data[16..20].copy_from_slice(&mapping_offset.to_le_bytes());
    data[20..24].copy_from_slice(&mapping_count.to_le_bytes());
    data[24..28].copy_from_slice(&images_offset.to_le_bytes());
    data[28..32].copy_from_slice(&images_count.to_le_bytes());

    // Mapping: covers the image region
    let m_off = mapping_offset as usize;
    data[m_off..m_off + 8].copy_from_slice(&image_va.to_le_bytes());
    data[m_off + 8..m_off + 16].copy_from_slice(&4096u64.to_le_bytes());
    data[m_off + 16..m_off + 24].copy_from_slice(&image_file_offset.to_le_bytes());
    data[m_off + 24..m_off + 28].copy_from_slice(&5u32.to_le_bytes());
    data[m_off + 28..m_off + 32].copy_from_slice(&5u32.to_le_bytes());

    // Image info (old format: address + modTime + inode + pathOffset + pad)
    let i_off = images_offset as usize;
    data[i_off..i_off + 8].copy_from_slice(&image_va.to_le_bytes());
    data[i_off + 8..i_off + 16].copy_from_slice(&0u64.to_le_bytes());
    data[i_off + 16..i_off + 24].copy_from_slice(&0u64.to_le_bytes());
    data[i_off + 24..i_off + 28].copy_from_slice(&path_offset.to_le_bytes());

    // Path string
    let p_off = path_offset as usize;
    data[p_off..p_off + path.len()].copy_from_slice(path);

    data
}

fn make_modern_cache(arch: &str) -> Vec<u8> {
    // Build a minimal modern-format cache (old image fields zeroed, uses imagesText)
    let mut magic = [0u8; 16];
    let prefix = format!("dyld_v1  {arch}");
    let bytes = prefix.as_bytes();
    let len = bytes.len().min(15);
    magic[..len].copy_from_slice(&bytes[..len]);

    let mapping_offset: u32 = 0x98; // after header (needs room for imagesText fields)
    let mapping_count: u32 = 1;

    let image_va: u64 = 0x1_8000_0000;
    let image_file_offset: u64 = 4096;

    // imagesText entries start after the mapping
    let images_text_offset: u64 = (mapping_offset as u64) + MAPPING_INFO_SIZE as u64;
    let images_text_count: u64 = 1;

    // Path after the image text info
    let path_offset: u32 = (images_text_offset as u32) + IMAGE_TEXT_INFO_SIZE as u32;
    let path = b"/usr/lib/libSystem.B.dylib\0";

    let total_size = path_offset as usize + path.len() + image_file_offset as usize + 4096;
    let mut data = vec![0u8; total_size];

    // Header
    data[..16].copy_from_slice(&magic);
    data[16..20].copy_from_slice(&mapping_offset.to_le_bytes());
    data[20..24].copy_from_slice(&mapping_count.to_le_bytes());
    // Old image fields: zero
    data[24..28].copy_from_slice(&0u32.to_le_bytes());
    data[28..32].copy_from_slice(&0u32.to_le_bytes());

    // imagesText fields at offsets 0x88/0x90
    data[0x88..0x90].copy_from_slice(&images_text_offset.to_le_bytes());
    data[0x90..0x98].copy_from_slice(&images_text_count.to_le_bytes());

    // Mapping
    let m_off = mapping_offset as usize;
    data[m_off..m_off + 8].copy_from_slice(&image_va.to_le_bytes());
    data[m_off + 8..m_off + 16].copy_from_slice(&4096u64.to_le_bytes());
    data[m_off + 16..m_off + 24].copy_from_slice(&image_file_offset.to_le_bytes());
    data[m_off + 24..m_off + 28].copy_from_slice(&5u32.to_le_bytes());
    data[m_off + 28..m_off + 32].copy_from_slice(&5u32.to_le_bytes());

    // Image text info: uuid(16) + loadAddress(8) + textSegmentSize(4) + pathOffset(4)
    let i_off = images_text_offset as usize;
    // uuid: leave as zeros
    data[i_off + 16..i_off + 24].copy_from_slice(&image_va.to_le_bytes());
    data[i_off + 24..i_off + 28].copy_from_slice(&4096u32.to_le_bytes()); // text_size
    data[i_off + 28..i_off + 32].copy_from_slice(&path_offset.to_le_bytes());

    // Path string
    let p_off = path_offset as usize;
    data[p_off..p_off + path.len()].copy_from_slice(path);

    data
}

fn make_v0_powerpc_cache() -> Vec<u8> {
    let mapping_offset = 32_u32;
    let images_offset = mapping_offset + MAPPING_INFO_SIZE as u32;
    let path_offset = images_offset + IMAGE_INFO_SIZE as u32;
    let image_va = 0x9000_0000_u64;
    let image_file_offset = 0x1000_u64;
    let path = b"/usr/lib/libSystem.B.dylib\0";
    let mut data = vec![0_u8; 0x2000];
    data[..16].copy_from_slice(b"dyld_v0     ppc\0");
    put_u32_be(&mut data, 16, mapping_offset);
    put_u32_be(&mut data, 20, 1);
    put_u32_be(&mut data, 24, images_offset);
    put_u32_be(&mut data, 28, 1);
    put_u64_be(&mut data, mapping_offset as usize, image_va);
    put_u64_be(&mut data, mapping_offset as usize + 8, 0x1000);
    put_u64_be(&mut data, mapping_offset as usize + 16, image_file_offset);
    put_u32_be(&mut data, mapping_offset as usize + 24, 5);
    put_u32_be(&mut data, mapping_offset as usize + 28, 5);
    put_u64_be(&mut data, images_offset as usize, image_va);
    put_u32_be(&mut data, images_offset as usize + 24, path_offset);
    data[path_offset as usize..path_offset as usize + path.len()].copy_from_slice(path);
    data
}

fn make_extended_mapping_cache() -> Vec<u8> {
    let mapping_offset = 0x228_usize;
    let extended_offset = mapping_offset + MAPPING_INFO_SIZE;
    let tpro_offset = extended_offset + MAPPING_AND_SLIDE_INFO_SIZE;
    let address = 0x1_8000_0000_u64;
    let mut data = vec![0_u8; 0x800];
    cache_magic(&mut data, "arm64e");
    put_u32(&mut data, 16, mapping_offset as u32);
    put_u32(&mut data, 20, 1);
    put_u32(&mut data, 0x138, extended_offset as u32);
    put_u32(&mut data, 0x13c, 1);
    put_u32(&mut data, 0x200, tpro_offset as u32);
    put_u32(&mut data, 0x204, 1);

    put_u64(&mut data, mapping_offset, address);
    put_u64(&mut data, mapping_offset + 8, 0x400);
    put_u64(&mut data, mapping_offset + 16, 0x400);
    put_u32(&mut data, mapping_offset + 24, 3);
    put_u32(&mut data, mapping_offset + 28, 3);

    put_u64(&mut data, extended_offset, address);
    put_u64(&mut data, extended_offset + 8, 0x400);
    put_u64(&mut data, extended_offset + 16, 0x400);
    put_u64(&mut data, extended_offset + 24, 0x380);
    put_u64(&mut data, extended_offset + 32, 0x10);
    put_u64(&mut data, extended_offset + 40, 1 << 6);
    put_u32(&mut data, extended_offset + 48, 3);
    put_u32(&mut data, extended_offset + 52, 3);

    put_u64(&mut data, tpro_offset, address + 0x100);
    put_u64(&mut data, tpro_offset + 8, 0x80);
    data
}

#[test]
fn parse_old_format_cache() {
    let data = make_minimal_cache("arm64e");
    let cache = parse_dyld_cache(&data).expect("failed to parse");
    assert_eq!(cache.arch(), "arm64e");
    assert_eq!(cache.mappings().len(), 1);
    assert_eq!(cache.images().len(), 1);
    assert_eq!(cache.images()[0].path, "/usr/lib/libSystem.B.dylib");
    assert_eq!(cache.header.generation, DyldCacheHeaderGeneration::Legacy);
    assert_eq!(cache.header.format_version, DyldCacheFormatVersion::V1);
    assert_eq!(cache.header.byte_order, DyldCacheByteOrder::Little);
}

#[test]
fn parse_historical_v0_big_endian_powerpc_cache() {
    let data = make_v0_powerpc_cache();
    let cache = parse_dyld_cache(&data).expect("parse historical PowerPC cache");
    assert_eq!(cache.arch(), "ppc");
    assert_eq!(cache.header.format_version, DyldCacheFormatVersion::V0);
    assert_eq!(cache.header.byte_order, DyldCacheByteOrder::Big);
    assert_eq!(cache.mappings()[0].address, 0x9000_0000);
    assert_eq!(cache.mappings()[0].file_offset, 0x1000);
    assert_eq!(cache.images()[0].address, 0x9000_0000);
    assert_eq!(cache.images()[0].path, "/usr/lib/libSystem.B.dylib");
}

#[test]
fn parse_modern_format_cache() {
    let data = make_modern_cache("arm64e");
    let cache = parse_dyld_cache(&data).expect("failed to parse");
    assert_eq!(cache.arch(), "arm64e");
    assert_eq!(cache.mappings().len(), 1);
    assert_eq!(cache.images().len(), 1);
    assert_eq!(cache.images()[0].path, "/usr/lib/libSystem.B.dylib");
    assert_eq!(cache.images()[0].text_size, 4096);
    assert_eq!(cache.images()[0].address, 0x1_8000_0000);
}

#[test]
fn incomplete_images_text_coordinates_are_rejected() {
    let mut data = make_modern_cache("arm64e");
    put_u64(&mut data, 0x90, 0);
    let error = parse_dyld_cache(&data).expect_err("imagesText count is required with its offset");
    assert!(error.to_string().contains("imagesText offset and count"));
}

#[test]
fn current_extended_mappings_and_tpro_ranges_are_retained() {
    let data = make_extended_mapping_cache();
    let cache = parse_dyld_cache(&data).expect("parse current extended cache layout");
    let mapping = &cache.mappings()[0];
    assert_eq!(mapping.slide_info_file_offset, Some(0x380));
    assert_eq!(mapping.slide_info_file_size, Some(0x10));
    assert_eq!(mapping.flags, Some(1 << 6));
    assert_eq!(
        cache.tpro_mappings,
        [CacheTproMapping {
            address: 0x1_8000_0100,
            size: 0x80,
        }]
    );

    let mut mismatch = data.clone();
    put_u64(&mut mismatch, 0x228 + MAPPING_INFO_SIZE + 8, 0x200);
    let error = parse_dyld_cache(&mismatch).expect_err("mapping tables disagree");
    assert!(error.to_string().contains("disagrees"));

    let mut escaped_tpro = data;
    let tpro_offset = 0x228 + MAPPING_INFO_SIZE + MAPPING_AND_SLIDE_INFO_SIZE;
    put_u64(&mut escaped_tpro, tpro_offset, 0x1_9000_0000);
    let family = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &escaped_tpro,
        },
        [],
    )
    .expect_err("TPRO range outside mapped VM space");
    assert!(family.to_string().contains("TPRO"));
}

#[test]
fn apple_header_generations_and_local_symbol_entry_widths_are_explicit() {
    let v1 = make_v1_cache_with_local_symbols();
    let cache = parse_dyld_cache(&v1).expect("parse V1 cache");
    assert_eq!(
        cache.header.generation,
        DyldCacheHeaderGeneration::SubcacheV1
    );
    assert_eq!(
        cache
            .subcaches()
            .iter()
            .map(|entry| entry.file_suffix.as_str())
            .collect::<Vec<_>>(),
        [".1", ".2"]
    );
    let locals = cache.local_symbols.as_ref().expect("embedded locals");
    assert_eq!(locals.entries[0].dylib_offset, 0x1400);

    let (primary, _, _) = make_family();
    let cache = parse_dyld_cache(&primary).expect("parse V2 cache");
    assert_eq!(
        cache.header.generation,
        DyldCacheHeaderGeneration::SubcacheV2
    );
    assert_eq!(cache.subcaches()[0].file_suffix, ".01");

    // Apple's width transition is tied to the symbolFileUUID field boundary,
    // before cacheSubType introduced suffix-bearing subcache records. Exercise
    // the exact offsetof boundary, where the UUID itself is not yet readable.
    let mut intermediate = vec![0_u8; 0x380];
    cache_magic(&mut intermediate, "arm64e");
    put_u32(&mut intermediate, 16, 0x190);
    put_u64(&mut intermediate, 0x48, 0x300);
    put_u64(&mut intermediate, 0x50, 0x40);
    put_u32(&mut intermediate, 0x300, 24);
    put_u32(&mut intermediate, 0x304, 1);
    put_u32(&mut intermediate, 0x308, 40);
    put_u32(&mut intermediate, 0x30c, 8);
    put_u32(&mut intermediate, 0x310, 48);
    put_u32(&mut intermediate, 0x314, 1);
    put_name(&mut intermediate, 0x328, "\0local\0");
    put_u64(&mut intermediate, 0x330, 0x1_0000_1400);
    put_u32(&mut intermediate, 0x338, 0);
    put_u32(&mut intermediate, 0x33c, 1);
    let cache = parse_dyld_cache(&intermediate).expect("parse intermediate header layout");
    assert_eq!(
        cache.header.generation,
        DyldCacheHeaderGeneration::SubcacheV1
    );
    assert_eq!(
        cache.local_symbols.as_ref().unwrap().entries[0].dylib_offset,
        0x1_0000_1400
    );
}

#[test]
fn current_image_array_wins_over_obsolete_nonzero_fields() {
    let (mut primary, _, _) = make_family();
    put_u32(&mut primary, 24, 0x340);
    put_u32(&mut primary, 28, 1);
    put_u64(&mut primary, 0x340, FAMILY_BASE + 0x88);
    put_u32(&mut primary, 0x358, 0x360);
    put_name(&mut primary, 0x360, "/obsolete/image");

    let cache = parse_dyld_cache(&primary).expect("parse cache with obsolete image fields");
    assert_eq!(cache.images().len(), 1);
    assert_eq!(cache.images()[0].address, IMAGE_VA);
    assert_eq!(cache.images()[0].path, "/usr/lib/libFixture.dylib");
}

#[test]
fn future_magic_and_headers_outside_apples_envelope_are_typed_unsupported() {
    let mut future_magic = make_minimal_cache("arm64e");
    future_magic[..7].copy_from_slice(b"dyld_v2");
    let error = parse_dyld_cache(&future_magic).expect_err("future magic");
    assert_eq!(error.kind, DyldCacheErrorKind::Unsupported);

    let mut future_header = make_minimal_cache("arm64e");
    put_u32(&mut future_header, 16, 0x408);
    let error = parse_dyld_cache(&future_header).expect_err("future header envelope");
    assert_eq!(error.kind, DyldCacheErrorKind::Unsupported);
}

#[test]
fn separate_symbols_member_is_required_and_uuid_validated() {
    let (mut primary, first, second) = make_family();
    let symbols_uuid = [0x77; 16];
    primary[0x190..0x1a0].copy_from_slice(&symbols_uuid);
    let symbols = make_symbols_member(symbols_uuid);
    let family = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: &first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: &second,
            },
            CacheMemberInput {
                name: ".symbols",
                data: &symbols,
            },
        ],
    )
    .expect("complete family with symbols");
    let symbol_member = family.members().last().expect("symbols member");
    assert_eq!(symbol_member.kind(), CacheFamilyMemberKind::Symbols);
    assert_eq!(
        symbol_member
            .cache()
            .local_symbols
            .as_ref()
            .expect("validated store")
            .entries[0]
            .dylib_offset,
        0x1400
    );
    let image = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("reconstruction with validated external locals");
    assert_eq!(
        image.completeness.local_symbols.state,
        CompletenessState::Unresolved
    );
    assert!(
        image
            .completeness
            .local_symbols
            .detail
            .contains("validated cache-level")
    );

    let missing = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: &first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: &second,
            },
        ],
    )
    .expect_err("missing symbols member");
    assert!(missing.to_string().contains(".symbols"));

    let mut wrong_symbols = symbols;
    wrong_symbols[0x58] ^= 0xff;
    let wrong = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: &first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: &second,
            },
            CacheMemberInput {
                name: ".symbols",
                data: &wrong_symbols,
            },
        ],
    )
    .expect_err("wrong symbols UUID");
    assert!(wrong.to_string().contains("UUID mismatch"));
}

#[test]
fn malformed_local_symbol_ranges_are_rejected() {
    let mut symbols = make_symbols_member([0x77; 16]);
    put_u32(&mut symbols, 0x33c, 2);
    let error = parse_dyld_cache(&symbols).expect_err("entry exceeds nlist array");
    assert!(error.to_string().contains("nlist range"));
}

#[test]
fn future_local_symbol_arch_and_zero_subcache_uuid_fail_closed() {
    let mut unknown_arch = make_symbols_member([0x77; 16]);
    cache_magic(&mut unknown_arch, "riscv64");
    let error = parse_dyld_cache(&unknown_arch).expect_err("unknown local-symbol ABI");
    assert_eq!(error.kind, DyldCacheErrorKind::Unsupported);

    let mut zero_uuid = make_v1_cache_with_local_symbols();
    zero_uuid[0x200..0x210].fill(0);
    let error = parse_dyld_cache(&zero_uuid).expect_err("zero subcache UUID");
    assert!(error.to_string().contains("zero UUID"));
}

#[test]
fn va_to_file_offset_works() {
    let data = make_minimal_cache("x86_64");
    let cache = parse_dyld_cache(&data).expect("failed to parse");
    let fo = cache.va_to_file_offset(0x1_0000_0000);
    assert_eq!(fo, Some(4096));
    assert_eq!(cache.va_to_file_offset(0x1_0000_0100), Some(4096 + 0x100));
    assert_eq!(cache.va_to_file_offset(0xDEAD), None);
}

#[test]
fn bad_magic_rejected() {
    let data = b"not a dyld cache file at all!!";
    assert!(parse_dyld_cache(data).is_err());
}

#[test]
fn too_small_rejected() {
    let data = b"dyld_v1";
    assert!(parse_dyld_cache(data).is_err());
}

#[test]
fn truncated_mapping_is_rejected_before_allocation() {
    let data = macho_test_support::dyld_cache_truncated_mapping();
    let error = parse_dyld_cache(&data).expect_err("mapping table is truncated");
    assert_eq!(error.kind, DyldCacheErrorKind::OutOfBounds);
    assert_eq!(error.code(), "dyld_cache.bounds.exceeded");
    assert!(error.location.is_some());
}

#[test]
fn split_family_reconstructs_compact_parseable_image() {
    let (primary, first, second) = make_family();
    let family = parse_family(&primary, &first, &second);
    assert_eq!(family.members().len(), 3);
    let result = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("reconstruct split image");
    assert!(
        result.byte_len < 0x10000,
        "output is compact: {}",
        result.byte_len
    );
    assert_eq!(
        result.completeness.segments.state,
        CompletenessState::Complete
    );
    assert_eq!(
        result.completeness.symbols.state,
        CompletenessState::Complete
    );
    assert_eq!(
        result.completeness.exports.state,
        CompletenessState::Complete
    );
    assert!(
        result
            .mappings
            .iter()
            .any(|mapping| mapping.source_members == [".01", ".02.dyldlinkedit"]),
        "one reconstructed segment crosses family members"
    );
    let container = crate::core::format::parse(result.bytes()).expect("strict core reparse");
    let macho = container.first_macho().expect("thin image");
    let symbols = crate::core::format::parse_symbol_table(macho).expect("rebuilt symbols");
    assert!(symbols.find_by_name("_symbol").is_some());
    let exports = crate::metadata::dyld::parse_exports(macho).expect("retained exports");
    assert!(exports.iter().any(|export| export.name == "_main"));
}

#[test]
fn reconstruction_is_deterministic_and_does_not_copy_shared_string_pool() {
    let (primary, first, second) = make_family();
    let family = parse_family(&primary, &first, &second);
    let first_result = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("first reconstruction");
    let second_result = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("second reconstruction");
    assert_eq!(first_result, second_result);
    assert!(first_result.byte_len < 0x10000);
}

#[test]
fn family_refuses_missing_and_wrong_uuid_siblings() {
    let (primary, first, mut second) = make_family();
    let missing = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [CacheMemberInput {
            name: ".01",
            data: &first,
        }],
    )
    .expect_err("missing sibling");
    assert!(missing.to_string().contains("missing required"));

    second[0x58] ^= 0xff;
    let wrong = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: &first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: &second,
            },
        ],
    )
    .expect_err("wrong UUID");
    assert!(wrong.to_string().contains("UUID mismatch"));
}

#[test]
fn family_refuses_wrong_arch_and_overlapping_mappings() {
    let (primary, first, second) = make_family();
    let mut wrong_arch = second.clone();
    cache_magic(&mut wrong_arch, "x86_64");
    let error = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: &first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: &wrong_arch,
            },
        ],
    )
    .expect_err("wrong architecture");
    assert_eq!(error.kind, DyldCacheErrorKind::Unsupported);

    let mut malformed = second;
    put_u32(&mut malformed, 20, 2);
    put_u64(&mut malformed, 0x280, FAMILY_BASE + 0x5000);
    put_u64(&mut malformed, 0x288, 0x1000);
    put_u64(&mut malformed, 0x290, 0x400);
    let error = parse_dyld_cache(&malformed).expect_err("overlapping member mappings");
    assert!(error.to_string().contains("overlaps"));
}

#[test]
fn reconstruction_refuses_unmapped_segment_tail_without_clamping() {
    let (primary, mut first, second) = make_family();
    // Grow __TEXT one byte past the end of the contiguous .01/.02 coverage.
    let text = 0x800 + 32;
    put_u64(&mut first, text + 32, 0x5c01);
    put_u64(&mut first, text + 48, 0x5c01);
    let family = parse_family(&primary, &first, &second);
    let error = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect_err("unmapped segment tail");
    assert_eq!(error.kind, DyldCacheErrorKind::InvalidAddress);
}

#[test]
fn family_refuses_duplicate_exact_image_paths() {
    let (mut primary, first, second) = make_family();
    put_u32(&mut primary, 0x1c4, 2);
    put_u32(&mut primary, 0x318, 0x360);
    put_u64(&mut primary, 0x320, IMAGE_VA);
    put_u32(&mut primary, 0x338, 0x360);
    put_name(&mut primary, 0x360, "/usr/lib/libFixture.dylib");
    let error = DyldCacheFamily::parse(
        CacheMemberInput {
            name: "primary",
            data: &primary,
        },
        [
            CacheMemberInput {
                name: ".01",
                data: &first,
            },
            CacheMemberInput {
                name: ".02.dyldlinkedit",
                data: &second,
            },
        ],
    )
    .expect_err("duplicate image path");
    assert!(error.to_string().contains("duplicate image path"));
}

#[test]
fn image_paths_require_bounded_nul_terminated_utf8() {
    let mut invalid_utf8 = make_minimal_cache("arm64e");
    invalid_utf8[96] = 0xff;
    let error = parse_dyld_cache(&invalid_utf8).expect_err("invalid UTF-8 path");
    assert!(error.to_string().contains("not UTF-8"));

    let mut out_of_bounds = make_minimal_cache("arm64e");
    put_u32(&mut out_of_bounds, 32 + 32 + 24, u32::MAX);
    let error = parse_dyld_cache(&out_of_bounds).expect_err("out-of-bounds path");
    assert_eq!(error.kind, DyldCacheErrorKind::OutOfBounds);

    let mut unterminated = make_minimal_cache("arm64e");
    for byte in &mut unterminated[96..] {
        *byte = b'a';
    }
    unterminated[96] = b'/';
    let error = parse_dyld_cache(&unterminated).expect_err("unterminated path");
    assert!(error.to_string().contains("not NUL-terminated"));
}

#[test]
fn malformed_domain_metadata_never_receives_complete_ledger_state() {
    let (primary, first, mut second) = make_family();
    second[0x1700] = 0xff;
    let family = parse_family(&primary, &first, &second);
    let result = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("core-parseable image with malformed export trie");
    assert_eq!(
        result.completeness.exports.state,
        CompletenessState::Unresolved
    );
    assert!(result.completeness.exports.detail.contains("did not parse"));

    let (primary, mut first, second) = make_family();
    let command = 0x800 + 32 + 72 + 72 + 24;
    put_u32(&mut first, command, 0x8000_0034);
    put_u32(&mut first, command + 8, 0x1700);
    put_u32(&mut first, command + 12, 4);
    let family = parse_family(&primary, &first, &second);
    let result = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("core-parseable image with malformed chained fixups");
    assert_eq!(
        result.completeness.imports.state,
        CompletenessState::Unresolved
    );
    assert_eq!(
        result.completeness.fixups.state,
        CompletenessState::Unresolved
    );
}

#[test]
fn malformed_symbol_reference_prevents_delivery() {
    let (primary, first, mut second) = make_family();
    put_u32(&mut second, 0x1500, 0x800);
    let family = parse_family(&primary, &first, &second);
    let error = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect_err("n_strx at string-table end");
    assert!(error.to_string().contains("string index"));
}

#[test]
fn reconstruction_fails_closed_on_unknown_load_commands() {
    let (primary, mut first, second) = make_family();
    let command = 0x800 + 32 + 72 + 72 + 24;
    put_u32(&mut first, command, 0x7fff_1234);
    let family = parse_family(&primary, &first, &second);
    let error = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect_err("unknown command may carry file coordinates");
    assert_eq!(error.kind, DyldCacheErrorKind::Unsupported);
    assert!(error.to_string().contains("unhandled Mach-O load command"));
}

#[test]
fn main_entry_file_coordinate_is_rewritten_to_same_va() {
    let (primary, mut first, second) = make_family();
    let text = 0x800 + 32;
    put_u64(&mut first, text + 40, 0x800);
    put_u32(&mut first, 0x800 + 12, 2);
    let command = 0x800 + 32 + 72 + 72;
    put_u32(&mut first, command, 0x8000_0028);
    put_u64(&mut first, command + 8, 0x900);
    put_u64(&mut first, command + 16, 0);
    let family = parse_family(&primary, &first, &second);
    let result = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect("executable reconstruction");
    let container = crate::core::format::parse(result.bytes()).expect("parse executable");
    let macho = container.first_macho().expect("thin executable");
    let main = macho
        .load_commands()
        .iter()
        .find_map(|command| command.kind().as_main())
        .expect("LC_MAIN");
    assert_eq!(main.entry_offset, 0x100);
    let va = macho
        .address_map()
        .thin_offset_to_va(crate::core::model::addr::ThinFileOffset(main.entry_offset))
        .expect("entry VA");
    assert_eq!(va.0, IMAGE_VA + 0x100);
}

#[test]
fn reconstruction_reports_checked_address_overflow() {
    let (primary, mut first, second) = make_family();
    let linkedit = 0x800 + 32 + 72;
    put_u64(&mut first, linkedit + 24, u64::MAX - 0x10);
    let family = parse_family(&primary, &first, &second);
    let error = family
        .reconstruct_image(0, MaterializationLimits::default())
        .expect_err("symbol VA overflow");
    assert_eq!(error.kind, DyldCacheErrorKind::InvalidAddress);
    assert!(error.to_string().contains("overflows"));
}
