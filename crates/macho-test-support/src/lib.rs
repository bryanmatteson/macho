//! Deterministic byte-level fixtures shared by tests, fuzz seeds, and benchmarks.

use base64::Engine as _;

mod disassembly_objc;
mod disassembly_scale;
mod signing_gap;

pub use disassembly_objc::{
    disassembly_objc_boundary, disassembly_objc_category_labels, disassembly_objc_duplicate_class,
};
pub use disassembly_scale::{disassembly_x86_64_dense, disassembly_x86_64_sections};
pub use signing_gap::signable_thin64_x86_64_with_data_gap;

/// CPU type used by [`thin64_arm64`].
pub const CPU_TYPE_ARM64: u32 = 0x0100_000c;
/// CPU type used by [`thin64_x86_64`].
pub const CPU_TYPE_X86_64: u32 = 0x0100_0007;
/// ARM64E CPU subtype used by [`disassembly_arm64e`].
pub const CPU_SUBTYPE_ARM64E: u32 = 2;
/// Haswell x86-64 subtype used by [`disassembly_fat_x86_subtypes`].
pub const CPU_SUBTYPE_X86_64_H: u32 = 8;
/// Synthetic unrecognized 64-bit CPU type used by unsupported-architecture tests.
pub const CPU_TYPE_UNKNOWN_64: u32 = 0x0100_7fff;

/// Build a minimal, structurally valid, little-endian 64-bit ARM64 Mach-O image.
pub fn thin64_arm64(file_type: u32) -> Vec<u8> {
    thin64(CPU_TYPE_ARM64, file_type)
}

/// Build a minimal, structurally valid, little-endian 64-bit x86-64 image.
pub fn thin64_x86_64(file_type: u32) -> Vec<u8> {
    thin64(CPU_TYPE_X86_64, file_type)
}

/// Build a structurally valid 64-bit image with an unrecognized CPU type.
pub fn thin64_unknown_cpu(file_type: u32) -> Vec<u8> {
    thin64(CPU_TYPE_UNKNOWN_64, file_type)
}

/// Build a thin ARM64 image with `__TEXT` and final `__LINKEDIT` segments and
/// enough load-command slack for an in-process signer to add
/// `LC_CODE_SIGNATURE`.
pub fn signable_thin64_arm64(file_type: u32) -> Vec<u8> {
    signable_thin64(CPU_TYPE_ARM64, file_type)
}

/// Build a thin x86-64 image with `__TEXT` and final `__LINKEDIT` segments and
/// enough load-command slack for an in-process signer to add
/// `LC_CODE_SIGNATURE`.
pub fn signable_thin64_x86_64(file_type: u32) -> Vec<u8> {
    signable_thin64(CPU_TYPE_X86_64, file_type)
}

/// Password for the repository-owned test-only PKCS#12 identity.
pub const TEST_SIGNING_IDENTITY_PASSWORD: &str = "macho-test";

/// Decode the repository-owned self-signed test-only PKCS#12 identity.
///
/// The identity has no trust value and must never be used outside tests.
pub fn test_signing_identity_pkcs12() -> Vec<u8> {
    let encoded = include_str!("../fixtures/test-signing-identity.p12.b64")
        .split_ascii_whitespace()
        .collect::<String>();
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .expect("checked-in PKCS#12 fixture must remain valid base64")
}

/// One nlist symbol used by [`thin64_x86_64_with_symbols`].
#[derive(Debug, Clone, Copy)]
pub struct SymbolFixture<'a> {
    /// Mach-O symbol spelling, including the platform-leading underscore.
    pub name: &'a str,
    /// Whether the nlist entry carries `N_EXT`.
    pub external: bool,
    /// Whether the symbol is defined in the synthetic `__text` section.
    pub defined: bool,
}

/// Build a deterministic x86-64 image with one executable section and nlist symbols.
pub fn thin64_x86_64_with_symbols(symbols: &[SymbolFixture<'_>]) -> Vec<u8> {
    thin64_x86_64_with_symbol_section(symbols, "__TEXT", "__text", 0x8000_0400)
}

/// Build a deterministic x86-64 image with one regular data section and nlist symbols.
pub fn thin64_x86_64_with_data_symbols(symbols: &[SymbolFixture<'_>]) -> Vec<u8> {
    thin64_x86_64_with_symbol_section(symbols, "__DATA", "__data", 0)
}

/// Build a deterministic x86-64 image with one TLS data section and nlist symbols.
pub fn thin64_x86_64_with_tls_symbols(symbols: &[SymbolFixture<'_>]) -> Vec<u8> {
    thin64_x86_64_with_symbol_section(symbols, "__DATA", "__thread_data", 0x11)
}

/// Build a deterministic x86-64 disassembly image with two exact code symbols,
/// direct control flow, ordinary instructions, and one trailing invalid byte.
pub fn disassembly_x86_64() -> Vec<u8> {
    let mut bytes = thin64_x86_64_with_symbols(&[
        SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "_helper",
            external: false,
            defined: true,
        },
    ]);
    let text = &mut bytes[0x100..0x140];
    for chunk in text.chunks_exact_mut(4) {
        chunk.copy_from_slice(&[0x90, 0x90, 0x90, 0xc3]);
    }
    text[..8].copy_from_slice(&[0xeb, 0x02, 0x90, 0xc3, 0x90, 0x90, 0x90, 0xc3]);
    text[0x3f] = 0x0f;
    bytes
}

/// Build a deterministic arm64 disassembly image with two exact code symbols.
pub fn disassembly_arm64() -> Vec<u8> {
    disassembly_arm64_with_subtype(0)
}

/// Build a deterministic arm64e disassembly image with two exact code symbols.
pub fn disassembly_arm64e() -> Vec<u8> {
    disassembly_arm64_with_subtype(CPU_SUBTYPE_ARM64E)
}

/// Build the canonical x86-64 plus arm64e universal disassembly fixture.
pub fn disassembly_fat() -> Vec<u8> {
    fat32(&[
        (CPU_TYPE_X86_64, 3, disassembly_x86_64()),
        (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E, disassembly_arm64e()),
    ])
}

/// Build ordinary x86-64 and qualified x86_64h sibling slices.
pub fn disassembly_fat_x86_subtypes() -> Vec<u8> {
    let ordinary = disassembly_x86_64();
    let mut haswell = disassembly_x86_64();
    haswell[8..12].copy_from_slice(&CPU_SUBTYPE_X86_64_H.to_le_bytes());
    fat32(&[
        (CPU_TYPE_X86_64, 3, ordinary),
        (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H, haswell),
    ])
}

/// Build an x86-64 image with `count` unique nlist aliases at the same code VA.
pub fn disassembly_x86_64_aliases(count: usize) -> Vec<u8> {
    let names = (0..count)
        .map(|index| format!("_alias{index:04}"))
        .collect::<Vec<_>>();
    let fixtures = names
        .iter()
        .map(|name| SymbolFixture {
            name,
            external: true,
            defined: true,
        })
        .collect::<Vec<_>>();
    let mut bytes = thin64_x86_64_with_symbols(&fixtures);
    for index in 0..count {
        let value_offset = 0x140 + index * 16 + 8;
        bytes[value_offset..value_offset + 8].copy_from_slice(&0x1_0000_0100u64.to_le_bytes());
    }
    bytes
}

/// Build an instruction-bearing image whose Objective-C pointer-list section
/// contains non-pointer instruction bytes, for fail-closed metadata tests.
pub fn disassembly_malformed_objc() -> Vec<u8> {
    let mut bytes = disassembly_x86_64();
    bytes[104..120].copy_from_slice(b"__objc_classlist");
    bytes
}

/// Build an x86-64 disassembly image with one regular export-trie symbol at
/// the start of `__TEXT,__text`.
pub fn disassembly_export_symbol() -> Vec<u8> {
    disassembly_with_export("_exported", 0x100)
}

/// Build an x86-64 disassembly image with a zero-offset regular export.
pub fn disassembly_zero_export() -> Vec<u8> {
    disassembly_with_export("_zero", 0)
}

fn disassembly_with_export(name: &str, image_offset: u64) -> Vec<u8> {
    let mut bytes = disassembly_x86_64();
    let trie = single_export_trie(name, image_offset);
    let command_offset = 32 + (72 + 80) + 24;
    let trie_offset = bytes.len();
    bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
    bytes[command_offset..command_offset + 4].copy_from_slice(&0x8000_0033u32.to_le_bytes());
    bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16u32.to_le_bytes());
    bytes[command_offset + 8..command_offset + 12]
        .copy_from_slice(&(trie_offset as u32).to_le_bytes());
    bytes[command_offset + 12..command_offset + 16]
        .copy_from_slice(&(trie.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&trie);
    let file_size = bytes.len() as u64;
    bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    bytes
}

fn single_export_trie(name: &str, image_offset: u64) -> Vec<u8> {
    assert!(!name.is_empty() && !name.as_bytes().contains(&0));
    let child_offset = 2usize
        .checked_add(name.len())
        .and_then(|value| value.checked_add(2))
        .expect("small fixture export name");
    assert!(
        child_offset < 0x80,
        "fixture child offset must fit one ULEB byte"
    );

    let mut terminal = vec![0]; // regular-export flags
    push_uleb(&mut terminal, image_offset);
    assert!(
        terminal.len() < 0x80,
        "fixture terminal must fit one ULEB byte"
    );

    let mut trie = vec![0, 1];
    trie.extend_from_slice(name.as_bytes());
    trie.push(0);
    trie.push(child_offset as u8);
    trie.push(terminal.len() as u8);
    trie.extend_from_slice(&terminal);
    trie.push(0);
    trie
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

/// Build a disassembly image with a bounded but malformed export trie.
pub fn disassembly_malformed_export() -> Vec<u8> {
    let mut bytes = disassembly_x86_64();
    let command_offset = 32 + (72 + 80) + 24;
    let trie_offset = bytes.len();
    bytes[16..20].copy_from_slice(&3u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&((72 + 80 + 24 + 16) as u32).to_le_bytes());
    bytes[command_offset..command_offset + 4].copy_from_slice(&0x8000_0033u32.to_le_bytes());
    bytes[command_offset + 4..command_offset + 8].copy_from_slice(&16u32.to_le_bytes());
    bytes[command_offset + 8..command_offset + 12]
        .copy_from_slice(&(trie_offset as u32).to_le_bytes());
    bytes[command_offset + 12..command_offset + 16].copy_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&[0, 1]);
    let file_size = bytes.len() as u64;
    bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    bytes
}

/// Build a disassembly image whose nlist string table is out of bounds.
pub fn disassembly_malformed_nlist() -> Vec<u8> {
    let mut bytes = disassembly_x86_64();
    let symtab_command_offset = 32 + (72 + 80);
    bytes[symtab_command_offset + 16..symtab_command_offset + 20]
        .copy_from_slice(&u32::MAX.to_le_bytes());
    bytes
}

fn disassembly_arm64_with_subtype(subtype: u32) -> Vec<u8> {
    let mut bytes = thin64_x86_64_with_symbols(&[
        SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        },
        SymbolFixture {
            name: "_helper",
            external: false,
            defined: true,
        },
    ]);
    bytes[4..8].copy_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    bytes[8..12].copy_from_slice(&subtype.to_le_bytes());
    let text = &mut bytes[0x100..0x140];
    for chunk in text.chunks_exact_mut(8) {
        chunk[..4].copy_from_slice(&0xd503_201fu32.to_le_bytes());
        chunk[4..].copy_from_slice(&0xd65f_03c0u32.to_le_bytes());
    }
    text[..4].copy_from_slice(&0x1400_0001u32.to_le_bytes());
    bytes
}

fn thin64_x86_64_with_symbol_section(
    symbols: &[SymbolFixture<'_>],
    segment_name: &str,
    section_name: &str,
    section_flags: u32,
) -> Vec<u8> {
    const HEADER_SIZE: usize = 32;
    const SEGMENT_COMMAND_SIZE: usize = 72 + 80;
    const SYMTAB_COMMAND_SIZE: usize = 24;
    const TEXT_OFFSET: usize = 0x100;
    const TEXT_SIZE: usize = 0x40;

    let symbol_offset = TEXT_OFFSET + TEXT_SIZE;
    let string_offset = symbol_offset + symbols.len() * 16;
    let mut strings = vec![0u8];
    let string_indices = symbols
        .iter()
        .map(|symbol| {
            let index = strings.len() as u32;
            strings.extend_from_slice(symbol.name.as_bytes());
            strings.push(0);
            index
        })
        .collect::<Vec<_>>();
    let file_size = string_offset + strings.len();

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
    push_fixed_name(&mut bytes, segment_name);
    bytes.extend_from_slice(&0x1_0000_0000u64.to_le_bytes());
    bytes.extend_from_slice(&0x1000u64.to_le_bytes());
    bytes.extend_from_slice(&0u64.to_le_bytes());
    bytes.extend_from_slice(&(file_size as u64).to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    push_fixed_name(&mut bytes, section_name);
    push_fixed_name(&mut bytes, segment_name);
    bytes.extend_from_slice(&0x1_0000_0100u64.to_le_bytes());
    bytes.extend_from_slice(&(TEXT_SIZE as u64).to_le_bytes());
    bytes.extend_from_slice(&(TEXT_OFFSET as u32).to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&section_flags.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());

    bytes.extend_from_slice(&0x02u32.to_le_bytes());
    bytes.extend_from_slice(&(SYMTAB_COMMAND_SIZE as u32).to_le_bytes());
    bytes.extend_from_slice(&(symbol_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&(symbols.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(string_offset as u32).to_le_bytes());
    bytes.extend_from_slice(&(strings.len() as u32).to_le_bytes());
    bytes.resize(TEXT_OFFSET, 0);
    for index in 0..(TEXT_SIZE / 4) {
        bytes.extend_from_slice(if index % 2 == 0 {
            &[0x90, 0x90, 0x90, 0xc3]
        } else {
            &[0x90, 0x90, 0x90, 0x90]
        });
    }
    for (index, symbol) in symbols.iter().enumerate() {
        bytes.extend_from_slice(&string_indices[index].to_le_bytes());
        bytes.push(if symbol.defined {
            0x0e | u8::from(symbol.external)
        } else {
            u8::from(symbol.external)
        });
        bytes.push(u8::from(symbol.defined));
        bytes.extend_from_slice(&0u16.to_le_bytes());
        let value = if symbol.defined {
            0x1_0000_0100u64 + (index as u64 * 4)
        } else {
            0
        };
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.extend_from_slice(&strings);
    bytes
}

/// Build a safe image whose segment protections produce a validation warning.
pub fn warning_bearing_image() -> Vec<u8> {
    let mut bytes = thin64_x86_64_with_symbols(&[]);
    bytes[88..92].copy_from_slice(&1u32.to_le_bytes());
    bytes[92..96].copy_from_slice(&5u32.to_le_bytes());
    bytes
}

/// Build a representable image whose file-backed segment fails validation.
pub fn validation_error_image() -> Vec<u8> {
    let mut bytes = thin64_x86_64_with_symbols(&[]);
    let invalid_size = bytes.len() as u64 + 1;
    bytes[80..88].copy_from_slice(&invalid_size.to_le_bytes());
    bytes
}

/// Build a thin image truncated in the header of its first load command.
pub fn truncated_load_command_image() -> Vec<u8> {
    let mut bytes = thin64_x86_64(2);
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&0x19u32.to_le_bytes());
    bytes
}

/// Build a valid thin image containing one preserved unknown load command.
pub fn unknown_load_command_image() -> Vec<u8> {
    let mut bytes = thin64_x86_64(2);
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&8u32.to_le_bytes());
    bytes.extend_from_slice(&0x1234_5678u32.to_le_bytes());
    bytes.extend_from_slice(&8u32.to_le_bytes());
    bytes
}

/// Build a thin image whose sole load command has an impossible four-byte size.
pub fn invalid_cmdsize_image() -> Vec<u8> {
    let mut bytes = thin64_x86_64(2);
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&4u32.to_le_bytes());
    bytes.extend_from_slice(&0x19u32.to_le_bytes());
    bytes.extend_from_slice(&4u32.to_le_bytes());
    bytes
}

/// Build a thin image with an empty, structurally valid `LC_DYLD_INFO_ONLY` command.
pub fn empty_dyld_info_image() -> Vec<u8> {
    dyld_info_image(0, 0)
}

/// Build a thin image whose dyld rebase stream points outside the input.
pub fn out_of_bounds_dyld_info_image() -> Vec<u8> {
    dyld_info_image(u32::MAX, 1)
}

fn dyld_info_image(rebase_offset: u32, rebase_size: u32) -> Vec<u8> {
    let mut bytes = thin64_x86_64(2);
    bytes[16..20].copy_from_slice(&1u32.to_le_bytes());
    bytes[20..24].copy_from_slice(&48u32.to_le_bytes());
    bytes.extend_from_slice(&0x8000_0022u32.to_le_bytes());
    bytes.extend_from_slice(&48u32.to_le_bytes());
    bytes.extend_from_slice(&rebase_offset.to_le_bytes());
    bytes.extend_from_slice(&rebase_size.to_le_bytes());
    bytes.extend_from_slice(&[0u8; 32]);
    bytes
}

/// Build the smallest valid embedded-signature SuperBlob (zero child blobs).
pub fn empty_super_blob() -> Vec<u8> {
    [
        0xfade_0cc0u32.to_be_bytes(),
        12u32.to_be_bytes(),
        0u32.to_be_bytes(),
    ]
    .concat()
}

/// Build a SuperBlob whose declared child index is truncated.
pub fn truncated_super_blob() -> Vec<u8> {
    [
        0xfade_0cc0u32.to_be_bytes(),
        12u32.to_be_bytes(),
        2u32.to_be_bytes(),
    ]
    .concat()
}

fn thin64(cpu_type: u32, file_type: u32) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32);
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&cpu_type.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&file_type.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes
}

fn signable_thin64(cpu_type: u32, file_type: u32) -> Vec<u8> {
    const HEADER_SIZE: usize = 32;
    const TEXT_SEGMENT_COMMAND_SIZE: usize = 72 + 80;
    const LINKEDIT_SEGMENT_COMMAND_SIZE: usize = 72;
    const TEXT_SIZE: usize = 0x1000;
    const LINKEDIT_SIZE: usize = 0x10;

    let mut bytes = Vec::with_capacity(TEXT_SIZE + LINKEDIT_SIZE);
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&cpu_type.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&file_type.to_le_bytes());
    bytes.extend_from_slice(&2u32.to_le_bytes());
    bytes.extend_from_slice(
        &((TEXT_SEGMENT_COMMAND_SIZE + LINKEDIT_SEGMENT_COMMAND_SIZE) as u32).to_le_bytes(),
    );
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    debug_assert_eq!(bytes.len(), HEADER_SIZE);

    push_segment64(
        &mut bytes,
        "__TEXT",
        0x1_0000_0000,
        TEXT_SIZE as u64,
        0,
        TEXT_SIZE as u64,
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
        "__LINKEDIT",
        0x1_0000_1000,
        0x1000,
        TEXT_SIZE as u64,
        LINKEDIT_SIZE as u64,
        1,
        1,
        0,
    );
    bytes.resize(TEXT_SIZE + LINKEDIT_SIZE, 0);
    if cpu_type == CPU_TYPE_X86_64 {
        // A complete, realistic x86_64 prologue: push rbp; mov rbp, rsp;
        // sub rsp, 0x20. Keeping whole instructions here lets executable
        // mutation tests prove their overwrite-window boundary contract.
        bytes[0x400..0x408].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20]);
    } else {
        bytes[0x400..0x404].copy_from_slice(&[0x1f, 0x20, 0x03, 0xd5]);
    }
    bytes
}

#[allow(clippy::too_many_arguments)]
fn push_segment64(
    bytes: &mut Vec<u8>,
    name: &str,
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    maxprot: u32,
    initprot: u32,
    section_count: u32,
) {
    bytes.extend_from_slice(&0x19u32.to_le_bytes());
    bytes.extend_from_slice(&(72 + section_count * 80).to_le_bytes());
    push_fixed_name(bytes, name);
    bytes.extend_from_slice(&vmaddr.to_le_bytes());
    bytes.extend_from_slice(&vmsize.to_le_bytes());
    bytes.extend_from_slice(&fileoff.to_le_bytes());
    bytes.extend_from_slice(&filesize.to_le_bytes());
    bytes.extend_from_slice(&maxprot.to_le_bytes());
    bytes.extend_from_slice(&initprot.to_le_bytes());
    bytes.extend_from_slice(&section_count.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
}

fn push_fixed_name(bytes: &mut Vec<u8>, name: &str) {
    let mut fixed = [0u8; 16];
    fixed[..name.len()].copy_from_slice(name.as_bytes());
    bytes.extend_from_slice(&fixed);
}

/// Build a zero-architecture fat header, which must be rejected.
pub fn zero_arch_fat() -> Vec<u8> {
    [0xcafe_babeu32.to_be_bytes(), 0u32.to_be_bytes()].concat()
}

/// Build a valid ARM64 fileset with two embedded members.
pub fn fileset64_arm64() -> Vec<u8> {
    let members = [
        ("com.example.first", 0x1_0000_0000u64, thin64_arm64(2)),
        ("com.example.second", 0x1_0001_0000u64, thin64_arm64(6)),
    ];
    let commands = members
        .iter()
        .map(|(id, _, _)| align_up(32 + id.len() + 1, 8))
        .collect::<Vec<_>>();
    let commands_size = commands.iter().sum::<usize>();
    let first_offset = align_up(32 + commands_size, 0x100);
    let second_offset = align_up(first_offset + members[0].2.len(), 0x100);
    let offsets = [first_offset, second_offset];
    let mut bytes = Vec::with_capacity(second_offset + members[1].2.len());
    bytes.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    bytes.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0xcu32.to_le_bytes());
    bytes.extend_from_slice(&(members.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&(commands_size as u32).to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes());
    for (index, ((id, vm_addr, _), cmdsize)) in members.iter().zip(commands).enumerate() {
        bytes.extend_from_slice(&0x8000_0035u32.to_le_bytes());
        bytes.extend_from_slice(&(cmdsize as u32).to_le_bytes());
        bytes.extend_from_slice(&vm_addr.to_le_bytes());
        bytes.extend_from_slice(&(offsets[index] as u64).to_le_bytes());
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(id.as_bytes());
        bytes.push(0);
        bytes.resize(bytes.len().next_multiple_of(8), 0);
    }
    bytes.resize(first_offset, 0);
    bytes.extend_from_slice(&members[0].2);
    bytes.resize(second_offset, 0);
    bytes.extend_from_slice(&members[1].2);
    bytes
}

/// Build a fileset whose second member offset is outside the input.
pub fn fileset64_out_of_bounds() -> Vec<u8> {
    let mut bytes = fileset64_arm64();
    let first_id_len = "com.example.first".len();
    let second_command = 32 + align_up(32 + first_id_len + 1, 8);
    bytes[second_command + 16..second_command + 24].copy_from_slice(&u64::MAX.to_le_bytes());
    bytes
}

/// Build a fileset truncated inside its second load command.
pub fn fileset64_truncated_command() -> Vec<u8> {
    let mut bytes = fileset64_arm64();
    bytes.truncate(32 + align_up(32 + "com.example.first".len() + 1, 8) + 20);
    bytes
}

/// Build a big-endian 32-bit fat container from complete Mach-O slices.
///
/// Slices are placed on 4 KiB boundaries and their table entries use an
/// alignment exponent of 12.
pub fn fat32(slices: &[(u32, u32, Vec<u8>)]) -> Vec<u8> {
    const TABLE_START: usize = 8;
    const ENTRY_SIZE: usize = 20;
    const ALIGN: usize = 4096;

    let table_end = TABLE_START + ENTRY_SIZE * slices.len();
    let first_slice = align_up(table_end, ALIGN);
    let mut offsets = Vec::with_capacity(slices.len());
    let mut cursor = first_slice;
    for (_, _, bytes) in slices {
        offsets.push(cursor);
        cursor = align_up(cursor + bytes.len(), ALIGN);
    }

    let mut out = vec![0u8; cursor];
    out[0..4].copy_from_slice(&0xcafe_babeu32.to_be_bytes());
    out[4..8].copy_from_slice(&(slices.len() as u32).to_be_bytes());
    for (index, ((cpu_type, cpu_subtype, bytes), offset)) in
        slices.iter().zip(offsets.iter().copied()).enumerate()
    {
        let entry = TABLE_START + index * ENTRY_SIZE;
        out[entry..entry + 4].copy_from_slice(&cpu_type.to_be_bytes());
        out[entry + 4..entry + 8].copy_from_slice(&cpu_subtype.to_be_bytes());
        out[entry + 8..entry + 12].copy_from_slice(&(offset as u32).to_be_bytes());
        out[entry + 12..entry + 16].copy_from_slice(&(bytes.len() as u32).to_be_bytes());
        out[entry + 16..entry + 20].copy_from_slice(&12u32.to_be_bytes());
        out[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
    out
}

/// Build a fat container whose two table entries overlap the same slice bytes.
pub fn overlapping_fat_slices() -> Vec<u8> {
    let arm = thin64_arm64(2);
    let x86 = thin64_x86_64(2);
    let mut bytes = fat32(&[(CPU_TYPE_ARM64, 0, arm), (CPU_TYPE_X86_64, 0, x86)]);
    let first_offset = u32::from_be_bytes(bytes[16..20].try_into().expect("fixed range"));
    bytes[36..40].copy_from_slice(&first_offset.to_be_bytes());
    bytes
}

/// Build a fat container truncated halfway through its declared Mach-O slice.
pub fn truncated_fat_slice() -> Vec<u8> {
    let mut bytes = fat32(&[(CPU_TYPE_ARM64, 0, thin64_arm64(2))]);
    let offset = u32::from_be_bytes(bytes[16..20].try_into().expect("fixed range")) as usize;
    bytes.truncate(offset + 16);
    bytes
}

/// Build a minimal old-format dyld shared cache with one mapping and one image.
pub fn dyld_cache_old() -> Vec<u8> {
    const MAPPING_INFO_SIZE: u32 = 32;
    const IMAGE_INFO_SIZE: u32 = 32;
    let mut magic = [0u8; 16];
    magic[..15].copy_from_slice(b"dyld_v1  arm64e");
    let mapping_offset = 32u32;
    let images_offset = mapping_offset + MAPPING_INFO_SIZE;
    let path_offset = images_offset + IMAGE_INFO_SIZE;
    let image_va = 0x1_0000_0000u64;
    let image_file_offset = 4096u64;
    let path = b"/usr/lib/libSystem.B.dylib\0";
    let mut data = vec![0u8; image_file_offset as usize + 4096];
    data[..16].copy_from_slice(&magic);
    data[16..20].copy_from_slice(&mapping_offset.to_le_bytes());
    data[20..24].copy_from_slice(&1u32.to_le_bytes());
    data[24..28].copy_from_slice(&images_offset.to_le_bytes());
    data[28..32].copy_from_slice(&1u32.to_le_bytes());
    let mapping = mapping_offset as usize;
    data[mapping..mapping + 8].copy_from_slice(&image_va.to_le_bytes());
    data[mapping + 8..mapping + 16].copy_from_slice(&4096u64.to_le_bytes());
    data[mapping + 16..mapping + 24].copy_from_slice(&image_file_offset.to_le_bytes());
    data[mapping + 24..mapping + 28].copy_from_slice(&5u32.to_le_bytes());
    data[mapping + 28..mapping + 32].copy_from_slice(&5u32.to_le_bytes());
    let image = images_offset as usize;
    data[image..image + 8].copy_from_slice(&image_va.to_le_bytes());
    data[image + 24..image + 28].copy_from_slice(&path_offset.to_le_bytes());
    let path_start = path_offset as usize;
    data[path_start..path_start + path.len()].copy_from_slice(path);
    data
}

/// Build a dyld cache whose declared mapping table is truncated.
pub fn dyld_cache_truncated_mapping() -> Vec<u8> {
    let mut data = dyld_cache_old();
    data.truncate(48);
    data
}

/// Build a dyld cache whose image virtual address is outside every mapping.
pub fn dyld_cache_out_of_bounds_image() -> Vec<u8> {
    let mut data = dyld_cache_old();
    data[64..72].copy_from_slice(&0x2_0000_0000u64.to_le_bytes());
    data
}

/// One deterministic corpus entry shared by corpus generation and verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FuzzCorpusCase {
    /// Cargo-fuzz target (and corpus directory) name.
    pub target: &'static str,
    /// File name within the target's corpus directory.
    pub name: &'static str,
    /// Exact bytes supplied to the target.
    pub bytes: Vec<u8>,
}

/// Return the complete valid/invalid seed corpus for every fuzz target.
pub fn fuzz_corpus_cases() -> Vec<FuzzCorpusCase> {
    let thin = thin64_arm64(2);
    let fat = fat32(&[(CPU_TYPE_ARM64, 0, thin.clone())]);
    vec![
        corpus("container", "valid-thin", thin.clone()),
        corpus("container", "valid-fat", fat),
        corpus("container", "invalid-zero-arch", zero_arch_fat()),
        corpus("container", "invalid-overlap", overlapping_fat_slices()),
        corpus("container", "invalid-truncated", truncated_fat_slice()),
        corpus(
            "load_commands",
            "valid-unknown",
            unknown_load_command_image(),
        ),
        corpus(
            "load_commands",
            "invalid-truncated",
            truncated_load_command_image(),
        ),
        corpus("load_commands", "invalid-cmdsize", invalid_cmdsize_image()),
        corpus("dyld", "valid-empty-streams", empty_dyld_info_image()),
        corpus(
            "dyld",
            "invalid-stream-bounds",
            out_of_bounds_dyld_info_image(),
        ),
        corpus("codesign", "valid-empty-superblob", empty_super_blob()),
        corpus(
            "codesign",
            "invalid-truncated-index",
            truncated_super_blob(),
        ),
        corpus(
            "insn",
            "valid-stream",
            vec![0x90, 0xc3, 0x1f, 0x20, 0x03, 0xd5],
        ),
        corpus("insn", "invalid-stream", vec![0x0f, 0x0b, 0x00]),
        corpus("mutation", "valid-thin", thin),
        corpus("mutation", "invalid-truncated", vec![0xcf, 0xfa, 0xed]),
        corpus("cache_fileset", "valid-cache", dyld_cache_old()),
        corpus(
            "cache_fileset",
            "invalid-cache-mapping",
            dyld_cache_truncated_mapping(),
        ),
        corpus("cache_fileset", "valid-fileset", fileset64_arm64()),
        corpus(
            "cache_fileset",
            "invalid-fileset-offset",
            fileset64_out_of_bounds(),
        ),
        corpus(
            "cache_fileset",
            "invalid-fileset-command",
            fileset64_truncated_command(),
        ),
    ]
}

fn corpus(target: &'static str, name: &'static str, bytes: Vec<u8>) -> FuzzCorpusCase {
    FuzzCorpusCase {
        target,
        name,
        bytes,
    }
}

fn align_up(value: usize, alignment: usize) -> usize {
    value.div_ceil(alignment) * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixtures_are_deterministic() {
        let thin = thin64_arm64(2);
        assert_eq!(thin, thin64_arm64(2));
        assert_eq!(
            fat32(&[(CPU_TYPE_ARM64, 0, thin.clone())]),
            fat32(&[(CPU_TYPE_ARM64, 0, thin)])
        );
        assert_eq!(disassembly_x86_64(), disassembly_x86_64());
        assert_eq!(disassembly_arm64(), disassembly_arm64());
        assert_eq!(disassembly_arm64e(), disassembly_arm64e());
        assert_eq!(disassembly_fat(), disassembly_fat());
        assert_eq!(
            disassembly_fat_x86_subtypes(),
            disassembly_fat_x86_subtypes()
        );
        assert_eq!(
            disassembly_x86_64_aliases(10),
            disassembly_x86_64_aliases(10)
        );
        assert_eq!(disassembly_malformed_objc(), disassembly_malformed_objc());
        let symbols = thin64_x86_64_with_symbols(&[SymbolFixture {
            name: "_fixture",
            external: true,
            defined: true,
        }]);
        assert_eq!(
            symbols.len(),
            thin64_x86_64_with_symbols(&[SymbolFixture {
                name: "_fixture",
                external: true,
                defined: true,
            }])
            .len()
        );
    }
}
