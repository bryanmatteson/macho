use macho::metadata::dyld::chained::parse_chained_fixups;
use macho::metadata::dyld::exports::{find_export, parse_exports};
use macho::metadata::dyld::types::{ExportKind, FixupKind};
use macho::model::container::MachContainer;

fn load_binary(path: &str) -> memmap2::Mmap {
    let file = std::fs::File::open(path).unwrap_or_else(|e| panic!("failed to open {path}: {e}"));
    unsafe { memmap2::Mmap::map(&file).unwrap() }
}

fn load_tar() -> memmap2::Mmap {
    load_binary("/usr/bin/tar")
}

// --- Chained fixups tests ---

#[test]
fn parse_chained_fixups_tar() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    // tar has arm64e with chained fixups
    for mach in container.mach_files() {
        match parse_chained_fixups(mach) {
            Ok(fixups) => {
                assert!(!fixups.imports.is_empty(), "expected imports");
                // All import names should be non-empty valid strings
                for imp in &fixups.imports {
                    assert!(!imp.name.is_empty());
                }
            }
            Err(_) => {
                // Some arches might not have chained fixups (older x86_64)
            }
        }
    }
}

#[test]
fn chained_fixups_import_names() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    // The arm64e arch should have archive_* imports
    if let MachContainer::Fat(ref fat) = container {
        for arch in fat.arches() {
            if arch.spec.is_arm64e() {
                let fixups = parse_chained_fixups(&arch.mach)
                    .expect("failed to parse chained fixups for arm64e");
                let has_archive = fixups
                    .imports
                    .iter()
                    .any(|i| i.name.starts_with("_archive_"));
                assert!(has_archive, "expected _archive_* imports in tar");
                return;
            }
        }
    }
}

#[test]
fn chained_fixups_have_bind_or_rebase() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        if let Ok(fixups) = parse_chained_fixups(mach) {
            if !fixups.fixups.is_empty() {
                // At least one should be a bind or rebase
                let has_bind = fixups
                    .fixups
                    .iter()
                    .any(|f| matches!(f.kind, FixupKind::Bind { .. } | FixupKind::AuthBind { .. }));
                let has_rebase = fixups.fixups.iter().any(|f| {
                    matches!(
                        f.kind,
                        FixupKind::Rebase { .. } | FixupKind::AuthRebase { .. }
                    )
                });
                assert!(
                    has_bind || has_rebase,
                    "expected at least one bind or rebase fixup"
                );
            }
        }
    }
}

// --- Exports trie tests ---

#[test]
fn parse_exports_tar() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let exports = parse_exports(mach).expect("failed to parse exports");
    assert!(!exports.is_empty(), "expected exports");

    // __mh_execute_header should be exported
    let mh = exports.iter().find(|e| e.name == "__mh_execute_header");
    assert!(mh.is_some(), "expected __mh_execute_header export");
    let mh = mh.unwrap();
    assert!(matches!(mh.kind, ExportKind::Regular { .. }));
}

#[test]
fn find_export_by_name() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let result = find_export(mach, "__mh_execute_header").expect("failed to find export");
    assert!(result.is_some());
    let export = result.unwrap();
    assert_eq!(export.name, "__mh_execute_header");
    assert!(export.address().is_some());
}

#[test]
fn find_export_nonexistent() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let result = find_export(mach, "_this_does_not_exist").expect("lookup failed");
    assert!(result.is_none());
}

#[test]
fn exports_all_have_names() {
    let mmap = load_tar();
    let container = macho::parse(&mmap).expect("failed to parse");

    for mach in container.mach_files() {
        let exports = parse_exports(mach).expect("failed to parse exports");
        for e in &exports {
            assert!(!e.name.is_empty(), "export has empty name");
        }
    }
}

// --- Binary without chained fixups ---

#[test]
fn no_chained_fixups_returns_error() {
    // Build a minimal binary with no LC_DYLD_CHAINED_FIXUPS
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
    data.extend_from_slice(&72u32.to_le_bytes()); // sizeofcmds
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // Just a segment, no dyld commands
    data.extend_from_slice(&0x19u32.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    data.extend_from_slice(&[0u8; 64]); // segment data

    let container = macho::parse(&data).expect("parse failed");
    let mach = container.first_mach();
    assert!(parse_chained_fixups(mach).is_err());
}

// --- ULEB128 edge cases tested in dyld/uleb.rs unit tests ---

// --- Exports trie synthetic test ---

#[test]
fn synthetic_exports_trie() {
    // Build a minimal exports trie by hand:
    // Root node: terminal="" (no export), 1 edge "_" -> node at offset 4
    // Child node at 4: terminal="" (no export), 1 edge "main" -> node at offset 12
    // Leaf node at 12: terminal info (flags=0, address=0x1000), 0 edges
    let mut trie = vec![
        0x00, // terminal_size = 0
        0x01, // edge_count = 1
        b'_', // edge label
        0x00, // null terminator
        0x06, // child offset (ULEB128) = 6
        0x00, // pad byte to make offset 6 valid
        0x00, // terminal_size = 0
        0x01, // edge_count = 1
    ];

    // Node at 6: terminal_size=0, 1 edge "main"
    trie.extend_from_slice(b"main");
    trie.push(0x00); // null terminator
    trie.push(14); // child offset = 14

    // Pad to offset 14
    while trie.len() < 14 {
        trie.push(0x00);
    }

    // Node at 14 (leaf "_main"): terminal_size=3, flags=0, address=0x1000
    trie.push(0x03); // terminal_size = 3 bytes (1 byte flags + 2 bytes address)
    trie.push(0x00); // flags = 0 (ULEB128, 1 byte)
    trie.push(0x80); // address = 0x1000 (ULEB128: 0x80, 0x20) (2 bytes)
    trie.push(0x20);
    trie.push(0x00); // edge_count = 0

    // Build a minimal binary containing this trie in LC_DYLD_EXPORTS_TRIE
    let trie_offset: u32 = 56; // right after header + command
    let trie_size = trie.len() as u32;

    let mut data = Vec::new();
    // Header (32 bytes)
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds
    data.extend_from_slice(&16u32.to_le_bytes()); // sizeofcmds (LinkeditDataCommand = 16)
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    // LC_DYLD_EXPORTS_TRIE (LinkeditDataCommand, 16 bytes) at offset 32
    data.extend_from_slice(&(0x33u32 | 0x80000000u32).to_le_bytes()); // cmd = LC_DYLD_EXPORTS_TRIE
    data.extend_from_slice(&16u32.to_le_bytes()); // cmdsize
    data.extend_from_slice(&trie_offset.to_le_bytes()); // dataoff
    data.extend_from_slice(&trie_size.to_le_bytes()); // datasize

    // Pad to trie_offset
    while data.len() < trie_offset as usize {
        data.push(0);
    }

    // Append trie data
    data.extend_from_slice(&trie);

    let container = macho::parse(&data).expect("parse failed");
    let mach = container.first_mach();

    let exports = parse_exports(mach).expect("export parse failed");
    assert_eq!(exports.len(), 1);
    assert_eq!(exports[0].name, "_main");
    assert_eq!(exports[0].address(), Some(0x1000));

    // find_export
    let found = find_export(mach, "_main").expect("find failed");
    assert!(found.is_some());
    assert_eq!(found.unwrap().name, "_main");

    // Not found
    let missing = find_export(mach, "_nonexistent").expect("find failed");
    assert!(missing.is_none());
}
