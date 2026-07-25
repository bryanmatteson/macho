//! Symbol-table corpus checks against Apple system binaries.
#![cfg(target_os = "macos")]

use macho::format::relocations::relocations_for_section;
use macho::model::symbol::{SymbolTable, SymbolType};

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn parse_symbol_table_via_ext() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let symtab = macho
        .ext::<SymbolTable>()
        .expect("failed to parse symbol table");
    assert!(!symtab.is_empty());

    // Verify symtab length matches SymtabData.nsyms
    let st_data = macho
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind().as_symtab())
        .expect("no LC_SYMTAB");
    assert_eq!(symtab.len(), st_data.nsyms as usize);
}

#[test]
fn symbol_names_are_valid_str() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    for macho in container.macho_files() {
        let symtab = macho
            .ext::<SymbolTable>()
            .expect("failed to parse symbol table");
        for sym in symtab.symbols() {
            // name should be a valid &str (not panic on access)
            let _ = sym.name.len();
        }
    }
}

#[test]
fn has_defined_symbol() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let symtab = macho
        .ext::<SymbolTable>()
        .expect("failed to parse symbol table");
    let defined_count = symtab.defined().count();
    assert!(defined_count > 0, "expected at least one defined symbol");
}

#[test]
fn find_by_name() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let symtab = macho
        .ext::<SymbolTable>()
        .expect("failed to parse symbol table");
    // __mh_execute_header is present in virtually all executables
    let sym = symtab.find_by_name("__mh_execute_header");
    assert!(sym.is_some(), "expected __mh_execute_header symbol");
    let sym = sym.unwrap();
    assert!(sym.is_defined());
    assert!(sym.external);
    assert_eq!(sym.sym_type, SymbolType::Section);
}

#[test]
fn string_table_accessible() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let symtab = macho
        .ext::<SymbolTable>()
        .expect("failed to parse symbol table");
    let st = symtab.string_table();
    assert!(!st.is_empty());
    // First byte of string table is conventionally a null byte
    assert_eq!(st.bytes()[0], 0);
}

#[test]
fn relocations_empty_for_linked_binary() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    // Linked executables typically have zero relocations per section
    for sect in macho.all_sections() {
        let relocs = relocations_for_section(macho, sect).expect("failed to parse relocations");
        // This is expected to be empty for linked binaries
        assert!(
            relocs.is_empty() || sect.relocation_count() > 0,
            "reloc count mismatch for {},{}: nreloc={} but parsed {}",
            sect.segment_name(),
            sect.section_name(),
            sect.relocation_count(),
            relocs.len()
        );
    }
}

#[test]
fn parse_symbol_table_standalone() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let symtab = macho::format::parse_symbol_table(macho).expect("failed to parse symbol table");
    assert!(!symtab.is_empty());
}

#[test]
fn missing_symtab_returns_error() {
    // Build a minimal binary with no LC_SYMTAB
    let mut data = Vec::new();
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes());
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
    data.extend_from_slice(&72u32.to_le_bytes()); // sizeofcmds
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    // LC_SEGMENT_64 only, no LC_SYMTAB
    data.extend_from_slice(&0x19u32.to_le_bytes()); // cmd
    data.extend_from_slice(&72u32.to_le_bytes()); // cmdsize
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    data.extend_from_slice(&segname);
    data.extend_from_slice(&0x100000000u64.to_le_bytes());
    data.extend_from_slice(&0x1000u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&104u64.to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    let container = macho::parse(&data).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let result = macho::format::parse_symbol_table(macho);
    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("no LC_SYMTAB"),
        "expected 'no LC_SYMTAB' error, got: {err_msg}"
    );
}

#[test]
fn stab_symbols_have_stab_type() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");

    // Check all arches — some may have stab symbols from debug info
    for macho in container.macho_files() {
        let symtab = match macho::format::parse_symbol_table(macho) {
            Ok(st) => st,
            Err(_) => continue,
        };

        for sym in symtab.symbols() {
            if sym.is_stab() {
                assert!(
                    matches!(sym.sym_type, SymbolType::Stab(_)),
                    "STAB symbol should have SymbolType::Stab, got {:?}",
                    sym.sym_type
                );
                // Stab symbols should NOT be classified as defined or undefined
                assert!(!sym.is_defined());
                assert!(!sym.is_undefined());
            }
        }
    }
}

#[test]
fn synthetic_symtab_parsing() {
    // Build a minimal thin 64-bit binary with LC_SEGMENT_64 + LC_SYMTAB
    // pointing to a hand-crafted nlist64 and string table
    let mut data = Vec::new();

    let strtab = b"\0_foo\0_bar\0";

    // Header (32 bytes)
    data.extend_from_slice(&0xFEEDFACFu32.to_le_bytes()); // magic
    data.extend_from_slice(&(0x0100000Cu32 as i32).to_le_bytes()); // cputype
    data.extend_from_slice(&0i32.to_le_bytes()); // cpusubtype
    data.extend_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
    data.extend_from_slice(&1u32.to_le_bytes()); // ncmds = 1
    data.extend_from_slice(&24u32.to_le_bytes()); // sizeofcmds = sizeof(RawSymtabCommand)
    data.extend_from_slice(&0u32.to_le_bytes()); // flags
    data.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // LC_SYMTAB (24 bytes) at offset 32
    data.extend_from_slice(&0x02u32.to_le_bytes()); // cmd = LC_SYMTAB
    data.extend_from_slice(&24u32.to_le_bytes()); // cmdsize
    data.extend_from_slice(&(56u32).to_le_bytes()); // symoff = 56 (right after this cmd)
    data.extend_from_slice(&2u32.to_le_bytes()); // nsyms = 2
    data.extend_from_slice(&(56 + 32u32).to_le_bytes()); // stroff = 88 (after 2 nlist64s)
    data.extend_from_slice(&(strtab.len() as u32).to_le_bytes()); // strsize

    assert_eq!(data.len(), 56); // 32 header + 24 symtab cmd

    // nlist64 entries (16 bytes each) at offset 56
    // Symbol 0: _foo, type=N_SECT|N_EXT, sect=1, value=0x1000
    data.extend_from_slice(&1u32.to_le_bytes()); // n_strx = 1 ("_foo")
    data.push(0x0f); // n_type = N_SECT | N_EXT
    data.push(1); // n_sect = 1
    data.extend_from_slice(&0u16.to_le_bytes()); // n_desc
    data.extend_from_slice(&0x1000u64.to_le_bytes()); // n_value

    // Symbol 1: _bar, type=N_UNDF|N_EXT, sect=0, value=0
    data.extend_from_slice(&6u32.to_le_bytes()); // n_strx = 6 ("_bar")
    data.push(0x01); // n_type = N_EXT (undefined)
    data.push(0); // n_sect = 0
    data.extend_from_slice(&0u16.to_le_bytes()); // n_desc
    data.extend_from_slice(&0u64.to_le_bytes()); // n_value

    assert_eq!(data.len(), 88); // 56 + 32

    // String table at offset 88
    data.extend_from_slice(strtab);

    let container = macho::parse(&data).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let symtab = macho::format::parse_symbol_table(macho).expect("failed to parse symbol table");

    assert_eq!(symtab.len(), 2);

    let foo = &symtab.symbols()[0];
    assert_eq!(foo.name, "_foo");
    assert_eq!(foo.sym_type, SymbolType::Section);
    assert!(foo.external);
    assert!(foo.is_defined());
    assert_eq!(foo.value, 0x1000);

    let bar = &symtab.symbols()[1];
    assert_eq!(bar.name, "_bar");
    assert_eq!(bar.sym_type, SymbolType::Undefined);
    assert!(bar.external);
    assert!(bar.is_undefined());
    assert_eq!(bar.value, 0);

    // find_by_name
    assert!(symtab.find_by_name("_foo").is_some());
    assert!(symtab.find_by_name("_nonexistent").is_none());

    // filtered iterators
    assert_eq!(symtab.defined().count(), 1);
    assert_eq!(symtab.undefined().count(), 1);
    assert_eq!(symtab.external().count(), 2);
}
