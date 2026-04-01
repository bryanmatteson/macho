use macho::model::load_command::LoadCommand;
use macho::model::macho_file::MachoFile;
use macho::mutate::MachoEditor;

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

fn minimal_fileset_binary(entry_id: &str, vm_addr: u64, file_offset: u64) -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const MH_FILESET: u32 = 0xC;
    const LC_REQ_DYLD: u32 = 0x8000_0000;
    const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;

    let str_offset = 32u32;
    let cmdsize = ((str_offset as usize + entry_id.len() + 1 + 7) & !7) as u32;

    let mut data = Vec::new();
    data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    data.extend_from_slice(&(CPU_TYPE_ARM64 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&MH_FILESET.to_le_bytes());
    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&cmdsize.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_FILESET_ENTRY.to_le_bytes());
    data.extend_from_slice(&cmdsize.to_le_bytes());
    data.extend_from_slice(&vm_addr.to_le_bytes());
    data.extend_from_slice(&file_offset.to_le_bytes());
    data.extend_from_slice(&str_offset.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(entry_id.as_bytes());
    data.push(0);
    while data.len() % 8 != 0 {
        data.push(0);
    }

    data
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn infer_page_size(macho: &MachoFile<'_>) -> usize {
    for seg in macho.segments() {
        if seg.file_size > 0 && seg.file_offset.0 > 0 {
            let offset = seg.file_offset.0 as usize;
            if offset % 0x4000 == 0 {
                return 0x4000;
            }
            if offset % 0x1000 == 0 {
                return 0x1000;
            }
        }
    }
    0x1000
}

fn expected_data_shift(original: &MachoFile<'_>, rebuilt: &MachoFile<'_>) -> usize {
    let header_size = original.bitness().header_size();
    let page_size = infer_page_size(original);
    let old_start = align_up(
        header_size + original.header().sizeofcmds as usize,
        page_size,
    );
    let new_start = align_up(
        header_size + rebuilt.header().sizeofcmds as usize,
        page_size,
    );
    new_start - old_start
}

fn main_entry_offset(macho: &MachoFile<'_>) -> Option<u64> {
    macho.load_commands().iter().find_map(|lc| {
        if let LoadCommand::Main(entry) = &lc.kind {
            Some(entry.entry_offset)
        } else {
            None
        }
    })
}

fn fileset_entry_offset(macho: &MachoFile<'_>) -> Option<u64> {
    macho.load_commands().iter().find_map(|lc| {
        if let LoadCommand::FilesetEntry(entry) = &lc.kind {
            Some(entry.file_offset)
        } else {
            None
        }
    })
}

#[test]
fn round_trip_identity() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let editor = MachoEditor::new(macho);
    let rebuilt = editor.build().expect("build failed");

    // Re-parse the rebuilt binary
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    // Verify header fields match
    assert_eq!(rm.header().ncmds, macho.header().ncmds);
    assert_eq!(rm.header().file_type, macho.header().file_type);
    assert_eq!(rm.header().cpu_type, macho.header().cpu_type);

    // Verify segment count
    assert_eq!(rm.segments().len(), macho.segments().len());

    // Verify load command count
    assert_eq!(rm.load_commands().len(), macho.load_commands().len());
}

#[test]
fn add_rpath() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let original_ncmds = macho.header().ncmds;

    let mut editor = MachoEditor::new(macho);
    editor.add_rpath("@executable_path/../Frameworks");

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    assert_eq!(rm.header().ncmds, original_ncmds + 1);

    // Find the new rpath
    let has_rpath = rm.load_commands().iter().any(|lc| {
        if let Some(path) = lc.kind.as_rpath() {
            path == "@executable_path/../Frameworks"
        } else {
            false
        }
    });
    assert!(has_rpath, "expected new rpath in rebuilt binary");
}

#[test]
fn remove_command() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let original_ncmds = macho.header().ncmds;

    // Find the UUID command index
    let uuid_idx = macho
        .load_commands()
        .iter()
        .position(|lc| matches!(lc.kind, LoadCommand::Uuid(_)));

    if let Some(idx) = uuid_idx {
        let mut editor = MachoEditor::new(macho);
        editor.remove_command(idx).expect("remove failed");

        let rebuilt = editor.build().expect("build failed");
        let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
        let rm = reparsed.first_mach();

        assert_eq!(rm.header().ncmds, original_ncmds - 1);
        assert!(rm.uuid().is_none(), "UUID should be gone");
    }
}

#[test]
fn segments_still_valid_after_add() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let mut editor = MachoEditor::new(macho);
    editor.add_rpath("/test/path");
    editor.add_rpath("/another/path");

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    // All segments should still be parseable
    assert_eq!(rm.segments().len(), macho.segments().len());

    // The TEXT segment should have correct name
    let text = rm.segments().iter().find(|s| s.name == "__TEXT");
    assert!(text.is_some(), "expected __TEXT segment");

    // Validation should pass
    let diags = macho::model::validate::validate(rm);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == macho::model::validate::Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
}

#[test]
fn add_load_dylib() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let mut editor = MachoEditor::new(macho);
    editor.add_load_dylib("/usr/lib/libfoo.dylib", 0x10000, 0x10000);

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    let has_foo = rm.load_commands().iter().any(|lc| {
        if let Some(d) = lc.kind.as_dylib() {
            d.name == "/usr/lib/libfoo.dylib"
        } else {
            false
        }
    });
    assert!(has_foo, "expected new dylib in rebuilt binary");
}

#[test]
fn remove_code_signature() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();

    let mut editor = MachoEditor::new(macho);
    editor.remove_code_signature();

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    let has_sig = rm
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::CodeSignature(_)));
    assert!(!has_sig, "code signature should be removed");
}

#[test]
fn lc_main_entry_offset_tracks_shifted_text_data() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container.first_mach();
    let original_entry = main_entry_offset(macho).expect("expected LC_MAIN");

    let mut editor = MachoEditor::new(macho);
    let large_rpath = format!("/{}", "a".repeat(0x5000));
    editor.add_rpath(&large_rpath);

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    let delta = expected_data_shift(macho, rm);
    assert!(delta > 0, "test must force a data-region shift");

    let rebuilt_entry = main_entry_offset(rm).expect("expected LC_MAIN after rebuild");
    assert_eq!(rebuilt_entry, original_entry + delta as u64);
}

#[test]
fn fileset_entry_offset_tracks_shifted_payload_data() {
    let data = minimal_fileset_binary("com.example.member", 0x1000_0000, 0x2000);
    let container = macho::parse(&data).expect("failed to parse synthetic fileset");
    let macho = container.first_mach();
    let original_offset = fileset_entry_offset(macho).expect("expected LC_FILESET_ENTRY");

    let mut editor = MachoEditor::new(macho);
    let large_rpath = format!("/{}", "b".repeat(0x1400));
    editor.add_rpath(&large_rpath);

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    let delta = expected_data_shift(macho, rm);
    assert!(delta > 0, "test must force a data-region shift");

    let rebuilt_offset = fileset_entry_offset(rm).expect("expected LC_FILESET_ENTRY after rebuild");
    assert_eq!(rebuilt_offset, original_offset + delta as u64);
}
