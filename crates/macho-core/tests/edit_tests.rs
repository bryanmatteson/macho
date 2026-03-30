use macho_core::edit::MachEditor;
use macho_core::model::load_command::LoadCommand;

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn round_trip_identity() {
    let mmap = load_true();
    let container = macho_core::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let editor = MachEditor::new(mach);
    let rebuilt = editor.build().expect("build failed");

    // Re-parse the rebuilt binary
    let reparsed = macho_core::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    // Verify header fields match
    assert_eq!(rm.header().ncmds, mach.header().ncmds);
    assert_eq!(rm.header().file_type, mach.header().file_type);
    assert_eq!(rm.header().cpu_type, mach.header().cpu_type);

    // Verify segment count
    assert_eq!(rm.segments().len(), mach.segments().len());

    // Verify load command count
    assert_eq!(rm.load_commands().len(), mach.load_commands().len());
}

#[test]
fn add_rpath() {
    let mmap = load_true();
    let container = macho_core::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let original_ncmds = mach.header().ncmds;

    let mut editor = MachEditor::new(mach);
    editor.add_rpath("@executable_path/../Frameworks");

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho_core::parse(&rebuilt).expect("re-parse failed");
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
    let container = macho_core::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let original_ncmds = mach.header().ncmds;

    // Find the UUID command index
    let uuid_idx = mach
        .load_commands()
        .iter()
        .position(|lc| matches!(lc.kind, LoadCommand::Uuid(_)));

    if let Some(idx) = uuid_idx {
        let mut editor = MachEditor::new(mach);
        editor.remove_command(idx).expect("remove failed");

        let rebuilt = editor.build().expect("build failed");
        let reparsed = macho_core::parse(&rebuilt).expect("re-parse failed");
        let rm = reparsed.first_mach();

        assert_eq!(rm.header().ncmds, original_ncmds - 1);
        assert!(rm.uuid().is_none(), "UUID should be gone");
    }
}

#[test]
fn segments_still_valid_after_add() {
    let mmap = load_true();
    let container = macho_core::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut editor = MachEditor::new(mach);
    editor.add_rpath("/test/path");
    editor.add_rpath("/another/path");

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho_core::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    // All segments should still be parseable
    assert_eq!(rm.segments().len(), mach.segments().len());

    // The TEXT segment should have correct name
    let text = rm.segments().iter().find(|s| s.name == "__TEXT");
    assert!(text.is_some(), "expected __TEXT segment");

    // Validation should pass
    let diags = macho_core::validate::validate(rm);
    let errors: Vec<_> = diags
        .iter()
        .filter(|d| d.severity == macho_core::validate::Severity::Error)
        .collect();
    assert!(
        errors.is_empty(),
        "unexpected validation errors: {errors:?}"
    );
}

#[test]
fn add_load_dylib() {
    let mmap = load_true();
    let container = macho_core::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut editor = MachEditor::new(mach);
    editor.add_load_dylib("/usr/lib/libfoo.dylib", 0x10000, 0x10000);

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho_core::parse(&rebuilt).expect("re-parse failed");
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
    let container = macho_core::parse(&mmap).expect("failed to parse");
    let mach = container.first_mach();

    let mut editor = MachEditor::new(mach);
    editor.remove_code_signature();

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho_core::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed.first_mach();

    let has_sig = rm
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::CodeSignature(_)));
    assert!(!has_sig, "code signature should be removed");
}
