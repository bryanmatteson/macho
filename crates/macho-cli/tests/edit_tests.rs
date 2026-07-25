//! Editor checks against the host's Apple system binaries.
#![cfg(target_os = "macos")]

use macho::model::load_command::LoadCommand;
use macho::mutate::MachoEditor;

fn load_true() -> memmap2::Mmap {
    let file = std::fs::File::open("/usr/bin/true").expect("failed to open /usr/bin/true");
    unsafe { memmap2::Mmap::map(&file).expect("failed to mmap") }
}

#[test]
fn round_trip_identity() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let editor = MachoEditor::new(macho);
    let rebuilt = editor.build().expect("build failed");

    // Re-parse the rebuilt binary
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed
        .first_macho()
        .expect("test container contains a Mach-O image");

    // Verify header fields match
    assert_eq!(
        rm.header().load_command_count(),
        macho.header().load_command_count()
    );
    assert_eq!(rm.header().file_type(), macho.header().file_type());
    assert_eq!(rm.header().cpu_type(), macho.header().cpu_type());

    // Verify segment count
    assert_eq!(rm.segments().len(), macho.segments().len());

    // Verify load command count
    assert_eq!(rm.load_commands().len(), macho.load_commands().len());
}

#[test]
fn add_rpath() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let original_ncmds = macho.header().load_command_count();

    let mut editor = MachoEditor::new(macho);
    editor.add_rpath("@executable_path/../Frameworks");

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed
        .first_macho()
        .expect("test container contains a Mach-O image");

    assert_eq!(rm.header().load_command_count(), original_ncmds + 1);

    // Find the new rpath
    let has_rpath = rm.load_commands().iter().any(|lc| {
        if let Some(path) = lc.kind().as_rpath() {
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
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let original_ncmds = macho.header().load_command_count();

    // Find the UUID command index
    let uuid_idx = macho
        .load_commands()
        .iter()
        .position(|lc| matches!(lc.kind(), LoadCommand::Uuid(_)));

    if let Some(idx) = uuid_idx {
        let mut editor = MachoEditor::new(macho);
        editor.remove_command(idx).expect("remove failed");

        let rebuilt = editor.build().expect("build failed");
        let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
        let rm = reparsed
            .first_macho()
            .expect("test container contains a Mach-O image");

        assert_eq!(rm.header().load_command_count(), original_ncmds - 1);
        assert!(rm.uuid().is_none(), "UUID should be gone");
    }
}

#[test]
fn segments_still_valid_after_add() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let mut editor = MachoEditor::new(macho);
    editor.add_rpath("/test/path");

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed
        .first_macho()
        .expect("test container contains a Mach-O image");

    // All segments should still be parseable
    assert_eq!(rm.segments().len(), macho.segments().len());

    // The TEXT segment should have correct name
    let text = rm.segments().iter().find(|s| s.name() == "__TEXT");
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
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");
    let mut editor = MachoEditor::new(macho);
    editor.add_load_dylib("/usr/lib/libfoo.dylib", 0x10000, 0x10000);

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed
        .first_macho()
        .expect("test container contains a Mach-O image");

    let has_foo = rm.load_commands().iter().any(|lc| {
        if let Some(d) = lc.kind().as_dylib() {
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
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let mut editor = MachoEditor::new(macho);
    editor.remove_code_signature();

    let rebuilt = editor.build().expect("build failed");
    let reparsed = macho::parse(&rebuilt).expect("re-parse failed");
    let rm = reparsed
        .first_macho()
        .expect("test container contains a Mach-O image");

    let has_sig = rm
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind(), LoadCommand::CodeSignature(_)));
    assert!(!has_sig, "code signature should be removed");
}

#[test]
fn load_command_growth_rejects_text_payload_relocation() {
    let mmap = load_true();
    let container = macho::parse(&mmap).expect("failed to parse");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");
    let original = macho.bytes().to_vec();
    let mut editor = MachoEditor::new(macho);
    let large_rpath = format!("/{}", "a".repeat(0x5000));
    editor.add_rpath(&large_rpath);

    let error = editor
        .build()
        .expect_err("existing text payload must never be relocated");
    assert!(
        error
            .to_string()
            .contains("insufficient load-command slack")
    );
    assert_eq!(macho.bytes(), original.as_slice());
}

#[test]
fn load_command_growth_rejects_fileset_payload_relocation() {
    let data = macho_test_support::fileset64_arm64();
    let container = macho::parse(&data).expect("failed to parse synthetic fileset");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");
    let mut editor = MachoEditor::new(macho);
    let large_rpath = format!("/{}", "b".repeat(0x1400));
    editor.add_rpath(&large_rpath);

    let error = editor
        .build()
        .expect_err("existing fileset payload must never be relocated");
    assert!(
        error
            .to_string()
            .contains("insufficient load-command slack")
    );
    assert_eq!(macho.bytes(), data.as_slice());
}
