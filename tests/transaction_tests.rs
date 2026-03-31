use macho::edit::transaction::{PatchOp, PatchTransaction, SignatureOutcome};
use macho::model::container::MachContainer;
use macho::model::load_command::LoadCommand;
use macho::model::mach::MachFile;

fn with_thin_mach(f: impl FnOnce(&macho::model::mach::MachFile<'_>)) {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    match &container {
        MachContainer::Fat(fat) => f(&fat.arches()[0].mach),
        MachContainer::Thin(mach) => f(mach),
    }
}

fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

fn infer_page_size(mach: &MachFile<'_>) -> usize {
    for seg in mach.segments() {
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

fn expected_data_shift(original: &MachFile<'_>, rebuilt: &MachFile<'_>) -> usize {
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

fn main_entry_offset(mach: &MachFile<'_>) -> Option<u64> {
    mach.load_commands().iter().find_map(|lc| {
        if let LoadCommand::Main(entry) = &lc.kind {
            Some(entry.entry_offset)
        } else {
            None
        }
    })
}

#[test]
fn transaction_add_rpath_preview() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.add_rpath("/opt/test");
        let preview = txn.preview().expect("preview");

        assert_eq!(preview.operations.len(), 1);
        assert!(preview.operations[0].contains("add rpath"));
        assert_eq!(preview.new_command_count, preview.old_command_count + 1);
    });
}

#[test]
fn transaction_signature_invalidation_detected() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.add_rpath("/opt/test");
        let preview = txn.preview().expect("preview");

        // System binaries are signed, so modifying them should flag invalidation
        assert!(
            preview.signature_outcome == SignatureOutcome::Invalidated,
            "adding rpath to signed binary should invalidate signature"
        );
    });
}

#[test]
fn transaction_commit_produces_valid_binary() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.add_rpath("/opt/test");
        let bytes = txn.commit().expect("commit");

        // Reparse the result
        let reparsed = macho::parse(&bytes).expect("reparse");
        let mach2 = reparsed.first_mach();

        // Should have one more load command
        assert_eq!(mach2.load_commands().len(), mach.load_commands().len() + 1);
    });
}

#[test]
fn transaction_remove_rpath_no_op_on_missing() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.remove_rpath("/nonexistent/path");
        let preview = txn.preview().expect("preview");

        // Should not change command count since the rpath doesn't exist
        assert_eq!(preview.old_command_count, preview.new_command_count);
    });
}

#[test]
fn transaction_noop_edit_does_not_invalidate_signature() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.remove_rpath("/definitely/not/present");
        let preview = txn.preview().expect("preview");

        assert!(
            preview.signature_outcome == SignatureOutcome::Unchanged,
            "no-op edits should not be treated as signature invalidation"
        );
    });
}

#[test]
fn transaction_remove_code_signature_reports_removed_outcome() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.remove_code_signature();
        let preview = txn.preview().expect("preview");

        assert_eq!(preview.signature_outcome, SignatureOutcome::Removed);
    });
}

#[test]
fn transaction_remove_code_signature() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.remove_code_signature();
        let bytes = txn.commit().expect("commit");

        let reparsed = macho::parse(&bytes).expect("reparse");
        let mach2 = reparsed.first_mach();

        // Should not have LC_CODE_SIGNATURE
        assert!(
            !mach2.load_commands().iter().any(|lc| {
                matches!(
                    lc.kind,
                    macho::model::load_command::LoadCommand::CodeSignature(_)
                )
            }),
            "code signature should be removed"
        );
    });
}

#[test]
fn transaction_multiple_ops() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.add_rpath("/first");
        txn.add_rpath("/second");
        let preview = txn.preview().expect("preview");

        assert_eq!(preview.operations.len(), 2);
        assert_eq!(preview.new_command_count, preview.old_command_count + 2);
    });
}

#[test]
fn transaction_preview_no_validation_errors_on_valid_ops() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.add_rpath("/opt/test");
        let preview = txn.preview().expect("preview");
        assert!(
            preview.validation_errors.is_empty(),
            "valid patch should produce no validation errors"
        );
    });
}

#[test]
fn transaction_patch_bytes_out_of_bounds_fails_cleanly() {
    with_thin_mach(|mach| {
        let mut txn = PatchTransaction::new(mach);
        txn.patch_bytes(u64::MAX, vec![0x90]);

        let err = txn.preview().expect_err("preview should fail");
        let msg = err.to_string();
        assert!(msg.contains("out of bounds"), "unexpected error: {msg}");
    });
}

#[test]
fn patch_op_display() {
    assert_eq!(
        PatchOp::AddRpath("/test".into()).to_string(),
        "add rpath: /test"
    );
    assert_eq!(
        PatchOp::RemoveCodeSignature.to_string(),
        "remove code signature"
    );
}

#[test]
fn transaction_build_unchecked_preserves_shifted_entrypoint() {
    with_thin_mach(|mach| {
        let original_entry = main_entry_offset(mach).expect("expected LC_MAIN");
        let mut txn = PatchTransaction::new(mach);
        txn.add_rpath(format!("/{}", "c".repeat(0x5000)));

        let bytes = txn.build_unchecked().expect("build_unchecked");
        let reparsed = macho::parse(&bytes).expect("reparse");
        let rebuilt = reparsed.first_mach();

        let delta = expected_data_shift(mach, rebuilt);
        assert!(delta > 0, "test must force a data-region shift");

        let rebuilt_entry = main_entry_offset(rebuilt).expect("expected LC_MAIN after rebuild");
        assert_eq!(rebuilt_entry, original_entry + delta as u64);
    });
}
