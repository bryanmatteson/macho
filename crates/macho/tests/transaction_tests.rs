#![cfg(feature = "cli")]

//! Transaction checks against signed Apple system binaries.
#![cfg(target_os = "macos")]

mod support;

use macho::model::container::MachoContainer;
use macho::mutate::transaction::{PatchOp, PatchTransaction, SignatureOutcome};
use std::path::Path;

fn with_thin_mach(f: impl FnOnce(&macho::model::macho_file::MachoFile<'_>)) {
    let source = Path::new("/usr/bin/true");
    let data = std::fs::read(source).expect("read");
    let container = macho::parse(&data).expect("parse");
    match &container {
        MachoContainer::Fat(fat) => f(fat.arches()[0].macho()),
        MachoContainer::Thin(macho) => f(macho),
    }
}

#[test]
fn transaction_add_rpath_preview() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.add_rpath("/opt/test");
        let preview = txn.preview().expect("preview");

        assert_eq!(preview.operations.len(), 1);
        assert!(preview.operations[0].contains("add rpath"));
        assert_eq!(preview.new_command_count, preview.old_command_count + 1);
    });
}

#[test]
fn transaction_signature_invalidation_detected() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
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
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.add_rpath("/opt/test");
        let bytes = txn.commit().expect("commit");

        // Reparse the result
        let reparsed = macho::parse(&bytes).expect("reparse");
        let macho2 = reparsed
            .first_macho()
            .expect("test container contains a Mach-O image");

        // Should have one more load command
        assert_eq!(
            macho2.load_commands().len(),
            macho.load_commands().len() + 1
        );
    });
}

#[test]
fn transaction_remove_rpath_no_op_on_missing() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.remove_rpath("/nonexistent/path");
        let preview = txn.preview().expect("preview");

        // Should not change command count since the rpath doesn't exist
        assert_eq!(preview.old_command_count, preview.new_command_count);
    });
}

#[test]
fn transaction_noop_edit_does_not_invalidate_signature() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
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
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.remove_code_signature();
        let preview = txn.preview().expect("preview");

        assert_eq!(preview.signature_outcome, SignatureOutcome::Removed);
    });
}

#[test]
fn transaction_remove_code_signature() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.remove_code_signature();
        let bytes = txn.commit().expect("commit");

        let reparsed = macho::parse(&bytes).expect("reparse");
        let macho2 = reparsed
            .first_macho()
            .expect("test container contains a Mach-O image");

        // Should not have LC_CODE_SIGNATURE
        assert!(
            !macho2.load_commands().iter().any(|lc| {
                matches!(
                    lc.kind(),
                    macho::model::load_command::LoadCommand::CodeSignature(_)
                )
            }),
            "code signature should be removed"
        );
    });
}

#[test]
fn transaction_multiple_ops() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.add_rpath("/first");
        txn.add_rpath("/second");
        let preview = txn.preview().expect("preview");

        assert_eq!(preview.operations.len(), 2);
        assert_eq!(preview.new_command_count, preview.old_command_count + 2);
    });
}

#[test]
fn transaction_preview_no_validation_errors_on_valid_ops() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
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
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.patch_bytes(u64::MAX, vec![0x90]);

        let err = txn.preview().expect_err("preview should fail");
        let msg = err.to_string();
        assert!(
            msg.contains("mutation.bounds.exceeded"),
            "unexpected error: {msg}"
        );
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
fn transaction_build_unchecked_rejects_payload_relocation() {
    with_thin_mach(|macho| {
        let mut txn = PatchTransaction::new(macho);
        txn.add_rpath(format!("/{}", "c".repeat(0x5000)));

        let error = txn
            .build_unchecked()
            .expect_err("unchecked build must still preserve layout safety");
        assert!(
            error
                .to_string()
                .contains("insufficient load-command slack")
        );
    });
}
