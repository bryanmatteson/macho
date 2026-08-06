#![cfg(feature = "cli")]

//! Re-signing plan checks against signed Apple system binaries.
#![cfg(target_os = "macos")]

use macho::model::container::MachoContainer;
use macho::mutate::resign::ResignPlan;
use macho::mutate::transaction::PatchTransaction;
use macho::parse;

fn malformed_codesign_binary() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const MH_EXECUTE: u32 = 2;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_CODE_SIGNATURE: u32 = 0x1D;

    let code_sig_offset = 32u32 + 72 + 16;
    let code_sig_size = 8u32;
    let total_size = code_sig_offset + code_sig_size;

    let mut data = Vec::new();
    data.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    data.extend_from_slice(&(CPU_TYPE_ARM64 as i32).to_le_bytes());
    data.extend_from_slice(&0i32.to_le_bytes());
    data.extend_from_slice(&MH_EXECUTE.to_le_bytes());
    data.extend_from_slice(&2u32.to_le_bytes());
    data.extend_from_slice(&88u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    data.extend_from_slice(&72u32.to_le_bytes());
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    data.extend_from_slice(&segname);
    data.extend_from_slice(&0x1000_0000u64.to_le_bytes());
    data.extend_from_slice(&0x1000u64.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.extend_from_slice(&(total_size as u64).to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&5i32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    data.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    data.extend_from_slice(&16u32.to_le_bytes());
    data.extend_from_slice(&code_sig_offset.to_le_bytes());
    data.extend_from_slice(&code_sig_size.to_le_bytes());
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 1, 2, 3]);

    data
}

#[test]
fn resign_plan_for_signed_binary() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };

    let plan = ResignPlan::from_mach(macho);
    assert!(plan.was_signed);
    assert!(plan.identifier.is_some());
    assert!(plan.hash_type.is_some());
    assert!(plan.has_cms_signature);
    assert!(plan.suggested_command.starts_with("macho patch"));
    assert!(plan.suggested_command.contains("<patched-binary>"));
    assert!(plan.suggested_command.contains("--sign-p12"));
    assert!(plan.suggested_command.contains("--output <signed-binary>"));
    assert!(!plan.suggested_command.contains("--in-place"));
    assert!(!plan.suggested_command.contains("xcrun"));
    assert!(plan.manual_steps.iter().any(|step| {
        step.contains("rerun the original mutation") && step.contains("same transaction")
    }));
    assert!(plan.manual_steps.iter().any(|step| {
        step.contains("already materialized patched artifact")
            && step.contains("does not apply the pending mutation")
    }));
}

#[test]
fn resign_plan_includes_identifier_in_command() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };

    let plan = ResignPlan::from_mach(macho);
    if let Some(ref id) = plan.identifier {
        assert!(
            plan.suggested_command.contains(id),
            "suggested command should include the identifier"
        );
    }
}

#[test]
fn resign_plan_serializes() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };

    let plan = ResignPlan::from_mach(macho);
    let json = serde_json::to_string(&plan).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(parsed["was_signed"], true);
    assert!(
        parsed["suggested_command"]
            .as_str()
            .is_some_and(|command| command.contains("--output") && !command.contains("--in-place"))
    );
}

#[test]
fn resign_plan_display() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };

    let plan = ResignPlan::from_mach(macho);
    let display = format!("{plan}");
    assert!(display.contains("Re-sign assistance:"));
    assert!(display.contains("Candidate signing command:"));
    assert!(display.contains("<patched-binary>"));
    assert!(display.contains("--output <signed-binary>"));
    assert!(!display.contains("--in-place"));
    assert!(display.contains("does not apply the pending mutation"));
    assert!(display.contains("macho patch"));
}

#[test]
fn resign_plan_for_unsigned_binary_is_explicit() {
    let data = std::fs::read("/usr/bin/true").expect("read");
    let container = macho::parse(&data).expect("parse");
    let macho = match &container {
        MachoContainer::Fat(fat) => fat.arches()[0].macho(),
        MachoContainer::Thin(macho) => macho,
    };

    let mut txn = PatchTransaction::new(macho);
    txn.remove_code_signature();
    let bytes = txn.commit().expect("commit");
    let reparsed = macho::parse(&bytes).expect("reparse");
    let unsigned = reparsed
        .first_macho()
        .expect("test container contains a Mach-O image");

    let plan = ResignPlan::from_mach(unsigned);
    assert!(!plan.was_signed);
    assert!(plan.identifier.is_none());
    assert!(!plan.has_cms_signature);
    assert!(format!("{plan}").contains("no re-signing needed"));
}

#[test]
fn resign_plan_reports_unreadable_signature_as_signed() {
    let data = malformed_codesign_binary();
    let container = parse(&data).expect("parse malformed binary");
    let macho = container
        .first_macho()
        .expect("test container contains a Mach-O image");

    let plan = ResignPlan::from_mach(macho);
    assert!(
        plan.was_signed,
        "LC_CODE_SIGNATURE should still count as signed"
    );
    assert!(plan.signature_parse_error.is_some());
    assert!(format!("{plan}").contains("Signature parse error"));
}
