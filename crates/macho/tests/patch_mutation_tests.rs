#![cfg(feature = "cli")]

mod support;

use macho::model::container::MachoContainer;
use support::{run_cli, temp_file_path, write_macho_fixture};

fn stdout_json(output: &support::CliOutput) -> serde_json::Value {
    assert!(
        output.status.success(),
        "command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("JSON report")
}

fn arm64e_far_detour_fixture(destination_instruction: u32) -> Vec<u8> {
    let mut bytes = macho_test_support::disassembly_arm64e();
    // Replace LC_SYMTAB with a tiny executable segment beyond B's signed
    // 28-bit byte range. It fits in existing load-command slack.
    let far_file_offset = bytes.len() as u64;
    bytes.extend_from_slice(&destination_instruction.to_le_bytes());
    let command = 32 + (72 + 80);
    bytes[20..24].copy_from_slice(&224_u32.to_le_bytes());
    bytes[command..command + 72].fill(0);
    bytes[command..command + 4].copy_from_slice(&0x19_u32.to_le_bytes());
    bytes[command + 4..command + 8].copy_from_slice(&72_u32.to_le_bytes());
    bytes[command + 8..command + 13].copy_from_slice(b"__FAR");
    bytes[command + 24..command + 32].copy_from_slice(&0x1_1000_0100_u64.to_le_bytes());
    bytes[command + 32..command + 40].copy_from_slice(&4_u64.to_le_bytes());
    bytes[command + 40..command + 48].copy_from_slice(&far_file_offset.to_le_bytes());
    bytes[command + 48..command + 56].copy_from_slice(&4_u64.to_le_bytes());
    bytes[command + 56..command + 60].copy_from_slice(&5_u32.to_le_bytes());
    bytes[command + 60..command + 64].copy_from_slice(&5_u32.to_le_bytes());
    bytes
}

#[test]
fn file_section_is_reparsed_and_preview_reports_final_placement() {
    let input_bytes = macho_test_support::signable_thin64_x86_64(2);
    let input = write_macho_fixture(&input_bytes, "section-input", true);
    let payload_path = temp_file_path("section-payload");
    let output_path = temp_file_path("section-output");
    std::fs::write(&payload_path, [0xde, 0xad, 0xbe, 0xef]).expect("payload");

    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--add-section",
        &format!(
            "__LINKEDIT,__meta,3,{}",
            payload_path.to_str().expect("path")
        ),
        "--output",
        output_path.to_str().expect("path"),
    ]);
    let report = stdout_json(&output);
    let detail = &report["data"]["previews"][0]["operation_details"][0];
    assert_eq!(detail["kind"], "section");
    assert_eq!(detail["alignment_exponent"], 3);
    assert_eq!(detail["size"], 4);
    assert_eq!(detail["section_type"], "S_REGULAR");

    let bytes = std::fs::read(&output_path).expect("output");
    let container = macho::parse(&bytes).expect("reparse output");
    let mach = container.first_macho().expect("image");
    let section = mach
        .segments()
        .iter()
        .find(|segment| segment.name() == "__LINKEDIT")
        .and_then(|segment| {
            segment
                .sections()
                .iter()
                .find(|section| section.section_name() == "__meta")
        })
        .expect("added section");
    let start = section.offset().as_usize();
    assert_eq!(&bytes[start..start + 4], &[0xde, 0xad, 0xbe, 0xef]);
    assert_eq!(&bytes[0x400..0x410], &input_bytes[0x400..0x410]);
    assert_eq!(&bytes[0x1000..0x1010], &input_bytes[0x1000..0x1010]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&output_path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
    }

    let _ = std::fs::remove_file(payload_path);
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn selected_fat_section_rebuild_preserves_nonselected_slice() {
    let x86 = macho_test_support::signable_thin64_x86_64(2);
    let arm = macho_test_support::signable_thin64_arm64(2);
    let fat_bytes = macho_test_support::fat32(&[
        (macho_test_support::CPU_TYPE_X86_64, 3, x86),
        (macho_test_support::CPU_TYPE_ARM64, 0, arm),
    ]);
    let input = write_macho_fixture(&fat_bytes, "section-fat-input", false);
    let output_path = temp_file_path("section-fat-output");
    let before = macho::parse(&fat_bytes).expect("before");
    let MachoContainer::Fat(before) = before else {
        panic!("fat fixture")
    };
    let arm_before = before.arches()[1].macho().bytes().to_vec();

    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--arch",
        "x86_64",
        "--add-zerofill-section",
        "__LINKEDIT,__scratch,4,0x20",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes = std::fs::read(&output_path).expect("output");
    let after = macho::parse(&bytes).expect("after");
    let MachoContainer::Fat(after) = after else {
        panic!("fat output")
    };
    assert_eq!(after.arches()[1].macho().bytes(), arm_before);
    assert!(
        after.arches()[0]
            .macho()
            .all_sections()
            .any(|section| section.section_name() == "__scratch")
    );
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn zero_fill_dry_run_never_writes_and_reports_no_file_offset() {
    let input = write_macho_fixture(
        &macho_test_support::signable_thin64_x86_64(2),
        "zerofill-input",
        false,
    );
    let output_path = temp_file_path("zerofill-output");
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--add-zerofill-section",
        "__LINKEDIT,__scratch,4,0x20",
        "--output",
        output_path.to_str().expect("path"),
        "--dry-run",
    ]);
    let report = stdout_json(&output);
    assert_eq!(report["data"]["written"], false);
    assert_eq!(
        report["data"]["previews"][0]["operation_details"][0]["file_offset"],
        serde_json::Value::Null
    );
    assert!(!output_path.exists());
}

#[test]
fn section_refuses_duplicate_invalid_alignment_and_no_slack() {
    let input = write_macho_fixture(
        &macho_test_support::signable_thin64_x86_64(2),
        "section-refusal",
        false,
    );
    for spec in ["__TEXT,__text,0,1", "__LINKEDIT,__x,32,1"] {
        let output = run_cli([
            "patch",
            input.path().to_str().expect("path"),
            "--add-zerofill-section",
            spec,
            "--dry-run",
        ]);
        assert!(!output.status.success(), "unexpected success for {spec}");
    }

    let no_slack = write_macho_fixture(
        &macho_test_support::thin64_x86_64_with_symbols(&[]),
        "section-no-slack",
        false,
    );
    let output = run_cli([
        "patch",
        no_slack.path().to_str().expect("path"),
        "--add-zerofill-section",
        "__TEXT,__extra,0,1",
        "--dry-run",
    ]);
    assert!(!output.status.success());

    let mut duplicate_bytes = macho_test_support::signable_thin64_x86_64(2);
    let second_segment_name = 32 + (72 + 80) + 8;
    duplicate_bytes[second_segment_name..second_segment_name + 16].fill(0);
    duplicate_bytes[second_segment_name..second_segment_name + 6].copy_from_slice(b"__TEXT");
    let duplicate = write_macho_fixture(&duplicate_bytes, "duplicate-segment", false);
    let output = run_cli([
        "patch",
        duplicate.path().to_str().expect("path"),
        "--add-zerofill-section",
        "__TEXT,__extra,0,1",
        "--dry-run",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("ambiguous"));
}

#[test]
fn missing_segment_name_creates_a_reparseable_aligned_segment() {
    let input = write_macho_fixture(
        &macho_test_support::signable_thin64_x86_64(2),
        "new-segment-input",
        false,
    );
    let output_path = temp_file_path("new-segment-output");
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--add-zerofill-section",
        "__NEW,__scratch,4,0x20",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    let report = stdout_json(&output);
    assert_eq!(report["data"]["written"], true);

    let bytes = std::fs::read(&output_path).expect("output");
    let container = macho::parse(&bytes).expect("reparse output");
    let macho = container.first_macho().expect("image");
    let segment = macho
        .segments()
        .iter()
        .find(|segment| segment.name() == "__NEW")
        .expect("new segment");
    let section = segment
        .sections()
        .iter()
        .find(|section| section.section_name() == "__scratch")
        .expect("new section");
    assert_eq!(section.size(), 0x20);
    assert_eq!(section.offset().as_usize(), 0);
    assert_eq!(segment.vm_addr().0 % 0x1000, 0);
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn valid_multi_instruction_x86_detour_uses_exact_planner_bytes() {
    let input_bytes = macho_test_support::signable_thin64_x86_64(2);
    let input = write_macho_fixture(&input_bytes, "detour-input", false);
    let output_path = temp_file_path("detour-output");
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000400,0x100000420,8",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    let report = stdout_json(&output);
    let detail = &report["data"]["previews"][0]["operation_details"][0];
    assert_eq!(detail["encoding"], "x86_64_relative");
    assert_eq!(detail["entry_offset"], 0x400);
    assert_eq!(detail["instruction_count"], 3);
    assert_eq!(detail["original_bytes"], "554889e54883ec20");
    assert_eq!(detail["replacement_bytes"], "e91b0000000f1f00");

    let output_bytes = std::fs::read(&output_path).expect("output");
    assert_eq!(
        &output_bytes[0x400..0x408],
        &[0xe9, 0x1b, 0, 0, 0, 0x0f, 0x1f, 0]
    );
    assert_eq!(&output_bytes[..0x400], &input_bytes[..0x400]);
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn arm64e_detour_preview_carries_compatible_pac_assessment() {
    let input = write_macho_fixture(
        &macho_test_support::disassembly_arm64e(),
        "arm64e-detour-pac",
        false,
    );
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000100,0x100000104,4",
        "--pac-policy",
        "require",
        "--dry-run",
    ]);
    let report = stdout_json(&output);
    let detail = &report["data"]["previews"][0]["operation_details"][0];
    assert_eq!(detail["arch"], "arm64e");
    assert_eq!(detail["pac"]["verdict"], "compatible");
    assert_eq!(detail["pac"]["findings"], serde_json::json!([]));
}

#[test]
fn arm64e_detour_can_explicitly_disable_pac_reporting() {
    let input = write_macho_fixture(
        &macho_test_support::disassembly_arm64e(),
        "arm64e-detour-pac-off",
        false,
    );
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000100,0x100000104,4",
        "--pac-policy",
        "off",
        "--dry-run",
    ]);
    let report = stdout_json(&output);
    let detail = &report["data"]["previews"][0]["operation_details"][0];
    assert!(detail.get("pac").is_none());
}

#[test]
fn arm64e_detour_preserves_existing_bti_entry_contract() {
    let mut bytes = macho_test_support::disassembly_arm64e();
    bytes[0x100..0x104].copy_from_slice(&0xD503_245F_u32.to_le_bytes()); // bti c
    let input = write_macho_fixture(&bytes, "arm64e-detour-bti", false);
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000100,0x100000120,8",
        "--pac-policy",
        "require",
        "--dry-run",
    ]);
    let report = stdout_json(&output);
    let detail = &report["data"]["previews"][0]["operation_details"][0];
    assert!(
        detail["replacement_bytes"]
            .as_str()
            .unwrap()
            .starts_with("5f2403d5")
    );
    assert_eq!(detail["pac"]["source_contract"]["bti"], "call");
    assert_eq!(detail["pac"]["mechanism"]["preserves_entry_bti"], true);
    assert_eq!(detail["pac"]["verdict"], "compatible");
}

#[test]
fn arm64e_required_policy_rejects_lost_return_address_contract() {
    let mut bytes = macho_test_support::disassembly_arm64e();
    bytes[0x100..0x104].copy_from_slice(&0xD503_233F_u32.to_le_bytes()); // paciasp
    let input = write_macho_fixture(&bytes, "arm64e-detour-return-contract", false);
    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000100,0x100000108,4",
        "--pac-policy",
        "require",
        "--dry-run",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pac.detour.return_address_contract_not_preserved"),
        "{stderr}"
    );
}

#[test]
fn arm64e_required_pac_policy_rejects_far_destination_without_bti() {
    let bytes = arm64e_far_detour_fixture(0xD503_201F); // nop
    let input = write_macho_fixture(&bytes, "arm64e-detour-pac-far", false);
    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000100,0x110000100,20",
        "--pac-policy",
        "require",
        "--dry-run",
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("pac.detour.indirect_destination_bti_unproven"),
        "{stderr}"
    );
}

#[test]
fn arm64e_required_pac_policy_accepts_materialized_far_jump_to_bti() {
    let bytes = arm64e_far_detour_fixture(0xD503_249F); // bti j
    let input = write_macho_fixture(&bytes, "arm64e-detour-pac-far-bti", false);
    let output = run_cli([
        "patch",
        "--format",
        "json",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000100,0x110000100,20",
        "--pac-policy",
        "require",
        "--dry-run",
    ]);
    let report = stdout_json(&output);
    let detail = &report["data"]["previews"][0]["operation_details"][0];
    assert_eq!(detail["encoding"], "arm64e_materialized_address");
    assert_eq!(detail["pac"]["verdict"], "compatible");
    assert_eq!(detail["pac"]["destination_contract"]["bti"], "jump");
}

#[test]
fn x86_detour_refuses_mid_instruction_and_undecodable_windows() {
    let input = write_macho_fixture(
        &macho_test_support::signable_thin64_x86_64(2),
        "detour-mid-instruction",
        false,
    );
    let output_path = temp_file_path("detour-mid-instruction-output");
    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--detour",
        "0x100000400,0x100000420,6",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a complete instruction sequence"),
        "{stderr}"
    );
    assert!(stderr.contains("VA 0x100000404"), "{stderr}");
    assert!(stderr.contains("file offset 0x404"), "{stderr}");
    assert!(!output_path.exists());

    let mut invalid_bytes = macho_test_support::signable_thin64_x86_64(2);
    invalid_bytes[0x400] = 0x06;
    let invalid = write_macho_fixture(&invalid_bytes, "detour-undecodable", false);
    let invalid_output_path = temp_file_path("detour-undecodable-output");
    let output = run_cli([
        "patch",
        invalid.path().to_str().expect("path"),
        "--detour",
        "0x100000400,0x100000420,8",
        "--output",
        invalid_output_path.to_str().expect("path"),
    ]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("decode failed at VA 0x100000400"),
        "{stderr}"
    );
    assert!(stderr.contains("file offset 0x400"), "{stderr}");
    assert!(!invalid_output_path.exists());
}

#[test]
fn detour_refuses_unaligned_small_non_executable_and_fat_family_selection() {
    let arm = write_macho_fixture(
        &macho_test_support::signable_thin64_arm64(2),
        "detour-arm",
        false,
    );
    for spec in [
        "0x100000401,0x100000440,4",
        "0x100000400,0x100000440,2",
        "0x100001000,0x100000440,4",
    ] {
        let output = run_cli([
            "patch",
            arm.path().to_str().expect("path"),
            "--detour",
            spec,
            "--dry-run",
        ]);
        assert!(!output.status.success(), "unexpected success for {spec}");
    }

    let fat = write_macho_fixture(
        &macho_test_support::fat32(&[
            (
                macho_test_support::CPU_TYPE_X86_64,
                3,
                macho_test_support::signable_thin64_x86_64(2),
            ),
            (
                macho_test_support::CPU_TYPE_ARM64,
                macho_test_support::CPU_SUBTYPE_ARM64E,
                macho_test_support::signable_thin64_arm64(2),
            ),
        ]),
        "detour-fat",
        false,
    );
    let no_arch = run_cli([
        "patch",
        fat.path().to_str().expect("path"),
        "--detour",
        "0x100000400,0x100000420,8",
        "--dry-run",
    ]);
    assert!(!no_arch.status.success());
    assert!(String::from_utf8_lossy(&no_arch.stderr).contains("requires --arch"));

    let family = run_cli([
        "patch",
        fat.path().to_str().expect("path"),
        "--arch",
        "arm64",
        "--detour",
        "0x100000400,0x100000440,4",
        "--dry-run",
    ]);
    assert!(!family.status.success());
    assert!(String::from_utf8_lossy(&family.stderr).contains("one exact --arch"));

    let unsupported = write_macho_fixture(
        &macho_test_support::thin64_unknown_cpu(2),
        "detour-unsupported",
        false,
    );
    let output = run_cli([
        "patch",
        unsupported.path().to_str().expect("path"),
        "--detour",
        "0x100000000,0x100000004,4",
        "--dry-run",
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unsupported"));
}

#[test]
fn raw_bytes_expected_original_mismatch_fails_before_write() {
    let input = write_macho_fixture(
        &macho_test_support::signable_thin64_x86_64(2),
        "raw-precondition",
        false,
    );
    let output_path = temp_file_path("raw-precondition-output");
    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--bytes",
        "0x400,00000000,90909090",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("expected original bytes"));
    assert!(!output_path.exists());
}

#[test]
fn selected_fat_detour_preserves_nonselected_slice() {
    let x86 = macho_test_support::signable_thin64_x86_64(2);
    let arm = macho_test_support::signable_thin64_arm64(2);
    let fat_bytes = macho_test_support::fat32(&[
        (macho_test_support::CPU_TYPE_X86_64, 3, x86),
        (
            macho_test_support::CPU_TYPE_ARM64,
            macho_test_support::CPU_SUBTYPE_ARM64E,
            arm,
        ),
    ]);
    let input = write_macho_fixture(&fat_bytes, "detour-fat-preserve", false);
    let output_path = temp_file_path("detour-fat-preserve-output");
    let before = macho::parse(&fat_bytes).expect("parse before");
    let MachoContainer::Fat(before) = before else {
        panic!("fat fixture")
    };
    let arm_before = before.arches()[1].macho().bytes().to_vec();

    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--arch",
        "x86_64",
        "--detour",
        "0x100000400,0x100000420,8",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output_bytes = std::fs::read(&output_path).expect("output");
    let after = macho::parse(&output_bytes).expect("parse after");
    let MachoContainer::Fat(after) = after else {
        panic!("fat output")
    };
    assert_eq!(after.arches()[1].macho().bytes(), arm_before);
    assert_eq!(
        &after.arches()[0].macho().bytes()[0x400..0x408],
        &[0xe9, 0x1b, 0, 0, 0, 0x0f, 0x1f, 0]
    );
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn selected_fat_detour_accepts_case_insensitive_exact_architecture() {
    let x86 = macho_test_support::signable_thin64_x86_64(2);
    let arm = macho_test_support::signable_thin64_arm64(2);
    let fat_bytes = macho_test_support::fat32(&[
        (macho_test_support::CPU_TYPE_X86_64, 3, x86),
        (
            macho_test_support::CPU_TYPE_ARM64,
            macho_test_support::CPU_SUBTYPE_ARM64E,
            arm,
        ),
    ]);
    let input = write_macho_fixture(&fat_bytes, "detour-fat-uppercase-arch", false);
    let output = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--arch",
        "X86_64",
        "--detour",
        "0x100000400,0x100000420,8",
        "--dry-run",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn fat_raw_bytes_require_exact_arch_and_preserve_nonselected_slice() {
    let ordinary = macho_test_support::signable_thin64_arm64(2);
    let arm64e = macho_test_support::signable_thin64_arm64(2);
    let family_bytes = macho_test_support::fat32(&[
        (macho_test_support::CPU_TYPE_ARM64, 0, ordinary),
        (
            macho_test_support::CPU_TYPE_ARM64,
            macho_test_support::CPU_SUBTYPE_ARM64E,
            arm64e,
        ),
    ]);
    let family = write_macho_fixture(&family_bytes, "raw-fat-family", false);
    let refused = run_cli([
        "patch",
        family.path().to_str().expect("path"),
        "--arch",
        "arm64",
        "--bytes",
        "0x400,1f2003d5,00000000",
        "--dry-run",
    ]);
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("one exact --arch"));

    let x86 = macho_test_support::signable_thin64_x86_64(2);
    let arm = macho_test_support::signable_thin64_arm64(2);
    let fat_bytes = macho_test_support::fat32(&[
        (macho_test_support::CPU_TYPE_X86_64, 3, x86),
        (macho_test_support::CPU_TYPE_ARM64, 0, arm),
    ]);
    let input = write_macho_fixture(&fat_bytes, "raw-fat-preserve", false);
    let output_path = temp_file_path("raw-fat-preserve-output");
    let before = macho::parse(&fat_bytes).expect("before");
    let MachoContainer::Fat(before) = before else {
        panic!("fat fixture")
    };
    let arm_before = before.arches()[1].macho().bytes().to_vec();
    let patched = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--arch",
        "x86_64",
        "--bytes",
        "0x400,554889e5,90909090",
        "--output",
        output_path.to_str().expect("path"),
    ]);
    assert!(
        patched.status.success(),
        "{}",
        String::from_utf8_lossy(&patched.stderr)
    );
    let output_bytes = std::fs::read(&output_path).expect("output");
    let after = macho::parse(&output_bytes).expect("after");
    let MachoContainer::Fat(after) = after else {
        panic!("fat output")
    };
    assert_eq!(after.arches()[1].macho().bytes(), arm_before);
    assert_eq!(&after.arches()[0].macho().bytes()[0x400..0x404], &[0x90; 4]);
    let _ = std::fs::remove_file(output_path);
}

#[test]
fn signed_mutation_reports_invalidation_or_verified_resigning() {
    let input = write_macho_fixture(
        &macho_test_support::signable_thin64_x86_64(2),
        "signature-input",
        false,
    );
    let signed_path = temp_file_path("signature-signed");
    let sign = run_cli([
        "patch",
        input.path().to_str().expect("path"),
        "--sign-adhoc",
        "--output",
        signed_path.to_str().expect("path"),
    ]);
    assert!(
        sign.status.success(),
        "{}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let invalidated = run_cli([
        "patch",
        "--format",
        "json",
        signed_path.to_str().expect("path"),
        "--add-zerofill-section",
        "__LINKEDIT,__scratch,0,1",
        "--dry-run",
    ]);
    let report = stdout_json(&invalidated);
    assert_eq!(
        report["data"]["previews"][0]["preview"]["signature_outcome"],
        "invalidated"
    );
    let resign_plan = &report["data"]["previews"][0]["preview"]["resign_plan"];
    let suggested = resign_plan["suggested_command"]
        .as_str()
        .expect("candidate-oriented signing command");
    assert!(suggested.contains("<patched-binary>"));
    assert!(suggested.contains("--output <signed-binary>"));
    assert!(!suggested.contains("--in-place"));
    assert!(
        resign_plan["manual_steps"]
            .as_array()
            .expect("manual steps")
            .iter()
            .any(|step| step
                .as_str()
                .is_some_and(|step| step.contains("does not apply the pending mutation")))
    );

    let resigned_path = temp_file_path("signature-resigned");
    let resigned = run_cli([
        "patch",
        "--format",
        "json",
        signed_path.to_str().expect("path"),
        "--add-zerofill-section",
        "__LINKEDIT,__scratch,0,1",
        "--sign-adhoc",
        "--output",
        resigned_path.to_str().expect("path"),
    ]);
    let report = stdout_json(&resigned);
    assert_eq!(
        report["data"]["previews"][0]["preview"]["signature_outcome"],
        "signed_ad_hoc"
    );
    assert_eq!(report["data"]["signing"]["verified"], true);
    macho::parse(&std::fs::read(&resigned_path).expect("resigned output"))
        .expect("resigned output reparses");

    let _ = std::fs::remove_file(signed_path);
    let _ = std::fs::remove_file(resigned_path);
}
