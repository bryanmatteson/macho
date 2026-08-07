#![cfg(feature = "cli")]

mod support;

use support::{run_cli, write_macho_fixture};

fn pac_fixture() -> Vec<u8> {
    let mut bytes = macho_test_support::disassembly_arm64e();
    bytes[0x100..0x104].copy_from_slice(&0xD503_233Fu32.to_le_bytes());
    bytes[0x104..0x108].copy_from_slice(&0xD73F_0B21u32.to_le_bytes());
    bytes[0x108..0x10c].copy_from_slice(&0xD65F_0BFFu32.to_le_bytes());
    bytes[0x10c..0x110].copy_from_slice(&0xDAC1_10A4_u32.to_le_bytes());
    bytes[0x110..0x114].copy_from_slice(&0xD61F_0080_u32.to_le_bytes());
    bytes
}

fn authenticated_pointer_fixture() -> Vec<u8> {
    const CHAINED_FIXUPS_OFFSET: usize = 0x1000;
    const CHAINED_FIXUPS_SIZE: u32 = 60;
    const POINTER_OFFSET: usize = 0x120;

    let mut bytes = macho_test_support::disassembly_arm64e();

    // Replace LC_SYMTAB with LC_DYLD_CHAINED_FIXUPS. The original command is
    // eight bytes larger, so the existing load-command area remains sufficient.
    bytes[20..24].copy_from_slice(&168u32.to_le_bytes());
    bytes[184..188].copy_from_slice(&0x8000_0034u32.to_le_bytes());
    bytes[188..192].copy_from_slice(&16u32.to_le_bytes());
    bytes[192..196].copy_from_slice(&(CHAINED_FIXUPS_OFFSET as u32).to_le_bytes());
    bytes[196..200].copy_from_slice(&CHAINED_FIXUPS_SIZE.to_le_bytes());
    bytes[200..208].fill(0);

    // One arm64e authenticated rebase at __TEXT+0x120. Key 2 is DA; both
    // constant diversity 0x1234 and address diversity participate in the PAC.
    let encoded_pointer = 0x130u64 | (0x1234u64 << 32) | (1u64 << 48) | (2u64 << 49) | (1u64 << 63);
    bytes[POINTER_OFFSET..POINTER_OFFSET + 8].copy_from_slice(&encoded_pointer.to_le_bytes());

    bytes.resize(CHAINED_FIXUPS_OFFSET, 0);
    let mut fixups = Vec::with_capacity(CHAINED_FIXUPS_SIZE as usize);
    fixups.extend_from_slice(&0u32.to_le_bytes()); // fixups_version
    fixups.extend_from_slice(&28u32.to_le_bytes()); // starts_offset
    fixups.extend_from_slice(&60u32.to_le_bytes()); // imports_offset
    fixups.extend_from_slice(&60u32.to_le_bytes()); // symbols_offset
    fixups.extend_from_slice(&0u32.to_le_bytes()); // imports_count
    fixups.extend_from_slice(&1u32.to_le_bytes()); // DYLD_CHAINED_IMPORT
    fixups.extend_from_slice(&0u32.to_le_bytes()); // symbols_format
    fixups.extend_from_slice(&1u32.to_le_bytes()); // seg_count
    fixups.extend_from_slice(&8u32.to_le_bytes()); // seg_info_offset[0]
    fixups.extend_from_slice(&24u32.to_le_bytes()); // starts_in_segment.size
    fixups.extend_from_slice(&0x1000u16.to_le_bytes()); // page_size
    fixups.extend_from_slice(&9u16.to_le_bytes()); // DYLD_CHAINED_PTR_ARM64E_USERLAND
    fixups.extend_from_slice(&0u64.to_le_bytes()); // segment_offset from image base
    fixups.extend_from_slice(&0u32.to_le_bytes()); // max_valid_pointer
    fixups.extend_from_slice(&1u16.to_le_bytes()); // page_count
    fixups.extend_from_slice(&(POINTER_OFFSET as u16).to_le_bytes());
    assert_eq!(fixups.len(), CHAINED_FIXUPS_SIZE as usize);
    bytes.extend_from_slice(&fixups);

    let file_size = bytes.len() as u64;
    bytes[64..72].copy_from_slice(&0x2000u64.to_le_bytes());
    bytes[80..88].copy_from_slice(&file_size.to_le_bytes());
    bytes
}

#[test]
fn pac_text_reports_summary_and_requested_sites() {
    let input = write_macho_fixture(&pac_fixture(), "pac-text", false);
    let output = run_cli([
        "pac",
        input.path().to_str().expect("path"),
        "--gadgets",
        "--color",
        "never",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("UTF-8 report");
    assert!(stdout.contains("PAC analysis: arm64e"));
    assert!(stdout.contains("authenticated calls    1"));
    assert!(stdout.contains("PACIASP"));
    assert!(stdout.contains("BLRAA"));
    assert!(stdout.contains("RETAA"));
    assert!(stdout.contains("auth@0x10000010c"));
}

#[test]
fn pac_json_retains_schema_sites_and_completeness() {
    let input = write_macho_fixture(&pac_fixture(), "pac-json", false);
    let output = run_cli([
        "pac",
        input.path().to_str().expect("path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    let data = &report["data"];
    assert_eq!(data["schema_version"], 1);
    assert_eq!(data["architecture"], "arm64e");
    assert_eq!(data["summary"]["authenticated_calls"], 1);
    assert_eq!(data["summary"]["authenticated_returns"], 1);
    assert_eq!(data["summary"]["authenticated_branches"], 1);
    assert_eq!(data["completeness"]["pointer_status"], "absent");
    assert_eq!(data["code_sites"].as_array().unwrap().len(), 5);
    assert!(!data["summary"]["code_keys"].as_array().unwrap().is_empty());
    assert!(data["code_sites"].as_array().unwrap().iter().any(|site| {
        site["evidence"] == "authenticate_then_transfer"
            && site["authentication_address"] == 0x1_0000_010c_u64
    }));
}

#[test]
fn pac_json_recovers_authenticated_chained_pointer_bytes_and_diversity() {
    let input = write_macho_fixture(
        &authenticated_pointer_fixture(),
        "pac-authenticated-pointer",
        false,
    );
    let output = run_cli([
        "pac",
        input.path().to_str().expect("path"),
        "--format",
        "json",
        "--color",
        "never",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON report");
    let data = &report["data"];
    assert_eq!(data["completeness"]["pointer_status"], "complete");
    assert_eq!(data["summary"]["authenticated_pointers"], 1);
    assert_eq!(
        data["summary"]["pointer_keys"],
        serde_json::json!([{"key": "da", "count": 1}])
    );
    assert_eq!(
        data["summary"]["pointer_diversities"],
        serde_json::json!([{
            "key": "da",
            "diversity": 0x1234,
            "address_diversity": true,
            "count": 1
        }])
    );

    let pointers = data["pointers"].as_array().expect("pointer array");
    assert_eq!(pointers.len(), 1);
    let pointer = &pointers[0];
    assert_eq!(pointer["file_offset"], 0x120);
    assert_eq!(pointer["address"], 0x1_0000_0120_u64);
    assert_eq!(pointer["encoding"], "chained_rebase");
    assert_eq!(pointer["chained_pointer_format"], 9);
    assert_eq!(pointer["authentication"]["state"], "authenticated");
    assert_eq!(pointer["authentication"]["key"], "da");
    assert_eq!(pointer["authentication"]["diversity"], 0x1234);
    assert_eq!(pointer["authentication"]["address_diversity"], true);
    assert_eq!(pointer["target"]["kind"], "internal");
    assert_eq!(pointer["target"]["address"], 0x1_0000_0130_u64);
    assert_eq!(
        pointer["stored_bytes"],
        serde_json::json!([48, 1, 0, 0, 52, 18, 5, 128])
    );
}

#[test]
fn pac_rejects_non_arm_images_with_a_typed_failure() {
    let input = write_macho_fixture(&macho_test_support::disassembly_x86_64(), "pac-x86", false);
    let output = run_cli(["pac", input.path().to_str().expect("path")]);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("PAC analysis requires an arm64 or arm64e image")
    );
}
