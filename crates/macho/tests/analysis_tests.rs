use macho::analysis::container::ext::MachoContainerExt;
use macho::analysis::snapshot::{ContainerFormat, ContainerSnapshot};

fn snapshot_for(path: &str) -> ContainerSnapshot {
    let data = std::fs::read(path).expect("read binary");
    let container = macho::parse(&data).expect("parse");
    ContainerSnapshot::from_container(&container)
}

fn malformed_codesign_binary() -> Vec<u8> {
    const MH_MAGIC_64: u32 = 0xFEEDFACF;
    const CPU_TYPE_ARM64: u32 = 0x0100000C;
    const MH_EXECUTE: u32 = 2;
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_CODE_SIGNATURE: u32 = 0x1D;

    let code_sig_offset = 32u32 + 72 + 16;
    let code_sig_size = 8u32;
    let total_size = code_sig_offset + code_sig_size;

    let mut buf = Vec::new();

    buf.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
    buf.extend_from_slice(&(CPU_TYPE_ARM64 as i32).to_le_bytes());
    buf.extend_from_slice(&0i32.to_le_bytes());
    buf.extend_from_slice(&MH_EXECUTE.to_le_bytes());
    buf.extend_from_slice(&2u32.to_le_bytes());
    buf.extend_from_slice(&88u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf.extend_from_slice(&LC_SEGMENT_64.to_le_bytes());
    buf.extend_from_slice(&72u32.to_le_bytes());
    let mut segname = [0u8; 16];
    segname[..6].copy_from_slice(b"__TEXT");
    buf.extend_from_slice(&segname);
    buf.extend_from_slice(&0x1000_0000u64.to_le_bytes());
    buf.extend_from_slice(&0x1000u64.to_le_bytes());
    buf.extend_from_slice(&0u64.to_le_bytes());
    buf.extend_from_slice(&(total_size as u64).to_le_bytes());
    buf.extend_from_slice(&5i32.to_le_bytes());
    buf.extend_from_slice(&5i32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());
    buf.extend_from_slice(&0u32.to_le_bytes());

    buf.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes());
    buf.extend_from_slice(&16u32.to_le_bytes());
    buf.extend_from_slice(&code_sig_offset.to_le_bytes());
    buf.extend_from_slice(&code_sig_size.to_le_bytes());

    buf.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0, 1, 2, 3]);
    assert_eq!(buf.len(), total_size as usize);
    buf
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

#[test]
fn snapshot_fat_binary_has_multiple_slices() {
    let data = std::fs::read("/usr/bin/true").expect("read binary");
    let container = macho::parse(&data).expect("parse");
    let snap = ContainerSnapshot::from_container(&container);

    // /usr/bin/true is a fat (universal) binary
    assert!(matches!(snap.format, ContainerFormat::Fat));
    assert!(snap.slices.len() >= 2);
}

#[test]
fn snapshot_contains_header_data() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        assert!(!slice.header.cpu_type.is_empty());
        assert!(!slice.header.file_type.is_empty());
        assert!(slice.header.ncmds > 0);
    }
}

#[test]
fn snapshot_contains_load_commands() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        assert!(!slice.load_commands.is_empty());
        // Every binary should have at least a segment
        assert!(
            slice
                .load_commands
                .iter()
                .any(|lc| lc.name.contains("LC_SEGMENT"))
        );
    }
}

#[test]
fn snapshot_contains_segments() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        assert!(!slice.segments.is_empty());
        // Should have __TEXT and __LINKEDIT at minimum
        assert!(slice.segments.iter().any(|s| s.name == "__TEXT"));
        assert!(slice.segments.iter().any(|s| s.name == "__LINKEDIT"));
    }
}

#[test]
fn snapshot_contains_codesign() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        let cs = slice.codesign.as_ref().expect("should be signed");
        assert!(cs.identifier.is_some());
        assert!(!cs.hash_type.is_empty());
        assert_eq!(
            cs.has_entitlements,
            cs.entitlements_xml.is_some() || cs.has_der_entitlements
        );
    }
}

#[test]
fn snapshot_contains_chained_fixups() {
    let snap = snapshot_for("/usr/bin/plutil");
    assert!(
        snap.slices.iter().any(|slice| !slice.fixups.is_empty()),
        "expected at least one chained fixup in plutil snapshot"
    );
}

#[test]
fn snapshot_uuid_is_present() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        assert!(slice.header.uuid.is_some(), "UUID should be present");
    }
}

#[test]
fn snapshot_diagnostics_empty_for_system_binary() {
    let snap = snapshot_for("/usr/bin/true");
    for slice in &snap.slices {
        assert!(
            slice.diagnostics.is_empty(),
            "system binary should have no validation errors"
        );
    }
}

#[test]
fn snapshot_serializes_to_json() {
    let snap = snapshot_for("/usr/bin/true");
    let json = serde_json::to_string(&snap).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("deserialize");
    assert!(parsed["slices"].is_array());
    assert!(parsed["format"].is_string());
    assert!(parsed["slices"][0]["fixups"].is_array());
}

#[test]
fn available_arches_returns_all_arch_names() {
    let snap = snapshot_for("/usr/bin/true");
    let arches = snap.available_arches();
    assert!(arches.len() >= 2);
    // Should contain at least arm64e and x86_64 for a universal binary
    assert!(arches.iter().any(|a| a.contains("arm64")));
    assert!(arches.iter().any(|a| a.contains("x86_64")));
}

#[test]
fn container_format_display() {
    assert_eq!(ContainerFormat::Thin.to_string(), "Thin");
    assert_eq!(ContainerFormat::Fat.to_string(), "Fat");
    assert_eq!(ContainerFormat::Fileset.to_string(), "Fileset");
}

#[test]
fn snapshot_records_codesign_analysis_issues() {
    let data = malformed_codesign_binary();
    let container = macho::parse(&data).expect("parse");
    let snap = ContainerSnapshot::from_container(&container);
    let slice = &snap.slices[0];

    assert!(
        slice.codesign.is_none(),
        "invalid signature should not parse"
    );

    let issue = slice
        .analysis_issues
        .iter()
        .find(|issue| issue.component == "codesign")
        .expect("expected a code-signature analysis issue");

    assert!(
        issue.message.contains("failed to parse code signature"),
        "unexpected issue: {}",
        issue.message
    );
}

#[test]
fn snapshot_contains_fileset_entry_details() {
    let data = minimal_fileset_binary("com.example.member", 0x1000_0000, 0x2000);
    let container = macho::parse(&data).expect("parse");
    let snap = ContainerSnapshot::from_container(&container);
    assert_eq!(snap.format, ContainerFormat::Fileset);
    let slice = &snap.slices[0];

    let lc = slice
        .load_commands
        .iter()
        .find(|lc| lc.name == "LC_FILESET_ENTRY")
        .expect("expected LC_FILESET_ENTRY");
    let entry = lc
        .fileset_entry
        .as_ref()
        .expect("expected fileset entry details");

    assert_eq!(entry.entry_id, "com.example.member");
    assert_eq!(entry.vm_addr, 0x1000_0000);
    assert_eq!(entry.file_offset, 0x2000);
}

#[test]
fn container_all_signed_tracks_codesign_state() {
    let data = malformed_codesign_binary();
    let container = macho::parse(&data).expect("parse");

    assert!(
        !container.all_signed(),
        "malformed signature should count as unsigned at the container surface"
    );
}
