//! Invalid-input regression tests.
//!
//! Each test feeds a hand-crafted malformed buffer into a parser and asserts
//! that the result is `Err(_)` — never a panic, never silent success. These
//! tests codify the WU1 safety contract: untrusted bytes produce typed errors.

#[test]
fn fat_binary_too_small_is_error() {
    // 4 bytes only — smaller than the 8-byte fat header.
    let data = [0xCA, 0xFE, 0xBA, 0xBE];
    let result = macho_core::format::fat::parse_fat_binary(&data);
    assert!(result.is_err());
}

#[test]
fn fat_binary_zero_arches_is_error() {
    // Fat magic with nfat_arch = 0 should be rejected.
    let mut data = Vec::new();
    data.extend_from_slice(&0xCAFE_BABEu32.to_be_bytes()); // magic
    data.extend_from_slice(&0u32.to_be_bytes()); // nfat_arch = 0
    let result = macho_core::format::fat::parse_fat_binary(&data);
    assert!(result.is_err());
}

#[test]
fn fat_binary_duplicate_architectures_are_rejected() {
    let data = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::thin64_arm64(2),
        ),
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::thin64_arm64(2),
        ),
    ]);

    let error = macho_core::format::fat::parse_fat_binary(&data).unwrap_err();
    assert_eq!(error.kind, macho_core::ParseErrorKind::InvalidFormat);
    assert!(error.message().contains("duplicate fat architecture"));
}

#[test]
fn fat_binary_misaligned_slice_is_rejected() {
    let mut data = macho_test_support::fat32(&[(
        macho_test_support::CPU_TYPE_ARM64,
        0,
        macho_test_support::thin64_arm64(2),
    )]);
    data[24..28].copy_from_slice(&13u32.to_be_bytes());

    let error = macho_core::format::fat::parse_fat_binary(&data).unwrap_err();
    assert_eq!(error.kind, macho_core::ParseErrorKind::InvalidFormat);
    assert!(error.message().contains("is not aligned"));
}
