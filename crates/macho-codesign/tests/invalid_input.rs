//! Invalid-input regression tests for code-signature parsing.

use macho_codesign::superblob::parse_super_blob;

#[test]
fn super_blob_bad_magic_is_error() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
    data.extend_from_slice(&12u32.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    assert!(parse_super_blob(&data).is_err());
}

#[test]
fn super_blob_count_overflows_is_error() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xFADE_0CC0u32.to_be_bytes());
    data.extend_from_slice(&12u32.to_be_bytes());
    data.extend_from_slice(&u32::MAX.to_be_bytes());
    assert!(parse_super_blob(&data).is_err());
}

#[test]
fn super_blob_truncated_index_is_error() {
    let mut data = Vec::new();
    data.extend_from_slice(&0xFADE_0CC0u32.to_be_bytes());
    data.extend_from_slice(&12u32.to_be_bytes());
    data.extend_from_slice(&10u32.to_be_bytes());
    assert!(parse_super_blob(&data).is_err());
}
