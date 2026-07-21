//! Leaf contract: `macho-codesign` works without the `macho` façade.

#[test]
fn codesign_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_arm64(0);
    let container = macho_core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    assert!(macho_codesign::parse_code_signature(image).is_err());
}

#[test]
fn codesign_leaf_parses_raw_superblobs_without_the_facade() {
    let empty = macho_test_support::empty_super_blob();
    let blobs = macho_codesign::superblob::parse_super_blob(&empty).expect("empty superblob");
    assert!(blobs.is_empty());
}
