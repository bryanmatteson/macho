//! Leaf contract: `macho::metadata::swift` works without the `macho` façade.

#[test]
fn swift_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_arm64(0);
    let container = macho::core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    let index = macho::metadata::swift::SwiftTypeIndex::build(image);
    assert!(index.types.is_empty());
    assert!(index.parents.is_empty());
    assert!(index.conformances.is_empty());
    assert!(index.associated_types.is_empty());

    let index_from_vec = macho::metadata::swift::SwiftTypeIndex::build_from_source(&bytes)
        .expect("borrowed vector parses");
    assert!(index_from_vec.types.is_empty());

    let raw: &[u8] = &bytes;
    let index_from_slice = macho::metadata::swift::SwiftTypeIndex::build_from_source(raw)
        .expect("borrowed slice parses");
    assert!(index_from_slice.types.is_empty());
}

#[test]
fn swift_source_requires_explicit_fat_architecture_selection() {
    let bytes = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::thin64_arm64(0),
        ),
        (
            macho_test_support::CPU_TYPE_X86_64,
            3,
            macho_test_support::thin64_x86_64(0),
        ),
    ]);

    let error = macho::metadata::swift::SwiftTypeIndex::build_from_source(&bytes)
        .expect_err("fat source must require architecture selection");
    assert_eq!(
        error.kind,
        macho::metadata::swift::SwiftErrorKind::Unsupported
    );
}
