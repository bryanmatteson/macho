//! Leaf contract: `macho-swift` works without the `macho` façade.

#[test]
fn swift_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_arm64(0);
    let container = macho_core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    let index = macho_swift::SwiftTypeIndex::build(image);
    assert!(index.types.is_empty());
    assert!(index.parents.is_empty());
    assert!(index.conformances.is_empty());
    assert!(index.associated_types.is_empty());
}
