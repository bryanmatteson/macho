//! Leaf contract: `macho-objc` works without the `macho` façade.

#[test]
fn objc_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_arm64(0);
    let container = macho_core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    let metadata = macho_objc::parse_objc_metadata(image).expect("absence is not failure");
    assert!(metadata.classes.is_empty());
    assert!(metadata.categories.is_empty());
    assert!(metadata.protocols.is_empty());

    let scan = macho_objc::scan_objc_metadata(image).expect("scan without lists");
    assert!(scan.observations.is_empty());
}
