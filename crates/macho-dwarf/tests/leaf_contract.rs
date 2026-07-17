#[test]
fn dwarf_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_arm64(0);
    let container = macho_core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    assert!(!macho_dwarf::has_dwarf_sections(image));
    assert!(
        macho_dwarf::load_dwarf(image)
            .expect("absence is not failure")
            .is_none()
    );
}
