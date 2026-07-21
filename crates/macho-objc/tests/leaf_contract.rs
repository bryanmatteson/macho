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

    let metadata_from_vec =
        macho_objc::parse_objc_metadata_from_source(&bytes).expect("borrowed vector parses");
    assert!(metadata_from_vec.classes.is_empty());

    let raw: &[u8] = &bytes;
    let scan_from_slice =
        macho_objc::scan_objc_metadata_from_source(raw).expect("borrowed slice parses");
    assert!(scan_from_slice.observations.is_empty());

    let imp_count = macho_objc::fold_method_imps_from_source(raw, 0usize, |count, _| {
        *count += 1;
        Ok(())
    })
    .expect("borrowed slice folds method implementations");
    assert_eq!(imp_count, 0);
}

#[test]
fn objc_source_requires_explicit_fat_architecture_selection() {
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

    let error = macho_objc::parse_objc_metadata_from_source(&bytes)
        .expect_err("fat source must require architecture selection");
    assert_eq!(error.kind, macho_objc::ObjcErrorKind::Unsupported);
}
