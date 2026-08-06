//! Leaf contract: `macho::metadata::cpp` works without the `macho` façade.

#[test]
fn cpp_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes =
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        }]);
    let container = macho::core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    let vtables = macho::metadata::cpp::VtableIndex::build(image).expect("symtab image builds");
    assert!(vtables.vtables().is_empty());

    let typeinfo = macho::metadata::cpp::build_typeinfo_index(image).expect("symtab image builds");
    assert!(typeinfo.is_empty());

    let vtables_from_vec = macho::metadata::cpp::VtableIndex::build_from_source(&bytes)
        .expect("borrowed vector parses");
    assert!(vtables_from_vec.vtables().is_empty());

    let raw: &[u8] = &bytes;
    let typeinfo_from_slice =
        macho::metadata::cpp::build_typeinfo_index_from_source(raw).expect("borrowed slice parses");
    assert!(typeinfo_from_slice.is_empty());
}

#[test]
fn cpp_source_requires_explicit_fat_architecture_selection() {
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

    let vtable_error = macho::metadata::cpp::VtableIndex::build_from_source(&bytes)
        .expect_err("fat source must require architecture selection");
    assert_eq!(
        vtable_error.kind,
        macho::metadata::cpp::CppErrorKind::Unsupported
    );

    let typeinfo_error = macho::metadata::cpp::build_typeinfo_index_from_source(&bytes)
        .expect_err("fat source must require architecture selection");
    assert_eq!(
        typeinfo_error.kind,
        macho::metadata::cpp::CppErrorKind::Unsupported
    );
}
