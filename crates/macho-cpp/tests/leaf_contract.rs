//! Leaf contract: `macho-cpp` works without the `macho` façade.

#[test]
fn cpp_leaf_operates_directly_on_core_models_without_the_facade() {
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "_main",
            external: true,
            defined: true,
        },
    ]);
    let container = macho_core::parse(&bytes).expect("shared fixture parses");
    let image = container.first_macho().expect("thin image");

    let vtables = macho_cpp::VtableIndex::build(image).expect("symtab image builds");
    assert!(vtables.vtables().is_empty());

    let typeinfo = macho_cpp::build_typeinfo_index(image).expect("symtab image builds");
    assert!(typeinfo.is_empty());
}
