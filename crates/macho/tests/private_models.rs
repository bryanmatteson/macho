#[test]
fn parsed_model_fields_are_not_public_construction_paths() {
    let cases = trybuild::TestCases::new();
    cases.compile_fail("tests/ui/private_parsed_models.rs");
}
