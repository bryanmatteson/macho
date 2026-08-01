use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DomainState, domain_reports};

#[test]
fn facade_consumer_gets_typed_header_symbols_and_xrefs() {
    let bytes =
        macho_test_support::thin64_x86_64_with_symbols(&[macho_test_support::SymbolFixture {
            name: "_facade_entry",
            external: true,
            defined: true,
        }]);
    let container = macho::parse(&bytes).unwrap();
    let document = Analyzer
        .run(
            &container,
            &AnalysisPlan::new([
                AnalysisDomain::Header,
                AnalysisDomain::Symbols,
                AnalysisDomain::Xrefs,
            ]),
        )
        .unwrap();
    let slice = &document.slices[0];

    let DomainState::Complete { value: header, .. } = slice.report(domain_reports::HEADER).unwrap()
    else {
        panic!("header analysis did not complete");
    };
    assert_eq!(header.cpu_type, "x86_64");

    let DomainState::Complete { value: symbols, .. } =
        slice.report(domain_reports::SYMBOLS).unwrap()
    else {
        panic!("symbol analysis did not complete");
    };
    assert!(symbols.iter().any(|symbol| symbol.name == "_facade_entry"));

    assert!(matches!(
        slice.report(domain_reports::XREFS).unwrap(),
        DomainState::Complete { .. }
    ));
}
