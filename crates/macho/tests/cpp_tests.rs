#![cfg(feature = "cli")]

mod support;

use std::path::Path;

use macho::analysis::report::{RecoveryLanguage, recover_symbol_surface};
use macho::cli::adapters::validate_cpp_header;

#[test]
fn cpp_header_validation_is_in_process_and_portable() {
    let path = support::temp_file_path("portable.hpp");
    std::fs::write(
        &path,
        "namespace sample { class Widget { public: int run(int value) const; }; }\n",
    )
    .expect("write header");

    validate_cpp_header(Path::new(&path)).expect("validate a complete C++ header");
    let _ = std::fs::remove_file(path);
}

#[test]
fn cpp_symbol_fallback_conserves_every_observation() {
    let bytes = macho_test_support::thin64_x86_64_with_symbols(&[
        macho_test_support::SymbolFixture {
            name: "__ZN4Demo3runEi",
            external: true,
            defined: true,
        },
        macho_test_support::SymbolFixture {
            name: "__ZN4Demo4stopEv",
            external: true,
            defined: false,
        },
        macho_test_support::SymbolFixture {
            name: "_plain_c_symbol",
            external: true,
            defined: true,
        },
    ]);
    let container = macho::parse(&bytes).expect("parse fixture");
    let macho = container.first_macho().expect("Mach-O image");
    let report = recover_symbol_surface(macho, RecoveryLanguage::Cpp).expect("recover symbols");
    let slice = &report.slices.as_slice()[0];

    assert_eq!(slice.observations.len(), 3);
    assert_eq!(slice.entities.len(), 2);
    report.validate().expect("canonical report validates");
}
