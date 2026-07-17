#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = macho_core::parse(data).ok().map(|container| {
        container.first_macho().map(|image| {
            (
                macho_dyld::bind::parse_bind_entries(image).is_ok(),
                macho_dyld::rebase::parse_rebase_entries(image).is_ok(),
                macho_dyld::exports::parse_exports(image).is_ok(),
                macho_dyld::chained::parse_chained_fixups(image).is_ok(),
            )
        })
    });
    let second = macho_core::parse(data).ok().map(|container| {
        container.first_macho().map(|image| {
            (
                macho_dyld::bind::parse_bind_entries(image).is_ok(),
                macho_dyld::rebase::parse_rebase_entries(image).is_ok(),
                macho_dyld::exports::parse_exports(image).is_ok(),
                macho_dyld::chained::parse_chained_fixups(image).is_ok(),
            )
        })
    });
    assert_eq!(first, second);
});
