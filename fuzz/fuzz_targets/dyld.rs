#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = macho::core::parse(data).ok().map(|container| {
        container.first_macho().map(|image| {
            let mut streamed_exports = Vec::new();
            let streamed_result = macho::metadata::dyld::visit_exports(image, |export| {
                streamed_exports.push(export);
                Ok(())
            });
            let collected_exports = macho::metadata::dyld::parse_exports(image);
            assert_eq!(streamed_result.is_ok(), collected_exports.is_ok());
            if let Ok(collected_exports) = collected_exports {
                assert_eq!(streamed_exports, collected_exports);
            }
            (
                macho::metadata::dyld::bind::parse_bind_entries(image).is_ok(),
                macho::metadata::dyld::rebase::parse_rebase_entries(image).is_ok(),
                streamed_result.is_ok(),
                macho::metadata::dyld::chained::parse_chained_fixups(image).is_ok(),
            )
        })
    });
    let second = macho::core::parse(data).ok().map(|container| {
        container.first_macho().map(|image| {
            (
                macho::metadata::dyld::bind::parse_bind_entries(image).is_ok(),
                macho::metadata::dyld::rebase::parse_rebase_entries(image).is_ok(),
                macho::metadata::dyld::exports::parse_exports(image).is_ok(),
                macho::metadata::dyld::chained::parse_chained_fixups(image).is_ok(),
            )
        })
    });
    assert_eq!(first, second);
});
