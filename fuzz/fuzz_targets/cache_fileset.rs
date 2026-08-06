#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let cache_first = macho::dyld_cache::parse_dyld_cache(data).is_ok();
    let cache_second = macho::dyld_cache::parse_dyld_cache(data).is_ok();
    assert_eq!(cache_first, cache_second);

    let fileset_first = macho::core::parse(data)
        .ok()
        .and_then(|container| {
            container
                .first_macho()
                .map(|image| image.header().file_type().name() == "MH_FILESET")
        });
    let fileset_second = macho::core::parse(data)
        .ok()
        .and_then(|container| {
            container
                .first_macho()
                .map(|image| image.header().file_type().name() == "MH_FILESET")
        });
    assert_eq!(fileset_first, fileset_second);
});
