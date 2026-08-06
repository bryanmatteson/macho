#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let first = macho::metadata::codesign::superblob::parse_super_blob(data).is_ok();
    let second = macho::metadata::codesign::superblob::parse_super_blob(data).is_ok();
    assert_eq!(first, second);
});
