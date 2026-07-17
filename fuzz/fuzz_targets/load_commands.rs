#![no_main]

use libfuzzer_sys::fuzz_target;
use macho_core::{ParseLimits, ParseMode, ParseOptions};

fuzz_target!(|data: &[u8]| {
    let limit = data.first().copied().unwrap_or(0) as usize % 32;
    let options = ParseOptions {
        mode: ParseMode::Forensic,
        limits: ParseLimits {
            max_load_commands: limit,
            max_fat_arches: 8,
            max_sections: 256,
            max_string_bytes: 16_384,
        },
    };
    let first = macho_core::parse_with_options(data, &options).is_ok();
    let second = macho_core::parse_with_options(data, &options).is_ok();
    assert_eq!(first, second);
});
