#![no_main]

use libfuzzer_sys::fuzz_target;
use macho::core::{ParseLimits, ParseMode, ParseOptions};

fn run(data: &[u8], mode: ParseMode) -> (bool, usize) {
    let options = ParseOptions {
        mode,
        limits: ParseLimits {
            max_fat_arches: 32,
            max_load_commands: 256,
            max_sections: 4_096,
            max_string_bytes: 1 << 20,
        },
    };
    match macho::core::parse_with_options(data, &options) {
        Ok(outcome) => (true, outcome.diagnostics.len()),
        Err(_) => (false, 0),
    }
}

fuzz_target!(|data: &[u8]| {
    for mode in [ParseMode::Strict, ParseMode::Forensic] {
        assert_eq!(run(data, mode), run(data, mode));
    }
});
