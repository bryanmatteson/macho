#![no_main]

use libfuzzer_sys::fuzz_target;
use macho_insn::Arch;

// Base virtual addresses to decode each input at. Beyond the ordinary low base,
// two addresses straddle the i64 sign boundary (0x8000_0000_0000_0000) so that
// branch, RIP-relative, and ADRP displacement math is exercised where a naive
// signed subtraction would overflow. Both high bases are chosen so the running
// VA (`base + offset`) never wraps u64 for any realistic input length, keeping
// the decode-success invariants below independent of address arithmetic.
const BASES: [u64; 3] = [0x1000, 0x7FFF_FFFF_FFFF_F000, 0x8000_0000_0000_0000];

fuzz_target!(|data: &[u8]| {
    for base in BASES {
        for arch in [Arch::X86_64, Arch::Arm64, Arch::Arm64e] {
            let strict: Vec<_> = macho_insn::decode_iter(data, base, arch).collect();
            let lossy = macho_insn::decode_lossy(data, base, arch);
            assert_eq!(
                strict,
                macho_insn::decode_iter(data, base, arch).collect::<Vec<_>>()
            );
            assert_eq!(lossy, macho_insn::decode_lossy(data, base, arch));
            let covered = lossy
                .instructions
                .iter()
                .map(|insn| insn.len)
                .sum::<usize>()
                + lossy.gaps.iter().map(|gap| gap.len).sum::<usize>();
            assert_eq!(covered, data.len());
            assert_eq!(strict.is_empty(), data.is_empty());

            let formatted = macho_insn::disassemble(data, base, arch);
            if strict.iter().all(Result::is_ok) {
                assert_eq!(formatted.unwrap().len(), strict.len());
            } else {
                assert!(formatted.is_err());
            }
        }
    }
});
