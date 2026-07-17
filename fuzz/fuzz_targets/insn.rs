#![no_main]

use libfuzzer_sys::fuzz_target;
use macho_insn::Arch;

fuzz_target!(|data: &[u8]| {
    for arch in [Arch::X86_64, Arch::Arm64, Arch::Arm64e] {
        let strict: Vec<_> = macho_insn::decode_iter(data, 0x1000, arch).collect();
        let lossy = macho_insn::decode_lossy(data, 0x1000, arch);
        assert_eq!(
            strict,
            macho_insn::decode_iter(data, 0x1000, arch).collect::<Vec<_>>()
        );
        assert_eq!(lossy, macho_insn::decode_lossy(data, 0x1000, arch));
        let covered = lossy.instructions.iter().map(|insn| insn.len).sum::<usize>()
            + lossy.gaps.iter().map(|gap| gap.len).sum::<usize>();
        assert_eq!(covered, data.len());
        assert_eq!(strict.is_empty(), data.is_empty());
    }
});
