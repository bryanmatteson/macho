//! Cross-architecture branch encoding, NOP fill, and instruction relocation.

use crate::insn::{Arch, EncodeError};

/// Encode a direct branch (or call) instruction from `from_va` to `to_va`.
pub fn encode_branch(
    from_va: u64,
    to_va: u64,
    link: bool,
    arch: Arch,
) -> Result<Vec<u8>, EncodeError> {
    match arch {
        Arch::X86_64 => crate::insn::x86_64::encode_branch_insn(from_va, to_va, link),
        Arch::Arm64 | Arch::Arm64e => crate::insn::arm64::encode_branch_insn(from_va, to_va, link),
    }
}

/// Generate `byte_count` bytes of architecture-appropriate NOP fill.
pub fn encode_nop(arch: Arch, byte_count: usize) -> Result<Vec<u8>, EncodeError> {
    match arch {
        Arch::Arm64 | Arch::Arm64e => encode_nop_arm64(byte_count),
        Arch::X86_64 => encode_nop_x86_64(byte_count),
    }
}

/// Relocate the instruction in `bytes` from `old_va` to `new_va`.
pub fn relocate_insn(
    bytes: &[u8],
    old_va: u64,
    new_va: u64,
    arch: Arch,
) -> Result<Vec<u8>, EncodeError> {
    if old_va == new_va {
        return Ok(bytes.to_vec());
    }
    match arch {
        Arch::X86_64 => crate::insn::x86_64::relocate(bytes, old_va, new_va),
        Arch::Arm64 | Arch::Arm64e => crate::insn::arm64::relocate(bytes, old_va, new_va),
    }
}

// ───────────────── NOP fill ─────────────────

const ARM64_NOP: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5]; // NOP = 0xD503201F LE

fn encode_nop_arm64(byte_count: usize) -> Result<Vec<u8>, EncodeError> {
    if byte_count % 4 != 0 {
        return Err(EncodeError {
            message: format!("arm64 NOP fill requires a multiple of 4 bytes, got {byte_count}"),
        });
    }
    let mut buf = Vec::with_capacity(byte_count);
    for _ in 0..(byte_count / 4) {
        buf.extend_from_slice(&ARM64_NOP);
    }
    Ok(buf)
}

/// x86_64 NOP encodings for lengths 1-15 bytes (Intel recommended sequences).
///
/// Source: Intel SDM Vol. 2, Table 4-12 "Recommended Multi-Byte NOP Sequences".
const X86_64_NOPS: [&[u8]; 16] = [
    &[],                                                     // 0
    &[0x90],                                                 // 1: NOP
    &[0x66, 0x90],                                           // 2: 66 NOP
    &[0x0F, 0x1F, 0x00],                                     // 3: NOP DWORD [rax]
    &[0x0F, 0x1F, 0x40, 0x00],                               // 4: NOP DWORD [rax+0]
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],                         // 5: NOP DWORD [rax+rax+0]
    &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],                   // 6: 66 NOP DWORD [rax+rax+0]
    &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],             // 7: NOP DWORD [rax+0x0]
    &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],       // 8: NOP DWORD [rax+rax+0x0]
    &[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 9: 66 NOP ...
    // 10-15: compose from smaller sequences
    &[0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 10
    &[
        0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    ], // 11
    &[
        0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    ], // 12
    &[
        0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    ], // 13
    &[
        0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    ], // 14
    &[
        0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00,
    ], // 15
];

fn encode_nop_x86_64(byte_count: usize) -> Result<Vec<u8>, EncodeError> {
    let mut buf = Vec::with_capacity(byte_count);
    let mut remaining = byte_count;

    while remaining > 0 {
        let chunk = remaining.min(15);
        buf.extend_from_slice(X86_64_NOPS[chunk]);
        remaining -= chunk;
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x86_64_nop_all_sizes() {
        for size in 1..=30 {
            let nops = encode_nop(Arch::X86_64, size).unwrap();
            assert_eq!(nops.len(), size, "nop size {size}");
        }
    }

    #[test]
    fn arm64_nop_multiples_of_4() {
        for n in &[4, 8, 12, 16, 100] {
            let nops = encode_nop(Arch::Arm64, *n).unwrap();
            assert_eq!(nops.len(), *n);
        }
    }

    #[test]
    fn arm64_nop_rejects_odd() {
        assert!(encode_nop(Arch::Arm64, 1).is_err());
        assert!(encode_nop(Arch::Arm64, 5).is_err());
    }

    #[test]
    fn relocate_identity() {
        let bytes = [0x90]; // x86_64 NOP
        let result = relocate_insn(&bytes, 0x1000, 0x1000, Arch::X86_64).unwrap();
        assert_eq!(result, bytes);
    }

    #[test]
    fn relocate_x86_64_call() {
        // CALL +0x100 from VA 0x1000 → target 0x1105
        let bytes = [0xE8, 0x00, 0x01, 0x00, 0x00];
        // Relocate to VA 0x2000 → should still target 0x1105
        let relocated = relocate_insn(&bytes, 0x1000, 0x2000, Arch::X86_64).unwrap();
        // Decode and verify target.
        let insn = crate::insn::decode_one(&relocated, 0x2000, Arch::X86_64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x2000),
            Some(0x1105)
        );
    }

    #[test]
    fn relocate_arm64_bl() {
        // BL +0x100 from VA 0x4000 → target 0x4100
        let original = crate::insn::arm64::encode_branch_insn(0x4000, 0x4100, true).unwrap();
        // Relocate to VA 0x5000
        let relocated = relocate_insn(&original, 0x4000, 0x5000, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x5000, Arch::Arm64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x5000),
            Some(0x4100)
        );
    }

    // ── Category 1: Encoding Boundaries ──

    #[test]
    fn arm64_branch_max_positive_range() {
        // imm26 = (1<<25)-1, byte offset = 0x7FF_FFFC
        let max_target = 0x7FF_FFFC_u64;
        let bytes = encode_branch(0x0, max_target, false, Arch::Arm64).unwrap();
        assert_eq!(bytes.len(), 4);
        let insn = crate::insn::decode_one(&bytes, 0x0, Arch::Arm64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x0),
            Some(max_target)
        );
    }

    #[test]
    fn arm64_branch_max_negative_range() {
        // imm26 = -(1<<25), byte offset = -0x800_0000
        let from = 0x800_0000_u64;
        let bytes = encode_branch(from, 0x0, false, Arch::Arm64).unwrap();
        assert_eq!(bytes.len(), 4);
        let insn = crate::insn::decode_one(&bytes, from, Arch::Arm64).unwrap();
        assert_eq!(crate::insn::resolve_branch_target(&insn, from), Some(0x0));
    }

    #[test]
    fn arm64_branch_overflow_positive_fails() {
        // One step beyond max: offset = 0x800_0000 → imm26 = 1<<25 (out of range)
        assert!(encode_branch(0x0, 0x800_0000, false, Arch::Arm64).is_err());
    }

    #[test]
    fn arm64_branch_overflow_negative_fails() {
        // One step beyond min: offset = -(0x800_0000 + 4)
        assert!(encode_branch(0x800_0004, 0x0, false, Arch::Arm64).is_err());
    }

    #[test]
    fn arm64_branch_misaligned_fails() {
        assert!(encode_branch(0x1000, 0x1002, false, Arch::Arm64).is_err());
    }

    #[test]
    fn arm64_branch_max_range_round_trip() {
        let from = 0x1000_u64;
        let to = from + 0x7FF_FFFC;
        let bytes = encode_branch(from, to, true, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&bytes, from, Arch::Arm64).unwrap();
        assert_eq!(crate::insn::resolve_branch_target(&insn, from), Some(to));
    }

    #[test]
    fn encode_nop_zero_x86_64() {
        let nops = encode_nop(Arch::X86_64, 0).unwrap();
        assert!(nops.is_empty());
    }

    #[test]
    fn encode_nop_zero_arm64() {
        let nops = encode_nop(Arch::Arm64, 0).unwrap();
        assert!(nops.is_empty());
    }

    #[test]
    fn arm64e_encodes_same_as_arm64() {
        let a = encode_branch(0x1000, 0x2000, true, Arch::Arm64).unwrap();
        let b = encode_branch(0x1000, 0x2000, true, Arch::Arm64e).unwrap();
        assert_eq!(a, b);
        let na = encode_nop(Arch::Arm64, 8).unwrap();
        let nb = encode_nop(Arch::Arm64e, 8).unwrap();
        assert_eq!(na, nb);
    }

    // ── Category 2: Relocation Error Paths ──

    #[test]
    fn relocate_arm64_bcond_out_of_range() {
        // B.EQ +0x100 at VA 0x5000 → target 0x5100
        // imm19 = 0x100/4 = 0x40, cond=0000 (EQ)
        let word: u32 = 0x5400_0000 | (0x40 << 5);
        let bytes = word.to_le_bytes();
        // Relocate to 0x200000 — new offset = 0x5100 - 0x200000 ≈ -2 MiB (out of ±1 MiB)
        assert!(relocate_insn(&bytes, 0x5000, 0x20_0000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_arm64_cbz_out_of_range() {
        // CBZ x0, +0x40 at VA 0x1000 → target 0x1040
        let word: u32 = 0xB400_0000 | (0x10 << 5); // imm19=0x10 → offset=0x40
        let bytes = word.to_le_bytes();
        // Relocate far: target 0x1040 from new VA 0x20_0000 → out of ±1 MiB
        assert!(relocate_insn(&bytes, 0x1000, 0x20_0000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_arm64_tbnz_out_of_range() {
        // TBNZ x0, #5, +0x20 at VA 0x1000 → target 0x1020
        // bit5=0, b40=00101 → bits[23:19]=00101, imm14=8 → offset=0x20
        let word: u32 = 0x3700_0000 | (5 << 19) | (8 << 5);
        let bytes = word.to_le_bytes();
        // Relocate to 0x10000 — new offset ≈ -60 KiB (out of ±32 KiB)
        assert!(relocate_insn(&bytes, 0x1000, 0x1_0000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_arm64_adr_out_of_range() {
        // ADR x0, +4 at VA 0x1000 → target 0x1004
        // immhi=1, immlo=0 → imm=4
        let word: u32 = 0x1000_0000 | (1 << 5); // immhi=1 at bits[23:5], Rd=0
        let bytes = word.to_le_bytes();
        // Relocate to 0x20_0000 — new offset = 0x1004 - 0x200000 ≈ -2 MiB (out of ±1 MiB)
        assert!(relocate_insn(&bytes, 0x1000, 0x20_0000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_arm64_adrp_out_of_range() {
        // ADRP x0, +1 page at VA 0x1000 → target page 0x2000
        // imm = 1 → immhi=0, immlo=1
        let word: u32 = 0x9000_0000 | (1 << 29); // immlo=1 at bits[30:29], Rd=0
        let bytes = word.to_le_bytes();
        // Target page is 0x2000. New VA must be far enough that page delta exceeds ±4 GiB.
        // ±4 GiB = ±(1<<20) pages = 0x100000 * 4096 = 0x1_0000_0000.
        // We need |new_page - target_page| >= 0x1_0000_0000.
        // target_page = 0x2000, so new_va in page 0x1_0000_3000 gives delta = 0x1_0000_1000 > 4 GiB.
        assert!(relocate_insn(&bytes, 0x1000, 0x1_0000_3000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_arm64_ldr_literal_out_of_range() {
        // LDR x0, +0x10 at VA 0x1000 → target 0x1010
        // opc=01, V=0, imm19=4 → offset=0x10
        let word: u32 = 0x5800_0000 | (4 << 5);
        let bytes = word.to_le_bytes();
        // Relocate to 0x20_0000 — offset out of ±1 MiB
        assert!(relocate_insn(&bytes, 0x1000, 0x20_0000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_arm64_short_input() {
        assert!(relocate_insn(&[0x00, 0x00], 0x1000, 0x2000, Arch::Arm64).is_err());
    }

    #[test]
    fn relocate_x86_64_invalid_bytes() {
        assert!(relocate_insn(&[0xFF, 0xFF], 0x1000, 0x2000, Arch::X86_64).is_err());
    }

    #[test]
    fn relocate_x86_64_empty_input() {
        assert!(relocate_insn(&[], 0x1000, 0x2000, Arch::X86_64).is_err());
    }

    // ── Category 3: Relocation Round-Trips ──

    #[test]
    fn relocate_arm64_bcond_preserves_target() {
        // B.EQ +0x100 at VA 0x5000 → target 0x5100
        let imm19 = 0x100_i64 / 4;
        let word: u32 = 0x5400_0000 | ((imm19 as u32 & 0x7FFFF) << 5); // cond=EQ (0)
        let bytes = word.to_le_bytes();
        // Relocate to 0x5200 (NOT 0x5100) so the offset is non-zero
        let relocated = relocate_insn(&bytes, 0x5000, 0x5200, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x5200, Arch::Arm64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x5200),
            Some(0x5100)
        );
        // Verify cond field (bits [3:0]) is preserved
        let new_word = u32::from_le_bytes([relocated[0], relocated[1], relocated[2], relocated[3]]);
        assert_eq!(new_word & 0xF, 0, "B.EQ cond field must be 0");
    }

    #[test]
    fn relocate_arm64_cbz_preserves_target() {
        // CBZ x0, +0x40 at VA 0x1000 → target 0x1040
        let imm19 = 0x40_i64 / 4;
        let word: u32 = 0xB400_0000 | ((imm19 as u32 & 0x7FFFF) << 5); // sf=1, CBZ, Rt=0
        let bytes = word.to_le_bytes();
        let relocated = relocate_insn(&bytes, 0x1000, 0x1100, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x1100, Arch::Arm64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x1100),
            Some(0x1040)
        );
    }

    #[test]
    fn relocate_arm64_tbnz_preserves_target_and_bits() {
        // TBNZ x0, #17, +0x20 at VA 0x2000 → target 0x2020
        // b5=0, b40=10001 (17), imm14=8 → offset=0x20
        let word: u32 = 0x3700_0000 | (17 << 19) | (8 << 5);
        let bytes = word.to_le_bytes();
        let relocated = relocate_insn(&bytes, 0x2000, 0x2010, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x2010, Arch::Arm64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x2010),
            Some(0x2020)
        );
        // Verify b5 and b40 fields preserved
        let new_word = u32::from_le_bytes([relocated[0], relocated[1], relocated[2], relocated[3]]);
        assert_eq!((new_word >> 19) & 0x1F, 17, "b40 must be preserved");
        assert_eq!((new_word >> 31) & 1, 0, "b5 must be preserved");
    }

    #[test]
    fn relocate_arm64_adr_preserves_target() {
        // ADR x0, +4 at VA 0x1000 → target 0x1004
        // imm=4 → immhi=1, immlo=0
        let word: u32 = 0x1000_0000 | (1 << 5); // immhi=1 at bit 5
        let bytes = word.to_le_bytes();
        let relocated = relocate_insn(&bytes, 0x1000, 0x1008, Arch::Arm64).unwrap();
        // Verify: decode at new VA 0x1008, displacement should point to 0x1004
        let insn = crate::insn::decode_one(&relocated, 0x1008, Arch::Arm64).unwrap();
        match insn.kind {
            crate::insn::InsnKind::PcRelative(ref info) => {
                let target = (0x1008_i64 + info.displacement) as u64;
                assert_eq!(target, 0x1004);
            }
            other => panic!("expected PcRelative, got {other:?}"),
        }
    }

    #[test]
    fn relocate_arm64_adrp_preserves_target_page() {
        // ADRP x0, +1 page at VA 0x2000 → target page 0x3000
        // imm = 1 → immlo=1 at bits[30:29]
        let word: u32 = 0x9000_0000 | (1 << 29);
        let bytes = word.to_le_bytes();
        // Relocate to VA 0x4000
        let relocated = relocate_insn(&bytes, 0x2000, 0x4000, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x4000, Arch::Arm64).unwrap();
        match insn.kind {
            crate::insn::InsnKind::PcRelative(ref info) => {
                // ADRP displacement is stored as (target_page - va), so
                // target_page = va + displacement
                let target_page = (0x4000_i64 + info.displacement) as u64;
                assert_eq!(target_page, 0x3000);
            }
            other => panic!("expected PcRelative, got {other:?}"),
        }
    }

    #[test]
    fn relocate_arm64_ldr_literal_preserves_target() {
        // LDR x0, +0x10 at VA 0x1000 → target 0x1010
        let imm19 = 0x10_i64 / 4;
        let word: u32 = 0x5800_0000 | ((imm19 as u32 & 0x7FFFF) << 5);
        let bytes = word.to_le_bytes();
        let relocated = relocate_insn(&bytes, 0x1000, 0x1100, Arch::Arm64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x1100, Arch::Arm64).unwrap();
        match insn.kind {
            crate::insn::InsnKind::PcRelative(ref info) => {
                let target = (0x1100_i64 + info.displacement) as u64;
                assert_eq!(target, 0x1010);
            }
            other => panic!("expected PcRelative, got {other:?}"),
        }
    }

    #[test]
    fn relocate_x86_64_jmp_preserves_target() {
        // JMP +0x3FFB from VA 0x1000 → target = 0x1000 + 5 + 0x3FFB = 0x5000
        let bytes = [0xE9, 0xFB, 0x3F, 0x00, 0x00];
        let relocated = relocate_insn(&bytes, 0x1000, 0x2000, Arch::X86_64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x2000, Arch::X86_64).unwrap();
        assert_eq!(
            crate::insn::resolve_branch_target(&insn, 0x2000),
            Some(0x5000)
        );
    }

    #[test]
    fn relocate_x86_64_lea_rip_preserves_target() {
        // LEA rax, [rip+0x10] at VA 0x1000 → target = 0x1000 + 7 + 0x10 = 0x1017
        let bytes = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let relocated = relocate_insn(&bytes, 0x1000, 0x2000, Arch::X86_64).unwrap();
        let insn = crate::insn::decode_one(&relocated, 0x2000, Arch::X86_64).unwrap();
        match insn.kind {
            crate::insn::InsnKind::PcRelative(ref info) => {
                let target = (0x2000_i64 + info.displacement) as u64;
                assert_eq!(target, 0x1017);
            }
            other => panic!("expected PcRelative, got {other:?}"),
        }
    }

    #[test]
    fn relocate_x86_64_out_of_range_fails() {
        let bytes = [0xE8, 0x00, 0x00, 0x00, 0x00];
        assert!(relocate_insn(&bytes, 0, 0x1_0000_0000, Arch::X86_64).is_err());
    }

    #[test]
    fn relocate_x86_64_non_pc_relative_preserves_bytes() {
        let bytes = [0x48, 0x01, 0xC8];
        assert_eq!(
            relocate_insn(&bytes, 0x1000, 0x2000, Arch::X86_64).unwrap(),
            bytes
        );
    }

    #[test]
    fn relocate_identity_arm64() {
        let original = crate::insn::arm64::encode_branch_insn(0x4000, 0x4100, true).unwrap();
        let result = relocate_insn(&original, 0x4000, 0x4000, Arch::Arm64).unwrap();
        assert_eq!(result, original);
    }
}
