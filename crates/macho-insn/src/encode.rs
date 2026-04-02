//! Cross-architecture branch encoding, NOP fill, and instruction relocation.

use crate::{Arch, EncodeError};

/// Encode a direct branch (or call) instruction from `from_va` to `to_va`.
pub fn encode_branch(
    from_va: u64,
    to_va: u64,
    link: bool,
    arch: Arch,
) -> Result<Vec<u8>, EncodeError> {
    match arch {
        Arch::X86_64 => crate::x86_64::encode_branch_insn(from_va, to_va, link),
        Arch::Arm64 | Arch::Arm64e => crate::arm64::encode_branch_insn(from_va, to_va, link),
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
        Arch::X86_64 => crate::x86_64::relocate(bytes, old_va, new_va),
        Arch::Arm64 | Arch::Arm64e => crate::arm64::relocate(bytes, old_va, new_va),
    }
}

// ───────────────── NOP fill ─────────────────

const ARM64_NOP: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5]; // NOP = 0xD503201F LE

fn encode_nop_arm64(byte_count: usize) -> Result<Vec<u8>, EncodeError> {
    if byte_count % 4 != 0 {
        return Err(EncodeError {
            message: format!(
                "arm64 NOP fill requires a multiple of 4 bytes, got {byte_count}"
            ),
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
    &[],                                                             // 0
    &[0x90],                                                         // 1: NOP
    &[0x66, 0x90],                                                   // 2: 66 NOP
    &[0x0F, 0x1F, 0x00],                                             // 3: NOP DWORD [rax]
    &[0x0F, 0x1F, 0x40, 0x00],                                      // 4: NOP DWORD [rax+0]
    &[0x0F, 0x1F, 0x44, 0x00, 0x00],                                // 5: NOP DWORD [rax+rax+0]
    &[0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00],                          // 6: 66 NOP DWORD [rax+rax+0]
    &[0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00],                    // 7: NOP DWORD [rax+0x0]
    &[0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],              // 8: NOP DWORD [rax+rax+0x0]
    &[0x66, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00],        // 9: 66 NOP ...
    // 10-15: compose from smaller sequences
    &[0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 10
    &[0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 11
    &[0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 12
    &[0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 13
    &[0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 14
    &[0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00], // 15
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
        let insn = crate::decode_one(&relocated, 0x2000, Arch::X86_64).unwrap();
        assert_eq!(crate::resolve_branch_target(&insn, 0x2000), Some(0x1105));
    }

    #[test]
    fn relocate_arm64_bl() {
        // BL +0x100 from VA 0x4000 → target 0x4100
        let original =
            crate::arm64::encode_branch_insn(0x4000, 0x4100, true).unwrap();
        // Relocate to VA 0x5000
        let relocated = relocate_insn(&original, 0x4000, 0x5000, Arch::Arm64).unwrap();
        let insn = crate::decode_one(&relocated, 0x5000, Arch::Arm64).unwrap();
        assert_eq!(crate::resolve_branch_target(&insn, 0x5000), Some(0x4100));
    }
}
