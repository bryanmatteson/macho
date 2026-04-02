//! AArch64 instruction decoding and disassembly via `bad64`.

use crate::{BranchInfo, BranchTarget, DecodeError, Insn, InsnKind, PcRelInfo};

pub(crate) fn decode_one(bytes: &[u8], va: u64) -> Result<Insn, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError {
            message: "need at least 4 bytes for arm64 instruction".into(),
        });
    }

    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let kind = classify(word, va);

    Ok(Insn {
        offset: 0,
        len: 4,
        kind,
    })
}

fn classify(word: u32, va: u64) -> InsnKind {
    // NOP: 0xD503201F
    if word == 0xD503_201F {
        return InsnKind::Nop;
    }

    // RET (and variants): 1101011 0010 11111 0000 00 Rn 00000
    // RET: 0xD65F03C0 (Rn=x30)
    // The general RET mask: bits[31:25]=1101011, bits[24:21]=0010, bits[20:16]=11111,
    //                       bits[15:10]=000000, bits[4:0]=00000
    if word & 0xFFFF_FC1F == 0xD65F_0000 {
        return InsnKind::Return;
    }

    // B (unconditional): 000101 imm26
    if word & 0xFC00_0000 == 0x1400_0000 {
        let imm26 = (word & 0x03FF_FFFF) as i32;
        let offset = sign_extend_26(imm26) as i64 * 4;
        return InsnKind::Branch(BranchInfo {
            target: BranchTarget::Direct(offset),
        });
    }

    // BL: 100101 imm26
    if word & 0xFC00_0000 == 0x9400_0000 {
        let imm26 = (word & 0x03FF_FFFF) as i32;
        let offset = sign_extend_26(imm26) as i64 * 4;
        return InsnKind::Call(BranchInfo {
            target: BranchTarget::Direct(offset),
        });
    }

    // B.cond: 01010100 imm19 0 cond
    if word & 0xFF00_0010 == 0x5400_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let offset = sign_extend_19(imm19) as i64 * 4;
        return InsnKind::CondBranch(BranchInfo {
            target: BranchTarget::Direct(offset),
        });
    }

    // CBZ / CBNZ: x0110100 imm19 Rt  (CBZ)  /  x0110101 imm19 Rt  (CBNZ)
    if word & 0x7E00_0000 == 0x3400_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let offset = sign_extend_19(imm19) as i64 * 4;
        return InsnKind::CondBranch(BranchInfo {
            target: BranchTarget::Direct(offset),
        });
    }

    // TBZ / TBNZ: x0110110 b5 imm14 Rt (TBZ) / x0110111 b5 imm14 Rt (TBNZ)
    if word & 0x7E00_0000 == 0x3600_0000 {
        let imm14 = ((word >> 5) & 0x3FFF) as i32;
        let offset = sign_extend_14(imm14) as i64 * 4;
        return InsnKind::CondBranch(BranchInfo {
            target: BranchTarget::Direct(offset),
        });
    }

    // BR (register branch): 1101011 0000 11111 000000 Rn 00000
    if word & 0xFFFF_FC1F == 0xD61F_0000 {
        return InsnKind::Branch(BranchInfo {
            target: BranchTarget::Register,
        });
    }

    // BLR (register call): 1101011 0001 11111 000000 Rn 00000
    if word & 0xFFFF_FC1F == 0xD63F_0000 {
        return InsnKind::Call(BranchInfo {
            target: BranchTarget::Register,
        });
    }

    // BRAA/BRAB/BLRAA/BLRAB and other unconditional-branch-register variants
    // not caught above (authenticated branches, ERET, etc.).
    // Mask 0xFE00_0000 matches both 0xD6xx and 0xD7xx top bytes.
    if word & 0xFE00_0000 == 0xD600_0000 {
        // Check if it's a link variant.
        let is_link = word & 0x0020_0000 != 0;
        if is_link {
            return InsnKind::Call(BranchInfo {
                target: BranchTarget::Register,
            });
        }
        return InsnKind::Branch(BranchInfo {
            target: BranchTarget::Register,
        });
    }

    // ADR: 0 immlo(2) 10000 immhi(19) Rd
    if word & 0x9F00_0000 == 0x1000_0000 {
        let immhi = ((word >> 5) & 0x7FFFF) as i32;
        let immlo = ((word >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let offset = sign_extend_21(imm) as i64;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: offset,
        });
    }

    // ADRP: 1 immlo(2) 10000 immhi(19) Rd
    if word & 0x9F00_0000 == 0x9000_0000 {
        let immhi = ((word >> 5) & 0x7FFFF) as i32;
        let immlo = ((word >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let offset = sign_extend_21(imm) as i64 * 4096;
        // ADRP target is page-relative: (page_of(va) + imm * 4096) - va
        let page_va = va & !0xFFF;
        let target = (page_va as i64 + offset) - va as i64;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: target,
        });
    }

    // LDR (literal) variants:
    // LDR Wt:  00 011 000 imm19 Rt
    // LDR Xt:  01 011 000 imm19 Rt
    // LDRSW:   10 011 000 imm19 Rt
    // LDR St:  00 011 100 imm19 Rt
    // LDR Dt:  01 011 100 imm19 Rt
    // LDR Qt:  10 011 100 imm19 Rt
    // PRFM:    11 011 000 imm19 Rt
    if word & 0x3B00_0000 == 0x1800_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let offset = sign_extend_19(imm19) as i64 * 4;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: offset,
        });
    }

    InsnKind::Other
}

// ───────────────── sign extension helpers ─────────────────

fn sign_extend_26(val: i32) -> i32 {
    if val & (1 << 25) != 0 {
        val | !0x03FF_FFFF
    } else {
        val
    }
}

fn sign_extend_21(val: i32) -> i32 {
    if val & (1 << 20) != 0 {
        val | !0x001F_FFFF
    } else {
        val
    }
}

fn sign_extend_19(val: i32) -> i32 {
    if val & (1 << 18) != 0 {
        val | !0x0007_FFFF
    } else {
        val
    }
}

fn sign_extend_14(val: i32) -> i32 {
    if val & (1 << 13) != 0 {
        val | !0x0000_3FFF
    } else {
        val
    }
}

// ───────────────── encoding ─────────────────

/// Encode a B or BL instruction targeting `to_va` from `from_va`.
pub(crate) fn encode_branch_insn(
    from_va: u64,
    to_va: u64,
    link: bool,
) -> Result<Vec<u8>, crate::EncodeError> {
    let delta = to_va as i64 - from_va as i64;

    if delta % 4 != 0 {
        return Err(crate::EncodeError {
            message: format!(
                "arm64 branch target {to_va:#x} is not 4-byte aligned from {from_va:#x}"
            ),
        });
    }

    let imm26 = delta / 4;
    if imm26 < -(1 << 25) || imm26 >= (1 << 25) {
        return Err(crate::EncodeError {
            message: format!(
                "arm64 branch target {to_va:#x} is out of ±128 MiB range from {from_va:#x}"
            ),
        });
    }

    let opcode: u32 = if link { 0x9400_0000 } else { 0x1400_0000 };
    let word = opcode | ((imm26 as u32) & 0x03FF_FFFF);
    Ok(word.to_le_bytes().to_vec())
}

/// Relocate an arm64 instruction from `old_va` to `new_va`.
pub(crate) fn relocate(
    bytes: &[u8],
    old_va: u64,
    new_va: u64,
) -> Result<Vec<u8>, crate::EncodeError> {
    if bytes.len() < 4 {
        return Err(crate::EncodeError {
            message: "need 4 bytes".into(),
        });
    }

    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    // B / BL: recompute imm26
    if word & 0xFC00_0000 == 0x1400_0000 || word & 0xFC00_0000 == 0x9400_0000 {
        let imm26 = (word & 0x03FF_FFFF) as i32;
        let old_offset = sign_extend_26(imm26) as i64 * 4;
        let old_target = old_va as i64 + old_offset;
        return encode_branch_insn(new_va, old_target as u64, word & 0xFC00_0000 == 0x9400_0000);
    }

    // B.cond: recompute imm19
    if word & 0xFF00_0010 == 0x5400_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let old_offset = sign_extend_19(imm19) as i64 * 4;
        let target = old_va as i64 + old_offset;
        let new_offset = target - new_va as i64;
        if new_offset % 4 != 0 {
            return Err(crate::EncodeError {
                message: "unaligned conditional branch relocation".into(),
            });
        }
        let new_imm19 = new_offset / 4;
        if new_imm19 < -(1 << 18) || new_imm19 >= (1 << 18) {
            return Err(crate::EncodeError {
                message: "conditional branch relocation out of ±1 MiB range".into(),
            });
        }
        let new_word = (word & !0x00FF_FFE0) | (((new_imm19 as u32) & 0x7FFFF) << 5);
        return Ok(new_word.to_le_bytes().to_vec());
    }

    // CBZ / CBNZ: recompute imm19
    if word & 0x7E00_0000 == 0x3400_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let old_offset = sign_extend_19(imm19) as i64 * 4;
        let target = old_va as i64 + old_offset;
        let new_offset = target - new_va as i64;
        if new_offset % 4 != 0 {
            return Err(crate::EncodeError {
                message: "unaligned CBZ/CBNZ relocation".into(),
            });
        }
        let new_imm19 = new_offset / 4;
        if new_imm19 < -(1 << 18) || new_imm19 >= (1 << 18) {
            return Err(crate::EncodeError {
                message: "CBZ/CBNZ relocation out of ±1 MiB range".into(),
            });
        }
        let new_word = (word & !0x00FF_FFE0) | (((new_imm19 as u32) & 0x7FFFF) << 5);
        return Ok(new_word.to_le_bytes().to_vec());
    }

    // TBZ / TBNZ: recompute imm14
    if word & 0x7E00_0000 == 0x3600_0000 {
        let imm14 = ((word >> 5) & 0x3FFF) as i32;
        let old_offset = sign_extend_14(imm14) as i64 * 4;
        let target = old_va as i64 + old_offset;
        let new_offset = target - new_va as i64;
        if new_offset % 4 != 0 {
            return Err(crate::EncodeError {
                message: "unaligned TBZ/TBNZ relocation".into(),
            });
        }
        let new_imm14 = new_offset / 4;
        if new_imm14 < -(1 << 13) || new_imm14 >= (1 << 13) {
            return Err(crate::EncodeError {
                message: "TBZ/TBNZ relocation out of ±32 KiB range".into(),
            });
        }
        let new_word = (word & !0x0007_FFE0) | (((new_imm14 as u32) & 0x3FFF) << 5);
        return Ok(new_word.to_le_bytes().to_vec());
    }

    // ADR: recompute immhi:immlo
    if word & 0x9F00_0000 == 0x1000_0000 {
        let immhi = ((word >> 5) & 0x7FFFF) as i32;
        let immlo = ((word >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let old_offset = sign_extend_21(imm) as i64;
        let target = old_va as i64 + old_offset;
        let new_offset = target - new_va as i64;
        if new_offset < -(1 << 20) || new_offset >= (1 << 20) {
            return Err(crate::EncodeError {
                message: "ADR relocation out of ±1 MiB range".into(),
            });
        }
        let imm = new_offset as u32;
        let new_immlo = (imm & 0x3) << 29;
        let new_immhi = ((imm >> 2) & 0x7FFFF) << 5;
        let new_word = (word & 0x9F00_001F) | new_immhi | new_immlo;
        return Ok(new_word.to_le_bytes().to_vec());
    }

    // ADRP: recompute page-relative
    if word & 0x9F00_0000 == 0x9000_0000 {
        let immhi = ((word >> 5) & 0x7FFFF) as i32;
        let immlo = ((word >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let old_offset = sign_extend_21(imm) as i64;
        let old_page = (old_va & !0xFFF) as i64;
        let target_page = old_page + old_offset * 4096;
        let new_page = (new_va & !0xFFF) as i64;
        let new_offset = target_page - new_page;
        if new_offset % 4096 != 0 {
            return Err(crate::EncodeError {
                message: "ADRP relocation page misalignment".into(),
            });
        }
        let new_imm = new_offset / 4096;
        if new_imm < -(1 << 20) || new_imm >= (1 << 20) {
            return Err(crate::EncodeError {
                message: "ADRP relocation out of ±4 GiB range".into(),
            });
        }
        let imm = new_imm as u32;
        let new_immlo = (imm & 0x3) << 29;
        let new_immhi = ((imm >> 2) & 0x7FFFF) << 5;
        let new_word = (word & 0x9F00_001F) | new_immhi | new_immlo;
        return Ok(new_word.to_le_bytes().to_vec());
    }

    // LDR literal: recompute imm19
    if word & 0x3B00_0000 == 0x1800_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let old_offset = sign_extend_19(imm19) as i64 * 4;
        let target = old_va as i64 + old_offset;
        let new_offset = target - new_va as i64;
        if new_offset % 4 != 0 {
            return Err(crate::EncodeError {
                message: "unaligned literal load relocation".into(),
            });
        }
        let new_imm19 = new_offset / 4;
        if new_imm19 < -(1 << 18) || new_imm19 >= (1 << 18) {
            return Err(crate::EncodeError {
                message: "literal load relocation out of ±1 MiB range".into(),
            });
        }
        let new_word = (word & !0x00FF_FFE0) | (((new_imm19 as u32) & 0x7FFFF) << 5);
        return Ok(new_word.to_le_bytes().to_vec());
    }

    // Register branches and non-PC-relative: no relocation needed, copy as-is.
    Ok(bytes[..4].to_vec())
}

// ───────────────── disassembly ─────────────────

pub(crate) fn disassemble_one(bytes: &[u8], va: u64) -> Result<String, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError {
            message: "need 4 bytes".into(),
        });
    }

    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    match bad64::decode(word, va) {
        Ok(decoded) => Ok(format!("{decoded}")),
        Err(_) => {
            // Fallback: show raw encoding.
            Ok(format!(".inst 0x{word:08x}"))
        }
    }
}

pub(crate) fn disassemble(
    bytes: &[u8],
    base_va: u64,
) -> Result<Vec<(u64, String)>, DecodeError> {
    if bytes.len() % 4 != 0 {
        return Err(DecodeError {
            message: "arm64 instruction stream must be 4-byte aligned".into(),
        });
    }

    let mut result = Vec::new();
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let va = base_va + (i * 4) as u64;
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let text = match bad64::decode(word, va) {
            Ok(decoded) => format!("{decoded}"),
            Err(_) => format!(".inst 0x{word:08x}"),
        };
        result.push((va, text));
    }

    Ok(result)
}
