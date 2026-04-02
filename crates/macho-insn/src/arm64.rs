//! AArch64 instruction decoding and disassembly via `bad64`.

use crate::{
    BranchInfo, BranchTarget, DecodeError, Insn, InsnKind, Operand, PcRelInfo, Reg, MAX_OPERANDS,
};

pub(crate) fn decode_one(bytes: &[u8], va: u64) -> Result<Insn, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError {
            message: "need at least 4 bytes for arm64 instruction".into(),
        });
    }

    let word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let kind = classify(word, va);
    let (ops, op_count) = extract_operands(word);

    Ok(Insn::with_ops(4, kind, ops, op_count))
}

fn classify(word: u32, va: u64) -> InsnKind {
    // NOP: 0xD503201F
    if word == 0xD503_201F {
        return InsnKind::Nop;
    }

    // RET (and variants): 1101011 0010 11111 0000 00 Rn 00000
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

    // BRAA/BRAB/BLRAA/BLRAB and other unconditional-branch-register variants.
    if word & 0xFE00_0000 == 0xD600_0000 {
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
        let page_va = va & !0xFFF;
        let target = (page_va as i64 + offset) - va as i64;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: target,
        });
    }

    // LDR (literal) variants
    if word & 0x3B00_0000 == 0x1800_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let offset = sign_extend_19(imm19) as i64 * 4;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: offset,
        });
    }

    InsnKind::Other
}

// ───────────────── operand extraction ─────────────────

/// Extract operands from an ARM64 instruction word.
///
/// Handles the major instruction formats needed by ABI analysis:
/// load/store pairs, load/store single, data processing, FP moves,
/// and register branches.
fn extract_operands(word: u32) -> ([Operand; MAX_OPERANDS], u8) {
    let mut ops = [Operand::Imm(0); MAX_OPERANDS];

    let rt = (word & 0x1F) as u8;
    let rn = ((word >> 5) & 0x1F) as u8;
    let rt2 = ((word >> 10) & 0x1F) as u8;
    let rm = ((word >> 16) & 0x1F) as u8;
    let rd = rt; // alias — same bit position

    // ── STP/LDP GPR (post-index, signed offset, pre-index) ──
    // Post-index:    x0 101 000 1x imm7 Rt2 Rn Rt  → 0x2880_0000
    // Signed offset: x0 101 001 0x imm7 Rt2 Rn Rt  → 0x2900_0000
    // Pre-index:     x0 101 001 1x imm7 Rt2 Rn Rt  → 0x2980_0000
    if word & 0x7FC0_0000 == 0x2880_0000
        || word & 0x7FC0_0000 == 0x2900_0000
        || word & 0x7FC0_0000 == 0x2980_0000
    {
        let sf = (word >> 31) & 1;
        let scale = if sf == 1 { 8i64 } else { 4 };
        let imm7 = ((word >> 15) & 0x7F) as i32;
        let disp = sign_extend_7(imm7) as i64 * scale;
        ops[0] = Operand::Reg(Reg::gpr(rt));
        ops[1] = Operand::Reg(Reg::gpr(rt2));
        ops[2] = Operand::Mem { base: Reg::gpr(rn), disp };
        return (ops, 3);
    }

    // ── STP/LDP FP (post-index, signed offset, pre-index) ──
    // opc=01: 32-bit (S), opc=10: 64-bit (D), opc=11: 128-bit (Q)
    if word & 0x7FC0_0000 == 0x6C80_0000
        || word & 0x7FC0_0000 == 0x6D00_0000
        || word & 0x7FC0_0000 == 0x6D80_0000
    {
        let opc = (word >> 30) & 0x3;
        let scale = match opc {
            0b01 => 4i64,
            0b10 => 8,
            0b11 => 16,
            _ => 8,
        };
        let imm7 = ((word >> 15) & 0x7F) as i32;
        let disp = sign_extend_7(imm7) as i64 * scale;
        ops[0] = Operand::Reg(Reg::fp(rt));
        ops[1] = Operand::Reg(Reg::fp(rt2));
        ops[2] = Operand::Mem { base: Reg::gpr(rn), disp };
        return (ops, 3);
    }

    // ── STR/LDR GPR (unsigned offset) ──
    // 1x 111 001 00 imm12 Rn Rt (STR)  /  1x 111 001 01 imm12 Rn Rt (LDR)
    if word & 0xBFC0_0000 == 0xB900_0000 || word & 0xBFC0_0000 == 0xB940_0000 {
        let sf = (word >> 30) & 1;
        let scale = if sf == 1 { 8i64 } else { 4 };
        let imm12 = ((word >> 10) & 0xFFF) as i64;
        let disp = imm12 * scale;
        ops[0] = Operand::Reg(Reg::gpr(rt));
        ops[1] = Operand::Mem { base: Reg::gpr(rn), disp };
        return (ops, 2);
    }

    // ── ADD/SUB (immediate) ──
    // sf 0 0 100010 sh imm12 Rn Rd (ADD)
    // sf 1 0 100010 sh imm12 Rn Rd (SUB)
    if word & 0x1F00_0000 == 0x1100_0000 {
        let is_sub = (word >> 30) & 1 == 1;
        let sh = ((word >> 22) & 1) as i64;
        let imm12 = ((word >> 10) & 0xFFF) as i64;
        let imm = if sh == 1 { imm12 << 12 } else { imm12 };
        let imm = if is_sub { -imm } else { imm };
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::Reg(Reg::gpr(rn));
        ops[2] = Operand::Imm(imm);
        return (ops, 3);
    }

    // ── ADD/SUB (shifted register) ──
    // sf 0 0 01011 shift 0 Rm imm6 Rn Rd (ADD)
    // sf 1 0 01011 shift 0 Rm imm6 Rn Rd (SUB)
    if word & 0x1F20_0000 == 0x0B00_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::Reg(Reg::gpr(rn));
        ops[2] = Operand::Reg(Reg::gpr(rm));
        return (ops, 3);
    }

    // ── FMOV (register, single/double) ──
    // 000 11110 xx 1 0000 00 10000 Rn Rd
    if word & 0xFF20_FC00 == 0x1E20_4000 {
        ops[0] = Operand::Reg(Reg::fp(rd));
        ops[1] = Operand::Reg(Reg::fp(rn));
        return (ops, 2);
    }

    // ── BR / BLR (register) ──
    if word & 0xFFFF_FC1F == 0xD61F_0000 || word & 0xFFFF_FC1F == 0xD63F_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rn));
        return (ops, 1);
    }

    // ── CBZ / CBNZ ──
    if word & 0x7E00_0000 == 0x3400_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rt));
        return (ops, 1);
    }

    // ── TBZ / TBNZ ──
    if word & 0x7E00_0000 == 0x3600_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rt));
        return (ops, 1);
    }

    // ── ADR / ADRP ──
    if word & 0x1F00_0000 == 0x1000_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        return (ops, 1);
    }

    // ── LDR literal ──
    if word & 0x3B00_0000 == 0x1800_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rt));
        return (ops, 1);
    }

    // ── RET ──
    if word & 0xFFFF_FC1F == 0xD65F_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rn));
        return (ops, 1);
    }

    (ops, 0)
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

fn sign_extend_7(val: i32) -> i32 {
    if val & (1 << 6) != 0 {
        val | !0x0000_007F
    } else {
        val
    }
}

// ───────────────── encoding ─────────────────

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

    // B / BL
    if word & 0xFC00_0000 == 0x1400_0000 || word & 0xFC00_0000 == 0x9400_0000 {
        let imm26 = (word & 0x03FF_FFFF) as i32;
        let old_offset = sign_extend_26(imm26) as i64 * 4;
        let old_target = old_va as i64 + old_offset;
        return encode_branch_insn(new_va, old_target as u64, word & 0xFC00_0000 == 0x9400_0000);
    }

    // B.cond
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

    // CBZ / CBNZ
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

    // TBZ / TBNZ
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

    // ADR
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

    // ADRP
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

    // LDR literal
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
        Err(_) => Ok(format!(".inst 0x{word:08x}")),
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
