//! AArch64 instruction decoding and disassembly with locally lowered semantics
//! and mkasm-generated text formatting.

use super::codecs::aarch64 as mkasm_aarch64;
use crate::insn::{
    BoundaryConfidence, BranchInfo, BranchTarget, DecodeError, DecodeErrorKind, Insn, InsnKind,
    InstructionRecovery, MAX_OPERANDS, MemoryEffect, Operand, PcRelInfo, PcRelKind, Reg,
    RegisterShift, ValueEffect,
};

pub(crate) fn decode_one(bytes: &[u8], va: u64) -> Result<Insn, DecodeError> {
    Ok(lower(read_word(bytes)?, va))
}

pub(crate) fn decode_and_disassemble_one(
    bytes: &[u8],
    va: u64,
) -> Result<(Insn, String, Option<InstructionRecovery>), DecodeError> {
    let word = read_word(bytes)?;
    let (text, unknown) = format_word(word, va);
    let instruction = if unknown {
        Insn::with_ops(
            4,
            InsnKind::Other,
            [Operand::Imm(0); MAX_OPERANDS],
            0,
            false,
            false,
            ValueEffect::None,
            MemoryEffect::None,
        )
    } else {
        lower(word, va)
    };
    Ok((
        instruction,
        text,
        unknown.then_some(InstructionRecovery {
            boundary_confidence: BoundaryConfidence::Exact,
            source: "architecture",
        }),
    ))
}

fn read_word(bytes: &[u8]) -> Result<u32, DecodeError> {
    if bytes.len() < 4 {
        return Err(DecodeError {
            kind: DecodeErrorKind::Truncated,
            message: "need at least 4 bytes for arm64 instruction".into(),
        });
    }

    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn lower(word: u32, va: u64) -> Insn {
    let kind = classify(word, va);
    let (ops, op_count) = extract_operands(word);
    let writes_op0_reg = op0_is_written(word);
    let value_effect = value_effect(word, writes_op0_reg);

    let memory_effect = if is_supported_store(word) {
        MemoryEffect::Store
    } else {
        MemoryEffect::None
    };
    Insn::with_ops(
        4,
        kind,
        ops,
        op_count,
        false,
        writes_op0_reg,
        value_effect,
        memory_effect,
    )
}

fn is_supported_store(word: u32) -> bool {
    (word & 0xBFC0_0000 == 0xB900_0000)
        || ((word & 0x7FC0_0000 == 0x2880_0000
            || word & 0x7FC0_0000 == 0x2900_0000
            || word & 0x7FC0_0000 == 0x2980_0000)
            && (word >> 22) & 1 == 0)
}

fn value_effect(word: u32, writes_op0_reg: bool) -> ValueEffect {
    if !writes_op0_reg {
        return ValueEffect::None;
    }
    if word & 0x1F00_0000 == 0x1000_0000 {
        return ValueEffect::Set;
    }
    if is_mov_register(word) {
        return ValueEffect::Set;
    }
    if let Some(effect) = pointer_authentication_effect(word) {
        return effect;
    }
    if word & 0x3B00_0000 == 0x1800_0000 {
        return ValueEffect::Load;
    }
    if word & 0x3F00_0000 == 0x3900_0000
        || is_load_register_offset(word)
        || word & 0x3E00_0000 == 0x2800_0000
        || word & 0x3E00_0000 == 0x2C00_0000
        || is_ldur_x(word)
    {
        return ValueEffect::Load;
    }
    if word & 0x1F00_0000 == 0x1100_0000 {
        return ValueEffect::AddImmediate;
    }
    if word & 0x1F20_0000 == 0x0B00_0000 {
        return if word & (1 << 30) == 0 {
            ValueEffect::AddRegister
        } else {
            ValueEffect::SubtractRegister
        };
    }
    if is_and_immediate(word) {
        return ValueEffect::BitwiseAndImmediate;
    }
    if let Some(effect) = extension_effect(word) {
        return effect;
    }
    if bitfield_shift(word).is_some() {
        return ValueEffect::ShiftImmediate;
    }
    if is_conditional_select(word) {
        return ValueEffect::ConditionalSelect;
    }
    ValueEffect::UnknownWrite
}

/// Whether the first operand of an ARM64 instruction is a register that the
/// instruction writes.
///
/// Returns `false` for stores (`STR`, `STP`), compares (`CMP`/`CMN`/`TST`
/// implemented as `SUBS`/`ADDS`/`ANDS` to `xzr`), branches that consume a
/// register, and any pattern this decoder does not recognize. Returns `true`
/// for loads (`LDR`, `LDP`, `LDR` literal), data-processing ops whose Rd is
/// op0 (`ADD`/`SUB` immediate and shifted-register, `FMOV`), and the
/// PC-relative address forms (`ADR`, `ADRP`).
///
/// The masks are derived from the ARM ARM "Data Processing" and
/// "Loads and stores" encoding tables, with bit 22 acting as the load/store
/// selector for the families that have one.
fn op0_is_written(word: u32) -> bool {
    // Load/store register pair (GPR) — bits 29:26 = 1010, V (bit 26) = 0.
    // Covers post-indexed, signed offset, and pre-indexed variants.
    // Bit 22 is the L bit: 1 = load (writes Rt/Rt2), 0 = store.
    if word & 0x3E00_0000 == 0x2800_0000 && (word >> 31) & 1 == 1 {
        return (word >> 22) & 1 == 1;
    }

    // Load/store register pair (SIMD/FP) — bits 29:26 = 1011.
    if word & 0x3E00_0000 == 0x2C00_0000 && (word >> 31) & 1 == 1 {
        return (word >> 22) & 1 == 1;
    }

    // Load/store register, unsigned immediate offset (GPR, 32- and 64-bit).
    // Encoding: `size V 111 0 01 opc imm12 Rn Rt` with V=0 (integer),
    // bits 25:24 = 01. Bit 23 distinguishes STR/LDR (opc[1]=0) from
    // LDRSW/PRFM (opc[1]=1); we only handle the STR/LDR case here and let
    // bit 22 act as the load/store selector (opc[0]=L).
    if word & 0x3F00_0000 == 0x3900_0000 {
        return (word >> 22) & 1 == 1;
    }

    // Load/store register offset (integer). opc=00 is a store; the remaining
    // encodings load or prefetch. Prefetch uses Rt=31 and does not expose a
    // useful destination register, so exclude it from the write model.
    if is_load_register_offset(word) {
        return (word >> 22) & 0x3 != 0 && word & 0x1F != 31;
    }

    // LDUR Xt, [Xn, #imm9]. Pre/post-indexed forms also write the base
    // register and therefore remain outside the single-destination model.
    if is_ldur_x(word) {
        return true;
    }

    // ADD/SUB immediate: Rd is op0, always written.
    if word & 0x1F00_0000 == 0x1100_0000 {
        return true;
    }

    // ADD/SUB shifted register: Rd is op0, always written. Note that this
    // pattern also matches `SUBS`/`ADDS`, which the ABI layer may use as
    // compare flags; those still write Rd (often xzr=31), so reporting true
    // here is correct — the ABI layer filters by whether Rd is an arg
    // register, and xzr is never one.
    if word & 0x1F20_0000 == 0x0B00_0000 {
        return true;
    }

    // Logical-immediate AND, bitfield shift aliases, and conditional select.
    if is_and_immediate(word)
        || extension_effect(word).is_some()
        || bitfield_shift(word).is_some()
        || is_conditional_select(word)
        || pointer_authentication_effect(word).is_some()
    {
        return true;
    }

    // MOV Xd, Xm is the ORR Xd, XZR, Xm alias with no shift.
    if is_mov_register(word) {
        return true;
    }

    // FMOV register: Rd is op0, written.
    if word & 0xFF20_FC00 == 0x1E20_4000 {
        return true;
    }

    // ADR / ADRP: Rd is op0, written.
    if word & 0x1F00_0000 == 0x1000_0000 {
        return true;
    }

    // LDR literal: Rt is op0, written.
    if word & 0x3B00_0000 == 0x1800_0000 {
        return true;
    }

    // BR/BLR/CBZ/CBNZ/TBZ/TBNZ/RET: op0 is consumed, not written.
    false
}

fn classify(word: u32, va: u64) -> InsnKind {
    // NOP: 0xD503201F
    if word == 0xD503_201F {
        return InsnKind::Nop;
    }

    // RET (and variants): 1101011 0010 11111 0000 00 Rn 00000
    // Also RETAA (0xD65F_0BFF) and RETAB (0xD65F_0FFF) — pointer-authentication returns.
    if word & 0xFFFF_FC1F == 0xD65F_0000 || word == 0xD65F_0BFF || word == 0xD65F_0FFF {
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
            kind: PcRelKind::Address,
        });
    }

    // ADRP: 1 immlo(2) 10000 immhi(19) Rd
    if word & 0x9F00_0000 == 0x9000_0000 {
        let immhi = ((word >> 5) & 0x7FFFF) as i32;
        let immlo = ((word >> 29) & 0x3) as i32;
        let imm = (immhi << 2) | immlo;
        let offset = sign_extend_21(imm) as i64 * 4096;
        // Displacement from the instruction to the target page. Since
        // `page_va == va & !0xFFF`, `(page_va + offset) - va` reduces to
        // `offset - (va & 0xFFF)`, which stays in range instead of overflowing
        // i64 when `va` sits near the sign boundary.
        let target = offset - (va & 0xFFF) as i64;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: target,
            kind: PcRelKind::PageAddress,
        });
    }

    // LDR (literal) variants
    if word & 0x3B00_0000 == 0x1800_0000 {
        let imm19 = ((word >> 5) & 0x7FFFF) as i32;
        let offset = sign_extend_19(imm19) as i64 * 4;
        return InsnKind::PcRelative(PcRelInfo {
            displacement: offset,
            kind: PcRelKind::Memory,
        });
    }

    InsnKind::Other
}

fn is_mov_register(word: u32) -> bool {
    word & 0xFFE0_FFE0 == 0xAA00_03E0
}

fn is_ldur_x(word: u32) -> bool {
    word & 0xFFE0_0C00 == 0xF840_0000
}

fn is_load_register_offset(word: u32) -> bool {
    word & 0x3B20_0C00 == 0x3820_0800
}

fn is_and_immediate(word: u32) -> bool {
    word & 0x7F80_0000 == 0x1200_0000 && decode_logical_immediate(word).is_some()
}

fn is_conditional_select(word: u32) -> bool {
    word & 0x7FE0_0C00 == 0x1A80_0000
}

fn extension_effect(word: u32) -> Option<ValueEffect> {
    let family = word & 0x7F80_0000;
    if family != 0x1300_0000 && family != 0x5300_0000 {
        return None;
    }
    let immr = (word >> 16) & 0x3F;
    let imms = (word >> 10) & 0x3F;
    if immr != 0 {
        return None;
    }
    match (family, imms) {
        (0x5300_0000, 7) => Some(ValueEffect::ZeroExtend8),
        (0x5300_0000, 15) => Some(ValueEffect::ZeroExtend16),
        (0x5300_0000, 31) => Some(ValueEffect::ZeroExtend32),
        (0x1300_0000, 7) => Some(ValueEffect::SignExtend8),
        (0x1300_0000, 15) => Some(ValueEffect::SignExtend16),
        (0x1300_0000, 31) => Some(ValueEffect::SignExtend32),
        _ => None,
    }
}

fn pointer_authentication_effect(word: u32) -> Option<ValueEffect> {
    let general = match word & 0xFFFF_FC00 {
        0xDAC1_0000 => Some(ValueEffect::SignPointerIa),
        0xDAC1_0400 => Some(ValueEffect::SignPointerIb),
        0xDAC1_0800 => Some(ValueEffect::SignPointerDa),
        0xDAC1_0C00 => Some(ValueEffect::SignPointerDb),
        0xDAC1_1000 => Some(ValueEffect::AuthenticatePointerIa),
        0xDAC1_1400 => Some(ValueEffect::AuthenticatePointerIb),
        0xDAC1_1800 => Some(ValueEffect::AuthenticatePointerDa),
        0xDAC1_1C00 => Some(ValueEffect::AuthenticatePointerDb),
        _ => None,
    };
    if general.is_some() {
        return general;
    }
    match word & 0xFFFF_FFE0 {
        0xDAC1_23E0 => Some(ValueEffect::SignPointerIa),
        0xDAC1_27E0 => Some(ValueEffect::SignPointerIb),
        0xDAC1_2BE0 => Some(ValueEffect::SignPointerDa),
        0xDAC1_2FE0 => Some(ValueEffect::SignPointerDb),
        0xDAC1_33E0 => Some(ValueEffect::AuthenticatePointerIa),
        0xDAC1_37E0 => Some(ValueEffect::AuthenticatePointerIb),
        0xDAC1_3BE0 => Some(ValueEffect::AuthenticatePointerDa),
        0xDAC1_3FE0 => Some(ValueEffect::AuthenticatePointerDb),
        0xDAC1_43E0 | 0xDAC1_47E0 => Some(ValueEffect::StripPointerAuthentication),
        _ => match word {
            0xD503_233F => Some(ValueEffect::SignPointerIa),
            0xD503_237F => Some(ValueEffect::SignPointerIb),
            0xD503_23BF => Some(ValueEffect::AuthenticatePointerIa),
            0xD503_23FF => Some(ValueEffect::AuthenticatePointerIb),
            _ => None,
        },
    }
}

fn bitfield_shift(word: u32) -> Option<(RegisterShift, u8)> {
    let family = word & 0x7F80_0000;
    if family != 0x5300_0000 && family != 0x1300_0000 {
        return None;
    }
    let width = if word >> 31 == 0 { 32_u8 } else { 64 };
    let immr = ((word >> 16) & 0x3F) as u8;
    let imms = ((word >> 10) & 0x3F) as u8;
    if immr >= width || imms >= width {
        return None;
    }
    if imms == width - 1 {
        return Some((
            if family == 0x1300_0000 {
                RegisterShift::ArithmeticRight
            } else {
                RegisterShift::LogicalRight
            },
            immr,
        ));
    }
    if family == 0x5300_0000 && immr == imms + 1 {
        return Some((RegisterShift::LogicalLeft, width - immr));
    }
    None
}

fn decode_logical_immediate(word: u32) -> Option<u64> {
    let width = if word >> 31 == 0 { 32_u32 } else { 64 };
    let n = (word >> 22) & 1;
    let immr = (word >> 16) & 0x3F;
    let imms = (word >> 10) & 0x3F;
    let length_source = (n << 6) | ((!imms) & 0x3F);
    let len = 31_u32.checked_sub(length_source.leading_zeros())?;
    if len < 1 {
        return None;
    }
    let element_size = 1_u32 << len;
    if element_size > width {
        return None;
    }
    let levels = element_size - 1;
    let set_bits = imms & levels;
    if set_bits == levels {
        return None;
    }
    let rotate = immr & levels;
    let element_mask = if set_bits == 63 {
        u64::MAX
    } else {
        (1_u64 << (set_bits + 1)) - 1
    };
    let element_width_mask = if element_size == 64 {
        u64::MAX
    } else {
        (1_u64 << element_size) - 1
    };
    let rotated = if rotate == 0 {
        element_mask
    } else {
        ((element_mask >> rotate) | (element_mask << (element_size - rotate))) & element_width_mask
    };
    let mut result = 0_u64;
    let mut offset = 0;
    while offset < width {
        result |= rotated << offset;
        offset += element_size;
    }
    Some(if width == 32 {
        result & 0xFFFF_FFFF
    } else {
        result
    })
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
        ops[2] = Operand::Mem {
            base: Reg::gpr(rn),
            disp,
        };
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
        ops[2] = Operand::Mem {
            base: Reg::gpr(rn),
            disp,
        };
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
        ops[1] = Operand::Mem {
            base: Reg::gpr(rn),
            disp,
        };
        return (ops, 2);
    }

    // ── LDR/LDRSW GPR (register offset) ──
    // The option field selects Xm/LSL or a Wm extension. Register width and
    // extension signedness are intentionally normalized here; bounded table
    // recovery needs the base, index, and byte scale, while exact arithmetic
    // semantics remain available from the original instruction bytes.
    if is_load_register_offset(word) && (word >> 22) & 0x3 != 0 && rt != 31 {
        let size = ((word >> 30) & 0x3) as u8;
        let shifted = (word >> 12) & 1 == 1;
        let scale = if shifted { 1_u8 << size } else { 1 };
        ops[0] = Operand::Reg(Reg::gpr(rt));
        ops[1] = Operand::IndexedMem {
            base: Reg::gpr(rn),
            index: Reg::gpr(rm),
            scale,
            disp: 0,
        };
        return (ops, 2);
    }

    // ── LDUR Xt, [Xn, #imm9] ──
    if is_ldur_x(word) {
        let imm9 = ((word >> 12) & 0x1FF) as i32;
        ops[0] = Operand::Reg(Reg::gpr(rt));
        ops[1] = Operand::Mem {
            base: Reg::gpr(rn),
            disp: sign_extend_9(imm9) as i64,
        };
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
        let shift = match (word >> 22) & 0x3 {
            0 => RegisterShift::LogicalLeft,
            1 => RegisterShift::LogicalRight,
            2 => RegisterShift::ArithmeticRight,
            _ => RegisterShift::RotateRight,
        };
        let amount = ((word >> 10) & 0x3F) as u8;
        ops[2] = if amount == 0 {
            Operand::Reg(Reg::gpr(rm))
        } else {
            Operand::ShiftedReg {
                register: Reg::gpr(rm),
                shift,
                amount,
            }
        };
        return (ops, 3);
    }

    // ── PAC/AUT/XPAC register and implicit-SP forms ──
    if pointer_authentication_effect(word).is_some() {
        let (destination, modifier, zero_modifier) = match word {
            0xD503_233F | 0xD503_237F | 0xD503_23BF | 0xD503_23FF => (30, 31, false),
            _ => (rd, rn, word & 0xFFFF_FC00 == 0xDAC1_2000),
        };
        ops[0] = Operand::Reg(Reg::gpr(destination));
        ops[1] = Operand::Reg(Reg::gpr(destination));
        if !matches!(
            pointer_authentication_effect(word),
            Some(ValueEffect::StripPointerAuthentication)
        ) {
            ops[2] = Operand::Reg(Reg::gpr(if zero_modifier { 31 } else { modifier }));
            return (ops, 3);
        }
        return (ops, 2);
    }

    // ── Integer extension aliases ──
    if extension_effect(word).is_some() {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::Reg(Reg::gpr(rn));
        return (ops, 2);
    }

    // ── AND (logical immediate) ──
    if is_and_immediate(word) {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::Reg(Reg::gpr(rn));
        ops[2] = Operand::Imm(decode_logical_immediate(word).unwrap_or(0) as i64);
        return (ops, 3);
    }

    // ── LSL/LSR/ASR bitfield aliases ──
    if let Some((shift, amount)) = bitfield_shift(word) {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::ShiftedReg {
            register: Reg::gpr(rn),
            shift,
            amount,
        };
        return (ops, 2);
    }

    // ── CSEL ──
    if is_conditional_select(word) {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::Reg(Reg::gpr(rn));
        ops[2] = Operand::Reg(Reg::gpr(rm));
        return (ops, 3);
    }

    // ── MOV Xd, Xm (ORR alias) ──
    if is_mov_register(word) {
        ops[0] = Operand::Reg(Reg::gpr(rd));
        ops[1] = Operand::Reg(Reg::gpr(rm));
        return (ops, 2);
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

    // ── Authenticated branch-register families ──
    // The target register is Rn. Forms with an explicit modifier encode it in
    // the low register field; retaining both is sufficient for target-value
    // recovery while authentication details remain in the raw opcode layer.
    if word & 0xFE00_0000 == 0xD600_0000 {
        ops[0] = Operand::Reg(Reg::gpr(rn));
        ops[1] = Operand::Reg(Reg::gpr(rt));
        return (ops, 2);
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

    // ── RET / RETAA / RETAB ──
    if word & 0xFFFF_FC1F == 0xD65F_0000 || word == 0xD65F_0BFF || word == 0xD65F_0FFF {
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

fn sign_extend_9(val: i32) -> i32 {
    if val & (1 << 8) != 0 {
        val | !0x1FF
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
) -> Result<Vec<u8>, crate::insn::EncodeError> {
    let delta = to_va as i64 - from_va as i64;

    if delta % 4 != 0 {
        return Err(crate::insn::EncodeError {
            message: format!(
                "arm64 branch target {to_va:#x} is not 4-byte aligned from {from_va:#x}"
            ),
        });
    }

    let imm26 = delta / 4;
    if !(-(1 << 25)..(1 << 25)).contains(&imm26) {
        return Err(crate::insn::EncodeError {
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
) -> Result<Vec<u8>, crate::insn::EncodeError> {
    if bytes.len() < 4 {
        return Err(crate::insn::EncodeError {
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
            return Err(crate::insn::EncodeError {
                message: "unaligned conditional branch relocation".into(),
            });
        }
        let new_imm19 = new_offset / 4;
        if !(-(1 << 18)..(1 << 18)).contains(&new_imm19) {
            return Err(crate::insn::EncodeError {
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
            return Err(crate::insn::EncodeError {
                message: "unaligned CBZ/CBNZ relocation".into(),
            });
        }
        let new_imm19 = new_offset / 4;
        if !(-(1 << 18)..(1 << 18)).contains(&new_imm19) {
            return Err(crate::insn::EncodeError {
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
            return Err(crate::insn::EncodeError {
                message: "unaligned TBZ/TBNZ relocation".into(),
            });
        }
        let new_imm14 = new_offset / 4;
        if !(-(1 << 13)..(1 << 13)).contains(&new_imm14) {
            return Err(crate::insn::EncodeError {
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
        if !(-(1 << 20)..(1 << 20)).contains(&new_offset) {
            return Err(crate::insn::EncodeError {
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
            return Err(crate::insn::EncodeError {
                message: "ADRP relocation page misalignment".into(),
            });
        }
        let new_imm = new_offset / 4096;
        if !(-(1 << 20)..(1 << 20)).contains(&new_imm) {
            return Err(crate::insn::EncodeError {
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
            return Err(crate::insn::EncodeError {
                message: "unaligned literal load relocation".into(),
            });
        }
        let new_imm19 = new_offset / 4;
        if !(-(1 << 18)..(1 << 18)).contains(&new_imm19) {
            return Err(crate::insn::EncodeError {
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
    Ok(format_word(read_word(bytes)?, va).0)
}

fn format_word(word: u32, va: u64) -> (String, bool) {
    match mkasm_aarch64::format(word, va) {
        Ok(text) => (text, false),
        Err(_) => (format!(".inst 0x{word:08x}"), true),
    }
}

pub(crate) fn disassemble(bytes: &[u8], base_va: u64) -> Result<Vec<(u64, String)>, DecodeError> {
    if bytes.len() % 4 != 0 {
        return Err(DecodeError {
            kind: DecodeErrorKind::Truncated,
            message: "arm64 instruction stream must be 4-byte aligned".into(),
        });
    }

    let mut result = Vec::new();
    for (i, chunk) in bytes.chunks_exact(4).enumerate() {
        let va = base_va + (i * 4) as u64;
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        let text = match mkasm_aarch64::format(word, va) {
            Ok(text) => text,
            Err(_) => format!(".inst 0x{word:08x}"),
        };
        result.push((va, text));
    }

    Ok(result)
}
