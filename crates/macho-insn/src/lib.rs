//! Architecture-aware instruction decoding, encoding, and relocation.
//!
//! Wraps [`iced_x86`] and [`bad64`] behind a unified API for the instruction-level
//! operations that Mach-O patching, xref analysis, and binary diffing need:
//!
//! - **Decode**: length, classification, branch target extraction
//! - **Encode**: branch instruction construction, NOP fill
//! - **Relocate**: rewrite PC-relative operands for a new address
//! - **Disassemble**: instruction-to-text for display

mod arm64;
mod encode;
mod x86_64;

use std::fmt;

// ───────────────────────────────────────────── types ─────

/// Register class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegClass {
    /// General-purpose register (x0-x30 on ARM64, rax-r15 on x86_64).
    Gpr,
    /// Floating-point / SIMD register (d0-d31 on ARM64, xmm0-xmm15 on x86_64).
    Fp,
}

/// A register operand.
///
/// `num` is the raw encoding number: 0-30 for ARM64 GPRs, 0-15 for x86_64 GPRs.
/// ARM64 register 31 encodes SP or ZR depending on instruction context.
/// x86_64 numbering: rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8-r15=8-15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Reg {
    pub class: RegClass,
    pub num: u8,
}

impl Reg {
    pub fn gpr(num: u8) -> Self {
        Self { class: RegClass::Gpr, num }
    }
    pub fn fp(num: u8) -> Self {
        Self { class: RegClass::Fp, num }
    }
}

impl fmt::Display for Reg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.class {
            RegClass::Gpr => write!(f, "gpr{}", self.num),
            RegClass::Fp => write!(f, "fp{}", self.num),
        }
    }
}

/// An instruction operand.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operand {
    /// Register operand.
    Reg(Reg),
    /// Immediate value.
    Imm(i64),
    /// Memory operand with base register and displacement.
    Mem { base: Reg, disp: i64 },
}

const MAX_OPERANDS: usize = 4;

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Arch {
    X86_64,
    Arm64,
    Arm64e,
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86_64 => write!(f, "x86_64"),
            Self::Arm64 => write!(f, "arm64"),
            Self::Arm64e => write!(f, "arm64e"),
        }
    }
}

impl Arch {
    /// Whether this architecture uses the AArch64 instruction set.
    pub fn is_arm64(self) -> bool {
        matches!(self, Self::Arm64 | Self::Arm64e)
    }
}

/// A decoded instruction.
#[derive(Debug, Clone)]
pub struct Insn {
    /// Byte offset into the input buffer where this instruction starts.
    pub offset: usize,
    /// Byte length of this instruction.
    pub len: usize,
    /// Semantic classification.
    pub kind: InsnKind,
    /// True when this instruction writes GPR0 (rax on x86_64) as a hidden
    /// side effect not visible in the operand list. Set for DIV, IDIV, MUL,
    /// single-operand IMUL, CWD/CDQ/CQO, and sign-extension instructions.
    /// Always false on ARM64 (no implicit register side effects).
    pub writes_implicit_gpr0: bool,
    ops: [Operand; MAX_OPERANDS],
    op_count: u8,
}

impl Insn {
    /// The instruction's operands (registers, immediates, memory references).
    pub fn operands(&self) -> &[Operand] {
        &self.ops[..self.op_count as usize]
    }

    pub(crate) fn with_ops(
        len: usize,
        kind: InsnKind,
        ops: [Operand; MAX_OPERANDS],
        op_count: u8,
        writes_implicit_gpr0: bool,
    ) -> Self {
        Self {
            offset: 0,
            len,
            kind,
            writes_implicit_gpr0,
            ops,
            op_count,
        }
    }
}

/// High-level classification of an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InsnKind {
    /// Unconditional branch (B, JMP).
    Branch(BranchInfo),
    /// Call with link (BL, CALL).
    Call(BranchInfo),
    /// Conditional branch (B.cond, Jcc, CBZ, CBNZ, TBZ, TBNZ, LOOP).
    CondBranch(BranchInfo),
    /// Return (RET, C3/CB).
    Return,
    /// No-op.
    Nop,
    /// PC-relative non-branch (ADR, ADRP, RIP-relative LEA, literal loads).
    PcRelative(PcRelInfo),
    /// Anything else.
    Other,
}

/// Branch operand information.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BranchInfo {
    pub target: BranchTarget,
}

/// How a branch resolves its destination.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchTarget {
    /// A PC-relative offset (signed, from the instruction's VA).
    Direct(i64),
    /// Register-indirect (BR x16, JMP rax).
    Register,
    /// Memory-indirect (JMP [rip+disp], etc.).
    Indirect,
}

/// PC-relative operand that is *not* a branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcRelInfo {
    /// Signed displacement from the instruction's VA.
    pub displacement: i64,
}

/// Errors from decode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    pub message: String,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "decode: {}", self.message)
    }
}

impl std::error::Error for DecodeError {}

/// Errors from encode / relocate operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodeError {
    pub message: String,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "encode: {}", self.message)
    }
}

impl std::error::Error for EncodeError {}

// ───────────────────────────────────── iterator ─────

/// Iterator over decoded instructions in a byte slice.
pub struct InsnIter<'a> {
    bytes: &'a [u8],
    base_va: u64,
    offset: usize,
    arch: Arch,
}

impl<'a> Iterator for InsnIter<'a> {
    type Item = Insn;

    fn next(&mut self) -> Option<Insn> {
        loop {
            if self.offset >= self.bytes.len() {
                return None;
            }
            let va = self.base_va + self.offset as u64;
            match decode_one(&self.bytes[self.offset..], va, self.arch) {
                Ok(mut insn) => {
                    insn.offset = self.offset;
                    self.offset += insn.len;
                    return Some(insn);
                }
                Err(_) => {
                    // Skip one byte (x86_64) or 4 bytes (arm64) on decode failure.
                    if self.arch.is_arm64() {
                        self.offset += 4;
                    } else {
                        self.offset += 1;
                    }
                }
            }
        }
    }
}

// ───────────────────────────────── public API ─────

/// Decode a single instruction at the start of `bytes`.
pub fn decode_one(bytes: &[u8], va: u64, arch: Arch) -> Result<Insn, DecodeError> {
    match arch {
        Arch::X86_64 => x86_64::decode_one(bytes, va),
        Arch::Arm64 | Arch::Arm64e => arm64::decode_one(bytes, va),
    }
}

/// Iterate over all instructions in `bytes`, starting at `base_va`.
pub fn decode_iter(bytes: &[u8], base_va: u64, arch: Arch) -> InsnIter<'_> {
    InsnIter {
        bytes,
        base_va,
        offset: 0,
        arch,
    }
}

/// Return the byte length of the instruction at the start of `bytes`.
pub fn instruction_len(bytes: &[u8], arch: Arch) -> Result<usize, DecodeError> {
    decode_one(bytes, 0, arch).map(|insn| insn.len)
}

/// Resolve the absolute branch/call target VA, if the instruction has a direct target.
pub fn resolve_branch_target(insn: &Insn, insn_va: u64) -> Option<u64> {
    let info = match &insn.kind {
        InsnKind::Branch(b) | InsnKind::Call(b) | InsnKind::CondBranch(b) => b,
        _ => return None,
    };
    match info.target {
        BranchTarget::Direct(offset) => Some(insn_va.wrapping_add_signed(offset)),
        _ => None,
    }
}

/// Whether an instruction can be safely relocated to a different VA.
///
/// Returns `true` for instructions that are either position-independent or
/// that the relocation engine knows how to rewrite.
pub fn can_relocate(insn: &Insn) -> bool {
    match &insn.kind {
        InsnKind::Other | InsnKind::Nop | InsnKind::Return => true,
        InsnKind::Branch(_) | InsnKind::Call(_) | InsnKind::CondBranch(_) => true,
        InsnKind::PcRelative(_) => true,
    }
}

/// Encode a direct branch (or call) instruction from `from_va` to `to_va`.
///
/// If `link` is `true`, encodes a call (BL / CALL); otherwise an unconditional
/// branch (B / JMP).
pub fn encode_branch(
    from_va: u64,
    to_va: u64,
    link: bool,
    arch: Arch,
) -> Result<Vec<u8>, EncodeError> {
    encode::encode_branch(from_va, to_va, link, arch)
}

/// Generate `byte_count` bytes of architecture-appropriate NOP fill.
pub fn encode_nop(arch: Arch, byte_count: usize) -> Result<Vec<u8>, EncodeError> {
    encode::encode_nop(arch, byte_count)
}

/// Relocate the instruction in `bytes` (decoded at `old_va`) so it executes
/// correctly at `new_va`. Returns the rewritten instruction bytes.
pub fn relocate_insn(
    bytes: &[u8],
    old_va: u64,
    new_va: u64,
    arch: Arch,
) -> Result<Vec<u8>, EncodeError> {
    encode::relocate_insn(bytes, old_va, new_va, arch)
}

/// Disassemble a single instruction to a human-readable string.
pub fn disassemble_one(bytes: &[u8], va: u64, arch: Arch) -> Result<String, DecodeError> {
    match arch {
        Arch::X86_64 => x86_64::disassemble_one(bytes, va),
        Arch::Arm64 | Arch::Arm64e => arm64::disassemble_one(bytes, va),
    }
}

/// Disassemble all instructions in `bytes` to `(va, text)` pairs.
pub fn disassemble(
    bytes: &[u8],
    base_va: u64,
    arch: Arch,
) -> Result<Vec<(u64, String)>, DecodeError> {
    match arch {
        Arch::X86_64 => x86_64::disassemble(bytes, base_va),
        Arch::Arm64 | Arch::Arm64e => arm64::disassemble(bytes, base_va),
    }
}

// ───────────────────────────────────── tests ─────

#[cfg(test)]
mod tests {
    use super::*;

    // x86_64: NOP (0x90)
    #[test]
    fn x86_64_nop() {
        let insn = decode_one(&[0x90], 0x1000, Arch::X86_64).unwrap();
        assert_eq!(insn.len, 1);
        assert_eq!(insn.kind, InsnKind::Nop);
    }

    // x86_64: RET (0xC3)
    #[test]
    fn x86_64_ret() {
        let insn = decode_one(&[0xC3], 0x1000, Arch::X86_64).unwrap();
        assert_eq!(insn.len, 1);
        assert_eq!(insn.kind, InsnKind::Return);
    }

    // x86_64: CALL rel32 (E8 xx xx xx xx)
    #[test]
    fn x86_64_call_rel32() {
        // CALL +0x100 (from VA 0x1000, next_ip = 0x1005, target = 0x1105)
        let bytes = [0xE8, 0x00, 0x01, 0x00, 0x00];
        let insn = decode_one(&bytes, 0x1000, Arch::X86_64).unwrap();
        assert_eq!(insn.len, 5);
        assert!(matches!(insn.kind, InsnKind::Call(_)));
        assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x1105));
    }

    // x86_64: JMP rel32 (E9 xx xx xx xx)
    #[test]
    fn x86_64_jmp_rel32() {
        // JMP +0 (from VA 0x2000, next_ip = 0x2005, target = 0x2005)
        let bytes = [0xE9, 0x00, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes, 0x2000, Arch::X86_64).unwrap();
        assert_eq!(insn.len, 5);
        assert!(matches!(insn.kind, InsnKind::Branch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x2000), Some(0x2005));
    }

    // x86_64: JE rel8 (74 xx)
    #[test]
    fn x86_64_je_rel8() {
        // JE +0x10 (from VA 0x3000, next_ip = 0x3002, target = 0x3012)
        let bytes = [0x74, 0x10];
        let insn = decode_one(&bytes, 0x3000, Arch::X86_64).unwrap();
        assert_eq!(insn.len, 2);
        assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x3000), Some(0x3012));
    }

    // ARM64: BL #offset
    #[test]
    fn arm64_bl() {
        // BL #0x100 (from VA 0x4000, target = 0x4100)
        // imm26 = 0x100 / 4 = 0x40
        // encoding: 0x94000000 | 0x40 = 0x94000040
        let bytes = 0x9400_0040u32.to_le_bytes();
        let insn = decode_one(&bytes, 0x4000, Arch::Arm64).unwrap();
        assert_eq!(insn.len, 4);
        assert!(matches!(insn.kind, InsnKind::Call(_)));
        assert_eq!(resolve_branch_target(&insn, 0x4000), Some(0x4100));
    }

    // ARM64: B #offset
    #[test]
    fn arm64_b() {
        // B #-0x10 (from VA 0x5000, target = 0x4FF0)
        // imm26 = -0x10 / 4 = -4 → 0x03FFFFFC
        let imm26 = ((-4i32) as u32) & 0x03FF_FFFF;
        let word = 0x1400_0000u32 | imm26;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x5000, Arch::Arm64).unwrap();
        assert_eq!(insn.len, 4);
        assert!(matches!(insn.kind, InsnKind::Branch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x5000), Some(0x4FF0));
    }

    // ARM64: NOP (0xD503201F)
    #[test]
    fn arm64_nop() {
        let bytes = 0xD503_201Fu32.to_le_bytes();
        let insn = decode_one(&bytes, 0x6000, Arch::Arm64).unwrap();
        assert_eq!(insn.len, 4);
        assert_eq!(insn.kind, InsnKind::Nop);
    }

    // ARM64: RET
    #[test]
    fn arm64_ret() {
        let bytes = 0xD65F_03C0u32.to_le_bytes();
        let insn = decode_one(&bytes, 0x7000, Arch::Arm64).unwrap();
        assert_eq!(insn.len, 4);
        assert_eq!(insn.kind, InsnKind::Return);
    }

    // NOP encoding
    #[test]
    fn nop_encoding_x86_64() {
        let nops = encode_nop(Arch::X86_64, 5).unwrap();
        assert_eq!(nops.len(), 5);
        // All bytes should decode as NOPs (or multi-byte NOPs)
    }

    #[test]
    fn nop_encoding_arm64() {
        let nops = encode_nop(Arch::Arm64, 8).unwrap();
        assert_eq!(nops.len(), 8);
        assert_eq!(&nops[0..4], &[0x1F, 0x20, 0x03, 0xD5]);
        assert_eq!(&nops[4..8], &[0x1F, 0x20, 0x03, 0xD5]);
    }

    #[test]
    fn nop_encoding_arm64_rejects_non_aligned() {
        assert!(encode_nop(Arch::Arm64, 3).is_err());
    }

    // Branch encoding round-trip
    #[test]
    fn encode_branch_x86_64_call() {
        let encoded = encode_branch(0x1000, 0x2000, true, Arch::X86_64).unwrap();
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 0xE8);
        let insn = decode_one(&encoded, 0x1000, Arch::X86_64).unwrap();
        assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x2000));
    }

    #[test]
    fn encode_branch_arm64_bl() {
        let encoded = encode_branch(0x4000, 0x4100, true, Arch::Arm64).unwrap();
        assert_eq!(encoded.len(), 4);
        let insn = decode_one(&encoded, 0x4000, Arch::Arm64).unwrap();
        assert_eq!(resolve_branch_target(&insn, 0x4000), Some(0x4100));
    }

    // decode_iter
    #[test]
    fn decode_iter_x86_64() {
        // NOP NOP RET
        let bytes = [0x90, 0x90, 0xC3];
        let insns: Vec<_> = decode_iter(&bytes, 0x1000, Arch::X86_64).collect();
        assert_eq!(insns.len(), 3);
        assert_eq!(insns[0].kind, InsnKind::Nop);
        assert_eq!(insns[0].offset, 0);
        assert_eq!(insns[1].kind, InsnKind::Nop);
        assert_eq!(insns[1].offset, 1);
        assert_eq!(insns[2].kind, InsnKind::Return);
        assert_eq!(insns[2].offset, 2);
    }

    // Disassembly
    #[test]
    fn disassemble_x86_64_nop() {
        let text = disassemble_one(&[0x90], 0x1000, Arch::X86_64).unwrap();
        assert!(text.to_lowercase().contains("nop"), "got: {text}");
    }

    #[test]
    fn disassemble_arm64_nop() {
        let bytes = 0xD503_201Fu32.to_le_bytes();
        let text = disassemble_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(text.to_lowercase().contains("nop"), "got: {text}");
    }

    // ── TBZ/TBNZ decode + relocation round-trip ──

    #[test]
    fn arm64_tbz_decode() {
        // TBZ x0, #0, +0x10  → b5=0, b40=00000, imm14=4, Rt=0
        // Encoding: 0 0110110 0 00000 00000000000100 00000
        //         = 0x36000080
        let word: u32 = 0x3600_0080;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x1010));
    }

    #[test]
    fn arm64_tbnz_high_bit_relocate_preserves_b40() {
        // TBNZ x0, #17, +0x20 — tests bit 17, so b5=0, b40=10001 (=17).
        // b40 field is bits[23:19]. b40=17=0b10001.
        // imm14 = 0x20 / 4 = 8.
        // Encoding: 0 0110111 0 10001 00000000001000 00000
        let b40: u32 = 17;
        let imm14: u32 = 8;
        let word: u32 = 0x3700_0000 | (b40 << 19) | (imm14 << 5);
        let bytes = word.to_le_bytes();

        // Verify decode
        let insn = decode_one(&bytes, 0x2000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x2000), Some(0x2020));

        // Relocate to 0x3000 — target should still be 0x2020
        let relocated = relocate_insn(&bytes, 0x2000, 0x3000, Arch::Arm64).unwrap();
        let relocated_word = u32::from_le_bytes([relocated[0], relocated[1], relocated[2], relocated[3]]);
        // Verify b40 field (bits[23:19]) is preserved
        let b40_after = (relocated_word >> 19) & 0x1F;
        assert_eq!(b40_after, 17, "b40 field corrupted during relocation");
        // Verify the target resolves correctly
        let insn2 = decode_one(&relocated, 0x3000, Arch::Arm64).unwrap();
        assert_eq!(resolve_branch_target(&insn2, 0x3000), Some(0x2020));
    }

    // ── CBZ/CBNZ decode ──

    #[test]
    fn arm64_cbz_decode() {
        // CBZ x0, +0x40  →  sf=1, op=0, imm19=0x10, Rt=0
        // Encoding: 1 011010 0 0000000000000010000 00000 = 0xB4000200
        let word: u32 = 0xB400_0200;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x1040));
    }

    // ── B.cond decode ──

    #[test]
    fn arm64_bcond_decode() {
        // B.EQ +0x100  →  imm19 = 0x100/4 = 0x40, cond=0000 (EQ)
        // Encoding: 0x54000000 | (0x40 << 5) = 0x54000800
        let word: u32 = 0x5400_0800;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x5000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x5000), Some(0x5100));
    }

    // ── ADR/ADRP decode ──

    #[test]
    fn arm64_adr_decode() {
        // ADR x0, +0x4  →  immhi=1, immlo=0, Rd=0
        // Encoding: 0 00 10000 0000000000000000001 00000 = 0x10000020
        let word: u32 = 0x1000_0020;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::PcRelative(_)));
        if let InsnKind::PcRelative(info) = &insn.kind {
            assert_eq!(info.displacement, 4);
        }
    }

    #[test]
    fn arm64_adrp_decode() {
        // ADRP x0, +0x1000 (one page forward)
        // immhi=0, immlo=01, Rd=0  →  imm = (0<<2)|1 = 1 → offset = 1 * 4096 = 0x1000
        // Encoding: 1 01 10000 0000000000000000000 00000 = 0x90000000 | (1<<29) = 0xB0000000
        let word: u32 = 0xB000_0000;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x2000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::PcRelative(_)));
        if let InsnKind::PcRelative(info) = &insn.kind {
            // ADRP: target = page_of(0x2000) + 1*4096 = 0x2000 + 0x1000 = 0x3000
            // displacement = 0x3000 - 0x2000 = 0x1000
            assert_eq!(info.displacement, 0x1000);
        }
    }

    // ── LDR literal decode ──

    #[test]
    fn arm64_ldr_literal_decode() {
        // LDR x0, +0x10  →  opc=01, V=0, imm19=4, Rt=0
        // Encoding: 01 011 0 00 0000000000000000100 00000 = 0x58000080
        let word: u32 = 0x5800_0080;
        let bytes = word.to_le_bytes();
        let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::PcRelative(_)));
        if let InsnKind::PcRelative(info) = &insn.kind {
            assert_eq!(info.displacement, 0x10);
        }
    }

    // ── BR / BLR (register) decode ──

    #[test]
    fn arm64_br_register() {
        // BR x16 = 0xD61F0200
        let bytes = 0xD61F_0200u32.to_le_bytes();
        let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(matches!(
            insn.kind,
            InsnKind::Branch(BranchInfo { target: BranchTarget::Register })
        ));
    }

    #[test]
    fn arm64_blr_register() {
        // BLR x8 = 0xD63F0100
        let bytes = 0xD63F_0100u32.to_le_bytes();
        let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert!(matches!(
            insn.kind,
            InsnKind::Call(BranchInfo { target: BranchTarget::Register })
        ));
    }

    // ── x86_64 RIP-relative (PcRelative) decode ──

    #[test]
    fn x86_64_lea_rip_relative() {
        // LEA rax, [rip+0x10]  →  48 8D 05 10 00 00 00
        let bytes = [0x48, 0x8D, 0x05, 0x10, 0x00, 0x00, 0x00];
        let insn = decode_one(&bytes, 0x1000, Arch::X86_64).unwrap();
        assert!(
            matches!(insn.kind, InsnKind::PcRelative(_)),
            "expected PcRelative, got {:?}",
            insn.kind
        );
    }

    // ── x86_64 branch encoding (JMP, not just CALL) ──

    #[test]
    fn encode_branch_x86_64_jmp() {
        let encoded = encode_branch(0x1000, 0x2000, false, Arch::X86_64).unwrap();
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[0], 0xE9);
        let insn = decode_one(&encoded, 0x1000, Arch::X86_64).unwrap();
        assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x2000));
    }

    // ── arm64 B (unconditional) encoding round-trip ──

    #[test]
    fn encode_branch_arm64_b() {
        let encoded = encode_branch(0x4000, 0x4100, false, Arch::Arm64).unwrap();
        assert_eq!(encoded.len(), 4);
        let insn = decode_one(&encoded, 0x4000, Arch::Arm64).unwrap();
        assert!(matches!(insn.kind, InsnKind::Branch(_)));
        assert_eq!(resolve_branch_target(&insn, 0x4000), Some(0x4100));
    }

    // ── decode error cases ──

    #[test]
    fn decode_error_empty_x86() {
        assert!(decode_one(&[], 0, Arch::X86_64).is_err());
    }

    #[test]
    fn decode_error_short_arm64() {
        assert!(decode_one(&[0x00, 0x00], 0, Arch::Arm64).is_err());
    }

    // ── decode_iter skips invalid bytes without stack overflow ──

    #[test]
    fn decode_iter_skips_invalid_bytes() {
        // 256 invalid bytes (0xFF) followed by NOP + RET.
        // Should not stack-overflow and should find the trailing instructions.
        let mut bytes = vec![0xFFu8; 256];
        bytes.push(0x90); // NOP
        bytes.push(0xC3); // RET
        let insns: Vec<_> = decode_iter(&bytes, 0x1000, Arch::X86_64).collect();
        assert!(insns.len() >= 2);
        let last_two: Vec<_> = insns.iter().rev().take(2).collect();
        assert_eq!(last_two[0].kind, InsnKind::Return);
        assert_eq!(last_two[1].kind, InsnKind::Nop);
    }

    // ── instruction_len ──

    #[test]
    fn instruction_len_x86_64() {
        assert_eq!(instruction_len(&[0x90], Arch::X86_64).unwrap(), 1);
        assert_eq!(
            instruction_len(&[0xE8, 0x00, 0x00, 0x00, 0x00], Arch::X86_64).unwrap(),
            5
        );
    }

    #[test]
    fn instruction_len_arm64() {
        let nop = 0xD503_201Fu32.to_le_bytes();
        assert_eq!(instruction_len(&nop, Arch::Arm64).unwrap(), 4);
    }

    // ── can_relocate ──

    #[test]
    fn can_relocate_all_kinds() {
        let nop = decode_one(&[0x90], 0x1000, Arch::X86_64).unwrap();
        assert!(can_relocate(&nop));

        let ret = decode_one(&[0xC3], 0x1000, Arch::X86_64).unwrap();
        assert!(can_relocate(&ret));

        let call_bytes = [0xE8, 0x00, 0x01, 0x00, 0x00];
        let call = decode_one(&call_bytes, 0x1000, Arch::X86_64).unwrap();
        assert!(can_relocate(&call));
    }

    // ── Arch Display + is_arm64 ──

    #[test]
    fn arch_display() {
        assert_eq!(format!("{}", Arch::X86_64), "x86_64");
        assert_eq!(format!("{}", Arch::Arm64), "arm64");
        assert_eq!(format!("{}", Arch::Arm64e), "arm64e");
    }

    #[test]
    fn arch_is_arm64() {
        assert!(!Arch::X86_64.is_arm64());
        assert!(Arch::Arm64.is_arm64());
        assert!(Arch::Arm64e.is_arm64());
    }

    // ── disassemble (multi-instruction) ──

    #[test]
    fn disassemble_x86_64_multi() {
        // NOP NOP RET
        let bytes = [0x90, 0x90, 0xC3];
        let result = disassemble(&bytes, 0x1000, Arch::X86_64).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, 0x1000);
        assert_eq!(result[1].0, 0x1001);
        assert_eq!(result[2].0, 0x1002);
    }

    #[test]
    fn disassemble_arm64_multi() {
        // NOP NOP RET
        let nop = 0xD503_201Fu32;
        let ret = 0xD65F_03C0u32;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&nop.to_le_bytes());
        bytes.extend_from_slice(&nop.to_le_bytes());
        bytes.extend_from_slice(&ret.to_le_bytes());
        let result = disassemble(&bytes, 0x1000, Arch::Arm64).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[0].0, 0x1000);
        assert_eq!(result[1].0, 0x1004);
        assert_eq!(result[2].0, 0x1008);
    }

    // ── resolve_branch_target returns None for non-branch ──

    #[test]
    fn resolve_branch_target_none_for_nop() {
        let insn = decode_one(&[0x90], 0x1000, Arch::X86_64).unwrap();
        assert_eq!(resolve_branch_target(&insn, 0x1000), None);
    }

    // ── error Display impls ──

    #[test]
    fn error_display() {
        let de = DecodeError { message: "test".into() };
        assert_eq!(format!("{de}"), "decode: test");

        let ee = EncodeError { message: "test".into() };
        assert_eq!(format!("{ee}"), "encode: test");
    }

    // ── operand extraction: x86_64 ──

    #[test]
    fn x86_64_push_rdi_operands() {
        // PUSH rdi = 0x57
        let insn = decode_one(&[0x57], 0x1000, Arch::X86_64).unwrap();
        let ops = insn.operands();
        assert!(
            ops.iter().any(|op| *op == Operand::Reg(Reg::gpr(7))),
            "expected rdi (gpr7) in operands, got: {ops:?}"
        );
    }

    #[test]
    fn x86_64_add_rdi_imm8_operands() {
        // ADD rdi, 8 = 48 83 C7 08
        let insn = decode_one(&[0x48, 0x83, 0xC7, 0x08], 0x1000, Arch::X86_64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 2, "expected 2 operands, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::gpr(7))); // rdi
        assert_eq!(ops[1], Operand::Imm(8));
    }

    #[test]
    fn x86_64_mov_rsp_disp_rdi_operands() {
        // MOV [rsp+0x08], rdi = 48 89 7C 24 08
        let insn = decode_one(&[0x48, 0x89, 0x7C, 0x24, 0x08], 0x1000, Arch::X86_64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 2, "expected 2 operands, got: {ops:?}");
        assert!(matches!(ops[0], Operand::Mem { base: Reg { num: 4, .. }, disp: 8 })); // [rsp+8]
        assert_eq!(ops[1], Operand::Reg(Reg::gpr(7))); // rdi
    }

    #[test]
    fn x86_64_movsd_xmm0_operands() {
        // MOVSD xmm0, xmm1 = F2 0F 10 C1
        let insn = decode_one(&[0xF2, 0x0F, 0x10, 0xC1], 0x1000, Arch::X86_64).unwrap();
        let ops = insn.operands();
        assert!(ops.len() >= 2, "expected >=2 operands, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::fp(0))); // xmm0
        assert_eq!(ops[1], Operand::Reg(Reg::fp(1))); // xmm1
    }

    // ── operand extraction: ARM64 ──

    #[test]
    fn arm64_stp_x0_x1_sp_operands() {
        // STP x0, x1, [sp, #-16]! = A9 BF 07 E0
        // sf=1, opc=10, V=0, pre-index, imm7=-2 (scaled by 8 → -16), Rt2=1, Rn=31(sp), Rt=0
        let word: u32 = 0xA9BF_07E0;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 3, "expected 3 operands for STP, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::gpr(0))); // x0
        assert_eq!(ops[1], Operand::Reg(Reg::gpr(1))); // x1
        assert!(matches!(ops[2], Operand::Mem { base: Reg { num: 31, .. }, disp: -16 }));
    }

    #[test]
    fn arm64_str_x8_sp_operands() {
        // STR x8, [sp] = F9 00 03 E8
        // sf=1, size=11, V=0, opc=00, imm12=0, Rn=31(sp), Rt=8
        let word: u32 = 0xF900_03E8;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 2, "expected 2 operands for STR, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::gpr(8))); // x8
        assert!(matches!(ops[2 - 1], Operand::Mem { base: Reg { num: 31, .. }, disp: 0 }));
    }

    #[test]
    fn arm64_add_x0_x1_imm_operands() {
        // ADD x0, x1, #42 = 91 00 A8 20
        // sf=1, op=0, S=0, 100010, sh=0, imm12=42, Rn=1, Rd=0
        let word: u32 = 0x9100_A820;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 3, "expected 3 operands for ADD, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::gpr(0))); // x0
        assert_eq!(ops[1], Operand::Reg(Reg::gpr(1))); // x1
        assert_eq!(ops[2], Operand::Imm(42));
    }

    #[test]
    fn arm64_fmov_d0_d1_operands() {
        // FMOV d0, d1 = 1E 60 40 20
        let word: u32 = 0x1E60_4020;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 2, "expected 2 operands for FMOV, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::fp(0)));  // d0
        assert_eq!(ops[1], Operand::Reg(Reg::fp(1)));  // d1
    }

    // ── writes_implicit_gpr0 flag ──

    #[test]
    fn x86_64_div_sets_implicit_gpr0() {
        // DIV rcx = 48 F7 F1
        let insn = decode_one(&[0x48, 0xF7, 0xF1], 0x1000, Arch::X86_64).unwrap();
        assert!(insn.writes_implicit_gpr0);
    }

    #[test]
    fn x86_64_idiv_sets_implicit_gpr0() {
        // IDIV ecx = F7 F9
        let insn = decode_one(&[0xF7, 0xF9], 0x1000, Arch::X86_64).unwrap();
        assert!(insn.writes_implicit_gpr0);
    }

    #[test]
    fn x86_64_mul_sets_implicit_gpr0() {
        // MUL rcx = 48 F7 E1
        let insn = decode_one(&[0x48, 0xF7, 0xE1], 0x1000, Arch::X86_64).unwrap();
        assert!(insn.writes_implicit_gpr0);
    }

    #[test]
    fn x86_64_cdq_sets_implicit_gpr0() {
        // CDQ = 99
        let insn = decode_one(&[0x99], 0x1000, Arch::X86_64).unwrap();
        assert!(insn.writes_implicit_gpr0);
    }

    #[test]
    fn x86_64_imul_two_operand_does_not_set_flag() {
        // IMUL rax, rcx = 48 0F AF C1 (2-operand form, explicit dest)
        let insn = decode_one(&[0x48, 0x0F, 0xAF, 0xC1], 0x1000, Arch::X86_64).unwrap();
        assert!(!insn.writes_implicit_gpr0);
    }

    #[test]
    fn x86_64_mov_does_not_set_implicit_gpr0() {
        // MOV eax, 42 = B8 2A 00 00 00
        let insn = decode_one(&[0xB8, 0x2A, 0x00, 0x00, 0x00], 0x1000, Arch::X86_64).unwrap();
        assert!(!insn.writes_implicit_gpr0);
    }

    #[test]
    fn arm64_never_sets_implicit_gpr0() {
        // NOP
        let insn = decode_one(&0xD503_201Fu32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        assert!(!insn.writes_implicit_gpr0);
    }

    // ── ARM64 RETAA/RETAB ──

    #[test]
    fn arm64_retaa_is_return() {
        let insn = decode_one(&0xD65F_0BFFu32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        assert_eq!(insn.kind, InsnKind::Return);
    }

    #[test]
    fn arm64_retab_is_return() {
        let insn = decode_one(&0xD65F_0FFFu32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        assert_eq!(insn.kind, InsnKind::Return);
    }

    // ── x86_64 displacement sign extension ──

    #[test]
    fn x86_64_negative_disp8_sign_extends() {
        // MOV rax, [rbp-8] = 48 8B 45 F8
        let insn = decode_one(&[0x48, 0x8B, 0x45, 0xF8], 0x1000, Arch::X86_64).unwrap();
        let ops = insn.operands();
        assert!(ops.len() >= 2, "got: {ops:?}");
        match &ops[1] {
            Operand::Mem { disp, .. } => assert_eq!(*disp, -8, "disp8 0xF8 must sign-extend to -8"),
            other => panic!("expected Mem, got {other:?}"),
        }
    }

    // ── ARM64 STP FP pair ──

    #[test]
    fn arm64_stp_d0_d1_sp_operands() {
        // STP d0, d1, [sp, #-16]! — FP pair store
        // opc=01(64-bit D), V=1, pre-index, imm7=-2 (scaled by 8), Rt2=1, Rn=31, Rt=0
        // Encoding: 0110_1101_1000_0000_0000_0111_1110_0000 = ...
        // Actually: 6D BF 07 E0 — let me compute:
        // opc=01, 1011_01_1_0_imm7_Rt2_Rn_Rt
        // For pre-index FP: 0x6DBF_07E0
        let word: u32 = 0x6DBF_07E0;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 3, "expected 3 operands for FP STP, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::fp(0)));  // d0
        assert_eq!(ops[1], Operand::Reg(Reg::fp(1)));  // d1
        assert!(matches!(ops[2], Operand::Mem { base: Reg { num: 31, .. }, .. }));
    }

    // ── ARM64 SUB immediate ──

    #[test]
    fn arm64_sub_imm_negates() {
        // SUB x0, x1, #10
        // sf=1, op=1, S=0, 100010, sh=0, imm12=10, Rn=1, Rd=0
        // = 1_10_100010_0_000000001010_00001_00000
        // = 0xD100_2820
        let word: u32 = 0xD100_2820;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 3, "got: {ops:?}");
        assert_eq!(ops[2], Operand::Imm(-10)); // SUB → negative immediate
    }

    // ── ARM64 post-index STP ──

    #[test]
    fn arm64_stp_post_index_gpr_operands() {
        // STP x0, x1, [sp], #16 — post-index GPR pair
        // opc=10, 101000_10, imm7=2 (scaled by 8=16), Rt2=1, Rn=31, Rt=0
        // = 0xA881_07E0
        let word: u32 = 0xA881_07E0;
        let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        let ops = insn.operands();
        assert_eq!(ops.len(), 3, "expected 3 operands for post-index STP, got: {ops:?}");
        assert_eq!(ops[0], Operand::Reg(Reg::gpr(0)));
        assert_eq!(ops[1], Operand::Reg(Reg::gpr(1)));
    }

    // ── x86_64 Gpr(255) sentinel for absolute addressing ──

    #[test]
    fn x86_64_absolute_addr_uses_sentinel_base() {
        // MOV eax, [0x12345678] = A1 78 56 34 12 (32-bit address form)
        // Actually on x86_64 this needs a specific encoding. Use MOV with SIB:
        // MOV rax, [disp32] = 48 8B 04 25 78 56 34 12
        let insn = decode_one(
            &[0x48, 0x8B, 0x04, 0x25, 0x78, 0x56, 0x34, 0x12],
            0x1000,
            Arch::X86_64,
        )
        .unwrap();
        let ops = insn.operands();
        // Should have Mem with base = Gpr(255) sentinel (no base register)
        assert!(
            ops.iter().any(|op| matches!(op, Operand::Mem { base, .. } if base.num == 255)),
            "expected Gpr(255) sentinel for absolute address, got: {ops:?}"
        );
    }
}
