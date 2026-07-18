#![deny(missing_docs)]
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
#[non_exhaustive]
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
    /// The class field.
    pub class: RegClass,
    /// The num field.
    pub num: u8,
}

impl Reg {
    /// Performs gpr.
    pub fn gpr(num: u8) -> Self {
        Self {
            class: RegClass::Gpr,
            num,
        }
    }
    /// Performs fp.
    pub fn fp(num: u8) -> Self {
        Self {
            class: RegClass::Fp,
            num,
        }
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
#[non_exhaustive]
pub enum Operand {
    /// Register operand.
    Reg(Reg),
    /// Immediate value.
    Imm(i64),
    /// Memory operand with base register and displacement.
    /// The Mem field.
    Mem {
        /// Base register used to address memory.
        base: Reg,
        /// Signed displacement in bytes from the base register.
        disp: i64,
    },
}

const MAX_OPERANDS: usize = 4;

/// Target architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Arch {
    /// The X86_64 variant.
    X86_64,
    /// The Arm64 variant.
    Arm64,
    /// The Arm64e variant.
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
///
/// The `writes_op0_reg` and `writes_implicit_gpr0` fields together form the
/// minimum write-set surface that ABI inference needs to decide whether a
/// register was clobbered mid-function. Consumers that need a full
/// read/write register set should inspect the underlying decoder (bad64 on
/// ARM64, iced on x86_64) directly; this struct intentionally stays small.
#[derive(Debug, Clone, PartialEq)]
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
    /// True when the first operand is a register and the instruction's
    /// semantics write that register (as opposed to reading it). This
    /// catches both the conventional destination-first forms (`MOV rdi, …`,
    /// `LDR x0, …`) and in-place arithmetic (`ADD rdi, rax`, `ADD x0, x1, x2`)
    /// that previously had no write-visibility in the operand list.
    ///
    /// False for comparisons (`CMP`, `TEST`, `TST`), branches, returns,
    /// stores (`STR`, `MOV [mem], reg`), and any instruction whose op0 is
    /// not a register.
    pub writes_op0_reg: bool,
    ops: [Operand; MAX_OPERANDS],
    op_count: u8,
}

impl Insn {
    /// The instruction's operands (registers, immediates, memory references).
    pub fn operands(&self) -> &[Operand] {
        &self.ops[..self.op_count as usize]
    }

    /// The register written by this instruction when `writes_op0_reg` is true.
    pub fn op0_write_target(&self) -> Option<Reg> {
        if !self.writes_op0_reg {
            return None;
        }
        match self.operands().first()? {
            Operand::Reg(r) => Some(*r),
            _ => None,
        }
    }

    pub(crate) fn with_ops(
        len: usize,
        kind: InsnKind,
        ops: [Operand; MAX_OPERANDS],
        op_count: u8,
        writes_implicit_gpr0: bool,
        writes_op0_reg: bool,
    ) -> Self {
        Self {
            offset: 0,
            len,
            kind,
            writes_implicit_gpr0,
            writes_op0_reg,
            ops,
            op_count,
        }
    }
}

/// High-level classification of an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The target field.
    pub target: BranchTarget,
}

/// How a branch resolves its destination.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
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
    /// The message field.
    pub message: String,
}

impl DecodeError {
    /// The CODE constant.
    pub const CODE: &'static str = "insn.decode.invalid";
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
    /// The message field.
    pub message: String,
}

impl EncodeError {
    /// The CODE constant.
    pub const CODE: &'static str = "insn.encode.invalid";
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
    stopped: bool,
}

impl<'a> Iterator for InsnIter<'a> {
    type Item = Result<Insn, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped || self.offset >= self.bytes.len() {
            return None;
        }
        let Some(va) = self.base_va.checked_add(self.offset as u64) else {
            self.stopped = true;
            return Some(Err(DecodeError {
                message: "instruction virtual address overflows".into(),
            }));
        };
        match decode_one(&self.bytes[self.offset..], va, self.arch) {
            Ok(mut insn) => {
                insn.offset = self.offset;
                self.offset += insn.len;
                Some(Ok(insn))
            }
            Err(error) => {
                self.stopped = true;
                Some(Err(error))
            }
        }
    }
}

/// One explicit region skipped by lossy instruction decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeGap {
    /// The offset field.
    pub offset: usize,
    /// The len field.
    pub len: usize,
    /// The va field.
    pub va: u64,
    /// The error field.
    pub error: DecodeError,
}

/// Decoded instructions plus every region skipped during explicit recovery.
#[derive(Debug, Clone, PartialEq)]
pub struct DecodeReport {
    /// The instructions field.
    pub instructions: Vec<Insn>,
    /// The gaps field.
    pub gaps: Vec<DecodeGap>,
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
        stopped: false,
    }
}

/// Decode with architecture-specific recovery while recording every skipped range.
pub fn decode_lossy(bytes: &[u8], base_va: u64, arch: Arch) -> DecodeReport {
    let mut instructions = Vec::new();
    let mut gaps: Vec<DecodeGap> = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let va = base_va.saturating_add(offset as u64);
        match decode_one(&bytes[offset..], va, arch) {
            Ok(mut instruction) => {
                instruction.offset = offset;
                offset += instruction.len;
                instructions.push(instruction);
            }
            Err(error) => {
                let len = if arch.is_arm64() { 4 } else { 1 }.min(bytes.len() - offset);
                if let Some(previous) = gaps.last_mut().filter(|gap| gap.offset + gap.len == offset)
                {
                    previous.len += len;
                } else {
                    gaps.push(DecodeGap {
                        offset,
                        len,
                        va,
                        error,
                    });
                }
                offset += len;
            }
        }
    }
    DecodeReport { instructions, gaps }
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

/// Strictly disassemble all instructions in `bytes` to `(va, text)` pairs.
///
/// Returns an error instead of a successfully decoded prefix when any byte in
/// the input cannot be decoded. Use [`decode_lossy`] when explicit recovery and
/// gap accounting are required.
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

#[cfg(test)]
mod tests;
