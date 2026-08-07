#![deny(missing_docs)]
#![allow(clippy::manual_is_multiple_of)]
//! Architecture-aware instruction decoding, encoding, and relocation.
//!
//! Uses mkasm-generated tables for encoding identity, physical encoding, and
//! formatting and x86 semantic lowering
//! for the instruction-level operations that Mach-O patching, xref analysis,
//! and binary diffing need:
//!
//! - **Decode**: length, classification, branch target extraction
//! - **Encode**: branch instruction construction, NOP fill
//! - **Relocate**: rewrite PC-relative operands for a new address
//! - **Disassemble**: instruction-to-text for display

mod arm64;
mod codecs;
mod encode;
mod x86_64;

mod generated;
pub use generated::{
    EncodedX86, EncodingIdentity, X86EncodeFields, encode_arm64_fields, encode_arm64_fixed,
    encode_x86_form, identify_encoding,
};

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
    /// Register operand transformed by an encoded shift.
    ShiftedReg {
        /// Register being shifted.
        register: Reg,
        /// Shift operation.
        shift: RegisterShift,
        /// Shift amount in bits.
        amount: u8,
    },
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
    /// Indexed memory operand with base, index, scale, and displacement.
    IndexedMem {
        /// Base register.
        base: Reg,
        /// Index register.
        index: Reg,
        /// Index scale in bytes.
        scale: u8,
        /// Signed displacement in bytes.
        disp: i64,
    },
}

/// Shift applied to a register operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RegisterShift {
    /// Logical shift left.
    LogicalLeft,
    /// Logical shift right.
    LogicalRight,
    /// Arithmetic shift right.
    ArithmeticRight,
    /// Rotate right.
    RotateRight,
}

/// Architecture-neutral effect of an instruction on its written first
/// operand, retained for bounded address-value recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ValueEffect {
    /// The instruction does not write its first operand.
    None,
    /// The destination is assigned from a register or immediate operand.
    Set,
    /// The destination is an address computed from a memory-form operand.
    Address,
    /// The destination is loaded from a memory-form operand.
    Load,
    /// The destination is a source register plus a signed immediate.
    AddImmediate,
    /// The destination is the sum of two source registers.
    AddRegister,
    /// The destination is the first source register minus the second.
    SubtractRegister,
    /// The destination is masked by an immediate bit pattern.
    BitwiseAndImmediate,
    /// The destination is shifted by an immediate amount.
    ShiftImmediate,
    /// The destination conditionally selects one of the decoded sources.
    ConditionalSelect,
    /// Zero-extend the low 8 bits of the source.
    ZeroExtend8,
    /// Zero-extend the low 16 bits of the source.
    ZeroExtend16,
    /// Zero-extend the low 32 bits of the source.
    ZeroExtend32,
    /// Sign-extend the low 8 bits of the source.
    SignExtend8,
    /// Sign-extend the low 16 bits of the source.
    SignExtend16,
    /// Sign-extend the low 32 bits of the source.
    SignExtend32,
    /// Sign a pointer with the IA key.
    SignPointerIa,
    /// Sign a pointer with the IB key.
    SignPointerIb,
    /// Sign a pointer with the DA key.
    SignPointerDa,
    /// Sign a pointer with the DB key.
    SignPointerDb,
    /// Authenticate a pointer with the IA key.
    AuthenticatePointerIa,
    /// Authenticate a pointer with the IB key.
    AuthenticatePointerIb,
    /// Authenticate a pointer with the DA key.
    AuthenticatePointerDa,
    /// Authenticate a pointer with the DB key.
    AuthenticatePointerDb,
    /// Strip pointer authentication without changing the canonical address.
    StripPointerAuthentication,
    /// The destination is written, but this decoder exposes no safe value
    /// transfer model for the instruction.
    UnknownWrite,
}

/// Architecture-neutral effect on an explicit memory operand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum MemoryEffect {
    /// The instruction does not perform a supported explicit memory write.
    None,
    /// A source register is stored through an explicit memory operand.
    Store,
    /// Memory is written but the source or location is not safely modeled.
    UnknownWrite,
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
/// read/write register set inspect the architecture backend directly; this
/// struct stays small.
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
    /// Address-value effect for the written first operand.
    pub value_effect: ValueEffect,
    /// Supported memory-write effect.
    pub memory_effect: MemoryEffect,
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

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_ops(
        len: usize,
        kind: InsnKind,
        ops: [Operand; MAX_OPERANDS],
        op_count: u8,
        writes_implicit_gpr0: bool,
        writes_op0_reg: bool,
        value_effect: ValueEffect,
        memory_effect: MemoryEffect,
    ) -> Self {
        Self {
            offset: 0,
            len,
            kind,
            writes_implicit_gpr0,
            writes_op0_reg,
            value_effect,
            memory_effect,
            ops,
            op_count,
        }
    }
}

/// One instruction decoded for both semantic analysis and display.
///
/// Produced by [`Disassembler::decode_one`] so a backend can share its native
/// decoded representation between semantic lowering and text formatting.
#[derive(Debug, Clone, PartialEq)]
pub struct DisassembledInsn {
    /// Architecture-neutral instruction semantics.
    pub instruction: Insn,
    /// Human-readable assembly text.
    pub text: String,
    /// Recovery provenance when architecture rules establish an instruction
    /// boundary but the formatter cannot provide semantics.
    pub recovery: Option<InstructionRecovery>,
}

/// Provenance for an instruction retained without primary-decoder semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstructionRecovery {
    /// How the instruction boundary was established.
    pub boundary_confidence: BoundaryConfidence,
    /// Architecture-owned source of the otherwise opaque boundary.
    pub source: &'static str,
}

/// Confidence in the retained boundary of an opaque instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryConfidence {
    /// Fixed-width architecture rules establish the boundary exactly.
    Exact,
}

/// Stateful single-instruction decoder and formatter.
///
/// Use this when both instruction semantics and display text are required.
/// Semantic-only callers should continue to use [`decode_one`] so they do not
/// pay for formatting or string allocation.
pub struct Disassembler {
    backend: DisassemblerBackend,
}

enum DisassemblerBackend {
    X86_64,
    Arm64,
}

impl Disassembler {
    /// Create a decoder and reusable formatter for `arch`.
    pub fn new(arch: Arch) -> Self {
        let backend = match arch {
            Arch::X86_64 => DisassemblerBackend::X86_64,
            Arch::Arm64 | Arch::Arm64e => DisassemblerBackend::Arm64,
        };
        Self { backend }
    }

    /// Decode and format the instruction at the start of `bytes` in one
    /// coordinated backend operation.
    pub fn decode_one(&mut self, bytes: &[u8], va: u64) -> Result<DisassembledInsn, DecodeError> {
        let (instruction, text, recovery) = match &mut self.backend {
            DisassemblerBackend::X86_64 => x86_64::decode_and_disassemble_one(bytes, va)?,
            DisassemblerBackend::Arm64 => arm64::decode_and_disassemble_one(bytes, va)?,
        };
        Ok(DisassembledInsn {
            instruction,
            text,
            recovery,
        })
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
    /// Indexed memory target with a retained base/index/scale expression.
    IndexedMemory {
        /// Optional mapped base register.
        base: Option<Reg>,
        /// Mapped index register.
        index: Reg,
        /// SIB scale in bytes.
        scale: u8,
        /// Signed encoded displacement.
        displacement: i64,
    },
}

/// PC-relative operand that is *not* a branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcRelInfo {
    /// Signed displacement from the instruction's VA.
    pub displacement: i64,
    /// Whether the instruction materializes an address, a page address, or
    /// references memory at the PC-relative target.
    pub kind: PcRelKind,
}

/// Semantics of a PC-relative non-branch instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcRelKind {
    /// Materializes the exact target address, such as ADR or RIP-relative LEA.
    Address,
    /// Materializes a page address, such as ADRP.
    PageAddress,
    /// Reads or writes memory at the target address, including literal loads.
    Memory,
}

/// Machine-readable category for a decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeErrorKind {
    /// The bytes are not a valid instruction for the selected architecture.
    InvalidEncoding,
    /// The primary decoder has no matching encoding.
    UnknownEncoding,
    /// More bytes are required to decide or complete the instruction.
    Truncated,
    /// Prefixes or instruction fields exceed the architectural length limit.
    TooLong,
}

impl DecodeErrorKind {
    /// Stable diagnostic code for this category.
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidEncoding => "insn.decode.invalid_encoding",
            Self::UnknownEncoding => "insn.decode.unknown_encoding",
            Self::Truncated => "insn.decode.truncated",
            Self::TooLong => "insn.decode.too_long",
        }
    }
}

/// Errors from decode operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeError {
    /// Machine-readable failure category.
    pub kind: DecodeErrorKind,
    /// The message field.
    pub message: String,
}

impl DecodeError {
    /// Legacy aggregate code retained for callers that group all failures.
    pub const CODE: &'static str = "insn.decode.invalid";

    /// Stable code for this specific failure category.
    pub const fn code(&self) -> &'static str {
        self.kind.code()
    }
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
    decoder: DecodeCursor<'a>,
    offset: usize,
    stopped: bool,
}

impl<'a> Iterator for InsnIter<'a> {
    type Item = Result<Insn, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.stopped || self.offset >= self.decoder.len() {
            return None;
        }
        match self.decoder.decode_at(self.offset) {
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

pub(crate) fn could_start_direct_call(bytes: &[u8], arch: Arch) -> bool {
    match arch {
        Arch::X86_64 => x86_64::could_start_direct_call(bytes),
        Arch::Arm64 | Arch::Arm64e => true,
    }
}

/// Iterate over all instructions in `bytes`, starting at `base_va`.
pub fn decode_iter(bytes: &[u8], base_va: u64, arch: Arch) -> InsnIter<'_> {
    InsnIter {
        decoder: DecodeCursor::new(bytes, base_va, arch),
        offset: 0,
        stopped: false,
    }
}

/// Stateful decoder used internally to amortize architecture decoder setup.
pub(crate) struct DecodeCursor<'a> {
    bytes: &'a [u8],
    base_va: u64,
    arch: Arch,
    x86: Option<x86_64::DecodeCursor<'a>>,
}

impl<'a> DecodeCursor<'a> {
    /// Create a cursor over one contiguous virtual-address range.
    pub(crate) fn new(bytes: &'a [u8], base_va: u64, arch: Arch) -> Self {
        Self {
            bytes,
            base_va,
            arch,
            x86: matches!(arch, Arch::X86_64).then(|| x86_64::DecodeCursor::new(bytes, base_va)),
        }
    }

    fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Decode at `offset`, resetting only when recovery skips invalid bytes.
    pub(crate) fn decode_at(&mut self, offset: usize) -> Result<Insn, DecodeError> {
        let va = self
            .base_va
            .checked_add(offset as u64)
            .ok_or_else(|| DecodeError {
                kind: DecodeErrorKind::InvalidEncoding,
                message: "instruction virtual address overflows".into(),
            })?;
        match self.arch {
            Arch::X86_64 => self
                .x86
                .as_mut()
                .expect("x86 cursor exists")
                .decode_at(offset),
            Arch::Arm64 | Arch::Arm64e => arm64::decode_one(&self.bytes[offset..], va),
        }
    }

    /// Decode only instruction length and a direct-call target, if present.
    pub(crate) fn probe_direct_call_at(
        &mut self,
        offset: usize,
    ) -> Result<(usize, Option<u64>), DecodeError> {
        let va = self
            .base_va
            .checked_add(offset as u64)
            .ok_or_else(|| DecodeError {
                kind: DecodeErrorKind::InvalidEncoding,
                message: "instruction virtual address overflows".into(),
            })?;
        match self.arch {
            Arch::X86_64 => self
                .x86
                .as_mut()
                .expect("x86 cursor exists")
                .probe_direct_call_at(offset),
            Arch::Arm64 | Arch::Arm64e => {
                let instruction = arm64::decode_one(&self.bytes[offset..], va)?;
                let target = matches!(instruction.kind, InsnKind::Call(_))
                    .then(|| resolve_branch_target(&instruction, va))
                    .flatten();
                Ok((instruction.len, target))
            }
        }
    }
}

/// Decode with architecture-specific recovery while recording every skipped range.
pub fn decode_lossy(bytes: &[u8], base_va: u64, arch: Arch) -> DecodeReport {
    let mut instructions = Vec::new();
    let mut gaps: Vec<DecodeGap> = Vec::new();
    let mut offset = 0usize;
    let mut decoder = DecodeCursor::new(bytes, base_va, arch);
    while offset < bytes.len() {
        let va = base_va.saturating_add(offset as u64);
        match decoder.decode_at(offset) {
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
    identify_encoding(bytes, arch)
        .map(|encoding| encoding.length)
        .or_else(|_| decode_one(bytes, 0, arch).map(|insn| insn.len))
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
