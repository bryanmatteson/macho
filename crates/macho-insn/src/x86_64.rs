//! x86_64 instruction decoding and disassembly via `iced-x86`.

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, FlowControl, Formatter as _, Instruction,
    InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

use crate::{
    BranchInfo, BranchTarget, DecodeError, Insn, InsnKind, MAX_OPERANDS, Operand, PcRelInfo, Reg,
};

pub(crate) fn decode_one(bytes: &[u8], va: u64) -> Result<Insn, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError {
            message: "empty input".into(),
        });
    }

    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let insn = decoder.decode();

    if insn.is_invalid() {
        return Err(DecodeError {
            message: "invalid instruction".into(),
        });
    }

    let kind = classify(&insn, va);
    let (ops, op_count) = extract_operands(&insn);

    // Flag instructions that write rax as an implicit side effect (not
    // reflected in the operand list). Consumers use this to avoid treating
    // DIV/MUL results as intentional return values.
    let writes_implicit_gpr0 = match insn.mnemonic() {
        Mnemonic::Div | Mnemonic::Idiv | Mnemonic::Mul => true,
        Mnemonic::Imul => insn.op_count() == 1, // single-operand form only
        Mnemonic::Cwd
        | Mnemonic::Cdq
        | Mnemonic::Cqo
        | Mnemonic::Cdqe
        | Mnemonic::Cbw
        | Mnemonic::Cwde => true,
        _ => false,
    };

    // writes_op0_reg: true iff op0 is a register and iced reports its
    // access as Write or ReadWrite. iced's InstructionInfoFactory walks
    // the operand-info tables that back the decoder, so this is the ground
    // truth for whether an instruction like `ADD rdi, rax` actually
    // modifies `rdi` rather than just reading both operands.
    let writes_op0_reg = if insn.op_count() >= 1 && insn.op0_kind() == OpKind::Register {
        let mut factory = InstructionInfoFactory::new();
        let info = factory.info(&insn);
        matches!(
            info.op_access(0),
            OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite
        )
    } else {
        false
    };

    Ok(Insn::with_ops(
        insn.len(),
        kind,
        ops,
        op_count,
        writes_implicit_gpr0,
        writes_op0_reg,
    ))
}

fn classify(insn: &Instruction, _va: u64) -> InsnKind {
    // NOP detection (single-byte 0x90 and multi-byte 0F 1F family).
    if insn.mnemonic() == Mnemonic::Nop || insn.code() == Code::Nopd {
        return InsnKind::Nop;
    }

    match insn.flow_control() {
        FlowControl::UnconditionalBranch => InsnKind::Branch(BranchInfo {
            target: extract_branch_target(insn),
        }),
        FlowControl::Call => InsnKind::Call(BranchInfo {
            target: extract_branch_target(insn),
        }),
        FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => {
            InsnKind::CondBranch(BranchInfo {
                target: extract_branch_target(insn),
            })
        }
        FlowControl::Return => InsnKind::Return,
        FlowControl::IndirectBranch => InsnKind::Branch(BranchInfo {
            target: BranchTarget::Indirect,
        }),
        FlowControl::IndirectCall => InsnKind::Call(BranchInfo {
            target: BranchTarget::Indirect,
        }),
        FlowControl::Next | FlowControl::Interrupt | FlowControl::Exception => {
            if let Some(disp) = rip_relative_displacement(insn) {
                return InsnKind::PcRelative(PcRelInfo { displacement: disp });
            }
            InsnKind::Other
        }
    }
}

fn extract_branch_target(insn: &Instruction) -> BranchTarget {
    if insn.op0_kind() == OpKind::NearBranch16
        || insn.op0_kind() == OpKind::NearBranch32
        || insn.op0_kind() == OpKind::NearBranch64
    {
        let target_va = insn.near_branch_target();
        let insn_va = insn.ip();
        // Wrapping two's-complement displacement: a plain `as i64 - as i64`
        // overflows when target and instruction straddle the i64 sign boundary.
        let offset = target_va.wrapping_sub(insn_va) as i64;
        return BranchTarget::Direct(offset);
    }

    if insn.op0_kind() == OpKind::FarBranch16 || insn.op0_kind() == OpKind::FarBranch32 {
        let target_va = insn.far_branch32() as u64;
        let insn_va = insn.ip();
        let offset = target_va.wrapping_sub(insn_va) as i64;
        return BranchTarget::Direct(offset);
    }

    if insn.op0_kind() == OpKind::Register {
        return BranchTarget::Register;
    }

    BranchTarget::Indirect
}

fn rip_relative_displacement(insn: &Instruction) -> Option<i64> {
    if insn.is_ip_rel_memory_operand() {
        let target = insn.ip_rel_memory_address();
        let disp = target.wrapping_sub(insn.ip()) as i64;
        return Some(disp);
    }
    None
}

// ───────────────── operand extraction ─────────────────

fn extract_operands(insn: &Instruction) -> ([Operand; MAX_OPERANDS], u8) {
    let mut ops = [Operand::Imm(0); MAX_OPERANDS];
    let mut count = 0u8;

    for i in 0..insn.op_count().min(MAX_OPERANDS as u32) {
        if let Some(op) = map_operand(insn, i) {
            ops[count as usize] = op;
            count += 1;
        }
    }

    (ops, count)
}

fn map_operand(insn: &Instruction, idx: u32) -> Option<Operand> {
    match insn.op_kind(idx) {
        OpKind::Register => {
            let reg = insn.op_register(idx);
            map_register(reg).map(Operand::Reg)
        }
        OpKind::Memory => {
            // Use a sentinel (Gpr(255)) when the base register isn't mappable
            // (e.g., absolute addresses with Register::None). This preserves
            // operand positions — consumers checking for specific bases like
            // Gpr(4)/RSP naturally skip the sentinel.
            let base = map_register(insn.memory_base()).unwrap_or(Reg::gpr(255));
            // Sign-extend the displacement correctly based on its encoded width.
            // memory_displacement64() returns the raw value without sign extension,
            // so [rbp-8] encoded as disp8=0xF8 would yield 248 instead of -8.
            let disp = insn.memory_displacement32() as i32 as i64;
            Some(Operand::Mem { base, disp })
        }
        OpKind::Immediate8
        | OpKind::Immediate8_2nd
        | OpKind::Immediate16
        | OpKind::Immediate32
        | OpKind::Immediate64
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => Some(Operand::Imm(insn.immediate(idx) as i64)),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            Some(Operand::Imm(insn.near_branch_target() as i64))
        }
        OpKind::FarBranch16 | OpKind::FarBranch32 => Some(Operand::Imm(insn.far_branch32() as i64)),
        _ => None,
    }
}

/// Map an iced-x86 register to our architecture-neutral Reg.
///
/// x86_64 GPR numbering: rax=0, rcx=1, rdx=2, rbx=3, rsp=4, rbp=5, rsi=6, rdi=7, r8-r15=8-15.
/// All register sizes (AL/AX/EAX/RAX) map to the same GPR number.
fn map_register(reg: Register) -> Option<Reg> {
    // 64-bit GPRs
    let gpr = match reg {
        Register::RAX | Register::EAX | Register::AX | Register::AL | Register::AH => Some(0),
        Register::RCX | Register::ECX | Register::CX | Register::CL | Register::CH => Some(1),
        Register::RDX | Register::EDX | Register::DX | Register::DL | Register::DH => Some(2),
        Register::RBX | Register::EBX | Register::BX | Register::BL | Register::BH => Some(3),
        Register::RSP | Register::ESP | Register::SP | Register::SPL => Some(4),
        Register::RBP | Register::EBP | Register::BP | Register::BPL => Some(5),
        Register::RSI | Register::ESI | Register::SI | Register::SIL => Some(6),
        Register::RDI | Register::EDI | Register::DI | Register::DIL => Some(7),
        Register::R8 | Register::R8D | Register::R8W | Register::R8L => Some(8),
        Register::R9 | Register::R9D | Register::R9W | Register::R9L => Some(9),
        Register::R10 | Register::R10D | Register::R10W | Register::R10L => Some(10),
        Register::R11 | Register::R11D | Register::R11W | Register::R11L => Some(11),
        Register::R12 | Register::R12D | Register::R12W | Register::R12L => Some(12),
        Register::R13 | Register::R13D | Register::R13W | Register::R13L => Some(13),
        Register::R14 | Register::R14D | Register::R14W | Register::R14L => Some(14),
        Register::R15 | Register::R15D | Register::R15W | Register::R15L => Some(15),
        _ => None,
    };
    if let Some(num) = gpr {
        return Some(Reg::gpr(num));
    }

    // XMM/YMM/ZMM → Fp with same number
    let fp = match reg {
        Register::XMM0 | Register::YMM0 | Register::ZMM0 => Some(0),
        Register::XMM1 | Register::YMM1 | Register::ZMM1 => Some(1),
        Register::XMM2 | Register::YMM2 | Register::ZMM2 => Some(2),
        Register::XMM3 | Register::YMM3 | Register::ZMM3 => Some(3),
        Register::XMM4 | Register::YMM4 | Register::ZMM4 => Some(4),
        Register::XMM5 | Register::YMM5 | Register::ZMM5 => Some(5),
        Register::XMM6 | Register::YMM6 | Register::ZMM6 => Some(6),
        Register::XMM7 | Register::YMM7 | Register::ZMM7 => Some(7),
        Register::XMM8 | Register::YMM8 | Register::ZMM8 => Some(8),
        Register::XMM9 | Register::YMM9 | Register::ZMM9 => Some(9),
        Register::XMM10 | Register::YMM10 | Register::ZMM10 => Some(10),
        Register::XMM11 | Register::YMM11 | Register::ZMM11 => Some(11),
        Register::XMM12 | Register::YMM12 | Register::ZMM12 => Some(12),
        Register::XMM13 | Register::YMM13 | Register::ZMM13 => Some(13),
        Register::XMM14 | Register::YMM14 | Register::ZMM14 => Some(14),
        Register::XMM15 | Register::YMM15 | Register::ZMM15 => Some(15),
        _ => None,
    };
    if let Some(num) = fp {
        return Some(Reg::fp(num));
    }

    // RIP → Gpr(16) as a sentinel, or skip. We use it as a memory base.
    if reg == Register::RIP || reg == Register::EIP {
        return Some(Reg::gpr(16));
    }

    None
}

// ───────────────── disassembly ─────────────────

pub(crate) fn disassemble_one(bytes: &[u8], va: u64) -> Result<String, DecodeError> {
    if bytes.is_empty() {
        return Err(DecodeError {
            message: "empty input".into(),
        });
    }

    let mut decoder = Decoder::with_ip(64, bytes, va, DecoderOptions::NONE);
    let insn = decoder.decode();

    if insn.is_invalid() {
        return Err(DecodeError {
            message: "invalid instruction".into(),
        });
    }

    let mut output = String::new();
    let mut formatter = iced_x86::IntelFormatter::new();
    formatter.format(&insn, &mut output);
    Ok(output)
}

pub(crate) fn disassemble(bytes: &[u8], base_va: u64) -> Result<Vec<(u64, String)>, DecodeError> {
    let mut result = Vec::new();
    let mut decoder = Decoder::with_ip(64, bytes, base_va, DecoderOptions::NONE);
    let mut formatter = iced_x86::IntelFormatter::new();

    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            return Err(DecodeError {
                message: "invalid instruction".into(),
            });
        }
        let mut output = String::new();
        formatter.format(&insn, &mut output);
        result.push((insn.ip(), output));
    }

    Ok(result)
}

/// Encode a direct branch or call from `from_va` to `to_va`.
pub(crate) fn encode_branch_insn(
    from_va: u64,
    to_va: u64,
    link: bool,
) -> Result<Vec<u8>, crate::EncodeError> {
    let code = if link {
        Code::Call_rel32_64
    } else {
        Code::Jmp_rel32_64
    };
    let mut insn = Instruction::with_branch(code, to_va).map_err(|e| crate::EncodeError {
        message: e.to_string(),
    })?;
    insn.set_ip(from_va);

    let mut encoder = Encoder::new(64);
    encoder
        .encode(&insn, from_va)
        .map_err(|e| crate::EncodeError {
            message: e.to_string(),
        })?;

    Ok(encoder.take_buffer())
}

/// Relocate an x86_64 instruction from `old_va` to `new_va`.
pub(crate) fn relocate(
    bytes: &[u8],
    old_va: u64,
    new_va: u64,
) -> Result<Vec<u8>, crate::EncodeError> {
    let mut decoder = Decoder::with_ip(64, bytes, old_va, DecoderOptions::NONE);
    let insn = decoder.decode();

    if insn.is_invalid() {
        return Err(crate::EncodeError {
            message: "cannot relocate invalid instruction".into(),
        });
    }

    let mut encoder = Encoder::new(64);
    encoder
        .encode(&insn, new_va)
        .map_err(|e| crate::EncodeError {
            message: format!("relocation failed: {e}"),
        })?;

    Ok(encoder.take_buffer())
}
