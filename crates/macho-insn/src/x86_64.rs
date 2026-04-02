//! x86_64 instruction decoding and disassembly via `iced-x86`.

use iced_x86::{
    Code, Decoder, DecoderOptions, Encoder, FlowControl, Formatter as _, Instruction, Mnemonic,
    OpKind,
};

use crate::{BranchInfo, BranchTarget, DecodeError, Insn, InsnKind, PcRelInfo};

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

    Ok(Insn {
        offset: 0,
        len: insn.len(),
        kind,
    })
}

fn classify(insn: &Instruction, _va: u64) -> InsnKind {
    // NOP detection (single-byte 0x90 and multi-byte 0F 1F family).
    if insn.mnemonic() == Mnemonic::Nop || insn.code() == Code::Nopd {
        return InsnKind::Nop;
    }

    match insn.flow_control() {
        FlowControl::UnconditionalBranch => {
            InsnKind::Branch(BranchInfo {
                target: extract_branch_target(insn),
            })
        }
        FlowControl::Call => {
            InsnKind::Call(BranchInfo {
                target: extract_branch_target(insn),
            })
        }
        FlowControl::ConditionalBranch | FlowControl::XbeginXabortXend => {
            InsnKind::CondBranch(BranchInfo {
                target: extract_branch_target(insn),
            })
        }
        FlowControl::Return => InsnKind::Return,
        FlowControl::IndirectBranch => {
            InsnKind::Branch(BranchInfo {
                target: BranchTarget::Indirect,
            })
        }
        FlowControl::IndirectCall => {
            InsnKind::Call(BranchInfo {
                target: BranchTarget::Indirect,
            })
        }
        FlowControl::Next | FlowControl::Interrupt | FlowControl::Exception => {
            // Check for RIP-relative addressing (non-branch PC-relative).
            if let Some(disp) = rip_relative_displacement(insn) {
                return InsnKind::PcRelative(PcRelInfo {
                    displacement: disp,
                });
            }
            InsnKind::Other
        }
    }
}

fn extract_branch_target(insn: &Instruction) -> BranchTarget {
    // Near branch with an immediate target.
    if insn.op0_kind() == OpKind::NearBranch16
        || insn.op0_kind() == OpKind::NearBranch32
        || insn.op0_kind() == OpKind::NearBranch64
    {
        let target_va = insn.near_branch_target();
        let insn_va = insn.ip();
        let offset = target_va as i64 - insn_va as i64;
        return BranchTarget::Direct(offset);
    }

    // Far branch.
    if insn.op0_kind() == OpKind::FarBranch16 || insn.op0_kind() == OpKind::FarBranch32 {
        let target_va = insn.far_branch32() as u64;
        let insn_va = insn.ip();
        let offset = target_va as i64 - insn_va as i64;
        return BranchTarget::Direct(offset);
    }

    // Register-based (JMP rax, CALL rax).
    if insn.op0_kind() == OpKind::Register {
        return BranchTarget::Register;
    }

    // Memory-indirect (JMP [rip+disp], etc.).
    BranchTarget::Indirect
}

/// Extract a RIP-relative displacement from a non-branch instruction.
fn rip_relative_displacement(insn: &Instruction) -> Option<i64> {
    // Check if any memory operand uses RIP-relative addressing.
    if insn.is_ip_rel_memory_operand() {
        let target = insn.ip_rel_memory_address();
        let disp = target as i64 - insn.ip() as i64;
        return Some(disp);
    }
    None
}

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

pub(crate) fn disassemble(
    bytes: &[u8],
    base_va: u64,
) -> Result<Vec<(u64, String)>, DecodeError> {
    let mut result = Vec::new();
    let mut decoder = Decoder::with_ip(64, bytes, base_va, DecoderOptions::NONE);
    let mut formatter = iced_x86::IntelFormatter::new();

    while decoder.can_decode() {
        let insn = decoder.decode();
        if insn.is_invalid() {
            break;
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
    let code = if link { Code::Call_rel32_64 } else { Code::Jmp_rel32_64 };
    let mut insn = Instruction::with_branch(code, to_va)
        .map_err(|e| crate::EncodeError { message: e.to_string() })?;
    insn.set_ip(from_va);

    let mut encoder = Encoder::new(64);
    encoder.encode(&insn, from_va).map_err(|e| crate::EncodeError {
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
    encoder.encode(&insn, new_va).map_err(|e| crate::EncodeError {
        message: format!("relocation failed: {e}"),
    })?;

    Ok(encoder.take_buffer())
}
