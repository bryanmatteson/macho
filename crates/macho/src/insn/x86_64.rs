//! x86_64 semantic decoding, formatting, encoding, and relocation via mkasm.

use super::codecs::x86_64::{
    self as mkasm_x86_64, Decoded, DecodedOperand, FlowControl, OperandKind, RegisterClass,
    RelativeBranchKind,
};

use crate::insn::{
    BranchInfo, BranchTarget, DecodeError, DecodeErrorKind, Insn, InsnKind, InstructionRecovery,
    MAX_OPERANDS, MemoryEffect, Operand, PcRelInfo, PcRelKind, Reg, ValueEffect,
};

pub(crate) fn could_start_direct_call(bytes: &[u8]) -> bool {
    for (index, byte) in bytes.iter().copied().take(15).enumerate() {
        if byte == 0xe8 {
            return index <= 10;
        }
        if !matches!(
            byte,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 | 0x66 | 0x67 | 0xf0 | 0xf2 | 0xf3 | 0x40
                ..=0x4f
        ) {
            return false;
        }
    }
    false
}

pub(crate) fn decode_one(bytes: &[u8], va: u64) -> Result<Insn, DecodeError> {
    let decoded = decode_mkasm(bytes)?;
    Ok(lower(&decoded, va))
}

pub(crate) struct DecodeCursor<'a> {
    bytes: &'a [u8],
    base_va: u64,
}

impl<'a> DecodeCursor<'a> {
    pub(crate) fn new(bytes: &'a [u8], base_va: u64) -> Self {
        Self { bytes, base_va }
    }

    pub(crate) fn decode_at(&mut self, offset: usize) -> Result<Insn, DecodeError> {
        let bytes = self.bytes.get(offset..).ok_or_else(empty_input)?;
        let decoded = decode_mkasm(bytes)?;
        Ok(lower(&decoded, self.base_va.saturating_add(offset as u64)))
    }

    pub(crate) fn probe_direct_call_at(
        &mut self,
        offset: usize,
    ) -> Result<(usize, Option<u64>), DecodeError> {
        let bytes = self.bytes.get(offset..).ok_or_else(empty_input)?;
        let decoded = decode_mkasm(bytes)?;
        let va = self.base_va.saturating_add(offset as u64);
        let target = (decoded.flow_control() == FlowControl::Call)
            .then(|| direct_target(&decoded, va))
            .flatten();
        Ok((decoded.length as usize, target))
    }
}

pub(crate) fn decode_and_disassemble_one(
    bytes: &[u8],
    va: u64,
) -> Result<(Insn, String, Option<InstructionRecovery>), DecodeError> {
    let decoded = decode_mkasm(bytes)?;
    Ok((lower(&decoded, va), decoded.format_intel(va), None))
}

fn decode_mkasm(bytes: &[u8]) -> Result<Decoded, DecodeError> {
    if bytes.is_empty() {
        return Err(empty_input());
    }
    mkasm_x86_64::decode(bytes, mkasm_x86_64::Mode::Mode64).map_err(|error| DecodeError {
        kind: match error {
            mkasm_x86_64::DecodeError::Truncated => DecodeErrorKind::Truncated,
            mkasm_x86_64::DecodeError::TooLong => DecodeErrorKind::TooLong,
            mkasm_x86_64::DecodeError::Unknown => DecodeErrorKind::UnknownEncoding,
        },
        message: match error {
            mkasm_x86_64::DecodeError::Truncated => "truncated instruction",
            mkasm_x86_64::DecodeError::TooLong => "instruction exceeds 15 bytes",
            mkasm_x86_64::DecodeError::Unknown => "unknown instruction encoding",
        }
        .into(),
    })
}

fn empty_input() -> DecodeError {
    DecodeError {
        kind: DecodeErrorKind::Truncated,
        message: "empty input".into(),
    }
}

fn explicit_operands(decoded: &Decoded) -> impl Iterator<Item = &DecodedOperand> {
    decoded
        .operands()
        .iter()
        .filter(|operand| !operand.implicit)
}

fn lower(decoded: &Decoded, va: u64) -> Insn {
    let explicit: Vec<_> = explicit_operands(decoded).collect();
    let kind = classify(decoded, va);
    let (mut ops, op_count) = extract_operands(decoded, va);
    let mnemonic = decoded.encoding().mnemonic;
    let op0 = explicit.first().copied();
    let writes_op0_reg = op0.is_some_and(|operand| {
        operand.kind == OperandKind::Register
            && (operand.access.write || operand.access.conditional_write)
    });
    let writes_implicit_gpr0 = matches!(
        mnemonic,
        "DIV" | "IDIV" | "MUL" | "IMUL" | "CWD" | "CDQ" | "CQO" | "CDQE" | "CBW" | "CWDE"
    ) && decoded.operands().iter().any(|operand| {
        operand.implicit
            && (operand.access.write || operand.access.conditional_write)
            && operand.register.is_some_and(|register| {
                register.class == RegisterClass::Gpr && matches!(register.number, 0 | 2)
            })
    });

    let value_effect = value_effect(mnemonic, &explicit, writes_op0_reg);
    if value_effect == ValueEffect::ShiftImmediate
        && let (Some(Operand::Reg(destination)), Some(Operand::Imm(amount))) =
            (ops.first().copied(), ops.get(1).copied())
    {
        let shift = match mnemonic {
            "SHL" | "SAL" => crate::insn::RegisterShift::LogicalLeft,
            "SHR" => crate::insn::RegisterShift::LogicalRight,
            "SAR" => crate::insn::RegisterShift::ArithmeticRight,
            _ => unreachable!(),
        };
        ops[1] = Operand::ShiftedReg {
            register: destination,
            shift,
            amount: amount as u8,
        };
    }

    let memory_effect = if op0.is_some_and(|operand| operand.kind == OperandKind::Memory) {
        let access = op0.expect("memory operand exists").access;
        if access.write || access.conditional_write {
            if explicit
                .get(1)
                .is_some_and(|operand| operand.kind == OperandKind::Register)
            {
                MemoryEffect::Store
            } else {
                MemoryEffect::UnknownWrite
            }
        } else {
            MemoryEffect::None
        }
    } else {
        MemoryEffect::None
    };

    Insn::with_ops(
        decoded.length as usize,
        kind,
        ops,
        op_count,
        writes_implicit_gpr0,
        writes_op0_reg,
        value_effect,
        memory_effect,
    )
}

fn value_effect(mnemonic: &str, operands: &[&DecodedOperand], writes_op0_reg: bool) -> ValueEffect {
    if !writes_op0_reg {
        return ValueEffect::None;
    }
    match mnemonic {
        "MOV" => {
            if operands
                .get(1)
                .is_some_and(|operand| operand.kind == OperandKind::Memory)
            {
                ValueEffect::Load
            } else {
                ValueEffect::Set
            }
        }
        "MOVZX" => extension_effect(operands, false).unwrap_or(ValueEffect::UnknownWrite),
        "MOVSX" | "MOVSXD" => extension_effect(operands, true).unwrap_or(ValueEffect::UnknownWrite),
        "LEA" => ValueEffect::Address,
        "ADD"
            if operands
                .get(1)
                .is_some_and(|operand| operand.kind == OperandKind::Register) =>
        {
            ValueEffect::AddRegister
        }
        "SUB"
            if operands
                .get(1)
                .is_some_and(|operand| operand.kind == OperandKind::Register) =>
        {
            ValueEffect::SubtractRegister
        }
        "ADD" | "SUB" => ValueEffect::AddImmediate,
        "AND"
            if operands
                .get(1)
                .is_some_and(|operand| operand.kind == OperandKind::Immediate) =>
        {
            ValueEffect::BitwiseAndImmediate
        }
        "SHL" | "SAL" | "SHR" | "SAR"
            if operands
                .get(1)
                .is_some_and(|operand| operand.kind == OperandKind::Immediate) =>
        {
            ValueEffect::ShiftImmediate
        }
        mnemonic if mnemonic.starts_with("CMOV") => ValueEffect::ConditionalSelect,
        _ => ValueEffect::UnknownWrite,
    }
}

fn extension_effect(operands: &[&DecodedOperand], signed: bool) -> Option<ValueEffect> {
    let width = match operands.get(1)?.kind {
        OperandKind::Register => operands[1].register?.width,
        OperandKind::Memory => operands[1].memory.size,
        _ => return None,
    };
    match (signed, width) {
        (false, 8) => Some(ValueEffect::ZeroExtend8),
        (false, 16) => Some(ValueEffect::ZeroExtend16),
        (false, 32) => Some(ValueEffect::ZeroExtend32),
        (true, 8) => Some(ValueEffect::SignExtend8),
        (true, 16) => Some(ValueEffect::SignExtend16),
        (true, 32) => Some(ValueEffect::SignExtend32),
        _ => None,
    }
}

fn classify(decoded: &Decoded, va: u64) -> InsnKind {
    if decoded.encoding().mnemonic == "NOP" {
        return InsnKind::Nop;
    }
    let branch = || BranchInfo {
        target: extract_branch_target(decoded, va),
    };
    match decoded.flow_control() {
        FlowControl::UnconditionalBranch | FlowControl::IndirectBranch => {
            InsnKind::Branch(branch())
        }
        FlowControl::Call | FlowControl::IndirectCall => InsnKind::Call(branch()),
        FlowControl::ConditionalBranch | FlowControl::Transactional => {
            InsnKind::CondBranch(branch())
        }
        FlowControl::Return => InsnKind::Return,
        FlowControl::Next | FlowControl::Interrupt | FlowControl::Exception => {
            if let Some(memory) = decoded
                .operands()
                .iter()
                .find(|operand| operand.kind == OperandKind::Memory && operand.memory.rip_relative)
            {
                return InsnKind::PcRelative(PcRelInfo {
                    displacement: (decoded.length as i64).wrapping_add(memory.memory.displacement),
                    kind: if decoded.encoding().mnemonic == "LEA" {
                        PcRelKind::Address
                    } else {
                        PcRelKind::Memory
                    },
                });
            }
            InsnKind::Other
        }
    }
}

fn direct_target(decoded: &Decoded, va: u64) -> Option<u64> {
    let relative =
        explicit_operands(decoded).find(|operand| operand.kind == OperandKind::Relative)?;
    Some(
        va.wrapping_add(decoded.length as u64)
            .wrapping_add_signed(relative.immediate.signed),
    )
}

fn extract_branch_target(decoded: &Decoded, va: u64) -> BranchTarget {
    let Some(operand) = explicit_operands(decoded).next() else {
        return BranchTarget::Indirect;
    };
    match operand.kind {
        OperandKind::Relative => {
            let target = va
                .wrapping_add(decoded.length as u64)
                .wrapping_add_signed(operand.immediate.signed);
            BranchTarget::Direct(target.wrapping_sub(va) as i64)
        }
        OperandKind::Register => BranchTarget::Register,
        OperandKind::Memory => {
            if let Some(index) = operand.memory.index.and_then(map_register) {
                BranchTarget::IndexedMemory {
                    base: operand.memory.base.and_then(map_register),
                    index,
                    scale: operand.memory.scale,
                    displacement: operand.memory.displacement,
                }
            } else {
                BranchTarget::Indirect
            }
        }
        _ => BranchTarget::Indirect,
    }
}

fn extract_operands(decoded: &Decoded, va: u64) -> ([Operand; MAX_OPERANDS], u8) {
    let mut operands = [Operand::Imm(0); MAX_OPERANDS];
    let mut count = 0usize;
    for operand in explicit_operands(decoded) {
        if count == MAX_OPERANDS {
            break;
        }
        if let Some(mapped) = map_operand(operand, decoded.length, va) {
            operands[count] = mapped;
            count += 1;
        }
    }
    (operands, count as u8)
}

fn map_operand(operand: &DecodedOperand, length: u8, va: u64) -> Option<Operand> {
    match operand.kind {
        OperandKind::Register => operand.register.and_then(map_register).map(Operand::Reg),
        OperandKind::Memory => {
            let base = if operand.memory.rip_relative {
                Reg::gpr(16)
            } else {
                operand
                    .memory
                    .base
                    .and_then(map_register)
                    .unwrap_or_else(|| Reg::gpr(255))
            };
            if let Some(index) = operand.memory.index.and_then(map_register) {
                Some(Operand::IndexedMem {
                    base,
                    index,
                    scale: operand.memory.scale,
                    disp: operand.memory.displacement,
                })
            } else {
                Some(Operand::Mem {
                    base,
                    disp: operand.memory.displacement,
                })
            }
        }
        OperandKind::Immediate => Some(Operand::Imm(operand.immediate.value as i64)),
        OperandKind::Relative => Some(Operand::Imm(
            va.wrapping_add(length as u64)
                .wrapping_add_signed(operand.immediate.signed) as i64,
        )),
        OperandKind::None | OperandKind::FarPointer | OperandKind::Mask | OperandKind::Other => {
            None
        }
    }
}

fn map_register(register: mkasm_x86_64::Register) -> Option<Reg> {
    match register.class {
        RegisterClass::Gpr => Some(Reg::gpr(register.number)),
        RegisterClass::Vector => Some(Reg::fp(register.number)),
        _ => None,
    }
}

pub(crate) fn disassemble_one(bytes: &[u8], va: u64) -> Result<String, DecodeError> {
    Ok(decode_mkasm(bytes)?.format_intel(va))
}

pub(crate) fn disassemble(bytes: &[u8], base_va: u64) -> Result<Vec<(u64, String)>, DecodeError> {
    let mut result = Vec::new();
    let mut offset = 0usize;
    while offset < bytes.len() {
        let decoded = decode_mkasm(&bytes[offset..])?;
        let va = base_va.saturating_add(offset as u64);
        result.push((va, decoded.format_intel(va)));
        offset += decoded.length as usize;
    }
    Ok(result)
}

pub(crate) fn encode_branch_insn(
    from_va: u64,
    to_va: u64,
    link: bool,
) -> Result<Vec<u8>, crate::insn::EncodeError> {
    let kind = if link {
        RelativeBranchKind::Call
    } else {
        RelativeBranchKind::Jump
    };
    let mut output = [0u8; 15];
    let length = mkasm_x86_64::encode_relative_branch(kind, from_va, to_va, &mut output).map_err(
        |error| crate::insn::EncodeError {
            message: format!("x86 relative branch encoding failed: {error:?}"),
        },
    )?;
    Ok(output[..length].to_vec())
}

pub(crate) fn relocate(
    bytes: &[u8],
    old_va: u64,
    new_va: u64,
) -> Result<Vec<u8>, crate::insn::EncodeError> {
    let decoded = decode_mkasm(bytes).map_err(|_| crate::insn::EncodeError {
        message: "cannot relocate invalid instruction".into(),
    })?;
    if decoded.length as usize != bytes.len() {
        return Err(crate::insn::EncodeError {
            message: "cannot relocate multiple or mismatched instructions".into(),
        });
    }
    let mut output = [0u8; 15];
    let length =
        mkasm_x86_64::relocate(&decoded, bytes, old_va, new_va, &mut output).map_err(|error| {
            crate::insn::EncodeError {
                message: format!("relocation failed: {error:?}"),
            }
        })?;
    Ok(output[..length].to_vec())
}

#[cfg(test)]
mod coverage_tests {
    use super::*;

    #[test]
    fn padlock_reserved_bits_are_not_promoted_to_instructions() {
        let decoded = decode_mkasm(&[0x0f, 0xa7, 0xc0]).unwrap();
        assert_eq!(decoded.encoding().mnemonic, "XSTORE");
        assert_eq!(decoded.length, 3);

        let error = decode_mkasm(&[0x0f, 0xa7, 0xc1]).unwrap_err();
        assert_eq!(error.kind, DecodeErrorKind::UnknownEncoding);
    }
}
