//! C++ function body analysis for ABI heuristics.
//!
//! Uses `macho-insn` to decode function prologues and infer:
//! - Whether the function is a stub, thunk, or standard body
//! - Return channel (GPR, FP/SIMD, aggregate-indirect, void)
//! - Estimated parameter count from register saves
//! - `this` adjustment for thunks

use super::types::{
    CppBodyAnalysis, CppBodyKind, CppConfidence, CppEvidence, CppEvidenceKind, CppReturnChannel,
};
use crate::core::model::addr::Va;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::{Symbol, SymbolTable};
use macho_insn::{Arch, InsnKind, Operand, Reg, RegClass};

/// Analyze the body of a C++ symbol for ABI characteristics.
pub fn analyze_symbol_body(
    macho: &MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    symbol: &Symbol<'_>,
) -> Option<CppBodyAnalysis> {
    if !symbol.is_defined() || symbol.value == 0 {
        return None;
    }

    let bytes = symbol_bytes(macho, symtab, symbol, 64)?;
    let arch_name = macho.header().cpu_type.name().to_string();

    let (kind, return_channel, likely_wrapper, this_adjustment, param_count, evidence_detail) =
        if arch_name.starts_with("arm64") {
            let arch = if arch_name == "arm64e" {
                Arch::Arm64e
            } else {
                Arch::Arm64
            };
            analyze_arm64(bytes, symbol.value, arch)
        } else if arch_name == "x86_64" {
            analyze_x86_64(bytes, symbol.value)
        } else {
            (
                CppBodyKind::Unknown,
                CppReturnChannel::Unknown,
                false,
                None,
                None,
                "unsupported architecture".to_string(),
            )
        };

    let confidence = match kind {
        CppBodyKind::Thunk | CppBodyKind::Stub => CppConfidence::High,
        CppBodyKind::Standard => {
            if return_channel != CppReturnChannel::Unknown {
                CppConfidence::Medium
            } else {
                CppConfidence::Low
            }
        }
        CppBodyKind::Unknown => CppConfidence::Low,
    };

    Some(CppBodyAnalysis {
        arch: arch_name,
        kind,
        return_channel,
        this_adjustment,
        likely_wrapper,
        param_count,
        evidence: vec![CppEvidence {
            kind: CppEvidenceKind::BodyAnalysis,
            confidence,
            detail: evidence_detail,
        }],
    })
}

fn symbol_bytes<'a>(
    macho: &'a MachoFile<'_>,
    symtab: &SymbolTable<'_>,
    symbol: &Symbol<'_>,
    max_len: usize,
) -> Option<&'a [u8]> {
    let next_va = symtab
        .defined()
        .filter(|candidate| candidate.value > symbol.value)
        .map(|candidate| candidate.value)
        .min()
        .unwrap_or(symbol.value + max_len as u64);
    let len = (next_va - symbol.value).min(max_len as u64) as usize;
    macho.read_bytes_at_va(Va(symbol.value), len.max(1)).ok()
}

// ───────────────────────── ARM64 analysis ─────────────────────────

fn analyze_arm64(
    bytes: &[u8],
    va: u64,
    arch: Arch,
) -> (CppBodyKind, CppReturnChannel, bool, Option<i64>, Option<u32>, String) {
    if bytes.len() < 4 {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            "function body too small".into(),
        );
    }

    // Classify the first instruction to detect stubs and thunks.
    if let Ok(first) = macho_insn::decode_one(bytes, va, arch) {
        match &first.kind {
            InsnKind::Return => {
                return (
                    CppBodyKind::Stub,
                    CppReturnChannel::Unknown,
                    true,
                    None,
                    Some(0),
                    "immediate RET".into(),
                );
            }
            InsnKind::Branch(_) | InsnKind::Call(_) => {
                return (
                    CppBodyKind::Thunk,
                    CppReturnChannel::Unknown,
                    true,
                    None,
                    None,
                    "immediate branch/call".into(),
                );
            }
            _ => {}
        }
    }

    // Standard function: scan prologue for register saves and return hints.
    let mut detail_parts = Vec::new();
    let mut param_count = None;
    let mut return_channel = CppReturnChannel::Unknown;
    let mut uses_fp_result = false;
    let mut has_sret = false;
    let mut max_gpr_arg_saved = -1i32;
    let mut max_fpr_arg_saved = -1i32;

    let mut insn_count = 0usize;
    for insn in macho_insn::decode_iter(bytes, va, arch).take(16) {
        if matches!(
            insn.kind,
            InsnKind::Return | InsnKind::Branch(_) | InsnKind::Call(_)
        ) {
            break;
        }

        // Only count argument registers in store instructions (STP/STR),
        // not in arithmetic or data-processing instructions. A store is
        // identified by having a Mem operand alongside the register operands.
        let ops = insn.operands();
        let is_store = ops.iter().any(|op| matches!(op, Operand::Mem { .. }));
        if is_store {
            for op in ops {
                match op {
                    Operand::Reg(r) if r.class == RegClass::Gpr && r.num <= 7 => {
                        max_gpr_arg_saved = max_gpr_arg_saved.max(r.num as i32);
                    }
                    Operand::Reg(r) if r.class == RegClass::Gpr && r.num == 8 => {
                        has_sret = true;
                    }
                    Operand::Reg(r) if r.class == RegClass::Fp && r.num <= 7 => {
                        max_fpr_arg_saved = max_fpr_arg_saved.max(r.num as i32);
                    }
                    _ => {}
                }
            }
        }

        insn_count += 1;
    }

    // Scan epilogue for FP return hints: FMOV to d0/s0.
    // Only match register-to-register FP moves (2 FP operands, destination is Fp(0)),
    // not loads/stores that happen to reference d0.
    let epilogue_start = insn_count.saturating_sub(8);
    for insn in macho_insn::decode_iter(bytes, va, arch).skip(epilogue_start) {
        let ops = insn.operands();
        if let [Operand::Reg(dst), Operand::Reg(src)] = ops {
            if dst.class == RegClass::Fp
                && dst.num == 0
                && src.class == RegClass::Fp
            {
                uses_fp_result = true;
            }
        }
    }

    // Infer return channel.
    if has_sret {
        return_channel = CppReturnChannel::AggregateIndirect;
        detail_parts.push("x8 saved (sret)");
    } else if uses_fp_result {
        return_channel = CppReturnChannel::FloatingPoint;
        detail_parts.push("FP return detected");
    } else if insn_count > 4 {
        return_channel = CppReturnChannel::GeneralPurpose;
        detail_parts.push("GPR return assumed");
    }

    // Infer parameter count from saved argument registers.
    if max_gpr_arg_saved >= 0 || max_fpr_arg_saved >= 0 {
        let gpr_args = if max_gpr_arg_saved >= 0 {
            (max_gpr_arg_saved + 1) as u32
        } else {
            0
        };
        let fpr_args = if max_fpr_arg_saved >= 0 {
            (max_fpr_arg_saved + 1) as u32
        } else {
            0
        };
        param_count = Some(gpr_args + fpr_args);
        detail_parts.push("param count from register saves");
    }

    let detail = if detail_parts.is_empty() {
        "standard body, no strong heuristics".to_string()
    } else {
        detail_parts.join("; ")
    };

    (
        CppBodyKind::Standard,
        return_channel,
        false,
        None,
        param_count,
        detail,
    )
}

// ───────────────────────── x86_64 analysis ─────────────────────────

/// x86_64 SysV ABI argument register numbers (in macho-insn Gpr numbering).
const X86_RDI: u8 = 7;
const X86_RSI: u8 = 6;
const X86_RDX: u8 = 2;
const X86_RCX: u8 = 1;
const X86_R8: u8 = 8;
const X86_R9: u8 = 9;

/// Map x86_64 GPR number to SysV argument position (0-5), if it's an argument register.
fn x86_arg_position(gpr_num: u8) -> Option<i32> {
    match gpr_num {
        X86_RDI => Some(0),
        X86_RSI => Some(1),
        X86_RDX => Some(2),
        X86_RCX => Some(3),
        X86_R8 => Some(4),
        X86_R9 => Some(5),
        _ => None,
    }
}

fn analyze_x86_64(
    bytes: &[u8],
    va: u64,
) -> (CppBodyKind, CppReturnChannel, bool, Option<i64>, Option<u32>, String) {
    if bytes.is_empty() {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            "empty body".into(),
        );
    }

    // Check for this-adjusting thunk: ADD/SUB rdi, imm; JMP.
    if let Ok(first) = macho_insn::decode_one(bytes, va, Arch::X86_64) {
        if matches!(first.kind, InsnKind::Other) {
            let ops = first.operands();
            if let (Some(Operand::Reg(dst)), Some(&Operand::Imm(imm))) =
                (ops.first(), ops.get(1))
            {
                if dst.class == RegClass::Gpr && dst.num == X86_RDI {
                    if let Ok(next) =
                        macho_insn::decode_one(&bytes[first.len..], va + first.len as u64, Arch::X86_64)
                    {
                        if matches!(next.kind, InsnKind::Branch(_)) {
                            // Determine sign: iced-x86 reports the raw immediate
                            // for both ADD and SUB. Distinguish via the ModRM reg
                            // field in the REX-prefixed encoding: ADD is reg=0,
                            // SUB is reg=5. The ModRM byte follows the REX prefix
                            // and opcode (bytes[2] for 48 83/81 xx patterns).
                            let adj = if bytes.len() > 2 && (bytes[2] >> 3) & 7 == 5 {
                                -imm
                            } else {
                                imm
                            };
                            return (
                                CppBodyKind::Thunk,
                                CppReturnChannel::Unknown,
                                true,
                                Some(adj),
                                None,
                                "this-adjusting thunk".into(),
                            );
                        }
                    }
                }
            }
        }

        // Single-instruction classification.
        match &first.kind {
            InsnKind::Branch(_) => {
                return (
                    CppBodyKind::Thunk,
                    CppReturnChannel::Unknown,
                    true,
                    None,
                    None,
                    "jump thunk".into(),
                );
            }
            InsnKind::Return => {
                return (
                    CppBodyKind::Stub,
                    CppReturnChannel::Unknown,
                    true,
                    None,
                    Some(0),
                    "immediate RET".into(),
                );
            }
            _ => {}
        }
    }

    // Standard function: scan prologue for argument register usage.
    let mut detail_parts = Vec::new();
    let mut return_channel = CppReturnChannel::Unknown;
    let mut param_count = None;
    let mut max_gpr_arg_touched = -1i32;
    let mut uses_xmm_return = false;
    let mut insn_count = 0;

    for insn in macho_insn::decode_iter(bytes, va, Arch::X86_64).take(20) {
        if matches!(insn.kind, InsnKind::Return | InsnKind::Branch(_)) {
            break;
        }

        // Track argument register spills — only count registers being stored,
        // not just mentioned. This avoids false positives from CMP, MOV-to-reg,
        // XOR-zero patterns, etc.
        let ops = insn.operands();
        match ops {
            // Single register operand (PUSH reg): count if it's an arg register.
            [Operand::Reg(r)] if r.class == RegClass::Gpr => {
                if let Some(pos) = x86_arg_position(r.num) {
                    max_gpr_arg_touched = max_gpr_arg_touched.max(pos);
                }
            }
            // Memory destination + register source (MOV [rsp+disp], reg): the
            // register is being stored to the stack frame.
            [Operand::Mem { .. }, Operand::Reg(r)] if r.class == RegClass::Gpr => {
                if let Some(pos) = x86_arg_position(r.num) {
                    max_gpr_arg_touched = max_gpr_arg_touched.max(pos);
                }
            }
            _ => {}
        }

        insn_count += 1;
    }

    // Scan epilogue for xmm0 writes before RET.
    let mut last_uses_xmm0 = false;
    for insn in macho_insn::decode_iter(bytes, va, Arch::X86_64).take(200) {
        if let Some(Operand::Reg(r)) = insn.operands().first() {
            if r.class == RegClass::Fp && r.num == 0 {
                last_uses_xmm0 = true;
            }
        }
        if matches!(insn.kind, InsnKind::Return) && last_uses_xmm0 {
            uses_xmm_return = true;
        }
    }

    // Infer return channel.
    if uses_xmm_return {
        return_channel = CppReturnChannel::FloatingPoint;
        detail_parts.push("xmm0 set before RET");
    } else if insn_count > 3 {
        return_channel = CppReturnChannel::GeneralPurpose;
        detail_parts.push("GPR return assumed");
    }

    // Infer parameter count from argument register usage.
    if max_gpr_arg_touched >= 0 {
        param_count = Some((max_gpr_arg_touched + 1) as u32);
        detail_parts.push("param count from register spills");
    }

    let detail = if detail_parts.is_empty() {
        "standard body, no strong heuristics".to_string()
    } else {
        detail_parts.join("; ")
    };

    (
        CppBodyKind::Standard,
        return_channel,
        false,
        None,
        param_count,
        detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_x86_jmp_thunk() {
        let (kind, _, wrapper, _, _, _) = analyze_x86_64(&[0xE9, 0, 0, 0, 0], 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }

    #[test]
    fn classifies_x86_ret_stub() {
        let (kind, _, _, _, param_count, _) = analyze_x86_64(&[0xC3], 0x1000);
        assert!(matches!(kind, CppBodyKind::Stub));
        assert_eq!(param_count, Some(0));
    }

    #[test]
    fn classifies_arm64_branch_thunk() {
        let word = 0x1400_0001u32.to_le_bytes();
        let (kind, _, wrapper, _, _, _) = analyze_arm64(&word, 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }

    #[test]
    fn classifies_arm64_ret_stub() {
        let word = 0xD65F_03C0u32.to_le_bytes();
        let (kind, _, _, _, param_count, _) = analyze_arm64(&word, 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Stub));
        assert_eq!(param_count, Some(0));
    }

    #[test]
    fn detects_x86_64_this_adjustment_add() {
        // ADD rdi, 8; JMP rel32
        let bytes = [0x48, 0x83, 0xC7, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let (kind, _, _, adj, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(8));
    }

    #[test]
    fn detects_x86_64_this_adjustment_sub() {
        // SUB rdi, 8; JMP rel32
        let bytes = [0x48, 0x83, 0xEF, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let (kind, _, _, adj, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(-8));
    }

    #[test]
    fn detects_x86_64_arg_push_spills() {
        // PUSH rdi; PUSH rsi; RET
        let bytes = [0x57, 0x56, 0xC3];
        let (_, _, _, _, param_count, _) = analyze_x86_64(&bytes, 0x1000);
        // rdi=arg0, rsi=arg1 → 2 params
        assert_eq!(param_count, Some(2));
    }

    #[test]
    fn x86_64_non_spill_does_not_inflate_param_count() {
        // CMP rdi, 0; JE +2; RET (rdi is tested, not spilled)
        // 48 83 FF 00  = CMP rdi, 0
        // 74 01        = JE +1
        // C3           = RET
        // 90           = NOP (filler for JE target)
        // C3           = RET
        let bytes = [0x48, 0x83, 0xFF, 0x00, 0x74, 0x01, 0xC3, 0x90, 0xC3];
        let (kind, _, _, _, param_count, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Standard));
        // CMP rdi, 0 should NOT count rdi as a spilled argument
        assert_eq!(param_count, None);
    }
}
