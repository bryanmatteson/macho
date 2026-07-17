fn analyze_arm64(bytes: &[u8], va: u64, arch: Arch) -> AnalysisResult {
    if bytes.len() < 4 {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "function body too small".into(),
        );
    }

    let cfg = FunctionCfg::build(bytes, va, arch);
    if cfg.insns.is_empty() {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "no decodable instructions".into(),
        );
    }

    // ── First-instruction classification (thunk / stub) ──
    match &cfg.insns[0].kind {
        InsnKind::Return => {
            return (
                CppBodyKind::Stub,
                CppReturnChannel::Unknown,
                true,
                None,
                Some(ParamCounts { gpr: 0, fp: 0 }),
                None,
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
                None,
                "immediate branch/call".into(),
            );
        }
        _ => {}
    }

    // ── Prologue scan: register spills ──
    let mut detail_parts = Vec::new();
    let mut has_sret = false;
    let mut max_gpr_arg_saved = -1i32;
    let mut max_fpr_arg_saved = -1i32;

    for insn in cfg.insns.iter().take(PROLOGUE_WINDOW) {
        if matches!(
            insn.kind,
            InsnKind::Return | InsnKind::Branch(_) | InsnKind::Call(_)
        ) {
            break;
        }

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
    }

    // ── Epilogue scan: all reachable RETs ──
    let ret_positions = cfg.ret_positions();
    let mut wrote_d0 = false;
    let mut wrote_x0 = false;

    for &rp in &ret_positions {
        let window_start = rp.saturating_sub(EPILOGUE_WINDOW);
        for insn in &cfg.insns[window_start..rp] {
            let ops = insn.operands();
            if let [Operand::Reg(dst), Operand::Reg(src)] = ops {
                if dst.class == RegClass::Fp && dst.num == 0 && src.class == RegClass::Fp {
                    wrote_d0 = true;
                }
            }
            if let Some(Operand::Reg(r)) = ops.first() {
                if r.class == RegClass::Gpr && r.num == 0 {
                    let is_restore = ops.iter().any(|op| {
                        matches!(
                            op,
                            Operand::Mem { base, .. } if base.class == RegClass::Gpr && base.num == 31
                        )
                    });
                    if !is_restore {
                        wrote_x0 = true;
                    }
                }
            }
        }
    }

    // ── Return channel ──
    let mut return_channel = CppReturnChannel::Unknown;
    if has_sret {
        return_channel = CppReturnChannel::AggregateIndirect;
        detail_parts.push("x8 saved (sret)");
    } else if wrote_d0 {
        return_channel = CppReturnChannel::FloatingPoint;
        detail_parts.push("FP return detected");
    } else if wrote_x0 {
        return_channel = CppReturnChannel::GeneralPurpose;
        detail_parts.push("x0 set before RET");
    } else if !ret_positions.is_empty() {
        return_channel = CppReturnChannel::Void;
        detail_parts.push("no return register written");
    }

    // ── Parameter count with ABI caps ──
    let param_counts = if max_gpr_arg_saved >= 0 || max_fpr_arg_saved >= 0 {
        let gpr = if max_gpr_arg_saved >= 0 {
            ((max_gpr_arg_saved + 1) as u32).min(ARM64_MAX_GPR_ARGS)
        } else {
            0
        };
        let fp = if max_fpr_arg_saved >= 0 {
            ((max_fpr_arg_saved + 1) as u32).min(ARM64_MAX_FP_ARGS)
        } else {
            0
        };
        detail_parts.push("param count from register saves");
        Some(ParamCounts { gpr, fp })
    } else {
        None
    };

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
        param_counts,
        Some(cfg),
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

/// Map x86_64 GPR number to SysV argument position (0-5).
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
