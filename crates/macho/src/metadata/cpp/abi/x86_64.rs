fn analyze_x86_64(bytes: &[u8], va: u64) -> AnalysisResult {
    if bytes.is_empty() {
        return (
            CppBodyKind::Unknown,
            CppReturnChannel::Unknown,
            false,
            None,
            None,
            None,
            "empty body".into(),
        );
    }

    // ── First-instruction classification (thunk / stub) ──

    // Check for this-adjusting thunk: ADD/SUB rdi, imm; JMP.
    if let Ok(first) = crate::insn::decode_one(bytes, va, Arch::X86_64) {
        if matches!(first.kind, InsnKind::Other) {
            let ops = first.operands();
            if let (Some(Operand::Reg(dst)), Some(&Operand::Imm(imm))) = (ops.first(), ops.get(1)) {
                if dst.class == RegClass::Gpr && dst.num == X86_RDI {
                    if let Ok(next) = crate::insn::decode_one(
                        &bytes[first.len..],
                        va + first.len as u64,
                        Arch::X86_64,
                    ) {
                        if matches!(next.kind, InsnKind::Branch(_)) {
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
                                None,
                                "this-adjusting thunk".into(),
                            );
                        }
                    }
                }
            }
        }

        match &first.kind {
            InsnKind::Branch(_) => {
                return (
                    CppBodyKind::Thunk,
                    CppReturnChannel::Unknown,
                    true,
                    None,
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
                    Some(ParamCounts { gpr: 0, fp: 0 }),
                    None,
                    "immediate RET".into(),
                );
            }
            _ => {}
        }
    }

    // ── Decode full body with CFG ──
    let cfg = FunctionCfg::build(bytes, va, Arch::X86_64);

    // ── Prologue scan: register spills ──
    let mut detail_parts = Vec::new();
    let mut max_gpr_arg_touched = -1i32;
    let mut max_fp_arg_touched = -1i32;
    let mut rdi_was_saved = false;

    for insn in cfg.insns.iter().take(PROLOGUE_WINDOW) {
        if matches!(
            insn.kind,
            InsnKind::Return | InsnKind::Branch(_) | InsnKind::Call(_)
        ) {
            break;
        }

        let ops = insn.operands();
        match ops {
            // Single register operand (PUSH reg).
            [Operand::Reg(r)] if r.class == RegClass::Gpr => {
                if r.num == X86_RDI {
                    rdi_was_saved = true;
                }
                if let Some(pos) = x86_arg_position(r.num) {
                    max_gpr_arg_touched = max_gpr_arg_touched.max(pos);
                }
            }
            // Memory destination + GPR source (MOV [rsp+disp], reg).
            [Operand::Mem { .. }, Operand::Reg(r)] if r.class == RegClass::Gpr => {
                if r.num == X86_RDI {
                    rdi_was_saved = true;
                }
                if let Some(pos) = x86_arg_position(r.num) {
                    max_gpr_arg_touched = max_gpr_arg_touched.max(pos);
                }
            }
            // Memory destination + FP source (MOVSD [rsp+disp], xmm0).
            [Operand::Mem { .. }, Operand::Reg(r)] if r.class == RegClass::Fp && r.num <= 7 => {
                max_fp_arg_touched = max_fp_arg_touched.max(r.num as i32);
            }
            _ => {}
        }
    }

    // ── Epilogue scan: all reachable RETs ──
    let ret_positions = cfg.ret_positions();
    let mut wrote_xmm0 = false;
    let mut wrote_rax = false;
    let mut rax_from_stack = false;

    for &rp in &ret_positions {
        let window_start = rp.saturating_sub(EPILOGUE_WINDOW);
        for insn in &cfg.insns[window_start..rp] {
            // Skip instructions that write rax as an implicit side effect.
            if insn.writes_implicit_gpr0 {
                continue;
            }
            match insn.operands() {
                // xmm0 written.
                [Operand::Reg(r), ..] if r.class == RegClass::Fp && r.num == 0 => {
                    wrote_xmm0 = true;
                }
                // rax loaded from memory → possible sret return.
                [Operand::Reg(r), Operand::Mem { .. }]
                    if r.class == RegClass::Gpr && r.num == 0 =>
                {
                    rax_from_stack = true;
                    wrote_rax = true;
                }
                // rax written explicitly.
                [Operand::Reg(r), ..] if r.class == RegClass::Gpr && r.num == 0 => {
                    wrote_rax = true;
                }
                _ => {}
            }
        }
    }

    // ── sret detection ──
    // On SysV, sret passes the return pointer in rdi and the function returns
    // it in rax. Both conditions must hold: rdi was saved AND rax was loaded
    // from the stack in the epilogue.
    let mut has_sret = false;
    if rdi_was_saved && rax_from_stack {
        has_sret = true;
    }

    // ── Return channel ──
    let mut return_channel = CppReturnChannel::Unknown;
    if has_sret {
        return_channel = CppReturnChannel::AggregateIndirect;
        detail_parts.push("sret (rax loaded from stack, rdi saved)");
        // rdi is the hidden sret pointer — adjust param count.
        if max_gpr_arg_touched == 0 {
            max_gpr_arg_touched = -1;
        } else if max_gpr_arg_touched > 0 {
            max_gpr_arg_touched -= 1;
        }
    } else if wrote_xmm0 {
        return_channel = CppReturnChannel::FloatingPoint;
        detail_parts.push("xmm0 set before RET");
    } else if wrote_rax {
        return_channel = CppReturnChannel::GeneralPurpose;
        detail_parts.push("rax set before RET");
    } else if !ret_positions.is_empty() {
        return_channel = CppReturnChannel::Void;
        detail_parts.push("no return register written");
    }

    // ── Parameter count with ABI caps ──
    let gpr = if max_gpr_arg_touched >= 0 {
        ((max_gpr_arg_touched + 1) as u32).min(X86_64_MAX_GPR_ARGS)
    } else {
        0
    };
    let fp = if max_fp_arg_touched >= 0 {
        ((max_fp_arg_touched + 1) as u32).min(X86_64_MAX_FP_ARGS)
    } else {
        0
    };
    let param_counts = if gpr > 0 || fp > 0 {
        detail_parts.push("param count from register spills");
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

// ───────────────────── argument type inference ─────────────────────

/// Known C string functions. If the function body calls any of these, pointer
/// arguments are likely C strings.
const STRING_FUNCTIONS: &[&str] = &[
    "strlen",
    "strcmp",
    "strncmp",
    "strcpy",
    "strncpy",
    "strcat",
    "strncat",
    "strdup",
    "strndup",
    "strchr",
    "strrchr",
    "strstr",
    "strtol",
    "strtoul",
    "strtod",
    "strtof",
    "atoi",
    "atol",
    "atof",
    "printf",
    "fprintf",
    "snprintf",
    "sprintf",
    "vprintf",
    "vfprintf",
    "vsnprintf",
    "vsprintf",
    "puts",
    "fputs",
    "fgets",
    "sscanf",
    "fscanf",
    "fopen",
    "freopen",
    // CoreFoundation / ObjC-adjacent
    "NSLog",
    "CFStringCreateWithCString",
];

/// Known ObjC runtime functions. If arg0 is a pointer and the function calls
/// one of these, arg0 is an ObjC object.
const OBJC_FUNCTIONS: &[&str] = &[
    "objc_msgSend",
    "objc_msgSendSuper",
    "objc_msgSendSuper2",
    "objc_msgSend_stret",
    "objc_retain",
    "objc_release",
    "objc_autorelease",
    "objc_alloc",
    "objc_alloc_init",
    "objc_opt_new",
    "objc_storeStrong",
    "objc_retainAutoreleasedReturnValue",
];
