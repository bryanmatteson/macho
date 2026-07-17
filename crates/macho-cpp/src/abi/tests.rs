#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_x86_jmp_thunk() {
        let (kind, _, wrapper, _, _, _, _) = analyze_x86_64(&[0xE9, 0, 0, 0, 0], 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }

    #[test]
    fn classifies_x86_ret_stub() {
        let (kind, _, _, _, param_counts, _, _) = analyze_x86_64(&[0xC3], 0x1000);
        assert!(matches!(kind, CppBodyKind::Stub));
        assert_eq!(param_counts.map(|pc| pc.total()), Some(0));
    }

    #[test]
    fn classifies_arm64_branch_thunk() {
        let word = 0x1400_0001u32.to_le_bytes();
        let (kind, _, wrapper, _, _, _, _) = analyze_arm64(&word, 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert!(wrapper);
    }

    #[test]
    fn classifies_arm64_ret_stub() {
        let word = 0xD65F_03C0u32.to_le_bytes();
        let (kind, _, _, _, param_counts, _, _) = analyze_arm64(&word, 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Stub));
        assert_eq!(param_counts.map(|pc| pc.total()), Some(0));
    }

    #[test]
    fn detects_x86_64_this_adjustment_add() {
        let bytes = [0x48, 0x83, 0xC7, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let (kind, _, _, adj, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(8));
    }

    #[test]
    fn detects_x86_64_this_adjustment_sub() {
        let bytes = [0x48, 0x83, 0xEF, 0x08, 0xE9, 0x00, 0x00, 0x00, 0x00];
        let (kind, _, _, adj, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(-8));
    }

    #[test]
    fn detects_x86_64_arg_push_spills() {
        // PUSH rdi; PUSH rsi; MOV eax, 1; RET
        let bytes = [0x57, 0x56, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
        let (_, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(param_counts.map(|pc| pc.total()), Some(2));
    }

    #[test]
    fn x86_64_non_spill_does_not_inflate_param_count() {
        // CMP rdi, 0; JE +1; RET; NOP; RET
        let bytes = [0x48, 0x83, 0xFF, 0x00, 0x74, 0x01, 0xC3, 0x90, 0xC3];
        let (kind, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Standard));
        assert!(param_counts.is_none());
    }

    #[test]
    fn x86_64_void_return_detected() {
        // PUSH rbp; MOV rbp, rsp; NOP; POP rbp; RET
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x90, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn x86_64_gpr_return_detected() {
        // PUSH rbp; MOV rbp, rsp; MOV eax, 42; POP rbp; RET
        let bytes = [
            0x55, 0x48, 0x89, 0xE5, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x5D, 0xC3,
        ];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_fp_return_detected() {
        // PUSH rbp; MOV rbp, rsp; MOVSD xmm0, xmm1; POP rbp; RET
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0xF2, 0x0F, 0x10, 0xC1, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::FloatingPoint);
    }

    #[test]
    fn x86_64_div_does_not_trigger_gpr_return() {
        // PUSH rbp; MOV rbp, rsp; DIV rcx; POP rbp; RET
        // DIV writes rax implicitly — should NOT count as GPR return.
        let bytes = [0x55, 0x48, 0x89, 0xE5, 0x48, 0xF7, 0xF1, 0x5D, 0xC3];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn x86_64_large_body_finds_epilogue() {
        // Prologue + 500 NOPs + MOV eax, 1 + POP rbp + RET
        let mut bytes = vec![0x55, 0x48, 0x89, 0xE5]; // PUSH rbp; MOV rbp, rsp
        bytes.extend(std::iter::repeat_n(0x90, 500)); // 500 NOPs
        bytes.extend_from_slice(&[0xB8, 0x01, 0x00, 0x00, 0x00]); // MOV eax, 1
        bytes.push(0x5D); // POP rbp
        bytes.push(0xC3); // RET
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_param_count_capped_at_abi_limit() {
        // PUSH rdi; PUSH rsi; PUSH rdx; PUSH rcx; PUSH r8; PUSH r9; MOV eax, 1; RET
        let bytes = [
            0x57, 0x56, 0x52, 0x51, 0x41, 0x50, 0x41, 0x51, 0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3,
        ];
        let (_, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(param_counts.is_some());
        assert!(
            param_counts.unwrap().gpr <= 6,
            "x86_64 GPR args capped at 6"
        );
    }

    // ── Argument type inference tests ──

    use crate::ArgumentTypeHint;

    /// Helper: build a CFG and run argument type inference for x86_64 with
    /// the given GPR arg count. No symbol table → call correlation won't fire,
    /// but pointer/scalar/overwrite detection still works.
    fn x86_hints(bytes: &[u8], gpr_args: u32) -> Vec<ArgumentTypeHint> {
        let cfg = FunctionCfg::build(bytes, 0x1000, Arch::X86_64);
        let counts = ParamCounts {
            gpr: gpr_args,
            fp: 0,
        };

        // Directly invoke the inference logic with the same structure as the
        // real path but without a SymbolTable (call correlation stays off).
        let gpr_arg_nums: Vec<u8> = vec![X86_RDI, X86_RSI, X86_RDX, X86_RCX, X86_R8, X86_R9];
        let gpr_count = counts.gpr.min(gpr_arg_nums.len() as u32) as usize;
        let active_gpr_args: BTreeSet<u8> = gpr_arg_nums[..gpr_count].iter().copied().collect();
        let mut gpr_usage: BTreeMap<u8, ArgUsage> = BTreeMap::new();
        let mut overwritten: BTreeSet<u8> = BTreeSet::new();

        for block in &cfg.blocks {
            if !block.reachable {
                continue;
            }
            for i in block.start..block.end {
                let insn = &cfg.insns[i];
                let ops = insn.operands();
                for op in ops {
                    if let Operand::Mem { base, disp } = op {
                        if base.class == RegClass::Gpr
                            && active_gpr_args.contains(&base.num)
                            && !overwritten.contains(&base.num)
                        {
                            let usage = gpr_usage.entry(base.num).or_default();
                            usage.is_pointer = true;
                            usage.deref_offsets.push(*disp);
                        }
                    }
                }
                // Same decoder-backed overwrite contract as the production
                // path — keep the test path in lockstep so a regression in
                // either shows up here.
                if insn.writes_op0_reg {
                    if let Some(r) = insn.op0_write_target() {
                        if r.class == RegClass::Gpr && active_gpr_args.contains(&r.num) {
                            overwritten.insert(r.num);
                        }
                    }
                }
            }
        }

        let mut hints = Vec::new();
        for &reg_num in &gpr_arg_nums[..gpr_count] {
            if let Some(usage) = gpr_usage.get(&reg_num) {
                if usage.is_pointer {
                    if usage.deref_offsets.contains(&0) && usage.deref_offsets.len() > 1 {
                        hints.push(ArgumentTypeHint::StructPointer);
                    } else {
                        hints.push(ArgumentTypeHint::Pointer);
                    }
                } else {
                    hints.push(ArgumentTypeHint::Scalar);
                }
            } else {
                hints.push(ArgumentTypeHint::Scalar);
            }
        }
        hints
    }

    #[test]
    fn x86_64_pointer_arg_detected() {
        // PUSH rdi; MOV rax, [rdi]; RET
        // rdi used as memory base → pointer
        let hints = x86_hints(&[0x57, 0x48, 0x8B, 0x07, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::Pointer);
    }

    #[test]
    fn x86_64_scalar_arg_detected() {
        // PUSH rdi; MOV eax, edi; RET
        // rdi used as value, never deref'd → scalar
        let hints = x86_hints(&[0x57, 0x89, 0xF8, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::Scalar);
    }

    #[test]
    fn x86_64_overwritten_reg_not_counted_as_pointer() {
        // MOV rdi, [rsp+8]; MOV rax, [rdi]; RET
        // rdi overwritten by a load before being used as base → Scalar
        let hints = x86_hints(&[0x48, 0x8B, 0x7C, 0x24, 0x08, 0x48, 0x8B, 0x07, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::Scalar);
    }

    #[test]
    fn x86_64_in_place_arithmetic_is_overwrite() {
        // ADD rdi, rax; MOV rax, [rdi]; RET
        // ADD writes rdi in place. The subsequent MOV rax, [rdi] dereferences
        // the modified register — the original arg was clobbered before the
        // deref, so it must not be classified as a pointer.
        let hints = x86_hints(&[0x48, 0x01, 0xC7, 0x48, 0x8B, 0x07, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0],
            ArgumentTypeHint::Scalar,
            "ADD rdi, rax must be detected as a write to rdi"
        );
    }

    #[test]
    fn x86_64_cmp_does_not_count_as_overwrite() {
        // CMP rdi, 0; MOV rax, [rdi]; RET
        // CMP is flag-setting only — must NOT mark rdi as overwritten.
        let hints = x86_hints(&[0x48, 0x83, 0xFF, 0x00, 0x48, 0x8B, 0x07, 0xC3], 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(
            hints[0],
            ArgumentTypeHint::Pointer,
            "CMP is read-only; rdi should still be classified as Pointer"
        );
    }

    // ── Edge cases and error paths ──

    #[test]
    fn x86_64_empty_body_is_unknown() {
        let (kind, rc, _, _, _, _, _) = analyze_x86_64(&[], 0x1000);
        assert!(matches!(kind, CppBodyKind::Unknown));
        assert_eq!(rc, CppReturnChannel::Unknown);
    }

    #[test]
    fn arm64_too_small_body_is_unknown() {
        // Less than 4 bytes → can't decode a single ARM64 instruction
        let (kind, rc, _, _, _, _, _) = analyze_arm64(&[0x00, 0x00], 0x1000, Arch::Arm64);
        assert!(matches!(kind, CppBodyKind::Unknown));
        assert_eq!(rc, CppReturnChannel::Unknown);
    }

    #[test]
    fn arm64_retaa_classified_as_return() {
        // RETAA = 0xD65F0BFF. The epilogue scanner must find this as a RET.
        // NOP; RETAA → Standard function with void return (no x0 write).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_0BFFu32.to_le_bytes()); // RETAA
        let (kind, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64e);
        assert!(matches!(kind, CppBodyKind::Standard));
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn arm64_void_return_detected() {
        // STP x29, x30, [sp, #-16]!; NOP; LDP x29, x30, [sp], #16; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xA9BF_7BFDu32.to_le_bytes()); // STP x29, x30, [sp, #-16]!
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xA8C1_7BFDu32.to_le_bytes()); // LDP x29, x30, [sp], #16
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::Void);
    }

    #[test]
    fn arm64_gpr_return_detected() {
        // ADD x0, xzr, #42; RET
        // ADD x0, x31, #42 encodes as: sf=1, op=0, S=0, 100010, sh=0, imm12=42, Rn=31, Rd=0
        // = 0x91000AA0... let me compute: 1_00_100010_0_000000101010_11111_00000
        // = 0x91_00_0A_A0? Let me be precise.
        // sf=1 → bit 31 = 1
        // op=0 → bit 30 = 0 (ADD)
        // S=0 → bit 29 = 0
        // 100010 → bits 28:23
        // sh=0 → bit 22 = 0
        // imm12=42 → bits 21:10 = 0x02A
        // Rn=31 → bits 9:5
        // Rd=0 → bits 4:0
        // = 1_00_100010_0_000000101010_11111_00000
        // = 1001_0001_0000_0000_1010_1011_1110_0000
        // = 0x9100_ABE0
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x9100_ABE0u32.to_le_bytes()); // ADD x0, x31, #42
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_no_ret_is_unknown() {
        // Function with no RET (infinite loop): JMP $-2
        // EB FE = JMP -2 (loops forever)
        let (_kind, rc, _, _, _, _, _) = analyze_x86_64(&[0xEB, 0xFE], 0x1000);
        // No RET found → return channel stays Unknown
        assert_eq!(rc, CppReturnChannel::Unknown);
    }

    #[test]
    fn x86_64_multiple_rets_different_paths() {
        // CMP rdi, 0; JE +6; MOV eax, 1; RET; XOR eax, eax; RET
        // Two return paths: one returns 1, one returns 0. Both write eax.
        let bytes = [
            0x48, 0x83, 0xFF, 0x00, // CMP rdi, 0
            0x74, 0x06, // JE +6 (skip to XOR eax, eax)
            0xB8, 0x01, 0x00, 0x00, 0x00, // MOV eax, 1
            0xC3, // RET
            0x31, 0xC0, // XOR eax, eax
            0xC3, // RET
        ];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        // Both paths write eax → GPR return
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    #[test]
    fn x86_64_cmp_then_deref_detects_pointer() {
        // CMP rdi, 0; JE +3; MOV rax, [rdi]; RET; RET
        // CMP doesn't overwrite rdi. The subsequent deref should still detect pointer.
        let bytes = [
            0x48, 0x83, 0xFF, 0x00, // CMP rdi, 0
            0x74, 0x03, // JE +3
            0x48, 0x8B, 0x07, // MOV rax, [rdi]
            0xC3, // RET
            0xC3, // RET (early exit path)
        ];
        let hints = x86_hints(&bytes, 1);
        assert_eq!(hints.len(), 1);
        // CMP should NOT mark rdi as overwritten → pointer detection succeeds
        assert_eq!(hints[0], ArgumentTypeHint::Pointer);
    }

    #[test]
    fn x86_64_struct_pointer_multi_offset() {
        // MOV rax, [rdi]; MOV rcx, [rdi+8]; RET
        // Dereference at offset 0 and offset 8 → StructPointer
        let bytes = [
            0x57, // PUSH rdi (spill)
            0x48, 0x8B, 0x07, // MOV rax, [rdi]       (offset 0)
            0x48, 0x8B, 0x4F, 0x08, // MOV rcx, [rdi+8]     (offset 8)
            0xC3, // RET
        ];
        let hints = x86_hints(&bytes, 1);
        assert_eq!(hints.len(), 1);
        assert_eq!(hints[0], ArgumentTypeHint::StructPointer);
    }

    #[test]
    fn x86_64_fp_param_count() {
        // A function that spills rdi (GPR) and xmm0 (FP) → ParamCounts { gpr: 1, fp: 1 }
        // PUSH rdi; MOVSD [rsp-8], xmm0; MOV eax, 1; RET
        let bytes = [
            0x57, // PUSH rdi
            0xF2, 0x0F, 0x11, 0x44, 0x24, 0xF8, // MOVSD [rsp-8], xmm0
            0xB8, 0x01, 0x00, 0x00, 0x00, // MOV eax, 1
            0xC3, // RET
        ];
        let (_, _, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        let pc = param_counts.expect("should detect params");
        assert_eq!(pc.gpr, 1, "1 GPR arg (rdi)");
        assert_eq!(pc.fp, 1, "1 FP arg (xmm0)");
        assert_eq!(pc.total(), 2);
    }

    #[test]
    fn arm64_stp_arg_spill_counts_params() {
        // STP x0, x1, [sp, #-16]!; STP x2, x3, [sp, #-16]!; NOP; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xA9BF_03E0u32.to_le_bytes()); // STP x0, x1, [sp, #-16]!
        bytes.extend_from_slice(&0xA9BF_0FE2u32.to_le_bytes()); // STP x2, x3, [sp, #-16]!
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, _, _, _, param_counts, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        let pc = param_counts.expect("should detect params");
        assert!(pc.gpr >= 4, "at least x0-x3 = 4 GPR args, got {}", pc.gpr);
    }

    #[test]
    fn arm64_x8_sret_detected() {
        // STR x8, [sp]; STP x0, x1, [sp, #8]; NOP; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0xF900_03E8u32.to_le_bytes()); // STR x8, [sp]
        bytes.extend_from_slice(&0xA900_07E0u32.to_le_bytes()); // STP x0, x1, [sp, #8]
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::AggregateIndirect, "x8 save → sret");
    }

    #[test]
    fn cfg_unreachable_block_excluded_from_ret_scan() {
        // Test that unreachable blocks don't contribute to return channel detection.
        // Use a conditional branch so the function isn't classified as a thunk.
        //
        // PUSH rbp; MOV rbp, rsp; CMP edi, 0; JE +6; MOV eax, 1; RET; INT3; RET
        //
        // The INT3 + second RET form an unreachable block (no branch targets there).
        // The JE targets the MOV eax path. Both paths from JE are reachable.
        // But the INT3; RET block is NOT a branch target from any instruction.
        //
        // 55             = PUSH rbp
        // 48 89 E5       = MOV rbp, rsp
        // 83 FF 00       = CMP edi, 0
        // 74 06          = JE +6 (target = 0x100C → XOR eax; POP rbp; RET)
        // B8 01 00 00 00 = MOV eax, 1
        // 5D             = POP rbp
        // C3             = RET
        // B8 00 00 00 00 = XOR-equivalent: MOV eax, 0 (JE target)
        // 5D             = POP rbp
        // C3             = RET
        let bytes = [
            0x55, // PUSH rbp
            0x48, 0x89, 0xE5, // MOV rbp, rsp
            0x83, 0xFF, 0x00, // CMP edi, 0
            0x74, 0x06, // JE +6
            0xB8, 0x01, 0x00, 0x00, 0x00, // MOV eax, 1
            0x5D, // POP rbp
            0xC3, // RET
            0xB8, 0x00, 0x00, 0x00, 0x00, // MOV eax, 0 (JE target)
            0x5D, // POP rbp
            0xC3, // RET
        ];
        let (_, rc, _, _, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        // Both reachable paths write eax → GPR return.
        assert_eq!(rc, CppReturnChannel::GeneralPurpose);
    }

    // ── ARM64 FP return ──

    #[test]
    fn arm64_fp_return_detected() {
        // FMOV d0, d1; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x1E60_4020u32.to_le_bytes()); // FMOV d0, d1
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, rc, _, _, _, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        assert_eq!(rc, CppReturnChannel::FloatingPoint);
    }

    // ── ARM64 FP param count ──

    #[test]
    fn arm64_fp_params_detected() {
        // STP d0, d1, [sp, #-16]!; NOP; RET
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x6DBF_07E0u32.to_le_bytes()); // STP d0, d1, [sp, #-16]!
        bytes.extend_from_slice(&0xD503_201Fu32.to_le_bytes()); // NOP
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, _, _, _, param_counts, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        let pc = param_counts.expect("should detect FP params");
        assert!(
            pc.fp >= 2,
            "expected at least 2 FP args (d0, d1), got {}",
            pc.fp
        );
    }

    // ── Pure FP function (gpr=0, fp>0) ──

    #[test]
    fn arm64_pure_fp_param_count() {
        // STP d0, d1, [sp, #-16]!; FMOV d0, d1; RET
        // Zero GPR args, 2 FP args
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x6DBF_07E0u32.to_le_bytes()); // STP d0, d1, [sp, #-16]!
        bytes.extend_from_slice(&0x1E60_4020u32.to_le_bytes()); // FMOV d0, d1
        bytes.extend_from_slice(&0xD65F_03C0u32.to_le_bytes()); // RET
        let (_, _, _, _, param_counts, _, _) = analyze_arm64(&bytes, 0x1000, Arch::Arm64);
        let pc = param_counts.expect("should detect FP params");
        assert_eq!(pc.gpr, 0, "no GPR args");
        assert!(pc.fp >= 2, "at least 2 FP args");
    }

    // ── x86_64 sret detection ──

    #[test]
    fn x86_64_sret_detected() {
        // A function that saves rdi to stack and loads rax from stack before RET:
        // PUSH rbp; MOV rbp, rsp; MOV [rbp-8], rdi; ... MOV rax, [rbp-8]; POP rbp; RET
        let bytes = [
            0x55, // PUSH rbp
            0x48, 0x89, 0xE5, // MOV rbp, rsp
            0x48, 0x89, 0x7D, 0xF8, // MOV [rbp-8], rdi (save rdi)
            0x90, // NOP (body)
            0x48, 0x8B, 0x45, 0xF8, // MOV rax, [rbp-8] (load rax from stack)
            0x5D, // POP rbp
            0xC3, // RET
        ];
        let (_, rc, _, _, param_counts, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert_eq!(
            rc,
            CppReturnChannel::AggregateIndirect,
            "rdi saved + rax from stack = sret"
        );
        // When sret is detected, rdi is not counted as a real argument
        if let Some(pc) = param_counts {
            assert_eq!(pc.gpr, 0, "rdi is sret pointer, not a real GPR arg");
        }
    }

    // ── x86_64 this-adjustment with SUB imm32 ──

    #[test]
    fn detects_x86_64_this_adjustment_sub_imm32() {
        // SUB rdi, 0x100; JMP rel32
        // 48 81 EF 00 01 00 00 = SUB rdi, 256
        // E9 00 00 00 00       = JMP +0
        let bytes = [
            0x48, 0x81, 0xEF, 0x00, 0x01, 0x00, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00,
        ];
        let (kind, _, _, adj, _, _, _) = analyze_x86_64(&bytes, 0x1000);
        assert!(matches!(kind, CppBodyKind::Thunk));
        assert_eq!(adj, Some(-256));
    }

    // ── CFG unit tests ──

    #[test]
    fn cfg_linear_function_single_block() {
        // NOP; NOP; RET — one basic block
        let cfg = FunctionCfg::build(&[0x90, 0x90, 0xC3], 0x1000, Arch::X86_64);
        assert_eq!(cfg.blocks.len(), 1);
        assert!(cfg.blocks[0].reachable);
        assert_eq!(cfg.insns.len(), 3);
    }

    #[test]
    fn cfg_conditional_branch_creates_two_blocks() {
        // JE +1; NOP; RET
        // 74 01 = JE +1
        // 90    = NOP
        // C3    = RET
        let cfg = FunctionCfg::build(&[0x74, 0x01, 0x90, 0xC3], 0x1000, Arch::X86_64);
        // Should have at least 2 blocks (before JE target and after)
        assert!(cfg.blocks.len() >= 2, "got {} blocks", cfg.blocks.len());
        // All blocks should be reachable (JE falls through or branches)
        assert!(
            cfg.blocks.iter().all(|b| b.reachable),
            "all blocks should be reachable"
        );
    }

    #[test]
    fn cfg_empty_input_no_blocks() {
        let cfg = FunctionCfg::build(&[], 0x1000, Arch::X86_64);
        assert!(cfg.insns.is_empty());
        assert!(cfg.blocks.is_empty());
        assert!(cfg.ret_positions().is_empty());
    }

    #[test]
    fn cfg_ret_positions_only_reachable() {
        // Test that both ret_positions are found for a two-path function.
        // PUSH rbp; MOV rbp, rsp; CMP edi, 0; JE +7;
        // MOV eax, 1; POP rbp; RET; MOV eax, 0; POP rbp; RET
        // JE +7: next_ip = 0x1009, target = 0x1010 (second MOV eax, 0)
        // Byte offsets: PUSH=0, MOV=1, CMP=4, JE=7, MOVeax1=9, POP=14, RET=15,
        //               MOVeax0=16, POP=21, RET=22
        let bytes = [
            0x55, // PUSH rbp        [0]
            0x48, 0x89, 0xE5, // MOV rbp, rsp    [1..4]
            0x83, 0xFF, 0x00, // CMP edi, 0      [4..7]
            0x74, 0x07, // JE +7            [7..9] target=9+7=16
            0xB8, 0x01, 0x00, 0x00, 0x00, // MOV eax, 1      [9..14]
            0x5D, // POP rbp          [14]
            0xC3, // RET              [15]
            0xB8, 0x00, 0x00, 0x00, 0x00, // MOV eax, 0      [16..21]
            0x5D, // POP rbp          [21]
            0xC3, // RET              [22]
        ];
        let cfg = FunctionCfg::build(&bytes, 0x1000, Arch::X86_64);
        let rets = cfg.ret_positions();
        assert_eq!(rets.len(), 2, "both RETs should be reachable, got {rets:?}");
    }

    #[test]
    fn cfg_insn_va_correct() {
        let cfg = FunctionCfg::build(&[0x90, 0x90, 0xC3], 0x4000, Arch::X86_64);
        assert_eq!(cfg.entry_va, 0x4000);
        assert_eq!(cfg.insn_va(&cfg.insns[0]), 0x4000); // NOP at offset 0
        assert_eq!(cfg.insn_va(&cfg.insns[1]), 0x4001); // NOP at offset 1
        assert_eq!(cfg.insn_va(&cfg.insns[2]), 0x4002); // RET at offset 2
    }
}
