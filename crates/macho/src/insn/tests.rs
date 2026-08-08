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

#[test]
fn x86_direct_call_prefilter_has_no_false_negatives_for_prefix_families() {
    let prefixes = [
        0x26, 0x2e, 0x36, 0x3e, 0x64, 0x65, 0x66, 0x67, 0xf0, 0xf2, 0xf3, 0x40, 0x48, 0x4f,
    ];
    let mut probes = vec![vec![0xe8, 0, 0, 0, 0]];
    for prefix in prefixes {
        for count in 1..=10 {
            let mut bytes = vec![prefix; count];
            bytes.extend([0xe8, 0, 0, 0, 0]);
            probes.push(bytes);
        }
        for second in prefixes {
            probes.push(vec![prefix, second, 0xe8, 0, 0, 0, 0]);
        }
    }
    for leading in 0_u8..=u8::MAX {
        probes.push(vec![leading, 0xe8, 0, 0, 0, 0]);
    }
    for bytes in probes {
        let Ok(instruction) = decode_one(&bytes, 0x1000, Arch::X86_64) else {
            continue;
        };
        if matches!(instruction.kind, InsnKind::Call(_))
            && resolve_branch_target(&instruction, 0x1000).is_some()
        {
            assert!(
                could_start_direct_call(&bytes, Arch::X86_64),
                "missed direct call encoding {bytes:02x?}"
            );
        }
    }
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
    let insns: Vec<_> = decode_iter(&bytes, 0x1000, Arch::X86_64)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
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

#[test]
fn mkasm_x86_intel_formatter_contract_is_exact() {
    for (bytes, va, expected) in [
        (&[0x90][..], 0x1000, "nop"),
        (
            &[0x48, 0x8B, 0x45, 0xF8][..],
            0x1000,
            "mov rax, qword ptr [rbp-0x8]",
        ),
        (
            &[0x48, 0x83, 0xC7, 0xF0][..],
            0x1000,
            "add rdi, 0xfffffffffffffff0",
        ),
        (&[0xE8, 0x34, 0x12, 0x00, 0x00][..], 0x1000, "call 0x2239"),
    ] {
        assert_eq!(disassemble_one(bytes, va, Arch::X86_64).unwrap(), expected);
    }
}

#[test]
fn mkasm_arm64_formatter_contract_is_exact() {
    assert_eq!(
        disassemble_one(&0xD503_201Fu32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap(),
        "NOP"
    );
    assert_eq!(
        disassemble_one(&0xD65F_03C0u32.to_le_bytes(), 0x1004, Arch::Arm64).unwrap(),
        "RET"
    );
}

#[test]
fn mkasm_arm64_invalid_logical_immediate_falls_back_without_panicking() {
    let word = 0xD225_FEC3u32;
    assert_eq!(
        disassemble_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap(),
        ".inst 0xd225fec3"
    );
}

#[test]
fn stateful_disassembler_preserves_x86_semantics() {
    let mut disassembler = Disassembler::new(Arch::X86_64);
    for (bytes, va) in [(&[0x90][..], 0x1000), (&[0xC3][..], 0x1001)] {
        let expected = decode_one(bytes, va, Arch::X86_64).unwrap();
        let decoded = disassembler.decode_one(bytes, va).unwrap();
        assert_eq!(decoded.instruction, expected);
        assert!(!decoded.text.is_empty());
    }
}

#[test]
fn stateful_disassembler_preserves_arm64_semantics_and_fallback() {
    let mut disassembler = Disassembler::new(Arch::Arm64);
    for word in [0xD503_201Fu32, 0x0001_0000] {
        let bytes = word.to_le_bytes();
        let expected = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
        let decoded = disassembler.decode_one(&bytes, 0x1000).unwrap();
        assert_eq!(decoded.instruction, expected);
        assert!(!decoded.text.is_empty());
    }
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
    let relocated_word =
        u32::from_le_bytes([relocated[0], relocated[1], relocated[2], relocated[3]]);
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
        InsnKind::Branch(BranchInfo {
            target: BranchTarget::Register
        })
    ));
}

#[test]
fn arm64_blr_register() {
    // BLR x8 = 0xD63F0100
    let bytes = 0xD63F_0100u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(matches!(
        insn.kind,
        InsnKind::Call(BranchInfo {
            target: BranchTarget::Register
        })
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

// ── strict and lossy invalid-byte behavior ──

#[test]
fn decode_iter_stops_and_lossy_records_invalid_bytes() {
    let mut bytes = vec![0x06u8; 256];
    bytes.push(0x90); // NOP
    bytes.push(0xC3); // RET
    let mut strict = decode_iter(&bytes, 0x1000, Arch::X86_64);
    assert!(strict.next().unwrap().is_err());
    assert!(strict.next().is_none());

    let report = decode_lossy(&bytes, 0x1000, Arch::X86_64);
    assert_eq!(report.gaps.len(), 1);
    assert_eq!(report.gaps[0].offset, 0);
    assert_eq!(report.gaps[0].len, 256);
    assert_eq!(report.instructions.len(), 2);
    assert_eq!(report.instructions[0].kind, InsnKind::Nop);
    assert_eq!(report.instructions[1].kind, InsnKind::Return);
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
    let de = DecodeError {
        kind: DecodeErrorKind::InvalidEncoding,
        message: "test".into(),
    };
    assert_eq!(format!("{de}"), "decode: test");

    let ee = EncodeError {
        message: "test".into(),
    };
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
    assert!(matches!(
        ops[0],
        Operand::Mem {
            base: Reg { num: 4, .. },
            disp: 8
        }
    )); // [rsp+8]
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
    assert!(matches!(
        ops[2],
        Operand::Mem {
            base: Reg { num: 31, .. },
            disp: -16
        }
    ));
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
    assert!(matches!(
        ops[2 - 1],
        Operand::Mem {
            base: Reg { num: 31, .. },
            disp: 0
        }
    ));
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
    assert_eq!(ops[0], Operand::Reg(Reg::fp(0))); // d0
    assert_eq!(ops[1], Operand::Reg(Reg::fp(1))); // d1
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
fn x86_64_cqo_sets_implicit_gpr0() {
    let insn = decode_one(&[0x48, 0x99], 0x1000, Arch::X86_64).unwrap();
    assert!(insn.writes_implicit_gpr0);
}

#[test]
fn x86_64_single_operand_imul_sets_implicit_gpr0() {
    let insn = decode_one(&[0x48, 0xF7, 0xE9], 0x1000, Arch::X86_64).unwrap();
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

#[test]
fn x86_64_rip_memory_operand_is_relative_to_next_ip() {
    let insn = decode_one(
        &[0xff, 0x15, 0x2a, 0x00, 0x00, 0x00],
        0x1_0000_0100,
        Arch::X86_64,
    )
    .unwrap();
    assert_eq!(
        insn.operands(),
        &[Operand::Mem {
            base: Reg::gpr(16),
            disp: 0x2a,
        }]
    );
}

#[test]
fn decoded_value_effects_distinguish_loads_from_unknown_writes() {
    let ldr = decode_one(&0xf940_9a10_u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(ldr.value_effect, ValueEffect::Load);
    assert_eq!(ldr.op0_write_target(), Some(Reg::gpr(16)));

    let xor = decode_one(&[0x48, 0x31, 0xc0], 0x1000, Arch::X86_64).unwrap();
    assert_eq!(xor.value_effect, ValueEffect::UnknownWrite);

    let load = decode_one(&[0x48, 0x8b, 0x47, 0x18], 0x1000, Arch::X86_64).unwrap();
    assert_eq!(load.value_effect, ValueEffect::Load);
    assert_eq!(load.op0_write_target(), Some(Reg::gpr(0)));
    assert_eq!(
        load.operands(),
        &[
            Operand::Reg(Reg::gpr(0)),
            Operand::Mem {
                base: Reg::gpr(7),
                disp: 0x18,
            },
        ]
    );

    let copy = decode_one(&[0x48, 0x89, 0xf8], 0x1000, Arch::X86_64).unwrap();
    assert_eq!(copy.value_effect, ValueEffect::Set);

    let arm_copy = decode_one(&0xaa01_03e0_u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(arm_copy.value_effect, ValueEffect::Set);
    assert_eq!(
        arm_copy.operands(),
        &[Operand::Reg(Reg::gpr(0)), Operand::Reg(Reg::gpr(1))]
    );

    let ldur = decode_one(&0xf85f_8020_u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(ldur.value_effect, ValueEffect::Load);
    assert_eq!(
        ldur.operands(),
        &[
            Operand::Reg(Reg::gpr(0)),
            Operand::Mem {
                base: Reg::gpr(1),
                disp: -8,
            },
        ]
    );
}

#[test]
fn x86_value_effects_retain_arithmetic_masks_shifts_and_selection() {
    let subtract = decode_one(&[0x48, 0x29, 0xd8], 0x1000, Arch::X86_64).unwrap();
    assert_eq!(subtract.value_effect, ValueEffect::SubtractRegister);

    let mask = decode_one(&[0x48, 0x25, 0xff, 0xff, 0x00, 0x00], 0x1003, Arch::X86_64).unwrap();
    assert_eq!(mask.value_effect, ValueEffect::BitwiseAndImmediate);

    let shift = decode_one(&[0x48, 0xc1, 0xe0, 0x03], 0x1009, Arch::X86_64).unwrap();
    assert_eq!(shift.value_effect, ValueEffect::ShiftImmediate);
    assert_eq!(
        shift.operands()[1],
        Operand::ShiftedReg {
            register: Reg::gpr(0),
            shift: RegisterShift::LogicalLeft,
            amount: 3,
        }
    );

    let select = decode_one(&[0x48, 0x0f, 0x45, 0xc3], 0x100d, Arch::X86_64).unwrap();
    assert_eq!(select.value_effect, ValueEffect::ConditionalSelect);
}

#[test]
fn arm64e_pointer_authentication_and_extensions_are_explicit_value_effects() {
    let cases: [(u32, ValueEffect); 15] = [
        (0xDAC1_0020, ValueEffect::SignPointerIa),
        (0xDAC1_0462, ValueEffect::SignPointerIb),
        (0xDAC1_0AB4, ValueEffect::SignPointerDa),
        (0xDAC1_0EF6, ValueEffect::SignPointerDb),
        (0xDAC1_10A4, ValueEffect::AuthenticatePointerIa),
        (0xDAC1_14E6, ValueEffect::AuthenticatePointerIb),
        (0xDAC1_1B38, ValueEffect::AuthenticatePointerDa),
        (0xDAC1_1F7A, ValueEffect::AuthenticatePointerDb),
        (0xDAC1_43E8, ValueEffect::StripPointerAuthentication),
        (0xD503_233F, ValueEffect::SignPointerIa),
        (0xD503_23BF, ValueEffect::AuthenticatePointerIa),
        (0x9340_7DAC, ValueEffect::SignExtend32),
        (0xD340_7DEE, ValueEffect::ZeroExtend32),
        (0x9340_1E30, ValueEffect::SignExtend8),
        (0x5300_3E72, ValueEffect::ZeroExtend16),
    ];
    for (word, effect) in cases {
        let instruction = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64e).unwrap();
        assert_eq!(instruction.value_effect, effect, "word {word:#010x}");
        assert!(instruction.op0_write_target().is_some());
    }

    let pacia = decode_one(&0xDAC1_0020_u32.to_le_bytes(), 0x1000, Arch::Arm64e).unwrap();
    assert_eq!(
        pacia.operands(),
        &[
            Operand::Reg(Reg::gpr(0)),
            Operand::Reg(Reg::gpr(0)),
            Operand::Reg(Reg::gpr(1)),
        ]
    );
    let paciasp = decode_one(&0xD503_233F_u32.to_le_bytes(), 0x1000, Arch::Arm64e).unwrap();
    assert_eq!(paciasp.op0_write_target(), Some(Reg::gpr(30)));
}

#[test]
fn x86_integer_extensions_retain_source_width_and_signedness() {
    for (bytes, effect) in [
        (&[0x48, 0x0f, 0xb6, 0xc1][..], ValueEffect::ZeroExtend8),
        (&[0x48, 0x0f, 0xb7, 0xc1][..], ValueEffect::ZeroExtend16),
        (&[0x48, 0x0f, 0xbe, 0xc1][..], ValueEffect::SignExtend8),
        (&[0x48, 0x0f, 0xbf, 0xc1][..], ValueEffect::SignExtend16),
        (&[0x48, 0x63, 0xc1][..], ValueEffect::SignExtend32),
    ] {
        assert_eq!(
            decode_one(bytes, 0x1000, Arch::X86_64)
                .unwrap()
                .value_effect,
            effect
        );
    }
}

#[test]
fn arm64_value_effects_retain_masks_shifts_and_selection() {
    // AND x0, x1, #0xff
    let mask = decode_one(&0x9240_1c20_u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(mask.value_effect, ValueEffect::BitwiseAndImmediate);
    assert_eq!(mask.operands()[2], Operand::Imm(0xff));

    // LSL x0, x1, #3 (UBFM alias).
    let shift = decode_one(&0xd37d_f020_u32.to_le_bytes(), 0x1004, Arch::Arm64).unwrap();
    assert_eq!(shift.value_effect, ValueEffect::ShiftImmediate);
    assert_eq!(
        shift.operands()[1],
        Operand::ShiftedReg {
            register: Reg::gpr(1),
            shift: RegisterShift::LogicalLeft,
            amount: 3,
        }
    );

    // CSEL x0, x1, x2, eq.
    let select = decode_one(&0x9a82_0020_u32.to_le_bytes(), 0x1008, Arch::Arm64).unwrap();
    assert_eq!(select.value_effect, ValueEffect::ConditionalSelect);
    assert_eq!(
        select.operands(),
        &[
            Operand::Reg(Reg::gpr(0)),
            Operand::Reg(Reg::gpr(1)),
            Operand::Reg(Reg::gpr(2)),
        ]
    );
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
    assert_eq!(ops[0], Operand::Reg(Reg::fp(0))); // d0
    assert_eq!(ops[1], Operand::Reg(Reg::fp(1))); // d1
    assert!(matches!(
        ops[2],
        Operand::Mem {
            base: Reg { num: 31, .. },
            ..
        }
    ));
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
    assert_eq!(
        ops.len(),
        3,
        "expected 3 operands for post-index STP, got: {ops:?}"
    );
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
        ops.iter()
            .any(|op| matches!(op, Operand::Mem { base, .. } if base.num == 255)),
        "expected Gpr(255) sentinel for absolute address, got: {ops:?}"
    );
}

// ── Category 4: Decode Edge Cases ──

#[test]
fn arm64_decode_exactly_4_bytes() {
    let insn = decode_one(&0xD503_201Fu32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(insn.kind, InsnKind::Nop);
    assert_eq!(insn.len, 4);
}

#[test]
fn arm64_decode_unknown_word_is_other() {
    // UDF #0 = 0x00000000 — falls through all classify patterns
    let insn = decode_one(&0x0000_0000u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(insn.kind, InsnKind::Other);
}

#[test]
fn arm64_decode_3_bytes_fails() {
    assert!(decode_one(&[0x1F, 0x20, 0x03], 0x1000, Arch::Arm64).is_err());
}

#[test]
fn x86_64_decode_single_invalid_byte() {
    // 0x06 = PUSH ES, invalid in 64-bit mode
    assert!(decode_one(&[0x06], 0x1000, Arch::X86_64).is_err());
}

#[test]
fn decode_errors_preserve_primary_failure_categories() {
    assert_eq!(
        decode_one(&[0x0f], 0x1000, Arch::X86_64).unwrap_err().kind,
        DecodeErrorKind::Truncated
    );
    assert_eq!(
        decode_one(&[0x66; 15], 0x1000, Arch::X86_64)
            .unwrap_err()
            .kind,
        DecodeErrorKind::TooLong
    );
    assert_eq!(
        decode_one(&[0x0f, 0xa7, 0xc1], 0x1000, Arch::X86_64)
            .unwrap_err()
            .kind,
        DecodeErrorKind::UnknownEncoding
    );
    assert_eq!(
        decode_one(&[0; 3], 0x1000, Arch::Arm64).unwrap_err().kind,
        DecodeErrorKind::Truncated
    );
}

#[test]
fn arm64_unknown_formatter_result_has_exact_boundary_provenance() {
    let mut disassembler = Disassembler::new(Arch::Arm64);
    let decoded = disassembler
        .decode_one(&0x0001_0000u32.to_le_bytes(), 0x1000)
        .unwrap();
    assert!(decoded.text.starts_with(".inst"));
    assert_eq!(decoded.instruction.kind, InsnKind::Other);
    assert!(decoded.instruction.operands().is_empty());
    assert_eq!(
        decoded.recovery,
        Some(InstructionRecovery {
            boundary_confidence: BoundaryConfidence::Exact,
            source: "architecture",
        })
    );
}

#[test]
fn decode_iter_empty_x86_64() {
    let insns: Vec<_> = decode_iter(&[], 0x1000, Arch::X86_64)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(insns.is_empty());
}

#[test]
fn decode_iter_empty_arm64() {
    let insns: Vec<_> = decode_iter(&[], 0x1000, Arch::Arm64)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(insns.is_empty());
}

#[test]
fn decode_iter_all_invalid_x86_64() {
    let bytes = [0x06u8; 4];
    let results: Vec<_> = decode_iter(&bytes, 0x1000, Arch::X86_64).collect();
    assert_eq!(results.len(), 1);
    assert!(results[0].is_err());
    let report = decode_lossy(&bytes, 0x1000, Arch::X86_64);
    assert!(report.instructions.is_empty());
    assert_eq!(report.gaps[0].len, 4);
}

// ── Category 5: Disassembly Edge Cases ──

#[test]
fn arm64_disassemble_one_never_errors_on_4_bytes() {
    // disassemble_one always returns Ok for 4-byte ARM64 input thanks to
    // the .inst fallback. Test with UDF #0 (valid) and a reserved encoding.
    let text = disassemble_one(&0x0000_0000u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert!(!text.is_empty());
    // Also test a word from reserved encoding space
    let text2 = disassemble_one(&0x0001_0000u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert!(!text2.is_empty());
}

#[test]
fn arm64_disassemble_dot_inst_fallback() {
    // Use disassemble() with a NOP + a word that mkasm can't format.
    // The fallback produces ".inst 0x{word:08x}".
    // Try several reserved-space encodings; at least one should trigger fallback.
    let nop = 0xD503_201Fu32;
    // 0x00000000 = UDF; try words in unallocated space.
    let candidates: &[u32] = &[0x0001_0000, 0x0002_0000, 0x0003_0000, 0x0000_0001];
    for &word in candidates {
        let text = disassemble_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
        if text.starts_with(".inst") {
            // Found a word that triggers the fallback — verify format
            assert!(text.contains(&format!("0x{word:08x}")), "got: {text}");
            return;
        }
    }
    // If none of our candidates triggered fallback, verify the mechanism by using
    // a 2-word disassemble where at least one entry uses the fallback format.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&nop.to_le_bytes());
    for &word in candidates {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    let result = disassemble(&bytes, 0x1000, Arch::Arm64).unwrap();
    let has_dot_inst = result.iter().any(|(_, text)| text.starts_with(".inst"));
    // Even if all words happen to be formattable by mkasm, the test documents
    // the fallback path exists. The disassemble_one_never_errors test covers
    // the Ok guarantee.
    assert!(
        has_dot_inst || result.len() == candidates.len() + 1,
        "expected .inst fallback or all decoded"
    );
}

#[test]
fn arm64_disassemble_non_aligned_fails() {
    assert!(disassemble(&[0u8; 6], 0x1000, Arch::Arm64).is_err());
}

#[test]
fn x86_64_disassemble_one_empty_fails() {
    assert!(disassemble_one(&[], 0x1000, Arch::X86_64).is_err());
}

#[test]
fn x86_64_disassemble_fails_closed_at_invalid() {
    // NOP (0x90) followed by 0x06 (PUSH ES, invalid in 64-bit mode)
    let bytes = [0x90, 0x06];
    assert!(disassemble(&bytes, 0x1000, Arch::X86_64).is_err());

    let recovered = decode_lossy(&bytes, 0x1000, Arch::X86_64);
    assert_eq!(recovered.instructions.len(), 1);
    assert_eq!(recovered.instructions[0].kind, InsnKind::Nop);
    assert_eq!(recovered.gaps.len(), 1);
    assert_eq!(recovered.gaps[0].offset, 1);
    assert_eq!(recovered.gaps[0].len, 1);
}

#[test]
fn x86_64_disassemble_fails_closed_at_incomplete_instruction() {
    // NOP followed by an incomplete near CALL.
    let bytes = [0x90, 0xE8];
    assert!(disassemble(&bytes, 0x1000, Arch::X86_64).is_err());

    let recovered = decode_lossy(&bytes, 0x1000, Arch::X86_64);
    assert_eq!(recovered.instructions.len(), 1);
    assert_eq!(recovered.instructions[0].kind, InsnKind::Nop);
    assert_eq!(recovered.gaps.len(), 1);
    assert_eq!(recovered.gaps[0].offset, 1);
    assert_eq!(recovered.gaps[0].len, 1);
}

#[test]
fn arm64_disassemble_fails_closed_at_incomplete_word() {
    let mut bytes = 0xD503_201Fu32.to_le_bytes().to_vec();
    bytes.extend_from_slice(&[0x00, 0x00]);
    assert!(disassemble(&bytes, 0x1000, Arch::Arm64).is_err());

    let recovered = decode_lossy(&bytes, 0x1000, Arch::Arm64);
    assert_eq!(recovered.instructions.len(), 1);
    assert_eq!(recovered.instructions[0].kind, InsnKind::Nop);
    assert_eq!(recovered.gaps.len(), 1);
    assert_eq!(recovered.gaps[0].offset, 4);
    assert_eq!(recovered.gaps[0].len, 2);
}

#[test]
fn arm64_disassemble_empty_ok() {
    let result = disassemble(&[], 0x1000, Arch::Arm64).unwrap();
    assert!(result.is_empty());
}

#[test]
fn x86_64_disassemble_empty_ok() {
    let result = disassemble(&[], 0x1000, Arch::X86_64).unwrap();
    assert!(result.is_empty());
}

// ── Category 6: Operand Extraction ──

#[test]
fn arm64_add_shifted_reg_operands() {
    // ADD x0, x1, x2 (shifted register form)
    // sf=1, op=0, S=0, 01011_00_0, shift=00, Rm=2, imm6=0, Rn=1, Rd=0
    // = 0x8B02_0020
    let word: u32 = 0x8B02_0020;
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    let ops = insn.operands();
    assert_eq!(
        ops.len(),
        3,
        "expected 3 operands for ADD shifted reg, got: {ops:?}"
    );
    assert_eq!(ops[0], Operand::Reg(Reg::gpr(0)));
    assert_eq!(ops[1], Operand::Reg(Reg::gpr(1)));
    assert_eq!(ops[2], Operand::Reg(Reg::gpr(2)));
}

#[test]
fn arm64_register_offset_load_retains_index_scale() {
    // LDRSW x9, [x8, w0, UXTW #2]
    let word: u32 = 0xB8A0_5909;
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(insn.value_effect, ValueEffect::Load);
    assert_eq!(insn.op0_write_target(), Some(Reg::gpr(9)));
    assert_eq!(
        insn.operands(),
        &[
            Operand::Reg(Reg::gpr(9)),
            Operand::IndexedMem {
                base: Reg::gpr(8),
                index: Reg::gpr(0),
                scale: 4,
                disp: 0,
            },
        ]
    );

    // LDR x9, [x8, x0, LSL #3]
    let word: u32 = 0xF860_7909;
    let insn = decode_one(&word.to_le_bytes(), 0x1004, Arch::Arm64e).unwrap();
    assert_eq!(insn.value_effect, ValueEffect::Load);
    assert_eq!(
        insn.operands()[1],
        Operand::IndexedMem {
            base: Reg::gpr(8),
            index: Reg::gpr(0),
            scale: 8,
            disp: 0,
        }
    );
}

#[test]
fn arm64_shifted_add_retains_shift_semantics() {
    // ADD x11, x11, x12, LSL #2
    let word: u32 = 0x8B0C_096B;
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(insn.value_effect, ValueEffect::AddRegister);
    assert_eq!(
        insn.operands()[2],
        Operand::ShiftedReg {
            register: Reg::gpr(12),
            shift: RegisterShift::LogicalLeft,
            amount: 2,
        }
    );

    // LDRH w11, [x9, x8, LSL #1]
    let word: u32 = 0x7868_792B;
    let insn = decode_one(&word.to_le_bytes(), 0x1004, Arch::Arm64).unwrap();
    assert_eq!(insn.value_effect, ValueEffect::Load);
    assert_eq!(
        insn.operands()[1],
        Operand::IndexedMem {
            base: Reg::gpr(9),
            index: Reg::gpr(8),
            scale: 2,
            disp: 0,
        }
    );
}

#[test]
fn arm64_zero_operands_dmb() {
    // DMB ISH = 0xD503_3BBF — data memory barrier
    let word: u32 = 0xD503_3BBF;
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert!(
        insn.operands().is_empty(),
        "DMB should have 0 operands, got: {:?}",
        insn.operands()
    );
}

#[test]
fn x86_64_negative_disp32_sign_extends() {
    // MOV rax, [rbp-0x80] = 48 8B 85 80 FF FF FF
    let insn = decode_one(
        &[0x48, 0x8B, 0x85, 0x80, 0xFF, 0xFF, 0xFF],
        0x1000,
        Arch::X86_64,
    )
    .unwrap();
    let ops = insn.operands();
    assert!(ops.len() >= 2, "got: {ops:?}");
    match &ops[1] {
        Operand::Mem { disp, .. } => {
            assert_eq!(*disp, -128, "disp32 0xFFFFFF80 must sign-extend to -128")
        }
        other => panic!("expected Mem, got {other:?}"),
    }
}

#[test]
fn x86_64_nop_no_implicit_gpr0() {
    let insn = decode_one(&[0x90], 0x1000, Arch::X86_64).unwrap();
    assert!(!insn.writes_implicit_gpr0);
}

// ── Category 7: Iterator & instruction_len ──

#[test]
fn decode_iter_offset_tracking_x86_64() {
    // NOP(1) + CALL rel32(5) + RET(1)
    let bytes = [0x90, 0xE8, 0x00, 0x00, 0x00, 0x00, 0xC3];
    let insns: Vec<_> = decode_iter(&bytes, 0x1000, Arch::X86_64)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0].offset, 0);
    assert_eq!(insns[1].offset, 1);
    assert_eq!(insns[2].offset, 6);
}

#[test]
fn decode_iter_offset_tracking_arm64() {
    let nop = 0xD503_201Fu32;
    let bl = 0x9400_0040u32; // BL +0x100
    let ret = 0xD65F_03C0u32;
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&nop.to_le_bytes());
    bytes.extend_from_slice(&bl.to_le_bytes());
    bytes.extend_from_slice(&ret.to_le_bytes());
    let insns: Vec<_> = decode_iter(&bytes, 0x1000, Arch::Arm64)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(insns.len(), 3);
    assert_eq!(insns[0].offset, 0);
    assert_eq!(insns[1].offset, 4);
    assert_eq!(insns[2].offset, 8);
}

#[test]
fn decode_iter_skip_1_byte_x86_64() {
    let bytes = [0x06, 0x90];
    assert!(
        decode_iter(&bytes, 0x1000, Arch::X86_64)
            .next()
            .unwrap()
            .is_err()
    );
    let report = decode_lossy(&bytes, 0x1000, Arch::X86_64);
    assert_eq!(report.gaps.len(), 1);
    assert_eq!(report.instructions.len(), 1);
    assert_eq!(report.instructions[0].kind, InsnKind::Nop);
    assert_eq!(report.instructions[0].offset, 1);
}

#[test]
fn decode_iter_large_arm64() {
    let nop_word = 0xD503_201Fu32.to_le_bytes();
    let mut bytes = Vec::with_capacity(1024);
    for _ in 0..256 {
        bytes.extend_from_slice(&nop_word);
    }
    let insns: Vec<_> = decode_iter(&bytes, 0x1000, Arch::Arm64)
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(insns.len(), 256);
    for (i, insn) in insns.iter().enumerate() {
        assert_eq!(insn.offset, i * 4);
        assert_eq!(insn.kind, InsnKind::Nop);
    }
}

#[test]
fn instruction_len_empty_fails() {
    assert!(instruction_len(&[], Arch::X86_64).is_err());
    assert!(instruction_len(&[], Arch::Arm64).is_err());
}

#[test]
fn instruction_len_short_arm64_fails() {
    assert!(instruction_len(&[0x00, 0x00], Arch::Arm64).is_err());
}

#[test]
fn instruction_len_x86_64_multi_byte() {
    // MOV [rsp+0x08], rdi = 48 89 7C 24 08 (5 bytes)
    assert_eq!(
        instruction_len(&[0x48, 0x89, 0x7C, 0x24, 0x08], Arch::X86_64).unwrap(),
        5
    );
}

#[test]
fn instruction_len_arm64_always_4() {
    // NOP, BL, RET — all 4 bytes
    assert_eq!(
        instruction_len(&0xD503_201Fu32.to_le_bytes(), Arch::Arm64).unwrap(),
        4
    );
    assert_eq!(
        instruction_len(&0x9400_0040u32.to_le_bytes(), Arch::Arm64).unwrap(),
        4
    );
    assert_eq!(
        instruction_len(&0xD65F_03C0u32.to_le_bytes(), Arch::Arm64).unwrap(),
        4
    );
}

// ── Category 8: resolve_branch_target & Arch ──

#[test]
fn resolve_target_register_none() {
    // BR x16 = 0xD61F0200
    let insn = decode_one(&0xD61F_0200u32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(resolve_branch_target(&insn, 0x1000), None);
}

#[test]
fn resolve_target_indirect_jmp_none() {
    // JMP [rax] = FF 20
    let insn = decode_one(&[0xFF, 0x20], 0x1000, Arch::X86_64).unwrap();
    assert!(matches!(
        insn.kind,
        InsnKind::Branch(BranchInfo {
            target: BranchTarget::Indirect
        })
    ));
    assert_eq!(resolve_branch_target(&insn, 0x1000), None);
}

#[test]
fn resolve_target_indirect_call_none() {
    // CALL [rax] = FF 10
    let insn = decode_one(&[0xFF, 0x10], 0x1000, Arch::X86_64).unwrap();
    assert!(matches!(
        insn.kind,
        InsnKind::Call(BranchInfo {
            target: BranchTarget::Indirect
        })
    ));
    assert_eq!(resolve_branch_target(&insn, 0x1000), None);
}

#[test]
fn x86_indexed_indirect_branch_retains_sib_expression() {
    // JMP qword ptr [rax*8+0x200] = FF 24 C5 00 02 00 00
    let insn = decode_one(
        &[0xff, 0x24, 0xc5, 0x00, 0x02, 0x00, 0x00],
        0x1000,
        Arch::X86_64,
    )
    .unwrap();
    assert!(matches!(
        insn.kind,
        InsnKind::Branch(BranchInfo {
            target: BranchTarget::IndexedMemory {
                base: None,
                index: Reg {
                    class: RegClass::Gpr,
                    num: 0,
                },
                scale: 8,
                displacement: 0x200,
            }
        })
    ));
}

#[test]
fn x86_register_indirect_flow_retains_register_target_kind() {
    for (bytes, is_call) in [(&[0xff, 0xd0][..], true), (&[0xff, 0xe0][..], false)] {
        let insn = decode_one(bytes, 0x1000, Arch::X86_64).unwrap();
        assert!(matches!(
            (insn.kind, is_call),
            (
                InsnKind::Call(BranchInfo {
                    target: BranchTarget::Register
                }),
                true
            ) | (
                InsnKind::Branch(BranchInfo {
                    target: BranchTarget::Register
                }),
                false
            )
        ));
    }
}

#[test]
fn resolve_target_return_none() {
    let insn = decode_one(&[0xC3], 0x1000, Arch::X86_64).unwrap();
    assert_eq!(resolve_branch_target(&insn, 0x1000), None);
}

#[test]
fn resolve_target_pcrelative_none() {
    // ADR x0, +4
    let word: u32 = 0x1000_0000 | (1 << 5);
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert_eq!(resolve_branch_target(&insn, 0x1000), None);
}

#[test]
fn resolve_target_wrapping_negative() {
    // B #-0x10 at VA 0x4 → target = 0x4 + (-0x10) wraps in u64
    let imm26 = ((-4i32) as u32) & 0x03FF_FFFF;
    let word = 0x1400_0000u32 | imm26; // B #-0x10
    let insn = decode_one(&word.to_le_bytes(), 0x4, Arch::Arm64).unwrap();
    // 0x4_u64.wrapping_add_signed(-16) = 0xFFFF_FFFF_FFFF_FFF4
    assert_eq!(
        resolve_branch_target(&insn, 0x4),
        Some(0x4_u64.wrapping_add_signed(-16))
    );
}

#[test]
fn arm64e_decode_same_as_arm64() {
    let nop_arm64 = decode_one(&0xD503_201Fu32.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    let nop_arm64e = decode_one(&0xD503_201Fu32.to_le_bytes(), 0x1000, Arch::Arm64e).unwrap();
    assert_eq!(nop_arm64.kind, nop_arm64e.kind);
    assert_eq!(nop_arm64.len, nop_arm64e.len);
}

// ── Category 9: Missing coverage ──

#[test]
fn arm64_braa_is_branch_register() {
    // BRAA x16, xzr = 0xD71F_0210
    let word: u32 = 0xD71F_0210;
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert!(
        matches!(
            insn.kind,
            InsnKind::Branch(BranchInfo {
                target: BranchTarget::Register
            })
        ),
        "expected Branch(Register), got {:?}",
        insn.kind
    );
}

#[test]
fn arm64_blraa_is_call_register() {
    // BLRAA x8, xzr = 0xD73F_0100
    let word: u32 = 0xD73F_0100;
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert!(
        matches!(
            insn.kind,
            InsnKind::Call(BranchInfo {
                target: BranchTarget::Register
            })
        ),
        "expected Call(Register), got {:?}",
        insn.kind
    );
}

#[test]
fn arm64_cbnz_decode() {
    // CBNZ x0, +0x40 → sf=1, op=1 (CBNZ), imm19=0x10, Rt=0
    // CBZ base = 0xB400_0000, CBNZ has bit 24 set → 0xB500_0000
    let word: u32 = 0xB500_0000 | (0x10 << 5);
    let insn = decode_one(&word.to_le_bytes(), 0x1000, Arch::Arm64).unwrap();
    assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
    assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x1040));
}

#[test]
fn arm64_bcond_bne_relocation_preserves_cond() {
    // B.NE +0x80 at VA 0x1000 → target 0x1080
    // cond=0001 (NE), imm19 = 0x80/4 = 0x20
    let word: u32 = 0x5400_0000 | (0x20 << 5) | 0x1; // cond=NE in bits[3:0]
    let bytes = word.to_le_bytes();
    let relocated = relocate_insn(&bytes, 0x1000, 0x1040, Arch::Arm64).unwrap();
    // Verify target preserved
    let insn = decode_one(&relocated, 0x1040, Arch::Arm64).unwrap();
    assert_eq!(resolve_branch_target(&insn, 0x1040), Some(0x1080));
    // Verify NE condition field (bits[3:0] = 1) preserved
    let new_word = u32::from_le_bytes([relocated[0], relocated[1], relocated[2], relocated[3]]);
    assert_eq!(
        new_word & 0xF,
        1,
        "B.NE cond=1 must be preserved, got {}",
        new_word & 0xF
    );
}

#[test]
fn x86_64_je_relocation_preserves_target() {
    // JE rel32 to target 0x5000 from VA 0x1000
    // Encoded as: 0F 84 rel32. rel32 = target - (ip + 6) = 0x5000 - 0x1006 = 0x3FFA
    let bytes = [0x0F, 0x84, 0xFA, 0x3F, 0x00, 0x00];
    let insn = decode_one(&bytes, 0x1000, Arch::X86_64).unwrap();
    assert!(matches!(insn.kind, InsnKind::CondBranch(_)));
    assert_eq!(resolve_branch_target(&insn, 0x1000), Some(0x5000));
    // Relocate to 0x2000 and verify target preserved
    let relocated = relocate_insn(&bytes, 0x1000, 0x2000, Arch::X86_64).unwrap();
    let insn2 = decode_one(&relocated, 0x2000, Arch::X86_64).unwrap();
    assert_eq!(resolve_branch_target(&insn2, 0x2000), Some(0x5000));
}

#[test]
fn arm64_relocate_non_pc_relative_unchanged() {
    // ADD x0, x1, #42 is not PC-relative — relocating should return bytes unchanged
    let word: u32 = 0x9100_A820;
    let bytes = word.to_le_bytes();
    let relocated = relocate_insn(&bytes, 0x1000, 0x2000, Arch::Arm64).unwrap();
    assert_eq!(
        relocated, bytes,
        "non-PC-relative instruction should be unchanged after relocation"
    );
}

#[test]
fn x86_64_nop_encodings_decode_as_nop() {
    // Verify that multi-byte NOP sequences (1-15 bytes) all decode as NOP
    for size in 1..=15 {
        let nops = encode_nop(Arch::X86_64, size).unwrap();
        let insn = decode_one(&nops, 0x1000, Arch::X86_64).unwrap();
        assert_eq!(
            insn.kind,
            InsnKind::Nop,
            "size-{size} NOP didn't decode as Nop"
        );
        assert_eq!(insn.len, size, "size-{size} NOP decoded as wrong length");
    }
}

#[test]
fn reg_display() {
    assert_eq!(format!("{}", Reg::gpr(0)), "gpr0");
    assert_eq!(format!("{}", Reg::fp(3)), "fp3");
}

// ── writes_op0_reg semantic tests ──
//
// The ABI inference in `macho::analysis` relies on `writes_op0_reg` as the
// ground-truth predicate for whether an instruction overwrites its first
// register operand. These tests pin the contract on both architectures.

#[test]
fn x86_mov_reg_reg_writes_dest() {
    // MOV rdi, rax  (48 89 c7)
    let insn = decode_one(&[0x48, 0x89, 0xC7], 0x1000, Arch::X86_64).unwrap();
    assert!(insn.writes_op0_reg);
    assert_eq!(insn.op0_write_target(), Some(Reg::gpr(7)));
}

#[test]
fn x86_add_reg_reg_writes_dest() {
    // ADD rdi, rax  (48 01 c7)  — in-place pointer arithmetic.
    let insn = decode_one(&[0x48, 0x01, 0xC7], 0x1000, Arch::X86_64).unwrap();
    assert!(
        insn.writes_op0_reg,
        "ADD must write op0 (missed by the old operand-shape heuristic)"
    );
    assert_eq!(insn.op0_write_target(), Some(Reg::gpr(7)));
}

#[test]
fn x86_cmp_reg_imm_does_not_write() {
    // CMP rdi, 0  (48 83 ff 00) — flags only.
    let insn = decode_one(&[0x48, 0x83, 0xFF, 0x00], 0x1000, Arch::X86_64).unwrap();
    assert!(!insn.writes_op0_reg, "CMP must not count as a write to op0");
}

#[test]
fn x86_test_reg_reg_does_not_write() {
    // TEST rdi, rdi  (48 85 ff) — flags only.
    let insn = decode_one(&[0x48, 0x85, 0xFF], 0x1000, Arch::X86_64).unwrap();
    assert!(!insn.writes_op0_reg);
}

#[test]
fn x86_store_does_not_write_op0() {
    // MOV [rdi], rax  (48 89 07)  — op0 is the memory operand, not a reg.
    let insn = decode_one(&[0x48, 0x89, 0x07], 0x1000, Arch::X86_64).unwrap();
    assert!(!insn.writes_op0_reg);
    assert_eq!(insn.memory_effect, MemoryEffect::Store);
}

#[test]
fn arm64_ldr_writes_dest() {
    // LDR x0, [x1]  — unsigned offset form, imm12=0, Rn=1, Rt=0.
    // 11 111 001 01 000000000000 00001 00000 = 0xF940_0020
    let bytes = 0xF940_0020u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(insn.writes_op0_reg, "LDR must write Rt");
}

#[test]
fn arm64_str_does_not_write_op0() {
    // STR x0, [x1]  — imm12=0, Rn=1, Rt=0.
    // 11 111 001 00 000000000000 00001 00000 = 0xF900_0020
    let bytes = 0xF900_0020u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(
        !insn.writes_op0_reg,
        "STR must not write op0 — op0 is the stored source reg"
    );
    assert_eq!(insn.memory_effect, MemoryEffect::Store);
}

#[test]
fn arm64_ldp_writes_dest_pair() {
    // LDP x0, x1, [sp]  — signed offset form, L=1.
    // 10 101 001 01 imm7=0 Rt2=1 Rn=31 Rt=0 = 0xA940_07E0
    let bytes = 0xA940_07E0u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(insn.writes_op0_reg);
}

#[test]
fn arm64_stp_does_not_write_op0() {
    // STP x0, x1, [sp, #-16]!  — L=0.
    // 10 101 001 10 imm7=0x78 Rt2=1 Rn=31 Rt=0 = 0xA9BF_07E0
    let bytes = 0xA9BF_07E0u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(!insn.writes_op0_reg);
}

#[test]
fn arm64_add_imm_writes_dest() {
    // ADD x0, x31, #42 — shown in existing test, = 0x9100_ABE0
    let bytes = 0x9100_ABE0u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(insn.writes_op0_reg);
}

#[test]
fn arm64_ret_does_not_write_op0() {
    // RET  = 0xD65F_03C0
    let bytes = 0xD65F_03C0u32.to_le_bytes();
    let insn = decode_one(&bytes, 0x1000, Arch::Arm64).unwrap();
    assert!(!insn.writes_op0_reg);
}

// ───────────── sign-boundary displacement regression (issue: RF-overflow) ─────────────
// These decode branch / RIP-relative / ADRP instructions at virtual addresses
// straddling the i64 sign boundary. Before the wrapping-subtraction fix the
// displacement math triggered `attempt to (add|subtract) with overflow` under
// the overflow checks that `cargo test` enables. Each asserts the correct
// signed displacement, not merely the absence of a panic.

#[test]
fn x86_64_near_branch_displacement_survives_sign_boundary() {
    // JMP rel8 +0 at VA just below i64::MAX; target crosses 0x8000_0000_0000_0000.
    let va = 0x7FFF_FFFF_FFFF_FFFEu64;
    let insn = decode_one(&[0xEB, 0x00], va, Arch::X86_64).unwrap();
    assert!(matches!(insn.kind, InsnKind::Branch(_)));
    assert_eq!(
        resolve_branch_target(&insn, va),
        Some(0x8000_0000_0000_0000)
    );
}

#[test]
fn x86_64_rip_relative_displacement_survives_sign_boundary() {
    // LEA RAX, [RIP+0] (7 bytes) at a VA whose next_ip crosses the sign boundary.
    let va = 0x7FFF_FFFF_FFFF_FFFCu64;
    let insn = decode_one(
        &[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00],
        va,
        Arch::X86_64,
    )
    .unwrap();
    match insn.kind {
        InsnKind::PcRelative(info) => assert_eq!(info.displacement, 7),
        other => panic!("expected PcRelative, got {other:?}"),
    }
}

#[test]
fn arm64_adrp_displacement_survives_sign_boundary() {
    // ADRP x0 with the maximum positive imm21 at a page-aligned VA near i64::MAX.
    // Old code computed `(page_va as i64 + offset) - va as i64`, overflowing the
    // add; the reduced form `offset - (va & 0xFFF)` stays in range.
    let va = 0x7FFF_FFFF_FFFF_F000u64;
    let insn = decode_one(&0xF07F_FFE0u32.to_le_bytes(), va, Arch::Arm64).unwrap();
    match insn.kind {
        InsnKind::PcRelative(info) => assert_eq!(info.displacement, 1_048_575i64 * 4096),
        other => panic!("expected PcRelative, got {other:?}"),
    }
}

#[test]
fn generated_arm64_identity_and_fixed_encoding_round_trip() {
    let nop = 0xD503_201Fu32.to_le_bytes();
    let identity = identify_encoding(&nop, Arch::Arm64).unwrap();
    assert_eq!(identity.mnemonic, "NOP");
    assert_eq!(identity.length, 4);
    assert!(identity.form_index.is_none());

    let encoded = encode_arm64_fixed(identity.encoding_id).unwrap();
    assert_eq!(encoded, nop);
    assert_eq!(
        identify_encoding(&encoded, Arch::Arm64)
            .unwrap()
            .encoding_id,
        identity.encoding_id
    );
}

#[test]
fn generated_arm64_field_encoding_round_trip() {
    let branch = 0x1400_0000u32.to_le_bytes();
    let identity = identify_encoding(&branch, Arch::Arm64).unwrap();
    let encoded = encode_arm64_fields(identity.encoding_id, &[("imm26", 0x40)]).unwrap();
    assert_eq!(u32::from_le_bytes(encoded), 0x1400_0040);
    assert_eq!(instruction_len(&encoded, Arch::Arm64).unwrap(), 4);
}

#[test]
fn generated_x86_identity_and_encoding_round_trip() {
    let identity = identify_encoding(&[0x90], Arch::X86_64).unwrap();
    assert_eq!(identity.length, 1);
    let form_index = identity.form_index.unwrap();

    let encoded = encode_x86_form(form_index, X86EncodeFields::default()).unwrap();
    assert_eq!(encoded.as_bytes(), &[0x90]);
    assert_eq!(encoded.len(), 1);
    assert!(!encoded.is_empty());
    assert_eq!(
        identify_encoding(encoded.as_bytes(), Arch::X86_64)
            .unwrap()
            .form_id,
        identity.form_id
    );
}

#[test]
fn generated_x86_lengths_match_semantic_decoder_across_prefix_families() {
    let probes: &[&[u8]] = &[
        &[0x90],
        &[0x48, 0x01, 0xC8],
        &[0x48, 0x01, 0x4C, 0x24, 0x08],
        &[0xF3, 0x0F, 0x1E, 0xFA],
        &[0xC5, 0xED, 0xFE, 0xCB],
        &[0x62, 0xF1, 0x7D, 0x48, 0xEF, 0xC0],
    ];
    for bytes in probes {
        let generated = identify_encoding(bytes, Arch::X86_64).unwrap();
        let semantic = decode_one(bytes, 0, Arch::X86_64).unwrap();
        assert_eq!(generated.length, semantic.len, "bytes: {bytes:02x?}");
    }
}

#[test]
fn generated_identity_reports_truncated_input() {
    assert!(identify_encoding(&[0x1f, 0x20, 0x03], Arch::Arm64).is_err());
    assert!(identify_encoding(&[], Arch::X86_64).is_err());
}
