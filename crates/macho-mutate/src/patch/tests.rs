#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_patcher() -> MachoPatcher {
        let data = vec![0u8; 0x2000];

        let mut symbols = PatchSymbolTable::new();
        symbols.insert(
            "_main".to_string(),
            PatchSymbolEntry {
                address: 0x100100,
                size: 0,
                section: Some(0),
                is_external: true,
            },
        );
        symbols.insert(
            "_helper".to_string(),
            PatchSymbolEntry {
                address: 0x101010,
                size: 0,
                section: Some(1),
                is_external: false,
            },
        );

        let segments = vec![
            PatchSegmentInfo {
                name: "__TEXT".to_string(),
                vmaddr: 0x100000,
                vmsize: 0x1000,
                fileoff: 0,
                filesize: 0x1000,
                sections: vec![PatchSectionInfo {
                    name: "__text".to_string(),
                    segment_name: "__TEXT".to_string(),
                    addr: 0x100000,
                    size: 0x1000,
                    offset: 0,
                    section_type: None,
                }],
            },
            PatchSegmentInfo {
                name: "__DATA".to_string(),
                vmaddr: 0x101000,
                vmsize: 0x1000,
                fileoff: 0x1000,
                filesize: 0x1000,
                sections: vec![PatchSectionInfo {
                    name: "__data".to_string(),
                    segment_name: "__DATA".to_string(),
                    addr: 0x101000,
                    size: 0x1000,
                    offset: 0x1000,
                    section_type: None,
                }],
            },
        ];

        MachoPatcher::new(data, symbols, segments)
    }

    #[test]
    fn va_to_offset_text_segment() {
        let p = make_test_patcher();
        // VA 0x100100 is in __TEXT: fileoff=0 + (0x100100 - 0x100000) = 0x100
        assert_eq!(p.va_to_offset(0x100100), Some(0x100));
    }

    #[test]
    fn va_to_offset_data_segment() {
        let p = make_test_patcher();
        // VA 0x101010 is in __DATA: fileoff=0x1000 + (0x101010 - 0x101000) = 0x1010
        assert_eq!(p.va_to_offset(0x101010), Some(0x1010));
    }

    #[test]
    fn va_to_offset_out_of_range() {
        let p = make_test_patcher();
        assert_eq!(p.va_to_offset(0x200000), None);
    }

    #[test]
    fn va_to_offset_at_segment_boundary() {
        let p = make_test_patcher();
        // Start of __TEXT
        assert_eq!(p.va_to_offset(0x100000), Some(0));
        // Start of __DATA
        assert_eq!(p.va_to_offset(0x101000), Some(0x1000));
    }

    #[test]
    fn va_to_offset_end_exclusive() {
        let p = make_test_patcher();
        // One past end of __TEXT vmrange => falls into __DATA? No: 0x101000
        // is the start of __DATA vmaddr, so it should map there.
        assert_eq!(p.va_to_offset(0x101000), Some(0x1000));
        // Beyond __DATA
        assert_eq!(p.va_to_offset(0x102000), None);
    }

    #[test]
    fn rva_to_offset() {
        let p = make_test_patcher();
        // Image base is __TEXT vmaddr = 0x100000.
        // RVA 0x100 => VA 0x100100 => file offset 0x100.
        assert_eq!(p.rva_to_offset(0x100), Some(0x100));
        // RVA 0x1010 => VA 0x101010 => file offset 0x1010.
        assert_eq!(p.rva_to_offset(0x1010), Some(0x1010));
    }

    #[test]
    fn image_base() {
        let p = make_test_patcher();
        assert_eq!(p.image_base(), 0x100000);
    }

    #[test]
    fn symbol_offset_lookup() {
        let p = make_test_patcher();
        assert_eq!(p.symbol_offset("_main"), Some(0x100));
        assert_eq!(p.symbol_offset("_helper"), Some(0x1010));
        assert_eq!(p.symbol_offset("_missing"), None);
    }

    #[test]
    fn read_write_bytes() {
        let mut p = make_test_patcher();

        // Write some bytes at offset 0x100.
        let patch = [0xDE, 0xAD, 0xBE, 0xEF];
        let original = p.write_bytes(0x100, &patch).unwrap();
        assert_eq!(original, [0x00, 0x00, 0x00, 0x00]);

        // Read them back.
        let readback = p.read_bytes(0x100, 4).unwrap();
        assert_eq!(readback, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn write_bytes_returns_original() {
        let mut p = make_test_patcher();

        // First write
        let patch1 = [0x01, 0x02, 0x03];
        let orig1 = p.write_bytes(0x10, &patch1).unwrap();
        assert_eq!(orig1, [0x00, 0x00, 0x00]);

        // Second write at same location
        let patch2 = [0xAA, 0xBB, 0xCC];
        let orig2 = p.write_bytes(0x10, &patch2).unwrap();
        assert_eq!(orig2, [0x01, 0x02, 0x03]);
    }

    #[test]
    fn write_bytes_out_of_bounds() {
        let mut p = make_test_patcher();
        let big = vec![0xFF; 0x3000]; // larger than 0x2000 buffer
        assert!(p.write_bytes(0, &big).is_err());
    }

    #[test]
    fn find_bytes_exact() {
        let mut p = make_test_patcher();
        // Plant a pattern.
        p.data[0x200] = 0xCA;
        p.data[0x201] = 0xFE;
        p.data[0x202] = 0xBA;
        p.data[0x203] = 0xBE;

        let pattern = [0xCA, 0xFE, 0xBA, 0xBE];
        let mask = [0xFF, 0xFF, 0xFF, 0xFF];
        let results = p.find_bytes(&pattern, &mask, 0..0x1000);
        assert_eq!(results, vec![0x200]);
    }

    #[test]
    fn find_bytes_with_wildcard() {
        let mut p = make_test_patcher();
        // Plant patterns.
        p.data[0x100] = 0xCA;
        p.data[0x101] = 0x11;
        p.data[0x102] = 0xBA;

        p.data[0x300] = 0xCA;
        p.data[0x301] = 0x99;
        p.data[0x302] = 0xBA;

        let pattern = [0xCA, 0x00, 0xBA]; // middle byte is wildcard
        let mask = [0xFF, 0x00, 0xFF];
        let results = p.find_bytes(&pattern, &mask, 0..0x1000);
        assert!(results.contains(&0x100));
        assert!(results.contains(&0x300));
    }

    #[test]
    fn find_bytes_no_match() {
        let p = make_test_patcher();
        let pattern = [0xDE, 0xAD];
        let mask = [0xFF, 0xFF];
        let results = p.find_bytes(&pattern, &mask, 0..0x2000);
        assert!(results.is_empty());
    }

    #[test]
    fn find_exact_helper() {
        let mut p = make_test_patcher();
        p.data[0x50] = 0xAB;
        p.data[0x51] = 0xCD;
        let results = p.find_exact(&[0xAB, 0xCD], 0..0x1000);
        assert_eq!(results, vec![0x50]);
    }

    #[test]
    fn find_cstring_basic() {
        let mut p = make_test_patcher();
        let s = b"hello";
        let offset = 0x500;
        p.data[offset..offset + s.len()].copy_from_slice(s);
        p.data[offset + s.len()] = 0; // null terminator
        // Add some padding nulls
        p.data[offset + s.len() + 1] = 0;
        p.data[offset + s.len() + 2] = 0;
        // Place a non-null byte to bound the allocation scan.
        p.data[offset + s.len() + 3] = 0x42;

        let results = p.find_cstring("hello");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, offset);
        // allocated size = "hello" (5) + null (1) + 2 padding nulls (2) = 8
        assert_eq!(results[0].1, 8);
    }

    #[test]
    fn find_cstring_no_match() {
        let p = make_test_patcher();
        let results = p.find_cstring("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn encode_hook_jump_x86_64_relative() {
        let jump = MachoPatcher::encode_hook_jump(PatchArch::X86_64, 0x1000, 0x1100).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::X86_64Relative);
        assert_eq!(jump.bytes, vec![0xE9, 0xFB, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_hook_jump_x86_64_absolute_fallback() {
        let jump =
            MachoPatcher::encode_hook_jump(PatchArch::X86_64, 0x1000, 0x1_0000_0000).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::X86_64Absolute);
        assert_eq!(
            jump.bytes,
            vec![
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn encode_hook_jump_arm64_direct_branch() {
        let jump = MachoPatcher::encode_hook_jump(PatchArch::Arm64, 0x1000, 0x1040).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::Arm64BranchImmediate);
        assert_eq!(jump.bytes, vec![0x10, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn encode_hook_jump_arm64e_absolute_literal() {
        let jump =
            MachoPatcher::encode_hook_jump(PatchArch::Arm64e, 0x1000, 0x9000_0000_0000).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::Arm64AbsoluteLiteral);
        assert_eq!(
            jump.bytes,
            vec![
                0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_trampoline_x86_64_appends_jump_back() {
        let trampoline = MachoPatcher::build_trampoline(
            PatchArch::X86_64,
            0x2000,
            &[0x55, 0x48, 0x89, 0xE5],
            0x3000,
        )
        .unwrap();

        assert_eq!(
            trampoline.jump_back.encoding,
            HookJumpEncoding::X86_64Relative
        );
        assert_eq!(
            trampoline.bytes,
            vec![0x55, 0x48, 0x89, 0xE5, 0xE9, 0xF7, 0x0F, 0x00, 0x00]
        );
    }

    #[test]
    fn build_trampoline_arm64_appends_jump_back() {
        let relocated = [
            0xFD, 0x7B, 0xBF, 0xA9, // stp x29, x30, [sp, #-16]!
            0xFD, 0x03, 0x00, 0x91, // mov x29, sp
        ];
        let trampoline =
            MachoPatcher::build_trampoline(PatchArch::Arm64, 0x2000, &relocated, 0x2048).unwrap();

        assert_eq!(
            trampoline.jump_back.encoding,
            HookJumpEncoding::Arm64BranchImmediate
        );
        assert_eq!(
            trampoline.bytes,
            vec![
                0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0x10, 0x00, 0x00, 0x14,
            ]
        );
    }

    #[test]
    fn build_trampoline_x86_64_allows_empty_relocated_bytes() {
        let trampoline =
            MachoPatcher::build_trampoline(PatchArch::X86_64, 0x2000, &[], 0x3000).unwrap();

        assert_eq!(trampoline.relocated_bytes, Vec::<u8>::new());
        assert_eq!(
            trampoline.jump_back.encoding,
            HookJumpEncoding::X86_64Relative
        );
        assert_eq!(trampoline.bytes, vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]);
    }

    #[test]
    fn validate_trampoline_instructions_x86_64_rejects_rip_relative_lea() {
        let err = MachoPatcher::validate_trampoline_instructions(
            PatchArch::X86_64,
            &[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00], // lea rax, [rip]
        )
        .unwrap_err();

        assert_eq!(err.kind, crate::MutationErrorKind::InvalidInput);
        assert!(err.message().contains("RIP-relative"));
    }

    #[test]
    fn instruction_failures_retain_typed_sources_and_location() {
        let decode = MachoPatcher::validate_trampoline_instructions(PatchArch::X86_64, &[0x0f])
            .expect_err("truncated instruction must fail");
        assert_eq!(decode.kind, crate::MutationErrorKind::Instruction);
        assert_eq!(decode.code(), "mutation.instruction.failed");
        assert_eq!(decode.location.expect("decode span").offset, 0);
        assert!(matches!(
            decode.source,
            Some(crate::error::MutationErrorSource::Decode(_))
        ));

        let encode = nop_bytes_for_arch(PatchArch::Arm64, 2)
            .expect_err("arm64 NOP size must be instruction-aligned");
        assert_eq!(encode.kind, crate::MutationErrorKind::Instruction);
        assert!(matches!(
            encode.source,
            Some(crate::error::MutationErrorSource::Encode(_))
        ));
    }

    #[test]
    fn plan_function_entry_hook_x86_64_relocates_relative_control_flow_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x105].copy_from_slice(&[0xE8, 0x01, 0x00, 0x00, 0x00]); // call +1

        let plan = p
            .plan_function_entry_hook(PatchArch::X86_64, 0x100100, 0x100200, 0x100300, 5)
            .unwrap();

        let disp = i32::from_le_bytes(plan.trampoline.relocated_bytes[1..5].try_into().unwrap());
        let target = (plan.trampoline.trampoline_va + 5).wrapping_add_signed(disp as i64);
        assert_eq!(target, 0x100106);
    }

    #[test]
    fn plan_function_entry_hook_x86_64_relocates_rip_relative_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x107].copy_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);

        let plan = p
            .plan_function_entry_hook(PatchArch::X86_64, 0x100100, 0x100200, 0x100300, 7)
            .unwrap();

        let disp = i32::from_le_bytes(plan.trampoline.relocated_bytes[3..7].try_into().unwrap());
        let target = (plan.trampoline.trampoline_va + 7).wrapping_add_signed(disp as i64);
        assert_eq!(target, 0x100107);
    }

    #[test]
    fn build_relocated_trampoline_arm64_rewrites_branch_immediate() {
        let source = 0x1400_0002u32.to_le_bytes();
        let trampoline = MachoPatcher::build_relocated_trampoline(
            PatchArch::Arm64,
            0x1000,
            0x2000,
            &source,
            0x1004,
        )
        .unwrap();

        let first = u32::from_le_bytes(trampoline.relocated_bytes[..4].try_into().unwrap());
        assert_ne!(first, 0x1400_0002);
    }

    #[test]
    fn plan_function_entry_patch_x86_64_pads_with_nops() {
        let mut p = make_test_patcher();
        let original = [0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56];
        p.data[0x100..0x108].copy_from_slice(&original);

        let plan = p
            .plan_function_entry_patch(PatchArch::X86_64, 0x100100, 0x100200, original.len())
            .unwrap();

        assert_eq!(plan.entry_offset, 0x100);
        assert_eq!(plan.original_bytes, original);
        assert_eq!(plan.jump.encoding, HookJumpEncoding::X86_64Relative);
        // Jump is 5 bytes, followed by 3 bytes of NOP padding.
        assert_eq!(&plan.patch_bytes[..5], &[0xE9, 0xFB, 0x00, 0x00, 0x00]);
        assert_eq!(plan.patch_bytes.len(), 8);
        // Verify the padding decodes as NOPs.
        let nop_insn =
            macho_insn::decode_one(&plan.patch_bytes[5..], 0, macho_insn::Arch::X86_64).unwrap();
        assert_eq!(nop_insn.kind, macho_insn::InsnKind::Nop);
        assert_eq!(plan.resume_va(), 0x100108);
    }

    #[test]
    fn plan_function_entry_patch_x86_64_far_target_requires_larger_window() {
        let p = make_test_patcher();
        let err = p
            .plan_function_entry_patch(PatchArch::X86_64, 0x100100, 0x1_0000_0000, 5)
            .unwrap_err();
        assert_eq!(err.kind, crate::MutationErrorKind::InvalidInput);
        assert!(err.message().contains("needs 14 bytes"));
    }

    #[test]
    fn plan_function_entry_patch_arm64_rejects_unaligned_overwrite_len() {
        let p = make_test_patcher();
        let err = p
            .plan_function_entry_patch(PatchArch::Arm64, 0x100100, 0x100200, 6)
            .unwrap_err();
        assert_eq!(err.kind, crate::MutationErrorKind::InvalidInput);
        assert!(err.message().contains("divisible by 4"));
    }

    #[test]
    fn plan_function_entry_hook_arm64_relocates_pc_relative_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x104].copy_from_slice(&[0x10, 0x00, 0x00, 0x14]); // b +0x40

        let plan = p
            .plan_function_entry_hook(PatchArch::Arm64, 0x100100, 0x100200, 0x100300, 4)
            .unwrap();

        let first = u32::from_le_bytes(plan.trampoline.relocated_bytes[..4].try_into().unwrap());
        assert_ne!(first, 0x1400_0010);
    }

    #[test]
    fn plan_function_entry_hook_arm64_rejects_register_branch_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x104].copy_from_slice(&[0x00, 0x02, 0x1F, 0xD6]); // br x16

        let err = p
            .plan_function_entry_hook(PatchArch::Arm64e, 0x100100, 0x100200, 0x100300, 4)
            .unwrap_err();

        assert_eq!(err.kind, crate::MutationErrorKind::InvalidInput);
        assert!(err.message().contains("register or authenticated branch"));
    }

    #[test]
    fn plan_function_entry_patch_rejects_va_window_crossing_segment_gap() {
        let p = make_test_patcher();
        let err = p
            .plan_function_entry_patch(PatchArch::X86_64, 0x100ffc, 8, 8)
            .unwrap_err();

        assert_eq!(err.kind, crate::MutationErrorKind::InvalidInput);
        assert!(err.message().contains("not fully mappable"));
    }

    #[test]
    fn nop_fill_x86() {
        let mut p = make_test_patcher();
        let original = p.nop_fill(0x100, 5, false).unwrap();
        assert_eq!(original, vec![0x00; 5]);
        // macho_insn uses Intel-recommended multi-byte NOP sequences.
        let nops = p.read_bytes(0x100, 5).unwrap();
        assert_eq!(nops.len(), 5);
        // Verify each byte decodes as NOP via macho_insn.
        let insn = macho_insn::decode_one(nops, 0, macho_insn::Arch::X86_64).unwrap();
        assert_eq!(insn.kind, macho_insn::InsnKind::Nop);
    }

    #[test]
    fn nop_fill_arm64() {
        let mut p = make_test_patcher();
        let original = p.nop_fill(0x100, 8, true).unwrap();
        assert_eq!(original, vec![0x00; 8]);
        let nop_arm64 = [0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5];
        assert_eq!(p.read_bytes(0x100, 8).unwrap(), &nop_arm64);
    }

    #[test]
    fn nop_fill_arm64_unaligned() {
        let mut p = make_test_patcher();
        let result = p.nop_fill(0x100, 5, true);
        assert!(result.is_err());
    }
}
