//! Leaf contract: `macho-insn` is usable without the `macho` façade or `macho-core`.

#[test]
fn insn_leaf_decodes_and_encodes_without_macho_crates() {
    // ARM64 `ret`
    let ret = [0xc0, 0x03, 0x5f, 0xd6];
    let insn =
        macho_insn::decode_one(&ret, 0x1000, macho_insn::Arch::Arm64).expect("decode known ret");
    assert_eq!(insn.len, 4);

    let text = macho_insn::disassemble_one(&ret, 0x1000, macho_insn::Arch::Arm64)
        .expect("disassemble known ret");
    assert!(text.to_ascii_lowercase().contains("ret"));

    let nops = macho_insn::encode_nop(macho_insn::Arch::Arm64, 4).expect("encode nop");
    assert_eq!(nops.len(), 4);
}
