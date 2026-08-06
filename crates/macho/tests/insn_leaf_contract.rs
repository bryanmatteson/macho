//! Leaf contract: `macho::insn` is usable without the `macho` façade or `macho::core`.

#[test]
fn insn_leaf_decodes_and_encodes_without_macho_crates() {
    // ARM64 `ret`
    let ret = [0xc0, 0x03, 0x5f, 0xd6];
    let mut disassembler = macho::insn::Disassembler::new(macho::insn::Arch::Arm64);
    let decoded = disassembler
        .decode_one(&ret, 0x1000)
        .expect("decode and disassemble known ret");
    assert_eq!(decoded.instruction.len, 4);
    assert!(decoded.text.to_ascii_lowercase().contains("ret"));

    let nops = macho::insn::encode_nop(macho::insn::Arch::Arm64, 4).expect("encode nop");
    assert_eq!(nops.len(), 4);
}
