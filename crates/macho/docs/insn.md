# macho::insn

Architecture-aware instruction decode, encode, relocate, and disassemble for
x86_64 and ARM64/ARM64e.

The `insn` feature has two layers: mkasm-generated, allocation-free tables for
encoding identity, physical encoding, and display, plus locally lowered ARM64
semantics and mkasm-backed x86 semantics, effects, and relocation.

Decode failures retain a typed `DecodeErrorKind`: invalid encoding, unknown
primary-table encoding, truncated input, or an instruction exceeding the x86
length limit. Recovering disassembly keeps strict decode fail-closed. A complete
AArch64 word whose formatter has no match is retained with an exact boundary;
it is opaque (`InsnKind::Other`) and carries no operand, control-flow, or
relocation authority. An x86 table miss remains a recovery gap until the local
codec is extended; no secondary production decoder promotes it to an
instruction. The vendored x86 codec regression suite encodes and decodes every
supported 64-bit catalog form and includes explicit coverage for 3DNow trailing
selectors and Knights Corner VEX map-zero branches.

```rust
let ret = [0xc0, 0x03, 0x5f, 0xd6]; // ARM64 `ret`
let identity = macho::insn::identify_encoding(&ret, macho::insn::Arch::Arm64)?;
assert_eq!(identity.length, 4);

let mut disassembler = macho::insn::Disassembler::new(macho::insn::Arch::Arm64);
let decoded = disassembler.decode_one(&ret, 0x1000)?;
assert_eq!(decoded.instruction.len, 4);
assert!(decoded.text.eq_ignore_ascii_case("ret"));
# Ok::<(), Box<dyn std::error::Error>>(())
```

Generated form identifiers round-trip through the physical encoders. ARM64
accepts named architecture fields through `encode_arm64_fields`; x86-64 returns
a form-table index accepted by `encode_x86_form`. Use `decode_one` when semantic
operand and access information is required. The checked-in tables are generated
by mkasm v0.2.0 and can be refreshed with
`scripts/generate-mkasm-codecs.sh /path/to/x86_64.json.xz`.
