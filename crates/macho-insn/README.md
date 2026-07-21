# macho-insn

Architecture-aware instruction decode, encode, relocate, and disassemble for
x86_64 and ARM64/ARM64e.

This crate has no Mach-O dependency. Depend on it directly for byte-level
instruction work without the `macho` façade or `macho-core`.

```rust
let ret = [0xc0, 0x03, 0x5f, 0xd6]; // ARM64 `ret`
let insn = macho_insn::decode_one(&ret, 0x1000, macho_insn::Arch::Arm64)?;
let text = macho_insn::disassemble_one(&ret, 0x1000, macho_insn::Arch::Arm64)?;
```
