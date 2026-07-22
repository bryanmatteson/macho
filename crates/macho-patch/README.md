# macho-patch

Architecture-aware executable patch and trampoline planning.

This crate owns function-entry jump encoding, stolen-instruction validation and
relocation, trampoline construction, and in-memory executable byte patching. It
depends on `macho-insn` for decoding and rewriting. Structural Mach-O editing,
layout, transactions, and signing remain in `macho-mutate`.
