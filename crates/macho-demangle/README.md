# macho-demangle

Process-free Rust, C++, and Swift symbol demangling and normalization.

This dependency-free workspace leaf owns language demangler adapters and the
shared cache used by symbol-heavy callers. It parses no Mach-O bytes and depends
on no other Mach-O crate.
