# macho-cpp

C++ RTTI, vtable indexing, and architecture-aware ABI inference for Mach-O
images.

Depend on this crate directly when you only need C++ structure recovery. It does
not require the `macho` façade.

```rust
let bytes = std::fs::read("libFoo.dylib")?;
let container = macho_core::parse(&bytes)?;
let image = container.first_macho().ok_or("no Mach-O image")?;
let vtables = macho_cpp::VtableIndex::build(image)?;
let typeinfo = macho_cpp::build_typeinfo_index(image)?;
```

Requires `macho-core`, `macho-insn`, `macho-symbols`, and `macho-dyld`.
