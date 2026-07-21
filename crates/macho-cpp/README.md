# macho-cpp

C++ RTTI, vtable indexing, and architecture-aware ABI inference for Mach-O
images.

Depend on this crate directly when you only need C++ structure recovery. It does
not require the `macho` façade.

```rust
let bytes = std::fs::read("libFoo.dylib")?;
let vtables = macho_cpp::VtableIndex::build_from_source(&bytes)?;
let typeinfo = macho_cpp::build_typeinfo_index_from_source(&bytes)?;
```

The source is borrowed through `AsRef<[u8]>`, so `&[u8]`, `&Vec<u8>`, and a
caller-retained read-only `memmap2::Mmap` are accepted without copying the input.
Parsing and index construction still allocate their result models. Source
helpers accept one thin image; parse universal binaries with `macho_core::parse`,
select an architecture, and call the existing `MachoFile` entry points.

Requires `macho-core`, `macho-insn`, `macho-symbols`, and `macho-dyld`.
