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

For evidence-bearing inspection and semantic graph construction, use the
strict leaf API instead of the name-keyed compatibility index:

```rust
let batch = macho_cpp::decode_strict_rtti_from_source(
    &bytes,
    macho_cpp::StrictRttiLimits::default(),
)?;
```

The strict batch is fail-closed and conserves every defined or external `_ZTI`
candidate. It retains exact file ranges, raw pointer values, chained or legacy
fixup provenance, pointer-authentication metadata, external ordinals, runtime
typeinfo family, encoded type names, pbase flags, and ordered base entries. A
malformed field or exceeded budget produces `rejected` with typed gaps; it does
not become absence, an empty index, or a usable truncated result. Validating
deserialization rejects forged conservation, pointer-observation links, and
family-specific shapes.

The source is borrowed through `AsRef<[u8]>`, so `&[u8]`, `&Vec<u8>`, and a
caller-retained read-only `memmap2::Mmap` are accepted without copying the input.
Parsing and index construction still allocate their result models. Source
helpers accept one thin image; parse universal binaries with `macho_core::parse`,
select an architecture, and call the existing `MachoFile` entry points.

The `itanium-rtti` and `fixups` features are enabled by default. Consumers that
disable default features must opt into both for the complete strict path.

Requires `macho-core`, `macho-insn`, `macho-symbols`, and `macho-dyld`.
