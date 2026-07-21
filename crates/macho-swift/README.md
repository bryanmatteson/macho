# macho-swift

Swift type-metadata indexing for Mach-O images, with injectable demangling.

Depend on this crate directly when you only need Swift type indexes. It does not
require the `macho` façade.

```rust
let bytes = std::fs::read("MyApp")?;
let index = macho_swift::SwiftTypeIndex::build_from_source(&bytes)?;
```

The source is borrowed through `AsRef<[u8]>`, so `&[u8]`, `&Vec<u8>`, and a
caller-retained read-only `memmap2::Mmap` are accepted without copying the input.
Parsing and index construction still allocate their result models. Source
helpers accept one thin image; parse universal binaries with `macho_core::parse`,
select an architecture, and call `SwiftTypeIndex::build`.

Requires `macho-core`, `macho-symbols`, and `macho-objc`.
