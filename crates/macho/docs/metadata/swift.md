# macho::metadata::swift

Swift type-metadata indexing for Mach-O images, with injectable demangling.

Depend on this crate for Swift type indexes without the `macho` façade.

```rust
let bytes = std::fs::read("MyApp")?;
let index = macho_swift::SwiftTypeIndex::build_from_source(&bytes)?;
```

The source is borrowed through `AsRef<[u8]>`, so `&[u8]`, `&Vec<u8>`, and a
caller-retained read-only `memmap2::Mmap` are accepted without copying the input.
Parsing and index construction still allocate their result models. Source
helpers accept one thin image; parse universal binaries with `macho_core::parse`,
select an architecture, and call `SwiftTypeIndex::build`.

Requires `macho::core` and the process-free `macho::metadata::demangle` leaf. With
`strict-rtti`, callers can request bounded, conserved descriptor and
already-materialized metadata batches. Swift parser ASTs remain private to
`macho::metadata::demangle`; this crate consumes only Macho-owned classifications.
Objective-C runtime enrichment is composed by `macho::analysis`; the Swift
parser does not depend on an Objective-C parser.
