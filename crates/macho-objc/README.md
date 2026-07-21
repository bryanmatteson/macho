# macho-objc

Objective-C runtime metadata parsing for Mach-O images.

Depend on this crate directly when you only need ObjC classes, categories,
protocols, encodings, and method-implementation folding. It does not require the
`macho` façade.

```rust
let bytes = std::fs::read("libFoo.dylib")?;
let metadata = macho_objc::parse_objc_metadata_from_source(&bytes)?;
```

The source is borrowed through `AsRef<[u8]>`, so `&[u8]`, `&Vec<u8>`, and a
caller-retained read-only `memmap2::Mmap` are accepted without copying the input.
Parsing and metadata output still allocate their structural models. Source
helpers accept one thin image; parse universal binaries with `macho_core::parse`,
select an architecture, and call `parse_objc_metadata`, `scan_objc_metadata`, or
`fold_method_imps`. A matching `fold_method_imps_from_source` entry point is
available for streaming method-implementation traversal.

Requires `macho-core` and `macho-dyld`.
