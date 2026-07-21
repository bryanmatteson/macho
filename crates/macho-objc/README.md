# macho-objc

Objective-C runtime metadata parsing for Mach-O images.

Depend on this crate directly when you only need ObjC classes, categories,
protocols, encodings, and method-implementation folding. It does not require the
`macho` façade.

```rust
let bytes = std::fs::read("libFoo.dylib")?;
let container = macho_core::parse(&bytes)?;
let image = container.first_macho().ok_or("no Mach-O image")?;
let metadata = macho_objc::parse_objc_metadata(image)?;
```

Requires `macho-core` and `macho-dyld`.
