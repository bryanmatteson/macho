# macho-swift

Swift type-metadata indexing for Mach-O images, with injectable demangling.

Depend on this crate directly when you only need Swift type indexes. It does not
require the `macho` façade.

```rust
let bytes = std::fs::read("MyApp")?;
let container = macho_core::parse(&bytes)?;
let image = container.first_macho().ok_or("no Mach-O image")?;
let index = macho_swift::SwiftTypeIndex::build(image);
```

Requires `macho-core`, `macho-symbols`, and `macho-objc`.
