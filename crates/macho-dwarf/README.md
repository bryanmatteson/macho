# macho-dwarf

DWARF section loading and typed function/type indexes for Mach-O images.

Depend on this crate for DWARF indexes without the `macho` façade.

```rust
let bytes = std::fs::read("binary.dSYM/Contents/Resources/DWARF/binary")?;
let container = macho_core::parse(&bytes)?;
let image = container.first_macho().ok_or("no Mach-O image")?;
if macho_dwarf::has_dwarf_sections(image) {
    let sections = macho_dwarf::load_dwarf(image)?;
}
```

Requires `macho-core` and `gimli`.
