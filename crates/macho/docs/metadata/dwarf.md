# macho::metadata::dwarf

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

Requires `macho::core` and `gimli`.

For consumers that must distinguish a complete traversal from a best-effort
summary, `traverse_dwarf` retains bounded section custody, every unit, DIE and
form-bearing attribute, every physical source-file entry, and every physical
line-program row:

```rust
let receipt = macho_dwarf::traverse_dwarf(
    image,
    macho_dwarf::DwarfTraversalLimits::default(),
)?;
```

Malformed headers, abbreviation streams, DIEs, forms, strings, and line
programs reject instead of returning a partial receipt. The current API reads
in-image, uncompressed, already-linked Mach-O DWARF. It does not resolve dSYM,
split DWARF, supplementary objects, compressed sections, or relocations from
Mach-O object files.
