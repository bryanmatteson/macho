# macho::metadata::codesign

Mach-O code-signature parsing: SuperBlob, CodeDirectory, and entitlements.

Depend on this crate for signature inspection without the `macho` façade.
Image-level parsing needs `macho::core`; raw blob helpers take `&[u8]`.

```rust
let bytes = std::fs::read("signed-binary")?;
let container = macho_core::parse(&bytes)?;
let image = container.first_macho().ok_or("no Mach-O image")?;
let signature = macho_codesign::parse_code_signature(image)?;
if let Some(requirement) = signature.designated_requirement() {
    println!("designated requirement: {} bytes", requirement.len());
}

// Or parse a detached SuperBlob:
let blobs = macho_codesign::superblob::parse_super_blob(&blob_bytes)?;
```
