# macho

`macho` is a Rust workspace for safe Mach-O parsing, selective analysis,
structural mutation, and command-line inspection. Version 0.2 separates the
byte-safe core, metadata leaves, analysis, mutation, semantic workflow, façade,
and CLI so library users pay only for the capabilities they select.

## Install and develop

```bash
cargo install --path crates/macho-cli
mise run verify
```

The CLI uses one flat command grammar. Every command accepts `--format text` or
`--format json` and `--color auto|always|never`; `audit` additionally accepts
`--format sarif`. JSON results use a versioned envelope, machine formats never
contain ANSI escapes, and errors are written only to stderr. Human output uses
color by default on interactive terminals and stays plain when redirected.
Semantic roles and the compatibility color theme are resolved by the pinned
Termosaic presentation library; reusable Mach-O crates remain output-neutral.

## Examples

```bash
macho info <binary>
macho info <binary> --arch arm64 --validate
macho symbols <binary> --defined-only --demangle
macho imports <binary> --format json
macho objc <binary> --headers
macho objc <binary> --kind class --presence defined --selector viewDidLoad
macho swift <binary> --state metadata-defined --name MyModule
macho disassemble <binary> --arch arm64e --symbol _main
macho disassemble <binary> --address 0x100003f50 --count 8 --format json
macho disassemble <binary> --address 0x100003f50 --end-address 0x100003f80
macho disassemble <binary> --symbol _main --no-addresses --no-bytes
macho disassemble <binary> --section __TEXT,__text --no-labels --no-targets
macho strings <binary> --min-length 8 --offsets
macho strings <binary> --search "secret" --exact
macho xrefs <binary> --import malloc --kind stub
macho ranges <binary> --name main --source nlist --demangle
macho diff <old-binary> <new-binary> --ignore-codesign --fail-on breaking
macho audit <binary> --min-severity warning --format sarif
macho snapshot <binary> --format json
macho patch <binary> --add-rpath @executable_path/../Frameworks --dry-run
macho patch <binary> --sign-adhoc --output <signed-binary>
macho patch <binary> --sign-p12 <identity.p12> --p12-password-file <password-file> --in-place
macho cache <dyld-cache> --info
```

Mach-O signing is performed and verified in process. It does not require Xcode,
`xcrun`, or the macOS Keychain, and the same ad-hoc and PKCS#12 inputs work on
macOS, Linux, and Windows. Passwords are accepted only through a file path so
they do not appear in the command line.

## Command reference

This table is generated from the production Clap router and checked by
`cargo xtask docs --check`.

<!-- BEGIN MACHO COMMAND REFERENCE -->
| Command | Purpose |
| --- | --- |
| `info` | Mach-O structure (header, segments, sections, load commands) |
| `deps` | Linked libraries and compatibility versions |
| `codesign` | Code signature, entitlements, and CMS info |
| `dwarf` | DWARF debug sections (view or extract with --output-dir) |
| `symbols` | Symbol table with filtering |
| `imports` | Imported symbols |
| `exports` | Exported symbols |
| `fixups` | Chained fixup entries |
| `relocations` | Relocation entries |
| `ranges` | Function and symbol address ranges |
| `strings` | String literals with heuristic scanning |
| `xrefs` | Cross-references between addresses |
| `vtables` | C++ virtual tables |
| `objc` | Objective-C classes, protocols, selectors |
| `swift` | Swift type metadata |
| `cpp` | C++ RTTI type hierarchies |
| `c` | C type declarations from debug info |
| `disassemble` | Decode selected executable instructions |
| `diff` | Compare two binaries semantically |
| `audit` | Security and configuration audit |
| `container` | Multi-architecture container analysis |
| `snapshot` | JSON structural snapshot |
| `patch` | Apply structural patches (rpaths, dylibs, signatures, bytes) |
| `header-infer` | Reconstruct Mach-O headers from evidence |
| `fileset` | Inspect fileset entries |
| `cache` | Inspect dyld shared cache |
<!-- END MACHO COMMAND REFERENCE -->

## Library usage

Core parsing is always available. Feature-selected metadata, analysis,
mutation, workflow, dyld-cache, and header-inference APIs are reexported by the
`macho` façade; narrow consumers can depend on leaf crates directly.

```rust
let bytes = std::fs::read("/usr/bin/true")?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no image")?;
println!("{}", image.header().file_type.name());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Mutation plans borrow added-section payloads and validate concrete placement
before rebuilding:

```rust
let bytes = std::fs::read("MyApp")?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no image")?;
let section = macho::mutate::AddSection::new("__LINKEDIT", "__meta", b"payload")?
    .with_alignment(3)?;
let mut transaction = macho::mutate::PatchTransaction::new(image);
transaction.add_section(section);
let rebuilt = transaction.commit()?;
std::fs::write("MyApp.patched", rebuilt)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

File-backed additions extend only the final file-backed segment when its
declared range ends exactly at the slice boundary. Load commands may grow only
through existing zero-filled header slack; mutation never relocates existing
payload, symbols, or fixups. Zero-fill additions extend virtual storage only.
`AddSection::new` accepts any borrowed `AsRef<[u8]>`, including a raw byte slice,
`Vec<u8>`, or caller-owned read-only `memmap2::Mmap`. It stores the payload as a
slice, copies only the two fixed-width Mach-O names into inline storage, and
performs no internal heap allocation. For a file, retain the mapping until the
transaction has committed; a bare `File` cannot expose borrowed bytes.

Injected `SignatureProvider` implementations may return a known ad-hoc or
certificate kind. External providers can omit `kind()` and are represented as
opaque without exposing credentials or provider-specific signing mechanics.
Opaque providers own signature verification; the generic verifier intentionally
accepts only the ad-hoc and certificate mechanisms it understands.

For selective analysis, build an `AnalysisPlan` before execution. Snapshot
documents use schema version 3 and preserve `not_requested`, `complete`,
`unsupported`, and `failed` as distinct states.

## Repository authorities

- `cargo xtask architecture` enforces dependency direction and source ownership.
- `cargo xtask docs --check` binds this reference and diagnostic registry to code.
- `cargo xtask release --check` binds workspace, CLI, changelog, lockfile, and tags.
- `cargo xtask verify` runs the stable format, lint, docs, test, and benchmark gate.
- `cargo xtask verify-fuzz` builds all fuzz targets and requires nightly Rust.
- `mise run verify` composes both gates while scoping nightly to fuzzing only.

See [CHANGELOG.md](CHANGELOG.md) for release history and
[docs/diagnostic-codes.md](docs/diagnostic-codes.md) for stable machine codes.
