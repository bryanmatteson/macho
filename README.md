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
`--format json`; `audit` additionally accepts `--format sarif`. JSON results use
a versioned envelope and errors are written only to stderr.

## Examples

```bash
macho info <binary>
macho info <binary> --arch arm64 --validate
macho symbols <binary> --defined-only --demangle
macho imports <binary> --format json
macho objc <binary> --headers
macho diff <old-binary> <new-binary> --ignore-codesign --fail-on breaking
macho audit <binary> --min-severity warning --format sarif
macho snapshot <binary> --format json
macho patch <binary> --add-rpath @executable_path/../Frameworks --dry-run
macho cache <dyld-cache> --info
```

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

For selective analysis, build an `AnalysisPlan` before execution. Snapshot
documents use schema version 2 and preserve `not_requested`, `complete`,
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
