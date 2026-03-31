# macho

`macho` is a Rust library and CLI for parsing, inspecting, comparing, auditing, and structurally editing Mach-O binaries.

It understands both thin Mach-O files and fat/universal containers, then lifts raw binary records into higher-level views over headers, load commands, segments, sections, symbol tables, dyld metadata, Objective-C metadata, Swift type discovery, code signatures, JSON snapshots, semantic diffs, and edit transactions.

The project is aimed at people who need more than `otool`-style field dumps:

- reverse engineering and binary triage
- CI checks for binary drift or policy regressions
- code-signing and load-path analysis
- automation over structured Mach-O metadata
- safe, scripted load-command rewrites

## Why `macho`

- One parser, two interfaces. Use the CLI for investigation and the library when you need direct Rust integration.
- Fat-binary aware by default. Inspect the full container or filter to a single slice with `--arch`.
- Higher-level analyses are built in. ObjC graphs, Swift type discovery, code-signature parsing, semantic diffing, audit rules, and container parity all sit on top of the same parser.
- JSON-first where it matters. `snapshot`, `diff`, `audit`, `container`, `swift`, and `objc graph` all support machine-consumable output paths.
- Editing is guarded by preview and validation. Patch flows can show what will change, warn when signatures are invalidated, and fail closed on validation errors unless you opt into `--force`.

## What It Covers Today

`macho` currently includes support for:

- thin and fat/universal Mach-O parsing
- headers, load commands, segments, sections, UUIDs, and platform/build metadata
- `LC_SYMTAB` symbols and per-section relocations
- dyld exports tries, chained fixups, bind/rebase views, and import tables
- Objective-C classes, categories, protocols, selectors, graphs, and cross-references
- Swift type discovery from demangled symbols plus Swift-marked ObjC metadata
- `LC_CODE_SIGNATURE`, CodeDirectories, entitlements, CMS presence, and code-sign audit rules
- JSON snapshots for downstream tooling
- semantic container diffing with severity filtering
- rule-based audit output in text, JSON, or SARIF
- structural patching for thin and fat binaries
- container parity and `MH_FILESET` entry inspection

## Install

The crate currently installs from source.

```bash
cargo install --path .
```

For local development:

```bash
cargo build
cargo run -- --help
```

Project requirements:

- Rust `1.85+`
- Edition `2024`
- macOS is the primary day-to-day development environment because the examples and tests use real system Mach-O binaries such as `/usr/bin/true`, `/usr/bin/tar`, and `/usr/bin/plutil`

## Quick Start

### Inspect a binary

```bash
macho inspect /usr/bin/true
macho inspect --validate /usr/bin/true
```

Real output starts like this:

```text
Fat binary (2 architectures, 84128 bytes)

=== Architecture 0: x86_64 (offset=0x4000, size=0x5840, align=2^14) ===

Header:
  CPU:       x86_64 (subtype: all)
  File type: MH_EXECUTE
  Bitness:   64-bit
  Endian:    Little
  Commands:  16
```

### Explore symbols, exports, imports, fixups, and relocations

```bash
macho symbols --defined-only --demangle /usr/bin/true
macho relocations --section __DATA,__la_symbol_ptr /usr/bin/tar
macho exports --demangle /usr/bin/tar
macho imports --demangle /usr/bin/tar
macho fixups --binds-only /usr/bin/tar
```

### Recover Objective-C and Swift surface area

```bash
macho objc /usr/bin/plutil --class PLUContext
macho objc graph /usr/bin/plutil --class PLUContext
macho objc selectors /usr/bin/plutil --name execute
macho objc xrefs /usr/bin/plutil --class PLUContext
macho swift /usr/bin/plutil --kind class
```

### Inspect code signing and run policy checks

```bash
macho codesign --entitlements /usr/bin/true
macho audit /usr/bin/true --min-severity warning
macho audit /usr/bin/true --sarif > audit.sarif
```

Example audit output:

```text
[warning] [x86_64] CS004: signed binary missing team ID
           evidence: CMS signature present, team_id absent
           fix: Sign with a Developer ID certificate that includes a team ID
[info] [x86_64] CS002: signed binary has no entitlements
```

### Snapshot or diff a build

```bash
macho snapshot /usr/bin/true > true.snapshot.json
macho diff old.bin new.bin --fail-on breaking
macho diff old.bin new.bin --json --ignore-codesign
```

### Analyze fat-container parity or filesets

```bash
macho container /usr/bin/true
macho container --resolve /usr/bin/true
macho fileset list some_fileset.bin
macho fileset inspect some_fileset.bin com.example.member
```

### Patch a binary

Patching works on both thin and fat binaries. Structural edits apply to every slice by default; use
`--arch` to target one architecture. Raw byte patches against fat binaries require `--arch` because
the offset is interpreted relative to the selected slice.

```bash
macho patch add-rpath /usr/bin/true @executable_path/../Frameworks --dry-run
macho patch add-rpath /usr/bin/true @executable_path/../Frameworks --arch arm64e --output /tmp/true.arm64e
```

Output in this shape:

```text
Dry run - changes that would be applied:
  add rpath: @executable_path/../Frameworks
Load commands: 16 -> 17

Warning: code signature will be invalidated.
Re-sign assistance:
  Identifier: com.apple.true
  Hash type:  SHA-256
  Command:    codesign -f -s <identity> --identifier com.apple.true <binary>
```

Apply a patch to a new file or in place:

```bash
macho patch add-rpath input.bin @executable_path/../Frameworks --output patched.bin
macho patch strip-signature input.bin --in-place --backup
macho patch patch-bytes fat.bin --arch arm64e --offset 0x100 --hex 90909090 --output patched.bin
```

## Command Guide

| Command | What it does | Notable options |
| --- | --- | --- |
| `inspect` | Print headers, segments, sections, load commands, and summary information. | `--arch`, `--validate` |
| `symbols` | List symbols from `LC_SYMTAB`. | `--arch`, `--external`, `--undefined-only`, `--defined-only`, `--sort-address`, `--demangle` |
| `relocations` | Show relocations for each section or a selected section. | `--arch`, `--section` |
| `exports` | Decode the dyld exports trie. | `--arch`, `--demangle` |
| `imports` | List chained-fixup imports. | `--arch`, `--demangle` |
| `fixups` | Walk chained fixups and split them into binds/rebases. | `--arch`, `--binds-only`, `--rebases-only`, `--demangle` |
| `objc` | Print ObjC classes/categories/protocols, or drill into graphs/selectors/xrefs. | `--arch`, `--headers`, `--class` |
| `codesign` | Inspect `LC_CODE_SIGNATURE`, entitlements, CodeDirectory data, and CMS presence. | `--arch`, `--entitlements` |
| `snapshot` | Emit a structured JSON snapshot of the parsed container. | `--arch` |
| `diff` | Compare two binaries semantically at the snapshot level. | `--arch`, `--json`, `--fail-on`, `--ignore-codesign`, `--ignore-objc`, `--ignore-symbols` |
| `audit` | Run bundled audit rules and print text, JSON, or SARIF. | `--arch`, `--json`, `--sarif`, `--min-severity`, `--fail-on` |
| `patch` | Add/remove load commands, strip signatures, or patch raw bytes. | `--arch`, `--dry-run`, `--output`, `--in-place`, `--backup`, `--force` |
| `swift` | Discover Swift type names and kinds from metadata/symbols. | `--arch`, `--json`, `--kind` |
| `container` | Report fat-container parity, fileset entries, and optional cross-image resolution. | `--arch`, `--json`, `--resolve` |
| `fileset` | List or inspect `MH_FILESET` entries. | `list`, `inspect` subcommands |

### `objc` subcommands

- `macho objc graph`: build a class/category/protocol graph, optionally as JSON
- `macho objc selectors`: find selector owners across classes
- `macho objc xrefs`: show method-to-symbol cross-references

### `patch` subcommands

- `add-rpath`
- `remove-rpath`
- `add-dylib`
- `strip-signature`
- `patch-bytes`

## Library Usage

The library API is intentionally close to the binary model. Parse once, then choose the level of abstraction you need: raw model access, borrowed analysis extensions, structured snapshots, validation, diffing, audit, or editing.

### Parse a container and inspect symbols

```rust
use macho::ext::MachExt;
use macho::model::symbol::SymbolTable;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("/usr/bin/true")?;
    let container = macho::parse(&bytes)?;
    let mach = container.first_mach();

    println!("file type: {}", mach.header().file_type.name());
    println!("segments: {}", mach.segments().len());

    let symtab = mach.ext::<SymbolTable>()?;
    if let Some(sym) = symtab.find_by_name("__mh_execute_header") {
        println!("__mh_execute_header = {:#x}", sym.value);
    }

    Ok(())
}
```

### Preview and commit an edit transaction

```rust
use macho::edit::transaction::PatchTransaction;

fn rewrite(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let container = macho::parse(&bytes)?;
    let mach = container.first_mach();

    let mut txn = PatchTransaction::new(mach);
    txn.add_rpath("@executable_path/../Frameworks");

    let preview = txn.preview()?;
    assert_eq!(preview.old_command_count + 1, preview.new_command_count);

    let rebuilt = txn.commit()?;
    Ok(rebuilt)
}
```

### Rebuild a fat container after editing one slice

```rust
use macho::edit::transaction::PatchTransaction;
use macho::model::container::MachContainer;
use macho::model::owned::OwnedFatBinary;

fn rewrite_arm64(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let container = macho::parse(&bytes)?;

    match &container {
        MachContainer::Fat(fat) => {
            let arm64_index = fat
                .arches()
                .iter()
                .position(|arch| arch.spec.name() == "arm64")
                .ok_or("missing arm64 slice")?;

            let mut txn = PatchTransaction::new(&fat.arches()[arm64_index].mach);
            txn.add_rpath("@executable_path/../Frameworks");

            let mut owned = OwnedFatBinary::from_fat(fat, &bytes);
            owned.replace_arch(arm64_index, txn.commit()?)?;
            Ok(owned.try_into_bytes()?)
        }
        MachContainer::Thin(_) => Err("expected fat binary".into()),
    }
}
```

### Useful API entry points

- `macho::parse(&[u8]) -> Result<MachContainer>`
- `MachContainer::{is_thin, is_fat, mach_files, first_mach, find_arch}`
- `MachFile::{header, load_commands, segments, all_sections, address_map, section_bytes, read_bytes_at_va, read_bytes_at_rva, ext}`
- `OwnedFatBinary::{from_fat, replace_arch, try_into_bytes}` for rebuilding universal containers after per-slice edits
- `macho::validate::validate(&MachFile)` for structural diagnostics
- `macho::analysis::snapshot::ContainerSnapshot::from_container(&container)` for structured analysis output
- `macho::diff::diff_containers(&old, &new)` for semantic comparison
- `macho::audit::audit_slice(&slice)` for rule-based findings
- `macho::edit::MachEditor` and `macho::edit::transaction::PatchTransaction` for structural rewriting

## Audit Rules Included

The bundled audit rules currently look for:

- unreadable or missing code signatures
- missing entitlements on CMS-signed binaries
- SHA-1 code-signature hashing
- missing team IDs
- suspicious entitlement keys such as JIT or library-validation disables
- absolute or relative `LC_RPATH` problems
- non-system absolute dylib paths
- writable-location load paths such as `/tmp` or `/Users/...`
- writable-and-executable segment protections
- missing PIE on executables
- `MH_ALLOW_STACK_EXECUTION`
- missing `__PAGEZERO` on executables

These are policy and security heuristics, not a formal proof that a binary is safe.

## Scope, Guarantees, and Limitations

- The parser and patch pipeline handle both thin and fat containers. Structural fat-binary edits rebuild the universal container and preserve per-slice alignment; raw byte patches require `--arch` and use slice-relative offsets.
- ObjC metadata parsing currently supports 64-bit binaries only.
- Swift discovery is best-effort and built from demangled Swift symbols plus Swift-marked ObjC metadata. It is useful for inventory and comparison, not a substitute for full Swift metadata reconstruction.
- Patch operations can invalidate existing code signatures. The CLI warns when that happens, but it does not re-sign the binary for you.
- Validation is structural, not exhaustive. Current checks cover header consistency, segment/file bounds, VM overlap, `__PAGEZERO`, segment protections, and `LC_SYMTAB` bounds.
- Snapshot, diff, and audit output describe current code behavior. They should be treated as implementation-defined unless the project later publishes a compatibility policy for schemas.
- Development and tests are currently macOS-centric because the fixture set uses Apple system binaries.

## Development

Typical local workflow:

```bash
cargo fmt
cargo test
cargo clippy --all-targets --all-features
```

Useful places to start:

- [`src/lib.rs`](src/lib.rs): public crate surface
- [`src/main.rs`](src/main.rs): CLI entrypoint
- [`src/commands`](src/commands): command implementations
- [`src/analysis`](src/analysis): snapshots and derived views
- [`src/edit`](src/edit): rebuilding and transactional patching
- [`tests`](tests): integration and feature coverage
- [`plans/README.md`](plans/README.md): implementation plans and roadmap notes

## License

Licensed under either:

- MIT
- Apache-2.0
