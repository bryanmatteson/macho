# macho

`macho` is a Rust library and CLI for parsing, inspecting, comparing, extracting from, auditing, and structurally editing Mach-O binaries.

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
- JSON-first where it matters. `compare`, `audit`, `extract swift`, `extract objc graph`, and container/fileset reporting all support machine-consumable output paths.
- Editing is guarded by preview and validation. Patch flows can show what will change, warn when signatures are invalidated, and fail closed on validation errors unless you opt into `--force`.

## What It Covers Today

`macho` currently includes support for:

- thin and fat/universal Mach-O parsing
- headers, load commands, segments, sections, UUIDs, and platform/build metadata
- `LC_SYMTAB` symbols and per-section relocations
- dyld exports tries, chained fixups, bind/rebase views, and import tables
- Objective-C classes, categories, protocols, selectors, graphs, cross-references, and high-fidelity header reconstruction via `macho extract objc --headers`
- Swift type discovery from demangled symbols plus Swift-marked ObjC metadata
- `LC_CODE_SIGNATURE`, CodeDirectories, entitlements, CMS presence, and code-sign audit rules
- JSON snapshots for downstream tooling
- semantic container diffing with severity filtering
- rule-based audit output in text, JSON, or SARIF
- structural patching for thin and fat binaries
- container parity and `MH_FILESET` entry inspection

## Install

The CLI currently installs from source from the workspace.

```bash
cargo install --path crates/macho-cli
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

### View binary structure

```bash
macho view header /usr/bin/true
macho view load-commands /usr/bin/true
macho view segments /usr/bin/true
macho view sections /usr/bin/true
macho view header /usr/bin/true --validate
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

### View symbols, exports, imports, fixups, and relocations

```bash
macho view symbols /usr/bin/true --defined-only --demangle
macho view relocations /usr/bin/tar --section __DATA,__la_symbol_ptr
macho view exports /usr/bin/tar --demangle
macho view imports /usr/bin/tar --demangle
macho view fixups /usr/bin/tar --binds-only
```

### Extract Objective-C, Swift, RTTI, and DWARF artifacts

```bash
macho extract objc /usr/bin/plutil --class PLUContext
macho extract objc /usr/bin/plutil --headers --class PLUContext
macho extract objc graph /usr/bin/plutil --class PLUContext
macho extract objc selectors /usr/bin/plutil --name execute
macho extract objc xrefs /usr/bin/plutil --class PLUContext
macho extract swift /usr/bin/plutil --kind class
macho extract rtti some_binary --headers
macho extract dwarf some_binary --output-dir /tmp/dwarf
```

### Inspect code signing and run policy checks

```bash
macho view code-signature /usr/bin/true --entitlements
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

### Compare two builds

```bash
macho compare old.bin new.bin --fail-on breaking
macho compare old.bin new.bin --json --ignore-codesign
macho compare old.bin new.bin --mode container
```

### Inspect filesets or dyld caches

```bash
macho fileset list some_fileset.bin
macho fileset inspect some_fileset.bin com.example.member
macho dyld-cache info /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
macho dyld-cache list /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
```

### Patch a binary

Patching works on both thin and fat binaries. Structural edits apply to every slice by default; use
`--arch` to target one architecture. Raw byte patches against fat binaries require `--arch` because
the offset is interpreted relative to the selected slice.

```bash
macho patch /usr/bin/true --add-rpath @executable_path/../Frameworks --dry-run
macho patch /usr/bin/true --add-rpath @executable_path/../Frameworks --arch arm64e --output /tmp/true.arm64e
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
macho patch input.bin --add-rpath @executable_path/../Frameworks --output patched.bin
macho patch input.bin --strip-signature --in-place --backup
macho patch fat.bin --arch arm64e --patch-bytes 0x100:90909090 --output patched.bin
macho patch input.bin \
  --remove-rpath /old/path \
  --add-rpath @executable_path/../Frameworks \
  --add-dylib /usr/lib/libfoo.dylib \
  --output patched.bin
```

## Command Guide

| Command | What it does | Notable options |
| --- | --- | --- |
| `view` | Inspect headers, load commands, segments, sections, symbols, relocations, imports, exports, fixups, strings, xrefs, code signatures, DWARF sections, or dependency summaries. | subcommands such as `header`, `symbols`, `imports`, `code-signature`, `dwarf`, `dependencies`; most accept `--arch` |
| `patch` | Apply one or more structural or raw binary edits in a single transaction. | `--add-rpath`, `--remove-rpath`, `--add-dylib`, `--strip-signature`, `--patch-bytes`, `--arch`, `--dry-run`, `--output`, `--in-place`, `--backup`, `--force` |
| `compare` | Compare two binaries semantically and optionally fail on severity. | `--mode`, `--arch`, `--json`, `--fail-on`, `--ignore-codesign`, `--ignore-objc`, `--ignore-symbols` |
| `extract` | Recover higher-level artifacts such as ObjC metadata, Swift types, C++ RTTI, DWARF payloads, raw sections, or code-signature material. | subcommands `objc`, `swift`, `rtti`, `dwarf`, `section`, `code-signature` |
| `fileset` | List or inspect `MH_FILESET` entries. | `list`, `inspect` |
| `dyld-cache` | Inspect or extract from dyld shared caches. | `info`, `list`, `extract` |
| `audit` | Run bundled audit rules and print text, JSON, or SARIF. | `--arch`, `--json`, `--sarif`, `--min-severity`, `--fail-on` |

### `extract objc` subcommands

- `macho extract objc graph`: build a class/category/protocol graph, optionally as JSON
- `macho extract objc selectors`: find selector owners across classes
- `macho extract objc xrefs`: show method-to-symbol cross-references

### `patch` operation flags

- `--add-rpath`
- `--remove-rpath`
- `--add-dylib`
- `--strip-signature`
- `--patch-bytes`

## Library Usage

The library API is intentionally close to the binary model. Parse once, then choose the level of abstraction you need: raw model access, borrowed analysis extensions, structured snapshots, validation, diffing, audit, or editing.

### Parse a container and inspect symbols

```rust
use macho::ext::MachoExt;
use macho::model::symbol::SymbolTable;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = std::fs::read("/usr/bin/true")?;
    let container = macho::parse(&bytes)?;
    let macho = container.first_mach();

    println!("file type: {}", macho.header().file_type.name());
    println!("segments: {}", macho.segments().len());

    let symtab = macho.ext::<SymbolTable>()?;
    if let Some(sym) = symtab.find_by_name("__mh_execute_header") {
        println!("__mh_execute_header = {:#x}", sym.value);
    }

    Ok(())
}
```

### Preview and commit a mutation transaction

```rust
use macho::mutate::transaction::PatchTransaction;

fn rewrite(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let container = macho::parse(&bytes)?;
    let macho = container.first_mach();

    let mut txn = PatchTransaction::new(macho);
    txn.add_rpath("@executable_path/../Frameworks");

    let preview = txn.preview()?;
    assert_eq!(preview.old_command_count + 1, preview.new_command_count);

    let rebuilt = txn.commit()?;
    Ok(rebuilt)
}
```

### Rebuild a fat container after mutating one slice

```rust
use macho::mutate::owned::OwnedFatBinary;
use macho::mutate::transaction::PatchTransaction;
use macho::model::container::MachoContainer;

fn rewrite_arm64(path: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path)?;
    let container = macho::parse(&bytes)?;

    match &container {
        MachoContainer::Fat(fat) => {
            let arm64_index = fat
                .arches()
                .iter()
                .position(|arch| arch.spec.name() == "arm64")
                .ok_or("missing arm64 slice")?;

            let mut txn = PatchTransaction::new(&fat.arches()[arm64_index].macho);
            txn.add_rpath("@executable_path/../Frameworks");

            let mut owned = OwnedFatBinary::from_fat(fat, &bytes);
            owned.replace_arch(arm64_index, txn.commit()?)?;
            Ok(owned.try_into_bytes()?)
        }
        MachoContainer::Thin(_) => Err("expected fat binary".into()),
    }
}
```

### Useful API entry points

- `macho::parse(&[u8]) -> Result<MachoContainer>`
- `MachoContainer::{is_thin, is_fat, macho_files, first_mach, find_arch}`
- `MachoFile::{header, load_commands, segments, all_sections, address_map, section_bytes, read_bytes_at_va, read_bytes_at_rva, ext}`
- `macho::mutate::owned::OwnedFatBinary::{from_fat, replace_arch, try_into_bytes}` for rebuilding universal containers after per-slice edits
- `macho::model::validate::validate(&MachoFile)` for structural diagnostics
- `macho::analysis::snapshot::ContainerSnapshot::from_container(&container)` for structured analysis output
- `macho::analysis::diff::diff_containers(&old, &new)` for semantic comparison
- `macho::analysis::audit::audit_slice(&slice)` for rule-based findings
- `macho::mutate::MachoEditor` and `macho::mutate::transaction::PatchTransaction` for structural rewriting

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

- [`crates/macho/src/lib.rs`](crates/macho/src/lib.rs): public library surface
- [`crates/macho-cli/src/main.rs`](crates/macho-cli/src/main.rs): thin CLI entrypoint
- [`crates/macho/src/commands`](crates/macho/src/commands): command implementations
- [`crates/macho-analysis/src`](crates/macho-analysis/src): snapshots, diffing, audit, and derived views
- [`crates/macho-metadata/src`](crates/macho-metadata/src): dyld, codesign, ObjC, Swift, and image metadata recovery
- [`crates/macho-mutate/src`](crates/macho-mutate/src): rebuilding and transactional mutation
- [`tests`](crates/macho/tests): integration and feature coverage
- [`plans/README.md`](plans/README.md): implementation plans and roadmap notes

## License

Licensed under either:

- MIT
- Apache-2.0
