# macho

**One Rust toolkit for reading, reconstructing, auditing, and rewriting Mach-O binaries — no Xcode, no `otool`, no macOS required.**

[![CI](https://github.com/bryanmatteson/macho/actions/workflows/ci.yml/badge.svg)](https://github.com/bryanmatteson/macho/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/macho-lib.svg)](https://crates.io/crates/macho-lib)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Libraries: Rust 1.85+](https://img.shields.io/badge/libraries-rust%201.85%2B-orange.svg)](https://www.rust-lang.org)
[![CLI: Rust 1.88+](https://img.shields.io/badge/CLI-rust%201.88%2B-orange.svg)](https://www.rust-lang.org)

`macho` is what you reach for when you have an Apple binary and a question. It reads the header, walks the load commands, recovers Objective-C and Swift declarations that were compiled away, disassembles the code, diffs two builds, audits the code signature, patches an rpath, re-signs the result, and cracks open a dyld shared cache — from a single static binary that runs the same on macOS, Linux, and Windows.

```console
$ macho objc Calculator --headers --arch arm64e
@interface _TtC10Calculator19CalculatorViewModel : _TtCs12_SwiftObject
@end
@protocol NSApplicationDelegate<NSObject>
- (unsigned long long)applicationShouldTerminate:(id)arg1;
- (void)application:(id)arg1 openURLs:(id)arg2;
...
```

That header was never in the file. `macho` projected the declaration supported by Objective-C metadata embedded in the binary; unresolved declarations and members remain visible in the JSON ledger instead of being guessed away.

---

## Why it exists

Inspecting Apple binaries usually means juggling `otool`, `nm`, `dyld_info`, `codesign`, `class-dump`, a Swift demangler, a disassembler, and a shared-cache extractor — most of which only run on a Mac with the right SDK installed. `macho` folds that toolbox into one command with a single, consistent grammar and a library you can build on.

| Instead of… | Use |
| --- | --- |
| `otool -l`, `otool -h` | `macho info` |
| `nm`, `dyld_info -exports` | `macho symbols`, `macho exports`, `macho imports` |
| `class-dump` | `macho objc --headers` |
| a Swift metadata reader + demangler | `macho swift --headers` |
| `otool -tV` / a standalone disassembler | `macho disassemble` |
| `codesign -d`, `codesign -s` | `macho codesign`, `macho patch --sign-*` |
| `install_name_tool`, `otool` byte-patching | `macho patch` |
| diffing two builds by hand | `macho diff` |
| a shared-cache extractor | `macho cache` |

Report-producing commands speak `--format text` for humans and `--format json` for pipelines; `audit` also emits **SARIF 2.1** so findings drop straight into GitHub code scanning. Artifact-producing `header-infer` actions use their explicit output files or emit source/prompt text instead.

## Highlights

- **Evidence-accountable header recovery.** `objc --headers`, `swift --headers`, `c --headers`, and `cpp --headers` project typed declarations from the runtime metadata, symbols, and debug evidence that survive compilation. Every report carries completeness states and an unresolved ledger, so partial evidence stays explicit instead of becoming a plausible-looking guess.
- **In-process code signing.** Ad-hoc and PKCS#12 signing and verification happen inside the tool. No `xcrun`, no Keychain, no macOS. The same inputs work on all three platforms, and passwords are read from a file so they never touch the command line or your shell history.
- **Byte-safe by construction.** The core parser validates structure before it trusts it, and the whole workspace is continuously fuzzed (headers, load commands, code signatures, dyld metadata, mutation, and more).
- **Mutation that refuses to corrupt.** Patches extend existing slack and file-backed segments only; they never relocate existing payload, symbols, or fixups. If a placement isn't provably safe, the transaction refuses to commit.
- **Semantic diffing and auditing.** `diff` compares two binaries by meaning and can fail CI on breaking changes; `audit` surfaces signing and configuration findings with stable diagnostic codes.
- **Pick only what you need.** A feature-gated façade over 18 focused leaf crates means a narrow consumer can depend on just the parser, or just the demangler, without pulling in the CLI, mutation, or workflow layers.

## Install

```bash
cargo add macho-lib --rename macho  # library façade: package `macho-lib`, imported as `macho`
cargo install macho-cli              # installs the `macho` binary
```

The libraries declare Rust 1.85 as their minimum supported version; the CLI requires Rust 1.88. From a checkout, use `cargo install --path crates/macho-cli` to install that exact source tree.

Then, from a clone:

```bash
mise run verify     # format, lint, docs, tests, benches, and fuzz-target builds
```

## Tour

```bash
# Structure
macho info <binary>
macho info <binary> --arch arm64 --validate

# Symbols
macho symbols <binary> --defined-only --demangle
macho imports <binary> --format json

# Evidence-backed header projections from stripped binaries
macho objc <binary> --headers
macho objc <binary> --kind class --presence defined --selector viewDidLoad
macho swift <binary> --state metadata-defined --name MyModule
macho swift <binary> --arch arm64 --name MyModule.Record --exact --headers

# Disassembly
macho disassemble <binary> --arch arm64e --symbol _main
macho disassemble <binary> --address 0x100003f50 --count 8 --format json
macho disassemble <binary> --section __TEXT,__text --no-labels --no-targets

# Strings and cross-references
macho strings <binary> --min-length 8 --offsets
macho strings <binary> --search "secret" --exact
macho xrefs <binary> --import malloc --kind stub
macho ranges <binary> --name main --source nlist --demangle

# Compare, audit, snapshot
macho diff <old-binary> <new-binary> --ignore-codesign --fail-on breaking
macho audit <binary> --min-severity warning --format sarif
macho snapshot <binary> --format json

# Patch and sign — no Xcode, no Keychain
macho patch <binary> --add-rpath @executable_path/../Frameworks --dry-run
macho patch <binary> --add-section __LINKEDIT,__meta,3,metadata.bin --output <patched-binary>
macho patch <binary> --add-zerofill-section __DATA,__scratch,4,0x100 --output <patched-binary>
macho patch <fat-binary> --arch arm64e --detour 0x100003f50,0x100004100,4 --dry-run --format json
macho patch <binary> --sign-adhoc --output <signed-binary>
macho patch <binary> --sign-p12 <identity.p12> --p12-password-file <password-file> --output <signed-binary>

# Shared cache
macho cache <dyld-cache> --info
macho cache <dyld-cache> --search libobjc
macho cache <dyld-cache> --extract /usr/lib/libobjc.A.dylib --output libobjc.A.dylib
```

`macho cache` opens the primary cache and every UUID-validated sibling named by
its subcache table. Extraction selects exactly one image, reconstructs a compact
standalone Mach-O from mapped segment bytes, rebuilds its per-image symbol and
string tables, rewrites file-coordinate load commands, and reparses the result
before writing it atomically. Existing outputs are never replaced unless
`--force` is explicit. The JSON result includes a per-domain completeness
ledger; cache-level local symbols and cache-resident signatures are reported as
unresolved, absent, or rejected rather than presented as standalone evidence.
Current support targets dyld v1 cache families with legacy numeric or modern
explicit subcache suffixes. Valid layouts that cannot be reconstructed safely
fail as unsupported instead of producing a partial artifact.

`macho diff` compares architecture slices, binary structure, relocations,
symbols and dynamic-link surfaces, code signatures and audit findings, strings,
code ranges, cross-reference relationships, and recovered C, C++, Objective-C,
and Swift declarations. Semantic identities suppress reorder and address-only
churn where the evidence supports it; unavailable, failed, and unrequested
analysis stays explicit instead of being treated as an empty result. JSON emits
the same architecture-attributed findings as structured records for automation.
Either input may also be a JSON file emitted by `macho snapshot`; `--arch`
selects the same family or qualified slice whether the input is a binary or a
saved snapshot.

Most report-producing commands accept `--format text|json`; JSON reports use a versioned envelope. `disassemble --format json` deliberately streams newline-delimited JSON (one object per line) so large binaries do not need to materialize one document; use `jq -s` when a collected array is needed. `audit` also accepts `sarif`. The `header-infer export`, `prompt`, and `apply` actions produce fixed bundle, prompt, header, or sidecar artifacts and intentionally require text mode, while `inspect`, `check-bundle`, and `validate` support text and JSON. Machine formats never contain ANSI escapes, and errors go only to stderr. Semantic roles and the terminal theme come from the pinned Termosaic presentation library; the reusable Mach-O crates stay output-neutral.

`macho patch` plans and reparses the complete candidate before it writes. Section
specifications name an existing segment and carry an explicit base-two alignment
exponent; names longer than Mach-O's 16-byte field are rejected rather than
truncated. `--detour ENTRY_VA,DESTINATION_VA,OVERWRITE_LEN` uses the
architecture-aware executable planner and requires one exact `--arch` for a fat
binary. Its preview reports the encoding, slice-relative file offset, original
bytes, replacement bytes, and decoded instruction count. Before planning the
branch, the CLI strictly decodes the entire overwrite window and refuses an
invalid instruction or a window ending partway through an instruction. Raw byte writes are deliberately guarded:
`--bytes OFFSET,EXPECTED_HEX,REPLACEMENT_HEX` refuses a changed input instead of
blindly overwriting it. Modifying a signed image reports `invalidated` unless
the same transaction strips or successfully re-signs it. Use `--dry-run` for a
no-write preview, `--output` for an atomic new artifact, or `--in-place
--backup` for an atomic replacement with a recoverable original.

## Command reference

Generated from the production Clap router and checked by `cargo xtask docs --check`.

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
| `patch` | Safely patch structure, sections, executable entries, and signatures |
| `header-infer` | Reconstruct Mach-O headers from evidence |
| `fileset` | Inspect fileset entries |
| `cache` | Inspect cache families and reconstruct standalone images |
<!-- END MACHO COMMAND REFERENCE -->

## Library usage

Core parsing is always available. Feature-selected metadata, analysis, mutation, workflow, dyld-cache, and header-inference APIs are re-exported by the `macho` façade; narrow consumers can depend on leaf crates directly.

Parse a container and read its first image:

```rust
let bytes = std::fs::read("/usr/bin/true")?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no image")?;
println!("{}", image.header().file_type.name());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run selective analysis and keep absence, partial evidence, and failure explicit
while consuming ordinary Rust report types:

```rust
use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DomainState, domain_reports};

let bytes = std::fs::read("/usr/bin/true")?;
let container = macho::parse(&bytes)?;
let document = Analyzer.run(
    &container,
    &AnalysisPlan::new([AnalysisDomain::Header, AnalysisDomain::Symbols]),
)?;
for slice in &document.slices {
    if let DomainState::Complete { value: header, .. } =
        slice.report(domain_reports::HEADER)?
    {
        println!("{}: {}", slice.identity.arch, header.file_type);
    }
    if let DomainState::Complete { value: symbols, issues } =
        slice.report(domain_reports::SYMBOLS)?
    {
        println!("{} symbols, {} issue(s)", symbols.len(), issues.len());
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`domain_reports` also provides typed keys for load commands, segments, exports,
imports, fixups, code signing, strings, ranges, xrefs, audit, and canonical C,
C++, Objective-C, and Swift recovery reports. Typed reads do not change the
schema-version-3 snapshot wire representation.

Plan a mutation, validate placement, and rebuild — the transaction borrows the payload and never relocates existing bytes:

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

File-backed additions extend only the final file-backed segment, and only when its declared range ends exactly at the slice boundary. Load commands grow only through existing zero-filled header slack. `AddSection::new` accepts any borrowed `AsRef<[u8]>` — a slice, a `Vec<u8>`, or a caller-owned read-only `memmap2::Mmap` — stores the payload as a slice, copies only the two fixed-width Mach-O names inline, and allocates no heap of its own. For a file, keep the mapping alive until the transaction commits; a bare `File` can't expose borrowed bytes.

Injected `SignatureProvider` implementations may declare a known ad-hoc or certificate kind; providers that omit `kind()` are opaque, own their own verification, and never expose credentials. The generic verifier accepts only the ad-hoc and certificate mechanisms it understands. Selective analysis builds an `AnalysisPlan` before execution, and snapshot documents (schema version 3) preserve `not_requested`, `complete`, `unsupported`, and `failed` as distinct states — a gap in the data is never silently rendered as a zero.

External transformation engines see exactly one immutable selected image through `macho::evidence::SelectedImageEvidence` and consume strict, bounded, Macho-owned language evidence — never its report, workflow, mutation, or CLI policy. The Swift ABI parsers and their syntax trees stay private to the Macho leaves; an external engine owns only its downstream semantic projection.

## Architecture

The workspace is layered so dependencies flow one direction — a byte-safe core at the bottom, metadata leaves and analysis above it, then mutation, format-local in-memory candidate validation, the façade, and the CLI on top. This is enforced, not aspirational:

- `cargo xtask architecture` enforces dependency direction and source ownership.
- `cargo xtask docs --check` binds this command reference and the diagnostic registry to the code.
- `cargo xtask release --check` binds workspace packaging, CLI, changelog, and lockfiles (`--require-tag` additionally demands clean version-bearing inputs and an exact matching `vX.Y.Z` tag).
- `cargo xtask verify` runs the stable format, lint, docs, test, and benchmark gate.
- `cargo xtask verify-fuzz` builds every fuzz target (nightly Rust).
- `mise run verify` composes both gates, scoping nightly to fuzzing only.

The 21 crates, bottom to top: `macho-core` (parsing) · `macho-symbols` · `macho-demangle` · `macho-codesign` · `macho-dwarf` · `macho-objc` · `macho-swift` · `macho-cpp` · `macho-insn` · `macho-dyld` · `macho-dyld-cache` · `macho-evidence` · `macho-header-syntax` · `macho-header-infer` · `macho-analysis` · `macho-mutate` · `macho-patch` · `macho-workflow` · `macho` (façade) · `macho-cli` · `xtask`.

## Contributing

Run `mise run verify` before opening a PR — it's the same gate CI runs. See [CHANGELOG.md](CHANGELOG.md) for release history and [docs/diagnostic-codes.md](docs/diagnostic-codes.md) for the stable machine-readable diagnostic codes.

## License

Licensed under the [MIT License](LICENSE).
