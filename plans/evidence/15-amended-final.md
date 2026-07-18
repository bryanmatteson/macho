# Amended Architecture and Language-Recovery Final Evidence

Date: 2026-07-18  
Baseline commit: `86ae47d`  
Verdict: `PASS`

This is the completion record for the accepted Gate-3 amendment and the active
plans 10, 13, 15, and 16. It supersedes the historical completion claim in
`15-final.md` and the historical STOP checkpoint in
`15-implementation-report.md`; neither historical record is deleted.

## Delivered contract

- The workspace contains exactly 19 packages. `macho-header-syntax` is the sole
  in-process C/C++/Objective-C AST, parser, renderer, and semantic validator.
- Snapshot schema 3 and the strict prerelease recovery wire are authoritative.
  The amended wire includes `tls`, `runtime_artifact`, `type`, and explicit
  `unknown` selection plus a dedicated `value_type` fact for globals.
- C and C++ reports conserve symbol observations, expose explicit selection and
  collector ledgers, keep conflicts and gaps typed, recover DWARF variables,
  materialize C++ types only from positive anchors, and project only safe typed
  headers.
- Objective-C uses runtime metadata and a typed semantic graph; Swift uses
  descriptor/reflection evidence before conservative symbol fallback. Both
  preserve referenced and partial states rather than manufacturing definitions.
- `info`, `deps`, and `ranges` share ANSI-aware aligned output, color defaults
  on for interactive human output, JSON is escape-free, ordinals are bare and
  right-aligned, and Rust-v0 TLV suffixes survive in-process demangling.
- Production inspection, recovery, demangling, correlation, and header
  validation do not launch host processes. The only production `xcrun` launch
  remains the explicitly isolated signing adapter.

## Gate results

| Gate | Result |
| --- | --- |
| Registry equality, strict schema, rejection, conservation, and referential-integrity fixtures | PASS |
| `cargo xtask architecture` | PASS |
| Direct leaf, analysis, header, workflow, façade, and CLI tests | PASS |
| Talos and iMazing live-corpus assertions | PASS |
| `cargo xtask docs --check` | PASS |
| `cargo xtask release --check` | PASS (`0.2.0`) |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets --all-features` | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS |
| `RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps` | PASS |
| `cargo test --workspace --all-features` | PASS |
| `cargo bench --workspace --all-features --no-run` | PASS, all 19 package targets built |
| `cargo xtask verify` | PASS |
| `cargo +nightly xtask verify-fuzz` | PASS |
| Metadata, tree, version/help, process-boundary, output-byte, and diff checks | PASS |

The first full workspace test exposed an Objective-C header dependency-closure
regression: reparsed `NSString *`-style spellings were not resolved by their
`@class` declarations. The shared validator was corrected, a direct regression
test was added, the failing CLI target passed, and the complete workspace suite
and composed verifier were rerun successfully. Clippy also found one
style-only nested-match issue; it was corrected before the final verifier.

The fuzz verifier requires nightly Rust as documented by `README.md`, CI, and
the task-scoped `mise verify:fuzz` definition. A stable-toolchain invocation
failed before repository compilation on `-Zsanitizer`; the same verifier then
passed under the installed nightly toolchain without changing the default
toolchain.

## Independent evidence

- `cargo metadata --no-deps --format-version 1` reported 19 workspace members,
  including `macho-header-syntax`.
- `cargo tree -p macho-core --depth 1` contained only `bitflags` and `zerocopy`
  as runtime dependencies. `cargo tree -p macho --no-default-features --depth 1`
  contained only `macho-core` as a runtime dependency.
- `target/debug/macho --version` reported `macho 0.2.0`; command help exited 0.
- `git diff --check` exited 0.
- The production process scan found `Command::new("xcrun")` only in
  `crates/macho-cli/src/adapters/signing.rs`; other hits were verifier/test
  tooling or a Mach-O `clang` tool-enum label.
- The rebuilt live CLI emitted 812 escape bytes for `info --color always`, no
  escape bytes for machine output, and aligned segment, section, dependency,
  range, size, source, and ordinal columns.
- The final Talos range probe demangled all sampled Rust-v0 thread-local
  initializers and preserved `$tlv$init`.

## Live-corpus summary

The exact binary hashes and detailed assertions are recorded in
`16-live-corpus.md`. Current decisive results are:

- Talos C: 90,545 observations, 46,358 entities, with 30,995 data, 14,943
  functions, 419 unknown, and exactly one `runtime_artifact` image header.
- iMazing C++ arm64: 423 entities, including 52 imported type entities and zero
  role conflicts. The default 11-entity header selection is fully accounted for
  and validates with `syntax_valid=true` and `semantic_valid=true`.
- iMazing C++ x86_64: 682 entities, including 87 defined and 51 imported type
  entities; no defined type lacks a defined anchor and no imported type has one.
- iMazing Objective-C: arm64 1,029 defined plus 71 referenced; x86_64 1,028
  defined plus 71 referenced; zero diagnostics on both slices.
- iMazing Swift: arm64 693 metadata-defined, 709 partial, 8 referenced; x86_64
  693 metadata-defined, 708 partial, 8 referenced. All 247 diagnostics per slice
  remain explicit rather than being promoted into false definitions.

## Preservation and verifier immutability

The initial dirty-tree digest was
`7eba6be135815d271679fd6861a903f95a82fe6c9890c6382650429b8e9fb305`.
No reset, checkout, clean, or destructive operation was used.

Immediately before and after the composed `cargo xtask verify`, a digest over
`git diff --binary HEAD` plus every sorted untracked path and its SHA-256 was:

```text
pre  4d7d0a339f298b9c99ae96fef2e9cd829c05649e77fbb979a8b222401ed33419
post 4d7d0a339f298b9c99ae96fef2e9cd829c05649e77fbb979a8b222401ed33419
```

The verifier therefore did not rewrite tracked or untracked repository
content. The exception ledger is empty, and A001-A020 are all satisfied.
