# Plan 15 Final Evidence

## Verdict

**COMPLETE.** Plan 15 is implemented as one coherent workspace change. Every
work package WP0-WP10 and every locked obligation S001-S015 is satisfied. No
exceptions or blockers remain.

The implementation began from `main` at `349cace` (`v0.1.3`) with the dirty
worktree recorded in [`15-baseline.md`](15-baseline.md). The completed workspace
contains 18 packages, all at version `0.2.0`.

## Contract result

| Contract area | Result and primary proof |
| --- | --- |
| Workspace graph | The exact 18-member edge matrix and owned third-party dependencies are enforced by metadata-backed positive and exhaustive negative fixtures in `cargo xtask architecture`. |
| Closed core | Core owns structural parsing only; strict/forensic behavior, limits, typed context, private invariant models, duplicate/overlap/alignment/overflow rejection, optional selection, and zero-allocation iteration are tested. Its normal tree contains only `bitflags` and `zerocopy`. |
| Metadata leaves | Symbols, dyld, code signing, DWARF, ObjC, Swift, and C++ have direct crate contracts, typed errors, permitted downward edges, and no host process execution. Demangler dependencies are owned only by `macho-symbols`. |
| Instructions | The strict iterator returns decode failures; lossy decoding records deterministic gaps; mutation fails closed with typed decode/encode sources; analysis propagates gaps; silent result dropping is rejected syntactically. |
| Selective analysis | `AnalysisPlan` resolves the exact required/advisory graph; excluded runners execute zero times and prerequisites at most once; limits truncate with issues; schema v2 represents all four domain states and rejects unversioned, future, or mismatched input. |
| Mutation and workflow | `macho-mutate` has no analysis, workflow, façade, or CLI dependency. Patch application is all-or-nothing and strictly reparsed. `macho-workflow` alone owns selected before/after analysis and semantic diff. |
| Module seams and adapters | C reconstruction, C++ ABI, diff including `report.rs`, and patch including `trampoline.rs` use the declared seams. Syntax-aware production-line and process-boundary checks pass. Fake adapters work everywhere and real adapters are CLI-owned. |
| Façade | The exact feature matrix is enforced; no-default depends only on core; individual, default, full, and combined features compile. The façade is library-only and contains no commands, inputs, Clap, memory mapping, or `anyhow`. |
| CLI | The canonical flat grammar, shared arguments, `--format`, JSON envelope, SARIF success format, injected writers, atomic file replacement, typed CLI errors, and centralized exit codes 0/1/2/3 are implemented. Representative live-process and injected calls are byte-identical. |
| Authorities and delivery | README command reference, examples, diagnostic registry, workspace/CLI/changelog/tag versions, CI, deterministic fixtures and corpora, seven fuzz targets, and Criterion benchmarks have executable checks. |

## Authoritative final gate

The final `cargo xtask verify` ran in the required order and passed:

| Ordered command | Result |
| --- | --- |
| `cargo xtask architecture` | PASS |
| `cargo xtask docs --check` | PASS |
| `cargo xtask release --check` | PASS (`0.2.0`) |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --all-targets --all-features` | PASS |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | PASS |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps` | PASS |
| `cargo test --workspace --all-features` | PASS |
| `cargo bench --workspace --all-features --no-run` | PASS |
| `cargo fuzz build` | PASS for all seven targets |

The content digest over `git diff --binary` plus the content of every untracked
file was identical before and after that final run:

```text
d800cab6dea63df640949ec737885c237443bfa729365d0ec9ee2e7a3302cd5c
```

This is direct evidence that the final verifier did not modify the source or
evidence tree.

## Independent evidence

The second-route inspections required by the plan passed after the verifier:

- `cargo metadata --no-deps --format-version 1`: 18 packages, every package at
  `0.2.0`.
- `cargo tree -p macho-core --depth 1`: normal dependencies are exactly
  `bitflags` and `zerocopy`.
- `cargo tree -p macho-mutate --depth 2`: core, insn, dyld, and codesign leaf
  dependencies only; no analysis, workflow, façade, or CLI edge.
- `cargo tree -p macho --no-default-features --depth 2`: core only as a normal
  dependency.
- `cargo run -q -p macho-cli -- --help`: all 25 canonical commands are accepted
  and only `--format text|json|sarif` is documented.
- `cargo run -q -p macho-cli -- --version`: `macho 0.2.0`.
- `production_and_injected_io_are_byte_identical`: missing input, malformed
  parse, missing architecture, semantic usage error, policy report, successful
  file output, and failed replacement produce identical exit status and exact
  stdout/stderr bytes through the live process and injected path.
- Syntax-aware source audit: process launches occur only in CLI adapters,
  xtask, and integration tests; demangler crates occur only in
  `macho-symbols`; removed `ImageInspector`, silent instruction drops, legacy
  format flags, direct CLI output, public `&Vec`, and mutation string-result
  surfaces are rejected.

## Fuzz and host-adapter execution

Each target completed a bounded 64-run smoke execution without a crash or
assertion failure:

```text
container
load_commands
dyld
codesign
insn
mutation
cache_fileset
```

The deterministic corpus writer then restored the exact committed seed set,
and `cargo test -p macho-test-support --test fuzz_corpus` passed. The separate
macOS adapter command
`cargo test -p macho-cli --test adapter_tests -- --ignored` also passed both
real `xcrun` SDK-locator and Swift-demangler smokes.

## Pre-existing change accounting (S014)

Every path present before implementation is retained in its final owner or
intentionally replaced by the Plan 15 authority:

| Baseline path or change | Final disposition |
| --- | --- |
| `Cargo.toml` | Preserved while becoming the 18-member workspace/version/dependency authority. |
| `macho-analysis/src/abi.rs` | Preserved in analysis and migrated to explicit lossy instruction handling. |
| `audit/rules/load_paths.rs`, `audit/rules/mod.rs` | Preserved in the selective audit rule registry. |
| `diff/compare.rs` | Preserved by responsibility across `diff/container.rs`, `structure.rs`, `symbols.rs`, `metadata.rs`, `diagnostics.rs`, `document.rs`, and `report.rs`. |
| `reconstruct/cpp/abi.rs` | Preserved in the `macho-cpp/src/abi/` leaf seam. |
| Core code-directory and superblob changes | Preserved in `macho-codesign`. |
| Core dyld export changes | Preserved in `macho-dyld`. |
| `core/format/fat.rs` | Preserved and strengthened by closed construction, alignment, duplicate, overlap, bounds, and limit validation. |
| `core/format/symbols.rs` | Preserved as structural parsing; presentation/demangling moved to `macho-symbols`. |
| `core/model/addr/mod.rs` and untracked `ptrauth.rs` | Preserved in the closed core address model. |
| Core ObjC method changes | Preserved in `macho-objc`. |
| Core pointer-resolution changes | Preserved in `macho-dyld`. |
| Core RTTI typeinfo changes | Preserved in `macho-cpp`. |
| `macho-insn` ARM64, x86-64, library, and test changes | Preserved and upgraded to the strict/lossy explicit-failure contract. |
| `macho-mutate/src/sign.rs` | Preserved behind the injected `SignatureProvider` boundary. |
| Façade dyld-cache input changes | Preserved in `macho-dyld-cache`; filesystem delivery moved to the CLI. |
| Plans 14 and README | Preserved as historical context and updated to identify Plan 15 as canonical. |
| Untracked core invalid-input tests | Preserved and expanded with typed zero-arch, duplicate, alignment, truncation, overlap, and bounds fixtures. |
| Untracked Plan 15 | Preserved as the immutable implementation authority. |

No unrelated change was reset, discarded, staged, or committed.

## Traceability closure

S001-S015 are all complete in [`15-ledger.md`](15-ledger.md). Every audit row
has an owning package, primary executable proof, and an invalid fixture. The
exception ledger is empty.
