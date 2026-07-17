# Plan 15 Baseline Evidence

Captured on 2026-07-16 from `main` at `349cace` (`v0.1.3`) before Plan 15
implementation edits. The worktree already contained user changes; the exact
pre-existing paths are recorded below and are preserved as implementation
inputs rather than reset.

## Pre-existing worktree changes

Modified:

- `Cargo.toml`
- `crates/macho-analysis/src/abi.rs`
- `crates/macho-analysis/src/audit/rules/load_paths.rs`
- `crates/macho-analysis/src/audit/rules/mod.rs`
- `crates/macho-analysis/src/diff/compare.rs`
- `crates/macho-analysis/src/reconstruct/cpp/abi.rs`
- `crates/macho-core/src/codesign/codedir.rs`
- `crates/macho-core/src/codesign/superblob.rs`
- `crates/macho-core/src/dyld/exports.rs`
- `crates/macho-core/src/format/fat.rs`
- `crates/macho-core/src/format/symbols.rs`
- `crates/macho-core/src/model/addr/mod.rs`
- `crates/macho-core/src/objc/method.rs`
- `crates/macho-core/src/resolve/pointers.rs`
- `crates/macho-core/src/rtti/typeinfo.rs`
- `crates/macho-insn/src/arm64.rs`
- `crates/macho-insn/src/lib.rs`
- `crates/macho-insn/src/tests.rs`
- `crates/macho-insn/src/x86_64.rs`
- `crates/macho-mutate/src/sign.rs`
- `crates/macho/src/inputs/dyld_cache/mod.rs`
- `plans/14-workspace-crate-refactor-plan.md`
- `plans/README.md`

Untracked:

- `crates/macho-core/src/model/addr/ptrauth.rs`
- `crates/macho-core/tests/invalid_input.rs`
- `plans/15-architecture-coherence-implementation-plan.md`

## Baseline probes

| Probe | Result | Evidence |
| --- | --- | --- |
| `cargo metadata --no-deps --format-version 1` | Passed | Six workspace packages at `0.1.0`; no Plan 15 leaf, workflow, test-support, or xtask packages exist. |
| `cargo tree --workspace --edges normal` | Passed as a command; architecture invalid | `macho-core` owns `serde`, demanglers, and `gimli`; `macho-mutate` depends on `macho-analysis`; `macho` owns Clap, `memmap2`, and `anyhow`. |
| `cargo test --workspace --all-features` | Passed | All discovered workspace unit, integration, and doc-test targets completed successfully. One unused-variable warning remains in C++ ABI tests. |
| `cargo fmt --all -- --check` | Failed | Formatting differences span the current workspace, including pre-existing user edits. |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | Failed | First failures: redundant field names in `format/fat.rs` and a derivable implementation in `dwarf/types.rs`. |
| `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps` | Failed | Broken intra-doc link to `read_pointer` in `resolve/pointers.rs`. |
| `cargo run -q -p macho-cli -- --help` | Passed | Live router exposes the canonical flat command set from `info` through `cache`. |
| `cargo run -q -p macho-cli -- --version` | Passed as a command; release authority invalid | Printed `macho 0.1.0` while `HEAD` is exactly tagged `v0.1.3`. |
| README command probe | Failed | README still teaches `view`, `extract`, `compare`, `dyld-cache`, `--json`, and `--sarif`, none of which match the Plan 15 grammar/format contract. |
| Capture ownership probe | Failed architecture contract | `run_captured` and output capture live under the façade; commands still contain direct printing. |

## Baseline falsification results

The baseline independently reproduces the plan's critical architecture claims:

1. core is not a small structural parser dependency;
2. mutation has an upward dependency on analysis;
3. the façade is also the delivery implementation;
4. documentation and the live command router disagree;
5. package, CLI, and exact-tag versions disagree; and
6. tests alone are green while format, lint, documentation, and architecture
   contracts are red.
