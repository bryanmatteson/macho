# Plan: `macho diff`

## Objective

Add a semantic diff engine that compares two Mach-O binaries by meaning rather
than by raw bytes. The result should be useful in CI, release review, and
reverse-engineering workflows.

## Why This Matters

The current CLI is inspection-oriented and single-input oriented. It can print
headers, symbols, imports, exports, ObjC metadata, and code-signing state, but
it cannot answer "what changed?" across two builds. A strong `diff` command
would turn the tool into a release gate instead of just an inspector.

## Current Repo Leverage

- Existing command structure: `src/main.rs`, `src/commands/`
- Existing domain parsers:
  - symbols: `src/commands/symbols.rs`
  - exports/imports/fixups: `src/dyld/`, `src/commands/exports.rs`,
    `src/commands/imports.rs`, `src/commands/fixups.rs`
  - ObjC: `src/objc/`
  - code signing: `src/codesign/`
  - validation: `src/validate/`

## Scope

### In Scope

- Compare thin binaries and fat binaries
- Compare per-arch slices
- Compare:
  - header and platform metadata
  - load commands
  - symbols and exported symbols
  - dyld imports and fixups
  - code-signing facts and entitlements presence/content
  - ObjC surface: classes, categories, protocols, selectors
  - structural validation regressions
- Emit text and JSON
- Support CI exit codes based on severity

### Out of Scope

- Raw disassembly diffs
- Full instruction-level semantic analysis
- Shared-cache-aware multi-image diffing in the first milestone

## Design

Create an owned `snapshot` layer that normalizes each parsed domain into stable
serializable data. The diff engine should compare snapshots, not terminal
output. This keeps the logic testable and reusable for later `audit` and
multi-image features.

Core types to add:

- `analysis::snapshot::SliceSnapshot`
- `analysis::snapshot::ContainerSnapshot`
- `diff::DiffReport`
- `diff::DiffFinding`
- `diff::ChangeSeverity`

## Milestones

### Milestone 1: Snapshot Foundation

Goal: normalize one binary into a stable analysis object.

Work:

- Add `src/analysis/mod.rs`
- Add `src/analysis/snapshot.rs`
- Add `src/analysis/container.rs`
- Add `serde` support in `Cargo.toml`
- Build snapshot extractors for:
  - header/load commands
  - symbols
  - dyld exports/imports/fixups
  - ObjC surface
  - code-signing facts
  - validation findings

Acceptance:

- A binary can be converted into a stable JSON snapshot
- Snapshot tests do not depend on current text formatting

### Milestone 2: Domain Comparators

Goal: compare snapshots by domain.

Work:

- Add `src/diff/mod.rs`
- Add `src/diff/compare.rs`
- Add `src/diff/classify.rs`
- Implement comparators for:
  - container and architecture presence
  - load commands
  - symbols and exports
  - imports/fixups
  - ObjC
  - code-signing
  - validation regressions

Acceptance:

- Domain diffs are independently testable
- Breaking and non-breaking changes are distinguishable

### Milestone 3: CLI and UX

Goal: expose the feature as a user-facing command.

Work:

- Add `src/commands/diff.rs`
- Wire the command into `src/commands/mod.rs` and `src/main.rs`
- Add flags:
  - `--arch`
  - `--json`
  - `--fail-on <severity>`
  - `--ignore-codesign`
  - `--ignore-objc`
  - `--ignore-symbols`

Acceptance:

- Text output is concise and grouped by severity/domain
- `--json` returns stable machine-readable output
- Exit code can fail CI on configured severity

## Suggested PR Breakdown

### PR 1

Add `analysis::snapshot` types and serialization.

Files:

- `src/analysis/mod.rs`
- `src/analysis/snapshot.rs`
- `src/analysis/container.rs`
- `Cargo.toml`
- `tests/diff_snapshot_tests.rs`

### PR 2

Add comparator engine and findings model.

Files:

- `src/diff/mod.rs`
- `src/diff/compare.rs`
- `src/diff/classify.rs`
- `tests/diff_engine_tests.rs`

### PR 3

Add CLI, human output, README docs, and golden tests.

Files:

- `src/commands/diff.rs`
- `src/commands/mod.rs`
- `src/main.rs`
- `tests/diff_cli_tests.rs`
- `README.md`

## Test Plan

- Synthetic fixture pairs:
  - removed export
  - added `LC_RPATH`
  - changed dylib load path
  - removed architecture from fat binary
  - changed entitlement blob
  - added ObjC category method
- Snapshot tests for JSON output
- CLI golden tests for text output

## Risks

- Diff noise if snapshot granularity is not chosen carefully
- Large output on binaries with many symbols
- Entitlement comparison may need content normalization

## Mitigations

- Keep default diff semantic and concise
- Offer domain filters and ignore flags
- Treat symbol table diffs and export diffs separately

## Done Means

- `macho diff old new` works for thin and fat binaries
- Output is useful both for humans and CI
- Tests cover common compatibility regressions
