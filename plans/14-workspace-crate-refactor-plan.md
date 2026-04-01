# Plan: Workspace and Crate Boundary Refactor

## Status

This is the concrete plan for splitting `macho` from one large package into a
workspace with a small number of real, reusable crates.

The goal is not to create a crate per directory. The goal is to produce crate
boundaries that represent publishable product surfaces, reduce cross-layer
coupling, and preserve a stable top-level `macho` API during the transition.

## Objective

Refactor the repository from the current single-package layout into a workspace
with:

- a parser and model foundation crate
- small leaf crates for independently reusable binary subsystems
- a facade crate that preserves the current ergonomic `macho` API
- a CLI crate that depends on the facade instead of sharing one package with it

## Why This Matters

The current package exposes every layer at once:

- byte parsing and binary model
- dyld, codesign, ObjC, Swift, and C++ analysis
- snapshot, diff, audit, and container reporting
- patching and edit transactions
- CLI dispatch and output capture

That creates three problems:

- public API sprawl: [`src/lib.rs`](../src/lib.rs) exports nearly every module
- false layering: core model types currently depend on analysis/reporting code
- reuse friction: downstream users cannot depend on narrow surfaces like
  “Mach-O parser only” or “codesign parser only”

## Current Repo Reality

The plan is anchored to the current codebase, not an aspirational redesign.

### Current Package Shape

- one root package with both library and binary targets in
  [`Cargo.toml`](../Cargo.toml)
- top-level module export surface in [`src/lib.rs`](../src/lib.rs)
- CLI entrypoint and command router in [`src/main.rs`](../src/main.rs) and
  [`src/cli.rs`](../src/cli.rs)

### Current Foundation Layer

These modules already form the read/parse/model base:

- [`src/addr/`](../src/addr)
- [`src/constants.rs`](../src/constants.rs)
- [`src/error.rs`](../src/error.rs)
- [`src/ext.rs`](../src/ext.rs)
- [`src/io/`](../src/io)
- [`src/model/`](../src/model)
- [`src/parse/`](../src/parse)
- [`src/validate/`](../src/validate)

### Current Cross-Layer Violations

These are the concrete seams that must be fixed before the split is clean:

- [`src/model/container.rs`](../src/model/container.rs) currently depends on
  snapshots, container analysis, and diff logic, which means a core model type
  points upward into higher-level analysis layers
- [`src/edit/transaction.rs`](../src/edit/transaction.rs) currently depends on
  snapshot diffing, validation, and resign-preview logic in addition to editing
- [`src/depgraph/mod.rs`](../src/depgraph/mod.rs) re-exports
  `inspect::DylibLinkKind`, which inverts ownership of a lower-level concept
- [`src/swift/mod.rs`](../src/swift/mod.rs) enriches results from ObjC
  metadata, so Swift is not an independent leaf today
- [`src/cpp/mod.rs`](../src/cpp/mod.rs) depends on
  [`src/data_surface/vtable.rs`](../src/data_surface/vtable.rs), which means
  that vtable analysis is really part of the current C++ product surface

## Refactor Principles

### Real Crate Rule

Every extracted crate must represent one of:

- a parser/model foundation
- a reusable binary subsystem
- a stable analysis/reporting layer
- an editing subsystem
- a facade or delivery surface

Do not create tiny support crates for `error`, `addr`, `io`, `commands`, or
other implementation substrate.

### Facade Preservation Rule

Keep a top-level `macho` crate as the public integration surface while the
refactor is in flight. Existing users should not be forced to rewrite imports
immediately.

### No Upward Core Dependencies

Core crates must not depend on:

- snapshot/diff/audit code
- ObjC, Swift, C++, or codesign subsystems
- CLI or output-capture code

## Target Workspace

```text
/Users/bryan/Code/macho
  Cargo.toml
  crates/
    macho-core/
    macho-dyld/
    macho-codesign/
    macho-objc/
    macho-cpp/
    macho-analysis/
    macho-edit/
    macho-dyld-cache/
    macho-header-infer/
    macho/
    macho-cli/
```

## Target Crates

### `macho-core`

Responsibility: parse, model, address translation, and validation.

Move here:

- `src/addr/`
- `src/constants.rs`
- `src/error.rs`
- `src/ext.rs`
- `src/io/`
- `src/model/` except `model/owned.rs`
- `src/parse/`
- `src/validate/`

Public role:

- `parse(&[u8]) -> MachoContainer`
- read-only Mach-O and fat-container types
- shared extension traits like `MachoExt`
- structural validation diagnostics

Must not own:

- snapshot generation
- diffing
- audit reports
- container parity reports
- ObjC, Swift, C++, dyld, or codesign parsing

### `macho-dyld`

Responsibility: dyld metadata parsing.

Move here:

- `src/dyld/`

Depends on:

- `macho-core`

Public role:

- bind/rebase parsing
- chained fixups
- exports trie
- dyld metadata value types

### `macho-codesign`

Responsibility: code-signature parsing and metadata extraction.

Move here:

- `src/codesign/`

Depends on:

- `macho-core`

Public role:

- `LC_CODE_SIGNATURE` decoding
- CodeDirectory extraction
- entitlements and CMS presence

### `macho-objc`

Responsibility: Objective-C and Swift surface recovery.

Move here:

- `src/objc/`
- `src/swift/`

Depends on:

- `macho-core`
- `macho-dyld`

Public role:

- ObjC metadata parsing
- ObjC graphing and rendering
- Swift type discovery from symbols plus ObjC metadata

Rationale:

`swift` is not a clean separate crate yet because it already imports
ObjC-derived facts.

### `macho-cpp`

Responsibility: C++ symbol, RTTI, vtable, and header reconstruction.

Move here:

- `src/cpp/`
- `src/demangle.rs`
- `src/data_surface/vtable.rs`

Depends on:

- `macho-core`
- `macho-dyld`

Public role:

- demangling helpers
- symbol IR
- RTTI and vtable indexing
- unified header rendering

Rationale:

The current vtable implementation is part of the C++ recovery stack, not an
independent product surface.

### `macho-analysis`

Responsibility: owned snapshot and reporting layer.

Move here:

- `src/analysis/`
- `src/diff/`
- `src/audit/`
- `src/container_analysis/`

Depends on:

- `macho-core`
- `macho-dyld`
- `macho-codesign`
- `macho-objc`

Public role:

- deterministic snapshots
- semantic diff reports
- audit rules and report formats
- fat/fileset parity and cross-slice resolution

### `macho-edit`

Responsibility: structural binary editing.

Move here:

- `src/edit/`
- `src/model/owned.rs`

Depends on:

- `macho-core`

Optional feature:

- `preview`: depends on `macho-analysis` and `macho-codesign`

Public role:

- load-command editing
- rebuild/layout logic
- owned mutable image/container types
- raw byte patch support

Rationale:

The editing engine is reusable. Preview-generation is integration logic and
should not define the core crate boundary.

### `macho-dyld-cache`

Responsibility: dyld shared cache indexing and extraction.

Move here:

- `src/dyld_cache/`

Depends on:

- `macho-core`

Public role:

- cache header parsing
- mapping and image enumeration
- extraction of embedded image bytes for further parsing

### `macho-header-infer`

Responsibility: deterministic declaration recovery plus LLM-facing header
inference workflow.

Move here:

- `src/dwarf/`
- `src/c/`
- `src/header_infer/`

Depends on:

- `macho-core`
- possibly `macho-cpp` later if cross-linking is needed

Public role:

- DWARF loading
- deterministic C declaration extraction
- evidence bundling and validation for LLM-assisted header inference

Status note:

This should be a second-wave extraction after the core workspace exists.

### `macho`

Responsibility: public facade and integration crate.

Own here:

- re-exports from all lower-level crates
- integration-only modules:
  - `src/inspect/`
  - `src/depgraph/`
  - `src/xref/`
  - `src/data_surface/strings.rs`
  - `src/prelude.rs`

Depends on:

- `macho-core`
- `macho-dyld`
- `macho-codesign`
- `macho-objc`
- `macho-cpp`
- `macho-analysis`
- `macho-edit`
- `macho-dyld-cache`
- `macho-header-infer` once extracted

Public role:

- compatibility surface for existing users
- integration-heavy APIs that intentionally compose multiple subsystems

### `macho-cli`

Responsibility: command-line delivery only.

Move here:

- `src/main.rs`
- `src/cli.rs`
- `src/commands/`
- `src/output/`

Depends on:

- `macho`

Public role:

- command parsing
- user-facing text/JSON output
- CLI-specific capture and formatting behavior

## Dependency Graph

The target graph should look like this:

```text
macho-core
├── macho-dyld
├── macho-codesign
├── macho-dyld-cache
├── macho-edit
├── macho-objc
│   └── macho-dyld
├── macho-cpp
│   └── macho-dyld
├── macho-analysis
│   ├── macho-dyld
│   ├── macho-codesign
│   └── macho-objc
├── macho-header-infer
└── macho

macho
├── macho-core
├── macho-dyld
├── macho-codesign
├── macho-objc
├── macho-cpp
├── macho-analysis
├── macho-edit
├── macho-dyld-cache
└── macho-header-infer

macho-cli
└── macho
```

## Non-Goals

Do not create separate crates for:

- `addr`
- `error`
- `io`
- `commands`
- `output`
- `constants`
- `data_surface` as a whole

Those are implementation layers or mixed-content modules, not stable reusable
products.

## Required Pre-Extraction Cleanup

### Cleanup 1: Remove Upward Dependencies from `model::container`

Before `macho-core` exists, trim [`src/model/container.rs`](../src/model/container.rs)
so core container types only expose model-centric operations:

- `is_thin`
- `is_fat`
- `macho_files`
- `first_mach`
- arch lookup helpers

Move these behaviors out of the core type:

- snapshot generation
- parity reporting
- fileset inspection reports
- cross-image resolution helpers
- diff helpers
- security posture helpers

Reintroduce them in `macho-analysis` or as facade-level extension traits in
`macho`.

### Cleanup 2: Split Editing from Preview Reporting

[`src/edit/transaction.rs`](../src/edit/transaction.rs) currently mixes:

- editing intent
- preview diff generation
- validation
- resign assistance

Refactor target:

- keep pure editing and byte production in `macho-edit`
- move preview/report assembly to a facade or optional feature layer

### Cleanup 3: Rehome `DylibLinkKind`

Move `DylibLinkKind` out of `inspect` into a lower-level crate, likely
`macho-core` or `macho-dyld`, so `depgraph` does not depend on `inspect` for a
fundamental dylib classification type.

### Cleanup 4: Move `model::owned` Out of Core

[`src/model/owned.rs`](../src/model/owned.rs) is a mutable editing-oriented
surface. It should ship with `macho-edit`, not with the read-only core model.

## Phased Refactor

### Phase 1: Establish the Workspace

Goal: create a working workspace without extracting every subsystem at once.

Create:

- `macho-core`
- `macho`
- `macho-cli`

Work:

- move foundation modules into `macho-core`
- keep `macho` as the top-level facade crate
- move CLI code into `macho-cli`
- preserve current import ergonomics by re-exporting `macho-core` from `macho`

Acceptance:

- `cargo test --workspace` passes
- `macho` still exposes the current high-level API
- the CLI builds from `macho-cli`

### Phase 2: Extract Leaf Binary Subsystems

Goal: make reusable parsers available without dragging in the full facade.

Create:

- `macho-dyld`
- `macho-codesign`
- `macho-dyld-cache`

Work:

- move each subsystem with minimal semantic change
- redirect facade re-exports to the new crates

Acceptance:

- downstream users can depend on these crates independently
- no leaf crate depends on `macho`

### Phase 3: Extract Analysis and Editing

Goal: separate reporting and mutation from the core parser.

Create:

- `macho-analysis`
- `macho-edit`

Work:

- move snapshot, diff, audit, and container analysis into one reporting crate
- move owned mutable model and editing machinery into one editing crate
- keep preview/report glue out of the core editing engine

Acceptance:

- `macho-core` has no dependency on analysis or editing
- edit flows still support current CLI behavior through the facade

### Phase 4: Extract Language Recovery Stacks

Goal: package language-specific recovery pipelines as reusable products.

Create:

- `macho-objc`
- `macho-cpp`
- `macho-header-infer`

Work:

- group ObjC and Swift together
- group C++ and vtable analysis together
- move DWARF/C/header inference into a dedicated recovery crate

Acceptance:

- language-recovery clients can choose narrow dependencies
- integration-heavy tools can still use the top-level `macho` facade

## Concrete Move Map by Phase

### Phase 1

- to `macho-core`:
  - `addr`
  - `constants`
  - `error`
  - `ext`
  - `io`
  - `model` except `owned`
  - `parse`
  - `validate`
- to `macho-cli`:
  - `main`
  - `cli`
  - `commands`
  - `output`
- remain in `macho` facade:
  - everything else

### Phase 2

- to `macho-dyld`: `dyld`
- to `macho-codesign`: `codesign`
- to `macho-dyld-cache`: `dyld_cache`

### Phase 3

- to `macho-analysis`:
  - `analysis`
  - `diff`
  - `audit`
  - `container_analysis`
- to `macho-edit`:
  - `edit`
  - `model/owned.rs`

### Phase 4

- to `macho-objc`:
  - `objc`
  - `swift`
- to `macho-cpp`:
  - `cpp`
  - `demangle`
  - `data_surface/vtable.rs`
- to `macho-header-infer`:
  - `dwarf`
  - `c`
  - `header_infer`

## Facade Policy

The facade crate must:

- preserve `macho::parse`
- preserve `macho::model::*` access
- preserve the current high-level command-facing analysis APIs
- own integration-centric modules like `inspect`, `depgraph`, and `xref`

The facade crate must not:

- become the only place where lower-level crates are usable
- reintroduce cyclic ownership between core and analysis crates

## Test Migration Strategy

### Move to `macho-core`

Tests that only cover parsing, model behavior, owned-free address translation,
or validation should move into `crates/macho-core/tests`.

Likely candidates:

- parser and synthetic parse tests
- symbol and relocation parsing tests
- validation-focused tests

### Keep in `macho`

Tests that exercise composed features should stay in `crates/macho/tests` until
later extraction phases are complete.

Likely candidates:

- audit tests
- diff tests
- ObjC graph tests
- container analysis tests
- edit preview tests
- dependency graph and compatibility tests

### Move Later

After subsystem extraction, move focused tests beside their owning crates.

## Risks

### Risk 1: Crate Explosion Without Real Reuse

Too many small crates would increase churn and versioning cost without adding
meaningful independence.

Mitigation:

- only extract the crates listed in this document
- keep support layers inside larger product crates

### Risk 2: Compatibility Breakage During Phase 1

Moving modules too aggressively can force large downstream import changes.

Mitigation:

- keep `macho` as the facade crate
- use re-exports aggressively during the transition

### Risk 3: Hidden Core Backedges Survive the Split

If `macho-core` still references analysis or reporting code, later extraction
will stall.

Mitigation:

- make the `model::container` cleanup a hard prerequisite
- reject any new `macho-core -> analysis` dependency during review

### Risk 4: Editing APIs Stay Coupled to Reporting

If preview-generation stays fused to editing, `macho-edit` will remain a
pseudo-facade instead of a reusable editing crate.

Mitigation:

- define a pure editing API first
- keep reporting as a wrapper or optional feature

## Recommended Execution Order

1. create `macho-core`, `macho`, and `macho-cli`
2. remove upward dependencies from `model::container`
3. extract `macho-dyld`, `macho-codesign`, and `macho-dyld-cache`
4. extract `macho-analysis`
5. extract `macho-edit`
6. extract `macho-objc`
7. extract `macho-cpp`
8. extract `macho-header-infer`

This order minimizes rework because the leaf parser crates and the analysis
crate depend on a stable core split.

## Done Means

The refactor is complete when:

- the repository builds as a workspace
- `macho-core` is free of upward dependencies
- reusable parser/editing/reporting subsystems are available as separate crates
- the top-level `macho` crate remains a coherent facade
- the CLI is a delivery crate, not a mixed library/binary package
- crate boundaries correspond to real reusable surfaces rather than directory
  names
