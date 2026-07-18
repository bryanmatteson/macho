# Historical Completion Record: ObjC/Swift Semantic Analysis

## Status

This document records the completed pre-workspace ObjC/Swift graph work. It is
not an implementation authority. Plan 10 now owns Objective-C behavior, and plan
15 owns crate placement, `Analyzer`, selective execution, Swift behavior, and
CLI delivery.

Names and paths below describe the implementation at the time of completion.
In particular, references to plan 06's `ImageInspector` are historical and do
not authorize restoring that type; plan 15 requires its deletion.

## Objective

Turn the existing ObjC graph and Swift type discovery baseline into a stable
semantic API that answers runtime questions directly:

- which class or category implements a selector
- where the effective implementation lives after category folding
- whether a class responds to a selector directly or via inheritance
- which Swift types can be surfaced with high confidence

## Why This Matters

The repository already parses ObjC metadata and exposes a first-pass
`ObjCGraph` and `SwiftTypeIndex`, but downstream consumers still need ad hoc
logic for method lookup, inheritance, and selector ownership. The semantic
graph should be the single source of truth for CLI output, diff/audit context,
and future integration APIs.

## Current Repo Leverage

- `src/objc/graph.rs`
- `src/objc/mod.rs`, `src/objc/resolve.rs`
- `src/swift/mod.rs`, `src/swift/types.rs`
- `src/commands/objc.rs`, `src/commands/swift.rs`

## Scope

### In Scope

- stable query methods on `ObjCGraph`
- category folding with explicit origin tracking
- inherited method resolution
- `MethodKind`, `AllMethods`, selector ownership helpers
- `objc_graph()` and Swift helpers on the inspection API from plan 06
- stable JSON-friendly output for ObjC and Swift queries

### Out of Scope

- full Swift ABI modeling
- disassembly-backed callgraph reconstruction
- decompiler-style semantic recovery

## Design

Keep one owned semantic layer per domain:

- `ObjCGraph` remains the canonical runtime model for classes, categories,
  protocols, selectors, and effective methods.
- Query helpers live on `ObjCGraph` rather than in a parallel resolver type.
- `SwiftTypeIndex` stays intentionally shallow: descriptor- and
  demangle-driven, explicit about unknown or partial cases.
- CLI commands become thin views over these APIs instead of bespoke parsers.

## Milestones

### Milestone 1: Graph Hardening

Goal: make the current graph trustworthy as a library surface.

Work:

- normalize category folding and method-origin tracking
- add `MethodKind`
- add `find_method`, `implementations_of`, and `responds_to`
- make superclass traversal explicit and cycle-safe

Acceptance:

- direct and category-provided methods resolve through one API
- selector ownership is deterministic and testable
- missing methods return `None`, not guessed symbol matches

### Milestone 2: Runtime-Oriented Resolution

Goal: answer the concrete lookup questions downstream tools need.

Work:

- add `method_impl_va` and `method_impl_offset`
- add `resolve_inherited`
- add `all_methods` / `AllMethods`
- preserve provenance for class-vs-category implementations

Acceptance:

- a caller can resolve a class/selector/kind tuple to VA and file offset
- inherited lookups identify the class that actually owns the implementation
- category and stripped-binary cases stay explicit instead of heuristic

### Milestone 3: Inspector and CLI Integration

Goal: make the semantic graph the shared product surface.

Work:

- expose `objc_graph()` and Swift helpers from the then-current plan 06
  `ImageInspector` (historical only; superseded by plan 15's `Analyzer`)
- align `macho objc` and `macho swift` with the shared model
- add stable JSON output paths for graph queries

Acceptance:

- CLI and library consumers use the same graph semantics
- `ObjCGraph` is reusable by plan 07 for code-entity resolution
- Swift type output clearly marks high-confidence vs partial discovery

## Dependencies

- plan 06 provides the stable cached inspection entrypoint
- plan 07 builds on this for `CodeEntity::ObjCMethod` and xref ownership

## Risks

- category ordering can differ from runtime load-order edge cases
- Swift metadata surfacing can sprawl if scope is not kept narrow

## Mitigations

- document category-folding semantics explicitly
- keep Swift support descriptor-first and mark unknowns instead of inferring

## Done Means

- `ObjCGraph` is the canonical method-resolution API
- CLI output, patching helpers, and future integrations stop guessing via
  mangled symbol names
- Swift-aware output exists without pretending to fully model the Swift runtime
