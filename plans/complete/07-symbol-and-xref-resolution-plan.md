# Plan: Symbol Ranges and Cross-Reference Resolution

## Status

This plan combines the earlier callsite/xref draft and the separate
symbol-range draft into one address-resolution track.

## Objective

Replace byte-pattern guessing and zero-size symbol heuristics with structured
APIs for:

- code/data ownership by VA and file-offset range
- stub, relocation, and import-backed references
- direct branch/callsite discovery in known code sections

## Why This Matters

These capabilities are tightly coupled. Range ownership without xrefs still
leaves callsites ambiguous; xrefs without stable ownership still leave symbol
sizes guessed. One canonical address model should back both features.

## Current Repo Leverage

- `src/model/symbol.rs`
- `src/model/section.rs`, `src/model/segment.rs`
- `src/addr/`
- `src/dyld/bind.rs`, `src/dyld/chained.rs`, `src/dyld/exports.rs`
- `src/model/relocation.rs`
- `src/edit/patch.rs`
- `src/objc/graph.rs`

## Scope

### In Scope

- `SymbolRangeIndex` for named ownership and reverse lookup
- `xref` APIs that unify relocations, fixups, stubs, and direct branches
- `CodeEntity` helpers for symbols, ObjC methods, and raw VAs
- JSON-friendly CLI and library queries

### Out of Scope

- full disassembly
- dataflow analysis
- shared-cache-wide callgraph reconstruction

## Design

Split the implementation into two cooperating layers:

- `ranges`: authoritative ownership and sizing of addressable entities
- `xref`: references between those entities and external imports/providers

Both layers should plug into plan 06's `ImageInspector` so downstream tools can
cache one address model per slice.

## Milestones

### Milestone 1: Range Ownership

Goal: make address ownership deterministic.

Work:

- add `SymbolRangeIndex`
- size entries by next higher address or section end
- merge nlist symbols, exports, and ObjC method implementations
- add reverse lookup by VA and file offset

Acceptance:

- symbols and ObjC methods have explicit ownership ranges
- alt-entry and unknown-boundary cases stay explicit

### Milestone 2: Xref Extraction

Goal: resolve the references that point at those owned ranges.

Work:

- add stub resolution from indirect symbol tables
- add chained-fixup and legacy-bind reference extraction
- add relocation-backed references
- add minimal arm64/x86_64 direct-branch decoding in known code sections

Acceptance:

- callers can enumerate references in a range or to a target
- import-backed references preserve provider/ordinal context when known

### Milestone 3: Higher-Level Queries and Integration

Goal: make the result usable by the rest of the roadmap.

Work:

- add `CodeEntity` helpers for symbols, ObjC methods, and raw VAs
- expose cached builders on `ImageInspector`
- add CLI commands or subcommands for ranges and xrefs

Acceptance:

- plan 04 can resolve `ObjCMethod` entities into owned code ranges
- patching and analysis workflows stop scanning arbitrary byte windows

## Dependencies

- depends on plan 04 for semantic ObjC method lookup
- depends on plan 06 for the canonical slice entrypoint
- feeds plan 09 for vtable-slot and string-reference ownership

## Risks

- x86_64 branch scanning can produce false positives without section limits
- stripped binaries reduce name quality even when address ownership is correct

## Mitigations

- restrict branch decoding to known executable sections
- separate raw address ownership from best-effort symbolic naming

## Done Means

- `macho` has one canonical address-resolution story for symbols, ObjC methods,
  and callsites
- downstream tools stop guessing function sizes and chasing raw byte patterns
- xref and range APIs share one coherent ownership model
