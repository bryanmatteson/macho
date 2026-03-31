# Plan: String Regions and C++ VTable Analysis

## Status

This plan combines the earlier string-region discovery draft and the separate
C++ vtable-index draft into one data-surface analysis track.

## Objective

Expose stable discovery APIs for the binary data surfaces most often needed by
patching and reverse-engineering workflows:

- string-bearing regions
- scoped string search
- C++ vtable ownership and slot decoding

## Why This Matters

Both features are about turning "raw bytes in sections" into structured,
queryable data. Keeping them together avoids inventing separate section
classification, address-range, and CLI patterns for two closely related
analysis problems.

## Current Repo Leverage

- `src/model/section.rs`, `src/model/segment.rs`
- `src/edit/patch.rs`
- `src/model/symbol.rs`
- `src/demangle.rs`
- plan 07's range/xref infrastructure

## Scope

### In Scope

- deterministic string-region discovery from section metadata
- conservative opt-in heuristics for mixed-content sections
- scoped C-string search for patching workflows
- `VtableIndex` for standard Apple Itanium-style vtables
- slot-to-target resolution and reverse lookup

### Out of Scope

- arbitrary string carving from every readable section by default
- non-Itanium C++ ABI support
- compiler-specific devirtualization or class hierarchy recovery

## Design

Use one "data surface" mental model:

- `strings` classifies regions and scoped search windows
- `vtable` classifies vtable-bearing regions and slot contents
- both features should integrate with plan 07's ownership model when it exists,
  but remain useful on their own

## Milestones

### Milestone 1: String Regions

Goal: stop searching the entire image for strings.

Work:

- add deterministic string-region discovery from known section types and names
- add scoped C-string search and point queries
- integrate scoped string search with the patching layer

Acceptance:

- callers can search string pools without scanning code or arbitrary data
- heuristic scanning is opt-in and clearly marked

### Milestone 2: VTable Index

Goal: make standard C++ vtables queryable by type and address.

Work:

- add `VtableIndex`, `VtableEntry`, and `VtableSlot`
- detect address points, typeinfo references, and pure-virtual slots
- support reverse lookup from slot target or table address

Acceptance:

- a caller can enumerate vtables and inspect slot ownership deterministically
- stripped-symbol cases degrade gracefully to raw addresses

### Milestone 3: Shared Integration Surface

Goal: make the data-surface features usable across commands and tooling.

Work:

- add CLI surfacing for strings and vtables
- reuse plan 07 ownership/range helpers where available
- align JSON output and naming conventions with the rest of the roadmap

Acceptance:

- patching and RE workflows can rely on structured string and vtable queries
- data-surface commands feel like part of the same product, not bolt-ons

## Dependencies

- largely independent
- benefits from plan 07 for code-range ownership and slot target enrichment

## Risks

- heuristic string detection can quickly become noisy
- vtable parsing can misfire on non-standard layouts or stripped metadata

## Mitigations

- keep heuristic string scanning opt-in
- validate vtable headers conservatively and surface unknowns explicitly

## Done Means

- string pools and C++ vtables are first-class analysis targets
- patching helpers can operate on scoped string regions instead of whole-image
  scans
- data-surface discovery is no longer split across unrelated plan documents
