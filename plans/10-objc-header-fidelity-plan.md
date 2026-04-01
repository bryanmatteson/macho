# Plan: ObjC Header Fidelity

## Status

This is the concrete plan for bringing `macho objc --headers` as close as
practical to `class-dump` output while staying honest about what Mach-O
metadata can and cannot recover.

## Objective

Raise Objective-C header reconstruction from today's lightweight
best-effort output to a high-fidelity runtime-surface renderer that can:

- render full method signatures instead of return-type-only stubs
- render richer property declarations and category surfaces
- preserve raw metadata while exposing structured type/signature models
- make remaining gaps explicit when source-level recovery is impossible

## Why This Matters

The repository already parses enough ObjC runtime metadata to identify classes,
categories, protocols, methods, ivars, and properties. That is the hard
foundation. The remaining gap versus `class-dump` is mostly modeling and
rendering fidelity, not access to the underlying data.

High-fidelity headers matter because they make `macho` useful for API recovery,
binary review, regression diffs, and downstream automation without forcing
consumers to parse raw type encodings themselves.

## Current Repo Leverage

- `src/objc/class.rs`
- `src/objc/category.rs`
- `src/objc/method.rs`
- `src/objc/property.rs`
- `src/objc/protocol.rs`
- `src/objc/render.rs`
- `src/commands/objc.rs`
- `tests/objc_tests.rs`
- `tests/cli_feature_tests.rs`

## Fidelity Contract

### Recoverable

- class, category, protocol names
- superclass relationships
- selector names
- method type encodings
- ivar names, offsets, sizes, alignments, and encoded types
- property names and encoded attribute strings
- adopted protocols

### Best-Effort

- human-readable type spellings from ObjC encodings
- placeholder method argument names
- block and protocol-qualified object rendering
- formatting choices to match `class-dump` style closely
- superclass resolution for internal and external references

### Not Recoverable From Mach-O Metadata Alone

- original parameter variable names
- typedef aliases instead of canonical underlying types
- nullability and most lightweight generics
- source comments, macros, and formatting
- many source-only annotations

## Scope

### In Scope

- parsed ASTs for ObjC types, property attributes, and method signatures
- high-fidelity header rendering for classes, categories, and protocols
- category property recovery and rendering
- deterministic output suitable for golden tests and diffs
- differential validation against `class-dump` on real binaries

### Out of Scope

- exact source reproduction
- decompiler-style semantic recovery
- Swift ABI modeling beyond current ObjC-adjacent surfacing

## Design

Split the work into three layers:

- parsing: raw ObjC encodings into structured ASTs
- modeling: attach parsed signatures and attributes to ObjC metadata types
- rendering: one deterministic high-fidelity header printer for CLI output

Keep raw strings alongside parsed representations so callers can inspect the
original runtime metadata and so parsing improvements do not destroy source
evidence.

## Milestones

### Milestone 1: Type and Signature AST

Goal: replace ad hoc string decoding with a reusable parser.

Work:

- add a dedicated ObjC encoding parser module
- parse primitive, object, pointer, array, struct, union, bitfield, block, and
  qualifier encodings
- parse method signature strings into return type plus ordered argument list
- keep stack offsets and raw encodings available for debugging

Acceptance:

- renderer code no longer needs to hand-parse encodings inline
- unit tests cover representative nested and qualified encodings
- method signatures can be rendered without losing argument ordering

### Milestone 2: Header Rendering Upgrade

Goal: move header output from summary strings to structured declarations.

Work:

- render full typed method signatures with generated placeholder parameter names
- render richer ivar type spellings
- render protocol-qualified object types and blocks
- normalize formatting for interfaces, categories, protocols, and `@optional`
  sections

Acceptance:

- methods no longer appear as `- (ret) selector;` when arguments exist
- output is deterministic and stable across runs
- golden tests compare directly against expected header fragments

### Milestone 3: Property Fidelity

Goal: reconstruct property declarations with materially better accuracy.

Work:

- parse the full property attribute grammar
- render ownership, atomicity, mutability, dynamic, getter, setter, and ivar
  attributes where recoverable
- distinguish object, scalar, block, struct, and protocol-qualified property
  types

Acceptance:

- property output contains substantially complete attribute lists
- custom accessors and backing ivars are surfaced when present

### Milestone 4: Category and Resolution Completeness

Goal: close the main metadata-surface gaps outside method/property decoding.

Work:

- parse and render category properties
- render adopted protocols on categories
- improve superclass resolution for internal classes
- normalize protocol adoption ordering and category folding side effects for
  deterministic output

Acceptance:

- category headers include all recoverable methods, protocols, and properties
- superclass output is correct for more than bind-backed cases

### Milestone 5: Validation and CLI Integration

Goal: make the higher-fidelity path the reliable product surface.

Work:

- add real-binary golden tests
- compare output against `class-dump` on a curated corpus and classify deltas
- route `macho objc --headers` through the structured renderer
- document remaining intentional gaps

Acceptance:

- known mismatches are either fixed or documented as non-recoverable
- CLI output is stable enough for regression testing and diff workflows

## Dependencies

- builds on the current ObjC metadata parsing in `src/objc/`
- complements `04-objc-swift-graph-plan.md` by improving fidelity rather than
  semantic query breadth
- may reuse symbol information from `07-symbol-and-xref-resolution-plan.md` for
  diagnostics, but should not depend on symbol presence for core header output

## Risks

- ObjC type encodings have edge cases that can sprawl into parser complexity
- chasing `class-dump` formatting exactly can waste time on cosmetic parity
- some binaries contain malformed or partial metadata that must degrade
  gracefully

## Mitigations

- keep parsing and rendering separate so failures can fall back cleanly
- prioritize declaration correctness over exact whitespace parity
- preserve raw encodings and surface parse uncertainty explicitly in tests

## Recommended Sequence

1. add the type/signature AST and parser
2. switch method rendering to structured signatures
3. expand property parsing and rendering
4. add category-property and superclass-resolution fixes
5. add golden tests and differential validation
6. promote the high-fidelity renderer to the default header path

## Done Means

- `macho objc --headers` reconstructs the highest-fidelity ObjC declarations
  reasonably possible from runtime metadata
- remaining differences versus `class-dump` are narrow, understood, and mostly
  limited to non-recoverable source details
- the ObjC renderer has a structured foundation instead of string heuristics
