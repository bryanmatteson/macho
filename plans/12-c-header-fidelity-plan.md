# Plan: C Header Fidelity

## Status

This is the concrete plan for reconstructing the highest-fidelity C header
surface practical from Mach-O binaries, symbols, DWARF debug information, and
correlated external headers.

For C, DWARF is the primary source of source-level fidelity. Symbol-only
recovery is a weaker fallback.

## Objective

Build a C recovery pipeline that can:

- reconstruct declarations directly from DWARF when present
- reconcile DWARF with Mach-O symbols, exports, imports, and sections
- correlate recovered declarations with SDK and project headers
- fall back to symbol- and usage-based inference when DWARF is absent
- emit deterministic, compileable headers grouped into plausible translation
  units or module surfaces

## Why This Matters

C lacks the rich runtime metadata that makes Objective-C reconstruction
straightforward. For real fidelity, the source of truth is usually DWARF, not
the symbol table.

When DWARF is present, `macho` can get close to true header reconstruction.
When it is absent, the tool should degrade honestly into ABI-surface recovery
instead of pretending symbols contain more than they do.

## Current Repo Leverage

- `src/commands/symbols.rs`
- `src/commands/exports.rs`
- `src/commands/imports.rs`
- `src/model/symbol.rs`
- `src/xref/`
- `src/dyld/`
- `src/model/section.rs`
- `src/model/load_command.rs`

## Fidelity Contract

### Recoverable With High Confidence

- function and global symbol names
- linkage and visibility metadata from Mach-O
- full declarations and many type graphs from DWARF
- source file paths and declaration locations from DWARF
- struct, union, enum, typedef, pointer, array, qualifier, and bitfield
  information represented in DWARF

### Best-Effort

- original header partitioning when only partial debug info exists
- macro-driven spellings reconstructed from DWARF plus external headers
- no-DWARF function prototypes inferred from usage and call conventions
- exact anonymous-type placement and typedef layering

### Not Reliably Recoverable Without Debug Info or Header Correlation

- exact prototypes for stripped internal symbols
- struct field names and layouts for types not present in DWARF
- macro definitions and conditional compilation structure
- original grouping across headers and private/internal partitions

## Scope

### In Scope

- DWARF ingestion and canonical C IR construction
- reconciliation with Mach-O symbols and linkage metadata
- external header correlation using Clang tooling
- no-DWARF fallback inference for functions and globals
- deterministic header emission and validation

### Out of Scope

- decompiler-style semantic recovery of local variables and control flow
- exact macro reconstruction from binary evidence alone
- compiler-specific debug extensions beyond a documented compatibility layer

## Design

Use one canonical C declaration graph:

- `CEntity`: function, variable, typedef, enum, struct, union, field, macro
  proxy, header unit
- `CType`: canonical source type with storage class, qualifiers, arrays,
  bitfields, and optional preferred spelling
- `EvidenceFact`: DWARF, symbol table, relocation, import/export, header match,
  or inference source

DWARF should drive source-level reconstruction. Mach-O metadata should provide
linkage, reachability, ownership, and no-debug fallback evidence.

## Milestones

### Milestone 1: DWARF Loader and Canonical IR

Goal: make DWARF the first-class source of truth for C declarations.

Work:

- add a DWARF parsing layer for compilation units, DIEs, and type graphs
- recover functions, variables, typedefs, structs, unions, enums, arrays,
  pointers, qualifiers, and bitfields
- preserve source file paths, declaration lines, and abstract-origin links
- normalize recursive and shared types into stable identities

Acceptance:

- DWARF-backed declarations can be queried without ad hoc DIE traversal
- recursive and reused types deduplicate cleanly
- tests cover representative C type graphs and declaration forms

### Milestone 2: Symbol and Linkage Reconciliation

Goal: align source-level declarations with binary ownership.

Work:

- map DWARF functions and globals to Mach-O symbols by address, name, and
  section ownership
- reconcile exports, imports, weak bindings, tentative definitions, TLS, and
  visibility
- surface mismatches between DWARF and the actual linked image

Acceptance:

- every emitted public declaration has correct linkage metadata
- symbol ownership disagreements are explicit instead of silently merged

### Milestone 3: Header Correlation

Goal: recover source spellings and header boundaries when headers are available.

Work:

- index SDK and optional project headers using Clang tooling
- convert source declarations into the canonical C IR
- match DWARF or symbol-backed entities to header declarations by file path,
  line info, canonical type, and symbol identity
- lift exact typedef names, enum spellings, tags, and grouping into the final
  model

Acceptance:

- correlated declarations prefer exact source spellings
- unmatched declarations still emit clean canonical C syntax
- header correlation remains optional

### Milestone 4: No-DWARF Fallback Inference

Goal: produce honest fallback headers when debug info is absent.

Work:

- infer function prototypes from symbol names, callsites, call conventions,
  imports, format strings, and relocation usage
- infer pointer-vs-scalar and probable varargs patterns where supported by
  strong evidence
- model globals from sections, sizes, relocations, and external references
- keep all such results clearly lower-confidence than DWARF-backed recovery

Acceptance:

- stripped binaries still produce an ABI-surface header
- fallback output marks unresolved or inferred regions in sidecar metadata

### Milestone 5: Deterministic Emitter and Verifier

Goal: turn the recovered graph into reliable header artifacts.

Work:

- group declarations into header units by source path, module ownership, or
  library surface
- emit forward declarations, typedefs, enums, structs, globals, and functions
  in dependency-safe order
- reparse output with Clang and compare against the recovered graph
- compare DWARF-backed declarations structurally rather than by text only

Acceptance:

- emitted headers parse cleanly
- DWARF-backed declarations survive a structural equivalence check
- output is stable across runs

## Dependencies

- depends on the existing symbol/export/import parsing baseline
- benefits from `05-multi-image-analysis-plan.md` for cross-image correlation
- benefits from `07-symbol-and-xref-resolution-plan.md` for address ownership
  and usage-based fallback inference

## Risks

- DWARF ingestion can balloon in scope if too many edge forms are tackled at
  once
- symbol-to-DWARF mapping can be ambiguous in stripped or LTO-heavy binaries
- header correlation can reintroduce source assumptions where the binary
  differs

## Mitigations

- keep a strict confidence ranking: DWARF exact, correlated, inferred
- preserve canonical types even when preferred source spellings are unknown
- verify emitted declarations against both Clang and the recovered graph

## Recommended Sequence

1. add DWARF parsing and the canonical C IR
2. reconcile DWARF entities with Mach-O symbols and linkage
3. add external header correlation
4. add no-DWARF fallback inference
5. add deterministic emission and structural validation

## Done Means

- `macho` can reconstruct high-fidelity C headers when DWARF is present
- stripped binaries degrade to an honest ABI-surface fallback instead of false
  precision
- external headers improve spelling and organization without being required for
  baseline recovery
