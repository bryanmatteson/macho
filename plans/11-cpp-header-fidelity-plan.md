# Plan: C++ Header Fidelity

## Status

This is the concrete plan for reconstructing the highest-fidelity C++ header
surface practical from Mach-O binaries, symbols, RTTI, vtables, ABI analysis,
and correlated external evidence.

The target is ABI-faithful, compileable declarations. It is not exact source
reproduction.

## Objective

Build a C++ recovery pipeline that can:

- parse Itanium C++ manglings into a structured type and declaration AST
- recover class graphs, virtual surfaces, and inheritance from RTTI and vtables
- infer missing ABI details from function bodies and callsites
- merge evidence across linked binaries and frameworks
- correlate recovered entities with SDK or project headers when available
- emit deterministic headers with explicit confidence and unresolved gaps

## Why This Matters

Objective-C is unusually rich because the runtime metadata is designed for
inspection. C++ is not. Recovering usable C++ declarations therefore requires a
multi-source evidence pipeline rather than a single metadata parser.

If done well, `macho` can recover large parts of a library's public and virtual
surface with enough fidelity for API review, ABI diffing, stub generation, and
downstream automation.

## Current Repo Leverage

- `src/demangle.rs`
- `src/commands/symbols.rs`
- `src/commands/exports.rs`
- `src/commands/imports.rs`
- `src/commands/data_surface.rs`
- `src/data_surface/vtable.rs`
- `src/xref/`
- `src/dyld/`
- `src/model/`
- `src/commands/deps.rs`

## Fidelity Contract

### Recoverable With High Confidence

- qualified names from mangled symbols
- overload identity and parameter types encoded in manglings
- ctor/dtor forms and many operator spellings
- class names and inheritance edges present in RTTI
- virtual slot order, thunk presence, and vtable shape
- deleting vs complete destructor patterns when emitted conventionally

### Best-Effort

- return types of ordinary non-template functions
- exact base-subobject ownership of secondary vtables in complex hierarchies
- pointerness, references, and aggregate returns inferred from calling
  convention and callsites
- source-level typedef spellings and template aliases
- access control and declaration grouping

### Not Reliably Recoverable From Binaries Alone

- original parameter variable names
- exact source formatting and comments
- private non-virtual data members when no debug info exists
- source-only annotations and many exception-spec details
- exact typedef names when only canonical ABI types remain

## Scope

### In Scope

- structured Itanium ABI symbol parsing
- RTTI and vtable graph recovery
- architecture-aware body analysis for `arm64` and `x86_64`
- evidence merging across binaries and frameworks
- external header correlation through Clang-based indexing
- deterministic C++ header emission
- confidence tracking and machine-checkable validation

### Out of Scope

- exact source reconstruction
- decompiler-grade full control-flow recovery
- MSVC ABI support in the first implementation
- template body recovery or source-level constexpr semantics

## Design

Build the pipeline around one shared evidence graph:

- `CppEntity`: function, method, class, field, base edge, vtable, typeinfo node
- `CppType`: canonical ABI type tree plus optional preferred source spelling
- `EvidenceFact`: source, confidence, architecture, image, address range,
  rationale, and conflicts
- `HeaderUnit`: a deterministic emission target for one module, framework, or
  class cluster

Keep exact evidence separate from presentation. The emitter must be able to
produce a compileable header without LLM help.

## Milestones

### Milestone 1: Symbol AST

Goal: replace string-only demangling with a typed Itanium declaration model.

Work:

- add a C++ ABI parser module for Itanium manglings
- represent names, nested scopes, operators, constructors, destructors,
  template arguments, cv/ref qualifiers, parameter types, and special names
- preserve the original mangled symbol and simplified demangled text
- normalize canonical type identities for later merging

Acceptance:

- symbol parsing produces a declaration AST instead of a flat string
- overloads are distinguishable without reparsing text
- tests cover representative names, templates, operators, and special symbols

### Milestone 2: RTTI and Vtable Recovery

Goal: build a reliable class and virtual-surface model.

Work:

- parse `typeinfo` objects and their concrete subclasses
- recover direct base edges, flags, and multiple-inheritance metadata
- parse primary and secondary vtables, address points, offset-to-top entries,
  RTTI pointers, virtual slots, and thunks
- identify complete, deleting, and base-destructor entry patterns
- map vtable slots back to recovered methods and owning classes

Acceptance:

- class graphs are queryable from RTTI-backed evidence
- vtables can be attributed to classes and subobjects
- virtual method surfaces are stable enough for regression tests

### Milestone 3: Function-Body ABI Analysis

Goal: infer ABI details missing from symbols and RTTI.

Work:

- add `arm64` and `x86_64` prologue/epilogue analyzers
- detect hidden `sret` and nontrivial return lowering
- classify return channels: GPR, FP/SIMD, aggregate, pointer-like, reference-like
- detect short thunks and `this` adjustments
- propagate evidence from direct callsites and wrapper bodies

Acceptance:

- non-template function return types improve beyond `unknown`
- thunks are distinguished from real method bodies
- inference results are explicit about confidence and conflicts

### Milestone 4: Cross-Binary Unification

Goal: stop treating each image as an island.

Work:

- add a multi-image entity index keyed by mangled name, qualified name, RTTI
  identity, install name, and UUID
- merge exports, imports, reexports, and duplicate definitions
- use linked frameworks and sibling binaries to fill declaration gaps
- preserve per-image deltas when declarations disagree

Acceptance:

- the same API seen in multiple binaries produces one merged declaration view
- disagreements are tracked instead of silently overwritten
- linked-framework scanning materially improves class and method coverage

### Milestone 5: External Header Correlation

Goal: upgrade ABI-faithful declarations toward source-faithful spellings when
headers are available.

Work:

- index SDK and optional project headers with Clang tooling
- map source declarations into the same canonical entity/type graph
- match recovered binary entities to source declarations by mangled name,
  canonical type, class graph, and vtable shape
- lift preferred source spellings, typedefs, enums, aliases, and grouping into
  the final model

Acceptance:

- matched public APIs use exact source spellings where available
- unmatched entities retain canonical ABI-safe spellings
- source correlation is optional and never required for baseline output

### Milestone 6: Deterministic Header Emitter

Goal: generate useful C++ headers without hallucination.

Work:

- emit classes, namespaces, functions, methods, and forward declarations from
  the merged graph
- use generated placeholder names when source names are absent
- emit opaque or synthetic helper types when required for type-checkable output
- annotate unresolved or inferred entities in sidecar metadata, not in the
  header syntax itself

Acceptance:

- emitted headers parse with Clang
- public and virtual surfaces are compileable
- output is deterministic across runs for the same evidence set

### Milestone 7: Validation Harness

Goal: keep “fidelity” measurable.

Work:

- reparse emitted headers with Clang
- remangle emitted declarations where possible and compare to original names
- compare emitted virtual surfaces to recovered vtable slot counts and ordering
- keep a corpus of known binaries with expected recovery quality

Acceptance:

- regressions are caught through structural checks, not visual inspection
- confidence claims map to measurable validation outcomes

## Dependencies

- extends the existing symbol, export/import, xref, and vtable foundations
- depends on `05-multi-image-analysis-plan.md` for cross-image workflows
- depends on `07-symbol-and-xref-resolution-plan.md` for address ownership and
  body/callsite evidence
- complements `09-binary-data-analysis-plan.md` by promoting vtables from a
  standalone index to a class-recovery input

## Risks

- Itanium ABI edge cases can sprawl into a large parser and validator surface
- body inference can become architecture-specific and brittle
- cross-binary merging can accidentally collapse distinct entities
- source correlation can overfit to SDK headers and hide binary differences

## Mitigations

- keep provenance and confidence on every inferred fact
- never replace exact evidence with weaker correlated evidence
- separate canonical ABI types from preferred source spellings
- require validator agreement before promoting low-confidence inference

## Recommended Sequence

1. add the Itanium symbol AST and canonical type graph
2. promote vtables and RTTI into a structured class model
3. add body and thunk analysis for `arm64`
4. add body and thunk analysis for `x86_64`
5. add multi-image entity merging
6. add external header correlation
7. build the deterministic emitter and validator loop

## Done Means

- `macho` can emit compileable C++ headers that are ABI-faithful for a large
  share of exported and virtual surfaces
- remaining uncertainty is tracked explicitly instead of hidden behind
  demangled strings
- SDK or project headers can upgrade fidelity when available without becoming a
  hard dependency for baseline recovery
