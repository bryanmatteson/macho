# Plan 15: Architecture Coherence and Scalable Workspace Completion

## Status and authority

This is the canonical implementation contract for correcting the repository-wide
design weaknesses identified in the July 2026 architecture audit. It replaces
the execution model and target layout in
[`14-workspace-crate-refactor-plan.md`](14-workspace-crate-refactor-plan.md).
Plan 14 remains historical context for why the workspace split began; an agent
must not implement both plans.

[`16-evidence-first-c-cpp-recovery-plan.md`](16-evidence-first-c-cpp-recovery-plan.md)
is the behavioral authority for C/C++ recovery, recovery snapshot schema 3,
safe header projection, and in-process header validation. This plan remains the
authority for crate placement, dependency direction, selective execution, and
CLI delivery.

[`10-objc-header-fidelity-plan.md`](10-objc-header-fidelity-plan.md) is the
Objective-C behavioral authority. This plan owns the integrated Swift behavior.
[`13-llm-header-inference-plan.md`](13-llm-header-inference-plan.md) owns only the
optional offline hypothesis artifact layer. All four active documents form one
contract with the ownership order recorded in `plans/README.md`.

[`schemas/language-recovery-wire-v1.md`](schemas/language-recovery-wire-v1.md)
is the normative language/recovery wire contract. `macho-analysis::report` owns
its common identity vocabulary, canonical JSON, report DTO validation, and
deterministic language/recovery schema registries. Domain leaves own semantic
values; analysis owns conversion into report DTOs. The leaves do not own
independent serialized report roots.

The workspace is prerelease: no external users exist, so no backward
compatibility obligation binds this plan. Removed surfaces are removed, not
mapped or aliased.

This is one coherent implementation pass. The work packages below are ordered by
dependency, but they are not calendar phases, optional milestones, or separately
shippable subsets. The repository is not complete or releasable until every work
package and the final whole-tree gate pass together.

The implementation may expand locally when compilation or an invariant requires
an adjacent change. It may not reduce, defer, stub, or silently reinterpret any
obligation in this plan.

## Outcome

At completion, `macho` has:

- a small, process-free core with closed construction paths and explicit parse
  policy;
- reusable domain crates whose dependency direction matches their abstraction
  level;
- structured, contextual errors instead of a shared string bucket;
- instruction APIs in which decode failures are either returned or represented;
- selective analysis that does not compute excluded domains and snapshots that
  distinguish absence, emptiness, unsupported input, and failure;
- a mutation crate that can be used without pulling in analysis;
- one explicit workflow layer for operations that genuinely compose mutation and
  analysis;
- a library-only, feature-gated façade;
- a CLI-owned command grammar, input layer, renderer, writer boundary, and exit
  policy;
- documentation and versions generated or checked against their actual
  authorities; and
- enforced architecture, formatting, lint, documentation, test, fuzz, and
  benchmark gates.

The target is a maintainable dependency graph and set of contracts, not merely a
different directory layout.

## Coherence boundary

The implementation boundary includes all of the following and must resolve them
together:

1. workspace members and dependency direction;
2. core parsing, validation, limits, addressing, models, construction, and
   errors;
3. symbols, dyld, code signing, DWARF, ObjC, Swift, C++, in-process language
   tooling, and host-signing ownership;
4. instruction decoding and relocation callers;
5. analysis planning, caching, domain dependencies, snapshots, diff, audit,
   reconstruction, and large-module seams;
6. mutation, transaction validation, signing, and semantic preview;
7. façade features, reexport surface, and public API documentation;
8. CLI arguments, file input, output formats, capture, writers, errors, and
   exit codes;
9. README/help/version/release authority; and
10. CI, fixtures, fuzzing, benchmarks, and architecture enforcement.

The coherence ceiling is the audited product surface. The implementation does
not invent new Mach-O formats, architectures, analysis algorithms, or commands
unless one is necessary to satisfy an explicit contract below.

## Falsification criteria

The design is invalid, even if the workspace compiles, if any of these statements
is true:

- `macho-core`, a metadata crate, `macho-insn`, or `macho-mutate` depends on
  `macho-analysis`, `macho-workflow`, the façade, or the CLI;
- a production inspection, recovery, demangling, header-correlation, or header-
  validation path invokes `xcrun`, a compiler, a demangler process, or another
  host executable;
- a public invariant-bearing type can be assembled into a state the parser would
  reject;
- recoverable parsing and hard structural failure are still conflated;
- an instruction decode failure can disappear without an error or a recorded
  gap;
- an excluded analysis domain executes;
- a recovery collector executes without a serialized resolved-plan entry or on
  an entity outside its resolved target set;
- a snapshot cannot distinguish `not_requested`, `complete` with an empty value,
  `unsupported`, and `failed`;
- C/C++/Objective-C header syntax, rendering, or semantic validation has more
  than one implementation authority, or syntactic success is treated as
  semantic validity;
- Objective-C or Swift output conflates referenced/symbol-only/partial entities
  with metadata-defined local definitions or hides them behind a bare zero;
- mutation pulls analysis into a downstream dependency graph;
- a CLI command writes around the injected output boundary;
- machine output can be mixed with status or error text;
- a diff or audit policy failure is indistinguishable by exit code from an
  execution failure;
- a documented command is rejected by the live router;
- a tagged release can report a version different from its tag;
- a requested audit weakness has no owner, executable check, and invalid case; or
- the final gates can pass while any of the above is true.

## Audited baseline

This amended contract starts from the live 0.2.0 workspace, not the pre-workspace
`src/` layout in plan 14 or the pre-implementation baseline previously recorded
for plan 15. On July 18, 2026, two independent package counts (`cargo metadata`
and workspace crate manifests) both report 18 packages. The target graph has 19:
`macho-header-syntax` is the sole missing package.

| Area | Verified live state | Required delta |
| --- | --- | --- |
| Workspace graph | The metadata leaves, analysis, mutation, workflow, façade, CLI, test support, and `crates/xtask` already exist. | Create only `macho-header-syntax`; update permitted edges, façade features, and all callers for that leaf. Audit existing crates in place rather than recreating them. |
| Core and mutation | `macho-core` has no normal workspace dependency; `macho-mutate` depends on core, instruction, dyld, and code-signing leaves and has no analysis edge. | Preserve these achieved boundaries while applying the amended language/report contracts. |
| Façade | `macho --no-default-features` depends only on `macho-core`. | Preserve the minimal tree and extend the feature authority only where header syntax requires it. |
| Verifier | `crates/xtask` already routes `architecture`, `docs --check`, `release --check`, `verify`, and `verify-fuzz`. Its architecture registry does not yet know `macho-header-syntax` or the amended dependency edges. | Extend the existing verifier and its invalid fixtures; do not create a new skeleton or a second verifier. |
| Snapshot/report schema | Analysis and CLI tests still assert snapshot/report schema version 2. | Implement schema 3, the normative language/recovery wire registry, exact rejection fixtures, and per-domain schema goldens. |
| Header validation | Production `header_infer` constructs `XcrunClangValidator`, and the CLI adapter launches `std::process::Command`. | Replace production inspection/recovery validation with `macho-header-syntax`; retain process execution only in the explicitly permitted signing adapter. |
| Language surfaces | C/C++ recovery, ObjC, and Swift crates exist, and the worktree contains in-progress Swift, symbol-demangling, and CLI-output edits. | Reconcile those edits with plans 10, 13, 15, and 16; complete evidence conservation, targeted execution, report schemas, and live-corpus acceptance without resetting user work. |
| Quality authority | `.github/workflows/ci.yml`, seven fuzz targets with corpora, one Criterion benchmark, and the xtask gate exist. | Extend the existing authorities with the amended schema/header/language fixtures and checks; do not claim their old PASS state covers the amended contract. |

WP0 re-runs and records every baseline probe before ownership changes. If the
live tree changes, the ledger records the new evidence and the implementation
preserves the behavioral contract rather than restoring stale code.

## Non-negotiable architecture

### Dependency graph

The final graph is a directed acyclic graph with the following permitted edges.
An omitted edge is forbidden.

```text
macho-core                     -> no workspace crates
macho-insn                     -> no workspace crates
macho-dyld                     -> core
macho-symbols                  -> core, dyld
macho-codesign                 -> core
macho-dwarf                    -> core
macho-objc                     -> core, dyld, header-syntax
macho-swift                    -> core, symbols, objc
macho-cpp                      -> core, insn, symbols, dyld, dwarf
macho-header-syntax            -> no workspace crates

macho-analysis                 -> core, insn, symbols, dyld, codesign,
                                  dwarf, objc, swift, cpp, header-syntax
macho-mutate                   -> core, insn, dyld, codesign
macho-dyld-cache               -> core, dyld
macho-header-infer             -> analysis, header-syntax
macho-workflow                 -> core, analysis, mutate

macho                          -> core; feature-selected insn, symbols, dyld,
                                  codesign, dwarf, objc, swift, cpp, analysis,
                                  mutate, workflow, dyld-cache, header-infer
macho-cli                      -> macho(full)
xtask                          -> macho-cli
macho-test-support             -> no product crates
```

`macho-insn`, `xtask`, and `macho-test-support` are workspace members.
`xtask` and `macho-test-support` are unpublished internal packages and are not
product dependencies. CLI adapter traits are reexported by the full façade, so
`macho-cli` has no direct leaf-crate dependency. Third-party dependencies are
also checked by ownership: Clap, memory mapping, `anyhow`, and CLI serialization
belong to `macho-cli`; cargo metadata/tooling dependencies belong to `xtask`.

### Workspace members and ownership

| Crate | Sole responsibility | Moves from the live tree | Forbidden content |
| --- | --- | --- | --- |
| `macho-core` | Byte-safe container/header/load-command/segment/section/symbol/relocation parsing, address types/maps, parse limits, structural validation, and diagnostics | Keep `format/`, structural `model/`, structural `ext`, and validation; reduce `lib.rs` | Serialization DTOs, domain metadata, analysis, mutation, CLI, process execution |
| `macho-insn` | Architecture-aware decode, encode, and relocation primitives | Existing crate | Mach-O parsing, analysis policy, silent decode recovery |
| `macho-symbols` | Symbol-table helpers, import/export naming, pure Rust/C++ demangling, demangler traits | `core/symbols/`; dyld-derived import/export collection calls downward into `macho-dyld` | Host process execution, ObjC/Swift graphs |
| `macho-dyld` | Bind/rebase/chained-fixup/export parsing, pointer resolution, and dyld value types | `core/dyld/`, `core/resolve/fixups.rs`, `core/resolve/pointers.rs` | Image compatibility policy, CLI paths, mutation |
| `macho-codesign` | Code-directory, superblob, entitlement, and signature parsing/types | `core/codesign/` | Signing mutation, audit policy, filesystem access |
| `macho-dwarf` | DWARF section loading and typed function/type indexes | `core/dwarf/` | Compiler invocation, header output, filesystem writes |
| `macho-objc` | ObjC metadata parsing, encoding, resolver, and owned metadata values | `core/objc/` | Swift enrichment, rendering, CLI filtering |
| `macho-swift` | Swift metadata indexing and in-process Swift demangling | `core/swift/` plus Swift-specific demangling coordination | Process-backed demangling, ObjC ownership |
| `macho-cpp` | RTTI/vtable parsing and architecture-specific ABI/body inference | `core/rtti/` and pure ABI inference from `analysis/reconstruct/cpp/abi.rs` | Header filesystem output, compiler invocation, generic diff/reporting |
| `macho-header-syntax` | Typed supported C/C++/Objective-C declaration ASTs, bundled in-process parsing, deterministic rendering, and syntax plus semantic validation | Consolidate header AST/parser/render/validation code split across reconstruction, ObjC rendering, and header inference | Mach-O evidence, runtime encodings, recovery facts, prompts, model hypotheses, process execution, filesystem access |
| `macho-analysis` | Domain planning/execution, snapshots, diff, audit, dependency compatibility, strings/xrefs, container analysis, recovery facts, and safe header projection | Existing crate plus normalized `core/image.rs` and path/compatibility policy | Mutation, CLI arguments, host processes, filesystem writes, C-family parser implementation |
| `macho-mutate` | Owned model, layout, patch planning/application, signing mutation, structural preview, and transactional validation | Existing crate | Analysis dependency/reexport, semantic diff, CLI concerns |
| `macho-workflow` | Cross-layer patch workflow and semantic before/after preview | Semantic portions of `mutate/preview.rs` and transaction orchestration that consumes analysis | CLI parsing/rendering, low-level parsers |
| `macho-dyld-cache` | Dyld shared-cache model, parsing, and extraction-bytes API | `macho/src/inputs/dyld_cache/` | Filesystem writes, CLI flags, text output |
| `macho-header-infer` | Bounded deterministic-report projection, prompt/response artifacts, model hypothesis records, and validation orchestration | Reusable inference logic now reached from `header_infer`; parser implementation moves to `macho-header-syntax` | Recovery-fact ownership, parser/AST ownership, process execution, environment discovery, filesystem writes |
| `macho` | Feature-gated library façade | Existing `lib.rs`, rebuilt as a clean reexport surface; no import path is preserved for its own sake | `commands`, `inputs`, Clap, `memmap2`, `anyhow`, direct implementation logic |
| `macho-cli` | Command grammar, file mapping, explicit inputs, host-signing adapters, orchestration, renderers, writers, and exit policy | All `macho/src/commands/` plus CLI-specific input and file-output code | Reimplementation of parsing or analysis algorithms; process-backed inspection or recovery |
| `macho-test-support` | Deterministic byte-level Mach-O/fat/cache fixtures shared by tests, fuzz seeds, docs, and benchmarks | Consolidate duplicated test builders | Production dependency, host files, process execution |

If a move exposes a cycle, do not add a reverse dependency. Move the shared
concept to the lowest crate that can own it without policy. Examples:

- raw load-command dylib kinds remain in `macho-core`; normalized dependency
  reports live in `macho-analysis`;
- raw dyld exports live in `macho-dyld`; symbol presentation lives in
  `macho-symbols` without making dyld depend on symbols;
- C++ RTTI can consume a caller-supplied name normalizer rather than making
  `macho-symbols` depend upward on `macho-cpp`;
- C/C++/Objective-C declaration syntax and semantic validation live in the dependency-free
  `macho-header-syntax` leaf so both analysis and hypothesis validation consume
  one parser/AST contract without depending on each other;
- semantic patch comparison belongs only in `macho-workflow`;
- fileset containers (`MH_FILESET`, `LC_FILESET_ENTRY`) are structural: entry
  parsing and per-entry image access stay in `macho-core`, fileset
  listing/inspection reports live in `macho-analysis`, and the `fileset`
  command only renders them.

### Façade features

`crates/macho/Cargo.toml` must define this feature authority:

```toml
[features]
default = ["analysis"]
metadata = [
  "dep:macho-symbols", "dep:macho-dyld", "dep:macho-codesign",
  "dep:macho-dwarf", "dep:macho-objc", "dep:macho-swift", "dep:macho-cpp",
]
analysis = ["metadata", "dep:macho-insn", "dep:macho-analysis"]
mutation = [
  "dep:macho-insn", "dep:macho-dyld", "dep:macho-codesign",
  "dep:macho-mutate",
]
workflow = ["analysis", "mutation", "dep:macho-workflow"]
dyld-cache = ["dep:macho-dyld-cache"]
header-infer = ["analysis", "dep:macho-header-infer"]
full = ["analysis", "mutation", "workflow", "dyld-cache", "header-infer"]
```

Core parsing is always present. `macho-cli` requests `features = ["full"]` and
`default-features = false`. The façade reexports stable entry points; it does not
mirror every internal module. Users requiring a narrow subsystem are directed to
the leaf crate.

The architectural break is released as workspace version `0.2.0`. Because the
workspace is prerelease, removed paths are removed outright: no migration
guide, compatibility alias, or deprecated reexport exists. No package may carry
an independent product version.

## Core contracts

### Parsing policy and limits

`macho-core` exposes this exact policy shape. An internal name collision is
resolved by renaming the internal item, not by changing this public contract:

```rust
#[non_exhaustive]
pub enum ParseMode {
    Strict,
    Forensic,
}

pub struct ParseLimits {
    pub max_fat_arches: usize,
    pub max_load_commands: usize,
    pub max_sections: usize,
    pub max_string_bytes: usize,
}

pub struct ParseOptions {
    pub mode: ParseMode,
    pub limits: ParseLimits,
}

pub struct ParseOutcome<'data> {
    pub container: MachoContainer<'data>,
    pub diagnostics: Vec<Diagnostic>,
}

pub fn parse(data: &[u8]) -> Result<MachoContainer<'_>, ParseError>;
pub fn parse_with_options(
    data: &[u8],
    options: &ParseOptions,
) -> Result<ParseOutcome<'_>, ParseError>;
```

Behavior is exact:

- `parse()` is strict and uses documented default limits;
- bounds, integer overflow, invalid magic, impossible layout, and limit
  exhaustion are hard errors in both modes;
- strict mode returns an error when structural validation emits an error-severity
  diagnostic;
- forensic mode returns a safe model plus recoverable diagnostics, excluding any
  invalid region that cannot be represented unambiguously;
- warnings never change memory-safety or bounds behavior;
- the inspection CLI uses forensic mode and renders diagnostics;
- mutation and workflow entry points use strict mode before and after editing.

### Model invariants

Apply these rules to all invariant-bearing core types, not only the examples:

- make fields of `FatArch`, `FatBinary`, `MachoFile`, address-map entries, and
  parsed command containers private;
- make parser-only constructors `pub(crate)`;
- provide validated public constructors or builders only where downstream
  construction is a real use case;
- make `FatBinary::try_new` reject zero arches, duplicates, overlap, out-of-bounds
  slices, invalid alignment, and arithmetic overflow;
- make `AddressMap::try_new` use checked arithmetic, stable ordering, and explicit
  overlap rejection;
- replace `first_mach()` with `first_macho() -> Option<&MachoFile<'_>>`; callers
  that require a selected image must use `require_first_macho() -> Result<_,
  SelectionError>` at their own policy layer;
- replace `macho_files() -> Vec<_>` with a zero-allocation `MachoFiles` iterator;
- return slices and iterators (`&[T]`, `impl Iterator`) instead of `&Vec<T>`;
- mark public, externally extensible enums `#[non_exhaustive]`; and
- document every public invariant and whether offsets are file-, slice-, or
  virtual-address relative.

Do not convert checked arithmetic to wrapping arithmetic to retain old behavior.

### Error and diagnostic taxonomy

Delete the shared string-bucket role of `macho_core::Error`. Each layer owns its
error:

```text
ParseError
  kind: ParseErrorKind
  location: optional OffsetSpan
  context: ordered Vec<ContextFrame>

AnalysisError
  domain: AnalysisDomain
  kind: AnalysisErrorKind
  context/source

MutationError
  operation: MutationOperation
  kind: MutationErrorKind
  context/source

WorkflowError
  stage: WorkflowStage
  source: Parse | Analysis | Mutation

CliError
  kind: Usage | Input | Execution | Policy
  source/context
```

Each metadata leaf owns a typed error of the same shape — `SymbolsError`,
`DyldError`, `CodesignError`, `DwarfError`, `ObjcError`, `SwiftError`,
`CppError`, and `DyldCacheError` each pair a `#[non_exhaustive]` kind enum with
structured location/context fields — and `macho-insn` keeps `DecodeError` and
`EncodeError`. A higher layer wraps a leaf error as a typed source plus a
context frame, never as a flattened string.

Requirements:

- error kinds are typed and `#[non_exhaustive]`;
- offsets, command indices, architecture, and operation names are structured
  fields rather than embedded only in prose;
- `Display` is human readable, while JSON output serializes stable diagnostic
  codes and fields;
- conversion adds a context frame instead of flattening the source to a string;
- `anyhow` exists only in `macho-cli` and `xtask`;
- libraries never decide process exit codes; and
- no test asserts a whole human error string when it can assert a kind, code, or
  field.

Diagnostic codes are stable lowercase dotted identifiers, for example
`parse.load_command.truncated` and `analysis.objc.unsupported_arch`. A registry in
`macho-core` documents code, severity, and field meaning; domain crates extend
the registry through their own typed constants without reusing codes. The
registry is a documented convention, not a shared runtime structure: every
crate — including `macho-insn`, which depends on no workspace crate — declares
its own typed code constants following the convention, and `cargo xtask docs
--check` fails when any constant in the workspace is missing from the registry
document or listed more than once.

## Instruction contract

`macho-insn` must make recovery explicit:

```rust
pub struct InsnIter<'data> { /* private */ }

impl Iterator for InsnIter<'_> {
    type Item = Result<Insn, DecodeError>;
}

pub struct DecodeGap {
    pub offset: usize,
    pub len: usize,
    pub va: u64,
    pub error: DecodeError,
}

pub struct DecodeReport {
    pub instructions: Vec<Insn>,
    pub gaps: Vec<DecodeGap>,
}

pub fn decode_iter(...) -> InsnIter<'_>;
pub fn decode_lossy(...) -> DecodeReport;
```

The strict iterator stops after yielding its first error unless the caller
explicitly advances a recovery cursor. `decode_lossy` advances one byte on
x86_64 and one aligned word on ARM64/ARM64e, records every skipped range, and
coalesces adjacent failures.

Call-site policy is fixed:

- relocation, patch planning, and any operation that writes bytes use strict
  decoding and fail closed;
- xref and heuristic ABI analysis may use `decode_lossy`, but copy every gap into
  analysis issues and lower confidence for affected results;
- no caller may use `filter_map(Result::ok)` or an equivalent silent discard on
  decoded instructions.

## Analysis contracts

### Plan before execution

Replace eager snapshot construction and the fixed-capability `ImageInspector`
with a dependency-driven executor:

```rust
pub struct AnalysisLimits {
    pub max_strings_per_slice: usize,
    pub max_xrefs_per_slice: usize,
    pub max_ranges_per_slice: usize,
    pub max_vtables_per_slice: usize,
    pub max_decoded_bytes_per_slice: usize,
    pub max_issues_per_domain: usize,
}

pub struct AnalysisPlan {
    selected_slices: SliceSelection,
    requests: BTreeMap<DomainId, DomainRequest>,
    limits: AnalysisLimits,
}
pub struct Analyzer { /* built-in domain runner registry */ }
pub struct AnalysisDocument { /* owned results */ }

impl Analyzer {
    pub fn run(
        &self,
        container: &MachoContainer<'_>,
        plan: &AnalysisPlan,
    ) -> Result<AnalysisDocument, AnalysisError>;
}
```

Analysis limits are policy, not advisory: reaching a limit truncates the
collection, records an `analysis.limit.truncated` issue on the owning domain,
and leaves the domain `Complete`. Documented defaults bound every built-in
domain; a plan may raise or lower them.

`AnalysisDomain` has these exact built-in IDs: `container`, `header`,
`load_commands`, `segments`, `relocations`, `symbols`, `exports`, `imports`,
`fixups`, `codesign`, `objc`, `swift`, `dwarf`, `vtables`, `strings`, `ranges`,
`xrefs`, `dependencies`, `audit`, `c_surface`, `cpp_surface`, and
`objc_headers`. Adding a built-in domain requires a schema-version decision,
runner, declared dependencies, state fixtures, and a benchmark decision in the
same change.

The dependency resolver is the sole authority for prerequisites. Every edge is
`Required` or `Advisory`. A required `Failed` or `Unsupported` prerequisite
produces the corresponding dependent state with a dependency diagnostic. An
advisory failure is copied into the dependent issues and the runner still
executes. `NotRequested` cannot occur inside the resolved closure. In the matrix,
`?` marks an advisory edge; all other edges are required. The built-in edge set
is exact:

```text
container       -> union of parity domains declared by ContainerPlan
header          -> none
load_commands   -> header
segments        -> load_commands
relocations     -> segments
symbols         -> load_commands
exports         -> load_commands
fixups          -> load_commands, segments
imports         -> load_commands, symbols?, fixups?
codesign        -> load_commands
objc            -> segments, fixups?
swift           -> segments, symbols?, objc?
dwarf           -> segments
vtables         -> segments, symbols?, fixups?
strings         -> segments
ranges          -> segments, symbols?, dwarf?
xrefs           -> ranges, fixups?, relocations?
dependencies    -> load_commands, imports?, exports?
c_surface       -> segments, symbols, dwarf?, ranges?
cpp_surface     -> segments, symbols, vtables, dwarf?, ranges?
objc_headers    -> objc, swift?
audit           -> union of requirements declared by the enabled rule registry
```

Each audit rule declares required/advisory domain specs as data. `AuditPlan`
resolves the union before execution, so the `audit` composite has no hidden
runner dependency. `ContainerPlan` likewise declares the domains whose slice
parity it compares; container identity itself comes from the already parsed core
model.

`DomainRequest` is a typed enum. `c_surface` and `cpp_surface` carry the complete
plan-16 `RecoveryRequest`, including selection, analysis level, header inputs,
and limits; other domains carry their own validated request or `Default`. The
outer domain closure is resolved once before any domain runs. Inside a selected
recovery domain, plan 16's declared discovery barrier materializes exact entity
targets before optional ABI collectors execute. Those collectors are internal
to the already-selected domain, appear in its serialized resolved plan/execution
ledger, and cannot enable another `AnalysisDomain`. Thus targeted execution does
not weaken the outer no-hidden-domain rule.

`DiffPlan`, `AuditPlan`, and `ContainerPlan` are front ends, not executors:
each compiles into the `AnalysisPlan` handed to `Analyzer::run`, so exactly one
resolved plan per analyzed input determines execution and selectivity has a
single enforcement point.

The executor resolves the transitive closure once, executes each domain at most
once per slice, and stores owned results in a domain map. Shared primitive facts
are cached in a private `FactStore`; adding a public domain must not add a field
to a façade inspector. Results borrow neither the mapped file nor the executor.

`ImageInspector` is deleted, not adapted: no deprecated shim, alias, or
compatibility constructor survives. Every caller uses `Analyzer` directly, and
the architecture scanner rejects any reintroduction of the type.

### Domain state and snapshot schema

Writers emit `SnapshotDocument` schema version 3:

```rust
pub struct SnapshotDocument {
    schema_version: SnapshotSchemaVersion, // exactly 3
    container: ContainerIdentity,
    slices: NonEmpty<SliceSnapshot>,
}

pub struct SliceSnapshot {
    identity: SliceIdentity,
    domains: BTreeMap<DomainId, DomainState<DomainPayload>>,
}

pub enum DomainState<T> {
    NotRequested,
    Complete { value: T, issues: Vec<AnalysisIssue> },
    Unsupported { reason: UnsupportedReason },
    Failed { error: AnalysisFailure, issues: Vec<AnalysisIssue> },
}
```

`DomainPayload` is a typed enum with one variant per built-in domain.
Constructors keep `DomainId` and payload variant consistent. Every registered
domain receives exactly one record, including `NotRequested`; a missing,
duplicate, or unknown domain key is invalid for schema 3. Snapshot fields are
private, and serde decodes through a wire DTO followed by the same constructor
validation, so a domain ID/payload mismatch or incomplete registry cannot be
assembled through deserialization.

There is no legacy reader. A snapshot missing `schema_version`, carrying schema
version 1 or 2, carrying an unknown future version, or containing a domain
ID/payload mismatch is rejected with a typed error that tells the user to
regenerate the snapshot. Diff rejects any input it cannot read. Version 3 is the
first schema that stores the canonical evidence-first recovery payload from
plan 16; readers never guess whether an older header-only payload is compatible.

Diff compares only domains selected in a `DiffPlan`. CLI `--ignore-*` flags are
translated into exclusions before either input is analyzed. An ignored domain
must have an execution count of zero, not merely zero findings.

Audit builds its plan from enabled rules. Unsupported input and domain failure
appear in the report and cannot masquerade as “no findings.”

### Large-module seams

Split by responsibility while preserving a small public module surface through
`mod.rs` reexports:

```text
macho-header-syntax/src/
  lib.rs              public typed AST, parser, renderer, and validator entry points
  ast.rs              shared types plus supported C/C++/Objective-C declaration nodes
  parse.rs            bundled C/C++/Objective-C lowering with error/missing-node spans
  render.rs           deterministic source rendering from typed nodes only
  validate.rs         scopes, references, redeclarations, linkage, and ABI syntax rules

macho-analysis/src/report/
  mod.rs              validated public report roots and read-only reexports
  common.rs           IDs, identities, cardinality types, canonical JSON, shared enums
  recovery.rs         plan-16 RecoveryReport DTOs and validators
  objc.rs             plan-10 ObjCReport DTOs and validators
  swift.rs            SwiftReport DTOs and validators
  snapshot.rs         schema-3 DomainPayload registry and state validation
  registry.rs         exact schema/code/enum registry checked against the normative contract

macho-header-infer/src/
  lib.rs              validated artifact API and orchestration entry points
  bundle.rs           bounded deterministic RecoveryReport projection
  schema.rs           hypothesis bundle/response/report DTOs and validators
  prompt.rs           deterministic human/model prompt rendering
  validate.rs         support, operation, digest, pinned-fact, and header validation

macho-analysis/src/reconstruct/c/
  mod.rs              public entry points and orchestration
  model.rs            C type/declaration/evidence values
  dwarf.rs            DWARF-to-model lowering
  correlate.rs        symbol/header correlation
  project.rs          RecoveryReport-to-header-syntax projection and eligibility ledger

macho-cpp/src/abi/
  mod.rs              public body-analysis entry points
  cfg.rs              shared control-flow model
  arm64.rs            ARM64/ARM64e inference
  x86_64.rs           x86_64 inference
  arguments.rs        argument/return inference
  tests.rs            synthetic architecture fixtures

macho-analysis/src/diff/
  mod.rs              plan and public entry points
  container.rs        container/slice matching
  structure.rs        header/load-command/segment comparisons
  symbols.rs          symbols/imports/exports
  metadata.rs         dyld/ObjC/code-signing domains
  diagnostics.rs      issue/diagnostic comparison
  report.rs           finding types and pure render model

macho-mutate/src/patch/
  mod.rs              public patch API
  model.rs            operations and patch symbols
  search.rs           byte/symbol lookup
  planner.rs          plan construction
  trampoline.rs       detour/trampoline layout
  relocate.rs         strict instruction relocation
  validate.rs         overlap/range/precondition checks
  arm64.rs            ARM64 encodings/policies
  x86_64.rs           x86_64 encodings/policies
```

No resulting production file may exceed 800 non-blank, non-comment lines without
a written exception in this plan explaining a single responsibility that cannot
be split. The implementation has no pre-approved exceptions. A production file
is a non-test source: a file that is entirely a `#[cfg(test)]` module (such as
`src/tests.rs`) is exempt, and `#[cfg(test)]` blocks inside mixed files do not
count toward the ceiling.

`macho-header-syntax` supports only the declaration subset the recovery systems
can prove: C/C++ namespaces, records, enums, typedefs/aliases, variables,
functions, methods, supported templates, pointers/references/arrays/functions,
cv/ref qualifiers, variadics, supported storage/linkage, and supported calling
conventions; and Objective-C interfaces, categories, protocols, ivars,
properties, required/optional sections, methods, adopted protocols, and external
forward declarations. Its semantic validator resolves referenced types and
declaration dependencies, enforces scope and redeclaration rules, rejects conflicting
duplicates, validates storage/linkage/calling-convention combinations, preserves
C empty-versus-unspecified parameter state, and requires complete template and
type dependency closure. Syntactic success alone is never header validity.
Unsupported or semantically invalid constructs produce typed unresolved entries;
they are never copied through as arbitrary source strings.

Pure reconstruction returns owned models or rendered strings. Filesystem writes
remain delivery concerns. Header correlation consumes only explicit user-supplied
roots; SDK discovery, `xcrun`, compiler invocation, and process-backed demangling
are removed from production inspection and recovery.

## Objective-C and Swift analysis surfaces

Objective-C behavior follows plan 10. `macho-objc::ObjCGraph` and its validated
runtime values are the only semantic authority; `macho-analysis` owns the
selective domain/report wrapper, and the CLI renders it. No caller recreates
selector ownership, category folding, inheritance, or header declarations from
symbol strings.

Swift analysis is descriptor- and reflection-first. `macho-swift` parses and
indexes supported context descriptors, nominal type descriptors, protocol and
conformance descriptors, field metadata, associated-type metadata, type
references, and reflection strings from the selected image. In-process Swift
demangling supplies supplementary symbol observations and display spellings; it
cannot promote a symbol-only name into a metadata-defined type.

The canonical `SwiftReport` records, per slice:

```rust
pub struct SwiftReport {
    schema_version: SwiftReportVersion, // exactly 1
    slices: NonEmpty<SwiftSliceReport>,
}

pub struct SwiftSliceReport {
    architecture: Architecture,
    image: ImageIdentity,
    observations: Vec<SwiftObservation>,
    evidence: Vec<SwiftEvidence>,
    entities: Vec<SwiftEntity>,
    selection: SwiftSelectionResult,
    diagnostics: Vec<SwiftDiagnostic>,
    executions: NonEmpty<SwiftCollectorExecution>,
}

pub struct SwiftEntity {
    id: SwiftEntityId,
    identity_stability: IdentityStability,
    state: SwiftEntityState,
    kind: SwiftValue<SwiftTypeKind>,
    qualified_name: SwiftValue<SwiftQualifiedName>,
    descriptor: SwiftValue<Option<SwiftDescriptorLocation>>,
    parent: SwiftValue<Option<SwiftEntityRef>>,
    fields_or_cases: SwiftValue<Vec<SwiftField>>,
    conformances: SwiftValue<Vec<SwiftConformanceRef>>,
    raw_linkages: Vec<String>,
    observation_ids: NonEmpty<SwiftObservationId>,
    gaps: Vec<SwiftGap>,
}

pub enum SwiftEntityState {
    MetadataDefined,
    Referenced,
    SymbolOnly,
    Partial,
    Unknown,
}

pub enum SwiftValue<T> {
    Known { value: T, evidence: NonEmpty<SwiftEvidenceId> },
    Conflicted { candidates: AtLeastTwo<SwiftCandidate<T>> },
    Unavailable { reason: SwiftUnavailableReason },
}

pub struct SwiftCandidate<T> {
    value: T,
    evidence: NonEmpty<SwiftEvidenceId>,
}

pub struct SwiftSelectionResult {
    selected_entity_ids: Vec<SwiftEntityId>,
    totals: SwiftPartitionCounts,
}

pub struct SwiftCollectorExecution {
    collector: SwiftCollectorId,
    outcome: SwiftCollectorOutcome,
    input_records: u64,
    output_records: u64,
}

pub enum SwiftCollectorId {
    MetadataDescriptors,
    ReflectionMetadata,
    SymbolDemangling,
    Reconciliation,
}

pub enum SwiftCollectorOutcome {
    Complete,
    Unsupported { reason: SwiftUnavailableReason },
    Failed { diagnostic_id: SwiftDiagnosticId },
    Truncated { omitted_lower_bound: u64 },
}

pub struct SwiftObservation {
    id: SwiftObservationId,
    source: SwiftObservationSource,
    raw: Vec<u8>,
    location: Option<SwiftMetadataLocation>,
    disposition: SwiftObservationDisposition,
}

pub enum SwiftObservationDisposition {
    Included { entity_ids: NonEmpty<SwiftEntityId> },
    Unknown { diagnostic_id: SwiftDiagnosticId },
    Excluded { reason: SwiftExclusionReason },
}
```

All fields and closed registries use the normative wire contract. They are
privately constructed, and serde validates unique IDs,
bidirectional references, parent/conformance edges, observation conservation,
selection totals, and collector counts. A unique canonical descriptor identity
is cross-build stable. Duplicate/local descriptor or symbol names use distinct
occurrence-scoped IDs; same-name observations at different locations never
merge without positive reference evidence.

- every metadata-defined type/protocol/conformance with stable ID, raw
  descriptor location, kind, qualified name components, fields/cases where
  encoded, parent/reference edges, and evidence;
- every supported demangled Swift symbol that does not resolve to a descriptor
  as a `SymbolOnly` entity with raw linkage, demangled AST/display name,
  presence, address/section, and explicit missing-descriptor reason;
- malformed descriptor/symbol observations as `Unknown` with raw evidence and
  stable diagnostics;
- unsupported or truncated metadata as `Partial`, never as a complete empty
  index; and
- excluded non-Swift observations and unselected-kind counts so a filtered or
  zero-result view remains accountable.

Entity states are `MetadataDefined`, `Referenced`, `SymbolOnly`, `Partial`, and
`Unknown`; text and JSON use these exact non-overlapping partitions. A referenced
or symbol-only nominal name is never rendered as a local type definition.
Unsupported metadata kinds or manglings remain typed gaps and never fall back to
a process.

The CLI grammar remains shallow and scriptable:

```text
macho swift PATH [--arch ARCH]
                 [--kind class|struct|enum|protocol|unknown]
                 [--format text|json]
```

Default text begins with completeness and source counts, then renders distinct
metadata-defined, referenced, symbol-only, partial, unknown, and excluded
sections through the shared aligned/colorized output layer. A kind filter changes
displayed IDs, not collection or report conservation. JSON always uses the
common envelope and a `slices` array for thin and fat inputs; it never unwraps a
single slice. No Swift header/source emitter is claimed by this contract.

Required fixtures cover each supported descriptor/reflection family, parent and
cross-reference resolution, valid and malformed modern/legacy manglings,
descriptor-plus-symbol reconciliation, symbol-only fallback, referenced versus
defined nominal types, truncation, thin/fat divergence, kind filtering, and a
zero selected result with complete counts. A panicking Swift collector proves
unrelated and symbols-only plans do not execute it. The current iMazing binary
is recorded with hash, architectures, commands, and assertions in
`plans/evidence/15-imazing-language-surfaces.md`; portable deterministic fixtures
remain the CI authority when that private binary is absent.

## Mutation and workflow contracts

`macho-mutate` owns structural work only:

- `PatchPlan` is validated for overlap, architecture support, branch range,
  expected original bytes, and code-signature consequences before application;
- `StructuralPatchPreview` reports byte ranges, load-command/layout changes,
  signing impact, and validation diagnostics without using analysis;
- transaction application is all-or-nothing in memory;
- output is strictly reparsed and validated before bytes are returned;
- the crate never writes files or chooses backup paths; and
- `macho-mutate` neither depends on nor reexports `macho-analysis`.

`macho-workflow` is the only owner of semantic composition:

```text
strict parse before
-> selected before-analysis plan
-> structural patch plan and preview
-> apply in memory
-> strict reparse and structural validation
-> selected after-analysis plan
-> semantic diff
-> WorkflowPreview / committed bytes
```

`WorkflowPreview` contains both `StructuralPatchPreview` and `DiffReport`. The
workflow accepts an explicit `AnalysisPlan`; it does not silently build every
domain. Signing adapters are injected. The CLI performs atomic filesystem
replacement and backup policy only after the workflow returns verified bytes.

## Host-process boundary

Inspection and recovery are process-free on every platform:

- `macho-symbols` performs Rust and Itanium demangling in process;
- `macho-swift` performs supported Swift demangling in process and reports an
  unsupported encoding as typed evidence rather than launching a tool;
- `macho-header-syntax` provides the bundled C/C++/Objective-C parsers, typed
  renderers, and semantic validator used by analysis and header inference;
- header lookup consumes explicit hashed roots and performs no SDK discovery;
- no inspection, recovery, demangling, or validation path has a degraded
  process-backed fallback.

`macho-mutate::SignatureProvider` remains the sole injectable host-process
boundary because signing is an explicit mutation action, not inspection. The
CLI can own host-signing implementations under `macho-cli/src/adapters/`.

The architecture verifier rejects `std::process::Command`, `Command::new`,
`xcrun`, and known compiler/demangler paths throughout product code except the
explicit signing-adapter module. Tests use in-process fakes and synthetic data;
they never require Xcode.

## CLI contract

### Ownership and entry point

Move all of `crates/macho/src/commands/` and CLI-specific input/file-output code
to `crates/macho-cli/src/`. Create a CLI library target containing testable
dispatch; keep `main.rs` limited to constructing system I/O, recording terminal
state, and converting the returned code to `ExitCode`. Shared presentation
mechanics live under `macho-cli/src/commands/output/`; command-specific content
remains in the owning command module.

```rust
pub struct CliIo<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
    pub stdout_is_terminal: bool,
    pub stderr_is_terminal: bool,
}

pub fn run_from<I, S>(args: I, io: &mut CliIo<'_>) -> ExitStatus;
```

Every command follows `parse arguments -> execute library operation -> return
typed report -> render once`. Renderers receive `&mut dyn Write`; shared layout,
color, JSON, and envelope operations delegate to the CLI output module. Delete
capture globals, output macros, local `println!` shadowing, and report methods
that print directly. `run_captured` uses two `Vec<u8>` writers through the same
`CliIo` path as production and marks both streams non-terminal.

No code under `macho-cli/src/commands/` may invoke `println!`, `print!`,
`eprintln!`, `eprint!`, `std::io::stdout`, or `std::io::stderr`.

### Canonical grammar

The current flat grammar is canonical — kept as a deliberate design choice, not
an inherited constraint:

```text
info deps codesign dwarf
symbols imports exports fixups relocations ranges
strings xrefs vtables
objc swift cpp c
diff audit container snapshot
patch header-infer
fileset cache
```

An unrecognized command is an ordinary usage error (exit code 2) through the
single Clap path; no adapter, alias, or normalization layer exists in front of
it. Primary help and README examples show only canonical syntax, and the
README command reference is generated from the live router.

### Arguments and output

Define common flattened argument structs for input path, architecture selection,
format, and analysis limits. Command-specific copies are forbidden when the
semantics are shared.

All human-table commands accept common `--format text|json` and
`--color auto|always|never`
options; audit additionally accepts `sarif`. `--format` is the only format
selector: the old `--json` and `--sarif` flags are removed, not aliased. Color
defaults to `auto`: human terminal output is colored only on a terminal and only
when neither `NO_COLOR` nor `TERM=dumb` disables it. `always` forces ANSI for
human table text even when redirected; `never` forbids ANSI. JSON, SARIF, and
header-source output never contain ANSI. Explicit `--color always` with JSON,
SARIF, or a header-source view is a usage error; `auto` and `never` are accepted
and both render those machine/source formats without ANSI.
JSON uses:

```json
{
  "schema_version": 1,
  "command": "info",
  "ok": true,
  "data": {},
  "diagnostics": []
}
```

The `data` payload is a command-specific typed report. Snapshot data carries its
own nested schema version. SARIF is emitted as the standard SARIF document and is
the only non-envelope machine format.

`macho-cli::commands::output` owns one ANSI-aware table/layout engine and one
semantic palette. It measures unstyled cell width, pads before styling, and
renders each logical table only after collecting its rows. Command modules own
row content and typed reports; the output module owns columns, indentation,
color policy, enum styling, `key=value` fragments, headings, and machine
envelopes. No separate `macho-output` crate is introduced because none of these
delivery concerns is a reusable library boundary.

`../talos/crates/talos-console` is the design reference for terminal capability,
semantic styling, and width-safe composition. `macho` does not depend on the
Talos workspace or copy its domain vocabulary; it implements the applicable
mechanics inside the CLI output module.

The semantic palette is fixed to basic ANSI roles and never carries meaning
without text/indentation: headings are bold; primary entity names are bold cyan;
child entity names are cyan without bold; enum/type values are magenta; numeric
addresses, offsets, and sizes are yellow; property keys and punctuation are
dim/default; property values are default or yellow when numeric; source tags and
secondary counts are dim/default; warnings are yellow and errors are red.
Callers request semantic roles, never raw escape sequences.

The owning block declares columns before styling:

| Block | Logical columns |
| --- | --- |
| `info` header | property key including colon, value; key width is the maximum unstyled key width |
| `info` segment | segment name, `VM`, VM address, VM size, `File`, file offset, file size, ordered property fragments |
| `info` section | indented section name, address, size, `off`, `align`, section enum, ordered optional property fragments |
| `info` load command | bare ordinal, command enum, primary payload, command-file offset, command size, ordered optional fragments |
| `deps` | install name, compatibility/current versions as present, right-aligned `linked` state |
| `ranges` | fixed-width `start..end`, right-aligned hexadecimal size, source tag, symbol text |

Segment and section rows are separate tables with coordinated address/size
anchors; a section is never padded into a fake segment row. Property fragments
are structured cells (`key`, `=`, typed value), not precolored strings. Optional
property columns are created only when at least one row in that block has the
property and retain declaration order rather than alphabetical or row-dependent
order.

Human-output requirements are exact:

- `info` aligns header properties, segment fields, section fields, and load-
  command fields by logical block;
- segment rows and their section children use distinct indentation and semantic
  styles; segment names, section names, enum values, property keys, and property
  values are visually distinguishable;
- load-command ordinals are bare right-aligned numbers, without brackets;
- `deps` renders its `linked` field in a right-aligned column through the shared
  console renderer;
- `ranges` aligns the fixed-width `start..end` range, size, source, and symbol
  columns, preserves symbol spelling without Markdown escaping, and applies
  demangling before width measurement;
- missing optional properties reserve no phantom column, while properties that
  occur in any row align across the block; and
- color never changes spacing or bytes outside ANSI sequences.

Golden tests cover the `info` header/segment/section/load-command blocks,
`ranges`, and `deps` with color `never` and `always`; stripping ANSI from the
colored golden output must produce the byte-identical uncolored output.

Channel rules are exact:

- stdout contains requested data only;
- stderr contains status, warnings, and errors only; text mode uses human text,
  while JSON mode uses a failure envelope with `ok: false`;
- JSON and SARIF stdout are never contaminated by warnings;
- commands that create files return a typed manifest; text renders it to stdout
  and JSON renders it in `data`;
- no progress output is emitted.

On execution failure, stdout is empty and the selected text/JSON error is written
to stderr. On diff or audit policy failure, the completed report remains on
stdout and a policy diagnostic is written to stderr. Usage parsing pre-scans the
format selector so a recognized JSON request receives a JSON usage error on
stderr; otherwise Clap text is used. SARIF is only a successful report format,
so usage and execution errors remain text or JSON rather than malformed SARIF.

Exit behavior is centralized:

| Code | Meaning |
| --- | --- |
| `0` | Command completed and any requested policy threshold passed. Empty-but-valid results are success. |
| `1` | Input/parse/execution failure, selected object not found, or unsupported required capability. |
| `2` | Argument/usage error. |
| `3` | Command completed but a diff or audit policy threshold failed; the completed report is on stdout. |

Policy failure (3) is distinct from execution failure (1) so CI can gate on
findings without conflating them with tool breakage. Libraries never return
these numeric codes.

## Version, docs, and release authority

The amended implementation retains every workspace package at `0.2.0`. Workspace
dependencies continue to use `version.workspace = true` or the one workspace
version declaration. `macho --version` must come from the same package metadata.

Preserve and update the existing authorities:

- `CHANGELOG.md` keeps its `0.2.0` architectural-break entry and records the
  amended language/report contract; and
- generated command reference markers in `README.md` remain bound to live help.

The existing unpublished `crates/xtask` crate and `.cargo/config.toml` alias
remain authoritative for these commands and are extended for this contract:

```text
cargo xtask architecture
cargo xtask docs --check
cargo xtask release --check
cargo xtask verify
cargo xtask verify-fuzz
```

`docs --check` compares generated Clap help, command tables, and checked
examples to committed documentation, and verifies that every diagnostic-code
constant and schema enum in the workspace appears exactly once in
`plans/schemas/language-recovery-wire-v1.md`.
Examples use deterministic `macho-test-support` fixtures and are executed with
`trycmd` in the docs test target. `release --check` verifies:

- one workspace product version;
- `macho --version` equals Cargo metadata;
- when version-bearing files match `HEAD` and `HEAD` has an exact `vX.Y.Z` tag,
  it equals the workspace version;
- the changelog heading contains that version; and
- the lockfile contains no stale workspace package version.

This tag rule prevents a dirty version edit from being mistaken for the
historical tag at `HEAD`; clean release CI always exercises the comparison. Unit
fixtures exercise both matching and mismatched clean-tag states.

`verify` composes the full final gate listed below. It must propagate the first
failure and print the command that failed.

## Quality infrastructure

### Architecture checks

`cargo xtask architecture` parses `cargo metadata` and enforces the permitted
edge matrix. It also scans source ownership for:

- `clap`, `memmap2`, and `anyhow` outside allowed delivery/tool crates;
- process execution outside the explicit signing adapter and build tooling;
- CLI output bypasses;
- `macho-analysis` references in `macho-mutate`;
- `commands` or `inputs` modules in the façade;
- public `&Vec<T>` return types;
- the removed zero-argument `first_mach()` API;
- silent decoded-instruction result dropping;
- resurrection of removed surfaces: `ImageInspector`, snapshot v1/v2 reading,
  and `--json`/`--sarif` flags; and
- production files over the module-size ceiling.

The scanner uses syntax-aware checks where an `rg` check would create material
false positives. Its own tests include one valid synthetic graph and one fixture
for every forbidden edge or source pattern.

### Fixtures

Create deterministic fixture builders and commit only minimal binary fixtures
whose exact bytes matter. Compile-fail fixtures use `trybuild`; executed doc
examples use `trycmd`. Every rule has a valid and an invalid case:

| Surface | Valid fixture | Invalid/negative fixture |
| --- | --- | --- |
| Container parse | thin plus multi-arch fat | zero-arch fat, overlapping slice, truncated slice, limit exhaustion |
| Fileset | fileset container listing and inspecting two entries | truncated `LC_FILESET_ENTRY` and out-of-bounds entry offset rejected |
| Dyld cache | minimal synthetic cache lists images and returns extraction bytes | truncated mapping and out-of-bounds image offset rejected |
| Address map | sorted non-overlapping segments | overlap and checked-add overflow |
| Load commands | bounded known and unknown command | truncated payload and impossible `cmdsize` |
| Parse mode | warning-bearing recoverable image | same image fails strict; hard bounds failure fails both modes |
| Error context | nested fat/slice/command failure | assertion that slice, command index, span, and code survive conversion |
| Instruction decode | complete x86_64 and ARM64 streams | invalid byte/word yields strict error and a lossy `DecodeGap` |
| Analysis state | requested empty domain | unrequested, unsupported architecture, and injected runner failure are distinct |
| Selective analysis | plan with two required domains | excluded runner panics if called; test must still pass |
| Snapshot versioning | v3 round trip | missing `schema_version`, schema v2, unknown future version, and mismatched domain ID/payload each rejected with a typed error |
| Mutation | non-overlapping valid patch | overlap, stale expected bytes, branch-range failure, failed strict reparse; original bytes unchanged |
| Workflow | selected semantic before/after diff | analysis failure prevents filesystem commit |
| In-process language tools | Rust, Itanium, and Swift names plus syntactically and semantically valid C/C++/Objective-C header ASTs | unsupported/malformed encodings, syntax-invalid headers, and syntax-valid headers with unresolved types, conflicting redeclarations, or illegal linkage/ownership are typed and recorded without a process launch |
| CLI I/O | `info`, `diff`, `audit`, and file-output commands through injected writers; TTY/non-TTY, `NO_COLOR`, `TERM=dumb`, `always`, and `never` color cases; Unicode and optional-column rows | parse error only on stderr; JSON stdout remains parseable; no global output; `--color always` with JSON/SARIF/header source is rejected; policy failure exits 3 with the report on stdout |
| CLI usage errors | every canonical command parses | unknown commands and malformed arguments return usage code 2 with empty stdout |
| Version/docs | matching synthetic tag/metadata/help | tag mismatch, stale command, and stale example fail xtask checks |

Synthetic Mach-O builders live in the unpublished `macho-test-support` crate and
are shared instead of copied across integration tests.

### Fuzzing

Extend the existing seven-target `cargo-fuzz` package to these ten targets:

1. container and fat parsing under strict and forensic options;
2. load-command parsing and limit enforcement;
3. dyld bind/rebase/export/chained-fixup parsing;
4. code-signature parsing;
5. instruction strict/lossy decoding;
6. mutation plan/apply/reparse round trips; and
7. dyld shared-cache and fileset container parsing;
8. header-syntax parse/render/reparse and semantic validation;
9. deterministic report wire decode, canonicalization, and validation; and
10. symbol routing, demangling, and recognized suffix preservation.

Every target asserts no panic, no unbounded allocation beyond configured limits,
and deterministic results for the same input. Mutation fuzzing additionally
asserts that a successful output strictly reparses and a failed application does
not alter the input buffer. Seed corpora include each valid and invalid fixture.

CI compiles every target and runs bounded smoke fuzzing. The exact smoke duration
is a CI scheduling value, not a substitute for deterministic regression tests.

### Benchmarks

Extend the existing Criterion benchmark suite for thin/fat parsing,
strict/forensic validation,
full versus selective snapshots, xref construction, semantic diff, C/C++
reconstruction, and structural/semantic patch preview. Benchmarks use committed
or deterministically generated fixtures and write normal Criterion baselines.

Acceptance is not an arbitrary wall-clock threshold. The structural performance
contracts are enforced in tests:

- container iteration allocates zero heap collections;
- excluded analysis runners execute zero times;
- each prerequisite domain executes at most once per slice;
- semantic preview analyzes only its explicit plan; and
- limits bound input-derived collection growth.

`cargo bench --workspace --all-features --no-run` is a required final gate; CI retains benchmark
artifacts so regressions can be compared deliberately.

### Lints and documentation

After public-surface reduction, every published library root uses
`#![deny(missing_docs)]`. Internal modules become private unless external users
need their module path. Every public item documents invariants, failure behavior,
and units where relevant.

The final lint gate is:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo test --workspace --all-features
cargo bench --workspace --all-features --no-run
```

Language and header-tool tests run entirely in process on every platform. No CI
job installs or invokes Xcode tooling for inspection, recovery, demangling, or
header validation. Host-signing integration is isolated from the portable
inspection/recovery gate.

## Dependency-ordered implementation packages

These packages are checkpoints in one pass. Do not publish, tag, or declare the
architecture complete between them.

### WP0 — Lock the executable contract

1. Re-run baseline `cargo metadata`, tree, test, format, Clippy, rustdoc, CLI
   help, capture, version, and documented-command probes.
2. Record results in `plans/evidence/15-baseline.md`, distinguishing pre-existing
   user changes from implementation changes.
3. Add failing architecture-check fixtures and behavioral tests for every
   falsification criterion before moving ownership.
4. Extend the existing `crates/xtask` commands and negative fixtures for the
   amended crate graph, schema registries, process boundary, language reports,
   and corpus ledgers. Every command remains fully working; no placeholder
   success path is permitted.
5. Generate one deterministic schema-2 payload golden for each existing domain,
   record its SHA-256 in the live ledger, and lock unchanged payload shapes
   before implementing the schema-3 wrapper and language payload replacements.

Checkpoint: each new negative fixture fails for the intended current weakness,
not because the fixture or command is malformed.

### WP1 — Close the core

1. Implement parse modes, limits, outcomes, structured errors, diagnostic codes,
   checked addressing, private fields, validated construction, optional first
   image access, zero-allocation iteration, and docs.
2. Move serialization/reporting types out of core.
3. Update callers to use explicit selection and address errors.
4. Make strict and forensic fixture matrices pass.

Checkpoint: core tests and fuzz targets pass with only the permitted core
dependencies; architecture check finds no upward or host edge.

### WP2 — Extract reusable metadata leaves

1. Audit and complete the existing `macho-symbols`, `macho-dyld`,
   `macho-codesign`, `macho-dwarf`, `macho-objc`, `macho-swift`, and `macho-cpp`
   crates in place. Create only `macho-header-syntax`, using the ownership above.
2. Resolve concepts by moving them downward or injecting traits; never add a
   reverse dependency.
3. Replace process-backed Swift demangling and header validation with complete
   in-process production implementations. Move the shared header AST, bundled
   parser, renderer, and semantic validator into `macho-header-syntax`;
   unsupported encodings or declarations remain typed gaps and never trigger a
   process fallback.
4. Complete plan 10's ObjC encoding/graph values and this plan's descriptor-
   first Swift metadata plus symbol-only fallback in their leaf crates.
5. Design the façade reexport surface clean; no import path is preserved for
   its own sake.
6. Add direct crate-level tests proving each leaf works without the façade.

Checkpoint: permitted-edge matrix passes; each leaf compiles/tests independently
with `cargo test -p CRATE`; no published crate contains a process launch.

### WP3 — Make instruction failure explicit

1. Change `InsnIter` to yield results and add `DecodeReport`/`DecodeGap`.
2. Convert relocation and mutation callers to strict mode.
3. Convert heuristic analysis callers to explicit lossy mode and issue
   propagation.
4. Replace skip-oriented tests with strict/lossy paired tests.

Checkpoint: injected invalid instructions fail mutation, remain visible in
analysis, and cannot be silently filtered by any caller.

### WP4 — Build selective analysis and schema v3

1. Implement domain IDs, runners, dependency resolution, analysis plans, fact
   caching, owned documents, and four-state domain results.
2. Move normalized image/dependency policy into analysis.
3. Implement v3 serialization and typed rejection of unversioned, schema-v2,
   or unknown-version snapshots.
4. Make snapshot, diff, audit, container, xref, and reconstruction entry points
   consume explicit plans.
5. Make ignored diff domains and disabled audit rules absent from execution.
6. Delete `ImageInspector` and migrate every caller to `Analyzer`.
7. Implement canonical ObjC and Swift reports with defined/referenced/
   symbol-only/partial/unknown accounting and serialized collector ledgers.

Checkpoint: execution-counter tests prove exclusion and at-most-once dependency
execution; snapshot-rejection and state-distinction fixtures pass.

### WP5 — Separate mutation from workflow

1. Remove the analysis dependency and reexport from `macho-mutate`.
2. Split patch planning by responsibility and architecture.
3. Implement structural preview and strict reparse/validation.
4. Complete the existing `macho-workflow` crate for selected semantic
   before/after analysis and diff.
5. Move filesystem atomic replace and backup behavior to CLI.

Checkpoint: `cargo tree -p macho-mutate` contains no analysis/facade/CLI crate;
failed patch and workflow fixtures preserve original and destination bytes.

### WP6 — Complete analysis module seams and adapters

1. Split C reconstruction, C++ ABI analysis, header syntax, diff, and patch
   modules into the declared layouts.
2. Keep public paths stable through narrow `mod.rs` reexports.
3. Convert renderers to pure string/model output.
4. Make analysis and header inference consume `macho-header-syntax`; prove both
   syntax and semantic header validation, and implement the isolated
   host-signing adapter with typed capability results.
5. Make Objective-C projection consume the shared Objective-C syntax AST and
   prove render/reparse/semantic validation without a host process.
6. Enforce the production-file size ceiling.

Checkpoint: module-size and process-boundary checks pass; reconstruction tests
use synthetic fixtures and in-process tooling on every platform.

### WP7 — Make the façade truthful

1. Define the exact feature matrix.
2. Remove `commands`, `inputs`, Clap, memory mapping, and `anyhow`.
3. Reexport only documented stable entry points.
4. Add feature-combination compile tests for no-default, each individual feature,
   default, and full.

Checkpoint: minimal façade dependency tree contains core plus no delivery
dependencies; every feature combination compiles and has a documented purpose.

### WP8 — Rebuild the CLI as the delivery layer

1. Move commands and input adapters into `macho-cli`.
2. Implement injected I/O, one render point, output envelope, format/color
   policy, and centralized exit mapping under `macho-cli::commands::output`.
3. Implement canonical shared arguments.
4. Convert each command to typed report execution and remove direct printing.
5. Complete `info`, `ranges`, `deps`, ObjC, Swift, C, C++, and header-infer
   layouts/partitions using the shared output contract.
6. Add golden text, JSON schema, SARIF, capture, usage-error, and exit tests.

Checkpoint: the same representative commands through system I/O and captured I/O
produce byte-identical stdout/stderr; architecture output scan is clean.

### WP9 — Bind docs, versioning, and delivery gates

1. Preserve workspace version `0.2.0` and update the existing changelog
   authority for the amended contract.
2. Replace stale README syntax with generated canonical help and examples.
3. Complete `xtask` architecture/docs/release/verify checks and their negative
   fixtures.
4. Extend the existing GitHub Actions workflow under `.github/workflows/` for
   Linux library coverage and macOS full/adapters coverage.
5. Extend the existing seven fuzz targets to the ten-target contract and extend
   the existing Criterion benchmark suite.
6. Reduce/document the public surface until strict Clippy and rustdoc pass.

Checkpoint: deliberately stale help, version, tag, dependency, process, and
output fixtures are rejected by their owning checks.

### WP10 — Whole-tree convergence

1. Search for and remove obsolete modules, reexports, macros, legacy snapshot
   constructors, eager analysis paths, process calls, and stale docs.
2. Run every focused negative/positive matrix.
3. Run `cargo xtask verify` and then `cargo xtask verify-fuzz` without allowing
   either verifier to modify files and with implementation-owned changes
   isolated from unrelated worktree changes.
4. Review `cargo metadata`, `cargo tree` for every published crate, public docs,
   and CLI help as independent evidence.
5. Record final commands and results in `plans/evidence/15-final.md`.

Checkpoint: every definition-of-done item below is evidenced. A green subset is
not completion.

## Agent execution protocol

An implementation agent must:

1. inspect `git status`, `git diff`, and live source before each ownership move;
2. preserve unrelated user changes and never use destructive reset/checkout;
3. keep a live obligation ledger at `plans/evidence/15-ledger.md`, keyed to
   the audit traceability table and updated at every checkpoint;
4. complete each touched API, caller migration, docs, valid fixture, invalid
   fixture, and verifier before advancing;
5. use compile errors as boundary evidence, not as permission to add a shortcut
   dependency;
6. update the plan only when live evidence proves a path/name changed, without
   reducing the behavior contract; and
7. stop on a trigger below instead of guessing across a design contradiction.

### STOP triggers

Stop implementation and report the exact evidence if:

- the permitted graph cannot be realized without a cycle and no lower shared
  owner or injected trait satisfies both callers;
- strict versus forensic behavior cannot be decided from a safe representational
  invariant;
- a mutation operation cannot prove atomic rollback or strict reparse;
- a requested rule cannot be paired with an invalid fixture that fails for the
  intended reason;
- real signing-tool behavior is the only available proof for the signing
  adapter contract and no deterministic adapter fixture can be built;
- implementation overlaps unresolved user changes in the same lines or moves;
  or
- any proposed fix requires weakening a falsification criterion.

Warnings, workload size, lint volume, or the need to update many callers are not
STOP conditions.

## Final verification gate

`cargo xtask verify` is the stable-toolchain gate and must run, in this order:

```text
cargo xtask architecture
cargo xtask docs --check
cargo xtask release --check
cargo fmt --all -- --check
cargo check --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo test --workspace --all-features
cargo bench --workspace --all-features --no-run
```

`cargo xtask verify-fuzz` then runs `cargo fuzz build` under the configured
nightly toolchain. Both commands are mandatory final gates. CI additionally
runs bounded fuzz smoke targets and the macOS host-signing adapter suite.
The agent must also run these independent inspections after `verify`:

```text
cargo metadata --no-deps --format-version 1
cargo tree -p macho-core
cargo tree -p macho-mutate
cargo tree -p macho --no-default-features
cargo run -q -p macho-cli -- --help
cargo run -q -p macho-cli -- --version
```

For representative valid, invalid, and machine-output CLI cases, compare
the live process result to the injected-writer result. This is the second route
that prevents a passing capture-only test from masking system-I/O drift.

## Definition of done

The plan is complete only when all statements are true:

- every target crate exists, owns only its declared responsibility, and satisfies
  the permitted edge matrix;
- core is free of domain metadata, serialization/reporting policy, process
  execution, panicking selection helpers, open invariant fields, and allocating
  container iteration;
- error kinds and diagnostics retain typed context through every layer;
- strict and forensic parsing have documented, tested divergence;
- instruction failures are errors or gaps at every call site;
- analysis plans determine actual execution and schema v3 represents all four
  domain states;
- `macho-analysis::report` is the sole common wire owner, and every language,
  recovery, header, hypothesis, and snapshot language payload matches the
  normative schema and closed registry;
- symbols-only plans execute no language, debug, RTTI, vtable, ABI-body, or
  header collector, while C/C++, Objective-C, and Swift surfaces conserve and
  expose every observation partition;
- `macho-header-syntax` is the sole typed header AST/parser/renderer/semantic-
  validator authority, and production inspection/recovery launches no process;
- mutation is independent of analysis and semantic composition exists only in
  workflow;
- the large modules are split along the declared seams and pass the size check;
- the façade has its feature matrix and no delivery dependencies;
- the CLI owns all commands/inputs/adapters, captures all output through injected
  writers, and obeys format/channel/exit contracts;
- canonical docs execute successfully;
- workspace, CLI, changelog, lockfile, and exact release tag cannot drift without
  a failing check;
- CI, fuzz targets, corpora, and benchmarks are committed and runnable;
- strict format, check, Clippy, rustdoc, test, benchmark-build, and fuzz-build
  gates pass; and
- final evidence accounts for every row below without “follow-up,” “later,”
  placeholder, or waived scope language.

## Audit traceability

| Audit weakness | Owning packages | Primary proof | Negative proof |
| --- | --- | --- | --- |
| Undefined or split serialized contracts | WP0, WP2, WP4 | normative wire registry plus schema equality and canonical goldens | unknown keys/tags, stale versions, dangling IDs, duplicate IDs, and registry drift are rejected |
| False core boundary and heavy dependencies | WP1, WP2 | metadata/tree matrix | forbidden-edge fixture |
| Recovery process execution | WP2, WP6 | source ownership check, in-process parser/demangler tests | process-call fixture outside the signing adapter |
| Split header ownership or syntax-only validation | WP2, WP6 | one header-syntax AST/parser/renderer/semantic-validator contract consumed by analysis and inference | dependency-cycle fixture plus syntax-valid unresolved-type/conflicting-redeclaration fixtures |
| Misleading ObjC/Swift language output | WP2, WP4, WP6, WP8 | canonical partitioned reports plus recorded iMazing language-surface acceptance | referenced/symbol-only/partial/malformed fixtures cannot become local definitions or an unaccounted zero |
| Open model invariants and panic/allocating helpers | WP1 | core API/tests/docs | zero-fat, overlap, overflow, compile-fail field construction |
| String-heavy shared errors | WP1, WP2, WP4, WP5 | typed error assertions | nested failure retains code/span/context |
| Silent instruction skips | WP3 | strict/lossy paired tests | invalid byte/word cannot disappear |
| Eager snapshots and post-compute ignore flags | WP4 | runner counters | excluded runner panics if invoked |
| Hidden or overbroad recovery collectors | WP4 | serialized request/resolved-plan/execution ledgers | panicking unselected collector and filtered ABI target-set fixtures |
| Kitchen-sink symbol fallback | WP4, WP8 | symbols-only and ranges execution counters plus useful aligned output goldens | every language/debug/RTTI/vtable/ABI/header collector panics if called |
| Misleading C/C++ recovery | WP2, WP4, WP6, WP8 | canonical recovery report, field provenance, safe-header ledger, and Talos acceptance | weak evidence cannot become a source type/prototype or silently disappear |
| Ambiguous analysis state | WP4 | v3 schema round trip | four states serialize distinctly; schema v2 is rejected |
| Fixed `ImageInspector` capability locks/lifetimes/`&Vec` | WP4 | type deleted; all callers on `Analyzer` | architecture scan rejects any reintroduction |
| Mutation depends on analysis | WP5 | `cargo tree -p macho-mutate` | forbidden-edge fixture |
| Façade owns CLI and has no features | WP7, WP8 | feature compile matrix/tree | commands/input/delivery-dep scan |
| Oversized mixed modules | WP6 | size and responsibility check | over-ceiling fixture |
| Broken/inconsistent output capture | WP8 | process-vs-injected byte comparison | global-output command fixture |
| Unaligned or indistinguishable terminal output | WP8 | unstyled and colored `info`, `deps`, `ranges`, and language goldens | stripped colored bytes differ from uncolored bytes, bracketed ordinals return, or optional columns drift |
| CLI format/channel/exit inconsistency | WP8 | golden and schema tests | contaminated JSON and usage cases |
| README/router drift | WP8, WP9 | docs check and executed examples | stale-command fixture |
| Workspace/tag/CLI version drift | WP9 | release check | synthetic tag mismatch |
| Missing CI/fuzz/bench and red quality gates | WP9, WP10 | workflow files plus final verify | seeded invalid corpus and failing lint/doc fixtures |

## Pre-send coherence review

- The plan starts at the core and works outward to the CLI.
- Every audited weakness has one owning work package and at least two proof routes.
- No crate is introduced as an empty scaffold; its ownership, dependencies,
  public role, fixtures, and gate are defined.
- Cross-layer semantic preview has one owner rather than a convenience backedge.
- Host tooling exists only for the explicit signing adapter; inspection,
  recovery, demangling, parsing, and validation are process-free.
- Selectivity is an execution property, not a report-filtering convention.
- Stale syntax is removed, not mapped; docs are generated from the live
  router.
- Versioning reflects the public break and has an executable release authority.
- No requested work is deferred to a later phase or release.
