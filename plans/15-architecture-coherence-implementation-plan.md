# Plan 15: Architecture Coherence and Scalable Workspace Completion

## Status and authority

This is the canonical implementation contract for correcting the repository-wide
design weaknesses identified in the July 2026 architecture audit. It replaces
the execution model and target layout in
[`14-workspace-crate-refactor-plan.md`](14-workspace-crate-refactor-plan.md).
Plan 14 remains historical context for why the workspace split began; an agent
must not implement both plans.

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
3. symbols, dyld, code signing, DWARF, ObjC, Swift, C++, and external-tool
   ownership;
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
- a published library invokes `xcrun`, a compiler, a demangler process, or any
  other host executable;
- a public invariant-bearing type can be assembled into a state the parser would
  reject;
- recoverable parsing and hard structural failure are still conflated;
- an instruction decode failure can disappear without an error or a recorded
  gap;
- an excluded analysis domain executes;
- a snapshot cannot distinguish `not_requested`, `complete` with an empty value,
  `unsupported`, and `failed`;
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

The implementation starts from the current workspace, not the pre-workspace
`src/` layout described by plan 14.

| Area | Live weakness to remove |
| --- | --- |
| Core ownership | `macho-core` owns code signing, DWARF, dyld, normalized image data, ObjC, Swift, RTTI, and demangling, and therefore depends on `serde`, demangler crates, and `gimli`. |
| Host coupling | Core demangling and analysis reconstruction invoke `xcrun` or host compilers. |
| Model invariants | `FatArch` and `FatBinary` expose invariant-bearing fields; `first_mach()` indexes and relies on an implicit non-empty-fat invariant; container iteration allocates. |
| Errors | The shared `Error` carries domain failures primarily as strings and is reused across parsing, analysis, and mutation. |
| Instruction decoding | `InsnIter` skips invalid bytes or words and yields only successful instructions. |
| Analysis cost | Snapshots eagerly compute all slices and domains; CLI diff ignore flags discard findings after full analysis. |
| Analysis state | Empty, unsupported, failed, and unrequested results are not represented independently. |
| Analysis growth | `ImageInspector` adds a dedicated `OnceLock` for every capability, ties output access to the input lifetime, and exposes `&Vec<T>`. |
| Upward mutation edge | `macho-mutate` depends unconditionally on `macho-analysis` for semantic preview. |
| False façade | `macho` reexports nearly everything and owns `commands` and `inputs`, so it depends on Clap, memory mapping, and `anyhow`; `macho-cli` is only a launcher. |
| Module seams | C reconstruction, C++ ABI inference, patch planning, and diff comparison are large mixed-responsibility files. |
| CLI behavior | Output capture relies on local macro shadowing and misses ordinary writes; format flags, error channels, and exit behavior vary by command. |
| CLI/document drift | The README teaches `view`, `extract`, `compare`, and `dyld-cache`, while the router exposes `info`, language commands, `diff`, and `cache`. |
| Release drift | The audited tag was `v0.1.3`, while workspace and CLI metadata reported `0.1.0`. |
| Delivery gates | Workspace tests and `cargo check` pass, but format, strict Clippy, and missing-doc gates do not; there is no in-repo CI, fuzz, or benchmark authority. |

The implementation agent must re-run these probes before editing. If the live
tree has already changed, update the evidence ledger and preserve the contracts;
do not restore stale code just to follow a path literally.

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
macho-objc                     -> core, dyld
macho-swift                    -> core, symbols, objc
macho-cpp                      -> core, insn, symbols, dyld, dwarf

macho-analysis                 -> core, insn, symbols, dyld, codesign,
                                  dwarf, objc, swift, cpp
macho-mutate                   -> core, insn, dyld, codesign
macho-dyld-cache               -> core, dyld
macho-header-infer             -> core, analysis
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
| `macho-swift` | Swift metadata indexing and injected Swift demangling | `core/swift/` plus Swift-specific demangling coordination | Direct `xcrun` calls, ObjC ownership |
| `macho-cpp` | RTTI/vtable parsing and architecture-specific ABI/body inference | `core/rtti/` and pure ABI inference from `analysis/reconstruct/cpp/abi.rs` | Header filesystem output, compiler invocation, generic diff/reporting |
| `macho-analysis` | Domain planning/execution, snapshots, diff, audit, dependency compatibility, strings/xrefs, container analysis, pure reconstruction/rendering | Existing crate plus normalized `core/image.rs` and path/compatibility policy | Mutation, CLI arguments, host processes, filesystem writes |
| `macho-mutate` | Owned model, layout, patch planning/application, signing mutation, structural preview, and transactional validation | Existing crate | Analysis dependency/reexport, semantic diff, CLI concerns |
| `macho-workflow` | Cross-layer patch workflow and semantic before/after preview | Semantic portions of `mutate/preview.rs` and transaction orchestration that consumes analysis | CLI parsing/rendering, low-level parsers |
| `macho-dyld-cache` | Dyld shared-cache model, parsing, and extraction-bytes API | `macho/src/inputs/dyld_cache/` | Filesystem writes, CLI flags, text output |
| `macho-header-infer` | Evidence aggregation, inference schema, prompt generation, and injectable source/header validators | Reusable inference logic now reached from `header_infer` and reconstruction modules | Process execution, environment discovery, filesystem writes |
| `macho` | Feature-gated library façade | Existing `lib.rs`, rebuilt as a clean reexport surface; no import path is preserved for its own sake | `commands`, `inputs`, Clap, `memmap2`, `anyhow`, direct implementation logic |
| `macho-cli` | Command grammar, file mapping, external-tool adapters, orchestration, renderers, writers, and exit policy | All `macho/src/commands/` plus CLI-specific input and file-output code | Reimplementation of parsing or analysis algorithms |
| `macho-test-support` | Deterministic byte-level Mach-O/fat/cache fixtures shared by tests, fuzz seeds, docs, and benchmarks | Consolidate duplicated test builders | Production dependency, host files, process execution |

If a move exposes a cycle, do not add a reverse dependency. Move the shared
concept to the lowest crate that can own it without policy. Examples:

- raw load-command dylib kinds remain in `macho-core`; normalized dependency
  reports live in `macho-analysis`;
- raw dyld exports live in `macho-dyld`; symbol presentation lives in
  `macho-symbols` without making dyld depend on symbols;
- C++ RTTI can consume a caller-supplied name normalizer rather than making
  `macho-symbols` depend upward on `macho-cpp`;
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

pub struct AnalysisPlan { /* selected slices, domains, AnalysisLimits */ }
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
`xrefs`, `dependencies`, `audit`, `c_headers`, `cpp_headers`, and
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
c_headers       -> dwarf, symbols?
cpp_headers     -> segments, vtables, symbols?, dwarf?, ranges?
objc_headers    -> objc, swift?
audit           -> union of requirements declared by the enabled rule registry
```

Each audit rule declares required/advisory domain specs as data. `AuditPlan`
resolves the union before execution, so the `audit` composite has no hidden
runner dependency. `ContainerPlan` likewise declares the domains whose slice
parity it compares; container identity itself comes from the already parsed core
model.

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

Writers emit `SnapshotDocument` schema version 2:

```rust
pub struct SnapshotDocument {
    pub schema_version: u32, // exactly 2
    pub container: ContainerIdentity,
    pub slices: Vec<SliceSnapshot>,
}

pub struct SliceSnapshot {
    pub identity: SliceIdentity,
    pub domains: BTreeMap<DomainId, DomainState<DomainPayload>>,
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
domain receives a record, including `NotRequested`; missing map keys are
reserved for domains unknown to that schema version.

There is no legacy reader. A snapshot missing `schema_version`, carrying an
unknown version, or containing a domain ID/payload mismatch is rejected with a
typed error that tells the user to regenerate the snapshot, and diff rejects
any input it cannot read. The version stays 2 rather than restarting at 1 so
an unversioned pre-schema file can never be confused with a current one.

Diff compares only domains selected in a `DiffPlan`. CLI `--ignore-*` flags are
translated into exclusions before either input is analyzed. An ignored domain
must have an execution count of zero, not merely zero findings.

Audit builds its plan from enabled rules. Unsupported input and domain failure
appear in the report and cannot masquerade as “no findings.”

### Large-module seams

Split by responsibility while preserving a small public module surface through
`mod.rs` reexports:

```text
macho-analysis/src/reconstruct/c/
  mod.rs              public entry points and orchestration
  model.rs            C type/declaration/evidence values
  dwarf.rs            DWARF-to-model lowering
  correlate.rs        symbol/header correlation
  render.rs           pure text rendering
  validate.rs         pure structural validation contracts

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

Pure reconstruction returns owned models or rendered strings. Filesystem writes,
SDK discovery, `xcrun`, and compiler invocation move behind CLI adapters.

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

## External-tool boundary

Published libraries define the following traits and pure implementations, but
do not discover or launch host tools:

- `macho-swift::SwiftDemangler` for Swift names;
- `macho-header-infer::HeaderValidator` for C/C++ parse or compile validation;
- `macho-header-infer::SdkLocator` for SDK-dependent include resolution; and
- `macho-mutate::SignatureProvider` for host-backed signing.

The CLI owns `XcrunSwiftDemangler`, `XcrunClangValidator`, `XcrunSdkLocator`, and
host signing adapters under `macho-cli/src/adapters/`. Adapters report unavailable
tools as typed unsupported capabilities. Analysis retains partial pure results
and records the unsupported capability; it does not silently skip validation.

The architecture verifier rejects `std::process::Command`, `Command::new`,
`xcrun`, and known compiler paths outside `macho-cli`, `xtask`, and integration
tests.

## CLI contract

### Ownership and entry point

Move all of `crates/macho/src/commands/` and CLI-specific input/file-output code
to `crates/macho-cli/src/`. Create a CLI library target containing testable
dispatch; keep `main.rs` limited to constructing system I/O and converting the
returned code to `ExitCode`.

```rust
pub struct CliIo<'a> {
    pub stdout: &'a mut dyn Write,
    pub stderr: &'a mut dyn Write,
}

pub fn run_from<I, S>(args: I, io: &mut CliIo<'_>) -> ExitStatus;
```

Every command follows `parse arguments -> execute library operation -> return
typed report -> render once`. Renderers receive `&mut dyn Write`. Delete capture
globals, output macros, local `println!` shadowing, and report methods that print
directly. `run_captured` uses two `Vec<u8>` writers through the same `CliIo` path
as production.

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

All commands accept a common `--format text|json`; audit additionally accepts
`sarif`. `--format` is the only format selector: the old `--json` and `--sarif`
flags are removed, not aliased. JSON uses:

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

The architectural change sets every workspace package to `0.2.0`. Workspace
dependencies continue to use `version.workspace = true` or the one workspace
version declaration. `macho --version` must come from the same package metadata.

Add:

- `CHANGELOG.md` with a `0.2.0` entry recording the architectural break; and
- generated command reference markers in `README.md`.

Add an unpublished `xtask` crate and `.cargo/config.toml` alias so these commands
are authoritative:

```text
cargo xtask architecture
cargo xtask docs --check
cargo xtask release --check
cargo xtask verify
```

`docs --check` compares generated Clap help, command tables, and checked
examples to committed documentation, and verifies that every diagnostic-code
constant in the workspace appears exactly once in the core registry document.
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
- process execution outside allowed adapters/tooling/tests;
- CLI output bypasses;
- `macho-analysis` references in `macho-mutate`;
- `commands` or `inputs` modules in the façade;
- public `&Vec<T>` return types;
- the removed zero-argument `first_mach()` API;
- silent decoded-instruction result dropping;
- resurrection of removed surfaces: `ImageInspector`, snapshot v1 reading,
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
| Snapshot versioning | v2 round trip | missing `schema_version`, unknown future version, and mismatched domain ID/payload each rejected with a typed error |
| Mutation | non-overlapping valid patch | overlap, stale expected bytes, branch-range failure, failed strict reparse; original bytes unchanged |
| Workflow | selected semantic before/after diff | analysis failure prevents filesystem commit |
| External adapters | fake demangler/compiler response | unavailable and malformed-tool-output results are typed and recorded |
| CLI I/O | `info`, `diff`, `audit`, and file-output commands through injected writers | parse error only on stderr; JSON stdout remains parseable; no global output; policy failure exits 3 with the report on stdout |
| CLI usage errors | every canonical command parses | unknown commands and malformed arguments return usage code 2 with empty stdout |
| Version/docs | matching synthetic tag/metadata/help | tag mismatch, stale command, and stale example fail xtask checks |

Synthetic Mach-O builders live in the unpublished `macho-test-support` crate and
are shared instead of copied across integration tests.

### Fuzzing

Add a `cargo-fuzz` package with targets for:

1. container and fat parsing under strict and forensic options;
2. load-command parsing and limit enforcement;
3. dyld bind/rebase/export/chained-fixup parsing;
4. code-signature parsing;
5. instruction strict/lossy decoding;
6. mutation plan/apply/reparse round trips; and
7. dyld shared-cache and fileset container parsing.

Every target asserts no panic, no unbounded allocation beyond configured limits,
and deterministic results for the same input. Mutation fuzzing additionally
asserts that a successful output strictly reparses and a failed application does
not alter the input buffer. Seed corpora include each valid and invalid fixture.

CI compiles every target and runs bounded smoke fuzzing. The exact smoke duration
is a CI scheduling value, not a substitute for deterministic regression tests.

### Benchmarks

Add Criterion benchmarks for thin/fat parsing, strict/forensic validation,
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

External-tool integration tests run with fake adapters everywhere. A separate
macOS CI job exercises the real `xcrun` adapters; absence of an optional host
tool is reported as a skipped adapter integration, not used to excuse a missing
pure-library test.

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
4. Add the `xtask` skeleton only with fully working `architecture`, `docs
   --check`, `release --check`, and `verify` command dispatch; no placeholder
   success paths.

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

1. Create `macho-symbols`, `macho-dyld`, `macho-codesign`, `macho-dwarf`,
   `macho-objc`, `macho-swift`, and `macho-cpp` with the ownership above.
2. Resolve concepts by moving them downward or injecting traits; never add a
   reverse dependency.
3. Move all process execution behind CLI adapter traits. Until WP8 wires the
   real adapters in `macho-cli`, the CLI runs on pure fallbacks (degraded
   Swift demangling and header validation); do not add temporary adapter
   plumbing to the façade.
4. Design the façade reexport surface clean; no import path is preserved for
   its own sake.
5. Add direct crate-level tests proving each leaf works without the façade.

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

### WP4 — Build selective analysis and schema v2

1. Implement domain IDs, runners, dependency resolution, analysis plans, fact
   caching, owned documents, and four-state domain results.
2. Move normalized image/dependency policy into analysis.
3. Implement v2 serialization and typed rejection of unversioned or
   unknown-version snapshots.
4. Make snapshot, diff, audit, container, xref, and reconstruction entry points
   consume explicit plans.
5. Make ignored diff domains and disabled audit rules absent from execution.
6. Delete `ImageInspector` and migrate every caller to `Analyzer`.

Checkpoint: execution-counter tests prove exclusion and at-most-once dependency
execution; snapshot-rejection and state-distinction fixtures pass.

### WP5 — Separate mutation from workflow

1. Remove the analysis dependency and reexport from `macho-mutate`.
2. Split patch planning by responsibility and architecture.
3. Implement structural preview and strict reparse/validation.
4. Create `macho-workflow` for selected semantic before/after analysis and diff.
5. Move filesystem atomic replace and backup behavior to CLI.

Checkpoint: `cargo tree -p macho-mutate` contains no analysis/facade/CLI crate;
failed patch and workflow fixtures preserve original and destination bytes.

### WP6 — Complete analysis module seams and adapters

1. Split C reconstruction, C++ ABI analysis, diff, and patch modules into the
   declared layouts.
2. Keep public paths stable through narrow `mod.rs` reexports.
3. Convert renderers to pure string/model output.
4. Implement fake and real external-tool adapters with typed capability results.
5. Enforce the production-file size ceiling.

Checkpoint: module-size and process-boundary checks pass; reconstruction tests
use synthetic fixtures and fake adapters on every platform.

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
2. Implement injected I/O, one render point, output envelope, format enum, channel
   policy, and centralized exit mapping.
3. Implement canonical shared arguments.
4. Convert each command to typed report execution and remove direct printing.
5. Add golden text, JSON schema, SARIF, capture, usage-error, and exit tests.

Checkpoint: the same representative commands through system I/O and captured I/O
produce byte-identical stdout/stderr; architecture output scan is clean.

### WP9 — Bind docs, versioning, and delivery gates

1. Set workspace version `0.2.0`; add changelog authority.
2. Replace stale README syntax with generated canonical help and examples.
3. Complete `xtask` architecture/docs/release/verify checks and their negative
   fixtures.
4. Add GitHub Actions workflows under `.github/workflows/` for Linux library
   coverage and macOS full/adapters coverage.
5. Add fuzz targets/corpora and Criterion benchmarks.
6. Reduce/document the public surface until strict Clippy and rustdoc pass.

Checkpoint: deliberately stale help, version, tag, dependency, process, and
output fixtures are rejected by their owning checks.

### WP10 — Whole-tree convergence

1. Search for and remove obsolete modules, reexports, macros, legacy snapshot
   constructors, eager analysis paths, process calls, and stale docs.
2. Run every focused negative/positive matrix.
3. Run `cargo xtask verify` without allowing the verifier to modify files and
   with implementation-owned changes isolated from unrelated worktree changes.
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
- real-tool behavior is the only available proof for a library contract and no
  deterministic adapter fixture can be built;
- implementation overlaps unresolved user changes in the same lines or moves;
  or
- any proposed fix requires weakening a falsification criterion.

Warnings, workload size, lint volume, or the need to update many callers are not
STOP conditions.

## Final verification gate

`cargo xtask verify` must run, in this order:

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
cargo fuzz build
```

CI additionally runs bounded fuzz smoke targets and the macOS real-adapter suite.
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
- analysis plans determine actual execution and schema v2 represents all four
  domain states;
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
| False core boundary and heavy dependencies | WP1, WP2 | metadata/tree matrix | forbidden-edge fixture |
| Library process execution | WP2, WP6 | source ownership check, fake adapters | process-call fixture outside CLI |
| Open model invariants and panic/allocating helpers | WP1 | core API/tests/docs | zero-fat, overlap, overflow, compile-fail field construction |
| String-heavy shared errors | WP1, WP2, WP4, WP5 | typed error assertions | nested failure retains code/span/context |
| Silent instruction skips | WP3 | strict/lossy paired tests | invalid byte/word cannot disappear |
| Eager snapshots and post-compute ignore flags | WP4 | runner counters | excluded runner panics if invoked |
| Ambiguous analysis state | WP4 | v2 schema round trip | four states serialize distinctly |
| Fixed `ImageInspector` capability locks/lifetimes/`&Vec` | WP4 | type deleted; all callers on `Analyzer` | architecture scan rejects any reintroduction |
| Mutation depends on analysis | WP5 | `cargo tree -p macho-mutate` | forbidden-edge fixture |
| Façade owns CLI and has no features | WP7, WP8 | feature compile matrix/tree | commands/input/delivery-dep scan |
| Oversized mixed modules | WP6 | size and responsibility check | over-ceiling fixture |
| Broken/inconsistent output capture | WP8 | process-vs-injected byte comparison | global-output command fixture |
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
- Host tools are integrations behind traits, not hidden library prerequisites.
- Selectivity is an execution property, not a report-filtering convention.
- Stale syntax is removed, not mapped; docs are generated from the live
  router.
- Versioning reflects the public break and has an executable release authority.
- No requested work is deferred to a later phase or release.
