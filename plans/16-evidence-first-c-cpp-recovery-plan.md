# Plan: Evidence-First C and C++ Recovery

## Status and Authority

This document is the single-pass behavioral implementation authority for C and
C++ recovery from Mach-O binaries. It supersedes
`11-cpp-header-fidelity-plan.md` and `12-c-header-fidelity-plan.md`.

`15-architecture-coherence-implementation-plan.md` remains authoritative for
crate placement, dependency direction, selective analysis, CLI delivery, and
workspace verification. This plan owns the recovery schema, evidence
resolution, C/C++ command behavior, safe header projection, recovery-domain
snapshot shape, and recovery-specific verification.

[`schemas/language-recovery-wire-v1.md`](schemas/language-recovery-wire-v1.md)
is the normative wire contract and closed registry for every serialized type
named here. The Rust blocks below are API projections of that contract.

`13-llm-header-inference-plan.md` remains authoritative only for optional model
inference. Its deterministic input is the `RecoveryReport` defined here. Model
output cannot mutate, replace, or silently resolve deterministic facts.

The 2026-07-18 Gate-3 amendment makes the already-required TLS,
runtime-artifact, and class/type entities representable and adds a dedicated
global value-type fact. It also gives the documented `--kind unknown` filter an
explicit kind instead of the empty-list spelling reserved for all kinds. It does
not broaden recovery beyond evidence-supported facts. The normative prerelease
recovery schema remains version 1 under the version decision recorded in the
wire contract.

The implementation is complete only when every obligation and STOP condition
in this document is satisfied in one coherent repository state.

## Objective

Every Mach-O input must produce the most useful C or C++ recovery surface that
its evidence supports without presenting unavailable source facts as known.

Weak evidence reduces precision; it never produces a confident false
declaration. Symbol-only recovery is a first-class ABI inventory rather than a
degraded header generator.

The implementation provides:

- a canonical, versioned recovery report for C-compatible ABI and C++ entities
- explicit accounting for every collected symbol-bearing observation
- field-level known, conflicted, and unavailable states with provenance
- lazy, dependency-planned collection rather than eager kitchen-sink analysis
- aligned and colored terminal output from `macho-cli`
- stable JSON for thin and fat inputs
- a deterministic safe-header projection
- in-process header parsing and validation with no `xcrun` or runtime compiler
  process
- snapshot and diff semantics based on stable entities and facts
- deterministic evidence input for header inference

## Coherence Boundary

This plan resolves all of these interacting surfaces:

- Mach-O symbol, export, bind, chained-fixup, section, and function-start facts
- language/linkage classification and language-specific demangling
- symbol ranges used as recovery evidence
- C DWARF recovery and external-header correlation
- C++ Itanium names, RTTI, vtables, thunks, and bounded ABI body evidence
- per-architecture and fat-container output
- `macho c` and `macho cpp` text, JSON, and header views
- `macho symbols` selective-execution isolation
- analysis domains, planner dependencies, snapshots, and diffs
- deterministic header inference bundles and validators
- CLI colors, columns, diagnostics, help, and exit behavior
- synthetic fixtures and live Talos/iMazing acceptance probes

The public-surface ceiling is:

- this plan does not claim source-language identity for plain-linkage symbols
- this plan does not generate callable prototypes from ABI register guesses
- this plan does not reconstruct local variables, control flow, function
  bodies, macros, comments, or original formatting
- this plan does not implement MSVC mangling for Mach-O inputs
- this plan does not traverse linked binaries or SDKs implicitly
- this plan does not add C/C++ SARIF output
- this plan does not implement a general C or C++ compiler

These limits are permanent behavior of this contract, not staged work.

## Governing Invariants

1. **Evidence before declaration.** Analysis records facts and gaps before any
   renderer selects a presentation.
2. **Per-field truth.** An entity-level confidence cannot promote an unknown
   return type, parameter, owner, layout, or base relation.
3. **Observation conservation.** Every collected symbol-bearing observation has
   exactly one disposition: included, excluded, or unknown.
4. **Conflict preservation.** Contradictory exact facts produce a conflict; no
   source silently wins.
5. **Imports are references.** Undefined symbols never create defined local
   functions, data, or classes.
6. **Encoding before demangling.** Raw symbol encoding determines the language
   parser. Generic demangling cannot change language classification.
7. **Headers are safe projections.** Header rendering cannot consume an
   unavailable or conflicted required fact.
8. **One serialized authority.** CLI JSON, snapshots, diffs, header inference,
   and header projection consume the same `RecoveryReport`.
9. **Selective execution.** Shared evidence types do not imply eager shared
   analysis. Collectors execute only when required by the requested plan.
10. **Cross-platform production.** C/C++ recovery, header parsing, and header
    validation launch no host process and do not discover Xcode tools.

## Terminology

- **Observation:** one raw symbol-bearing record collected from nlist, exports,
  binds, chained fixups, or another explicitly requested symbol source.
- **Entity:** one semantic recovered item built from one or more observations.
- **Fact:** one typed property of an entity with status, strength, and evidence.
- **Disposition:** the result of routing an observation to an entity, excluding
  it for a typed reason, or retaining it as unknown.
- **C-compatible ABI:** plain external linkage that can be consumed through a C
  ABI. It does not assert that the source was C.
- **Safe header projection:** the subset of recovery facts complete enough to
  express as valid, non-misleading C or C++ declarations.

## Canonical Recovery Schema

The public schema belongs to `macho-analysis::report`. Domain collectors retain private
intermediate models only behind this boundary; no private model is serialized
or rendered directly. The Rust API exposes validated constructors and read-only
accessors. Serde decodes through wire DTOs and then runs the same validator, so
deserialization cannot bypass the invariants shown here.

```rust
pub struct RecoveryReport {
    schema_version: RecoverySchemaVersion, // exactly 1
    language: RecoveryLanguage,
    request: RecoveryRequestSummary,
    slices: NonEmpty<SliceRecovery>,
}

pub enum RecoveryLanguage {
    CAbi,
    Cpp,
}

pub struct SliceRecovery {
    architecture: Architecture,
    image: ImageIdentity,
    inputs: RecoveryInputs,
    resolved_plan: ResolvedRecoveryPlan,
    executions: NonEmpty<CollectorExecution>,
    observations: Vec<SymbolObservation>,
    entities: Vec<RecoveredEntity>,
    header: Option<HeaderProjection>,
    diagnostics: Vec<RecoveryDiagnostic>,
    truncations: Vec<Truncation>,
}

pub struct SymbolObservation {
    id: ObservationId,
    source: ObservationSource,
    ordinal: u64,
    raw_name: String,
    presence: Presence,
    address: Option<u64>,
    section: Option<SectionIdentity>,
    disposition: ObservationDisposition,
}

pub enum ObservationDisposition {
    Included { entity_ids: NonEmpty<EntityId> },
    Excluded { reason: ExclusionReason },
    Unknown { reason: UnknownReason },
}

pub struct RecoveredEntity {
    id: EntityId,
    identity_stability: IdentityStability,
    observation_ids: NonEmpty<ObservationId>,
    linkage: Fact<LinkageEncoding>,
    display_name: Fact<String>,
    role: Fact<EntityRole>,
    presence: Fact<Presence>,
    visibility: Fact<Visibility>,
    weakness: Fact<Weakness>,
    location: Fact<EntityLocation>,
    owner: Fact<EntityOwner>,
    value_type: Fact<TypeEvidence>,
    signature: RecoveredSignature,
    layout: RecoveredLayout,
    hierarchy: RecoveredHierarchy,
    evidence: Vec<EvidenceRecord>,
    gaps: Vec<RecoveryGap>,
}

pub enum Fact<T> {
    Known {
        id: FactId,
        value: T,
        strength: EvidenceStrength,
        evidence_ids: NonEmpty<EvidenceId>,
    },
    Conflicted {
        id: FactId,
        candidates: AtLeastTwo<FactCandidate<T>>,
    },
    Unavailable {
        id: FactId,
        reason: UnavailableReason,
        evidence_ids: Vec<EvidenceId>,
    },
}

pub struct FactCandidate<T> {
    value: T,
    strength: EvidenceStrength,
    evidence_ids: NonEmpty<EvidenceId>,
}

pub enum EvidenceStrength {
    Exact,
    Correlated,
    Inferred,
}

pub struct RecoveryInputs {
    image: ImageInputIdentity,
    selected_architecture: Architecture,
    header_roots: Vec<HashedHeaderRoot>,
}

pub struct RecoveryRequestSummary {
    language: RecoveryLanguage,
    architectures: ArchitectureSelection,
    view: RecoveryView,
    selection: EntitySelection,
    analysis: AnalysisLevel,
    header_roots: Vec<HashedHeaderRoot>,
    limits: RecoveryLimits,
}

pub struct HashedHeaderRoot {
    logical_label: LogicalInputLabel,
    content_hash: ContentHash,
    files: Vec<HashedHeaderFile>,
}

pub struct RecoveryDiagnostic {
    id: DiagnosticId,
    code: RecoveryDiagnosticCode,
    severity: RecoverySeverity,
    message: String,
    observation_id: Option<ObservationId>,
    entity_id: Option<EntityId>,
    evidence_ids: Vec<EvidenceId>,
}

pub struct Truncation {
    collector: CollectorId,
    limit_name: RecoveryLimitName,
    limit: u64,
    collected: u64,
    omitted_lower_bound: u64,
}

pub struct CollectorExecution {
    collector: CollectorId,
    request_digest: RequestDigest,
    target_entity_ids: Vec<EntityId>,
    outcome: CollectorOutcome,
    counts: CollectorCounts,
}

pub enum CollectorOutcome {
    Complete,
    Unsupported { reason: UnsupportedReason },
    Failed { diagnostic_id: DiagnosticId },
    Truncated { truncation_index: usize },
}

pub struct EvidenceRecord {
    id: EvidenceId,
    collector: CollectorId,
    observation_ids: Vec<ObservationId>,
    strength: EvidenceStrength,
    payload: EvidencePayload,
}

pub enum EvidencePayload {
    Symbol(SymbolEvidence),
    Dwarf(DwarfEvidence),
    Range(RangeEvidence),
    Rtti(RttiEvidence),
    Vtable(VtableEvidence),
    Header(HeaderCorrelationEvidence),
    Abi(AbiEvidence),
}

pub struct RecoveryGap {
    id: RecoveryGapId,
    field: RecoveryField,
    reason: RecoveryGapReason,
    evidence_ids: Vec<EvidenceId>,
}

pub enum RecoveryGapReason {
    Unavailable(UnavailableReason),
    Conflicted { fact_id: FactId },
    HeaderIneligible(HeaderIneligibilityReason),
}

pub struct RecoveredSignature {
    return_type: Fact<TypeEvidence>,
    parameters: Fact<ParameterList>,
    variadic: Fact<bool>,
    calling_convention: Fact<CallingConvention>,
    qualifiers: Fact<FunctionQualifiers>,
}

pub enum ParameterList {
    Unspecified,
    Known(Vec<RecoveredParameter>), // empty is a proven zero-parameter list
}

pub struct RecoveredParameter {
    type_evidence: Fact<TypeEvidence>,
    source_name: Fact<String>, // unavailable permits deterministic argN rendering
}

pub enum TypeEvidence {
    Source(macho_header_syntax::Type),
    AbiClass(AbiValueClass),
}

pub struct RecoveredLayout {
    size: Fact<u64>,
    alignment: Fact<u64>,
    fields: Fact<Vec<RecoveredField>>,
    completeness: Fact<LayoutCompleteness>,
}

pub struct RecoveredHierarchy {
    bases: Fact<Vec<BaseRelation>>,
    virtual_surface: Fact<Vec<VirtualMember>>,
}

pub struct EntityLocation {
    address: Option<u64>,
    section: Option<SectionIdentity>,
    range: Option<AddressRange>,
}

pub enum ObservationSource {
    Nlist,
    ExportTrie,
    DyldBind,
    ChainedFixup,
}

pub enum CollectorId {
    SymbolDiscovery,
    FunctionRanges,
    Dwarf,
    Rtti,
    Vtables,
    HeaderCorrelation,
    AbiBody,
    HeaderProjection,
}

pub struct CollectorCounts {
    input_records: u64,
    output_records: u64,
    selected_targets: u64,
}

pub enum RecoveryDiagnosticCode {
    MalformedKnownEncoding,
    ConflictingExactFacts,
    AmbiguousIdentity,
    UnmatchedOccurrence,
    CollectorUnsupported,
    CollectorFailed,
    CollectorTruncated,
    HeaderSyntaxInvalid,
    HeaderSemanticInvalid,
    UnsupportedHeaderSyntax,
    UnresolvedRequiredFact,
}
```

Every ID, common identity, evidence payload, recovered leaf value, reason,
diagnostic code, limit/default, enum tag, and stable spelling is defined in the
normative wire contract. Parsed semantic values remain owned by their leaf
crate; `macho-analysis::report` owns their validated serialized projections.
There is no implementation-local reason registry or unvalidated string map.
Adding or renaming a variant is a recovery-schema change.

`TypeEvidence::AbiClass` is intentionally not a source type. It may be shown as
ABI evidence but is always rejected by header eligibility. `ParameterList`
preserves C's unspecified-parameter state separately from a proven empty list.
Source parameter names may be unavailable without making a signature invalid;
the renderer uses deterministic `argN` names only after every parameter type is
eligible.

`NonEmpty<T>` and `AtLeastTwo<T>` are validated collection types, not aliases
for `Vec<T>`. `AtLeastTwo<FactCandidate<T>>` additionally rejects duplicate
candidate values. An inferred value is known as an inference; it is not exact.
A conflict retains each distinct value and its evidence independently.

The execution-only `RecoveryRequest` and serialized `ResolvedRecoveryPlan` are
defined in the selective-execution section below. `RecoveryRequestSummary` is
the path-free, hash-qualified request compiled from it. `RecoveryInputs.image`
contains only content hash, byte length, Mach-O UUID when present, container
kind, slice index, and architecture. Host input paths remain transient CLI
diagnostic context and never enter stable identity or diffs. The selected slice
repeats its architecture so a report is self-describing. Header roots serialize a caller-assigned logical
label, normalized relative file names, and deterministic content hashes. They
never serialize an absolute host path into identity or diff semantics.

The wire contract is the complete registry for `RecoveryDiagnosticCode`,
`ExclusionReason`, `UnknownReason`, `UnavailableReason`, `CollectorId`, and
`RecoveryLimitName`. Adding a variant requires a schema fixture and rendering
test; arbitrary strings are not accepted as codes. Diagnostics use `Info`,
`Warning`, or `Error` severity and reference typed observation, entity,
evidence, or diagnostic IDs rather than relying on display text.

An included disposition contains at least one entity ID. One observation can
support more than one semantic entity, such as a vtable artifact and its owning
class, without being counted more than once in conservation.

`RecoveryReport::validate` enforces all referential integrity in both
directions:

- report, slice, observation, entity, evidence, diagnostic, and execution IDs
  are unique in their scopes; every nested fact and gap ID is unique within the
  slice;
- every observation/entity/evidence/diagnostic/truncation reference resolves;
- every entity observation back-reference agrees with the observation's
  included disposition, and neither side has an unpaired edge;
- known and conflicted facts reference evidence owned by that entity;
- every entity-owned evidence observation is one of that entity's observations;
- every gap names a field on its owning entity and corresponds to an unavailable
  or conflicted field state rather than duplicating a known fact;
- included dispositions and entity observation lists are non-empty;
- conflicts contain at least two distinct candidates;
- execution outcomes reference an existing diagnostic or truncation where
  required, and the referenced collector matches; and
- collector counts, conservation totals, selected targets, and truncation
  counts agree with the resolved plan.

Deliberately malformed wire fixtures cover every invariant. No renderer,
snapshot reader, diff, or inference-bundle builder accepts an unvalidated
report.

### Stable Identity

- Observation IDs are deterministic within an input slice and include the
  observation source and source ordinal.
- A unique externally meaningful symbol-backed entity uses
  `hash("entity-v1", recovery_language, normalized_linkage)` and is marked
  `IdentityStability::CrossBuild`. Address, presence, and role remain facts for
  this case so a move or defined/imported transition is a fact diff.
- If normalized linkage is duplicated, local, synthesized, or otherwise not
  unique, each occurrence receives a distinct
  `hash("occurrence-v1", slice_content_identity, observation_source,
  source_ordinal, normalized_linkage, role_discriminator)` and is marked
  `SliceOnly` or `Ambiguous`. Distinct locations with the same displayed or
  normalized name are never merged.
- Observations may share an entity only when the binary supplies positive alias
  evidence for the same occurrence, such as the same mapped location and an
  explicit alias relationship. Name equality and adjacency are insufficient.
- A C++ class ID uses a unique canonical mangled type identity when available.
  A provenance-qualified header name is cross-build stable only when its logical
  input label, content hash, and declaration identity are stable and unique;
  otherwise it is occurrence-scoped.
- Entity ordering is deterministic by entity ID. Observation ordering is
  deterministic by source and ordinal.
- Diff matches only equal cross-build entity IDs. Slice-only or ambiguous
  entities are reported as unmatched occurrences; optional similarity
  candidates may be shown as diagnostics but never converted silently into a
  stable match.

The fixture corpus includes repeated `GCC_except_table3`-style local C/C++
names, repeated Rust linkage spellings at distinct addresses, same-address
aliases, and defined/imported transitions. It proves local C/C++ occurrences
remain distinct entities, Rust records remain distinct excluded observations,
and true aliases share only the explicitly proven entity.

### Observation Conservation

Conservation is checked per observation source:

```text
collected = included + excluded + unknown
```

Truncated collection reports the configured limit and a lower bound for omitted
records. A truncated source cannot claim complete conservation over uncollected
records.

Entity merging never changes observation counts. Every merged entity lists all
of its observation IDs.

## Linkage and Language Routing

Routing occurs on normalized raw encoding before demangling:

1. remove only the Mach-O nlist decoration needed to inspect the underlying
   encoding while preserving the original raw name
2. split only recognized platform/linker adornments from a candidate encoding
   while preserving them as typed suffix facts
3. classify Rust v0, Itanium C++, Swift, legacy Swift runtime, Objective-C
   runtime, plain linkage, malformed known prefix, or unknown
4. invoke only the parser for the classified encoding core
5. record malformed known encodings as unknown with a diagnostic

Required routing behavior:

- Rust v0 never reaches C++ parsing
- a valid Rust v0 core followed by the Mach-O `$tlv$init` adornment demangles
  the core and preserves the suffix in display output; the full decorated name
  is never passed to `rustc-demangle`
- an unrecognized suffix is never stripped merely to make a demangler succeed
- Swift and Objective-C runtime names never enter C-compatible ABI recovery
- Itanium symbols enter only C++ recovery
- plain identifiers enter C-compatible ABI recovery and retain unknown source
  language
- `_mh_execute_header`, `_mh_dylib_header`, section anchors, guard variables,
  typeinfo, vtables, VTTs, construction vtables, and thunks receive explicit
  runtime or ABI roles
- a demangler failure cannot reclassify a symbol as plain C-compatible linkage

The reusable routing API belongs to `macho-symbols`. `macho symbols`, `ranges`,
imports, exports, C recovery, and C++ recovery consume the same classification.

## Field Resolution Contract

Resolution is field-specific. There is no global winner order.

| Field | Exact evidence | Correlated evidence | Inferred evidence | Conflict behavior |
|---|---|---|---|---|
| presence | nlist, bind, export, reexport | none | none | contradictory exact records conflict |
| linkage encoding | parsed raw prefix | none | none | malformed known prefix stays unknown |
| address/section | nlist, export, section map | none | range ownership | retain conflicting locations |
| function boundary | function starts, unwind, exact DWARF range | symbol-range adjacency | bounded code analysis | retain every range and mark conflict |
| display name | Itanium AST, plain normalized linkage, DWARF linkage name | parsed header declaration | simplified display spelling | exact disagreement conflicts |
| parameters/qualifiers | DWARF, Itanium AST where encoded | parsed header declaration | ABI register classes | inferred ABI classes never become source types |
| return type | DWARF, Itanium AST where encoded | parsed header declaration | return register class | unavailable when source type is absent |
| global value type | DWARF variable type | parsed header variable declaration | ABI storage class | unavailable when source type is absent; ABI class is never a source type |
| owner kind | DWARF | RTTI, vtable, defined ctor/dtor | qualified-scope heuristic | qualified scope alone remains unknown |
| layout | complete DWARF layout | parsed complete declaration | section size is not source layout | incomplete layout cannot emit a definition |
| hierarchy | DWARF, parsed RTTI | parsed header declaration | none | conflicting base graphs remain conflicted |

Parsed-header facts are never exact binary facts. They remain correlated even
when the declaration is complete.

## Selective Analysis and Recovery Plans

`RecoveryReport` is the output of an explicit recovery plan. It is not a global
index constructed for every command.

The collection contract is exact:

```rust
pub struct RecoveryRequest {
    language: RecoveryLanguage,
    architectures: ArchitectureSelection,
    view: RecoveryView,
    selection: EntitySelection,
    analysis: AnalysisLevel,
    header_roots: Vec<HeaderRootRequest>,
    limits: RecoveryLimits,
}

pub struct EntitySelection {
    scope: RecoveryScope,
    kinds: Vec<EntityKind>,       // empty means every kind for the language
    name_globs: Vec<ValidatedGlob>, // empty means every name
}

pub enum AnalysisLevel {
    Sources,
    Abi,
}

pub struct ResolvedRecoveryPlan {
    request_digest: RequestDigest,
    discovery: NonEmpty<CollectorSpec>,
    selected_entity_ids: Vec<EntityId>,
    targeted: Vec<ResolvedCollectorSpec>,
    projection: Option<HeaderProjectionSpec>,
}

pub struct ResolvedCollectorSpec {
    collector: CollectorId,
    target_entity_ids: NonEmpty<EntityId>,
    required: bool,
    limits: CollectorLimits,
}
```

`RecoveryRequest` is an execution input and is never serialized into the report
or hashed with host paths. Request validation reads each explicit header root,
normalizes relative names, computes content hashes, produces
`RecoveryRequestSummary`, and computes `RequestDigest` from that canonical
path-free summary.

Planning has two explicit barriers, not a hidden dynamic dependency:

1. Before collection, `RecoveryRequest` is validated and compiled into the
   complete allowed stage graph. Discovery collectors and every conditional
   collector kind are declared with their target policy and limits.
2. Discovery runs, preliminary entities are routed, and scope/kind/name filters
   produce exact selected entity IDs. The executor then materializes and
   serializes `ResolvedRecoveryPlan` before any targeted collector runs.
3. Targeted collectors receive only their resolved non-empty ID list. Header
   projection runs only after the selected entities and their requested evidence
   are complete.

No collector may start unless it appears in the resolved plan. Each start and
outcome is recorded in `CollectorExecution`, including request digest, exact
targets, counts, failure, unsupported state, and truncation. An optional
collector with no targets is absent, not recorded as a zero-target execution.
An advisory collector failure remains an execution record plus diagnostic; it
cannot masquerade as an empty successful result.

### Symbols-Only Plan

`macho symbols` executes:

- structural parsing needed to reach the requested slice and symbol table
- symbol-table decoding
- selected language demangling only when requested

It executes zero:

- DWARF collection
- range-index construction
- body or callsite analysis
- RTTI parsing
- vtable parsing
- header parsing or correlation
- header projection
- linked-image traversal

The analyzer must record collector execution counts in tests. The required
symbols-only assertion is:

```text
symbols=1
dwarf=0
ranges=0
body_analysis=0
rtti=0
vtables=0
header_parser=0
header_projection=0
```

Filtering an eagerly constructed recovery report does not satisfy this
contract.

### C Surface Plan

`macho c --view surface` requests:

- sections and symbol-bearing sources
- linkage/language routing
- function starts and bounded symbol ranges
- DWARF when present in the selected slice
- external-header parsing only when `--header-root` is supplied

It does not request C++ RTTI, C++ vtables, generic xrefs, linked-image traversal,
or header projection.

`macho c --view header` adds safe header projection and in-process validation.

Bounded body and callsite analysis runs only for selected defined functions
when the user requests `--analysis=abi`. It is never implied by surface or
header view, and inferred ABI register facts remain ineligible as source types.
The resolved body/callsite collector target list must equal the selected,
defined function entity IDs; a broader list is an invariant failure.

### C++ Surface Plan

`macho cpp --view surface` requests:

- sections and symbol-bearing sources
- linkage/language routing
- Itanium AST parsing
- RTTI and vtable evidence
- function starts and bounded symbol ranges
- DWARF when present in the selected slice
- external-header parsing only when a header root is supplied

Full body and callsite analysis runs only when the user requests
`--analysis=abi`. The default surface does not decode every function body.

`macho cpp --view header` adds safe header projection and in-process validation;
it does not add body analysis because ABI register guesses cannot make a source
declaration header-eligible.

### Snapshot Planning

Selecting only the `symbols` analysis domain executes the symbols-only plan.
Selecting `c_surface` or `cpp_surface` resolves only that domain's declared
dependencies. Snapshot planning never constructs every recovery domain and
filters afterward.

Execution-isolation fixtures inject panicking implementations for every
unrequested collector. They cover `macho symbols`, default C/C++ surface,
name-filtered ABI analysis, and surface mode with a supplied-but-unselected
header-root parser implementation when no `--header-root` was requested. A
passing result proves the collector was never called rather than merely filtered
from the report.

## C-Compatible ABI Recovery

Symbol-only C recovery reports what the binary proves:

- name and raw linkage
- defined, imported, or reexported presence
- address, section, and symbol/range size when available
- function, data, TLS, runtime artifact, or unknown role
- visibility and weakness
- inferred ABI register facts only when explicitly requested

It does not fabricate `int` return types, empty parameter lists, byte-array data
types, or source-language identity.

DWARF adds typed functions, variables, records, enums, typedefs, source
locations, and complete layouts. Exact DWARF facts reconcile with structural
binary facts field by field. A disagreement is a diagnostic and conflict.

`_mh_execute_header` and related image-header symbols are runtime artifacts, not
functions.

## C++ Recovery

C++ recovery accepts only valid Itanium encodings and typed C++ metadata.

- parsed mangling provides exact qualified spelling, parameters where encoded,
  qualifiers, constructor/destructor forms, operators, templates, and special
  symbol roles
- RTTI and vtables establish class identity, hierarchy, virtual surface, and
  thunks
- undefined constructors and methods create referenced-class entities, not
  local class definitions
- qualified scope alone does not distinguish namespaces from classes
- imported class references are rendered separately from defined classes
- standard-library imports remain dependency references
- Rust, Swift, Objective-C runtime, malformed, and plain-linkage observations
  do not enter the C++ entity graph

A defined constructor or destructor is correlated class-owner evidence. It does
not establish complete layout.

## Header Parsing and Correlation

`macho-header-syntax` owns the typed C/C++ declaration AST, a pure
`HeaderParser` trait, the bundled production `TreeSitterHeaderParser`, the only
header renderer, and syntax plus semantic validators. The C and C++ grammars
are compiled into the application. The crate has no workspace dependencies and
launches no process or SDK discovery; bundled parser crates remain ordinary
third-party implementation dependencies.

`macho-analysis` owns correlation from parsed declarations into recovery facts
and projection from recovery facts back into the supported syntax AST.
`macho-header-infer` consumes the same AST and validators but owns no parser,
renderer, or deterministic fact type.

The parser returns:

- a typed declaration AST
- source span and header identity
- declaration dependencies and include references
- parser error and missing-node spans
- canonical names and signatures available from the parsed declaration

A declaration containing an error or missing node cannot contribute correlated
signature or layout facts. Macro-generated or preprocessing-dependent
declarations that lack a complete parsed AST remain unresolved.

The supported semantic subset is explicit: namespaces, records, enums,
typedefs/aliases, variables, functions, methods, supported template declarations
and specializations, pointers/references/arrays/function types, cv/ref
qualifiers, variadics, C empty-versus-unspecified parameter state, supported
storage/linkage, and supported calling conventions. Parsing a node outside this
subset yields `UnsupportedSyntax`; it is not retained as raw declaration text.

Semantic validation builds scopes and symbol tables, resolves every referenced
type and declaration dependency, checks redeclarations and conflicting
duplicates, validates storage/linkage/calling-convention combinations, enforces
qualifier and parameter-state rules, and requires complete template and type
dependency closure. A syntactically parseable header with an unresolved type,
ambiguous scope, conflicting redeclaration, illegal storage/linkage, invalid
calling convention, or incomplete template context is invalid.

Name-only identifier occurrence is not header correlation. The current textual
identifier matcher is removed from confidence promotion.

Header correlation records caller-assigned logical root labels, normalized
relative file names, and deterministic content hashes in `RecoveryInputs`.
Absolute host paths may appear in transient CLI diagnostics but never in the
serialized identity. Snapshot recovery has no external header corpus unless the
analysis plan explicitly supplies one.

## Safe Header Projection

Header projection consumes `RecoveryReport` and produces a typed
`HeaderProjection`:

```rust
pub struct HeaderProjection {
    language: RecoveryLanguage,
    declarations: Vec<HeaderDecl>,
    unresolved: Vec<HeaderGap>,
    diagnostics: Vec<RecoveryDiagnostic>,
    source: String,
    validation: HeaderValidationReport,
}
```

The source string is rendered only from typed `HeaderDecl` nodes. Arbitrary
declaration strings cannot enter the renderer.

### Eligibility Rules

A C function declaration requires:

- exact or correlated return type
- exact or correlated type for every parameter
- known empty-vs-unspecified parameter state
- known variadic state
- supported calling convention
- valid linkage spelling

A C or C++ global variable declaration requires:

- defined presence
- a complete exact or correlated source `value_type`
- a valid linkage identifier
- a supported storage class, including explicit thread-local storage only for a
  `tls` entity

An imported data or TLS entity remains a referenced dependency in the surface
report and is not projected as a local declaration. An ABI-only value class is
not a source type.

A C++ free function requires:

- complete return and parameter types
- known qualifiers and exception specification state required by the encoding
- namespace ownership established independently of a qualified string split
- complete template declaration context when templated

A C++ method requires all free-function facts plus proven class ownership.

A class or record definition requires a `type` entity with defined presence,
complete layout, and dependency closure. RTTI-only, vtable-only, imported
member, or name-only class evidence creates a referenced or partial `type`
entity and permits only a forward declaration when its namespace path and
identifier are proven. An imported-only class can never acquire defined
presence through a related imported member.

The projection rejects:

- unknown or conflicted required facts
- inferred ABI register classes used as source types
- template specializations without sufficient template context
- unresolved namespace/class ownership
- runtime artifacts, guard variables, typeinfo, vtables, VTTs, and thunks
- declarations whose referenced type or include closure cannot be emitted

The `runtime_artifact` role is never header-eligible. `tls` is eligible only
under the global-variable rules above. `type` is eligible only as the proven
forward declaration or complete definition described above.

Every rejected entity appears in `unresolved` with entity ID, missing facts,
and evidence references. A projection with zero declarations is successful when
the unresolved ledger is complete.

### Validation

Every rendered header is reparsed by the bundled in-process parser before
delivery and then passes the semantic validator. Any error node, missing node,
unsupported syntax, unresolved or ambiguous dependency, invalid scope,
conflicting redeclaration, illegal storage/linkage/calling convention,
qualifier/parameter-state violation, incomplete template closure, or
entity-coverage mismatch fails the command.

The renderer accepts only validated supported AST nodes. A failed semantic check
moves the affected entity into the unresolved ledger before delivery; no caller
may bypass validation by constructing or appending source text directly.

The legacy `--validate` switch is removed from help and grammar. Header validity
is an unconditional production invariant. Header JSON includes the validation
report; validation cannot be disabled.

No required test invokes `xcrun`, `clang`, `clang++`, or another host compiler.
Compiler-backed experimentation is not part of the production or acceptance
contract.

## CLI Contract

Both commands use the same grammar:

```text
macho c PATH [--arch ARCH] [--view surface|header]
             [--scope defined|imports|all] [--kind KIND]
             [--name PATTERN] [--analysis sources|abi]
             [--evidence none|sources]
             [--header-root LABEL=PATH]... [--format text|json]

macho cpp PATH [--arch ARCH] [--view surface|header]
               [--scope defined|imports|all] [--kind KIND]
               [--name PATTERN] [--analysis sources|abi]
               [--evidence none|sources]
               [--header-root LABEL=PATH]... [--format text|json]
```

`--headers` is a visible alias for `--view header` on both commands. Conflicting
view selections are usage errors.

### Filtering and Evidence Selection

- `--scope` defaults to `defined`; its values select defined entities, imported
  and reexported references, or both.
- `--kind` is repeatable with OR semantics. C accepts `function`, `data`,
  `tls`, `runtime-artifact`, and `unknown`. C++ accepts `function`,
  `qualified-function`, `class`, `method`, `rtti`, `vtable`, `thunk`,
  `runtime-artifact`, and `unknown`. A kind outside the selected language's
  vocabulary is a usage error.
- `--name` is repeatable with OR semantics and accepts a case-sensitive shell
  glob matched against both raw linkage and display name. Malformed patterns
  are usage errors. Filtering never enables an analysis collector.
- `--header-root` is repeatable and requires a unique, portable logical label
  plus a host path. The path is used only for that execution; snapshots, diffs,
  reports, and bundle digests contain the label, normalized relative file names,
  and content hashes, never the absolute path.
- `--analysis` defaults to `sources` and is part of `RecoveryRequest` in every
  format. `abi` additionally enables bounded body/callsite collection for the
  selected defined functions; it never means “print more detail.”
- `--evidence` is an optional text-surface presentation setting. When omitted,
  text surface output behaves as `sources`. `none` suppresses per-entity
  evidence detail and `sources` displays already collected provenance. It never
  changes collection or the canonical report.
- Explicit `--evidence` with JSON or header view is a usage error, avoiding a
  flag that appears to change machine evidence or header source while doing
  nothing. JSON always retains canonical evidence records and provenance.
- Filters are applied before any optional ABI body/callsite collector is
  scheduled, so `--analysis=abi --name PATTERN` does not analyze unselected
  functions.

### Surface Text View

- default view is `surface`
- default scope is `defined`
- output begins with evidence-tier and completeness summaries
- defined entities, referenced imports, runtime artifacts, unknowns, and
  exclusions are distinct sections
- rows use shared ANSI-aware column alignment
- enum values and `key=value` properties use shared semantic styling
- automatic color is enabled only for human terminal output; `always` forces
  color for redirected human table text, while `NO_COLOR` and `TERM=dumb`
  affect only `auto`
- omitted scopes show counts and the exact flag that expands them
- no-result output reports excluded and unknown counts rather than a bare zero

The text renderer consumes the canonical report and performs no analysis.

### Header Text View

- output is deterministic source with no ANSI escapes
- a fat input requires `--arch`; architecture banners cannot appear in source
- the leading comment reports emitted and unresolved counts
- unresolved details remain source comments and typed projection metadata

### JSON View

The global CLI envelope remains schema version 1 because its outer shape is
unchanged. `data` contains `RecoveryReport` schema version 1.

JSON always uses a `slices` array, including thin inputs. It never unwraps a
single slice into a different shape.

- `surface + json` returns the canonical report
- `header + json` returns that same canonical report with exactly one selected
  slice `SliceRecovery.header = Some(...)`; no second projection copy exists
- filters determine `resolved_plan.selected_entity_ids`; the report retains all
  discovery observations/entities needed for conservation and unfiltered totals,
  while optional evidence exists only on the selected targets
- JSON contains no ANSI escapes

### SARIF and Help

C and C++ do not support SARIF. Command help advertises only `text` and `json`.
The CLI grammar must not advertise a format that dispatch rejects. SARIF remains
an audit-command capability.

### Exit Behavior

- successful recovery with unresolved facts exits successfully
- invalid arguments, including fat header output without `--arch`, use the
  usage exit class
- parser, conservation, projection, or invariant failure uses the execution
  failure class
- a complete zero-declaration header is successful when every selected entity
  is represented in the unresolved ledger

## Analysis Domains, Snapshots, and Diffs

Replace `c_headers` and `cpp_headers` with `c_surface` and `cpp_surface`.
Keeping header-only names would preserve the superseded declaration-first
contract.

Snapshot schema increments from 2 to 3. Schema-v2 snapshots are rejected with
the existing regenerate guidance.

The domain payload is the canonical `RecoveryReport`. Rendered header text is a
projection inside the report, not the comparison authority.

Diff compares:

- entity additions and removals only by equal cross-build-stable entity ID
- slice-only and ambiguous occurrences as unmatched, with any similarity
  candidates retained as non-authoritative diagnostics
- observation-presence transitions
- fact status, value, and evidence-strength changes
- new and resolved conflicts
- header eligibility changes
- truncation and diagnostic changes

Address movement is a location fact change, not entity replacement, only for a
cross-build-stable identity. Occurrence-scoped IDs do not claim continuity
across snapshots.

Planner dependencies must distinguish required and advisory facts. An advisory
collector failure appears in recovery diagnostics and cannot masquerade as an
empty result.

## Header Inference Integration

`macho-header-infer` consumes a bounded projection of `RecoveryReport`.

- deterministic fact and entity IDs are preserved
- exact facts are immutable
- correlated and inferred facts retain strength and source
- conflicted and unavailable facts remain explicit
- model hypotheses reference entity and evidence IDs
- model output is a separate hypothesis layer
- accepted model output cannot change deterministic fact status
- safe header projection still enforces eligibility and in-process validation

The duplicate header-language, evidence-strength, and validation contracts
currently split between `macho-analysis::reconstruct` and
`macho-header-infer` are consolidated: analysis owns recovery facts and header
projection; `macho-header-syntax` owns the parser, AST, renderer, and semantic
validator; header-infer owns only bounded inference packaging, prompts,
hypothesis records, and validation orchestration.

No header-inference path launches `xcrun` or discovers SDK roots implicitly.
User-supplied header roots are explicit hashed inputs.

## Crate Ownership

- `macho-core`: structural Mach-O facts only
- `macho-symbols`: linkage encoding classification and language-specific
  demangling/parsing entry points
- `macho-dwarf`: typed DWARF facts
- `macho-cpp`: Itanium, RTTI, vtable, thunk, and bounded ABI analysis facts
- `macho-header-syntax`: supported C/C++ declaration AST, bundled parser,
  deterministic renderer, and syntax plus semantic validators
- `macho-analysis`: recovery planning, fact resolution, canonical report,
  conflicts, header projection, snapshot domains, and diffs
- `macho-header-infer`: inference packaging, prompts, hypothesis records, and
  validation orchestration over `macho-header-syntax`
- `macho-cli`: grammar, explicit filesystem inputs, columns, color, JSON,
  diagnostics, and exit policy

No output crate is added. Shared presentation remains in
`macho-cli/src/commands/output/`.

## Verification Fixtures

All required fixtures are committed or constructed deterministically through
`macho-test-support`. They do not invoke a host compiler.

### Routing Fixtures

- Rust v0 symbol beside Itanium, Swift, Objective-C runtime, and plain symbols
- the exact Mach-O nlist spellings
  `__RNvNCNKNvNtCsfTOUOv1Xnuk_12tracing_core10dispatcher13CURRENT_STATE0023___RUST_STD_INTERNAL_VAL$tlv$init`
  and
  `__RNvNtNtNtNtCsfiKLhsWjRsE_3std3sys12thread_local11destructors4list5DTORS$tlv$init`;
  `symbols --demangle` and `ranges --demangle` must demangle the Rust core and
  preserve the recognized TLS suffix
- Mach-O-prefixed and unprefixed encodings
- malformed known prefixes
- runtime and linker artifacts
- alias symbols sharing one address

### Presence and Ownership Fixtures

- defined and undefined C functions with the same normalized name
- repeated local C/C++ names at distinct addresses and repeated identical Rust
  linkage spellings at distinct addresses; C/C++ entities and excluded Rust
  observations remain occurrence-distinct
- same-address aliases with explicit alias evidence; only the proven aliases
  share an entity
- undefined libc++ constructor and method references
- defined C++ constructor/destructor without layout evidence
- RTTI and primary/secondary vtable evidence
- weak definition, reexport, TLS, common, and absolute symbols

### Fact and Conflict Fixtures

- invalid wire reports: known fact without evidence, conflict with fewer than
  two distinct candidates, empty included/entity lists, duplicate IDs, dangling
  references, asymmetric observation/entity back-references, unknown
  diagnostic codes, truncation for the wrong collector, and execution counts
  inconsistent with the resolved plan
- matching and conflicting DWARF/mangled signatures
- exact function starts beside symbol-adjacency ranges
- complete and incomplete record layouts
- parsed header match, name-only occurrence, parser-error declaration, and
  macro-dependent declaration
- bounded collector truncation

### Header Projection Fixtures

- complete C function and global declarations
- unknown return type
- unknown empty-vs-unspecified C parameter state
- ambiguous C++ namespace/class owner
- RTTI-only forward declaration
- incomplete class layout
- template specialization without primary context
- unresolved type dependency
- runtime special symbol
- duplicate declaration conflict
- syntax-valid unresolved type, conflicting redeclaration, illegal
  storage/linkage combination, unsupported calling convention, and incomplete
  template context

### Container and Delivery Fixtures

- thin arm64 and x86_64 inputs
- fat input with matching surfaces
- fat input with divergent facts
- text with color always/never/auto
- text under TTY, non-TTY, `NO_COLOR`, and `TERM=dumb`; Unicode names and
  heterogeneous optional columns; ANSI-stripped `always` output must equal
  `never` byte-for-byte
- JSON for thin and fat inputs
- header view with and without required architecture selection
- explicit `--evidence` with JSON/header and `--color always` with
  JSON/header are usage errors with empty stdout
- panicking unselected collector doubles for symbols-only, source-only,
  name-filtered ABI, and no-header-root requests

## Required Verification

The implementation runs all of these checks:

1. schema validation for valid and deliberately invalid reports
2. per-source observation conservation
3. collector execution-count assertions for every command plan
4. routing partition tests across all supported encodings
5. conflict-resolution tests that prove no silent winner
6. header eligibility tests for every rejection rule
7. render, reparse, and semantic validation through `macho-header-syntax`
8. text/JSON entity-ID and count parity
9. snapshot-v3 round-trip and rejection of schema v2
10. semantic diff fixtures for fact and eligibility changes
11. `PATH=/nonexistent` runs for C surface, C header, C++ surface, C++ header,
    and header inference
12. architecture verification rejecting process launch in recovery and header
    inference production paths
13. workspace formatting, checks, Clippy, documentation, tests, and feature
    matrix verification
14. portable deterministic fixture corpus on every supported CI host
15. a recorded local Talos and iMazing acceptance run on every architecture
    present in those files

The deterministic fixture corpus is the portable required product gate. It may
not skip behavior because a host lacks Talos, iMazing, Xcode, or macOS. The
current implementation acceptance additionally runs the two user-supplied live
corpora when present and writes `plans/evidence/16-live-corpus.md` with absolute
input path, SHA-256, discovered architectures, exact commands, exit codes, and
assertion results. A different CI host may verify the committed ledger and
synthetic equivalents without possessing those private binaries; it must not
report that it reran the live corpus. Updating either binary invalidates the
ledger until the probes are rerun.

The live Talos probe proves:

- Rust symbols do not enter C++ entities
- Rust-mangled symbols do not become C declarations
- symbol-only C-compatible ABI entities remain visible and useful
- no recovery command launches a host process

The live iMazing probe proves:

- `_mh_execute_header` is a runtime artifact
- imported libc++ classes appear as referenced dependencies
- defined C++ symbols remain visible
- no imported-only class appears as a defined class
- header projection reparses successfully or records every ineligible entity as
  unresolved

## Negative STOP Conditions

Stop implementation and report the exact evidence if any condition occurs:

1. any collected observation lacks exactly one disposition
2. conservation passes only by discarding aliases, malformed names, or unknowns
3. a renderer or snapshot serializes `CAnalysis`, `CppImageIndex`, or another
   private collector model directly
4. generic demangling changes an observation's language route
5. an imported observation creates a defined entity
6. an unavailable, conflicted, or ABI-only inferred fact enters a source
   declaration
7. an RTTI-only class becomes a class definition
8. a rendered header contains an error or missing parser node
9. a syntactically valid header fails semantic validation or contains an
   unresolved dependency
10. thin and fat JSON use different structural shapes
11. a symbols-only request executes DWARF, ranges, body analysis, RTTI, vtables,
    header parsing, or header projection
12. production recovery or header inference launches a process or references
    `xcrun`
13. a data or TLS declaration consumes a function return-type fact instead of
    its dedicated `value_type` fact
14. a runtime artifact becomes header-eligible or a section-based heuristic
    classifies a recognized Mach-O image header as a function
15. an imported-only member, RTTI record, or vtable promotes its owner `type`
    entity to defined presence
13. a snapshot still stores the legacy header-only payload
14. Talos or iMazing passes only through a binary-name exception
15. a new error class, exclusion reason, or validator exception is introduced
    solely to force an acceptance fixture to pass
16. two distinct same-name occurrences are merged without positive alias
    evidence, or an ambiguous occurrence is silently matched across builds
17. a collector runs without a resolved-plan entry or on an entity outside its
    exact target list
18. any required check is skipped, ignored, or converted to a warning

No verifier, fixture, corpus expectation, or classifier rule may be weakened to
make a STOP condition disappear.

## Dependency Checkpoints

These are implementation dependency checkpoints, not release phases:

1. define the canonical schema, stable IDs, validation, and invalid schema
   fixtures
2. implement routing and observation conservation, then prove symbols-only
   collector isolation
3. lower C and C++ evidence into the canonical report with field conflicts
4. replace CLI, analysis-domain, snapshot, diff, and header-inference consumers
   so no parallel serialized authority remains
5. implement typed header projection, bundled parser correlation, and syntax
   plus semantic validation through `macho-header-syntax`
6. complete shared CLI views, filtering, columns, color, JSON, help, and exit
   behavior
7. replace host-compiler fixtures and remove required process-backed validation
8. run the entire verifier and portable synthetic corpus, then record the
   environment-specific Talos/iMazing acceptance ledger

A checkpoint cannot pass while a downstream consumer still relies on a
superseded schema.

## Done Means

- every collected observation is included, excluded, or unknown with typed
  provenance
- every recovered fact is validly known, validly conflicted, or unavailable,
  with referential integrity proven on construction and deserialization
- symbol-only C and C++ output is useful without fabricated declarations
- `macho symbols` performs no recovery kitchen-sink work
- imports and local definitions are distinct in every output
- C and C++ text, JSON, header, snapshot, diff, and inference surfaces share one
  canonical report
- headers contain only eligible typed declarations and always reparse in-process
- fat headers require explicit architecture selection
- snapshots use schema 3 and semantic recovery diffs
- no C/C++ recovery or header-inference production path launches `xcrun` or a
  host compiler
- all valid and invalid fixtures, STOP conditions, workspace checks, and
  portable corpus gates pass without verifier weakening, and the current local
  Talos/iMazing acceptance run is recorded without pretending it is portable
