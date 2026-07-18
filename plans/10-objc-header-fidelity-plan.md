# Plan 10: Objective-C Runtime Surface and Header Fidelity

## Status and Authority

This document is the single-pass behavioral authority for Objective-C runtime
surface and header output. Plan 15 owns crate placement, `Analyzer`, selective
execution, shared CLI delivery, snapshot state, and process boundaries.
`complete/04-objc-swift-graph-plan.md` is a historical completion record, not an
implementation authority; its surviving graph obligations are absorbed here and
in plan 15.

[`schemas/language-recovery-wire-v1.md`](schemas/language-recovery-wire-v1.md)
is the normative wire contract and closed registry for every serialized type,
reason, diagnostic code, and AST projection named here. The Rust blocks below
are API projections of that contract.

The implementation is complete only when the parser, graph, report, surface,
header, JSON, invalid fixtures, and live-corpus acceptance below pass together.
The dependency checkpoints are not release phases.

## Objective

`macho objc` must expose the most useful runtime truth present in a Mach-O image:
classes, categories, protocols, selectors, effective method ownership,
properties, ivars, and reference/definition state. `--headers` must render
only declarations supported by valid runtime metadata and must retain a complete
unresolved ledger for malformed or incomplete records.

The target is ABI-faithful deterministic output, not source reproduction or
cosmetic imitation of a particular host tool.

## Coherence Boundary

This plan resolves:

- Objective-C type, method, property, ivar, class, category, and protocol
  metadata parsing;
- `ObjCGraph` category folding, inheritance, selector ownership, and cycle-safe
  resolution;
- explicit defined, referenced, partial, malformed, and excluded states;
- one canonical report consumed by text, JSON, headers, snapshots, and diffs;
- typed Objective-C header AST parsing/rendering/validation in
  `macho-header-syntax`, with runtime-to-header projection in `macho-objc`;
- thin/fat, architecture selection, columns, color, diagnostics, and exit rules;
- deterministic fixtures plus a recorded iMazing acceptance run; and
- process-free cross-platform operation.

It permanently excludes original parameter names, typedef aliases not encoded
in metadata, most nullability and lightweight generics, source comments/macros,
source ordering/formatting, decompilation, and full Swift ABI recovery.

## Falsification Criteria

The design is wrong if:

- malformed metadata is silently replaced with `id`, `void`, or an empty
  parameter list;
- an external class/protocol reference appears as a local definition;
- category folding loses the originating category or silently chooses an
  ambiguous implementation;
- selector spelling and encoded argument count disagree without a diagnostic;
- header output contains arbitrary strings rather than typed declarations;
- a syntactically tidy declaration has an unresolved type, owner, or protocol;
- text, JSON, header, snapshot, and diff use different semantic models;
- an ObjC command launches `class-dump`, `xcrun`, a compiler, or any process;
- a zero-result surface hides partial, malformed, excluded, or referenced
  counts; or
- a required corpus result is obtained through an iMazing-specific exception.

## Canonical Model

`macho-objc` owns validated runtime values and the semantic graph. `macho-analysis`
owns the plan/domain wrapper and snapshot/diff integration.

```rust
pub struct ObjCReport {
    schema_version: ObjCReportVersion, // exactly 1
    slices: NonEmpty<ObjCSliceReport>,
}

pub struct ObjCSliceReport {
    architecture: Architecture,
    image: ImageIdentity,
    graph: ObjCGraph,
    entities: Vec<ObjCEntity>,
    observations: Vec<ObjCObservation>,
    evidence: Vec<ObjCEvidence>,
    selection: ObjCSelectionResult,
    header: Option<ObjCHeaderProjection>,
    diagnostics: Vec<ObjCDiagnostic>,
    executions: NonEmpty<ObjCCollectorExecution>,
}

pub enum ObjCEntity {
    Class(ObjCClassEntity),
    Category(ObjCCategoryEntity),
    Protocol(ObjCProtocolEntity),
}

pub enum ObjCPresence {
    Defined,
    Referenced,
    Partial,
}

pub struct ObjCSelectionResult {
    selected_entity_ids: Vec<ObjCEntityId>,
    totals: ObjCPartitionCounts,
}

pub struct ObjCCollectorExecution {
    collector: ObjCCollectorId,
    outcome: ObjCCollectorOutcome,
    input_records: u64,
    output_records: u64,
}

pub enum ObjCCollectorId {
    RuntimeMetadata,
    SemanticGraph,
    HeaderProjection,
}

pub enum ObjCCollectorOutcome {
    Complete,
    Unsupported { reason: ObjCUnavailableReason },
    Failed { diagnostic_id: ObjCDiagnosticId },
    Truncated { omitted_lower_bound: u64 },
}

pub enum ObjCValue<T> {
    Known { value: T, evidence: NonEmpty<ObjCEvidenceId> },
    Conflicted { candidates: AtLeastTwo<ObjCCandidate<T>> },
    Unavailable { reason: ObjCUnavailableReason },
}

pub struct ObjCCandidate<T> {
    value: T,
    evidence: NonEmpty<ObjCEvidenceId>,
}

pub struct ObjCEntityCommon {
    id: ObjCEntityId,
    presence: ObjCPresence,
    name: ObjCValue<String>,
    observation_ids: NonEmpty<ObjCObservationId>,
}

pub struct ObjCClassEntity {
    common: ObjCEntityCommon,
    superclass: ObjCValue<Option<ObjCTypeRef>>,
    adopted_protocols: Vec<ObjCTypeRef>,
    ivars: Vec<ObjCIvar>,
    properties: Vec<ObjCProperty>,
    instance_methods: Vec<ObjCMethod>,
    class_methods: Vec<ObjCMethod>,
}

pub struct ObjCCategoryEntity {
    common: ObjCEntityCommon,
    extended_class: ObjCValue<ObjCTypeRef>,
    adopted_protocols: Vec<ObjCTypeRef>,
    properties: Vec<ObjCProperty>,
    instance_methods: Vec<ObjCMethod>,
    class_methods: Vec<ObjCMethod>,
    fold_order: ObjCValue<u64>,
}

pub struct ObjCProtocolEntity {
    common: ObjCEntityCommon,
    adopted_protocols: Vec<ObjCTypeRef>,
    required_instance_methods: Vec<ObjCMethod>,
    required_class_methods: Vec<ObjCMethod>,
    optional_instance_methods: Vec<ObjCMethod>,
    optional_class_methods: Vec<ObjCMethod>,
    properties: Vec<ObjCProperty>,
}

pub struct ObjCMethod {
    id: ObjCMemberId,
    selector: ObjCValue<Selector>,
    kind: MethodKind,
    raw_encoding: Vec<u8>,
    signature: ObjCValue<ObjCMethodSignature>,
    implementation: ObjCValue<Option<ImplementationLocation>>,
    origin: ObjCEntityId,
}

pub struct ObjCProperty {
    id: ObjCMemberId,
    name: ObjCValue<String>,
    raw_attributes: Vec<u8>,
    parsed_attributes: ObjCValue<ObjCPropertyAttributes>,
    origin: ObjCEntityId,
}

pub struct ObjCIvar {
    id: ObjCMemberId,
    name: ObjCValue<String>,
    raw_encoding: Vec<u8>,
    parsed_type: ObjCValue<ObjCEncodedType>,
    offset: ObjCValue<u64>,
    size: ObjCValue<u64>,
    alignment: ObjCValue<u64>,
}

pub struct ObjCObservation {
    id: ObjCObservationId,
    source: ObjCObservationSource,
    location: ObjCMetadataLocation,
    raw: Vec<u8>,
    disposition: ObjCObservationDisposition,
}

pub enum ObjCObservationDisposition {
    Included { entity_ids: NonEmpty<ObjCEntityId> },
    Referenced { entity_id: ObjCEntityId },
    Malformed { diagnostic_id: ObjCDiagnosticId },
    Excluded { reason: ObjCExclusionReason },
}
```

The concrete class/category/protocol values contain stable IDs, presence,
origin observations, raw addresses/references, parsed names, superclass or
extended-class references, adopted protocols, ivars, properties, instance/class
methods, and unresolved items. All invariant-bearing fields use private
constructors and validated serde DTOs. IDs and references are unique and
bidirectionally valid.

Raw metadata bytes/strings remain available beside parsed values. Parse failure
never destroys the original evidence and never creates a known typed value.
Diagnostic codes, unavailable reasons, evidence payloads, graph edges,
partition counts, and header projection DTOs use the exact closed registry in
the normative wire contract.

The report validator enforces unique IDs, non-empty included dispositions,
bidirectional observation/entity references, valid owner/origin edges, resolved
member IDs, valid graph edges, and execution/count consistency. Class and
protocol cross-build IDs use unique runtime names. Category IDs use extended
class plus category name only when that pair is unique; duplicates become
distinct occurrence-scoped entities using metadata location. Methods and
properties include owner, kind, and selector/name in their identity. Same-name
records at distinct metadata locations never merge without an explicit runtime
alias/reference edge.

## Encoding AST and Parser

`macho-objc` owns one typed Objective-C encoding AST covering:

- scalar and special primitives;
- object, class, selector, block, protocol-qualified object, and unknown-object
  forms;
- pointers, fixed arrays, structs, unions, bitfields, and nested composites;
- const/in/out/inout/bycopy/byref/oneway qualifiers;
- method return and ordered arguments with raw frame/offset data;
- property type, readonly/readwrite, copy/retain/strong/weak/assign,
  atomic/non-atomic, dynamic, custom getter/setter, backing ivar, and raw unknown
  attributes; and
- ivar alignment/size/offset metadata without pretending those values are a
  source declaration when the encoded type is incomplete.

The parser is bounded, total over bytes, and returns either a complete typed
node or a typed error span. It rejects trailing unconsumed encoding data except
for grammar-defined offsets/attributes. Selector colon count, implicit `self`
and `_cmd`, and explicit encoded argument count are reconciled; disagreement is
a conflict and makes the method header-ineligible.

Unknown or future encodings remain raw unresolved evidence. They are never
coerced to a convenient type.

## Semantic Graph

`ObjCGraph` is the only runtime query authority. It provides cycle-safe,
deterministic queries for:

- direct and inherited instance/class method lookup;
- all implementations of a selector with class/category origin;
- effective method ownership after deterministic category folding;
- class superclass and adopted-protocol traversal;
- protocol required/optional and instance/class method partitions; and
- VA/file-offset resolution when the metadata proves an implementation target.

Category folding preserves both effective order and origin. Where load order is
not provable, the graph reports all candidates and an ambiguity diagnostic
instead of selecting one. Missing or external superclasses/protocols remain
typed references. Graph cycles are diagnostics and terminate traversal.

`objc graph` and `objc selectors` are typed projections of `ObjCReport` and
never rebuild metadata. `objc xrefs` is a typed composite report produced in
`macho-analysis` from one explicit `AnalysisPlan` requesting the `objc` and
standard `xrefs` domains. It joins only through proven implementation
VA/file-offset identities and retains both source IDs. The CLI does not match
selector or symbol strings to invent cross-references, and the composite does
not serialize a second ObjC graph.

## Header Projection

`macho-header-syntax` owns the typed `ObjCHeaderAst`, bundled Objective-C parser,
deterministic renderer, and syntax/semantic validators. `macho-objc` owns the
projection from validated runtime values into that AST. The renderer cannot
accept raw declaration strings.

Eligibility is exact:

- a method requires a valid selector, complete parsed return type, complete
  parsed explicit argument types, consistent argument count, and known
  instance/class kind;
- an ivar requires a complete parsed type plus valid owning class;
- a property requires a complete type and non-conflicting attributes/accessors;
- a class/category/protocol declaration requires a proven local definition;
- superclass, extended class, and adopted protocol references must resolve to a
  local declaration or an explicit external forward declaration; and
- blocks, structs, unions, nested types, protocol qualifications, and property
  attributes must be representable by the supported AST.

Rendered source is reparsed in-process before delivery. The semantic validator
then checks unique declarations, owner/reference closure, selector/argument
agreement, duplicate/conflicting methods and properties, required/optional
protocol sections, class/category/protocol kind consistency, and deterministic
dependency order. Every ineligible entity/member appears in
`ObjCHeaderProjection.unresolved` with stable ID, reason, raw evidence, and
diagnostic references. An empty projection succeeds only when that ledger is
complete.

Placeholder names `arg1`, `arg2`, and so on are permitted only for source
parameter identifiers, which runtime metadata does not preserve. They do not
stand in for missing types or selectors.

## CLI Contract

```text
macho objc PATH [--arch ARCH] [--headers] [--class NAME]
macho objc graph PATH [--arch ARCH] [--class NAME]
macho objc selectors PATH [--arch ARCH] [--name SELECTOR]
macho objc xrefs PATH [--arch ARCH] [--class NAME]
```

The base command is the runtime surface; `--headers` changes that view to header
source. `graph`, `selectors`, and `xrefs` are actions and therefore remain
subcommands rather than mode flags. Every form inherits `--format text|json` and
`--color auto|always|never`; a fat header source requires `--arch`.

`graph` renders entity/edge and category-folding state. `selectors` renders
selector, method kind, effective owner, origin, implementation location, and
ambiguity. `xrefs` renders the composite typed joins above and clearly separates
resolved, ambiguous, and unresolved references. All three preserve stable IDs
in JSON and use the shared column/color engine in text.

Surface text uses distinct sections for defined, referenced, partial, malformed,
and excluded records. Class/category/protocol rows and child method/property/
ivar rows have distinct indentation and shared ANSI-aware columns. Enum values,
origin, and `key=value` fragments use the shared palette. A zero selected result
still prints unselected/reference/partial/malformed/excluded counts and the flag
that expands them.

Header text is deterministic source with no ANSI. JSON uses the common envelope
and always contains an `ObjCReport` with a `slices` array; header view stores its
projection once in the selected slice. Class/selector filters select displayed
IDs without destroying observations or unfiltered totals. JSON and header source
reject explicit `--color always`.

Unresolved runtime metadata is a successful analysis result. Invalid arguments
use the usage exit class. Bounds, graph invariants, report validation, or header
semantic failure use the execution-failure class.

## Ownership

- `macho-objc` owns runtime metadata/encoding parsing, validated owned values,
  graph semantics, and runtime-to-header projection.
- `macho-header-syntax` owns shared C-family types plus the Objective-C header
  AST, parser, renderer, and syntax/semantic validators.
- `macho-analysis` owns selective domain execution, report/snapshot/diff
  integration, and collector ledgers.
- `macho-cli` owns arguments, files, text/JSON/header delivery, color, and exit
  policy.

`macho-objc` depends only on `macho-core`, `macho-dyld`, and
`macho-header-syntax`. No reverse edge or CLI dependency is permitted.

## Cross-Platform and Tool Boundary

All metadata parsing, graph resolution, encoding parsing, header construction,
reparsing, and validation are in-process. `class-dump` is a non-authoritative design
reference only. Curated expected declarations are committed as fixture text;
no test or product path shells out to reproduce them. The architecture scanner
rejects process execution and known host-tool strings in Objective-C production
paths.

## Verification

Required deterministic fixtures cover:

- defined and referenced classes, protocols, and categories;
- category folding with preserved origin and ambiguous ordering;
- inherited method lookup, superclass/protocol gaps, and graph cycles;
- resolved, ambiguous, and unresolved ObjC/xref joins with a negative fixture
  proving same-name selector/symbol text cannot create a join;
- required/optional protocol methods and instance/class partitions;
- primitive/object/block/protocol/pointer/array/struct/union/bitfield/nested and
  qualified type encodings;
- full method offsets, multi-colon selectors, malformed/trailing encodings, and
  selector/argument conflicts;
- every property attribute, custom accessors, backing ivars, unknown attributes,
  and contradictory attributes;
- complete header projection, external forwards, duplicate declarations,
  unresolved types/owners/protocols, and empty-but-accounted projection;
- thin/fat, arm64/x86_64, text/JSON/header parity, ANSI stripping, Unicode
  alignment, channel purity, and exit behavior;
- symbols-only and unrelated analysis plans with a panicking ObjC collector to
  prove selective execution; and
- `PATH=/nonexistent` plus the process-boundary architecture scan.

The current implementation acceptance runs
`macho objc /Applications/iMazing.app/Contents/MacOS/iMazing` for every contained
architecture and records path, SHA-256, architectures, commands, outputs, and
assertions in `plans/evidence/10-imazing-objc.md`. The live binary is an
environment-specific acceptance probe, not a portable CI dependency. Synthetic
fixtures encode every required behavior and cannot be skipped when iMazing is
absent elsewhere.

The live probe proves that output is non-empty and accounted, referenced
framework classes are not local definitions, categories/protocols/methods retain
origin and presence, malformed metadata is explicit, headers are semantically
valid or fully unresolved, and no process launches. Binary-name exceptions are
forbidden.

## Negative STOP Conditions

Stop implementation and report exact evidence if:

1. raw metadata must be discarded to build the typed graph;
2. a malformed encoding can reach a known rendered type;
3. an external reference must be represented as a local definition;
4. category ambiguity must be hidden to provide one answer;
5. a header declaration requires unresolved owner/type/protocol information;
6. source text must bypass the shared typed ObjC header AST;
7. a library or test contract requires a host process;
8. any iMazing result requires a binary-name exception;
9. an invalid fixture passes only after weakening a validator; or
10. a required check is skipped, ignored, or converted to a warning.

## Dependency Checkpoints

1. Define validated report/encoding/header ASTs and malformed-wire/encoding
   fixtures.
2. Complete graph resolution, presence/origin semantics, and all graph invalid
   fixtures.
3. Make surface text and JSON consume only the canonical report.
4. Implement typed header eligibility, shared rendering, render/reparse plus
   semantic validation, and the complete unresolved ledger.
5. Complete shared CLI alignment/color/channel/exit tests, selective-execution
   tests, architecture gates, workspace gates, and the recorded live probe.

A checkpoint cannot pass while any CLI or snapshot consumer uses an ad hoc
metadata parser or a model different from `ObjCReport`/`ObjCGraph`.

## Done Means

- Objective-C runtime output is useful for defined, referenced, partial,
  malformed, and excluded surfaces;
- methods, properties, ivars, categories, and protocols preserve raw evidence
  and expose validated typed values;
- graph queries are deterministic, cycle-safe, origin-preserving, and honest
  about ambiguity;
- headers contain only eligible typed declarations and a complete unresolved
  ledger;
- text, JSON, header, snapshot, and diff consume one canonical report;
- every path is process-free and cross-platform; and
- all positive/negative fixtures, STOP conditions, workspace gates, and the
  current iMazing acceptance ledger pass without verifier weakening.
