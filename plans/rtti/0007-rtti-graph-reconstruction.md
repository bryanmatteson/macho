# Plan 0007 — Exact RTTI graph reconstruction

**State:** agent-executable implementation contract.

This plan refines Plan 0006 without weakening it. Plan 0006 owns the runtime-type
product vocabulary, language coverage, public inspection journeys, and guarded
dispatch boundary. Plan 0007 owns the missing proof boundary between decoded
bytes and that public graph: a lossless, replayable reconstruction model that
can demonstrate why every entity, relationship, value, unknown, conflict, and
coverage claim exists.

The byte-locked v1 specifications are unchanged. The existing
`splice.semantic.rtti.*/v2` family remains a supported compatibility surface;
its wire shape is not silently expanded or reinterpreted. Exact reconstruction
uses a new v3 graph/report/evidence family and a separately versioned replay
contract. Native dispatch activation remains governed by Plans 0002 and 0006
and is not a prerequisite for completing file and coherent-module
reconstruction.

## 1. Outcome

Given a supported Mach-O file or one closed mapped-module snapshot set, Splice
must be able to:

1. discover every in-profile Swift, Objective-C, and Itanium C++ RTTI record;
2. retain the exact bytes, pointer interpretation, profile rule, and source
   coordinate for every decoded fact;
3. normalize those facts into typed semantic claims without selecting by
   display name, traversal order, or executable-looking addresses;
4. reconcile local, cross-module, external, unknown, and contradictory claims
   through one deterministic engine-owned graph builder;
5. reproduce every published entity field and edge from the retained evidence
   bundle without invoking a production decoder;
6. state completeness per collector, semantic component, entity, relationship,
   and query instead of deriving all coverage from one graph-wide flag; and
7. return useful unaffected components when another language or collector is
   absent, partial, conflicted, or rejected.

“Accurate reconstruction” is the conjunction of these properties:

- **Soundness:** every material public output has a checked derivation from
  in-scope facts and an admitted profile rule.
- **Conservation:** every discovered candidate and every required record field
  is represented by a fact, a typed unknown, or a rejecting diagnostic.
- **Identity preservation:** distinct scopes, modules, definitions, metadata
  instances, subobjects, address points, and slots cannot collapse through
  names or coincident addresses.
- **Conflict fidelity:** incompatible claims remain visible and no source wins
  through ordering, language preference, or presentation policy.
- **Replayability:** an independent consumer can reconstruct the canonical
  semantic result from the exported profile and bounded evidence bundle.
- **Determinism:** input enumeration order, hash-map order, thread scheduling,
  and repeated effect-free capture do not change canonical JSON or digests.
- **Query honesty:** a query is ready only for the exact components and fields
  it consumes; unrelated completeness cannot upgrade or downgrade it.

An entity count, relationship count, digest equality, successful
deserialization, or repeated execution of the same production lowerer is not
proof of accurate reconstruction.

## 2. Grounded implementation baseline

The current implementation is a substantial v2 foundation, not a
reconstructible graph:

- `crates/splice-engine/src/semantic_authoring/runtime_type_graph.rs` owns
  scoped entities, canonical keys, relationships, observations, diagnostics,
  conservation, validation, composition, and graph digests.
- `runtime_type_query.rs` owns digest-bound list/show/hierarchy/layout/members/
  conforms/dispatch/bridges/evidence selection and validated JSON/text reports.
- `swift_runtime_type_graph.rs`, `objc_runtime_type_graph.rs`, and
  `cpp_adapter/graph.rs` lower language-specific decoder records directly into
  v2 entities and edges.
- `spec/semantic/rtti/schema.py` owns the generated v2 graph, query, report, and
  evidence schemas.
- `spec/conformance/semantic/rtti/` owns fixtures, a registry, mutations,
  oracle checks, and the `rtti-oracle`/`rtti-conformance` gates.
- `apps/splice-cli/tests/semantic_rtti_journey.rs` exercises real spawned CLI
  reports.

The following observed properties prevent an exact reconstruction claim and
are binding inputs to this plan:

1. A v2 observation retains a coordinate and byte digest, but not the bytes or
   a content-addressed slice needed to replay decoding. Its optional pointer
   record is insufficient to reproduce non-pointer fields.
2. Entities and edges cite observations directly. There is no typed record
   fact, normalized claim, profile rule, or derivation between bytes and the
   chosen semantic body.
3. Lowerers choose canonical bodies while walking decoder records. Duplicate
   bodies are merged and incompatible bodies frequently become immediate
   errors, so competing claims cannot be retained and reconciled centrally.
4. Graph composition uses one aggregate outcome/completeness value. A rejected
   component can suppress usable entities from unrelated components, while a
   graph-wide partial value makes query-specific coverage imprecise.
5. Conservation is one attempted/included/unknown/excluded tuple. It does not
   prove which collector, record kind, or required field was conserved.
6. Module entity and observation scopes do not carry the full image binding at
   every local coordinate, leaving cross-module resolution dependent on
   surrounding lookup context.
7. The Swift lowerer currently derives identity and module presentation from
   qualified-name strings, marks nominal resilience uniformly, emits empty
   bound arguments for static metadata, and uses fixed value-witness operation
   assumptions.
8. The Objective-C lowerer currently emits record observations without pointer
   provenance, infers a fixed eight-byte class layout alignment, derives a
   dispatch table from method-record ordering, and has no claim boundary for
   static versus realized dispatch.
9. The C++ lowerer currently creates an unknown ABI-profile layout for every
   definition, synthesizes external identities for unresolved local or null
   targets, maps an unknown vtable slot role to `function`, and has fallback
   owner keys. Those are honest approximations only when explicitly typed as
   unresolved claims; they are not exact semantic facts.
10. The checked C++ expected result primarily records definition keys and
    aggregate hierarchy/dispatch/evidence counts. Objective-C and Swift
    expectations likewise reuse broader fixture registries. Those expectations
    cannot detect a wrong endpoint, value, order, subobject, pointer rule, or
    provenance set when totals still match.
11. Query coverage is copied from graph-wide completeness, and entity
    completeness is inferred from attached diagnostic effects. Neither proves
    that the fields required by a particular operation are reconstructed.

Implementation must preserve the useful v2 validation and CLI work while
replacing these proof gaps. It must not discard the existing graph and start an
unrelated second semantic system.

## 3. Authority and version boundary

Plan 0006 remains the semantic intent. Plan 0007 adds these public schema
identities:

```text
splice.semantic.rtti.profile/v3
splice.semantic.rtti.graph/v3
splice.semantic.rtti.query/v3
splice.semantic.rtti.report/v3
splice.semantic.rtti.evidence/v3
splice.semantic.rtti.replay/v1
```

The authored source remains `spec/semantic/rtti/schema.py`; its generator is
the only writer under `spec/generated/v3/`. `spec/semantic/rtti/verify.py`
independently reconstructs both the retained v2 family and the new v3 family.
The v3 Rust values belong in `splice-engine`, and all language adapters lower
through them.

The capability registry adds:

```text
semantic.rtti.graph.reconstructible.file/v1
semantic.rtti.graph.reconstructible.module_set/v1
semantic.rtti.replay/v1
```

These capabilities are false until the exact oracle and replay gates pass for
the advertised language/profile/architecture tuple. Existing v2 graph and
query capabilities do not imply reconstructibility. File reconstruction does
not imply mapped-module reconstruction, and neither implies native guard
authority.

Each v3 profile pins:

- platform, architecture, pointer width/endian, ABI/runtime compatibility, and
  supported record kinds;
- pointer/fixup and pointer-authentication rules;
- the closed fact, claim, derivation-rule, diagnostic, and limit registries;
- exact `macho-*` decoder package versions and enabled features;
- the schema-family digest and rule-registry digest; and
- collector discovery surfaces and terminal-state requirements.

A profile mismatch, unknown rule ID, unknown record field, or unregistered
decoder build rejects replay. A verifier never guesses a nearby profile.

## 4. The v3 graph contract

### 4.1 Closed component and scope model

`RuntimeTypeGraphV3` has this conceptual shape:

```text
RuntimeTypeGraphV3 {
    schema
    profile
    scope
    availability: absent | available | rejected
    components: [RuntimeTypeComponentV1]
    evidence_manifest: [RuntimeTypeEvidenceBlobRefV1]
    discovery_roots: [RuntimeTypeDiscoveryRootV1]
    observations: [RuntimeTypeObservationV3]
    facts: [RuntimeTypeFactV1]
    claims: [RuntimeTypeClaimV1]
    derivations: [RuntimeTypeDerivationV1]
    entities: [RuntimeTypeEntityV3]
    edges: [RuntimeTypeEdgeV3]
    diagnostics: [RuntimeTypeDiagnosticV3]
    coverage: RuntimeTypeCoverageV1
    graph_sha256
}
```

Components are closed partitions such as Swift nominal definitions, Swift
metadata instances, Swift conformances, Swift dispatch, Objective-C static
metadata, Objective-C realized metadata, Itanium typeinfo, Itanium dispatch,
layouts, and bridges. Each component records:

```text
component_id
language
domain
collector_ids
status: absent | complete | partial | conflicted | rejected
diagnostic_ids
coverage_ids
```

Top-level `available` means at least one component publishes usable entities.
A rejected component publishes no entities derived from its rejected records
but does not erase independently valid components. Top-level `rejected` is
reserved for an invalid scope/profile, corrupt graph contract, unbalanced
global evidence, or another failure that makes every component untrustworthy.

Every file coordinate binds the artifact digest, container index, architecture,
offset, and length. Every module coordinate additionally binds the process
generation, capture epoch, image binding, image role, module generation, module
snapshot digest, RVA, and length. No module lookup is allowed by generation or
RVA alone.

### 4.2 Replayable evidence

The graph carries a canonical evidence manifest of blob ID, content digest, and
byte length; it does not duplicate raw bytes in every query projection. The v3
evidence/replay document supplies each manifested blob as either:

- bounded inline bytes in canonical base64; or
- a closed source-snapshot reference plus an exact range whose retained bytes
  are required to be present during replay.

Public `type evidence --format json` uses inline bounded slices and deduplicates
identical overlapping bytes. Internal module reconstruction may retain snapshot
references, but an exported replay bundle materializes every referenced slice.
The evidence digest is checked against the bytes before any fact is accepted.

Each collector has one or more discovery roots. A discovery root binds the
collector ID, discovery-surface kind, exact coordinate, evidence blob/range,
profile rule, and terminal state. The bundle retains the complete authoritative
root table or section needed to enumerate candidates plus every transitively
consumed record slice. Retaining only the records production happened to emit
is insufficient: replay must be able to rediscover an omitted candidate from
the root bytes.

An observation identifies one exact consumed byte span and records:

```text
observation_id
component_id
collector_id
record_kind
field_kind
source_coordinate
declared_length
consumed_length
evidence_blob_id
blob_range
pointer_observation?
```

Pointer observations retain storage bytes, signed raw value, width, encoding,
base coordinate, addend, fixup/import identity, decoded local/external/null
target, authentication state, and failure. Null, unresolved local, unresolved
external, malformed, and unsupported are different closed states. A digest
without retained bytes is never replayable evidence.

### 4.3 Facts, claims, and derivations

The v3 model separates three layers:

1. A **fact** is one decoder-owned statement about an ABI record field. It
   carries a closed fact kind, typed value, exact scope, profile rule ID, and
   non-empty observation IDs.
2. A **claim** is one language adapter-owned semantic proposition normalized
   from facts. It carries a closed claim kind, structural subject key, typed
   value, authority class, and non-empty fact IDs.
3. A **derivation** is the engine-owned reconciliation result for one material
   output selector. It names the exact claim IDs and rule ID that produced a
   known value, explicit unknown, or conflict.

Fact kinds are ABI-specific and closed. They include at minimum context parent,
descriptor flags, generic requirement, field/case record, conformance record,
metadata/value-witness field, Objective-C class/metaclass/list/ivar/property/
encoding/fixup fields, Itanium typeinfo family/name/base/flags/offset fields,
vtable header/address-point/slot/thunk/destructor fields, VTT membership, and
every discovery/gap terminal.

Claim kinds are language-neutral where semantics are genuinely shared and
language-specific otherwise. They include definition identity and kind,
display alias, parent context, field/case/member, base subobject, conformance,
metadata instance, layout dimension, value-witness operation, dispatch table,
address point, slot role/disposition, route, implementation, thunk adjustment,
bridge, pointee, member-pointer owner, and external target.

`RuntimeTypeOutputSelectorV1` is a closed tagged union, not a free-form JSON
path. It can select:

- entity identity, role, and one registered body field;
- edge identity, relationship kind, endpoint, ordinal, or semantic attribute;
- component status and one registered coverage dimension; or
- a diagnostic subject/effect.

Every material entity/body field and edge field has exactly one terminal
derivation. A terminal derivation is:

```text
known      { rule_id, claim_ids }
unknown    { rule_id, claim_ids, diagnostic_id }
conflicted { rule_id, claim_ids, diagnostic_id }
```

Known derivations must reproduce the serialized output exactly. Unknown and
conflicted derivations must preserve every contributing claim and cannot emit a
fabricated default. Claim and derivation IDs are canonical hashes of their
closed bodies and scope. Facts, claims, and derivations are sorted by ID only
after construction; order-sensitive ABI lists retain explicit ordinals.

The rule registry is data, checked into the authored RTTI authority, and maps
each rule ID to:

- the byte extraction or validation recipe for each admitted fact, including
  width, endian, signedness, mask/shift, base/addend, bounds, and pointer rule,
  or one closed named variable-record algorithm;
- accepted fact/claim kinds;
- output selector kind;
- profile applicability;
- cardinality and ordering requirements;
- conflict behavior;
- diagnostics and coverage effects; and
- the independent oracle rule with which it must agree.

Named variable-record algorithms have separate production and reference
implementations and a shared vector corpus, but no shared evaluator. An opaque
rule that means “trust the production decoder” is invalid. Production code
cannot register rules dynamically.

### 4.4 Structural identity

Display names, demangled strings, qualified-name splitting, symbol order, and
presentation aliases never participate in canonical identity.

Definition keys use language plus the ABI identity record and exact scope:

- Swift definitions use descriptor coordinates and structural parent-context
  identity; metadata instances additionally use metadata coordinates and
  proven generic arguments.
- Objective-C classes and metaclasses use their exact class object/read-only
  data identity and image scope; categories and protocols retain their own
  record coordinates.
- Itanium definitions use the scoped typeinfo object identity. Type-name and
  symbol records are claims/aliases, not the key.

Base subobjects use derived identity, direct-base ordinal, path identity,
virtuality, and the exact base target. Dispatch tables use owner/subobject,
group identity, table start, and table kind. Address points use their table,
subobject, ordinal, and exact address. Slots use address point, ABI slot
ordinal, and retained role. Implementations use scoped executable coordinate
and callable-ABI digest; a coincident RVA in another image is distinct.

Aliases may help list/search presentation only. Alias agreement never creates
a bridge or merges entities.

### 4.5 Coverage and conservation

Coverage is a ledger rather than a single enum:

```text
RuntimeTypeCoverageV1 {
    collectors: [CollectorCoverage]
    record_kinds: [RecordCoverage]
    components: [ComponentCoverage]
    outputs: [OutputCoverage]
}
```

Each collector balances discovered candidates into included, unknown,
excluded, or rejected terminals. Each record balances all profile-required
fields into decoded facts, explicit unknowns, or rejection. Each component
balances claims into known, unknown, conflicted, or rejected derivations. Each
query report lists the exact output coverage IDs it consumed.

`complete` is legal only when all required ledgers for that component balance
with no unknown, conflict, rejection, or usable truncation. `absent` requires
the component's authoritative discovery surfaces to be structurally absent.
Unsupported, over-budget, unreadable, or malformed candidates are never
absence.

Graph-level summary coverage is derived from component ledgers and is
informational. Query status is derived only from the selected operation's
required output selectors and component ledgers.

### 4.6 External references and conflicts

External targets retain language, source pointer fact, import/fixup identity,
expected image/library identity, target coordinate when known, and stable
symbol/type-name digests when present. Null is not external. A local pointer
whose target record was not reconstructed is `unresolved_local`, not an
invented external symbol.

Module-set linking runs only after every component has emitted claims from the
same closed snapshot set. It resolves a target only through exact image binding
and coordinate/fixup identity. Name equality may corroborate a resolved target
but cannot resolve it.

Competing claims are grouped by output selector. Equivalent claims retain the
union of fact IDs. Non-equivalent claims produce a conflict derivation and
diagnostic. There is no first-wins, last-wins, language-priority, DWARF-priority,
or runtime-priority rule. A profile may define a semantic relationship between
two authorities, but that relationship must be a named rule and independently
tested.

## 5. Reconstruction pipeline and ownership

There is exactly one production pipeline:

```text
bounded bytes / closed snapshots
  -> strict macho leaf batches
  -> scoped observations and typed facts
  -> language claim emitters
  -> closed module linker
  -> engine claim reconciliation
  -> validated v3 graph
  -> digest-bound query
  -> validated report/evidence/replay bundle
```

Ownership is binding:

- `macho-swift`, `macho-objc`, `macho-cpp`, and `macho-dyld` expose bounded
  records, pointer facts, discovery terminals, and conservation. They do not
  know Splice entities, claims, queries, or verdicts.
- `splice-cartridge-macho` converts strict leaf batches into observations,
  facts, and claims. It does not choose between conflicting claims or compute
  report status.
- `splice-engine` owns rule validation, identity construction, claim
  reconciliation, graph validation, component/query coverage, replay
  validation, and v2 compatibility projection.
- `splice` owns orchestration and immutable snapshot admission.
- the CLI and toolkit consume validated queries/reports. They do not infer
  missing semantics or alter coverage wording.
- `splice-conformance`/`xtask` own independent expected results and verdicts.
  They own a non-shipping reference evaluator for the closed extraction and
  derivation rules and do not call or link production lowerers to construct
  expected graphs.

The three current language lowerers are migrated to emit claims into one
`RuntimeTypeGraphBuilderV3`; direct `Vec<RuntimeTypeEntityV2>`/
`Vec<RuntimeTypeEdgeV2>` construction is not retained as an alternate v3 path.
The builder accepts unordered inputs, validates them, links only after the input
set closes, and emits canonical output once.

## 6. Language reconstruction obligations

### 6.1 Swift

The Swift fact layer must retain descriptor kind/flags, exact context parent
chain, module/extension/anonymous/private context identity, field and case
records, mangled type references, generic headers/parameters/requirements,
superclass references, protocol and builtin conformances, associated types,
metadata accessors, metadata patterns/instances, field-offset vectors,
value-witness fields/operations, class vtable entries, override records, and
witness mappings admitted by the profile.

The claim emitter must:

- build identities from descriptor/context records rather than qualified-name
  text;
- derive module and display names as non-identity claims;
- derive resilience from flags/profile rules rather than assigning one value
  to every nominal;
- preserve unresolved generic arguments instead of emitting an empty argument
  list as known;
- distinguish static descriptor layout, already-realized runtime layout,
  resilient layout, and unavailable runtime instances;
- derive value-witness operation count and roles from the admitted table
  profile rather than a hard-coded count; and
- retain witness-table/accessor state and requirement-to-witness mappings.

No accessor, initializer, metadata instantiation, or target code may execute.

### 6.2 Objective-C

The Objective-C fact layer must retain class/metaclass objects, read-only and
realized read-write data, superclass pointers, categories, protocols, method/
property/ivar/protocol list headers and entries, selector/type/IMP pointers,
type-encoding AST facts, ivar-offset storage, strong/weak layouts, image/fixup
provenance, and static versus runtime observations.

The claim emitter must:

- preserve class, metaclass, category, and protocol identity independently;
- retain declaration/list order explicitly and never derive slot order by
  sorted entity ID;
- derive instance start, size, alignment, stride, and ivar offsets only from
  exact records and profile rules; a fixed eight-byte alignment is not a
  universal fact;
- distinguish declared methods, category contributions, recorded static
  dispatch, realized dispatch, and cache observations;
- retain pointer/fixup facts for every relationship and route; and
- create bridge claims only from exact runtime/metadata evidence.

Static file order cannot claim current Objective-C precedence.

### 6.3 Itanium C++

The C++ fact layer must retain all admitted typeinfo families, runtime typeinfo
vtable family, type-name object, qualifiers, VMI flags, direct-base ordinal,
public/virtual flags, signed fixed or vbase-slot offsets, pointer and
pointer-to-member targets, weak/external state, vtable group/table extents,
address points, offset-to-top, RTTI header, vcall/vbase entries, slot roles,
destructor variants, pure/deleted/null entries, this/return adjustments,
construction tables, and VTT membership.

The claim emitter must:

- key definitions by scoped typeinfo object identity, not symbol or type-name;
- preserve each repeated/diamond base as a distinct path/subobject;
- represent unavailable object layout as an absent/unknown layout claim, not a
  fabricated ABI-profile layout entity;
- keep null, unresolved local, and external typeinfo targets distinct;
- retain an unknown slot role as unknown and gate routing rather than map it to
  `function`;
- require exact subobject evidence before assigning primary/secondary table
  ownership;
- reject fallback owner synthesis as route authority; and
- route a function only when slot role, pointer target, callable ABI, thunk
  adjustments, and executable coordinate are all derived.

Relative vtables remain a separate profile. Recognition without support is a
typed unsupported component, not absolute-vtable decoding.

### 6.4 Cross-language bridges

A bridge is a derived edge backed by non-empty claims from both source and
target identity domains plus an admitted bridge rule. Equal spellings,
selectors, symbols, implementations, or executable addresses are
corroboration only. Bridge conflicts do not merge definitions and do not alter
the language-specific source graphs.

## 7. Queries, reports, replay, and v2 compatibility

The v3 query operations remain list, show, hierarchy, layout, members,
conforms, dispatch, bridges, and evidence. Query values bind the v3 graph
digest. Exact-subject operations accept only a v3 entity ID minted by that
graph.

Each operation has a checked requirement registry. For example:

- hierarchy requires definition identity, base-edge endpoints, subobject/path
  identity, order, offset state, virtuality, and visibility;
- layout requires the subject identity plus every selected dimension/source
  derivation;
- dispatch requires owner/subobject, group/table, address point, slot
  role/disposition, route, thunk, implementation, and callable ABI; and
- evidence requires every fact, claim, derivation, diagnostic, and evidence
  slice reachable from the selected output.

The v3 report status is:

```text
ready | partial | conflicted | gated | absent | rejected
```

`ready` requires every operation-required selector to be known and every
required coverage ledger complete. `partial` and `conflicted` list exact
coverage/diagnostic IDs. `gated` means the graph is accurate for inspection but
the requested authority, such as runtime guard use, is unavailable. Human text
is rendered from a validated v3 report and contains no additional inference.

The replay document contains the profile, scope, component registry, discovery
roots, evidence blobs, observations, and expected graph digest. Starting from
the discovery roots, the independent replay engine re-enumerates candidates
and reconstructs facts, claims, derivations, entities, edges, diagnostics,
coverage, and the graph digest. A replay bundle is bounded and portable; it
does not depend on the original file path, process, sibling checkout, or
production lowerer.

Compatibility rules are exact:

- v2 schemas and Rust values remain readable and serializable.
- `v3 -> v2` is an explicit engine-owned projection. It carries a projection
  diagnostic and partial coverage whenever v2 cannot represent a v3 fact,
  claim, conflict, component status, or derivation.
- `v2 -> v3` never yields a reconstructible graph. It yields a
  `legacy_projection` component with unavailable replay evidence and cannot be
  used for semantic resolution or dispatch guards.
- the completed CLI emits v3 by default and accepts `--report-version v2` for
  the compatibility projection. It never labels v2 output reconstructible.
- public Rust API snapshots document both versions and the non-upgrade rule.

## 8. Independent oracle and conformance contract

The existing RTTI oracle is upgraded from count-oriented expectations to exact
graph expectations. Expectations live in one compact authored reconstruction
catalog, with shared rule templates and architecture parameters where that does
not hide a material value. The oracle expands that catalog in memory or a
temporary directory; it does not commit one generated graph per case. Each
positive fixture has an architecture-specific catalog entry that determines:

- every discovery root, evidence slice digest, and coordinate;
- every observation and pointer interpretation;
- every typed fact and normalized claim;
- every derivation and rule ID;
- every entity body and canonical key;
- every edge endpoint, ordinal, and attribute;
- every diagnostic and coverage ledger; and
- the canonical graph, report, evidence, and replay digests.

Catalog entries are authored from fixture source plus primary ABI rules. They
are not generated, refreshed, or blessed from production output. Small
independent fixture readers verify explicit byte coordinates and pointer
arithmetic and materialize expected evidence slices directly from the
digest-pinned fixtures; they do not import Splice, `splice-cartridge-macho`, or
the production `macho-*` decoders. Expanded expected graphs and replay bundles
are ephemeral verifier products.

The current `expected-graph/v1` count document remains migration evidence but
cannot satisfy a v3 case. A v3 family with only aggregate assertions is a zero-
proof family and fails the verifier.

The corpus includes at least:

- Swift nested/private/same-name contexts, fields/cases, generic requirements,
  resilient references, static and realized metadata, unavailable metadata,
  value witnesses, conditional conformances, witness mappings, class dispatch,
  malformed relative references, and ambiguous aliases;
- Objective-C class/metaclass/superclass, categories, protocols, ivars,
  properties, encodings, static/realized dispatch, shared IMPs, legacy/chained
  fixups, malformed lists, and conflicting layout evidence;
- all admitted Itanium typeinfo families, no/single/multiple/virtual/repeated
  inheritance, diamonds, primary/secondary/construction tables, address-point
  headers, vcall/vbase offsets, destructor pairs, thunks, pure/deleted/null/
  unknown slots, VTTs, weak/external/unresolved/null targets, stripped symbols,
  no RTTI, malformed records, and relative-vtable rejection; and
- closed multi-image sets with duplicate names/RVAs, cross-image references,
  changed generations, changed fixups, and changed pointer authentication.

arm64 and x86_64 file and module-set expectations are mandatory. arm64e
pointer-authenticated file/module reconstruction is mandatory before those
profiles advertise reconstructibility. Native guard execution remains a
separate gated mode.

Mutation operators cover every material boundary:

- change, delete, duplicate, reorder, or cross-scope an observation;
- change or omit a discovery root, candidate, or terminal state;
- alter evidence bytes without its digest or alter a digest without bytes;
- alter pointer width, encoding, base, addend, target, import, or auth state;
- drop a required fact or invent one without observations;
- change a claim subject/value/authority or detach its facts;
- change a derivation rule/input/output or convert unknown/conflict to known;
- merge identities by name/address, collapse subobjects, or change ordinals;
- redirect an edge, route, thunk, implementation, or external target;
- forge component/query coverage or unbalance a ledger;
- make v2 projection upgrade coverage;
- make text diverge from the validated report; and
- make production and replay paths share an implementation dependency.

Every mutation has an expected diagnostic/effect and is killed by verifier
selftest. Unknown mutation IDs, zero selected cases/tests, stale fixture
digests, duplicate test claims, count-only expectations, unclaimed executable
tests, and a positive family without a negative mutation reject the gate.

## 9. Dependency-ordered work packages

These are dependency order, not calendar phases. A package is complete only
with its authored schema, implementation, valid and invalid fixtures,
independent verifier coverage, and public documentation.

| ID | Work package | Depends on | Binding completion evidence |
|---|---|---|---|
| G001 | Freeze v3 schemas, rule registry, diagnostics, limits, capability IDs, v2 migration rules, and the compact exact-expectation schema | none | Generated schemas and independent selftests reject unknown arms, rules, fields, versions, count-only expectations, and invalid compatibility claims. |
| G002 | Build the production-independent catalog expander, replay checker, mutation harness, and fail-closed `rtti-reconstruction` gate before production migration | G001 | One minimal hand-authored valid fixture and its hostile mutations prove complete graph comparison, replay, dependency separation, and zero-match rejection. |
| G003 | Extend strict `macho-*` leaves with closed field facts, discovery terminals, image-bound coordinates, and per-collector/per-record conservation | G001-G002 | Leaf tests and independent catalog entries prove every candidate and required field reaches a fact, typed gap, or rejection without Splice dependencies. |
| G004 | Implement `RuntimeTypeGraphBuilderV3`, fact/claim/derivation validation, component isolation, linker, coverage ledgers, canonicalization, and replay in `splice-engine` | G001-G003 | Permutation, collision, conflict, cross-scope, conservation, and replay differential tests pass without language lowerers choosing verdicts. |
| G005 | Migrate Swift lowering to observations/facts/claims and close definitions, members, instances, layouts, conformances, witnesses, and class dispatch | G002-G004 | Exact Swift graph/replay catalog entries and mutations pass for arm64 and x86_64; unavailable/effectful cases safe-stop. |
| G006 | Migrate Objective-C lowering and close identity, hierarchy, members, encodings, layout, categories/protocols, and static versus realized dispatch | G002-G004 | Exact Objective-C graph/replay catalog entries pass for arm64 and x86_64; ordering/fixup/conflict mutations fail. |
| G007 | Migrate Itanium C++ lowering and close typeinfo, subobjects, all table/address-point/slot forms, thunks, destructors, construction tables, VTTs, and external states | G002-G004 | Exact C++ graph/replay catalog entries pass for arm64 and x86_64; no unknown role or fallback owner becomes route authority. |
| G008 | Complete closed module-set linking, per-component composition, cross-language bridge derivation, and repeatability | G005-G007 | Multi-image exact catalog entries reject image/generation/fixup/auth drift while unaffected components remain queryable. |
| G009 | Ship v3 toolkit/query/report/evidence/replay and CLI journeys with explicit v2 projection | G005-G008 | Every language/operation has spawned JSON/text journeys; schema validation, coverage, ambiguity, replay export, and v2 non-upgrade tests pass. |
| G010 | Close the exact corpus and mutations, capability/architecture/dependency/public-API documentation, performance, and whole-artifact review | G001-G009 | Production-independent replay reproduces every digest, every mutation is killed, and all portable gates pass with zero applicable skips; native-only capabilities remain false unless their exact profile passes separately. |

### 9.1 Primary implementation map

The expected edit boundary is:

- `crates/splice-engine/src/semantic_authoring/` — v3 values, builder,
  reconciliation, validation, replay, queries, reports, and v2 projection;
- `crates/splice-cartridge-macho/src/{swift_runtime_type_graph.rs,objc_runtime_type_graph.rs,cpp_adapter/graph.rs,runtime_type_adapter.rs}`
  — fact/claim emitters and closed composition;
- the sibling `macho` leaf crates — only the strict reusable decoder facts
  required by G003;
- `crates/splice/src/lib.rs` — deliberate facade exports;
- `apps/splice-cli/src/runtime_type.rs` and
  `apps/splice-cli/tests/semantic_rtti_journey.rs` — v3 journeys and explicit v2
  compatibility;
- `spec/semantic/rtti/` and `spec/generated/v3/` — authored schemas, rule
  registry, generated projections, and independent checks;
- `spec/conformance/semantic/rtti/` — compact exact expectation catalog,
  registry, mutations, ephemeral replay construction, and verifier;
- `apps/xtask/src/semantic.rs`, `mise.toml`, `quality/public-api/`,
  `docs/architecture.md`, `architecture.toml`, `README.md`, and
  `spec/semantic/rtti/README.md` — gates, boundaries, public API, and product
  claims.

If implementation discovers another public or serialized surface, it joins
this boundary before the owning work package can complete.

## 10. Resource and determinism requirements

Limits cover evidence blobs/bytes, observations, facts, claims, derivations,
rule applications, components, records and required fields, definitions,
instances, members, bases and path depth, conformances, layouts, tables,
address points, slots, routes, thunks, implementations, bridges, external
targets, diagnostics, module images, query closure, and replay output.

Every count and byte sum uses checked arithmetic. Limits are applied before
allocation proportional to untrusted counts. No usable prefix is returned
after a structural limit, malformed required field, or unbalanced collector.
Component isolation does not permit partial publication from the rejected
component.

Tests cover zero, exact boundary, boundary plus one, overflow, duplicate IDs,
recursive types, inheritance cycles/diamonds, hostile list lengths, overlapping
evidence, conflicting facts, repeated aliases, graph permutations, and replay
permutations. Canonical output must be byte-identical across at least 100
deterministic input permutations for each representative multi-record fixture.

The acceptance corpus records peak evidence bytes, facts, claims, derivations,
entities, edges, and wall-independent operation counts. A performance
regression threshold is expressed in deterministic operation/resource counts;
wall-clock benchmarks remain quality evidence, not a semantic verdict.

## 11. Acceptance commands

Focused implementation commands:

```bash
python3 spec/semantic/rtti/generate.py --check
python3 spec/semantic/rtti/verify.py check
python3 spec/semantic/rtti/verify.py selftest
cargo test --locked -p splice-engine semantic_rtti_reconstruction
cargo test --locked -p splice-cartridge-macho semantic_rtti_reconstruction
cargo test --locked -p splice-cli --test semantic_rtti_journey
```

Repository-owned acceptance:

```bash
cargo run --locked -p xtask -- rtti-dependency-audit
cargo run --locked -p xtask -- rtti-oracle
cargo run --locked -p xtask -- rtti-reconstruction
cargo run --locked -p xtask -- rtti-conformance
cargo run --locked -p xtask -- boundary-check
cargo run --locked -p xtask -- quality-check
mise run ci:spec
mise run ci:rust
mise run ci:xtask
mise run ci:quality
mise run ci:dependencies
```

`rtti-reconstruction` is a required new gate. It:

1. independently validates every v3 expected graph and replay bundle;
2. runs the production inspector on each applicable real fixture;
3. compares the complete canonical graph, not selected counts;
4. replays the exported evidence without production lowerers;
5. requires production, expected, and replay digests to agree;
6. executes every registered reconstruction mutation and requires rejection;
7. rejects zero fixtures, zero applicable architectures, count-only
   expectations, or shared production/oracle dependencies; and
8. emits a bounded JSON report validated against a checked schema.

The unfiltered file and module-set profiles must have zero applicable skips.
`mise run ci:native` and native guard profiles are required only before
advertising their exact native capability; they cannot be substituted for the
portable reconstruction gates and portable gates cannot be reported as native
closure.

## 12. Negative stopping criteria

Stop the affected work package and report the exact gap if any of these remain:

- a public entity/body/edge field has no terminal derivation;
- a derivation cannot be recomputed from retained evidence and the pinned
  profile;
- an observation has only a digest and no replayable byte source;
- a discovered record or required field is absent from conservation;
- identity or resolution uses a display name, demangled text, sorted
  presentation order, coincident RVA, or executable-range heuristic;
- an unknown/null/unresolved/external value is converted to another state;
- a rejected language component erases an independently valid component;
- graph-wide completeness is used as query-specific proof;
- v2 input is upgraded to reconstructible v3 or used as guard authority;
- an expected graph asserts only counts or is generated from production output;
- a verifier and production path share a lowerer, builder, rule evaluator, or
  canonical result generator;
- a mutation family has no killed negative case;
- a strict lowerer retains silent `filter_map`, saturating coordinate math,
  fallback owner/identity synthesis, scan-until-executable, error-to-empty, or
  usable truncation on a material path;
- generated schema or expected output has multiple writers; or
- a capability is advertised for a language/profile/architecture tuple whose
  exact reconstruction and replay profile did not pass.

These are correctness failures, not follow-up cleanup.

## 13. Completion

Plan 0007 is complete when a clean consumer can inspect real Swift,
Objective-C, and Itanium C++ Mach-O files and closed module sets, export bounded
evidence, independently replay that evidence, and reproduce every canonical v3
entity, edge, diagnostic, coverage ledger, report, and digest for arm64 and
x86_64 with zero applicable skips.

Completion additionally requires:

- exact expected graphs instead of aggregate-count substitutes;
- every current v2 journey preserved through an explicit compatibility
  projection;
- v2 inputs prevented from claiming reconstructibility or guard authority;
- component- and query-specific coverage that does not overclaim unaffected or
  incomplete domains;
- arm64e reconstructibility advertised only after its pointer-authenticated
  exact profile passes; and
- all native dispatch capabilities left false unless their separate Plan 0006
  native acceptance profiles pass.

At that point “reconstructible” means independently reproducible from retained
evidence. It does not mean merely deterministic production output, plausible
names, matching counts, or a graph that validates its own serialization.
