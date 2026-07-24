# Plan 0006 — Runtime type knowledge and handling

**State:** agent-executable implementation contract.

This plan jointly refines Plans 0003 and 0004. It defines the complete RTTI
knowledge boundary required by semantic inspection, vtable selection, guarded
dispatch, reports, and future type-aware capture. It does not revise the
byte-locked v1 corpus. Its public values belong to the existing coherent v2
semantic and instrumentation boundary.

Plan 0006 does not block Plan 0005's offline 1.0 closure, including its existing
Objective-C inspection surface. It is the subsequent cross-language runtime-
type knowledge milestone. A release may omit Plan 0006 only by omitting every
capability, schema, command, and coverage claim defined here; partial
implementation never permits partial or implied RTTI capability advertisement.

## 1. Outcome

Splice must answer type questions from evidence instead of treating RTTI as a
side effect of locating functions. For Mach-O inputs it provides one strict,
queryable runtime-type graph spanning:

- Swift nominal descriptors, reflection records, generic contexts, metadata
  instances, layouts, conformances, witness tables, and class dispatch;
- Objective-C classes, metaclasses, categories, protocols, ivars, properties,
  type encodings, realization state, and effective dispatch; and
- Itanium C++ typeinfo, class subobjects, base graphs, vtable groups, address
  points, VTT/construction tables, thunks, and destructor roles.

The graph is useful for inspection even when mutation is unavailable. Runtime
authority is granted only after its independently gated observation, barrier,
and native fixture families pass.

“World class” means all of the following are simultaneously true:

1. identity is structural and coordinate-backed, never display-name based;
2. definitions, runtime metadata instances, layouts, subobjects, dispatch
   tables, address points, slots, and implementations are different entities;
3. every derived edge retains exact source records and pointer provenance;
4. absent, unknown, external, conflicted, malformed, unsupported, and budget
   rejection remain distinct;
5. generic, resilient, stripped, multiply inherited, bridged, and
   pointer-authenticated cases are represented honestly;
6. public queries, reports, digests, fixtures, and verifiers see the same graph;
   and
7. no decoder, provider, CLI, or presentation layer supplies a semantic
   verdict that belongs to the engine.

## 2. Authority and ABI profiles

The implementation follows primary ABI authorities:

- Swift mangling, type metadata, type layout, reflection, calling-convention,
  and generics ABI documents from `swiftlang/swift`;
- the Itanium C++ ABI sections for data layout, virtual table layout,
  construction virtual tables, RTTI, mangling, and virtual calls; and
- Apple Objective-C runtime structures and behavior, qualified by the exact
  target runtime profile.

Documents explain the ABI but are not runtime inputs. Production uses pinned,
content-addressed profiles. Each profile fixes platform, architecture, pointer
encoding, compiler/runtime compatibility range, record discriminants, layout
algorithms, authentication rules, and supported feature set. Unknown or
contradictory material is not repaired by probing.

Initial production profiles are:

```text
swift-apple-stable-v1
objc-apple-modern-v1
itanium-cxx-apple-v1
```

Relative C++ vtables, pre-stable Swift layouts, MSVC RTTI, non-Apple Swift
runtime metadata, and private runtime revisions require separate profiles.
Recognition without a profile is inspectable `unsupported`, never generic
array-of-pointers handling.

### 2.1 Public schema, capability, and diagnostic vocabulary

The v2 boundary freezes these schema identities before decoder work begins:

```text
splice.semantic.rtti.profile/v2
splice.semantic.rtti.graph/v2
splice.semantic.rtti.query/v2
splice.semantic.rtti.report/v2
splice.semantic.rtti.evidence/v2
```

The RTTI capability registry adds exactly these initial members:

```text
semantic.rtti.graph.file/v1
semantic.rtti.graph.module_set/v1
semantic.rtti.query/v1
semantic.rtti.swift.types/v1
semantic.rtti.objc.types/v1
semantic.rtti.cxx.itanium/v1
semantic.rtti.layout.static/v1
semantic.rtti.layout.runtime/v1
semantic.rtti.dispatch.recorded/v1
semantic.rtti.dispatch.cxx.itanium.observe/v1
semantic.rtti.dispatch.cxx.itanium.guard/v1
```

Format support, file inspection, mapped-module observation, and mutation
authority are independent bits. A provider must not infer one from another.
The Swift decoder and runtime arms reuse Plan 0004's exact
`semantic.swift.*` capabilities, including `semantic.swift.inspect.file/v1`,
`semantic.swift.inspect.module/v1`, `semantic.swift.graph.module_set/v1`,
`semantic.swift.dispatch.class.observe/v1`, and
`semantic.swift.dispatch.class.guard/v1`; Plan 0006 does not mint aliases for
them. Existing Objective-C semantic and guard capabilities likewise remain
their owning authority. Aggregate RTTI capabilities declare those language
capabilities as prerequisites and never replace or weaken them.

Every public gap uses one closed diagnostic code and one closed effect:

```text
rtti_metadata_absent
rtti_metadata_malformed
rtti_profile_unsupported
rtti_record_unsupported
rtti_record_lost
rtti_pointer_unresolved
rtti_pointer_authentication_failed
rtti_external_reference_unresolved
rtti_entity_conflicted
rtti_graph_incomplete
rtti_graph_cycle
rtti_layout_unknown
rtti_layout_conflicted
rtti_runtime_instance_unavailable
rtti_runtime_observation_unavailable
rtti_runtime_observation_effect_forbidden
rtti_snapshot_set_drift
rtti_dispatch_drift
rtti_guard_authority_mismatch
rtti_structural_budget_exceeded
```

```text
none
mark_entity_incomplete
reject_graph
gate_operation
reject_operation
gate_capability
reject_checkpoint
```

Schemas reject unknown codes, effects, capabilities, record kinds, edge kinds,
and coverage terms. Extensions require a reviewed v2 schema and registry
revision; a display string cannot become machine policy.
Language decoders retain their owning diagnostic codes, including Plan 0004's
closed `swift_*` registry. The `rtti_*` codes apply only to shared graph,
cross-language, query, and guard aggregation. An aggregate diagnostic links the
source diagnostic; it never rewrites or suppresses it.

## 3. Shared ontology

The v2 semantic entity union gains these roles without replacing existing
Objective-C and Swift callable roles:

```text
runtime_type_definition
runtime_type_expression
runtime_type_field
runtime_type_case
runtime_type_base_subobject
runtime_type_conformance
runtime_metadata_instance
runtime_type_layout
runtime_value_witness_table
runtime_dispatch_table
runtime_dispatch_address_point
runtime_dispatch_slot
runtime_implementation
runtime_adjustor_thunk
runtime_type_bridge
cpp_typeinfo
```

Every entity has one `SemanticEntityRef`, exact file or module scope, canonical
key, and nonempty observation set. Relationships are separate typed edges.
Entity equality never follows from equal display text, equal manglings in
different scopes, equal implementation addresses, or one runtime pointer.

### 3.1 Definitions, expressions, and instances

```text
RuntimeTypeDefinitionV1 {
    language: swift | objc | cxx
    kind: LanguageTypeDefinitionKindV1
    declaration_key: LanguageDeclarationKeyV1
    defining_descriptor: SemanticCoordinate
    generic_signature: RuntimeGenericSignatureV1, optional
    resilience: fixed | resilient | runtime_private | unknown
}

RuntimeTypeExpressionV1 =
    nominal(definition, arguments) |
    generic_parameter(depth, index) |
    dependent_member(base, member, protocol?) |
    tuple(elements) | function(signature) | metatype(instance) |
    existential(protocols, superclass?, class_constraint) |
    pointer(pointee, qualifiers) | reference(referent, kind) |
    array(element, extent?) | member_pointer(owner, member) |
    builtin(profile_atom) | opaque(profile_atom)

RuntimeMetadataInstanceV1 {
    definition: SemanticEntityRef refined to runtime_type_definition
    bound_arguments: [RuntimeTypeExpressionV1]
    process_generation: String
    module_generation: String
    metadata_rva: Hex
    realization: realized | allocated_uninitialized | unavailable | unknown
    canonicality: canonical | noncanonical | unknown
    provenance: NonEmpty<SemanticObservationRef>
}
```

A definition is not a metadata instance. A generic instantiation is not its
unbound nominal. A metaclass is not its class. A C++ most-derived object is not
one of its base subobjects.

### 3.2 Members, inheritance, and conformance

Fields and enum cases retain declaration order, raw flags, type-expression
evidence, indirectness, mutability/ownership facts when proven, and either a
fixed offset/discriminator or an explicit dynamic/resilient source. Missing
layout does not erase the member.

Base edges retain language-specific semantics:

```text
RuntimeBaseEdgeV1 {
    derived_definition
    base_definition | external_base
    subobject_id
    offset: fixed(Int) | virtual(vbase_slot) | resilient | unknown
    visibility: public | protected | private | language_default | unknown
    is_virtual: Bool | unknown
    is_primary: Bool | unknown
    observations
}
```

Swift protocol conformances retain the concrete type, protocol, conditional
requirements, associated-type witnesses, requirement-to-witness mapping, and
table/accessor state. Objective-C protocol adoption and C++ base inheritance
remain distinct edge kinds even when they support similar user queries.

Cycles, duplicate subobject IDs, contradictory offsets, mismatched protocols,
and a base edge crossing incompatible scopes reject graph construction.
Pointer and pointer-to-member typeinfo retain separate `pointee` and
`member_pointer_owner` edges. Their local or external definition targets carry
the same exact pointer evidence as inheritance targets; unresolved targets are
diagnosed rather than collapsed into names.

### 3.3 Layout and value operations

```text
RuntimeTypeLayoutV1 {
    subject: definition | metadata_instance
    source: static_descriptor | runtime_metadata | dwarf_corroboration |
            abi_profile
    size, stride, alignment: KnownOrUnknown<Int>
    extra_inhabitant_count: KnownOrUnknown<Int>
    fields: [RuntimeFieldLayoutV1]
    enum_strategy: RuntimeEnumLayoutV1, optional
    class_instance_start: KnownOrUnknown<Int>, optional
    class_instance_size: KnownOrUnknown<Int>, optional
    completeness: complete | partial | conflicted
    observations
}

RuntimeValueWitnessTableV1 {
    metadata_instance
    table_coordinate
    layout_flags
    size, stride
    operations: [RuntimeValueWitnessOperationV1]
    extra_inhabitant_count
    observations
}
```

DWARF may corroborate or conflict with ABI metadata. It is never silently
preferred, and stripped DWARF does not make runtime metadata absent.

## 4. Language obligations

### 4.1 Swift

The strict Swift decoder conserves module, extension, anonymous, protocol,
class, struct, and enum contexts; parent chains; field descriptors and records;
generic context headers, parameters, and requirements; superclass references;
associated types; builtin and protocol conformances; metadata accessors;
class methods, overrides, and vtable entries; witness patterns; and every
relative-reference or fixup field used to derive them.

Runtime inspection distinguishes nominal descriptors from metadata objects and
supports only already-realized metadata. It models metadata kind, address
point, bounds, superclass metadata, generic arguments, field-offset vector,
vtable region, value-witness table, and pointer-authentication state when the
selected profile proves each field. It never calls an accessor or initializes
metadata.

Resilient superclass references, resilient field offsets, generic metadata
patterns, prespecialized metadata, opaque types, packs, existential metadata,
and runtime-private records remain explicit even when a layout or hook is
gated.

### 4.2 Objective-C

The Objective-C graph conserves class and metaclass objects, read-only and
realized read-write data, superclass and subclass relations, categories,
protocols, method/property/ivar/protocol lists, ivar-offset storage, strong and
weak layouts, selector references, IMPs, and image/fixup provenance.

Objective-C type encodings parse into a bounded structural AST. Unsupported
encoding atoms remain typed gaps; string equality is not type equality.
Category contribution order, runtime realization, method-cache contents, and
effective dispatch are different observations. Static file order cannot claim
current runtime precedence.

### 4.3 Itanium C++

The C++ decoder supports the complete admitted `type_info` family: fundamental,
array, function, enum, class, single-inheritance class, virtual/multiple-
inheritance class, pointer, pointer-to-member, and qualified variants.

Class RTTI retains VMI flags, direct-base order, public/virtual flags, signed
offset-or-vbase-offset values, incomplete/weak external refs, and exact
type-name objects. The index keys by scoped RTTI identity, never demangled name.

A vtable is a group of address points, not one symbol-sized function array.
The graph represents offset-to-top, RTTI pointer, vcall offsets, vbase offsets,
function entries, null/deleted/pure-virtual entries, adjustor and covariant
thunks, complete/deleting destructor pairs, primary and secondary tables,
construction vtables, and VTT membership. Each function slot binds its class
subobject and `this` adjustment. Stripped RTTI and `-fno-rtti` remain distinct.

## 5. Evidence, strictness, and conservation

Every decoder returns:

```text
RuntimeTypeDecodeBatchV1 {
    coordinates
    profile_sha256
    outcome: absent | complete | rejected
    records
    observations
    gaps
    collector_outcomes
    conservation { attempted, included, unknown, excluded }
}
```

Every pointer observation records storage coordinate, raw bytes digest,
encoding/fixup kind, base rule, decoded target, target scope, authentication
state, and failure reason. Every variable-length record records declared and
consumed length. Checked arithmetic is mandatory.

`complete` requires terminal collectors, exact conservation, no rejection gap,
and no usable truncation. `absent` means the authoritative discovery surfaces
are structurally absent. Malformed sections, an unreadable record, unsupported
discriminants, limits, or a failed fixup never become absence or an empty graph.

The upstream `macho` seam must expose strict leaf decoders over caller-owned
bounded sources. Existing name-keyed, `filter_map`, substring, scan-until-
executable, silent `break`, or error-to-empty APIs are test-only legacy until
deleted. Splice policy and entity IDs do not enter the leaf crates.

Plan 0005 publishes the already-reviewed `macho` 0.3 family unchanged. Plan
0006 uses one coordinated public 0.4 family and pins it exactly:

```toml
macho-core = { version = "=0.4.0", default-features = false }
macho-dyld = { version = "=0.4.0", default-features = false }
macho-objc = { version = "=0.4.0", default-features = false,
               features = ["fixups", "strict-rtti"] }
macho-swift = { version = "=0.4.0", default-features = false,
                features = ["strict-rtti"] }
macho-cpp = { version = "=0.4.0", default-features = false,
              features = ["itanium-rtti", "fixups"] }
```

All five packages come from one reviewed public tag and registry publication.
The release archive records package checksums and proves a clean consumer can
build with `--locked` using registry sources only. Git, path, vendor, sibling-
checkout, unpublished, and private-registry resolutions reject the dependency
audit. `macho-analysis` and the `macho` CLI are not Splice dependencies.

## 6. Queries and product surface

The shared query surface supports exact, bounded operations:

```text
type list       -- language/kind/module/completeness
type show       -- exact definition or metadata instance
type hierarchy  -- bases/subobjects/superclass/derived types
type layout     -- definition or bound runtime instance
type members    -- fields/cases/ivars/properties
type conforms   -- protocols/conformances/witnesses
type dispatch   -- vtable group/address point/slot/routes/implementations
type bridges    -- Swift/Objective-C identity and dispatch aliases
type evidence   -- observations, gaps, conflicts, provenance
```

Queries return zero, exactly one, or explicit ambiguity. Presentation ordering
never selects a candidate. Public semantic info, toolkit bindings, JSON
validation, canonical printing, reports, and CLI all lower through the same
query and report values. Human output is a view over validated reports.

Reports include graph completeness, profile identity, selected scopes,
definition/instance distinction, every known conflict, omitted-count bounds,
and coverage wording. They never say “all calls” or “complete layout” unless
the corresponding verifier opinion is complete.

An interactive inspection query may accept an entity ID only when it also
binds the immutable graph digest that minted the ID. Authored hook intent
remains target-free: it cannot contain entity IDs, file coordinates, RVAs,
module or process generations, observation IDs, runtime pointers, address
points, or slot indices. Resolution derives and consumes those values through
R0 and R1 evidence.

## 7. Runtime handling and vtable authority

File RTTI is inspection evidence, not current dispatch. Mapped-module graphs
come only from one closed coherent snapshot set. Runtime metadata inspection is
effect-free and cannot call metadata accessors, realize Objective-C classes,
instantiate conformances, execute initializers, allocate target memory, or
search outside reviewed regions.

A guarded vtable operation binds:

```text
definition -> metadata instance / most-derived object model
           -> exact subobject
           -> dispatch table group
           -> address point
           -> slot role and index
           -> adjustor/destructor semantics
           -> implementation
           -> callable ABI
```

An implementation is a first-class scoped graph entity keyed by language,
executable RVA, and callable-ABI digest. A `routes_to` edge references that
entity; it never embeds an opaque implementation-shaped value. Every routed
slot has exactly one route, every non-routed slot has none, and every
implementation is reachable from at least one route. Multiple slots may share
one implementation only when all identity fields agree.

R0, R1, and apply retain full RTTI and dispatch observations. The engine
compares stable state; the provider returns evidence only. The final guard is
observed inside the same exclusive barrier consumed by exact-RVA Hook install.
Swift class dispatch, Objective-C dispatch, and C++ vtable dispatch use distinct
guard arms and cannot substitute for one another.

No runtime type capability is advertised until observation effects, drift
dimensions, barrier lifetime, crash/recovery, pointer authentication, and
receipt reconstruction pass on a native runner for the exact profile.

## 8. Limits and denial resistance

Limits cover input bytes, sections, records, contexts, type-AST nodes/depth,
generic requirements, definitions, metadata instances, fields/cases, base
edges, conformances, vtable groups, address points, slots, VTT entries,
implementations, observations, relationships, external refs, diagnostics, and
evidence bytes.

Every default and hard limit has exact-boundary, zero, negative, overflow,
cycle, duplicate, and no-usable-truncation tests. Hash-collision simulations,
pathological inheritance diamonds, recursive types, generic explosions, and
malicious record lengths fail deterministically within their limits.

## 9. Conformance corpus

The corpus is reproducible and source-backed. It includes arm64, arm64e, and
x86_64 partitions and records compiler/runtime/profile identity.

Swift fixtures cover all context kinds, nested/private/same-name declarations,
generic and resilient classes/structs/enums, indirect and multi-payload enums,
field-offset vectors, metadata accessors, prespecializations, inheritance,
overrides, protocols, conditional conformances, associated types, witness
tables, Objective-C bridges, stripping, optimization, and damaged relative
pointers.

Objective-C fixtures cover classes/metaclasses, categories, protocols,
inheritance cycles, ivar encodings and offsets, properties, strong/weak layouts,
duplicate selectors, shared IMPs, fixups, realization changes, and malformed
lists.

C++ fixtures cover every admitted `type_info` kind, no/single/multiple/virtual
inheritance, repeated diamonds, primary/secondary address points, vcall/vbase
offsets, thunks, covariant returns, destructor pairs, pure/deleted virtuals,
construction vtables, VTTs, weak/external RTTI, stripped symbols, `-fno-rtti`,
relative-vtable rejection, and malformed counts/offsets.

The oracle is production-independent. Expected graphs are never generated by
the production decoder. Mutation families delete, reorder, redirect, forge,
truncate, overflow, cross-scope, deauthenticate, or alias every material field.

### 9.1 Required conformance families

The generated conformance registry is closed and maps every normative rule,
fixture, mutation, test identity, capability, schema arm, diagnostic, and
coverage claim to one of these families:

| ID | Family | Minimum proof |
|---|---|---|
| RT-C01 | Structural identity | Same-name and same-address entities remain distinct across scopes, subobjects, and generations. |
| RT-C02 | Strict decoding | Every admitted record is conserved; every malformed, unsupported, lost, or over-budget record produces the exact diagnostic and effect. |
| RT-C03 | Swift definitions | Contexts, fields, cases, generic signatures, resilient references, and mangled type expressions reproduce oracle graphs. |
| RT-C04 | Swift instances and layout | Already-realized metadata, bounds, arguments, offsets, layouts, and value witnesses remain distinct from definitions and never cause target execution. |
| RT-C05 | Swift conformance | Conditional requirements, associated types, witness mappings, patterns, and accessors retain exact state and provenance. |
| RT-C06 | Objective-C graph | Class/metaclass, categories, protocols, ivars, properties, encodings, and static versus realized dispatch remain distinct. |
| RT-C07 | C++ typeinfo | Every admitted Itanium `type_info` family, qualifier, weak/external reference, and no-RTTI case has an oracle-backed result. |
| RT-C08 | C++ subobjects | Primary, secondary, virtual, repeated, and diamond bases retain unique subobject identity and correct offset semantics. |
| RT-C09 | Vtable groups | Groups, tables, address points, headers, vcall/vbase entries, slots, construction tables, and VTT membership are reconstructed exactly. |
| RT-C10 | Thunks and destructors | This/return adjustments, pure/deleted entries, and complete/deleting destructor pairs route without collapsing slot roles. |
| RT-C11 | Layouts | Static, resilient, runtime, unknown, partial, and conflicting layout claims produce stable values and coverage wording. |
| RT-C12 | Bridges | Swift/Objective-C identity and dispatch aliases require evidence and never merge unrelated definitions. |
| RT-C13 | Queries and reports | Every query has zero/one/ambiguity behavior, graph-digest binding, deterministic JSON/text views, and schema validation. |
| RT-C14 | Module snapshots | Closed snapshot sets reconstruct repeatably and reject generation, image-set, fixup, or pointer-authentication drift. |
| RT-C15 | Runtime guards | Swift, Objective-C, and C++ guard arms bind exact route evidence inside the consumed barrier and reconstruct receipts. |
| RT-C16 | Limits and conservation | All structural limits, cycles, collisions, duplicates, boundary values, and hostile growth terminate deterministically without usable truncation. |

The generated ledger records the exact number of claimed tests and their fully
qualified identities. Zero matches, duplicate claims, unclaimed executable
tests, stale fixtures, and a family with no negative mutation fail the gate.
RT-C15 cannot be completed by file inspection, mocks, recorded reports, or a
portable-only provider; its native profile must pass independently.

## 10. Dependency-ordered work packages

| ID | Work package | Depends on | Binding evidence |
|---|---|---|---|
| R001 | Freeze the ontology, schemas, capability IDs, diagnostics, queries, reports, and limits | none | Generated schemas and hostile-value tests cover every closed union. |
| R002 | Stabilize strict `macho-swift`, `macho-objc`, and `macho-cpp` leaf records | R001 | Borrowed bounded readers, typed failures, pointer provenance, and conservation tests pass upstream. |
| R003 | Build exact file RTTI graphs | R002 | All three languages build deterministic graphs with conflicts and external refs conserved. |
| R004 | Ship public RTTI info/query/report/toolkit/CLI surfaces | R003 | Spawned CLI journeys and JSON differential tests use real fixtures. |
| R005 | Build coherent mapped-module RTTI graphs | R003 | Closed snapshot-set reconstruction and no-effect observation suites pass. |
| R006 | Integrate Swift and C++ vtable routes with R0/R1 and guarded Hook install | R005, Plan 0002 native gates | Exact subobject/address-point/slot/implementation evidence survives receipts and recovery. |
| R007 | Complete mutation, differential, performance, and whole-artifact review | R001-R006 | Every registry mutation is killed and a fresh complete rereview has no material findings. |

Runtime gating does not defer R001 schema, report, verifier, and diagnostic
shape. R006 may remain false while R001-R005 ship inspection honestly.

## 11. Acceptance commands

```bash
# Upstream reusable leaf libraries
cargo test --locked -p macho-swift
cargo test --locked -p macho-objc
cargo test --locked -p macho-cpp
cargo xtask verify

# Splice authority and product surfaces
cargo run --locked -p xtask -- rtti-dependency-audit
cargo run --locked -p xtask -- rtti-oracle
cargo run --locked -p xtask -- rtti-conformance
cargo test --locked -p splice-engine semantic_rtti
cargo test --locked -p splice-cartridge-macho semantic_rtti
cargo test --locked -p splice-cli --test semantic_rtti_journey
cargo run --locked -p xtask -- semantic-swift-conformance
cargo run --locked -p xtask -- instrumentation-conformance --profile portable
mise run ci
```

Each named command must exist and reject zero matching tests, stale fixtures,
unknown record kinds, unknown mutations, unclaimed tests, partial graphs used
for resolution, and capability/report disagreement.

## 12. Completion

Plan 0006 is complete when a clean consumer can inspect and query real Swift,
Objective-C, and C++ types; reproduce every entity and edge from retained
evidence; distinguish definitions, instances, layouts, and dispatch routes;
observe explicit safe stops for unsupported runtime cases; and run the complete
acceptance matrix without a sibling checkout or private oracle.

Vtable activation is complete only when the RTTI route in section 7—not a name,
symbol, or executable-looking pointer—selects and guards the exact slot through
installation and receipt verification.
