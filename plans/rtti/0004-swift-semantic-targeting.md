# Design Proposal 0004 — Swift semantic recovery and guarded callable targeting

**State:** accepted agent-executable architecture and implementation contract.
Its slices are dependency order, not calendar phases. Schema, identity,
capability, safety, report, and verifier implications are absorbed now;
explicitly gated runtime paths remain unavailable until their named acceptance
profiles pass.

**Dependency:** this proposal extends Design Proposal 0003. The canonical v1
specification corpus and its lock are immutable, so this proposal takes the
fallback required by its original candidate contract: the combined Swift delta
is implemented as the coherent v2 semantic and instrumentation surface. It does
not mutate, reinterpret, or feature-extend the locked v1 identities. Shared
implementation may reuse v1 internals only behind an explicit v2 boundary.

**Current authority:** `spec/splice-design.md`,
`spec/splice-language-spec.md`, `spec/splice-instrumentation.md`, their generated
artifacts, and the conformance corpus remain controlling. Plan 0003 and this
proposal are design inputs until their contracts are absorbed there.

## 1. Decision

Splice should add Swift after Objective-C, but it must not pretend that a Swift
source declaration denotes one executable address. Swift semantic recovery has
three distinct layers:

```text
logical declaration
        |
        v
callable variant
(direct, dispatch, thunk, specialization, async)
        |
        v
one or more executable implementations
```

The first shippable surface is read-only Swift recovery for files and coherent
mapped-module snapshots. The first hook-authoring surface is exact
`observe_before` targeting of one direct, synchronous implementation. It states
that it observes calls reaching that entry only; it never claims to cover
inlining, specialization, class dispatch, protocol dispatch, dynamic
replacement, or async continuations.

This proposal also absorbs the complete entity roles, authored query shape,
capability vocabulary, reports, diagnostics, and Hook v1 guard variants needed
for current class-vtable and protocol-witness dispatch. Their native execution
is independently gated. Generic, async, coroutine/yielding, throwing,
actor-isolated, closure, opaque-result, pack, move-only, reabstraction,
specialization, destructor/deallocator, and dynamic-replacement variants remain
visible inspection facts and typed non-runnable outcomes; this proposal does
not implement their hook runtime.

Swift methods exposed through Objective-C dispatch, including an admitted
`@objc dynamic` method, use Plan 0003's Objective-C logical method and
`objc_dispatch` guard. A Swift presentation alias does not create a competing
Swift dispatch authority.

The semantic layer remains pure. It never initializes Swift metadata, calls a
metadata or witness accessor, runs target code, publishes a file, loads a
library, installs a hook, or declares instrumentation success.

## 2. Why Swift is a separate contract

Objective-C has a selector-oriented runtime dispatch model. Swift does not.
A Swift source method may be represented by a direct symbol, a class-vtable
entry, a protocol requirement and witness entry, a dispatch thunk, one or more
specializations, a reabstraction thunk, an async entry/resume family, or no
remaining call edge after inlining.

Swift's physical calling convention also cannot be inferred by translating a
demangled signature into C. It includes direct and indirect values, ownership,
special treatment for `self`, closure context, error results, generic metadata,
witness tables, resilient/address-only values, and architecture-specific
lowering. Public ABI stability does not make an internal callable's convention
or continued existence a cross-build promise.

The authoritative external design references for this proposal are Swift's
[mangling](https://github.com/swiftlang/swift/blob/main/docs/ABI/Mangling.rst),
[calling convention](https://github.com/swiftlang/swift/blob/main/docs/ABI/CallingConvention.rst),
[type metadata](https://github.com/swiftlang/swift/blob/main/docs/ABI/TypeMetadata.rst),
and [type layout](https://github.com/swiftlang/swift/blob/main/docs/ABI/TypeLayout.rst)
ABI documents.

Those documents explain the ABI, but they are not Splice runtime inputs. The
production implementation uses pinned built-in profiles and exact target
evidence. Unsupported or internally inconsistent ABI material rejects.

## 3. Current baseline and dependency seam

### 3.1 Splice today

Current Splice has no canonical Swift entity, locator, callable, ABI, report,
or runtime-dispatch model. Generic Mach-O sections, symbols, VA/RVA locators,
and Carve can expose bytes, but none of them proves a Swift declaration,
callable role, specialization, vtable slot, witness entry, or physical ABI.

Instrumentation already owns exact RVA hooks, before-entry continuation,
trampoline relocation, handler-library binding, review, barriers, recovery,
receipts, and verification. This proposal does not create another hook engine
or broaden generic `ProcessEdit`.

The current canonical instrumentation schema does not yet contain Plan 0003's
`HookApplyGuardV1`. Joint absorption therefore revises pre-release Hook v1 once
to include all arms declared by Plans 0003 and 0004. Old and revised Hook v1
must never coexist under one schema identity.

### 3.2 Reuse `github.com/bryanmatteson/macho`

At inspected commit `7267c63dede115edbe77d50006e4ede65285a00c`, the clean
local `~/Code/macho` repository already provides:

- `macho-swift` descriptor-first nominal type discovery;
- classes, structs, enums, protocols, fields/cases, parent contexts,
  conformances, associated-type records, and pure in-process demangling;
- `macho-analysis` `SwiftReport` observations, evidence, entities, gaps,
  selection partitions, diagnostics, collector outcomes, and conservation
  validation; and
- a `macho swift` text/JSON command.

The focused qualification run on 2026-07-20 passed 124 `macho-analysis` tests
and 8 `macho-swift` tests. That is useful baseline evidence, not Splice
conformance.

The current decoder is not yet a safe Splice production seam. In particular,
`SwiftTypeIndex::build` converts any typed failure to an empty index, descriptor
discovery uses `filter_map` for malformed entries, the type index is shallow,
and no complete callable/vtable/witness graph exists. An empty or partial index
must never be interpreted as “no Swift.”

Splice uses a narrow internal adapter:

```text
MachoSwiftDecoder.decode_strict(
    source: SelectedImmutableByteView,
    coordinates: FileCoordinates | ModuleCoordinates,
    profile: SwiftAbiProfileRef,
    limits: SwiftSemanticLimitsV1
) -> Outcome<SwiftDecodeBatchV1>

SwiftDecodeBatchV1 {
    coordinates: FileCoordinates | ModuleCoordinates
    abi_profile_sha256: String
    outcome: absent | complete | rejected
    records: [MachoSwiftRecordV1]
    observations: [SwiftObservationV1]
    gaps: [SwiftDecodeGapV1]
    collector_outcomes: [SwiftCollectorOutcomeV1]
    conservation: {
        attempted: Int,
        included: Int,
        unknown: Int,
        excluded: Int
    }
}
```

`MachoSwiftRecordV1`, `SwiftDecodeGapV1`, and
`SwiftCollectorOutcomeV1` are revision-pinned internal closed unions, not
public Splice schemas. The admitted record union has explicit payloads for
context/nominal/field/protocol/requirement/conformance/associated-type/method/
override/vtable/witness/symbol/export/Objective-C-alias facts and their exact
relative-reference forms. It has no opaque/custom/JSON fact arm. The dependency
audit snapshots those Rust discriminants and payload layouts; adding or
removing one requires review and conformance updates.

`attempted = included + unknown + excluded` uses checked arithmetic and equals
the number of discovered input records, including malformed records represented
by gaps. `complete` is legal only with no loss, no rejection-severity gap, and
all collectors terminal. Only a `complete` batch may contribute to a semantic
resolution graph; `absent` and `rejected` remain reportable inspection outcomes.

`SelectedImmutableByteView` is the exact file selection or
`ModuleSemanticSnapshot` from Plan 0003. The decoder never opens a path, reads a
live module lazily, chooses a fat slice, invokes `swift-demangle`, launches a
process, calls a target runtime accessor, or produces a Splice verdict.

The dependency revision is pinned in Cargo.lock and release source provenance,
with source-tree SHA-256, license/SBOM inventory, and a development-only local
path override. `macho` reports and image-local IDs are not Splice authority.
The production decoder cannot be the independent Swift oracle.

Before production use, the adapter or upstream crate must:

1. accept the bounded immutable-reader contract rather than require an
   unaccounted whole-file allocation;
2. return strict per-record failures with descriptor, relative-pointer,
   section, fixup, symbol, and mangling provenance;
3. distinguish absent sections from damaged or unsupported metadata;
4. expose every admitted relative-pointer storage field, base, decoded target,
   file/module coordinate, and fixup observation;
5. remove error-to-empty and `filter_map` loss from the strict path;
6. provide typed mangling components rather than display text as identity;
7. parse the callable, method, override, vtable, protocol-requirement,
   conformance, and witness records admitted below; and
8. prove equal results through bounded and full-report paths.

### 3.3 Cross-module Swift graph snapshots

One decoder call still consumes exactly one immutable file or module view. A
Swift graph may, however, refer from a conformance in one image to a type or
protocol descriptor in another. Semantic resolution may therefore join decode
batches only through this immutable aggregate:

```text
SwiftModuleSnapshotRefV1 {
    module_generation: String
    module_snapshot_sha256: String
}

SwiftSemanticSnapshotSetV1 {
    process_generation: String
    primary: SwiftModuleSnapshotRefV1
    dependencies: [SwiftModuleSnapshotRefV1]
    set_sha256: String
}

set_sha256 = H(
  "splice-swift-semantic-snapshot-set-v1",
  process_generation,
  RFC8785(primary),
  RFC8785(dependencies sorted by module_generation))
```

All members are ordinary Plan 0003 `ModuleSemanticSnapshot` values captured in
one effect-free coherent session. Module generations are unique, the primary
cannot recur in dependencies, and every member carries the same process
generation. The set is closed before decoding; graph construction cannot lazily
read or add a module. Every dependency is retained in R0/R1 and recaptured as a
whole. A generation, membership, ordering-key collision, or content change
rejects the operation.
The stored `set_sha256` must equal an independent recomputation of the formula;
it is not a caller-supplied opaque identity.

An unresolved bind remains a typed external declaration reference. It is not
resolved by consulting ambient loaded images, a host linker, name similarity,
or the first matching symbol. Direct hooks that do not depend on that reference
may proceed only when their callable, implementation, role, ABI/capture, and
coverage proofs are otherwise complete. Class/witness dispatch requires every
descriptor and table identity used by its guard to be resolved inside the
closed snapshot set.

## 4. Scope and runtime gates

| ID | Surface | Contract | Runtime disposition |
|---|---|---|---|
| SW001 | file Swift nominal/protocol/conformance recovery | absorbed | active after file corpus passes |
| SW002 | coherent mapped-module and dependency-set recovery | absorbed | `gated:swift-module-snapshot` |
| SW003 | typed mangling and callable graph | absorbed | active for admitted records |
| SW004 | exact structural locators and inspection | absorbed | follows SW001/SW002 |
| SW005 | Swift authored queries, knowledge, profiles, templates | absorbed | active for resolution |
| SW006 | direct synchronous implementation `observe_before` | absorbed | `gated:swift-direct-hook` |
| SW007 | direct-call capture ABI | absorbed | `gated:swift-direct-capture` |
| SW008 | recorded class-vtable and witness inspection | absorbed | active when decoded |
| SW009 | current class-vtable dispatch guard | absorbed | `gated:swift-class-dispatch` |
| SW010 | current protocol-witness dispatch guard | absorbed | `gated:swift-witness-dispatch` |
| SW011 | `@objc` Swift alias routing | absorbed | uses Plan 0003 ObjC gate |
| SW012 | generic/specialized/reabstraction hook execution | schema-visible | gated; no success path |
| SW013 | async/actor/coroutine hook execution | schema-visible | gated; no success path |
| SW014 | throwing function hook execution | schema-visible | gated; no success path |
| SW015 | replacement, suppression, after, return control | invalid Hook v1 | requires future instrumentation mode |
| SW016 | Swift metadata or witness mutation | excluded | no schema success arm |
| SW017 | runtime metadata initialization or accessor calls | excluded | no fallback |
| SW018 | on-disk Swift metadata mutation | excluded | requires separate layout/fixup/signing proposal |

Gated surfaces still have exact enum values, capability reasons, report states,
diagnostics, fixtures, and verifier opinions. They never advertise success,
emit a lowerable operation, or silently fall back to direct-entry semantics.

## 5. Atomic schema integration

Joint absorption extends the pre-release Plan 0003 schemas rather than adding a
parallel semantic product:

```text
splice.semantic.knowledge/v1
splice.semantic.abi/v1
splice.semantic.provider-interface/v1
splice.semantic.profile/v1
splice.semantic.resolution/v1
splice.semantic.report/v1
splice.instrumentation.request/v1       # HookApplyGuardV1 revision
splice.instrumentation.report/v1        # guard evidence revision
```

Every generated Rust type, JSON schema, toolkit binding, CLI catalog, report
schema, component signature, conformance case, fixture manifest, and verifier
registry changes in the same canonical generation. No consumer chooses an ObjC-
only or ObjC-plus-Swift interpretation by feature flag.

The shared `SemanticEntityRef.kind` registry gains exactly:

```text
swift_nominal_type
swift_protocol
swift_conformance
swift_callable
swift_callable_variant
swift_dispatch_slot
swift_implementation
```

This atomically narrows Plan 0003 section 6.3's “vtables do not enter v1”
statement to generic/C++ vtables. `swift_dispatch_slot` is admitted only under
the Swift ABI/profile/identity contract here; it does not create a generic
array-of-pointers locator or pre-adopt the Itanium/MSVC proposal.

The existing common coordinate, observation, evidence, knowledge, template,
expanded-operation, handler-binding, lowering, report, and digest foundations
remain shared. Their closed unions gain the Swift arms in this proposal, while
the explicitly listed Objective-C-shaped operation/scope/checkpoint records are
normalized atomically below.

Plan 0003's authored and resolved operation examples are Objective-C-shaped
records, so joint absorption normalizes them rather than appending optional
Swift fields:

```text
AuthoredEntityQueryV1 =
    { kind: objc_method, query: AuthoredObjcEntityQueryV1 } |
    { kind: swift_callable, query: SwiftAuthoredEntityQueryV1 }

SemanticDispatchAuthorityV1 =
    recorded_metadata_implementation | current_runtime_dispatch |
    recorded_direct_implementation | recorded_class_vtable_entry |
    current_class_vtable_dispatch | recorded_protocol_witness_entry |
    current_protocol_witness_dispatch | recorded_variant_implementation

ResolvedSemanticTargetV1 =
    { kind: objc_method,
      logical_method: SemanticEntityRef refined to objc_method,
      implementation: SemanticEntityRef refined to objc_implementation } |
    { kind: swift_callable,
      target: ResolvedSwiftHookTargetV1 }
```

`AuthoredObjcEntityQueryV1` is Plan 0003's exact `AuthoredEntityQuery` value,
renamed only to disambiguate the closed union arm; its fields and semantics do
not change.

`AuthoredSemanticOperation.target` becomes `AuthoredEntityQueryV1` or the
existing template parameter refined to `entity_query`; its existing
`dispatch_authority` field becomes `SemanticDispatchAuthorityV1`.
`ResolvedSemanticOperation` replaces its Objective-C-only `logical_method` and
`implementation` members with one `target: ResolvedSemanticTargetV1`. Its
common executable module, ABI, provider export, captures, guard, evidence, and
`known_aliases` members remain. For Swift, `known_aliases` contains the other
logical callables proven to share the selected implementation.

The common operation scope becomes:

```text
OperationScopeV1 {
    process_generation: String
    semantic_source_module_generation: String
    semantic_source_snapshot_sha256: String
    swift_snapshot_set: SwiftSemanticSnapshotSetV1, optional
}
```

`swift_snapshot_set` is absent for Objective-C and present for Swift; its
primary exactly equals the two semantic-source fields. The entire canonical set
enters resolved-operation, R0-row, R0-preimage target, R1-row, semantic-evidence,
and report digests. R1 reacquires every member rather than validating only the
primary. This is an atomic pre-release revision of the Plan 0003 examples, not
an unhashed report attachment.

The authored/resolved/R0/R1 digest preimages replace the former Objective-C-
specific fields with the canonical closed target union; they do not add
language-conditioned optional fields. The first two dispatch-authority values
are legal only for an Objective-C target; the remaining six are legal only for
a Swift target. A cross-language or role/authority mismatch is invalid before
target access.

If atomic absorption cannot be proved, implementation stops. A feature flag,
sidecar Swift JSON dialect, private alternate schema, or decoder-owned public
report is not an acceptable bridge.

## 6. Swift entities, observations, and identity

### 6.1 Observation model

```text
SwiftObservationSource =
    context_descriptor | nominal_descriptor | field_descriptor |
    protocol_descriptor | protocol_requirement | conformance_descriptor |
    associated_type_descriptor | method_descriptor | override_descriptor |
    class_vtable_entry | witness_table_pattern | witness_table_accessor |
    reflection_string | nlist | export_trie | objc_runtime_alias |
    live_class_vtable | live_witness_table

SwiftObservationV1 {
    observation_id: String
    source: SwiftObservationSource
    storage: SemanticCoordinate, optional
    relative_base: SemanticCoordinate, optional
    decoded_coordinate: SemanticCoordinate, optional
    raw_sha256: String
    fixup: StructuralValue, optional
    evidence_sha256: String
    disposition: included | unknown | excluded
}
```

Every input record receives one disposition. Unsupported, malformed, duplicate,
or unresolved records remain observations with typed evidence and diagnostics;
they do not disappear. A broad inspection may return partial entities, but a
semantic hook operation requires a complete exact entity and fails on any
relevant unknown or conflicted field.

### 6.2 Logical keys

```text
SwiftDeclarationRefV1 =
    { kind: resolved,
      entity: SemanticEntityRef refined to
              swift_nominal_type | swift_protocol | objc_class } |
    { kind: external,
      expected_kind: swift_nominal_type | swift_protocol | objc_class,
      raw_linkage_sha256: String,
      library_ordinal: Int, optional,
      reference_coordinate: SemanticCoordinate,
      typed_name: SwiftMangledEntityV1, optional }

SwiftDeclarationPathComponentV1 =
    { kind: identifier, value: String } |
    { kind: private_context, discriminator_sha256: String } |
    { kind: local_context, discriminator_sha256: String } |
    { kind: extension_context,
      defining_module: String,
      extended_declaration_sha256: String }

swift_declaration_discriminator_sha256 = H(
  "splice-swift-declaration-discriminator-v1",
  private_context | local_context,
  exact discriminator bytes)

SwiftNominalKind = class | struct | enum | type_alias | opaque

SwiftNominalKeyV1 {
    module: String
    declaration_path: NonEmpty<SwiftDeclarationPathComponentV1>
    kind: SwiftNominalKind
    generic_signature_sha256: String, optional
}

SwiftProtocolKeyV1 {
    module: String
    declaration_path: NonEmpty<SwiftDeclarationPathComponentV1>
    generic_signature_sha256: String, optional
}

SwiftConformanceKeyV1 {
    defining_module: String
    conforming_type: SwiftDeclarationRefV1 refined to
                     swift_nominal_type | objc_class
    protocol: SwiftDeclarationRefV1 refined to swift_protocol
    conditional_requirements_sha256: String, optional
}

SwiftCallableKind =
    function | instance_method | static_method | class_method |
    initializer | allocator | deinitializer | subscript_get |
    subscript_set | property_get | property_set | property_read |
    property_modify | closure

SwiftTraitStateV1 = absent | present | unknown

SwiftCallableEffectsV1 {
    async: SwiftTraitStateV1
    throwing: SwiftTraitStateV1
    actor_isolation: none | actor_instance | global_actor | unknown
}

SwiftCallableTraitsV1 {
    generic_context: SwiftTraitStateV1
    pack_expansion: SwiftTraitStateV1
    closure_context: SwiftTraitStateV1
    coroutine: SwiftTraitStateV1
    dynamic_replacement_participation: SwiftTraitStateV1
    foreign_calling_convention: SwiftTraitStateV1
    opaque_result: SwiftTraitStateV1
    address_only_values: SwiftTraitStateV1
    move_only_values: SwiftTraitStateV1
    resilient_layout: SwiftTraitStateV1
}

SwiftCallableKeyV1 {
    owner: SwiftDeclarationRefV1 refined to
           swift_nominal_type | swift_protocol | objc_class, optional
    module: String
    declaration_path: [SwiftDeclarationPathComponentV1]
    base_name: String
    kind: SwiftCallableKind
    formal_signature_sha256: String
    generic_signature_sha256: String, optional
    effects: SwiftCallableEffectsV1
    traits: SwiftCallableTraitsV1
}
```

Qualified name alone is not identity. Same-named local contexts, extensions,
private discriminators, overloads, generic signatures, accessors, and callable
kinds remain distinct.

Metadata-defined nominal entities canonicalize by proven descriptor identity
inside one file or module scope before graph construction. An explicit relative
reference may link observations to that entity. Demangled text, raw linkage,
source order, registration order, or address coincidence never merges entities.

An external declaration ref becomes `resolved` only when its exact bind/fixup
target and typed linkage identify one compatible descriptor entity in the
closed `SwiftSemanticSnapshotSetV1`. A disagreement between bind target,
mangling, descriptor kind, or expected module is `conflicted`; zero/multiple
targets remain external. External refs are preserved for inspection but cannot
own an admitted hook query, callable ABI, dispatch slot, or runtime guard.

### 6.3 Callable variants and implementations

```text
SwiftCallableVariantRole =
    direct_entry | class_vtable_entry | protocol_witness_entry |
    dispatch_thunk | reabstraction_thunk | specialization |
    prespecialization | async_entry | async_resume |
    coroutine_entry | coroutine_resume |
    destroying_deallocator | deallocating_deallocator |
    dynamic_replacement | metadata_accessor | witness_accessor

SwiftSpecializationKeyV1 {
    substitutions_sha256: String
    pass_id: String, optional
}

SwiftCallableVariantKeyV1 {
    callable: SemanticEntityRef refined to swift_callable
    role: SwiftCallableVariantRole
    specialization: SwiftSpecializationKeyV1, optional
    raw_linkage_sha256: String, optional
    descriptor_coordinate: SemanticCoordinate, optional
}

SwiftImplementationKeyV1 {
    executable_scope: FileSemanticScope | ModuleSemanticScope
    executable_rva: Hex
    architecture: Arch
    cpu_subtype: arm64 | arm64e | x86_64
}

SwiftDispatchSlotKind = class_vtable | protocol_witness

SwiftDispatchSlotKeyV1 =
    { kind: class_vtable,
      owner: SemanticEntityRef refined to swift_nominal_type,
      callable: SemanticEntityRef refined to swift_callable,
      slot_index: Int,
      descriptor_coordinate: SemanticCoordinate } |
    { kind: protocol_witness,
      conformance: SemanticEntityRef refined to swift_conformance,
      requirement: SemanticEntityRef refined to swift_callable,
      requirement_index: Int,
      descriptor_coordinate: SemanticCoordinate }
```

A logical callable never canonicalizes by mangled symbol or implementation RVA.
Several variants may implement one callable; several callables or variants may
share one implementation. The implementation entity canonicalizes only by
executable scope, RVA, and architecture. Every alias/variant relation remains
an evidence-backed graph edge.

The same raw linkage at different coordinates remains separate observations.
An external/public Swift mangling may be a stable linkage contract; an internal
mangling is only build-specific evidence. Neither is a durable cross-build
Splice identity without the selected knowledge variant and content identity.

### 6.4 Entity ID preimages

```text
splice-swift-nominal-file-v1:
  content_sha256, selection, descriptor Region, canonical SwiftNominalKeyV1
splice-swift-nominal-module-v1:
  process_generation, module_generation, module_snapshot_sha256,
  descriptor RVA, canonical SwiftNominalKeyV1
splice-swift-protocol-file-v1:
  content_sha256, selection, descriptor Region, canonical protocol key
splice-swift-protocol-module-v1:
  process_generation, module_generation, module_snapshot_sha256,
  descriptor RVA, canonical protocol key
splice-swift-conformance-file-v1:
  content_sha256, selection, descriptor Region, canonical conformance key
splice-swift-conformance-module-v1:
  process_generation, module_generation, module_snapshot_sha256,
  descriptor RVA, canonical conformance key
splice-swift-callable-v1:
  file or module semantic scope identity, canonical owner declaration ref or
  absent, canonical SwiftCallableKeyV1
splice-swift-variant-v1:
  callable entity ID, canonical SwiftCallableVariantKeyV1
splice-swift-dispatch-slot-v1:
  canonical SwiftDispatchSlotKeyV1
splice-swift-implementation-v1:
  executable scope identity, architecture, CPU subtype, executable RVA
```

Every field uses Plan 0003's length-framed ID encoding. A symbol-only callable
without a descriptor uses an occurrence-scoped entity ID that includes its
exact linkage observation coordinate. It is never upgraded to metadata-defined
by name similarity.

## 7. Typed mangling and reconciliation

Production demangling is pure and in-process. It returns a closed typed result:

```text
SwiftManglingResultV1 =
    { kind: supported,
      raw: Bytes,
      scheme: stable_swift | embedded_swift | legacy_swift,
      ast: SwiftMangledEntityV1,
      canonical_ast_sha256: String,
      display: String } |
    { kind: unsupported, raw: Bytes, reason: SwiftManglingGap } |
    { kind: malformed, raw: Bytes, diagnostic: String }

SwiftManglingGap =
    unsupported_scheme | unsupported_node | unsupported_representation |
    unsupported_requirement | unsupported_builtin | profile_mismatch |
    type_ast_depth_exceeded | type_ast_nodes_exceeded
```

The supported arm uses these closed structural values:

```text
SwiftTypeDeclarationKeyV1 {
    module: String
    declaration_path: NonEmpty<SwiftDeclarationPathComponentV1>
    kind: class | struct | enum | protocol | type_alias | opaque | objc_class
}

extended_declaration_sha256 = H(
  "splice-swift-extended-declaration-v1",
  RFC8785(SwiftTypeDeclarationKeyV1))

SwiftFunctionRepresentationV1 =
    thin | thick | method | witness_method | c_function | block

SwiftTypeAstV1 =
    { kind: nominal,
      declaration: SwiftTypeDeclarationKeyV1,
      arguments: [SwiftTypeAstV1] } |
    { kind: generic_parameter, depth: Int, index: Int } |
    { kind: dependent_member,
      base: SwiftTypeAstV1,
      member: String,
      protocol: SwiftTypeDeclarationKeyV1, optional } |
    { kind: tuple, elements: [SwiftTupleElementV1] } |
    { kind: function,
      representation: SwiftFunctionRepresentationV1,
      parameters: [SwiftFormalParameterV1],
      result: SwiftTypeAstV1,
      async: Bool,
      throwing: Bool } |
    { kind: metatype,
      representation: thick | thin | objc,
      instance: SwiftTypeAstV1 } |
    { kind: existential,
      protocols: [SwiftTypeDeclarationKeyV1],
      superclass: SwiftTypeAstV1, optional,
      class_constraint: Bool } |
    { kind: inout, value: SwiftTypeAstV1 } |
    { kind: owned, value: SwiftTypeAstV1 } |
    { kind: shared, value: SwiftTypeAstV1 } |
    { kind: pack, elements: [SwiftTypeAstV1] } |
    { kind: pack_expansion, pattern: SwiftTypeAstV1 } |
    { kind: builtin, profile_atom: String }

SwiftTupleElementV1 { label: String, optional, type: SwiftTypeAstV1 }
SwiftFormalParameterV1 {
    label: String, optional
    type: SwiftTypeAstV1
    variadic: Bool
}

SwiftFormalTypeAstV1 {
    representation: SwiftFunctionRepresentationV1
    parameters: [SwiftFormalParameterV1]
    result: SwiftTypeAstV1
    async: Bool
    throwing: Bool
}

SwiftGenericRequirementAstV1 =
    { kind: conformance,
      subject: SwiftTypeAstV1,
      protocol: SwiftTypeDeclarationKeyV1 } |
    { kind: same_type, left: SwiftTypeAstV1, right: SwiftTypeAstV1 } |
    { kind: superclass,
      subject: SwiftTypeAstV1,
      superclass: SwiftTypeAstV1 } |
    { kind: layout,
      subject: SwiftTypeAstV1,
      layout: class | native_class | trivial | ref_counted |
              { profile_atom: String } } |
    { kind: same_shape, left: SwiftTypeAstV1, right: SwiftTypeAstV1 }

SwiftMangledEntityV1 {
    module: String
    declaration_path: [SwiftDeclarationPathComponentV1]
    declaration: SwiftTypeDeclarationKeyV1, optional
    callable_kind: SwiftCallableKind, optional
    base_name: String, optional
    formal_type: SwiftFormalTypeAstV1, optional
    generic_requirements: [SwiftGenericRequirementAstV1]
    variant_role: SwiftCallableVariantRole, optional
    specialization: SwiftSpecializationKeyV1, optional
}

substitutions_sha256 = H(
  "splice-swift-specialization-substitutions-v1",
  RFC8785([SwiftTypeAstV1] in mangling substitution order))

canonical_ast_sha256 = H(
  "splice-swift-mangled-entity-v1",
  RFC8785(SwiftMangledEntityV1))
```

Recursive ASTs are acyclic values bounded by `max_type_ast_depth` and
`max_type_ast_nodes`. Protocol lists and generic requirement sets sort by their
canonical encoded bytes; parameter, tuple-element, declaration-path, and pack
arrays retain semantic order. `profile_atom` is legal only when the selected
ABI profile defines its exact semantics. An unrecognized mangling node,
representation, requirement, or builtin produces `unsupported`, not a lossy
string node.
An extension component's hashed declaration key is the underlying non-extension
type key and cannot recursively contain that same extension component.

`display` is presentation only. `SwiftMangledEntityV1` preserves module and
context components, entity kind, callable type, effects, generic signature,
specialization/thunk role, private discriminator, and ABI-relevant
representation markers when the admitted profile encodes them.

Descriptor and mangling evidence reconcile only through positive references:

- a method/override/vtable record points to the callable or implementation;
- a supported mangling encodes the same complete callable key;
- a symbol coordinate equals the decoded implementation coordinate inside the
  same selected scope; or
- an Objective-C runtime record explicitly names the Swift class/method alias.

Equal display strings, suffix stripping, fuzzy matching, or first symbol wins
are forbidden. Equally strong conflicting evidence produces `conflicted`, not
priority resolution. A stronger descriptor observation may supersede a weaker
symbol-only presentation fact while retaining both observations.

## 8. Callable ABI contract

Swift source types and demangled signatures are not physical calling
conventions. The shared semantic ABI schema therefore gains an exact Swift arm:

```text
SwiftAbiStability = apple_public_swift5 | build_specific_internal

SwiftAbiProfileRef {
    schema: splice.semantic.abi/v1
    id: String
    version: String
    content_sha256: String
}

SwiftParameterConvention =
    direct_owned | direct_guaranteed | direct_unowned |
    indirect_in | indirect_inout | indirect_out

SwiftRegisterSliceV1 {
    register: String
    bit_offset: Int
    bit_width: Int
}

SwiftStackSliceV1 {
    base: entry_stack_pointer
    signed_offset: Int
    size: Int
    alignment: Int
}

SwiftPhysicalValueV1 {
    logical_type: AbiType
    convention: SwiftParameterConvention
    passing:
        registers { registers: NonEmpty<SwiftRegisterSliceV1> } |
        stack { offset: Int, size: Int, alignment: Int } |
        indirect { pointer: SwiftRegisterSliceV1 | SwiftStackSliceV1,
                   pointee_size: Int, pointee_alignment: Int }
    ownership: owned | guaranteed | unowned | inout | unknown
    layout_evidence_sha256: String
}

SwiftHiddenInputsV1 {
    self_value: SwiftPhysicalValueV1, optional
    closure_context: SwiftPhysicalValueV1, optional
    error_result: SwiftPhysicalValueV1, optional
    async_context: SwiftPhysicalValueV1, optional
    coroutine_context: SwiftPhysicalValueV1, optional
    generic_metadata: [SwiftPhysicalValueV1]
    witness_tables: [SwiftPhysicalValueV1]
}

SwiftCallableAbiV1 {
    profile_ref: SwiftAbiProfileRef
    architecture: Arch
    cpu_subtype: arm64 | arm64e | x86_64
    stability: SwiftAbiStability
    compiler_build: String, optional
    optimization: String, optional
    effects: SwiftCallableEffectsV1
    parameters: [SwiftPhysicalValueV1]
    results: [SwiftPhysicalValueV1]
    hidden_inputs: SwiftHiddenInputsV1
    resilient_layout: none | fully_bound | unresolved
    evidence_sha256: String
}
```

`apple_public_swift5` is legal only for a public ABI rule explicitly covered by
the selected platform and architecture profile. Internal functions, thunks,
specializations, private layouts, and compiler-private entry points require an
exact `build_specific_internal` profile and build evidence. A demangled type,
DWARF-style presentation, symbol spelling, or source declaration cannot supply
missing physical fields.
CPU subtypes `arm64` and `arm64e` require common `Arch = aarch64`; subtype
`x86_64` requires `Arch = x86_64`. Thus arm64e pointer-authentication support
does not silently add a third Hook v1 architecture or bypass the existing
architecture capability.

The authored operation's existing `target_abi` is an `AbiContractRef` whose
resolved document arm is exactly `SwiftCallableAbiV1`. It may be absent for an
empty-capture operation. Any capture requires it, and resolution must reconcile
its callable key, role, build/profile scope, architecture, effects, signature,
and physical layout evidence with the selected target. A profile rule may
instantiate the document deterministically, but the resulting canonical value
and digest are frozen before target access and enter expanded identity.

The handler has Hook v1's fixed `HookContext` ABI. `SwiftCallableAbiV1`
describes the target entry and capture extraction only; it does not change the
handler ABI. An empty capture set does not require Splice to interpret target
arguments or results, but the report still says that the target ABI is
unavailable for captures.

Plan 0003's capture-source union remains shared. For a Swift target,
`parameter_index` and an ABI-proven `self` are legal; Objective-C `selector` is
invalid. A static/class method may expose `self` only when the exact Swift ABI
contract describes its metatype input. Closure context, generic metadata,
witness tables, error results, coroutine/async contexts, yielded values, and
return values have no authored capture source in this proposal even though the
ABI schema can represent them for inspection and future validation.

### 8.1 First admitted direct-entry subset

An operation can enter `gated:swift-direct-hook` only when all of the following
are proven:

1. the chosen variant role is exactly `direct_entry`;
2. the implementation has one exact executable RVA in the selected module;
3. async, throwing, generic context, pack expansion, closure context,
   coroutine, dynamic-replacement participation, and foreign calling
   convention are all proven `absent`, and actor isolation is proven `none`;
4. it is not a closure/thick-function entry, async entry/resume, dynamic
   replacement, specialization, reabstraction thunk, coroutine entry/resume,
   metadata accessor, or witness accessor;
5. the operation mode is exactly `observe_before`;
6. capture is empty, or every capture binding is supported by one exact
   `SwiftCallableAbiV1`;
7. no captured value has unresolved resilient, opaque, address-only, move-only,
   ownership, or layout state; and
8. the entry bytes, reviewed instruction window, selected generation, and
   ordinary instrumentation preconditions all pass.

This is deliberately a syntactic-and-evidence subset, not a best-effort ABI
classifier. Any unknown predicate is false for admission. Throwing, generic,
async, actor-isolated, coroutine/yielding, and capture-unsafe callables remain
inspectable with a typed gate reason.
Trait values, mangling AST representation, descriptor role, and ABI contract
must agree. A `c_function` or `block` representation is foreign-convention and
does not enter the first Swift direct subset.

### 8.2 First admitted guarded-dispatch subset

Current class-vtable and protocol-witness operations use the same effect/trait,
mode, exact-implementation, instruction-review, and ordinary instrumentation
predicates as section 8.1, except their required roles are respectively
`class_vtable_entry` and `protocol_witness_entry`. They additionally require
the runtime-state restrictions in section 11 and an empty `capture_bindings`
array. The exact callable ABI may be reported but is not interpreted by Hook
v1. A nonempty capture, generic requirement, async/coroutine entry, throwing
entry, actor isolation, dynamic replacement, foreign convention, or unresolved
trait returns its typed gate result before runtime observation.

The class/witness guard proves the selected route reaches the implementation at
apply linearization. It does not relax this callable subset, validate capture
ABI, or authorize handler-visible dispatch context.

## 9. Authored Swift intent and resolved operations

Swift authored intent stays target-free and survives build changes. It cannot
contain an entity ID, descriptor address, RVA, module generation, runtime table
pointer, or decoder observation ID.

```text
SwiftAuthoredOwnerQueryV1 {
    module: String
    declaration_path: NonEmpty<SwiftDeclarationPathComponentV1>
    kind: class | struct | enum | type_alias | opaque | protocol | objc_class,
          optional
}

SwiftDispatchAuthorityV1 =
    recorded_direct_implementation |
    recorded_class_vtable_entry |
    current_class_vtable_dispatch |
    recorded_protocol_witness_entry |
    current_protocol_witness_dispatch |
    recorded_variant_implementation

SwiftAuthoredConformanceQueryV1 {
    defining_module: String, optional
    conforming_type: SwiftAuthoredOwnerQueryV1
    protocol: SwiftAuthoredOwnerQueryV1
    conditional_requirements_sha256: String, optional
}

SwiftAuthoredEntityQueryV1 {
    module: String
    owner: SwiftAuthoredOwnerQueryV1, optional
    declaration_path: [SwiftDeclarationPathComponentV1]
    base_name: String
    callable_kind: SwiftCallableKind
    formal_signature_sha256: String, optional
    generic_signature_sha256: String, optional
    variant_role: SwiftCallableVariantRole, optional
    raw_linkage_sha256: String, optional
    specialization: SwiftSpecializationKeyV1, optional
    conformance: SwiftAuthoredConformanceQueryV1, optional
}
```

Query digests are not hashes of display text or free-form user labels:

```text
formal_signature_sha256 = H(
  "splice-swift-formal-signature-v1", RFC8785(SwiftFormalTypeAstV1))
generic_signature_sha256 = H(
  "splice-swift-generic-signature-v1",
  RFC8785([SwiftGenericRequirementAstV1] in canonical requirement order))
conditional_requirements_sha256 = H(
  "splice-swift-conditional-requirements-v1",
  RFC8785([SwiftGenericRequirementAstV1] in canonical requirement order))
raw_linkage_sha256 = H(
  "splice-swift-raw-linkage-v1", exact linkage bytes)
```

The first three ASTs are sealed generated schema values. Raw linkage is legal
only in an exact-build knowledge variant bound to content identity and
architecture/CPU subtype; an interactive presentation name cannot supply it.
Private/local discriminator path components and `pass_id` are likewise build-
specific and legal only under that exact-build binding. A reusable query that
omits them must resolve exactly one candidate or reject ambiguity. A
specialization transform not fully represented by substitutions and
the supported mangling role requires exact raw linkage; otherwise the variant
is incomplete and inspection-only.

The operation's shared `dispatch_authority` must be one of
`SwiftDispatchAuthorityV1` for this query. `conformance` is required exactly for
recorded/current protocol-witness authority and forbidden otherwise. Its
`protocol.kind` is required to be `protocol`; its `conforming_type.kind` is
required and cannot be `protocol`; and its protocol must equal the selected
requirement callable's protocol owner. Current witness authority requires
`conditional_requirements_sha256` absent; a conditional conformance is
inspection-only in v1. Existing typed template parameters
use the same `entity_query` parameter kind; there is no Swift-only template
language.

Authority fixes the admissible role: `recorded_direct_implementation` requires
`direct_entry`; recorded/current class authority requires `class_vtable_entry`;
recorded/current witness authority requires `protocol_witness_entry`; and
`recorded_variant_implementation` requires an explicit role from
`dispatch_thunk`, `reabstraction_thunk`, `specialization`, `prespecialization`,
`async_entry`, `async_resume`, `coroutine_entry`, `coroutine_resume`, or
`destroying_deallocator`, `deallocating_deallocator`, or `dynamic_replacement`.
If `variant_role` is present it must equal the
authority-implied role; it is required for `recorded_variant_implementation`.
Recorded class/witness/variant authority produces inspection/typed-gate
evidence only in this proposal;
current authority is the only route to a corresponding runtime guard.
Class authority also requires an owner of kind `class`; witness authority
requires the protocol requirement owner and exact conformance query. A free
function has no owner; a method/accessor requires one. Invalid shape rejects
before target access.

Resolution requires exactly one callable, one role compatible with the
requested dispatch authority, and one admissible implementation or dispatch
slot. Zero matches produce `swift_callable_not_found`. More than one produces
`swift_callable_ambiguous` with bounded, deterministically ordered candidates
and the smallest additional discriminators that would separate them. Resolver
order, symbol-table order, address order, or knowledge-pack order never breaks
a tie.

```text
ResolvedSwiftHookTargetV1 {
    callable: SemanticEntityRef refined to swift_callable
    variant: SemanticEntityRef refined to swift_callable_variant
    implementation: SemanticEntityRef refined to swift_implementation
    dispatch_slot: SemanticEntityRef refined to swift_dispatch_slot, optional
    coverage: SwiftHookCoverageV1
    evidence_sha256: String
}
```

Dispatch authority, target ABI reference, and apply guard remain common
`ResolvedSemanticOperation` fields rather than duplicated inside the target
arm. `none` is the only legal guard for `recorded_direct_implementation`.
Current class and witness authorities require their corresponding Swift guard.
A recorded table entry is an inspection fact in this proposal and is not
silently lowered as though it were current process state.

## 10. Coverage and dispatch authority

```text
SwiftGuaranteedRouteV1 =
    selected_direct_variant {
        variant: SemanticEntityRef refined to swift_callable_variant
    } |
    current_class_slot {
        nominal_type: SemanticEntityRef refined to swift_nominal_type,
        slot: SemanticEntityRef refined to swift_dispatch_slot
    } |
    current_conformance_witness {
        conformance: SemanticEntityRef refined to swift_conformance,
        requirement: SemanticEntityRef refined to swift_callable,
        slot: SemanticEntityRef refined to swift_dispatch_slot
    }

SwiftHookCoverageV1 {
    effect_scope: implementation_entry
    implementation: SemanticEntityRef refined to swift_implementation
    guaranteed_route: SwiftGuaranteedRouteV1
    invocation_route_attribution: unavailable
    co_targeted_callables: [SemanticEntityRef refined to swift_callable]
    not_proven_to_reach_entry: [SwiftCoverageExclusion]
}

SwiftCoverageExclusion =
    inlined_calls | other_specialized_variants |
    other_reabstraction_thunks | other_direct_implementations |
    other_class_vtable_slots | other_protocol_witness_tables |
    objc_dispatch_to_other_implementation | dynamic_replacements |
    async_continuations | coroutine_resumes | unknown_variants
```

Coverage is part of resolved identity, review, R0/R1, receipts, and reports.
All admitted Swift hooks patch an implementation entry, so the actual effect is
implementation-wide: any route that reaches that exact entry may be observed.
Hook v1 cannot attribute an invocation to direct, vtable, witness, or
Objective-C dispatch. A current class/witness guard proves only that the named
route points to the patched implementation at apply linearization; it does not
make route attribution available or confine the hook's effects to that route.
After the barrier is released, later runtime dispatch changes are not
continuously guarded: the receipt preserves the apply-time fact, while the
installed entry hook remains on the reviewed implementation until ordinary
retirement/recovery. Reports never present apply-time current dispatch as an
ongoing invariant.

The report therefore lists the one guaranteed route, every logical callable
proven to share the implementation, and every known route/variant not proven to
reach it. `unknown_variants` is present whenever graph completeness is not
proved. A class-vtable claim is limited to the specified concrete metadata and
slot. A witness claim is limited to the specified unconditional concrete
conformance, table, and requirement. Neither proves coverage of devirtualized
calls, inherited slots in unobserved metadata, other witness tables,
specializations, thunks, dynamic replacements, async continuations, or inlined
code. No surface says “all calls to the Swift method.”

Several semantic callables may legitimately share an implementation. Shared-
implementation admission follows Plan 0003's exact shared-callable policy and
always reports the co-targeted callables. It does not invent a selector- or
Swift-specific exception.

An explicit Objective-C runtime alias routes an admitted `@objc`/Objective-C-
dispatched method through Plan 0003's `objc_dispatch` authority. Pure Swift
class dispatch never borrows the Objective-C guard merely because a class is
Objective-C-compatible.

Metadata and witness accessors are graph entities, not dispatch evidence.
Inspection and preview may observe already-realized, coherently snapshotted
tables; they must not call an accessor, initialize metadata, instantiate a
conditional conformance, allocate, block, run a target initializer, or cause
dynamic replacement.

## 11. Hook v1 apply-guard expansion

Joint absorption of Plans 0003 and 0004 defines the final pre-release closed
union:

```text
HookApplyGuardV1 =
    { kind: none } |
    { kind: objc_dispatch,
      expected: ObjCRuntimeDispatchStateV1,
      expected_dispatch_state_sha256: String } |
    { kind: swift_class_vtable,
      expected: SwiftClassDispatchStableStateV1,
      expected_dispatch_state_sha256: String } |
    { kind: swift_protocol_witness,
      expected: SwiftWitnessDispatchStableStateV1,
      expected_dispatch_state_sha256: String }
```

`ObjCRuntimeDispatchStateV1` is exactly Plan 0003's stable state. Joint
absorption normalizes Plan 0003's illustrative flat guard arm into the nested
`expected` value above without changing any state field or comparison semantic.
All three non-`none` arms store the canonical expected state and its independently
recomputed digest; a mismatch between the value and digest is schema-invalid.

These arms are a safety precondition on an ordinary exact-RVA Hook v1 install.
They do not make the provider a semantic resolver, add a new hook mode, mutate
runtime dispatch tables, or authorize a provider fallback.

### 11.1 Observer identity and stable state

```text
SwiftObserverIdentityV1 {
    observer_id: String
    observer_version: String
    implementation_sha256: String
    abi_profile_sha256: String
}

SwiftClassMetadataLayoutStateV1 {
    pointer_size: Int
    metadata_address_point_rva: Hex
    negative_size_words: Int
    positive_size_words: Int
    immediate_members_offset_words: Int
    vtable_start_offset_words: Int
    vtable_entry_count: Int
}

SwiftWitnessTableLayoutStateV1 {
    pointer_size: Int
    first_requirement_offset_bytes: Int
    requirement_count: Int
}

SwiftPointerAuthenticationStateV1 =
    { kind: none } |
    { kind: arm64e,
      key: instruction_a | instruction_b,
      address_diversity: Bool,
      discriminator: Hex,
      authenticated: true }

SwiftObservedFunctionPointerV1 {
    storage_module_generation: String
    storage_rva: Hex
    raw_bytes_sha256: String
    authentication: SwiftPointerAuthenticationStateV1
    implementation_module_generation: String
    implementation_rva: Hex
}

SwiftClassDispatchStableStateV1 {
    observer: SwiftObserverIdentityV1
    process_generation: String
    type_metadata_module_generation: String
    type_metadata_rva: Hex
    class_descriptor_module_generation: String
    class_descriptor_rva: Hex
    slot_index: Int
    slot_offset_bytes: Int
    metadata_layout: SwiftClassMetadataLayoutStateV1
    function_pointer: SwiftObservedFunctionPointerV1
}

SwiftWitnessDispatchStableStateV1 {
    observer: SwiftObserverIdentityV1
    process_generation: String
    conformance_descriptor_module_generation: String
    conformance_descriptor_rva: Hex
    protocol_descriptor_module_generation: String
    protocol_descriptor_rva: Hex
    type_metadata_module_generation: String
    type_metadata_rva: Hex
    witness_table_module_generation: String
    witness_table_rva: Hex
    requirement_index: Int
    slot_offset_bytes: Int
    witness_layout: SwiftWitnessTableLayoutStateV1
    function_pointer: SwiftObservedFunctionPointerV1
}
```

Every record uses module-relative coordinates. A pointer outside the admitted
module set, a non-executable implementation, an unbound conditional
conformance, a noncanonical metadata object, an out-of-range slot, or a table
that changes during observation rejects. Raw process virtual addresses are
never stable-state identity.

The profile must prove and the engine must independently validate
`slot_offset_bytes` from the embedded layout, pointer size, and slot/requirement
index. The offset must fall inside the recorded positive metadata bounds or
witness requirement array as appropriate. A provider-supplied offset or an
executable-looking value at another offset cannot repair a mismatch.
`metadata_layout.metadata_address_point_rva` must equal the surrounding
`type_metadata_rva`.
The function-pointer storage RVA must equal the profile-derived slot address.
On arm64e, the profile fixes key, address diversity, and discriminator
derivation; the provider must authenticate before normalizing the executable
coordinate and retain the raw bytes digest. Authentication failure, a
non-arm64e `arm64e` arm, or unauthenticated bit stripping rejects.

The v1 class guard admits only a nongeneric class whose already-realized
canonical metadata is uniquely attributable to a selected module generation
and RVA and whose selected ABI profile proves the metadata-bounds/vtable-offset
calculation. Generic instantiations, runtime-allocated metadata, or metadata
requiring an accessor remain inspectable and unsupported for current class
dispatch.

The v1 witness guard admits only an unconditional conformance whose
already-realized witness table is uniquely attributable to a selected module
generation and RVA. Conditional/generic conformances and runtime-allocated
witness tables remain inspectable and typed as unsupported for current witness
dispatch, even when their conditional requirements are known. Supporting them
requires a future stable runtime-allocation identity; raw heap addresses do not
fill that role.

Stable-state digests are computed exactly as:

```text
swift_class_dispatch_state_sha256 = H(
  "splice-swift-class-dispatch-state-v1",
  RFC8785(SwiftClassDispatchStableStateV1))

swift_witness_dispatch_state_sha256 = H(
  "splice-swift-witness-dispatch-state-v1",
  RFC8785(SwiftWitnessDispatchStableStateV1))
```

Capture epoch, read timestamps, thread IDs, retry counts, and evidence
packaging are deliberately absent.

### 11.2 Full observations and provenance

```text
SwiftClassDispatchObservationV1 {
    state: SwiftClassDispatchStableStateV1
    stable_state_sha256: String
    capture_epoch: Int
    source_snapshot_sha256: String
    evidence_sha256: String
}

SwiftWitnessDispatchObservationV1 {
    state: SwiftWitnessDispatchStableStateV1
    stable_state_sha256: String
    capture_epoch: Int
    source_snapshot_sha256: String
    evidence_sha256: String
}

SwiftRuntimeDispatchObservationV1 =
    { kind: swift_class_vtable,
      observation: SwiftClassDispatchObservationV1 } |
    { kind: swift_protocol_witness,
      observation: SwiftWitnessDispatchObservationV1 }
```

`source_snapshot_sha256` hashes the canonically ordered bounded read records
`{module_generation, rva, length, bytes_sha256}` used to derive the state. It is
full provenance, not stable identity. Immutable session evidence stores the
read values or digest-addressed byte evidence required to reconstruct those
records under the existing redaction/retention policy; the public report need
not inline target bytes. The verifier can recompute both state and observation
digests without rereading the target.

```text
swift_class_dispatch_observation_sha256 = H(
  "splice-swift-class-dispatch-observation-v1",
  RFC8785(SwiftClassDispatchObservationV1))

swift_witness_dispatch_observation_sha256 = H(
  "splice-swift-witness-dispatch-observation-v1",
  RFC8785(SwiftWitnessDispatchObservationV1))
```

R0, R1, and apply observations may have different full-observation digests
while their stable-state digests remain equal. Reports retain every full
observation and the comparison verdict. Hashing an epoch or evidence envelope
into stable state is nonconforming; discarding them entirely is also
nonconforming.

### 11.3 Coherent observer and exclusive apply barrier

The semantic runtime provider gains an effect-free observation operation:

```text
SwiftObservationReadRegionV1 {
    module_generation: String
    rva: Hex
    length: Int
}

ReviewedSwiftObservationInstructionV1 =
    { kind: swift_class_vtable,
      observer: SwiftObserverIdentityV1,
      process_generation: String,
      snapshot_set: SwiftSemanticSnapshotSetV1,
      type_metadata_module_generation: String,
      type_metadata_rva: Hex,
      class_descriptor_module_generation: String,
      class_descriptor_rva: Hex,
      slot_index: Int,
      slot_offset_bytes: Int,
      read_regions: NonEmpty<SwiftObservationReadRegionV1> } |
    { kind: swift_protocol_witness,
      observer: SwiftObserverIdentityV1,
      process_generation: String,
      snapshot_set: SwiftSemanticSnapshotSetV1,
      conformance_descriptor_module_generation: String,
      conformance_descriptor_rva: Hex,
      protocol_descriptor_module_generation: String,
      protocol_descriptor_rva: Hex,
      type_metadata_module_generation: String,
      type_metadata_rva: Hex,
      witness_table_module_generation: String,
      witness_table_rva: Hex,
      requirement_index: Int,
      slot_offset_bytes: Int,
      read_regions: NonEmpty<SwiftObservationReadRegionV1> }

SwiftRuntimeObserver.observe_coherent(
    barrier: ObservationBarrier,
    instruction: ReviewedSwiftObservationInstructionV1
) -> Outcome<SwiftRuntimeDispatchObservationV1>
```

`ReviewedSwiftObservationInstructionV1` contains the exact selected module
generations, descriptor/table coordinates, metadata coordinate, slot index,
profile-derived byte offset, bounded read regions, and expected record kinds.
The engine constructs and reviews it from the resolved graph. The provider may
only perform those bounded reads and attribute the resulting implementation to
one executable module; it cannot search by name, enumerate alternatives, or
derive a different slot.

The observer reads only already-realized process state under a documented
coherence mechanism. It cannot invoke Swift metadata/witness accessors, execute
target code, ask the provider to choose a slot, or initialize missing state. If
the platform cannot prove a complete effect-free coherent observation, the
corresponding current-dispatch capability is false.
`ObservationBarrier` is an immutable snapshot/coherence capability, not
permission to suspend/quiesce the target or hold the apply mutation barrier;
double-read stability is not a substitute for an atomic observation.

Apply uses the same provider boundary fixed by Plan 0003:

```text
InstrumentationProvider.observe_hook_apply_guard(
    barrier: BarrierGuard,
    instruction: ReviewedHookGuardInstruction
) -> Outcome<HookApplyGuardObservationV1>
```

```text
HookApplyGuardObservationV1 =
    { kind: objc_dispatch,
      observation: ObjCRuntimeDispatchObservation } |
    { kind: swift_class_vtable,
      observation: SwiftClassDispatchObservationV1 } |
    { kind: swift_protocol_witness,
      observation: SwiftWitnessDispatchObservationV1 }
```

Guard `none` performs no guard-observer call and has no fabricated observation.
The returned kind must exactly equal the reviewed non-`none` instruction.

The engine, not the provider, compares the canonical expected and observed
stable states. The provider returns observation material and typed failures;
it never returns `match`, `safe`, `allow`, or a semantic verdict.

After engine comparison, the still-live same `BarrierGuard` is passed to the
existing `install_hook(BarrierGuard, ReviewedHookInstruction)` operation. A
newly acquired, cloned, serialized, or provider-substituted guard is invalid.

The apply barrier is exclusive across final guard observation, target-byte
validation, trampoline allocation/fixup, patch installation, receipt capture,
and release. It excludes mutation of the target mapping, loader/module set,
Objective-C dispatch state, Swift metadata/vtable state, and Swift witness
state relevant to any retained operation. Observing outside the barrier,
releasing it before install, or silently changing to `none` is a hard failure.

Guard and authority must agree exactly:

- direct implementation requires `none`;
- current class-vtable dispatch requires `swift_class_vtable`;
- current protocol-witness dispatch requires `swift_protocol_witness`; and
- Objective-C dispatch requires Plan 0003's `objc_dispatch`.

Any other combination is schema-invalid before provider dispatch.

## 12. Resolution, review, R0/R1, and lowering

Swift extends Plan 0003's existing semantic pipeline; it does not create a
second checkpoint or apply path:

```text
authored intent + selected knowledge/profile/template
  -> expanded operations
  -> exact semantic graph and capability evaluation
  -> resolved operation + coverage + ABI + guard expectation
  -> operator review
  -> R0 generation/content/byte/dispatch preimages
  -> R1 refresh and comparison
  -> ordinary exact-RVA Hook v1 request
  -> exclusive-barrier apply observation and install
  -> receipt and verification report
```

### 12.1 Expansion and resolution

Expanded-operation identity includes the authored Swift query, selected profile
and knowledge identities, template arguments, feature, missing policy, handler
binding, capture bindings, and requested dispatch authority. It excludes
resolved addresses and generations.

Resolution produces one `ResolvedSwiftHookTargetV1`. Its canonical callable,
variant, implementation, optional slot, coverage, and evidence value enters the
common resolved-operation preimage through `ResolvedSemanticTargetV1`; the
common ABI reference, dispatch authority, aliases, and guard enter their
existing members. Reports may expose derived component digests, but those are
recomputed from these canonical values and never supplied as independent
authoritative inputs.

An unresolved ABI is legal only for the admitted empty-capture direct-entry
case. It is not legal for a capture or for any future operation that interprets
arguments, return values, error results, async contexts, generic metadata, or
witness-table inputs.

The review surface shows the authored declaration, exact role, implementation
module generation and RVA, declared coverage and exclusions, co-targeted
callables, captures and physical sources, runtime guard kind and expected
stable state, all capability gates, and every warning. A demangled label alone
is never sufficient review material.

### 12.2 R0 and R1

The proposal reuses Plan 0003's preimage domain names, length framing,
canonicalization, sorting, and comparison framework while atomically revising
the listed operation/scope/checkpoint values. There is no `SwiftCheckpoint`,
shortened content identity, or language-specific retry loop.

Joint absorption replaces the Objective-C-only optional observation member in
both checkpoint rows with:

```text
SemanticRuntimeDispatchObservationV1 =
    { kind: objc_dispatch,
      observation: ObjCRuntimeDispatchObservation } |
    { kind: swift_class_vtable,
      observation: SwiftClassDispatchObservationV1 } |
    { kind: swift_protocol_witness,
      observation: SwiftWitnessDispatchObservationV1 }
```

The member is absent exactly for guard `none` and present with the same kind as
every non-`none` guard. Its canonical full-observation value replaces the old
Objective-C-only value in the corresponding R0/R1 row preimage member. Guard
expected state, observation state, and independently recomputed stable digest
must agree.

For a direct operation, R0 records the module-generation, module-snapshot,
selected bytes, instruction review, implementation entity, ABI/capture data,
coverage, and `none` guard. For a current-dispatch operation, R0 additionally
records the full coherent class or witness observation and embeds its stable
state in `HookApplyGuardV1`.

R1 reacquires the process generation, selected modules and content snapshots,
target bytes, semantic graph, aliases, implementation, ABI/capture facts,
coverage, and current dispatch observation. The operation is retained only if
all ordinary Plan 0003 comparisons pass and its resolved identity and stable
dispatch state are unchanged. Fresh capture epoch or evidence packaging alone
does not make stable dispatch drift; both full observations remain in the
report.

Zero retained operations yields Plan 0003's `no_change` result. It never calls
the instrumentation provider. One operation drifting does not authorize
applying a different candidate or a different dispatch authority.

### 12.3 Lowering and provider boundary

Each retained Swift operation lowers to the existing Hook v1 instruction with:

- the exact implementation module generation and RVA;
- the reviewed instruction window and target-byte precondition;
- exactly one authored handler-library binding;
- before-entry continuation;
- the exact `HookApplyGuardV1`; and
- no semantic query, Swift entity, mangled name, descriptor pointer, or runtime
  resolution request in the provider instruction.

Lowering cannot call a metadata/witness accessor, ask the provider to
re-resolve a symbol, switch implementations, choose a table, or mutate a Swift
dispatch slot. Provider invocation remains reachable only through the same
instrumentation authority, recovery journal, signing/library checks, barrier,
receipt, and verifier flow as every other Hook v1 install.

## 13. Inspection, toolkit, and CLI

### 13.1 Structural locators

The shared paired `ImageView`/`ModuleView` locator registry gains:

```text
macho.swift_type(
    module: String, optional,
    display_path: String, optional,
    kind: SwiftNominalKind, optional,
    entity_id: String, optional
) -> macho.swift_type

macho.swift_protocol(
    module: String, optional,
    display_path: String, optional,
    entity_id: String, optional
) -> macho.swift_protocol

macho.swift_callable(
    module: String, optional,
    owner_display_path: String, optional,
    base_name: String, optional,
    callable_kind: SwiftCallableKind, optional,
    variant_role: SwiftCallableVariantRole, optional,
    entity_id: String, optional
) -> macho.swift_callable

macho.swift_conformance(
    type_entity_id: String, optional,
    protocol_entity_id: String, optional,
    entity_id: String, optional
) -> macho.swift_conformance

macho.swift_dispatch_slot(
    owner_entity_id: String, optional,
    conformance_entity_id: String, optional,
    slot_kind: SwiftDispatchSlotKind, optional,
    slot_index: Int, optional,
    entity_id: String, optional
) -> macho.swift_dispatch_slot
```

With no filters a locator returns every admitted entity in deterministic entity
ID order. `entity_id` is an exact inspection selector and cannot appear in
authored operations. Incompatible filters reject rather than being ignored.
Display-path filters are presentation-only and broad; equal display paths
return every distinct discriminator/entity.
Image locators use file coordinates; module locators require one coherent
`ModuleSemanticSnapshot` and return module coordinates. All enum values are
qualified registry values, not free-form decoder labels.

The existing generic `splice inspect --locator ... --format text|json` flow
owns rendering. Broad output includes observation conservation counts,
unsupported/malformed evidence, conflicts, incomplete fields, variants,
implementations, dispatch slots, ABI availability, and coverage limitations.

### 13.2 Toolkit

Toolkit bindings expose the generated schema types and the same pure operations
as the CLI:

```text
semantic.inspect_swift(...)
semantic.resolve_operation(...)
semantic.preview(...)
semantic.apply(...)
```

No binding accepts a raw process address as a Swift declaration or exposes a
decoder-owned ID as durable intent. All bindings return the shared report
envelopes and typed diagnostics.

### 13.3 Operator flow

Swift uses Plan 0003's semantic command group:

```text
splice instrument semantic info
splice instrument semantic preview --profile <path> [--feature <id>] ...
splice instrument semantic apply --profile <path> [--feature <id>] ...
```

`info` lists whether file/module and closed module-set Swift recovery, direct
hooks, captures, current class dispatch, and current witness dispatch are
compiled, supported by the selected platform provider, and active under
conformance. Preview remains
read-only and effect-free. Apply requires an accepted preview/review identity
and emits the ordinary instrumentation result plus semantic evidence.

There is no new top-level `swift hook` command and no production dependency on
the `macho swift` CLI. The latter remains a useful development diagnostic for
the dependency, not a Splice authority.

## 14. Knowledge, profiles, templates, and capabilities

One semantic profile may contain Objective-C and Swift operations. Selection,
signatures, expiration, exact-build overlays, template provenance, feature
closure, missing policy, and profile identity remain exactly those in Plan
0003. Swift cannot introduce an unsigned overlay or a weaker source tier.

Each `SwiftAbiProfileRef` resolves to one digest-pinned profile that states the
platform, architecture, OS range, Swift ABI generation, compiler-build scope,
mangling schemes, relative/indirect pointer encodings, context and conformance
record layouts, class metadata-bounds/vtable-offset algorithm, protocol
requirement ordering, witness pattern/table layout, callable physical lowering
rules, arm64e pointer-authentication key/discriminator derivation where
applicable, and every unsupported feature. Public-stable rules and
compiler-private rules are separate profile entries. Missing layout data is
unsupported; the decoder or observer cannot probe a plausible offset, strip
pointer bits, and accept what looks like an executable pointer.

The capability catalog gains these exact IDs:

```text
semantic.swift.inspect.file/v1
semantic.swift.inspect.module/v1
semantic.swift.graph.module_set/v1
semantic.swift.mangling.typed/v1
semantic.swift.callable_graph/v1
semantic.swift.hook.direct_before/v1
semantic.swift.capture.direct/v1
semantic.swift.dispatch.class.observe/v1
semantic.swift.dispatch.class.guard/v1
semantic.swift.dispatch.witness.observe/v1
semantic.swift.dispatch.witness.guard/v1
semantic.swift.objc_alias/v1
```

Every capability records schema identity, implementation identity, platform,
architecture, Swift ABI profile identity, provider identity when applicable,
conformance profile, status, and a closed reason. `supported` means the exact
named conformance profile has passed; presence of metadata sections, a
demangler, or a provider method is not enough.

The capability gate is conjunctive. For example, a captured direct hook
requires file-or-module inspection, typed mangling where used, callable graph,
the module-set graph capability whenever an external declaration participates,
direct hook, exact callable ABI, capture, the common instrumentation Hook v1
capability, and all selected template/provider capabilities. Current class and
witness dispatch require the closed module-set graph; current witness dispatch
additionally requires effect-free witness observation and the witness guard. A
dispatch authority cannot degrade to a direct hook because the direct
capability is true.

Feature-selection and expanded-operation digests include these capabilities
and their decisions. `missing = required | optional | forbidden` and strategy
groups behave exactly as in Plan 0003. A gated Swift capability returns a typed
missing result; optional omission is reported, not silently substituted.

Templates may parameterize a Swift query through the existing sealed
`entity_query` type and may expose typed enum/string/hash parameters required by
that query. They cannot accept an entity ID, RVA, mangled display label,
metadata pointer, witness-table pointer, or opaque JSON fragment. Template
validation, expansion limits, provenance, and capture sealing remain shared.

## 15. Reports, diagnostics, and limits

The common semantic report schema gains Swift entity, graph, ABI, coverage,
runtime-observation, guard-comparison, and gate-result arms. JSON is canonical
authority; text is a deterministic rendering of the same value.

For every authored Swift operation, preview/apply reports include:

- authored query and expanded-operation ID;
- selected knowledge/profile/template and their content identities;
- primary and dependency module generations/snapshot digests plus the closed
  Swift snapshot-set digest;
- candidate counts and deterministic ambiguity evidence;
- callable, variant, implementation, and optional slot entity references;
- implementation generation/RVA and reviewed bytes;
- complete coverage claim and exclusions;
- ABI/capture availability and evidence;
- R0 and R1 comparison fields;
- full R0/R1/apply runtime observations when applicable;
- expected/observed stable-state digests and engine verdict;
- handler binding, lowerable operation digest, provider receipt, and
  verification outcome when reached; and
- every warning, omission, unsupported construct, and stopping reason.

Status remains monotonic under Plan 0003: later rejection cannot be rendered as
earlier success, and `installed` cannot mean `verified`. A report never equates
graph recovery, resolution, review, R0, R1, provider installation, or receipt
verification.

`SwiftDiagnosticEffectV1` is closed:

```text
none | mark_entity_incomplete | reject_graph | gate_operation |
reject_operation | gate_capability | reject_checkpoint
```

The registry adds exactly these code/severity/effect triples:

| Code | Severity | Effect |
|---|---|---|
| `swift_metadata_absent` | info | `none` |
| `swift_metadata_malformed` | error | `reject_graph` |
| `swift_metadata_unsupported` | warning | `mark_entity_incomplete` |
| `swift_decoder_record_lost` | error | `reject_graph` |
| `swift_mangling_malformed` | error | `mark_entity_incomplete` |
| `swift_mangling_unsupported` | warning | `mark_entity_incomplete` |
| `swift_entity_incomplete` | warning | `mark_entity_incomplete` |
| `swift_entity_conflicted` | error | `mark_entity_incomplete` |
| `swift_external_declaration_unresolved` | warning | `mark_entity_incomplete` |
| `swift_snapshot_set_drift` | error | `reject_checkpoint` |
| `swift_callable_not_found` | error | `reject_operation` |
| `swift_callable_ambiguous` | error | `reject_operation` |
| `swift_variant_unsupported` | warning | `gate_operation` |
| `swift_coverage_incomplete` | error | `reject_operation` |
| `swift_abi_unknown` | warning | `gate_operation` |
| `swift_abi_profile_mismatch` | error | `reject_operation` |
| `swift_layout_profile_mismatch` | error | `reject_operation` |
| `swift_pointer_authentication_failed` | error | `reject_checkpoint` |
| `swift_capture_unsupported` | warning | `gate_operation` |
| `swift_runtime_observation_unavailable` | warning | `gate_operation` |
| `swift_runtime_observation_effect_forbidden` | error | `gate_capability` |
| `swift_class_dispatch_drift` | error | `reject_checkpoint` |
| `swift_witness_dispatch_drift` | error | `reject_checkpoint` |
| `swift_conditional_conformance_unbound` | warning | `gate_operation` |
| `swift_guard_authority_mismatch` | error | `reject_operation` |
| `swift_invocation_route_unattributed` | info | `none` |
| `swift_structural_budget_exceeded` | error | `reject_graph` |

Every row also has a required subject path, related-evidence list, and safe
display. A mark-incomplete effect preserves the observation/entity for broad
inspection but makes that entity ineligible for resolution. A gated operation
flows through the existing required/optional/forbidden missing policy; a reject
does not. Runtime coordinates render as module generation plus RVA; raw VAs and
target-memory contents are not emitted unless an existing explicit
diagnostic-data policy already permits them.

### 15.1 Structural budgets

```text
SwiftSemanticLimitsV1 {
    max_context_depth:                default 64,       hard 256
    max_type_ast_depth:               default 128,      hard 512
    max_type_ast_nodes:               default 262_144,  hard 4_194_304
    max_module_dependencies:          default 256,      hard 4_096
    max_identifier_bytes:             default 4_096,    hard 65_536
    max_mangling_bytes:               default 16_384,   hard 262_144
    max_mangling_nodes:               default 65_536,   hard 1_048_576
    max_nominal_descriptors:          default 1_000_000, hard 4_000_000
    max_callable_descriptors:         default 1_000_000, hard 4_000_000
    max_protocol_requirements:        default 1_000_000, hard 4_000_000
    max_conformances:                 default 1_000_000, hard 4_000_000
    max_dispatch_slots:               default 2_000_000, hard 8_000_000
    max_external_references:          default 2_000_000, hard 8_000_000
    max_observations:                 default 8_000_000, hard 32_000_000
    max_variants_per_callable:        default 4_096,    hard 65_536
    max_relationships:                default 4_000_000, hard 16_000_000
    max_evidence_bytes:               default 67_108_864, hard 536_870_912
}
```

Zero, negative, overflowed, or above-hard-limit values reject before decoding.
All counters use checked arithmetic and count attempted records, including
malformed and excluded observations. Limits are part of profile and report
identity.

Identifier/mangling byte limits and context/type-AST/mangling-node depth or
node limits apply per value. `max_variants_per_callable` applies per canonical
callable. Module dependencies apply per snapshot set. Every other record,
relationship, observation, and evidence counter is cumulative across the
entire file selection or closed module snapshot set, not reset for each member
or collector. Evidence bytes count retained raw/derived evidence before
compression and deduplication.

Exceeding a structural budget rejects the selected Swift semantic graph. It
does not return a truncated graph eligible for resolution or hooks. Read-only
inspection may return the observations and counts collected before the bound
only in a `rejected` report explicitly marked incomplete; locators cannot
select entities from that incomplete graph.

## 16. Conformance and independent oracles

Swift cases extend Plan 0003's single
`spec/conformance/semantic/fixtures.json` manifest with `language = "swift"`.
There is no second private manifest. Each fixture pins source identity, emitted
artifact identity, architecture, platform, Swift compiler build, optimization
mode, expected entity/observation/relationship counts, expected IDs and graph
edges, supported/unsupported features, operation outcomes, report digest, and
applicable mutations.

The corpus includes synthetic Swift sources under
`spec/conformance/semantic/src/swift/`, pinned built Mach-O inputs, malformed
and boundary mutations, expected graph maps, and native runtime helpers for
already-realized class-vtable and witness-table observations. Checked-in binary
fixtures include reproducible build manifests and redistribution provenance.

The oracle path is production-independent. Corpus regeneration may use the
pinned Swift toolchain's `swiftc -emit-sil`, `swiftc -emit-ir`,
`swift-demangle --expand`, and platform symbol tools to produce reviewed locked
expectations. CI consumes checked-in artifacts and expectations; it does not
need the host's current Swift compiler. The production `macho` decoder,
Splice's typed demangler, or Splice runtime observer may not generate its own
expected answers.

Offline fixtures cover arm64, arm64e, and x86_64 decoding and pointer-state
normalization. A current class/witness guard capability additionally requires
the barrier, observation, pointer-authentication, install, drift, and recovery
cases to pass on a native runner of that exact architecture/profile. Cross-
compiled helpers or simulated pointer bytes cannot activate a runtime guard.

### 16.1 Required case families

| ID | Family | Minimum proof |
|---|---|---|
| SW-C01 | nominal contexts | nested/private/same-name contexts remain distinct |
| SW-C02 | overloads/accessors | callable keys separate overloads and accessor roles |
| SW-C03 | malformed relative pointers | strict evidence; no error-to-empty loss |
| SW-C04 | mangling | supported/unsupported/malformed and typed AST identity |
| SW-C05 | callable variants | direct/thunk/specialization/async/coroutine/deallocator/replacement roles do not merge |
| SW-C06 | class vtables | descriptor slot, override, implementation, and coverage |
| SW-C07 | conformances/witnesses | requirement index and concrete conformance identity |
| SW-C08 | conditional conformance | remains inspectable but current witness authority rejects |
| SW-C09 | Objective-C aliases | explicit alias routes through `objc_dispatch` only |
| SW-C10 | direct empty capture | admitted subset lowers with guard `none` |
| SW-C11 | direct captures | exact registers/stack/indirect values and negative ABI cases |
| SW-C12 | excluded effects | generic/throws/async/actor/coroutine/closure/move-only are typed gates |
| SW-C13 | direct coverage | unproven variants/routes and unavailable route attribution are reported |
| SW-C14 | class guard | R0/R1/apply stable equality and independent drift dimensions |
| SW-C15 | witness guard | table/conformance/requirement/implementation drift dimensions |
| SW-C16 | observation effects | accessor/init/target-call attempts fail closed |
| SW-C17 | barrier | guard observed inside exclusive barrier through install |
| SW-C18 | limits | each exact/default/hard/overflow boundary and no usable truncation |
| SW-C19 | reports | JSON/text differential, redaction, status monotonicity |
| SW-C20 | cross-language profile | ObjC and Swift operations share expansion/R0/R1/apply atomically |
| SW-C21 | cross-module graph | exact bind joins, unresolved externals, closed-set membership/content drift |

The manifest supplies every applicable success, zero-match, ambiguity,
malformed, unsupported, stale-generation, wrong-architecture, and
capability-off dimension. A non-applicable dimension carries one verifier-owned
closed reason; blank or unknown applicability fails discovery. Guard families
vary one stable field at a time and separately vary only provenance fields to
prove the correct comparison boundary.

### 16.2 Mandatory mutation operators

The verifier must prove that each of these mutations fails a named case:

- convert decoder error or malformed record to empty/absent;
- drop a record through `filter_map`;
- resolve an external reference from an ambient/lazily added module;
- choose an external descriptor by first matching linkage text;
- merge same-display or same-qualified-name descriptors;
- use demangled display text as an entity ID;
- merge callables because they share an implementation;
- collapse specializations or thunks into `direct_entry`;
- claim a direct hook covers all dispatched calls or attributes their route;
- infer physical Swift ABI from a display signature;
- probe alternate metadata/vtable offsets until one looks executable;
- strip or accept an arm64e function pointer without profile-authentication;
- admit generic capture without metadata/witness inputs;
- admit async entry as synchronous Hook v1;
- admit a coroutine/yielding entry as an ordinary synchronous entry;
- admit class/witness dispatch with nonempty capture bindings;
- route a pure-Swift method through `objc_dispatch`;
- initialize metadata during inspection or preview;
- invoke a witness accessor during inspection or preview;
- use guard `none` for current class or witness authority;
- include capture epoch in stable-state identity;
- discard full dispatch-observation provenance;
- observe the apply guard before or after the exclusive barrier;
- release the barrier before installation completes;
- let the provider return the guard verdict;
- pick one conditional-conformance witness ambiguously;
- accept a truncated graph for resolution;
- use the production parser/demangler/observer as its own oracle; or
- add a Swift-only sidecar schema or apply path.

Mutation discovery is automatic and registry-backed. An unknown surviving
mutation, unknown fixture case, unknown capability, or unclaimed test target is
a verifier failure, not a warning.

### 16.3 Acceptance commands

```text
cargo test --locked -p splice-engine semantic_swift_model
cargo test --locked -p splice-toolchain semantic_swift
cargo run --locked -p xtask -- semantic-swift-dependency-audit
cargo run --locked -p xtask -- semantic-swift-oracle
cargo run --locked -p xtask -- semantic-swift-conformance
cargo run --locked -p xtask -- instrumentation-conformance --profile portable
cargo run --locked -p xtask -- instrumentation-report-differential
cargo run --locked -p xtask -- instrumentation-crash-matrix
mise run ci
```

Each command is a required implemented gate before its owning capability can be
advertised. Cargo succeeding with zero matching tests, a missing fixture
family, a skipped architecture, a stale expected digest, or an unknown
mutation is failure. The conformance report records tool versions, fixture and
schema digests, architecture partitions, mutation kill matrix, and exact test
counts.

## 17. Dependency-ordered implementation slices

These are dependency slices, not dates or permission to postpone schema work.
Each slice begins only after its entry conditions are true and stops on any
listed negative gate. Later runtime slices do not revise earlier identities.

### Slice 1 — absorb the combined semantic and Hook v1 schemas

Work:

1. merge Plans 0003 and 0004 into the controlling specs as one change;
2. define all Swift entity, key, query, variant, coverage, ABI, observation,
   capability, diagnostic, report, and limit arms;
3. expand `HookApplyGuardV1` with Objective-C, Swift class, and Swift witness
   arms plus full-observation report types;
4. regenerate Rust, JSON schemas, toolkit bindings, CLI catalogs, component
   signatures, verifier registries, and fixture schemas; and
5. freeze golden schema digests and forward/backward rejection cases.

Exit evidence: every generated consumer uses one identical closed union; the
schema/registry audit and all non-runtime schema tests pass.

Stop if any affected v1 is already released, any old/new v1 ambiguity remains,
or a consumer needs a sidecar/feature-dependent interpretation. Re-propose the
entire delta under v2 if v1 has shipped.

### Slice 2 — make the Mach-O dependency a strict bounded decoder

Work:

1. pin the approved `github.com/bryanmatteson/macho` revision and provenance;
2. implement `MachoSwiftDecoder.decode_strict` over the immutable-reader seam;
3. remove error-to-empty and record-dropping behavior from the strict path;
4. add typed mangling ASTs and complete admitted descriptor/callable/slot edges;
5. expose relative-pointer, fixup, symbol, and record provenance; and
6. prove bounded/full-path equality and observation conservation.

Exit evidence: dependency audit, independent oracle, malformed corpus, every
limit boundary, and conservation checks pass on arm64, arm64e, and x86_64
fixtures for every architecture the owning capability advertises.

Stop if absent and damaged metadata cannot be separated, unsupported records
can disappear, decoder IDs leak into Splice identity, production calls a host
tool, or the decoder is used as its own oracle.

### Slice 3 — ship the read-only Swift graph and locators

Work:

1. build canonical nominal/protocol/conformance/callable/variant/slot/
   implementation graphs from strict observations;
2. reconcile descriptor, mangling, symbol, fixup, and Objective-C alias evidence;
3. implement file locators and deterministic JSON/text inspection;
4. implement module locators only after coherent immutable module snapshots
   meet Plan 0003's generation/content rules;
5. implement closed snapshot-set graph joins and typed unresolved external
   references without lazy target reads; and
6. surface every unsupported/conflicted/incomplete fact and budget rejection.

Exit evidence: `semantic.swift.inspect.file/v1` passes SW-C01 through SW-C09,
SW-C18, and SW-C19. Module and module-set inspection have their own separately
passing capabilities, including SW-C21.

Stop if names or addresses become logical identity, incomplete graphs are
selectable, mapped reads occur outside the snapshot, or inspection runs target
code.

### Slice 4 — resolve and lower exact direct synchronous entries

Work:

1. implement the target-free authored Swift query and template binding;
2. enforce exact-one resolution and admitted direct-entry predicates;
3. compute honest coverage/exclusions and shared-implementation effects;
4. implement exact callable ABI only for the selected capture profiles;
5. integrate review, common R0/R1, exact-RVA Hook v1 lowering with guard
   `none`, reports, receipts, and verification; and
6. keep all other roles/effects as typed non-runnable outcomes.

Exit evidence: SW-C10 through SW-C13 and SW-C20 pass with all common
instrumentation suites and mutation operators. Empty capture and supported
capture activate independently.

Stop if direct targeting claims source-declaration coverage, missing ABI is
accepted for capture, a gated role lowers, or semantic code bypasses ordinary
instrumentation authority.

### Slice 5 — activate current class-vtable dispatch

Work:

1. implement effect-free coherent observation of already-realized class
   metadata and its exact vtable slot;
2. enforce the empty-capture synchronous guarded-dispatch subset and bind the
   observation to descriptor, callable, implementation, generations, and profile;
3. integrate full R0/R1 observations and stable-state comparisons;
4. implement `swift_class_vtable` final observation inside the exclusive apply
   barrier; and
5. verify coverage wording and drift dimensions.

Exit evidence: SW-C06, SW-C14, SW-C16, SW-C17, SW-C19, the crash matrix, and the
full common instrumentation suite pass under the native helper.

Stop if observation may initialize metadata, the platform cannot exclude
relevant mutation through install, a table pointer lacks stable module
coordinates, or provider code makes the verdict.

### Slice 6 — activate current protocol-witness dispatch

Work:

1. implement effect-free observation for one already-realized concrete
   conformance, table, requirement index, and implementation;
2. enforce the empty-capture synchronous guarded-dispatch subset and reject
   conditional conformances/runtime-allocated witness tables while retaining
   their inspection evidence;
3. integrate R0/R1 and `swift_protocol_witness` inside the same exclusive apply
   barrier; and
4. verify conformance-specific coverage and every independent drift dimension.

Exit evidence: SW-C07, SW-C08, SW-C15 through SW-C17, SW-C19, the crash matrix,
and all common instrumentation suites pass under the native helper.

Stop if resolving the table requires an accessor call, the conformance is
conditional, witness-table liveness/module attribution cannot be proven, or
the guard can fall back to a direct implementation.

### Slice 7 — activate the integrated product surface

Work:

1. finish capability discovery, profile/template selection, CLI/toolkit
   bindings, report rendering, redaction, help, and examples;
2. exercise mixed Objective-C/Swift profiles across no-change, partial optional
   omission, full apply, recovery, and verification paths;
3. run the exact acceptance commands on clean release inputs; and
4. freeze the release evidence bundle and capability matrix.

Exit evidence: every advertised capability maps to a passing conformance
profile and immutable evidence; every unadvertised surface returns its exact
typed gate reason.

Stop if help/report/schema disagree, a zero-test command passes, release inputs
are dirty or unpinned, or success depends on unavailable procedural evidence.

## 18. Global stopping criteria

Implementation stops and the affected operation/capability fails closed when
any of the following is true:

1. the controlling semantic or instrumentation schema cannot absorb the full
   delta atomically under its declared identity;
2. the selected `macho` revision, Swift ABI profile, knowledge source, schema,
   template, handler, provider, or fixture identity is missing or mismatched;
3. file selection, architecture, process generation, module generation,
   closed snapshot-set membership/content, executable scope, or target-byte
   evidence is ambiguous;
4. a metadata section is present but damaged, an admitted record is malformed,
   or the strict decoder cannot conserve every input observation;
5. nominal/callable identity depends on display text, source order, first match,
   raw address coincidence, or an unproven demangling/reference edge;
6. the query has zero or multiple matches, the role/authority combination is
   invalid, or the implementation/dispatch slot is not exact;
7. coverage cannot enumerate applicable exclusions or a shared implementation
   would co-target an unreviewed callable;
8. capture requires an unknown physical ABI, unresolved layout/ownership,
   unsupported hidden input, or an effect outside the admitted direct subset;
9. preview or observation would invoke target code, initialize metadata, call
   an accessor, allocate through the target runtime, or block on target state;
10. current class/witness state is unavailable, incoherent, noncanonical,
    outside admitted modules, changed during observation, or different across
    R0/R1/apply stable-state comparisons;
11. the provider cannot hold the exclusive barrier across guard observation,
    target-byte check, installation, receipt capture, and release;
12. the requested guard is absent, wrong for its dispatch authority, observed
    outside the barrier, or adjudicated by the provider;
13. any R0/R1 common preimage changes, any operation is substituted after
    review, or a zero-retained result would still reach the provider;
14. a structural budget overflows/exceeds, a truncated graph would be used, or
    a report omits required unknown/conflict/provenance material;
15. a required conformance case, architecture, mutation, differential report,
    crash-matrix case, or independent oracle is absent or failing; or
16. an operator-visible claim exceeds the exact installed entry, apply-time
    guaranteed route, and unavailable route attribution proven by the receipt.

Failures are typed and reported. They never trigger a name-only fallback,
symbol guess, direct-entry substitution, Objective-C substitution, runtime
accessor call, downgraded guard, or best-effort partial apply.

## 19. Deliberate non-adoptions

This proposal explicitly rejects:

- Swift source syntax, USRs, display names, or demangled strings as durable
  binary identity;
- the claim that hooking one implementation observes all calls to a source
  declaration;
- “Swift class method equals Objective-C selector” absent an explicit runtime
  alias and Objective-C authority;
- treating file-recorded vtable/witness entries as current runtime dispatch;
- production shelling out to `swift-demangle`, `swiftc`, `nm`, or another host
  tool;
- inferring target calling conventions from a demangled signature;
- calling metadata or witness accessors to make preview convenient;
- mutating class metadata, vtables, conformance records, witness tables,
  replacement chains, or on-disk Swift metadata;
- call-site rewriting, de-inlining, specialization fan-out, async continuation
  interception, return/throw observation, replacement, suppression, or
  after-call semantics under Hook v1;
- a language-specific hook provider, journal, checkpoint, report, or sidecar
  schema; and
- silently activating a gated capability because read-only recovery succeeds.

Those are not “later phases” implicitly authorized here. Each needs a future
proposal that proves its identity, ABI, effects, safety barrier, recovery,
coverage, and conformance implications.

## 20. Definition of done

The design is fully absorbed only when all items below are true:

- [ ] Plans 0003 and 0004 are reconciled into the controlling specs as one
      coherent pre-release schema change, or a new v2 proposal replaces this
      path after any v1 release.
- [ ] Every public schema/binding/catalog/registry shares the same generated
      Swift entity, query, ABI, coverage, diagnostic, report, capability, and
      Hook apply-guard unions.
- [ ] The pinned `macho` strict adapter is bounded, lossless, provenance-rich,
      independently oracled, and free of production host-tool/runtime calls.
- [ ] File inspection passes its corpus and advertises only
      `semantic.swift.inspect.file/v1`.
- [ ] Module inspection independently proves coherent immutable snapshots
      before advertising `semantic.swift.inspect.module/v1`.
- [ ] Cross-module graphs join only an immutable closed snapshot set, retain
      unresolved external refs, and bind every dependency into R0/R1/report
      identity before advertising `semantic.swift.graph.module_set/v1`.
- [ ] Callable identity separates declarations, roles, specializations,
      thunks, slots, and implementations without name/address heuristics.
- [ ] Direct empty-capture hooks meet the admitted subset, exact-one resolution,
      coverage, review, R0/R1, ordinary Hook v1, receipt, and verification gates.
- [ ] Direct capture is advertised only for exact proven physical ABI profiles
      and fails closed on every unresolved layout/ownership/hidden input.
- [ ] Current class dispatch is advertised only for the empty-capture
      synchronous subset after effect-free observation and the exclusive-
      barrier `swift_class_vtable` suite passes.
- [ ] Current witness dispatch is advertised only for the empty-capture
      synchronous subset after effect-free concrete-conformance observation and
      the exclusive-barrier
      `swift_protocol_witness` suite passes.
- [ ] Explicit Objective-C aliases route through the Plan 0003 Objective-C
      entity and `objc_dispatch` guard with no competing Swift authority.
- [ ] Generic, throwing, async, actor, coroutine/yielding, closure, opaque,
      pack, move-only, reabstraction, specialization, replacement, accessor,
      deallocator, and mutation surfaces remain visible typed gates with no lowerable
      success arm.
- [ ] Every fixture family and mutation operator is discovered and claimed;
      every acceptance command rejects zero tests and passes on pinned inputs.
- [ ] JSON/text reports agree, status is monotonic, all full runtime
      observations are retained, stable-state comparisons exclude provenance,
      and safe-display rules hold.
- [ ] Mixed Objective-C/Swift profiles prove deterministic expansion,
      capability selection, no-change, apply-barrier atomicity, recovery,
      receipts, and verification through the shared product path.
- [ ] The final operator documentation says exactly which executable entries
      are observed and never upgrades that evidence to source-level coverage.

Passing read-only inspection does not imply hook readiness. Passing direct
entry hooks does not imply class or witness dispatch readiness. Passing class
dispatch does not imply witness dispatch readiness. A capability becomes true
only when its exact implementation slice, common instrumentation gates, and
named conformance profile all pass.
