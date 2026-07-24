# Design Proposal 0003 — Semantic targeting and reviewed hook intent

**State:** accepted agent-executable implementation contract. Release A and the
Release B target-free authoring, report model, resolution/lowering verifier,
and portable guarded-Hook substrate are implemented in ordinary CI. Of the
seven Release B public semantic documents, ABI, convention-profile,
provider-interface, semantic profile, knowledge, resolution, and report are now
canonical generated authority. Native semantic hook activation is
governed independently by this proposal's activation gate in section 17.

**Historical input:** the non-repository archive at `../splice-lang` is research
material only. Its examples and prose supply ideas, not compatibility,
terminology, syntax, implementation, or acceptance authority.

**Current authority:** `spec/splice-design.md`,
`spec/splice-language-spec.md`, `spec/splice-instrumentation.md`, and the
generated conformance corpus remain controlling. This proposal does not weaken
an existing v1 behavior or claim that currently specified instrumentation is
already implemented.

## 1. Decision

Splice should recover the best idea in the historical language work: authors
should name the semantic thing they intend to observe or change, while Splice
proves exactly which current bytes and runtime address that name denotes.

The first release target is read-only Objective-C recovery in the built-in
Mach-O cartridge. A second, independently gated release deterministically
lowers one uniquely resolved recorded implementation, or one current runtime
dispatch target protected by a new in-barrier Objective-C guard, to the reviewed
Hook v1 RVA request. The guard is an explicit expansion of canonical Hook v1
and a Release B prerequisite. The broader design records the ownership and
safety constraints for versioned target knowledge, typed callable contracts,
provider interfaces, named features, explicit degradation, typed extractors,
reusable templates, strategy groups, future hook intents, and C++ vtables. A
future idea is not put in a v1 enum merely to make it visible: it receives a
complete versioned model and negative corpus when its owning release is
proposed.

This is not a revival of the historical execution grammar. Release A adds only
the locator expressions in section 13.1. Release B adds the declarative symbol
source in section 7.1 as a frontend to the same closed, content-addressed
knowledge documents and immutable toolkit values. It adds no `<<`, implicit
target, in-language loading, dynamic symbol construction, or mutation
authority. Source and JSON inputs must lower to byte-for-byte equal typed
values, canonical JSON, and IDs. Equivalent valid inputs then produce equal
post-lowering validation, resolution, and reports; source-parser diagnostics
may additionally carry source spans that never enter authority or a digest.
Neither spelling gains authority unavailable to the other.

The product boundary is:

```text
authored knowledge + semantic profile + provider interface
                         |
                         v
              pure semantic resolution
      (all candidates, evidence, ABI, feature state)
                         |
                         v
              exact reviewed lowering
       +-----------------+------------------+
       |                                    |
       v                                    v
read-only structural result      instrumentation Plan/action
(entities, Regions, evidence)    (module generation + exact RVA)
```

The semantic layer never publishes a file, writes process memory, loads a
library, installs a hook, chooses a credential, or declares success. Those
remain owned by the existing publisher and instrumentation facet.

## 2. Why these ten ideas

Impact is ranked by the amount of unsafe build-specific knowledge removed from
callers, the number of current surfaces it improves, and whether it composes
with Splice's exact-plan and evidence model.

| Rank | Historical idea | Modern disposition | Primary evidence |
|---:|---|---|---|
| 1 | Objective-C classes and methods as semantic entities | Adopt first as Mach-O structural values and exact locators | `../splice-lang/splice-spec-v3.md:329-346`, `../splice-lang/examples/03-objc-runtime.splice:3-24` |
| 2 | Target knowledge separate from transformations, including version deltas | Adopt as content-addressed knowledge packs and exact build overlays | `../splice-lang/splice-rationale.md:12-43`, `../splice-lang/splice-spec-v3.md:369-442` |
| 3 | Logical method ABI plus explicit raw-implementation access | Adopt as closed callable contracts; never infer omitted ABI facts | `../splice-lang/splice-spec-v3.md:269-292`, `../splice-lang/splice-spec-v3.md:314-346` |
| 4 | Authored provider APIs with call direction | Adopt as digest-pinned provider-interface documents | `../splice-lang/splice-spec-v3.md:1198-1226`, `../splice-lang/splice-cookbook.md:151-178` |
| 5 | Distinct intercept/replace/wrap/redirect intent | Preserve the distinctions; use modern `observe_before` for current Hook v1 and require separate schemas for the others | `../splice-lang/splice-spec-v3.md:519-571`, `../splice-lang/examples/10-feature-ordering.splice:33-42` |
| 6 | Public feature slots, selection profiles, and per-feature manifests | Adopt as immutable plan inputs and complete report projections | `../splice-lang/named-slots-exploration.md:36-130`, `../splice-lang/examples/12-kitchen-sink.splice:38-85` |
| 7 | Required, skipped, degraded, and alternative strategies | Adopt as a plan-time state lattice plus all/one/any strategy groups | `../splice-lang/splice-spec-v3.md:824-930`, `../splice-lang/splice-cookbook.md:438-468` |
| 8 | Typed captures feeding handler arguments | Adopt as provenance-carrying extractors, never as a cast from bytes | `../splice-lang/splice-cookbook.md:538-569`, `../splice-lang/byte-regex.md:214-244` |
| 9 | Reusable typed patch templates and sealed capture interfaces | Adopt as acyclic semantic templates with explicit exported fields | `../splice-lang/splice-spec-v3.md:446-487`, `../splice-lang/byte-regex.md:246-326` |
| 10 | Typed C++ vtable slots | Adopt the declaration and convention-profile shape now; gate runtime entity resolution on an ABI-specific accepted profile | `../splice-lang/splice-spec-v3.md:348-358`, `../splice-lang/examples/08-vtable-hooks.splice:8-30` |

The archive is internally inconsistent, so none of these ideas is adopted
verbatim. Examples mix `cstr` and `cstring`, reference names they did not
declare, and pair a Boolean target with a replacement whose historically
implicit return is `void`; they also promise automatic method or vtable ABI
behavior without selecting an ABI. Its byte-pattern completion
markers are also stale: on 2026-07-20, the checked-in v1 verifier passed 19 of
23 checks and the v2 verifier passed 19 of 30. Many checks merely search prose
for phrases. This proposal therefore requires executable fixtures, plan and
report assertions, output-byte or live-observation evidence, and independent
negative cases.

The strongest ideas not selected for the top ten were fixture-native tests,
call-site-only redirection, host-resolved relocation expressions, scan-only
findings, deterministic unordered groups, consuming recursion, and bit
windows. Fixture-native testing is mandatory acceptance machinery rather than
a product feature. Call-site redirection is already represented by rank 5.
The remaining ideas improve Carve or generic authoring but have less leverage
on the semantic targeting gap than the selected ten.

## 3. Current boundary and gap

Current Splice already supplies most of the safety substrate:

- every Invocation and Plan has one target and plans against an immutable
  snapshot; a batch retains per-target atomicity (`spec/splice-language-spec.md`
  section 1);
- cartridge locators return all candidates, mutation requires one contiguous
  result, and registration or result order never selects a winner
  (`spec/splice-language-spec.md` sections 8.3 and 25.1);
- a process handle and each mapped module carry non-reused generations;
- ordinary Process edits are fixed-width and may not allocate, inject, call
  target code, or configure hooks;
- instrumentation separately owns admission, library delivery, allocation,
  hook relocation, review, apply, recovery, evidence, and verification;
- Hook v1 admits only `before` entry hooks that always continue, targeted by a
  unique symbol or module-generation-bound RVA; and
- file structural edits already account for metadata, layout, relocation, and
  signature integrity through cartridges.

The missing surface is semantic target recovery. Mach-O v1 currently exposes
only scalar counts, `macho.load_command`, `macho.dylib`, add-section,
add-load-dylib, resign, and strip-signature. The implementation parses headers,
segments, sections, the ordinary symbol table, and signature presence. It does
not parse Objective-C classes, metaclasses, categories, protocols, selectors,
methods, IMPs, class references, selector references, relative method lists,
or chained-fixup provenance. Its demangled-symbol path compares the supplied
text directly with the stored native name.

There is a second implementation prerequisite: the runtime cartridge schema
currently collapses the normative typed cartridge surface into lists of names,
and the instrumentation implementation is behind its canonical specification.
Most public instrumentation commands currently return `unsupported`; no native
hook install path or pure trampoline relocator is established by the current
Rust implementation. Semantic hook success must therefore remain gated until
both prerequisites pass their own conformance gates.

### 3.1 Reuse boundary for `github.com/bryanmatteson/macho`

Splice should reuse the local `~/Code/macho` project as a decoder dependency,
not copy its parser and not adopt its report as Splice authority. At inspected
commit `7267c63dede115edbe77d50006e4ede65285a00c`, `macho-objc` already decodes
64-bit classes, categories, protocols, absolute and relative method lists,
method encodings, and chained or legacy fixups. `macho-analysis` adds thin/fat
selection, image content identity, typed Objective-C reports, stable member
references, graph edges, and observation/evidence conservation checks. Its
focused `macho-objc` and `macho-analysis` test run passes 146 tests.

The production seam is a narrow internal `MachoObjcDecoder` adapter. Releases
pin an immutable Git revision in Cargo.lock and record the vendored/source-tree
SHA-256 plus SBOM; a local path override is development-only. The adapter consumes one exact selected immutable byte view,
explicit coordinates, and Splice budgets, and returns raw typed observations
and candidates. Splice still owns cartridge schemas, target capture, file and
module coordinates, content/module-generation identity, limits, damage policy,
diagnostics, public reports, live observation, ABI interpretation, resolution,
and lowering.

The dependency is not conformant for this use until it:

- accepts Splice's bounded snapshot/reader contract for both selected files and
  mapped modules instead of requiring an unaccounted whole-file byte slice;
- distinguishes absent chained fixups from damaged fixup metadata rather than
  falling back on every parse error;
- conserves nested method, property, ivar, protocol, selector, and fixup
  failures instead of `unwrap_or_default` or sentinel strings;
- reports every method-list entry's storage, relative-offset basis, resolved
  implementation coordinate, and fixup provenance;
- proves identical relative-IMP results through its streaming and full-report
  paths; and
- exposes raw observations without making its image-local IDs or heuristic ABI
  comparison authoritative in Splice.

If this decoder is used in production, it cannot also be the independent
Objective-C conformance oracle. The oracle must use a separately implemented
parser or compiler/runtime-derived fixture truth.

For a mapped module, that immutable view is a
`ModuleSemanticSnapshot`, not a lazy `ModuleView` reader. Release A adds an
optional generic `ProcessBackend.capture_coherent_module` read capability. In
one backend-defined atomic observation it copies the complete readable mapping
set belonging to one bound module generation into an immutable sparse byte
source, or rejects. The operation may use an OS copy-on-write snapshot or an
equivalent primitive, but its contract forbids suspension, quiescence,
protection changes, target writes, loader activity, and every other target or
process-control effect. There is no double-read heuristic and no fallback to a
barrier in `splice inspect` or semantic preview.

```text
capture_coherent_module(handle, module_generation, byte_limit, region_limit)
    -> Outcome<ModuleSemanticSnapshot>

capture_coherent_module_set(handle, bindings, byte_limit, region_limit)
    -> Outcome<ModuleSemanticSnapshotSet>

ModuleSemanticSnapshotSet {
    process_generation: String
    snapshots: NonEmpty<{
        image_binding: String
        role: internal | external
        module_generation: String
        snapshot: ModuleSemanticSnapshot
    }>
    capture_epoch: String
    set_sha256: String
    provider: { id, version, implementation_sha256 }
}
```

The immutable snapshot records process/module generations, the complete
ordered mapping descriptors and bytes, capture SHA-256, provider identity, and
capture epoch. The cartridge then derives its bounded header, metadata, fixup,
string, and executable ranges from only that byte source. A missing capability,
range omission, read fault, mapping inconsistency, or budget excess rejects the
whole observation set; no partial graph is called a snapshot. File inspection
may ship while mapped-module semantic capability remains false. A native
provider may advertise coherent capture only after its effect audit proves the
target remained running and unchanged and its atomicity corpus passes.

The set operation is a separate optional capability. It captures all requested
module generations in one provider-defined atomic observation, sorts rows by
image-binding UTF-8 bytes, rejects duplicate bindings or generations, and
hashes the complete row set plus process generation, capture epoch, and
provider identity. Calling the single-module operation repeatedly is not a
coherent set. Until this capability passes its effect and atomicity corpus, a
runtime semantic request that references more than one image binding reports
`semantic_multi_image_gated`; single-image Release A inspection is unchanged.

## 4. Scope

### 4.1 Included

This proposal specifies:

1. typed semantic entity and observation values;
2. Objective-C recovery for thin and selected fat Mach-O images and mapped
   Mach-O modules;
3. canonical entity identity with observation conservation;
4. content-addressed knowledge packs and exact build overlays;
5. closed callable ABI and provider-interface documents;
6. semantic operation intent, feature selection, state, strategy, and template
   models;
7. typed extractor contracts from structural evidence;
8. read-only semantic inspection;
9. deterministic read-only projection to a Region when an exact extent exists,
   plus lowering to the expanded exact Hook v1 RVA-and-guard request;
10. report, diagnostics, limits, schemas, fixtures, and verifier obligations;
11. one `::`-scoped declarative symbol grammar covering C-like functions and
    data, Objective-C methods, raw-mangled functions, and ABI-profiled vtable
    slots, with exact lowering into knowledge documents;
12. forward-visible declaration, convention-profile, diagnostic, and verifier
    shapes for C, Swift, and vtables while their resolution runtimes remain
    explicitly gated; and
13. the implementation and acceptance order needed to avoid false support.

### 4.2 Excluded

This proposal does not:

- mutate Objective-C metadata on disk;
- create any semantic file mutation or file Plan in v1;
- claim that an on-disk method list is current runtime dispatch truth;
- add `<<`, files-as-functions, ambient targets, dynamic symbol construction,
  or a second mutation language;
- infer an ABI from a provider's exports or debug names;
- permit raw virtual addresses as durable identity;
- add arbitrary remote calls or inline host-language hook bodies;
- weaken Hook v1 to permit replacement, suppression, after hooks, arbitrary
  return control, or unwinding;
- make a multi-image or multi-action workflow atomic;
- put hook machinery on `ProcessBackend` or mutation authority on a cartridge;
- allow first-match strategy selection;
- expose hidden capture values merely because a diagnostic can see them; or
- count generated-schema, phrase-presence, or self-reported adapter success as
  implementation conformance.

## 5. Release and schema identities

The read-only recovery release extends the canonical cartridge and inspection
models; it does not create a parallel inspection report. The hook-authoring
release adds these closed canonical JSON schemas with unknown fields denied:

```text
splice.semantic.knowledge/v1
splice.semantic.abi/v1
splice.semantic.convention-profile/v1
splice.semantic.provider-interface/v1
splice.semantic.profile/v1
splice.semantic.resolution/v1
splice.semantic.report/v1
```

The corresponding toolkit values are typed and immutable. JSON is an exchange
and CLI-input representation, while section 7.1 source is an authoring
frontend; neither is the in-process source of truth.

Instrumentation remains separately versioned. A successful semantic lowering
produces a v1 `HookInstallRequest` using its RVA arm. This proposal deliberately
revises the pre-release closed Hook v1 model to require `HookApplyGuardV1`:
ordinary hooks use `none`, while current Objective-C dispatch uses the reviewed
guard defined in section 12. The revision is atomic across canonical prose,
schemas, bindings, reports, generators, and conformance; an old and revised v1
must never coexist under one schema identity. A future hook *mode* still
requires `splice.instrumentation.request/v2`; that schema is not defined or
admitted here.

Authored knowledge, ABI, provider-interface, and profile documents carry:

```text
schema
id
version
content_sha256
```

`content_sha256` is SHA-256 of RFC 8785 JSON Canonicalization Scheme bytes for
the document with that member omitted; floats are forbidden. Schema-declared
sets sort by their stable key before hashing, while ordered workflow and
strategy arrays retain declared order. A resolution instead carries
`resolution_id` and `resolution_sha256`; a report carries its existing Splice
report identity plus `semantic_evidence_sha256`. Generated evidence is not an
authored versioned document.

An embedded or reported reference contains schema, id, version, and digest.
Identity never depends on a path, modification time, registration order, or
ambient search.

Durable semantic IDs use SHA-256 over `domain || 0x00 || fields`, where every
field is encoded as an unsigned 64-bit big-endian byte length followed by its
bytes. Domains and field orders are fixed below; JSON serialization is never
an ID preimage.

## 6. Semantic entities and observations

### 6.1 Common model

```text
SemanticEntityRef {
    kind: objc_class | objc_metaclass | objc_category | objc_protocol |
          objc_method | objc_implementation | objc_selector
    entity_id: String
    scope: FileSemanticScope | ModuleSemanticScope
}

FileSemanticScope { content_sha256, selection }
ModuleSemanticScope {
    process_generation, module_generation, module_snapshot_sha256
}

SemanticEntity {
    ref: SemanticEntityRef
    scope: FileSemanticScope | ModuleSemanticScope
    semantic_key: SemanticKey
    coordinate: SemanticCoordinate, optional
    extent: Region, optional
    abi: AbiContractRef, optional
    observations: NonEmpty<SemanticObservation>
}

SemanticCoordinate =
    { kind: file_region, region: Region } |
    { kind: module_rva, module_generation: String, rva: Hex }

SemanticObservation {
    observation_id: String
    source_kind: section_pointer | absolute_record | relative_record |
                 chained_fixup | legacy_rebase | symbol | live_runtime
    source_region: Region, optional
    pointer_slot: Region, optional
    decoded_coordinate: SemanticCoordinate, optional
    fixup: StructuralValue, optional
    evidence_sha256: String
    disposition: retained
}
```

`retained` is the only Release A observation disposition. A decoder failure is
reported as a diagnostic and cannot be disguised as a dropped or rejected
observation inside an otherwise successful entity. Adding any other
disposition is a format revision with fixtures and verifier changes.

A pointer-list entry is an observation, not automatically a semantic entity.
Within one scope, runtime objects of the same runtime-record kind and proven
typed coordinate canonicalize before graph construction. Every observation remains
attached to the retained entity. Same-named objects at different addresses
remain distinct. Address equality never merges a class with its metaclass,
merges different record kinds, or crosses scopes.

Logical Objective-C methods never canonicalize by IMP. Two selectors, owners,
dispatch kinds, or category occurrences may intentionally share one
`objc_implementation`. The implementation entity, not either logical method,
canonicalizes by executable RVA inside its scope.

Entity ID domains and preimages are:

```text
splice-semantic-file-entity-v1:
  kind, content_sha256, container_index, architecture, entity discriminator
splice-semantic-module-entity-v1:
  kind, process_generation, module_generation, module_snapshot_sha256,
  entity discriminator
```

Runtime-record discriminators use a file Region or module-generation-bound RVA
plus class-versus-metaclass or record kind. Method discriminators use owner entity ID, dispatch,
selector bytes, contribution kind, category entity ID when present, and method
record location. Implementation discriminators use executable RVA. Selector
discriminators use the exact selector spelling bytes. Selector cstring, selref,
method-record, and runtime coordinates are observations of that one scoped
logical selector, not identity. Presentation formatting and observation order
are never identity.

An entity without a proven implementation RVA cannot lower to a hook. A file
entity with a unique proven extent may still project a read-only Region.

### 6.2 Objective-C kinds

```text
ObjcClassKey {
    dispatch: class | metaclass
    name: String
}

ObjcMethodKey {
    owner: SemanticEntityRef refined to objc_class | objc_metaclass |
           objc_protocol | objc_category
    dispatch: instance | class
    selector: String
    contribution: base | category
    category_name: String, optional
    category_entity: SemanticEntityRef, optional
    method_record: Region
    implementation: SemanticEntityRef refined to objc_implementation, optional
}

ObjcSelectorKey { spelling: String }
```

Within one file or module scope, all selector records with the same exact
spelling canonicalize to one `objc_selector` before graph construction. Every
record and selref remains a conserved observation. Equal spellings in different
scopes remain distinct scoped selector entities.

The Mach-O cartridge parses the admitted Objective-C metadata encodings for the
selected architecture, including absolute and relative method lists and the
fixup forms required by the active runtime profile. Each decoded pointer keeps
its storage, decoding rule, and fixup provenance.

Inspection returns every matching candidate. A query such as class name plus
selector is not identity. Duplicate class names, category contributions,
multiple executable IMPs, malformed ownership, absent selector strings,
unsupported pointer encodings, or an IMP outside an executable mapping produce
typed candidates or rejection; they never choose by list, section, category,
or registration order.

On disk or in a mapped module, a method entity describes recorded metadata.
`recorded_metadata_implementation` may lower to that recorded executable RVA
while saying nothing about effective dispatch. `current_runtime_dispatch`
requires a separate read-only `ObjCRuntimeObserver` capability. Its observation
binds the process generation, class module generation, implementation module
generation, class or metaclass runtime identity, selector identity, observed
IMP RVA, observer identity/version, and capture epoch. Static metadata never
claims post-load swizzling, runtime registration, forwarding, or cache state.

```text
ObjCRuntimeObserver {
    id() -> String
    version() -> String
    implementation_sha256() -> String
    observe_coherent(session, class_module_generation, class_entity, selector,
                     dispatch) -> ObjCRuntimeDispatchObservation
}

ObjCRuntimeDispatchStateV1 {
    observer: { id, version, implementation_sha256 }
    process_generation
    class_module_generation
    class_or_metaclass_runtime_rva
    selector
    dispatch
    implementation_module_generation
    implementation_rva
}

ObjCRuntimeDispatchObservation {
    state: ObjCRuntimeDispatchStateV1
    capture_epoch
    evidence_sha256
}

objc_runtime_dispatch_state_sha256 = H(
  "splice-objc-runtime-dispatch-state-v1",
  RFC8785(ObjCRuntimeDispatchStateV1))

objc_runtime_dispatch_observation_sha256 = H(
  "splice-objc-runtime-dispatch-observation-v1",
  RFC8785(ObjCRuntimeDispatchObservation))
```

The observer resolves the observed IMP to exactly one current executable mapped
module and returns that module generation plus its RVA. A category, swizzle, or
runtime registration may therefore move effective dispatch outside the module
that supplied the class metadata. An unmapped address or one that cannot be
attributed uniquely is rejected; it is never coerced into the class module's
coordinate space.

The observer is a genuinely read-only coherent-snapshot capability: it cannot
suspend or quiesce the process, install a hook, or declare a verdict. If the
platform cannot atomically observe the required runtime state without a target
or process-control effect, the capability is false; double-read stability is
not a substitute. Preview reports the result only as point-in-time evidence,
and any bound generation change expires it. The observer profile ID/version/
implementation digest is the same algorithm identity used by the guarded
provider operation. For mutation, the expanded Hook v1 request
binds `objc_runtime_dispatch_state_sha256` as the stable expected state in
`HookApplyGuardV1`; the owning
instrumentation supervisor re-observes and compares it inside the same retained
barrier used for hook installation. A semantic callback outside that barrier is
insufficient.

The state digest deliberately excludes `capture_epoch` and `evidence_sha256`:
fresh R0, R1, and in-barrier observations may have different provenance while
describing the same dispatch state. Every stage still retains its complete
`ObjCRuntimeDispatchObservation`, full observation digest, capture epoch, and
evidence digest in checkpoint/session/receipt/report evidence. Only the stable
state digest is compared for guard equality; provenance is never discarded or
silently reused.

### 6.3 Gated C, Swift, and vtable profiles

C-like, raw-mangled, data, vtable, and vtable-slot declarations are valid
authored knowledge shapes under section 7.1, but they do not enter
`SemanticEntityRef` or resolution v1 merely because the parser recognizes
them. Until an owning resolution profile passes its complete runtime corpus,
semantic info reports the declaration and the exact gated capability while
preview rejects an operation targeting it with `semantic_profile_gated`.

A vtable resolution profile introduces `vtable` and `vtable_slot` entities
under an explicit layout profile such as `itanium-cxx/v1`, `msvc-cxx/v1`, or
`swift-class-vtable/v1`. Each resolved slot records address point, subobject,
slot index, adjustment, destructor role, callable ABI, and all backing
observations. No layout profile means unsupported, not a generic
array-of-pointers fallback. Multiple inheritance, secondary vtables,
destructor pairs, shared tables, stripped RTTI, resilient Swift class layouts,
and runtime replacement must have invalid or ambiguous fixtures before the
owning profile advertises support.

A raw-mangled declaration binds the exact raw symbol spelling and one identity
convention profile. Demangled text is presentation evidence only. A C-like or
Swift callable additionally binds one complete `AbiContractRef`; an identity
profile never supplies or implies a calling convention. A data declaration
binds one layout convention profile. Recognition, demangling, layout, and
callable ABI remain separate claims.

## 7. Knowledge packs and exact build overlays

`splice.semantic.knowledge/v1` separates reusable facts about targets from the
operations that use them.

```text
KnowledgePack {
    schema, id, version, content_sha256
    abi_contracts: [AbiContract]
    convention_profiles: [ConventionProfile]
    images: NonEmpty<KnowledgeImage>
}

KnowledgeImage {
    binding: String
    role: internal | external
    requirements: [ExactBuildPredicateAtom]
    declarations: [EntityDeclaration]
    variants: NonEmpty<KnowledgeVariant>
}

KnowledgeVariant {
    variant_id: String
    match: ExactBuildPredicate
    extends: String, optional
    operations: [declare | expect_absent | alias | supersede]
    evidence: [FixtureEvidenceRef]
}
```

Exactly one image binding has role `internal`; any number may be `external`.
The roles describe the authored module set, not trust, linkage visibility, or
loading authority. An `internal` image is still supplied explicitly by the
caller. Every `external` image is captured and matched independently; there is
no basename search, dependency-walk adoption, dyld-order selection, or ambient
module fallback. A runtime request that references several image bindings
captures one immutable module-snapshot set before resolving any declaration.
Failure or drift of any referenced binding rejects the whole semantic
resolution without claiming multi-image mutation atomicity.

An authored image does not select its cartridge. After the caller binds the
image to an exact file or module, the Engine applies the existing deterministic
cartridge-selection rules and records the selected `CartridgeRef`. Every
declaration's `required_capability` must be advertised by that cartridge under
the active release gate. This keeps `external loader: Image { ... }` complete
without a hidden source-only default or a JSON-only cartridge override.

`ExactBuildPredicate` may constrain content SHA-256, Mach-O UUID, architecture,
platform, code-signing public identity, version, and build. A variant that
contains a raw RVA or offset requires content SHA-256 and architecture. Version
or build text alone is never sufficient for an address-bearing declaration.

Exactly one variant applies per bound image. Image requirements are inherited
by every variant. `ExactBuildPredicate` is a closed conjunction of equality,
inclusive integer-range, and SemVer-range atoms. Validation computes pairwise
satisfiability for every variant and rejects every overlap; an undecidable
matcher is not admitted. No match is `target_mismatch`. An `extends` graph is
single-parent, acyclic, and flattened before resolution. A content digest at
image scope therefore constrains every variant and cannot describe several
different builds; build-specific digests belong in their variants.

Historical `rename` is represented as `supersede`: it says that one authored
semantic role is now fulfilled by another observed entity for a named build. It
does not prove runtime identity across builds. `alias` preserves both authored
names for the same entity within one build. An overlay cannot remove a
cartridge observation or override its address; it may assert expected absence,
attach an ABI contract, add a fingerprint-bound location, or select among
reported candidates with additional verifiable predicates.

Every `EntityDeclaration` has a pack-local stable `declaration_id`, unique
before variant flattening, plus its owning image binding. An authored owner
query may reference only that pair; variant selection and observation
verification produce candidates but never turn the declaration ID itself into
runtime identity.

Knowledge is evidence, not authority to mutate. The complete pack digest,
selected variants by image binding, declarations used, and unresolved or
contradicted claims appear in the resolution and final report.

V1 accepts exactly one knowledge pack. Pack merging, search paths, and
last-writer-wins overlays are forbidden. Fixture evidence, when supplied, is
an immutable artifact reference `{sha256, length, media_type}` plus expected
target identity, never a path. An empty evidence array does not relax target
matching, declaration verification, or the exact architecture-and-content
requirements for an address-bearing effective variant.

ABI contracts and convention profiles are closed embedded documents in that
one pack. Their IDs are unique within their kind, every reference includes the
document digest, and unreferenced or cross-pack references reject. There is no
ambient ABI, demangler, mangling, or layout registry.

### 7.1 Declarative symbol source

A semantic knowledge source is a separate Splice module kind. It cannot contain
entries, phases, mutations, instrumentation operations, or tests. The explicit
header supplies the durable pack ID and version; neither is inferred from the
source path.

#### Grammar

```ebnf
semantic_knowledge_module ::= "semantic" "knowledge" string_literal
                              "version" string_literal
                              "{" { semantic_use }
                                  semantic_image_decl
                                  { semantic_image_decl } "}" ;

semantic_use          ::= "use" semantic_document_kind string_literal
                          terminator ;
semantic_document_kind ::= "abi" | "convention" ;

semantic_image_decl   ::= image_role identifier ":" "Image"
                          "{" { semantic_image_item } "}" ;
image_role            ::= "internal" | "external" ;
semantic_image_item   ::= semantic_require
                        | function_decl
                        | data_decl
                        | objc_decl
                        | vtable_decl
                        | variant_decl ;

semantic_require      ::= "require" exact_build_predicate terminator ;

exact_build_predicate ::= exact_build_clause
                          { "&&" exact_build_clause } ;
exact_build_clause    ::= exact_build_field "==" exact_build_value
                        | ".version" ">=" string_literal
                        | ".version" "<=" string_literal
                        | ".build" ">=" integer_literal
                        | ".build" "<=" integer_literal ;
exact_build_field     ::= ".content_sha256" | ".uuid" | ".arch"
                        | ".platform" | ".codesign_team_id"
                        | ".version" | ".build" ;
exact_build_value     ::= string_literal | identifier | integer_literal ;

function_decl         ::= "fn" function_signature symbol_binding_opt
                          attributes location_opt terminator ;
function_signature    ::= semantic_path "(" semantic_params_opt ")"
                          "->" semantic_type ;
semantic_params_opt   ::= [ semantic_param { "," semantic_param } [ "," ] ] ;
semantic_param        ::= ( identifier | "_" ) ":" semantic_type ;

data_decl             ::= "var" semantic_path ":" semantic_type
                          symbol_binding_opt attributes location_opt
                          terminator ;

objc_decl             ::= "objc" identifier attributes
                          "{" { objc_method_decl } "}" ;
objc_method_decl      ::= objc_dispatch objc_unary_selector "->" semantic_type
                          attributes_opt terminator
                        | objc_dispatch objc_keyword_parameter
                          { objc_keyword_parameter } "->" semantic_type
                          attributes_opt terminator ;
objc_dispatch         ::= "-" | "+" ;
objc_unary_selector   ::= identifier ;
objc_keyword_parameter ::= identifier ":" "(" semantic_type ")" identifier ;

vtable_decl           ::= "vtable" semantic_path attributes
                          "{" { vtable_slot_decl } "}" ;
vtable_slot_decl      ::= "[" integer_literal "]" function_signature
                          attributes terminator ;

symbol_binding_opt    ::= [ "for" "symbol" string_literal ] ;
location_opt          ::= [ "at" location_space integer_literal ] ;
location_space        ::= "file" | "va" | "rva" ;

attributes_opt        ::= [ attributes ] ;
attributes            ::= "[" semantic_attribute
                          { "," semantic_attribute } "]" ;
semantic_attribute    ::= "identity" string_literal
                        | "abi" string_literal
                        | "layout" string_literal ;

variant_decl          ::= "when" exact_build_predicate variant_id_opt extends_opt
                          "{" { semantic_require }
                              { variant_operation } "}" ;
variant_id_opt        ::= [ "as" string_literal ] ;
extends_opt           ::= [ "extends" string_literal ] ;
variant_operation     ::= semantic_declaration
                        | rename_decl
                        | remove_decl
                        | alias_decl ;
semantic_declaration  ::= function_decl | data_decl | objc_decl | vtable_decl ;
rename_decl           ::= "rename" local_semantic_ref "=>"
                          replacement_semantic_ref terminator
                        | "rename" raw_symbol_ref "=>"
                          raw_symbol_ref terminator ;
remove_decl           ::= "remove" local_semantic_ref terminator ;
alias_decl            ::= "alias" local_semantic_ref "=>"
                          local_semantic_ref terminator ;

semantic_ref          ::= identifier "::" local_semantic_ref ;
local_semantic_ref    ::= function_ref | data_ref | objc_ref | vtable_slot_ref ;
replacement_semantic_ref ::= function_replacement | data_ref | objc_ref
                           | vtable_slot_ref ;
function_ref          ::= function_signature ;
function_replacement  ::= function_signature symbol_binding_opt
                          attributes_opt location_opt ;
raw_symbol_ref         ::= "symbol" string_literal ;
data_ref              ::= semantic_path ;
objc_ref              ::= objc_dispatch "[" identifier objc_selector "]" ;
objc_selector         ::= identifier | identifier ":"
                          { identifier ":" } ;
vtable_slot_ref       ::= semantic_path "::" "slot" "["
                          integer_literal "]" ;

semantic_path         ::= identifier { "::" identifier } ;
semantic_type         ::= semantic_path | "*" semantic_type ;
```

The existing expression, literal, comment, terminator, and identifier lexical
rules apply. `semantic_knowledge_module` is a module alternative, not another
`top_level` item, so semantic knowledge cannot be mixed with executable source.
`internal`, `external`, `semantic`, `knowledge`, `version`, `use`, `convention`,
`fn`, `var`, `objc`, `vtable`, `when`, `as`, `extends`, `rename`, `remove`,
`alias`, `for`, `symbol`, `identity`, `abi`, `layout`, `file`, `va`, `rva`, and
`slot` are reserved in this module kind.

#### Names and image binding

`::` is the only semantic scope separator. A semantic path is therefore
`Module::Type::method`, never `Module.Type.method`. The first segment outside
an image block is always the image binding:

```splice
loader::Module::Type::method(param: Int) -> String
loader::-[IMDaemon _handleIncomingMessage:]
loader::AMInstaller::slot[10]
app::main() -> Int32
```

`.` remains property or member projection, including `.arch`,
`.content_sha256`, and existing `.macho.objc_method(...)` locator expressions.
This semantic-name rule does not rewrite current import, cartridge-member, or
locator grammar. The parser accepts trivia around `::`; the canonical printer
emits none. A dot inside a semantic path is `source_invalid` and may offer an
exact `.` to `::` correction only when reparsing proves one unambiguous result.

Inside one image block, every declaration and variant operation is local to
the enclosing binding; the grammar provides no image-qualification form there.
Outside an image block every reference is image-qualified, so there is no
ambient image. A raw symbol is always a string literal: an unquoted Swift
`$s...` spelling is invalid source. Function references include parameter
labels, parameter types, and the explicit return type; overload resolution
never guesses an omitted type. The zero-parameter spelling is exactly
`Module::Type::method()` before its required return type.

#### Requirements, variants, locations, and attributes

`semantic_require` reuses expression syntax but admits only the closed
`ExactBuildPredicate` atoms over `.content_sha256`, `.uuid`, `.arch`,
`.platform`, `.codesign_team_id`, `.version`, and `.build`. The digest value is
the canonical quoted `sha256:` plus 64 lowercase hexadecimal digits. A digest
is never an integer literal: integer parsing would discard width and leading
zeroes. Arbitrary property access, calls, arithmetic, target reads, and
non-closed Boolean expressions reject before any target access.

An inclusive version or integer-build range is written as one conjunction with
exactly one `>=` lower bound and one `<=` upper bound for the same field. A
one-sided, repeated, reversed, mixed-field, or equality-plus-range constraint
rejects; the compiler normalizes the admitted pair to one range atom. No other
field admits ordering comparisons.

Image-level requirements are common to every variant. A module-local `when`
introduces one closed `ExactBuildPredicate` and lowers to one
`KnowledgeVariant`; its header expression and any contained `require` clauses
are conjoined. It is not the executable language's general condition form. For
the common exact matcher `when .version == "VALUE"`, omission of `as` gives the
variant ID `VALUE`. Every other matcher must supply `as "STABLE_ID"`. Variant
IDs are unique per image. Each variant has at most one explicit parent.
Declarations in the image body form the common declaration set; declarations
inside a `when` are `declare`. `extends` inherits the parent's flattened
declaration state and operations, never its match predicate or fixture
evidence; every variant must match a target independently beneath the common
image requirements. The parent graph is acyclic, but several independent
parentless variants are valid. `rename` lowers to `supersede` and retains the
original
`declaration_id`, and replaces all presentation, raw-symbol, convention, ABI,
and location fields written on its right-hand side as one atomic authored fact.
A semantic rename of a raw-mangled function must carry its replacement raw
symbol when the semantic path changes. The explicit
`rename symbol "OLD" => symbol "NEW"` form instead resolves exactly one
raw-mangled declaration in the flattened parent, changes only its raw symbol,
and retains its presentation, identity profile, callable ABI, and location.
Zero or several matches reject. `remove` lowers to `expect_absent`. The
`alias OLD => CURRENT` form keeps OLD as an additional authored name for
CURRENT inside that exact variant. None of these operations deletes or
rewrites a cartridge observation.

An image with no written `when` block receives one synthetic variant whose ID
is `baseline`, whose matcher is its image requirements, and whose operation
list is empty. The ID `baseline` is reserved, and an image with any written
`when` receives no synthetic variant. With written variants, failure to match
exactly one is `target_mismatch` or `target_ambiguous` as applicable.

The only location forms are `at file`, `at va`, and `at rva`. Bare `at NUMBER`
and `at symbol` are invalid; `for symbol "..."` is the one raw-symbol binding.
Every address-bearing effective variant must contain `.arch` and
`.content_sha256` equality either locally or through inherited image
requirements. `va` describes a file-image virtual coordinate and must map
uniquely to a file Region/RVA during verification; it is never retained as a
live absolute process address.

Attributes are unordered in source and canonicalized by kind. Duplicate or
unknown attributes reject. Every callable has one `abi` attribute, directly or
as the explicit default on its enclosing `objc` block. A raw-mangled callable
also has one `identity` attribute. Every data declaration and vtable has one
`layout` attribute. Every vtable slot has one callable `abi` attribute; its
vtable's layout profile never supplies a calling convention. An attribute
string names exactly one document loaded by a matching `use abi` or
`use convention`; absent, duplicate, wrong-kind, wrong-architecture,
wrong-family, unreferenced, and digest-mismatched documents reject. The source
path is capture provenance only. The compiled pack embeds the complete
documents and their digests.

A function without `identity` requires a `c` ABI and lowers to
`semantic_c_symbol_v1`. A function with `identity "swift-mangling/v1"`
requires a `swift_call` ABI and lowers to `semantic_swift_symbol_v1`;
neither the `$s` prefix nor a demangled path selects that family. An Objective-C
block default and every override use `objc_method`. An Itanium/MSVC vtable slot
uses `cxx_method`; a Swift class-vtable slot uses `swift_call`. A data
declaration uses `c_data_layout` and lowers to `semantic_c_data_v1`. Every
other family combination rejects.

#### Lowered model

The source compiler expands container syntax into this closed declaration
model:

```text
EntityDeclaration =
  { kind: function, declaration_id, image_binding,
    path: NonEmpty<String>, parameters: [SemanticParameter],
    return: SemanticType, raw_symbol: String?,
    identity_profile: ConventionProfileRef?, abi: AbiContractRef,
    location: AuthoredLocation?,
    required_capability: SemanticDeclarationCapability } |
  { kind: data, declaration_id, image_binding,
    path: NonEmpty<String>, type: SemanticType,
    raw_symbol: String?, layout_profile: ConventionProfileRef,
    location: AuthoredLocation?,
    required_capability: SemanticDeclarationCapability } |
  { kind: objc_class, declaration_id, image_binding, name: String,
    required_capability: semantic_objc_v1 } |
  { kind: objc_method, declaration_id, image_binding, owner_declaration_id,
    selector: String, dispatch: instance | class,
    parameters: [SemanticParameter], return: SemanticType,
    abi: AbiContractRef, required_capability: semantic_objc_v1 } |
  { kind: vtable, declaration_id, image_binding,
    path: NonEmpty<String>, layout_profile: ConventionProfileRef,
    required_capability: SemanticDeclarationCapability } |
  { kind: vtable_slot, declaration_id, image_binding,
    vtable_declaration_id, slot_index: Int, path: NonEmpty<String>,
    parameters: [SemanticParameter], return: SemanticType,
    abi: AbiContractRef,
    required_capability: SemanticDeclarationCapability }

SemanticDeclarationCapability =
    semantic_c_symbol_v1 | semantic_c_data_v1 | semantic_swift_symbol_v1 |
    semantic_objc_v1 |
    semantic_itanium_vtable_v1 | semantic_msvc_vtable_v1 |
    semantic_swift_vtable_v1

AuthoredLocation =
  { kind: file | va | rva, value: UInt64,
    content_sha256: String, architecture: Arch }

ConventionProfile {
    schema, id, version, content_sha256
    kind: identity | layout
    family: swift_mangling | c_data_layout | swift_class_vtable |
            itanium_cxx_vtable | msvc_cxx_vtable
    architectures: NonEmpty<Arch>
    specification: { sha256, length, media_type }
}
```

`SemanticType` is a closed nominal path plus pointer construction in source v1;
two equal-width nominal types do not become interchangeable. Objective-C
container syntax emits one class declaration plus one declaration per method.
Vtable syntax emits one table declaration plus one declaration per explicit
slot; omitted indexes are unknown, not inferred gaps or removals. Declaration
IDs use:

```text
declaration_id = H(
  "splice-semantic-declaration-v1",
  knowledge_pack_id,
  image_binding,
  canonical root declaration reference)
```

The root reference uses `::`, explicit parameter and return types, raw-symbol
binding when present, and the exact ABI and convention-profile refs. Raw
mangled spelling plus the selected identity convention and callable ABI is
therefore part of authored identity, not presentation metadata. A variant
`rename` retains that ID. A newly declared variant entity receives an ID from
its own canonical declaration.
Duplicate IDs, paths, overload signatures, Objective-C selectors in one owner
and dispatch, or vtable slot indexes reject before variant flattening.

JSON knowledge and compiled source converge before semantic validation: source
spans and paths are parser-diagnostic provenance and are absent from the
canonical `KnowledgePack`. After lowering, both inputs run the same validator,
canonical sorts, RFC 8785 hashing, resolver, reports, and conformance cases. A
source-only default, hidden declaration, different post-lowering diagnostic,
or different digest is a conformance failure.

#### Complete example

The consolidated spelling is therefore:

```splice
semantic knowledge "com.example.application" version "1" {
    use abi "abi/swift-call-arm64.json"
    use abi "abi/objc-method-arm64.json"
    use abi "abi/c-arm64-darwin.json"
    use convention "conventions/swift-mangling.json"
    use convention "conventions/swift-class-vtable.json"

    external loader: Image {
        require .arch == arm64

        fn Module::Type::method(param: Int) -> String
            for symbol "$s6Module4TypeC6method5paramSSSiF"
            [identity "swift-mangling/v1", abi "swift-call/arm64/v1"]

        objc IMDaemon [abi "objc-method/arm64/v1"] {
            -_handleIncomingMessage:(id)msg -> void
        }

        vtable AMInstaller [layout "swift-class-vtable/v1"] {
            [0] destroy() -> void [abi "swift-call/arm64/v1"]
            [10] resize(size: u64) -> void [abi "swift-call/arm64/v1"]
        }

        when .version == "1.1" {
            require .content_sha256 ==
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        }

        when .version == "1.2" extends "1.1" {
            require .content_sha256 ==
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

            rename Module::Type::method(param: Int) -> String
                => Module::Type::method(newParam: Int) -> String
                    for symbol "$s6Module4TypeC6method8newParamSSSiF"
        }

        when .version == "1.3" {
            require .content_sha256 ==
                "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"

            remove Module::Type::method(param: Int) -> String
        }
    }

    internal app: Image {
        require .arch == arm64
        require .content_sha256 ==
            "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"

        fn main() -> Int32 [abi "c/arm64-darwin/v1"]

        objc AppDelegate [abi "objc-method/arm64/v1"] {
            -applicationDidFinishLaunching:(id)notification -> void
            +sharedDelegate -> id
        }
    }
}
```

When only the raw native identity changes and the stable semantic presentation
should not, the corresponding delta is deliberately smaller:

```splice
when .version == "1.2" {
    rename symbol "$s6Module4TypeC6method5paramSSSiF"
        => symbol "$s6Module4TypeC6method8newParamSSSiF"
}
```

## 8. Callable ABI and provider interfaces

### 8.1 ABI contracts

```text
AbiContract {
    schema, id, version, content_sha256
    family: c | objc_method | raw_imp | cxx_method | swift_call
    architecture: Arch
    calling_convention: String
    return: AbiType
    return_passing: AbiPassing
    parameters: [AbiParameter]
    implicit_parameters: [self | selector | swift_context |
                          swift_error_result]
    variadic: Bool
    ownership: [AbiOwnership]
    exception_policy: forbidden | profile_defined
    mitigation_profile: String
    stack_alignment_bytes: UInt64
    red_zone_bytes: UInt64
}

AbiType =
    { kind: void } |
    { kind: integer, bits: UInt64, signed: Bool } |
    { kind: floating,
      format: binary16 | bfloat16 | binary32 | binary64 | x87_80 |
              binary128 } |
    { kind: pointer,
      pointee: data | function | block | opaque,
      address_space: UInt64, nullable: Bool } |
    { kind: aggregate,
      size_bytes: UInt64, alignment_bytes: UInt64,
      layout_sha256: String, trivial: Bool } |
    { kind: vector, lanes: UInt64, element: AbiScalarType,
      alignment_bytes: UInt64 } |
    { kind: opaque,
      identity: String, size_bytes: UInt64, alignment_bytes: UInt64 }

AbiScalarType =
    { kind: integer, bits: UInt64, signed: Bool } |
    { kind: floating,
      format: binary16 | bfloat16 | binary32 | binary64 | x87_80 |
              binary128 }

AbiPassing =
    { kind: ignored } |
    { kind: direct, register_classes: NonEmpty<String>,
      extension: none | sign | zero } |
    { kind: indirect, alignment_bytes: UInt64,
      by_value: Bool }

AbiParameter {
    role: explicit | self | selector | this
    type: AbiType
    passing: AbiPassing
}

AbiOwnership {
    target: { kind: return } | { kind: parameter, index: UInt64 }
    convention: unmanaged | borrowed | consumed | retained | autoreleased
}
```

Bit widths, vector lane counts, direct register-class lists, indirect
alignments, stack alignment, and aggregate/opaque alignments are positive.
Every alignment is a power of two. Aggregate and opaque sizes may be zero only
for a target ABI that explicitly represents a zero-sized value; `void` is the
only type accepted with `ignored` passing. A non-void return or parameter may
not use `ignored`. Ownership targets are unique, in return-then-parameter-index
order, in range, and name pointer-typed values only. Register-class strings,
opaque identities, calling conventions, and mitigation profiles are bounded
nonempty exact identifiers; they select no ambient registry.

`c`, `raw_imp`, and `cxx_method` contracts have no implicit parameters.
`objc_method` has exactly `[self, selector]`. A `swift_call` contract may use
`swift_context`, `swift_error_result`, or both, in that order. A C++ `this` and
the explicit `self` and selector of a `raw_imp` are ordinary leading
`AbiParameter` rows with those exact roles; every other row has role `explicit`.
`c`, `objc_method`, and `swift_call` accept only `explicit` rows, `raw_imp`
requires leading `[self, selector]`, and `cxx_method` requires leading `[this]`.
No hidden parameter is inferred. `return_passing` and each
parameter passing mode record the complete ABI classification. The exact
calling-convention and mitigation-profile strings plus architecture interpret
register-class names and pointer-authentication rules; unknown profiles are
unsupported, never approximated.

Logical Objective-C methods omit `self` and `_cmd` from the authored explicit
parameter list, but the resolved ABI contains them. A `raw_imp` contract exposes
them explicitly. Logical and raw contracts are never interchangeable by arity.
Structure return, floating return, register classification, variadics, blocks,
ownership conventions, pointer authentication, stack alignment, red zones, and
exception behavior are explicit admitted facts or unsupported.

`cxx_method` and `swift_call` are forward-visible authoring families. Release B
validates and hashes them but reports their target resolution capabilities as
gated. `this` is an explicit callable-ABI parameter; vtable address points,
subobjects, slot adjustments, destructor roles, and Swift resilient-layout
facts belong to the selected convention profile and resolved vtable evidence,
not to the calling convention. No identity or layout profile fills an omitted
callable-ABI field.

A method encoding from metadata is an observation. It may confirm or contradict
an authored ABI, but an incomplete encoding does not invent ownership,
nullability, aggregate layout, or calling convention. Contradiction rejects
before planning.

### 8.2 Provider interfaces

```text
ProviderInterface {
    schema, id, version, content_sha256
    artifact: { sha256, length, media_type, abi }
    architecture: Arch
    capture_interfaces: [CaptureInterface]
    exports: NonEmpty<ProviderExport>
}

ProviderExport {
    public_name: String
    native_symbol: String
    direction: target_calls_provider
    role: hook_handler_v1
    handler_abi: splice-hook-handler/v1
    capture_interface: CaptureInterfaceRef, optional
}

CaptureInterface {
    interface_id: String
    content_sha256: String
    fields: NonEmpty<DecoderField>
}

DecoderField {
    name: String
    type: AbiType
    source: register | bounded_memory
    address_space: target_process | immediate
    lifetime: entry_snapshot | copied_payload
    max_bytes: Int, optional
}
```

`CaptureInterface.content_sha256` is SHA-256 of RFC 8785 canonical JSON for
`{ interface_id, fields }`; it uses the document-content rule above even though
the interface is embedded rather than independently versioned.

The provider-interface document contains the existing immutable
instrumentation artifact descriptor; the caller separately supplies one
captured `ByteSource` whose length and digest must equal it before target
access. A source path is capture provenance, never identity. There is no path
search and no ABI-inferred export fallback. The selected export must resolve
uniquely in that exact artifact.
For v1 its ABI is exactly `splice-hook-handler/v1`, because the trampoline calls
it with `HookContextV1`; it is never compared for equality with the target
method ABI. Presentation aliases do not change the native symbol or digest.

An export with capture bindings must reference exactly one capture interface in
the same provider-interface document. Field names are unique. Every binding's
`decoder_field`, extractor output type, destination source class, address space,
lifetime, and bound must equal that field; unused, duplicate, or multiply bound
fields reject unless the field explicitly declares optionality in a future
schema. The capture-interface digest is bound into R0, R1, Hook request review,
decoder configuration, and semantic evidence; the `LoweringSummary` binds that
semantic review to the exact Hook request capture and register masks without
adding decoder field names to the instrumentation request. An export with no
capture bindings may omit the reference.

The target ABI is separate evidence used only to validate capture/register
bindings and decoding. Every compatibility adapter is a separately versioned,
digest-pinned built-in with an exact input and output ABI; v1 defines no
adapter from an Objective-C method signature to a handler call.

`provider_calls_target` is not admitted by the v1 schema. Runtime callback
support requires a later instrumentation request schema and does not emerge
from a capability string.

## 9. Semantic operation intent

```text
AuthoredOwnerQuery =
    { kind: class_name, name: String } |
    { kind: declaration, declaration_id: String }

AuthoredEntityQuery = {
    kind: objc_method
    image_binding: String
    owner: AuthoredOwnerQuery
    selector: String
    dispatch: instance | class
    contribution: base | any_category | named_category
    category: String, optional
}

CaptureBinding {
    source: self | selector | { parameter_index: Int }
    extractor: ExtractorRef | TemplateParameterRef refined to extractor
    destination: { register: String, decoder_field: String } |
                 { bounded_memory: CaptureSpec, decoder_field: String }
}

ResolvedCaptureBinding {
    source: self | selector | { parameter_index: Int }
    extractor: { ref: ExtractorRef, implementation_sha256: String }
    decoder_field: String
    lowered_capture: { register: String } | { bounded_memory: CaptureSpec }
    capture_interface_sha256: String
    evidence_sha256: String
}

OperationMissingPolicy =
    { kind: fail } |
    { kind: skip } |
    { kind: degrade, outcome: ReducedEffectOutcomeRef }

AuthoredSemanticOperation {
    local_operation_id: String
    intent: observe_before
    target: AuthoredEntityQuery |
            TemplateParameterRef refined to entity_query
    dispatch_authority: recorded_metadata_implementation |
                        current_runtime_dispatch
    shared_implementation: reject | admit_implementation_wide
    handler: ProviderExportRef |
             TemplateParameterRef refined to provider_export
    target_abi: AbiContractRef |
                TemplateParameterRef refined to abi_contract, optional
    capture_bindings: [CaptureBinding]
    missing: OperationMissingPolicy
}

OperationScope {
    process_generation: String
    semantic_source_image_binding: String
    semantic_source_module_generation: String
    semantic_source_snapshot_sha256: String
}

ResolvedSemanticOperation {
    resolved_operation_sha256: String
    expanded_identity: ExpandedOperationIdentity
    expanded_operation_graph_sha256: String
    authored_operation_sha256: String
    scope: OperationScope
    logical_method: SemanticEntityRef refined to objc_method
    implementation: SemanticEntityRef refined to objc_implementation
    executable_module_generation: String
    executable_module_snapshot_sha256: String
    dispatch_authority: recorded_metadata_implementation |
                        current_runtime_dispatch
    known_aliases: [SemanticEntityRef refined to objc_method]
    target_abi: AbiContractRef, optional
    provider_export: ProviderExportRef
    capture_interface: CaptureInterfaceRef, optional
    capture_bindings: [ResolvedCaptureBinding]
    apply_guard: HookApplyGuardV1
    evidence_sha256: String
}
```

`AuthoredSemanticOperation` is reusable, target-free, and content-addressed;
it never contains a process/module generation, snapshot digest, entity ID, RVA,
or apply guard. `ResolvedSemanticOperation` exists only after target capture and
exact resolution. `OperationScope` is exactly one bound process generation, semantic-source
module generation, and immutable module-snapshot digest. Resolution separately binds exactly one executable
implementation module generation; for recorded metadata these commonly match,
while current runtime dispatch may resolve into a category or swizzle image.
Each operation still produces one lowering against one executable module.
Multi-hook workflows use multiple operations and separate lowerings.

An authored owner is either a presentation class name within the named image
binding or a stable declaration ID paired with that binding from the one
knowledge pack. A declaration ref contributes only authored predicates and is
still verified against target observations; it is not a runtime entity ID.
`category` is present exactly for `named_category`. Authored queries never
contain the inspection-only `entity_id` or `member_id`; if the authored
predicates do not prove exactly one logical method, hook resolution rejects
with every candidate. V1 capture bindings are either any number of register
destinations lowered to one sorted `CaptureSpec::Registers`, or one
bounded-memory destination lowered to one bounded-memory `CaptureSpec`; mixed
or multiple bounded-memory bindings reject. Writable registers are never
derived from a read-only semantic capture.

Hook v1 patches an implementation entry, not Objective-C dispatch metadata. If
several logical methods resolve to the same implementation, `reject` fails with
all known alias method IDs. `admit_implementation_wide` states the real effect:
every invocation that reaches that executable entry is instrumented, including
direct calls and aliases not discoverable from the selected module's metadata.
R0, review, and report bind the complete alias set observed in the selected
semantic graph, label it `known_aliases` rather than globally exhaustive, and
warn about implementation-wide scope. Drift in that observed set before R1
rejects. The handler may inspect captured `_cmd`, but that does not make the
entry patch selector-specific.

The historical intents remain distinct design constraints:

| Intent | Target changes | Original callable | v1 disposition |
|---|---|---|---|
| `observe_before` | entry trampoline invokes HookContext handler, then continues | not exposed | semantic v1; active only when Hook v1 is conformant |
| `intercept` | handler controls whether/how original is invoked | explicit typed handle | requires complete instrumentation request/v2 proposal |
| `replace` | original body is suppressed | absent | requires complete instrumentation request/v2 proposal |
| `wrap` | standardized pre/post handler surrounds one original call | automatic exactly once | requires complete instrumentation request/v2 proposal |
| `redirect_calls` | selected direct call sites change; callee stays intact | not applicable | requires complete call-site rewrite proposal |

The v1 schema admits only `observe_before`; every other spelling is an unknown
enum value and rejects before target access. It never silently lowers to
`observe_before`. A later request/v2 must define handler and original-call ABI,
result/control authority, reentrancy, unwinding, recovery, retirement,
capabilities, reports, and its complete invalid matrix before any of these
names becomes public input.

Any future `redirect_calls` declares a finite scope; it never means “global.”
Direct PC-relative calls, stubs, import indirection, relocation-backed calls,
indirect calls, veneers, range extension, and architecture mitigations require
distinct admitted classes.

`CaptureBinding` maps a logical target value (`self`, `selector`, or explicit
parameter index) through one typed extractor to the current instrumentation
register mask, `CaptureSpec`, and decoder input. It never changes the handler
ABI. A missing `target_abi` is allowed only when `capture_bindings` is empty.

## 10. Features, selection, missing policy, and strategies

### 10.1 Feature model

```text
SemanticFeature {
    feature_id: String
    public: Bool
    doc: String
    default: enabled | disabled
    requires_features: [String]
    operations: NonEmpty<AuthoredSemanticOperation | StrategyGroup |
                         TemplateInvocation>
}

FeatureSelection {
    profile_id: String, optional
    enable: [String]
    disable: [String]
}

SemanticProfile {
    schema, id, version, content_sha256
    instrumentation_profile: { schema, sha256 }
    features: NonEmpty<SemanticFeature>
    reduced_outcomes: [ReducedEffectOutcome]
    templates: [SemanticTemplate]
    extractors: [Extractor]
    selection: FeatureSelection
    caller_overrides: locked | enable_only | enable_disable
}

ReducedEffectOutcome {
    outcome_id: String
    feature_id: String
    reason: String
    omitted_operations: NonEmpty<ExpandedOperationIdentity>
    retained_operations: [ExpandedOperationIdentity]
}

ReducedEffectOutcomeRef { feature_id: String, outcome_id: String }

FeatureResolutionOutcome {
    feature_id: String
    state: disabled | ready | skipped | degraded | failed
    reason: String, optional
    dependencies: [FeatureDependencyOutcome]
    operations: [ExpandedOperationIdentity]
    strategy_groups: [StrategyGroupResolutionOutcome]
    effective_reduced_outcome: ReducedEffectOutcomeRef, optional
    evidence_sha256: String
}

OperationEffectOutcome {
    expanded_identity: ExpandedOperationIdentity
    state: not_attempted | no_change | applied | rolled_back | partial |
           target_gone
    terminal_cause: none | rejected | rolled_back | crash_uncertain |
                    target_gone
    action_id: String, optional
}

FeatureEffectOutcome {
    feature_id: String
    state: not_attempted | no_change | applied | rolled_back | partial |
           target_gone
    terminal_cause: none | rejected | rolled_back | crash_uncertain |
                    target_gone
    operations: [OperationEffectOutcome]
}
```

Selection is canonicalized, included in the semantic resolution digest, shown
at review, and bound by semantic checkpoint records to the exact downstream
request, Plan, action, and report digests. Closed instrumentation artifacts gain
no feature-selection fields. The dependency
closure is computed before effects. Explicitly disabling a required dependency
rejects; it does not degrade the dependent feature. Private features may be
omitted from ordinary discovery presentation but never from plans, evidence,
history, rollback, or reports.

Named profiles are immutable named `FeatureSelection` values within
`splice.semantic.profile/v1`. `enable` and `disable` are disjoint. Unknown or
duplicate names reject. A caller override is either allowed by the profile and
digest-bound or rejected; there is no last-writer-wins merge.

Selection starts from each feature's declared default, applies the profile's
disjoint enable/disable sets, then applies caller sets only as allowed by
`caller_overrides`. A name appearing in both caller sets rejects. Profile and
caller selections never merge by order. Feature IDs are unique and sort by
UTF-8 bytes for hashing/reporting; operations retain declared order solely as
workflow order and never as candidate or strategy priority.

### 10.2 Missing policy

Missing policy is evaluated during resolution:

- `fail` discovered in initial resolution makes the feature `failed` and
  prevents the first effect. A failure discovered at a later hash-chained
  checkpoint stops remaining actions and reports already completed effects;
- `skip` records an explicit skipped operation without a warning and may leave
  the feature `ready` if its remaining obligations hold; and
- `degrade` requires a profile-local `ReducedEffectOutcomeRef`. The referenced
  outcome lists the omitted and retained expanded operation identities, those
  identities must belong to
  the same feature and be disjoint, and every selected feature operation must
  appear in exactly one list. The report preserves the declared stable reason,
  missing fact, capability, entity candidates, and affected dependents.

All active operation, strategy, and effective-fallback degradations in one
feature must reference the same `ReducedEffectOutcomeRef`; distinct refs are a
`semantic_feature_conflict` before effects. Every missing standalone operation
that triggered degradation, and every operation nested under a triggering
missing strategy, must occur in the effective outcome's
`omitted_operations` and must not occur in `retained_operations`.
Fallback-inherited degradation is subject to the same rule. The one effective
ref is recorded in `FeatureResolutionOutcome`; evaluation order cannot compose
or override outcomes.

Degradation never bypasses identity, ambiguity, cardinality, ABI, preimage,
integrity, review, barrier, signing, recovery, or verifier requirements.

### 10.3 Strategy groups

```text
StrategyGroup {
    group_id: String
    cardinality: all | exactly_one | any
    strategies: NonEmpty<SemanticStrategy>
}

SemanticStrategy {
    strategy_id: String
    availability: AuthoredEntityQuery | CapabilityPredicate
    missing: StrategyMissingPolicy
    operations: NonEmpty<AuthoredSemanticOperation | TemplateInvocation>
}

CapabilityPredicate {
    capability: String
}

StrategyMissingPolicy =
    { kind: fail } |
    { kind: skip } |
    { kind: degrade, outcome: ReducedEffectOutcomeRef } |
    { kind: fallback, strategy: StrategyRef }

StrategyRef { group_id: String, strategy_id: String }

StrategyResolutionOutcome {
    strategy_id: String
    state: ready | skipped | degraded | failed
    effective_strategy_id: String, optional
    reduced_outcome: ReducedEffectOutcomeRef, optional
    operations: [ExpandedOperationIdentity]
    evidence_sha256: String
}

StrategyGroupResolutionOutcome {
    group_id: String
    state: ready | skipped | degraded | failed
    strategies: NonEmpty<StrategyResolutionOutcome>
    effective_strategy_ids: [String]
    evidence_sha256: String
}
```

Resolution-outcome arrays are canonical evidence, not workflow order:
dependencies sort by required feature ID, `operations` by canonical expanded
identity, strategy-group outcomes by `group_id`, strategy outcomes by
`strategy_id`, and effective strategy IDs by UTF-8 bytes. These rules make the
`feature_resolution_sha256` preimage unique without changing the declared
operation order used later for effects.

Feature-effect rows sort by `feature_id`; their operation rows sort by canonical
expanded identity. `action_id` is present exactly when instrumentation assigned
an owning action to that operation; it is absent only for a never-planned
`not_attempted` row. The feature state and cause are the monotone aggregation of
these operation rows under the report precedence in section 15, never a second
verdict source.

Every strategy is evaluated against the same immutable observation set. For
`exactly_one`, exactly one obligation must resolve ready, through a ready
fallback, or to a declared degraded outcome; zero or multiple reject. `all`
requires every obligation to be ready or discharged by its explicit non-fail
missing policy. `any` admits zero or more only when each absent member has an
explicit non-fail missing policy. A fallback reference is confined to its own group; fallback
edges are validated as an acyclic graph before target access. A ready fallback
satisfies the unavailable strategy's obligation, but its operation set and
cardinality contribution are counted once by strategy ID. An unavailable or
failed fallback fails the referring strategy. Degrade references the same
profile-local reduced-outcome registry and never adds operations. No strategy
is applied until group cardinality and the union of
conflicts visible during semantic resolution are validated. Final displaced-
byte, allocation, trampoline, and instruction-pointer conflicts belong to the
owning instrumentation Plan. Source, registration, declaration, and candidate
order never pick a winner.

Aggregation is fixed. A fallback outcome inherits the referenced strategy's
state and records `effective_strategy_id`; a declared strategy degradation is
`degraded` even when it admits no operation. A group is `failed` when
cardinality fails or any required member/fallback fails, `degraded` when no
failure exists and any member or effective fallback is degraded, `skipped`
when no failure/degradation exists and it admits no operation, and otherwise
`ready`. A disabled feature is `disabled`; any failed dependency, operation,
strategy, or group makes it `failed`; otherwise any degraded operation,
strategy, or group makes it `degraded`; a selected feature with no admitted
operation is `skipped`; otherwise it is `ready`. Skipped operations and
strategy outcomes inside a ready feature remain listed. Effect state is
computed only from owning action receipts and never overwrites resolution
state. For one feature, target loss before any effect is `target_gone`; target
loss after a durable or uncertain effect is `partial` with
`terminal_cause: target_gone`, matching the report-level precedence.

## 11. Typed extractors and reusable templates

### 11.1 Extractors

```text
Extractor {
    extractor_id: String
    input: EntityRef | Region | StructuralValue
    output: AbiType
    rule: BuiltinExtractorRef
    provenance: {
        width, endian, coordinate, address_space, lifetime, validation
    }
}

BuiltinExtractorRef {
    builtin_id: String
    version: String
    implementation_sha256: String
    capture_schema_sha256: String
}

ExtractorRef {
    extractor_id: String
    implementation_sha256: String
    capture_schema_sha256: String
}
```

Extractors bridge structural facts to HookContext capture and decoder inputs.
A Carve capture or
Objective-C metadata field may feed a handler only through a registered,
versioned built-in extractor whose result type, address space, width, endian,
lifetime, and validation rule match the target ABI value and the destination
decoder-field schema. The fixed HookContext handler ABI is unchanged. A type
label on arbitrary bytes is not an extractor and never becomes an ABI
guarantee.

V1 extractors are pure and plan-time only: they compile structural provenance
and ABI classification into the existing instrumentation register mask,
`CaptureSpec`, and decoder-field mapping. Runtime register or bounded-memory
capture is performed only by that existing instrumentation mechanism. This
facet adds no resident evaluator or remote-call ABI. An unsupported live
capture class is gated. Extractor inputs and output evidence appear in the
review and session artifact subject to the capture policy.

### 11.2 Sealed capture interfaces

A reusable pattern or extractor library exports an explicit field schema, an
implementation SHA-256, and a capture-schema SHA-256. A handler export's
decoder fields are owned by the digest-pinned `CaptureInterface` above; an
extractor template may only expose fields compatible with that interface.
Internal captures remain
available to its own matcher
and diagnostics but cannot be referenced by importers. Refactoring hidden
captures without changing exported names/types leaves the public interface
fingerprint unchanged, but the implementation digest still changes and is
bound into every resolution. Changing an exported field is a new schema
version.

### 11.3 Templates

```text
SemanticTemplate {
    template_id: String
    parameters: NonEmpty<TemplateParameter>
    body: NonEmpty<AuthoredSemanticOperation | TemplateInvocation>
}

TemplateParameter {
    name: String
    kind: entity_query | abi_contract | provider_export | extractor
}

TemplateParameterRef {
    parameter: String
    kind: entity_query | abi_contract | provider_export | extractor
}

TemplateArgumentValue = AuthoredEntityQuery | AbiContractRef |
    ProviderExportRef | ExtractorRef

TemplateInvocation {
    invocation_id: String
    template_id: String
    arguments: NonEmpty<{ parameter: String, value: TemplateArgumentValue }>
}

ExpandedOperationIdentity {
    feature_id: String
    group_id: String, optional
    strategy_id: String, optional
    invocation_path: [String]
    local_operation_id: String
}
```

Parameter kinds are the four v1 substitution sites shown in section 9: entity
query, ABI contract, provider export, and sealed extractor reference. Each
`TemplateParameterRef.kind` must equal its declaration and the field's stated
refinement. There is no untyped scalar or region parameter in v1. Feature and
strategy bodies may invoke templates, but a template body produces operations
only; it cannot expand to a `StrategyGroup` and therefore cannot change the
enclosing body's shape. Arguments are keyed uniquely by parameter name, must
cover every parameter exactly once, and must match its declared kind. Nested
invocation is allowed only through this model. Static template expansion fixes
the authored operation graph before target access and is pure, acyclic, depth-
and expansion-bounded. It substitutes every parameter and leaves no
`TemplateParameterRef` or `TemplateInvocation` in the expanded graph. After
one immutable referenced-image snapshot or coherent module-snapshot set,
semantic binding resolves the already-concrete entity queries and extractors
without adding operations or changing control flow.
Arity, kind, field-refinement, ABI, capture-schema, cycle,
and resource-limit failures reject. Every expanded operation receives the
structural identity above: direct operations use an empty invocation path;
nested templates append each invocation ID. The complete tuple must be unique
after expansion; source or registration order never repairs a collision.
Every complete `TemplateInvocationIdentity` must also be unique before graph
hashing, even when duplicate invocation paths would expand templates with
disjoint local operation IDs. A duplicate invocation identity rejects; template
ID, argument digest, row order, and operation-ID disjointness never break the
tie.

Template definitions and invocations have these exact derived digests:

```text
template_definition_sha256 = H(
  "splice-semantic-template-definition-v1",
  profile.content_sha256,
  template_id,
  RFC8785(parameters),
  RFC8785(body))

TemplateInvocationIdentity {
    feature_id: String
    group_id: String, optional
    strategy_id: String, optional
    invocation_path: NonEmpty<String>
}

template_arguments_sha256 = H(
  "splice-semantic-template-arguments-v1",
  canonical TemplateInvocationIdentity,
  template_id,
  RFC8785(arguments sorted by parameter))
```

The current invocation ID is the last component of `invocation_path`; parent
IDs precede it. The closed expanded-graph preimage is:

```text
ExpandedFeatureNode =
    { kind: operation, identity: ExpandedOperationIdentity } |
    { kind: strategy_group,
      group_id: String,
      cardinality: all | exactly_one | any,
      strategies: NonEmpty<{
          strategy_id: String,
          availability_sha256: String,
          missing_policy_sha256: String,
          operations: NonEmpty<ExpandedOperationIdentity>
      }> }

ExpandedOperationGraphPreimageV1 {
    profile_ref: { schema, id, version, content_sha256 }
    template_definitions: [
        { template_id, template_definition_sha256 }
    ]
    invocations: [
        { identity: TemplateInvocationIdentity,
          template_id, template_arguments_sha256 }
    ]
    features: NonEmpty<{
        feature_id, requires_features,
        nodes: NonEmpty<ExpandedFeatureNode>
    }>
    operations: NonEmpty<{
        identity: ExpandedOperationIdentity,
        canonical_body_sha256: String
    }>
    extractors: [{ extractor_id, implementation_sha256,
                   capture_schema_sha256 }]
    reduced_outcomes: [ReducedEffectOutcome]
}

canonical_body_sha256 = H(
  "splice-expanded-semantic-operation-body-v1",
  RFC8785(concrete AuthoredSemanticOperation))

availability_sha256 = H(
  "splice-semantic-strategy-availability-v1",
  RFC8785(AuthoredEntityQuery | CapabilityPredicate))

missing_policy_sha256 = H(
  "splice-semantic-strategy-missing-policy-v1",
  RFC8785(StrategyMissingPolicy))

expanded_operation_graph_sha256 = H(
  "splice-expanded-operation-graph-v1",
  RFC8785(ExpandedOperationGraphPreimageV1))
```

Template-definition rows sort by `template_id`; invocation rows by their
already-proven-unique canonical `TemplateInvocationIdentity`; features by
`feature_id`; operation rows by
canonical `ExpandedOperationIdentity`; extractors by `extractor_id`; and
reduced outcomes by `(feature_id, outcome_id)`. Feature `nodes`, strategy rows,
and each strategy's operations retain declared workflow order. Dependency IDs
and template arguments are sets and sort by UTF-8 key bytes. No other field,
ambient registry order, or source order enters this preimage. For each expanded
operation:

```text
authored_operation_sha256 = H(
  "splice-authored-semantic-operation-v1",
  profile.content_sha256,
  expanded_operation_graph_sha256,
  canonical ExpandedOperationIdentity)

resolved_operation_sha256 = H(
  "splice-resolved-semantic-operation-v1",
  authored_operation_sha256,
  canonical OperationScope,
  canonical logical_method ref,
  canonical implementation ref,
  executable_module_generation,
  executable_module_snapshot_sha256,
  dispatch_authority,
  sorted known_alias refs,
  target_abi ref or absent,
  provider_export ref,
  capture_interface ref or absent,
  canonical resolved capture bindings,
  canonical HookApplyGuardV1,
  evidence_sha256)
```

`H` uses the length-framed field encoding from section 5; a `canonical` or
`RFC8785(...)` field is the RFC 8785 byte string supplied as one framed field.
The expanded graph, template-definition and argument digests, operation
identities, concrete body digests, authored and resolved digests,
implementation digest, and capture-interface digest are recorded. Runtime
never executes a first-class template or dynamically constructs a symbol.

## 12. Resolution and lowering pipeline

Ordinary structural inspection has its own four-step, authored-input-free
pipeline: (S1) capture one immutable file snapshot or
`ModuleSemanticSnapshot`; (S2) select exactly one cartridge and artifact
selection/module generation; (S3) decode and canonicalize observations and
entities without mutation; and (S4) execute the broad locator and return every
candidate. It never validates a knowledge pack, profile, provider interface, or
feature selection, never selects a knowledge variant, and creates no semantic
resolution handle, Plan, or commit guard.

Semantic resolution freezes this exact first checkpoint:

```text
R0OperationRowV1 {
    expanded_identity: ExpandedOperationIdentity
    authored_operation_sha256: String
    resolved_operation_sha256: String
    semantic_source_image_binding: String
    semantic_source_module_generation: String
    semantic_source_snapshot_sha256: String
    executable_module_generation: String
    executable_module_snapshot_sha256: String
    expected_entry_sha256: String
    observation_evidence_sha256: String
    runtime_observation: ObjCRuntimeDispatchObservation, optional
    known_aliases_sha256: String
    provisional_apply_guard: HookApplyGuardV1
}

known_aliases_sha256 = H(
  "splice-semantic-known-aliases-v1",
  RFC8785(alias refs sorted by canonical SemanticEntityRef))

feature_resolution_sha256 = H(
  "splice-semantic-feature-resolution-v1",
  RFC8785(feature outcomes sorted by feature_id))

limits_sha256 = H(
  "splice-semantic-limits-v1",
  RFC8785(SemanticLimits))

R0PreimageV1 {
    knowledge_ref: { schema, id, version, content_sha256 }
    selected_variants: [{ image_binding, variant_id, evidence_sha256 }]
    profile_ref: { schema, id, version, content_sha256 }
    provider_interface_ref: { schema, id, version, content_sha256 }
    provider_artifact_sha256: String
    feature_selection: FeatureSelection
    limits_sha256: String
    target: { process_generation,
              coherent_module_set_sha256: String, optional,
              images: [{ image_binding, role, module_generation,
                         module_snapshot_sha256 }] }
    expanded_operation_graph_sha256: String
    feature_resolution_sha256: String
    operations: [R0OperationRowV1]
}

r0_operation_row_sha256 = H(
  "splice-semantic-r0-operation-row-v1",
  RFC8785(R0OperationRowV1))

r0_sha256 = H(
  "splice-semantic-r0-v1",
  RFC8785(R0PreimageV1))
```

R0 contains exactly the retained, effect-eligible operations after feature,
missing-policy, and strategy resolution; skipped and omitted identities remain
in feature evidence but have no R0 operation row. R0 operation rows sort by
canonical `ExpandedOperationIdentity`. Alias refs are
sorted before hashing `known_aliases_sha256`; feature outcomes use their closed
section 10 models, including expanded operation identities. The R0 handle binds
`r0_sha256`, its exact preimage, and all row digests; it is Engine-bound and
non-serializable. `coherent_module_set_sha256` is present exactly when several
runtime image bindings were captured as one set and binds that set's complete
capture provenance. An R0 `runtime_observation` is present exactly when its
guard is `objc_dispatch`; its stable state digest must equal the guard's
`expected_dispatch_state_sha256`. An empty R0 operation array is valid only
when resolution retains no effect-eligible operation; apply then reports
`no_change` from R0 without loading a handler, constructing R1, or acquiring an
apply barrier.

Handler loading and the refreshed checkpoint use these closed models:

```text
HandlerLibraryBinding =
    { kind: resident,
      artifact_sha256,
      library_generation,
      binding_evidence_sha256 } |
    { kind: loaded,
      artifact_sha256,
      load_request_sha256,
      load_receipt_sha256,
      library_generation }

OperationHandlerBindingRow {
    expanded_identity: ExpandedOperationIdentity
    provider_export: ProviderExportRef
    native_symbol: String
    handler_library_generation: String
    export_binding_evidence_sha256: String
}

RefreshedOperationRowV1 {
    expanded_identity: ExpandedOperationIdentity
    r0_operation_row_sha256: String
    resolved_operation_sha256: String
    handler: OperationHandlerBindingRow
    process_generation: String
    semantic_source_image_binding: String
    semantic_source_module_generation: String
    semantic_source_snapshot_sha256: String
    executable_module_generation: String
    executable_module_snapshot_sha256: String
    known_aliases_sha256: String
    entry_sha256: String
    runtime_observation: ObjCRuntimeDispatchObservation, optional
    apply_guard: HookApplyGuardV1
}

RefreshedTargetV1 {
    process_generation: String
    coherent_module_set_sha256: String, optional
    images: [{ image_binding, role, module_generation,
               module_snapshot_sha256 }]
}

r1_operation_row_sha256 = H(
  "splice-semantic-r1-operation-row-v1",
  r0_sha256,
  RFC8785(RefreshedOperationRowV1))

R1PreimageV1 {
    r0_sha256: String
    handler_library_binding: HandlerLibraryBinding
    refreshed_target: RefreshedTargetV1
    operations: NonEmpty<RefreshedOperationRowV1>
}

r1_sha256 = H(
  "splice-semantic-r1-v1",
  RFC8785(R1PreimageV1))
```

R1 operation rows sort by canonical `ExpandedOperationIdentity`. Every row's
identity and resolved digest must match its R0 row. The refreshed target repeats
the complete binding set. Its process, roles, module generations, stable module
snapshot digests, aliases, and entry bytes must compare equal to R0. A
multi-image runtime target has a non-null coherent-set digest at both
checkpoints; the fresh R1 set digest need not equal R0 because it retains a new
capture epoch, but each digest proves that checkpoint's rows came from one set
capture. For `objc_dispatch`, the stable state digest derived from the fresh
`runtime_observation` must equal the R0 guard's expected state; the full
observation digest, capture epoch, and evidence digest are retained and need
not equal R0 provenance. Its `apply_guard` is the unchanged R0 provisional
guard. `runtime_observation` is present exactly for `objc_dispatch`; it is
absent for `none`. Every handler row must name the
same generation as `HandlerLibraryBinding` and the exact export selected by its
resolved operation. The R1 handle binds the exact preimage and each derived R1
row digest.

Semantic preview and hook authoring use this separate hash-chained pipeline:

1. validate and hash the complete knowledge, ABI contracts, convention
   profiles, profile, provider-interface, captured provider artifact, static
   template graph, typed invocations/arguments, expanded operation
   identities/graph, feature selection, and limits before target access;
2. resolve every referenced image binding explicitly and capture one immutable
   file snapshot or one coherent `ModuleSemanticSnapshotSet`; the set records
   the process generation and each binding, role, module generation, and
   snapshot digest in binding-name order, and its full set digest is retained
   in the checkpoint;
3. select exactly one cartridge, artifact selection/module generation, and
   knowledge variant independently for every referenced image binding;
4. decode observations and canonicalize runtime-record, logical-selector, and
   implementation identities before building ownership, category, selector,
   and logical-method graphs;
5. verify every used declaration against observations from its named image;
   an unused external declaration never causes an ambient module lookup;
6. resolve every already-expanded concrete query, returning exact-one for an
   operation and constructing a `ResolvedSemanticOperation`
   from its target-free expanded authored operation and exact authored digest;
7. validate target ABI only where capture bindings require it; separately
   validate the provider export as `splice-hook-handler/v1` and every binding
   against its digest-pinned capture interface;
8. compute dependency closure, selection, operation/strategy missing policy,
   fallback graph, strategy cardinality, the single effective reduced outcome
   per feature, runtime capabilities, and provisional semantic conflicts;
9. for `current_runtime_dispatch`, obtain a point-in-time runtime observation
   and construct the exact `objc_dispatch` apply guard from its stable state
   digest while retaining the full observation; recorded
   metadata uses the `none` guard;
10. construct `R0PreimageV1` exactly, sort its operation rows by expanded
    identity, derive every row digest and `r0_sha256`, and freeze those values
    in one opaque R0 handle;
11. create one closed `HandlerLibraryBinding`: either validate an
    already-resident library generation against the exact artifact digest, or
    create, review, and apply the existing `library_load` request and derive
    the actual library generation from its owning receipt. For every retained
    operation, resolve its selected provider export to one
    `OperationHandlerBindingRow`; several operations may bind different native
    symbols in the same artifact generation;
12. require the process, complete referenced image-binding set, each semantic
    source module, and every executable module generation to remain exactly
    equal to R0; recapture and compare all relevant module snapshots/known
    aliases, refresh entry bytes, and refresh the current-dispatch observation.
    Require its stable state digest to match R0 while retaining its new capture
    provenance. Construct the exact `RefreshedTargetV1`, sorted
    `RefreshedOperationRowV1` array, and `R1PreimageV1`, retaining the new
    coherent-set digest where applicable, then freeze all row digests and
    `r1_sha256` in one opaque R1 handle;
13. lower one declared `ExpandedOperationIdentity` from R1 to the expanded Hook
    v1 request, including that row's reviewed apply guard, then let
    instrumentation plan and review under its own authority;
14. apply acquires and retains the owning Hook v1 barrier, evaluates the guard
    through the fixed provider guard operation, validates the returned
    observation's stable state digest in the supervisor while retaining the
    full observation, and, without releasing the barrier,
    rechecks the ordinary Hook v1 generations/mappings/entry bytes and installs
    the hook. Any guard drift rejects with no hook effect; and
15. recover, retire, and project a semantic report that references, but never
    replaces, the owning action reports and guard evidence.

The resident library branch is valid only when instrumentation proves the
exact loaded artifact identity and current library generation. Absence of that
evidence uses the reviewed load branch; it never guesses from a path or symbol.
Export binding is per operation, so a multi-operation profile is not forced
through one accidental `native_symbol`.

Hook v1 gains this closed, required request member; ordinary hooks use `none`:

```text
HookApplyGuardV1 =
    { kind: none } |
    { kind: objc_dispatch,
      observer: { id, version, implementation_sha256 },
      process_generation,
      class_module_generation,
      class_runtime_rva,
      selector,
      dispatch: instance | class,
      expected_implementation_module_generation,
      expected_implementation_rva,
      expected_dispatch_state_sha256 }
```

Adopting this proposal therefore includes an atomic canonical revision of the
pre-release Hook v1 request, reviewed instruction, Plan/review rendering,
provider contract, reports, generated schemas, and conformance corpus. The
instrumentation provider adds one fixed read operation,
`observe_hook_apply_guard(BarrierGuard, ReviewedHookGuardInstruction)`, which
returns a typed observation and never a verdict. It is not an arbitrary target
call or semantic callback. The supervisor computes the stable dispatch-state
digest, owns comparison and rejection, retains the fresh full observation and
provenance in receipt/session/report evidence, and
the same retained guard is passed to `install_hook` only after equality. The
guard and its observation are included in Plan, action, receipt, raw session
evidence, and verifier closure. A provider without the exact observer profile
advertises the guard capability false.

For `objc_dispatch`, `BarrierGuard` is a proved critical-section capability,
not a sequencing token: the expanded Hook v1 barrier must exclude target-thread
and loader mutations that could change the inspected dispatch result, mappings,
or entry bytes from the guard observation through installation. The provider's
observer rejects a foreign, released, or insufficient barrier guard. If a
backend cannot establish that linearization boundary, it advertises
`objc_dispatch` apply-guard support false; “read then install while the target
keeps running” is not an admitted implementation.

Each operation has a distinct lowering ID and consumed bit keyed by canonical
`ExpandedOperationIdentity`. A workflow-level
resolution is reusable only to derive those retained per-operation lowerings;
each lowering is Engine-bound, single-use, and hash-linked to its checkpoint.
No raw JSON resolution can be replayed as authority.

Apart from the canonical `HookApplyGuardV1` member, instrumentation requests
gain no knowledge, entity-query, feature, or template members. The immutable
`LoweringSummary` binds `{expanded_identity, r1_sha256,
r1_operation_row_sha256, instrumentation_request_sha256}` and the semantic
report references the owning instrumentation report by digest. Request
equality tests compare the generated
request with a separately authored Hook v1 request, including the guard, after
canonical serialization.

For live Objective-C Hook v1 lowering, the result must bind:

- process, semantic-source image binding/module, and executable implementation
  module generations;
- logical method ID, implementation ID, dispatch authority, and R1 digest in
  semantic evidence;
- the exact executable RVA admitted by `HookLocator::Rva`;
- target ABI/capture mapping when present and the fixed provider handler ABI;
- handler library generation, artifact digest, and symbol;
- exact original-byte digest, architecture, masks, limits, capture policy, and
  idempotency key already required by instrumentation; and
- whether recorded metadata supplied a recorded target or an independently
  revalidated runtime observation supplied current dispatch.

The instrumentation provider receives only the existing reviewed
instrumentation instruction. It does not receive knowledge packs, semantic
source, candidate sets, policy, or the authority to re-resolve the target. The
handler provider-interface document is an Engine input and is not itself an
instrumentation provider command.

One semantic profile may require several reviewed instrumentation actions.
Planning does not pretend these are one byte-complete Plan. Preflight rejection
prevents the first effect; a later checkpoint failure stops the remaining
actions and reports partial effects. Compensation claims are limited to
separately reviewed actions and receipts.

## 13. Inspection, toolkit, and CLI

### 13.1 Read-only inspection

The existing `InspectQuery { kind: "locator", source }` arm gains structural
terminal results; no parallel query language is added. Mach-O v1 adds paired
`ImageView` and `ModuleView` locators with these exact arguments:

```text
macho.objc_class(name: String,
                 record_kind: macho.objc_record_kind,
                 entity_id: String?) -> macho.objc_class
macho.objc_category(class_name: String?, class_entity_id: String?,
                    name: String?, entity_id: String?) -> macho.objc_category
macho.objc_protocol(name: String, entity_id: String?) -> macho.objc_protocol
macho.objc_method(class_name: String?, owner_entity_id: String?,
                  selector: String, dispatch: macho.objc_dispatch,
                  contribution: macho.objc_contribution,
                  category_name: String?,
                  member_id: String?) -> macho.objc_method
macho.objc_selector(spelling: String,
                    entity_id: String?) -> macho.objc_selector
```

The cartridge declares these qualified enum values:

```text
macho.objc_record_kind =
    macho.objc_class_record | macho.objc_metaclass_record
macho.objc_dispatch = macho.objc_instance | macho.objc_class_dispatch
macho.objc_contribution =
    macho.objc_base | macho.objc_any_category | macho.objc_named_category
```

`macho.objc_category` and `macho.objc_method` require exactly one of their
class-name and class-entity-ID arguments. The name form is broad and may return
several owners. `category_name` is present exactly with
`macho.objc_named_category`; it is absent for base and any-category queries.
Strings never coerce to cartridge enum values.

Every identity argument is optional for a broad inspection query and is added
by the cartridge's source-exact canonical invocation for a returned candidate.
It is the only admitted exact selector when names are ambiguous.

`InspectPayload.info` adds `structural: [StructuralInfo]`:

```text
StructuralInfo {
    query: InspectQuerySummary
    locator: ResolvedLocator
    selection: ArtifactSelectionSummary, optional
    module: ProcessModuleRef, optional
    structural_type: String
    entity_id: String
    properties: [PropertyInfo]
    observations: [
        { observation_id, source_kind, source_region?, pointer_slot?,
          decoded_coordinate?, evidence_sha256, disposition }
    ]
}
```

Rows sort by structural type, entity ID UTF-8 bytes, then canonical locator
text. Observation rows sort by observation ID. Human output may group rows but
JSON uses this order. Safe output represents live addresses as module
generation plus RVA. This semantic projection never prints raw process VAs.

Inspection returns every candidate with identity, presentation name, owning
selection/module generation, typed file Region or module-generation-bound RVA
when proven, extent when
known, ABI evidence, and observations. It never silently applies a knowledge
overlay or chooses one candidate. Knowledge packs are evaluated by semantic
preview, not ordinary inspection.

CLI uses the existing command and flag, for example:

```text
splice inspect APP \
  --locator '.macho.objc_class(name: "Widget", record_kind: macho.objc_class_record)'
splice inspect --process PID --module MODULE \
  --locator '.macho.objc_method(class_name: "Widget", selector: "draw:", \
    dispatch: macho.objc_instance, contribution: macho.objc_base)'
```

The output remains the ordinary `splice.report/v1` `InspectReport`; a read-only
query never emits `splice.semantic.report/v1`.

### 13.2 Toolkit

```text
SemanticKnowledgeCompiler
  .compile(source_bundle) -> KnowledgePack

SemanticEngineBuilder
  .engine(existing_engine)
  .knowledge(pack)
  .image_bindings(NonEmpty<{ binding, module_selector }>)
  .provider_interface(interface)
  .provider_artifact(byte_source)
  .profile(profile)
  .limits(limits)
  .build()

SemanticEngine
  .resolve_hook(session, profile, feature_selection) -> R0Handle
  .plan_handler_bindings(r0) -> {
      library: ResidentBindingEvidence | InstrumentationRequest,
      operations: NonEmpty<OperationHandlerBindingPlan>
  }
  .resume_with_handlers(r0, resident_evidence | load_receipt,
                        operation_binding_evidence) -> R1Handle
  .lower_hook(r1, expanded_identity) -> InstrumentationRequest
```

`SemanticKnowledgeCompiler` is the same compiler used by `splice check` and
`splice info` when their root is a `semantic knowledge` module. It captures
every `use` document through the existing closed `SourceBundle`, lowers the
source, and then invokes the ordinary `KnowledgePack` validator. Its output is
byte-for-byte equal to validating the equivalent JSON document. Source spans
remain diagnostic provenance and never enter the pack digest.

Read-only structural inspection remains on the existing Engine. R0/R1 and
lowered values are Engine-bound, non-serializable opaque handles with immutable
views. Public JSON is evidence, not a portable Plan. Lowering rejects a foreign
Engine, stale process/module/handler generation, changed input digest, load
receipt mismatch, entry-byte drift, live-dispatch drift, or consumed operation
lowering. `OperationHandlerBindingPlan` is keyed by
`ExpandedOperationIdentity`; the supplied evidence set must cover the R0
retained operations exactly once with no extra row.

### 13.3 Operator flow

The semantic profile is a separate input that references, rather than extends,
the closed instrumentation profile. It does not make generic
`splice apply --process` allocate or hook. The public command grammar is:

```text
splice instrument semantic info --profile PROFILE

splice instrument semantic preview --session ID --profile PROFILE
  (--knowledge PACK | --knowledge-source MODULE)
  --image BINDING=MODULE ...
  --provider-interface INTERFACE --provider-artifact ARTIFACT
  [--enable FEATURE]... [--disable FEATURE]...

splice instrument semantic apply --session ID --profile PROFILE
  (--knowledge PACK | --knowledge-source MODULE)
  --image BINDING=MODULE ...
  --provider-interface INTERFACE --provider-artifact ARTIFACT
  [--enable FEATURE]... [--disable FEATURE]... [-y|--yes]
```

The existing `splice check MODULE...` and `splice info MODULE` commands accept
semantic knowledge modules. `check` validates the complete source bundle,
every used ABI/convention document, source-to-model lowering, and the resulting
pack without target access. `info` additionally renders image bindings,
variants, declarations, canonical `::` references, document refs, and the
active or gated resolution capability for each declaration.
They remain ordinary `splice.report/v1` check/info commands; parsing a
knowledge source does not manufacture a semantic execution report.

`--knowledge` and `--knowledge-source` are mutually exclusive and exactly one
is required. `--image` is repeatable, keyed by the source/pack image binding,
and must cover every image referenced by the effective feature graph exactly
once with no extra or duplicate binding. `MODULE` uses the existing closed
module selector grammar; its basename, load order, and dependency edges never
choose a binding. The `internal` role provides no implicit main-module default.
CLI order is preserved in the request summary, while validation and hashing
sort bound images by binding-name UTF-8 bytes.

`info` validates the profile and reports features plus active/gated reasons
without target access. `preview` performs R0 only and never loads or hooks. `apply` emits the complete
selection and R0 review, then the existing stage-specific library and hook
review checkpoints. In human mode absent confirmation rejects without effect;
`--yes` approves each checkpoint separately. Global JSON/JSONL formatting and
exit status retain current instrumentation rules: success is 0, an owning
rejection/non-success verdict is 1, usage is 2, and internal failure is 3.

The accepted CLI must expose:

- semantic inspection for files and process modules through `--locator`;
- profile and feature discovery with active/gated capability reasons;
- plan-only semantic resolution with no mutation;
- feature/profile selection bound into review; and
- semantic report output linked to existing instrumentation reports.

It must not expose a command that accepts a raw semantic resolution JSON as
mutation authority.

## 14. Diagnostics and limits

Stable semantic detail codes appear under the existing diagnostic families:

```text
semantic_source_invalid
semantic_scope_invalid
semantic_document_invalid
semantic_pack_invalid
semantic_image_binding_invalid
semantic_declaration_collision
semantic_symbol_identity_invalid
semantic_location_invalid
semantic_variant_absent
semantic_variant_ambiguous
semantic_entity_absent
semantic_entity_ambiguous
semantic_metadata_damaged
semantic_module_snapshot_unstable
semantic_encoding_unsupported
semantic_overlay_contradicted
semantic_imp_nonexecutable
semantic_runtime_evidence_absent
semantic_apply_guard_drift
semantic_abi_mismatch
semantic_provider_mismatch
semantic_feature_conflict
semantic_dependency_disabled
semantic_strategy_cardinality
semantic_intent_gated
semantic_profile_gated
semantic_multi_image_gated
semantic_extractor_invalid
semantic_template_cycle
```

Diagnostics include the entity query, stable candidate IDs, presentation names,
source observations, selected build variant, expected and actual ABI fields,
affected feature/strategy, causes, and safe actions. They do not dump provider
secrets, captured payloads, raw pointers outside the admitted reporting policy,
or hidden capture values.

Detail codes map to existing outer codes as follows: malformed authored schema,
template, extractor, or profile is `source_invalid`; absent or contradicted
target facts are `target_mismatch`; multiple candidates or variants are
`target_ambiguous`; unsupported encoding, observer, intent, or runtime
capability is `target_unsupported`; digest, generation, entry-byte, or dispatch
drift is `target_mismatch`; and any semantic budget excess is
`resource_limit`. Before instrumentation planning, severity is error, stage is
`semantic_resolution`, effect is `no_effect`, and status is `rejected`. An
in-barrier guard rejection uses the owning instrumentation `hook_apply_guard`
stage with `no_effect` and `rejected`. After a
completed checkpoint, the owning instrumentation diagnostic supplies stage and
effect. Semantic status can only remain equal or become `target_gone` before
any effect, or `partial` after a durable/uncertain effect.

The initial limit registry is per semantic request:

| Limit | Default | Hard maximum | Unit |
|---|---:|---:|---|
| `semantic_source_bytes` | 8,388,608 | 67,108,864 | captured source/document bytes |
| `semantic_pack_bytes` | 8,388,608 | 67,108,864 | bytes |
| `semantic_image_bindings` | 256 | 4,096 | images |
| `semantic_name_segments` | 64 | 256 | segments per semantic path |
| `semantic_name_bytes` | 4,096 | 65,536 | UTF-8 bytes per canonical reference |
| `semantic_used_documents` | 1,024 | 16,384 | ABI/convention documents |
| `semantic_module_capture_bytes` | 134,217,728 | 1,073,741,824 | bytes |
| `semantic_module_capture_regions` | 4,096 | 65,536 | regions |
| `semantic_variants` | 4,096 | 65,536 | records |
| `semantic_declarations` | 100,000 | 1,000,000 | records |
| `semantic_observations` | 1,000,000 | 10,000,000 | records |
| `semantic_entities` | 500,000 | 5,000,000 | records |
| `semantic_graph_edges` | 2,000,000 | 20,000,000 | edges |
| `semantic_methods_per_entity` | 65,536 | 1,000,000 | methods |
| `semantic_vtable_slots` | 65,536 | 1,000,000 | slots per declaration |
| `semantic_candidates_per_query` | 100,000 | 1,000,000 | candidates |
| `semantic_template_depth` | 64 | 256 | nesting levels |
| `semantic_template_expansion` | 100,000 | 1,000,000 | expanded nodes |
| `semantic_features` | 4,096 | 65,536 | features |
| `semantic_strategies` | 16,384 | 262,144 | strategies |
| `semantic_extractor_steps` | 1,024 | 65,536 | steps per binding |
| `semantic_diagnostic_candidates` | 1,024 | 65,536 | rendered candidates |
| `semantic_report_bytes` | 67,108,864 | 268,435,456 | UTF-8 JSON bytes |

Static limits reject before target access. Target-derived excess rejects
`resource_limit`; it never truncates a candidate set and then claims
uniqueness. Reports may summarize candidates only after the verdict has already
recorded ambiguity or resource exhaustion.

## 15. Reports and evidence

`splice.semantic.report/v1` is a projection over owning reports and immutable
semantic evidence:

```text
SemanticInfoReport =
    { schema, command: semantic_info, status: ready,
      profile_ref, feature_selection,
      features: [SemanticFeatureInfo],
      capability_reasons: [CapabilityReason],
      semantic_evidence_sha256, diagnostics } |
    { schema, command: semantic_info, status: rejected,
      invalid_request_sha256,
      semantic_evidence_sha256, diagnostics }

BoundKnowledgeImageSummary {
    image_binding: String
    role: internal | external
    source: { kind: file, selection: ArtifactSelectionSummary,
              content_sha256: String } |
            { kind: module, module: ProcessModuleRef,
              module_snapshot_sha256: String }
}

R0Summary {
    r0_sha256: String
    preimage: R0PreimageV1
    operation_rows: [
        { expanded_identity, r0_operation_row_sha256 }
    ]
}

R1Summary {
    r1_sha256: String
    preimage: R1PreimageV1
    operation_rows: NonEmpty<
        { expanded_identity, r1_operation_row_sha256 }>
}

LoweringSummary {
    expanded_identity: ExpandedOperationIdentity
    r1_sha256: String
    r1_operation_row_sha256: String
    instrumentation_request_sha256: String
}

SemanticExecutionReport =
    { schema, command: semantic_preview | semantic_apply,
      status: rejected, request_state: invalid,
      invalid_request_sha256,
      semantic_evidence_sha256, diagnostics } |
    { schema, command: semantic_preview | semantic_apply,
      request_state: valid,
      status: ready | no_change | applied | rejected | partial | target_gone,
      terminal_cause: none | rejected | rolled_back | crash_uncertain |
                      target_gone,
      target: { process_generation?, images: [BoundKnowledgeImageSummary] },
      cartridges: [{ image_binding, cartridge }],
      knowledge_ref, profile_ref, provider_interface_ref,
      selected_variants: [{ image_binding, variant_id, evidence_sha256 }],
      feature_selection,
      entities: [SemanticEntitySummary],
      resolutions: [ResolvedSemanticOperationSummary],
      checkpoints: [R0Summary | R1Summary],
      feature_resolution: [FeatureResolutionOutcome],
      feature_effects: [FeatureEffectOutcome],
      lowerings: [LoweringSummary],
      downstream_refs: [
          { request_sha256, plan_sha256?, action_id?, report_schema?,
            report_sha256? }
      ],
      semantic_evidence_sha256, diagnostics }

SemanticReport = SemanticInfoReport | SemanticExecutionReport
```

`semantic_evidence_sha256` is SHA-256 of canonical
`SemanticEvidencePreimageV1`, never of presentation text. The info preimage
contains either the profile ref plus canonical selection and complete feature
IDs/static capability reasons, or `invalid_request_sha256`,
and diagnostics. An invalid execution request uses the same digest-only
preimage rule and contains no target or resolution fields. A valid execution
preimage contains all authored input refs/digests, target snapshot digest and generations, selected
variant, expanded-graph/operation identities and authored/resolved digests,
entity/observation/evidence IDs, feature and strategy outcomes, R0/R1,
`HandlerLibraryBinding`, every `OperationHandlerBindingRow`, capture-interface
digest, apply-guard stable state, and each stage's full runtime observation
digest/capture epoch/evidence digest, `LoweringSummary` rows, and ordered
downstream request/Plan/action/report
digests. The digest field itself is omitted from the preimage. Preview uses the
available prefix through R0; apply extends that evidence with every later
checkpoint and owning artifact. The verifier reconstructs the preimage from
the report plus referenced immutable session evidence and rejects a missing,
extra, reordered, or mismatched reference.

Read-only inspection uses `InspectReport` and never this schema. `semantic_info`
is target-free and cannot contain entities, lowerings, or downstream refs. Its
rejected arm contains no selection/features/capabilities and hashes the exact
captured invalid request bytes into `invalid_request_sha256`; it contains one
owning source diagnostic.
Preview is
`ready` only after R0. Apply is `no_change` only when every retained operation's
owning action proves `no_change`; it is `applied` when at least one action is
applied and every other action is applied or no-change. A pre-effect rejection
is `rejected`. `target_gone` is a top-level status only when no action has
produced a durable or uncertain effect. Once any effect has completed, a later
rejection, rollback, crash uncertainty, not-attempted action, or target loss
makes the workflow `partial`; `terminal_cause` preserves the final owning cause,
including `target_gone`. A semantic report never upgrades an instrumentation
verdict or erases a prior effect.

The valid execution arm requires `cartridge` before any entity, R0, ready, or
effect state may appear. A cartridge-selection rejection leaves it absent and
retains the deterministic cartridge candidates in diagnostics. The invalid
execution arm contains no target, authored refs, selection, entities, or
downstream refs.

`ready`, `no_change`, and `applied` require `terminal_cause: none`; `rejected`
requires `rejected`; `target_gone` requires `target_gone`; and `partial`
requires the actual non-`none` final cause. Any other status/cause product is
invalid.

Entity summaries sort by scope, kind, and entity ID; observations sort by ID;
features sort by `feature_id`, lowerings by canonical expanded identity, and
checkpoints and owning
downstream refs retain execution order. Operation rows inside each checkpoint
summary sort by canonical expanded identity. Every semantic entity summary conserves its
observation count and identifies
which observations supported resolution. Every resolved-operation summary
binds its expanded identity, expanded-graph digest, authored operation digest,
resolved operation digest, runtime scope, entity/implementation,
capture/interface mapping, guard, and evidence digest. Every feature outcome
lists expanded operation identities and action IDs. A degraded result repeats the exact declared reason
and the evidence that triggered it. Hidden/private features remain present.

## 16. Conformance contract

Every normative rule and rejection clause receives a generated case ID, a
positive fixture where applicable, and deliberately invalid fixtures for every
independent failure. Structural generation is not implementation evidence.

Minimum families are:

| Family | Required evidence |
|---|---|
| S01 schema and identity | canonical documents; unknown field, digest, version, duplicate ID, path/mtime identity negatives |
| S02 typed cartridge schema | real typed structural values/arguments/results survive projection; name-list collapse and registration-order negatives |
| S03 ObjC thin images | classes, metaclasses, selectors, instance/class methods, IMPs, extents, provenance on arm64 and x86-64 |
| S04 ObjC fat images/modules | exact selection and atomic effect-free `capture_coherent_module`; atomic multi-binding `capture_coherent_module_set` where applicable; cross-slice leakage, duplicate arch, partial mapping or binding set, sequential pseudo-set capture, unstable/nonatomic snapshot, hidden suspension or process-control effect, absent capability, stale generation, and budget negatives |
| S05 ObjC encodings | absolute/relative admitted lists and fixups; truncated, cyclic, overflow, misaligned, unsupported, PAC/fixup negatives |
| S06 canonical identity | duplicate runtime-record observations collapse by typed coordinate; equal selector spellings in one scope become one logical selector with all cstring/selref/method observations conserved; shared IMP methods remain distinct and point to one implementation; implementation-wide admission reports bounded known aliases without claiming global completeness; same name/different address and class/metaclass remain distinct |
| S07 categories/protocol context | base/category contributions, shared logical selectors across records, inheritance context; ambiguous owner and malformed graph negatives |
| S08 inspection | all candidates, stable IDs, provenance, deterministic projection; no first-result selection and unchanged target digest |
| S09 semantic source and knowledge | `::` paths and canonical references, image roles/bindings, source/JSON byte-equal lowering, closed document uses, exact-one per-image variant selection, extends flattening, declare/alias/supersede/absence, semantic and exact-one raw-symbol rename forms, explicit raw symbols and coordinate spaces; dot-scoped name, unquoted mangling, numeric/short digest, duplicate/unknown attribute, missing/wrong ABI or convention document, duplicate declaration/slot, overload collision, overlap, cycle, unmatched, contradicted, presentation rename without replacement raw identity, zero/multi-match raw rename, address-without-hash/arch, implicit image and extra/missing binding negatives |
| S10 ABI | logical ObjC and raw IMP evidence plus capture mappings; forward-visible C/C++/Swift call and identity/layout separation; hidden-arg, return-class, aggregate, variadic, ownership, convention, architecture, mitigation, identity-as-call-ABI, and layout-as-call-ABI mismatches |
| S11 provider interface | digest-pinned `splice-hook-handler/v1` export and capture interface; target-ABI equality, unknown/duplicate/wrong-type decoder field, capture-digest drift, ambient path, ABI inference, missing/duplicate symbol, wrong artifact/arch/direction negatives |
| S12 feature selection | target-free image-bound authored operations/queries/profiles/templates, profiles, enable/disable, dependency closure, private evidence; runtime scope/entity/member ID/RVA in authored input, absent/extra image binding, unknown declaration, unknown, duplicate, conflicting, disabled-required negatives |
| S13 missing and strategies | typed operation/strategy fail/skip/degrade/fallback and all/exactly-one/any; one effective reduced outcome per feature keyed by full expanded identities, triggering-operation omission, fallback deduplication, plus local-ID collision, distinct-outcome conflict, retained-unavailable operation, zero/multiple, cross-group/cyclic/failed fallback, incomplete reduced outcome, overlap, hidden conflict, degradation-bypass negatives |
| S14 extractors/templates | four closed parameter kinds and substitution sites, operation-only template bodies, typed invocation/arguments, nested expansion, exact template-definition/argument/expanded-graph preimages, unique invocation and expanded-operation identities, typed provenance, provider decoder-field binding, and sealed exports; missing/extra/wrong-kind/wrong-site argument, strategy-producing template, unresolved parameter/invocation, duplicate invocation identity even with disjoint local operation IDs, duplicate or truncated expanded ID, fake cast, wrong field/type/source/address space/lifetime/bound/digest, cycle, depth, expansion negatives |
| S15 semantic lowering | exact authored/resolved operation, R0 row/preimage, refreshed target, R1 row/preimage, and graph digest reconstruction; exact source and executable module generations/snapshots plus coherent-set evidence where applicable; effect-free coherent preview observer; stable dispatch-state digest separated from full capture provenance; one closed resident/loaded `HandlerLibraryBinding` plus per-operation export bindings; HookApplyGuardV1 and hash chain; multi-export and foreign-module current dispatch positives plus mutated expansion/identity/field-order/digest, singular guard/export binding, volatile epoch/evidence in guard state, dropped full observation, runtime evidence in authored input, ambiguity, hidden preview suspension/double-read, unmapped/nonexecutable IMP, recorded/current authority mismatch, generation/dispatch drift, stale/foreign/consumed handle negatives |
| S16 intent boundary | observe-before positive; intercept/replace/wrap/redirect are invalid v1 enum values and never change target state |
| S17 instrumentation composition | expanded Hook v1 schema and provider boundary, exact R0, exact resident evidence or reviewed library receipt, per-operation handler rows, refreshed per-operation evidence and R1, one lowering per full expanded identity, stable-state equality across distinct R0/R1/apply epochs with every full observation retained, an exclusive Objective-C mutation boundary from in-barrier guard observation through install without barrier release, exact Hook request equivalence, failure/rollback/crash/target-gone evidence; no impossible atomic workflow claim |
| S18 reports/diagnostics | closed ready/rejected semantic-info arms, invalid-request digest, exact graph/R0/R1/evidence-preimage reconstruction, full expanded identities in outcomes and lowerings, downstream digest linkage, target-gone-after-effect precedence, status/cause products, feature/entity/observation conservation, owning-verdict monotonicity, safe redaction, stable detail codes, deterministic JSON/JSONL |
| S19 dependency seam | pinned Macho revision, bounded adapter, strict nested errors, full method provenance, equal relative-IMP paths, no dependency report/ABI authority |
| S20 real corpus | locked stripped and category-heavy fixtures for arm64 and x86-64, bounded memory, deterministic repeated output |

`spec/conformance/semantic/fixtures.json` is the sole fixture manifest. Every
row names source path, generation command, architecture, artifact SHA-256,
license/provenance, expected observation/entity/member counts, and applicable
case IDs. Synthetic sources live under `spec/conformance/semantic/src/` and
locked artifacts under `spec/conformance/semantic/artifacts/`. The manifest
must include at least one stripped and one category-heavy image for arm64 and
x86-64; native live cases are separately applicable only to Darwin arm64.

The independent Objective-C oracle must not reuse the production parser. The
relocation oracle must decode emitted instructions independently. The
conformance supervisor, not the cartridge/provider/adapter, decides
applicability and verdict.

Mutation selftests use fixed operators: delete-required-field, admit-unknown-
field, swap-ID-domain, persist-raw-VA, fragment-selector-by-coordinate,
merge-shared-IMP-methods, claim-known-aliases-global, discard-observation,
quiesce-during-inspect, choose-first-candidate,
replace-semantic-scope-with-dot, accept-unquoted-raw-symbol,
parse-content-digest-as-integer, share-one-content-digest-across-distinct-builds,
drop-raw-symbol-half-of-rename, infer-call-ABI-from-identity-profile,
infer-call-ABI-from-layout-profile, accept-unbound-external-image,
capture-module-set-sequentially, diverge-source-and-JSON-lowering,
accept-target-handler-ABI-equality,
put-runtime-scope-in-authored-operation, put-entity-id-in-authored-query,
drop-template-argument, substitute-template-argument-at-wrong-site,
admit-strategy-producing-template, leave-template-parameter,
omit-template-definition-digest, duplicate-template-invocation-identity,
collide-expanded-operation-id,
truncate-expanded-operation-identity, key-outcome-by-local-operation-id,
swap-authored-resolved-operation-digest, bind-unknown-decoder-field,
admit-fallback-cycle, compose-distinct-reduced-outcomes,
retain-degradation-trigger, disable-dependency-check,
mutate-R0-preimage-field, reuse-R0-after-handler-binding,
reuse-one-handler-symbol-for-several-exports, drop-R1-operation-row,
skip-R1-refresh, admit-unsupported-intent, bypass-hook-apply-guard,
hash-capture-provenance-into-guard-state, drop-full-guard-observation,
release-barrier-between-guard-and-install, accept-provider-guard-verdict,
accept-nonexclusive-objc-barrier,
consume-lowering-twice, drop-downstream-evidence-ref,
omit-invalid-info-request-digest, erase-prior-effect-with-target-gone,
upgrade-owning-verdict, and truncate-before-cardinality. Each operator has one
stable case ID and must make its paired case fail.

The serial acceptance commands are:

```text
cargo test -p splice-engine semantic_model
cargo test -p splice-toolchain semantic_objc
cargo run -p xtask -- semantic-dependency-audit
cargo run -p xtask -- semantic-oracle
cargo run -p xtask -- semantic-conformance
mise run ci
```

The first two commands exist only after their named targets are added; an
unknown target is a failed gate, not not-applicable. The dependency audit checks
the pinned revision, SBOM/license, forbidden path/branch dependency, reader
budgets, and production-versus-oracle separation. `semantic-conformance` runs
the supervisor against the stock adapter without filters and rejects skipped
applicable arm64/x86-64 file cases. Native Darwin cases report explicit
applicability from the supervisor.

The specialized instrumentation conformance, crash matrix, report differential,
and semantic cases must be wired into ordinary local and hosted CI before any
native semantic hook capability is true. A lock wait, generated artifact count,
phrase match, skipped profile, or gated capability is not a pass.

## 17. Execution order and runtime gates

These are independently claimable release contracts, not calendar phases:

### Release A — `semantic-objc-inspect/v1`

1. **Dependency seam.** Pin Macho, implement the bounded adapter, strict nested
   observations, provenance, budgets, relative-IMP equality, and an independent
   oracle. *Stop:* Macho consumes unaccounted bytes, drops a nested failure, or
   serves as both production decoder and oracle.
2. **Typed cartridge substrate.** Upgrade runtime `CartridgeSchema`, canonical
   generation, and inspection so structural types, arguments, results, and
   `StructuralInfo` survive every view. *Stop:* any type collapses to a name
   list or registration order affects output.
3. **Pure Objective-C recovery.** Implement scoped identities, observation
   conservation, logical method/implementation separation, exact locators,
   effect-free coherent `ModuleSemanticSnapshot`, and the locked corpus. *Stop:*
   candidates truncate, shared IMPs merge logical methods, selector records
   fragment one logical selector, observations disappear, a mapped range is
   read lazily or through suspension/double-read heuristics, or file/module coordinates
   conflate.

Release A file recovery is complete without a hook runtime and may ship
independently. Its mapped-module capability remains false until the stock
backend passes the coherent-snapshot atomicity and no-effect profile.

### Release B — `semantic-hook-authoring/v1`

4. **Closed authoring models and source compiler.** Absorb the semantic
   knowledge module grammar, `::` name model, image bindings, source-to-JSON
   lowering, convention-profile and declaration variants, plus complete
   schemas for the single-pack knowledge model, target ABI/captures,
   HookContext provider interface, features, strategies, extractors, typed
   template invocations/arguments, expanded/authored/resolved operation
   identities, reports, limits, diagnostics, toolkit, and CLI. *Stop:* source
   and equivalent JSON differ, a dot is admitted as semantic scope, an image is
   ambient, an ABI/profile is inferred, a raw-mangled rename is partial, an
   undefined type remains, runtime entity/scope enters an authored
   operation/query, a parameter lacks one exact substitution site, a template
   produces a strategy, a template is uninstantiable, an expanded-operation or
   invocation identity duplicates, or any merge is nondeterministic.
5. **Pure R0 resolution.** Implement validation and resolution with all invalid
   fixtures. *Stop:* an authored claim overrides bytes, a target ABI field is
   inferred, a disabled dependency degrades, distinct reduced outcomes compose,
   a degradation trigger remains in the retained operation set, or an authored
   or resolved operation, template-definition, argument, expanded-graph, R0
   row, or R0 preimage digest cannot be reconstructed.
6. **Hook v1 apply-barrier expansion.** Canonically revise Hook v1 with the
   required `HookApplyGuardV1`, reviewed guard instruction, fixed provider
   observation method, supervisor comparison, same-barrier install sequencing,
   evidence, reports, recovery, verifier, generated artifacts, and mutation
   selftests. *Stop:* guard observation occurs before/across barrier release, a
   provider declares the verdict, current dispatch lowers with `none`, guard
   equality includes capture epoch/evidence identity, a full observation is
   discarded, an unproved barrier permits target/loader dispatch mutation, or
   an old and revised v1 coexist under one schema identity.
7. **Hash-chained exact lowering.** Implement exact resident evidence or load
   receipt → per-operation export bindings → refreshed per-operation evidence
   → exact R1, then prove byte-for-byte equality with an independently authored
   Hook v1 RVA-plus-guard request. *Stop:* JSON is replayable authority, a name
   is re-resolved by a provider, one symbol is reused for distinct exports, a
   handler generation is guessed, a target generation/snapshot refreshes to a
   different identity, an R1 row/preimage cannot be reconstructed, a bare local
   operation ID selects a lowering, or a lowering is consumed twice.

Release B may report `semantic_intent_gated`, `semantic_profile_gated`, or
`semantic_multi_image_gated`; it does not make Hook v1, C/Swift resolution,
vtable resolution, or multi-image capture support true.

### Activation gate — existing instrumentation authority

8. Activate semantic `observe_before` only where the revised canonical portable
   relocator, hook install/remove, recovery, retirement, report differential,
   crash matrix, guarded apply-barrier path, and native profile all pass and are
   in ordinary CI. Static metadata claims only a recorded implementation;
   current dispatch requires the runtime observer and in-barrier guard
   revalidation. Intercept, replace, wrap, and redirect require separate
   accepted proposals and do not appear as v1 intent values. C/Swift/vtable
   declaration shapes are forward-visible, but their runtime capabilities
   remain false until their owning resolution profiles and complete corpora are
   accepted.

## 18. Global stopping criteria

The implementation is not complete if any of these is true:

- a semantic query, pointer slot, selector spelling, class name, category order,
  candidate order, registration order, or knowledge overlay silently chooses a
  runtime entity;
- duplicate semantic entities are deduplicated after graph or ID construction,
  observations are discarded, same-named distinct addresses merge, or logical
  methods sharing one IMP merge;
- equal selector spellings in one scope fragment by cstring/selref coordinate,
  or those storage observations are discarded;
- mapped-module bytes are decoded lazily, from an incomplete/non-atomic
  snapshot, or through hidden suspension, quiescence, double-read heuristics,
  or another process-control effect;
- a raw VA, path, mtime, version string, or presentation name becomes durable
  identity;
- a semantic entity path uses `.`, an image binding is implicit, a raw symbol
  is unquoted, a content digest is parsed as an integer or lacks its exact
  canonical width, or canonical printing emits anything other than `::` scope;
- source and equivalent JSON lower to different knowledge values or hashes, or
  produce different post-lowering diagnostics or reports;
- a semantic raw-mangled rename drops its replacement raw identity, an explicit
  raw-symbol rename changes any non-symbol field or resolves other than exactly
  one declaration, a convention profile supplies a callable ABI, a layout
  profile supplies a slot calling convention, or an address-bearing variant
  lacks exact architecture and content identity;
- several image bindings are captured by sequential single-module reads, an
  internal or external binding is adopted by basename/load order/dependency
  traversal, or a changed binding set survives R0/R1 refresh;
- a knowledge overlay overwrites cartridge evidence or a rename claims identity
  across builds;
- an authored profile/template operation contains a process/module generation,
  snapshot digest, resolved entity/member ID, RVA, or apply guard;
- static Objective-C metadata claims current dispatch after swizzling or runtime
  registration;
- an ABI, ownership rule, hidden parameter, calling convention, mitigation, or
  provider export is inferred to force compatibility;
- an Objective-C target ABI is compared as if it were the fixed HookContext
  handler ABI;
- an unsupported intent silently lowers to before-entry observation;
- missing/degraded handling bypasses identity, cardinality, ABI, integrity,
  review, barrier, signing, rollback, or evidence;
- a disabled required dependency is treated as degradation;
- a strategy wins because it was first, a fallback crosses groups or cycles, or
  a reduced outcome does not partition its feature operations;
- one feature composes distinct active reduced outcomes, or a triggering
  unavailable operation remains in the effective retained set;
- hidden captures escape their exported schema, a destination is not bound to
  the selected export's capture-interface digest, or arbitrary bytes gain a
  typed ABI through annotation alone;
- templates remain dynamic at runtime or recursion/expansion is unbounded;
- a template has no typed invocation/argument closure, an expanded operation ID
  collides, a complete invocation identity is duplicated, a
  parameter/invocation survives expansion, a template expands to a strategy
  group, or template-definition, argument, expanded-graph,
  authored-operation, or resolved-operation digests do not reconstruct from
  their fixed preimages;
- a reduced outcome, feature/strategy outcome, checkpoint row, handler binding,
  lowering, or report keys an expanded operation by bare local ID;
- generic Process edits allocate, inject, hook, or call target code;
- a cartridge, semantic resolver, provider, or adapter mutates the target or
  declares its own success;
- on-disk Objective-C mutation ships without complete relocation, fixup,
  layout, integrity, and signing semantics;
- multi-action instrumentation is reported as one atomic Plan;
- a handler library generation is predicted before its load receipt or a
  resident generation is accepted without exact artifact evidence, a
  multi-export workflow has only one handler-symbol binding, R0/R1 omits an
  operation row or fixed preimage field, R1 omits refreshed evidence, or one
  consumed lowering authorizes several actions;
- current dispatch lowers without the reviewed Objective-C guard, guard
  observation happens outside the retained Hook v1 barrier, the barrier is
  released before install, the barrier fails to exclude target/loader dispatch
  mutation, capture epoch/evidence is hashed into stable guard state, a full
  guard observation is discarded, or a provider observation is trusted as a
  verdict;
- feature selection is injected into a closed downstream artifact instead of
  linked through exact digests, or semantic evidence cannot be reconstructed;
- rejected semantic info omits its invalid-request digest, or target loss
  erases an earlier durable/uncertain effect instead of producing `partial`;
- native semantic hook success is claimed while canonical instrumentation remains
  unsupported, gated, or absent from ordinary CI;
- structural generation, stale archive completion markers, phrase matching,
  adapter self-report, or a Cargo lock wait is accepted as conformance; or
- the implementation modifies or normalizes unrelated dirty-tree work to make
  its gates pass.

## 19. Deliberate historical non-adoptions

The following archive ideas are intentionally not part of this proposal:

- **Files as functions, partial program values, and `<<`.** Current entries,
  phases, imports, typed parameters, pipelines, CLI binding, and fixture tests
  already carry the practical value without adding dynamic program authority.
- **A new universal `when`.** The section 7.1 spelling is a closed build-variant
  selector available only inside semantic knowledge images. It does not become
  a general executable condition. Current `require`, phase conditions, exact
  invocation parameters, cartridge guards, and instrumentation admission
  remain established authorities. Feature selection and missing policy compile
  to typed model values rather than a second executable predicate language.
- **In-language provider loading.** Provider artifacts remain explicit,
  digest-bound instrumentation inputs with separate reviewed load actions.
- **ABI inference.** The archive suggested importing exports without a config
  block. This proposal requires an explicit provider interface.
- **First-match fallbacks.** Alternative strategies evaluate completely against
  one snapshot and enforce cardinality before effects.
- **Generic recursive Carve for Objective-C parsing.** Objective-C metadata is a
  cartridge format responsibility with bounded typed parsing and an independent
  oracle. Current Carve remains acyclic.
- **Unordered mutation as an optimization promise.** Current phase snapshot and
  overlap rules remain. An implementation may parallelize only where existing
  semantics already make order unobservable.
- **Inline host-language bodies and arbitrary remote calls.** These remain out
  of scope.
- **Multi-image mutation atomicity.** A coherent read-only module-snapshot set
  does not turn several instrumentation actions into one atomic mutation.
  Existing per-target and per-action boundaries are reported honestly.

## 20. Definition of done

Release A file recovery is done only when its contract is canonical, the
file-applicable cases in S02–S08, S19, and S20 pass through the unfiltered stock
adapter, Macho is revision/SBOM pinned, `splice inspect --locator` exposes every
candidate and observation without mutation, repeated output is deterministic,
and `mise run ci` contains the semantic dependency/oracle gates. Mapped-module
activation is an additional claim requiring all module-applicable S04/S08/S20
cases and the stock backend's atomicity/no-effect profile; unsupported is the
only valid status before then.

Release B authoring is done only when every authored and generated schema is
closed; the semantic source parser, canonical printer, source compiler, JSON
validator, toolkit, `check`, `info`, and semantic CLI share one lowering; every
valid source fixture equals its canonical JSON pack byte for byte; every
invalid scope, binding, variant, digest, location, symbol, ABI, convention, and
rename fixture rejects before target access; S01 and S09–S18 pass; R0/R1
handles are non-serializable; each R0 handle is consumed by at most one
handler-resume transition; and each R1 expanded operation lowering is
single-use. Authored operations are target-free and image-bound, and every
resolved operation binds its expanded identity, graph/authored digest, runtime
scope, source image binding, executable snapshot, and reconstructible resolved
digest. Every template invocation has a unique complete invocation identity
and is fully expanded through one of the four exact parameter
sites, every graph/R0/R1 row and preimage digest reconstructs,
each degraded feature has one
effective reduced outcome that omits all triggers, every retained operation has
one full-identity-keyed export binding, exact RVA-plus-guard lowering equals the independently authored
revised Hook v1 request, reports conserve every
entity/observation/feature/checkpoint/action verdict and reconstruct their
evidence digest, and every unsupported historical intent is rejected as invalid
v1 input.

Native activation is a separate claim. It is done only when the existing
instrumentation portable and applicable native gates pass for every semantic
success path, the runtime observer revalidates current dispatch through the
fixed provider guard operation inside the retained apply barrier, the
supervisor compares only stable dispatch state while retaining every fresh full
observation and provenance before same-barrier install, crash/rollback/target-gone
cases conserve effects, and the specialized gates run in ordinary local and
hosted CI.

No release is done by generated counts, stale completion markers, phrase
matching, a skipped applicable profile, adapter self-report, or a Cargo lock
wait. No gate may be made green by weakening existing v1 behavior or touching
unrelated dirty-tree work.

## 21. Item 3 — RT-C01–RT-C16 conformance proof closure

**Scope:** agent-executable closure contract for item 3 of the RTTI R004 gap
audit. This section refines Plan 0006 sections 8, 9, 9.1, and 11 without
redefining the runtime-type ontology, public query surface, or capability
semantics.

### 21.1 Outcome and completion boundary

This section replaces the current label-based RTTI test ledger with an
independently verifiable conformance system for RT-C01 through RT-C16. Each
family receives its prescribed positive proof, a deliberately invalid case for
each material failure mode, exact fixture and mutation provenance, and an
executable test identity. A test may claim a family only through one or more
case rows that satisfy that family's minimum proof.

The completed system answers four different questions without conflating them:

1. Did the production decoder, graph, query, report, snapshot, or guard produce
   the independently authored expected result?
2. Did every malformed or hostile input produce the exact diagnostic and
   effect prescribed by the family?
3. Is the evidence applicable to the declared language, architecture,
   capability profile, and file/module/native observation mode?
4. Does the repository contain and execute every test, fixture, mutation, and
   generated projection named by the closed registry?

This section owns the complete proof shape for all sixteen families. It also
owns the file, module-snapshot, and native evidence needed by RT-C14 and
RT-C15; those families are not permitted to pass on mocks, recorded reports,
or portable-only evidence.

This necessarily crosses the R004 implementation boundary discovered by the
audit. Plan 0006 assigns coherent mapped-module graphs to R005 and native guard
execution to R006. An implementation restricted to the current R004 query/CLI
surface can truthfully register RT-C14/RT-C15 as gated, but cannot call item 3
or all-family coverage complete. C008 and C009 therefore consume the real
R005/R006 prerequisites instead of manufacturing R004 substitutes.

Two separately assigned implementation items remain visible completion
dependencies rather than hidden deferrals:

- `gated:rtti-arm64e-corpus` supplies the missing arm64e partition described by
  item 4. This section fixes its manifest, oracle, schema, and verifier obligations
  now. The complete R004 matrix gate cannot pass while that partition is
  absent.
- `gated:rtti-cli-positive-matrix` supplies the full language-by-operation
  spawned CLI matrix described by item 5. This section proves the query/report
  semantics in RT-C13 and fixes the journey manifest and verifier obligations
  now. The complete R004 gate cannot pass while that journey matrix is absent.

The markers gate execution work only. They do not permit omitted schema arms,
capability vocabulary, invalid cases, diagnostics, verifier opinions, or
completion checks.

Item 3 closes the RT-C family-proof dimension: all sixteen minimum proofs must
execute on every baseline profile applicable to the family, including the real
module/native profiles required by RT-C14/RT-C15. Items 4 and 5 then close two
orthogonal expansion dimensions: the remaining arm64e partition and the full
spawned-CLI positive matrix. A focused `rtti-family-conformance` command may
pass after item 3 while those forward obligations remain visibly blocked.
Plan 0006's strict `rtti-conformance` command may not pass until all three items
are complete. This distinction permits the requested work order without
misreporting Plan 0006 closure.

The item 3 baseline profiles are closed:

- file inspection over the registered arm64 and x86_64 fixtures;
- coherent module inspection on Darwin arm64 and Darwin x86_64;
- native guard execution on Darwin arm64 and Darwin x86_64; and
- the minimum authenticated-pointer snapshot/native fixtures required to prove
  RT-C14/RT-C15 pointer-authentication drift on an accepted arm64e-capable
  Darwin arm64 runner.

Item 4 owns the complete arm64e Swift/Objective-C/C++ file-corpus expansion. It
does not own or defer the narrower authenticated runtime proof already required
to make RT-C14/RT-C15 true.

### 21.2 Authority and conflict rules

The authority order for this work is:

1. Plan 0006 sections 2 through 9.1 own RTTI semantics and the RT-C01–RT-C16
   minimum proofs.
2. Plan 0006 section 11 owns the named public acceptance commands.
3. This section owns the concrete conformance registry, fixture classes, oracle
   boundary, mutation accounting, test discovery, and completion behavior.
4. `spec/semantic/rtti/schema.py` remains the authored source for public RTTI
   schemas; its generated v2 projections remain outputs.
5. `spec/conformance/semantic/rtti/registry.json` becomes the reviewed authored
   source for RTTI conformance cases. Generated indexes and reports are outputs
   and are never hand-edited.

Development dependency override (2026-07-23): until the Mach-O `0.4.0` leaves
are published, repository-local implementation and family-proof work may use
only the exact sibling paths `../macho/crates/macho-{core,dyld,objc,swift,cpp}`
and `../macho/crates/macho-mutate`, with version `=0.4.0` and the same closed
feature sets required of the eventual public packages. The dependency audits
must reject every other path, version, Git source, or feature set and must
verify the sibling workspace/package manifests plus path-bound lock entries.
This override removes source availability as a local Item 3 implementation
blocker; it does not satisfy public registry or release provenance. Release
closure must replace the paths with exact checksum-bound crates.io `0.4.0`
dependencies and rerun the public dependency audit.

If a current test or fixture disagrees with either plan, the test or fixture is
insufficient evidence. It does not weaken the family definition. If a family
cannot be proved on the available provider or host, its status is
`blocked_prerequisite`; it is not omitted, skipped, or counted as a pass.

### 21.3 Observed baseline and required disposition

The following statements describe the working tree inspected while authoring
this plan. They are implementation inputs, not acceptance evidence:

- `spec/conformance/semantic/rtti/r004-ledger.json` names seven tests and six
  mutations. Its broad test rows attach family labels but do not identify the
  exact minimum-proof clause, fixture, expected result, diagnostic, or killed
  mutation.
- RT-C04, RT-C14, and RT-C15 have no claimed executable evidence. Several other
  families have a label but not their complete minimum proof.
- `spec/conformance/semantic/rtti/oracle.py` validates source tokens, digests,
  two Mach-O CPU headers, and hard-coded summary counts for a single C++
  fixture. Its selftest mutates those same constants rather than exercising
  production inputs and comparing full expected graphs.
- `spec/conformance/semantic/rtti/fixtures/manifest.json` records one C++ source
  fixture for arm64 and x86_64. It is useful evidence for part of RT-C07–RT-C10,
  not the prescribed Swift/Objective-C/C++ corpus.
- The repository already contains reusable Swift arm64, arm64e, and x86_64
  artifacts and Objective-C arm64/x86_64 positive and negative fixtures under
  `spec/conformance/semantic/`. They may be imported by reference only after
  their source, build provenance, profile, hashes, expected RTTI facts, and
  applicable family cases are registered.
- `verify_r004_ledger()` currently checks operation spelling, mutation-list
  equality, known family identifiers, one negative marker, sorted identities,
  and equality with discovered tests. It does not prove family completeness,
  positive/negative balance per family, mutation kills, fixture freshness,
  architecture applicability, capability truth, or oracle independence.

Implementation therefore performs these migrations:

- Replace `r004-ledger.json` as an authored file with a generated case/test
  index derived from `registry.json`. Retain the filename only if an existing
  consumer needs it; if retained, its schema advances and its generated status
  is explicit.
- Replace the current monolithic `oracle.py` checks with a small dispatcher over
  independent expected-graph and expected-failure documents. Summary counts
  remain permitted only as secondary invariants.
- Retain the current C++ fixture and existing semantic fixtures as source-backed
  corpus inputs. Do not describe any one of them as the complete corpus.
- Move policy out of `apps/xtask/src/semantic.rs`: xtask invokes the independent
  generator/verifier, discovers the exact executable tests, and runs the named
  gates; it does not become a second RTTI engine or oracle.

### 21.4 Closed conformance model

#### 21.4.1 Authored registry

`spec/conformance/semantic/rtti/registry.json` has a schema-owned closed shape
with these top-level registries:

```text
families              RT-C01 through RT-C16, exactly once and in order
capability_profiles   file, closed-module-snapshot, and native-guard profiles
architectures         arm64, arm64e, and x86_64
fixtures              source, build, artifact, observation, and license facts
expected_results      independently authored graph/query/report/failure facts
mutations             exact mutation operators and expected effects
cases                 atomic positive or negative proof obligations
tests                 fully qualified executable test identities
journeys              spawned CLI matrix rows consumed by item 5
forward_obligations   typed item 4/item 5 execution rows and blockers
```

The registry schema closes all discriminants. Unknown keys, kinds, languages,
architectures, profiles, family IDs, diagnostic codes, query operations,
mutation effects, and applicability states reject.

Each family row declares:

```text
id
title
minimum_proof_clauses[]
required_modes[]                 file | module_snapshot | native_guard
required_languages[]
required_capability_profiles[]
required_schema_arms[]
required_diagnostics[]
```

Each case is atomic. It declares one family, one minimum-proof clause, one
polarity, one observation mode, one or more fixtures, one expected result, and
one or more executable tests. Negative cases additionally name exactly one
primary mutation and the exact diagnostic/effect that kills it. A broad test
may execute many cases, but the generated index expands it into case rows; the
test name alone never establishes coverage.

Test rows declare a closed runner kind (`rust_test`, `spawned_cli`, or
`native_conformance`), package or job owner, discovery selector, and fully
qualified identity. Forward-obligation rows may carry `execution: gated` and
no test identity before item 4 or item 5 is implemented; they remain blockers
in the full matrix report and cannot contribute to family coverage or a
capability verdict.

Each fixture row declares:

```text
fixture_id
language                           swift | objc | cxx | cross_language
architecture                       arm64 | arm64e | x86_64
mode                               file | module_snapshot | native_guard
source_paths[]
build_recipe
compiler_and_runtime_profile
artifact_paths[]
sha256_by_path
license_and_redistribution
expected_result_ids[]
```

Generated artifacts additionally carry the generator version and input digest.
Hand-authored hostile byte fixtures carry a construction description and an
independent parser-level assertion that the intended damage is present.

#### 21.4.2 Applicability and verdicts

Case status is one of:

- `pass`: applicable evidence executed and matched the independent expectation;
- `fail`: applicable evidence executed and disagreed;
- `blocked_prerequisite`: the required dependency, architecture, provider,
  native runner, or separately assigned execution item is unavailable;
- `not_applicable`: permitted only when the family row excludes the profile by
  construction.

`blocked_prerequisite` is durable reporting, not acceptance. The strict
`rtti-conformance` command exits nonzero if any required case is failed,
blocked, missing, duplicated, stale, or unexpectedly not applicable.
`rtti-family-conformance` applies the same rule to RT-C minimum-proof cases but
does not convert item 4/item 5 forward-obligation blockers into family
failures.

Capabilities are computed from passed case sets. A registry author cannot set
a capability to true. In particular, file graph proof cannot activate a module
snapshot capability, and neither can activate a native guard capability.

### 21.5 Production-independent oracle

The oracle boundary is structural, not organizational:

- Expected graphs, query results, reports, and diagnostics are authored from
  source semantics, ABI/runtime documentation, and deliberately constructed
  byte facts. Production RTTI decoders, graph builders, query evaluators,
  serializers, and their snapshots never generate or refresh expectations.
- Expected graphs record every relevant entity, structural key component,
  relationship, completeness state, conflict, external reference,
  observation, diagnostic, and conservation total. Stable symbolic coordinates
  are used where addresses vary by build. Display names and aggregate counts
  are never sufficient identity.
- A small oracle normalizer resolves only declared fixture-local symbols and
  coordinates into stable symbolic values. It cannot discard unknown records,
  sort away multiplicity, merge same-name entities, or turn partial evidence
  into complete evidence.
- Production output is serialized through the public JSON report path,
  validated against the generated public schema, normalized, and compared to
  the independent expectation. Text output is checked as a deterministic view
  of that already validated report.
- Expected failures name the diagnostic code, affected record/entity, evidence
  coordinate, completeness transition, and whether any usable result is
  forbidden. Message substrings are supplementary and never the sole oracle.

The oracle selftest attacks its own trust boundary. It must reject an expected
graph produced by a production module, an unregistered normalizer rule, a
missing entity or edge, an extra unknown record, collapsed multiplicity,
changed completeness, stale hashes, an undeclared toolchain, a reordered
ordered field, and a mutated diagnostic/effect pair.

### 21.6 Required family proof matrix

The following rows are indivisible completion obligations. “Reuse” means the
current artifact can become an input after registration; it does not mean the
current test already proves the row.

| Family | Required positive evidence | Required hostile evidence |
|---|---|---|
| RT-C01 Structural identity | Same leaf name in distinct modules and lexical scopes; same executable address used by distinct implementations; repeated base subobjects; identical logical type across distinct module/process generations. Every entity remains separately addressable. | Cross-scope alias, forged generation, duplicate structural key, and hash-collision simulation reject or remain explicitly ambiguous; presentation order never selects. |
| RT-C02 Strict decoding | For every admitted Swift, Objective-C, and Itanium record kind, attempted equals included plus unknown plus excluded, with exact provenance and no silent loss. | Malformed lengths, counts, discriminants, relative/fixup pointers, unsupported kinds, budget exhaustion, and trailing loss each produce their exact diagnostic and no usable truncation. This family remains blocked while the strict public Mach-O dependency audit is red. |
| RT-C03 Swift definitions | Registered nominal-context, generic, resilient, enum, field, and mangled-type fixtures reproduce complete expected definition graphs across applicable architectures. Existing Swift semantic artifacts are candidates for reuse. | Damaged context chains, field/case pointers, generic signatures, resilient references, and unknown context/type-expression kinds retain exact diagnostics and completeness effects. |
| RT-C04 Swift instances and layout | File evidence proves prespecialized/already-materialized metadata instances separately from definitions. A native no-effect fixture observes already-realized metadata bounds, generic arguments, field offsets, layouts, and value witnesses without invoking metadata accessors or allocating target memory. | A fixture whose metadata would require realization must stop as unavailable; accessor-call, allocation, target write, generation drift, and definition/instance collapse detectors must kill the case. |
| RT-C05 Swift conformance | Conditional requirements, associated types, witness mappings, patterns, and accessor references reproduce full expected graphs and provenance. Existing conditional-conformance artifacts are candidates for reuse. | Corrupted requirement, associated-type, witness, pattern, and accessor pointers remain conserved with exact failure effects; unavailable accessors never execute. |
| RT-C06 Objective-C graph | Class/metaclass pairs, categories, protocols, ivars, properties, encodings, strong/weak layouts, inheritance, duplicate selectors, shared IMPs, and static versus already-realized dispatch reproduce expected graphs. | Cyclic inheritance, malformed lists/encodings/offsets, broken fixups, realization drift, selector aliasing, and class/metaclass collapse stop or remain explicitly incomplete. |
| RT-C07 C++ typeinfo | Every admitted Itanium `type_info` family and qualifier, weak/external RTTI, stripped-symbol recovery, and `-fno-rtti` absence has an oracle result. The current world-class fixture supplies only a subset. | Malformed typeinfo counts/offsets/pointers, unsupported relative-vtable ABI, unresolved external RTTI, and forged kind discriminants have exact outcomes. |
| RT-C08 C++ subobjects | No, single, multiple, virtual, repeated, and diamond inheritance retain primary/secondary/virtual subobject identities and exact offset semantics. | Deleted base edges, repeated-base aliasing, invalid virtual-base offsets, cycles, and offset overflow cannot yield a complete hierarchy. |
| RT-C09 Vtable groups | Primary and secondary tables, address points, headers, vcall/vbase entries, slots, construction vtables, and VTT membership reproduce the complete expected group. | Missing/reordered table members, forged address points, redirected VTT members, malformed counts, and out-of-range entries stop or make the exact scoped component incomplete. |
| RT-C10 Thunks and destructors | This/return/covariant adjustments, pure/deleted entries, complete/deleting destructor pairs, slot roles, routes, and shared implementations remain distinct. | Redirected routes, collapsed destructor roles, erased adjustments, callable-ABI mismatch, and executable-looking non-implementations reject. |
| RT-C11 Layouts | Static, resilient, runtime, unknown, partial, and conflicting layout claims produce stable typed values, provenance, and coverage wording. | Conflicting offsets/sizes, definition-instance substitution, forged complete status, overflow, and omitted-count underreporting cannot yield complete wording. |
| RT-C12 Bridges | Swift/Objective-C identity and dispatch aliases are backed by explicit cross-language evidence while both definitions remain distinct. Existing Swift Objective-C alias artifacts are candidates for reuse. | Same spelling, shared implementation, or coincident address without bridge evidence never merges definitions; redirected bridge evidence and generation mismatch reject. |
| RT-C13 Queries and reports | Every list/show/hierarchy/layout/members/conforms/dispatch/bridges/evidence query proves zero, exactly-one, and ambiguity behavior; entity queries bind the graph digest; JSON validates; text is deterministic; conflicts, omissions, and coverage survive. | Unknown operation/filter/schema arm, stale digest, unbound entity ID, ambiguity suppression, partial graph used for resolution, nondeterministic order, JSON/text disagreement, and capability/report disagreement reject. Full spawned language-by-operation journeys arrive through `gated:rtti-cli-positive-matrix`. |
| RT-C14 Module snapshots | A closed mapped-image set reconstructs the same graph repeatedly from one coherent snapshot and records module/process generations, image membership, fixups, pointer-authentication state, and observation provenance. No file-only or open-ended module enumeration counts. | Added/removed image, generation change, mixed snapshot, fixup change, stale observation, and pointer-authentication drift reject before resolution. |
| RT-C15 Runtime guards | On an exact accepted native profile, Swift class, Objective-C dispatch, and C++ vtable guard arms bind definition → instance/object → subobject → table/address point → slot → route → implementation → callable ABI inside the consumed exclusive barrier. Receipts reconstruct after success, failure, and recovery. | Barrier loss, any route-component drift, wrong guard arm, pointer-authentication failure, crash boundary, failed readback, rollback failure, and receipt mismatch prevent capability activation. Portable providers, mocks, and recorded reports are inapplicable. |
| RT-C16 Limits and conservation | Every default and hard limit named by Plan 0006 has zero, exact-boundary, and one-over-boundary cases with deterministic accounting and termination. | Negative/overflow values, cycles, duplicates, collisions, hostile diamonds, recursive types, generic explosions, malicious lengths, evidence growth, and no-usable-truncation attacks fail with exact diagnostics and bounded work. |

### 21.7 Architecture, language, and journey cross-product

The registry generator computes required coverage instead of storing a claimed
total. The required product is derived from each family's declared languages,
modes, and architectures, with explicit exclusions only where ABI/runtime
semantics are genuinely inapplicable.

Every required file-corpus fixture class has coverage rows for arm64, arm64e,
and x86_64. A source may be shared across architectures, but never its build
provenance, artifact hash, or architecture-sensitive pointer/fixup facts.
Individual hostile artifacts need not be mechanically triplicated when the
failure is architecture-independent, but each architecture partition must
contain applicable positive and hostile evidence and the registry must explain
every excluded cross-product cell. Item 4 completes the missing arm64e
artifacts and hostile cases; until then the generated report lists their exact
obligation IDs as `blocked_prerequisite(gated:rtti-arm64e-corpus)`. These rows
do not contribute to item 3's family-proof verdict; they do prevent strict
R004 matrix closure.

RT-C13 additionally generates this required positive CLI matrix:

```text
(swift | objc | cxx) ×
(list | show | hierarchy | layout | members | conforms | dispatch | bridges | evidence)
```

Each cell is either an exact positive journey or an authored
`not_applicable` rule justified by the query contract. A query returning a
valid empty result can be positive evidence; replacing an applicable cell with
`not_applicable` cannot. Every journey uses a real registered artifact, spawns
the built CLI, validates JSON, checks the canonical text projection, and
records the graph digest. Item 5 implements these rows; the registry and gate
shape land under this plan.

### 21.8 Mutation execution and kill accounting

Mutations are executable operators, not names copied between JSON files. The
registry assigns each operator to exactly one layer:

- source/build mutations create ABI features or declared omissions;
- byte mutations damage records, pointers, fixups, counts, authentication, or
  bounds in copied fixture bytes;
- observation mutations alter closed snapshot membership, generations,
  barriers, or native readback;
- graph mutations attack identity, edges, completeness, routes, layouts, and
  evidence conservation after decoding but before public query evaluation;
- query/report mutations attack binding, ambiguity, deterministic ordering,
  schema arms, coverage wording, and JSON/text equivalence.

Each negative case records `mutation_id`, `operator_version`, input digest,
output digest or observation delta, expected diagnostic/effect, and killing
test. The verifier requires every registered mutation to be killed by at least
one applicable executable case and every negative case to kill its declared
mutation. Mutations that accidentally leave the target unchanged reject as
invalid test setup.

Mutation operators write only to a temporary directory. Generated corpus
artifacts and source fixtures remain immutable during checking.

### 21.9 Generator, verifier, and report

#### 21.9.1 Files and ownership

Implementation adds or reshapes these authored surfaces:

```text
spec/conformance/semantic/rtti/registry.schema.json
spec/conformance/semantic/rtti/registry.json
spec/conformance/semantic/rtti/expected.schema.json
spec/conformance/semantic/rtti/conformance-report.schema.json
spec/conformance/semantic/rtti/expected/**/*.json
spec/conformance/semantic/rtti/fixtures/**
spec/conformance/semantic/rtti/invalid/**
spec/conformance/semantic/rtti/mutations.py
spec/conformance/semantic/rtti/oracle.py
spec/conformance/semantic/rtti/generate.py
spec/conformance/semantic/rtti/verify.py
spec/conformance/semantic/rtti/generated/case-index.json
spec/conformance/semantic/rtti/generated/fixture-manifest.json
spec/conformance/semantic/rtti/generated/journey-matrix.json
```

`generate.py` is the sole writer for the three files under `generated/`.
`verify.py` independently reconstructs those outputs from the authored
registry and filesystem. Neither imports production Rust code or
production-generated expectations. `r004-ledger.json` is removed after its
consumers migrate; if a compatibility projection is temporarily required, the
generator is its sole writer and the verifier requires exact equality with
`case-index.json`.

The final run writes a deterministic report to
`target/conformance/rtti/report.json`. It includes registry and artifact
digests, toolchain/profile identity,
case totals by family/polarity/language/architecture/mode, mutation kills,
test-discovery reconciliation, capability verdicts, and exact blockers. It
contains no wall-clock value in its canonical digest.

#### 21.9.2 Verifier opinions

The verifier rejects all of the following:

- a missing, duplicate, reordered, or unknown RT-C01–RT-C16 family;
- a minimum-proof clause with no positive case or no applicable hostile case;
- a case with no fixture, expectation, test, schema arm, or applicable
  capability profile; a positive case with no expected success effect; or a
  negative case with no exact diagnostic/failure effect;
- a broad family claim that is not decomposed into minimum-proof case rows;
- an unknown, unused, unchanged, multiply defined, or surviving mutation;
- a stale source, build recipe, artifact, expectation, or generated digest;
- an expectation generated or refreshed by a production decoder;
- an unlicensed or non-reproducible distributable fixture;
- a missing required architecture/language/mode cell or an unjustified
  `not_applicable` cell;
- file evidence used for RT-C14, or file/mock/portable/recorded evidence used
  for RT-C15;
- a capability marked active before every required case passes on its exact
  profile;
- a test discovered under an owned RTTI target but absent from the registry, a
  registered test absent from discovery, duplicate ownership, or zero matches;
- a partial graph used for exact resolution, an unbound graph entity ID, or a
  report whose coverage wording exceeds its evidence;
- a JSON report that fails schema validation or canonical text that does not
  lower from that report;
- any failed or blocked required case when strict acceptance is requested.

Oracle independence is checked mechanically: expectation files have no writer
in `generate.py`; the oracle and verifier import no workspace production
module; an allowlist closes their imports; and the boundary check rejects any
production path that writes under `expected/`.

#### 21.9.3 Verifier selftest

`verify.py selftest` makes one isolated hostile copy for every verifier opinion
above and proves the expected rejection code. It also executes at least one
real operator from every mutation layer. A selftest that only edits registry
constants is insufficient.

Adding a verifier rejection code requires adding its hostile selftest in the
same change. Removing or weakening an opinion requires an explicit update to
this plan or its successor; implementation may not relax the verifier merely
to admit a current fixture.

### 21.10 Dependency-ordered implementation work

These are dependency slices of one implementation, not calendar phases.

| ID | Work package | Depends on | Deliverable and negative stopping criterion |
|---|---|---|---|
| C001 | Freeze the case model | Plan 0006 | Add the closed registry schema, all sixteen family/minimum-proof rows, capability profiles, architecture/mode vocabulary, journey matrix, and authored invalid registry fixtures. Stop if any Plan 0006 clause has no machine-addressable row. |
| C002 | Migrate current evidence honestly | C001 | Register the current C++ and reusable Swift/Objective-C fixtures with exact provenance; expand the seven broad test claims into atomic cases or remove unsupported claims. Stop if any generated claim exceeds observed evidence. |
| C003 | Build the independent oracle | C001 | Add full expected graphs/failures, strict normalization, public-report differential comparison, and oracle self-attacks. Stop if production code can generate or refresh an expectation. |
| C004 | Complete Swift proof | C002, C003, strict Mach-O leaf inputs | Implement RT-C03–RT-C05 positive and hostile cases, including already-realized instance/layout no-effect evidence. Stop if RT-C04 invokes a metadata accessor or substitutes a definition for an instance. |
| C005 | Complete Objective-C proof | C002, C003, strict Mach-O leaf inputs | Implement RT-C06 and the Objective-C portions of RT-C01/02/11/12/16. Stop if static and realized dispatch or class and metaclass collapse. |
| C006 | Complete C++ proof | C002, C003, strict Mach-O leaf inputs | Expand the world-class fixture set to every admitted typeinfo/subobject/vtable/thunk/destructor case for RT-C07–RT-C10. Stop if relative-vtable rejection, no-RTTI, external RTTI, construction tables, or VTTs lack exact outcomes. |
| C007 | Complete shared graph/query/limit proof | C004–C006 | Implement cross-language RT-C01/02/11–RT-C13/16 cases, deterministic JSON/text differential checks, exact limits, and all query outcome states. Stop if a partial graph can satisfy exact resolution. |
| C008 | Complete coherent module proof | C004–C007, Plan 0006 R005 implementation | Implement RT-C14 against closed mapped-module snapshot sets with generation/image/fixup/authentication drift attacks. Stop if an open-ended or mixed-generation set passes. |
| C009 | Complete native guard proof | C008, Plan 0002 accepted native provider, Plan 0006 R006 implementation | Implement RT-C15 on the exact native profile for Swift, Objective-C, and C++ arms, including barrier consumption, drift, receipts, crash, rollback, and recovery. Stop if any mock, portable provider, or recorded report contributes a pass. |
| C010 | Execute all mutation layers | C004–C009 | Implement and kill every mutation; generate the kill matrix. Stop on an unchanged mutation, surviving mutation, or negative case without an exact effect. |
| C011 | Integrate item 3 gates | C003, C010 | Replace the weak xtask ledger check, reconcile exact test discovery, add `rtti-family-conformance` and `rtti-native-conformance`, emit the deterministic report, and keep the strict R004 gate red on forward blockers. Stop on zero matches, family blockers, capability disagreement, or an item 4/item 5 blocker omitted from the report. |
| C012 | Whole-artifact rereview | C011 | Reread Plan 0006, this plan, registry, fixtures, oracle, mutations, schemas, reports, tests, forward journey obligations, module/native evidence, and all named commands from the beginning. Repair the complete finding set once and repeat the full review. Stop until a fresh sweep finds no material defect in item 3 and all item 4/item 5 blockers are exact. |

Work packages may be implemented concurrently only where their inputs are
already frozen. They merge through the registry and oracle contracts; no
package may invent a private family definition, fixture identity, or verdict.

### 21.11 Acceptance commands and exact meaning

The implementation preserves Plan 0006's named commands and C011 adds the
focused commands with the exact spellings below. The final public acceptance
surface is:

```bash
# Generated and independently reconstructed conformance authority
python3 spec/conformance/semantic/rtti/generate.py --check
python3 spec/conformance/semantic/rtti/oracle.py check
python3 spec/conformance/semantic/rtti/oracle.py selftest
python3 spec/conformance/semantic/rtti/verify.py check
python3 spec/conformance/semantic/rtti/verify.py selftest

# Upstream strict leaf authority
# Run in the pinned public macho producer source tree; Splice consumption does
# not require a sibling checkout.
cargo test --locked -p macho-swift
cargo test --locked -p macho-objc
cargo test --locked -p macho-cpp
cargo xtask verify

# Splice authority and product surfaces
cargo run --locked -p xtask -- rtti-dependency-audit
cargo run --locked -p xtask -- rtti-oracle
cargo run --locked -p xtask -- rtti-family-conformance
cargo run --locked -p xtask -- rtti-native-conformance --job darwin-aarch64
cargo run --locked -p xtask -- rtti-native-conformance --job darwin-x86_64
cargo run --locked -p xtask -- rtti-conformance
cargo test --locked -p splice-engine semantic_rtti
cargo test --locked -p splice-cartridge-macho semantic_rtti
cargo test --locked -p splice-cli --test semantic_rtti_journey
cargo run --locked -p xtask -- semantic-swift-conformance
cargo run --locked -p xtask -- instrumentation-conformance --profile portable
cargo run --locked -p xtask -- ci-native --job darwin-aarch64
mise run ci
```

The portable instrumentation command proves only that unsupported native RTTI
capabilities remain truthful. It does not prove RT-C15.
`rtti-native-conformance --job <job>` is the focused native RTTI command and
accepts only closed job IDs declared by the native CI matrix. `ci-native` must
invoke it on applicable Darwin jobs and execute the RT-C14/RT-C15 cases rather
than treating host presence as proof. Darwin arm64 covers the accepted arm64
and arm64e runtime profiles; Darwin x86_64 supplies its independent native
profile in the full CI matrix.

On a host where a case is structurally inapplicable, the registry's closed
profile rule may yield `not_applicable`; host detection alone cannot. On an
applicable Darwin profile, a missing provider, runner, fixture, or barrier is
`blocked_prerequisite` and fails that job. Item 3 completion is the conjunction
of the portable/file gate and both applicable Darwin native jobs, not a PASS
printed by one host for foreign evidence it did not execute.

`rtti-oracle` means the independent expected results, hostile inputs, and
oracle self-attacks pass. `rtti-family-conformance` means every item 3
RT-C01–RT-C16 minimum-proof case, mutation, exact test identity, and applicable
file/module/native profile passes. `rtti-conformance` means those cases plus
every required architecture partition and positive CLI journey pass. It is not
a focused R004 smoke test and must not print PASS while an item 4 or item 5
gate is blocked.

`mise run ci` is repository-local current-host closure. Cross-platform/release
closure still requires every host declared by `plans/README.md`; this plan does
not relabel one-host evidence as cross-platform completion.

### 21.12 Hard blockers and safe stops

Implementation reports and stops rather than weakening proof when:

- neither the exact authorized sibling Mach-O `0.4.0` development family nor,
  for release closure, the strict public `macho-swift`, `macho-objc`, and
  `macho-cpp` dependencies and their upstream verification are available and
  passing;
- a fixture lacks source, reproducible build provenance, redistribution
  authority, exact profile identity, or a stable artifact digest;
- an item 3 baseline fixture, coherent module case, or native guard case is
  incomplete;
- no closed coherent mapped-module provider exists for RT-C14;
- no accepted native provider, exact profile, exclusive barrier, receipt
  reconstruction path, or recoverable native runner exists for RT-C15;
- obtaining proof would require target execution during inspection, unsafe Rust,
  a second orchestration engine, a fabricated expectation, or a capability
  advertisement ahead of conformance;
- the dirty working tree prevents a required clean-tree native job. Existing
  work is not stashed, reset, or discarded to manufacture the run.

The deterministic report must also name the exact item 4/item 5 forward
obligation IDs while those items remain incomplete. It must never convert a
blocker into `not_applicable`, skip the case, reduce a required cross-product,
or lower the expected count.

### 21.13 Definition of done

Item 3 is complete only when all of the following are true:

1. The closed registry contains RT-C01 through RT-C16 and machine-addresses
   every minimum-proof clause in Plan 0006.
2. Every required clause has applicable positive and hostile evidence with
   source/build/artifact provenance, independent expectations, exact executable
   tests, schema arms, diagnostics/effects, and capability mappings.
3. Every prescribed Swift, Objective-C, and C++ fixture class needed by the
   RT-C minimum proofs has source-backed evidence on its applicable item 3
   baseline profiles. The registry also contains verifier-enforced forward
   obligations for every arm64e expansion owned by item 4.
4. RT-C14 passes only with repeatable closed snapshot-set evidence, and RT-C15
   passes independently on an accepted native provider/profile for all three
   guard arms.
5. Every material mutation is actually applied and killed; every verifier
   opinion has a hostile selftest.
6. Test discovery exactly equals the generated case/test index, with no zero
   matches, duplicates, stale names, unclaimed owned tests, or label-only
   claims.
7. Public JSON reports validate, canonical text is a view over the same report,
   and oracle differentials reproduce every applicable expected result.
8. `rtti-family-conformance` and the applicable
   `rtti-native-conformance --job` commands pass. The strict
   `rtti-conformance` report remains non-PASS only for the exact typed item 4
   and item 5 forward obligations, if those separately assigned items have not
   yet executed.
9. Every item 3 command in section 21.11 passes in its stated scope, and the
   final deterministic conformance report contains no failed or blocked RT-C
   family case and no active capability without its exact proof.
10. A fresh whole-artifact rereview finds no material defect after all repairs.

Seven tests with sixteen labels cannot satisfy this definition. Completion is
the executable proof graph described above, not a claimed family count.
