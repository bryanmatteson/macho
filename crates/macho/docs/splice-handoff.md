# Splice Handoff

This is the consumer contract for lowering Macho recovery into Splice. The
pre-release baseline is Program Fact IR schema `1` and recovery contract schema `1`.
There are no earlier public wire versions to migrate.

## Architecture boundary

`RecoveredProgram` is the only full-facts entry. `ProgramFactDocument` is its
strict durable form. `SelectedImageEvidence` is a leaf decoding port used below
program recovery; it is not a second program model.

```text
selected Mach-O bytes
        |
        v
SelectedImageEvidence (leaf implementation detail)
        |
        v
RecoveredProgram <---- complete RecoveryGuide compiled from a Splice branch
        |
        +---- ProgramFactDocument (durable Mach-O Fact IR)
        |
        v
Splice lowering ----> Splice product IR ----> edits, branches, queries, mutation
```

Macho owns selected-image identity, format and language decoding, joined
program recovery, completeness, questions, guide validation, and fact
authority. Splice owns product semantics, the edit database and branch model,
lowering policy, presentation, cross-format concepts, and mutation policy.

Do not reconstruct CFG, xref, function, or language facts from
`SelectedImageEvidence` in Splice. A deliberately narrow feature that needs one
leaf and no joined program may import `macho::evidence`; the main Splice
pipeline must use `macho::analysis`.

## Dependency and imports

Enable the `analysis` feature. It includes the program recovery and recovery
wire surfaces as well as the evidence implementation used internally:

```toml
[dependencies]
macho = { /* pinned pre-release source */, default-features = false, features = ["analysis"] }
```

Import consumer types from the stable facade instead of reaching through
private implementation modules:

```rust
use macho::analysis::{
    ProgramFactAuthority, ProgramFactDocument, ProgramRecoveryLimits,
    ProgramRecoveryRequest, ProgramRecoveryStage, ProgramStageStatus,
    RecoveredProgram, RecoveryGuide,
};
```

The facade also exports coverage, completeness, questions, decisions,
application receipts, deltas, subject keys, and borrowed program views needed
by lowering.

## Cold recovery and persistence

Recover all stages for the canonical full-facts path, or construct a selective
request when the resulting absence is intentional and represented in the
product state:

```rust
let bytes = std::fs::read(input_path)?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no Mach-O image")?;

let request = ProgramRecoveryRequest::all(ProgramRecoveryLimits::default());
let program = RecoveredProgram::recover(image, request)?;
let document = program.to_fact_document();
std::fs::write(facts_path, document.to_json_pretty()?)?;
```

For universal binaries, Splice must select one thin image before recovery and
retain that architecture choice with the source artifact. The Fact IR identity
binds SHA-256 content, byte length, CPU type, and CPU subtype. One document
always describes exactly one selected thin image.

The Fact IR does not contain Mach-O bytes. Keep the source bytes available in a
content-addressed blob or another immutable artifact store when a branch may be
refined or deepened. A relocated Fact IR file remains safe to inspect offline,
but it cannot re-decode itself.

## Offline load and lowering

Always use the strict loader and reconstruct the public program view before
lowering. Do not scrape private Rust fields or treat the ordinary CLI report
envelope as Fact IR.

```rust
let bytes = std::fs::read(facts_path)?;
let document = ProgramFactDocument::load_json(&bytes)?;
let program = RecoveredProgram::from_document(document)?;

lower_into_splice(&program)?;
```

`load_json` rejects unknown fields recursively and validates the exact schema,
recovery contract, image identity, request closure, payload presence, stage
limits, completeness, coverage, questions, and guide provenance. The raw file
written by `to_json_pretty` is a `ProgramFactDocument`; CLI JSON output instead
places that document inside the command report envelope.

Persist at least these values with each lowered Splice revision:

- the raw `ProgramFactDocument` or its content-addressed object ID;
- the selected source-image object ID and architecture selector;
- the Splice product IR revision;
- the complete Splice edit branch used to compile the retained guide.

The document already retains the applied guide and its application/provenance
receipt. Splice may index receipt fields separately, but the document remains
the authoritative Macho-side state.

## Lowering rules

Use public readers such as `image`, `completeness`, `coverage`, `questions`,
`facts`, `functions`, `control_flow`, `xrefs`, `pointers`, `annotations_at`,
`function_by_entry`, and `reference_owner`. Use `facts().disassembly_inputs()`
when lowering requires the complete typed prerequisite bundle.

For every consumed stage, inspect `stage_status(stage)`:

| Status | Splice interpretation |
| --- | --- |
| `Absent` | The stage was not selected. It is unknown, not an empty result. |
| `Complete` | Macho completed the stage's declared examined universe. |
| `Partial` | Retained facts are useful, but unresolved evidence remains. |
| `Truncated` | A declared budget omitted evidence; retain the facts and an open frontier. |

Completeness is not authority. Preserve both axes independently. For retained
structural subjects, call `subject_authority(subject)` and distinguish
`Independent` from `Guided`; `None` means that subject is not present. For
reference ownership, use `reference_owner` or the borrowed reference view so
the authority of the exact source-use relation is retained. Do not promote a
guided operator premise into an independent ABI or byte-derived fact.

Use `frontier_subjects()` plus completeness and coverage to create Splice
recovery frontiers. Do not infer a closed world from an empty index when its
stage is absent, partial, or truncated. Coverage keeps independent and guided
counts separate and should remain separate in product precision accounting.

Reference ownership applies to one exact source, target, and reference-kind
tuple. It does not grant exclusive ownership of a target string or object;
several references may legitimately share the same target.

Lower pointer encodings from their typed `PointerRecordKind`. Chained and
legacy binds remain imports; chained and legacy rebases remain in-image
addresses. Do not infer a legacy rebase from the target shape of a
`LegacyBind`: the Fact IR retains `LegacyRebase` as its own durable kind.
When a lazy or weak legacy bind and rebase cover the same field, retain both in
the authoritative Fact IR and select the bind as the effective target in a
consumer model that permits only one pointer fact per address. The rebase is
corroborating source evidence in that narrower projection, not a conflicting
second effective target.

## Compiling edits into a guide

A call to `RecoveredProgram::refine` takes the complete desired guide for the
next state, not a patch against the prior guide. On every Splice branch update:

1. Read the branch's complete current Mach-O recovery edit set.
2. Build a fresh guide bound to `prior.image().clone()`.
3. Add authored premises and question answers in deterministic order.
4. Validate or refine against the exact live image.
5. Persist and lower the immutable returned program state.

Starting from an old guide and appending only the latest edit is incorrect when
an operator removed, replaced, or reverted an earlier edit.

```rust
let guide = RecoveryGuide::builder(prior.image().clone())
    // Add every currently active branch decision here.
    .suppress_direct_call(caller, instruction_address, decoded_target)
    .build();

let transition = RecoveredProgram::refine_with_reuse_receipt(image, &prior, &guide)?;
let (next, reuse) = transition.into_parts();
let delta = next.delta_from(&prior)?;
let application = next
    .guide_application()
    .expect("refine always records a guide application receipt");

persist_and_lower(next.to_fact_document(), application, delta)?;
record_operational_reuse(reuse)?;
```

Use `RecoveryGuideBuilder::answer_question` when replay must bind to a
question's complete current signal set. Use the authored methods when Splice is
asserting a premise that need not have originated as an emitted question:

| Splice recovery edit | Guide builder method | Exact identity |
| --- | --- | --- |
| Accept function entry | `accept_function` | executable address |
| Reject function candidate | `reject_function` | executable address |
| Relate alternate/cold/shared entry | `relate_function` | address, owner entry, relationship |
| Replace function extents | `function_ranges` | function entry and ordered half-open ranges |
| Reclassify executable bytes | `byte_role` | section ordinal and half-open range |
| Suppress CFG edge | `suppress_control_flow_edge` | function, source, target, edge kind |
| Suppress direct call | `suppress_direct_call` | caller, instruction address, decoded target |
| Select xref source owner | `assign_reference_owner` / `assign_xref_owner` | source, target, xref kind, owner function |

Names and presentation-only labels do not belong in `RecoveryGuide` unless
they change Mach-O recovery. Keep those edits entirely in Splice.

Guide decisions are exact and intentionally narrow. Never lower an aggregated
caller/callee relation back into a call suppression: preserve the original
callsite coordinates. Preserve `ControlFlowEdgeKind` when editing parallel
edges with the same endpoints.

## Refine, replace, revert, and deepen

`RecoveredProgram::refine(image, &prior, &guide)` checks image identity,
rebuilds the stages affected by the complete guide, and returns a new immutable
state. It can replace or remove guidance already retained by `prior`; an empty
guide is therefore a valid revert-to-unguided transition. Every successful
refine records a `RecoveryGuideApplication`, including an empty or redundant
guide.

`next.delta_from(&prior)` is valid only when image and request are identical,
which is true for refine. Preserve the delta and application derivations when
Splice explains why product facts changed.

Use `prior.deepen_with_reuse_receipt(image, extra_stages, limits)` to union
additional requested stages or replace the complete nested limit set while
retaining the operational receipt. `deepen` remains the convenience spelling
when that receipt is not needed. Deepen retains a valid guide and reuses exact
unaffected stages, but its request changes. Consequently, `delta_from`
intentionally returns `RequestMismatch` across a deepening transition; lower
the deepened state as a new fact-universe revision and compare product
revisions with Splice's own request-aware logic.

Refine/deepen cache reuse remains equivalent to a cold rebuild. An unguided
dirty ControlFlow stage may additionally reuse a prior `FunctionControlFlow`
record when the selected image, ControlFlow limits, complete recovered
Function record, pointer and exception inputs, non-returning fixed-point set,
and incoming global decoded-byte budget are exact matches. Guided transitions
add a normalized function-local key containing overlapping byte roles, the
function's exact edge/call suppressions, and the complete instruction-role set.
Instruction roles are conservative because a suppressed jump table leaves no
retained table from which to derive a narrower dependency. A changed Function
record or local guide key invalidates that entry; a changed fixed-point set or
shifted global budget prevents reuse of every affected graph.

`ProgramRecoveryReuseReceipt` is a versioned operational receipt. Its disjoint
`reused_stages` and `rebuilt_stages` sets partition the new state's executed
stages. When ControlFlow is present, `ControlFlowReuseReceipt` reports final,
reused, and rebuilt function-graph counts; a rebuilt ControlFlow stage can
therefore prove selective reuse within that stage. Persist this receipt beside
Splice transition telemetry if useful, never as graph truth.

The reuse receipt does not appear in Fact IR, change completeness or
authority, or alter the ordered graph. Warm output must remain equal to a cold
recovery under the same request. `refine` and `deepen` discard only this
operational receipt and otherwise execute the same transition paths as their
`*_with_reuse_receipt` forms.

## Failure handling

Fail the Splice transition atomically and retain the prior revision on any
Macho error:

- `ProgramImageMismatch` means the live bytes are not the prior document's
  exact selected image. Do not offer a force option.
- `GuideValidationFailed { validation }` contains structured results for stale,
  conflicting, malformed, or unsupported decisions. Surface those results to
  the operator; do not silently drop decisions.
- Fact document decode or validation failure means the artifact is not a
  supported Fact IR state. Do not deserialize permissively.
- A partial or truncated successful program is not an exception. Lower its
  retained facts together with its explicit status, coverage, and frontiers.

Because this is pre-release, Splice should require exactly Fact IR schema `1`
and recovery contract schema `1`. Breaking contract work before the first public
release replaces that baseline in place; it must not invent compatibility with
intermediate development artifacts. Coordinate the Macho and Splice pins when
the baseline changes.

## Splice integration acceptance checklist

- The full recovery path imports `macho::analysis`, not leaf decoders.
- A cold selected image can recover, persist, strict-load, and lower offline.
- Product lowering distinguishes absent, partial, truncated, and complete.
- Guided authority remains distinct from independent authority everywhere.
- The source artifact is addressable by exact image identity for later refine.
- Each branch compiles its complete active recovery edits into a fresh guide.
- Refine persists the next Fact IR and guide application receipt atomically
  with the new product revision.
- Reopening a retained revision reattaches and strict-loads that exact Fact IR
  as the prior `RecoveredProgram`; projected Function addresses are validation
  coordinates, not a replacement durable program state.
- Reverting all recovery edits produces an empty complete guide and an
  unguided next state.
- Image mismatch and unknown-field fixtures fail closed.
- Structured guide validation failures reach the operator unchanged.
- Exact CFG edge, callsite, and xref-use coordinates survive product lowering
  and edit round trips.
- Pure legacy rebases survive cold recovery, Fact IR persistence, strict load,
  and lowering as legacy-rebase pointers rather than disappearing or becoming
  legacy binds.
- Deepening is treated as a new request universe rather than a normal refine
  delta.

The detailed schema, ownership, validation, and guide decision matrix lives in
[`program-fact-ir.md`](program-fact-ir.md).
