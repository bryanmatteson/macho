# Program Fact IR

`RecoveredProgram` is Macho's primary full-facts entry for one exact selected
thin image. `ProgramFactDocument` is its durable, strict wire form.
`SelectedImageEvidence` is a leaf decoding session below program recovery, not
an alternate program model. A consumer such as Splice lowers the Fact IR into
its own product IR and owns edits, histories, queries, and mutations.

Splice integration details and an acceptance checklist are in
[`splice-handoff.md`](splice-handoff.md).

## Ownership boundary

| Layer | Owns | Does not own |
| --- | --- | --- |
| `SelectedImageEvidence` | One parsed image, shared pointer resolution, bounded format/language leaf decodes | CFGs, xrefs, recovery policy, mutation |
| `RecoveredProgram` | Dependency-closed stages, questions, completeness, coverage, guide application, stable readers | Product decisions, edit history, cross-format IR |
| `ProgramFactDocument` | Durable program facts and receipts for offline queries | Selected-image bytes |
| Consumer product IR | Accepted/candidate/exact product semantics, edit database, lowering, presentation | Mach-O recovery physics |

Program recovery opens one `SelectedImageEvidence` session and routes pointer,
function-start, Objective-C, Swift, and C++ strict leaves through it. The same
session exposes bounded indirect-symbol bindings for stubs and lazy/non-lazy
pointer slots, plus separate legacy-bind and legacy-rebase inventories so each
source has an independent limit. Pure rebases remain distinct xref, pointer,
and durable Fact IR records; a field covered by both mechanisms retains both
source occurrences. Narrow consumers may use the evidence session directly. They
must not treat it as a substitute for `RecoveredProgram` when they need joined
whole-program facts. `PointerIndex::recover` is a convenience entry that opens
this same session and delegates to `recover_with_evidence`; it is not a second
pointer decoder.

## Wire contract

`PROGRAM_FACT_IR_SCHEMA_VERSION` versions the document layout. The current
document contains:

- exact selected-image identity;
- the selective request, nested limits, and executed dependency closure;
- validated completeness and materialized coverage;
- the retained recovery guide and application/provenance receipt;
- current recovery questions;
- owned stage payloads in `RecoveredProgramBody`, including durable guided
  ownership relations for exact reference uses.

JSON decoding rejects unknown fields recursively, including inside retained
stage records. `ProgramFactDocument::load_json` and
`RecoveredProgram::from_document` validate before returning data. Validation
fails closed on an unsupported schema, malformed identity, inconsistent stage
closure or payload presence, per-stage image/limit mismatch, impossible
completeness, stale coverage/questions, or inconsistent guide provenance. It
also revalidates the canonical ordering, secondary lookup tables, graph
topology, byte-conservation ledgers, and derived receipts of durable layout,
image-layout, pointer, symbol, string, Objective-C, Swift, DWARF, function,
control-flow, executable-byte, direct-call, transfer, indirect-call, xref,
RTTI, exception, dependency, and semantic indexes before
exposing their query readers; serialized vectors are never trusted merely
because they deserialize.

Pointer and xref kind identity is lossless across the wire. In particular,
legacy rebases are not inferred from a legacy-bind target shape: they serialize
as `legacy_rebase`, while legacy imports serialize as `legacy_bind`.

The document deliberately does not co-locate image bytes. It remains queryable
without them. `refine` and `deepen` require a live `MachoFile` and compare its
SHA-256, byte length, CPU type, and CPU subtype with the prior state before any
recovery. Thus moving a facts file does not weaken its binding, and supplying a
different same-architecture image still fails.

Before the first public release, breaking wire edits replace schema 1 in place;
there is no compatibility promise or artificial migration history. After the
first public release, increment `PROGRAM_FACT_IR_SCHEMA_VERSION` for a breaking
document or stage-payload change. Increment `RECOVERY_CONTRACT_SCHEMA_VERSION`
when a subject key, question identity, choice meaning, or guide-validation rule
changes incompatibly. Before that release, both prerelease schemas remain `1`
and are updated in place. A Fact IR document records both versions and loading
currently requires the exact supported recovery contract.

The current pre-release wire is Fact IR schema 1 / recovery contract schema 1.

## Independent and guided facts

Independent facts are established from selected-image bytes and mechanically
derived recovery products. Guided facts are admitted or reclassified through a
caller-authored `RecoveryGuide`. Guidance never upgrades caller knowledge into
independent ABI evidence.

Functions retain authority directly. Other structural subjects use causal
derivations in `RecoveryGuideApplication::delta`.
`RecoveredProgram::subject_authority` provides the common reader and returns
`None` for a subject absent from the current state, preventing absence from
masquerading as independent evidence. Coverage keeps independent and
caller-guided counts separate. A guide application receipt is durable and
`RecoveredProgram::refine` emits one even when a guide is empty or redundant.
`reference_owner` and the borrowed reference views return the selected source
owner together with that relation's authority.

## State transitions

Cold recovery starts with `RecoveredProgram::recover` or `recover_all`.
`RecoveredProgram::refine(macho, prior, guide)` returns an immutable next state
under the prior request. The supplied guide is the complete desired guidance
for the next state: refine obtains an unguided base under the prior request,
validates the guide against that base, and rebuilds the affected dependency
closure. An unguided prior is already the matching base; an already-guided
prior requires a cold base recovery. A stage outside the dirty closure is
cloned from that base without reopening its leaf decoder.
This allows a guide to be reapplied to or replaced on an already-guided prior;
callers can compare the returned state to `prior` with `delta_from`.
`prior.deepen(macho, extra_stages, limits)` unions requested stages, recomputes
dependency closure, and reuses an already-executed stage when that stage's
limit block is unchanged. A limit override dirties only the stages whose own
limit block changed and their transitive consumers. A retained guide takes the
conservative cold-base path and must remain valid, otherwise the transition
fails rather than silently dropping operator intent.

Call `refine_with_reuse_receipt` or `deepen_with_reuse_receipt` when the host
needs operational proof of what was reused. The returned
`ProgramRecoveryTransition` separates the immutable program from a
schema-versioned `ProgramRecoveryReuseReceipt`; the convenience methods above
discard that receipt and return the same program.

Consumers can persist with `to_fact_document` plus `to_json_pretty`, load with
`ProgramFactDocument::load_json` plus `RecoveredProgram::from_document`, inspect
stage availability with `stage_status`, and map open-world or incomplete work
through `frontiers`; `frontier_subjects` remains the compact identity-only
projection. Site-local indirect and runtime-dispatch frontiers retain their
exact function and instruction subject, stable reason, omitted-candidate
count, and whether current runtime evidence is required. Unsupported computed
branch transforms additionally retain the bounded instruction coordinates
that contributed indexed-memory operands. A runtime-open frontier never
promotes a recorded file candidate to current process truth.

The stable consumer façade is `macho::analysis`; it re-exports the program
entrypoints, Fact IR and completeness types, guide authoring/validation and
delta vocabulary, coverage receipts, and borrowed program views. Leaf-only
consumers import `macho::evidence` instead.

## CLI persistence

The program command keeps its ordinary JSON report envelope separate from the
raw Fact IR file:

```text
macho program MyApp --all --fact-ir-output facts.json
macho program --load-fact-ir facts.json
macho program --load-fact-ir facts.json --format json
```

`--fact-ir-output` writes one raw `ProgramFactDocument` while stdout retains the
normal program report. A universal input must use `--arch` so the facts file is
bound to exactly one selected thin image. `--load-fact-ir` needs no Mach-O bytes;
it strictly decodes, validates, and materializes the saved program for offline
inspection. JSON printed by the CLI still uses the global command-success
envelope, with the raw document under `data`; the file itself has no report
envelope.

## Guide decision coverage

Every choice in the current recovery contract has a cold-rebuild path. The
affected-stage column names semantic consumers; recovery may also rerun their
dependency closure to preserve full-rebuild equivalence.

| `RecoveryChoice` | Affected stages | Status |
| --- | --- | --- |
| `KeepUnresolved` | None; explicitly retains the site-local indirect/runtime frontier without promoting a candidate | Supported |
| `AcceptFunctionEntry` | Functions, control flow, executable bytes, direct calls, transfers, indirect calls, xrefs, semantics | Supported |
| `Reject` on a function candidate | Same function-dependent stages | Supported |
| `FunctionRelationship` | Same function-dependent stages | Supported |
| `FunctionRanges` | Same function-dependent stages | Supported |
| `ByteRole` | Functions when code is suppressed, control flow, executable bytes, call/transfer/xref consumers, semantics | Supported |
| `SuppressControlFlowEdge` | Control flow reachability, executable bytes, call/transfer/xref consumers, semantics | Supported; exact function + source block + target block + edge kind |
| `SuppressDirectCall` | Direct-call function evidence, control flow callsites, direct/indirect call consumers, xrefs, executable bytes, semantics | Supported; exact caller + instruction + decoded target |
| `ReferenceOwner` | Xref/source ownership used by Fact IR consumers | Supported; exact source + target + xref kind, selecting an already-recovered source-range owner |

Invalid coordinates, stale signals, conflicting decisions, proposition/subject
mismatches, and choices without a coherent application path all return
`ProgramRecoveryError::GuideValidationFailed` with one structured decision
result. No decision is silently ignored. Aggregated `DirectCall { caller,
callee }` subjects are deliberately query-only: a guide must use the precise
`DirectCallsite` subject so one edit cannot erase several independent
callsites. Edge identity includes `ControlFlowEdgeKind`, so parallel edge
semantics sharing block endpoints remain independently editable. String/xref
ownership is represented as ownership of one exact reference use. It does not
assign exclusive ownership to the target string: several independently
retained references, from the same or different functions, can continue to
target one shared literal. Recovery emits `ReferenceOwnership` questions only
when an exact xref source has multiple recovered range owners. Authored choices
must select one of those owners (including an owner introduced by a
`FunctionRanges` decision in the same complete guide).

Reuse is a performance optimization only. Dirty roots expand through all
declared consumers, and the Functions/ControlFlow extent-refinement feedback is
treated as a dirty edge in both directions. Optional symbol evidence also
invalidates Functions whenever both stages are selected. Equivalence tests
compare selective refine and deepen results to full cold rebuilds.

Function-local CFG reuse is admitted only for an exact prior image and limits,
an equal complete `RecoveredFunction`, unchanged pointer/exception inputs, the
same non-returning fixed-point set, and the same incoming global decoded-byte
budget. Guided transitions additionally compare a normalized function-local
key containing overlapping byte roles, exact edge/call suppressions, and the
complete instruction-role set. Instruction roles are deliberately conservative:
a prior role can suppress a jump table so completely that no retained table
remains from which to reconstruct a narrower dependency. Reused graphs are
charged their retained decoded-byte count before the next function is
considered, so truncation and continuations stay identical to a cold fold.
The operational receipt serializes independently when a host wants telemetry,
but cache admission and hit counts are never embedded in program Fact IR and
never change its identity, coverage, limitations, or questions. Its stage sets
partition the executed stages into whole-stage reuse and rebuilds; its optional
ControlFlow detail partitions the final function graphs into reused and
rebuilt counts.

The `architecture` Criterion target keeps `cold_recover_with_guide` and
`warm_refine_from_retained_base` side by side on the same deterministic
multi-function fixture. Benchmark setup asserts exact cold/warm program
equality and the presence of an unaffected function graph before timing; wall
times remain host-specific quality evidence rather than a semantic threshold.
