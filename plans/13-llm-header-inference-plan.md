# Plan 13: Offline Model Hypothesis Layer for Header Recovery

## Status and Authority

This document is the single-pass authority for the optional model hypothesis
layer. Plan 16 owns the deterministic `RecoveryReport`, facts, stable IDs,
header eligibility, and recovery behavior. Plan 15 owns crate placement,
dependency direction, delivery, and process boundaries. This plan may consume
those contracts but cannot redefine them.

[`schemas/language-recovery-wire-v1.md`](schemas/language-recovery-wire-v1.md)
is the normative wire contract for bundle, response, report, header-fragment,
diagnostic, limit, and common identity values. The Rust blocks below are API
projections of that contract.

The model is an offline ambiguity assistant. It is not a collector, fact source,
compiler, provider integration, or second recovery authority. No model output
can mutate a `RecoveryReport`, change a `Fact<T>`, create an entity, resolve a
deterministic conflict, or enter a snapshot.

The implementation is complete only when this artifact exchange, its validators,
CLI surface, invalid fixtures, and STOP conditions pass together. The dependency
checkpoints below are not release phases.

## Objective

Allow a user to export a bounded deterministic evidence projection, obtain a
structured response from any external model or human process, validate that
response in-process, and emit an optional inferred header plus a provenance
sidecar. Deterministic recovery remains fully useful when this layer is absent.

The product itself performs no network access, provider authentication, model
selection, subprocess launch, retry loop, or SDK discovery. The exchange is
files and standard input/output.

## Coherence Boundary

This plan resolves:

- one bounded bundle projected from validated plan-16 IDs and gaps;
- one structured response contract that can propose only allowed operations;
- one hypothesis report with validator results and provenance;
- use of the plan-15 `macho-header-syntax` AST and semantic validator;
- exact CLI grammar, output, file-write, color, and exit behavior;
- deterministic response fixtures requiring no live model; and
- preservation of deterministic authority across inspect, validate, and apply.

It permanently excludes:

- free-form source as accepted model output;
- a parallel fact, confidence, declaration, or evidence schema;
- automatic remote or local model execution;
- automatic repair/retry loops;
- aggregate confidence scores that obscure field-level support;
- promotion of an accepted hypothesis into deterministic facts; and
- host compiler, `xcrun`, SDK locator, or process-backed validation.

## Falsification Criteria

The design is wrong if any of these statements is true:

- a bundle can refer to an entity, fact, gap, or evidence ID absent from its
  source `RecoveryReport`;
- a response can add an entity or overwrite an exact, correlated, conflicted,
  or unavailable deterministic fact;
- accepted model output is serialized into `RecoveryReport` or snapshot schema;
- model support is represented by a single aggregate confidence score;
- arbitrary header text can bypass the typed syntax AST;
- syntactic success is treated as semantic validity;
- inspect, prompt, validate, or apply launches a process or contacts a provider;
- a stale response can be applied to a different bundle; or
- deterministic C/C++ output requires this feature to exist.

## Artifact Schemas

All fields use private construction plus validated serde wire DTOs. Schema
versions are exact and independently versioned from `RecoveryReport`.

```rust
pub struct HypothesisBundle {
    schema_version: HypothesisBundleVersion, // exactly 1
    recovery_schema_version: RecoverySchemaVersion, // exactly 1
    recovery_digest: ContentHash,
    bundle_digest: ContentHash,
    language: RecoveryLanguage,
    architecture: Architecture,
    image: ImageIdentity,
    targets: NonEmpty<HypothesisTarget>,
    facts: Vec<FactExcerpt>,
    evidence: Vec<EvidenceExcerpt>,
    constraints: BundleConstraints,
    limits: HypothesisLimits,
}

pub struct HypothesisTarget {
    entity_id: EntityId,
    gap_ids: NonEmpty<RecoveryGapId>,
    allowed_operations: NonEmpty<HypothesisOperationKind>,
}

pub struct EvidenceExcerpt {
    evidence_id: EvidenceId,
    entity_id: EntityId,
    canonical_projection: CanonicalJsonValue,
}

pub struct FactExcerpt {
    fact_id: FactId,
    entity_id: EntityId,
    field: RecoveryField,
    canonical_projection: CanonicalJsonValue,
}

pub struct BundleConstraints {
    pinned_fact_ids: Vec<FactId>,
    supported_header_subset: HeaderSubsetVersion,
}

pub struct ModelResponse {
    schema_version: ModelResponseVersion, // exactly 1
    bundle_digest: ContentHash,
    hypotheses: Vec<ProposedHypothesis>,
    unresolved_gap_ids: Vec<RecoveryGapId>,
}

pub struct ProposedHypothesis {
    id: HypothesisId,
    entity_id: EntityId,
    gap_id: RecoveryGapId,
    operation: HypothesisOperation,
    support: NonEmpty<SupportRef>,
}

pub enum SupportRef {
    Evidence(EvidenceId),
    DeterministicFact(FactId),
    RelatedEntity(EntityId),
}

pub enum HypothesisOperation {
    ChooseCandidate { candidate_index: usize },
    ProposeCanonicalName { name: Identifier },
    ProposeDeclarationFragment { fragment: HeaderSyntaxFragmentWire },
    ProposeGrouping { owner: HeaderOwnerRef },
}

pub struct HypothesisReport {
    schema_version: HypothesisReportVersion, // exactly 1
    bundle_digest: ContentHash,
    response_digest: ContentHash,
    results: Vec<HypothesisResult>,
    unresolved_gap_ids: Vec<RecoveryGapId>,
    validation: HeaderValidationReport,
    projected_header: Option<HeaderProjection>,
}

pub struct HypothesisResult {
    hypothesis_id: HypothesisId,
    entity_id: EntityId,
    gap_id: RecoveryGapId,
    disposition: HypothesisDisposition,
    support: NonEmpty<SupportRef>,
    diagnostics: Vec<HypothesisDiagnostic>,
}

pub enum HypothesisDisposition {
    Accepted,
    Rejected,
    Unresolved,
}
```

`Proposed` is the state of entries in an unvalidated `ModelResponse`; only the
three post-validation dispositions occur in `HypothesisReport`. There is no
confidence basis-point, probability, or “overall confidence” field. Support is
inspectable by exact deterministic IDs.

`EvidenceExcerpt.canonical_projection` is the source-equality-constrained
canonical JSON subtree defined by the wire contract, and `FactExcerpt` is the
corresponding projection of an existing plan-16 `Fact<T>`; neither is a new
fact/evidence authority. `HeaderSyntaxFragmentWire` is exactly one validated
`HeaderDecl` from the shared header-syntax wire registry and cannot carry raw
declaration text.

## Bounds and Determinism

The required default and hard maximums are:

| Limit | Default | Hard maximum |
| --- | ---: | ---: |
| target entities per bundle | 512 | 4,096 |
| fact excerpts per bundle | 8,192 | 32,768 |
| evidence excerpts per bundle | 4,096 | 16,384 |
| serialized bundle bytes | 1 MiB | 4 MiB |
| prompt bytes | 1 MiB | 2 MiB |
| response bytes | 1 MiB | 2 MiB |
| rendered header bytes | 1 MiB | 2 MiB |

Exceeding a limit produces a typed error with selected and excess counts; the
user must export a smaller explicit gap set. The builder never truncates or
implicitly partitions a target. Bundle and response digests cover canonical
JSON bytes. Map ordering, diagnostic ordering, prompt ordering, and header
rendering are deterministic.

## Bundle Construction

The bundle builder accepts only `RecoveryReport::validate()` output. It selects
explicit entity and gap IDs from one architecture. The builder:

1. rejects cross-slice or dangling IDs;
2. copies only the minimum referenced deterministic projections;
3. includes and pins every exact and correlated fact relevant to the requested
   gap;
4. lists the allowed operation kinds per gap;
5. includes conflicted candidates without selecting a winner;
6. preserves unavailable reasons and evidence references; and
7. computes the bundle digest after canonical serialization.

Models cannot infer entities absent from the bundle targets. A gap without a
safe model operation remains in the source `RecoveryReport`; `export` rejects it
as a target and it stays deterministically unresolved.

## Response Validation

Validation is a pure, ordered pipeline:

1. parse schema version 1 within the response byte limit;
2. require exact bundle digest equality;
3. reject duplicate hypothesis IDs or duplicate operations for one gap;
4. resolve every entity, gap, fact, and evidence reference against the bundle;
5. require every target gap to appear exactly once as either one proposed
   hypothesis or an unresolved gap, never both and never omitted;
6. prove the operation kind is allowed for that target;
7. prove pinned deterministic facts are unchanged;
8. lower proposed fragments into `macho-header-syntax` typed nodes;
9. combine accepted candidates with the deterministic safe projection;
10. run header syntax, scope, reference, redeclaration, linkage, calling-
   convention, qualifier, parameter-state, template, and dependency validation;
11. run applicable in-process ABI checks: Itanium remangling, vtable ownership,
    and DWARF comparison; and
12. produce `HypothesisReport` without modifying the source report or bundle.

A hypothesis is `Accepted` only if its own references and every affected header
semantic invariant pass. `Rejected` means concrete evidence or validation
contradicts it. `Unresolved` means the operation is structurally allowed but the
available evidence cannot establish a safe choice. Validator diagnostics use
closed stable codes and reference hypothesis plus deterministic IDs.

There is no automatic retry. A failed validation report contains the rejected
and unresolved IDs needed for a user to produce a narrower external response;
the original artifacts remain immutable and auditable.

## Application and Authority

`apply` revalidates the bundle and response; it never trusts a saved report. It
may emit:

- a header rendered from deterministic eligible declarations plus accepted
  hypothesis AST nodes; and
- a sidecar containing `HypothesisReport`, digests, support references, and
  validation results.

The header is explicitly labeled as hypothesis-assisted. The sidecar is the
only authority for accepted model choices. Neither output is a snapshot input,
and a later deterministic recovery run cannot ingest accepted hypotheses as
facts.

## CLI Contract

The grammar is exact:

```text
macho header-infer export RECOVERY-JSON --arch ARCH --gap GAP-ID...
    --output BUNDLE
macho header-infer inspect BUNDLE [--format text|json]
macho header-infer check-bundle BUNDLE [--format text|json]
macho header-infer prompt BUNDLE [--output PATH]
macho header-infer validate BUNDLE RESPONSE [--format text|json]
macho header-infer apply BUNDLE RESPONSE
    [--header-out PATH] [--sidecar-out PATH]
```

- `export` consumes the common JSON envelope produced by `macho c` or
  `macho cpp`, requires one architecture and at least one repeatable `--gap`,
  validates the nested `RecoveryReport`, and atomically writes exactly one
  bundle. A gap from another slice, a deterministic-only gap, or a selection
  over a bundle limit is an explicit failure; there is no “all gaps” default.
- `inspect` renders bundle targets, gaps, bounds, and deterministic references.
- `check-bundle` validates schema, digests, bounds, and all references.
- `prompt` emits deterministic UTF-8 prompt text to stdout or atomically to
  `--output`; it contains no ANSI.
- `validate` emits the typed `HypothesisReport` as text or the common JSON
  envelope. Unresolved/rejected hypotheses are a successful analysis result;
  malformed or invariant-breaking artifacts are execution failures.
- `apply` writes header source to stdout unless `--header-out` is supplied and
  atomically writes the sidecar only when requested. Header stdout contains no
  status text or ANSI; diagnostics use stderr.
- `inspect`, `check-bundle`, and text `validate` use the shared CLI column and
  color engine. JSON never has ANSI. Explicit `--color always` with JSON,
  `export`, `prompt`, or `apply` is a usage error.
- No subcommand accepts provider, model, endpoint, token, SDK, compiler,
  demangler, retry, or shell-command options.

All filesystem reads and atomic writes belong to `macho-cli`. The
`macho-header-infer` library accepts bytes/typed values and returns owned
artifacts.

## Ownership

- `macho-analysis` owns `RecoveryReport`, deterministic facts/gaps, bundle
  selection inputs, and deterministic safe projection.
- `macho-header-syntax` owns the supported AST, parser, renderer, and syntax
  plus semantic validator.
- `macho-header-infer` owns the artifact schemas, bounded bundle builder, prompt
  builder, response validator/orchestration, and sidecar report.
- `macho-cli` owns grammar, files, atomic writes, shared output, and exit policy.

`macho-header-infer` depends on `macho-analysis` and `macho-header-syntax`. It
does not own a `HeaderParser`, model-provider trait, HTTP client, runtime, or
process adapter.

## Verification

Required deterministic fixtures include:

- a minimal valid C bundle/response and a valid C++ bundle/response;
- stable bundles from the same explicitly ordered gap set and distinct bundles
  from deliberately split gap sets;
- unknown schema versions, stale digest, duplicate IDs, dangling IDs, cross-
  slice IDs, unsupported operations, and changed pinned facts;
- response, prompt, bundle, entity, fact, evidence, and header limit exhaustion;
- invented entity, invented evidence, unsupported raw text, aggregate-confidence
  field, conflicting candidate selection, and duplicate gap operation;
- syntax-invalid fragment and syntax-valid fragments with unresolved types,
  ambiguous scope, conflicting redeclarations, illegal linkage/calling
  convention, and incomplete template context;
- accepted, rejected, and unresolved results with exact support references;
- byte-identical canonical bundles, prompts, reports, sidecars, and headers
  across repeated runs;
- `PATH=/nonexistent` for every subcommand and an architecture scan rejecting
  process/network/provider code; and
- JSON/ANSI/channel/atomic-write/usage/exit tests through both injected I/O and
  the live CLI process.

No required test calls a model. Committed response fixtures are the acceptance
authority. Optional manual experiments may compare external models but cannot
replace, skip, or weaken a deterministic fixture.

## Negative STOP Conditions

Stop implementation and report exact evidence if:

1. a required proposal cannot be represented without changing `RecoveryReport`;
2. an accepted hypothesis must overwrite or resolve a deterministic fact;
3. analysis and inference require different header AST or validation semantics;
4. arbitrary response text must bypass `macho-header-syntax`;
5. a bundle cannot prove all references and bounds before prompt emission;
6. a response cannot be bound cryptographically to the exact bundle;
7. apply cannot reproduce validation without trusting cached status;
8. any product path requires a provider, network, compiler, SDK, or process;
9. an invalid fixture passes only after weakening a validator or exception; or
10. any required check is skipped, ignored, or converted to a warning.

## Dependency Checkpoints

1. Define validated artifact schemas, canonical serialization, bounds, and all
   malformed-wire fixtures.
2. Implement deterministic bounded projection from validated recovery IDs and
   prove no parallel fact/evidence authority exists.
3. Implement structured response validation through the shared syntax and ABI
   validators, including accepted/rejected/unresolved fixtures.
4. Implement export/inspect/check/prompt/validate/apply with exact I/O, color,
   JSON, atomic-write, and exit tests.
5. Run architecture, feature, workspace, deterministic corpus, and independent
   live-process-versus-injected-I/O checks in one final repository state.

A checkpoint cannot pass while a consumer still uses the old provider model,
parallel header schema, process-backed validator, or aggregate confidence.

## Done Means

- deterministic recovery works unchanged without header inference;
- bundles are bounded, deterministic projections of validated plan-16 IDs;
- responses can only propose allowed operations on existing gaps;
- every accepted choice retains exact support and validator results;
- model choices never become deterministic facts or snapshot state;
- all output header nodes pass shared syntax and semantic validation;
- the complete workflow is offline, cross-platform, and process-free;
- CLI artifacts and sidecars are deterministic and channel-safe; and
- every positive/negative fixture, STOP condition, architecture gate, and
  workspace gate passes without a live model or verifier weakening.
