# Plan: LLM-Assisted Header Inference

## Status

This is the concrete plan for packaging binary-recovery evidence into a
verifiable LLM workflow that can infer polished C and C++ headers without
replacing deterministic extraction and validation.

The LLM is an ambiguity resolver and presentation layer. It is not the source
of truth.

## Objective

Build an end-to-end inference system that can:

- collect deterministic evidence from the C++ and C fidelity pipelines
- package that evidence into bounded, machine-readable bundles
- query an LLM for structured declaration inference
- validate the result with parsers, mangling checks, vtable checks, and DWARF
  checks
- iteratively repair only the unresolved or invalid parts
- emit final headers plus sidecar provenance and confidence summaries

## Why This Matters

Deterministic extraction is essential for trust, but it cannot recover every
source spelling or resolve every ambiguity. An LLM can help choose among
plausible interpretations, smooth rough canonical syntax, and group recovered
entities into more natural header surfaces.

That only works if the LLM is boxed in by evidence, schema, and validators.
Without that discipline, it will invent declarations that look plausible but do
not match the binary.

## Current Repo Leverage

- the planned C++ fidelity pipeline in `11-cpp-header-fidelity-plan.md`
- the planned C fidelity pipeline in `12-c-header-fidelity-plan.md`
- existing JSON-friendly CLI surfaces and serialization patterns
- existing symbol, vtable, xref, and multi-image infrastructure

## Fidelity Contract

### Deterministic Truth Sources

- mangled symbol ASTs
- RTTI and vtable graph facts
- body-analysis facts and confidence
- DWARF-backed declarations
- cross-binary merged entities
- external header matches and source locations

### LLM Responsibilities

- choose among competing plausible spellings or declaration organizations
- infer source-like grouping when multiple ABI-safe renderings are possible
- propose canonical placeholder names when source names are absent
- smooth type spellings using correlated source evidence

### LLM Non-Responsibilities

- invent entities absent from the evidence graph
- override exact deterministic facts
- fill missing declarations by general world knowledge
- silently resolve conflicts without reporting them

## Scope

### In Scope

- evidence-bundle schema and packaging
- prompt design for C, C++, and mixed header units
- structured LLM output and retry loops
- parser and ABI validators
- provenance-preserving final emission

### Out of Scope

- fully unconstrained free-form header generation
- use of the LLM as the first pass instead of the last-mile inference layer
- remote-eval orchestration unrelated to header reconstruction

## Design

The pipeline has five stages:

1. deterministic recovery
2. evidence bundling
3. structured LLM inference
4. validation and repair
5. final emission with sidecar metadata

The LLM only sees bounded evidence for one `HeaderUnit` at a time. Every output
must round-trip through validators before promotion.

## Milestones

### Milestone 1: Evidence Bundle Schema

Goal: make recovered facts portable and compact enough for model input.

Work:

- define stable JSON schemas for `HeaderUnit`, entities, canonical types,
  confidence, conflicts, and provenance
- include exact facts, inferred facts, external matches, and unresolved gaps
- add size-bounded summarization for large classes, modules, or binaries

Acceptance:

- any header-recovery target can be serialized into one or more deterministic
  bundles
- bundles are diffable and validator-friendly

### Milestone 2: Prompt and Output Contract

Goal: keep the model boxed into useful work.

Work:

- define separate system prompts for C and C++
- require JSON output only, not raw headers
- require unresolved items and confidence summaries in the output
- instruct the model to prefer exact evidence over priors and canonical ABI-safe
  spellings over invention

Acceptance:

- model responses are machine-parseable
- the prompt contract is strict enough to reject unsupported creativity

### Milestone 3: Validation Loop

Goal: convert “looks plausible” into measurable correctness.

Work:

- parse the model's declaration JSON into the canonical IR
- render headers and reparse them with Clang
- remangle recoverable C++ declarations and compare against binary names
- compare virtual surfaces to vtable graphs
- compare C declarations to DWARF where available
- feed only concrete validation failures into repair prompts

Acceptance:

- invalid or ABI-inconsistent model output is rejected automatically
- retries focus on specific failures instead of resubmitting the entire bundle

### Milestone 4: Iterative Repair and Conflict Handling

Goal: resolve ambiguity without losing provenance.

Work:

- add targeted retry prompts for invalid declarations, unresolved return types,
  conflicting header matches, and grouping problems
- allow the system to pin exact facts and ask the LLM only about the remaining
  unknowns
- record every accepted LLM decision as a derived fact with provenance

Acceptance:

- retries converge on smaller unresolved sets
- accepted model choices remain auditable

### Milestone 5: Final Emitter and Product Surface

Goal: expose the workflow as a usable feature.

Work:

- emit headers plus sidecar JSON containing provenance, confidence, and
  validation results
- support dry-run inspection of evidence bundles and model prompts
- add CLI surfaces for deterministic-only and LLM-assisted modes
- add corpus-based regression tests for representative binaries

Acceptance:

- users can inspect both the generated header and why each declaration exists
- deterministic mode remains available for high-trust workflows

## Prompt Template

Use a strict structured prompt with evidence-first instructions. The seed form
should be:

```text
System:
You reconstruct ABI-faithful C/C++ declarations from binary evidence.
Prefer explicit evidence over priors.
Do not invent entities or facts.
When a source spelling is unknown, use a canonical ABI-safe spelling.
When a parameter or field name is unknown, use argN or fieldN.
Return JSON only.

User:
Language: <C|C++>
Target ABI: <abi description>
Goal: infer a compileable header that best matches the recovered ABI surface.

Evidence bundle:
<JSON bundle>

Tasks:
1. Infer declarations only for entities present in the bundle.
2. Preserve exact spellings from external header matches when confidence is high.
3. Prefer canonical spellings when exact source spellings are unsupported.
4. Report unresolved or conflicting cases explicitly.
5. Return JSON with:
   - header_name
   - declarations[]
   - dependencies[]
   - unresolved[]
   - confidence_summary
   - notes
```

## Dependencies

- depends on the deterministic recovery outputs from
  `11-cpp-header-fidelity-plan.md` and `12-c-header-fidelity-plan.md`
- depends on validation infrastructure capable of structural and ABI checks

## Risks

- oversized bundles can force the model to ignore important evidence
- weak prompts can let the model overfit to familiar SDK declarations
- repeated retries can hide deterministic gaps behind model churn

## Mitigations

- bundle by `HeaderUnit` with hard size caps
- keep exact facts pinned and immutable across retries
- require validators to explain every rejection concretely
- preserve deterministic output as a first-class alternative

## Recommended Sequence

1. finish the deterministic C++ and C evidence pipelines
2. define the bundle schema and prompt contract
3. build the validator and repair loop
4. add CLI surfaces for bundle export and LLM-assisted inference
5. add regression corpora and provenance-rich sidecar output

## Done Means

- `macho` can package recovered evidence, ask an LLM for header inference, and
  validate the result before presenting it as output
- users can inspect provenance and confidence instead of trusting opaque model
  guesses
- the LLM improves presentation and ambiguity resolution without replacing the
  deterministic recovery core
