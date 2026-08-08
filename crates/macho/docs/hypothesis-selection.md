# Hypotheses and selection policy

Macho keeps three layers distinct:

1. **Facts** are independently recovered or explicitly supplied, durable, and
   fail closed. They stay in their originating recovery model.
2. **Hypotheses** are ranked interpretations of unresolved subjects. Each
  candidate retains typed references to its evidence, evidence authority, confidence, generating
   rule, alternatives, and possible consequences.
3. **Decisions** are operator authority allowing a candidate to affect a
   projection. A decision does not upgrade the candidate's evidence.

`analysis::hypothesis` is the reusable contract. C++ headers are its first
consumer; function boundaries, executable-byte roles, suppressed edges, and
ownership decisions can use the same vocabulary without adding subsystem-local
escape hatches.

## Policies

| Mode | Projection | Hypothesis ledger |
| --- | --- | --- |
| `strict` | Independent/correlated facts and exact choices only | No automatic selection |
| `suggest` | Identical to strict | Ranked hypotheses for each reached blocker |
| `best_effort` | Top-ranked candidates may affect projection | Hypotheses and selection receipts |

An exact `HypothesisOverride` always takes precedence over automatic ranking,
including under strict and suggest. Invalid or stale subject/candidate keys are
rejected instead of ignored.

Suggest may follow a top-ranked candidate in an internal, non-emitting
simulation to reveal a downstream blocker (for example, an unavailable return
type behind unresolved ownership). The strict declaration and unresolved
ledger remain unchanged. The automatic simulation step receives no receipt;
an explicit override encountered during traversal remains an operator decision
and is recorded. This lets an operator obtain every selection key needed for a
chained explicit choice in one suggest report.

The two authority dimensions are deliberately orthogonal:

- `EvidenceAuthority`: `independent`, `correlated`, or `heuristic`;
- `DecisionAuthority`: `operator_policy` or `explicit_operator_choice`.

An unselected hypothesis has no decision receipt and therefore no decision
authority. A blocker for which Macho has no supported interpretation carries an
explicit `abstention` explanation and an empty candidate list. Abstention is not
modeled as a perfect-confidence candidate and cannot be selected.

Thus a heuristic selected by an explicit operator remains heuristic evidence.
It never becomes a recovered fact merely because the operator authorized its
use. Candidate authority is the least authoritative evidence required by the
complete interpretation: for example, a correlated class anchor combined with
a heuristic `public` access default is still recorded as `heuristic`.

## Receipts

Every selected candidate that can affect projection records the unresolved
statement and stable subject, chosen candidate and interpretation, ranked
alternatives, supporting evidence, evidence authority, confidence in basis
points, rule, operator policy, decision authority, explicit-versus-automatic
status, and affected stages/declarations. Receipts are self-contained; the
complete ranked hypothesis remains alongside them. `HypothesisLedger::validate`
checks stable identities, typed evidence references, candidate ranks, abstention
state, override targets, and receipt/policy agreement. Evidence references name
retained entity, fact, evidence, observation, or recovery-gap IDs; prose is a
description, never the identity itself.

For C++ header JSON the ledger is at:

```text
slices[].header.assumption_ledger
```

Best-effort source includes a generated preamble pointing back to those
machine-readable receipts. The canonical recovered entities and
`RecoveredProgram` are not changed.

## C++ header consumer

Use:

```text
macho cpp Binary --headers --projection-policy strict
macho cpp Binary --headers --projection-policy suggest --format json
macho cpp Binary --headers --projection-policy best-effort
```

An operator can copy a subject key and candidate ID from suggest JSON and make
an exact choice with `--hypothesis-selection GAP_ID=CANDIDATE_ID`. Exact choices
take precedence over mode ranking; an unknown or stale pair fails closed.

Selections can also be supplied as a strict, versioned JSON document for
machine producers:

```json
{
  "schema_version": 1,
  "selections": [
    {
      "subject": {
        "domain": "cpp_header",
        "key": "COPY_FROM_THE_HYPOTHESIS_LEDGER"
      },
      "candidate_id": "class_owner_public"
    }
  ]
}
```

Load it with:

```text
macho cpp Binary --headers --hypothesis-selection-file selections.json
```

For hand-authored policy, the equivalent compact TOML form is:

```toml
[selections.cpp_header]
"GAP_ID" = "class_owner_public"
"ANOTHER_GAP_ID" = "opaque_return_type"
```

TOML defaults an omitted `schema_version` to version 1 so the hand-authored
form stays concise. `schema_version = 1` may be supplied explicitly. JSON
remains explicitly versioned for machine producers.

Load it through the same option:

```text
macho cpp Binary --headers --hypothesis-selection-file selections.toml
```

The `.json` or `.toml` extension selects the parser; other extensions are
rejected. Files and repeated inline flags may be combined. Every subject may
appear only once across both inputs; duplicate subjects, unknown fields,
unsupported schema versions, and stale subject/candidate pairs are errors
rather than implicit precedence rules.

The initial rules are intentionally small and conspicuous:

- constructor, destructor, RTTI, vtable, or typed class-owner anchors preserve
  every exactly anchored component of a nested class path;
- unknown owner prefixes prefer namespaces absent contrary class evidence;
- a selected class member defaults to public access;
- an ordinary Itanium name with no encoded source return type uses the explicit
  non-reserved, per-gap `macho_unknown_return_<GAP_ID>` placeholder rather than
  inventing a concrete type or conflating unrelated unknown types;
- a type spelling that cannot be represented safely may use a non-reserved,
  per-gap `macho_unknown_type_<GAP_ID>` partial forward declaration; its
  spelling, specialization, layout, and ABI remain explicitly unauthoritative;
- an exact nested record type used by a projected member is forward-declared
  inside the same already-selected owner shell. This preserves the recovered
  type spelling and shares the owner's receipt; it does not independently
  assert the shell's namespace/class interpretation or record layout;
- competing namespace/class interpretations remain in the ledger.

This prerelease contract remains on recovery schema version 1; development
changes update that schema in place until a release boundary is declared. The
complete `hypothesis_selection_policy`, including exact overrides, is part of
the canonical request digest and must match the resolved projection plan.
Header validation rejects an assumption-dependent owner or generated opaque
type that lacks its matching selection receipt. It reparses generated source,
recomputes the serialized syntax/semantic validation report, reconstructs
expected declarations from the wire model and receipts, and rejects any source
declaration that is not represented by that machine-readable state.

These are projection rules only. Strict output and recovered facts retain the
original unresolved state.
