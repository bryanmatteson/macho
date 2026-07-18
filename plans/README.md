# Plans

This directory separates active implementation authorities from historical
records. The workspace is prerelease, and the active documents are one coherent
agent-executable specification rather than a calendar roadmap.

## Active Authorities

Every implementation pass must read these interacting contracts together:

| Plan | Authority |
| --- | --- |
| [`10-objc-header-fidelity-plan.md`](10-objc-header-fidelity-plan.md) | Objective-C runtime graph, surface, encoding, and header behavior |
| [`13-llm-header-inference-plan.md`](13-llm-header-inference-plan.md) | Optional offline model hypothesis artifacts and validation only |
| [`15-architecture-coherence-implementation-plan.md`](15-architecture-coherence-implementation-plan.md) | Workspace ownership, dependencies, selective analysis, snapshot schema 3, ObjC/Swift integration, CLI delivery, and whole-tree gates |
| [`16-evidence-first-c-cpp-recovery-plan.md`](16-evidence-first-c-cpp-recovery-plan.md) | Deterministic C/C++ recovery schema, identity, evidence, targeted execution, safe header projection, snapshots/diffs, and recovery verification |
| [`18-in-process-signing-plan.md`](18-in-process-signing-plan.md) | Process-free ad-hoc and PKCS#12 signing, final-layout verification, patch integration, and signing-specific gates |

The serialized contract used by all four plans is
[`schemas/language-recovery-wire-v1.md`](schemas/language-recovery-wire-v1.md).
It is normative for common report identities, JSON rules, header-syntax DTOs,
closed enum/code registries, language reports, hypothesis artifacts, and the
snapshot language payload registry. Inline Rust blocks in the plans are API
projections; the schema document wins if wording differs.

Plan 15 owns placement and shared execution/delivery mechanics. Plan 18 amends
plan 15's former host-signing exception and owns the in-process raw Mach-O
signing contract. Plan 10 owns
Objective-C behavior. Plan 16 owns deterministic C/C++ behavior. Plan 13 consumes
validated plan-16 artifacts and cannot change deterministic facts. If wording
appears to overlap, that ownership order resolves it; a contradiction must be
fixed in the plans before implementation rather than guessed around.

`macho-analysis::report` owns the shared serialized vocabulary, including
`IdentityStability`, stable report IDs, canonical JSON, and deterministic
language/recovery report registries. `macho-header-infer` owns only the
hypothesis artifact root DTOs and validation while importing that vocabulary.
Leaf language crates own parsed semantic values; analysis owns conversion into
report DTOs. The leaves do not define competing serialized report roots.

Shared wire ownership does not create an upward dependency. Header AST and
language semantic values remain ID-free leaf types; `macho-analysis` depends on
those leaves and converts them into ID-bearing report DTOs.

The work-package and dependency-checkpoint ordering inside these documents is an
implementation dependency order. It is not a sequence of separately shippable
phases. No active plan is complete until its callers, valid and invalid fixtures,
STOP conditions, portable verification, and environment-specific acceptance
ledger are coherent in one repository state.

## Superseded Context

These root documents are retained to explain earlier design choices but are not
implementation authorities:

- [`11-cpp-header-fidelity-plan.md`](11-cpp-header-fidelity-plan.md) and
  [`12-c-header-fidelity-plan.md`](12-c-header-fidelity-plan.md) are superseded
  by plan 16.
- [`14-workspace-crate-refactor-plan.md`](14-workspace-crate-refactor-plan.md) is
  superseded by plan 15.

The files under [`complete/`](complete/) are historical completion records for
the pre-workspace feature set. They preserve prior intent and evidence but do
not own current crate paths, dependency direction, façade types, snapshot
schemas, command delivery, or verification. In particular, their references to
`ImageInspector` do not authorize restoring it; plan 15's `Analyzer` contract is
current.

Historical records cover:

1. diff behavior;
2. transactional patching;
3. audit behavior;
4. the original ObjC/Swift graph;
5. multi-image analysis;
6. the original image API;
7. symbol/xref resolution;
8. dependency/compatibility analysis; and
9. binary-data analysis.

Surviving behavior from those records must be preserved when it does not
conflict with an active authority. Current ownership and type names always come
from plans 10, 13, 15, and 16.

## Repository Anchors

- Workspace and dependency authority: `Cargo.toml`
- Structural parser/model: `crates/macho-core/src/`
- Instruction handling: `crates/macho-insn/src/`
- Analysis, snapshots, diffs, and recovery: `crates/macho-analysis/src/`
- Objective-C metadata/graph: `crates/macho-objc/src/`
- Swift metadata/demangling: `crates/macho-swift/src/`
- C++ ABI metadata: `crates/macho-cpp/src/`
- Shared C/C++/Objective-C header AST/parser/renderer/validator target:
  `crates/macho-header-syntax/src/`
- Optional hypothesis artifacts: `crates/macho-header-infer/src/`
- Mutation: `crates/macho-mutate/src/`
- Feature-gated façade: `crates/macho/src/`
- CLI grammar and output: `crates/macho-cli/src/`
- Architecture/docs/release verifier: `crates/xtask/`
- Plan acceptance evidence: `plans/evidence/`
- Current amended completion record:
  [`evidence/15-amended-final.md`](evidence/15-amended-final.md)

The verified baseline had 18 packages; the completed workspace has the required
nineteenth package at `crates/macho-header-syntax`. It is a production authority,
not an optional scaffold. Any future implementation that discovers a cycle or
path conflict must apply the active plans' STOP rules and update the
specification without reducing its behavioral contract.
