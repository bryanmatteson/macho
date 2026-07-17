# Plans

This directory now contains the canonical roadmap for `macho`.

The previous draft set had two problems:

- duplicate numbering (`06` through `10` existed twice)
- overlapping scopes (`ObjC resolver`, `fat parity`, `load-path metadata`,
  `compat`, and `symbol ranges` were split across competing documents)

Those drafts have been consolidated into the plan set below. Plans `01` through
`13` remain the feature authorities. Plan `15` is the architecture-completion
authority for the workspace now present under `crates/`. Plan `14` is retained
only as historical context for the first split and is superseded by plan `15`.

## Canonical Plan Set

### Foundation and Completion Track

1. `01-diff-plan.md`
2. `02-transactional-patching-plan.md`
3. `03-audit-plan.md`
4. `04-objc-swift-graph-plan.md`
5. `05-multi-image-analysis-plan.md`

### Public API and Deep Analysis Track

6. `06-image-api-plan.md`
7. `07-symbol-and-xref-resolution-plan.md`
8. `08-dependency-and-compatibility-plan.md`
9. `09-binary-data-analysis-plan.md`
10. `10-objc-header-fidelity-plan.md`
11. `11-cpp-header-fidelity-plan.md`
12. `12-c-header-fidelity-plan.md`
13. `13-llm-header-inference-plan.md`

### Architecture Integration Track

15. `15-architecture-coherence-implementation-plan.md`

## Recommended Sequence

The plans are not strictly linear, but this is the dependency-respecting order
that keeps shared infrastructure from being reinvented:

1. `01-diff-plan.md`
2. `03-audit-plan.md`
3. `02-transactional-patching-plan.md`
4. `04-objc-swift-graph-plan.md`
5. `05-multi-image-analysis-plan.md`
6. `06-image-api-plan.md`
7. `07-symbol-and-xref-resolution-plan.md`
8. `08-dependency-and-compatibility-plan.md`
9. `09-binary-data-analysis-plan.md`
10. `10-objc-header-fidelity-plan.md`
11. `11-cpp-header-fidelity-plan.md`
12. `12-c-header-fidelity-plan.md`
13. `13-llm-header-inference-plan.md`

Apply `15-architecture-coherence-implementation-plan.md` as one integration
pass against the current tree. Its work packages are dependency checkpoints,
not additional release phases after the feature plans.

## Dependency Notes

- `04-objc-swift-graph-plan.md` is the canonical home for ObjC method
  resolution and Swift type surfacing. There is no separate resolver plan now.
- `05-multi-image-analysis-plan.md` is the canonical home for fat-binary parity
  and cross-slice helpers. There is no separate parity-helper plan now.
- `06-image-api-plan.md` is the canonical home for normalized load-path,
  install-name, and linked-dylib metadata. There is no separate load-path plan
  now.
- `07-symbol-and-xref-resolution-plan.md` combines code-range ownership with
  callsite/xref resolution so branch decoding, stub resolution, and symbol
  sizing share one address model.
- `08-dependency-and-compatibility-plan.md` combines the import/export graph
  with provider/target compatibility checking so ordinals, reexports, and load
  paths have one source of truth.
- `09-binary-data-analysis-plan.md` groups string-region discovery and C++
  vtable indexing because both are data-surface discovery features used by
  patching and reverse-engineering workflows.
- `10-objc-header-fidelity-plan.md` is the canonical home for raising
  `macho objc --headers` toward class-dump-style fidelity using structured
  ObjC encoding parsing and richer header rendering.
- `11-cpp-header-fidelity-plan.md`, `12-c-header-fidelity-plan.md`, and
  `13-llm-header-inference-plan.md` extend the roadmap from metadata recovery
  into higher-fidelity declaration reconstruction and evidence-driven inference.
- `15-architecture-coherence-implementation-plan.md` is the canonical,
  single-pass execution authority for completing the live workspace design from
  the core library outward through the CLI. It supersedes plan 14's pre-workspace
  target graph and phased migration.

Plans `01` through `13` remain feature authorities where their behavior is not
in conflict with plan 15. Plan 15 owns crate placement, dependency direction,
shared execution contracts, public delivery boundaries, and final gates.

## Repository Anchors

These plans are intentionally tied to the current repository layout:

- Workspace authority: `Cargo.toml`
- Core parsing/model: `crates/macho-core/src/`
- Instruction handling: `crates/macho-insn/src/`
- Snapshot/diff/audit/reconstruction: `crates/macho-analysis/src/`
- Mutation: `crates/macho-mutate/src/`
- Façade and current command ownership: `crates/macho/src/`
- CLI entrypoint: `crates/macho-cli/src/main.rs`
- Architecture completion contract:
  `15-architecture-coherence-implementation-plan.md`

## Superseded Drafts

The following drafts were merged into or superseded by the canonical set:

- old ObjC resolver draft merged into `04-objc-swift-graph-plan.md`
- old fat-parity draft merged into `05-multi-image-analysis-plan.md`
- old load-path/install-name draft merged into `06-image-api-plan.md`
- old callsite/xref and symbol-range drafts merged into
  `07-symbol-and-xref-resolution-plan.md`
- old import/export graph and compat drafts merged into
  `08-dependency-and-compatibility-plan.md`
- old string-region and vtable drafts merged into
  `09-binary-data-analysis-plan.md`
- `14-workspace-crate-refactor-plan.md` is retained for history but superseded by
  `15-architecture-coherence-implementation-plan.md`
