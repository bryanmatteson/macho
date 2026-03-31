# Plans

This directory now contains the canonical roadmap for `macho`.

The previous draft set had two problems:

- duplicate numbering (`06` through `10` existed twice)
- overlapping scopes (`ObjC resolver`, `fat parity`, `load-path metadata`,
  `compat`, and `symbol ranges` were split across competing documents)

Those drafts have been consolidated into the plan set below. Plans `01` through
`05` describe the analysis foundation that is already partially represented in
the current tree (`src/analysis/`, `src/diff/`, `src/audit/`,
`src/container_analysis/`, `src/objc/graph.rs`, `src/swift/`). Plans `06`
through `09` are the canonical follow-on API and analysis tracks.

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

## Repository Anchors

These plans are intentionally tied to the current repository layout:

- CLI entrypoint: `src/main.rs`
- Command surfaces: `src/commands/`
- Snapshot/diff/audit: `src/analysis/`, `src/diff/`, `src/audit/`
- Editing: `src/edit/`
- Validation: `src/validate/`
- ObjC and Swift metadata: `src/objc/`, `src/swift/`
- Container analysis: `src/container_analysis/`, `src/model/container.rs`
- Dyld/import-export parsing: `src/dyld/`

## Superseded Drafts

The following drafts were merged into the canonical set and intentionally
removed:

- old ObjC resolver draft merged into `04-objc-swift-graph-plan.md`
- old fat-parity draft merged into `05-multi-image-analysis-plan.md`
- old load-path/install-name draft merged into `06-image-api-plan.md`
- old callsite/xref and symbol-range drafts merged into
  `07-symbol-and-xref-resolution-plan.md`
- old import/export graph and compat drafts merged into
  `08-dependency-and-compatibility-plan.md`
- old string-region and vtable drafts merged into
  `09-binary-data-analysis-plan.md`
