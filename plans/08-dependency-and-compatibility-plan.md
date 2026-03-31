# Plan: Dependency Graph and Compatibility Analysis

## Status

This plan combines the earlier import/export graph draft and the separate
provider/target compatibility report draft into one dependency-analysis track.

## Objective

Build one canonical dependency model that understands:

- linked dylibs and ordinals
- imports, exports, and reexports
- provider ownership of imported symbols
- provider/target compatibility decisions

## Why This Matters

Compatibility checking is only as good as its dependency model. A standalone
compat report that re-derives ordinals, load paths, or reexports would drift
from the graph used elsewhere. The graph and the verdict system need the same
normalized source of truth.

## Current Repo Leverage

- `src/dyld/bind.rs`, `src/dyld/chained.rs`, `src/dyld/exports.rs`
- `src/model/load_command.rs`
- `src/analysis/snapshot.rs`
- the metadata normalization planned in `06-image-api-plan.md`

## Scope

### In Scope

- one dependency graph with normalized ordinals and dylib identities
- import/export/reexport queries
- provider lookup and graph validation helpers
- a machine-readable compatibility report built on the graph
- human and JSON CLI output

### Out of Scope

- filesystem validation of whether a dylib actually exists on disk
- recursive full-system resolution of reexport chains outside provided inputs
- link-time emulation beyond binary-visible facts

## Design

Separate the concepts but share the normalization:

- `depgraph` owns dependency extraction, ordinals, imports, exports, and
  reexports
- `compat` owns verdicts and findings, but consumes the graph and plan 06's
  normalized image metadata instead of re-parsing load commands itself

That keeps one source of truth for linked dylibs, ordinals, and path facts.

## Milestones

### Milestone 1: Dependency Normalization

Goal: normalize dylib identity and import/export ownership.

Work:

- build ordinal resolution on top of plan 06 metadata
- normalize imports across chained fixups and legacy binds
- enrich exports with reexport provider information

Acceptance:

- a caller can ask which dylib an import belongs to without load-command math
- ordinals and special lookup modes are explicit in the model

### Milestone 2: Public Dependency Graph

Goal: expose the reusable graph surface.

Work:

- add graph construction and indexes
- support queries such as provider-of, imports-from, reexports, and validation
- keep graph output stable for CLI and JSON consumers

Acceptance:

- import/export ownership can be queried through one public API
- graph validation catches malformed ordinals or unresolved provider state

### Milestone 3: Compatibility Report

Goal: build compatibility verdicts on the same graph.

Work:

- add `CompatReport`, categories, and verdict severities
- implement checks for arch, platform, min OS, file type, dylib versions,
  rpaths, import/export coverage, weak imports, and namespace mode
- wire CLI output and exit-code policy

Acceptance:

- compatibility checks no longer duplicate dependency normalization logic
- warnings vs incompatibilities are explicit and machine-readable

## Dependencies

- depends directly on plan 06 for canonical load-path and dylib metadata
- benefits from plan 05 for future cross-slice provider parity work

## Risks

- compatibility output will lose trust quickly if ordinal resolution is shaky
- reexport handling can create false confidence when the transitive provider is
  unavailable

## Mitigations

- make ordinal normalization reusable and test it independently
- downgrade unverifiable reexport cases to explicit warnings or partial results

## Done Means

- imports, exports, reexports, and compatibility verdicts all share one
  dependency model
- downstream tools stop reimplementing ordinal and provider-resolution logic
- machine-readable compatibility checks are trustworthy enough for automation
