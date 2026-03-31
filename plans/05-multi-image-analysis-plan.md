# Plan: Multi-Image and Container Analysis

## Status

This is the canonical container plan. It consolidates the earlier multi-image
analysis draft and the separate fat-binary parity helper draft.

## Objective

Turn the existing container-analysis baseline into a coherent public surface for
thin binaries, fat binaries, filesets, and later read-only dyld shared cache
workflows.

## Why This Matters

Modern Apple binaries are frequently container-shaped rather than single-image.
`macho` already has `ContainerSnapshot`, `ContainerReport`, parity logic, and
fileset awareness, but those capabilities still need to converge on one stable
API that downstream tools can query without rebuilding container semantics by
hand.

## Current Repo Leverage

- `src/model/container.rs`
- `src/analysis/snapshot.rs`
- `src/container_analysis/mod.rs`, `parity.rs`, `resolve.rs`
- `src/commands/container.rs`, `src/commands/fileset.rs`
- `src/parse/fat.rs`

## Scope

### In Scope

- first-class container reports for thin, fat, and fileset inputs
- public parity and cross-slice query helpers on container types
- slice-to-slice diff helpers backed by the existing diff model
- fileset enumeration and inspection
- dyld shared cache phase 1: read-only indexing and extraction

### Out of Scope

- shared cache editing
- full loader emulation
- kernelcache-specific semantics in the first pass

## Design

Keep `ContainerSnapshot` as the canonical comparison substrate, but expose the
useful results directly on `MachContainer` and `FatBinary` so callers do not
need to manually build snapshots for common operations.

The plan should converge on:

- one parity model with configurable domains
- one cross-slice diff path
- one fileset report shape
- one container CLI that reflects the same library surface

## Milestones

### Milestone 1: Stabilize Current Container Surface

Goal: make the existing reports and commands coherent.

Work:

- align `ContainerReport`, fileset inspection, and CLI output
- remove duplicate container/fat/fileset terminology
- define the canonical parity domains and report structure

Acceptance:

- thin vs fat vs fileset reporting is consistent
- users can inspect fileset members and parity from the same product surface

### Milestone 2: Public Parity and Cross-Slice Helpers

Goal: promote container analysis from internal reports to reusable APIs.

Work:

- add `parity_report()` / `check_parity()` style helpers
- add `diff_slices()` using the existing diff model
- add convenience queries such as `common_exports()`, `divergent_exports()`,
  `common_imports()`, and `all_signed()`
- support selective parity domains

Acceptance:

- downstream tools can ask container-level questions without building custom
  snapshot logic
- parity failures are structured and automation-friendly

### Milestone 3: Cross-Image Resolution and dyld Shared Cache V1

Goal: broaden the container model without fragmenting it.

Work:

- extend cross-image ownership and divergence reporting
- keep fat/fileset resolution tied to the same snapshot vocabulary
- add read-only dyld shared cache indexing and extraction

Acceptance:

- cross-slice or cross-member ownership queries reuse one model
- dyld shared cache extraction feeds the normal parser and command set

## Dependencies

- builds directly on `analysis::snapshot`, `diff`, and current
  `container_analysis`
- plan 08 can reuse these helpers for cross-slice dependency or provider-parity
  checks

## Risks

- parity semantics can sprawl if every domain grows custom rules
- shared cache support can become a project of its own

## Mitigations

- keep parity domains explicit and configurable
- keep shared cache work read-only and extraction-first in V1

## Done Means

- container analysis is a first-class public API rather than an internal report
- fat parity, fileset inspection, and cross-slice diffing no longer live in
  separate plan documents or disconnected code paths
- multi-image workflows reuse the same core snapshot and diff vocabulary
