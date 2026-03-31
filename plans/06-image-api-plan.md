# Plan: Slice-Aware Image Inspection and Metadata API

## Status

This is the canonical image-inspection plan. It consolidates the earlier
`ImageInspector` draft and the separate load-path/install-name metadata draft.

## Objective

Expose one stable public entrypoint for slice-aware inspection that covers both
cheap identity metadata and cached deeper parses.

## Why This Matters

Several follow-on plans need the same normalized facts:

- arch, platform, UUID, file type, image base
- install name, linked dylibs, ordinals, rpaths, target triple
- symbols, exports, imports, ObjC metadata, code-signing state

Without a canonical inspection layer, every command and downstream consumer
reassembles those facts differently.

## Current Repo Leverage

- `src/model/container.rs`
- `src/analysis/mod.rs`, `src/analysis/snapshot.rs`
- `src/commands/inspect.rs`
- `src/dyld/`
- `src/codesign/`
- `src/objc/`

## Scope

### In Scope

- a slice-aware `ImageInspector<'data>` entrypoint
- a cheap normalized metadata view for install names, dylibs, ordinals,
  rpaths, versions, and platform facts
- lazy cached access to symbols, exports, imports, ObjC metadata, codesign,
  and later `ObjCGraph`
- path-resolution helpers for `@rpath`, `@loader_path`, and
  `@executable_path`
- migration of CLI inspection code onto the shared API

### Out of Scope

- filesystem existence checks for resolved paths
- full package/framework resolution outside the binary itself
- replacing every low-level parser with new wrapper types

## Design

Use one top-level inspector and one cheap metadata sub-structure:

- `ImageInspector<'data>` is the canonical slice-bound facade
- `ImageInfo` is the normalized load-command-derived metadata payload returned
  by the inspector
- expensive parses are cached behind the inspector
- cheap metadata is parsed once and reused by later plans instead of creating
  a second top-level load-path API

This keeps plan 08's dependency graph and compat checks from inventing their
own ordinal or dylib-normalization logic.

## Milestones

### Milestone 1: Core Inspector and Metadata

Goal: establish the canonical entrypoint and cheap facts.

Work:

- add `ImageInspector<'data>`
- add `ImageInfo`, `LinkedDylib`, and platform/version helpers
- support slice selection by arch
- normalize install name, dylib list, ordinals, rpaths, target triple, and
  source/build version facts

Acceptance:

- callers can open thin or fat binaries through one API
- load-path and linked-dylib metadata are normalized once, not per feature

### Milestone 2: Cached Deep Parses

Goal: expose the fallible, expensive views safely.

Work:

- cache symbols, exports, imports, ObjC metadata, codesign, and later
  `ObjCGraph`
- expose address-map and raw-mach escape hatches
- add path-resolution helpers on top of `ImageInfo`

Acceptance:

- repeated calls do not re-run deep parsers
- binaries with missing optional metadata degrade cleanly

### Milestone 3: CLI and Downstream Adoption

Goal: prove the inspector is the new source of truth.

Work:

- migrate `inspect` and related commands away from ad hoc load-command walks
- make plan 04 and plan 08 consume the shared inspector surface
- lock down JSON-friendly output contracts for cheap metadata

Acceptance:

- command implementations stop duplicating normalization logic
- later plans depend on `ImageInspector` rather than inventing their own entry
  layer

## Dependencies

- foundation for plans 04, 07, and 08
- benefits from the snapshot vocabulary already present in `src/analysis/`

## Risks

- the API can become too broad if every parser detail is surfaced directly
- careless layering could create both `ImageInspector` and `ImageInfo` as
  competing public entrypoints

## Mitigations

- keep `ImageInspector` as the only top-level facade
- keep `ImageInfo` as a cheap normalized payload owned by the inspector

## Done Means

- `ImageInspector` is the default library entrypoint for slice-aware inspection
- load-path, install-name, and ordinal metadata have one canonical home
- commands and downstream tools stop rebuilding the same metadata adapters
