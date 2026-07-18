# Active Architecture and Language-Recovery Obligation Ledger

> **Status: COMPLETE — VERIFIED 2026-07-18.** This ledger covers active plans
> 10, 13, 15, and 16 plus the normative language/recovery wire contract. Final
> PASS dispositions and their amended-tree evidence are recorded below.

This is the live scope, dependency, acceptance, exception, and evidence map for
the single coherent implementation pass. It replaces the historical schema-2
S001-S015 ledger. The old completion claim remains only in git history and in
the explicitly invalidated `15-final.md`; it has no authority over this contract.

The user accepted the exact Gate-3 correction on 2026-07-18 by directing
execution to continue: the prerelease recovery wire now includes explicit
`tls`, `runtime_artifact`, and `type` roles, concrete TLS/runtime kinds, and a
dedicated global `value_type` fact. The documented unknown-role filter also has
an explicit `unknown` kind rather than colliding with the empty-list “all kinds”
sentinel. This is a contract correction, not an exception or a weakened
acceptance condition.

## Locked problem statement

```yaml
problem_statement:
  user_goal: >-
    Complete the modular architecture and make every C, C++, Objective-C, Swift,
    symbols-only, text, JSON, and header surface useful, aligned, process-free,
    evidence-accountable, and cross-platform.
  verified_baseline:
    date: 2026-07-18
    workspace_packages: 18
    existing_xtask_path: crates/xtask
    sole_missing_target_crate: macho-header-syntax
    snapshot_schema_asserted_by_live_tests: 2
    production_header_validator: XcrunClangValidator
  target_workspace_packages: 19
  target_snapshot_schema: 3
  non_goals_from_user:
    - process-backed inspection, recovery, demangling, or header validation
    - source-code reconstruction beyond evidence-supported declarations
    - implicit SDK or linked-binary traversal
  important_context:
    - The repository is prerelease and carries no compatibility obligation.
    - Existing dirty-tree source and plan edits are user work and must not be reset.
    - Work packages are dependency checkpoints, not separately shippable phases.
```

The target count is cross-footed as the 18 verified current packages plus the
one required `macho-header-syntax` package. The package list and manifest count
must be recorded again at WP0 before source ownership changes.

## Locked obligation ledger

`INCLUDED_NOT_YET_VERIFIED` means the obligation is mandatory and has no amended
PASS evidence yet. `BASELINE_PRESENT_REVERIFY_REQUIRED` means the live tree
already contains the named structure, but the amended gates still have to prove
that it remains correct.

| ID | Included obligation | Authority | Initial state | Required acceptance evidence |
| --- | --- | --- | --- | --- |
| A001 | Enforce the exact 19-package graph and ownership matrix, including `macho-header-syntax` and the shared report owner. | Plan 15 graph; wire authority | INCLUDED_NOT_YET_VERIFIED | Metadata, per-package trees, a passing valid graph fixture, and one failing fixture per forbidden edge. |
| A002 | Preserve the process-free minimal core, explicit parse policy, closed invariants, structured errors, and checked address/model construction. | Plan 15 WP1 | BASELINE_PRESENT_REVERIFY_REQUIRED | Core tree, strict/forensic valid and invalid fixtures, compile-fail constructors, docs, and architecture scan pass. |
| A003 | Preserve explicit strict/lossy instruction failure and propagate every lossy gap. | Plan 15 WP3 | BASELINE_PRESENT_REVERIFY_REQUIRED | Paired decode fixtures and syntax-aware rejection of silent `Result` dropping pass. |
| A004 | Implement selective dependency-planned analysis; excluded domains and collectors execute zero times. | Plans 15 and 16 | INCLUDED_NOT_YET_VERIFIED | Domain and collector execution-counter tests, resolved-plan goldens, and panicking unrequested collectors pass. |
| A005 | Implement snapshot schema 3 with four states, exact domain registry, canonical language payloads, and typed rejection of unversioned/v1/v2/future/mismatched input. | Plan 15; wire snapshot registry | INCLUDED_NOT_YET_VERIFIED | Per-domain schema-2 preservation hashes, schema-3 thin/fat goldens, and every rejection fixture pass. |
| A006 | Implement the normative common wire vocabulary, canonical JSON, stable IDs, closed registries, limits, and two-stage validation in `macho-analysis::report`, including explicit TLS/runtime/type roles and the global `value_type` fact. | Wire contract | INCLUDED_NOT_YET_VERIFIED | Registry equality test plus canonicalization, amended-v1 goldens, unknown-key, old/mixed-shape, enum, ID, bounds, duplicate, and referential-integrity rejection fixtures pass. |
| A007 | Complete in-process Rust, Itanium C++, and Swift demangling without a process fallback, including Mach-O underscore/TLV suffix normalization. | Plans 15 and 16 | INCLUDED_NOT_YET_VERIFIED | Unit/golden fixtures cover the supplied Talos names, malformed names, already-demangled names, and suffix restoration; process scan passes. |
| A008 | Make `macho symbols` and `macho ranges` useful without executing ObjC, Swift, C/C++, DWARF, RTTI, vtable, ABI-body, or header collectors unless explicitly requested. | Plan 16 symbols-only contract | INCLUDED_NOT_YET_VERIFIED | Panicking kitchen-sink collectors remain uncalled; aligned/color goldens and observation conservation pass. |
| A009 | Implement the canonical C/C++ `RecoveryReport`, exact reasons/evidence/limits, occurrence-safe identity, conflict preservation, explicit TLS/runtime/type entities, typed global values, and useful symbol-only ABI inventory. | Plan 16; wire recovery registry | INCLUDED_NOT_YET_VERIFIED | Thin/fat/symbol-only/DWARF/RTTI/vtable/header/ABI goldens plus image-header, TLS, class-presence, global-value, malformed, conservation, and conflict fixtures pass. |
| A010 | Implement safe C/C++ header projection from typed AST nodes with complete function, global/TLS, forward-type, and defined-type eligibility plus unresolved ledgers. | Plan 16; wire header registry | INCLUDED_NOT_YET_VERIFIED | Render/reparse/semantic validation fixtures cover eligible functions, globals/TLS, forward/defined types, runtime-artifact exclusion, imported-only exclusion, ABI-value exclusion, and each rejection reason without launching a process. |
| A011 | Implement the Objective-C report, encoding AST, semantic graph, category folding, referenced/partial/malformed accounting, and typed header projection. | Plan 10; wire ObjC registry | INCLUDED_NOT_YET_VERIFIED | Runtime family, graph cycle/ambiguity, encoding, thin/fat, zero-selection, header, and iMazing ledger assertions pass. |
| A012 | Implement descriptor/reflection-first Swift recovery with symbol-only fallback, exact partitions, occurrence-safe identity, and no false local definitions. | Plan 15; wire Swift registry | INCLUDED_NOT_YET_VERIFIED | Descriptor, reflection, mangling, reconciliation, symbol-only, malformed, thin/fat, filter, zero-selection, and iMazing ledger assertions pass. |
| A013 | Implement the offline hypothesis artifact exchange with exact bounds, source-equal deterministic excerpts, allowed operations, stale-digest rejection, and typed header validation. | Plan 13; wire hypothesis registry | INCLUDED_NOT_YET_VERIFIED | Bundle/response/report goldens and every schema/reference/operation/pinned-fact/limit/header rejection fixture pass without network or process access. |
| A014 | Create `macho-header-syntax` as the sole C/C++/Objective-C AST, parser, deterministic renderer, and syntax/semantic validation authority. | Plan 15 WP2/WP6; wire header registry | INCLUDED_NOT_YET_VERIFIED | Direct crate tests, valid/invalid syntax and semantic matrices, permitted tree, and duplicate-authority scan pass. |
| A015 | Preserve structural-only mutation and complete the existing workflow composition without an upward mutation edge. | Plan 15 WP5 | BASELINE_PRESENT_REVERIFY_REQUIRED | Mutation tree excludes analysis; strict reparse, rollback, structural preview, selected before/after analysis, and semantic diff fixtures pass. |
| A016 | Keep `macho` a truthful library façade and extend its exact feature matrix only for the new leaf and amended reports. | Plan 15 WP7 | BASELINE_PRESENT_REVERIFY_REQUIRED | No-default, individual, default, and full feature combinations plus dependency trees pass. |
| A017 | Complete CLI-owned output: aligned ANSI-aware columns, default terminal color, stable JSON envelope, header source, pure writers, channel separation, bare load-command ordinals, right-aligned dependency state, and unescaped/demangled range symbols. | Plan 15 WP8; Plan 16 CLI | INCLUDED_NOT_YET_VERIFIED | `info`, `deps`, `ranges`, language, JSON, failure-channel, capture/process parity, and strip-ANSI byte-equivalence goldens pass. |
| A018 | Remove production `XcrunClangValidator` and every inspection/recovery process path; permit process execution only in the isolated signing adapter and build tooling. | Plans 10, 13, 15, 16 | INCLUDED_NOT_YET_VERIFIED | Syntax-aware process-boundary scan, in-process validator fixtures, and cross-platform tests pass. |
| A019 | Extend the existing docs, release, architecture, continuous-integration, fuzz, benchmark, fixture, and module-size authorities for the amended contract. | Plan 15 WP9/WP10 | INCLUDED_NOT_YET_VERIFIED | `cargo xtask` commands, CI definition, corpus/fuzz builds, benchmark build, docs/version checks, and negative verifier fixtures pass. |
| A020 | Preserve all pre-existing user changes and record reproducible baseline, per-obligation, live-corpus, and final evidence without allowing verification to rewrite the tree. | Agent protocol | INCLUDED_NOT_YET_VERIFIED | Before/after dirty-path accounting, command transcripts, corpus hashes/assertions, and identical pre/post verifier tree digests are recorded. |

## Dependency order

The implementation order is binding because later checks consume earlier
contracts:

1. A020 baseline accounting and schema-2 domain goldens.
2. A001 and A006 graph plus common wire authority.
3. A014 shared header syntax and validation.
4. A002, A003, A007, and existing leaf-boundary reconciliation.
5. A004 and A005 selective analysis plus snapshot schema 3.
6. A008-A013 language/recovery/hypothesis behavior.
7. A015 and A016 mutation/workflow/façade integration.
8. A017 and A018 CLI/process delivery.
9. A019 whole-tree authorities and A020 closure evidence.

No checkpoint is a release boundary. A later failure reopens every obligation
whose acceptance evidence depends on the invalidated contract.

## Required verification order

1. Schema registry equality, schema goldens, and schema rejection fixtures.
2. `cargo xtask architecture`
3. Direct tests for `macho-header-syntax`, symbols, ObjC, Swift, C++, analysis,
   header inference, mutation, workflow, façade, and CLI.
4. Live Talos and iMazing acceptance commands when those recorded binaries are
   present; otherwise the ledger records `ENVIRONMENT_UNAVAILABLE`, never PASS.
5. `cargo xtask docs --check`
6. `cargo xtask release --check`
7. `cargo fmt --all -- --check`
8. `cargo check --workspace --all-targets --all-features`
9. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
10. `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
11. `cargo test --workspace --all-features`
12. `cargo bench --workspace --all-features --no-run`
13. `cargo xtask verify`
14. `cargo xtask verify-fuzz`
15. Independent metadata, package-count, core/mutation/minimal-façade tree,
    command-help, version, process scan, execution-counter, and output-byte
    comparisons after the composed verifier.

The final verifier must run without modifying tracked or untracked content. A
green subset, an unavailable corpus, or an old schema-2 PASS record is not
completion.

## Exception ledger

No exceptions, user exclusions, or weakened acceptance checks are approved.
The 2026-07-18 Gate-3 contradiction was resolved by an accepted specification
amendment before downstream implementation resumed; it is therefore not an
exception. Any further contradiction triggers the STOP rules in the owning plan
and must be resolved in the specification before downstream work continues.

## Current checkpoint state

| Contract group | State | Evidence location |
| --- | --- | --- |
| Baseline and preservation accounting | PASS | `15-amended-final.md` preservation and digest evidence |
| Common wire/schema authority | PASS | wire contract, registry, strict-wire, and workspace tests |
| Header-syntax authority | PASS | direct crate, ObjC integration, and architecture tests |
| Selective analysis and schema 3 | PASS | analysis, snapshot, execution-counter, and CLI tests |
| C/C++ and symbols-only recovery | PASS | focused tests and `16-live-corpus.md` amended rerun |
| Objective-C and Swift recovery | PASS | focused tests and iMazing assertions |
| Offline hypothesis exchange | PASS | header-infer direct and CLI artifact tests |
| Mutation, workflow, façade | PASS | direct packages, feature matrix, and workspace tests |
| CLI output and process boundary | PASS | output tests, live Talos output, and process scan |
| Whole-tree gates and closure evidence | PASS | composed verifier, fuzz build, and identical digests |

## Closure rule

The amended contract is complete only when A001-A020 each has dated evidence,
every mandatory portable gate passes, every available live-corpus ledger passes,
unavailable live corpora are explicitly classified, the exception ledger is
empty, and the verifier's pre/post content digests match. Until then the only
valid implementation verdicts are `PARTIAL`, `NOT READY`, or `BLOCKED`.

## Final obligation dispositions

| ID | Disposition | Acceptance evidence |
| --- | --- | --- |
| A001 | PASS | Metadata reports exactly 19 packages; architecture graph and exhaustive negative-edge fixtures pass. |
| A002 | PASS | Minimal core tree, strict/forensic tests, compile-time boundaries, docs, and architecture scans pass. |
| A003 | PASS | Instruction strict/lossy fixtures and the complete workspace suite pass with no silent-result-drop finding. |
| A004 | PASS | Selective analyzer and collector execution-counter tests prove excluded work executes zero times. |
| A005 | PASS | Schema-3 snapshots round-trip; unversioned, old, future, unknown, and mismatched documents are rejected. |
| A006 | PASS | Registry equality, canonicalization, amended-v1 shape, ID, bound, duplicate, and referential-integrity tests pass. |
| A007 | PASS | Rust-v0, Itanium, Swift, decoration, malformed, and TLV suffix demangling tests pass; Talos confirms live behavior. |
| A008 | PASS | Symbol/range conservation and targeted-planning tests pass; live ranges remain aligned and demangled. |
| A009 | PASS | C/C++ focused tests plus both live binaries prove TLS/runtime/type/value facts, conflicts, anchors, and conservation. |
| A010 | PASS | Typed function/global/TLS/type projection, unresolved coverage, render/reparse, and semantic validation pass in-process. |
| A011 | PASS | ObjC runtime/graph/encoding/header suites and both iMazing slices pass; the full-suite forward-declaration regression is covered. |
| A012 | PASS | Swift descriptor/reflection/reconciliation/filter tests and both iMazing slices preserve exact defined/partial/reference partitions. |
| A013 | PASS | Offline bundle/prompt/response/apply tests enforce digests, bounds, operations, pinned facts, and typed headers without process/network access. |
| A014 | PASS | `macho-header-syntax` direct parser/render/validation tests, ObjC class-forward regression, and ownership scans pass. |
| A015 | PASS | Mutation remains below analysis; rollback, strict reparse, preview, workflow, and workspace tests pass. |
| A016 | PASS | No-default, individual, default, full, and workspace façade feature combinations compile and test. |
| A017 | PASS | Output unit/integration tests and live Talos `info`, `deps`, and `ranges` prove alignment, color, JSON, ordinals, and channel separation. |
| A018 | PASS | Production scan finds process launch only in the signing adapter; recovery/header tests pass with no SDK or host process. |
| A019 | PASS | Architecture, docs, release, fmt, check, clippy, rustdoc, tests, benchmark, CI contract, and nightly fuzz build pass. |
| A020 | PASS | User changes were preserved; live hashes/counts are recorded; verifier pre/post digest is identical at `4d7d0a…3419`. |

Final evidence: `plans/evidence/15-amended-final.md`. Exception ledger: empty.
