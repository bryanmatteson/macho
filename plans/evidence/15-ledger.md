# Plan 15 Obligation Ledger

This file is the live scope, acceptance, verification, exception, and coverage
ledger for Plan 15. The plan itself is the accepted immutable feature contract.
No requested item is removed by this ledger.

## Problem statement

```yaml
problem_statement:
  user_goal: Implement plans/15-architecture-coherence-implementation-plan.md.
  current_pain: The live workspace compiles and tests but has inverted ownership, open construction paths, eager analysis, delivery concerns in the facade, documentation/version drift, and incomplete quality authorities.
  desired_outcome: One coherent 0.2.0 workspace satisfying every Plan 15 work package and final gate.
  non_goals_from_user: []
  important_context:
    - The repository is prerelease and carries no backward-compatibility obligation.
    - Pre-existing dirty-tree changes are implementation inputs and must not be reset.
```

## Locked scope ledger

| ID | Included obligation | Source | Disposition | Acceptance evidence |
| --- | --- | --- | --- | --- |
| S001 | Enforce the exact workspace member and dependency graph. | Plan 15 graph | INCLUDED | `cargo xtask architecture`, metadata, and per-crate trees pass. |
| S002 | Close core parsing, policy, limits, addressing, models, construction, errors, and diagnostics. | WP1 | INCLUDED | Core valid/invalid fixtures, docs, and dependency tree pass. |
| S003 | Extract symbols, dyld, code signing, DWARF, ObjC, Swift, and C++ metadata leaves. | WP2 | INCLUDED | Each leaf compiles/tests independently and has only permitted edges. |
| S004 | Make instruction decode failures returned or represented at every caller. | WP3 | INCLUDED | Strict/lossy paired tests and source scan pass. |
| S005 | Implement selective dependency-driven analysis and snapshot schema v2 with four states. | WP4 | INCLUDED | Runner counters, state fixtures, and schema rejection tests pass. |
| S006 | Separate structural mutation from semantic workflow composition. | WP5 | INCLUDED | Mutation tree excludes analysis; rollback/reparse/workflow fixtures pass. |
| S007 | Split large mixed modules and establish pure external-tool adapter boundaries. | WP6 | INCLUDED | Size/process scans and fake-adapter tests pass. |
| S008 | Rebuild `macho` as the exact feature-gated library façade. | WP7 | INCLUDED | Feature combination matrix and minimal dependency tree pass. |
| S009 | Move grammar, input, output, rendering, writers, adapters, and exit policy into `macho-cli`. | WP8 | INCLUDED | Injected/process I/O, golden, schema, channel, usage, and exit tests pass. |
| S010 | Bind README/help/diagnostic docs, workspace 0.2.0 version, changelog, and tag checks to executable authorities. | WP9 | INCLUDED | `cargo xtask docs --check` and `release --check` plus negative fixtures pass. |
| S011 | Add in-repo CI, deterministic shared fixtures, fuzz targets/corpora, and Criterion benchmarks. | WP9 | INCLUDED | Workflow files exist; fixture tests, fuzz build, and bench build pass. |
| S012 | Enforce strict formatting, Clippy, missing-doc, test, fuzz, benchmark, and architecture gates. | WP9/WP10 | INCLUDED | `cargo xtask verify` passes without modifying the tree. |
| S013 | Remove obsolete eager APIs, aliases, direct process/output paths, and stale documentation. | WP10 | INCLUDED | Whole-tree architecture scan and explicit resurrection checks pass. |
| S014 | Preserve pre-existing user changes through ownership moves. | Agent protocol | INCLUDED | Final diff accounting maps every original dirty path to retained code or an intentional Plan 15 replacement. |
| S015 | Record baseline, checkpoint, and final evidence. | WP0/WP10 | INCLUDED | Baseline, live ledger, and final evidence documents are complete. |

## Acceptance contract

The result is acceptable only when every S001-S015 item is satisfied, no item is
silently weakened, every final verification command is run, and independent
metadata/tree/help/version/I/O inspections agree with the verifier. Any failed
or unavailable included item makes the verdict `PARTIAL`, `NOT READY`, or
`BLOCKED` rather than `COMPLETE`.

Unacceptable results include a green workspace that retains a forbidden edge,
a skipped fuzz or benchmark build, tests that only filter output after eager
execution, a façade that still owns delivery code, or a verifier that succeeds
through placeholder command paths.

## Verification plan

Required commands, in contract order:

1. `cargo xtask architecture`
2. `cargo xtask docs --check`
3. `cargo xtask release --check`
4. `cargo fmt --all -- --check`
5. `cargo check --workspace --all-targets --all-features`
6. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
7. `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps`
8. `cargo test --workspace --all-features`
9. `cargo bench --workspace --all-features --no-run`
10. `cargo fuzz build`
11. independent metadata, core/mutation/minimal-façade trees, help, version, and
    process-versus-injected I/O comparisons from the plan.

## Exception ledger

No exceptions are approved. Any discovered exception is added here before work
continues across the affected boundary.

## Checkpoint coverage

| Work package | State | Evidence |
| --- | --- | --- |
| WP0 | COMPLETE | Baseline is recorded; xtask commands are executable; every forbidden edge and source pattern has a negative fixture. |
| WP1 | COMPLETE | Strict/forensic matrices, typed parser errors, closed fat/address invariants, zero-allocation iteration, and core tree checks pass. |
| WP2 | COMPLETE | All seven metadata leaves exist, pass direct crate tests, retain typed errors, use permitted dependencies, and contain no process launches. |
| WP3 | COMPLETE | Strict and lossy decode tests pass; mutation retains typed decode/encode sources; the syntax-aware scan rejects silent result dropping. |
| WP4 | COMPLETE | Analyzer plan resolution, four states, schema v2 rejection, limits, advisory/required dependencies, and execution-counter tests pass. |
| WP5 | COMPLETE | Mutation has no analysis edge; structural rollback/reparse and selected semantic workflow tests pass. |
| WP6 | COMPLETE | Declared C, C++ ABI, diff/report, and patch/trampoline seams exist; syntax-aware size/process checks and fake adapters pass. |
| WP7 | COMPLETE | The exact feature authority and every feature combination compile; the minimal façade tree contains only core. |
| WP8 | COMPLETE | CLI owns grammar, inputs, adapters, rendering, writers, and exit policy; process/injected byte parity and channel/exit cases pass. |
| WP9 | COMPLETE | Version 0.2.0, changelog, generated README authority, release/docs checks, CI, corpora, seven fuzz targets, and Criterion benchmarks pass. |
| WP10 | COMPLETE | Full verifier, independent metadata/trees/help/version, all fuzz smokes, real macOS adapters, source resurrection scan, and final evidence pass. |

## Closure

All S001-S015 obligations are complete. `cargo xtask verify` passed in the
required order. A content digest over the complete tracked diff plus every
untracked file was
`d800cab6dea63df640949ec737885c237443bfa729365d0ec9ee2e7a3302cd5c`
both before and after the final verifier run, proving that the verifier did not
modify the implementation tree. The exception ledger remains empty.

Detailed commands, independent checks, fuzz and adapter results, and the S014
pre-existing-change accounting are recorded in
[`15-final.md`](15-final.md).
