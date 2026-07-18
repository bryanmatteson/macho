# Architecture and Recovery Implementation Checkpoint

Date: 2026-07-18  
Historical checkpoint verdict: `BLOCKED_AT_ACCEPTED_CONTRACT_STOP`  
Current verdict: `PASS` — see `15-amended-final.md`

This file records implementation evidence only. It does not edit the accepted
obligation ledger or normative wire contract.

## Implemented in this pass

- Added the nineteenth workspace package, `macho-header-syntax`, as the shared
  in-process C/C++/Objective-C AST, parser, renderer, and semantic validator.
- Removed inspection/recovery compiler subprocesses; process execution remains
  isolated to the signing adapter.
- Added modern Swift and Rust-v0 demangling, including Mach-O decoration and
  recognized TLV-suffix preservation.
- Added ANSI-aware aligned output for `info`, `deps`, and `ranges`, bare
  right-aligned load-command/dependency ordinals, terminal color resolution,
  and stable JSON delivery.
- Added canonical C/C++, Objective-C, Swift, and offline hypothesis reports,
  strict schema decoding, observation conservation, collector plans/execution
  ledgers, bounded ABI execution, and typed header correlation.
- Added descriptor/reflection-first Swift field, parent, conformance, and
  associated-type recovery and occurrence-safe entity identity.
- Added strict offline hypothesis bundle/response/report validation with no
  network, provider, SDK, compiler, or host-process dependency.
- Added schema-v3 snapshot rejection of unversioned, v1, v2, future, unknown-
  field, and domain/payload-mismatched documents.
- Added negative recovery validation for duplicate IDs, dangling references,
  asymmetric conservation, and collector execution outside the resolved plan.
- Added exact selected-target ABI execution proof and strength-aware field
  reconciliation: stronger evidence replaces weaker disagreement, while equal-
  strength disagreement remains conflicted.
- Fixed parallel CLI fixture collisions by making temporary paths process- and
  sequence-unique.

## Verified checkpoint

The following current-tree checks passed after the latest changes:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo xtask architecture
cargo test -p macho-header-syntax --all-features
cargo test -p macho-analysis report::recovery::validate::tests --all-features
cargo test -p macho-analysis report::recovery_execute::types::tests --all-features
cargo test -p macho-header-infer --all-features
cargo test -p macho-cli --test c_tests --all-features
cargo test -p macho-cli --test cpp_tests --all-features
cargo test -p macho-cli --test cpp_cli_tests --all-features
cargo test -p macho-cli --test header_infer_tests --all-features
cargo test -p macho-cli --test objc_tests --all-features
cargo test -p macho-cli --test swift_tests --all-features
cargo test -p macho-cli --test analysis_tests --all-features
cargo test -p macho-cli --test inspect_tests --all-features
cargo xtask docs --check
cargo xtask release --check
cargo check --workspace --all-targets --all-features
RUSTDOCFLAGS='-D warnings' cargo doc --workspace --all-features --no-deps
```

The first workspace-wide test attempt found and led to fixes for unresolved
typedef validation and parallel fixture collisions. It was intentionally not
rerun as a claimed final gate after the live-corpus STOP condition. The composed
`cargo xtask verify`, benchmark build, and fuzz build therefore remain unclaimed.

## Accepted-contract contradiction

The binding plan requires the C surface to represent `function`, `data`, `TLS`,
`runtime artifact`, and `unknown`, and requires `_mh_execute_header` to be a
runtime artifact. The normative registry instead closes `EntityKind` and
`EntityRole` without `tls` or `runtime_artifact`. It contains
`EntityKind::type` but no `EntityRole::type`, preventing a canonical class entity
from satisfying the existing entity model.

The same canonical `RecoveredEntity` has no source value-type fact for a C/C++
global, while A010 requires complete global-declaration projection. Reusing a
function return-type field for a variable would falsify the schema rather than
implement it.

Resolving this requires a Gate-3 contract amendment, at minimum:

1. add closed `tls`, `runtime_artifact`, and `type` roles/kinds with exact
   selection and header-eligibility semantics;
2. add a typed value-type fact for data/TLS entities, including evidence,
   conflicts, gaps, canonical JSON, hypothesis operations, and header
   projection;
3. add migration-free schema goldens and negative fixtures for the amended
   prerelease wire;
4. rerun acceptance before implementation resumes.

No exception or weakened assertion has been recorded. A006, A009, A010, A019,
and A020 remain open, and the overall implementation cannot honestly be marked
complete under the accepted contract.

## Gate-3 amendment acceptance

The user accepted the exact correction above on 2026-07-18 by directing the
execution to continue. The normative wire, plan 16, and A001-A020 ledger were
amended together to add explicit TLS/runtime/type representation and the
dedicated global value-type fact. This checkpoint remains historical evidence
of the STOP; subsequent implementation and verification evidence is appended
separately and does not rewrite this result.

## Post-amendment completion

The accepted amendment was implemented without a compatibility fork: the
prerelease v1 recovery wire and its goldens were replaced atomically. Runtime
artifacts, TLS, C++ type entities, explicit unknown selection, global
`value_type`, variable DWARF/header correlation, safe global/type projection,
closed registry equality, and referential/header-coverage validation now share
one canonical report authority.

The full direct package sweep, Talos/iMazing corpus, workspace test suite,
benchmark build, composed verifier, nightly fuzz build, and independent graph,
process, version, output, and diff checks passed. A full-suite Objective-C
forward-declaration regression and one clippy style failure were corrected and
all affected gates were rerun. The final disposition, exact commands, live
counts, and verifier digests are recorded in `15-amended-final.md` and the
amended rerun section of `16-live-corpus.md`.
