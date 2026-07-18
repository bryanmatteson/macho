# Plan: In-Process Cross-Platform Signing

## Status and authority

This document is the reviewed and accepted feature contract for removing the
production `xcrun codesign` dependency while preserving useful ad-hoc and
identity-backed signing. The user accepted execution in the instruction
`plan, design-plan-review, implement`; Gate 2 passed before source implementation
began. The dependency-ordered work packages below are one coherent execution
pass, not separately shippable phases.

[`15-architecture-coherence-implementation-plan.md`](15-architecture-coherence-implementation-plan.md)
remains authoritative for workspace ownership, dependency direction, CLI
delivery, output channels, and whole-tree verification. This plan amends its
host-signing exception: production signing is an in-process library capability,
and production code launches no signing process or discovers Xcode tools.

## Problem statement

```yaml
problem_statement:
  user_goal: "Remove signing's xcrun requirement and implement the replacement."
  current_pain: "The only host signing adapter shells out to xcrun codesign, is not portable, and is not wired into a useful CLI path; the existing hand-written ad-hoc signer hashes bytes before its final load-command rewrite."
  desired_outcome: "macho can apply a patch and produce an in-process verified ad-hoc or PKCS#12-backed signature on macOS, Linux, and Windows without launching a process."
  non_goals_from_user: []
  important_context:
    - "macho-workflow already accepts an injected SignatureProvider."
    - "macho patch currently performs mutation without signing and only prints external codesign guidance."
    - "macho-codesign owns the repository's parsed signature report."
```

## Verified live baseline

The live tree was re-read on July 18, 2026:

- `crates/macho-cli/src/adapters/signing.rs` is the sole production `xcrun`
  signing implementation and has no caller;
- `crates/macho-cli/src/commands/subcommands/patch.rs` always invokes the
  workflow with `signing: None`;
- `crates/macho-mutate/src/sign.rs` owns `SignatureProvider`, an ad-hoc
  provider, and the current hand-written signer;
- the hand-written signer computes CodeDirectory page hashes before adding the
  final `LC_CODE_SIGNATURE`, after which `MachoEditor::build` re-encodes the
  load-command region covered by those hashes;
- `macho-workflow` reparses and structurally validates provider output but does
  not verify CodeDirectory page or special-slot digests;
- `macho-codesign` parses CodeDirectory, SuperBlob, entitlement, and CMS
  presence but does not yet verify stored digests; and
- `apple-codesign` 0.29.0 supports Rust 1.81, thin and universal Mach-O
  signing, ad-hoc and key-backed signatures, explicit final-layout reservation,
  and in-process digest/CMS verification.

## Outcome

The accepted implementation provides all of the following in one repository
state:

1. no production `xcrun`, `codesign`, `rcodesign`, or other signing-process
   invocation;
2. one `SignatureProvider` implementation backed by `apple-codesign` with its
   default notarization/AWS feature disabled;
3. deterministic ad-hoc signing and explicit PKCS#12 certificate signing;
4. preservation of an existing identifier and entitlements unless explicitly
   overridden;
5. automatic in-process verification of every provider result before it leaves
   the signing boundary;
6. thin and selected/all-slice fat patch signing;
7. `macho patch` flags for signing mode, PKCS#12 password file, identifier, and
   entitlement input;
8. dry-run, text, and JSON output that report the actual signing outcome;
9. atomic output behavior: credential, mutation, signing, parse, and digest
   failures occur before destination replacement; and
10. portable positive and negative fixtures plus a macOS Apple-tool oracle test
    that is test-only and never part of production execution.

## Coherence boundary

| Surface | Contract | Owner |
| --- | --- | --- |
| Mach-O signature parsing and user-facing signature metadata | Existing typed report remains authoritative | `macho-codesign` |
| Mutation-to-signing capability boundary | Backend-neutral bytes-in/bytes-out provider | `macho-mutate` |
| Final signature layout, CodeDirectory, SuperBlob, CMS, and digest verification | In-process `apple-codesign` backend | `macho-mutate::sign` |
| Signing order relative to mutation and after-analysis | Sign after prepared mutation, verify before after-analysis | `macho-workflow` |
| Credential files and password-file input | Explicit CLI filesystem input | `macho-cli` |
| Thin/fat selection and atomic output | Existing patch command transaction | `macho-cli` |
| Process prohibition and dependency policy | Positive and negative architecture checks | `xtask` and tests |

No requested signing behavior is hidden behind a disabled default. Keychain
identity-name lookup cannot be portable and is replaced by explicit certificate
and private-key material in a PKCS#12 file. Bundle resource sealing,
notarization, stapling, remote signing, and Keychain integration are not part of
the existing raw-Mach-O patch workflow and are not introduced by this contract.

## Falsification criteria

This plan is wrong if any accepted implementation exhibits one of these cases:

- a production signing path calls `Command`, `xcrun`, `codesign`, or
  `rcodesign`;
- ad-hoc signing is the only replacement and certificate-backed behavior is
  silently lost;
- any byte covered by the CodeDirectory changes after its digest is computed;
- a signer returns bytes with a missing CodeDirectory, a page-hash mismatch, a
  special-slot mismatch, or a malformed CMS container;
- ad-hoc verification treats the expected absence of CMS as corruption, or
  certificate verification ignores an absent/invalid CMS signature;
- signing an already signed input drops its identifier or XML entitlements
  without an explicit override;
- `--arch` signs or mutates an unselected fat slice;
- signing all fat slices produces overlapping, unaligned, or unparsable slices;
- a credential, password, entitlement, signing, verification, or structural
  failure modifies the destination;
- a password is accepted directly on the process command line;
- dry-run skips signing or verification and therefore reports an untested
  candidate;
- text and JSON disagree about signing mode or outcome;
- a test changes expected bytes to bless a digest mismatch;
- the `apple-codesign` notarization feature or its network/AWS dependency stack
  is enabled; or
- a required verifier is skipped or weakened to make the result pass.

## Feature contract

```yaml
feature_contract:
  title: "In-process cross-platform Mach-O signing"
  intent: "Replace the xcrun adapter and invalid hand-written signer with one portable, verified signing capability used by patch."
  included_behavior:
    - "Ad-hoc sign patched thin and fat Mach-O images in process."
    - "Certificate sign patched thin and fat Mach-O images from explicit PKCS#12 bytes and a password file."
    - "Preserve existing identifier and entitlements unless overridden."
    - "Verify CodeDirectory, special-slot, and CMS integrity before returning candidate bytes."
    - "Expose signing mode and outcome in dry-run, text, and JSON patch output."
  decision_required_behavior: []
  blocked_behavior: []
  user_excluded_behavior: []
  required_user_visible_changes:
    - "Add --sign-adhoc and --sign-p12 PATH to macho patch."
    - "Add --p12-password-file PATH, --identifier VALUE, and --entitlements PATH."
    - "Reject contradictory signing and strip-signature options as usage errors."
    - "Replace external codesign guidance with native macho patch signing guidance."
  required_internal_changes:
    - "Delete HostSignatureProvider and the hand-written CodeDirectory builder."
    - "Add a configured in-process provider and typed verification result."
    - "Mark signed structural previews as signed only after provider verification."
    - "Keep apple-codesign outside macho-core and macho-codesign parser ownership."
    - "Extend architecture source and dependency checks."
  required_error_handling:
    - "Classify CLI option conflicts and missing signing-only prerequisites as usage failures."
    - "Classify unreadable/non-UTF-8 password files and entitlement files as input failures."
    - "Classify malformed PKCS#12, wrong passwords, signing failures, and verification failures as typed signing failures."
    - "Return no signed candidate when verification reports a disallowed problem."
  required_edge_cases:
    - "Unsigned and already signed inputs; explicit and preserved identifiers; no, XML, and malformed entitlements; empty/wrong PKCS#12 passwords; thin arm64/x86_64; all and selected fat slices; dry-run; in-place and separate output; post-sign byte tampering."
  compatibility_requirements:
    - "Preserve existing patch operations, architecture selection, atomic write, output capture, and machine envelope behavior."
    - "Remove macOS Keychain identity-name semantics rather than pretending they are portable."
  performance_requirements:
    - "Signing work is linear in input bytes plus signature material and retains no duplicate whole-binary copy beyond the backend and final candidate buffers required by the existing bytes-in/bytes-out contract."
    - "The default dependency disables apple-codesign notarization features."
  security_or_safety_requirements:
    - "Production signing launches no process and performs no network access."
    - "Passwords are read only from a named file, are not formatted with Debug, and are not serialized to output."
    - "All failures precede atomic destination replacement."
  observability_requirements:
    - "Text and JSON identify ad-hoc versus certificate mode and verified signed outcome without exposing credential material."
```

## Public contract

The provider, not `SignatureRequest`, owns key material. Requests remain safe to
log and contain only per-binary metadata:

```rust
pub struct SignatureRequest {
    pub identifier: Option<String>,
    pub entitlements_xml: Option<String>,
}

pub enum InProcessSignatureProvider {
    AdHoc,
    Certificate { /* parsed key and certificate, never Debug */ },
}

impl InProcessSignatureProvider {
    pub fn adhoc() -> Self;
    pub fn from_pkcs12(bytes: &[u8], password: &str)
        -> Result<Self, SignatureProviderError>;
}
```

`sign` configures `apple_codesign::SigningSettings`, imports existing Mach-O
settings after applying explicit request overrides, supplies a deterministic
fallback identifier only for otherwise unidentified ad-hoc input, signs with
`MachOSigner`, and verifies the resulting bytes. Certificate-backed input with
neither an existing nor explicit identifier fails closed.

Ad-hoc verification allows only `NoCryptographicSignature`; all structural,
CodeDirectory, slot-digest, or CMS parse problems fail. Certificate verification
allows no problem, including `NoCryptographicSignature`.

## Canonical CLI grammar

```text
macho patch PATH PATCH-OPERATION... OUTPUT
            [--arch ARCH]
            [--sign-adhoc | --sign-p12 PATH]
            [--p12-password-file PATH]
            [--identifier VALUE]
            [--entitlements PATH]
```

Rules:

- `--sign-adhoc` and `--sign-p12` conflict;
- both conflict with `--strip-signature`;
- `--p12-password-file` requires `--sign-p12`; absent means the empty PKCS#12
  password;
- the password file is UTF-8 and one terminal CRLF or LF is removed;
- `--identifier` and `--entitlements` require a signing mode;
- `--entitlements` must contain a valid XML property list and is parsed before
  patch preparation;
- signing is applied only to selected slices; and
- dry-run executes mutation, signing, parsing, and signature verification but
  performs no filesystem write.

## Scope ledger

| ID | Item | Source | Disposition | Acceptance evidence |
| --- | --- | --- | --- | --- |
| S001 | Remove production `xcrun` signing | user | INCLUDED | source-policy scan and deleted adapter |
| S002 | Preserve actual identity-backed signing | inferred correctness | INCLUDED | valid PKCS#12 produces verified CMS signature |
| S003 | Provide portable ad-hoc signing | prior design | INCLUDED | deterministic valid thin and fat fixtures |
| S004 | Fix final-layout/hash circularity | codebase | INCLUDED | post-sign digest verifier plus tamper-negative test |
| S005 | Preserve/override identifier and entitlements | prior design | INCLUDED | paired preservation and override tests |
| S006 | Wire signing into a useful CLI surface | codebase | INCLUDED | executed patch CLI tests for text/JSON/dry-run |
| S007 | Keep credentials explicit and secret-safe | inferred safety | INCLUDED | password-file-only grammar and output assertions |
| S008 | Support thin and selected/all fat slices | inferred compatibility | INCLUDED | fixture matrix and unselected-slice equality |
| S009 | Preserve atomic output | existing contract | INCLUDED | signing-failure destination-preservation test |
| S010 | Add in-process verification | design review | INCLUDED | positive verification and deliberate tamper failures |
| S011 | Add macOS Apple-tool oracle | design review | INCLUDED | ignored/macOS-only `codesign --verify` test |
| S012 | Update architecture and user guidance | codebase | INCLUDED | xtask and docs checks |

No ledger item requires a user decision, is blocked, or is user-excluded.

## Acceptance contract

| ID | Scenario | Expected behavior | Evidence required |
| --- | --- | --- | --- |
| A001 | Patch and ad-hoc sign a thin image | output reparses, reports signed, and has no verification problem except absent CMS | library and CLI tests |
| A002 | Patch and certificate sign from PKCS#12 | output contains a CMS signature and has zero verification problems | fixture-backed integration test |
| A003 | Sign an existing signature without overrides | identifier and XML entitlements survive | equality assertions |
| A004 | Override metadata | output carries the requested identifier and entitlements | parsed-report assertions |
| A005 | Sign all fat slices | every slice is verified and the rebuilt container reparses | fat integration test |
| A006 | Sign one fat slice | selected slice changes and verifies; unselected slice bytes are identical | fat selection test |
| A007 | Tamper with a signed covered byte | in-process verifier reports a code-digest mismatch | negative verifier test |
| A008 | Supply wrong PKCS#12 password or malformed entitlements | command fails before writing destination | negative CLI tests |
| A009 | Request dry-run signing | full signing and verification execute; no file is written | dry-run test |
| A010 | Inspect production source | no signing process or Xcode discovery remains | architecture/source scan |
| A011 | Verify on macOS with Apple tooling | ad-hoc output passes strict `codesign --verify` | test-only macOS oracle |

Unacceptable results include parse-only validation, skipped dry-run signing,
ad-hoc-only replacement, output replacement before verification, and any
production process invocation.

## Verification plan

| ID | Command/check | Expected signal |
| --- | --- | --- |
| V001 | `cargo test -p macho-mutate sign` | positive, preservation, tamper, and credential tests pass |
| V002 | `cargo test -p macho-workflow` | provider ordering and signed preview tests pass |
| V003 | `cargo test -p macho-cli patch_signing` | grammar, thin/fat, dry-run, JSON, and atomic failures pass |
| V004 | `cargo xtask architecture` | dependency and process-policy checks pass |
| V005 | `cargo test -p macho-cli macos_codesign_oracle -- --ignored --nocapture` on macOS | Apple verifier accepts the generated ad-hoc signature |
| V006 | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | no warnings |
| V007 | `cargo test --workspace --all-features` | whole workspace passes |
| V008 | `cargo xtask verify` | stable whole-tree gate passes without modifying files |
| V009 | final `git diff` and `rg` review | no unrelated signing changes, no secret output, no production process escape |

## Exception ledger

| ID | Type | Description | Impact | Status |
| --- | --- | --- | --- | --- |
| E001 | blocked_dependency | The worktree contains extensive unrelated user changes, including overlapping CLI and plan files. | Implementation must patch narrowly and report only the signing-owned diff; unrelated failures cannot be claimed as signing regressions. | pending until final diff review |
| E002 | test_gap | `apple-codesign` documents that its verifier is not a complete model of Apple's proprietary execution policy. | The in-process verifier proves internal digests/CMS; the macOS test-only oracle adds platform evidence without becoming a runtime dependency. | accepted risk |

## Design-plan review

Reviewer verdict: **APPROVED_WITH_RISK**.

The reviewed contract absorbs every surface that shapes whether signed output is
valid: credential form, final layout, thin/fat behavior, identifier and
entitlement preservation, verification, CLI reachability, atomicity, output,
and architecture policy. It does not defer certificate signing behind an
ad-hoc-only implementation.

The scope ceiling is runtime behavior unrelated to raw Mach-O signing. Bundle
resource traversal, notarization, stapling, remote signing, and Keychain
integration do not shape validity of the raw patched Mach-O artifact accepted
here, so they are not added. `apple-codesign` notarization remains disabled.

The verifier is the design center. The contract cannot pass on parse success or
blob-shape tests; it requires digest mismatch negatives, CMS presence for
certificate mode, selected-slice conservation, atomic failure, and a test-only
Apple oracle. Every checkpoint has a condition that can fail.

Risk E001 is visible because the accepted files overlap a dirty tree. Risk E002
is intrinsic to non-Apple verification and is mitigated without weakening the
cross-platform production boundary. Neither risk removes requested scope.

## Dependency-ordered implementation work

1. Add `apple-codesign` 0.29 with default features disabled to
   `macho-mutate`; delete the hand-written CodeDirectory/SuperBlob generator.
2. Implement configured ad-hoc and PKCS#12 providers plus fail-closed
   verification and fixture-backed positive/negative tests.
3. Teach the workflow to report `SignedAdHoc` or `SignedCertificate` only after
   provider success and verification.
4. Add patch signing grammar, credential loading, per-slice provider use,
   deterministic text/JSON reporting, and atomic negative tests.
5. Delete the CLI host-signing adapter and replace external resign guidance
   with native command guidance.
6. Amend plan 15, README/help, and architecture checks to prohibit production
   signing processes.
7. Run the focused, portable, macOS-oracle, and whole-tree verification matrix;
   then review the diff against every scope and acceptance row.

## STOP conditions

Stop implementation and report the exact evidence if:

- `apple-codesign` cannot sign and verify the portable thin/fat fixtures without
  weakening their structural validity;
- PKCS#12 certificate signing cannot be tested with a repository-owned fixture;
- signing requires changing bytes after the backend computes CodeDirectory
  digests;
- the selected fat-slice contract cannot preserve unselected bytes;
- a required option or signing failure can reach destination replacement;
- architecture policy cannot distinguish production from test-only Apple-tool
  oracle execution;
- implementation requires enabling notarization/network features; or
- overlapping dirty user edits cannot be preserved with a narrow patch.

