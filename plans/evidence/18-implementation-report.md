# In-Process Signing Implementation Evidence

Date: 2026-07-18  
Contract: [`../18-in-process-signing-plan.md`](../18-in-process-signing-plan.md)  
Design review verdict: `APPROVED_WITH_RISK`  
Implementation verdict: `PASS_WITH_EXTERNAL_GAPS`

This is the completion record for plan 18. The requested signing behavior is
implemented and passes its feature acceptance matrix. The verdict is qualified
because unrelated concurrent source changes prevent the repository-wide
formatter/docs/composed-verifier gates from being claimed, and the installed
cross-target environments lack the C compiler/header setup required by the
workspace's existing native dependencies.

## Delivered contract

- Production signing launches no process and performs no Xcode discovery.
  The former CLI `xcrun codesign` adapter is deleted.
- `macho-mutate` owns the only `apple-codesign` dependency. Default features
  are disabled, and neither notarization nor AWS functionality is enabled.
- `InProcessSignatureProvider` supports deterministic ad-hoc signing and
  PKCS#12-backed certificate signing. Passwords are consumed during provider
  construction and are not retained.
- Existing identifiers and XML entitlements are preserved unless explicitly
  overridden. Certificate signing fails closed when an unsigned input has no
  existing or explicit identifier.
- Every provider result is verified in process before it reaches workflow
  after-analysis or filesystem replacement. Covered-byte tampering, malformed
  credentials, wrong passwords, malformed entitlements, and invalid CMS data
  are rejected.
- `macho patch` supports `--sign-adhoc`, `--sign-p12`,
  `--p12-password-file`, `--identifier`, and `--entitlements`. Signing-only,
  patch-and-sign, dry-run, text, JSON, thin, all-fat-slice, and selected-slice
  paths use the same provider boundary.
- The command rejects signing/strip conflicts, reads passwords only from a
  named file, preserves unselected fat-slice bytes, and atomically replaces the
  destination only after all selected slices sign and verify.
- Resign and audit guidance now points to native `macho patch` signing rather
  than `xcrun`, `codesign`, or `rcodesign`.

## Scope ledger disposition

| ID | Result | Evidence |
| --- | --- | --- |
| S001 | PASS | host adapter deleted; architecture and source scans reject production signing processes |
| S002 | PASS | repository-owned PKCS#12 fixture produces a verified non-empty CMS signature |
| S003 | PASS | deterministic arm64 and x86-64 ad-hoc fixtures verify |
| S004 | PASS | backend owns final-layout reservation; covered-byte tamper test reports digest mismatch |
| S005 | PASS | preservation and explicit override tests parse the resulting identifier and entitlements |
| S006 | PASS | patch integration tests execute signing-only, dry-run, text, and JSON paths |
| S007 | PASS | password-file-only grammar and stdout/stderr secret-absence assertions |
| S008 | PASS | thin, all-slice fat, and selected-slice conservation tests |
| S009 | PASS | malformed credential, password, and entitlement failures leave destinations absent |
| S010 | PASS | every provider return passes `verify_macho_data`; negative tamper coverage is active |
| S011 | PASS | ignored macOS-only strict Apple verifier oracle passed when explicitly executed |
| S012 | PASS | architecture policy, README, plan 15 amendment, resign guidance, and audit guidance updated |

No scope item was reduced, deferred, or replaced with parse-only validation.

## Acceptance matrix

| ID | Result | Decisive observation |
| --- | --- | --- |
| A001 | PASS | thin ad-hoc output reparses, verifies, and reports CMS absent |
| A002 | PASS | PKCS#12 output contains CMS and has no in-process verification problem |
| A003 | PASS | re-signing without overrides preserves identifier and XML entitlements |
| A004 | PASS | explicit identifier and entitlement overrides survive parsed-report inspection |
| A005 | PASS | both slices of the synthetic universal image verify after signing |
| A006 | PASS | selected slice changes and verifies; unselected slice bytes compare equal |
| A007 | PASS | flipping the final covered byte produces a code-digest mismatch |
| A008 | PASS | wrong password, malformed PKCS#12, and malformed XML fail before output creation |
| A009 | PASS | dry-run signs and verifies while reporting `written=false` and creating no output |
| A010 | PASS | product source contains no signing process or Xcode discovery path |
| A011 | PASS | `/usr/bin/codesign --verify --strict --verbose=4` accepts generated ad-hoc output |

## Verification evidence

| Check | Result |
| --- | --- |
| `cargo test -p macho-mutate` | PASS, 49 tests including 8 signing tests |
| `cargo test -p macho-workflow` | PASS, 3 tests |
| `cargo test -p macho-codesign` | PASS, 6 unit and 3 integration tests |
| `cargo test -p macho-cli --test patch_signing_tests -- --nocapture` | PASS, 8 tests; macOS oracle intentionally ignored by default |
| `cargo test -p macho-cli --test patch_signing_tests macos_codesign_oracle -- --ignored --nocapture` | PASS; Apple strict verifier accepted the result |
| `cargo test -p macho-cli --test resign_tests` | PASS, 6 tests |
| `cargo test -p xtask architecture -- --nocapture` | PASS, 7 tests |
| `cargo xtask architecture` | PASS, `architecture: ok` |
| `cargo clippy -p macho-mutate -p macho-codesign --all-targets --all-features -- -D warnings` | PASS |
| `RUSTDOCFLAGS=-Dwarnings cargo doc -p macho-mutate -p macho-workflow -p macho-cli -p macho-codesign --all-features --no-deps` | PASS |
| `cargo test --workspace --all-features` | PASS |
| `cargo metadata --no-deps --format-version 1` | PASS; 19 packages, with `apple-codesign` owned only by `macho-mutate`, default features false, feature set empty |
| signing-owned `git diff --check` | PASS |
| final production process and former-provider scans | PASS; no signing-process call and no `HostSignatureProvider` implementation remain |

The test-only Apple oracle is deliberately excluded from production policy. A
separate `/usr/bin/true` smoke signed and passed Apple's strict verifier for its
x86-64 and arm64e slices; `macho codesign` reported the preserved
`com.apple.true` identifier and no CMS payload, as expected for ad-hoc mode.

## Implementation review

Verdict: `PASS` for the signing-owned diff. No severity finding remains.

The review checked credential lifetime and output, explicit-over-preserved
setting precedence, entitlement prevalidation, workflow ordering, ad-hoc CMS
classification, certificate CMS requirements, fat-slice replacement,
post-rebuild structural validation, dry-run execution, and atomic replacement.
The narrow ad-hoc verifier exception applies only when every parsed slice has a
canonical empty BlobWrapper payload; all non-CMS verification problems remain
fatal.

## Exceptions and risks

| ID | Classification | Evidence and consequence |
| --- | --- | --- |
| R001 | upstream verifier scope | `apple-codesign` verifies digests and CMS but is not a complete model of Apple's proprietary execution policy. The macOS oracle supplies a second route for ad-hoc output; platform policy equivalence is not claimed. |
| R002 | dependency footprint | Disabling default/notarization/AWS features does not remove all network-capable transitive crates from `apple-codesign`'s monolithic graph. The production provider imports and calls only local signing, PKCS#12, digest, and CMS APIs; no network API or process path is invoked. |
| R003 | unrelated dirty-tree gates | Workspace `cargo fmt --check` and full clippy encounter concurrent unformatted/disassembly code and a pre-existing `needless_question_mark` finding. `cargo xtask docs --check` and therefore `cargo xtask verify` stop on the unrelated missing typed diagnostic constant `cli.usage.unsupported_format`. Signing-owned formatting, focused clippy, architecture, docs build, and the complete workspace test suite pass. |
| R004 | cross-target environment | Linux-musl and Windows-GNU checks cannot complete here: the installed targets lack their native C compilers, and temporary Zig compiler wrappers then reach the workspace's existing `bad64-sys` bindgen dependency, which lacks target headers. No signing-source error was reached, but actual Linux and Windows CI remains required before claiming target-build evidence. |

## Trust calibration

Confidence is high for macOS runtime behavior and for the platform-neutral
bytes-in/bytes-out signing code exercised by synthetic arm64, x86-64, and fat
fixtures. Confidence is moderate, not high, for end-to-end Linux and Windows
buildability until those targets run in environments with the workspace's
native dependency toolchains. The implementation removes the `xcrun`
requirement by construction; it does not claim that unrelated workspace native
dependencies are already cross-buildable from this macOS host.
