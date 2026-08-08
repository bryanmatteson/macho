# Macho 1.x stability policy

Macho 1.0 makes the `macho` package a compatibility boundary. Passing tests on
one checkout is not sufficient for a release: the published archive, its
feature graph, its minimum Rust version, and its machine-readable contracts must
all agree with the source tree.

## Rust API and features

Public items reachable from the documented `macho` modules follow Cargo
SemVer. Removing or renaming an item, narrowing an accepted input, changing a
public type incompatibly, or adding a variant to an exhaustive public enum is a
major-version change. Deprecation may precede removal but does not authorize a
1.x removal.

Declared Cargo feature names and their dependency closures are public API.
Every feature is compiled alone with default features disabled, and the empty,
default, CLI, and complete compositions are checked independently. Removing a
feature or making a previously valid composition fail is a breaking change.
New additive features may be introduced in a minor release.

Macho 1.0 requires Rust 1.91.1. CI compiles both the empty and complete library
compositions on that exact toolchain. A future 1.x MSRV increase requires a
minor release and an explicit changelog entry; patch releases do not raise it.

## Machine contracts

Versioned JSON reports, snapshots, Program Fact IR, recovery guides and
selection documents are compatibility contracts at their declared schema or
contract version. A breaking field, identity, validation, or interpretation
change requires the owning schema or major contract version to change. Readers
reject unsupported versions and unknown fields rather than guessing a
migration. Compatible additions use the owning minor contract where one
exists.

Diagnostic codes in the repository registry are stable identifiers. Existing
codes keep their meaning throughout 1.x. New diagnostics receive new codes;
codes are not silently repurposed.

Human-oriented text output is deterministic but is not a field-level wire
protocol. Automation should use the documented JSON, NDJSON, SARIF, or raw Fact
IR surfaces.

## Behavioral and safety contract

Accepted inputs remain bounded and panic-free. Malformed, unsupported, stale,
ambiguous, over-budget, or identity-mismatched inputs fail explicitly. A minor
or patch release may reject an input that was previously accepted only when the
old acceptance violated a documented invariant or could produce unsound,
corrupt, or misleading output; the correction must be called out in the
changelog.

Mutation remains plan-first, compare-before-write, reparsed before commit, and
atomic at the CLI boundary. Evidence authority and operator decision authority
remain distinct; a policy-authorized hypothesis does not become an independently
recovered fact.

## Release evidence

The stable gate performs, in order:

1. architecture, generated documentation, diagnostic registry, lockfile, and
   changelog checks;
2. construction and Cargo verification of the actual publishable `macho`
   archive;
3. isolated compilation of every declared feature plus empty, default, CLI,
   and complete compositions;
4. locked formatting, all-target checking, denied-warning clippy, rustdoc,
   tests, and benchmark compilation; and
5. nightly fuzz-target construction and bounded sanitizer smoke runs in CI.

CI runs stable verification on Linux, macOS, and Windows. It separately checks
the exact MSRV, and macOS runs the ignored system `codesign` oracle. A tagged
release additionally requires a clean tracked tree and an exact `vX.Y.Z` tag
matching the package, CLI, lockfiles, and changelog.

These gates prove the hosts and inputs they execute. They do not turn an
unexecuted platform, credential provider, or external signing service into a
release claim.
