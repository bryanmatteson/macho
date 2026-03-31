# Plan: `macho audit`

## Objective

Add a policy and security audit engine that sits above structural validation and
produces prioritized findings suitable for release review and CI.

## Why This Matters

Current validation is intentionally structural. That is useful, but it does not
answer whether a binary is risky, suspicious, or policy-noncompliant. The audit
track is what makes the tool valuable to security engineering and release
pipelines.

## Current Repo Leverage

- Structural diagnostics: `src/validate/mod.rs`
- Codesign parsing: `src/codesign/`
- Load-command and segment views: `src/model/`, `src/commands/inspect.rs`
- Dyld imports/fixups: `src/dyld/`
- ObjC and symbol metadata for contextual findings

## Scope

### In Scope

- Rule engine with stable IDs and severities
- Text, JSON, and SARIF output
- Findings with evidence and remediation
- Initial rule packs for:
  - code signing
  - entitlements
  - load paths and rpaths
  - memory protections
  - architecture parity

### Out of Scope

- Malware classification
- Full notarization or trust-chain verification
- Runtime sandbox analysis outside binary contents

## Design

Keep `validate` focused on structural invariants. Build a parallel `audit`
layer that consumes parsed binaries or snapshots and emits findings with:

- rule id
- severity
- title
- body
- evidence
- remediation

Core types to add:

- `audit::AuditFinding`
- `audit::Rule`
- `audit::AuditContext`
- `audit::RulePack`

## Milestones

### Milestone 1: Audit Engine

Goal: build the shared rule execution model.

Work:

- Add `src/audit/mod.rs`
- Add `src/audit/rule.rs`
- Add `src/audit/finding.rs`
- Add `src/audit/context.rs`
- Define severity model and evidence attachment

Acceptance:

- Rules can run independently and emit stable finding records

### Milestone 2: Initial High-Value Rules

Goal: ship a small number of high-confidence findings.

Work:

- Add `src/audit/rules/codesign.rs`
- Add `src/audit/rules/load_paths.rs`
- Add `src/audit/rules/memory.rs`
- Add `src/audit/rules/container.rs`
- Implement checks for:
  - risky or malformed signature state
  - suspicious entitlements
  - absolute or unsafe dylib paths
  - dangerous `rpath`s
  - writable + executable mappings
  - per-arch drift in security posture

Acceptance:

- Rules are high signal and not obviously noisy
- Findings include actionable remediation

### Milestone 3: CLI and CI Output

Goal: make the feature usable in build pipelines.

Work:

- Add `src/commands/audit.rs`
- Add `src/output/sarif.rs`
- Add CLI flags:
  - `--json`
  - `--sarif`
  - `--min-severity`
  - `--fail-on`

Acceptance:

- Findings can fail CI by severity threshold
- SARIF can be consumed by code-scanning tooling

## Suggested PR Breakdown

### PR 1

Audit engine and finding model.

Files:

- `src/audit/mod.rs`
- `src/audit/rule.rs`
- `src/audit/finding.rs`
- `src/audit/context.rs`
- `tests/audit_engine_tests.rs`

### PR 2

First rule pack.

Files:

- `src/audit/rules/codesign.rs`
- `src/audit/rules/load_paths.rs`
- `src/audit/rules/memory.rs`
- `src/audit/rules/container.rs`
- `tests/audit_rule_tests.rs`

### PR 3

CLI, JSON/SARIF, docs.

Files:

- `src/commands/audit.rs`
- `src/output/sarif.rs`
- `src/commands/mod.rs`
- `src/main.rs`
- `README.md`

## Test Plan

- Synthetic fixtures for each rule
- Regression tests on system binaries with expected low finding counts
- Snapshot tests for JSON and SARIF stability
- Threshold tests for exit-code behavior

## Risks

- Low-confidence rules will damage trust in the feature
- Entitlement policy can become Apple-version-specific
- SARIF support can distract from finding quality

## Mitigations

- Start with a small curated rule set
- Separate structural findings from policy findings
- Keep rule IDs stable and document rationale

## Done Means

- `macho audit` produces prioritized, evidence-backed findings
- CI can fail on configured severities
- The initial rule set is high-signal enough to trust in automation
