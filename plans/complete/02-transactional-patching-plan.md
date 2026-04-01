# Plan: Transactional Patching

## Objective

Turn the existing editor into a safe, reviewable patch pipeline with preview,
validation, rollback, and code-signing awareness.

## Why This Matters

The repository already has real editing capability in `src/edit/mod.rs`, but it
is library-first and intentionally limited. Best-in-class tooling here does not
mean "can write bytes"; it means "can make changes safely enough to automate."

## Current Repo Leverage

- Structural editor: `src/edit/mod.rs`
- Binary rebuild layout/encoding: `src/edit/layout.rs`, `src/edit/encoder.rs`
- Mutable owned images: `src/model/owned.rs`
- Validation: `src/validate/mod.rs`
- Code-signing inspection: `src/codesign/mod.rs`

## Scope

### In Scope

- CLI patch commands
- Dry-run mode
- Preview before/after changes
- Reparse and validate before write
- Rollback on failed rebuild
- Signature invalidation detection
- Re-sign assistance manifest

### Out of Scope

- Full cryptographic signing implementation
- Arbitrary load-command editing UI
- Instruction relocation or code generation

## Design

Layer a transaction abstraction on top of `MachoEditor` and `OwnedMachFile`.
Every patch operation should:

1. Stage intended edits
2. Build candidate bytes
3. Reparse candidate bytes
4. Run structural validation
5. Produce semantic before/after summary
6. Write only if the candidate passes policy

Core types to add:

- `edit::transaction::PatchTransaction`
- `edit::ops::PatchOp`
- `edit::resign::ResignPlan`
- `edit::preview::PatchPreview`

## Milestones

### Milestone 1: Transaction Core

Goal: stage multiple edits and validate them before persistence.

Work:

- Add `src/edit/transaction.rs`
- Add `src/edit/ops.rs`
- Support operations:
  - add/remove rpath
  - add dylib
  - remove code signature
  - selected raw byte patching
  - replace load command by index
- Reparse candidate output and run `validate::validate`

Acceptance:

- One transaction can stage multiple operations
- Invalid candidates fail before write

### Milestone 2: CLI Patch Surface

Goal: expose safe patching as CLI commands.

Work:

- Add `src/commands/patch.rs`
- Add subcommands:
  - `patch add-rpath`
  - `patch remove-rpath`
  - `patch add-dylib`
  - `patch strip-signature`
  - `patch patch-bytes`
- Add flags:
  - `--dry-run`
  - `--output`
  - `--in-place`
  - `--backup`
  - `--force`

Acceptance:

- Users can preview a patch without writing output
- In-place writes are explicit and safe

### Milestone 3: Signature Awareness

Goal: make mutation results explicit when signing becomes invalid.

Work:

- Add `src/edit/resign.rs`
- Detect whether an operation invalidates `LC_CODE_SIGNATURE`
- Summarize current signing facts:
  - identifier
  - team ID
  - entitlements presence
  - CMS presence
- Emit a re-sign assistance plan

Acceptance:

- Users are warned when output is no longer validly signed
- Output includes enough context for downstream re-signing

## Suggested PR Breakdown

### PR 1

Transaction and operation model.

Files:

- `src/edit/transaction.rs`
- `src/edit/ops.rs`
- `src/edit/mod.rs`
- `tests/transaction_tests.rs`

### PR 2

Patch command and preview UX.

Files:

- `src/commands/patch.rs`
- `src/commands/mod.rs`
- `src/main.rs`
- `tests/patch_cli_tests.rs`

### PR 3

Signature invalidation and re-sign assistance.

Files:

- `src/edit/resign.rs`
- `src/codesign/mod.rs`
- `tests/patch_codesign_tests.rs`
- `README.md`

## Test Plan

- Rebuild identity test through transaction layer
- Dry-run does not write output
- Invalid command index or malformed patch fails cleanly
- Patch followed by reparse produces expected load-command changes
- Signature stripping removes `LC_CODE_SIGNATURE`
- Fat binary slice patching preserves container integrity

## Risks

- Rebuild logic may succeed structurally while still creating unusable output
- Preview can become too low-level and noisy
- In-place patching on fat binaries needs careful arch offset handling

## Mitigations

- Always reparse and revalidate
- Use semantic preview instead of raw byte dumps by default
- Keep fat-binary patching conservative in the first iteration

## Done Means

- A user can safely preview and apply common binary patches
- Failed rebuilds do not corrupt the original target
- Signature fallout is explicit rather than implicit
