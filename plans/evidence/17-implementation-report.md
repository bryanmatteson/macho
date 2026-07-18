# Plan 17 Implementation Report

```yaml
implementation_report:
  contract: plans/17-disassemble-command-plan.md
  files_changed:
    - crates/macho-insn/src/lib.rs
    - crates/macho-insn/src/x86_64.rs
    - crates/macho-insn/src/tests.rs
    - crates/macho-dyld/src/exports.rs
    - crates/macho-dyld/src/lib.rs
    - crates/macho-dyld/src/types.rs
    - crates/macho-core/src/format/mod.rs
    - crates/macho-core/src/format/symbols.rs
    - crates/macho-core/src/model/container.rs
    - crates/macho-core/src/format/fat.rs
    - crates/macho-objc/Cargo.toml
    - crates/macho-objc/src/imp.rs
    - crates/macho-objc/src/lib.rs
    - crates/macho-analysis/src/disassembly/
    - crates/macho-analysis/src/report/disassembly/
    - crates/macho-analysis/src/report/common.rs
    - crates/macho-analysis/src/lib.rs
    - crates/macho-analysis/src/report/mod.rs
    - crates/macho-cli/src/commands/mod.rs
    - crates/macho-cli/src/commands/output/format.rs
    - crates/macho-cli/src/commands/output/mod.rs
    - crates/macho-cli/src/commands/subcommands/disassemble.rs
    - crates/macho-cli/src/commands/subcommands/mod.rs
    - crates/macho-cli/tests/disassemble_tests.rs
    - crates/macho-cli/tests/goldens/disassemble-address-count2.txt
    - crates/macho-cli/tests/goldens/disassemble-address-count2.json
    - crates/macho-cli/tests/goldens/disassemble-help.txt
    - crates/macho-cli/tests/goldens/disassemble-thin-x86-default.txt
    - crates/macho-cli/tests/goldens/disassemble-thin-x86-default.json
    - crates/macho-cli/tests/goldens/disassemble-fat-all.json
    - crates/macho-cli/tests/goldens/disassemble-objc-boundary.txt
    - crates/macho-cli/tests/goldens/disassemble-objc-boundary.json
    - crates/macho-cli/tests/io_parity.rs
    - crates/macho-cli/tests/output_tests.rs
    - crates/macho-test-support/src/lib.rs
    - crates/macho-test-support/src/disassembly_objc.rs
    - crates/macho-test-support/src/disassembly_scale.rs
    - crates/macho/benches/architecture.rs
    - fuzz/fuzz_targets/insn.rs
    - fuzz/fuzz_targets/dyld.rs
    - README.md
    - CHANGELOG.md
    - docs/diagnostic-codes.md
    - plans/15-architecture-coherence-implementation-plan.md
    - plans/README.md
  behavior_changed:
    - Added the canonical `macho disassemble` command with text and JSON delivery.
    - Added exact subtype-aware slice, section, raw-symbol, and address selection.
    - Added strict fail-closed and recovering gap-bearing decode behavior with cumulative bounds.
    - Added schema-version-1 typed reports, semantic validation, identities, dual offsets, labels, and structured targets.
    - Added alias-aware symbol budgets, Objective-C-aware range ends, metadata-failure propagation, and work counters.
    - Bounded exact-symbol metadata discovery and presentation to the user-approved two physical traversals per authority while keeping retained state capped by the alias budget.
    - Added transactional raw nlist, export-trie, and Objective-C IMP folds that return caller-owned state only after a complete physical pass succeeds; disassembly does not materialize full symbol/export/Objective-C graphs.
    - Made nested Objective-C class/category ownership strict for required names, method-list layouts, and non-zero IMPs, with successful-prefix state discarded on any later failure.
    - Charged every leaf decoder and formatter invocation, overlapping decoder input window, and unretained recovery probe under the user-approved executable work formulas.
    - Measured report-owned heap allocation by vector and string capacity rather than logical payload length.
    - Added validated non-empty selector/request construction and request-coupled semantic report validation.
    - Made target symbolication conservative whenever truncated or malformed metadata cannot prove range ownership.
    - Indexed section ownership/name lookups, requested-symbol boundaries, retained label ranges, and target owners so metadata observations, regions, and branch annotations do not rescan sections or retained aliases.
    - Added physical traversal, section-index, boundary-query, label-range-query, and target-owner-query counters with N/2N metadata, region, and section fixtures.
    - Rejected false zero-length byte/count truncation and added a checked-in JSON gap golden with raw bytes, code, and message.
    - Made `macho_insn::disassemble` fail closed instead of returning a successful prefix.
    - Added fail-closed `visit_exports` compatibility plus transactional `fold_exports`, and rebuilt collecting traversal on the fold.
    - Centralized rejection of explicit color for JSON/SARIF while retaining audit-only SARIF success.
  tests_added_or_changed:
    - Added deterministic x86-64, arm64, arm64e, fat, subtype-collision, alias-flood, valid Objective-C, malformed-Objective-C, malformed-nlist, and malformed-export fixtures.
    - Added direct analysis coverage for selectors, gaps, strict mode, atomic bounds, false byte/count truncation, the full schema rejection matrix, raw identities, offsets, targets, nested metadata failures, alias budgets, parsed Objective-C ends, and byte/metadata/region/section work scaling.
    - Added CLI grammar, checked-in text/JSON goldens, color, output-policy, exact-arch, negative selector matrices, strict-failure, fat-order, and captured/process parity tests.
    - Added instruction/export malformed-input regressions and fuzz coverage.
    - Added a bounded disassembly benchmark case.
  verification_results:
    - id: V001
      command: cargo test -p macho-insn
      result: passed
      evidence: 150 tests passed; invalid and incomplete streams fail closed.
    - id: V002
      command: cargo test -p macho-analysis --all-features
      result: passed
      evidence: 121 analysis tests passed; 38 disassembly-service tests plus the section-index unit test cover the accepted service contract and repaired review findings.
    - id: V003
      command: cargo test -p macho-cli --test disassemble_tests
      result: passed
      evidence: 14 tests passed across complete help/thin/fat goldens, grammar, success, negative matrices, policy, fat selection, and route parity.
    - id: V004
      command: cargo run -q -p macho-cli -- disassemble --help
      result: passed
      evidence: Live help exposes only the canonical command, selectors, limits, format note, and examples.
    - id: V005
      command: cargo xtask architecture
      result: passed
      evidence: architecture: ok
    - id: V006
      command: cargo xtask docs --check
      result: passed
      evidence: docs: ok
    - id: V007
      command: cargo tree -p macho-cli --depth 1; cargo tree -p macho-analysis --depth 1
      result: passed
      evidence: CLI retains only the macho facade edge; analysis owns the required leaf edges.
    - id: V008
      command: cargo bench --workspace --all-features --no-run
      result: passed
      evidence: All benchmark targets, including bounded_disassembly, compiled.
    - id: V009
      command: RUSTUP_TOOLCHAIN=nightly cargo xtask verify-fuzz
      result: passed
      evidence: verify-fuzz: ok; the shared worktree's pre-existing fuzz lockfile change was preserved.
    - id: V010
      command: cargo xtask verify
      result: passed
      evidence: Fresh post-repair verify: ok across architecture, docs, release, fmt, check, clippy, docs, workspace tests, feature matrix, and benches.
    - id: V011
      command: cargo test -p macho-cli --test disassemble_tests captured_and_process_routes_match_core_disassembly_cases
      result: passed
      evidence: Valid text, valid JSON, usage failure, strict failure, and limit truncation match byte-for-byte between both routes.
    - id: V012
      command: cargo test -p macho-cli --test output_tests; cargo test -p macho-cli --test io_parity
      result: passed
      evidence: Machine-color and SARIF policy matrix passed while audit SARIF and human color remained intact.
    - id: V013
      command: cargo test -p macho-core; cargo test -p macho-dyld; cargo test -p macho-objc
      result: passed
      evidence: Raw nlist, export trie, and Objective-C IMP transactional-fold tests pass, including malformed suffixes after valid prefix observations; core 43, dyld 15, and ObjC 22 unit tests pass.
    - id: V014
      command: cargo test -p macho-analysis --all-features disassembly_work_bounds
      result: passed
      evidence: N/2N byte, metadata-observation, selected-region, and parsed-section fixtures charge physical folds and indexed section/boundary/label/target queries; exact symbols use [2,2,1] traversals with Objective-C present; owned allocation counts capacities; every decoder/input/lookahead formula passes, including an atomic over-budget invalid x86 unit.
    - id: V015
      command: cargo test -p macho-cli --test disassemble_tests thin_x86_64_default_selection_has_text_and_gap_json_goldens; cargo test -p macho-analysis report_validator_rejects_false_truncation_after_fully_examined_extents
      result: passed
      evidence: The checked-in JSON gap variant asserts bytes/code/message, and adversarial fully satisfied byte/count reports cannot claim zero-length truncation.
  review_history:
    - verdict: rejected
      findings: [RF022, RF023, RF024, RF025, RF026]
      disposition: All five findings were repaired and reverified.
    - verdict: approved
      findings: []
      disposition: Fresh independent live-source, test, and golden audit confirmed A001-A028, S001-S029, E003, and E004; RF022-RF026 are closed. The resumed sandbox prevented a duplicate test execution from starting, so the reviewer relied on the recorded green full-verifier and nightly-fuzz evidence for dynamic verification.
  known_gaps: []
  approved_contract_amendments:
    - id: E003
      decision: approved_by_user
      effect: Exact-symbol selection may use at most two bounded metadata traversals per authority; all exactness, failure, and retention requirements remain locked.
    - id: E004
      decision: approved_by_user
      effect: Decoder work is judged by truthful leaf-attempt, input-window, decode-eligible, and unexamined-lookahead counters; byte conservation and atomic truncation remain locked.
  workspace_context:
    - The shared worktree also contains a parallel in-process signing implementation. Its files and behavior are outside Plan 17 except where shared documentation or test-support files contain independently attributable additions.
```
