# Plan: Streaming Disassembly Output

## Status and authority

Feature contract for making `macho disassemble` a streaming command: it emits
one record (instruction or gap) per line, directly to stdout, with peak heap
constant in the decoded instruction count. It amends the delivery/allocation
model of [`17-disassemble-command-plan.md`](17-disassemble-command-plan.md);
Plan 17 remains authoritative for decode semantics, selection grammar, and
diagnostic codes. Plan 19 changes how output is produced and its serialized
shape (line-oriented, not a single enveloped document).

Accepted by the user with this design: `macho disassemble` always streams,
defaults to pretty text lines, and emits NDJSON (one JSON object per line) under
`--format json` — invoked like every other command. `schema_version` in each
JSON line stays `1`.

Ownership unchanged from Plan 15/17: `macho-analysis::disassembly` owns the
bounded decode service and the streaming core; `macho-cli` owns delivery.

## Problem statement

```yaml
problem_statement:
  user_goal: >-
    Disassemble arbitrarily large executable sections without holding the whole
    result in memory; emit each instruction as a line of text or JSON.
  current_pain: >-
    disassemble() materializes the whole DisassemblyReport (region.records grows
    O(instructions)); the CLI additionally buffers the entire rendered output in
    a Vec, and the JSON delivery re-parses it into a sorted serde_json::Value.
    Peak heap scales with instruction count for both formats.
  desired_outcome: >-
    A line-oriented streaming disassembler: decode one record, write one line,
    drop it. Default pretty text; --format json emits NDJSON. Constant
    output-side memory, independent of instruction count.
  non_goals_from_user: []
  important_context:
    - "Input is already mmap-lazy; the O(n) heap is the record Vec plus the CLI's
      rendered buffer and the JSON delivery Value."
    - "Line-oriented output sidesteps the sorted-key single-document problem:
      each line is an independent object that can sort its own keys in O(1)."
```

## Verified live baseline

Grounded at commit `f0799ab`:

- Input is `Mmap`; section bytes are borrows into the mapping, never copied
  ([`common.rs:15`](../crates/macho-cli/src/commands/subcommands/common.rs:15),
  [`decode.rs:172`](../crates/macho-analysis/src/disassembly/decode.rs:172)).
- The O(instructions) heap is `DisassemblyRegion.records: Vec`
  ([`decode.rs:306`](../crates/macho-analysis/src/disassembly/decode.rs:306)),
  collected into `DisassemblyReport`
  ([`disassembly/mod.rs:465`](../crates/macho-analysis/src/disassembly/mod.rs:465)).
- The CLI buffers ALL command output in `rendered: Vec<u8>` then delivers it
  ([`commands/mod.rs:500`](../crates/macho-cli/src/commands/mod.rs:500)); for
  JSON, `write_success` re-parses that buffer into a sorted `serde_json::Value`
  and wraps it in an envelope
  ([`delivery.rs:37`](../crates/macho-cli/src/commands/output/delivery.rs:37)).
  So today both formats are fully materialized twice.
- The label index is bounded by `--max-ranges` and queryable during decode
  without buffering records
  ([`metadata.rs:153`](../crates/macho-analysis/src/disassembly/metadata.rs:153),
  `collect_metadata` runs before `decode_slice`).
- Every summary scalar is produced within the single decode pass or before it;
  no scalar forces a second pass.
- `--format` is the global selector (text default; json; sarif rejected for
  disassemble) ([`args.rs:37`](../crates/macho-cli/src/commands/args.rs:37)).
- Dense single-region scaling fixture does not yet exist; the section-count
  fixture grows regions, not records-per-region, so it cannot prove F3.

## Outcome

`macho disassemble` decodes and writes one line at a time straight to stdout.
Output-side heap is O(1) in instruction count for both text and NDJSON. The only
memory that scales with input is the pre-existing bounded label index
(`--max-ranges`) and the fixed mmap working set. The library
`disassemble() -> DisassemblyReport` API, its DTOs, validation, and round-trip
are preserved for programmatic/test use, reimplemented over the same streaming
core so there is one decode path.

## Line protocol

Each output line is one event. Text and NDJSON carry the same event sequence:

1. Slice header (only when more than one slice) — text: `=== arch [slice n, …]`;
   json: `{"schema_version":1,"type":"slice","index":n,"arch":…}`.
2. Region header — text: `SEG,SECT  <extent>`; json:
   `{"type":"region","segment":…,"section":…,"start_va":…,…}`.
3. Label — emitted before the record at its VA — text: `name:`; json:
   `{"type":"label","va":…,"raw_name":…,"display_name":…,"source":…}`.
4. Instruction / gap — text: `  <va>  <bytes>  <text|<code> message>`; json:
   `{"type":"instruction",…}` / `{"type":"gap",…}` with the existing record
   fields.
5. Region trailer — json: `{"type":"region_end","emitted_instruction_count":…,
   "examined_end_va":…,"next_unexamined_va":…}`; text: the `Partial:` line when
   `next_unexamined_va` is set.
6. Slice trailer — json: `{"type":"slice_end","status":…,"decoded_bytes":…,
   "symbol_ranges_truncated":…}` then one `{"type":"issue",…}` per issue; text:
   the `Partial:`/`Warning:` lines.
7. Empty selection (no regions in any slice) — text: `No executable sections
   found.`; json: a single `{"type":"empty"}` line.

Text is the fixed-column layout (VA 18 chars, bytes `raw_width`, over-wide gaps
ragged) written per line with no region buffer. Each NDJSON line is a small
serde struct serialized with `serde_json::to_writer` + `\n`; keys within a line
may be sorted (O(1)); there is no enclosing array or envelope.

## Governing invariants

1. One decode path. The library `disassemble()`, its `CollectingSink`, and the
   CLI streaming sinks share one event-emitting core; no second decoder.
2. Line independence. Every stdout line is a complete text row or a complete
   JSON object; nothing spans lines; nothing buffers a region or slice.
3. Constant output memory. The streaming path retains only the mmap working set,
   the bounded label index, the current record, O(1) running scalars, and a
   bounded per-slice/region header (F3).
4. Collected equality. Parsing the NDJSON stream and reassembling it yields a
   report equal to the materialized `disassemble()` for the same request (F1).
   The materialized path keeps `validate()`; the streamed path does not
   re-validate at runtime (E004).
5. Semantics frozen. No decode result, selection, mode meaning, diagnostic code,
   or record field meaning changes; only output production and shape.

## Behavior deltas (accepted)

- D1 — JSON output shape changes from a single enveloped, sorted document to
  NDJSON (one object per line). This is the point of the feature. The enveloped
  `--format json` document for disassemble is removed; JSON goldens are replaced
  with NDJSON goldens. Other commands are unchanged.
- D2 — Text layout becomes fixed-column (VA fixed 18, bytes `raw_width`), no
  region-global alignment; over-wide coalesced gaps render ragged. Text goldens
  regenerate. No existing golden has an over-wide gap.
- D3 — Strict mode (`--strict`) fails on the first invalid byte/clipped
  instruction, but because output streams, lines already emitted precede the
  error on stdout (the Plan 17 "empty stdout on strict failure" guarantee cannot
  hold for a stream). Exit code and typed stderr are unchanged.
- D4 — The streamed path does not call `report.validate()` at runtime;
  correctness rests on F1 collected-equality plus the materialized path's
  validation.

## Sink API (design)

```rust
// macho-analysis::disassembly
pub trait DisassemblySink {
    fn slice_start(&mut self, h: &SliceHeader) -> Result<(), DisassemblyError>;
    fn region_start(&mut self, h: &RegionHeader) -> Result<(), DisassemblyError>;
    fn record(&mut self, r: &DisassemblyRecord, labels: &[DisassemblyLabel])
        -> Result<(), DisassemblyError>;
    fn region_end(&mut self, s: &RegionSummary) -> Result<(), DisassemblyError>;
    fn slice_end(&mut self, s: &SliceSummary, issues: &[DisassemblyIssue])
        -> Result<(), DisassemblyError>;
}

pub fn disassemble_streaming(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
    sink: &mut dyn DisassemblySink,
) -> Result<(), DisassemblyError>;
```

- `record` receives the (bounded) labels at its VA so text/NDJSON can emit label
  lines inline without a region buffer.
- `decode_region` calls `sink.record(&r, labels_at_va)?` instead of pushing to a
  Vec, dropping `r` afterward.
- `disassemble()` and any programmatic caller use `CollectingSink`:
  `disassemble_streaming` into it, `into_report()`, `validate()`. Equal to
  today's report (F5).
- A bounded region pre-pass (`resolve_regions` over all selected slices; regions
  are bounded, no decode) decides all-slices-empty before any line is written.

## CLI delivery

- The top-level runner routes `Commands::Disassemble` to a streaming path that
  writes directly to `io.stdout` (bypassing the `rendered` buffer and the
  `write_success` envelope). Errors still use the standard `write_failure`
  path (typed stderr; enveloped for `--format json`).
- Two sinks: `TextLineSink` (fixed columns) and `NdjsonSink` (`to_writer` per
  line). Recovering-mode issues become trailer lines (text `Warning:` /
  json `issue`); strict-mode errors abort mid-stream (D3).

## Work packages

- WP1 — Streaming sink core in `macho-analysis`: trait, headers/summaries,
  `disassemble_streaming`, region pre-pass; convert `decode_region`/
  `decode_slice`/`disassemble_inner` to emit events; reimplement `disassemble()`
  as `CollectingSink`. `disassemble_with_work_stats` retained. F5 holds.
- WP2 — CLI streaming delivery: route disassemble to a direct-stdout streaming
  runner; implement `TextLineSink` and `NdjsonSink`; keep error/diagnostic
  paths. Remove the enveloped-json path for disassemble.
- WP3 — Goldens and fixtures: replace JSON goldens with NDJSON goldens;
  regenerate text goldens (fixed-column); add `disassembly_x86_64_dense(n)` and
  the over-wide-gap fixture.
- WP4 — Memory instrumentation and gates: add `WorkStats.
  streamed_peak_retained_bytes`; add the F3 scaling assertion on the streaming
  path; add the collected-equality (F1) test; run whole-tree gates.

## Falsification criteria

- F1: Parsing the NDJSON stream and reassembling it equals the materialized
  `disassemble()` report for every fixture.
- F2: For every fixture, `TextLineSink` output equals a collect-then-render pass
  using the same fixed-column renderer (internal equivalence; goldens lock it).
- F3: On `disassembly_x86_64_dense(n)` with growing instruction n,
  `streamed_peak_retained_bytes` is flat while `owned_report_bytes` grows.
- F5: `disassemble()` returns a report equal to today's for every fixture.

## Scope ledger

```yaml
scope_ledger:
  - id: S001
    item: "Streaming decode core emitting typed events"
    source: user
    disposition: INCLUDED
    verification: "V001, V002"
  - id: S002
    item: "Materialized disassemble() preserved via CollectingSink"
    source: inferred
    disposition: INCLUDED
    verification: "V001"
  - id: S003
    item: "NDJSON line sink; --format json emits one object per line"
    source: user
    disposition: INCLUDED
    verification: "V001, V003"
  - id: S004
    item: "Fixed-column text line sink; default pretty text, constant memory"
    source: user
    disposition: INCLUDED
    verification: "V001, V003"
  - id: S005
    item: "CLI routes disassemble to direct-stdout streaming (no rendered buffer)"
    source: inferred
    disposition: INCLUDED
    verification: "V001, V003"
  - id: S006
    item: "Constant recovering-mode output memory on dense fixture (F3)"
    source: user
    disposition: INCLUDED
    verification: "V001"
  - id: S007
    item: "Collected-equality: NDJSON reassembles to the materialized report"
    source: inferred
    disposition: INCLUDED
    verification: "V001"
  - id: S008
    item: "Replace enveloped-json disassemble output with NDJSON; regen goldens"
    source: user
    disposition: INCLUDED
    verification: "V001, V003"
    notes: "D1. Disassemble no longer emits the shared enveloped JSON document."
  - id: S009
    item: "Fixed-column text layout replacing region-global alignment"
    source: inferred
    disposition: INCLUDED
    verification: "V001, V003"
    notes: "D2. Over-wide gaps ragged; text goldens regenerate."
  - id: S010
    item: "Strict mode fails mid-stream with prior lines emitted"
    source: inferred
    disposition: INCLUDED
    verification: "V001"
    notes: "D3. Plan 17 empty-stdout-on-strict guarantee cannot hold for a stream."
  - id: S011
    item: "Dense single-region fixture disassembly_x86_64_dense(n) for F3"
    source: reviewer
    disposition: INCLUDED
    verification: "V001"
```

## Acceptance contract

```yaml
acceptance_contract:
  acceptance_tests:
    - id: A001
      scenario: "CLI streams a thin x86-64 image as text and NDJSON."
      expected_behavior: "One line per event; matches goldens; direct stdout."
      evidence_required: "CLI golden tests over the real run path."
    - id: A002
      scenario: "Collected equality (F1) over all fixtures."
      expected_behavior: "Reassembled NDJSON equals materialized report."
      evidence_required: "Equivalence test."
    - id: A003
      scenario: "Text equals fixed-column collect-then-render (F2)."
      expected_behavior: "Byte-for-byte equal; over-wide-gap fixture ragged."
      evidence_required: "Text goldens + F2 test."
    - id: A004
      scenario: "Scale disassembly_x86_64_dense(n) (F3)."
      expected_behavior: "streamed_peak_retained_bytes flat; owned grows."
      evidence_required: "Scaling assertion on the streaming path."
    - id: A005
      scenario: "Materialized disassemble() unchanged (F5)."
      expected_behavior: "Report equals today's."
      evidence_required: "Existing analysis tests pass."
    - id: A006
      scenario: "Strict mode on an invalid stream (D3)."
      expected_behavior: "Exit 1, typed stderr; prior lines may precede error."
      evidence_required: "Strict CLI test updated from Plan 17 A010."
  unacceptable_results:
    - "Any line spanning records or any region/slice buffered."
    - "Peak streamed retention growing with instruction count."
    - "NDJSON that does not reassemble to the materialized report."
    - "Any decode-semantic, code, or record-field-meaning change."
```

## Verification plan

```yaml
verification_plan:
  required_commands:
    - id: V001
      command: "cargo test -p macho-analysis -p macho-cli"
      purpose: "Streaming core, equivalence, scaling, strict, CLI goldens."
      expected_signal: "All pass."
    - id: V002
      command: "cargo test -p macho-insn --lib"
      purpose: "Decode core unaffected."
      expected_signal: "All pass."
    - id: V003
      command: "cargo xtask verify"
      purpose: "Whole-tree gates: fmt, clippy, docs, architecture, goldens."
      expected_signal: "verify: ok."
```

## Exception ledger

```yaml
exception_ledger:
  - id: E001
    type: behavior_mismatch
    description: "D1: disassemble JSON becomes NDJSON, dropping the shared
      enveloped-document shape for this command."
    requested_by: user
    impact: "JSON consumers of disassemble must read NDJSON."
    required_user_decision: false
    status: approved_by_user
  - id: E002
    type: behavior_mismatch
    description: "D3: strict mode is no longer empty-stdout-on-failure; a stream
      cannot retract already-written lines. Amends Plan 17 invariant #6 / A010."
    requested_by: planner
    impact: "Partial stdout can precede a strict-mode error."
    required_user_decision: true
    status: pending
  - id: E003
    type: behavior_mismatch
    description: "D4: streamed path forgoes runtime validate(); correctness rests
      on F1 collected-equality plus materialized validation."
    requested_by: planner
    impact: "No runtime schema validation on the streamed path."
    required_user_decision: true
    status: pending
  - id: E004
    type: behavior_mismatch
    description: "Pre-existing: Plan 17 documents an enveloped JSON that the live
      code produced via the shared delivery layer; NDJSON supersedes it for
      disassemble. Tracked so the Plan 17 text is reconciled."
    requested_by: planner
    impact: "Plan 17 doc reference is now historical for disassemble JSON."
    required_user_decision: false
    status: pending
```

## STOP triggers

Stop and ask if, during implementation: a region or slice must be buffered to
produce a line; constant memory (F3) needs a second decode pass; NDJSON cannot
reassemble to the materialized report (F1); or any decode result, code, or
record field meaning would change.
