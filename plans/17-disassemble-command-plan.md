# Plan: Typed Disassembly Command

## Status and authority

This document is the independently reviewed feature contract for adding
`macho disassemble`. Gate 2 passed with the dirty-overlap risk in E002; it
becomes an implementation authority only after user acceptance. Implementation
must not begin before that gate passes.

[`15-architecture-coherence-implementation-plan.md`](15-architecture-coherence-implementation-plan.md)
remains authoritative for crate ownership, dependency direction, instruction
failure visibility, CLI delivery, output channels, exit codes, and whole-tree
verification. This plan amends plan 15 only where it adds the command grammar,
the reusable disassembly report/service, and the command-specific acceptance
surface. It does not add a snapshot domain or change snapshot schema version 3.

The dependency-ordered work packages below are one coherent implementation
pass. They are not separately accepted delivery stages.

## Problem statement

```yaml
problem_statement:
  user_goal: "Add a first-class disassemble command to macho."
  current_pain: "macho-insn can format instruction bytes, but the CLI cannot select Mach-O code regions, disassemble them, or emit typed text and JSON reports."
  desired_outcome: "A bounded, scriptable command disassembles supported thin and fat Mach-O slices by executable section, symbol, section name, or explicit virtual address while preserving invalid-byte evidence."
  non_goals_from_user: []
  important_context:
    - "The CLI has one flat Clap grammar and one injected output path."
    - "macho-insn already supports x86_64, arm64, and arm64e decoding and text formatting."
    - "Plan 15 forbids silent instruction-decode loss."
```

## Verified live baseline

The planning baseline was re-read from the live tree on July 18, 2026:

- `crates/macho-cli/src/commands/mod.rs` owns a flat grouped grammar and has no
  `disassemble` variant;
- `crates/macho-insn/src/lib.rs` exposes `decode_iter`, `decode_lossy`,
  `disassemble_one`, and `disassemble` for `x86_64`, `arm64`, and `arm64e`;
- the current x86-64 multi-instruction `disassemble` implementation stops at an
  invalid instruction and returns `Ok` with the prefix, and its test explicitly
  blesses that silent partial result;
- `macho-insn` has explicit strict and recovering decode APIs with `DecodeGap`;
- `MachoFile` exposes sections, address mapping, slice-relative reads, and
  virtual-address reads;
- `macho-analysis::xref::SymbolRangeIndex` provides current symbol/export/
  Objective-C ownership ranges for labels and target annotation, while exact
  symbol selection requires the fail-closed raw observation traversal specified
  below;
- CLI JSON success uses the versioned command envelope and all command output is
  captured through injected writers;
- `cargo test -p macho-insn` passes 148 tests; and
- the latest `cargo xtask architecture` baseline passes.

Earlier probes were blocked first by an unresolved `SectionType` import and then
by size-ceiling violations in dirty analysis files. Those live files changed
during contract review. The latest rerun is green, so neither historical failure
is a current blocker. This churn is why implementation must refresh the baseline
without adopting unrelated fixes as feature work.

## Outcome

The accepted implementation provides all of the following in one repository
state:

1. `macho disassemble` in the canonical flat grammar and grouped help;
2. a reusable, typed, bounded disassembly service in `macho-analysis`;
3. strict and recovering decode behavior with no invisible bytes;
4. deterministic text and versioned JSON for thin and fat Mach-O inputs;
5. executable-section, named-section, exact-symbol, and explicit-address
   selection;
6. raw instruction bytes, architecture text, instruction classification,
   file/virtual addresses, labels, and direct branch targets;
7. stable handling of unsupported architectures, missing or ambiguous
   selections, bounds, truncation, and malformed instruction streams;
8. portable x86-64, arm64, arm64e, fat-container, and negative fixtures; and
9. help, README, changelog, diagnostic registry, architecture checks, tests,
   benchmarks, and fuzz coverage updated with the command.

## Coherence boundary

| Surface | State | Contract owner |
| --- | --- | --- |
| Instruction decode, formatting, and recovery cursor | Resolved | `macho-insn` plus plan 15 |
| Fail-closed streaming export-trie traversal | Resolved | `macho-dyld` |
| Mach-O slice, section, symbol/export, and address selection | Resolved | `macho-analysis` |
| Typed request, report, validation, bounds, and symbolication | Resolved | `macho-analysis` |
| Flat command grammar, text/JSON rendering, channels, and exits | Resolved | `macho-cli` plus plan 15 |
| Façade reexport and dependency direction | Resolved | `macho` plus plan 15 |
| Portable fixtures, fuzzing, benchmarks, docs, and release checks | Resolved | test support, fuzz, benchmark, and xtask authorities |
| Clean architecture planning baseline | Resolved at latest probe | `cargo xtask architecture` passes; dirty-tree overlap remains an implementation risk |

No user-requested surface is excluded. The changing dirty baseline requires a
fresh pre-implementation probe; it does not reduce any feature obligation.

## Falsification criteria

This plan is wrong if any accepted implementation exhibits one of these cases:

- one selected byte belongs to neither an instruction, a gap, nor the explicit
  unexamined suffix beginning at a truncation boundary;
- the same request selects different regions in text and JSON execution;
- strict and recovering modes disagree on the valid instructions before the
  first gap;
- a missing, ambiguous, non-code, unmapped, or cross-section selector is
  broadened, guessed, or clamped;
- an architecture display name matching two raw subtypes selects either one
  without an ambiguity error;
- malformed nlist/export/Objective-C evidence is reported as a missing symbol, or malformed
  auxiliary metadata disappears without a partial issue;
- an Objective-C IMP that is the next code start fails to terminate a selected
  nlist/export symbol;
- equal-VA aliases bypass the range budget, or malformed export traversal
  returns a successful prefix;
- a selector ending inside a valid instruction labels the selected tail as
  corrupt input;
- any arm64/arm64e selector starts decoding at an unaligned VA or silently
  rounds that VA;
- a decoded-byte limit creates a false decode gap or permits examined bytes to
  exceed the configured per-slice bound;
- a thin and one-slice fat representation of the same image produce different
  regions or thin-relative records after common identity and expected
  container-relative offsets are normalized;
- schema version 1 accepts an unknown field, inconsistent size/bytes pair, bad
  address, invalid record order, or gap/instruction overlap;
- adding the command changes snapshot schema 3, `AnalysisDomain::ALL`, default
  diff/audit execution, or the permitted dependency graph;
- real-process and injected-writer execution differ in bytes or exit status; or
- a machine format accepts explicit color, disassembly accepts SARIF, or the
  output-policy correction breaks audit SARIF; or
- any required verifier is deleted, skipped, weakened, or reinterpreted to make
  the implementation pass.

## Feature contract

```yaml
feature_contract:
  title: "Typed disassembly command"
  intent: "Expose bounded Mach-O disassembly as a reusable analysis report and a flat, scriptable CLI command."
  included_behavior:
    - "Disassemble supported thin and fat slices through default, section, symbol, and address selectors."
    - "Emit deterministic text and schema-version-1 JSON from one typed report."
    - "Preserve every examined byte as an instruction or explicit gap."
    - "Support recovering and strict decode policies."
    - "Resolve bounded labels and structured direct branch targets."
  decision_required_behavior: []
  blocked_behavior: []
  user_excluded_behavior: []
  required_user_visible_changes:
    - "Add disassemble to help and README command references."
    - "Add selector, strictness, demangling, and resource-limit flags."
    - "Add aligned text, JSON, diagnostics, and exit behavior."
  required_internal_changes:
    - "Remove silent prefix success from the multi-instruction formatter."
    - "Add a fail-closed streaming export-trie visitor in macho-dyld and implement the existing collecting API on top of it."
    - "Add validated disassembly request/report/service modules in macho-analysis."
    - "Add an internal work observer for deterministic scaling and allocation-bound assertions."
    - "Reexport the service through the analysis façade feature."
    - "Add deterministic fixtures, tests, benchmarks, fuzz checks, docs, and verifier coverage."
  required_error_handling:
    - "Classify grammar conflicts as usage errors."
    - "Classify mapping, selection, unsupported-architecture, and strict decode failures as execution failures with typed codes."
    - "Represent recovering gaps and configured-limit truncation in successful partial reports."
  required_edge_cases:
    - "Zero executable sections, repeated selectors, symbol aliases, data symbols, malformed symbol metadata, unsupported slices, duplicate architecture display names, fat address selection, section boundaries, caller-clipped instructions, invalid x86 bytes, arm64 fallback words, trailing arm64 bytes, address alignment/overflow, and exact limit boundaries."
  compatibility_requirements:
    - "Preserve the flat grammar, common output envelope, snapshot schema 3, domain registry, façade dependency direction, and existing Intel/bad64 formatter spellings."
    - "Do not retain the existing silent partial-success behavior as compatibility."
  performance_requirements:
    - "Runtime is linear in input bytes hashed for common identity plus metadata bytes/observations scanned plus examined bytes plus owned/serialized output bytes; exact symbol selection visits each nlist/export/Objective-C authority once per selected slice."
    - "Examined bytes and retained presentation ranges have independent hard per-slice limits."
    - "Symbol matching streams input metadata without retaining an unbounded all-symbol copy."
    - "No allocation trusts an unchecked input-derived count or byte length."
  security_or_safety_requirements:
    - "The command is read-only, writes no input or output files, launches no process, and uses checked address/offset arithmetic."
  observability_requirements:
    - "Reports expose selected extents, examined boundaries, counts, gaps, truncation causes, stable issue codes, and per-slice completion state."
```

## Governing invariants

1. **No silent bytes.** Every selected byte is represented by an instruction,
   a decode-gap record, or an explicit truncation boundary.
2. **Library operation before delivery.** Mach-O region selection,
   address-to-file mapping, decoding, classification, and symbol resolution live
   below the CLI. The command parses arguments and renders the typed report.
3. **Bounded work.** The decoded-byte limit is cumulative per selected slice and
   is enforced before allocating or formatting an instruction/gap record; the
   symbol-observation budget is enforced before retaining an alias.
4. **Exact selection.** Section and raw symbol matching are case-sensitive and
   exact. The implementation never broadens a missing selector with fuzzy or
   demangled-name matching.
5. **Evidence-bearing recovery.** Recovering mode continues after invalid x86-64
   bytes, but every skipped span remains in the report with raw bytes and
   `insn.decode.invalid`.
6. **Fail-closed strict mode.** Strict mode returns an execution failure on the
   first decode error and emits no partial stdout.
7. **One machine contract.** JSON is the ordinary CLI envelope whose `data` is
   `DisassemblyReport` schema version 1. Text and JSON derive from the same
   report.
8. **No snapshot inflation.** Disassembly is request-shaped and potentially
   large, so it is a public analysis service rather than an `AnalysisDomain`.
   `AnalysisDomain::ALL`, snapshot schema 3, diff defaults, and audit closure do
   not acquire raw instruction output.
9. **Architecture truth.** Any `CPU_TYPE_X86_64` subtype uses the x86-64
   decoder. Any `CPU_TYPE_ARM64` subtype uses arm64e mode only when its masked
   subtype is `CPU_SUBTYPE_ARM64E`, otherwise arm64 mode. Every other CPU type
   is unsupported. An unsupported selected slice is an explicit error naming
   its raw CPU tuple and the supported CPU types.
10. **Deterministic order.** Slices retain container order; selected regions are
    deduplicated and sorted by virtual address; records within a region are in
    increasing virtual-address order.
11. **Subtype-aware identity.** Display architecture names are labels, not
    unique identifiers. Selection and reports retain raw CPU type/subtype plus
    container slice index.
12. **Boundary truth.** A caller-clipped valid instruction is a selection
    boundary, never evidence that the input bytes are corrupt.

## Canonical command grammar

```text
macho disassemble PATH [--arch ARCH]
                       [--symbol NAME ... |
                        --section SEGMENT,SECTION ... |
                        --address VA [--length BYTES | --count INSTRUCTIONS]]
                       [--demangle]
                       [--strict]
                       [--max-decoded-bytes BYTES]
                       [--max-ranges RANGES]
                       [--format text|json|sarif]
                       [--color auto|always|never]
```

`disassemble` is the only command name. No `disasm` alias or argument
normalization layer is added. The root parser's shared `FormatArgs` exposes the
same three syntactic tokens to every command. For `disassemble`, `text` and
`json` are the only semantically supported formats: `--format sarif` parses far
enough to produce the centralized `cli.usage.unsupported_format` usage error,
exit code 2, and empty stdout. Help must say that SARIF is audit-only rather than
implying it is a valid disassembly output.

### Shared arguments

- `PATH`, `--arch`, `--format`, and `--color` use the existing shared argument
  authorities.
- `--arch NAME` preserves the existing ASCII-case-insensitive display-name
  selector. `--arch 0xCCCCCCCC:0xSSSSSSSS` adds an exact raw CPU-type/subtype
  selector using two eight-digit hexadecimal `u32` bit patterns. A malformed
  tuple is a usage error. A display name matching more than one legal fat slice
  is `analysis.disassembly.arch.ambiguous`, exit 1, and lists exact tuple forms;
  the command never picks the first match. The report stores the resolved raw
  `Architecture`, not the user spelling.
- The centralized output-policy check rejects `--format json --color always`
  and `--format sarif --color always` as usage errors before dispatch. This
  closes the current plan-15 deviation where machine formats silently disable
  requested color. The typed code is `cli.usage.color_machine` and the exact
  message is `--color always is incompatible with machine output`. `auto` and
  `never` remain valid for JSON and never emit ANSI.
- `--max-decoded-bytes` uses the existing analysis default of 64 MiB per slice,
  and `--max-ranges` uses the existing one-million-range default as a retained
  symbol-observation budget for labels and target resolution. One unique
  `(va, source, raw_name)` alias consumes one unit even when another alias has
  the same VA. Deduplicated explicitly requested symbol names reserve one unit
  each before auxiliary observations; a symbol request with more names than the
  limit is `cli.usage.invalid_arguments`, exit 2. The existing common analysis limits are factored
  into narrow decode/range limit arguments so `disassemble --help` does not
  expose unrelated string, xref, vtable, or issue limits.
- `--max-decoded-bytes 0`, `--max-ranges 0`, `--length 0`, and `--count 0` are
  usage errors.
- `--address` accepts hexadecimal VA text with an optional `0x` prefix, matching
  the existing xref-address parser. `--length` accepts decimal or `0x`-prefixed
  hexadecimal bytes. Counts and both resource limits are decimal integers.

### Selection modes

Exactly one selection mode is active:

1. With no selector, select every non-empty file-backed section carrying
   `S_ATTR_PURE_INSTRUCTIONS` or `S_ATTR_SOME_INSTRUCTIONS`. If none exist, the
   command returns a complete empty report and text says `No executable sections
   found.`
2. `--section SEGMENT,SECTION` is repeatable. Each pair is exact and each named
   section must exist in every selected slice. An explicitly named file-backed
   section is decoded even when its flags do not claim instructions; the
   report records that fact.
3. `--symbol NAME` is repeatable and matches nlist or export-trie spelling
   exactly. Matches at the same virtual address coalesce; the same name at
   different virtual addresses is ambiguous. Objective-C method display labels
   do not become `--symbol` selector aliases. `--demangle` changes display only.
   Every requested name must resolve uniquely to a file-backed instruction
   section in every selected slice; ambiguity tells the user to select
   `--address`. Raw nlist/export observations establish exact matches before
   request-specific extent resolution and range deduplication, so neither
   deduplication nor the presentation range limit can hide ambiguity.
4. `--address VA` selects one instruction by default. `--count N` selects exactly
   N decoded instructions while retaining intervening gap records. `--length N`
   selects the half-open byte range `[VA, VA + N)`. Count and length conflict,
   and both require `--address`. Reaching the natural section end before the
   requested instruction count is an input error unless the configured decoded-
   byte limit was reached first, in which case the report is partial/truncated.

Symbol extents follow one authority: the current `SymbolRangeIndex` ownership
policy. A requested start still matches nlist/export names only, but its next
code start is the minimum greater VA in the same section across nlist, export,
and Objective-C IMP observations, clamped to the section end. An Objective-C IMP
therefore terminates a selected nlist/export symbol when it is the next start.
Request-specific matching and next-start calculation stream all three raw
authorities before the bounded presentation index is built, so a low
`--max-ranges` value cannot hide or resize an explicitly requested symbol. The
region reports `range_source` for its selected start and `end_source` as
`nlist | export_trie | objc_metadata | section_end`; it does not claim a
recovered source-level function size. Explicit address ranges are clamped to no
boundary: a requested range that is not wholly file-backed in one section is an
input error rather than a silently shortened selection.

Symbol selection treats nlist, export-trie, and Objective-C ownership parsing as
required evidence because all three can determine the end. A malformed
table/trie/metadata graph, invalid string reference, overflow, or other parse
failure from any source aborts selection with
`analysis.disassembly.symbol.metadata_invalid`; it can never degrade into
`symbol.missing`, a guessed extent, or a partial match. In non-symbol selection
modes the same nlist/export failure, or malformed auxiliary Objective-C label
metadata, does not discard decoded bytes: it adds a
`analysis.disassembly.symbol.metadata_invalid` slice issue, marks that slice
partial, and omits only labels/target annotations that cannot be proven.

An address selection on a fat input requires `--arch`, because one virtual
address is not a portable selector across slices. Without `--arch`, default,
section, and symbol modes select every slice in container order; one unsupported
slice fails the whole command rather than disappearing. With `--arch`, only the
unique resolved raw CPU type/subtype executes. This makes a fat file containing
both ordinary x86_64 and x86_64h selectable without pretending their identical
current display names are unique.

### Decode modes

Recovering mode is the default inspection behavior:

- valid instructions become instruction records;
- an invalid x86-64 byte advances the recovery cursor by one byte;
- adjacent invalid bytes are coalesced into one gap record until the next valid
  instruction, region end, or decoded-byte boundary;
- a trailing partial arm64/arm64e word becomes a gap record;
- an undecodable complete arm64 word rendered by `bad64` fallback remains a
  visible `.inst 0x????????` instruction record; and
- reaching `--max-decoded-bytes` stops before starting a record that would cross
  the limit, marks the slice partial/truncated, and does not mislabel clipped
  bytes as corrupt.

With `--strict`, the first decode error fails the command with exit code 1 and
empty stdout. A caller-requested decoded-byte limit is still a limit, not a
decode error; reaching it returns a partial report with exit code 0.

## Reusable analysis contract

`macho-analysis` owns request validation, container/slice selection, region
resolution, bounded decoding, and report construction. The public shape is:

```rust
pub struct DisassemblyRequest {
    pub arches: SliceSelection,
    pub selection: DisassemblySelection,
    pub mode: DecodeMode,
    pub demangle: bool,
    pub max_decoded_bytes_per_slice: usize,
    pub max_symbol_ranges_per_slice: usize,
}

pub enum SliceSelection {
    All,
    Exact(Architecture),
}

pub enum DisassemblySelection {
    ExecutableSections,
    Sections(NonEmpty<SectionSelector>),
    Symbols(NonEmpty<String>),
    Address {
        start: Va,
        extent: AddressExtent,
    },
}

pub enum AddressExtent {
    InstructionCount(NonZeroUsize),
    ByteLength(NonZeroUsize),
}

pub enum DecodeMode {
    Recovering,
    Strict,
}

pub fn resolve_architecture_selector(
    container: &MachoContainer<'_>,
    selector: &str,
) -> Result<Architecture, DisassemblyError>;

pub fn disassemble(
    container: &MachoContainer<'_>,
    request: &DisassemblyRequest,
) -> Result<DisassemblyReport, DisassemblyError>;
```

Validated constructors keep invalid field combinations unrepresentable; every
observable request state above remains constructible. Request and report types
are owned values and do not borrow the input bytes.

The façade reexports the service through its existing analysis feature. The CLI
continues to depend only on `macho(full)` and gains no direct leaf dependency.

### Instruction-layer correction

The existing public `macho_insn::disassemble` cannot continue returning `Ok`
after silently stopping at an invalid x86-64 instruction. The implementation
must make that function strict or replace it with an explicit strict/recovering
pair. Existing callers and tests must migrate in the same change; a compatibility
wrapper that preserves silent partial success is forbidden by plan 15.

The analysis service uses `decode_iter` for strict mode and `decode_lossy` for
recovering mode, with the boundary checks specified below. It does not infer
instruction boundaries from formatted text.

### Export-trie traversal correction

`macho-dyld` adds a public fail-closed `visit_exports` API that yields one owned
`Export` at a time to a fallible callback and retains no `Vec<Export>` internally.

```rust
pub fn visit_exports(
    macho: &MachoFile<'_>,
    visitor: impl FnMut(Export) -> Result<()>,
) -> Result<()>;
```

Traversal scratch remains bounded by the existing node-count/depth safety
limits. Truncated ULEB values, terminal payloads, labels, child offsets, cycles,
and out-of-bounds nodes return typed errors; the visitor never reports a
successful prefix. Existing `parse_exports` remains source-compatible and is
implemented solely by collecting `visit_exports` callbacks. `find_export`
retains its direct lookup path but adopts the same fail-closed malformed-trie
semantics. `macho-analysis` uses the visitor for matching, boundary evidence,
budgeted labels, and target ranges, so the command never materializes the full
export set.

## Typed report and JSON contract

`macho-analysis::report::disassembly` owns the versioned DTOs and validation.
All serialized structs reject unknown fields when read back. Addresses, file
offsets, sizes, and counts are JSON `u64` values, matching the existing report
wire convention; raw bytes use one lowercase, even-length hexadecimal string
without separators. The reused `Architecture` retains its existing signed `i32`
CPU fields. Human output renders addresses and offsets in hexadecimal.

```text
DisassemblyReport
  schema_version = 1
  container = ReportContainerIdentity
  request
    arch? = Architecture { cpu_type: i32, cpu_subtype: i32 }; absent means all slices
    selection = tagged union
      { kind = executable_sections }
      { kind = sections, selectors[] = { segment, section } }
      { kind = symbols, names[] }
      { kind = address, start_va, extent = tagged union
        { kind = instruction_count, value } |
        { kind = byte_length, value } }
    mode = recovering | strict
    demangle
    max_decoded_bytes_per_slice
    max_symbol_ranges_per_slice
  slices[]
    identity = ReportSliceIdentity
    container_offset
    slice_size
    status = complete | partial
    decoded_bytes
    decoded_bytes_truncated
    symbol_ranges_truncated
    regions[]
      segment
      section
      selection_source = executable_section | explicit_section | symbol | address
      range_source? = nlist | export_trie
      end_source? = nlist | export_trie | objc_metadata | section_end
      start_va
      requested_end_va?
      requested_instruction_count?
      emitted_instruction_count
      examined_end_va
      next_unexamined_va?
      instruction_flags
        pure_instructions
        some_instructions
      labels[]
        va
        raw_name
        display_name
        source = nlist | export_trie | objc_metadata
      records[]
        instruction
          va
          thin_file_offset
          container_file_offset
          size
          bytes
          text
          kind = branch | call | conditional_branch | return | nop | pc_relative | other
          direct_target?
            va
            raw_symbol?
            display_symbol?
            source? = nlist | export_trie | objc_metadata
            offset?
        gap
          va
          thin_file_offset
          container_file_offset
          bytes
          code = insn.decode.invalid | analysis.disassembly.selection.partial_instruction
          message
    issues[]
      code
      message
```

All enum and union tags serialize as the lower-snake-case literals shown. Each
record carries `record_type: "instruction" | "gap"`. Every field marked `?` is
present and JSON `null` when absent; variant-only fields exist only on their
tagged variant. `range_source` and `end_source` are non-null exactly for symbol
selection and null for the other three selection sources. No other optional or
flattened fields exist in schema v1.
Each issue is exactly `{ code: String, message: String }`; issues are ordered by
code then message and duplicates coalesce. Location-bearing failures remain
records or top-level typed errors instead of adding an open-ended issue shape.

The report reuses `report::common::ReportContainerIdentity` and
`ReportSliceIdentity`; it does not extend the snapshot-only `SliceIdentity`.
The common image identity's slice index plus raw CPU type/subtype is the unique
slice key even when two display architecture names are equal. `container_offset`
is `0` for thin input and the fat-table slice offset for fat input. Every record
has both coordinate systems: `thin_file_offset` is relative to the selected
Mach-O image, while `container_file_offset` is relative to the input file. They
are equal for thin input; fat offsets use `FatArch::thin_to_fat_offset` and
checked arithmetic. `slice_size` is the thin image byte length.

The `records` array is a tagged union so a consumer cannot mistake a gap for an
instruction. `decoded_bytes` counts instruction and gap bytes actually examined.
`instruction_flags` is the exact two-boolean wire object shown above. `labels`
contains every budgeted alias whose VA lies in the region, ordered by VA,
source, raw name, then display name; an instruction label is derived by exact VA
equality and is not duplicated in the instruction record. Demangling changes
only `display_name`. A `direct_target.offset` is an unsigned byte offset from
the start of its containing range and is present only with a resolved target
symbol; `raw_symbol`, `display_symbol`, `source`, and `offset` are either all
present or all absent. The request union uses the literal `kind` tags shown
above, preserves user selector order only until validation, then stores
deduplicated sections and symbols in deterministic lexical order. Architecture
names are normalized through the existing architecture selector authority.

Every region carries exactly one request extent: `requested_end_va` for a byte-
bounded section/symbol/address selection, or `requested_instruction_count` for
an instruction-count address selection. `examined_end_va` is the exclusive end
of accounted records. `next_unexamined_va` is absent for a fully examined region
and equals `examined_end_va` when a decoded-byte limit leaves an unexamined
suffix. For byte-bounded selections that suffix is exactly
`[next_unexamined_va, requested_end_va)`. For instruction-count selection its
byte end is intentionally unknown, while
`requested_instruction_count - emitted_instruction_count` gives the remaining
instruction count. When complete, byte-bounded regions satisfy
`examined_end_va == requested_end_va`; count-bounded regions satisfy
`emitted_instruction_count == requested_instruction_count` and end immediately
after the requested instruction. If the next complete instruction or recovery
unit would cross the remaining decoded-byte budget, it is not examined and the
boundary stays at that unit's starting VA. Natural section end before a count is
an `analysis.disassembly.count.unsatisfied` error unless the resource boundary
was reached first.

Byte-bounded decoding distinguishes malformed input from a selector that ends
inside an otherwise valid instruction. The decoder is permitted to inspect bytes from the
cursor through the enclosing file-backed section end solely to establish the
next instruction's true length. If that valid instruction crosses
`requested_end_va`, recovering mode emits one gap containing only the selected
tail bytes with code `analysis.disassembly.selection.partial_instruction`, marks
the slice partial, and exits 0; strict mode returns that code as an execution
error with empty stdout. If the bytes are undecodable even with the natural
section tail available, the ordinary `insn.decode.invalid` policy applies.
Decoded-byte-limit boundaries never create either gap. On arm64/arm64e, every
selected region start must be four-byte aligned before decoding. This applies
equally to default executable sections, explicit sections (including unflagged
ones), exact symbols, and explicit addresses. An unaligned start fails the whole
command with `analysis.disassembly.address.unaligned`, selector kind, raw VA,
slice index, and CPU tuple; it is never rounded, skipped, or passed to `bad64`.

`decoded_bytes_truncated` and `symbol_ranges_truncated` identify which configured
bound was reached. A recovering decode gap makes the slice `partial` without
making either truncation field true. Exact symbol selection scans requested
names before the bounded presentation/range index is built, so a label bound
cannot turn a present requested symbol into a false missing-symbol error. That
scan visits every nlist/export/Objective-C observation in the selected slice in the worst case, but it
streams matches and next-start candidates rather than retaining an unbounded
copy; CPU time is input-metadata bounded and retained range memory remains
bounded by `--max-ranges`.

Budget retention is deterministic and bounded. After canonical requested-symbol
observations are reserved (`nlist` before `export_trie` at an equal name/VA),
auxiliary observations are considered in nlist table order, export-trie visitor
order, then Objective-C metadata order. Exact duplicate tuples coalesce. The
first unique tuple beyond the budget makes `symbol_ranges_truncated` true, but
the raw streaming scan continues so malformed metadata, selector ambiguity, and
next-start evidence remain visible. Retained observations are sorted only after
the bound is enforced. Equal-VA aliases never become free budget entries, and a
direct target chooses the lowest retained alias by source priority then raw name.

Validation rejects a report unless container/slice counts and kinds agree;
common image byte lengths agree with `slice_size`; raw CPU identities and slice
indices are unique; thin container/image hashes and lengths agree; every fat `container_file_offset` equals checked
`container_offset + thin_file_offset`; instruction `size` equals decoded bytes;
hex byte lengths agree with every instruction/gap extent; records are ordered,
non-overlapping, and contiguous across the examined prefix; region and per-slice
counts equal their record sums; optional target fields obey their all-or-none
rule; and status/truncation/issue fields obey the boundary semantics above.
`complete` means no gap, issue, or configured truncation occurred. Any one of
those evidence losses makes the slice `partial`.

### Executable work and allocation bounds

The service has an internal observer used by tests (not a public report field)
with counters for container bytes hashed, slice bytes hashed, metadata
observations and name bytes visited per source, aliases retained, decode
attempts, examined bytes, records retained, owned report bytes, and serialized
bytes. The implementation performs one metadata pass per source and proves:

- container-plus-slice hashing visits at most `2 * input_len` bytes; a thin
  input reuses its one image digest;
- aliases retained never exceed `max_symbol_ranges_per_slice`, including
  equal-VA aliases;
- records retained never exceed examined bytes, and decode attempts never exceed
  examined bytes plus selected-region count;
- raw instruction/gap bytes retained equal examined bytes; and
- other owned memory and rendering work are charged to retained metadata-name
  bytes or actual serialized output bytes, not to an unchecked file count.

`disassembly_work_bounds` runs fixed-content fixtures at N and 2N selected bytes,
asserts each relevant counter grows by at most 2x plus one region's constant
overhead, and runs an alias flood at 10x the configured budget to prove retained
aliases remain exactly at the cap while truncation is reported. A malformed
export fixture proves streaming returns an error instead of successful-prefix
statistics. These are deterministic count assertions; elapsed wall time is not
used as acceptance evidence.

Direct branch/call/conditional targets come from the structured `InsnKind`, not
from parsing display text. When a target belongs to a known range, the report
includes raw and display names plus the offset into that range. Indirect targets
remain absent rather than guessed.

Thin and fat inputs always use the same `slices` array. The CLI delivery layer
wraps this report in:

```json
{
  "schema_version": 1,
  "command": "disassemble",
  "ok": true,
  "data": {
    "schema_version": 1,
    "container": {
      "content_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
      "byte_len": 4096,
      "container": "thin",
      "slice_count": 1
    },
    "request": {
      "arch": null,
      "selection": { "kind": "executable_sections" },
      "mode": "recovering",
      "demangle": false,
      "max_decoded_bytes_per_slice": 67108864,
      "max_symbol_ranges_per_slice": 1000000
    },
    "slices": [
      {
        "identity": {
          "image": {
            "content_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "byte_len": 4096,
            "container": "thin",
            "slice_index": 0,
            "architecture": { "cpu_type": 16777228, "cpu_subtype": 0 },
            "uuid": null
          }
        },
        "container_offset": 0,
        "slice_size": 4096,
        "status": "complete",
        "decoded_bytes": 0,
        "decoded_bytes_truncated": false,
        "symbol_ranges_truncated": false,
        "regions": [],
        "issues": []
      }
    ]
  },
  "diagnostics": []
}
```

This is a schema-valid complete response for a thin arm64 image with no
executable sections; the digest strings are illustrative but satisfy the common
identity validators. Non-empty golden fixtures exercise every record field.

## Human-readable output

Text renders from the typed report once. Its schematic layout is:

```text
=== arm64 [slice 1, 0x0100000c:0x00000000] ===
__TEXT,__text  0x0000000100003f50..0x0000000100003f60
_main:
  0x0000000100003f50  <raw bytes>  <decoder text>
  0x0000000100003f54  <raw bytes>  <decoder text> ; <resolved target>
```

x86-64 text uses the existing `iced_x86::IntelFormatter`; arm64 and arm64e use
the existing `bad64` spelling with the `.inst` fallback. These spellings are
part of the text and JSON `text` contract.

Requirements:

- the address, raw-byte, and instruction-text columns align before ANSI styling;
- x86-64 raw-byte width accommodates its maximum instruction size without
  changing following-column alignment;
- slice headers appear only when more than one slice is emitted; each header
  includes display name, slice index, and raw CPU tuple so duplicate names stay
  distinguishable;
- section/range headers and symbol labels remain visible without color;
- the decoder formatter receives no symbol resolver and each resolved direct
  target receives exactly one appended symbolic annotation;
- a gap row shows its address, raw bytes, stable code, and message;
- partial state and the specific decoded-byte/range truncation cause are visible
  in the region or slice summary;
- `--demangle` changes labels and target display names before width measurement
  while JSON retains both raw and display names; and
- stripping ANSI from `--color always` output produces byte-identical
  `--color never` output.

No progress text is emitted. Requested data goes to stdout; warnings and errors
obey the existing channel and envelope contract.

## Errors and diagnostics

The implementation adds documented stable codes for:

- `cli.usage.unsupported_format`;
- `cli.usage.color_machine`;
- `analysis.disassembly.arch.unsupported`;
- `analysis.disassembly.arch.ambiguous`;
- `analysis.disassembly.section.invalid`;
- `analysis.disassembly.section.missing`;
- `analysis.disassembly.symbol.missing`;
- `analysis.disassembly.symbol.ambiguous`;
- `analysis.disassembly.symbol.non_code`;
- `analysis.disassembly.symbol.metadata_invalid`;
- `analysis.disassembly.address.unmapped`;
- `analysis.disassembly.address.cross_section`;
- `analysis.disassembly.address.unaligned`;
- `analysis.disassembly.selection.partial_instruction`;
- `analysis.disassembly.count.unsatisfied`;
- the existing `analysis.limit.truncated`; and
- the existing `insn.decode.invalid`.

`DisassemblyError::code()` is retained as the CLI diagnostic code while the
central `CliErrorKind` still decides usage versus execution exit class. Text and
JSON failures therefore expose the same command-specific code.

Argument-shape conflicts are usage failures with exit code 2. Input mapping,
parsing, or selection failures and strict decode failures use exit code 1 with
empty stdout. Recovering gaps and configured-limit truncation produce an
inspectable report with exit code 0 and explicit partial state.

## Dependency-ordered implementation packages

### WP1 - Lock leaf decoding and export traversal

1. Replace silent partial success in `macho_insn::disassemble` with an explicit
   strict result or strict/recovering APIs.
2. Add fail-closed streaming `macho-dyld::visit_exports`; rebuild
   `parse_exports` on that visitor and remove successful-prefix malformed-trie
   behavior.
3. Add paired invalid-byte/incomplete-word instruction tests and streaming,
   collecting-parity, alias-order, and malformed export-trie tests.
4. Extend the instruction and export-trie fuzz targets so arbitrary bytes cannot
   panic, silently disappear, or allocate beyond traversal safety limits.

Checkpoint: strict invalid input errors; recovering input accounts for the
entire selected byte span; streaming and collecting exports agree on valid
tries and fail on malformed tries; `cargo test -p macho-insn` and
`cargo test -p macho-dyld` pass.

### WP2 - Build the report and analysis service

1. Add validated schema-version-1 disassembly DTOs under
   `macho-analysis::report`.
2. Add request/selector validation and exact architecture mapping.
3. Resolve executable, named-section, symbol, and address regions with checked
   arithmetic, file-backed bounds, three-source symbol ends, and uniform ARM
   alignment.
4. Decode with the cumulative per-slice limit, construct tagged instruction/gap
   records, and mark partial/truncated state.
5. Attach labels and structured direct targets through budgeted range evidence,
   counting every retained alias.
6. Add the internal work observer and deterministic scaling/allocation-bound
   tests.
7. Reexport the service through the façade analysis surface.

Checkpoint: direct analysis tests cover every selector, supported architecture,
fat order, gap, limit, target, schema round trip, and invalid schema case without
invoking the CLI.

### WP3 - Add CLI delivery

1. Add `Disassemble` to `Commands`, grouped help, name mapping, and dispatch.
2. Add `subcommands/disassemble.rs` with flattened common arguments and Clap
   conflicts/requires rules.
3. Close plan 15's centralized output-policy gap: reject color-always for every
   machine format before dispatch while preserving audit as the sole SARIF
   success command.
4. Convert CLI arguments into the validated library request, including unique
   subtype-aware architecture resolution.
5. Render text through the shared column/style layer and JSON through the common
   success envelope.
6. Preserve typed errors through centralized exit and diagnostic delivery.

Checkpoint: `parse_only`, `run_captured`, and real-process tests agree on valid,
invalid, text, JSON, and color behavior.

### WP4 - Complete fixtures, docs, and gates

1. Extend `macho-test-support` with deterministic x86-64 and arm64/arm64e
   executable-section fixtures containing symbols, direct branches, invalid
   bytes or fallback words, and a fat combination.
2. Add CLI integration/golden tests and system-I/O versus injected-I/O parity.
3. Add bounded disassembly cases to the existing benchmark authority and build
   them in the whole-tree gate.
4. Update README examples/reference, grouped help expectations, changelog,
   diagnostic-code registry, plan 15's canonical grammar, and `plans/README.md`.
5. Run the complete plan-15 verification gate and record any unrelated baseline
   failures separately from this feature's evidence.

Checkpoint: docs derive from the live router, portable fixtures prove the full
contract, and the whole-tree verification result is reported without laundering
pre-existing failures into feature success.

## Scope ledger

| ID | Item | Source | Disposition | Acceptance evidence | Verification |
| --- | --- | --- | --- | --- | --- |
| S001 | Canonical `macho disassemble` command and help | user | INCLUDED | command parses and appears once in grouped help | A001, V004 |
| S002 | Thin and supported fat Mach-O operation | inferred | INCLUDED | ordered per-slice reports | A002, A003 |
| S003 | Default executable-section selection | inferred | INCLUDED | both instruction flags select file-backed regions | A004 |
| S004 | Repeatable exact section selection | inferred | INCLUDED | exact pairs resolve; malformed/missing pairs fail | A005, A014 |
| S005 | Repeatable exact raw-symbol selection | inferred | INCLUDED | unique code symbols resolve; missing/ambiguous/data symbols fail | A006, A015 |
| S006 | Address, byte-length, and instruction-count selection | inferred | INCLUDED | one-instruction default and explicit extents are exact | A007, A016 |
| S007 | x86-64, arm64, and arm64e decoding | codebase | INCLUDED | architecture fixtures produce correct text and sizes | A008 |
| S008 | Recovering gap accounting | existing_spec | INCLUDED | every invalid selected byte appears once | A009 |
| S009 | Strict fail-closed decoding | existing_spec | INCLUDED | first gap yields exit 1 and empty stdout | A010 |
| S010 | Cumulative decoded-byte and symbol-range bounds | existing_spec | INCLUDED | neither resource crosses its limit and each truncation cause is reported | A011 |
| S011 | Typed versioned report and validation | inferred | INCLUDED | v1 round trip; wrong version/unknown fields rejected | A012 |
| S012 | Raw bytes, addresses, offsets, text, and kinds | inferred | INCLUDED | instruction records contain all fields | A008, A012 |
| S013 | Labels, demangling, and structured direct targets | codebase | INCLUDED | raw/display labels and target offsets agree | A013 |
| S014 | Aligned/color-safe text | existing_spec | INCLUDED | ANSI-stripped colored golden equals plain golden | A017 |
| S015 | Common JSON envelope and clean channels | existing_spec | INCLUDED | stdout parses; stderr cannot contaminate data | A018 |
| S016 | Stable errors and exit classes | existing_spec | INCLUDED | usage/input/execution/partial cases have exact codes/status | A014-A016, A019 |
| S017 | No snapshot-domain/schema expansion | codebase | INCLUDED | domain registry and schema v3 remain byte-for-byte compatible | A020 |
| S018 | Silent `macho-insn::disassemble` behavior removed | existing_spec | INCLUDED | invalid x86-64 stream cannot return `Ok(prefix)` | A009, V001 |
| S019 | Portable fixtures, docs, changelog, diagnostics, benchmark, and fuzz updates | inferred | INCLUDED | repository checks enumerate each artifact | V005-V009 |
| S020 | CLI depends only on façade full feature | existing_spec | INCLUDED | dependency and architecture checks remain green | V005, V007 |
| S021 | Dirty baseline churn accounted separately | codebase | INCLUDED | fresh probes distinguish renewed unrelated failures from introduced failures | V005, V010 |
| S022 | Shared machine-format/color policy correction | existing_spec | INCLUDED | disassembly rejects SARIF and colored JSON; audit SARIF and ordinary text/color remain intact | A024, V012 |
| S023 | Subtype-aware fat-slice identity and selection | review | INCLUDED | duplicate display names never select ambiguously and raw tuples select exactly | A021, A025 |
| S024 | Caller-clipped instruction boundary semantics | review | INCLUDED | clipped valid x86/ARM instructions are never labeled corrupt | A022 |
| S025 | Malformed selector-metadata propagation | review | INCLUDED | corrupt symbol authorities cannot become false missing-symbol results | A023 |
| S026 | Streaming fail-closed export traversal | review | INCLUDED | visitor/collector parity without full-set retention or successful malformed prefixes | A023, V013 |
| S027 | Alias-aware symbol budget | review | INCLUDED | equal-VA aliases consume units and alias floods stay capped | A027, V014 |
| S028 | Objective-C-aware selected-symbol ends | review | INCLUDED | next Objective-C IMP terminates the selected symbol exactly | A026 |
| S029 | Executable scaling and allocation evidence | review | INCLUDED | deterministic N/2N and alias-flood counters satisfy hard bounds | A028, V014 |

## Acceptance contract

| ID | Scenario | Expected behavior | Required evidence |
| --- | --- | --- | --- |
| A001 | `disassemble --help` | canonical usage, selector conflicts, defaults, examples, and no alias | help golden and parse test |
| A002 | thin x86-64 default | all instruction-bearing regions decode in VA order | typed report assertion and text golden |
| A003 | fat x86-64 plus arm64e | both slices emit in container order; `--arch` selects one | JSON golden and process test |
| A004 | pure/some-instructions flags | both flag forms select; unflagged section does not enter default selection | analysis fixture |
| A005 | repeated named sections | exact requested sections deduplicate and sort | analysis and CLI tests |
| A006 | repeated exact symbols | each unique raw symbol selects its range and exposes range source | analysis and CLI tests |
| A007 | address extents | no extent decodes one; count decodes exactly N; length covers exactly N bytes or fails visibly | boundary tests |
| A008 | three supported architectures | correct instruction sizes, bytes, architecture text, kinds, and offsets | deterministic fixtures |
| A009 | invalid/recoverable stream | instructions plus gaps account for every examined byte exactly once | byte-conservation assertion |
| A010 | strict invalid stream | exit 1, empty stdout, typed stderr | captured and real-process tests |
| A011 | decoded-byte and symbol-observation limits | no examined byte or retained alias crosses its limit; partial state names each truncation cause; requested-symbol count above the range budget is usage failure | limit boundary tests |
| A012 | JSON report | valid empty and non-empty v1 examples round trip; wrong version, unknown field/enum, bad digest/hex, bad thin/container coordinate, duplicate slice identity, record disorder/overlap/hole, inconsistent instruction size, region/slice count sum, target option set, request extent, boundary, truncation flag, and complete/partial status each reject | full DTO validator negative matrix and JSON goldens |
| A013 | labels and branch targets | direct target comes from `InsnKind`; raw/display names and offsets are correct | x86-64 and arm64 fixtures |
| A014 | malformed/missing section | usage error for grammar; input error for absent section; empty stdout | negative CLI tests |
| A015 | missing/ambiguous/non-code symbol | exact diagnostic suggests address selection where applicable | negative analysis/CLI tests |
| A016 | address outside or across file-backed section | input failure; fat address without `--arch` is usage failure | negative CLI tests |
| A017 | text/color | aligned goldens; stripping ANSI from always equals never | golden comparison |
| A018 | JSON/channels | stdout is one success envelope; warnings/errors stay on stderr | injected/process parity |
| A019 | unsupported architecture | explicitly selected unsupported tuple, or any unsupported slice selected implicitly in a mixed fat input, names raw selected/supported CPU identities and returns exit 1 without skipping | unknown-CPU and mixed-fat fixtures |
| A020 | snapshot isolation | `AnalysisDomain::ALL` and schema-v3 domain registry do not include disassembly | registry equality test |
| A021 | fat x86_64 plus x86_64h display-name collision | `--arch x86_64` fails ambiguous with exact tuple suggestions; a raw tuple selects one slice | analysis fixture, JSON identity assertion, and CLI negative/positive tests |
| A022 | byte length ends inside valid x86 instruction or arm64 word; arm64 region starts unaligned | recovering emits `selection.partial_instruction`; strict fails empty; default, section, symbol, and address selectors each fail `address.unaligned` without rounding | boundary fixtures in both decode modes plus four unaligned-selector fixtures |
| A023 | corrupt nlist/export/Objective-C selector metadata | symbol selection fails `symbol.metadata_invalid`, never `symbol.missing`; the same corruption in non-symbol address mode yields a partial report issue | corrupt symtab/export and Objective-C fixture tests |
| A024 | shared output-policy matrix | disassembly SARIF exits 2 with typed code `cli.usage.unsupported_format`, empty stdout, and exact stderr line `Error: SARIF output is supported only by the audit command\n`; JSON plus color-always exits 2 with empty stdout and a JSON `cli.usage.color_machine` failure envelope on stderr; audit SARIF auto/never succeeds; audit SARIF/color-always fails with the color code; existing human text/color still works | validator unit test plus parse, captured, and real-process regression matrix |
| A025 | common identity and offset coordinates | common identity preserves raw subtype and slice index; thin/container offsets agree for thin and differ by the exact fat slice base for fat | v1 JSON golden and checked-offset assertions |
| A026 | nlist/export symbol followed by Objective-C IMP | selected symbol ends at the IMP, reports `end_source: objc_metadata`, and never decodes into the next owner | typed range assertion and text/JSON golden |
| A027 | more same-VA aliases than `--max-ranges` | each unique source/name alias consumes one unit; canonical requested aliases reserve first; retained count equals the cap; truncation is true; output ordering and direct-target choice follow the locked precedence | alias-flood and exact-bound tests |
| A028 | N/2N work scaling and export stream | observer counters satisfy every stated hash/metadata/decode/retention/output bound; 10x alias flood stays capped; malformed export traversal errors without a prefix | `disassembly_work_bounds` and `macho-dyld` visitor tests |

Unacceptable results:

- returning successful prefix-only disassembly after an invalid instruction;
- decoding a fuzzy, demangled, or case-folded symbol match;
- silently clamping an explicit address range;
- calling the decoder from CLI region-selection logic;
- serializing a gap as an instruction or dropping its bytes;
- adding disassembly to snapshots, default semantic diffs, or audit closure;
- contaminating JSON stdout with warnings, progress, or errors;
- accepting a colored machine format; or
- claiming complete verification while any architecture or feature-owned
  verification remains red.

## Verification plan

| ID | Command or check | Purpose | Expected signal |
| --- | --- | --- | --- |
| V001 | `cargo test -p macho-insn` | strict/recovering decoder and formatter behavior | all tests pass; invalid prefix test rejects silent success |
| V002 | `cargo test -p macho-analysis --all-features` | request, selection, report, schema, and branch-target behavior | all tests pass |
| V003 | `cargo test -p macho-cli --test disassemble_tests` | command behavior and negative cases | all tests pass |
| V004 | `cargo run -q -p macho-cli -- disassemble --help` | live grammar/help | canonical grammar and examples only |
| V005 | `cargo xtask architecture` | crate ownership, dependency edges, and output rules | pass |
| V006 | `cargo xtask docs --check` | README/router/diagnostic/changelog drift | pass |
| V007 | `cargo tree -p macho-cli` and `cargo tree -p macho-analysis` | dependency boundary | CLI has no direct leaf edge; no cycle/new forbidden edge |
| V008 | `cargo bench --workspace --all-features --no-run` | benchmark authority compiles | pass |
| V009 | `cargo xtask verify-fuzz` | instruction and export-trie fuzz targets/corpora build | pass |
| V010 | `cargo xtask verify` | complete stable whole-tree gate | pass, or exact unrelated pre-existing failures reported with the feature verdict not COMPLETE |
| V011 | compare real process and `run_captured` for valid text, valid JSON, usage failure, strict decode failure, and limit truncation | independent I/O route | byte-identical stdout, stderr, and exit status |
| V012 | run captured and real-process output-policy matrix for disassemble SARIF, disassemble JSON/color-always, info JSON/color-always, audit SARIF auto/never, audit SARIF/color-always, and text color-always | shared output-policy regression | exact exit/code/channel behavior from A024; audit remains the sole SARIF success command |
| V013 | `cargo test -p macho-dyld exports` | streaming export visitor, collecting compatibility, and malformed-trie behavior | visitor and collector agree on ordered valid exports; truncation/cycle/bounds cases fail without successful prefixes |
| V014 | `cargo test -p macho-analysis --all-features disassembly_work_bounds` | executable work/allocation limits | N/2N counters remain within linear inequalities; record/raw-byte/alias caps hold; 10x alias flood truncates at the exact cap |

## Exception ledger

| ID | Type | Description | Owner | Requested by | Impact | User decision required | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| E001 | baseline_churn | Planning-time architecture probes changed from import failure, to size failures, to green as unrelated analysis files moved; the latest `cargo xtask architecture` passes. | existing in-progress analysis work | planner | Refresh the gate before implementation and separate any renewed unrelated failure from feature failures; no baseline failure is fixed incidentally. | false | resolved |
| E002 | dirty_overlap_risk | The shared dirty tree already contains changes under `macho-analysis::report`, CLI arguments/output/router, test support, and plan 15. | existing user/in-progress work | independent reviewer | Before implementation, reopen `git status` and diffs for every target; prefer new modules and additive tests, and STOP if same-line ownership cannot be isolated. | false | pending |

No skipped feature verification, behavior mismatch, or proposed scope reduction
is accepted by this contract. Any such condition discovered during
implementation must be added here and returned for user decision when it would
weaken an accepted item.

## STOP triggers

Stop implementation and report exact evidence if:

- the user has not accepted this reviewed contract;
- implementing the service requires a forbidden dependency edge or snapshot
  schema change not specified here;
- symbol range selection cannot distinguish code-backed from data-backed
  symbols without guessing;
- a selected byte cannot be represented exactly once as instruction, gap, or
  truncation boundary;
- strict and recovering output cannot be derived from the same decoder facts;
- address arithmetic or section mapping cannot prove the requested range is
  wholly file-backed;
- implementation overlaps unresolved user changes in the same lines and cannot
  be isolated; or
- any proposed fix weakens a governing invariant or acceptance test.

Workload size, the number of required fixtures, and unrelated lint volume are
not STOP conditions.

## Contract review

Reviewer verdict: APPROVED_WITH_RISK

The independent reviewer approved the frozen semantic contract at SHA-256
`c6d8d09e60ef5e26a7ad5bd2b289e306292dc6c485023b79443509b3e198a45b`.
The review confirmed that the final contract closes subtype-aware identity,
wire DTO closure, clipped-instruction behavior, malformed symbol evidence,
shared output policy, three-source symbol ends, streaming export traversal,
alias-budget accounting, uniform ARM alignment, complete schema evidence, and
executable scaling evidence.

No contract fix remains. E002 is the sole residual risk: implementation must
refresh the dirty-tree ownership map and stop on an unisolatable same-line
collision. This risk does not weaken scope. Gate 3 user acceptance is pending.
