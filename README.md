# macho

**One Rust toolkit for reading, reconstructing, auditing, and rewriting Mach-O binaries — no Xcode, no `otool`, no macOS required.**

[![CI](https://github.com/bryanmatteson/macho/actions/workflows/ci.yml/badge.svg)](https://github.com/bryanmatteson/macho/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/macho.svg)](https://crates.io/crates/macho)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust 1.91.1+](https://img.shields.io/badge/rust-1.91.1%2B-orange.svg)](https://www.rust-lang.org)

`macho` is what you reach for when you have an Apple binary and a question. It reads the header, walks the load commands, recovers Objective-C and Swift declarations that were compiled away, disassembles the code, diffs two builds, audits the code signature, patches an rpath, re-signs the result, and cracks open a dyld shared cache — from a single static binary that runs the same on macOS, Linux, and Windows.

```console
$ macho objc Calculator --headers --arch arm64e
@interface _TtC10Calculator19CalculatorViewModel : _TtCs12_SwiftObject
@end
@protocol NSApplicationDelegate<NSObject>
- (unsigned long long)applicationShouldTerminate:(id)arg1;
- (void)application:(id)arg1 openURLs:(id)arg2;
...
```

That header was never in the file. `macho` projected the declaration supported by Objective-C metadata embedded in the binary; unresolved declarations and members remain visible in the JSON ledger instead of being guessed away.

---

## Why it exists

Inspecting Apple binaries usually means juggling `otool`, `nm`, `dyld_info`, `codesign`, `class-dump`, a Swift demangler, a disassembler, and a shared-cache extractor — most of which only run on a Mac with the right SDK installed. `macho` folds that toolbox into one command with a single, consistent grammar and a library you can build on.

| Instead of… | Use |
| --- | --- |
| `otool -l`, `otool -h` | `macho info` |
| `nm`, `dyld_info -exports` | `macho symbols`, `macho exports`, `macho imports` |
| `class-dump` | `macho objc --headers` |
| a Swift metadata reader + demangler | `macho swift --headers` |
| `otool -tV` / a standalone disassembler | `macho disassemble` |
| manual arm64e fixup and opcode auditing | `macho pac` |
| `codesign -d`, `codesign -s` | `macho codesign`, `macho patch --sign-*` |
| `install_name_tool`, `otool` byte-patching | `macho patch` |
| diffing two builds by hand | `macho diff` |
| a shared-cache extractor | `macho cache` |

Measured comparisons against Apple CLIs, class-dump-style dumpers, `ipsw`, and
interactive RE suites — plus host-captured demos on Calculator arm64e (ObjC /
Swift recovery, PAC completeness, fail-closed patch, SARIF audit) — live in
[`docs/comparison-evidence.md`](docs/comparison-evidence.md).

Report-producing commands speak `--format text` for humans and `--format json` for pipelines; `audit` also emits **SARIF 2.1** so findings drop straight into GitHub code scanning. Artifact-producing `header-infer` actions use their explicit output files or emit source/prompt text instead.

## Highlights

- **Evidence-accountable header recovery.** `objc --headers`, `swift --headers`, `c --headers`, and `cpp --headers` project typed declarations from the runtime metadata, symbols, and debug evidence that survive compilation. Every report carries completeness states and an unresolved ledger, so partial evidence stays explicit instead of becoming a plausible-looking guess.
- **In-process code signing.** Ad-hoc and PKCS#12 signing and verification happen inside the tool. No `xcrun`, no Keychain, no macOS. The same inputs work on all three platforms, and passwords are read from a file so they never touch the command line or your shell history.
- **Byte-safe by construction.** The core parser validates structure before it trusts it, and the whole workspace is continuously fuzzed (headers, load commands, code signatures, dyld metadata, mutation, and more).
- **Mutation that refuses to corrupt.** Patches extend existing slack and file-backed segments only; they never relocate existing payload, symbols, or fixups. If a placement isn't provably safe, the transaction refuses to commit. The [layout boundary](crates/macho/docs/mutation-layout.md) inventories every modeled coordinate and the opaque structures that make universal relayout unsound.
- **Semantic diffing and auditing.** `diff` compares two binaries by meaning and can fail CI on breaking changes; `audit` surfaces signing and configuration findings with stable diagnostic codes.
- **Pick only what you need.** One package exposes feature-gated parser, metadata, analysis, mutation, workflow, and CLI modules, so narrow consumers do not compile capabilities they did not select.

## Install

```bash
cargo add macho
cargo install macho --features cli  # installs the `macho` binary
```

The unified package requires Rust 1.91.1. From a checkout, use `cargo install --path crates/macho --features cli` to install that exact source tree.

Then, from a clone:

```bash
mise run verify     # format, lint, docs, tests, benches, and fuzz-target builds
```

## Tour

```bash
# Structure
macho info <binary>
macho info <binary> --arch arm64 --validate

# Symbols
macho symbols <binary> --defined-only --demangle
macho imports <binary> --format json

# Evidence-backed header projections from stripped binaries
macho objc <binary> --headers
macho objc <binary> --kind class --presence defined --selector viewDidLoad
macho swift <binary> --state metadata-defined --name MyModule
macho swift <binary> --arch arm64 --name MyModule.Record --exact --headers
macho c <binary> --headers
macho cpp <binary> --headers

# Export exact C++ projection blockers into the bounded operator-edit workflow
macho cpp <binary> --headers --arch x86_64 --format json > cpp-recovery.json
macho header-infer export cpp-recovery.json --arch x86_64 --all-header-gaps --output header-gaps.json
macho header-infer inspect header-gaps.json

# Pointer authentication inventory and code-site recovery
macho pac <binary> --arch arm64e
macho pac <binary> --arch arm64e --pointers --gadgets
macho pac <binary> --arch arm64e --format json

# Disassembly
macho disassemble <binary> --arch arm64e --symbol _main
macho disassemble <binary> --address 0x100003f50 --count 8 --format json
macho disassemble <binary> --section __TEXT,__text --no-labels --no-targets

# Strings and cross-references
macho strings <binary> --min-length 8 --offsets
macho strings <binary> --search "secret" --exact
macho xrefs <binary> --import malloc --kind stub
macho ranges <binary> --name main --source nlist --demangle

# Evidence-accounted program recovery (select stages or use --all)
macho program <binary> --all --coverage --format json
macho program <binary> --stage dependencies --stage semantics
macho program <binary> --load-dependencies --dependency-search-path ./Frameworks --format json
macho program <binary> --load-dependencies --dyld-cache <dyld-cache> --format json
macho program <binary> --all --limits-file recovery-limits-v1.json

# Compare, audit, snapshot
macho diff <old-binary> <new-binary> --ignore-codesign --fail-on breaking
macho audit <binary> --min-severity warning --format sarif
macho snapshot <binary> --format json

# Patch and sign — no Xcode, no Keychain
macho patch <binary> --add-rpath @executable_path/../Frameworks --dry-run
macho patch <binary> --add-section __LINKEDIT,__meta,3,metadata.bin --output <patched-binary>
macho patch <binary> --add-zerofill-section __DATA,__scratch,4,0x100 --output <patched-binary>
macho patch <fat-binary> --arch arm64e --detour 0x100003f50,0x100004100,4 --pac-policy require --dry-run --format json
macho patch <binary> --sign-adhoc --output <signed-binary>
macho patch <binary> --sign-p12 <identity.p12> --p12-password-file <password-file> --output <signed-binary>

# Shared cache
macho cache <dyld-cache> --info
macho cache <dyld-cache> --search libobjc
macho cache <dyld-cache> --extract /usr/lib/libobjc.A.dylib --output libobjc.A.dylib
```

Header-inference bundles keep independent recovery separate from operator-guided
projection. A `propose_grouping` target carries the exact declaration template
derived from Mach-O evidence; the response may place that template in an exact
typed owner path. Each path component names its `namespace`, `record`, or
`class` kind, and record boundaries include explicit public/protected/private
access. Correlated source headers use the same representation, so class members
render inside their owner without guessing ABI-absent scope kinds or access.
Targets without a safe template require an explicit declaration fragment, and
unsupported owner shapes remain in the unresolved ledger. Use
`header-infer validate` before `header-infer apply`; applying writes both the
projected header and its authority sidecar.

C++ header projection also exposes a reusable ranked-hypothesis policy:
`--projection-policy strict|suggest|best-effort`. Suggest preserves strict
source while reporting every reached blocker; best-effort may project the
top-ranked interpretation and emits a conspicuous source preamble plus
`slices[].header.assumption_ledger` receipts. Evidence authority remains
separate from the operator decision that authorized a guess. Exact
`--hypothesis-selection GAP_ID=CANDIDATE_ID` overrides win over automatic
ranking and reject stale IDs. Versioned JSON and compact TOML selection
documents are accepted with `--hypothesis-selection-file PATH`; file and inline
selections may be combined, with duplicate subjects rejected. The shared
contract is documented in
[`crates/macho/docs/hypothesis-selection.md`](crates/macho/docs/hypothesis-selection.md).

`macho cache` opens the primary cache, every UUID-validated V1 numeric or V2
suffix-bearing sibling named by its subcache table, and the separately declared
`.symbols` member when `symbolFileUUID` is nonzero. Embedded and separate
local-symbol chunks are bounds-checked with their generation-specific entry
layout. Extraction selects exactly one image, reconstructs a compact
standalone Mach-O from mapped segment bytes, rebuilds its per-image symbol and
string tables, exhaustively classifies load commands before rewriting known
file coordinates, and reparses the result before writing it atomically. Unknown
commands and future cache generations fail as typed unsupported input before an
artifact is delivered. Existing outputs are never replaced unless
`--force` is explicit. The JSON result includes a per-domain completeness
ledger; cache-level local symbols and cache-resident signatures are reported as
unresolved, absent, or rejected rather than presented as standalone evidence.
Layout coverage includes every published `dyld_v0` and `dyld_v1` cache family:
historical big-endian PowerPC caches, legacy and extended mapping tables,
monolithic and V1/V2 split families, both local-symbol entry widths, separate
`.symbols` members, and current TPRO ranges. The exact support and validation
matrix is documented in the [dyld shared-cache layout contract](crates/macho/docs/dyld-cache-layouts.md).
Unknown future cache generations or architectures fail as unsupported. A
layout-valid image whose Mach-O coordinates cannot be reconstructed safely also
fails as unsupported instead of producing a partial artifact; validated
cache-level locals remain explicit unresolved evidence because they are not
silently merged into the standalone image's `LC_SYMTAB`.

`macho diff` compares architecture slices, binary structure, relocations,
symbols and dynamic-link surfaces, code signatures and audit findings, strings,
code ranges, cross-reference relationships, and recovered C, C++, Objective-C,
and Swift declarations. Semantic identities suppress reorder and address-only
churn where the evidence supports it; unavailable, failed, and unrequested
analysis stays explicit instead of being treated as an empty result. JSON emits
the same architecture-attributed findings as structured records for automation.
Either input may also be a JSON file emitted by `macho snapshot`; `--arch`
selects the same family or qualified slice whether the input is a binary or a
saved snapshot.

Most report-producing commands accept `--format text|json`; JSON reports use a versioned envelope. `disassemble --format json` deliberately streams NDJSON with exactly one self-contained instruction object per line, so large binaries do not need to materialize one document. Each object carries its architecture, location, mnemonic, operands, classification, and instruction-local metadata such as section, labels, and resolved direct target. A complete AArch64 word whose encoding boundary is exact but whose formatter has no match is retained as `kind: "other"`; `metadata.encoding` records `status: "unknown"`, exact boundary confidence, unavailable semantics, and its architecture source. Ambiguous or invalid x86 bytes remain recovery gaps and never enter the instruction stream. Stream headers, trailers, gaps, and issues are excluded from stdout; use `jq -s` when a collected instruction array is needed. `audit` also accepts `sarif`. The `header-infer export`, `prompt`, and `apply` actions produce fixed bundle, prompt, header, or sidecar artifacts and intentionally require text mode, while `inspect`, `check-bundle`, and `validate` support text and JSON. Machine formats never contain ANSI escapes, and errors go only to stderr. Semantic roles and the terminal theme come from the pinned Termosaic presentation library; the reusable Mach-O crates stay output-neutral.

`macho patch` plans and reparses the complete candidate before it writes. Section
specifications name an existing segment and carry an explicit base-two alignment
exponent; names longer than Mach-O's 16-byte field are rejected rather than
truncated. `--detour ENTRY_VA,DESTINATION_VA,OVERWRITE_LEN` uses the
architecture-aware executable planner and requires one exact `--arch` for a fat
binary. Its preview reports the encoding, slice-relative file offset, original
bytes, replacement bytes, and decoded instruction count. Before planning the
branch, the CLI strictly decodes the entire overwrite window and refuses an
invalid instruction or a window ending partway through an instruction. On
arm64e, the default `--pac-policy report` attaches a typed compatibility
assessment to each detour. `--pac-policy require` rejects plans that replace an
entry BTI contract, cannot establish a jump-compatible landing pad for an
indirect far destination, lose a recovered return-address signing contract, or
cannot complete the required pointer evidence; `off` skips the assessment.
`--pac-max-pointers` makes the planner's pointer-evidence bound explicit and
strict mode rejects a truncated inventory.
Existing BTI entry instructions are preserved automatically. Far arm64e
detours materialize the destination from instruction immediates instead of
embedding a plain pointer literal. PAC instructions replaced at the entry are
disclosed as evidence because a detour permanently supersedes them. Raw byte writes are deliberately guarded:
`--bytes OFFSET,EXPECTED_HEX,REPLACEMENT_HEX` refuses a changed input instead of
blindly overwriting it. Modifying a signed image reports `invalidated` unless
the same transaction strips or successfully re-signs it. Use `--dry-run` for a
no-write preview, `--output` for an atomic new artifact, or `--in-place
--backup` for an atomic replacement with a recoverable original.

The complete PAC evidence and detour-policy contract is documented in
[`crates/macho/docs/pac.md`](crates/macho/docs/pac.md).

## Command reference

Generated from the production Clap router and checked by `cargo xtask docs --check`.

<!-- BEGIN MACHO COMMAND REFERENCE -->
| Command | Purpose |
| --- | --- |
| `info` | Mach-O structure (header, segments, sections, load commands) |
| `deps` | Linked libraries and compatibility versions |
| `codesign` | Code signature, entitlements, and CMS info |
| `dwarf` | DWARF debug sections (view or extract with --output-dir) |
| `symbols` | Symbol table with filtering |
| `imports` | Imported symbols |
| `exports` | Exported symbols |
| `fixups` | Chained fixup entries |
| `relocations` | Relocation entries |
| `ranges` | Function and symbol address ranges |
| `strings` | String literals with heuristic scanning |
| `xrefs` | Cross-references between addresses |
| `vtables` | C++ virtual tables |
| `objc` | Objective-C classes, protocols, selectors |
| `swift` | Swift type metadata |
| `cpp` | C++ RTTI type hierarchies |
| `c` | C type declarations from debug info |
| `program` | Selective whole-program recovery with typed evidence |
| `pac` | Pointer-authentication inventory and authenticated control-flow sites |
| `disassemble` | Decode selected executable instructions |
| `diff` | Compare two binaries semantically |
| `audit` | Security and configuration audit |
| `container` | Multi-architecture container analysis |
| `snapshot` | JSON structural snapshot |
| `patch` | Safely patch structure, sections, executable entries, and signatures |
| `header-infer` | Reconstruct Mach-O headers from evidence |
| `fileset` | Inspect fileset entries |
| `cache` | Inspect cache families and reconstruct standalone images |
<!-- END MACHO COMMAND REFERENCE -->

## Library usage

Core parsing is always available. Feature-selected evidence, metadata, analysis, mutation, workflow, dyld-cache, and header-inference APIs are exposed by the `macho` façade; narrow consumers can depend on leaf crates directly.

Parse a container and read its first image:

```rust
let bytes = std::fs::read("/usr/bin/true")?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no image")?;
println!("{}", image.header().file_type.name());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Run selective analysis and keep absence, partial evidence, and failure explicit
while consuming ordinary Rust report types:

```rust
use macho::analysis::{AnalysisDomain, AnalysisPlan, Analyzer, DomainState, domain_reports};

let bytes = std::fs::read("/usr/bin/true")?;
let container = macho::parse(&bytes)?;
let document = Analyzer.run(
    &container,
    &AnalysisPlan::new([AnalysisDomain::Header, AnalysisDomain::Symbols]),
)?;
for slice in &document.slices {
    if let DomainState::Complete { value: header, .. } =
        slice.report(domain_reports::HEADER)?
    {
        println!("{}: {}", slice.identity.arch, header.file_type);
    }
    if let DomainState::Complete { value: symbols, issues } =
        slice.report(domain_reports::SYMBOLS)?
    {
        println!("{} symbols, {} issue(s)", symbols.len(), issues.len());
    }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`domain_reports` also provides typed keys for load commands, segments, exports,
imports, fixups, code signing, strings, ranges, xrefs, audit, and canonical C,
C++, Objective-C, and Swift recovery reports. Typed reads do not change the
schema-version-1 snapshot wire representation.

Whole-program recovery is also selective. Each module is independently
queryable; the request adds only declared prerequisites. Higher-level layers can
borrow a narrow capability view without copying records or depending on
unrequested call, transfer, or RTTI analysis:

```rust
use macho::analysis::program::{
    ProgramRecoveryLimits, ProgramRecoveryLimitsFile, ProgramRecoveryRequest,
    ProgramRecoveryStage, RecoveredProgram,
};
use macho::analysis::recovery::{RecoveryAddressRange, RecoveryGuide};

let bytes = std::fs::read("/usr/bin/true")?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no image")?;
let request = ProgramRecoveryRequest::new(
    [ProgramRecoveryStage::Strings, ProgramRecoveryStage::Xrefs],
    ProgramRecoveryLimits::default(),
);
let program = RecoveredProgram::recover(image, request.clone())?;
program.completeness().validate()?;
let limits_file = ProgramRecoveryLimitsFile::current(request.limits());
println!("{}", serde_json::to_string_pretty(&limits_file)?);
let disassembly = program
    .facts()
    .disassembly_inputs()
    .ok_or("disassembly prerequisites were not selected")?;

println!("{} functions", disassembly.functions.functions().len());
println!("strings selected: {}", disassembly.strings.is_some());
println!("RTTI selected: {}", disassembly.rtti.is_some());

// Streaming disassemblers can query one address without materializing vectors.
let annotations = program.annotations_at(0x1000_0000);
for reference in annotations.references() {
    if let Some(owner) = reference.source_owner() {
        println!(
            "reference owner: {:#x} ({:?})",
            owner.owner.function.entry, owner.authority
        );
    }
    if let Some(string) = reference.target_string() {
        println!("string reference: {}", string.value);
    }
}

// Guidance is not limited to questions emitted by the base recovery. A caller
// can author an exact image-bound premise, validate it against the selected
// Mach-O layout, and preview its complete recovery consequences.
let function = program
    .functions()
    .and_then(|functions| functions.functions().first())
    .ok_or("no recovered function")?;
let extent = function.extent.ok_or("function extent is unresolved")?;
let guide = RecoveryGuide::builder(program.image().clone())
    .function_ranges(
        function.entry,
        vec![RecoveryAddressRange::new(extent.start, extent.end_exclusive)?],
    )?
    .build();
let validation = program.validate_guide_for_image(image, &guide);
println!("guide validation: {:?}", validation.applicability);
let preview = RecoveredProgram::preview_guide(image, request, &guide)?;
if let Some(application) = preview.application() {
    println!("{} changed subjects", application.delta.records.len());
    println!("coverage: {:#?}", application.coverage_delta);
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

The concrete `ImageLayoutIndex`, `PointerIndex`, `SymbolInventory`,
`StringIndex`, `ObjcIndex`, `SwiftIndex`, `DwarfIndex`, `FunctionIndex`,
`ControlFlowIndex`, `ExecutableByteIndex`, `XrefIndex`, `RttiIndex`, and
`ExceptionIndex` types remain usable directly by analysis layers that need an
even narrower dependency. `ExecutableByteIndex` conserves every admitted
executable-section byte as an instruction, embedded data, padding, alignment,
stub, literal pool, or an explicitly unresolved span. Proven jump-table bytes
are removed from the retained instruction stream before the final CFG is built.
`RecoveryGuide::builder` accepts image-bound function entries, rejections,
alternate/cold/shared relationships, contiguous or discontiguous function
ranges, every executable-byte role, exact CFG/call suppressions, and exact
xref-source owners without requiring recovery to emit a question first. A
reference-owner decision chooses among recovered source-range owners; it never
claims exclusive ownership of a shared target string. Exact validation rejects
stale coordinates, invalid section ownership, unsupported alignment, missing
range/reference owners, and contradictory roles before the immutable
base/guided preview is built. Its receipt retains
caller authority separately from independent evidence and reports causal object
and multidimensional coverage deltas.
Closed entry-reachable CFGs can establish derived function extents when every
reachable exit and local byte is accounted for; adjacency remains candidate
only. Every graph exposes a non-overlapping byte ledger that classifies its
admitted coverage as instruction, data, explicit decode gap, or budget-omitted
range, plus per-kind conservation totals. Supported imported non-returning calls carry typed return behavior and
are resolved structurally through stub bind slots so stripping names does not
restore false fallthrough. Bounded jump-table dispatch and terminal dispatch
through a function pointer loaded from a statically addressed global slot are
retained as distinct exit kinds; their runtime-selected targets remain
unresolved, and an unexplained indirect branch still prevents CFG closure.
`RttiIndex` exposes both exact symbol-backed records and ABI-structural records,
so stripping `_ZTI` and `_ZTV` names does not discard recoverable type or vtable
identities. `ExceptionIndex` independently decodes object-file compact unwind,
linked `__unwind_info`, `__eh_frame`, and bounded Itanium LSDAs. It evaluates
CFI into CFA/register state rows and retains protected call-site ranges,
cleanup/catch/specification action chains, landing pads, exceptional CFG edges,
and outward-unwind exits with exact source evidence and budgets.
Object compact-unwind and exception-frame records retain true function extents;
linked-unwind page intervals are explicitly typed as lookup ranges and never
fabricate function boundaries.

The same selection model is available from the CLI. Only requested stages and
their declared dependencies are recovered; JSON retains every typed record and
completion receipt:

```bash
macho program MyApp --stage functions --stage strings --stage xrefs
macho program MyApp --stage executable-bytes
macho program MyApp --coverage
macho program MyApp --guide recovery.macho-guide.json --validate-guide
macho program MyApp --guide recovery.macho-guide.json
macho program MyApp --stage indirect-calls \
  --max-indirect-value-flow-work 8000000 \
  --max-indirect-values-per-register 4096 \
  --max-indirect-loop-values-per-register 64
macho --format json program MyApp --stage objc --stage swift --stage rtti
```

On macOS, the checked-in system-corpus receipt runner emits deterministic,
ordered JSON for the explicit default limits and enforces the per-slice wall
ceiling:

```bash
cargo run -p macho --example system_corpus_receipt -- \
  /bin/ls /bin/cp /usr/bin/file /usr/bin/xcrun
```

The bounded recovery surface includes allocator-derived heap aliases,
independently evidenced shared function tails, protocol-qualified Objective-C
receivers, and anchor-free C++ RTTI with absolute/relative vtables, stripped
VTTs, and common adjustment thunks. Unsupported computed-branch transforms and
runtime-populated dispatch slots remain typed frontiers rather than inferred
targets. The corpus gate combines architecture, stripping, language, exception,
switch, authentication, malformed-input, container, shared-cache, and debug-info
fixtures; every serialized nested limit is validated and every stage has a
deterministic primary-budget monotonicity check.

The current `/bin/ls`, `/bin/cp`, `/usr/bin/file`, and `/usr/bin/xcrun` system
corpus is stronger than that general frontier rule: all nine
x86-64/ARM64/ARM64e slices report `Complete` for all 18 stages. Closed
non-escaping mutable-global store sets resolve initialized and zero-fill
dispatch slots, bounded strided record-loop proofs resolve parser and
decompressor callbacks, and exact non-returning import boundaries close the
small launcher slices. The same targets survive nlist stripping, including
unnamed/named import-alias reconciliation.

Plan a mutation, validate placement, and rebuild — the transaction borrows the payload and never relocates existing bytes:

```rust
let bytes = std::fs::read("MyApp")?;
let container = macho::parse(&bytes)?;
let image = container.first_macho().ok_or("container has no image")?;
let section = macho::mutate::AddSection::new("__LINKEDIT", "__meta", b"payload")?
    .with_alignment(3)?;
let mut transaction = macho::mutate::PatchTransaction::new(image);
transaction.add_section(section);
let rebuilt = transaction.commit()?;
std::fs::write("MyApp.patched", rebuilt)?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

File-backed additions use a bounded gap in the named segment or extend that
segment only when no later file-backed payload would move and no modeled load
command or relocation table owns the candidate bytes—even if those bytes are
zero. If the named segment does not exist, the editor can instead append a
page-aligned segment and its first section after the existing file and VM
ranges; callers may set the new segment's initial and maximum protections
explicitly. Existing payload, symbols, fixups, and address-bearing records
never move. Load commands still grow only through existing zero-filled header
slack, so a packed header rejects the operation rather than attempting an
implicit relink. `AddSection::new`
accepts any borrowed `AsRef<[u8]>` — a slice, a `Vec<u8>`, or a caller-owned
read-only `memmap2::Mmap` — stores the payload as a slice, copies only the two
fixed-width Mach-O names inline, and allocates no heap of its own. For a file,
keep the mapping alive until the transaction commits; a bare `File` can't
expose borrowed bytes.

Injected `SignatureProvider` implementations may declare a known ad-hoc or certificate kind; providers that omit `kind()` are opaque, own their own verification, and never expose credentials. The generic verifier accepts only the ad-hoc and certificate mechanisms it understands. Selective analysis builds an `AnalysisPlan` before execution, and snapshot documents (schema version 1) preserve `not_requested`, `complete`, `unsupported`, and `failed` as distinct states — a gap in the data is never silently rendered as a zero.

External transformation engines use `macho::analysis::program::RecoveredProgram`
as the full-facts entry and persist `ProgramFactDocument` when they need durable,
query-only state. `macho::evidence::SelectedImageEvidence` is the narrower leaf
port for consumers that intentionally do not need a program. Product IR,
operator edit storage, branches, queries, and mutations remain consumer-owned;
Macho owns selected-image decoding, recovery questions, guides, completeness,
and independent-versus-guided provenance. Refinement and deepening can return a
versioned operational reuse receipt with exact whole-stage and function-local
CFG reuse counts; that receipt remains outside durable Fact IR. See
[`crates/macho/docs/program-fact-ir.md`](crates/macho/docs/program-fact-ir.md)
for the Fact IR contract and
[`crates/macho/docs/splice-handoff.md`](crates/macho/docs/splice-handoff.md) for
the Splice integration handoff.
The CLI writes the raw wire document with
`macho program TARGET --all --fact-ir-output facts.json` and validates or
inspects it offline with `macho program --load-fact-ir facts.json`.

## Architecture

The workspace keeps product code in one feature-gated package. Module ownership separates the byte-safe core, instruction support, metadata, analysis, mutation, workflow, and CLI without turning those implementation details into release units:

- `cargo xtask architecture` enforces dependency direction and source ownership.
- `cargo xtask docs --check` binds this command reference and the diagnostic registry to the code.
- `cargo xtask release --check` builds and verifies the publishable crate and binds its CLI, changelog, and lockfiles (`--require-tag` additionally demands a clean tracked tree and an exact matching `vX.Y.Z` tag).
- `cargo xtask verify` checks every declared feature composition before the locked all-feature format, lint, docs, test, and benchmark gate.
- `cargo xtask verify-fuzz` builds every fuzz target (nightly Rust).
- `mise run verify` composes both gates, scoping nightly to fuzzing only.

The [1.x stability policy](crates/macho/docs/stability.md) defines which Rust
APIs, feature names, machine documents, diagnostics, platforms, and MSRV claims
are compatibility contracts.

The workspace contains three packages: `macho` for all shipped library and CLI
functionality, private `xtask` for repository automation, and private
`macho-test-support` for shared deterministic fixtures. The mkasm-generated
ARM64/x86-64 codecs are private `macho::insn` implementation modules, vendored
for offline Rust builds and refreshed through `scripts/generate-mkasm-codecs.sh`.

## Contributing

Run `mise run verify` before opening a PR. CI repeats the stable and fuzz gates
on supported hosts, checks Rust 1.91.1 exactly, and runs the real macOS signing
oracle. See [CHANGELOG.md](CHANGELOG.md) for release history and
[docs/diagnostic-codes.md](docs/diagnostic-codes.md) for the stable
machine-readable diagnostic codes.

## License

Licensed under the [MIT License](LICENSE).
