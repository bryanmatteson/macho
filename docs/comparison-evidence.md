# Comparison evidence

Measured and structural evidence for positioning `macho` against common Apple
binary tools. Intended for README excerpts, design docs, talks, and buyer /
adopter evaluation.

**Capture metadata**

| Field | Value |
| --- | --- |
| Tool version | `macho 1.0.0` (release binary, this tree) |
| Host | macOS 26.5.2, arm64 |
| Apple sample | `/System/Applications/Calculator.app/Contents/MacOS/Calculator` (universal `x86_64` + `arm64e`) |
| Tiny sample | `/usr/bin/true` (universal, ~84 KiB) |
| Capture date | 2026-08-06 |

Commands below used `./target/release/macho` built from this workspace. Wall
times are single-run `perf_counter` samples on a quiet laptop; they are
**order-of-magnitude UX evidence**, not published benchmarks.

---

## 1. One-sentence positioning

`macho` is a **cross-platform, library-first Mach-O toolkit** that unifies
structure inspection, language recovery (ObjC / Swift / C / C++), disassembly,
PAC analysis, semantic diff/audit, safe mutation, and in-process re-signing —
with **evidence-accountable** reports that prefer incompleteness over guessing.

It is **not** an interactive decompiler IDE (Hopper / IDA / Ghidra / Binary
Ninja). It **is** a serious replacement for the ad-hoc macOS CLI mash-up of
`otool`, `nm`, `codesign`, `install_name_tool`, class-dump-style header dumpers,
and many one-off dyld-cache scripts — and a Rust API you can embed in CI or
products.

---

## 2. Capability matrix

Legend: **Y** = first-class in-product support · **P** = partial / related ·
**—** = not the job of that tool · **M** = typically macOS-only host tooling.

| Capability | `macho` | `otool`/`nm`/`dyld_info` | `codesign` / `install_name_tool` | class-dump / dsdump / iCDump | `ipsw` | Hopper/IDA/BN |
| --- | --- | --- | --- | --- | --- | --- |
| Runs without macOS / Xcode | **Y** (Rust; CI on Linux + macOS) | **M** | **M** | varies | **Y** (Go) | desktop hosts |
| Fat / thin structure (`info`) | **Y** | **Y** | — | — | **Y** (Mach-O helpers) | **Y** |
| Symbols / imports / exports | **Y** | **Y** | — | — | **Y** | **Y** |
| Chained fixups / relocations | **Y** | **P** | — | — | **P** | **Y** |
| ObjC class dump / headers | **Y** + evidence ledger | raw `otool -ov` | — | **Y** (headers) | **Y** (esp. cache) | **Y** |
| Swift type / header recovery | **Y** + unavailability comments | — | — | rare / experimental | **P** experimental | plugins / manual |
| C / C++ RTTI + vtables | **Y** | — | — | — | — | **Y** |
| DWARF traversal | **Y** | limited | — | — | — | **Y** |
| Disassembly (arm64 / x86_64) | **Y** (streaming text + NDJSON) | `otool -tV` | — | — | **P** | **Y** + decompiler |
| Cross-refs / ranges / strings | **Y** | **P** | — | — | **P** | **Y** |
| arm64e PAC inventory + gadgets | **Y** (`pac`) | — | — | — | — | plugin / manual |
| PAC-aware detour planning | **Y** (`patch --pac-policy`) | — | — | — | — | manual |
| Semantic multi-domain **diff** | **Y** | — | — | — | — | limited |
| Audit findings + **SARIF 2.1** | **Y** | — | **P** | — | — | varies |
| Snapshot JSON (versioned domains) | **Y** (schema v3) | — | — | — | — | project formats |
| Safe structural **mutation** | **Y** (fail-closed slack) | — | rpath/id only | — | — | patches / scripts |
| In-process ad-hoc / P12 **sign** | **Y** | — | **Y** (Keychain/macOS) | — | — | external |
| dyld shared cache extract | **Y** (`cache`) | limited | — | — | **Y** (flagship) | loaders |
| IPSW / firmware download | — | — | — | — | **Y** | — |
| Interactive UI / decompiler | — | — | — | — | — | **Y** |
| Embeddable library API | **Y** (feature-gated crate) | — | — | — | Go packages | SDKs / plugins |
| CI-friendly machine output | **Y** (`text` / `json` / `sarif`) | text-oriented | text | text | text/json varies | export |

### Tool-by-tool takeaway

| Tool | Best at | Where `macho` wins | Where they win |
| --- | --- | --- | --- |
| **Apple CLI** (`otool`, `nm`, `codesign`, …) | Ubiquitous on Mac developer machines | One grammar, JSON/SARIF, recovery, mutation, Linux CI, PAC | Zero install on macOS; Apple’s oracle for some signing edges |
| **class-dump family** | Classic ObjC headers | Evidence hashes, presence states, Swift/C/C++, no guess fill-in | Sometimes simpler “just dump headers” UX |
| **ipsw** | IPSW download, kernel/cache research Swiss army knife | Library-first Mach-O product surface, mutation+sign, PAC policy, semantic diff/audit | Firmware acquisition and broader iOS research workflow |
| **Hopper / IDA / BN / Ghidra** | Interactive RE, decompilation, graphs | Headless automation, CI contracts, fail-closed patch, evidence ledger | Human-in-the-loop exploration and decompilers |

---

## 3. Measured demos (this host)

### 3.1 Wall time (release binary)

| Command | Target | Time | Exit |
| --- | --- | --- | --- |
| `macho info` | `/usr/bin/true` | 12.1 ms | 0 |
| `otool -hl` | same | 10.6 ms | 0 |
| `macho symbols` | same | 11.0 ms | 0 |
| `nm` | same | 8.7 ms | 0 |
| `macho disassemble --section __TEXT,__text --count 8` | same | 13.1 ms | 0 |
| `otool -tV` | same | 16.3 ms | 0 |
| `macho audit --format sarif` | same | 10.7 ms | 0 |
| `macho snapshot --format json` | same | 12.1 ms | 0 |
| `macho info --arch arm64e` | Calculator | 12.0 ms | 0 |
| `macho objc --headers --arch arm64e` | Calculator | 12.5 ms | 0 |
| `macho swift --headers --arch arm64e` | Calculator | 13.6 ms | 0 |
| `macho pac --arch arm64e` (text summary) | Calculator | **~50–70 ms** | 0 |
| `macho pac --arch arm64e --format json` | Calculator | **~150–180 ms** | 0 |
| `macho patch --add-rpath … --dry-run` | Calculator copy | 12.6 ms | 0 |

**Read:** light structure / recovery commands are in the same ballpark as Apple
CLIs on small inputs. PAC on Calculator arm64e is a full pointer inventory plus
an instruction scan over ~1.1 MiB of decoded code; default text is summary-only
(~16 KiB), while JSON materializes the full report (~11.9 MiB on this sample).

**PAC latency (Calculator arm64e, release):** an earlier single-run capture in
this doc was ~775 ms for text. After the recovery-path speedup on the same
host/binary:

| Mode | Before | After (this host, n=7) |
| --- | ---: | ---: |
| Summary (`--format text`) | 710–760 ms | **p50 67 ms** (min 64, max 71) |
| Full JSON (`--format json`) | 800–870 ms | **p50 158 ms** (min 147, max 174) |

Roughly **~11×** faster for the default summary path and **~5×** for full JSON.
JSON remains dominated by serializing the complete pointer/code-site inventory
(not by a second analysis pass). Completeness on this sample is unchanged:
`pointer_status: complete`, 6084/6084 pointers retained, `code_truncated: false`,
`decode_gaps: 0`.

### 3.2 Objective-C recovery — Calculator `arm64e`

```text
$ macho objc Calculator --headers --arch arm64e
@class NSButtonCell, NSObject, NSString, _TtCs12_SwiftObject;
@protocol NSApplicationDelegate, …;
@interface _TtC10Calculator19CalculatorViewModel : _TtCs12_SwiftObject
@end
@protocol NSApplicationDelegate<NSObject>
- (unsigned long long)applicationShouldTerminate:(id)arg1;
- (void)application:(id)arg1 openURLs:(id)arg2;
…
```

| Metric | Value |
| --- | --- |
| JSON entities | 43 (`class` 36, `protocol` 7) |
| Presence | `defined` 40, `referenced` 3 |
| Header lines | 185 (`@interface` 33, `@protocol` 8) |

**Evidence accountability (JSON field, not invented types):**

```json
"name": {
  "kind": "known",
  "value": "_TtC10Calculator22AnalyticsTimeStampInfo",
  "evidence": ["93dba224…"]
},
"offset": { "kind": "unavailable", "reason": "unresolved_reference" },
"parsed_type": { "kind": "unavailable", "reason": "not_encoded" }
```

That is the product thesis in one field: **known stays known; missing stays
missing** (with a reason), instead of a plausible-looking wrong type.

### 3.3 Swift recovery — same binary

```text
$ macho swift Calculator --headers --arch arm64e
// Recovered Swift declarations.
// Unavailable metadata is preserved as comments; this is not original source.

struct AccessibilityMathEquationViewModifier: SwiftUI.ViewModifier {
    var expression: Calculate.CalculateExpression
    var accessibilityLabel: Swift.String
}

protocol AnalyticsEvent {
    // Conformances unavailable: not encoded.
    // Requirements are not encoded by nominal field metadata.
}

class AnalyticsManager {
    // Conformances unavailable: not encoded.
    var timeStampInfo: Calculator.AnalyticsTimeStampInfo
    var lastConfigSnapshot: Calculator.CalculatorConfigSnapshot
    var isReadyToTrack: Swift.Bool
}
```

| Metric | Value |
| --- | --- |
| Header lines | 1169 |
| `class` / `struct` / `protocol` lines | 33 / 70 / 5 |
| Lines noting unavailability / not encoded | 33 |

### 3.4 arm64e PAC inventory — Calculator

```text
$ macho pac Calculator --arch arm64e
PAC analysis: arm64e
Pointers:
  authenticated          3694
  plain                  2390
  address-diverse        3693
Authentication keys:
  IA                     2521
  DA                     1173
```

From the versioned JSON report:

| Field | Value |
| --- | --- |
| `completeness.pointer_status` | `complete` |
| `available_pointers` / `retained_pointers` | 6084 / 6084 |
| `decoded_code_bytes` | 1 094 976 |
| `code_truncated` / `decode_gaps` | `false` / `0` |
| Authenticated calls / branches / returns | 3574 / 1391 / 2348 |
| Authenticate / sign / strip sites | 3293 / 7203 / 943 |

**Docs contract:** `crates/macho/docs/pac.md` (pointer domain vs code domain;
detour policy `report` | `require` | `off`).

### 3.5 Fail-closed mutation

**Refuses unsafe rpath on a packed tiny binary** (`/usr/bin/true`):

```json
{
  "ok": false,
  "diagnostics": [{
    "code": "cli.execution.failed",
    "message": "… insufficient load-command slack: commands end at 0x388, but existing payload begins at 0x368; relocating existing payload is unsupported"
  }]
}
```

**Plans a safe dry-run on Calculator** (has slack):

| Field | Value |
| --- | --- |
| `ok` | `true` |
| `dry_run` / `written` | `true` / `false` |
| Operation | `add rpath: @executable_path/../Frameworks` |
| `signature_outcome` | `invalidated` (explicit; re-sign in same transaction or afterward) |
| `validation_errors` | `[]` |

This is marketing-relevant: mutation either proves placement or **refuses**, and
signing invalidation is a first-class outcome, not a silent side effect.

### 3.6 Audit → GitHub code scanning (SARIF)

```text
$ macho audit /usr/bin/true --format sarif
```

| Field | Value |
| --- | --- |
| SARIF | `2.1.0` |
| `$schema` | OASIS SARIF 2.1 schema URL |
| Tool | `macho audit` `1.0.0` |
| Rules observed | `CS002`, `CS004` |
| Results | 4 |

### 3.7 Streaming disassembly (instruction-only NDJSON)

```text
$ macho disassemble /usr/bin/true --arch arm64e --section __TEXT,__text --count 4 --format json
```

**Text** (default) remains human layout:

```text
__TEXT,__text  0x0000000100000368..0x0000000100000370
  0x0000000100000368  00008052  MOV w0, #0x0
  0x000000010000036c  c0035fd6  RET
```

**JSON** emits **exactly one self-contained instruction per NDJSON line** — no
stream headers, trailers, gaps, or issues on stdout (those stay off the
instruction pipe). On `/usr/bin/true` arm64e `__TEXT,__text` this is **2 lines**
for 2 instructions (`--count 4` still only covers the 8-byte body):

```json
{"schema_version":1,"architecture":{"name":"arm64e","cpu_type":16777228,"cpu_subtype":-2147483646},"slice_index":1,"va":4294968168,"thin_file_offset":872,"container_file_offset":50024,"size":4,"bytes":"00008052","mnemonic":"mov","operands":["w0","#0x0"],"kind":"other","metadata":{"segment":"__TEXT","section":"__text"}}
{"schema_version":1,"architecture":{"name":"arm64e","cpu_type":16777228,"cpu_subtype":-2147483646},"slice_index":1,"va":4294968172,"thin_file_offset":876,"container_file_offset":50028,"size":4,"bytes":"c0035fd6","mnemonic":"ret","operands":[],"kind":"return","metadata":{"segment":"__TEXT","section":"__text"}}
```

| Field | Role |
| --- | --- |
| `schema_version` | Wire version (`1`) |
| `architecture` | Name + raw cpu type/subtype |
| `slice_index` | Fat-slice index |
| `va` / `thin_file_offset` / `container_file_offset` | Location |
| `size` / `bytes` | Instruction width and raw hex |
| `mnemonic` / `operands` | Decoded text (split) |
| `kind` | Classification (`other`, `return`, `pc_relative`, …) |
| `metadata` | Instruction-local context (section; labels/targets and exact fixed-width opaque encoding when present) |

Pipeline note: `jq -s` collects instructions into one array; each line is already
a complete record — consumers never wait on a framing trailer.

Recovering mode does not silently turn decoder misses into authoritative
semantics. If an AArch64 fixed-width boundary is exact, the instruction is
retained as `kind: "other"`. Its `metadata.encoding` object reports an
`unknown` status, `exact` boundary confidence, `unavailable` semantics, and the
architecture source. Ambiguous, reserved, or locally unknown x86 bytes remain
internal gaps and do not enter the instruction stream; coverage deficits are
fixed in the local codec rather than hidden behind a production fallback.

### 3.8 Snapshot domain coverage

`macho snapshot /usr/bin/true --format json` → outer CLI envelope schema **1**,
inner snapshot schema **3**, domains present on slices:

`audit`, `c_surface`, `codesign`, `container`, `cpp_surface`, `dependencies`,
`dwarf`, `exports`, `fixups`, `header`, `imports`, `load_commands`, `objc`,
`objc_headers`, `ranges`, `relocations`, `segments`, `strings`, `swift`,
`symbols`, `vtables`, `xrefs` — **22 domains**.

---

## 4. Engineering evidence (repo facts)

| Signal | Evidence |
| --- | --- |
| Version | Workspace `1.0.0`, CLI `macho 1.0.0` |
| Public CLI commands | **27** (structure → language → analysis → mutation → cache) |
| Feature gates | `insn`, `codesign`, `objc`, `swift`, `cpp`, `metadata`, `analysis`, `patch`, `signing`, `mutation`, `workflow`, `dyld-cache`, `header-infer`, `cli`, … |
| Integration tests | **59** `crates/macho/tests/*.rs` |
| Leaf contracts | codesign, cpp, dwarf, dyld, insn, objc, swift |
| Fuzz targets | **7**: `container`, `load_commands`, `dyld`, `codesign`, `insn`, `mutation`, `cache_fileset` |
| CI OS matrix | `ubuntu-latest`, `macos-latest` (`verify` + `fuzz`) |
| macOS signing oracle | Ignored test run on macOS runners vs real `codesign` |
| Large-binary 1.0.0 perf (CHANGELOG) | disasm wall **−40.9%**, CFG peak mem **−21.1%**, xref wall **−16.0%** (bounded workloads; deterministic output preserved) |
| Release binary size (this build) | ~**56 MiB** arm64 Mach-O (full CLI features) |
| Docs contracts | `crates/macho/docs/{pac,patch,insn,metadata/**}.md` |
| Missing-docs policy | `#![deny(missing_docs)]` on the library root |

### Feature map (library consumers)

```text
core ──► insn
      └► metadata (dyld, objc, swift, cpp, dwarf, codesign, symbols)
            └► analysis (disasm, program, diff, audit, snapshot, header-infer)
            └► dyld-cache
      └► mutate (structural + patch + signing)
            └► workflow
                  └► cli
```

Default feature set is `analysis`; `cli` pulls `full` (analysis + mutation +
workflow + cache + header-infer).

---

## 5. “Instead of…” cheat sheet (README-ready)

| Instead of… | Use |
| --- | --- |
| `otool -l`, `otool -h` | `macho info` |
| `nm`, `dyld_info -exports` | `macho symbols`, `exports`, `imports` |
| `class-dump` / ObjC dumpers | `macho objc --headers` |
| Swift metadata spelunking | `macho swift --headers` |
| `otool -tV` | `macho disassemble` |
| Manual arm64e PAC notes | `macho pac` |
| `codesign -d` / ad-hoc re-sign scripts | `macho codesign`, `macho patch --sign-*` |
| `install_name_tool` + hope | `macho patch` (dry-run, refuse unsafe) |
| Hand-rolled binary diff in CI | `macho diff --fail-on breaking` |
| One-off cache extractors | `macho cache` (scoped families; completeness ledger) |
| Spreadsheet of audit findings | `macho audit --format sarif` |

---

## 6. Honest limits (use in docs so claims stay credible)

1. **Not an interactive RE suite.** No decompiler UI, graph canvas, or debugger.
2. **Windows runtime** is a product goal (pure Rust + in-process signing) but
   **CI currently gates Linux + macOS**. Prefer “Linux and macOS verified in CI;
   Windows supported as a Rust target” until a Windows job is green.
3. **dyld cache** support is deliberately scoped (documented family support;
   unsupported layouts fail closed rather than emit half-extracted dylibs).
4. **Header recovery is not source recovery.** Swift/ObjC projections annotate
   what the binary does not encode; treat output as evidence-backed
   reconstruction, not original headers.
5. **Mutation never relocates existing payload.** Binaries without load-command
   slack cannot grow commands; the tool refuses instead of rewriting the file
   layout.
6. **Release CLI is large (~56 MiB here)** because it links the full feature
   set; library consumers should enable only needed features.

---

## 7. Suggested README / site blurbs

### Short (hero)

> One Rust toolkit for reading, reconstructing, auditing, and rewriting Mach-O
> binaries — structure, ObjC/Swift/C/C++ evidence, PAC, patch, and re-sign —
> without Xcode, without juggling `otool`, and without requiring a Mac in CI.

### Medium (after tour)

> On Apple Calculator’s arm64e slice, `macho` recovered **43** ObjC entities and
> **1 100+** lines of Swift declarations while marking unencoded fields as
> unavailable; inventoried **6 084** dyld-managed pointers (**3 694**
> authenticated) with `pointer_status: complete`; and either **planned** an
> rpath patch with explicit signature invalidation or **refused** an unsafe
> edit on a packed binary. The same CLI emits versioned JSON and SARIF for
> pipelines.

### Adopter evaluation questions (answer “yes” with links to this doc)

- Can we run analysis on Linux CI without a Mac runner?
- Do incomplete recoveries show up as data, not silent omission?
- Can we fail a PR on semantic binary drift (`diff --fail-on`)?
- Can we dry-run patches and see signature outcomes before write?
- Can security findings land in code scanning (SARIF)?
- Can we depend on a crate feature set smaller than the full CLI?

---

## 8. Reproducing the demos

```bash
cargo build -p macho --release --features cli
BIN=./target/release/macho
CALC=/System/Applications/Calculator.app/Contents/MacOS/Calculator

$BIN --version
$BIN info /usr/bin/true
$BIN objc "$CALC" --headers --arch arm64e
$BIN swift "$CALC" --headers --arch arm64e
$BIN pac "$CALC" --arch arm64e --format json | jq '.data | .. | .completeness? // empty'
$BIN audit /usr/bin/true --format sarif | jq '.version, .runs[0].tool.driver.name'
$BIN patch /usr/bin/true --add-rpath '@executable_path/../Frameworks' --dry-run --format json
cp "$CALC" /tmp/calc && $BIN patch /tmp/calc --arch arm64e \
  --add-rpath '@executable_path/../Frameworks' --dry-run --format json
```

On Linux CI images, use any checked-in or corpus Mach-O fixtures instead of
Calculator; structure, fuzz, and most analysis paths do not require Apple host
frameworks.

---

## 9. Related in-tree docs

| Doc | Contract |
| --- | --- |
| [`crates/macho/docs/pac.md`](../crates/macho/docs/pac.md) | PAC domains + detour policy |
| [`crates/macho/docs/patch.md`](../crates/macho/docs/patch.md) | Executable patch planning |
| [`crates/macho/docs/metadata.md`](../crates/macho/docs/metadata.md) | Metadata modules |
| [`docs/diagnostic-codes.md`](diagnostic-codes.md) | Stable diagnostic codes |
| Root [`README.md`](../README.md) | Tour + command reference |
| [`CHANGELOG.md`](../CHANGELOG.md) | 1.0.0 perf and feature notes |
