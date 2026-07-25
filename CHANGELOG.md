# Changelog

## 0.4.0

- Licensed the complete workspace and published crate family under the MIT
  License.
- Added opt-in strict RTTI leaves for Swift and Objective-C. Swift retains
  emitted static metadata objects separately from accessors and decodes local
  value-witness layouts without target execution. Objective-C provides an
  all-or-error conserved scan over runtime lists and strict method records.
- Exposed the strict C++ Itanium RTTI, vtable, fixup, and ABI surfaces through
  their closed feature set for deterministic runtime-type graph construction.
- Added `macho-evidence`, a policy-free selected-image composition seam for
  strict Objective-C, Swift, C++, and shared pointer provenance.

## 0.3.0

- Added a bounded format probe that identifies Mach-O input without accepting
  malformed containers.
- Isolated structural mutation from executable patch planning, instruction,
  dyld, analysis, workflow, and CLI dependencies. Hook and trampoline planning
  live in the separate `macho-patch` leaf.
- Added a minimal external-signing feature whose dependency closure contains
  only the structural core, code-signature parsing, and digest support.
- Isolated Objective-C fixup decoding behind the `fixups` feature while
  retaining strict chained and legacy pointer resolution for Splice.
- Moved process-free Rust, C++, and Swift demangling into the independent
  `macho-demangle` leaf and removed lateral language-crate re-exports.
- Kept `macho-cpp` ABI/body inference behind explicit features and removed its
  direct symbol-layer dependency.

## 0.2.0

- Split structural parsing, metadata, analysis, mutation, workflow, façade, and
  CLI ownership into an enforced acyclic workspace.
- Added strict and forensic parsing with limits and structured diagnostics.
- Added borrowed `AsRef<[u8]>` source entry points to `macho-objc`,
  `macho-swift`, and `macho-cpp`, supporting raw slices, vectors, and
  caller-owned read-only mappings without copying input bytes.
- Added the stable `macho-mutate::AddSection` transaction API for file-backed
  and zero-fill sections. Placement is alignment-aware, extends file data only
  at a final segment's exact EOF, preserves all existing payload offsets, and
  fails closed on insufficient command slack or file/VM overlap. File-backed
  requests borrow raw slices, vectors, or caller-owned read-only mappings
  without copying or internally allocating.
- Made injected external signing providers opaque by default while preserving
  explicit ad-hoc and certificate outcomes for the in-process provider. Opaque
  providers verify their own output.
- Added explicit instruction decode errors and lossy gap reporting.
- Added `macho disassemble`: streaming, line-oriented instruction disassembly
  with constant output memory — pretty text by default, or newline-delimited
  JSON with `--format json`. Exact architecture, section, symbol, and address
  selection; recovering or strict decoding (strict aborts on the first invalid
  byte after streaming the valid prefix); typed gaps, labels, targets,
  identities, and schema-version-1 records. The materialized `disassemble()`
  library API shares the same decode core.
- Help and usage text render through Macho's Termosaic theme and obey `--color`.
  Section headers, literals, and placeholders resolve the same tokens as report
  output. Usage errors stay plain because the diagnostic path sanitizes writes;
  the `Error:` label still carries the theme.
- Added Termosaic syntax highlighting to `disassemble` text output: a lexer
  splits decoded instruction text into lexical runs, each run receives a
  Termosaic `TokenId`, and the `Span` stream resolves against the theme at
  render time. Classification is independent of colour; tokenization is tested
  against token identities. Stripping ANSI from `--color always` reproduces
  `--color never` byte for byte. Machine output is unaffected. Byte-column
  padding is measured unstyled so records stay aligned. Target annotations are
  separated from the instruction by two spaces.
- Added `disassemble --end-address` (exclusive range end for `--address`)
  selection and the text-display flags `--no-addresses`, `--no-bytes`,
  `--no-labels`, and `--no-targets` for diff-friendly output.
- Added composable Objective-C `--kind`, `--name`, `--presence`, and `--selector`
  filters across the surface, graph, and xref views; added repeatable Swift
  `--kind`/`--state` filters plus substring or exact `--name` matching.
- Added analysis filters: `strings --min-length/--exact/--offsets`,
  `xrefs --kind/--import/--demangle` (address and kind filters now intersect
  instead of `--from` silently overriding `--to`), and
  `ranges --name/--source`. `vtables` gained `--demangle`, and its class
  filter is now spelled `--class` (`--class-filter` remains a hidden alias).
- Fixed `objc` aborting with `duplicate Objective-C entity ID` on binaries whose
  `__objc_protolist`/`__objc_catlist`/`__objc_classlist` reference one runtime
  object through several pointer slots. Such slots share one entity identity and
  collapse to a single entity; each slot is retained individually as an
  observation. Distinct same-named entities at different addresses stay separate.
- Added fail-closed streaming export-trie traversal and centralized rejection
  of explicit color for machine-readable output.
- Adopted pinned Termosaic semantic tokens, theme resolution, and human-text
  sanitization in the CLI presentation layer without changing JSON or SARIF.
- Added selective analysis plans and schema-v2 four-state snapshots.
- Added injected CLI I/O, canonical output formats, and distinct policy exits.
- Added architecture, documentation, release, CI, fuzz, and benchmark authorities.
