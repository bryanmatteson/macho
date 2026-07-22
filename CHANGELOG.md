# Changelog

## 0.3.0

- Added a bounded format probe for callers that need to identify Mach-O input
  without accepting malformed containers.
- Isolated structural mutation from executable patch planning, instruction,
  dyld, analysis, workflow, and CLI dependencies. Hook and trampoline planning
  now lives in the separate `macho-patch` leaf.
- Added a minimal external-signing feature whose dependency closure contains
  only the structural core, code-signature parsing, and digest support.
- Isolated Objective-C fixup decoding behind the `fixups` feature while
  retaining strict chained and legacy pointer resolution for Splice.
- Moved process-free Rust, C++, and Swift demangling into the independent
  `macho-demangle` leaf and removed lateral language-crate re-exports.
- Kept `macho-cpp` ABI/body inference available behind explicit features while
  removing its direct symbol-layer dependency.

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
  providers retain responsibility for verifying their own output.
- Added explicit instruction decode errors and lossy gap reporting.
- Added `macho disassemble`: streaming, line-oriented instruction disassembly
  with constant output memory — pretty text by default, or newline-delimited
  JSON (one record per line) with `--format json`. Exact architecture, section,
  symbol, and address selection; recovering or strict decoding (strict aborts on
  the first invalid byte after streaming the valid prefix); typed gaps, labels,
  targets, identities, and schema-version-1 records. The materialized
  `disassemble()` library API is retained on the same decode core.
- Help and usage text is now rendered through Macho's Termosaic theme instead of
  Clap's independent palette, and obeys `--color`: previously Clap decided
  colouring from its own terminal heuristic, ignoring the flag. Section headers,
  literals, and placeholders resolve the same tokens as report output. Usage
  errors stay plain because the diagnostic path sanitizes what it writes, which
  would otherwise turn Clap's escapes into replacement characters; the `Error:`
  label continues to carry the theme.
- Added Termosaic syntax highlighting to `disassemble` text output through an
  explicit three-stage pipeline: a lexer splits decoded instruction text into
  lexical runs, each run is assigned a Termosaic `TokenId`, and the resulting
  `Span` stream is resolved against the theme at render time. Mnemonics,
  registers, immediates, operand punctuation, size/shift qualifiers, the raw
  byte column, addresses, branch-target comments, and decode-gap codes each
  carry their own token, and whole record and region-header lines are assembled
  as span streams. Because classification is independent of colour, tokenization
  is tested against token identities rather than escape sequences. Colour is
  presentation only — stripping ANSI from `--color always` reproduces `--color
  never` byte for byte, machine output is unaffected, and byte-column padding is
  measured unstyled so records stay aligned in both modes. Target annotations are
  now separated from the instruction by two spaces.
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
  are now collapsed to a single entity (each slot still retained individually as
  an observation), while genuinely distinct same-named entities at different
  addresses stay separate. This unblocks `objc` on large real-world images.
- Added fail-closed streaming export-trie traversal and centralized rejection
  of explicit color for machine-readable output.
- Adopted pinned Termosaic semantic tokens, theme resolution, and human-text
  sanitization in the CLI presentation layer without changing JSON or SARIF.
- Added selective analysis plans and schema-v2 four-state snapshots.
- Added injected CLI I/O, canonical output formats, and distinct policy exits.
- Added architecture, documentation, release, CI, fuzz, and benchmark authorities.
