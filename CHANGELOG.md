# Changelog

## Unreleased

- Fixed `macho objc --headers` failing semantic validation on any image with a
  protocol-qualified object type. The header parser stripped a pointer suffix
  before its Objective-C check, so `NSObject<Proto> *` re-parsed as a C++
  template instantiation and its protocol resolved against record tags instead
  of declared protocols.
- Nested Objective-C members under the entity that declares them, and rendered
  their recovered types, property attributes, and method signatures instead of
  the state label `known`. Values the recovery could not establish stay visually
  distinct from values it did.
- Added `macho swift --headers`, which attaches a Swift declaration projection
  to each report slice. Unlike the former text-only path, the projection carries
  structured declarations and an unresolved ledger through `--format json`.
  `--declarations` remains as an alias.
- Declared each Swift nominal type once. A type exposed to Objective-C is
  observed twice, and the projection previously emitted one declaration per
  observation. Displaced observations that hold conflicting evidence are
  recorded in the unresolved ledger.
- Stopped reporting an absent Objective-C ivar type encoding as malformed. A
  null encoding pointer is now `not-encoded` and an unresolvable one is
  `unresolved-reference`, which separates Swift stored properties from genuine
  metadata damage.
- Reported header omissions as separate declaration and member counts rather
  than describing every ledger entry as a dropped declaration.
- Kept diagnostics that belong to no entity visible under a filter. A record
  that never decoded into an entity describes the image, so narrowing a
  selection no longer hides malformed metadata.
- Recovered Swift generic parameters nested inside type arguments and behind
  dependent member types, so a type whose only mention of a placeholder is
  `Swift.Optional<A>` or `Swift.Range<A.Swift.Collection.Index>` declares `<A>`.
  A placeholder is recognized by position — a lone uppercase letter that is a
  whole segment or the root of a dotted path — so `Module.A` stays a real type.
  In `libswiftCreateML.dylib`, 10 of 363 rendered declarations previously
  referenced a parameter they never declared.
- Reported header omissions as separate declaration and member counts on the
  Swift projection too, matching the Objective-C footer.
- Accepted qualified slice names in `--arch` for `swift`, `objc`, and the
  symbol-recovery commands. `arm64e` is the name a fat listing and the
  disassembler print for that slice, but the report commands compared it against
  the CPU-type name alone, so `--arch arm64e` selected nothing and failed with
  `no selected Mach-O slices`. An unmatched selector now names itself.
- Escaped Swift reserved words in rendered declarations. `/usr/bin/plutil`
  declares an enum whose cases are named `true` and `false`, which rendered as
  invalid Swift; keywords in declaration position are now backtick-escaped.
- Stated an empty header projection instead of emitting nothing. `macho objc
  --headers` on an image with no Objective-C metadata wrote zero bytes, which was
  indistinguishable from the command failing.
- Recovered a Swift class's superclass from its context descriptor, so a derived
  class declares `class Derived: Base` instead of `class Derived`. The reference
  is read only for a class kind: a struct or enum stores a field count at that
  same offset, so reading it ungated reports a small integer as a base type.
  A null reference is a root class, which is a complete fact rather than a gap —
  native Swift classes inherit from nothing unless declared. The name reaches
  `--format json` as `superclass` on each declaration, and joins the inheritance
  clause ahead of any protocol conformances.
- Carried a resolved superclass through Swift type merging. A descriptor-derived
  observation holds facts no symbol-derived candidate can supply, so it now
  survives a merge for the same reason `fields` already did.
- Added a ground-truth test that compiles a known class hierarchy with the host
  `swiftc` and asserts the recovered inheritance against the source it was built
  from, including the struct and enum cases that catch an ungated read. Every
  other Swift test checks metadata whose original source is unavailable, where a
  wrong descriptor offset yields a plausible name and passes.
- Replaced ad-hoc column alignment with the `laidout` layout kernel. Cells carry
  their theme token as a layout annotation and are laid out as unstyled text, so
  ANSI escapes never count toward a column and every run is measured by its
  Unicode display width.

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
