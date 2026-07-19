# Changelog

## 0.2.0

- Split structural parsing, metadata, analysis, mutation, workflow, façade, and
  CLI ownership into an enforced acyclic workspace.
- Added strict and forensic parsing with limits and structured diagnostics.
- Added explicit instruction decode errors and lossy gap reporting.
- Added `macho disassemble`: streaming, line-oriented instruction disassembly
  with constant output memory — pretty text by default, or newline-delimited
  JSON (one record per line) with `--format json`. Exact architecture, section,
  symbol, and address selection; recovering or strict decoding (strict aborts on
  the first invalid byte after streaming the valid prefix); typed gaps, labels,
  targets, identities, and schema-version-1 records. The materialized
  `disassemble()` library API is retained on the same decode core.
- Added fail-closed streaming export-trie traversal and centralized rejection
  of explicit color for machine-readable output.
- Added selective analysis plans and schema-v2 four-state snapshots.
- Added injected CLI I/O, canonical output formats, and distinct policy exits.
- Added architecture, documentation, release, CI, fuzz, and benchmark authorities.
