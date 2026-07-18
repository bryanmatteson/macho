# Changelog

## 0.2.0

- Split structural parsing, metadata, analysis, mutation, workflow, façade, and
  CLI ownership into an enforced acyclic workspace.
- Added strict and forensic parsing with limits and structured diagnostics.
- Added explicit instruction decode errors and lossy gap reporting.
- Added bounded `macho disassemble` text/JSON delivery with exact architecture,
  section, symbol, and address selection; strict fail-closed decoding; typed
  gaps, labels, targets, identities, and schema-version-1 reports.
- Added fail-closed streaming export-trie traversal and centralized rejection
  of explicit color for machine-readable output.
- Added selective analysis plans and schema-v2 four-state snapshots.
- Added injected CLI I/O, canonical output formats, and distinct policy exits.
- Added architecture, documentation, release, CI, fuzz, and benchmark authorities.
