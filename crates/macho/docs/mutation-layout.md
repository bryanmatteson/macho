# Mach-O mutation layout boundary

`macho::mutate` does not offer arbitrary existing-payload relayout. This is a
correctness boundary, not an unfinished byte-copy loop: a Mach-O image can
carry addresses and file coordinates outside the structures for which this
crate has a complete rewrite contract. Moving payload while only updating the
modeled load-command fields can produce a file that reparses successfully but
executes incorrectly.

## Modeled coordinates

The parser retains these coordinate-bearing structures and the encoder can
round-trip their load-command fields:

- segment `vmaddr`, `vmsize`, `fileoff`, and `filesize`;
- section `addr`, `size`, `offset`, `reloff`, and `nreloc`;
- `LC_SYMTAB` symbol and string-table file offsets;
- all six file-offset tables in `LC_DYSYMTAB`;
- the five offset/size pairs in `LC_DYLD_INFO[_ONLY]`;
- `linkedit_data_command` offsets for code signatures, split-segment info,
  function starts, data-in-code, code-signing DRS, linker optimization hints,
  exports tries, chained fixups, atom info, function variants, and variant
  fixups;
- `LC_ENCRYPTION_INFO[_64]`, `LC_TWOLEVEL_HINTS`, and `LC_NOTE` file ranges;
- `LC_MAIN`'s `__TEXT`-relative entry offset;
- `LC_FILESET_ENTRY` file offset and VM address; and
- `LC_ROUTINES[_64]` initializer VM address.

This is sufficient to preserve those fields when their referenced bytes do
not move. It is not sufficient to rewrite the contents of every referenced
payload.

## Why universal relayout is unsound

The following accepted inputs contain coordinate-bearing or semantically
opaque bytes without a repository-wide relocation writer:

- `LC_THREAD`, `LC_UNIXTHREAD`, `LC_PREBOUND_DYLIB`, `LC_IDENT`, and unknown
  load commands are retained as raw bytes. Thread states include architecture-
  specific program counters; future or vendor commands may contain either
  file offsets or VM addresses.
- Regular and unknown section types are arbitrary bytes. They may contain
  absolute pointers, relative pointers, architecture-specific instructions,
  ObjC/Swift/C++ runtime metadata, unwind records, DWARF references, or
  application-defined address tables. Parsing some of those domains for
  analysis is not an exhaustive rewrite contract.
- Symbol-table `n_value` fields, classic relocation records, indirect-symbol
  consumers, dyld opcode streams, chained-fixup payloads, exports, function
  starts, split-segment info, data-in-code entries, atom/function-variant data,
  and owner-defined `LC_NOTE` payloads have internal coordinates or semantics.
  The structural editor moves none of them and has no closed writer for the
  complete set.
- Code signatures hash file pages and encode a signed code limit. Moving bytes
  invalidates the signature even when `LC_CODE_SIGNATURE.dataoff` is updated;
  signing support is a separate terminal transformation, not evidence that all
  preceding address rewrites were complete.
- Executable bytes may use PC-relative or absolute addressing. The patch
  module can relocate a bounded, decoded trampoline instruction sequence, but
  that local proof cannot authorize relocating every instruction in an image.

Consequently, strict reparse after a candidate rewrite is necessary but not a
semantic proof: opaque bytes can remain well-formed while pointing at stale
locations.

## Broadest sound layout API

The supported boundary is coordinate-preserving extension:

1. Load commands may be edited only within proven zero-filled header slack.
2. A file-backed section may extend its segment into a bounded, zero-filled
   gap only when its written bytes do not overlap any modeled command-owned or
   relocation-table range, and without crossing a later file-backed segment or
   VM mapping. Unknown commands make ownership unprovable and fail closed.
3. A terminal segment may grow only when its declared file range ends exactly
   at the input boundary.
4. A new segment may be appended after every existing file and VM range.
5. Zero-fill sections may consume non-overlapping virtual slack without moving
   file bytes.
6. Every transaction reparses and validates the candidate; unsupported motion
   returns `mutation.unsupported` without modifying the input.

Within this boundary, every existing file offset and VM address remains stable,
so opaque payloads do not require interpretation. A future relayout API must be
domain-closed: it must reject unknown commands and section types, enumerate and
rewrite every admitted payload format, remove or regenerate signatures, and
revalidate every rewritten reference before it may move a byte.
