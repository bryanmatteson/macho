# arm64e pointer authentication

`macho pac` reports two deliberately separate evidence domains for a selected
arm64 or arm64e image:

- every admitted dyld-managed pointer, including its exact stored bytes,
  encoding, chained format, authentication key and diversity, address-diversity
  bit, complete import addends/weakness, and legacy bind/rebase provenance;
- four-byte-aligned PAC instructions and authenticated control transfers decoded
  from sections marked as instructions.

The pointer inventory is complete only when `completeness.pointer_status` is
`complete` or `absent`. `truncated` includes the available and retained counts.
Code scanning similarly reports its byte budget, first omitted address, and
decode gaps. An `executable_section_decode` code site proves the instruction
bytes and location, not reachability. `authenticate_then_transfer` additionally
proves a conservative straight-line register relationship: an `AUT*`
instruction established the transferred register and only decoded NOPs occurred
before `BR`, `BLR`, or `RET`. Any other instruction, decode gap, or control-flow
boundary ends that evidence chain.

```console
macho pac App --arch arm64e --pointers --gadgets
macho pac App --arch arm64e --format json \
  --max-pointers 2000000 --max-code-bytes 134217728
```

## Detour policy

Every arm64e `macho patch --detour` is assessed unless `--pac-policy off` is
explicit. The preview retains the source and destination entry contracts,
selected transfer mechanism, evidence bounds, stable findings, and verdict.

| Verdict | Meaning under `--pac-policy require` |
| --- | --- |
| `compatible` | admitted |
| `degrades_protection` | rejected |
| `indeterminate` | rejected because required evidence is incomplete |
| `incompatible` | rejected because recovered evidence proves a broken contract |

The arm64e planner preserves an existing entry BTI instruction. A direct `B`
remains preferred. When the destination is outside its range, the planner
materializes the address with `MOVZ`/`MOVK` instructions instead of embedding a
plain pointer literal, then uses `BR`; strict policy therefore also requires a
jump-compatible `BTI j` or `BTI jc` at that indirect destination. If the replaced
source prologue signs LR with SP, strict policy requires a corresponding signing
contract at the destination. `--pac-max-pointers` controls the planner's explicit
pointer-evidence bound, and truncation is indeterminate rather than silently
treated as absence.
