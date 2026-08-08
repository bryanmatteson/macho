# Dyld shared-cache layout contract

Macho accepts every published `dyld_v0` and `dyld_v1` structural cache layout.
It selects layouts from the 16-byte magic and header extent, exactly as Apple's
reader does; optional fields are never inferred from nonzero payload values.
Unknown future magic generations and unknown architecture encodings fail with
`DyldCacheErrorKind::Unsupported` before listing or extraction.

## Supported layout matrix

| Surface | Published variants | Macho behavior |
| --- | --- | --- |
| Magic generation | `dyld_v0`, `dyld_v1` | Retained as `DyldCacheFormatVersion` |
| Numeric byte order | big-endian PowerPC; little-endian Intel and ARM | Applied to every numeric header and table field |
| Image inventory | legacy `imagesOffsetOld`, `imagesText`, current relocated `imagesOffset` | Header-extent selection with bounded paths and deterministic order |
| VM mappings | `dyld_cache_mapping_info`, `dyld_cache_mapping_and_slide_info` | Extended records retain slide ranges and flags and must agree with the legacy projection |
| Family topology | monolithic, numeric V1 subcaches, suffix-bearing V2 subcaches, separate `.symbols` | Every declared member is required and UUID-, generation-, architecture-, and byte-order-validated |
| Local symbols | embedded or separate, 32-bit and 64-bit per-image entry layouts | Entry width follows Apple's `symbolFileUUID` header boundary; nlist and string ranges are validated |
| Thread-protected ranges | `dyld_cache_tpro_mapping_info` | Retained and required to fit within one member mapping |

Supported magic architectures are `ppc`, `ppc64`, `i386`, `x86_64`,
`x86_64h`, `armv5`, `armv6`, `armv7`, `armv7f`, `armv7s`, `armv7k`,
`arm64`, `arm64e`, and `arm64_32`. This closed list determines both numeric
byte order and the local-symbol nlist width. A new architecture spelling is a
new layout contract and is rejected as unsupported until its representation is
known.

## Validation and reconstruction boundary

All table products, offsets, extents, VM ranges, slide-info ranges, strings,
and local-symbol subranges are checked for overflow and member bounds. Mapping
and TPRO ranges may not overlap illegally. A split family is assembled only
after every declared sibling has the expected UUID and the same format,
architecture, and byte order as the primary.

Layout support does not mean arbitrary cached Mach-O bytes can always become a
safe standalone image. Extraction additionally requires exhaustive ownership
of every load-command file coordinate it must rewrite. An otherwise valid
cache containing a future or opaque Mach-O load-command layout is reported as
unsupported rather than emitted partially. Cache-level local symbols and
cache-resident signatures remain explicit unresolved evidence; they are not
silently presented as standalone image evidence.

`macho cache CACHE --info --format json` exposes the selected format and byte
order, legacy or extended mappings, slide metadata, flags, TPRO ranges, and
family-member identities. Text output includes the family format and TPRO
ranges. Both outputs retain the schema-version-1 command envelope.
