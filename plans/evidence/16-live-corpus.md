# C/C++ and Language-Recovery Live-Corpus Evidence

Date: 2026-07-18  
Tool: dirty-tree `target/debug/macho 0.2.0` built from baseline commit `86ae47d`

This is execution evidence, not an amendment to the accepted plan or wire
contract. The run reached a mandatory STOP condition, so the corpus verdict is
`FAIL_CONTRACT_REPRESENTATION` rather than PASS.

## Inputs

| Input | SHA-256 | Architectures |
| --- | --- | --- |
| `/usr/local/bin/talos` | `435aee40453c400ebdcc4b2559df83d5792bd47403effe0f74bf348651a558fa` | arm64 |
| `/Applications/iMazing.app/Contents/MacOS/iMazing` | `b666b3b31578257aaabad3bbd64fa84f0e599e8ce3931705d8bdd7f5ac8c60b4` | x86_64, arm64 |

Input discovery commands exited 0:

```text
shasum -a 256 /usr/local/bin/talos /Applications/iMazing.app/Contents/MacOS/iMazing
file /usr/local/bin/talos /Applications/iMazing.app/Contents/MacOS/iMazing
```

## Talos

All commands below exited 0.

```text
target/debug/macho ranges --demangle --color never /usr/local/bin/talos
target/debug/macho c --format json /usr/local/bin/talos
target/debug/macho cpp --format json /usr/local/bin/talos
```

Assertions:

- The supplied Rust-v0 TLV symbols demangle in `ranges`, including
  `tracing_core[...]::dispatcher::CURRENT_STATE::{K#0}::{closure#0}::__RUST_STD_INTERNAL_VAL$tlv$init`
  and
  `std[...]::sys::thread_local::destructors::list::DTORS$tlv$init`.
- Range columns remain aligned after demangling.
- C recovery conserved 90,545 observations into 46,358 C-compatible entities;
  45,939 matched the default defined selection. The source plan executed
  `symbol_discovery`, `function_ranges`, and `dwarf` only.
- A representative Rust-v0 observation was explicitly `wrong_language`, not a
  C entity.
- C++ recovery conserved all 90,545 observations and produced zero entities;
  Rust symbols did not enter the Itanium surface.

The production process scan found process launch only in the isolated signing
adapter. `std::process::id` uses are nonce generation, not launches, and the
remaining `clang` occurrence is a Mach-O tool enum label:

```text
rg -n "std::process|process::Command|Command::new|xcrun|clang" crates \
  --glob '*.rs' --glob '!**/tests/**' --glob '!**/benches/**' \
  --glob '!**/xtask/**'
```

## iMazing Objective-C

Both commands exited 0:

```text
target/debug/macho objc --arch arm64 --format json /Applications/iMazing.app/Contents/MacOS/iMazing
target/debug/macho objc --arch x86_64 --format json /Applications/iMazing.app/Contents/MacOS/iMazing
```

| Architecture | Observations | Defined | Referenced | Partial | Malformed | Excluded | Diagnostics |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| arm64 | 1,100 | 1,029 | 71 | 0 | 0 | 0 | 0 |
| x86_64 | 1,099 | 1,028 | 71 | 0 | 0 | 0 | 0 |

Every observation had exactly one disposition, every selected observation had
one entity, and referenced Objective-C dependencies remained referenced.

## iMazing Swift

Both commands exited 0:

```text
target/debug/macho swift --arch arm64 --format json /Applications/iMazing.app/Contents/MacOS/iMazing
target/debug/macho swift --arch x86_64 --format json /Applications/iMazing.app/Contents/MacOS/iMazing
```

| Architecture | Observations | Included | Unknown | Entities | Metadata-defined | Partial | Referenced | Diagnostics |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| arm64 | 2,550 | 2,544 | 6 | 1,410 | 693 | 709 | 8 | 247 |
| x86_64 | 2,549 | 2,543 | 6 | 1,409 | 693 | 708 | 8 | 247 |

The arm64 report contained 3,554 recovered fields/cases, 2,905 conformance
references, and 38 known parent relationships. The x86_64 report contained
3,552 fields/cases, 2,903 conformance references, and 38 known parents. Unknown
reflection records and unresolved external protocol references remain explicit;
they are not promoted to local definitions.

## iMazing C++ and Header Projection

These commands exited 0:

```text
target/debug/macho cpp --arch arm64 --scope all --format json /Applications/iMazing.app/Contents/MacOS/iMazing
target/debug/macho cpp --arch arm64 --view header --format json /Applications/iMazing.app/Contents/MacOS/iMazing
target/debug/macho c --arch arm64 --scope all --name '*mh_execute_header*' --format json /Applications/iMazing.app/Contents/MacOS/iMazing
```

- C++ recovery conserved 2,973 observations, excluded 2,602 wrong-language
  observations, and included 371 Itanium entities: 11 defined and 360 imported.
- The default defined C++ header view selected 11 entities, emitted no unsafe
  declarations, recorded 100 field-level unresolved entries, and reparsed with
  `syntax_valid=true` and `semantic_valid=true`.
- The selected `__mh_execute_header` C entity is currently reported as
  `role=function`, `presence=defined`. This violates the required runtime-
  artifact assertion.

## STOP evidence

The accepted recovery plan requires explicit TLS and runtime-artifact roles and
specifically requires `_mh_execute_header` to be a runtime artifact. The
normative closed wire registry has neither value. It also defines
`EntityKind::type` without a corresponding `EntityRole::type`, so the required
C++ class entities have no representable role.

Changing those closed enums is a wire-contract amendment. The accepted feature
contract forbids silently changing it during implementation, and the plan's
STOP rules require the contradiction to be resolved in the specification
before downstream completion. No PASS disposition is recorded for A006, A009,
A010, or the final live-corpus gate.

## Amended-contract rerun — PASS

The user accepted the exact Gate-3 amendment on 2026-07-18. After the wire,
implementation, fixtures, and validators were updated together, the same input
hashes above were rerun with the rebuilt `target/debug/macho 0.2.0`. This section
supersedes the historical STOP verdict without erasing its evidence.

### Talos

- `ranges --demangle` produced aligned columns and demangled the supplied
  Rust-v0 TLS initializer family, including tracing, Tokio, std, and reqwest
  names, while preserving `$tlv$init`.
- C recovery conserved 90,545 observations into 46,358 entities: 30,995 data,
  14,943 function, 419 unknown, and exactly one runtime artifact.
- `__mh_execute_header` is `role=runtime_artifact`, `presence=defined`; it is no
  longer classified from its executable section as a function.
- C++ recovery still produces no false Itanium entities from the Rust binary.

### iMazing C and C++

- The arm64 C image-header selection contains exactly one selected entity:
  `__mh_execute_header`, `runtime_artifact`, `defined`.
- Explicit `--kind unknown` selects 1,338 arm64 C entities, every selected role
  is `unknown`, and no non-unknown entity enters the selection. The canonical
  report intentionally retains the full evidence ledger; selection authority is
  `resolved_plan.selected_entity_ids`.
- arm64 C++ recovery contains 423 entities: 49 methods, 15 static data, 5 plain
  functions, 3 guards, 10 thunks, 52 types, 34 typeinfo, 13 vtables, and 242
  unknown. All 52 type entities are imported and role conflicts are zero.
- x86_64 C++ recovery contains 682 entities, including 87 defined and 51
  imported type entities. `defined_types_without_defined_anchor=0` and
  `imported_types_with_defined_anchor=0` when occurrence links are checked
  against observation presence.
- The arm64 default header view selected 11 entities. Every selected ID occurs
  in the declared-or-unresolved coverage union; the projection emitted no unsafe
  declarations and validated with `syntax_valid=true` and
  `semantic_valid=true`.

### iMazing Objective-C and Swift

The final rebuilt CLI reproduced the earlier language partitions:

| Language | Architecture | Observations | Entities | Defined / metadata-defined | Partial | Referenced | Diagnostics |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Objective-C | arm64 | 1,100 | 1,100 | 1,029 | 0 | 71 | 0 |
| Objective-C | x86_64 | 1,099 | 1,099 | 1,028 | 0 | 71 | 0 |
| Swift | arm64 | 2,550 | 1,410 | 693 | 709 | 8 | 247 |
| Swift | x86_64 | 2,549 | 1,409 | 693 | 708 | 8 | 247 |

Objective-C header dependency closure also passed after the shared validator
was taught that reparsed named pointer types are resolved by Objective-C
`@class` declarations. Swift diagnostics remain explicit evidence gaps and do
not create false local definitions.

Final live-corpus verdict: `PASS`.
