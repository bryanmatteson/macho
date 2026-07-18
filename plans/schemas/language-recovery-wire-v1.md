# Language and Recovery Wire Contract v1

## Authority

This document is the normative serialized contract for the common report
vocabulary and the C/C++, Objective-C, Swift, and offline-hypothesis artifacts
owned by active plans 10, 13, 15, and 16. The Rust blocks in those plans are API
projections of this contract. If a block and this document disagree, this
document wins and the block must be corrected in the same change.

`macho-analysis::report` owns common wire DTOs, canonical JSON, stable IDs, the
deterministic C/C++/Objective-C/Swift report roots, and their schema registries.
`macho-header-infer` owns the hypothesis bundle/response/report root DTOs and
validation while importing the common vocabulary. `macho-header-syntax` owns
the nonserialized AST and validators. Leaf language crates own parsed semantic
values; `macho-analysis` converts them into analysis-owned report DTOs. The
leaves do not own an independent serialized report. `IdentityStability` therefore has one
wire owner and is shared by C/C++ and Swift reports without a dependency from a
leaf crate to `macho-analysis`.

No type, enum, code, reason, or default used by a serialized artifact may be
added outside this file. Changing a field, tag, spelling, default, limit, or
validation rule requires a schema-version decision and golden plus rejection
fixtures in the same change.

The 2026-07-18 Gate-3 amendment adds the previously required but unrepresentable
TLS, runtime-artifact, class/type, and global-value-type facts. The recovery
schema remains version 1 because this prerelease wire has never had a supported
external release; all v1 goldens are replaced atomically and strict unknown-
field/unknown-enum rejection prevents mixed pre-amendment documents from being
accepted.

## Root field registry

The keys in this section are exhaustive. `Option<T>` uses the required nullable
key rule above; `Vec<T>`, `NonEmpty<T>`, and `AtLeastTwo<T>` use the collection
rules above. Generic `Fact<T>`, `ObjCValue<T>`, and `SwiftValue<T>` payloads must
validate as the named `T` at each field site.

### Recovery roots

| Type | Exact keys |
| --- | --- |
| `RecoveryReport` | `schema_version`, `language`, `request`, `slices` |
| `SliceRecovery` | `architecture`, `image`, `inputs`, `resolved_plan`, `executions`, `observations`, `entities`, `header`, `diagnostics`, `truncations` |
| `SymbolObservation` | `id`, `source`, `ordinal`, `raw_name`, `presence`, `address`, `section`, `disposition` |
| `RecoveredEntity` | `id`, `identity_stability`, `observation_ids`, `linkage`, `display_name`, `role`, `presence`, `visibility`, `weakness`, `location`, `owner`, `value_type`, `signature`, `layout`, `hierarchy`, `evidence`, `gaps` |
| `FactCandidate<T>` | `value`, `strength`, `evidence_ids` |
| `RecoveryInputs` | `image`, `selected_architecture`, `header_roots` |
| `RecoveryRequestSummary` | `language`, `architectures`, `view`, `selection`, `analysis`, `header_roots`, `limits` |
| `HashedHeaderRoot` | `logical_label`, `content_hash`, `files` |
| `RecoveryDiagnostic` | `id`, `code`, `severity`, `message`, `observation_id`, `entity_id`, `evidence_ids` |
| `Truncation` | `collector`, `limit_name`, `limit`, `collected`, `omitted_lower_bound` |
| `CollectorExecution` | `collector`, `request_digest`, `target_entity_ids`, `outcome`, `counts` |
| `CollectorCounts` | `input_records`, `output_records`, `selected_targets` |
| `EvidenceRecord` | `id`, `collector`, `observation_ids`, `strength`, `payload` |
| `RecoveryGap` | `id`, `field`, `reason`, `evidence_ids` |
| `RecoveredSignature` | `return_type`, `parameters`, `variadic`, `calling_convention`, `qualifiers` |
| `RecoveredParameter` | `type_evidence`, `source_name` |
| `RecoveredLayout` | `size`, `alignment`, `fields`, `completeness` |
| `RecoveredHierarchy` | `bases`, `virtual_surface` |
| `RecoveryRequest` | `language`, `architectures`, `view`, `selection`, `analysis`, `header_roots`, `limits` |
| `EntitySelection` | `scope`, `kinds`, `name_globs` |
| `ResolvedRecoveryPlan` | `request_digest`, `discovery`, `selected_entity_ids`, `targeted`, `projection` |
| `ResolvedCollectorSpec` | `collector`, `target_entity_ids`, `required`, `limits` |
| `HeaderProjection` | `language`, `declarations`, `unresolved`, `diagnostics`, `source`, `validation` |

| Data enum | Exact tags and payload keys |
| --- | --- |
| `ObservationDisposition` | `included(entity_ids)`, `excluded(reason)`, `unknown(reason)` |
| `Fact<T>` | `known(id,value,strength,evidence_ids)`, `conflicted(id,candidates)`, `unavailable(id,reason,evidence_ids)` |
| `CollectorOutcome` | `complete()`, `unsupported(reason)`, `failed(diagnostic_id)`, `truncated(truncation_index)` |
| `EvidencePayload` | `symbol(value)`, `dwarf(value)`, `range(value)`, `rtti(value)`, `vtable(value)`, `header(value)`, `abi(value)` |
| `RecoveryGapReason` | `unavailable(reason)`, `conflicted(fact_id)`, `header_ineligible(reason)` |
| `ParameterList` | `unspecified()`, `known(parameters)` |
| `TypeEvidence` | `source(type)`, `abi_class(class)` |

### Objective-C roots

| Type | Exact keys |
| --- | --- |
| `ObjCReport` | `schema_version`, `slices` |
| `ObjCSliceReport` | `architecture`, `image`, `graph`, `entities`, `observations`, `evidence`, `selection`, `header`, `diagnostics`, `executions` |
| `ObjCSelectionResult` | `selected_entity_ids`, `totals` |
| `ObjCCollectorExecution` | `collector`, `outcome`, `input_records`, `output_records` |
| `ObjCCandidate<T>` | `value`, `evidence` |
| `ObjCEntityCommon` | `id`, `presence`, `name`, `observation_ids` |
| `ObjCClassEntity` | `common`, `superclass`, `adopted_protocols`, `ivars`, `properties`, `instance_methods`, `class_methods` |
| `ObjCCategoryEntity` | `common`, `extended_class`, `adopted_protocols`, `properties`, `instance_methods`, `class_methods`, `fold_order` |
| `ObjCProtocolEntity` | `common`, `adopted_protocols`, `required_instance_methods`, `required_class_methods`, `optional_instance_methods`, `optional_class_methods`, `properties` |
| `ObjCMethod` | `id`, `selector`, `kind`, `raw_encoding`, `signature`, `implementation`, `origin` |
| `ObjCProperty` | `id`, `name`, `raw_attributes`, `parsed_attributes`, `origin` |
| `ObjCIvar` | `id`, `name`, `raw_encoding`, `parsed_type`, `offset`, `size`, `alignment` |
| `ObjCObservation` | `id`, `source`, `location`, `raw`, `disposition` |

| Data enum | Exact tags and payload keys |
| --- | --- |
| `ObjCEntity` | `class(value)`, `category(value)`, `protocol(value)` |
| `ObjCCollectorOutcome` | `complete()`, `unsupported(reason)`, `failed(diagnostic_id)`, `truncated(omitted_lower_bound)` |
| `ObjCValue<T>` | `known(value,evidence)`, `conflicted(candidates)`, `unavailable(reason)` |
| `ObjCObservationDisposition` | `included(entity_ids)`, `referenced(entity_id)`, `malformed(diagnostic_id)`, `excluded(reason)` |

### Swift roots

| Type | Exact keys |
| --- | --- |
| `SwiftReport` | `schema_version`, `slices` |
| `SwiftSliceReport` | `architecture`, `image`, `observations`, `evidence`, `entities`, `selection`, `diagnostics`, `executions` |
| `SwiftEntity` | `id`, `identity_stability`, `state`, `kind`, `qualified_name`, `descriptor`, `parent`, `fields_or_cases`, `conformances`, `raw_linkages`, `observation_ids`, `gaps` |
| `SwiftCandidate<T>` | `value`, `evidence` |
| `SwiftSelectionResult` | `selected_entity_ids`, `totals` |
| `SwiftCollectorExecution` | `collector`, `outcome`, `input_records`, `output_records` |
| `SwiftObservation` | `id`, `source`, `raw`, `location`, `disposition` |

| Data enum | Exact tags and payload keys |
| --- | --- |
| `SwiftValue<T>` | `known(value,evidence)`, `conflicted(candidates)`, `unavailable(reason)` |
| `SwiftCollectorOutcome` | `complete()`, `unsupported(reason)`, `failed(diagnostic_id)`, `truncated(omitted_lower_bound)` |
| `SwiftObservationDisposition` | `included(entity_ids)`, `unknown(diagnostic_id)`, `excluded(reason)` |

### Hypothesis roots

| Type | Exact keys |
| --- | --- |
| `HypothesisBundle` | `schema_version`, `recovery_schema_version`, `recovery_digest`, `bundle_digest`, `language`, `architecture`, `image`, `targets`, `facts`, `evidence`, `constraints`, `limits` |
| `HypothesisTarget` | `entity_id`, `gap_ids`, `allowed_operations` |
| `EvidenceExcerpt` | `evidence_id`, `entity_id`, `canonical_projection` |
| `FactExcerpt` | `fact_id`, `entity_id`, `field`, `canonical_projection` |
| `BundleConstraints` | `pinned_fact_ids`, `supported_header_subset` |
| `ModelResponse` | `schema_version`, `bundle_digest`, `hypotheses`, `unresolved_gap_ids` |
| `ProposedHypothesis` | `id`, `entity_id`, `gap_id`, `operation`, `support` |
| `HypothesisReport` | `schema_version`, `bundle_digest`, `response_digest`, `results`, `unresolved_gap_ids`, `validation`, `projected_header` |
| `HypothesisResult` | `hypothesis_id`, `entity_id`, `gap_id`, `disposition`, `support`, `diagnostics` |

| Data enum | Exact tags and payload keys |
| --- | --- |
| `SupportRef` | `evidence(evidence_id)`, `deterministic_fact(fact_id)`, `related_entity(entity_id)` |
| `HypothesisOperation` | `choose_candidate(candidate_index)`, `propose_canonical_name(name)`, `propose_declaration_fragment(fragment)`, `propose_grouping(owner)` |

## Universal JSON rules

- Structs are JSON objects with the exact `snake_case` keys declared here.
  Unknown and duplicate keys are rejected. Every declared key is present;
  optional values are encoded as JSON `null`, never by omitting the key.
- Unit enums are the exact `snake_case` strings listed in their registry.
  Data-carrying enums are objects with a required `kind` key containing the
  listed spelling and the exact payload keys declared for that variant.
- Integer fields are non-negative JSON integers unless explicitly declared
  signed. Floating-point values, non-finite numbers, and numeric strings are
  rejected. Counts and byte offsets are `u64`; array indexes are `u32`.
- Byte strings are lowercase hexadecimal with two characters per byte. Stable
  IDs and SHA-256 digests are lowercase hexadecimal strings of exactly 64
  characters. UUIDs are uppercase canonical `8-4-4-4-12` strings.
- `NonEmpty<T>` is a JSON array with at least one element. `AtLeastTwo<T>` is an
  array with at least two distinct validated values. Set-like arrays are sorted
  by their canonical element bytes and reject duplicates. Order-bearing arrays
  retain semantic order.
- `CanonicalJsonValue` is a parsed JSON subtree copied from the exact referenced
  validated record. It is valid only when canonical serialization is
  byte-identical to that source subtree; it cannot contain invented keys or
  values.
- Canonical JSON is UTF-8, contains no insignificant whitespace, sorts object
  keys lexicographically by Unicode scalar value, preserves array order, uses
  shortest decimal integers, and escapes only control characters, quotation
  marks, and reverse solidus. Digests cover these bytes.
- Validation is two-stage: deserialize a deny-unknown-fields wire DTO, then run
  referential, conservation, bounds, and semantic validation. Renderers and
  snapshot readers accept only the validated type.

Schema-version newtypes serialize as JSON integers with one accepted value:
`RecoverySchemaVersion`, `ObjCReportVersion`, `SwiftReportVersion`,
`HypothesisBundleVersion`, `ModelResponseVersion`, and `HypothesisReportVersion`
accept exactly `1`; `SnapshotSchemaVersion` accepts exactly `3`.

## Common wire vocabulary

### Identity types

All types ending in `Id` below use the 64-lowercase-hex representation:

`ObservationId`, `EntityId`, `FactId`, `EvidenceId`, `DiagnosticId`,
`RecoveryGapId`, `RequestDigest`, `ObjCEntityId`, `ObjCMemberId`,
`ObjCObservationId`, `ObjCEvidenceId`, `ObjCDiagnosticId`, `SwiftEntityId`,
`SwiftObservationId`, `SwiftEvidenceId`, `SwiftDiagnosticId`, `SwiftGapId`, and
`HypothesisId`. `ContentHash` is the same representation and always names a
SHA-256 digest.

```text
Architecture        = { cpu_type: i32, cpu_subtype: i32 }
ImageIdentity       = { content_sha256: ContentHash, byte_len: u64,
                        container: ContainerKind, slice_index: u32,
                        architecture: Architecture, uuid: UUID|null }
ImageInputIdentity  = ImageIdentity
SliceIdentity       = { image: ImageIdentity }
ContainerIdentity   = { content_sha256: ContentHash, byte_len: u64,
                        container: ContainerKind, slice_count: u32 }
SectionIdentity     = { segment: MachName, section: MachName, ordinal: u32 }
AddressRange        = { start: u64, end_exclusive: u64 }
EntityLocation      = { address: u64|null, section: SectionIdentity|null,
                        range: AddressRange|null }
LogicalInputLabel   = non-empty UTF-8 string, at most 128 bytes, no slash or NUL
MachName            = non-empty UTF-8 string, at most 16 bytes, no NUL
Identifier          = one C-family identifier token, at most 255 bytes
ValidatedGlob       = UTF-8 glob with `*`, `?`, and bracket classes only;
                      at most 1,024 bytes and no path separator or NUL
```

`AddressRange.end_exclusive` must be greater than `start`. `slice_index` is
zero-based and must resolve in the container. `Architecture` equality uses both
numeric fields; display names are derived and are not identity.

| Enum | Exact values |
| --- | --- |
| `ContainerKind` | `thin`, `fat` |
| `IdentityStability` | `cross_build`, `slice_only`, `ambiguous` |
| `Severity` / `RecoverySeverity` | `info`, `warning`, `error` |
| `EvidenceStrength` | `exact`, `correlated`, `inferred` |

### Shared header-syntax wire values

`macho-header-syntax` owns the validated in-memory AST. The `HeaderType` and
`HeaderDecl` names below are report DTOs owned by `macho-analysis::report` and
are the complete serialized projection of `macho_header_syntax::Type` and
`macho_header_syntax::Decl`; raw source is never an AST variant. Analysis
depends downward on the syntax crate and performs the conversion. The syntax
crate contains no report IDs and never depends upward on analysis.

```text
HeaderType =
  { kind: "builtin", name: BuiltinType } |
  { kind: "named", tag: NamedTypeTag, path: NonEmpty<Identifier>,
    template_arguments: [HeaderTemplateArgument] } |
  { kind: "pointer", pointee: HeaderType, qualifiers: TypeQualifiers } |
  { kind: "reference", target: HeaderType, reference: ReferenceKind } |
  { kind: "array", element: HeaderType, count: u64|null } |
  { kind: "function", return_type: HeaderType,
    parameters: [HeaderParameter], parameter_state: ParameterState,
    variadic: bool, calling_convention: CallingConvention,
    qualifiers: HeaderFunctionQualifiers } |
  { kind: "objc_object", name: Identifier|null,
    protocols: [Identifier], qualifiers: TypeQualifiers } |
  { kind: "objc_block", signature: HeaderType }

HeaderTemplateArgument =
  { kind: "type", value: HeaderType } |
  { kind: "integer", value: i64 } |
  { kind: "identifier", path: NonEmpty<Identifier> }

HeaderParameter = { name: Identifier, type: HeaderType }
TypeQualifiers = { const: bool, volatile: bool, restrict: bool }
HeaderFunctionQualifiers = { const: bool, volatile: bool,
                             reference: ReferenceKind|null,
                             noexcept: bool|null }

HeaderDecl =
  { kind: "function", id: EntityId, owner: HeaderOwnerRef|null,
    name: Identifier, signature: HeaderType, storage: StorageClass,
    linkage: HeaderLinkage } |
  { kind: "variable", id: EntityId, owner: HeaderOwnerRef|null,
    name: Identifier, type: HeaderType, storage: StorageClass,
    linkage: HeaderLinkage } |
  { kind: "record", id: EntityId, record_kind: RecordKind,
    path: NonEmpty<Identifier>, complete: bool, bases: [HeaderBase],
    fields: [HeaderField], members: [HeaderDecl] } |
  { kind: "forward", id: EntityId, record_kind: RecordKind,
    path: NonEmpty<Identifier> } |
  { kind: "alias", id: EntityId, path: NonEmpty<Identifier>,
    target: HeaderType } |
  { kind: "objc_interface", id: ObjCEntityId, name: Identifier,
    superclass: Identifier|null, protocols: [Identifier],
    ivars: [ObjCHeaderIvar], members: [ObjCHeaderMember] } |
  { kind: "objc_category", id: ObjCEntityId, name: Identifier,
    extended_class: Identifier, protocols: [Identifier],
    members: [ObjCHeaderMember] } |
  { kind: "objc_protocol", id: ObjCEntityId, name: Identifier,
    protocols: [Identifier], members: [ObjCHeaderMember] } |
  { kind: "objc_forward", entity_kind: ObjCForwardKind,
    names: NonEmpty<Identifier> }
```

Recursive `HeaderDecl.members` may contain only function, variable, alias, and
forward variants. A record definition must have `complete=true`; a forward
declaration uses the separate `forward` variant. `HeaderSyntaxFragmentWire` is
exactly one `HeaderDecl`.

Validated header values have a maximum type recursion depth of 64, declaration
nesting depth of 64, 1,024 template arguments or members on one node, and
1,000,000 total AST nodes per artifact. `ObjCEncodedType` uses the same recursion
depth. Exceeding any bound is a typed limit error; the parser and deserializer
must reject it before recursive rendering or semantic validation.

| Enum | Exact values |
| --- | --- |
| `BuiltinType` | `void`, `bool`, `char`, `signed_char`, `unsigned_char`, `short`, `unsigned_short`, `int`, `unsigned_int`, `long`, `unsigned_long`, `long_long`, `unsigned_long_long`, `int128`, `unsigned_int128`, `float`, `double`, `long_double` |
| `NamedTypeTag` | `typedef`, `struct`, `union`, `enum`, `class`, `protocol` |
| `ReferenceKind` | `lvalue`, `rvalue` |
| `ParameterState` | `unspecified`, `known` |
| `CallingConvention` | `c`, `swift`, `objc_method`, `thiscall`, `vectorcall`, `aapcs`, `aapcs_vfp`, `unknown` |
| `StorageClass` | `none`, `extern`, `static`, `thread_local` |
| `HeaderLinkage` | `c`, `cpp`, `objc` |
| `RecordKind` | `struct`, `union`, `class`, `enum` |
| `ObjCForwardKind` | `class`, `protocol` |

```text
HeaderOwnerRef = { kind: HeaderOwnerKind, path: NonEmpty<Identifier>,
                   entity_id: EntityId|null }
HeaderBase     = { type: HeaderType, access: Access, virtual: bool }
HeaderField    = { name: Identifier, type: HeaderType, offset: u64|null,
                   bit_width: u32|null, access: Access }
ObjCHeaderIvar = { id: ObjCMemberId, name: Identifier, type: HeaderType,
                   access: ObjCAccess }
ObjCHeaderMember =
  { kind: "method", id: ObjCMemberId, method_kind: MethodKind,
    selector: Selector, return_type: HeaderType,
    parameters: [HeaderParameter], required: bool|null } |
  { kind: "property", id: ObjCMemberId, name: Identifier,
    type: HeaderType, attributes: [ObjCPropertyAttribute] }
HeaderGap = { entity_id: EntityId, field: RecoveryField,
              reason: HeaderIneligibilityReason,
              diagnostic_ids: [DiagnosticId] }
HeaderValidationReport = { syntax_valid: bool, semantic_valid: bool,
                           diagnostics: [HeaderValidationDiagnostic] }
HeaderValidationDiagnostic = { code: HeaderValidationCode,
                               severity: Severity, message: string,
                               declaration_index: u32|null }
```

| Enum | Exact values |
| --- | --- |
| `HeaderOwnerKind` | `namespace`, `record`, `class` |
| `Access` | `public`, `protected`, `private`, `unspecified` |
| `ObjCAccess` | `public`, `protected`, `private`, `package` |
| `HeaderValidationCode` | `syntax_error`, `duplicate_declaration`, `conflicting_redeclaration`, `unresolved_type`, `unresolved_owner`, `invalid_linkage`, `invalid_storage`, `invalid_calling_convention`, `incomplete_template_context`, `selector_arity_mismatch`, `objc_kind_mismatch`, `dependency_cycle` |

## Recovery report registry

### Limits and request-only values

`RecoveryLimits` has exactly these fields. A request below one is invalid; a
request above the hard maximum is rejected before collection.

| Field | Default | Hard maximum |
| --- | ---: | ---: |
| `max_observations` | 1,000,000 | 8,000,000 |
| `max_entities` | 250,000 | 2,000,000 |
| `max_evidence_records` | 2,000,000 | 8,000,000 |
| `max_ranges` | 500,000 | 4,000,000 |
| `max_dwarf_dies` | 2,000,000 | 16,000,000 |
| `max_decoded_bytes` | 67,108,864 | 1,073,741,824 |
| `max_header_files` | 10,000 | 100,000 |
| `max_header_bytes` | 67,108,864 | 536,870,912 |
| `max_diagnostics` | 100,000 | 1,000,000 |
| `max_serialized_bytes` | 268,435,456 | 1,073,741,824 |

```text
HashedHeaderFile = { relative_path: string, content_sha256: ContentHash,
                     byte_len: u64 }
HeaderRootRequest = { logical_label: LogicalInputLabel, root_token: string }
ArchitectureSelection =
  { kind: "all" } |
  { kind: "one", architecture: Architecture }
RecoveryView = "surface" | "header"
RecoveryScope = "all" | "defined" | "referenced" | "symbol_only"
EntityKind = "function" | "data" | "tls" | "runtime_artifact" |
             "method" | "type" | "vtable" | "typeinfo" | "thunk" |
             "guard" | "unknown"
CollectorLimits = { max_records: u64, max_bytes: u64,
                    max_diagnostics: u64 }
CollectorSpec = { collector: CollectorId, required: bool,
                  limits: CollectorLimits, target_policy: TargetPolicy }
HeaderProjectionSpec = { target_entity_ids: NonEmpty<EntityId>,
                         language: RecoveryLanguage }
TargetPolicy = "all_observations" | "selected_entities"
```

`root_token` is transient and is never serialized into `RecoveryReport`; it is
an opaque caller handle resolved by an injected input provider. The serialized
`HashedHeaderRoot.files` array is sorted by normalized relative path. Relative
paths use `/`, reject absolute paths, `.` and `..` components, duplicate paths,
and NUL.

### Recovery leaf values

| Enum | Exact values |
| --- | --- |
| `Presence` | `defined`, `imported`, `reexported`, `tentative`, `unknown` |
| `Visibility` | `default`, `hidden`, `protected`, `private_extern`, `unknown` |
| `Weakness` | `strong`, `weak_definition`, `weak_reference`, `tentative`, `unknown` |
| `EntityRole` | `function`, `data`, `tls`, `runtime_artifact`, `cpp_method`, `cpp_static_data`, `type`, `typeinfo`, `vtable`, `vtt`, `thunk`, `guard`, `unknown` |
| `LinkageFamily` | `plain`, `itanium_cpp`, `rust_v0`, `rust_legacy`, `swift`, `objc`, `unknown` |
| `LayoutCompleteness` | `complete`, `partial`, `opaque` |
| `AbiValueClass` | `integer`, `floating`, `vector`, `aggregate`, `indirect`, `void`, `unknown` |
| `RecoveryLanguage` | `c_abi`, `cpp` |
| `AnalysisLevel` | `sources`, `abi` |

```text
LinkageEncoding = { raw: string, normalized: string,
                    family: LinkageFamily }
EntityOwner = { kind: HeaderOwnerKind|null, path: [Identifier],
                entity_id: EntityId|null }
RecoveredField = { name: Fact<string>, type: Fact<TypeEvidence>,
                   offset: Fact<u64>, bit_width: Fact<u32|null> }
BaseRelation = { base: EntityId, offset: Fact<u64>, access: Fact<Access>,
                 virtual: Fact<bool> }
VirtualMember = { slot: u32, target: Fact<EntityId>,
                  adjustment: Fact<i64> }
FunctionQualifiers = { const: bool|null, volatile: bool|null,
                       reference: ReferenceKind|null,
                       noexcept: bool|null }
```

`Fact<T>` uses the plan-16 three variants with `kind` spellings `known`,
`conflicted`, and `unavailable`; its `value` and candidate `value` must validate
as the named `T`. `TypeEvidence` uses `kind` spellings `source` with
`type: HeaderType` and `abi_class` with `class: AbiValueClass`.

`RecoveredEntity.value_type` is `Fact<TypeEvidence>`. It is applicable to
`data`, `tls`, and `cpp_static_data`; other roles encode it as unavailable with
`not_applicable`. Only an exact or correlated `source` value may enter a header.
An `abi_class` value is inventory evidence and is never a source declaration
type.

### Evidence payloads

```text
SymbolEvidence = { raw_name: string, normalized_linkage: string,
                   source: ObservationSource, ordinal: u64,
                   presence: Presence, address: u64|null,
                   section: SectionIdentity|null }
DwarfEvidence = { unit_offset: u64, die_offset: u64, tag: DwarfTag,
                  attribute: DwarfAttribute, source_file: ContentHash|null }
RangeEvidence = { start: u64, end_exclusive: u64, source: RangeSource }
RttiEvidence = { kind: RttiKind, address: u64,
                 type_identity: string|null }
VtableEvidence = { address: u64, owner: EntityId|null, slot: u32|null,
                   target: EntityId|null, kind: VtableKind }
HeaderCorrelationEvidence = { root_label: LogicalInputLabel,
                              relative_path: string,
                              content_sha256: ContentHash,
                              start_byte: u64, end_byte: u64,
                              declaration: HeaderDecl }
AbiEvidence = { architecture: Architecture, entity_id: EntityId,
                range: AddressRange, return_class: AbiValueClass,
                parameter_classes: [AbiValueClass],
                decode_gaps: [AddressRange] }
```

| Enum | Exact values |
| --- | --- |
| `DwarfTag` | `subprogram`, `variable`, `structure_type`, `class_type`, `union_type`, `enumeration_type`, `member`, `inheritance`, `formal_parameter`, `unspecified_parameters`, `other` |
| `DwarfAttribute` | `name`, `linkage_name`, `type`, `byte_size`, `alignment`, `data_member_location`, `low_pc`, `high_pc`, `calling_convention`, `declaration`, `other` |
| `RangeSource` | `function_starts`, `unwind_info`, `dwarf`, `symbol_adjacency`, `section_bounds` |
| `RttiKind` | `class_type_info`, `si_class_type_info`, `vmi_class_type_info`, `unknown` |
| `VtableKind` | `primary`, `secondary`, `construction`, `vtt`, `unknown` |

### Closed recovery registries

| Enum | Exact values |
| --- | --- |
| `ObservationSource` | `nlist`, `export_trie`, `dyld_bind`, `chained_fixup` |
| `CollectorId` | `symbol_discovery`, `function_ranges`, `dwarf`, `rtti`, `vtables`, `header_correlation`, `abi_body`, `header_projection` |
| `RecoveryDiagnosticCode` | `malformed_known_encoding`, `conflicting_exact_facts`, `ambiguous_identity`, `unmatched_occurrence`, `collector_unsupported`, `collector_failed`, `collector_truncated`, `header_syntax_invalid`, `header_semantic_invalid`, `unsupported_header_syntax`, `unresolved_required_fact` |
| `ExclusionReason` | `wrong_language`, `unselected_kind`, `unselected_name`, `unselected_presence`, `debug_only`, `synthetic_non_entity`, `duplicate_alias` |
| `UnknownReason` | `unrecognized_encoding`, `malformed_encoding`, `ambiguous_role`, `ambiguous_ownership`, `missing_location` |
| `UnavailableReason` | `not_encoded`, `unsupported_encoding`, `missing_dependency`, `collector_unsupported`, `collector_failed`, `truncated`, `ambiguous`, `conflicted`, `not_applicable` |
| `UnsupportedReason` | `architecture`, `format`, `missing_section`, `missing_debug_info`, `missing_runtime_metadata`, `header_language_subset` |
| `HeaderIneligibilityReason` | `unavailable_required_fact`, `conflicted_required_fact`, `abi_class_is_not_source_type`, `unsupported_type`, `unsupported_calling_convention`, `unproven_owner`, `incomplete_layout`, `incomplete_template_context`, `invalid_linkage`, `semantic_validation_failed` |
| `RecoveryField` | `linkage`, `display_name`, `role`, `presence`, `visibility`, `weakness`, `location`, `owner`, `value_type`, `return_type`, `parameters`, `variadic`, `calling_convention`, `qualifiers`, `layout_size`, `layout_alignment`, `layout_fields`, `layout_completeness`, `bases`, `virtual_surface` |
| `RecoveryLimitName` | the ten `RecoveryLimits` field spellings above |

## Objective-C report registry

`ObjCSliceReport` adds `evidence: Vec<ObjCEvidence>` between observations and
selection. `ObjCValue<T>` evidence IDs must resolve in that array.

```text
ObjCPartitionCounts = { defined_entities: u64, referenced_entities: u64,
                        partial_entities: u64,
                        malformed_observations: u64,
                        excluded_observations: u64 }
ObjCEvidence = { id: ObjCEvidenceId, observation_ids: NonEmpty<ObjCObservationId>,
                 kind: ObjCEvidenceKind, location: ObjCMetadataLocation,
                 raw: bytes }
ObjCMetadataLocation = { virtual_address: u64, file_offset: u64|null,
                         section: SectionIdentity|null }
ObjCTypeRef = { entity_id: ObjCEntityId|null, name: string,
                presence: ObjCPresence }
Selector = { spelling: string, colon_count: u32 }
ImplementationLocation = { virtual_address: u64, file_offset: u64|null }
ObjCMethodSignature = { return_type: ObjCEncodedType,
                        parameters: [ObjCEncodedType],
                        frame_size: u64|null, argument_offsets: [i64] }
ObjCPropertyAttributes = { type: ObjCEncodedType, readonly: bool,
                           ownership: ObjCOwnership, nonatomic: bool,
                           dynamic: bool, getter: Selector|null,
                           setter: Selector|null, ivar: string|null,
                           unknown: [string] }
ObjCEncodedType =
  { kind: "primitive", value: ObjCPrimitive, qualifiers: [ObjCQualifier] } |
  { kind: "object", name: string|null, protocols: [string],
    qualifiers: [ObjCQualifier] } |
  { kind: "class" } | { kind: "selector" } |
  { kind: "block", signature: ObjCMethodSignature|null } |
  { kind: "pointer", pointee: ObjCEncodedType } |
  { kind: "array", count: u64, element: ObjCEncodedType } |
  { kind: "record", record_kind: RecordKind, name: string|null,
    fields: [ObjCEncodedType] } |
  { kind: "bitfield", width: u32 } |
  { kind: "unknown", raw: bytes }
ObjCGraph = { nodes: [ObjCGraphNode], inheritance: [ObjCGraphEdge],
              conformances: [ObjCGraphEdge], categories: [ObjCGraphEdge],
              selector_owners: [ObjCSelectorOwner] }
ObjCGraphNode = { entity_id: ObjCEntityId, presence: ObjCPresence }
ObjCGraphEdge = { from: ObjCEntityId, to: ObjCEntityId,
                  kind: ObjCGraphEdgeKind }
ObjCSelectorOwner = { selector: Selector, method_kind: MethodKind,
                      effective_owner: ObjCEntityId|null,
                      candidates: [ObjCMemberId] }
ObjCDiagnostic = { id: ObjCDiagnosticId, code: ObjCDiagnosticCode,
                   severity: Severity, message: string,
                   observation_id: ObjCObservationId|null,
                   entity_id: ObjCEntityId|null,
                   evidence_ids: [ObjCEvidenceId] }
ObjCHeaderProjection = { declarations: [HeaderDecl],
                         unresolved: [ObjCHeaderGap], source: string,
                         validation: HeaderValidationReport }
ObjCHeaderGap = { entity_id: ObjCEntityId, member_id: ObjCMemberId|null,
                  reason: ObjCUnavailableReason,
                  diagnostic_ids: [ObjCDiagnosticId] }
```

| Enum | Exact values |
| --- | --- |
| `ObjCPresence` | `defined`, `referenced`, `partial` |
| `ObjCCollectorId` | `runtime_metadata`, `semantic_graph`, `header_projection` |
| `ObjCEvidenceKind` | `class_ro`, `category`, `protocol`, `method_list`, `property_list`, `ivar_list`, `class_ref`, `protocol_ref`, `selector_ref` |
| `ObjCObservationSource` | `class_list`, `category_list`, `protocol_list`, `class_refs`, `protocol_refs`, `selector_refs` |
| `ObjCExclusionReason` | `unselected_class`, `unselected_selector`, `duplicate_alias`, `non_objective_c_record` |
| `ObjCUnavailableReason` | `not_encoded`, `malformed_encoding`, `unresolved_reference`, `ambiguous_owner`, `conflicting_metadata`, `truncated`, `unsupported_encoding`, `semantic_validation_failed` |
| `ObjCDiagnosticCode` | `malformed_metadata`, `malformed_encoding`, `selector_arity_mismatch`, `ambiguous_category_order`, `graph_cycle`, `unresolved_reference`, `conflicting_metadata`, `collector_failed`, `collector_truncated`, `header_syntax_invalid`, `header_semantic_invalid` |
| `ObjCPrimitive` | `void`, `char`, `unsigned_char`, `short`, `unsigned_short`, `int`, `unsigned_int`, `long`, `unsigned_long`, `long_long`, `unsigned_long_long`, `int128`, `unsigned_int128`, `float`, `double`, `long_double`, `bool`, `cstring`, `unknown_object` |
| `ObjCQualifier` | `const`, `in`, `inout`, `out`, `bycopy`, `byref`, `oneway`, `atomic` |
| `ObjCOwnership` | `assign`, `copy`, `retain`, `strong`, `weak`, `unsafe_unretained`, `unspecified` |
| `ObjCPropertyAttribute` | `readonly`, `readwrite`, `copy`, `retain`, `strong`, `weak`, `assign`, `atomic`, `nonatomic`, `dynamic`, `class` |
| `MethodKind` | `instance`, `class` |
| `ObjCGraphEdgeKind` | `superclass`, `adopts_protocol`, `extends_class` |

## Swift report registry

`SwiftSliceReport` adds `evidence: Vec<SwiftEvidence>` between observations and
entities. Every `SwiftValue<T>` evidence ID must resolve in that array.

```text
SwiftPartitionCounts = { metadata_defined: u64, referenced: u64,
                         symbol_only: u64, partial: u64, unknown: u64,
                         excluded_observations: u64 }
SwiftEvidence = { id: SwiftEvidenceId,
                  observation_ids: NonEmpty<SwiftObservationId>,
                  kind: SwiftEvidenceKind,
                  location: SwiftMetadataLocation|null, raw: bytes }
SwiftQualifiedName = { module: string|null, path: NonEmpty<string> }
SwiftDescriptorLocation = { virtual_address: u64, file_offset: u64|null,
                            section: SectionIdentity, relative_offset: i64|null }
SwiftMetadataLocation = SwiftDescriptorLocation
SwiftEntityRef = { entity_id: SwiftEntityId|null,
                   qualified_name: SwiftQualifiedName|null }
SwiftField = { name: string|null, mangled_type: bytes|null,
               type_name: string|null, flags: u32 }
SwiftConformanceRef = { protocol: SwiftEntityRef,
                        type: SwiftEntityRef|null,
                        descriptor: SwiftDescriptorLocation|null }
SwiftGap = { id: SwiftGapId, field: SwiftFieldName,
             reason: SwiftUnavailableReason,
             evidence_ids: [SwiftEvidenceId] }
SwiftDiagnostic = { id: SwiftDiagnosticId, code: SwiftDiagnosticCode,
                    severity: Severity, message: string,
                    observation_id: SwiftObservationId|null,
                    entity_id: SwiftEntityId|null,
                    evidence_ids: [SwiftEvidenceId] }
```

| Enum | Exact values |
| --- | --- |
| `SwiftEntityState` | `metadata_defined`, `referenced`, `symbol_only`, `partial`, `unknown` |
| `SwiftCollectorId` | `metadata_descriptors`, `reflection_metadata`, `symbol_demangling`, `reconciliation` |
| `SwiftTypeKind` | `class`, `struct`, `enum`, `protocol`, `type_alias`, `opaque`, `unknown` |
| `SwiftEvidenceKind` | `context_descriptor`, `field_descriptor`, `protocol_descriptor`, `conformance_descriptor`, `associated_type_descriptor`, `reflection_string`, `demangled_symbol` |
| `SwiftObservationSource` | `type_metadata`, `protocols`, `conformances`, `fields`, `associated_types`, `reflection_strings`, `nlist`, `export_trie` |
| `SwiftExclusionReason` | `not_swift`, `unselected_kind`, `duplicate_alias`, `unsupported_record_kind` |
| `SwiftUnavailableReason` | `not_encoded`, `malformed_descriptor`, `unsupported_descriptor`, `unsupported_mangling`, `unresolved_reference`, `ambiguous_identity`, `collector_failed`, `truncated` |
| `SwiftDiagnosticCode` | `malformed_descriptor`, `unsupported_descriptor`, `malformed_mangling`, `unsupported_mangling`, `unresolved_reference`, `ambiguous_identity`, `conflicting_metadata`, `collector_failed`, `collector_truncated` |
| `SwiftFieldName` | `kind`, `qualified_name`, `descriptor`, `parent`, `fields_or_cases`, `conformances` |

## Offline hypothesis registry

`HypothesisLimits` has exactly the seven fields and bounds below. Values are
serialized as bytes, not human unit strings.

| Field | Default | Hard maximum |
| --- | ---: | ---: |
| `max_target_entities` | 512 | 4,096 |
| `max_fact_excerpts` | 8,192 | 32,768 |
| `max_evidence_excerpts` | 4,096 | 16,384 |
| `max_bundle_bytes` | 1,048,576 | 4,194,304 |
| `max_prompt_bytes` | 1,048,576 | 2,097,152 |
| `max_response_bytes` | 1,048,576 | 2,097,152 |
| `max_rendered_header_bytes` | 1,048,576 | 2,097,152 |

| Enum | Exact values |
| --- | --- |
| `HypothesisOperationKind` | `choose_candidate`, `propose_canonical_name`, `propose_declaration_fragment`, `propose_grouping` |
| `HypothesisDiagnosticCode` | `schema_version_mismatch`, `bundle_digest_mismatch`, `duplicate_hypothesis`, `duplicate_gap_operation`, `dangling_reference`, `operation_not_allowed`, `pinned_fact_change`, `invalid_identifier`, `unsupported_header_fragment`, `header_syntax_invalid`, `header_semantic_invalid`, `limit_exceeded` |
| `HypothesisDisposition` | `accepted`, `rejected`, `unresolved` |

```text
HypothesisDiagnostic = { code: HypothesisDiagnosticCode,
                         severity: Severity, message: string,
                         hypothesis_id: HypothesisId|null }
HeaderSubsetVersion = 1
HeaderOwnerRef       = the common type above
HeaderSyntaxFragmentWire = HeaderDecl
CanonicalJsonValue  = the common source-equality-constrained subtree above
```

The `HypothesisOperation` tags are the `HypothesisOperationKind` spellings.
`choose_candidate` carries `candidate_index: u32`; `propose_canonical_name`
carries `name: Identifier`; `propose_declaration_fragment` carries
`fragment: HeaderDecl`; and `propose_grouping` carries `owner: HeaderOwnerRef`.

## Snapshot payload registry

Snapshot schema 3 has one `DomainPayload` variant per exact Plan 15 domain ID.
Each variant uses `{ "kind": DOMAIN_ID, "report_schema": 1, "report": VALUE }`.
The domain key and `kind` must match. The language-domain values are the reports
defined by this contract: `objc` is `ObjCReport`, `swift` is `SwiftReport`,
`c_surface` and `cpp_surface` are `RecoveryReport`, and `objc_headers` is an
`ObjCHeaderProjection` paired with its source `ObjCReport` digest.

For the remaining schema-2 domains, `VALUE` is the existing validated owned DTO
for that exact domain moved to its Plan 15 owner without field or spelling
changes. WP0 must generate one schema golden per domain from the committed
deterministic fixtures and record its SHA-256 in the live ledger before any DTO
move. A changed golden is a schema-version decision, not an incidental refactor.
This rule preserves the already-implemented payload contract while schema 3
changes the wrapper, state accounting, and language recovery payloads.

The exact variant registry is: `container`, `header`, `load_commands`,
`segments`, `relocations`, `symbols`, `exports`, `imports`, `fixups`, `codesign`,
`objc`, `swift`, `dwarf`, `vtables`, `strings`, `ranges`, `xrefs`,
`dependencies`, `audit`, `c_surface`, `cpp_surface`, and `objc_headers`.

## Required schema verification

The implementation must add a schema registry test that enumerates every type
and spelling in this document and fails on additions, omissions, or renames.
Each root artifact has canonical-JSON golden fixtures for thin and fat inputs,
plus rejection fixtures for: unknown/duplicate/missing keys, unknown enum tags,
bad ID/hash/byte encoding, dangling IDs, duplicate IDs, invalid collection
cardinality, conservation mismatch, over-limit input, wrong nested schema
version, and non-canonical digest input. The verifier must compare the
implemented registry to this document and must not rewrite either side.
