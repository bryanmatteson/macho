# Diagnostic code registry

Diagnostic codes are stable lowercase dotted identifiers. Each code has one
declaring crate; the table records its default severity and field meaning.
`cargo xtask docs --check` rejects duplicate declarations, duplicate rows,
unregistered constants, and rows without an owning constant.

| Code | Severity | Meaning |
| --- | --- | --- |
| `analysis.capability.unsupported` | error | A requested analysis domain is unavailable for the selected input or build. |
| `analysis.codesign.failed` | error | Code-signature analysis failed while retaining its typed source. |
| `analysis.cpp.failed` | error | C++ metadata analysis failed while retaining its typed source. |
| `analysis.dependency.advisory_failed` | warning | An advisory prerequisite failed and analysis continued. |
| `analysis.dependency.advisory_unsupported` | warning | An advisory prerequisite was unavailable and analysis continued. |
| `analysis.dependency.required_failed` | error | A required prerequisite did not complete. |
| `analysis.disassembly.address.cross_section` | error | An explicit address range crosses its file-backed section. |
| `analysis.disassembly.address.unaligned` | error | A selected ARM instruction start is not four-byte aligned. |
| `analysis.disassembly.address.unmapped` | error | A selected virtual address is outside file-backed section bytes. |
| `analysis.disassembly.arch.ambiguous` | error | A display architecture name matches more than one raw CPU tuple. |
| `analysis.disassembly.arch.unsupported` | error | A selected raw CPU tuple is absent or unsupported by the decoder. |
| `analysis.disassembly.count.unsatisfied` | error | Natural section end was reached before the requested instruction count. |
| `analysis.disassembly.output.failed` | error | Streamed disassembly output could not be written to its destination. |
| `analysis.disassembly.report.invalid` | error | A schema-version-1 disassembly report is internally inconsistent. |
| `analysis.disassembly.request.invalid` | error | A disassembly request has an invalid cross-field combination. |
| `analysis.disassembly.section.invalid` | error | An exact section selector is malformed. |
| `analysis.disassembly.section.missing` | error | An exact selected section is absent or not file-backed. |
| `analysis.disassembly.selection.partial_instruction` | error | A caller-selected byte end falls inside a valid instruction. |
| `analysis.disassembly.symbol.ambiguous` | error | An exact raw symbol name resolves to multiple virtual addresses. |
| `analysis.disassembly.symbol.metadata_invalid` | error | Metadata required to prove symbol ownership is malformed. |
| `analysis.disassembly.symbol.missing` | error | An exact raw symbol name is absent from nlist and export authorities. |
| `analysis.disassembly.symbol.non_code` | error | An exact selected symbol is not backed by an instruction section. |
| `analysis.domain.type_mismatch` | error | A typed report key was applied to a payload from another analysis domain. |
| `analysis.dwarf.failed` | error | DWARF analysis failed while retaining its typed source. |
| `analysis.dyld.failed` | error | Dyld analysis failed while retaining its typed source. |
| `analysis.exports.failed` | warning | Export extraction failed and the selected domain returned an issue. |
| `analysis.fixups.failed` | warning | Chained-fixup extraction failed and the selected domain returned an issue. |
| `analysis.imports.failed` | warning | Import extraction failed and the selected domain returned an issue. |
| `analysis.input.invalid` | error | The analysis input or selection is invalid. |
| `analysis.limit.truncated` | warning | A configured per-slice collection limit truncated a complete domain value. |
| `analysis.objc.failed` | error | Objective-C metadata analysis failed while retaining its typed source. |
| `analysis.parse.failed` | error | Analysis could not consume the typed parser result. |
| `analysis.swift.failed` | error | Swift metadata analysis failed while retaining its typed source. |
| `analysis.symbols.failed` | error | Symbol analysis failed while retaining its typed source. |
| `analysis.validation.failed` | error | An analysis result could not be validated or serialized. |
| `cli.execution.failed` | error | A delivery-layer command failed during execution or rendering. |
| `cli.input.failed` | error | The CLI could not map, parse, or select the requested input. |
| `cli.policy.threshold` | error | A completed report crossed a caller-selected policy threshold. |
| `cli.usage.invalid_arguments` | error | Command-line arguments do not satisfy the live command grammar. |
| `cli.usage.color_machine` | error | Explicit color was requested for JSON or SARIF output. |
| `cli.usage.unsupported_format` | error | The selected command does not support the requested output format. |
| `codesign.address.invalid` | error | Code-signature metadata contains an address or offset that cannot be mapped safely. |
| `codesign.bounds.exceeded` | error | Code-signature metadata references bytes outside the bounded input. |
| `codesign.core.failed` | error | Code-signature parsing failed through a retained core parser source. |
| `codesign.format.invalid` | error | Code-signature metadata is malformed or internally inconsistent. |
| `codesign.input.unsupported` | error | Structurally valid code-signature metadata uses an unsupported form. |
| `cpp.address.invalid` | error | C++ metadata contains an address or offset that cannot be mapped safely. |
| `cpp.bounds.exceeded` | error | C++ metadata references bytes outside the bounded input. |
| `cpp.core.failed` | error | C++ metadata parsing failed through a retained core parser source. |
| `cpp.dyld.failed` | error | C++ metadata parsing failed through a retained dyld source. |
| `cpp.format.invalid` | error | C++ metadata is malformed or internally inconsistent. |
| `cpp.input.unsupported` | error | Structurally valid C++ metadata uses an unsupported form. |
| `dwarf.address.invalid` | error | DWARF metadata contains an address or offset that cannot be mapped safely. |
| `dwarf.bounds.exceeded` | error | DWARF metadata references bytes outside the bounded input. |
| `dwarf.core.failed` | error | DWARF parsing failed through a retained core parser source. |
| `dwarf.format.invalid` | error | DWARF metadata is malformed or internally inconsistent. |
| `dwarf.input.unsupported` | error | Structurally valid DWARF metadata uses an unsupported form. |
| `dyld.address.invalid` | error | Dyld metadata contains an address or offset that cannot be mapped safely. |
| `dyld.bounds.exceeded` | error | Dyld metadata references bytes outside the bounded input. |
| `dyld.core.failed` | error | Dyld parsing failed through a retained core parser source. |
| `dyld.format.invalid` | error | Dyld metadata is malformed or internally inconsistent. |
| `dyld.input.unsupported` | error | Structurally valid dyld metadata uses an unsupported form. |
| `dyld_cache.address.invalid` | error | A shared-cache address or offset cannot be mapped safely. |
| `dyld_cache.bounds.exceeded` | error | Shared-cache metadata references bytes outside the bounded input. |
| `dyld_cache.core.failed` | error | Shared-cache parsing failed through a retained core parser source. |
| `dyld_cache.format.invalid` | error | Shared-cache metadata is malformed or internally inconsistent. |
| `dyld_cache.input.unsupported` | error | A structurally valid shared cache uses an unsupported form. |
| `insn.decode.invalid` | error | Instruction bytes could not be decoded for the selected architecture. |
| `insn.encode.invalid` | error | An instruction could not be encoded or relocated safely. |
| `mutation.bounds.exceeded` | error | A mutation requested bytes outside the bounded image. |
| `mutation.codesign.failed` | error | Mutation failed through a retained code-signature source. |
| `mutation.input.invalid` | error | A patch or mutation request is invalid. |
| `mutation.parse.failed` | error | Mutation failed through a retained core parser source. |
| `mutation.unsupported` | error | A valid mutation request requires a structural rewrite that is not modeled safely. |
| `mutation.validation.failed` | error | A candidate mutation failed structural validation. |
| `objc.address.invalid` | error | Objective-C metadata contains an address or offset that cannot be mapped safely. |
| `objc.bounds.exceeded` | error | Objective-C metadata references bytes outside the bounded input. |
| `objc.core.failed` | error | Objective-C parsing failed through a retained core parser source. |
| `objc.format.invalid` | error | Objective-C metadata is malformed or internally inconsistent. |
| `objc.input.unsupported` | error | Structurally valid Objective-C metadata uses an unsupported form. |
| `parse.address.invalid` | error | A parsed address or offset cannot be mapped safely. |
| `parse.bounds.exceeded` | error | A byte range lies outside the bounded input. |
| `parse.format.invalid` | error | Input does not encode a recognized or internally consistent format. |
| `parse.input.unsupported` | error | Structurally valid input uses an unsupported format feature. |
| `parse.limit.exceeded` | error | Input-derived structure exceeded a configured parse limit. |
| `parse.load_command.invalid` | error | A load command is malformed within its bounded command region. |
| `parse.validation.duplicate_segment` | warning | Structural validation found a duplicate segment name. |
| `parse.validation.failed` | error | Strict parsing rejected an error-severity structural diagnostic. |
| `parse.validation.header_command_count` | error | The header command count differs from the parsed command count. |
| `parse.validation.header_command_size` | error | The header command-byte total differs from the parsed command sizes. |
| `parse.validation.pagezero_file_size` | error | `__PAGEZERO` has a nonzero file-backed size. |
| `parse.validation.protection_mismatch` | warning | Initial segment protections contain bits absent from maximum protections. |
| `parse.validation.section_bounds` | warning | A non-zerofill section lies outside its containing file-backed segment. |
| `parse.validation.segment_bounds` | error | A file-backed segment lies outside the image bytes. |
| `parse.validation.segment_overlap` | error | Two segments have overlapping virtual-address ranges. |
| `parse.validation.string_table_bounds` | error | The string table lies outside the image or overflows checked arithmetic. |
| `parse.validation.symbol_table_bounds` | error | The symbol table lies outside the image or overflows checked arithmetic. |
| `patch.bounds.exceeded` | error | An executable patch range lies outside its admitted byte buffer. |
| `patch.input.invalid` | error | An executable hook, trampoline, or relocation request is invalid. |
| `patch.instruction.failed` | error | Executable patch planning failed through a retained instruction decode or encode source. |
| `swift.address.invalid` | error | Swift metadata contains an address or offset that cannot be mapped safely. |
| `swift.bounds.exceeded` | error | Swift metadata references bytes outside the bounded input. |
| `swift.core.failed` | error | Swift metadata parsing failed through a retained core parser source. |
| `swift.format.invalid` | error | Swift metadata is malformed or internally inconsistent. |
| `swift.input.unsupported` | error | Structurally valid Swift metadata uses an unsupported form. |
| `symbols.address.invalid` | error | Symbol metadata contains an address or offset that cannot be mapped safely. |
| `symbols.bounds.exceeded` | error | Symbol metadata references bytes outside the bounded input. |
| `symbols.core.failed` | error | Symbol parsing failed through a retained core parser source. |
| `symbols.format.invalid` | error | Symbol metadata is malformed or internally inconsistent. |
| `symbols.input.unsupported` | error | Structurally valid symbol metadata uses an unsupported form. |
