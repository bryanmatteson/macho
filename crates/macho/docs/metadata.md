# macho::metadata

Feature-gated read-only Mach-O metadata decoding. Modules cover code signing,
C++, demangling, DWARF, dyld, Objective-C, Swift, and symbols without pulling
analysis, mutation, workflow, or CLI policy into the package.

## Swift advanced evidence checklist

The strict Swift surface retains the following shapes without turning ABI
layout knowledge into runtime truth:

| Shape | Typed public evidence | Regression |
| --- | --- | --- |
| Generic class metadata | `MachoSwiftClassTrailingLayoutV1::generic_context` / `MachoSwiftGenericContextLayoutV1` | Generic counts, argument counts, and descriptor length are decoded before dispatch records. |
| Resilient-superclass layout | `MachoSwiftClassTrailingLayoutV1::{resilient_superclass_descriptor_va,resilient_superclass_type_reference_relative}` | The exact trailing-record address and raw relative type reference are retained. |
| Metadata-initialized class | `MachoSwiftMetadataInitializationLayoutV1::{Singleton,Foreign}` | Singleton and foreign initialization layouts retain each encoded relative pointer and the following dispatch address. |
| Reabstraction thunk | `SwiftMangledEntityEvidence` with `ReabstractionThunk` role and a `SwiftFormalTypeEvidence` | The implementation-function target is decoded, not merely symbol-classified. |
| Generic closure | `SwiftMangledEntityEvidence` with `Closure` kind and generic `SwiftTypeEvidence` | A generic closure retains its generic-parameter formal result. |
| Accessor/function requirements | `SwiftGenericRequirementEvidence::{Conformance,SameType}` on the callable entity | Generic free-function and generic-subscript accessor requirements are retained; setters retain value-parameter/unit-result shape when the demangler exposes the property type. |

Generic implementation-function transforms and layout requirements remain
typed gaps. For generic subscript accessors, the current parser can expose the
generic signature while omitting the property/index formal type; the entity and
requirements are retained with `formal_type: None` rather than fabricating a
signature.
