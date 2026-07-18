//! Closed schema registries used by the implementation and verifier.

/// Exact snapshot schema-3 domain IDs.
pub const DOMAIN_IDS: &[&str] = &[
    "container",
    "header",
    "load_commands",
    "segments",
    "relocations",
    "symbols",
    "exports",
    "imports",
    "fixups",
    "codesign",
    "objc",
    "swift",
    "dwarf",
    "vtables",
    "strings",
    "ranges",
    "xrefs",
    "dependencies",
    "audit",
    "c_surface",
    "cpp_surface",
    "objc_headers",
];

/// Exact recovery diagnostic code spellings.
pub const RECOVERY_DIAGNOSTIC_CODES: &[&str] = &[
    "malformed_known_encoding",
    "conflicting_exact_facts",
    "ambiguous_identity",
    "unmatched_occurrence",
    "collector_unsupported",
    "collector_failed",
    "collector_truncated",
    "header_syntax_invalid",
    "header_semantic_invalid",
    "unsupported_header_syntax",
    "unresolved_required_fact",
];

/// Exact recovery entity-kind spellings.
pub const RECOVERY_ENTITY_KINDS: &[&str] = &[
    "function",
    "data",
    "tls",
    "runtime_artifact",
    "method",
    "type",
    "vtable",
    "typeinfo",
    "thunk",
    "guard",
    "unknown",
];

/// Exact recovery entity-role spellings.
pub const RECOVERY_ENTITY_ROLES: &[&str] = &[
    "function",
    "data",
    "tls",
    "runtime_artifact",
    "cpp_method",
    "cpp_static_data",
    "type",
    "typeinfo",
    "vtable",
    "vtt",
    "thunk",
    "guard",
    "unknown",
];

/// Exact recovery field spellings.
pub const RECOVERY_FIELDS: &[&str] = &[
    "linkage",
    "display_name",
    "role",
    "presence",
    "visibility",
    "weakness",
    "location",
    "owner",
    "value_type",
    "return_type",
    "parameters",
    "variadic",
    "calling_convention",
    "qualifiers",
    "layout_size",
    "layout_alignment",
    "layout_fields",
    "layout_completeness",
    "bases",
    "virtual_surface",
];

/// Exact shared header semantic diagnostic code spellings.
pub const HEADER_VALIDATION_CODES: &[&str] = &[
    "syntax_error",
    "duplicate_declaration",
    "conflicting_redeclaration",
    "unresolved_type",
    "unresolved_owner",
    "invalid_linkage",
    "invalid_storage",
    "invalid_calling_convention",
    "incomplete_template_context",
    "selector_arity_mismatch",
    "objc_kind_mismatch",
    "dependency_cycle",
];

#[cfg(test)]
mod tests {
    use crate::AnalysisDomain;
    use crate::report::{EntityKind, EntityRole, RecoveryField};

    use super::*;

    #[test]
    fn domain_registry_matches_analysis_authority_exactly() {
        assert_eq!(
            AnalysisDomain::ALL
                .iter()
                .map(|domain| domain.as_str())
                .collect::<Vec<_>>(),
            DOMAIN_IDS
        );
    }

    #[test]
    fn header_validation_registry_matches_syntax_authority() {
        use macho_header_syntax::HeaderValidationCode as Code;
        let implemented = [
            Code::SyntaxError,
            Code::DuplicateDeclaration,
            Code::ConflictingRedeclaration,
            Code::UnresolvedType,
            Code::UnresolvedOwner,
            Code::InvalidLinkage,
            Code::InvalidStorage,
            Code::InvalidCallingConvention,
            Code::IncompleteTemplateContext,
            Code::SelectorArityMismatch,
            Code::ObjectiveCKindMismatch,
            Code::DependencyCycle,
        ];
        assert_eq!(implemented.len(), HEADER_VALIDATION_CODES.len());
    }

    #[test]
    fn amended_recovery_registries_match_serde_exactly() {
        let kinds = [
            EntityKind::Function,
            EntityKind::Data,
            EntityKind::Tls,
            EntityKind::RuntimeArtifact,
            EntityKind::Method,
            EntityKind::Type,
            EntityKind::Vtable,
            EntityKind::Typeinfo,
            EntityKind::Thunk,
            EntityKind::Guard,
            EntityKind::Unknown,
        ];
        let roles = [
            EntityRole::Function,
            EntityRole::Data,
            EntityRole::Tls,
            EntityRole::RuntimeArtifact,
            EntityRole::CppMethod,
            EntityRole::CppStaticData,
            EntityRole::Type,
            EntityRole::Typeinfo,
            EntityRole::Vtable,
            EntityRole::Vtt,
            EntityRole::Thunk,
            EntityRole::Guard,
            EntityRole::Unknown,
        ];
        let fields = [
            RecoveryField::Linkage,
            RecoveryField::DisplayName,
            RecoveryField::Role,
            RecoveryField::Presence,
            RecoveryField::Visibility,
            RecoveryField::Weakness,
            RecoveryField::Location,
            RecoveryField::Owner,
            RecoveryField::ValueType,
            RecoveryField::ReturnType,
            RecoveryField::Parameters,
            RecoveryField::Variadic,
            RecoveryField::CallingConvention,
            RecoveryField::Qualifiers,
            RecoveryField::LayoutSize,
            RecoveryField::LayoutAlignment,
            RecoveryField::LayoutFields,
            RecoveryField::LayoutCompleteness,
            RecoveryField::Bases,
            RecoveryField::VirtualSurface,
        ];
        let serialized = |values: serde_json::Value| {
            values
                .as_array()
                .unwrap()
                .iter()
                .map(|value| value.as_str().unwrap().to_owned())
                .collect::<Vec<_>>()
        };
        assert_eq!(
            serialized(serde_json::to_value(kinds).unwrap()),
            RECOVERY_ENTITY_KINDS
        );
        assert_eq!(
            serialized(serde_json::to_value(roles).unwrap()),
            RECOVERY_ENTITY_ROLES
        );
        assert_eq!(
            serialized(serde_json::to_value(fields).unwrap()),
            RECOVERY_FIELDS
        );
    }
}
