use super::types::{CppConfidence, CppFunctionDecl, CppHeaderMatch, CppType, QualifiedName};

/// The ExternalHeaderIndex type.
pub trait ExternalHeaderIndex {
    /// Performs match_function.
    fn match_function(
        &self,
        qualified_name: &QualifiedName,
        params: &[CppType],
    ) -> Option<HeaderCandidate>;
}

#[derive(Debug, Clone)]
/// The HeaderCandidate type.
pub struct HeaderCandidate {
    /// The declaration field.
    pub declaration: String,
    /// The header field.
    pub header: String,
    /// The confidence field.
    pub confidence: CppConfidence,
}

/// Performs correlate_functions.
pub fn correlate_functions(
    functions: &[CppFunctionDecl],
    headers: &dyn ExternalHeaderIndex,
) -> Vec<CppHeaderMatch> {
    functions
        .iter()
        .filter_map(|function| {
            let params: Vec<CppType> = function
                .signature
                .params
                .iter()
                .map(|param| param.ty.clone())
                .collect();
            headers
                .match_function(&function.name, &params)
                .map(|candidate| CppHeaderMatch {
                    declaration: candidate.declaration,
                    header: candidate.header,
                    confidence: candidate.confidence,
                })
        })
        .collect()
}
