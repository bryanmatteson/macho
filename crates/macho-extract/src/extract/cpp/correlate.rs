use crate::extract::cpp::types::{
    CppConfidence, CppFunctionDecl, CppHeaderMatch, CppType, QualifiedName,
};

pub trait ExternalHeaderIndex {
    fn match_function(
        &self,
        qualified_name: &QualifiedName,
        params: &[CppType],
    ) -> Option<HeaderCandidate>;
}

#[derive(Debug, Clone)]
pub struct HeaderCandidate {
    pub declaration: String,
    pub header: String,
    pub confidence: CppConfidence,
}

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
