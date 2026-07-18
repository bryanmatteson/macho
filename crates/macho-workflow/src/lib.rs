#![deny(missing_docs)]
//! Cross-layer semantic mutation workflow contracts.

use macho_analysis::diff::{DiffReport, diff_documents};
use macho_analysis::{AnalysisPlan, Analyzer};
use macho_mutate::preview::StructuralPatchPreview;
use macho_mutate::{
    PatchPlan, PatchTransaction, SignatureKind, SignatureProvider, SignatureProviderError,
    SignatureRequest,
};

/// Stage at which a semantic patch workflow failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkflowStage {
    /// Strict parsing of the original bytes.
    ParseBefore,
    /// Selected analysis of the original image.
    AnalyzeBefore,
    /// Structural patch planning or application.
    Mutate,
    /// Optional injected signing.
    Sign,
    /// Strict parsing and validation of candidate bytes.
    ValidateAfter,
    /// Selected analysis of the candidate image.
    AnalyzeAfter,
    /// Semantic diff construction.
    Diff,
}

/// Typed source layer retained by a workflow failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum WorkflowErrorSource {
    /// Core strict-parse failure.
    #[error(transparent)]
    Parse(#[from] macho_core::ParseError),
    /// Selective-analysis failure.
    #[error(transparent)]
    Analysis(#[from] macho_analysis::AnalysisError),
    /// Structural mutation failure.
    #[error(transparent)]
    Mutation(#[from] macho_mutate::MutationError),
    /// Injected signing failure.
    #[error(transparent)]
    Signing(#[from] SignatureProviderError),
}

/// Typed workflow failure retaining its stage and source layer.
#[derive(Debug, thiserror::Error)]
#[error("workflow failed during {stage:?}: {source}")]
pub struct WorkflowError {
    /// Stage that failed.
    pub stage: WorkflowStage,
    /// Typed source category and context.
    #[source]
    pub source: WorkflowErrorSource,
}

/// Combined structural and semantic preview returned before filesystem commit.
#[derive(Debug, Clone)]
pub struct WorkflowPreview {
    /// Structural byte/layout/signing consequences.
    pub structural: StructuralPatchPreview,
    /// Selected semantic difference report.
    pub semantic: DiffReport,
}

/// Verified in-memory workflow result. The caller alone chooses filesystem
/// replacement and backup policy.
#[derive(Debug, Clone)]
pub struct WorkflowResult {
    /// Combined structural and semantic preview.
    pub preview: WorkflowPreview,
    /// Strictly reparsed candidate bytes.
    pub bytes: Vec<u8>,
}

/// Optional signing capability and request applied before after-analysis.
pub struct WorkflowSigning<'a> {
    /// Injected provider; the workflow never discovers host tools.
    pub provider: &'a dyn SignatureProvider,
    /// Explicit signing request.
    pub request: &'a SignatureRequest,
}

/// Execute the complete in-memory semantic patch workflow.
pub fn execute(
    original: &[u8],
    patch_plan: &PatchPlan,
    analysis_plan: &AnalysisPlan,
    signing: Option<WorkflowSigning<'_>>,
) -> Result<WorkflowResult, WorkflowError> {
    let before_container = macho_core::parse(original).map_err(|source| WorkflowError {
        stage: WorkflowStage::ParseBefore,
        source: source.into(),
    })?;
    let before_document = Analyzer
        .run(&before_container, analysis_plan)
        .map_err(|source| WorkflowError {
            stage: WorkflowStage::AnalyzeBefore,
            source: source.into(),
        })?;
    let before_image = before_container
        .first_macho()
        .ok_or_else(|| WorkflowError {
            stage: WorkflowStage::ParseBefore,
            source: macho_core::ParseError::format("container has no Mach-O image").into(),
        })?;

    patch_plan
        .validate(before_image.bytes())
        .map_err(|source| WorkflowError {
            stage: WorkflowStage::Mutate,
            source: source.into(),
        })?;
    let mut transaction = PatchTransaction::new(before_image);
    for operation in patch_plan.operations() {
        transaction.add_op(operation.clone());
    }
    let prepared = transaction.prepare().map_err(|source| WorkflowError {
        stage: WorkflowStage::Mutate,
        source: source.into(),
    })?;

    let (candidate, signing_kind) = if let Some(signing) = signing {
        let kind = signing.provider.kind();
        let bytes = signing
            .provider
            .sign(&prepared.bytes, signing.request)
            .map_err(|source| WorkflowError {
                stage: WorkflowStage::Sign,
                source: source.into(),
            })?;
        (bytes, Some(kind))
    } else {
        (prepared.bytes, None)
    };
    let after_container = macho_core::parse(&candidate).map_err(|source| WorkflowError {
        stage: WorkflowStage::ValidateAfter,
        source: source.into(),
    })?;
    let validation_errors = after_container
        .macho_files()
        .flat_map(macho_core::model::validate::validate)
        .filter(|diagnostic| diagnostic.severity == macho_core::model::validate::Severity::Error)
        .map(|diagnostic| format!("{}: {}", diagnostic.code.0, diagnostic.message))
        .collect::<Vec<_>>();
    if !validation_errors.is_empty() {
        return Err(WorkflowError {
            stage: WorkflowStage::ValidateAfter,
            source: macho_core::ParseError::format(format!(
                "candidate failed structural validation: {}",
                validation_errors.join("; ")
            ))
            .into(),
        });
    }
    let after_document = Analyzer
        .run(&after_container, analysis_plan)
        .map_err(|source| WorkflowError {
            stage: WorkflowStage::AnalyzeAfter,
            source: source.into(),
        })?;
    let semantic = diff_documents(&before_document, &after_document, analysis_plan.domains());

    let mut structural = prepared.preview;
    if let Some(kind) = signing_kind {
        structural.signature_outcome = match kind {
            SignatureKind::AdHoc => macho_mutate::preview::SignatureOutcome::SignedAdHoc,
            SignatureKind::Certificate => {
                macho_mutate::preview::SignatureOutcome::SignedCertificate
            }
        };
        structural.resign_plan = None;
    }

    Ok(WorkflowResult {
        preview: WorkflowPreview {
            structural,
            semantic,
        },
        bytes: candidate,
    })
}

/// Assemble a preview from independently verified structural and semantic parts.
pub fn preview_from_parts(
    structural: StructuralPatchPreview,
    semantic: DiffReport,
) -> WorkflowPreview {
    WorkflowPreview {
        structural,
        semantic,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use macho_analysis::AnalysisDomain;
    use macho_mutate::PatchOp;

    struct IdentitySigner;

    impl SignatureProvider for IdentitySigner {
        fn sign(
            &self,
            bytes: &[u8],
            _request: &SignatureRequest,
        ) -> Result<Vec<u8>, SignatureProviderError> {
            Ok(bytes.to_vec())
        }

        fn kind(&self) -> SignatureKind {
            SignatureKind::AdHoc
        }
    }

    struct InvalidSigner;

    impl SignatureProvider for InvalidSigner {
        fn sign(
            &self,
            _bytes: &[u8],
            _request: &SignatureRequest,
        ) -> Result<Vec<u8>, SignatureProviderError> {
            Ok(vec![0, 0, 0, 0])
        }

        fn kind(&self) -> SignatureKind {
            SignatureKind::AdHoc
        }
    }

    fn no_op_plan() -> PatchPlan {
        PatchPlan::new(vec![PatchOp::PatchBytes {
            offset: 0,
            bytes: Vec::new(),
        }])
    }

    #[test]
    fn selected_semantic_workflow_returns_verified_bytes() {
        let input = macho_test_support::thin64_arm64(2);
        let analysis = AnalysisPlan::new([AnalysisDomain::Header]);
        let request = SignatureRequest::default();
        let result = execute(
            &input,
            &no_op_plan(),
            &analysis,
            Some(WorkflowSigning {
                provider: &IdentitySigner,
                request: &request,
            }),
        )
        .expect("workflow succeeds");
        macho_core::parse(&result.bytes).expect("workflow returns strictly valid bytes");
        assert!(result.preview.semantic.findings.is_empty());
        assert_eq!(
            result.preview.structural.signature_outcome,
            macho_mutate::preview::SignatureOutcome::SignedAdHoc
        );
        assert!(result.preview.structural.resign_plan.is_none());
    }

    #[test]
    fn invalid_signer_output_fails_before_commit() {
        let input = macho_test_support::thin64_arm64(2);
        let analysis = AnalysisPlan::new([AnalysisDomain::Header]);
        let request = SignatureRequest::default();
        let error = execute(
            &input,
            &no_op_plan(),
            &analysis,
            Some(WorkflowSigning {
                provider: &InvalidSigner,
                request: &request,
            }),
        )
        .expect_err("invalid signed bytes must fail");
        assert_eq!(error.stage, WorkflowStage::ValidateAfter);
    }

    #[test]
    fn analysis_failure_prevents_mutation_stage() {
        let input = macho_test_support::thin64_arm64(2);
        let analysis =
            AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["x86_64".to_owned()]);
        let error = execute(&input, &no_op_plan(), &analysis, None)
            .expect_err("missing selected architecture must fail");
        assert_eq!(error.stage, WorkflowStage::AnalyzeBefore);
    }
}
