//! Format-local, in-memory mutation validation contracts.
//!
//! This module composes Mach-O parsing, analysis, mutation, optional signing,
//! reparsing, and before/after diffing for one candidate. It owns no persisted
//! investigation, review policy, apply history, undo/rollback store, or
//! cross-format orchestration; callers retain those product-level concerns.

use crate::analysis::diff::{DiffReport, diff_documents};
use crate::analysis::{AnalysisPlan, Analyzer};
use crate::mutate::preview::StructuralPatchPreview;
use crate::mutate::{
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
    Parse(#[from] crate::core::ParseError),
    /// Selective-analysis failure.
    #[error(transparent)]
    Analysis(#[from] crate::analysis::AnalysisError),
    /// Structural mutation failure.
    #[error(transparent)]
    Mutation(#[from] crate::mutate::MutationError),
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
    patch_plan: &PatchPlan<'_>,
    analysis_plan: &AnalysisPlan,
    signing: Option<WorkflowSigning<'_>>,
) -> Result<WorkflowResult, WorkflowError> {
    let before_container = crate::core::parse(original).map_err(|source| WorkflowError {
        stage: WorkflowStage::ParseBefore,
        source: source.into(),
    })?;
    let crate::core::model::MachoContainer::Thin(before_image) = &before_container else {
        return Err(WorkflowError {
            stage: WorkflowStage::ParseBefore,
            source: crate::core::ParseError::format(
                "in-memory mutation workflow requires one selected thin Mach-O; select and rebuild a universal slice explicitly",
            )
            .into(),
        });
    };
    let before_document = Analyzer
        .run(&before_container, analysis_plan)
        .map_err(|source| WorkflowError {
            stage: WorkflowStage::AnalyzeBefore,
            source: source.into(),
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
    let after_container = crate::core::parse(&candidate).map_err(|source| WorkflowError {
        stage: WorkflowStage::ValidateAfter,
        source: source.into(),
    })?;
    let validation_errors = after_container
        .macho_files()
        .flat_map(crate::core::model::validate::validate)
        .filter(|diagnostic| diagnostic.severity == crate::core::model::validate::Severity::Error)
        .map(|diagnostic| format!("{}: {}", diagnostic.code.0, diagnostic.message))
        .collect::<Vec<_>>();
    if !validation_errors.is_empty() {
        return Err(WorkflowError {
            stage: WorkflowStage::ValidateAfter,
            source: crate::core::ParseError::format(format!(
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
            SignatureKind::AdHoc => crate::mutate::preview::SignatureOutcome::SignedAdHoc,
            SignatureKind::Certificate => {
                crate::mutate::preview::SignatureOutcome::SignedCertificate
            }
            _ => crate::mutate::preview::SignatureOutcome::SignedOpaque,
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
