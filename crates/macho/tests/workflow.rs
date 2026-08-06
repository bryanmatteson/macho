#![cfg(feature = "workflow")]

use macho::analysis::{AnalysisDomain, AnalysisPlan};
use macho::mutate::{
    PatchOp, PatchPlan, SignatureProvider, SignatureProviderError, SignatureRequest,
};
use macho::workflow::{WorkflowSigning, WorkflowStage, execute};

struct IdentitySigner;

impl SignatureProvider for IdentitySigner {
    fn sign(
        &self,
        bytes: &[u8],
        _request: &SignatureRequest,
    ) -> Result<Vec<u8>, SignatureProviderError> {
        Ok(bytes.to_vec())
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
}

fn no_op_plan() -> PatchPlan<'static> {
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
    macho::parse(&result.bytes).expect("workflow returns strictly valid bytes");
    assert!(result.preview.semantic.findings.is_empty());
    assert_eq!(
        result.preview.structural.signature_outcome,
        macho::mutate::preview::SignatureOutcome::SignedOpaque
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
    let analysis = AnalysisPlan::new([AnalysisDomain::Header]).with_slices(["x86_64".to_owned()]);
    let error = execute(&input, &no_op_plan(), &analysis, None)
        .expect_err("missing selected architecture must fail");
    assert_eq!(error.stage, WorkflowStage::AnalyzeBefore);
}

#[test]
fn universal_input_is_rejected_instead_of_dropping_sibling_slices() {
    let input = macho_test_support::fat32(&[
        (
            macho_test_support::CPU_TYPE_X86_64,
            3,
            macho_test_support::signable_thin64_x86_64(2),
        ),
        (
            macho_test_support::CPU_TYPE_ARM64,
            0,
            macho_test_support::signable_thin64_arm64(2),
        ),
    ]);
    let analysis = AnalysisPlan::new([AnalysisDomain::Header]);
    let error = execute(&input, &no_op_plan(), &analysis, None)
        .expect_err("unselected universal input must not become a thin result");
    assert_eq!(error.stage, WorkflowStage::ParseBefore);
    assert!(error.to_string().contains("one selected thin Mach-O"));
}
