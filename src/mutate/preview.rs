use crate::Result;
use crate::analysis::diff::{DiffReport, diff_slice_snapshots};
use crate::analysis::snapshot::SliceSnapshot;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::model::validate;
use crate::mutate::patch::PatchOp;
use crate::mutate::resign::ResignPlan;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PatchPreview {
    pub operations: Vec<String>,
    pub old_command_count: usize,
    pub new_command_count: usize,
    pub validation_errors: Vec<String>,
    pub validation_warnings: Vec<String>,
    pub semantic_diff: DiffReport,
    pub signature_outcome: SignatureOutcome,
    pub resign_plan: Option<ResignPlan>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SignatureOutcome {
    Unchanged,
    Invalidated,
    Removed,
}

pub fn build_preview(
    original_mach: &MachoFile<'_>,
    candidate_bytes: &[u8],
    candidate_mach: &MachoFile<'_>,
    ops: &[PatchOp],
) -> Result<PatchPreview> {
    let original_commands: Vec<LoadCommand> = original_mach
        .load_commands()
        .iter()
        .map(|lc| lc.kind.clone())
        .collect();
    let candidate_commands: Vec<LoadCommand> = candidate_mach
        .load_commands()
        .iter()
        .map(|lc| lc.kind.clone())
        .collect();

    let semantic_diff = diff_slice_snapshots(
        &SliceSnapshot::from_macho(original_mach),
        &SliceSnapshot::from_macho(candidate_mach),
    );

    let diags = validate::validate(candidate_mach);
    let errors: Vec<String> = diags
        .iter()
        .filter(|d| d.severity == validate::Severity::Error)
        .map(|d| format!("{}: {}", d.code.0, d.message))
        .collect();
    let warnings: Vec<String> = diags
        .iter()
        .filter(|d| d.severity == validate::Severity::Warning)
        .map(|d| format!("{}: {}", d.code.0, d.message))
        .collect();

    let original_signed = has_code_signature(original_mach);
    let candidate_signed = has_code_signature(candidate_mach);
    let signature_changed = candidate_commands != original_commands
        || byte_patches_changed(original_mach.bytes(), candidate_bytes, ops);
    let signature_outcome = if original_signed && !candidate_signed {
        SignatureOutcome::Removed
    } else if original_signed && signature_changed {
        SignatureOutcome::Invalidated
    } else {
        SignatureOutcome::Unchanged
    };

    let resign_plan = if matches!(
        signature_outcome,
        SignatureOutcome::Invalidated | SignatureOutcome::Removed
    ) {
        Some(ResignPlan::from_mach(original_mach))
    } else {
        None
    };

    Ok(PatchPreview {
        operations: ops.iter().map(|op| op.to_string()).collect(),
        old_command_count: original_commands.len(),
        new_command_count: candidate_commands.len(),
        validation_errors: errors,
        validation_warnings: warnings,
        semantic_diff,
        signature_outcome,
        resign_plan,
    })
}

fn has_code_signature(macho: &MachoFile<'_>) -> bool {
    macho
        .load_commands()
        .iter()
        .any(|lc| matches!(lc.kind, LoadCommand::CodeSignature(_)))
}

fn byte_patches_changed(original: &[u8], candidate: &[u8], ops: &[PatchOp]) -> bool {
    for op in ops {
        if let PatchOp::PatchBytes { offset, bytes } = op {
            let Ok(start) = usize::try_from(*offset) else {
                return true;
            };
            let end = start.saturating_add(bytes.len());
            if end > original.len() || end > candidate.len() {
                return true;
            }
            if original[start..end] != candidate[start..end] {
                return true;
            }
        }
    }
    false
}
