use crate::format::parse;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::mutate::MachoEditor;
pub use crate::mutate::patch::PatchOp;
use crate::mutate::preview::build_structural_preview;
pub use crate::mutate::preview::{SignatureOutcome, StructuralPatchPreview};
use crate::{Error, Result};

/// Validated, owned structural patch plan.
#[derive(Debug, Clone, Default)]
pub struct PatchPlan {
    ops: Vec<PatchOp>,
    expected: Vec<(u64, Vec<u8>)>,
}

impl PatchPlan {
    /// Create a plan from operations. Validation occurs against concrete input
    /// bytes before any candidate buffer is changed.
    pub fn new(ops: Vec<PatchOp>) -> Self {
        Self {
            ops,
            expected: Vec::new(),
        }
    }

    /// Require exact original bytes at a slice-relative file offset.
    pub fn expect_bytes(mut self, offset: u64, bytes: Vec<u8>) -> Self {
        self.expected.push((offset, bytes));
        self
    }

    /// Borrow the ordered operations.
    pub fn operations(&self) -> &[PatchOp] {
        &self.ops
    }

    /// Validate byte ranges, overlap, arithmetic, and original-byte
    /// preconditions against an immutable input buffer.
    pub fn validate(&self, input: &[u8]) -> Result<()> {
        let mut ranges = Vec::new();
        for op in &self.ops {
            if let PatchOp::PatchBytes { offset, bytes } = op {
                let start = usize::try_from(*offset)
                    .map_err(|_| Error::bounds(*offset, bytes.len() as u64, input.len() as u64))?;
                let end = start.checked_add(bytes.len()).ok_or_else(|| {
                    Error::bounds(*offset, bytes.len() as u64, input.len() as u64)
                })?;
                if end > input.len() {
                    return Err(Error::bounds(
                        *offset,
                        bytes.len() as u64,
                        input.len() as u64,
                    ));
                }
                ranges.push((start, end));
            }
        }
        ranges.sort_unstable();
        for pair in ranges.windows(2) {
            if pair[1].0 < pair[0].1 {
                return Err(Error::validation(format!(
                    "patch byte ranges overlap at {:#x}..{:#x}",
                    pair[1].0, pair[0].1
                )));
            }
        }
        for (offset, expected) in &self.expected {
            let start = usize::try_from(*offset)
                .map_err(|_| Error::bounds(*offset, expected.len() as u64, input.len() as u64))?;
            let end = start
                .checked_add(expected.len())
                .ok_or_else(|| Error::bounds(*offset, expected.len() as u64, input.len() as u64))?;
            if input.get(start..end) != Some(expected.as_slice()) {
                return Err(Error::validation(format!(
                    "expected original bytes do not match at offset {offset:#x}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
/// The PreparedPatch type.
pub struct PreparedPatch {
    /// The preview field.
    pub preview: StructuralPatchPreview,
    /// The bytes field.
    pub bytes: Vec<u8>,
}

/// The PatchTransaction type.
pub struct PatchTransaction<'data> {
    macho: &'data MachoFile<'data>,
    ops: Vec<PatchOp>,
}

impl<'data> PatchTransaction<'data> {
    /// Performs new.
    pub fn new(macho: &'data MachoFile<'data>) -> Self {
        Self {
            macho,
            ops: Vec::new(),
        }
    }

    /// Performs add_op.
    pub fn add_op(&mut self, op: PatchOp) {
        self.ops.push(op);
    }

    /// Performs add_rpath.
    pub fn add_rpath(&mut self, path: impl Into<String>) {
        self.ops.push(PatchOp::AddRpath(path.into()));
    }

    /// Performs remove_rpath.
    pub fn remove_rpath(&mut self, path: impl Into<String>) {
        self.ops.push(PatchOp::RemoveRpath(path.into()));
    }

    /// Performs add_dylib.
    pub fn add_dylib(&mut self, name: impl Into<String>, compat: u32, current: u32) {
        self.ops.push(PatchOp::AddDylib {
            name: name.into(),
            compat_version: compat,
            current_version: current,
        });
    }

    /// Performs add_command.
    pub fn add_command(&mut self, cmd: LoadCommand) {
        self.ops.push(PatchOp::AddCommand(cmd));
    }

    /// Performs remove_command.
    pub fn remove_command(&mut self, index: usize) {
        self.ops.push(PatchOp::RemoveCommand(index));
    }

    /// Performs replace_command.
    pub fn replace_command(&mut self, index: usize, cmd: LoadCommand) {
        self.ops.push(PatchOp::ReplaceCommand(index, cmd));
    }

    /// Performs remove_code_signature.
    pub fn remove_code_signature(&mut self) {
        self.ops.push(PatchOp::RemoveCodeSignature);
    }

    /// Performs ops.
    pub fn ops(&self) -> &[PatchOp] {
        &self.ops
    }

    /// Performs preview.
    pub fn preview(&self) -> Result<StructuralPatchPreview> {
        Ok(self.prepare()?.preview)
    }

    /// Performs prepare.
    pub fn prepare(&self) -> Result<PreparedPatch> {
        PatchPlan::new(self.ops.clone()).validate(self.macho.bytes())?;
        let mut editor = MachoEditor::new(self.macho);
        apply_ops(&mut editor, &self.ops)?;
        let mut candidate = editor.build()?;
        apply_byte_patches(&mut candidate, &self.ops)?;
        let reparsed = parse(&candidate)?;
        let reparsed_mach = reparsed.first_macho().ok_or_else(|| {
            Error::validation("patched container does not contain a Mach-O image")
        })?;

        let preview =
            build_structural_preview(self.macho, candidate.as_slice(), reparsed_mach, &self.ops)?;

        Ok(PreparedPatch {
            preview,
            bytes: candidate,
        })
    }

    /// Performs patch_bytes.
    pub fn patch_bytes(&mut self, offset: u64, bytes: Vec<u8>) {
        self.ops.push(PatchOp::PatchBytes { offset, bytes });
    }

    /// Performs build_unchecked.
    pub fn build_unchecked(&self) -> Result<Vec<u8>> {
        let mut editor = MachoEditor::new(self.macho);
        apply_ops(&mut editor, &self.ops)?;
        let mut output = editor.build()?;
        apply_byte_patches(&mut output, &self.ops)?;
        Ok(output)
    }

    /// Build the candidate, reparse, validate, and return bytes only if valid.
    pub fn commit(&self) -> Result<Vec<u8>> {
        let prepared = self.prepare()?;

        if !prepared.preview.validation_errors.is_empty() {
            return Err(Error::invalid(format!(
                "candidate binary failed validation:\n  {}",
                prepared.preview.validation_errors.join("\n  ")
            )));
        }

        Ok(prepared.bytes)
    }
}

fn apply_ops(editor: &mut MachoEditor<'_>, ops: &[PatchOp]) -> Result<()> {
    for op in ops {
        match op {
            PatchOp::AddRpath(path) => editor.add_rpath(path),
            PatchOp::RemoveRpath(path) => editor.remove_rpath(path),
            PatchOp::AddDylib {
                name,
                compat_version,
                current_version,
            } => editor.add_load_dylib(name, *compat_version, *current_version),
            PatchOp::RemoveCodeSignature => editor.remove_code_signature(),
            PatchOp::AddCommand(cmd) => editor.add_command(cmd.clone()),
            PatchOp::RemoveCommand(idx) => {
                editor.remove_command(*idx)?;
            }
            PatchOp::ReplaceCommand(idx, cmd) => {
                editor.replace_command(*idx, cmd.clone())?;
            }
            PatchOp::PatchBytes { .. } => {
                // Byte patches are applied after build, not through MachoEditor
            }
        }
    }
    Ok(())
}

fn apply_byte_patches(output: &mut [u8], ops: &[PatchOp]) -> Result<()> {
    for op in ops {
        if let PatchOp::PatchBytes { offset, bytes } = op {
            let start = usize::try_from(*offset)
                .map_err(|_| Error::bounds(*offset, bytes.len() as u64, output.len() as u64))?;
            let end = start
                .checked_add(bytes.len())
                .ok_or_else(|| Error::bounds(*offset, bytes.len() as u64, output.len() as u64))?;
            if end > output.len() {
                return Err(Error::bounds(
                    *offset,
                    bytes.len() as u64,
                    output.len() as u64,
                ));
            }
            output[start..end].copy_from_slice(bytes);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MutationErrorKind, MutationOperation};

    #[test]
    fn plan_rejects_overlap_without_mutating_input() {
        let input = macho_test_support::thin64_arm64(2);
        let original = input.clone();
        let plan = PatchPlan::new(vec![
            PatchOp::PatchBytes {
                offset: 4,
                bytes: vec![1, 2, 3, 4],
            },
            PatchOp::PatchBytes {
                offset: 6,
                bytes: vec![5, 6],
            },
        ]);
        let error = plan.validate(&input).expect_err("overlap must fail");
        assert_eq!(error.kind, MutationErrorKind::Validation);
        assert_eq!(error.operation, MutationOperation::Validate);
        assert_eq!(input, original);
    }

    #[test]
    fn plan_rejects_stale_expected_bytes() {
        let input = macho_test_support::thin64_arm64(2);
        let plan = PatchPlan::default().expect_bytes(0, vec![0, 0, 0, 0]);
        let error = plan
            .validate(&input)
            .expect_err("stale precondition must fail");
        assert_eq!(error.kind, MutationErrorKind::Validation);
    }

    #[test]
    fn failed_strict_reparse_leaves_original_unchanged() {
        let input = macho_test_support::thin64_arm64(2);
        let original = input.clone();
        let container = macho_core::parse(&input).expect("fixture parses");
        let mut transaction = PatchTransaction::new(container.first_macho().unwrap());
        transaction.patch_bytes(0, vec![0, 0, 0, 0]);
        let error = transaction.prepare().expect_err("invalid magic must fail");
        assert_eq!(error.kind, MutationErrorKind::Parse);
        assert_eq!(input, original);
    }
}
