use crate::edit::MachEditor;
pub use crate::edit::ops::PatchOp;
use crate::error::{Error, Result};
use crate::model::load_command::LoadCommand;
use crate::model::mach::MachFile;
use crate::validate;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct PatchPreview {
    pub operations: Vec<String>,
    pub old_command_count: usize,
    pub new_command_count: usize,
    pub validation_errors: Vec<String>,
    pub validation_warnings: Vec<String>,
    pub signature_invalidated: bool,
}

pub struct PatchTransaction<'data> {
    mach: &'data MachFile<'data>,
    ops: Vec<PatchOp>,
}

impl<'data> PatchTransaction<'data> {
    pub fn new(mach: &'data MachFile<'data>) -> Self {
        Self {
            mach,
            ops: Vec::new(),
        }
    }

    pub fn add_op(&mut self, op: PatchOp) {
        self.ops.push(op);
    }

    pub fn add_rpath(&mut self, path: impl Into<String>) {
        self.ops.push(PatchOp::AddRpath(path.into()));
    }

    pub fn remove_rpath(&mut self, path: impl Into<String>) {
        self.ops.push(PatchOp::RemoveRpath(path.into()));
    }

    pub fn add_dylib(&mut self, name: impl Into<String>, compat: u32, current: u32) {
        self.ops.push(PatchOp::AddDylib {
            name: name.into(),
            compat_version: compat,
            current_version: current,
        });
    }

    pub fn add_command(&mut self, cmd: LoadCommand) {
        self.ops.push(PatchOp::AddCommand(cmd));
    }

    pub fn remove_command(&mut self, index: usize) {
        self.ops.push(PatchOp::RemoveCommand(index));
    }

    pub fn replace_command(&mut self, index: usize, cmd: LoadCommand) {
        self.ops.push(PatchOp::ReplaceCommand(index, cmd));
    }

    pub fn remove_code_signature(&mut self) {
        self.ops.push(PatchOp::RemoveCodeSignature);
    }

    pub fn ops(&self) -> &[PatchOp] {
        &self.ops
    }

    pub fn preview(&self) -> Result<PatchPreview> {
        let mut editor = MachEditor::new(self.mach);
        let old_count = editor.command_count();
        let original_commands: Vec<LoadCommand> = self
            .mach
            .load_commands()
            .iter()
            .map(|lc| lc.kind.clone())
            .collect();

        apply_ops(&mut editor, &self.ops)?;
        let new_count = editor.command_count();

        let mut candidate = editor.build()?;
        apply_byte_patches(&mut candidate, &self.ops)?;
        let reparsed = crate::parse::parse(&candidate)?;
        let reparsed_mach = reparsed.first_mach();
        let diags = validate::validate(reparsed_mach);

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

        let sig_invalidated = has_code_signature(self.mach)
            && (editor.commands() != original_commands.as_slice()
                || byte_patches_changed(self.mach.bytes(), &candidate, &self.ops));

        Ok(PatchPreview {
            operations: self.ops.iter().map(|op| op.to_string()).collect(),
            old_command_count: old_count,
            new_command_count: new_count,
            validation_errors: errors,
            validation_warnings: warnings,
            signature_invalidated: sig_invalidated,
        })
    }

    pub fn patch_bytes(&mut self, offset: u64, bytes: Vec<u8>) {
        self.ops.push(PatchOp::PatchBytes { offset, bytes });
    }

    pub fn build_unchecked(&self) -> Result<Vec<u8>> {
        let mut editor = MachEditor::new(self.mach);
        apply_ops(&mut editor, &self.ops)?;
        let mut output = editor.build()?;
        apply_byte_patches(&mut output, &self.ops)?;
        Ok(output)
    }

    /// Build the candidate, reparse, validate, and return bytes only if valid.
    pub fn commit(&self) -> Result<Vec<u8>> {
        let candidate = self.build_unchecked()?;

        // Reparse and validate
        let reparsed = crate::parse::parse(&candidate)?;
        let reparsed_mach = reparsed.first_mach();
        let diags = validate::validate(reparsed_mach);
        let errors: Vec<String> = diags
            .iter()
            .filter(|d| d.severity == validate::Severity::Error)
            .map(|d| format!("{}: {}", d.code.0, d.message))
            .collect();

        if !errors.is_empty() {
            return Err(Error::Format(format!(
                "candidate binary failed validation:\n  {}",
                errors.join("\n  ")
            )));
        }

        Ok(candidate)
    }
}

fn apply_ops(editor: &mut MachEditor<'_>, ops: &[PatchOp]) -> Result<()> {
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
                // Byte patches are applied after build, not through MachEditor
            }
        }
    }
    Ok(())
}

fn apply_byte_patches(output: &mut [u8], ops: &[PatchOp]) -> Result<()> {
    for op in ops {
        if let PatchOp::PatchBytes { offset, bytes } = op {
            let start = usize::try_from(*offset).map_err(|_| Error::Bounds {
                offset: *offset,
                needed: bytes.len() as u64,
                available: output.len() as u64,
            })?;
            let end = start.checked_add(bytes.len()).ok_or(Error::Bounds {
                offset: *offset,
                needed: bytes.len() as u64,
                available: output.len() as u64,
            })?;
            if end > output.len() {
                return Err(Error::Bounds {
                    offset: *offset,
                    needed: bytes.len() as u64,
                    available: output.len() as u64,
                });
            }
            output[start..end].copy_from_slice(bytes);
        }
    }
    Ok(())
}

fn has_code_signature(mach: &MachFile<'_>) -> bool {
    mach.load_commands()
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
