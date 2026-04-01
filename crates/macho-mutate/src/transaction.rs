use crate::format::parse;
use crate::model::load_command::LoadCommand;
use crate::model::macho_file::MachoFile;
use crate::mutate::MachoEditor;
pub use crate::mutate::patch::PatchOp;
use crate::mutate::preview::build_preview;
pub use crate::mutate::preview::{PatchPreview, SignatureOutcome};
use crate::{Error, Result};

#[derive(Debug, Clone)]
pub struct PreparedPatch {
    pub preview: PatchPreview,
    pub bytes: Vec<u8>,
}

pub struct PatchTransaction<'data> {
    macho: &'data MachoFile<'data>,
    ops: Vec<PatchOp>,
}

impl<'data> PatchTransaction<'data> {
    pub fn new(macho: &'data MachoFile<'data>) -> Self {
        Self {
            macho,
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
        Ok(self.prepare()?.preview)
    }

    pub fn prepare(&self) -> Result<PreparedPatch> {
        let mut editor = MachoEditor::new(self.macho);
        apply_ops(&mut editor, &self.ops)?;
        let mut candidate = editor.build()?;
        apply_byte_patches(&mut candidate, &self.ops)?;
        let reparsed = parse(&candidate)?;
        let reparsed_mach = reparsed.first_mach();

        let preview = build_preview(self.macho, candidate.as_slice(), reparsed_mach, &self.ops)?;

        Ok(PreparedPatch {
            preview,
            bytes: candidate,
        })
    }

    pub fn patch_bytes(&mut self, offset: u64, bytes: Vec<u8>) {
        self.ops.push(PatchOp::PatchBytes { offset, bytes });
    }

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
            return Err(Error::Format(format!(
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
