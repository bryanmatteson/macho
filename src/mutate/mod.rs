pub mod layout;
pub mod owned;
pub mod patch;
pub mod preview;
pub mod resign;
pub mod transaction;

pub use patch::{
    FunctionEntryHookPlan, FunctionEntryPatchPlan, HookJump, HookJumpEncoding, MachoPatcher,
    PatchArch, PatchOp, PatchSectionInfo, PatchSegmentInfo, PatchSymbolEntry, PatchSymbolTable,
    TrampolinePlan, nop_bytes_for_arch, vtable_mangled_prefix,
};

use crate::model::load_command::*;
use crate::model::mach_file::MachFile;
use crate::model::segment::Segment;
use crate::{Error, Result};

/// A structural editor for Mach-O binaries.
///
/// Allows adding, removing, and replacing load commands, then rebuilding
/// the binary with updated offsets. Segment data is copied verbatim.
pub struct MachEditor<'data> {
    original: &'data MachFile<'data>,
    commands: Vec<LoadCommand>,
    segments: Vec<Segment>,
}

impl<'data> MachEditor<'data> {
    pub fn new(mach: &'data MachFile<'data>) -> Self {
        let commands: Vec<LoadCommand> = mach
            .load_commands()
            .iter()
            .map(|lc| lc.kind.clone())
            .collect();
        let segments = mach.segments().to_vec();
        Self {
            original: mach,
            commands,
            segments,
        }
    }

    pub fn commands(&self) -> &[LoadCommand] {
        &self.commands
    }

    pub fn command_count(&self) -> usize {
        self.commands.len()
    }

    /// Add a load command at the end.
    pub fn add_command(&mut self, cmd: LoadCommand) {
        self.commands.push(cmd);
    }

    /// Remove the load command at the given index.
    pub fn remove_command(&mut self, index: usize) -> Result<LoadCommand> {
        if index >= self.commands.len() {
            return Err(Error::Format(format!(
                "command index {index} out of range (have {})",
                self.commands.len()
            )));
        }
        Ok(self.commands.remove(index))
    }

    /// Replace the load command at the given index.
    pub fn replace_command(&mut self, index: usize, cmd: LoadCommand) -> Result<LoadCommand> {
        if index >= self.commands.len() {
            return Err(Error::Format(format!(
                "command index {index} out of range (have {})",
                self.commands.len()
            )));
        }
        Ok(std::mem::replace(&mut self.commands[index], cmd))
    }

    /// Add an LC_RPATH load command.
    pub fn add_rpath(&mut self, path: &str) {
        self.commands.push(LoadCommand::Rpath(StringData {
            value: path.to_string(),
        }));
    }

    /// Add an LC_LOAD_DYLIB load command.
    pub fn add_load_dylib(&mut self, name: &str, compat_version: u32, current_version: u32) {
        self.commands.push(LoadCommand::LoadDylib(DylibData {
            name: name.to_string(),
            timestamp: 0,
            current_version: PackedVersion(current_version),
            compatibility_version: PackedVersion(compat_version),
        }));
    }

    /// Find and remove all LC_RPATH commands matching the given path.
    pub fn remove_rpath(&mut self, path: &str) {
        self.commands.retain(|cmd| {
            if let Some(rpath) = cmd.as_rpath() {
                rpath != path
            } else {
                true
            }
        });
    }

    /// Remove the LC_CODE_SIGNATURE command (if present).
    pub fn remove_code_signature(&mut self) {
        self.commands
            .retain(|cmd| !matches!(cmd, LoadCommand::CodeSignature(_)));
    }

    /// Build the modified binary, returning the new bytes.
    ///
    /// This encodes all commands, adjusts offsets, and produces a complete
    /// Mach-O binary. The result can be written to a file.
    pub fn build(&self) -> Result<Vec<u8>> {
        let endian = self.original.endian();
        let bitness = self.original.bitness();

        // Encode all commands
        let encoded: Vec<(LoadCommand, Vec<u8>)> = self
            .commands
            .iter()
            .map(|cmd| {
                let bytes = layout::encode_load_command(cmd, &self.segments, endian, bitness)?;
                Ok((cmd.clone(), bytes))
            })
            .collect::<Result<_>>()?;

        layout::build_binary(self.original, &encoded, &self.segments)
    }
}

impl LoadCommand {
    /// Create a new LC_RPATH command.
    pub fn new_rpath(path: &str) -> Self {
        Self::Rpath(StringData {
            value: path.to_string(),
        })
    }

    /// Create a new LC_LOAD_DYLIB command.
    pub fn new_load_dylib(name: &str, current_version: u32, compat_version: u32) -> Self {
        Self::LoadDylib(DylibData {
            name: name.to_string(),
            timestamp: 0,
            current_version: PackedVersion(current_version),
            compatibility_version: PackedVersion(compat_version),
        })
    }
}
