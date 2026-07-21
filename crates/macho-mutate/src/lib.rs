#![deny(missing_docs)]
//! In-memory structural Mach-O mutation and transactional validation.

pub use macho_core::{format, model};

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{MutationError, MutationErrorKind, MutationOperation, Result};

/// The metadata module.
pub mod metadata {
    pub use macho_codesign as codesign;
    pub use macho_dyld as dyld;
}

/// The layout module.
pub mod layout;
/// The owned module.
pub mod owned;
/// The patch module.
pub mod patch;
/// The preview module.
pub mod preview;
/// The resign module.
pub mod resign;
/// Section-addition request types.
pub mod section;
#[cfg(feature = "external-signing")]
pub mod sign;
/// The transaction module.
pub mod transaction;

pub use patch::{
    FunctionEntryHookPlan, FunctionEntryPatchPlan, HookJump, HookJumpEncoding, MachoPatcher,
    PatchArch, PatchOp, PatchSectionInfo, PatchSegmentInfo, PatchSymbolEntry, PatchSymbolTable,
    TrampolinePlan, nop_bytes_for_arch, vtable_mangled_prefix,
};
pub use section::{AddSection, SectionContent};
#[cfg(feature = "signing")]
pub use sign::InProcessSignatureProvider;
#[cfg(feature = "external-signing")]
pub use sign::{
    AdHocSignatureProvider, ExternalDigestSigner, ExternalSignatureProvider, SignatureKind,
    SignatureProvider, SignatureProviderError, SignatureRequest, verify_signed_binary,
};
pub use transaction::{PatchPlan, PatchTransaction, PreparedPatch};

use crate::model::load_command::*;
use crate::model::macho_file::MachoFile;

/// A structural editor for Mach-O binaries.
///
/// Allows adding, removing, and replacing load commands, then rebuilding
/// the binary without relocating existing payload. Segment data is copied
/// verbatim, and command growth fails if existing header slack is insufficient.
pub struct MachoEditor<'image, 'section> {
    original: &'image MachoFile<'image>,
    commands: Vec<LoadCommand>,
    segments: Vec<section::EditableSegment<'section>>,
}

impl<'image, 'section> MachoEditor<'image, 'section> {
    /// Performs new.
    pub fn new(macho: &'image MachoFile<'image>) -> Self {
        let commands: Vec<LoadCommand> = macho
            .load_commands()
            .iter()
            .map(|lc| lc.kind().clone())
            .collect();
        let segments = macho
            .segments()
            .iter()
            .cloned()
            .map(section::EditableSegment::from)
            .collect();
        Self {
            original: macho,
            commands,
            segments,
        }
    }

    /// Performs commands.
    pub fn commands(&self) -> &[LoadCommand] {
        &self.commands
    }

    /// Performs command_count.
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
            return Err(Error::invalid(format!(
                "command index {index} out of range (have {})",
                self.commands.len()
            )));
        }
        Ok(self.commands.remove(index))
    }

    /// Replace the load command at the given index.
    pub fn replace_command(&mut self, index: usize, cmd: LoadCommand) -> Result<LoadCommand> {
        if index >= self.commands.len() {
            return Err(Error::invalid(format!(
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

    /// Add a section to an existing segment.
    ///
    /// Placement consumes only free file and virtual-address space. The edit
    /// fails rather than relocating a later segment or overwriting unrelated
    /// bytes.
    pub fn add_section(&mut self, request: AddSection<'section>) -> Result<()> {
        section::place_section(
            &mut self.segments,
            self.original.bytes().len(),
            self.original.bitness(),
            request,
        )
    }

    /// Build the modified binary, returning the new bytes.
    ///
    /// This encodes all commands and produces a complete Mach-O binary. Load
    /// commands may grow only into existing command slack; existing payload is
    /// never relocated. The result can be written to a file.
    pub fn build(&self) -> Result<Vec<u8>> {
        let endian = self.original.endian();
        let bitness = self.original.bitness();

        let encoded: Vec<(LoadCommand, Vec<u8>)> = self
            .commands
            .iter()
            .map(|cmd| {
                let bytes =
                    layout::encode_edited_load_command(cmd, &self.segments, endian, bitness)?;
                Ok((cmd.clone(), bytes))
            })
            .collect::<Result<_>>()?;

        layout::build_edited_binary(self.original, &encoded, &self.segments)
    }
}

/// The LoadCommandEditExt type.
pub trait LoadCommandEditExt {
    /// Performs new_rpath.
    fn new_rpath(path: &str) -> Self;
    /// Performs new_load_dylib.
    fn new_load_dylib(name: &str, current_version: u32, compat_version: u32) -> Self;
}

impl LoadCommandEditExt for macho_core::model::load_command::LoadCommand {
    fn new_rpath(path: &str) -> Self {
        Self::Rpath(StringData {
            value: path.to_string(),
        })
    }

    fn new_load_dylib(name: &str, current_version: u32, compat_version: u32) -> Self {
        Self::LoadDylib(DylibData {
            name: name.to_string(),
            timestamp: 0,
            current_version: PackedVersion(current_version),
            compatibility_version: PackedVersion(compat_version),
        })
    }
}

/// The mutate module.
pub mod mutate {
    pub use crate::layout;
    pub use crate::owned;
    pub use crate::patch;
    pub use crate::preview;
    pub use crate::resign;
    pub use crate::transaction;
    pub use crate::{
        AddSection, FunctionEntryHookPlan, FunctionEntryPatchPlan, HookJump, HookJumpEncoding,
        LoadCommandEditExt, MachoEditor, MachoPatcher, PatchArch, PatchOp, PatchSectionInfo,
        PatchSegmentInfo, PatchSymbolEntry, PatchSymbolTable, SectionContent, TrampolinePlan,
        nop_bytes_for_arch, vtable_mangled_prefix,
    };
}
