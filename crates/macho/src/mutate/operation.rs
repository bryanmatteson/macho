use std::fmt;

use crate::mutate::model::load_command::LoadCommand;
use crate::mutate::section::AddSection;

/// One structural Mach-O mutation operation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PatchOp<'section> {
    /// Add an `LC_RPATH` command.
    AddRpath(String),
    /// Remove matching `LC_RPATH` commands.
    RemoveRpath(String),
    /// Add an `LC_LOAD_DYLIB` command.
    AddDylib {
        /// Install name.
        name: String,
        /// Compatibility version.
        compat_version: u32,
        /// Current version.
        current_version: u32,
    },
    /// Remove the code-signature load command.
    RemoveCodeSignature,
    /// Add a load command.
    AddCommand(LoadCommand),
    /// Remove a load command by index.
    RemoveCommand(usize),
    /// Replace a load command by index.
    ReplaceCommand(usize, LoadCommand),
    /// Add a section.
    AddSection(AddSection<'section>),
    /// Replace bytes at a slice-relative file offset.
    PatchBytes {
        /// File offset.
        offset: u64,
        /// Replacement bytes.
        bytes: Vec<u8>,
    },
}

impl fmt::Display for PatchOp<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AddRpath(path) => write!(formatter, "add rpath: {path}"),
            Self::RemoveRpath(path) => write!(formatter, "remove rpath: {path}"),
            Self::AddDylib { name, .. } => write!(formatter, "add dylib: {name}"),
            Self::RemoveCodeSignature => formatter.write_str("remove code signature"),
            Self::AddCommand(command) => write!(formatter, "add command: {}", command.name()),
            Self::RemoveCommand(index) => write!(formatter, "remove command at index {index}"),
            Self::ReplaceCommand(index, command) => write!(
                formatter,
                "replace command at index {index} with {}",
                command.name()
            ),
            Self::AddSection(section) => write!(
                formatter,
                "add section: {},{} ({} bytes)",
                section.segment_name(),
                section.section_name(),
                section.content().size()
            ),
            Self::PatchBytes { offset, bytes } => {
                write!(
                    formatter,
                    "patch {} bytes at offset {offset:#x}",
                    bytes.len()
                )
            }
        }
    }
}
