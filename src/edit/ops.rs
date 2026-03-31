use crate::model::load_command::LoadCommand;

#[derive(Debug, Clone)]
pub enum PatchOp {
    AddRpath(String),
    RemoveRpath(String),
    AddDylib {
        name: String,
        compat_version: u32,
        current_version: u32,
    },
    RemoveCodeSignature,
    AddCommand(LoadCommand),
    RemoveCommand(usize),
    ReplaceCommand(usize, LoadCommand),
    /// Overwrite bytes at an absolute file offset in the built binary.
    PatchBytes {
        offset: u64,
        bytes: Vec<u8>,
    },
}

impl std::fmt::Display for PatchOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AddRpath(p) => write!(f, "add rpath: {p}"),
            Self::RemoveRpath(p) => write!(f, "remove rpath: {p}"),
            Self::AddDylib { name, .. } => write!(f, "add dylib: {name}"),
            Self::RemoveCodeSignature => write!(f, "remove code signature"),
            Self::AddCommand(cmd) => write!(f, "add command: {}", cmd.name()),
            Self::RemoveCommand(idx) => write!(f, "remove command at index {idx}"),
            Self::ReplaceCommand(idx, cmd) => {
                write!(f, "replace command at index {idx} with {}", cmd.name())
            }
            Self::PatchBytes { offset, bytes } => {
                write!(f, "patch {} bytes at offset {offset:#x}", bytes.len())
            }
        }
    }
}
