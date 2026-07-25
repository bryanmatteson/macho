/// The addr module.
pub mod addr;
/// The container module.
pub mod container;
/// The header module.
pub mod header;
/// The load_command module.
pub mod load_command;
/// The macho_file module.
pub mod macho_file;
/// The section module.
pub mod section;
/// The segment module.
pub mod segment;
/// The symbol module.
pub mod symbol;
/// The validate module.
pub mod validate;

/// The ext module.
pub mod ext;
pub(crate) mod names;
/// The relocation module.
pub mod relocation;

pub use container::{FatArch, FatBinary, MachoContainer, SelectedImage, SelectionKey};
pub use header::{ArchSpec, Bitness, CpuSubtype, CpuType, FileType, MachoHeader, MagicNumber};
pub use load_command::{LoadCommand, ParsedLoadCommand};
pub use macho_file::MachoFile;
pub use section::{Section, SectionType};
pub use segment::Segment;
pub use symbol::{StringTable, Symbol, SymbolTable, SymbolType};
pub use validate::{Diagnostic, DiagnosticCode, Severity, Span};
