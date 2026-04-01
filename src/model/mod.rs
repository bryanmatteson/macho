pub mod addr;
pub mod container;
pub mod header;
pub mod load_command;
pub mod macho_file;
pub mod section;
pub mod segment;
pub mod symbol;
pub mod validate;

pub(crate) mod ext;
pub(crate) mod names;
pub(crate) mod relocation;

pub use container::{FatArch, FatBinary, MachoContainer};
pub use header::{Bitness, CpuSubtype, CpuType, FileType, MachoHeader, MagicNumber};
pub use load_command::{LoadCommand, ParsedLoadCommand};
pub use macho_file::MachoFile;
pub use section::{Section, SectionType};
pub use segment::Segment;
pub use symbol::{StringTable, Symbol, SymbolTable, SymbolType};
pub use validate::{Diagnostic, DiagnosticCode, Severity, Span};
