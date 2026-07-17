#![deny(missing_docs)]
//! Byte-safe Mach-O structural parsing, validation, and diagnostics.

mod error;

/// The ext module.
pub mod ext {
    pub use crate::model::ext::MachoExt;
}
/// The format module.
pub mod format;
/// The model module.
pub mod model;

pub use crate::error::{ContextFrame, OffsetSpan, ParseError, ParseErrorKind, ParseResult};
pub use crate::format::{
    ParseLimits, ParseMode, ParseOptions, ParseOutcome, parse, parse_with_options,
};

pub use format::load_commands::parse_load_commands;
pub use model::load_command::{LoadCommand, format_uuid};
pub use model::macho_file::MachoFile;
pub use model::section::Section;
pub use model::symbol::{Symbol, SymbolTable};
