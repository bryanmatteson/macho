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

/// Return whether the leading bytes identify a thin or universal Mach-O.
///
/// This intentionally recognizes truncated inputs so callers can route them to
/// strict Mach-O parsing and preserve fail-closed diagnostics.
pub fn probe(data: &[u8]) -> bool {
    let Some(magic) = data.get(..4) else {
        return false;
    };
    matches!(
        magic,
        [0xfe, 0xed, 0xfa, 0xce]
            | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf]
            | [0xcf, 0xfa, 0xed, 0xfe]
            | [0xca, 0xfe, 0xba, 0xbe]
            | [0xbe, 0xba, 0xfe, 0xca]
            | [0xca, 0xfe, 0xba, 0xbf]
            | [0xbf, 0xba, 0xfe, 0xca]
    )
}

#[cfg(test)]
mod probe_tests {
    #[test]
    fn probe_recognizes_truncated_thin_and_fat_headers() {
        assert!(super::probe(&0xfeed_facfu32.to_be_bytes()));
        assert!(super::probe(&0xcafe_babeu32.to_be_bytes()));
        assert!(!super::probe(b"ELF!"));
        assert!(!super::probe(&[0xfe, 0xed, 0xfa]));
    }
}
