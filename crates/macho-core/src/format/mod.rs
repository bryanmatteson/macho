/// The constants module.
pub mod constants;
mod container;
/// The fat module.
pub mod fat;
/// The io module.
pub mod io;
/// The load_commands module.
pub mod load_commands;
/// The macho module.
pub mod macho;
/// The relocations module.
pub mod relocations;
/// The sections module.
pub mod sections;
/// The symbols module.
pub mod symbols;

pub use container::{parse, parse_with_options};
pub use fat::parse_fat_binary;
pub use macho::parse_macho_file;
pub use relocations::relocations_for_section;
pub use symbols::parse_symbol_table;

use crate::model::container::MachoContainer;
use crate::model::validate::Diagnostic;

/// Policy for handling recoverable structural diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseMode {
    /// Reject any error-severity structural diagnostic.
    Strict,
    /// Return the safe model together with recoverable diagnostics.
    Forensic,
}

/// Hard bounds applied before input-derived allocation or iteration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLimits {
    /// Maximum architecture entries in one fat container.
    pub max_fat_arches: usize,
    /// Maximum load commands in one Mach-O image.
    pub max_load_commands: usize,
    /// Maximum sections in one Mach-O image.
    pub max_sections: usize,
    /// Maximum cumulative load-command string bytes in one image.
    pub max_string_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_fat_arches: 256,
            max_load_commands: 10_000,
            max_sections: 100_000,
            max_string_bytes: 16 * 1024 * 1024,
        }
    }
}

/// Parse mode and hard resource limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseOptions {
    /// Recovery policy.
    pub mode: ParseMode,
    /// Hard limits.
    pub limits: ParseLimits,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            mode: ParseMode::Strict,
            limits: ParseLimits::default(),
        }
    }
}

/// Safe parsed model plus recoverable diagnostics.
pub struct ParseOutcome<'data> {
    /// Parsed thin or fat container.
    pub container: MachoContainer<'data>,
    /// Structural diagnostics emitted after safe parsing.
    pub diagnostics: Vec<Diagnostic>,
}
