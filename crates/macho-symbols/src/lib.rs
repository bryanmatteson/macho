#![deny(missing_docs)]
//! Symbol-table and demangling helpers.

pub use macho_core::model;

/// The error module.
pub mod error;
pub use error::{Result, SymbolsError, SymbolsErrorKind};

/// Process-free symbol demangling and normalization.
pub use macho_demangle as demangle;
/// The table module.
pub mod table;
