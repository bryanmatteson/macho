#![deny(missing_docs)]
//! Symbol, import, export, and demangling helpers.

pub use macho_core::model;
pub use macho_dyld as dyld;

/// The error module.
pub mod error;
pub use error::{Result, SymbolsError, SymbolsErrorKind};

/// The demangle module.
pub mod demangle;
/// The exports module.
pub mod exports;
/// The imports module.
pub mod imports;
/// The table module.
pub mod table;
