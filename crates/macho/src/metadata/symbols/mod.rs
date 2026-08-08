#![deny(missing_docs)]
//! Symbol-table and demangling helpers.

pub use crate::core::model;

/// The error module.
pub mod error;
pub use error::{Result, SymbolsError, SymbolsErrorKind};

/// Typed bounded indirect-symbol evidence.
pub mod indirect;
pub use indirect::{
    IndirectBindingContinuation, IndirectBindingKind, IndirectBindingsOutcome, IndirectBoundSymbol,
    IndirectSymbolBinding, IndirectSymbolTarget, decode_indirect_bindings,
};

/// Process-free symbol demangling and normalization.
pub use crate::metadata::demangle;
/// The table module.
pub mod table;
