#![deny(missing_docs)]
//! Dyld bind, rebase, export, fixup, and pointer-resolution primitives.

extern crate self as dyld;

pub use macho_core::{format, model};

/// The error module.
pub mod error;
pub use error::{DyldError, DyldErrorKind, Result};

/// The bind module.
pub mod bind;
/// The chained module.
pub mod chained;
/// The exports module.
pub mod exports;
/// Strict bounded `LC_FUNCTION_STARTS` evidence.
pub mod function_starts;
/// Canonical imported-symbol collection across chained and legacy dyld encodings.
pub mod imports;
/// The rebase module.
pub mod rebase;
pub mod resolve;
/// The types module.
pub mod types;
/// The uleb module.
pub mod uleb;

pub use bind::parse_bind_entries;
pub use chained::{
    ChainedFixups, ChainedImportFormat, ChainedImportLookup, ChainedImports, lookup_chained_import,
    parse_chained_fixups, parse_chained_imports,
};
pub use exports::{find_export, fold_exports, parse_exports, visit_exports};
pub use function_starts::{
    FunctionStart, FunctionStartContinuation, FunctionStartsOutcome, decode_function_starts,
};
pub use imports::{ImportRecord, collect_imports};
pub use rebase::parse_rebase_entries;
pub use types::{
    BindEntry, ChainedImport, ChainedImportRecord, Export, ExportKind, Fixup, FixupKind,
    RebaseEntry,
};
