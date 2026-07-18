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
/// The rebase module.
pub mod rebase;
pub mod resolve;
/// The types module.
pub mod types;
/// The uleb module.
pub mod uleb;

pub use bind::parse_bind_entries;
pub use chained::{ChainedFixups, parse_chained_fixups};
pub use exports::{find_export, fold_exports, parse_exports, visit_exports};
pub use rebase::parse_rebase_entries;
pub use types::{BindEntry, ChainedImport, Export, ExportKind, Fixup, FixupKind, RebaseEntry};
