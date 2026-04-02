// Internal re-exports (not part of public API)
pub(crate) use macho_core as core;
pub(crate) use macho_core::dwarf;
pub(crate) use macho_core::ext;
pub(crate) use macho_core::symbols;
pub(crate) use macho_core::{Error, Result};
pub(crate) use macho_core::{format, model};

// Analysis modules
pub mod abi;
pub mod audit;
pub mod container;
pub mod deps;
pub mod diff;
pub mod reconstruct;
pub mod snapshot;
pub mod strings;
pub mod vtables;
pub mod xref;
