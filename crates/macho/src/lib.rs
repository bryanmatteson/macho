extern crate self as macho;

pub mod error {
    pub use macho_core::{Error, Result};
}

pub use macho_analysis as analysis;
pub use macho_core as core;
pub use macho_core::ext;
pub use macho_core::format;
pub use macho_core::model;
pub use macho_core::{Error, Result, parse};
pub use macho_extract as extract;
pub use macho_metadata::metadata;
pub use macho_mutate as mutate;

pub mod resolve {
    pub use macho_core::resolve::{ResolutionContext, ResolvedTarget};
    pub use macho_metadata::resolve::{fixups, paths};
}

pub mod symbols {
    pub use macho_core::symbols::{demangle, table};
    pub use macho_metadata::symbols::{exports, imports};
}

pub mod api;
pub mod commands;
pub mod inputs;
