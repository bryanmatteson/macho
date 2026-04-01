extern crate self as macho;

pub mod error {
    pub use macho_core::{Error, Result};
}

pub use macho_analysis as analysis;
pub use macho_core as core;
pub use macho_core::ext;
pub use macho_core::format;
pub use macho_core::metadata;
pub use macho_core::model;
pub use macho_core::resolve;
pub use macho_core::symbols;
pub use macho_core::{Error, Result, parse};
pub use macho_edit as mutate;
pub use macho_extract as extract;

pub mod api;
pub mod commands;
pub mod inputs;
