mod error;

pub mod analysis;
pub mod api;
pub mod cli;
pub mod format;
pub mod inputs;
pub mod metadata;
pub mod model;
pub mod mutate;
pub mod recovery;
pub mod resolve;
pub mod symbols;

extern crate self as macho;

pub use crate::error::{Error, Result};
pub use crate::format::parse;
