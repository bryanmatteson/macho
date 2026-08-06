#![deny(missing_docs)]
#![allow(unreachable_patterns)] // Keep conservative fallbacks for evolving public enums.
//! Testable command-line grammar and delivery implementation.

pub use crate::*;

/// Delivery-only input adapters.
pub mod inputs {
    /// Dyld cache parser reexported by the full façade.
    pub use crate::dyld_cache;
}

pub mod adapters;
/// The commands module.
pub mod commands;

pub use commands::{
    CapturedRun, CliIo, ExitStatus, clap_command, parse_only, run_captured, run_from, version,
};
