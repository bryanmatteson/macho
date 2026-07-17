#![deny(missing_docs)]
//! Testable command-line grammar and delivery implementation.

pub use macho::*;

/// Delivery-only input adapters.
pub mod inputs {
    /// Dyld cache parser reexported by the full façade.
    pub use macho::dyld_cache;
}

pub mod adapters;
/// The commands module.
pub mod commands;

pub use commands::{
    CapturedRun, CliIo, ExitStatus, clap_command, parse_only, run_captured, run_from, version,
};
