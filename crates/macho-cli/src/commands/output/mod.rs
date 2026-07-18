//! Shared human and machine output rendering for the CLI delivery layer.

mod delivery;
mod error;
mod format;
mod style;

/// Column alignment for human-readable output.
pub mod columns;
/// JSON serialization helpers for machine output.
pub mod json;
/// SARIF rendering for audit output.
pub mod sarif;

pub use delivery::{Diagnostic, write_diagnostics, write_failure, write_success};
pub use error::{Error, Result};
pub use format::{ColorChoice, Format, Options, PolicyError, validate_policy};
pub use style::Style;
