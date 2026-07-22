//! Shared human and machine output rendering for the CLI delivery layer.

mod delivery;
mod error;
mod format;
mod style;

/// Syntax highlighting for decoded instruction text.
pub mod asm;
/// Column alignment for human-readable output.
pub mod columns;
/// JSON serialization helpers for machine output.
pub mod json;
/// Objective-C semantic profile for recovered header presentation.
pub mod objc;
/// SARIF rendering for audit output.
pub mod sarif;

pub use delivery::{Diagnostic, write_diagnostics, write_failure, write_success};
pub use error::{Error, Result};
pub use format::{ColorChoice, Format, Options, PolicyError, validate_policy};
pub use style::{ADDRESS as ADDRESS_TOKEN, RAW_BYTES as RAW_BYTES_TOKEN, Style, clap_styles};
