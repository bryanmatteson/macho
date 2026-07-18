#![deny(missing_docs)]
//! Process-free parsing, validation, and rendering for recovered headers.
//!
//! The crate deliberately owns only the non-serialized syntax model. Stable
//! report identifiers and JSON projections belong to `macho-analysis`.

mod ast;
mod parse;
mod render;
mod validate;

pub use ast::*;
pub use parse::{HeaderParser, ParseError, SourceSpan, TreeSitterHeaderParser};
pub use render::{RenderError, render};
pub use validate::{
    HeaderValidationCode, HeaderValidationDiagnostic, HeaderValidationReport, Severity,
    ValidationError, ValidationLimits, validate,
};
