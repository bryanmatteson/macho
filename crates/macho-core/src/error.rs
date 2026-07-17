//! Structured parser errors with location and ordered context.

use std::fmt;

const INVALID_FORMAT_CODE: &str = "parse.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "parse.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "parse.address.invalid";
const INVALID_LOAD_COMMAND_CODE: &str = "parse.load_command.invalid";
const LIMIT_EXCEEDED_CODE: &str = "parse.limit.exceeded";
const UNSUPPORTED_INPUT_CODE: &str = "parse.input.unsupported";
const VALIDATION_FAILED_CODE: &str = "parse.validation.failed";

/// Stable category for a structural parse failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseErrorKind {
    /// The input does not encode a recognized or internally consistent format.
    InvalidFormat,
    /// A byte range lies outside the supplied input.
    OutOfBounds,
    /// An address or offset cannot be mapped safely.
    InvalidAddress,
    /// A load command is malformed.
    InvalidLoadCommand,
    /// A safe parser limit was exhausted.
    LimitExceeded,
    /// The input is structurally valid but unsupported by this parser.
    Unsupported,
    /// Strict structural validation rejected the parsed model.
    Validation,
}

/// Byte range associated with a parser failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetSpan {
    /// File- or slice-relative byte offset, described by the surrounding context.
    pub offset: u64,
    /// Length in bytes.
    pub len: u64,
}

/// Ordered structural context retained while errors cross parser boundaries.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContextFrame {
    /// A fat-container architecture table entry.
    /// The FatArchitecture field.
    FatArchitecture {
        /// Zero-based architecture index in the containing fat binary.
        index: usize,
    },
    /// A load command within one Mach-O image.
    /// The LoadCommand field.
    LoadCommand {
        /// Zero-based command index in the selected Mach-O image.
        index: usize,
    },
    /// A named parsing operation.
    /// The Operation field.
    Operation {
        /// Stable operation name supplied by the layer adding context.
        name: &'static str,
    },
}

/// Structured failure returned by core parsing and structural accessors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// Machine-inspectable error category.
    pub kind: ParseErrorKind,
    /// Optional byte location.
    pub location: Option<OffsetSpan>,
    /// Context ordered from the innermost operation outward.
    pub context: Vec<ContextFrame>,
    message: String,
}

impl ParseError {
    /// Construct a parser error with a typed category and human context.
    pub fn new(kind: ParseErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            location: None,
            context: Vec::new(),
            message: message.into(),
        }
    }

    /// Construct an invalid-format error.
    pub fn format(message: impl Into<String>) -> Self {
        Self::new(ParseErrorKind::InvalidFormat, message)
    }

    /// Construct an out-of-bounds error with the attempted range.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        Self::new(
            ParseErrorKind::OutOfBounds,
            format!("offset {offset:#x}, needed {needed} bytes, have {available}"),
        )
        .with_location(OffsetSpan {
            offset,
            len: needed,
        })
    }

    /// Construct an invalid-address error.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(ParseErrorKind::InvalidAddress, message)
    }

    /// Construct an invalid-load-command error.
    pub fn command(message: impl Into<String>) -> Self {
        Self::new(ParseErrorKind::InvalidLoadCommand, message)
    }

    /// Construct a limit-exhaustion error.
    pub fn limit(message: impl Into<String>) -> Self {
        Self::new(ParseErrorKind::LimitExceeded, message)
    }

    /// Construct an unsupported-input error.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ParseErrorKind::Unsupported, message)
    }

    /// Construct a strict-validation error.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(ParseErrorKind::Validation, message)
    }

    /// Attach a byte location.
    pub fn with_location(mut self, location: OffsetSpan) -> Self {
        self.location = Some(location);
        self
    }

    /// Add an outer context frame without flattening the original error.
    pub fn with_context(mut self, frame: ContextFrame) -> Self {
        self.context.push(frame);
        self
    }

    /// Human-readable detail without the category prefix.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Stable lowercase dotted diagnostic code for this category.
    pub const fn code(&self) -> &'static str {
        match self.kind {
            ParseErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            ParseErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            ParseErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            ParseErrorKind::InvalidLoadCommand => INVALID_LOAD_COMMAND_CODE,
            ParseErrorKind::LimitExceeded => LIMIT_EXCEEDED_CODE,
            ParseErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            ParseErrorKind::Validation => VALIDATION_FAILED_CODE,
        }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)?;
        if let Some(location) = self.location {
            write!(
                formatter,
                " at {:#x}..{:#x}",
                location.offset,
                location.offset.saturating_add(location.len)
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for ParseError {}

/// Result returned by core parsing and structural accessors.
pub type ParseResult<T> = core::result::Result<T, ParseError>;

pub(crate) type Error = ParseError;
pub(crate) type Result<T> = ParseResult<T>;
