use std::fmt;

use crate::core::{ContextFrame, OffsetSpan, ParseError};

const INVALID_FORMAT_CODE: &str = "dyld.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "dyld.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "dyld.address.invalid";
const UNSUPPORTED_INPUT_CODE: &str = "dyld.input.unsupported";
const CORE_FAILED_CODE: &str = "dyld.core.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The DyldErrorKind type.
#[non_exhaustive]
pub enum DyldErrorKind {
    /// The InvalidFormat variant.
    InvalidFormat,
    /// The OutOfBounds variant.
    OutOfBounds,
    /// The InvalidAddress variant.
    InvalidAddress,
    /// The Unsupported variant.
    Unsupported,
    /// The Core variant.
    Core,
}

#[derive(Debug)]
/// The DyldError type.
pub struct DyldError {
    /// The kind field.
    pub kind: DyldErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<Box<ParseError>>,
}

impl DyldError {
    /// Performs new.
    pub fn new(kind: DyldErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            location: None,
            context: Vec::new(),
            message: message.into(),
            source: None,
        }
    }

    /// Performs format.
    pub fn format(message: impl Into<String>) -> Self {
        Self::new(DyldErrorKind::InvalidFormat, message)
    }
    /// Performs address.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(DyldErrorKind::InvalidAddress, message)
    }
    /// Performs unsupported.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(DyldErrorKind::Unsupported, message)
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            DyldErrorKind::OutOfBounds,
            format!("offset {offset:#x}, needed {needed} bytes, have {available}"),
        );
        error.location = Some(OffsetSpan {
            offset,
            len: needed,
        });
        error
    }
    /// Performs with_context.
    pub fn with_context(mut self, frame: ContextFrame) -> Self {
        self.context.push(frame);
        self
    }
    /// Performs message.
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Performs code.
    pub const fn code(&self) -> &'static str {
        match self.kind {
            DyldErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            DyldErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            DyldErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            DyldErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            DyldErrorKind::Core => CORE_FAILED_CODE,
        }
    }
}

impl From<ParseError> for DyldError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "dyld" });
        Self {
            kind: DyldErrorKind::Core,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for DyldError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}

impl std::error::Error for DyldError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, DyldError>;
/// The Error type.
pub(crate) type Error = DyldError;
