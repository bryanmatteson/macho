use std::fmt;

use macho_core::{ContextFrame, OffsetSpan, ParseError};
use macho_dyld::DyldError;

const INVALID_FORMAT_CODE: &str = "symbols.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "symbols.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "symbols.address.invalid";
const UNSUPPORTED_INPUT_CODE: &str = "symbols.input.unsupported";
const CORE_FAILED_CODE: &str = "symbols.core.failed";
const DYLD_FAILED_CODE: &str = "symbols.dyld.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The SymbolsErrorKind type.
#[non_exhaustive]
pub enum SymbolsErrorKind {
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
    /// The Dyld variant.
    Dyld,
}

#[derive(Debug)]
/// The SymbolsErrorSource type.
#[non_exhaustive]
pub enum SymbolsErrorSource {
    /// The Parse variant.
    Parse(Box<ParseError>),
    /// The Dyld variant.
    Dyld(Box<DyldError>),
}

#[derive(Debug)]
/// The SymbolsError type.
pub struct SymbolsError {
    /// The kind field.
    pub kind: SymbolsErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<SymbolsErrorSource>,
}

impl SymbolsError {
    /// Performs new.
    pub fn new(kind: SymbolsErrorKind, message: impl Into<String>) -> Self {
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
        Self::new(SymbolsErrorKind::InvalidFormat, message)
    }
    /// Performs address.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(SymbolsErrorKind::InvalidAddress, message)
    }
    /// Performs unsupported.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(SymbolsErrorKind::Unsupported, message)
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            SymbolsErrorKind::OutOfBounds,
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
            SymbolsErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            SymbolsErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            SymbolsErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            SymbolsErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            SymbolsErrorKind::Core => CORE_FAILED_CODE,
            SymbolsErrorKind::Dyld => DYLD_FAILED_CODE,
        }
    }
}

impl From<ParseError> for SymbolsError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "symbols" });
        Self {
            kind: SymbolsErrorKind::Core,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(SymbolsErrorSource::Parse(Box::new(source))),
        }
    }
}

impl From<DyldError> for SymbolsError {
    fn from(source: DyldError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "symbols" });
        Self {
            kind: SymbolsErrorKind::Dyld,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(SymbolsErrorSource::Dyld(Box::new(source))),
        }
    }
}

impl fmt::Display for SymbolsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for SymbolsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            SymbolsErrorSource::Parse(source) => source as _,
            SymbolsErrorSource::Dyld(source) => source as _,
        })
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, SymbolsError>;
