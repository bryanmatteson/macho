use std::fmt;

use crate::core::{ContextFrame, OffsetSpan, ParseError};

const INVALID_FORMAT_CODE: &str = "dyld_cache.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "dyld_cache.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "dyld_cache.address.invalid";
const UNSUPPORTED_INPUT_CODE: &str = "dyld_cache.input.unsupported";
const CORE_FAILED_CODE: &str = "dyld_cache.core.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The DyldCacheErrorKind type.
#[non_exhaustive]
pub enum DyldCacheErrorKind {
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
/// The DyldCacheError type.
pub struct DyldCacheError {
    /// The kind field.
    pub kind: DyldCacheErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<Box<ParseError>>,
}

impl DyldCacheError {
    /// Performs new.
    pub fn new(kind: DyldCacheErrorKind, message: impl Into<String>) -> Self {
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
        Self::new(DyldCacheErrorKind::InvalidFormat, message)
    }
    /// Performs address.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(DyldCacheErrorKind::InvalidAddress, message)
    }
    /// Performs unsupported.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(DyldCacheErrorKind::Unsupported, message)
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            DyldCacheErrorKind::OutOfBounds,
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
            DyldCacheErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            DyldCacheErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            DyldCacheErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            DyldCacheErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            DyldCacheErrorKind::Core => CORE_FAILED_CODE,
        }
    }
}

impl From<ParseError> for DyldCacheError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "dyld_cache" });
        Self {
            kind: DyldCacheErrorKind::Core,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for DyldCacheError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for DyldCacheError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, DyldCacheError>;
/// The Error type.
pub(crate) type Error = DyldCacheError;
