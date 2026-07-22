use std::fmt;

use macho_core::{ContextFrame, OffsetSpan, ParseError};
#[cfg(feature = "fixups")]
use macho_dyld::DyldError;

const INVALID_FORMAT_CODE: &str = "cpp.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "cpp.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "cpp.address.invalid";
const UNSUPPORTED_INPUT_CODE: &str = "cpp.input.unsupported";
const CORE_FAILED_CODE: &str = "cpp.core.failed";
#[cfg(feature = "fixups")]
const DYLD_FAILED_CODE: &str = "cpp.dyld.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The CppErrorKind type.
#[non_exhaustive]
pub enum CppErrorKind {
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
    #[cfg(feature = "fixups")]
    /// The Dyld variant.
    Dyld,
}

#[derive(Debug)]
/// The CppErrorSource type.
#[non_exhaustive]
pub enum CppErrorSource {
    /// The Parse variant.
    Parse(Box<ParseError>),
    #[cfg(feature = "fixups")]
    /// The Dyld variant.
    Dyld(Box<DyldError>),
}

#[derive(Debug)]
/// The CppError type.
pub struct CppError {
    /// The kind field.
    pub kind: CppErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<CppErrorSource>,
}

impl CppError {
    /// Performs new.
    pub fn new(kind: CppErrorKind, message: impl Into<String>) -> Self {
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
        Self::new(CppErrorKind::InvalidFormat, message)
    }
    /// Performs address.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(CppErrorKind::InvalidAddress, message)
    }
    /// Performs unsupported.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(CppErrorKind::Unsupported, message)
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            CppErrorKind::OutOfBounds,
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
            CppErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            CppErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            CppErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            CppErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            CppErrorKind::Core => CORE_FAILED_CODE,
            #[cfg(feature = "fixups")]
            CppErrorKind::Dyld => DYLD_FAILED_CODE,
        }
    }
}

impl From<ParseError> for CppError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "cpp" });
        Self {
            kind: CppErrorKind::Core,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(CppErrorSource::Parse(Box::new(source))),
        }
    }
}

#[cfg(feature = "fixups")]
impl From<DyldError> for CppError {
    fn from(source: DyldError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "cpp" });
        Self {
            kind: CppErrorKind::Dyld,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(CppErrorSource::Dyld(Box::new(source))),
        }
    }
}

impl fmt::Display for CppError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for CppError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            CppErrorSource::Parse(source) => source as _,
            #[cfg(feature = "fixups")]
            CppErrorSource::Dyld(source) => source as _,
        })
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, CppError>;
/// The Error type.
#[cfg(feature = "fixups")]
pub(crate) type Error = CppError;
