use std::fmt;

use macho_core::{ContextFrame, OffsetSpan, ParseError};

const INVALID_FORMAT_CODE: &str = "objc.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "objc.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "objc.address.invalid";
const UNSUPPORTED_INPUT_CODE: &str = "objc.input.unsupported";
const CORE_FAILED_CODE: &str = "objc.core.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The ObjcErrorKind type.
#[non_exhaustive]
pub enum ObjcErrorKind {
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
/// The ObjcError type.
pub struct ObjcError {
    /// The kind field.
    pub kind: ObjcErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<Box<ParseError>>,
}

impl ObjcError {
    /// Performs new.
    pub fn new(kind: ObjcErrorKind, message: impl Into<String>) -> Self {
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
        Self::new(ObjcErrorKind::InvalidFormat, message)
    }
    /// Performs address.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(ObjcErrorKind::InvalidAddress, message)
    }
    /// Performs unsupported.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(ObjcErrorKind::Unsupported, message)
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            ObjcErrorKind::OutOfBounds,
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
            ObjcErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            ObjcErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            ObjcErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            ObjcErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            ObjcErrorKind::Core => CORE_FAILED_CODE,
        }
    }
}

impl From<ParseError> for ObjcError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "objc" });
        Self {
            kind: ObjcErrorKind::Core,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(Box::new(source)),
        }
    }
}

#[cfg(feature = "fixups")]
impl From<macho_dyld::DyldError> for ObjcError {
    fn from(source: macho_dyld::DyldError) -> Self {
        let message = source.message().to_owned();
        let kind = match source.kind {
            macho_dyld::DyldErrorKind::InvalidFormat => ObjcErrorKind::InvalidFormat,
            macho_dyld::DyldErrorKind::OutOfBounds => ObjcErrorKind::OutOfBounds,
            macho_dyld::DyldErrorKind::InvalidAddress => ObjcErrorKind::InvalidAddress,
            macho_dyld::DyldErrorKind::Unsupported => ObjcErrorKind::Unsupported,
            macho_dyld::DyldErrorKind::Core => ObjcErrorKind::Core,
            _ => ObjcErrorKind::Core,
        };
        let mut context = source.context;
        context.push(ContextFrame::Operation { name: "objc" });
        Self {
            kind,
            location: source.location,
            context,
            message,
            source: source.source,
        }
    }
}

impl fmt::Display for ObjcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for ObjcError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, ObjcError>;
/// The Error type.
pub(crate) type Error = ObjcError;
