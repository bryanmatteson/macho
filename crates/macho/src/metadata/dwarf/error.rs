use std::fmt;

use crate::core::{ContextFrame, OffsetSpan, ParseError};

const INVALID_FORMAT_CODE: &str = "dwarf.format.invalid";
const OUT_OF_BOUNDS_CODE: &str = "dwarf.bounds.exceeded";
const INVALID_ADDRESS_CODE: &str = "dwarf.address.invalid";
const UNSUPPORTED_INPUT_CODE: &str = "dwarf.input.unsupported";
const CORE_FAILED_CODE: &str = "dwarf.core.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The DwarfErrorKind type.
#[non_exhaustive]
pub enum DwarfErrorKind {
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
/// The DwarfError type.
pub struct DwarfError {
    /// The kind field.
    pub kind: DwarfErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<Box<ParseError>>,
}

impl DwarfError {
    /// Performs new.
    pub fn new(kind: DwarfErrorKind, message: impl Into<String>) -> Self {
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
        Self::new(DwarfErrorKind::InvalidFormat, message)
    }
    /// Performs address.
    pub fn address(message: impl Into<String>) -> Self {
        Self::new(DwarfErrorKind::InvalidAddress, message)
    }
    /// Performs unsupported.
    pub fn unsupported(message: impl Into<String>) -> Self {
        Self::new(DwarfErrorKind::Unsupported, message)
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            DwarfErrorKind::OutOfBounds,
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
            DwarfErrorKind::InvalidFormat => INVALID_FORMAT_CODE,
            DwarfErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            DwarfErrorKind::InvalidAddress => INVALID_ADDRESS_CODE,
            DwarfErrorKind::Unsupported => UNSUPPORTED_INPUT_CODE,
            DwarfErrorKind::Core => CORE_FAILED_CODE,
        }
    }
}

impl From<ParseError> for DwarfError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation { name: "dwarf" });
        Self {
            kind: DwarfErrorKind::Core,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(Box::new(source)),
        }
    }
}

impl fmt::Display for DwarfError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for DwarfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref().map(|source| source as _)
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, DwarfError>;
/// The Error type.
pub(crate) type Error = DwarfError;
