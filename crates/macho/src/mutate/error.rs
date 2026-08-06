use std::fmt;

use crate::core::{ContextFrame, OffsetSpan, ParseError};
use crate::metadata::codesign::CodesignError;

const INVALID_INPUT_CODE: &str = "mutation.input.invalid";
const OUT_OF_BOUNDS_CODE: &str = "mutation.bounds.exceeded";
const VALIDATION_FAILED_CODE: &str = "mutation.validation.failed";
const PARSE_FAILED_CODE: &str = "mutation.parse.failed";
const CODESIGN_FAILED_CODE: &str = "mutation.codesign.failed";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The MutationOperation type.
#[non_exhaustive]
pub enum MutationOperation {
    /// The EditLoadCommands variant.
    EditLoadCommands,
    /// The Layout variant.
    Layout,
    /// The Patch variant.
    Patch,
    /// The Sign variant.
    Sign,
    /// The Validate variant.
    Validate,
    /// The Serialize variant.
    Serialize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The MutationErrorKind type.
#[non_exhaustive]
pub enum MutationErrorKind {
    /// The InvalidInput variant.
    InvalidInput,
    /// The OutOfBounds variant.
    OutOfBounds,
    /// The Validation variant.
    Validation,
    /// The Parse variant.
    Parse,
    /// The Codesign variant.
    Codesign,
}

#[derive(Debug)]
/// The MutationErrorSource type.
#[non_exhaustive]
pub enum MutationErrorSource {
    /// The Parse variant.
    Parse(Box<ParseError>),
    /// The Codesign variant.
    Codesign(Box<CodesignError>),
}

#[derive(Debug)]
/// The MutationError type.
pub struct MutationError {
    /// The operation field.
    pub operation: MutationOperation,
    /// The kind field.
    pub kind: MutationErrorKind,
    /// The location field.
    pub location: Option<OffsetSpan>,
    /// The context field.
    pub context: Vec<ContextFrame>,
    message: String,
    /// The source field.
    pub source: Option<MutationErrorSource>,
}

impl MutationError {
    /// Performs new.
    pub fn new(
        operation: MutationOperation,
        kind: MutationErrorKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            operation,
            kind,
            location: None,
            context: Vec::new(),
            message: message.into(),
            source: None,
        }
    }
    /// Performs invalid.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self::new(
            MutationOperation::Patch,
            MutationErrorKind::InvalidInput,
            message,
        )
    }
    /// Performs validation.
    pub fn validation(message: impl Into<String>) -> Self {
        Self::new(
            MutationOperation::Validate,
            MutationErrorKind::Validation,
            message,
        )
    }
    /// Performs bounds.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        let mut error = Self::new(
            MutationOperation::Patch,
            MutationErrorKind::OutOfBounds,
            format!("offset {offset:#x}, needed {needed} bytes, have {available}"),
        );
        error.location = Some(OffsetSpan {
            offset,
            len: needed,
        });
        error
    }
    /// Performs message.
    pub fn message(&self) -> &str {
        &self.message
    }
    /// Performs code.
    pub const fn code(&self) -> &'static str {
        match self.kind {
            MutationErrorKind::InvalidInput => INVALID_INPUT_CODE,
            MutationErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            MutationErrorKind::Validation => VALIDATION_FAILED_CODE,
            MutationErrorKind::Parse => PARSE_FAILED_CODE,
            MutationErrorKind::Codesign => CODESIGN_FAILED_CODE,
        }
    }
}

impl From<ParseError> for MutationError {
    fn from(source: ParseError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation {
            name: "mutation.validate",
        });
        Self {
            operation: MutationOperation::Validate,
            kind: MutationErrorKind::Parse,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(MutationErrorSource::Parse(Box::new(source))),
        }
    }
}
impl From<CodesignError> for MutationError {
    fn from(source: CodesignError) -> Self {
        let mut context = source.context.clone();
        context.push(ContextFrame::Operation {
            name: "mutation.sign",
        });
        Self {
            operation: MutationOperation::Sign,
            kind: MutationErrorKind::Codesign,
            location: source.location,
            context,
            message: source.message().to_owned(),
            source: Some(MutationErrorSource::Codesign(Box::new(source))),
        }
    }
}
impl fmt::Display for MutationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}
impl std::error::Error for MutationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            MutationErrorSource::Parse(source) => source as _,
            MutationErrorSource::Codesign(source) => source as _,
        })
    }
}

/// The Result type.
pub type Result<T> = std::result::Result<T, MutationError>;
/// The Error type.
pub(crate) type Error = MutationError;
