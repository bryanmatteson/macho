use std::fmt;

use macho_core::OffsetSpan;
use macho_insn::{DecodeError, EncodeError};

const INVALID_INPUT_CODE: &str = "patch.input.invalid";
const OUT_OF_BOUNDS_CODE: &str = "patch.bounds.exceeded";
const INSTRUCTION_FAILED_CODE: &str = "patch.instruction.failed";

/// Stable category for executable patch-planning failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum PatchErrorKind {
    /// Invalid patch request or unsupported patch architecture.
    InvalidInput,
    /// A patch range exceeds its admitted byte buffer.
    OutOfBounds,
    /// Instruction decoding or encoding failed.
    Instruction,
}

/// Typed lower-level source for a patch-planning failure.
#[derive(Debug)]
#[non_exhaustive]
pub enum PatchErrorSource {
    /// Instruction decoding failed.
    Decode(Box<DecodeError>),
    /// Instruction encoding failed.
    Encode(Box<EncodeError>),
}

/// Executable patch-planning failure with stable kind and byte location.
#[derive(Debug)]
pub struct PatchError {
    /// Stable failure category.
    pub kind: PatchErrorKind,
    /// Relevant offset within the inspected instruction sequence.
    pub location: Option<OffsetSpan>,
    message: String,
    /// Typed lower-level source.
    pub source: Option<PatchErrorSource>,
}

impl PatchError {
    /// Construct an invalid-input failure.
    pub fn invalid(message: impl Into<String>) -> Self {
        Self {
            kind: PatchErrorKind::InvalidInput,
            location: None,
            message: message.into(),
            source: None,
        }
    }

    /// Construct a byte-range failure.
    pub fn bounds(offset: u64, needed: u64, available: u64) -> Self {
        Self {
            kind: PatchErrorKind::OutOfBounds,
            location: Some(OffsetSpan {
                offset,
                len: needed,
            }),
            message: format!("offset {offset:#x}, needed {needed} bytes, have {available}"),
            source: None,
        }
    }

    /// Human-readable failure detail.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Stable diagnostic code.
    pub const fn code(&self) -> &'static str {
        match self.kind {
            PatchErrorKind::InvalidInput => INVALID_INPUT_CODE,
            PatchErrorKind::OutOfBounds => OUT_OF_BOUNDS_CODE,
            PatchErrorKind::Instruction => INSTRUCTION_FAILED_CODE,
        }
    }
}

impl From<DecodeError> for PatchError {
    fn from(source: DecodeError) -> Self {
        Self {
            kind: PatchErrorKind::Instruction,
            location: None,
            message: source.message.clone(),
            source: Some(PatchErrorSource::Decode(Box::new(source))),
        }
    }
}

impl From<EncodeError> for PatchError {
    fn from(source: EncodeError) -> Self {
        Self {
            kind: PatchErrorKind::Instruction,
            location: None,
            message: source.message.clone(),
            source: Some(PatchErrorSource::Encode(Box::new(source))),
        }
    }
}

impl fmt::Display for PatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code(), self.message)
    }
}

impl std::error::Error for PatchError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|source| match source {
            PatchErrorSource::Decode(source) => source as _,
            PatchErrorSource::Encode(source) => source as _,
        })
    }
}

/// Executable patch-planning result.
pub type Result<T> = std::result::Result<T, PatchError>;
pub(crate) type Error = PatchError;
