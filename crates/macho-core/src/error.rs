#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid format: {0}")]
    Format(String),

    #[error("out of bounds: offset {offset:#x}, needed {needed} bytes, have {available}")]
    Bounds {
        offset: u64,
        needed: u64,
        available: u64,
    },

    #[error("invalid address: {0}")]
    Address(String),

    #[error("invalid load command: {0}")]
    Command(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("validation: {0}")]
    Validation(String),
}

pub type Result<T> = core::result::Result<T, Error>;
