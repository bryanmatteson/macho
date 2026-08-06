use std::io;

/// Output rendering failure.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Writing to the injected output stream failed.
    #[error("output I/O failed: {0}")]
    Io(#[from] io::Error),

    /// JSON serialization failed.
    #[error("JSON serialization failed: {0}")]
    Json(#[from] serde_json::Error),

    /// A command selected for JSON delivery returned bytes that were not JSON.
    #[error("command returned a non-JSON report: {0}")]
    InvalidJsonReport(#[source] serde_json::Error),
}

/// Result alias for output rendering operations.
pub type Result<T> = std::result::Result<T, Error>;
