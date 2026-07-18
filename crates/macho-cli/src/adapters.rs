//! Delivery-owned adapters at explicit process and filesystem boundaries.

mod signing;

use std::path::Path;

use anyhow::{Context, Result, bail};
use macho::header_syntax::{
    HeaderParser as _, Language, TreeSitterHeaderParser, ValidationLimits, validate,
};

pub use signing::HostSignatureProvider;

/// Validates a complete C header in-process.
pub fn validate_c_header(source: &str) -> Result<()> {
    validate_header(Language::C, source)
}

/// Validates a complete C++ header from `path` in-process.
pub fn validate_cpp_header(path: &Path) -> Result<()> {
    let source = std::fs::read_to_string(path)
        .with_context(|| format!("read C++ header {}", path.display()))?;
    validate_header(Language::Cpp, &source)
}

fn validate_header(language: Language, source: &str) -> Result<()> {
    let unit = TreeSitterHeaderParser
        .parse(language, source)
        .map_err(anyhow::Error::new)?;
    let report = validate(&unit, ValidationLimits::default()).map_err(anyhow::Error::new)?;
    if !report.semantic_valid {
        let diagnostics = report
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{:?}: {}", diagnostic.code, diagnostic.message))
            .collect::<Vec<_>>()
            .join("; ");
        bail!("header semantic validation failed: {diagnostics}");
    }
    Ok(())
}
