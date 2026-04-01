use crate::model::mach::MachFile;
use crate::{Error, Result};

/// Placeholder entrypoint for future C declaration recovery.
///
/// The crate exposes the module so the CLI and roadmap can stabilize around a
/// consistent surface, but there is no C recovery implementation yet.
pub fn build_headers_for_mach(_mach: &MachFile<'_>) -> Result<String> {
    Err(Error::Unsupported(
        "C header recovery is not implemented yet".into(),
    ))
}
