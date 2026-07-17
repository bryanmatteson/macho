pub use crate::dyld::types::{Export, ExportKind, FixupKind};
use crate::model::macho_file::MachoFile;

/// Performs parse.
pub fn parse(macho: &MachoFile<'_>) -> crate::Result<Vec<Export>> {
    Ok(crate::dyld::parse_exports(macho)?)
}

/// Performs find.
pub fn find(macho: &MachoFile<'_>, name: &str) -> crate::Result<Option<Export>> {
    Ok(crate::dyld::find_export(macho, name)?)
}
