pub use crate::dyld::types::{Export, ExportKind, FixupKind};
use crate::model::macho_file::MachoFile;

pub fn parse(macho: &MachoFile<'_>) -> crate::Result<Vec<Export>> {
    crate::dyld::parse_exports(macho)
}

pub fn find(macho: &MachoFile<'_>, name: &str) -> crate::Result<Option<Export>> {
    crate::dyld::find_export(macho, name)
}
