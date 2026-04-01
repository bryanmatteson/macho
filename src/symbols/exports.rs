pub use crate::metadata::dyld::types::{Export, ExportKind, FixupKind};
use crate::model::mach_file::MachFile;

pub fn parse(mach: &MachFile<'_>) -> crate::Result<Vec<Export>> {
    crate::metadata::dyld::parse_exports(mach)
}

pub fn find(mach: &MachFile<'_>, name: &str) -> crate::Result<Option<Export>> {
    crate::metadata::dyld::find_export(mach, name)
}
