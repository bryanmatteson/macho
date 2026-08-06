#![deny(missing_docs)]
//! DWARF section loading and typed indexes.
//!
//! Depend on this crate directly for DWARF indexes without the `macho` façade:
//! [`crate::metadata::dwarf::has_dwarf_sections`] /
//! [`crate::metadata::dwarf::load_dwarf`] on a [`crate::core::MachoFile`].

pub use crate::core::MachoFile;
pub use crate::core::model;

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{DwarfError, DwarfErrorKind, Result};

#[allow(non_upper_case_globals)]
pub mod functions;
mod traversal;
pub mod types;

pub use functions::{DwarfFunctionIndex, DwarfVariableIndex};
pub use traversal::{
    DwarfAttributeRecord, DwarfEntryRecord, DwarfLineRowRecord, DwarfRangeEntryRecord,
    DwarfRangeListRecord, DwarfSectionReceipt, DwarfSourceFileRecord, DwarfTraversal,
    DwarfTraversalLimits, DwarfUnitRecord, traverse_dwarf,
};

use gimli::{DwarfSections, SectionId};

/// Performs has_dwarf_sections.
pub fn has_dwarf_sections(macho: &MachoFile<'_>) -> bool {
    macho
        .all_sections()
        .any(|section| section.section_name() == "__debug_info" && section.size() > 0)
}

/// Performs load_dwarf.
pub fn load_dwarf(macho: &MachoFile<'_>) -> Result<Option<DwarfSections<Vec<u8>>>> {
    if !has_dwarf_sections(macho) {
        return Ok(None);
    }

    let dwarf = DwarfSections::load(|id| load_section_bytes(macho, id))
        .map_err(|err| Error::format(format!("failed to load DWARF sections: {err}")))?;
    Ok(Some(dwarf))
}

fn load_section_bytes(macho: &MachoFile<'_>, id: SectionId) -> Result<Vec<u8>> {
    let wanted = macho_section_name(id);
    let Some(section) = macho
        .all_sections()
        .find(|section| section.section_name() == wanted.as_str())
    else {
        return Ok(Vec::new());
    };

    if section.section_type().is_zerofill() {
        return Ok(Vec::new());
    }

    Ok(macho
        .read_bytes_at(section.offset(), section.size() as usize)
        .map(|bytes| bytes.to_vec())?)
}

fn macho_section_name(id: SectionId) -> String {
    match id.name() {
        ".debug_str_offsets" => "__debug_str_offs".to_string(),
        ".debug_loclists" => "__debug_loclists".to_string(),
        ".debug_rnglists" => "__debug_rnglists".to_string(),
        ".debug_line_str" => "__debug_line_str".to_string(),
        ".debug_names" => "__debug_names".to_string(),
        raw => {
            if let Some(stripped) = raw.strip_prefix('.') {
                format!("__{stripped}")
            } else {
                raw.replace('.', "__")
            }
        }
    }
}
