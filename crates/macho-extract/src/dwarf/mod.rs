use gimli::{DwarfSections, SectionId};

use crate::core::MachoFile;
use crate::{Error, Result};

pub fn has_dwarf_sections(macho: &MachoFile<'_>) -> bool {
    macho
        .all_sections()
        .any(|section| section.segment_name == "__DWARF" || section.section_name == "__debug_info")
}

pub fn load_dwarf(macho: &MachoFile<'_>) -> Result<Option<DwarfSections<Vec<u8>>>> {
    if !has_dwarf_sections(macho) {
        return Ok(None);
    }

    let dwarf = DwarfSections::load(|id| load_section_bytes(macho, id))
        .map_err(|err| Error::Format(format!("failed to load DWARF sections: {err}")))?;
    Ok(Some(dwarf))
}

fn load_section_bytes(macho: &MachoFile<'_>, id: SectionId) -> Result<Vec<u8>> {
    let wanted = macho_section_name(id);
    let Some(section) = macho
        .all_sections()
        .find(|section| section.section_name == wanted.as_str())
    else {
        return Ok(Vec::new());
    };

    if section.section_type.is_zerofill() {
        return Ok(Vec::new());
    }

    macho
        .read_bytes_at(section.offset, section.size as usize)
        .map(|bytes| bytes.to_vec())
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
