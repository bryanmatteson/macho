use gimli::{Dwarf, SectionId};

use crate::error::{Error, Result};
use crate::model::mach::MachFile;

pub fn has_dwarf_sections(mach: &MachFile<'_>) -> bool {
    mach.all_sections()
        .any(|section| section.segment_name == "__DWARF" || section.section_name == "__debug_info")
}

pub fn load_dwarf(mach: &MachFile<'_>) -> Result<Option<Dwarf<Vec<u8>>>> {
    if !has_dwarf_sections(mach) {
        return Ok(None);
    }

    let dwarf = Dwarf::load(|id| load_section_bytes(mach, id))
        .map_err(|err| Error::Format(format!("failed to load DWARF sections: {err}")))?;
    Ok(Some(dwarf))
}

fn load_section_bytes(mach: &MachFile<'_>, id: SectionId) -> Result<Vec<u8>> {
    let wanted = macho_section_name(id);
    let Some(section) = mach
        .all_sections()
        .find(|section| section.section_name == wanted.as_str())
    else {
        return Ok(Vec::new());
    };

    if section.section_type.is_zerofill() {
        return Ok(Vec::new());
    }

    mach.read_bytes_at(section.offset, section.size as usize)
        .map(|bytes| bytes.to_vec())
}

fn macho_section_name(id: SectionId) -> String {
    let raw = id.name();
    if let Some(stripped) = raw.strip_prefix('.') {
        format!("__{stripped}")
    } else {
        raw.replace('.', "__")
    }
}
