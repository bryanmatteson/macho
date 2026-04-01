use crate::error::{Error, Result};
use crate::format::constants::R_SCATTERED;
use crate::format::io::pod::{self, RawRelocationInfo};
use crate::model::macho_file::MachoFile;
use crate::model::relocation::{Relocation, ScatteredRelocation, StandardRelocation};
use crate::model::section::Section;

const MAX_RELOCS_PER_SECTION: usize = 1_000_000;

/// Parse relocation entries for a given section.
pub fn relocations_for_section(macho: &MachoFile<'_>, section: &Section) -> Result<Vec<Relocation>> {
    let nreloc = section.nreloc as usize;
    if nreloc == 0 {
        return Ok(Vec::new());
    }
    if nreloc > MAX_RELOCS_PER_SECTION {
        return Err(Error::Format(format!(
            "section {},{} claims {nreloc} relocations, exceeding limit of {MAX_RELOCS_PER_SECTION}",
            section.segment_name, section.section_name
        )));
    }

    let data = macho.bytes();
    let endian = macho.endian();
    let entry_size = size_of::<RawRelocationInfo>();
    let offset = section.reloff.as_usize();

    let max_cap = data.len().saturating_sub(offset) / entry_size;
    let mut relocs = Vec::with_capacity(nreloc.min(max_cap));

    for i in 0..nreloc {
        let raw: RawRelocationInfo = pod::read_pod(data, offset + i * entry_size)?;
        let r_address = endian.interpret_i32(raw.r_address);
        let r_info = endian.interpret_u32(raw.r_symbolnum_and_flags);

        // On LE hosts (all modern Apple), the r_address word doubles as the
        // scattered relocation indicator. Check the high bit of the
        // little-endian interpretation of the first word.
        let first_word = endian.interpret_u32(raw.r_address as u32);
        if first_word & R_SCATTERED != 0 {
            // Scattered relocation (LE bit layout):
            //   bits 0-23:  r_address
            //   bit  24:    r_type (bit 0)
            //   bits 25-27: r_type (bits 1-3)
            //   bits 28-29: r_length
            //   bit  30:    r_pcrel
            //   bit  31:    R_SCATTERED (already checked)
            // Note: The r_type/r_length/r_pcrel bit layout shown above matches
            // the Apple scattered_relocation_info on LE. On BE, the layout
            // would be different. We only support LE for now.
            let address = first_word & 0x00FF_FFFF;
            let reloc_type = ((first_word >> 24) & 0xF) as u8;
            let length = ((first_word >> 28) & 0x3) as u8;
            let pc_relative = (first_word >> 30) & 1 != 0;

            relocs.push(Relocation::Scattered(ScatteredRelocation {
                reloc_type,
                length,
                pc_relative,
                address,
                value: r_info as i32,
            }));
        } else {
            // Standard relocation (LE bit layout of r_info):
            //   bits 0-23:  r_symbolnum
            //   bit  24:    r_pcrel
            //   bits 25-26: r_length
            //   bit  27:    r_extern
            //   bits 28-31: r_type
            let symbol_num = r_info & 0x00FF_FFFF;
            let pc_relative = (r_info >> 24) & 1 != 0;
            let length = ((r_info >> 25) & 0x3) as u8;
            let is_extern = (r_info >> 27) & 1 != 0;
            let reloc_type = ((r_info >> 28) & 0xF) as u8;

            relocs.push(Relocation::Standard(StandardRelocation {
                address: r_address as u32,
                symbol_num,
                pc_relative,
                length,
                is_extern,
                reloc_type,
            }));
        }
    }

    Ok(relocs)
}
