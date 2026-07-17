use crate::error::Result;
use crate::format::constants::{SECTION_ATTRIBUTES_MASK, SectionAttributes};
use crate::format::io::endian::Endian;
use crate::format::io::pod::{self, RawSection32, RawSection64};
use crate::model::addr::ThinFileOffset;
use crate::model::addr::Va;
use crate::model::names::{SectionName, SegmentName};
use crate::model::section::{Section, SectionType};

/// Performs parse_sections_32.
pub fn parse_sections_32(
    data: &[u8],
    endian: Endian,
    offset: usize,
    count: u32,
) -> Result<Vec<Section>> {
    let sect_size = size_of::<RawSection32>();
    let max_sects = data.len().saturating_sub(offset) / sect_size;
    let mut sections = Vec::with_capacity((count as usize).min(max_sects));

    for i in 0..count as usize {
        let raw: RawSection32 = pod::read_pod(data, offset + i * sect_size)?;
        let flags = endian.interpret_u32(raw.flags);

        sections.push(Section {
            section_name: SectionName::from_bytes(raw.sectname),
            segment_name: SegmentName::from_bytes(raw.segname),
            addr: Va(endian.interpret_u32(raw.addr) as u64),
            size: endian.interpret_u32(raw.size) as u64,
            offset: ThinFileOffset(endian.interpret_u32(raw.offset) as u64),
            align: endian.interpret_u32(raw.align),
            reloff: ThinFileOffset(endian.interpret_u32(raw.reloff) as u64),
            nreloc: endian.interpret_u32(raw.nreloc),
            section_type: SectionType::from_flags(flags),
            attributes: SectionAttributes::from_bits_truncate(flags & SECTION_ATTRIBUTES_MASK),
            reserved1: endian.interpret_u32(raw.reserved1),
            reserved2: endian.interpret_u32(raw.reserved2),
            reserved3: 0,
        });
    }

    Ok(sections)
}

/// Performs parse_sections_64.
pub fn parse_sections_64(
    data: &[u8],
    endian: Endian,
    offset: usize,
    count: u32,
) -> Result<Vec<Section>> {
    let sect_size = size_of::<RawSection64>();
    let max_sects = data.len().saturating_sub(offset) / sect_size;
    let mut sections = Vec::with_capacity((count as usize).min(max_sects));

    for i in 0..count as usize {
        let raw: RawSection64 = pod::read_pod(data, offset + i * sect_size)?;
        let flags = endian.interpret_u32(raw.flags);

        sections.push(Section {
            section_name: SectionName::from_bytes(raw.sectname),
            segment_name: SegmentName::from_bytes(raw.segname),
            addr: Va(endian.interpret_u64(raw.addr)),
            size: endian.interpret_u64(raw.size),
            offset: ThinFileOffset(endian.interpret_u32(raw.offset) as u64),
            align: endian.interpret_u32(raw.align),
            reloff: ThinFileOffset(endian.interpret_u32(raw.reloff) as u64),
            nreloc: endian.interpret_u32(raw.nreloc),
            section_type: SectionType::from_flags(flags),
            attributes: SectionAttributes::from_bits_truncate(flags & SECTION_ATTRIBUTES_MASK),
            reserved1: endian.interpret_u32(raw.reserved1),
            reserved2: endian.interpret_u32(raw.reserved2),
            reserved3: endian.interpret_u32(raw.reserved3),
        });
    }

    Ok(sections)
}
