use macho_core::format::constants::SectionAttributes;
use macho_core::model::section::SectionType;
use macho_core::model::segment::Segment;

use crate::{Error, Result};

const MAX_MACHO_NAME_LEN: usize = 16;
const MAX_ALIGNMENT_EXPONENT: u32 = 31;

/// Bytes or virtual storage carried by a newly added section.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SectionContent {
    /// File-backed section contents.
    FileBacked(Vec<u8>),
    /// Zero-filled virtual storage with no bytes in the file.
    ZeroFill(u64),
}

impl SectionContent {
    /// Return the section's virtual size.
    pub fn size(&self) -> u64 {
        match self {
            Self::FileBacked(bytes) => bytes.len() as u64,
            Self::ZeroFill(size) => *size,
        }
    }

    /// Return file-backed contents, if any.
    pub fn file_bytes(&self) -> Option<&[u8]> {
        match self {
            Self::FileBacked(bytes) => Some(bytes),
            Self::ZeroFill(_) => None,
        }
    }
}

/// Owned request to add one section to an existing segment.
///
/// Names use Mach-O's fixed 16-byte representation. Construction rejects
/// empty, overlong, or NUL-containing names so an accepted request cannot be
/// truncated during encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddSection {
    segment_name: String,
    section_name: String,
    content: SectionContent,
    align: u32,
    section_type: SectionType,
    attributes: SectionAttributes,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

impl AddSection {
    /// Create a regular file-backed section.
    pub fn new(
        segment_name: impl Into<String>,
        section_name: impl Into<String>,
        data: impl Into<Vec<u8>>,
    ) -> Result<Self> {
        Self::with_content(
            segment_name,
            section_name,
            SectionContent::FileBacked(data.into()),
        )
    }

    /// Create a zero-filled section with the requested virtual size.
    pub fn zero_fill(
        segment_name: impl Into<String>,
        section_name: impl Into<String>,
        size: u64,
    ) -> Result<Self> {
        Self::with_content(segment_name, section_name, SectionContent::ZeroFill(size))
    }

    fn with_content(
        segment_name: impl Into<String>,
        section_name: impl Into<String>,
        content: SectionContent,
    ) -> Result<Self> {
        let segment_name = segment_name.into();
        let section_name = section_name.into();
        validate_name("segment", &segment_name)?;
        validate_name("section", &section_name)?;
        let section_type = match content {
            SectionContent::FileBacked(_) => SectionType::Regular,
            SectionContent::ZeroFill(_) => SectionType::ZeroFill,
        };
        Ok(Self {
            segment_name,
            section_name,
            content,
            align: 0,
            section_type,
            attributes: SectionAttributes::empty(),
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        })
    }

    /// Set the base-two alignment exponent.
    pub fn with_alignment(mut self, align: u32) -> Result<Self> {
        if align > MAX_ALIGNMENT_EXPONENT {
            return Err(Error::invalid(format!(
                "section alignment exponent {align} exceeds {MAX_ALIGNMENT_EXPONENT}"
            )));
        }
        self.align = align;
        Ok(self)
    }

    /// Set the encoded Mach-O section type.
    ///
    /// Zero-fill content requires a zero-fill type, and file-backed content
    /// requires a non-zero-fill type. This invariant is checked when the
    /// operation is applied so builder calls remain order-independent.
    pub fn with_section_type(mut self, section_type: SectionType) -> Self {
        self.section_type = section_type;
        self
    }

    /// Set encoded section attributes.
    pub fn with_attributes(mut self, attributes: SectionAttributes) -> Self {
        self.attributes = attributes;
        self
    }

    /// Set the three type-specific reserved words.
    pub fn with_reserved(mut self, reserved1: u32, reserved2: u32, reserved3: u32) -> Self {
        self.reserved1 = reserved1;
        self.reserved2 = reserved2;
        self.reserved3 = reserved3;
        self
    }

    /// Name of the existing segment that will contain the section.
    pub fn segment_name(&self) -> &str {
        &self.segment_name
    }

    /// Name of the section to add.
    pub fn section_name(&self) -> &str {
        &self.section_name
    }

    /// Section contents or zero-fill extent.
    pub fn content(&self) -> &SectionContent {
        &self.content
    }

    /// Base-two alignment exponent.
    pub const fn alignment(&self) -> u32 {
        self.align
    }

    /// Encoded Mach-O section type.
    pub const fn section_type(&self) -> SectionType {
        self.section_type
    }

    /// Encoded Mach-O section attributes.
    pub const fn attributes(&self) -> SectionAttributes {
        self.attributes
    }

    /// Type-specific reserved words.
    pub const fn reserved(&self) -> (u32, u32, u32) {
        (self.reserved1, self.reserved2, self.reserved3)
    }
}

fn validate_name(kind: &str, name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(Error::invalid(format!("{kind} name must not be empty")));
    }
    if name.as_bytes().contains(&0) {
        return Err(Error::invalid(format!("{kind} name must not contain NUL")));
    }
    if name.len() > MAX_MACHO_NAME_LEN {
        return Err(Error::invalid(format!(
            "{kind} name {name:?} is {} bytes; Mach-O permits at most {MAX_MACHO_NAME_LEN}",
            name.len()
        )));
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub(crate) struct PlacedSection {
    pub(crate) request: AddSection,
    pub(crate) address: u64,
    pub(crate) file_offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct EditableSegment {
    pub(crate) original: Segment,
    pub(crate) vm_size: u64,
    pub(crate) file_size: u64,
    pub(crate) added_sections: Vec<PlacedSection>,
}

impl From<Segment> for EditableSegment {
    fn from(original: Segment) -> Self {
        Self {
            vm_size: original.vm_size(),
            file_size: original.file_size(),
            original,
            added_sections: Vec::new(),
        }
    }
}

pub(crate) fn place_section(
    segments: &mut [EditableSegment],
    input_len: usize,
    request: AddSection,
) -> Result<()> {
    validate_content_type(&request)?;

    let matching = segments
        .iter()
        .enumerate()
        .filter(|(_, segment)| segment.original.name() == request.segment_name())
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    let target_index = match matching.as_slice() {
        [] => {
            return Err(Error::invalid(format!(
                "segment {} not found",
                request.segment_name()
            )));
        }
        [index] => *index,
        _ => {
            return Err(Error::invalid(format!(
                "segment name {} is ambiguous",
                request.segment_name()
            )));
        }
    };

    let duplicate = segments[target_index]
        .original
        .sections()
        .iter()
        .any(|section| section.section_name() == request.section_name())
        || segments[target_index]
            .added_sections
            .iter()
            .any(|section| section.request.section_name() == request.section_name());
    if duplicate {
        return Err(Error::invalid(format!(
            "section {},{} already exists",
            request.segment_name(),
            request.section_name()
        )));
    }

    let alignment = 1u64
        .checked_shl(request.alignment())
        .ok_or_else(|| Error::invalid("section alignment overflow"))?;
    let target = &segments[target_index];
    let segment_file_start = target.original.file_offset().0;
    let segment_vm_start = target.original.vm_addr().0;

    let (file_offset, address, new_file_size, new_vm_size) = match request.content() {
        SectionContent::FileBacked(bytes) => {
            if target.original.name() == "__PAGEZERO" {
                return Err(Error::invalid("cannot add file-backed data to __PAGEZERO"));
            }
            let declared_end = segment_file_start
                .checked_add(target.file_size)
                .ok_or_else(|| Error::invalid("segment file range overflow"))?;
            let next_file_start = segments
                .iter()
                .enumerate()
                .filter(|(index, segment)| {
                    *index != target_index
                        && segment.original.file_size() > 0
                        && segment.original.file_offset().0 >= declared_end
                })
                .map(|(_, segment)| segment.original.file_offset().0)
                .min();
            let placement_base = if next_file_start.is_some() {
                declared_end
            } else {
                declared_end.max(input_len as u64)
            };
            let file_offset = align_up(placement_base, alignment)?;
            let file_end = file_offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::invalid("new section file range overflow"))?;
            if let Some(limit) = next_file_start {
                if file_end > limit {
                    return Err(Error::invalid(format!(
                        "section {},{} needs file range {file_offset:#x}..{file_end:#x}, but the next segment starts at {limit:#x}",
                        request.segment_name(),
                        request.section_name()
                    )));
                }
            }
            let relative = file_offset
                .checked_sub(segment_file_start)
                .ok_or_else(|| Error::invalid("new section file offset precedes its segment"))?;
            let address = segment_vm_start
                .checked_add(relative)
                .ok_or_else(|| Error::invalid("new section address overflow"))?;
            let vm_end = address
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::invalid("new section VM range overflow"))?;
            (
                file_offset,
                address,
                file_end - segment_file_start,
                target.vm_size.max(vm_end - segment_vm_start),
            )
        }
        SectionContent::ZeroFill(size) => {
            let used_vm_end = target
                .original
                .sections()
                .iter()
                .map(|section| section.addr().0.saturating_add(section.size()))
                .chain(target.added_sections.iter().map(|section| {
                    section
                        .address
                        .saturating_add(section.request.content().size())
                }))
                .max()
                .unwrap_or(segment_vm_start)
                .max(segment_vm_start.saturating_add(target.file_size));
            let address = align_up(used_vm_end, alignment)?;
            let vm_end = address
                .checked_add(*size)
                .ok_or_else(|| Error::invalid("new zero-fill section VM range overflow"))?;
            (
                0,
                address,
                target.file_size,
                target.vm_size.max(vm_end - segment_vm_start),
            )
        }
    };

    let new_vm_end = segment_vm_start
        .checked_add(new_vm_size)
        .ok_or_else(|| Error::invalid("extended segment VM range overflow"))?;
    if let Some(next_vm_start) = segments
        .iter()
        .enumerate()
        .filter(|(index, segment)| {
            *index != target_index && segment.original.vm_addr().0 >= segment_vm_start
        })
        .map(|(_, segment)| segment.original.vm_addr().0)
        .filter(|address| *address > segment_vm_start)
        .min()
    {
        if new_vm_end > next_vm_start {
            return Err(Error::invalid(format!(
                "section {},{} would extend segment {} through {new_vm_end:#x}, overlapping the next segment at {next_vm_start:#x}",
                request.segment_name(),
                request.section_name(),
                request.segment_name()
            )));
        }
    }

    let target = &mut segments[target_index];
    target.file_size = new_file_size;
    target.vm_size = new_vm_size;
    target.added_sections.push(PlacedSection {
        request,
        address,
        file_offset,
    });
    Ok(())
}

fn validate_content_type(request: &AddSection) -> Result<()> {
    let content_is_zero_fill = matches!(request.content(), SectionContent::ZeroFill(_));
    if content_is_zero_fill != request.section_type().is_zerofill() {
        return Err(Error::invalid(format!(
            "section {},{} content does not match section type {}",
            request.segment_name(),
            request.section_name(),
            request.section_type().name()
        )));
    }
    Ok(())
}

fn align_up(value: u64, alignment: u64) -> Result<u64> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|rounded| rounded & !(alignment - 1))
        .ok_or_else(|| Error::invalid("section alignment overflow"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_are_validated_without_truncation() {
        assert!(AddSection::new("", "__x", []).is_err());
        assert!(AddSection::new("__DATA", "0123456789abcdefg", []).is_err());
        assert!(AddSection::new("__DATA", "bad\0name", []).is_err());
        assert!(AddSection::new("0123456789abcdef", "0123456789abcdef", []).is_ok());
    }

    #[test]
    fn alignment_is_bounded() {
        let request = AddSection::new("__DATA", "__x", []).expect("valid names");
        assert!(request.clone().with_alignment(31).is_ok());
        assert!(request.with_alignment(32).is_err());
    }
}
