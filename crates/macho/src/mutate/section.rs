use crate::core::format::constants::SectionAttributes;
use crate::core::model::header::Bitness;
use crate::core::model::section::SectionType;
use crate::core::model::segment::Segment;

use crate::mutate::{Error, Result};

const MAX_MACHO_NAME_LEN: usize = 16;
const MAX_ALIGNMENT_EXPONENT: u32 = 31;
const MAX_FILE_PADDING: u64 = 16 * 1024 * 1024;

/// Bytes or virtual storage carried by a newly added section.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SectionContent<'data> {
    /// File-backed section contents.
    FileBacked(&'data [u8]),
    /// Zero-filled virtual storage with no bytes in the file.
    ZeroFill(u64),
}

impl SectionContent<'_> {
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

/// Borrowed request to add one section to an existing segment.
///
/// Names use Mach-O's fixed 16-byte representation. Construction rejects
/// empty, overlong, or NUL-containing names so an accepted request cannot be
/// truncated during encoding.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AddSection<'data> {
    segment_name: MachoName,
    section_name: MachoName,
    content: SectionContent<'data>,
    align: u32,
    section_type: SectionType,
    attributes: SectionAttributes,
    reserved1: u32,
    reserved2: u32,
    reserved3: u32,
}

impl<'data> AddSection<'data> {
    /// Create a regular file-backed section borrowing a byte source.
    ///
    /// The source is never copied. Raw slices, vectors, and read-only memory
    /// maps can all be passed by reference through [`AsRef<[u8]>`]. Successful
    /// construction performs no internal heap allocation.
    pub fn new<S>(
        segment_name: impl AsRef<str>,
        section_name: impl AsRef<str>,
        data: &'data S,
    ) -> Result<Self>
    where
        S: AsRef<[u8]> + ?Sized,
    {
        Self::with_content(
            segment_name,
            section_name,
            SectionContent::FileBacked(data.as_ref()),
        )
    }

    /// Create a zero-filled section with the requested virtual size.
    pub fn zero_fill(
        segment_name: impl AsRef<str>,
        section_name: impl AsRef<str>,
        size: u64,
    ) -> Result<Self> {
        Self::with_content(segment_name, section_name, SectionContent::ZeroFill(size))
    }

    fn with_content(
        segment_name: impl AsRef<str>,
        section_name: impl AsRef<str>,
        content: SectionContent<'data>,
    ) -> Result<Self> {
        let segment_name = MachoName::new("segment", segment_name.as_ref())?;
        let section_name = MachoName::new("section", section_name.as_ref())?;
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
    /// requires a non-zero-fill type. A mismatch is rejected immediately.
    pub fn with_section_type(mut self, section_type: SectionType) -> Result<Self> {
        self.section_type = section_type;
        validate_content_type(&self)?;
        Ok(self)
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
        self.segment_name.as_str()
    }

    /// Name of the section to add.
    pub fn section_name(&self) -> &str {
        self.section_name.as_str()
    }

    /// Section contents or zero-fill extent.
    pub fn content(&self) -> &SectionContent<'data> {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MachoName {
    bytes: [u8; MAX_MACHO_NAME_LEN],
    len: u8,
}

impl MachoName {
    fn new(kind: &str, name: &str) -> Result<Self> {
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
        let mut bytes = [0; MAX_MACHO_NAME_LEN];
        bytes[..name.len()].copy_from_slice(name.as_bytes());
        Ok(Self {
            bytes,
            len: name.len() as u8,
        })
    }

    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..usize::from(self.len)])
            .expect("MachoName is constructed only from valid UTF-8")
    }
}

#[derive(Debug, Clone)]
pub(crate) struct PlacedSection<'data> {
    pub(crate) request: AddSection<'data>,
    pub(crate) address: u64,
    pub(crate) file_offset: u64,
}

#[derive(Debug, Clone)]
pub(crate) struct EditableSegment<'data> {
    pub(crate) original: Segment,
    pub(crate) vm_size: u64,
    pub(crate) file_size: u64,
    pub(crate) added_sections: Vec<PlacedSection<'data>>,
}

impl From<Segment> for EditableSegment<'_> {
    fn from(original: Segment) -> Self {
        Self {
            vm_size: original.vm_size(),
            file_size: original.file_size(),
            original,
            added_sections: Vec::new(),
        }
    }
}

pub(crate) fn place_section<'data>(
    segments: &mut [EditableSegment<'data>],
    input_len: usize,
    bitness: Bitness,
    request: AddSection<'data>,
) -> Result<()> {
    validate_content_type(&request)?;
    if bitness == Bitness::Bits32 && request.reserved3 != 0 {
        return Err(Error::invalid(
            "reserved3 is not representable in a 32-bit Mach-O section",
        ));
    }

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
            let next_file_segment = segments
                .iter()
                .enumerate()
                .filter(|(index, segment)| {
                    *index != target_index
                        && segment.original.file_size() > 0
                        && segment.original.file_offset().0 > segment_file_start
                })
                .map(|(_, segment)| segment.original.file_offset().0)
                .min();
            let input_len =
                u64::try_from(input_len).map_err(|_| Error::invalid("input length exceeds u64"))?;
            if next_file_segment.is_none()
                && target.file_size == target.original.file_size()
                && declared_end != input_len
            {
                return Err(Error::invalid(format!(
                    "cannot extend segment {}: its declared file range ends at {declared_end:#x}, but the input ends at {input_len:#x}",
                    request.segment_name()
                )));
            }
            let file_offset = align_up(declared_end, alignment)?;
            let padding = file_offset - declared_end;
            if padding > MAX_FILE_PADDING {
                return Err(Error::invalid(format!(
                    "section {},{} alignment requires {padding} bytes of file padding, exceeding the {MAX_FILE_PADDING}-byte limit",
                    request.segment_name(),
                    request.section_name()
                )));
            }
            if file_offset > u64::from(u32::MAX) {
                return Err(Error::invalid(
                    "section file offset exceeds Mach-O's u32 field",
                ));
            }
            let file_end = file_offset
                .checked_add(bytes.len() as u64)
                .ok_or_else(|| Error::invalid("new section file range overflow"))?;
            if let Some(next_start) = next_file_segment
                && file_end > next_start
            {
                return Err(Error::invalid(format!(
                    "cannot extend segment {} through {file_end:#x}: the next file-backed segment starts at {next_start:#x}",
                    request.segment_name()
                )));
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
    let section_vm_end = address
        .checked_add(request.content().size())
        .ok_or_else(|| Error::invalid("new section VM range overflow"))?;
    if request.content().size() > 0 {
        let overlaps_existing = segments[target_index]
            .original
            .sections()
            .iter()
            .map(|section| {
                (
                    section.addr().0,
                    section.addr().0.saturating_add(section.size()),
                )
            })
            .chain(segments[target_index].added_sections.iter().map(|section| {
                (
                    section.address,
                    section
                        .address
                        .saturating_add(section.request.content().size()),
                )
            }))
            .any(|(start, end)| start < section_vm_end && address < end);
        if overlaps_existing {
            return Err(Error::invalid(format!(
                "section {},{} VM range {address:#x}..{section_vm_end:#x} overlaps an existing section",
                request.segment_name(),
                request.section_name()
            )));
        }
    }
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

fn validate_content_type(request: &AddSection<'_>) -> Result<()> {
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
        assert!(AddSection::new("", "__x", &[]).is_err());
        assert!(AddSection::new("__DATA", "0123456789abcdefg", &[]).is_err());
        assert!(AddSection::new("__DATA", "bad\0name", &[]).is_err());
        assert!(AddSection::new("0123456789abcdef", "0123456789abcdef", &[]).is_ok());
    }

    #[test]
    fn file_content_borrows_raw_slice_without_copying() {
        let payload = [1, 2, 3, 4];
        let bytes: &[u8] = &payload;
        let request = AddSection::new("__DATA", "__bytes", bytes).expect("valid request");
        let borrowed = request.content().file_bytes().expect("file-backed bytes");

        assert_eq!(borrowed.as_ptr(), bytes.as_ptr());
        assert_eq!(borrowed.len(), bytes.len());
    }

    #[test]
    fn alignment_is_bounded() {
        let request = AddSection::new("__DATA", "__x", &[]).expect("valid names");
        assert!(request.clone().with_alignment(31).is_ok());
        assert!(request.with_alignment(32).is_err());
    }

    #[test]
    fn content_and_section_type_must_agree() {
        assert!(
            AddSection::new("__DATA", "__x", &[])
                .unwrap()
                .with_section_type(SectionType::ZeroFill)
                .is_err()
        );
        assert!(
            AddSection::zero_fill("__DATA", "__x", 1)
                .unwrap()
                .with_section_type(SectionType::Regular)
                .is_err()
        );
    }
}
