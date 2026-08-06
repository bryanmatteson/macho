use crate::core::error::{Error, Result};
use crate::core::format::io::endian::Endian;
use crate::core::model::addr::map::{AddressMap, MappingEntry};
use crate::core::model::addr::types::{Rva, ThinFileOffset, Va};
use crate::core::model::header::{Bitness, MachoHeader};
use crate::core::model::load_command::{LoadCommand, ParsedLoadCommand};
use crate::core::model::names::SegmentName;
use crate::core::model::section::Section;
use crate::core::model::segment::Segment;

/// The MachoFile type.
pub struct MachoFile<'data> {
    bytes: &'data [u8],
    header: MachoHeader,
    load_commands: Vec<ParsedLoadCommand>,
    segments: Vec<Segment>,
    endian: Endian,
    bitness: Bitness,
    derived: DerivedIndexes,
}

struct DerivedIndexes {
    address_map: AddressMap,
    uuid: Option<[u8; 16]>,
    image_base: Va,
}

impl DerivedIndexes {
    fn build(segments: &[Segment], load_commands: &[ParsedLoadCommand]) -> Result<Self> {
        let entries: Vec<MappingEntry> = segments
            .iter()
            .map(|segment| {
                MappingEntry::try_new(
                    segment.file_offset,
                    segment.file_size,
                    segment.vm_addr,
                    segment.vm_size,
                )
            })
            .collect::<Result<_>>()?;

        let address_map = AddressMap::try_new(entries)?;

        let uuid = load_commands.iter().find_map(|lc| {
            if let LoadCommand::Uuid(ref d) = lc.kind {
                Some(d.uuid)
            } else {
                None
            }
        });

        let image_base = segments
            .iter()
            .find(|seg| seg.name == SegmentName::TEXT)
            .map(|seg| seg.vm_addr)
            .unwrap_or(Va(0));

        Ok(Self {
            address_map,
            uuid,
            image_base,
        })
    }
}

impl<'data> MachoFile<'data> {
    pub(crate) fn new(
        bytes: &'data [u8],
        header: MachoHeader,
        load_commands: Vec<ParsedLoadCommand>,
        segments: Vec<Segment>,
        endian: Endian,
        bitness: Bitness,
    ) -> Result<Self> {
        let derived = DerivedIndexes::build(&segments, &load_commands)?;
        Ok(Self {
            bytes,
            header,
            load_commands,
            segments,
            endian,
            bitness,
            derived,
        })
    }

    fn derived(&self) -> &DerivedIndexes {
        &self.derived
    }

    /// Performs header.
    pub fn header(&self) -> &MachoHeader {
        &self.header
    }

    /// Performs load_commands.
    pub fn load_commands(&self) -> &[ParsedLoadCommand] {
        &self.load_commands
    }

    /// Performs segments.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Performs endian.
    pub fn endian(&self) -> Endian {
        self.endian
    }

    /// Performs bitness.
    pub fn bitness(&self) -> Bitness {
        self.bitness
    }

    /// Performs bytes.
    pub fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    /// Performs file_size.
    pub fn file_size(&self) -> usize {
        self.bytes.len()
    }

    /// Performs is_64bit.
    pub fn is_64bit(&self) -> bool {
        self.bitness == Bitness::Bits64
    }

    /// Flat iterator over all sections across all segments.
    pub fn all_sections(&self) -> impl Iterator<Item = &Section> {
        self.segments.iter().flat_map(|s| s.sections.iter())
    }

    /// Find the first load command whose kind matches the predicate.
    pub fn find_load_command(
        &self,
        pred: impl Fn(&LoadCommand) -> bool,
    ) -> Option<&ParsedLoadCommand> {
        self.load_commands.iter().find(|lc| pred(&lc.kind))
    }

    /// Return the exact numeric command word retained in the input.
    pub fn load_command_code(&self, command: &ParsedLoadCommand) -> Result<u32> {
        let start = command.file_offset().as_usize();
        let raw: [u8; 4] = self
            .bytes
            .get(start..start.saturating_add(4))
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| Error::bounds(start as u64, 4, self.bytes.len() as u64))?;
        Ok(self.endian.read_u32(raw))
    }

    /// Performs address_map.
    pub fn address_map(&self) -> &AddressMap {
        &self.derived().address_map
    }

    /// Performs uuid.
    pub fn uuid(&self) -> Option<&[u8; 16]> {
        self.derived().uuid.as_ref()
    }

    /// Performs image_base.
    pub fn image_base(&self) -> Va {
        self.derived().image_base
    }

    /// Performs section.
    pub fn section(&self, seg_name: &str, sect_name: &str) -> Option<&Section> {
        self.segments.iter().find_map(|seg| {
            if seg.name == seg_name {
                seg.sections.iter().find(|s| s.section_name == sect_name)
            } else {
                None
            }
        })
    }

    /// Performs section_bytes.
    pub fn section_bytes(&self, seg_name: &str, sect_name: &str) -> Result<&'data [u8]> {
        let section = self
            .section(seg_name, sect_name)
            .ok_or_else(|| Error::format(format!("section {seg_name},{sect_name} not found")))?;
        if section.section_type.is_zerofill() {
            return Err(Error::format(format!(
                "section {seg_name},{sect_name} is zero-fill and has no file data"
            )));
        }
        self.read_bytes_at(section.offset, section.size as usize)
    }

    /// Performs read_bytes_at.
    pub fn read_bytes_at(&self, offset: ThinFileOffset, len: usize) -> Result<&'data [u8]> {
        let start = offset.as_usize();
        let end = start
            .checked_add(len)
            .ok_or_else(|| Error::bounds(offset.0, len as u64, self.bytes.len() as u64))?;
        if end > self.bytes.len() {
            return Err(Error::bounds(offset.0, len as u64, self.bytes.len() as u64));
        }
        Ok(&self.bytes[start..end])
    }

    /// Performs read_bytes_at_va.
    pub fn read_bytes_at_va(&self, va: Va, len: usize) -> Result<&'data [u8]> {
        let offset = self.address_map().va_to_thin_offset(va)?;
        self.read_bytes_at(offset, len)
    }

    /// Performs read_bytes_at_rva.
    pub fn read_bytes_at_rva(&self, rva: Rva, len: usize) -> Result<&'data [u8]> {
        let va = AddressMap::rva_to_va(rva, self.image_base())?;
        self.read_bytes_at_va(va, len)
    }
}

impl std::fmt::Debug for MachoFile<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MachFile")
            .field("header", &self.header)
            .field("endian", &self.endian)
            .field("bitness", &self.bitness)
            .field("num_load_commands", &self.load_commands.len())
            .field("num_segments", &self.segments.len())
            .field("size", &self.bytes.len())
            .finish()
    }
}

// Safety: MachFile is Send + Sync because:
// - &[u8] is Send + Sync
// - OnceLock<DerivedIndexes> is Sync (and Send)
// - All other fields are Send + Sync
// This is verified by the static assertions below.
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<MachoFile<'static>>();
};
