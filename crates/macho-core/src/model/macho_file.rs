use std::sync::OnceLock;

use crate::error::{Error, Result};
use crate::format::io::endian::Endian;
use crate::model::addr::map::{AddressMap, MappingEntry};
use crate::model::addr::types::{Rva, ThinFileOffset, Va};
use crate::model::header::{Bitness, MachoHeader};
use crate::model::load_command::{LoadCommand, ParsedLoadCommand};
use crate::model::names::SegmentName;
use crate::model::section::Section;
use crate::model::segment::Segment;

pub struct MachoFile<'data> {
    bytes: &'data [u8],
    header: MachoHeader,
    load_commands: Vec<ParsedLoadCommand>,
    segments: Vec<Segment>,
    endian: Endian,
    bitness: Bitness,
    derived: OnceLock<DerivedIndexes>,
}

struct DerivedIndexes {
    address_map: AddressMap,
    uuid: Option<[u8; 16]>,
    image_base: Va,
}

impl DerivedIndexes {
    fn build(segments: &[Segment], load_commands: &[ParsedLoadCommand]) -> Self {
        let entries: Vec<MappingEntry> = segments
            .iter()
            .map(|seg| MappingEntry {
                file_offset: seg.file_offset,
                file_size: seg.file_size,
                vm_addr: seg.vm_addr,
                vm_size: seg.vm_size,
            })
            .collect();

        let address_map = AddressMap::new(entries);

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

        Self {
            address_map,
            uuid,
            image_base,
        }
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
    ) -> Self {
        Self {
            bytes,
            header,
            load_commands,
            segments,
            endian,
            bitness,
            derived: OnceLock::new(),
        }
    }

    fn derived(&self) -> &DerivedIndexes {
        self.derived
            .get_or_init(|| DerivedIndexes::build(&self.segments, &self.load_commands))
    }

    pub fn header(&self) -> &MachoHeader {
        &self.header
    }

    pub fn load_commands(&self) -> &[ParsedLoadCommand] {
        &self.load_commands
    }

    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    pub fn endian(&self) -> Endian {
        self.endian
    }

    pub fn bitness(&self) -> Bitness {
        self.bitness
    }

    pub fn bytes(&self) -> &'data [u8] {
        self.bytes
    }

    pub fn file_size(&self) -> usize {
        self.bytes.len()
    }

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

    pub fn address_map(&self) -> &AddressMap {
        &self.derived().address_map
    }

    pub fn uuid(&self) -> Option<&[u8; 16]> {
        self.derived().uuid.as_ref()
    }

    pub fn image_base(&self) -> Va {
        self.derived().image_base
    }

    pub fn section(&self, seg_name: &str, sect_name: &str) -> Option<&Section> {
        self.segments.iter().find_map(|seg| {
            if seg.name == seg_name {
                seg.sections.iter().find(|s| s.section_name == sect_name)
            } else {
                None
            }
        })
    }

    pub fn section_bytes(&self, seg_name: &str, sect_name: &str) -> Result<&'data [u8]> {
        let section = self
            .section(seg_name, sect_name)
            .ok_or_else(|| Error::Format(format!("section {seg_name},{sect_name} not found")))?;
        if section.section_type.is_zerofill() {
            return Err(Error::Format(format!(
                "section {seg_name},{sect_name} is zero-fill and has no file data"
            )));
        }
        self.read_bytes_at(section.offset, section.size as usize)
    }

    pub fn read_bytes_at(&self, offset: ThinFileOffset, len: usize) -> Result<&'data [u8]> {
        let start = offset.as_usize();
        let end = start.checked_add(len).ok_or(Error::Bounds {
            offset: offset.0,
            needed: len as u64,
            available: self.bytes.len() as u64,
        })?;
        if end > self.bytes.len() {
            return Err(Error::Bounds {
                offset: offset.0,
                needed: len as u64,
                available: self.bytes.len() as u64,
            });
        }
        Ok(&self.bytes[start..end])
    }

    pub fn read_bytes_at_va(&self, va: Va, len: usize) -> Result<&'data [u8]> {
        let offset = self.address_map().va_to_thin_offset(va)?;
        self.read_bytes_at(offset, len)
    }

    pub fn read_bytes_at_rva(&self, rva: Rva, len: usize) -> Result<&'data [u8]> {
        let va = AddressMap::rva_to_va(rva, self.image_base());
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
