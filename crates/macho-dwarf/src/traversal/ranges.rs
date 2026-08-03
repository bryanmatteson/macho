//! Physical DWARF range-list parsing and bounded resolution.

use gimli::{AttributeValue, DebugAddrIndex, Dwarf, RawRngListEntry, Reader, RunTimeEndian};

use super::{
    DwarfRangeEntryRecord, DwarfRangeListRecord, DwarfSectionReceipt, DwarfTraversalLimits,
};
use crate::{Error, Result};

#[allow(clippy::too_many_arguments)]
pub(super) fn retain_range_list<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    sections: &[DwarfSectionReceipt],
    unit_ordinal: u64,
    entry_offset: u64,
    attribute_ordinal: u64,
    attribute: gimli::Attribute<R>,
    endian: RunTimeEndian,
    limits: DwarfTraversalLimits,
    lists: &mut Vec<DwarfRangeListRecord>,
    entries: &mut Vec<DwarfRangeEntryRecord>,
) -> Result<()> {
    let attribute_value = match attribute.value() {
        AttributeValue::RangeListsRef(value) => u64::try_from(value.0)
            .map_err(|_| Error::unsupported("DWARF range-list offset exceeds u64"))?,
        AttributeValue::DebugRngListsIndex(value) => u64::try_from(value.0)
            .map_err(|_| Error::unsupported("DWARF range-list index exceeds u64"))?,
        _ => {
            return Err(Error::unsupported(format!(
                "unsupported DW_AT_ranges form {}",
                attribute.form()
            )));
        }
    };
    let list_offset = dwarf
        .attr_ranges_offset(unit, attribute.value())
        .map_err(|error| Error::format(format!("failed to resolve DW_AT_ranges: {error}")))?
        .ok_or_else(|| Error::unsupported("DW_AT_ranges did not resolve to a range list"))?;
    let section_id = if unit.header.version() <= 4 {
        ".debug_ranges"
    } else {
        ".debug_rnglists"
    };
    let section = sections
        .iter()
        .find(|section| section.section_id == section_id)
        .ok_or_else(|| Error::format(format!("DW_AT_ranges references absent {section_id}")))?;
    let raw_entries = parse_raw_range_list(
        &section.bytes,
        list_offset.0,
        unit.header.version(),
        unit.header.address_size(),
        endian,
        limits
            .max_range_entries
            .checked_sub(
                u64::try_from(entries.len())
                    .map_err(|_| Error::unsupported("DWARF range-entry count exceeds u64"))?,
            )
            .ok_or_else(|| Error::unsupported("DWARF range-list entry count exceeds limit"))?,
    )?;
    let mut resolver = dwarf
        .ranges(unit, list_offset)
        .map_err(|error| Error::format(format!("failed to open DW_AT_ranges: {error}")))?;
    let mut active_base = unit.low_pc;
    let mut coverage = "complete";
    for (ordinal, raw) in raw_entries.into_iter().enumerate() {
        super::enforce_count(entries.len(), limits.max_range_entries, "range-list entry")?;
        let (kind, raw_operand0, raw_operand1, is_base) = raw.fields();
        let gimli_raw = raw.into_gimli()?;
        let converted = resolver.convert_raw(gimli_raw).map_err(|error| {
            Error::format(format!("failed to resolve DW_AT_ranges entry: {error}"))
        })?;
        if is_base {
            active_base = match (kind, raw_operand0) {
                ("base_address", Some(address)) => address,
                ("base_addressx", Some(index)) => dwarf
                    .address(
                        unit,
                        DebugAddrIndex(usize::try_from(index).map_err(|_| {
                            Error::unsupported("range-list address index exceeds host")
                        })?),
                    )
                    .map_err(|error| {
                        Error::format(format!(
                            "failed to resolve range-list base address: {error}"
                        ))
                    })?,
                _ => return Err(Error::format("range-list base record lost its operand")),
            };
        }
        let (start, end, disposition, limitation) = if is_base {
            (None, None, "base", None)
        } else if let Some(range) = converted {
            (Some(range.begin), Some(range.end), "range", None)
        } else {
            coverage = "partial";
            (
                None,
                None,
                "suppressed",
                Some("dwarf.range_entry_suppressed".to_string()),
            )
        };
        let ordinal = u64::try_from(ordinal)
            .map_err(|_| Error::unsupported("DWARF range-entry ordinal exceeds u64"))?;
        entries.push(DwarfRangeEntryRecord {
            unit_ordinal,
            entry_offset,
            attribute_ordinal,
            ordinal,
            kind: kind.to_string(),
            raw_operand0,
            raw_operand1,
            active_base_address: active_base,
            start,
            end,
            disposition: disposition.to_string(),
            limitation,
        });
    }
    lists.push(DwarfRangeListRecord {
        unit_ordinal,
        entry_offset,
        attribute_ordinal,
        attribute_form: attribute.form().0,
        attribute_form_name: format!("{}", attribute.form()),
        attribute_value,
        list_offset: u64::try_from(list_offset.0)
            .map_err(|_| Error::unsupported("DWARF range-list offset exceeds u64"))?,
        initial_base_address: unit.low_pc,
        coverage: coverage.to_string(),
    });
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedRangeEntry {
    AddressOrOffsetPair(u64, u64),
    BaseAddress(u64),
    BaseAddressx(u64),
    StartxEndx(u64, u64),
    StartxLength(u64, u64),
    OffsetPair(u64, u64),
    StartEnd(u64, u64),
    StartLength(u64, u64),
}

impl ParsedRangeEntry {
    fn fields(self) -> (&'static str, Option<u64>, Option<u64>, bool) {
        match self {
            Self::AddressOrOffsetPair(begin, end) => {
                ("address_or_offset_pair", Some(begin), Some(end), false)
            }
            Self::BaseAddress(address) => ("base_address", Some(address), None, true),
            Self::BaseAddressx(index) => ("base_addressx", Some(index), None, true),
            Self::StartxEndx(begin, end) => ("startx_endx", Some(begin), Some(end), false),
            Self::StartxLength(begin, length) => {
                ("startx_length", Some(begin), Some(length), false)
            }
            Self::OffsetPair(begin, end) => ("offset_pair", Some(begin), Some(end), false),
            Self::StartEnd(begin, end) => ("start_end", Some(begin), Some(end), false),
            Self::StartLength(begin, length) => ("start_length", Some(begin), Some(length), false),
        }
    }

    fn into_gimli(self) -> Result<RawRngListEntry<usize>> {
        let index = |value: u64| {
            usize::try_from(value)
                .map(DebugAddrIndex)
                .map_err(|_| Error::unsupported("range-list address index exceeds host"))
        };
        Ok(match self {
            Self::AddressOrOffsetPair(begin, end) => {
                RawRngListEntry::AddressOrOffsetPair { begin, end }
            }
            Self::BaseAddress(addr) => RawRngListEntry::BaseAddress { addr },
            Self::BaseAddressx(addr) => RawRngListEntry::BaseAddressx { addr: index(addr)? },
            Self::StartxEndx(begin, end) => RawRngListEntry::StartxEndx {
                begin: index(begin)?,
                end: index(end)?,
            },
            Self::StartxLength(begin, length) => RawRngListEntry::StartxLength {
                begin: index(begin)?,
                length,
            },
            Self::OffsetPair(begin, end) => RawRngListEntry::OffsetPair { begin, end },
            Self::StartEnd(begin, end) => RawRngListEntry::StartEnd { begin, end },
            Self::StartLength(begin, length) => RawRngListEntry::StartLength { begin, length },
        })
    }
}

fn parse_raw_range_list(
    bytes: &[u8],
    offset: usize,
    version: u16,
    address_size: u8,
    endian: RunTimeEndian,
    maximum_entries: u64,
) -> Result<Vec<ParsedRangeEntry>> {
    if version > 5 {
        return Err(Error::unsupported(format!(
            "unsupported DWARF range-list version {version}"
        )));
    }
    let mut cursor = offset;
    if cursor >= bytes.len() {
        return Err(Error::format("range-list offset is outside its section"));
    }
    let mut entries = Vec::new();
    loop {
        if version <= 4 {
            let begin = read_address(bytes, &mut cursor, address_size, endian)?;
            let end = read_address(bytes, &mut cursor, address_size, endian)?;
            if begin == 0 && end == 0 {
                return Ok(entries);
            }
            let maximum = match address_size {
                2 => u16::MAX as u64,
                4 => u32::MAX as u64,
                8 => u64::MAX,
                _ => return Err(Error::unsupported("unsupported DWARF address size")),
            };
            if begin == maximum {
                push_range_entry(
                    &mut entries,
                    ParsedRangeEntry::BaseAddress(end),
                    maximum_entries,
                )?;
            } else {
                push_range_entry(
                    &mut entries,
                    ParsedRangeEntry::AddressOrOffsetPair(begin, end),
                    maximum_entries,
                )?;
            }
            continue;
        }
        let opcode = *bytes
            .get(cursor)
            .ok_or_else(|| Error::format("DWARF5 range list is missing its terminator"))?;
        cursor += 1;
        match opcode {
            0x00 => return Ok(entries),
            0x01 => {
                let entry = ParsedRangeEntry::BaseAddressx(read_uleb(bytes, &mut cursor)?);
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            0x02 => {
                let entry = ParsedRangeEntry::StartxEndx(
                    read_uleb(bytes, &mut cursor)?,
                    read_uleb(bytes, &mut cursor)?,
                );
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            0x03 => {
                let entry = ParsedRangeEntry::StartxLength(
                    read_uleb(bytes, &mut cursor)?,
                    read_uleb(bytes, &mut cursor)?,
                );
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            0x04 => {
                let entry = ParsedRangeEntry::OffsetPair(
                    read_uleb(bytes, &mut cursor)?,
                    read_uleb(bytes, &mut cursor)?,
                );
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            0x05 => {
                let entry = ParsedRangeEntry::BaseAddress(read_address(
                    bytes,
                    &mut cursor,
                    address_size,
                    endian,
                )?);
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            0x06 => {
                let entry = ParsedRangeEntry::StartEnd(
                    read_address(bytes, &mut cursor, address_size, endian)?,
                    read_address(bytes, &mut cursor, address_size, endian)?,
                );
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            0x07 => {
                let entry = ParsedRangeEntry::StartLength(
                    read_address(bytes, &mut cursor, address_size, endian)?,
                    read_uleb(bytes, &mut cursor)?,
                );
                push_range_entry(&mut entries, entry, maximum_entries)?;
            }
            value => {
                return Err(Error::format(format!(
                    "unknown DWARF5 range-list opcode 0x{value:02x}"
                )));
            }
        }
    }
}

fn push_range_entry(
    entries: &mut Vec<ParsedRangeEntry>,
    entry: ParsedRangeEntry,
    maximum: u64,
) -> Result<()> {
    super::enforce_count(entries.len(), maximum, "range-list entry")?;
    entries.push(entry);
    Ok(())
}

fn read_address(
    bytes: &[u8],
    cursor: &mut usize,
    address_size: u8,
    endian: RunTimeEndian,
) -> Result<u64> {
    let width = usize::from(address_size);
    if !matches!(width, 2 | 4 | 8) {
        return Err(Error::unsupported("unsupported DWARF address size"));
    }
    let end = cursor
        .checked_add(width)
        .ok_or_else(|| Error::format("range-list address offset overflow"))?;
    let raw = bytes
        .get(*cursor..end)
        .ok_or_else(|| Error::format("truncated range-list address"))?;
    *cursor = end;
    let mut padded = [0_u8; 8];
    match endian {
        RunTimeEndian::Little => padded[..width].copy_from_slice(raw),
        RunTimeEndian::Big => padded[8 - width..].copy_from_slice(raw),
    }
    Ok(match endian {
        RunTimeEndian::Little => u64::from_le_bytes(padded),
        RunTimeEndian::Big => u64::from_be_bytes(padded),
    })
}

fn read_uleb(bytes: &[u8], cursor: &mut usize) -> Result<u64> {
    let mut value = 0_u64;
    for shift in (0..=63).step_by(7) {
        let byte = *bytes
            .get(*cursor)
            .ok_or_else(|| Error::format("truncated range-list ULEB128"))?;
        *cursor += 1;
        let payload = u64::from(byte & 0x7f);
        if shift == 63 && payload > 1 {
            return Err(Error::format("range-list ULEB128 overflow"));
        }
        value |= payload << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Error::format("range-list ULEB128 overflow"))
}
