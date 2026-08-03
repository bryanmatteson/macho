//! Lossless-enough, bounded traversal receipts for normalized consumers.

use gimli::{
    AttributeValue, ColumnType, Dwarf, EndianSlice, Reader, RunTimeEndian, SectionId, UnitType,
};
use macho_core::format::io::Endian;

use crate::{Error, MachoFile, Result};

mod ranges;

/// Hard limits for one deterministic DWARF traversal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DwarfTraversalLimits {
    /// Maximum combined uncompressed section bytes.
    pub max_section_bytes: u64,
    /// Maximum compilation or type units.
    pub max_units: u64,
    /// Maximum retained DIEs.
    pub max_entries: u64,
    /// Maximum retained attributes.
    pub max_attributes: u64,
    /// Maximum retained physical line-program rows.
    pub max_line_rows: u64,
    /// Maximum retained raw range-list entries, including base selections.
    pub max_range_entries: u64,
}

impl Default for DwarfTraversalLimits {
    fn default() -> Self {
        Self {
            max_section_bytes: 64 * 1024 * 1024,
            max_units: 65_536,
            max_entries: 2_000_000,
            max_attributes: 8_000_000,
            max_line_rows: 4_000_000,
            max_range_entries: 4_000_000,
        }
    }
}

/// Exact Mach-O section custody for one loaded DWARF section.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfSectionReceipt {
    /// Canonical DWARF section identity.
    pub section_id: &'static str,
    /// Mach-O segment spelling.
    pub segment_name: String,
    /// Mach-O section spelling.
    pub section_name: String,
    /// File offset of the retained bytes.
    pub file_offset: u64,
    /// Exact retained bytes.
    pub bytes: Vec<u8>,
}

/// One compilation or type unit header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfUnitRecord {
    /// Unit ordinal in section order.
    pub ordinal: u64,
    /// Section-relative unit offset.
    pub offset: u64,
    /// Serialized unit length including its initial length field.
    pub length: u64,
    /// DWARF version.
    pub version: u16,
    /// DWARF32 or DWARF64.
    pub format: String,
    /// Compilation, type, partial, skeleton, or split unit.
    pub unit_type: String,
    /// Address size in bytes.
    pub address_size: u8,
    /// Root `DW_AT_language`, when present.
    pub language: Option<u64>,
    /// Root `DW_AT_producer`, when present and valid UTF-8.
    pub producer: Option<String>,
    /// Root `DW_AT_comp_dir`, when present and valid UTF-8.
    pub compilation_directory: Option<String>,
}

/// One retained DIE in physical depth-first order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfEntryRecord {
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// Unit-relative DIE offset.
    pub offset: u64,
    /// Absolute offset in `.debug_info`, derived through gimli's unit mapping.
    pub debug_info_offset: u64,
    /// Parent DIE offset, absent only for the unit root.
    pub parent_offset: Option<u64>,
    /// Physical ordinal within the unit.
    pub ordinal: u64,
    /// DIE tree depth.
    pub depth: u64,
    /// DWARF tag numeric value.
    pub tag: u16,
    /// Stable display spelling for the tag.
    pub tag_name: String,
}

/// One form-bearing DIE attribute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfAttributeRecord {
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// Owning DIE offset.
    pub entry_offset: u64,
    /// Physical attribute ordinal.
    pub ordinal: u64,
    /// DWARF attribute numeric value.
    pub name: u16,
    /// Stable display spelling for the attribute.
    pub name_text: String,
    /// DWARF form numeric value.
    pub form: u16,
    /// Stable display spelling for the form.
    pub form_text: String,
    /// Closed normalized value class.
    pub value_kind: String,
    /// Unsigned/address/section-offset value.
    pub unsigned: Option<u64>,
    /// Signed value.
    pub signed: Option<i64>,
    /// Resolved or inline string bytes.
    pub text: Option<Vec<u8>>,
    /// Exact block or expression bytes.
    pub block: Option<Vec<u8>>,
    /// Resolved `.debug_info` target for a unit-relative reference.
    pub unit_reference: Option<u64>,
    /// Debug-info-relative referenced DIE offset.
    pub debug_info_reference: Option<u64>,
}

/// One physical source file table entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfSourceFileRecord {
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// DWARF line-table file index.
    pub file_index: u64,
    /// Resolved directory bytes, if supplied.
    pub directory: Option<Vec<u8>>,
    /// Exact file-name bytes.
    pub file_name: Vec<u8>,
    /// Source timestamp retained from the program header.
    pub timestamp: u64,
    /// Source size retained from the program header.
    pub size: u64,
    /// DWARF v5 MD5 checksum, present only when the line header declares it.
    pub md5: Option<[u8; 16]>,
}

/// One emitted physical line-program row, including terminal rows.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfLineRowRecord {
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// Monotonic address-sequence ordinal.
    pub sequence: u64,
    /// Physical row ordinal within the sequence.
    pub ordinal: u64,
    /// Image virtual address.
    pub address: u64,
    /// Source file index.
    pub file_index: u64,
    /// One-based source line, absent for line zero.
    pub line: Option<u64>,
    /// One-based column, absent for left edge.
    pub column: Option<u64>,
    /// Discriminator.
    pub discriminator: u64,
    /// Recommended statement boundary.
    pub is_statement: bool,
    /// Basic-block boundary.
    pub basic_block: bool,
    /// Terminal row for one address sequence.
    pub end_sequence: bool,
    /// Function prologue end.
    pub prologue_end: bool,
    /// Function epilogue beginning.
    pub epilogue_begin: bool,
    /// Instruction-set architecture selector.
    pub isa: u64,
}

/// One `DW_AT_ranges` list attached to a physical DIE attribute.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfRangeListRecord {
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// Owning DIE offset.
    pub entry_offset: u64,
    /// Physical `DW_AT_ranges` attribute ordinal.
    pub attribute_ordinal: u64,
    /// Physical attribute form numeric value.
    pub attribute_form: u16,
    /// Stable physical attribute form spelling.
    pub attribute_form_name: String,
    /// Raw section offset or range-list index carried by the attribute.
    pub attribute_value: u64,
    /// Resolved section-relative list offset.
    pub list_offset: u64,
    /// Unit base address in effect before the first list entry.
    pub initial_base_address: u64,
    /// `complete` when every raw range materialized, otherwise `partial`.
    pub coverage: String,
}

/// One raw physical range-list entry and its bounded resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfRangeEntryRecord {
    /// Owning unit ordinal.
    pub unit_ordinal: u64,
    /// Owning DIE offset.
    pub entry_offset: u64,
    /// Physical `DW_AT_ranges` attribute ordinal.
    pub attribute_ordinal: u64,
    /// Physical entry ordinal within the referenced range list.
    pub ordinal: u64,
    /// Closed raw entry kind.
    pub kind: String,
    /// First raw address, offset, index, or length operand.
    pub raw_operand0: Option<u64>,
    /// Second raw address, offset, index, or length operand.
    pub raw_operand1: Option<u64>,
    /// Resolved active base after a base selection, or before a range entry.
    pub active_base_address: u64,
    /// Exact resolved half-open start when the entry materialized.
    pub start: Option<u64>,
    /// Exact resolved half-open end when the entry materialized.
    pub end: Option<u64>,
    /// `base`, `range`, or `suppressed`.
    pub disposition: String,
    /// Typed reason for a suppressed non-base entry.
    pub limitation: Option<String>,
}

/// Complete bounded traversal receipt for the supported in-image DWARF package.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DwarfTraversal {
    /// Exact section custody sorted by DWARF section identity.
    pub sections: Vec<DwarfSectionReceipt>,
    /// Units in physical order.
    pub units: Vec<DwarfUnitRecord>,
    /// DIEs in physical order.
    pub entries: Vec<DwarfEntryRecord>,
    /// Attributes in physical order.
    pub attributes: Vec<DwarfAttributeRecord>,
    /// File-table entries in unit and file-index order.
    pub source_files: Vec<DwarfSourceFileRecord>,
    /// Physical line rows including `end_sequence` rows.
    pub line_rows: Vec<DwarfLineRowRecord>,
    /// `DW_AT_ranges` list headers in physical attribute order.
    pub range_lists: Vec<DwarfRangeListRecord>,
    /// Raw range-list entries in physical list order.
    pub range_entries: Vec<DwarfRangeEntryRecord>,
}

/// Traverse every supported in-image DWARF unit, DIE, attribute, file, and line row.
///
/// The traversal is fail-closed: malformed headers, abbreviations, DIEs, forms,
/// strings, or line programs return a typed error instead of silently producing
/// an apparently complete subset. Split/external DWARF and relocated object-file
/// sections are not resolved by this API.
pub fn traverse_dwarf(
    macho: &MachoFile<'_>,
    limits: DwarfTraversalLimits,
) -> Result<Option<DwarfTraversal>> {
    validate_limits(limits)?;
    let sections = section_receipts(macho, limits)?;
    if sections.is_empty() {
        return Ok(None);
    }
    let loaded = crate::load_dwarf(macho)?
        .ok_or_else(|| Error::format("DWARF sections disappeared during bounded traversal"))?;
    let endian = match macho.endian() {
        Endian::Little => RunTimeEndian::Little,
        Endian::Big => RunTimeEndian::Big,
    };
    let dwarf = loaded.borrow(|section| EndianSlice::new(section, endian));
    traverse_loaded(&dwarf, sections, limits, endian).map(Some)
}

fn validate_limits(limits: DwarfTraversalLimits) -> Result<()> {
    if limits.max_section_bytes == 0
        || limits.max_units == 0
        || limits.max_entries == 0
        || limits.max_attributes == 0
        || limits.max_line_rows == 0
        || limits.max_range_entries == 0
    {
        return Err(Error::unsupported(
            "DWARF traversal limits must be non-zero",
        ));
    }
    Ok(())
}

fn section_receipts(
    macho: &MachoFile<'_>,
    limits: DwarfTraversalLimits,
) -> Result<Vec<DwarfSectionReceipt>> {
    let mut receipts = Vec::new();
    let mut total = 0_u64;
    for id in DWARF_SECTION_IDS {
        let wanted = super::macho_section_name(id);
        let mut matches = macho
            .all_sections()
            .filter(|section| section.section_name() == wanted.as_str());
        let Some(section) = matches.next() else {
            continue;
        };
        if matches.next().is_some() {
            return Err(Error::format(format!(
                "duplicate canonical DWARF section {wanted}"
            )));
        }
        if section.section_type().is_zerofill() {
            return Err(Error::unsupported(format!(
                "DWARF section {} is zero-fill",
                section.section_name()
            )));
        }
        total = total
            .checked_add(section.size())
            .ok_or_else(|| Error::unsupported("DWARF section byte count overflow"))?;
        if total > limits.max_section_bytes {
            return Err(Error::unsupported(format!(
                "DWARF section bytes {total} exceed limit {}",
                limits.max_section_bytes
            )));
        }
        let section_size = usize::try_from(section.size())
            .map_err(|_| Error::unsupported("DWARF section size exceeds host address space"))?;
        let bytes = macho
            .read_bytes_at(section.offset(), section_size)
            .map_err(Error::from)?
            .to_vec();
        receipts.push(DwarfSectionReceipt {
            section_id: id.name(),
            segment_name: section.segment_name().to_string(),
            section_name: section.section_name().to_string(),
            file_offset: section.offset().0,
            bytes,
        });
    }
    receipts.sort_by_key(|receipt| receipt.section_id);
    Ok(receipts)
}

fn traverse_loaded<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    sections: Vec<DwarfSectionReceipt>,
    limits: DwarfTraversalLimits,
    endian: RunTimeEndian,
) -> Result<DwarfTraversal> {
    let mut result = DwarfTraversal {
        sections,
        units: Vec::new(),
        entries: Vec::new(),
        attributes: Vec::new(),
        source_files: Vec::new(),
        line_rows: Vec::new(),
        range_lists: Vec::new(),
        range_entries: Vec::new(),
    };
    let mut headers = dwarf.units();
    while let Some(header) = headers
        .next()
        .map_err(|error| Error::format(format!("failed to parse DWARF unit header: {error}")))?
    {
        enforce_count(result.units.len(), limits.max_units, "unit")?;
        let unit_ordinal = result.units.len() as u64;
        let unit = dwarf
            .unit(header)
            .map_err(|error| Error::format(format!("failed to parse DWARF unit: {error}")))?;
        let mut language = None;
        let mut producer = None;
        let mut compilation_directory = None;
        let mut parents = Vec::<u64>::new();
        let mut entry_ordinal = 0_u64;
        let mut cursor = unit.entries();
        while let Some(entry) = cursor
            .next_dfs()
            .map_err(|error| Error::format(format!("failed to traverse DWARF DIE: {error}")))?
        {
            enforce_count(result.entries.len(), limits.max_entries, "DIE")?;
            let depth = entry.depth() as usize;
            if depth > parents.len() {
                return Err(Error::format("DWARF DIE depth skipped a parent level"));
            }
            parents.truncate(depth);
            let offset = entry.offset().0 as u64;
            let debug_info_offset = entry
                .offset()
                .to_debug_info_offset(&unit.header)
                .ok_or_else(|| Error::unsupported("DWARF entry is not in .debug_info"))?
                .0 as u64;
            let parent_offset = depth
                .checked_sub(1)
                .and_then(|index| parents.get(index).copied());
            result.entries.push(DwarfEntryRecord {
                unit_ordinal,
                offset,
                debug_info_offset,
                parent_offset,
                ordinal: entry_ordinal,
                depth: depth as u64,
                tag: entry.tag().0,
                tag_name: format!("{}", entry.tag()),
            });
            entry_ordinal += 1;
            if parents.len() == depth {
                parents.push(offset);
            } else {
                parents[depth] = offset;
            }
            for (attribute_ordinal, attribute) in entry.attrs().iter().enumerate() {
                enforce_count(result.attributes.len(), limits.max_attributes, "attribute")?;
                if depth == 0 {
                    match attribute.name() {
                        gimli::DW_AT_language => language = attribute.udata_value(),
                        gimli::DW_AT_producer => {
                            producer = resolved_utf8(dwarf, &unit, attribute.value())?
                        }
                        gimli::DW_AT_comp_dir => {
                            compilation_directory = resolved_utf8(dwarf, &unit, attribute.value())?
                        }
                        _ => {}
                    }
                }
                if attribute.name() == gimli::DW_AT_ranges {
                    let range_attribute_ordinal =
                        u64::try_from(attribute_ordinal).map_err(|_| {
                            Error::unsupported("DWARF range attribute ordinal exceeds u64")
                        })?;
                    ranges::retain_range_list(
                        dwarf,
                        &unit,
                        &result.sections,
                        unit_ordinal,
                        offset,
                        range_attribute_ordinal,
                        attribute.clone(),
                        endian,
                        limits,
                        &mut result.range_lists,
                        &mut result.range_entries,
                    )?;
                }
                result.attributes.push(attribute_record(
                    dwarf,
                    &unit,
                    unit_ordinal,
                    offset,
                    attribute_ordinal as u64,
                    attribute.clone(),
                    endian,
                )?);
            }
        }
        if let Some(program) = unit.line_program.clone() {
            let header = program.header();
            if header.version() <= 4
                && let Some(file) = header.file(0)
            {
                result.source_files.push(source_file_record(
                    dwarf,
                    &unit,
                    header,
                    unit_ordinal,
                    0,
                    file,
                )?);
            }
            for (index, file) in header.file_names().iter().enumerate() {
                result.source_files.push(source_file_record(
                    dwarf,
                    &unit,
                    header,
                    unit_ordinal,
                    line_file_index(header.version(), index),
                    file,
                )?);
            }
            let mut rows = program.rows();
            let mut sequence = 0_u64;
            let mut ordinal = 0_u64;
            while let Some((_header, row)) = rows.next_row().map_err(|error| {
                Error::format(format!("failed to execute DWARF line program: {error}"))
            })? {
                enforce_count(result.line_rows.len(), limits.max_line_rows, "line row")?;
                let column = match row.column() {
                    ColumnType::LeftEdge => None,
                    ColumnType::Column(value) => Some(value.get()),
                };
                result.line_rows.push(DwarfLineRowRecord {
                    unit_ordinal,
                    sequence,
                    ordinal,
                    address: row.address(),
                    file_index: row.file_index(),
                    line: row.line().map(|value| value.get()),
                    column,
                    discriminator: row.discriminator(),
                    is_statement: row.is_stmt(),
                    basic_block: row.basic_block(),
                    end_sequence: row.end_sequence(),
                    prologue_end: row.prologue_end(),
                    epilogue_begin: row.epilogue_begin(),
                    isa: row.isa(),
                });
                ordinal += 1;
                if row.end_sequence() {
                    sequence += 1;
                    ordinal = 0;
                }
            }
        }
        result.units.push(DwarfUnitRecord {
            ordinal: unit_ordinal,
            offset: unit.header.offset().0 as u64,
            length: unit.header.length_including_self() as u64,
            version: unit.header.version(),
            format: format!("{:?}", unit.header.format()).to_ascii_lowercase(),
            unit_type: unit_type_name(unit.header.type_()).to_owned(),
            address_size: unit.header.address_size(),
            language,
            producer,
            compilation_directory,
        });
    }
    if result.units.is_empty() {
        return Err(Error::format(
            "nonempty .debug_info contains no compilation or type unit",
        ));
    }
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn source_file_record<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    header: &gimli::LineProgramHeader<R>,
    unit_ordinal: u64,
    file_index: u64,
    file: &gimli::FileEntry<R>,
) -> Result<DwarfSourceFileRecord> {
    Ok(DwarfSourceFileRecord {
        unit_ordinal,
        file_index,
        directory: file
            .directory(header)
            .map(|value| resolved_bytes(dwarf, unit, value))
            .transpose()?,
        file_name: resolved_bytes(dwarf, unit, file.path_name())?,
        timestamp: file.timestamp(),
        size: file.size(),
        md5: header.file_has_md5().then_some(*file.md5()),
    })
}

fn enforce_count(current: usize, maximum: u64, label: &str) -> Result<()> {
    let current = u64::try_from(current)
        .map_err(|_| Error::unsupported(format!("DWARF {label} count exceeds u64")))?;
    if current >= maximum {
        return Err(Error::unsupported(format!(
            "DWARF {label} count exceeds limit {maximum}"
        )));
    }
    Ok(())
}

fn unit_type_name<Offset: gimli::ReaderOffset>(unit_type: UnitType<Offset>) -> &'static str {
    match unit_type {
        UnitType::Compilation => "compile",
        UnitType::Type { .. } => "type",
        UnitType::Partial => "partial",
        UnitType::Skeleton(_) => "skeleton",
        UnitType::SplitCompilation(_) => "split_compile",
        UnitType::SplitType { .. } => "split_type",
    }
}

fn resolved_utf8<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: AttributeValue<R>,
) -> Result<Option<String>> {
    let bytes = match dwarf.attr_string(unit, value) {
        Ok(value) => value
            .to_slice()
            .map_err(|error| Error::format(format!("failed to read DWARF string: {error}")))?
            .into_owned(),
        Err(_) => return Ok(None),
    };
    Ok(std::str::from_utf8(&bytes).ok().map(str::to_owned))
}

fn resolved_bytes<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    value: AttributeValue<R>,
) -> Result<Vec<u8>> {
    dwarf
        .attr_string(unit, value)
        .and_then(|value| value.to_slice().map(|value| value.into_owned()))
        .map_err(|error| Error::format(format!("failed to resolve DWARF string: {error}")))
}

fn attribute_record<R: Reader<Offset = usize>>(
    dwarf: &Dwarf<R>,
    unit: &gimli::Unit<R>,
    unit_ordinal: u64,
    entry_offset: u64,
    ordinal: u64,
    attribute: gimli::Attribute<R>,
    endian: RunTimeEndian,
) -> Result<DwarfAttributeRecord> {
    let mut record = DwarfAttributeRecord {
        unit_ordinal,
        entry_offset,
        ordinal,
        name: attribute.name().0,
        name_text: format!("{}", attribute.name()),
        form: attribute.form().0,
        form_text: format!("{}", attribute.form()),
        value_kind: String::new(),
        unsigned: None,
        signed: None,
        text: None,
        block: None,
        unit_reference: None,
        debug_info_reference: None,
    };
    match attribute.value() {
        AttributeValue::Addr(value) => {
            record.value_kind = "address".into();
            record.unsigned = Some(value);
        }
        AttributeValue::Data1(value) => set_unsigned(&mut record, value.into()),
        AttributeValue::Data2(value) => set_unsigned(&mut record, value.into()),
        AttributeValue::Data4(value) => set_unsigned(&mut record, value.into()),
        AttributeValue::Data8(value) | AttributeValue::Udata(value) => {
            set_unsigned(&mut record, value)
        }
        AttributeValue::Data16(value) => {
            record.value_kind = "block".into();
            record.block = Some(match endian {
                RunTimeEndian::Little => value.to_le_bytes().to_vec(),
                RunTimeEndian::Big => value.to_be_bytes().to_vec(),
            });
        }
        AttributeValue::Sdata(value) => {
            record.value_kind = "signed".into();
            record.signed = Some(value);
        }
        AttributeValue::Flag(value) => set_unsigned(&mut record, u64::from(value)),
        AttributeValue::UnitRef(value) => {
            record.value_kind = "unit_reference".into();
            record.unsigned = Some(value.0 as u64);
            record.unit_reference = Some(
                value
                    .to_debug_info_offset(&unit.header)
                    .ok_or_else(|| Error::unsupported("unit reference is not in .debug_info"))?
                    .0 as u64,
            );
        }
        AttributeValue::DebugInfoRef(value) => {
            record.value_kind = "debug_info_reference".into();
            record.unsigned = Some(value.0 as u64);
            record.debug_info_reference = Some(value.0 as u64);
        }
        AttributeValue::SecOffset(value) => {
            record.value_kind = "section_offset".into();
            record.unsigned = Some(value as u64);
        }
        AttributeValue::DebugAddrBase(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugAddrIndex(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugInfoRefSup(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugLineRef(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::LocationListsRef(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugLocListsBase(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugLocListsIndex(value) => {
            set_section_offset(&mut record, value.0 as u64)
        }
        AttributeValue::DebugMacinfoRef(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugMacroRef(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::RangeListsRef(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugRngListsBase(value) => set_section_offset(&mut record, value.0 as u64),
        AttributeValue::DebugRngListsIndex(value) => {
            set_section_offset(&mut record, value.0 as u64)
        }
        AttributeValue::DebugTypesRef(value) => set_section_offset(&mut record, value.0),
        AttributeValue::DebugStrOffsetsBase(value) => {
            set_section_offset(&mut record, value.0 as u64)
        }
        AttributeValue::DebugStrOffsetsIndex(value) => {
            record.value_kind = "text".into();
            record.unsigned = Some(value.0 as u64);
            record.text = Some(resolved_bytes(
                dwarf,
                unit,
                AttributeValue::DebugStrOffsetsIndex(value),
            )?);
        }
        AttributeValue::FileIndex(value) => set_unsigned(&mut record, value),
        AttributeValue::DwoId(value) => set_unsigned(&mut record, value.0),
        AttributeValue::Encoding(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::DecimalSign(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Endianity(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Accessibility(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Visibility(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Virtuality(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Language(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::AddressClass(value) => set_unsigned(&mut record, value.0),
        AttributeValue::IdentifierCase(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::CallingConvention(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Inline(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Ordering(value) => set_unsigned(&mut record, value.0 as u64),
        AttributeValue::Block(value) => {
            record.value_kind = "block".into();
            record.block = Some(
                value
                    .to_slice()
                    .map_err(|error| Error::format(format!("failed to read DWARF block: {error}")))?
                    .into_owned(),
            );
        }
        AttributeValue::Exprloc(value) => {
            record.value_kind = "expression".into();
            record.block = Some(
                value
                    .0
                    .to_slice()
                    .map_err(|error| {
                        Error::format(format!("failed to read DWARF expression: {error}"))
                    })?
                    .into_owned(),
            );
        }
        value => {
            if let Ok(bytes) = dwarf.attr_string(unit, value.clone()) {
                record.value_kind = "text".into();
                record.text = Some(
                    bytes
                        .to_slice()
                        .map_err(|error| {
                            Error::format(format!("failed to read DWARF string: {error}"))
                        })?
                        .into_owned(),
                );
            } else if let Some(value) = attribute.udata_value() {
                set_unsigned(&mut record, value);
            } else {
                return Err(Error::unsupported(format!(
                    "unsupported retained DWARF attribute form {} for {}",
                    attribute.form(),
                    attribute.name()
                )));
            }
        }
    }
    Ok(record)
}

fn set_unsigned(record: &mut DwarfAttributeRecord, value: u64) {
    record.value_kind = "unsigned".into();
    record.unsigned = Some(value);
}

fn set_section_offset(record: &mut DwarfAttributeRecord, value: u64) {
    record.value_kind = "section_offset".into();
    record.unsigned = Some(value);
}

fn line_file_index(version: u16, zero_based_index: usize) -> u64 {
    let index = zero_based_index as u64;
    if version <= 4 { index + 1 } else { index }
}

const DWARF_SECTION_IDS: [SectionId; 25] = [
    SectionId::DebugAbbrev,
    SectionId::DebugAddr,
    SectionId::DebugAranges,
    SectionId::DebugCuIndex,
    SectionId::DebugFrame,
    SectionId::EhFrame,
    SectionId::EhFrameHdr,
    SectionId::DebugGnuPubNames,
    SectionId::DebugGnuPubTypes,
    SectionId::DebugInfo,
    SectionId::DebugLine,
    SectionId::DebugLineStr,
    SectionId::DebugLoc,
    SectionId::DebugLocLists,
    SectionId::DebugMacinfo,
    SectionId::DebugMacro,
    SectionId::DebugNames,
    SectionId::DebugPubNames,
    SectionId::DebugPubTypes,
    SectionId::DebugRanges,
    SectionId::DebugRngLists,
    SectionId::DebugStr,
    SectionId::DebugStrOffsets,
    SectionId::DebugTuIndex,
    SectionId::DebugTypes,
];

#[cfg(test)]
mod tests {
    #[test]
    fn physical_file_indexes_follow_gimli_dwarf_version_semantics() {
        assert_eq!(super::line_file_index(4, 0), 1);
        assert_eq!(super::line_file_index(4, 2), 3);
        assert_eq!(super::line_file_index(5, 0), 0);
        assert_eq!(super::line_file_index(5, 2), 2);
    }
}
