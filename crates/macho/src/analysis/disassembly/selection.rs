use std::collections::{BTreeMap, BTreeSet};

use crate::core::format::constants::SectionAttributes;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::section::Section;
use crate::insn::Arch;

use crate::analysis::report::Architecture;
use crate::analysis::report::disassembly::{
    InstructionFlags, RangeEndSource, SelectionSource, SymbolSource,
};

use super::metadata::{Metadata, Observation};
use super::{
    AddressExtent, DisassemblyError, DisassemblyRequest, DisassemblySelection, SectionSelector,
    instruction_arch,
};

pub(crate) struct SelectedSlice<'input, 'data> {
    pub(crate) macho: &'input MachoFile<'data>,
    pub(crate) index: u32,
    pub(crate) container_offset: u64,
    pub(crate) architecture: Architecture,
    pub(crate) arch: Arch,
}

impl<'input, 'data> SelectedSlice<'input, 'data> {
    pub(crate) fn new(
        macho: &'input MachoFile<'data>,
        index: u32,
        container_offset: u64,
        architecture: Architecture,
    ) -> Result<Self, DisassemblyError> {
        Ok(Self {
            macho,
            index,
            container_offset,
            architecture,
            arch: instruction_arch(architecture)?,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct RegionPlan {
    pub(crate) segment: String,
    pub(crate) section: String,
    pub(crate) section_start: u64,
    pub(crate) section_end: u64,
    pub(crate) section_file_offset: u64,
    pub(crate) start: u64,
    pub(crate) extent: RegionExtent,
    pub(crate) selection_source: SelectionSource,
    pub(crate) range_source: Option<SymbolSource>,
    pub(crate) end_source: Option<RangeEndSource>,
    pub(crate) flags: InstructionFlags,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum RegionExtent {
    Bytes(u64),
    Instructions(u64),
}

pub(crate) fn resolve_regions(
    slice: &SelectedSlice<'_, '_>,
    request: &DisassemblyRequest,
    metadata: &Metadata,
) -> Result<Vec<RegionPlan>, DisassemblyError> {
    let mut regions = match &request.selection {
        DisassemblySelection::ExecutableSections => slice
            .macho
            .all_sections()
            .filter(|section| {
                let attrs = section.attributes();
                (attrs.contains(SectionAttributes::PURE_INSTRUCTIONS)
                    || attrs.contains(SectionAttributes::SOME_INSTRUCTIONS))
                    && is_file_backed(slice.macho, section)
                    && section.size() > 0
            })
            .map(|section| {
                region_for_section(section, SelectionSource::ExecutableSection, None, None)
            })
            .collect::<Result<Vec<_>, _>>()?,
        DisassemblySelection::Sections(selectors) => {
            let selectors: BTreeSet<_> = selectors.iter().cloned().collect();
            selectors
                .iter()
                .map(|selector| explicit_section(slice, selector, metadata))
                .collect::<Result<Vec<_>, _>>()?
        }
        DisassemblySelection::Address { start, extent } => {
            vec![address_region(start.0, *extent, metadata)?]
        }
        DisassemblySelection::Symbols(names) => symbol_regions(names.as_slice(), metadata)?,
    };
    regions.sort_by(|left, right| {
        (left.start, left.section_end, &left.segment, &left.section).cmp(&(
            right.start,
            right.section_end,
            &right.segment,
            &right.section,
        ))
    });
    for region in &regions {
        if slice.arch.is_arm64() && region.start % 4 != 0 {
            return Err(DisassemblyError::new(
                "analysis.disassembly.address.unaligned",
                format!(
                    "{} selector starts at unaligned VA {:#x} in slice {} (0x{:08x}:0x{:08x})",
                    source_name(region.selection_source),
                    region.start,
                    slice.index,
                    slice.architecture.cpu_type as u32,
                    slice.architecture.cpu_subtype as u32
                ),
            ));
        }
    }
    Ok(regions)
}

fn explicit_section(
    slice: &SelectedSlice<'_, '_>,
    selector: &SectionSelector,
    metadata: &Metadata<'_>,
) -> Result<RegionPlan, DisassemblyError> {
    let section = metadata
        .named_section(&selector.segment, &selector.section)
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.section.missing",
                format!(
                    "section {},{} is missing from slice {}",
                    selector.segment, selector.section, slice.index
                ),
            )
        })?;
    if !is_file_backed(slice.macho, section) {
        return Err(DisassemblyError::new(
            "analysis.disassembly.section.missing",
            format!(
                "section {},{} has no file-backed bytes",
                selector.segment, selector.section
            ),
        ));
    }
    region_for_section(section, SelectionSource::ExplicitSection, None, None)
}

fn address_region(
    start: u64,
    extent: AddressExtent,
    metadata: &Metadata<'_>,
) -> Result<RegionPlan, DisassemblyError> {
    let section = metadata.find_file_section(start).ok_or_else(|| {
        DisassemblyError::new(
            "analysis.disassembly.address.unmapped",
            format!("VA {start:#x} is not in a file-backed section"),
        )
    })?;
    let section_end = section
        .addr()
        .0
        .checked_add(section.size())
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.address.unmapped",
                "section VA range overflows",
            )
        })?;
    let region_extent = match extent {
        AddressExtent::InstructionCount(count) => RegionExtent::Instructions(count.get() as u64),
        AddressExtent::ByteLength(length) => {
            let end = start.checked_add(length.get() as u64).ok_or_else(|| {
                DisassemblyError::new(
                    "analysis.disassembly.address.cross_section",
                    "requested address range overflows",
                )
            })?;
            if end > section_end {
                return Err(DisassemblyError::new(
                    "analysis.disassembly.address.cross_section",
                    format!("address range {start:#x}..{end:#x} crosses its file-backed section"),
                ));
            }
            RegionExtent::Bytes(end)
        }
    };
    region_from_parts(
        section,
        start,
        region_extent,
        SelectionSource::Address,
        None,
        None,
    )
}

fn symbol_regions(
    names: &[String],
    metadata: &Metadata,
) -> Result<Vec<RegionPlan>, DisassemblyError> {
    let names: BTreeSet<&str> = names.iter().map(String::as_str).collect();
    let mut by_start: BTreeMap<u64, (&Section, SymbolSource)> = BTreeMap::new();
    for name in names {
        let matches = metadata.requested.get(name).cloned().unwrap_or_default();
        if matches.is_empty() {
            if metadata.requested_non_code.contains(name) {
                return Err(DisassemblyError::new(
                    "analysis.disassembly.symbol.non_code",
                    format!("symbol '{name}' is not a file-backed code definition"),
                ));
            }
            return Err(DisassemblyError::new(
                "analysis.disassembly.symbol.missing",
                format!("symbol '{name}' was not found"),
            ));
        }
        let addresses: BTreeSet<u64> = matches.iter().map(|item| item.va).collect();
        if addresses.len() != 1 {
            return Err(DisassemblyError::new(
                "analysis.disassembly.symbol.ambiguous",
                format!(
                    "symbol '{name}' resolves to multiple virtual addresses; select --address to disambiguate"
                ),
            ));
        }
        let start = *addresses.iter().next().expect("non-empty address set");
        let section = metadata.find_file_section(start).ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.symbol.non_code",
                format!("symbol '{name}' is not in a file-backed section"),
            )
        })?;
        if !has_instruction_flags(section) {
            return Err(DisassemblyError::new(
                "analysis.disassembly.symbol.non_code",
                format!("symbol '{name}' is not in an instruction section"),
            ));
        }
        let source = matches
            .iter()
            .map(|item| item.source)
            .min()
            .expect("non-empty matches");
        by_start.entry(start).or_insert((section, source));
    }

    by_start
        .into_iter()
        .map(|(start, (section, range_source))| {
            let section_end = section
                .addr()
                .0
                .checked_add(section.size())
                .ok_or_else(|| {
                    DisassemblyError::new(
                        "analysis.disassembly.symbol.non_code",
                        "symbol section range overflows",
                    )
                })?;
            let next = next_code_start(metadata, start);
            let (end, end_source) = next
                .map(|item| (item.va, end_source(item.source)))
                .unwrap_or((section_end, RangeEndSource::SectionEnd));
            region_from_parts(
                section,
                start,
                RegionExtent::Bytes(end),
                SelectionSource::Symbol,
                Some(range_source),
                Some(end_source),
            )
        })
        .collect()
}

fn next_code_start<'a>(metadata: &'a Metadata<'_>, start: u64) -> Option<&'a Observation> {
    metadata.next_boundary(start)
}

fn region_for_section(
    section: &Section,
    source: SelectionSource,
    range_source: Option<SymbolSource>,
    end_source: Option<RangeEndSource>,
) -> Result<RegionPlan, DisassemblyError> {
    let end = section
        .addr()
        .0
        .checked_add(section.size())
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.section.invalid",
                "section VA range overflows",
            )
        })?;
    region_from_parts(
        section,
        section.addr().0,
        RegionExtent::Bytes(end),
        source,
        range_source,
        end_source,
    )
}

fn region_from_parts(
    section: &Section,
    start: u64,
    extent: RegionExtent,
    selection_source: SelectionSource,
    range_source: Option<SymbolSource>,
    end_source: Option<RangeEndSource>,
) -> Result<RegionPlan, DisassemblyError> {
    let section_end = section
        .addr()
        .0
        .checked_add(section.size())
        .ok_or_else(|| {
            DisassemblyError::new(
                "analysis.disassembly.section.invalid",
                "section VA range overflows",
            )
        })?;
    Ok(RegionPlan {
        segment: section.segment_name().to_string(),
        section: section.section_name().to_string(),
        section_start: section.addr().0,
        section_end,
        section_file_offset: section.offset().0,
        start,
        extent,
        selection_source,
        range_source,
        end_source,
        flags: flags(section),
    })
}

fn is_file_backed(macho: &MachoFile<'_>, section: &Section) -> bool {
    !section.section_type().is_zerofill()
        && section
            .offset()
            .0
            .checked_add(section.size())
            .is_some_and(|end| end <= macho.file_size() as u64)
}

fn has_instruction_flags(section: &Section) -> bool {
    let attrs = section.attributes();
    attrs.contains(SectionAttributes::PURE_INSTRUCTIONS)
        || attrs.contains(SectionAttributes::SOME_INSTRUCTIONS)
}

fn flags(section: &Section) -> InstructionFlags {
    InstructionFlags {
        pure_instructions: section
            .attributes()
            .contains(SectionAttributes::PURE_INSTRUCTIONS),
        some_instructions: section
            .attributes()
            .contains(SectionAttributes::SOME_INSTRUCTIONS),
    }
}

fn end_source(source: SymbolSource) -> RangeEndSource {
    match source {
        SymbolSource::Nlist => RangeEndSource::Nlist,
        SymbolSource::ExportTrie => RangeEndSource::ExportTrie,
        SymbolSource::ObjcMetadata => RangeEndSource::ObjcMetadata,
    }
}

fn source_name(source: SelectionSource) -> &'static str {
    match source {
        SelectionSource::ExecutableSection => "executable-section",
        SelectionSource::ExplicitSection => "section",
        SelectionSource::Symbol => "symbol",
        SelectionSource::Address => "address",
    }
}
