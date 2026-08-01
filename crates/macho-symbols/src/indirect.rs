//! Typed, bounded indirect-symbol bindings for stubs and pointer slots.

use macho_core::MachoFile;
use macho_core::model::addr::{ThinFileOffset, Va};
use macho_core::model::load_command::{DysymtabData, LoadCommand};
use macho_core::model::section::SectionType;

use crate::error::{Result, SymbolsError};

const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

/// Kind of section entry backed by the indirect-symbol table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IndirectBindingKind {
    /// Callable symbol stub.
    Stub,
    /// Non-lazy imported pointer slot.
    NonLazyPointer,
    /// Lazy imported pointer slot.
    LazyPointer,
}

/// Exact interpretation of one raw indirect-symbol word.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndirectSymbolTarget {
    /// Ordinary symbol-table reference.
    Symbol {
        /// Zero-based `nlist` index.
        index: u32,
        /// Validated symbol name, including the possibility of an intentionally empty name.
        name: String,
    },
    /// `INDIRECT_SYMBOL_LOCAL` special entry.
    Local,
    /// `INDIRECT_SYMBOL_ABS` special entry.
    Absolute,
    /// Both special bits are present and retained exactly.
    LocalAbsolute,
}

/// One section slot and its indirect-symbol binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectSymbolBinding {
    /// Zero-based section index in flattened segment/section order.
    pub section_index: u32,
    /// Strict UTF-8 segment name.
    pub segment_name: String,
    /// Strict UTF-8 section name.
    pub section_name: String,
    /// Section entry kind.
    pub kind: IndirectBindingKind,
    /// Zero-based entry index within the section.
    pub entry_index: u64,
    /// Unslid virtual address of the entry.
    pub address: Va,
    /// Thin-file offset of the entry bytes.
    pub file_offset: ThinFileOffset,
    /// Entry width/stride in bytes.
    pub size: u64,
    /// Zero-based index into the indirect-symbol table.
    pub indirect_table_index: u32,
    /// Raw indirect-symbol word.
    pub raw_indirect_index: u32,
    /// Validated semantic interpretation.
    pub target: IndirectSymbolTarget,
}

/// Continuation coordinate for a bounded indirect-symbol inventory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndirectBindingContinuation {
    /// First omitted binding.
    pub next: IndirectSymbolBinding,
}

/// Explicit bounded indirect-symbol evidence state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndirectBindingsOutcome {
    /// The selected image has no `LC_DYSYMTAB` command.
    Absent,
    /// Every stub and pointer-slot entry was retained.
    Complete(Vec<IndirectSymbolBinding>),
    /// A deterministic section-order prefix was retained.
    Truncated {
        /// Retained prefix.
        bindings: Vec<IndirectSymbolBinding>,
        /// Total number of relevant section entries.
        available: u64,
        /// Exact first omitted entry.
        continuation: IndirectBindingContinuation,
    },
}

/// Decode all stub, lazy-pointer, and non-lazy-pointer bindings for one image.
///
/// `limit` is the maximum retained entry count and must be positive. Special
/// local/absolute rows are evidence, not omissions. Malformed strides, ranges,
/// names, and symbol references reject the whole result.
pub fn decode_indirect_bindings(
    macho: &MachoFile<'_>,
    limit: u64,
) -> Result<IndirectBindingsOutcome> {
    if limit == 0 {
        return Err(SymbolsError::format(
            "indirect-symbol inventory limit must be positive",
        ));
    }
    let Some(dysymtab) = unique_dysymtab(macho)? else {
        return Ok(IndirectBindingsOutcome::Absent);
    };
    reject_duplicate_symtab(macho)?;

    let table_count = usize::try_from(dysymtab.nindirectsyms)
        .map_err(|_| SymbolsError::format("indirect-symbol count exceeds host"))?;
    let table_start = usize::try_from(dysymtab.indirectsymoff)
        .map_err(|_| SymbolsError::format("indirect-symbol offset exceeds host"))?;
    let table_size = table_count
        .checked_mul(4)
        .ok_or_else(|| SymbolsError::format("indirect-symbol table size overflows"))?;
    let table_end = table_start
        .checked_add(table_size)
        .ok_or_else(|| SymbolsError::format("indirect-symbol table range overflows"))?;
    let table = macho.bytes().get(table_start..table_end).ok_or_else(|| {
        SymbolsError::bounds(
            table_start as u64,
            table_size as u64,
            macho.file_size() as u64,
        )
    })?;

    let mut layouts = Vec::new();
    let mut available = 0_u64;
    for (section_index, section) in macho.all_sections().enumerate() {
        let (size, kind) = match section.section_type() {
            SectionType::SymbolStubs => (u64::from(section.reserved2()), IndirectBindingKind::Stub),
            SectionType::NonLazySymbolPointers => (
                if macho.is_64bit() { 8 } else { 4 },
                IndirectBindingKind::NonLazyPointer,
            ),
            SectionType::LazySymbolPointers => (
                if macho.is_64bit() { 8 } else { 4 },
                IndirectBindingKind::LazyPointer,
            ),
            _ => continue,
        };
        if size == 0 || section.size() % size != 0 {
            return Err(SymbolsError::format(format!(
                "indirect-symbol section {section_index} has invalid stride {size} for size {}",
                section.size()
            )));
        }
        let count = section.size() / size;
        let first = u64::from(section.reserved1());
        let end = first
            .checked_add(count)
            .ok_or_else(|| SymbolsError::format("indirect-symbol index range overflows"))?;
        if end > dysymtab.nindirectsyms as u64 {
            return Err(SymbolsError::format(format!(
                "section {section_index} indirect-symbol range {first}..{end} exceeds table count {}",
                dysymtab.nindirectsyms
            )));
        }
        available = available
            .checked_add(count)
            .ok_or_else(|| SymbolsError::format("indirect-symbol entry count overflows"))?;
        layouts.push((section_index, section, size, kind, count));
    }

    let mut needs_symbols = false;
    'sections: for (_, section, _, _, count) in &layouts {
        for entry in 0..*count {
            let table_index = u64::from(section.reserved1())
                .checked_add(entry)
                .ok_or_else(|| SymbolsError::format("indirect-symbol index overflows"))?;
            let range = indirect_word_range(table_index)?;
            let raw = macho.endian().read_u32(
                table[range]
                    .try_into()
                    .expect("validated indirect table word"),
            );
            if raw & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) == 0 {
                needs_symbols = true;
                break 'sections;
            }
        }
    }
    let symbols = needs_symbols
        .then(|| macho_core::format::parse_symbol_table(macho).map_err(SymbolsError::from))
        .transpose()?;

    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut bindings =
        Vec::with_capacity(limit.min(usize::try_from(available).unwrap_or(usize::MAX)));
    for (section_index, section, size, kind, count) in layouts {
        let segment_name = strict_name(section.segment_name().trimmed_bytes(), "segment")?;
        let section_name = strict_name(section.section_name().trimmed_bytes(), "section")?;
        for entry_index in 0..count {
            let indirect_table_index = u64::from(section.reserved1())
                .checked_add(entry_index)
                .and_then(|index| u32::try_from(index).ok())
                .ok_or_else(|| SymbolsError::format("indirect-symbol index exceeds u32"))?;
            let raw_range = indirect_word_range(u64::from(indirect_table_index))?;
            let raw_indirect_index = macho.endian().read_u32(
                table[raw_range]
                    .try_into()
                    .expect("validated indirect table word"),
            );
            let target = match raw_indirect_index & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) {
                0 => {
                    let symbol_index = usize::try_from(raw_indirect_index)
                        .map_err(|_| SymbolsError::format("symbol index exceeds host"))?;
                    let symbol = symbols
                        .as_ref()
                        .and_then(|table| table.get(symbol_index))
                        .ok_or_else(|| {
                            SymbolsError::format(format!(
                                "indirect-symbol row {indirect_table_index} references absent symbol {raw_indirect_index}"
                            ))
                        })?;
                    IndirectSymbolTarget::Symbol {
                        index: raw_indirect_index,
                        name: symbol.name.to_owned(),
                    }
                }
                INDIRECT_SYMBOL_LOCAL => IndirectSymbolTarget::Local,
                INDIRECT_SYMBOL_ABS => IndirectSymbolTarget::Absolute,
                _ => IndirectSymbolTarget::LocalAbsolute,
            };
            let relative = entry_index
                .checked_mul(size)
                .ok_or_else(|| SymbolsError::address("indirect-symbol entry offset overflows"))?;
            let address = section
                .addr()
                .0
                .checked_add(relative)
                .map(Va)
                .ok_or_else(|| SymbolsError::address("indirect-symbol entry address overflows"))?;
            let file_offset = section
                .offset()
                .0
                .checked_add(relative)
                .map(ThinFileOffset)
                .ok_or_else(|| SymbolsError::address("indirect-symbol file offset overflows"))?;
            macho
                .read_bytes_at(
                    file_offset,
                    usize::try_from(size).map_err(|_| {
                        SymbolsError::format("indirect-symbol entry size exceeds host")
                    })?,
                )
                .map_err(SymbolsError::from)?;
            let binding = IndirectSymbolBinding {
                section_index: u32::try_from(section_index)
                    .map_err(|_| SymbolsError::format("section index exceeds u32"))?,
                segment_name: segment_name.clone(),
                section_name: section_name.clone(),
                kind,
                entry_index,
                address,
                file_offset,
                size,
                indirect_table_index,
                raw_indirect_index,
                target,
            };
            if bindings.len() == limit {
                return Ok(IndirectBindingsOutcome::Truncated {
                    bindings,
                    available,
                    continuation: IndirectBindingContinuation { next: binding },
                });
            }
            bindings.push(binding);
        }
    }
    Ok(IndirectBindingsOutcome::Complete(bindings))
}

fn unique_dysymtab<'image>(macho: &'image MachoFile<'_>) -> Result<Option<&'image DysymtabData>> {
    let mut commands = macho
        .load_commands()
        .iter()
        .filter_map(|command| match command.kind() {
            LoadCommand::Dysymtab(data) => Some(data),
            _ => None,
        });
    let first = commands.next();
    if commands.next().is_some() {
        return Err(SymbolsError::format("duplicate LC_DYSYMTAB commands"));
    }
    Ok(first)
}

fn reject_duplicate_symtab(macho: &MachoFile<'_>) -> Result<()> {
    if macho
        .load_commands()
        .iter()
        .filter(|command| matches!(command.kind(), LoadCommand::Symtab(_)))
        .count()
        > 1
    {
        return Err(SymbolsError::format("duplicate LC_SYMTAB commands"));
    }
    Ok(())
}

fn strict_name(bytes: &[u8], kind: &str) -> Result<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|error| SymbolsError::format(format!("invalid UTF-8 in {kind} name: {error}")))
}

fn indirect_word_range(index: u64) -> Result<std::ops::Range<usize>> {
    let start = usize::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(size_of::<u32>()))
        .ok_or_else(|| SymbolsError::format("indirect-symbol word offset exceeds host"))?;
    let end = start
        .checked_add(size_of::<u32>())
        .ok_or_else(|| SymbolsError::format("indirect-symbol word range exceeds host"))?;
    Ok(start..end)
}

#[cfg(test)]
mod tests {
    use super::indirect_word_range;

    #[test]
    fn adversarial_word_index_returns_an_error() {
        assert!(indirect_word_range(u64::MAX).is_err());
    }
}
