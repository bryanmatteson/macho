use crate::core::error::{Error, Result};
use crate::core::format::constants::*;
use crate::core::format::io::pod::{self, RawNlist32, RawNlist64};
use crate::core::model::ext::MachoExt;
use crate::core::model::header::Bitness;
use crate::core::model::macho_file::MachoFile;
use crate::core::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

const MAX_SYMBOLS: usize = 10_000_000;

impl<'data> MachoExt<'data> for SymbolTable<'data> {
    type Error = Error;

    fn parse<'mf>(macho: &'mf MachoFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        parse_symbol_table(macho)
    }
}

/// Performs parse_symbol_table.
pub fn parse_symbol_table<'data>(macho: &MachoFile<'data>) -> Result<SymbolTable<'data>> {
    let layout = symbol_table_layout(macho)?;
    let mut symbols = Vec::new();
    fold_nlist_symbols(macho, &layout, &mut symbols, |symbols, symbol| {
        symbols.push(symbol);
        Ok(())
    })?;

    Ok(SymbolTable::new(symbols, layout.string_table))
}

/// Parse selected `nlist` entries without walking or materializing the complete
/// symbol table.
///
/// Results preserve the requested index order, including duplicate indices.
/// The symbol- and string-table layouts and every requested entry are fully
/// bounds checked. An out-of-range index rejects the whole request.
pub fn parse_symbols_at<'data>(
    macho: &MachoFile<'data>,
    indices: &[usize],
) -> Result<Vec<Symbol<'data>>> {
    let layout = symbol_table_layout(macho)?;
    let mut symbols = Vec::with_capacity(indices.len());
    for &index in indices {
        if index >= layout.symbol_count {
            return Err(Error::format(format!(
                "symbol index {index} exceeds table count {}",
                layout.symbol_count
            )));
        }
        symbols.push(parse_nlist_symbol(macho, &layout, index)?);
    }
    Ok(symbols)
}

/// Fold raw `nlist` entries in physical symbol-table order without first
/// materializing a [`SymbolTable`].
///
/// This performs one pass over the `nlist` entries. The accumulator is returned
/// only after every entry and referenced string-table name has parsed
/// successfully. If a later entry is malformed, the partially folded
/// accumulator is dropped and only the parse error is returned. The caller
/// controls retained memory through the accumulator and need not collect
/// [`Symbol`] values.
pub fn fold_symbols<'data, State>(
    macho: &MachoFile<'data>,
    mut state: State,
    mut folder: impl FnMut(&mut State, Symbol<'data>) -> Result<()>,
) -> Result<State> {
    let layout = symbol_table_layout(macho)?;
    fold_nlist_symbols(macho, &layout, &mut state, &mut folder)?;
    Ok(state)
}

struct SymbolTableLayout<'data> {
    string_table: StringTable<'data>,
    symbol_count: usize,
    symbol_offset: usize,
}

fn symbol_table_layout<'data>(macho: &MachoFile<'data>) -> Result<SymbolTableLayout<'data>> {
    let symtab = macho
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind.as_symtab())
        .ok_or_else(|| Error::format("no LC_SYMTAB load command found"))?;

    let data = macho.bytes();

    // Validate and slice the string table
    let str_start = symtab.str_offset as usize;
    let str_end = str_start
        .checked_add(symtab.str_size as usize)
        .ok_or_else(|| {
            Error::bounds(str_start as u64, symtab.str_size as u64, data.len() as u64)
        })?;
    if str_end > data.len() {
        return Err(Error::bounds(
            str_start as u64,
            symtab.str_size as u64,
            data.len() as u64,
        ));
    }
    let string_table = StringTable::new(&data[str_start..str_end]);

    let nsyms = symtab.nsyms as usize;
    if nsyms > MAX_SYMBOLS {
        return Err(Error::format(format!(
            "symbol table claims {nsyms} symbols, which exceeds the limit of {MAX_SYMBOLS}"
        )));
    }

    Ok(SymbolTableLayout {
        string_table,
        symbol_count: nsyms,
        symbol_offset: symtab.sym_offset as usize,
    })
}

fn fold_nlist_symbols<'data, State>(
    macho: &MachoFile<'data>,
    layout: &SymbolTableLayout<'data>,
    state: &mut State,
    mut folder: impl FnMut(&mut State, Symbol<'data>) -> Result<()>,
) -> Result<()> {
    match macho.bitness() {
        Bitness::Bits64 => fold_nlist64(
            macho.bytes(),
            macho.endian(),
            layout.symbol_offset,
            layout.symbol_count,
            &layout.string_table,
            state,
            &mut folder,
        ),
        Bitness::Bits32 => fold_nlist32(
            macho.bytes(),
            macho.endian(),
            layout.symbol_offset,
            layout.symbol_count,
            &layout.string_table,
            state,
            &mut folder,
        ),
    }
}

fn parse_nlist_symbol<'data>(
    macho: &MachoFile<'data>,
    layout: &SymbolTableLayout<'data>,
    index: usize,
) -> Result<Symbol<'data>> {
    match macho.bitness() {
        Bitness::Bits64 => {
            let entry_size = size_of::<RawNlist64>();
            let entry_off = nlist_offset(layout.symbol_offset, index, entry_size, "nlist64")?;
            let raw: RawNlist64 = pod::read_pod(macho.bytes(), entry_off)?;
            let endian = macho.endian();
            Ok(Symbol {
                name: layout.string_table.get(endian.interpret_u32(raw.n_strx))?,
                sym_type: SymbolType::from_n_type(raw.n_type),
                external: raw.n_type & N_EXT != 0,
                private_external: raw.n_type & N_PEXT != 0,
                section_index: raw.n_sect,
                desc: endian.interpret_u16(raw.n_desc),
                value: endian.interpret_u64(raw.n_value),
                index,
            })
        }
        Bitness::Bits32 => {
            let entry_size = size_of::<RawNlist32>();
            let entry_off = nlist_offset(layout.symbol_offset, index, entry_size, "nlist32")?;
            let raw: RawNlist32 = pod::read_pod(macho.bytes(), entry_off)?;
            let endian = macho.endian();
            Ok(Symbol {
                name: layout.string_table.get(endian.interpret_u32(raw.n_strx))?,
                sym_type: SymbolType::from_n_type(raw.n_type),
                external: raw.n_type & N_EXT != 0,
                private_external: raw.n_type & N_PEXT != 0,
                section_index: raw.n_sect,
                desc: endian.interpret_u16(raw.n_desc as u16),
                value: u64::from(endian.interpret_u32(raw.n_value)),
                index,
            })
        }
    }
}

fn nlist_offset(base: usize, index: usize, entry_size: usize, kind: &str) -> Result<usize> {
    base.checked_add(
        index
            .checked_mul(entry_size)
            .ok_or_else(|| Error::format(format!("{kind}[{index}]: stride overflows")))?,
    )
    .ok_or_else(|| Error::format(format!("{kind}[{index}]: offset overflows")))
}

#[allow(clippy::too_many_arguments)]
fn fold_nlist64<'data, State>(
    data: &'data [u8],
    endian: crate::core::format::io::Endian,
    offset: usize,
    count: usize,
    string_table: &StringTable<'data>,
    state: &mut State,
    folder: &mut impl FnMut(&mut State, Symbol<'data>) -> Result<()>,
) -> Result<()> {
    let entry_size = size_of::<RawNlist64>();

    for i in 0..count {
        let entry_off = offset
            .checked_add(
                i.checked_mul(entry_size)
                    .ok_or_else(|| Error::format(format!("nlist64[{i}]: stride overflows")))?,
            )
            .ok_or_else(|| Error::format(format!("nlist64[{i}]: offset overflows")))?;
        let raw: RawNlist64 = pod::read_pod(data, entry_off)?;
        let n_strx = endian.interpret_u32(raw.n_strx);
        let n_desc = endian.interpret_u16(raw.n_desc);
        let n_value = endian.interpret_u64(raw.n_value);

        let name = string_table.get(n_strx)?;

        folder(
            state,
            Symbol {
                name,
                sym_type: SymbolType::from_n_type(raw.n_type),
                external: raw.n_type & N_EXT != 0,
                private_external: raw.n_type & N_PEXT != 0,
                section_index: raw.n_sect,
                desc: n_desc,
                value: n_value,
                index: i,
            },
        )?;
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn fold_nlist32<'data, State>(
    data: &'data [u8],
    endian: crate::core::format::io::Endian,
    offset: usize,
    count: usize,
    string_table: &StringTable<'data>,
    state: &mut State,
    folder: &mut impl FnMut(&mut State, Symbol<'data>) -> Result<()>,
) -> Result<()> {
    let entry_size = size_of::<RawNlist32>();

    for i in 0..count {
        let entry_off = offset
            .checked_add(
                i.checked_mul(entry_size)
                    .ok_or_else(|| Error::format(format!("nlist32[{i}]: stride overflows")))?,
            )
            .ok_or_else(|| Error::format(format!("nlist32[{i}]: offset overflows")))?;
        let raw: RawNlist32 = pod::read_pod(data, entry_off)?;
        let n_strx = endian.interpret_u32(raw.n_strx);
        // Cast i16 to u16 to preserve bit pattern for bitmask interpretation
        let n_desc = endian.interpret_u16(raw.n_desc as u16);
        let n_value = endian.interpret_u32(raw.n_value) as u64;

        let name = string_table.get(n_strx)?;

        folder(
            state,
            Symbol {
                name,
                sym_type: SymbolType::from_n_type(raw.n_type),
                external: raw.n_type & N_EXT != 0,
                private_external: raw.n_type & N_PEXT != 0,
                section_index: raw.n_sect,
                desc: n_desc,
                value: n_value,
                index: i,
            },
        )?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn macho_with_symbols(second_name_offset: u32) -> Vec<u8> {
        let command_size = 24u32;
        let symbol_offset = 32u32 + command_size;
        let symbol_count = 2u32;
        let string_table = b"\0second\0first\0";
        let string_offset = symbol_offset + symbol_count * size_of::<RawNlist64>() as u32;
        let mut bytes = Vec::with_capacity(string_offset as usize + string_table.len());

        // mach_header_64
        bytes.extend_from_slice(&MH_MAGIC_64.to_le_bytes());
        bytes.extend_from_slice(&CPU_TYPE_X86_64.to_le_bytes());
        bytes.extend_from_slice(&CPU_SUBTYPE_X86_64_ALL.to_le_bytes());
        bytes.extend_from_slice(&MH_EXECUTE.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&command_size.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());

        // symtab_command
        bytes.extend_from_slice(&LC_SYMTAB.to_le_bytes());
        bytes.extend_from_slice(&command_size.to_le_bytes());
        bytes.extend_from_slice(&symbol_offset.to_le_bytes());
        bytes.extend_from_slice(&symbol_count.to_le_bytes());
        bytes.extend_from_slice(&string_offset.to_le_bytes());
        bytes.extend_from_slice(&(string_table.len() as u32).to_le_bytes());

        // File order differs from lexical name order.
        push_nlist64(&mut bytes, 8, 0x2000);
        push_nlist64(&mut bytes, second_name_offset, 0x1000);
        bytes.extend_from_slice(string_table);
        bytes
    }

    fn push_nlist64(bytes: &mut Vec<u8>, name_offset: u32, value: u64) {
        bytes.extend_from_slice(&name_offset.to_le_bytes());
        bytes.push(N_SECT | N_EXT);
        bytes.push(1);
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn parse_fixture(bytes: &[u8]) -> MachoFile<'_> {
        crate::core::format::macho::parse_macho_file(bytes).unwrap()
    }

    #[test]
    fn fold_symbols_uses_physical_nlist_order() {
        let bytes = macho_with_symbols(1);
        let macho = parse_fixture(&bytes);

        let names = fold_symbols(&macho, Vec::new(), |names, symbol| {
            names.push((symbol.index, symbol.name, symbol.value));
            Ok(())
        })
        .unwrap();

        assert_eq!(names, [(0, "first", 0x2000), (1, "second", 0x1000)]);
        let table = parse_symbol_table(&macho).unwrap();
        assert_eq!(
            table
                .symbols()
                .iter()
                .map(|symbol| symbol.name)
                .collect::<Vec<_>>(),
            ["first", "second"]
        );
    }

    #[test]
    fn fold_symbols_does_not_require_a_symbol_collection() {
        let bytes = macho_with_symbols(1);
        let macho = parse_fixture(&bytes);

        let (count, value_sum) = fold_symbols(&macho, (0usize, 0u64), |summary, symbol| {
            summary.0 += 1;
            summary.1 += symbol.value;
            Ok(())
        })
        .unwrap();

        assert_eq!(count, 2);
        assert_eq!(value_sum, 0x3000);
    }

    #[test]
    fn selected_symbols_preserve_request_order_and_skip_unrequested_rows() {
        let bytes = macho_with_symbols(99);
        let macho = parse_fixture(&bytes);

        let symbols = parse_symbols_at(&macho, &[0, 0]).unwrap();
        assert_eq!(
            symbols
                .iter()
                .map(|symbol| (symbol.index, symbol.name, symbol.value))
                .collect::<Vec<_>>(),
            [(0, "first", 0x2000), (0, "first", 0x2000)]
        );
        assert!(parse_symbols_at(&macho, &[1]).is_err());
        assert!(parse_symbols_at(&macho, &[2]).is_err());
    }

    #[test]
    fn malformed_suffix_does_not_return_partially_folded_symbol_state() {
        let bytes = macho_with_symbols(99);
        let macho = parse_fixture(&bytes);
        let mut folder_calls = 0usize;

        let result = fold_symbols(&macho, 0usize, |count, _symbol| {
            folder_calls += 1;
            *count += 1;
            Ok(())
        });

        assert!(result.is_err());
        assert_eq!(folder_calls, 1);
        assert!(parse_symbol_table(&macho).is_err());
    }
}
