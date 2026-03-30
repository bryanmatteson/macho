use crate::constants::*;
use crate::error::{Error, Result};
use crate::ext::MachExt;
use crate::io::pod::{self, RawNlist32, RawNlist64};
use crate::model::header::Bitness;
use crate::model::mach::MachFile;
use crate::model::symbol::{StringTable, Symbol, SymbolTable, SymbolType};

const MAX_SYMBOLS: usize = 10_000_000;

impl<'data> MachExt<'data> for SymbolTable<'data> {
    fn parse<'mf>(mach: &'mf MachFile<'data>) -> Result<Self>
    where
        'data: 'mf,
    {
        parse_symbol_table(mach)
    }
}

pub fn parse_symbol_table<'data>(mach: &MachFile<'data>) -> Result<SymbolTable<'data>> {
    let symtab = mach
        .find_load_command(|lc| lc.as_symtab().is_some())
        .and_then(|lc| lc.kind.as_symtab())
        .ok_or_else(|| Error::Format("no LC_SYMTAB load command found".into()))?;

    let data = mach.bytes();

    // Validate and slice the string table
    let str_start = symtab.str_offset as usize;
    let str_end = str_start.checked_add(symtab.str_size as usize).ok_or({
        Error::Bounds {
            offset: str_start as u64,
            needed: symtab.str_size as u64,
            available: data.len() as u64,
        }
    })?;
    if str_end > data.len() {
        return Err(Error::Bounds {
            offset: str_start as u64,
            needed: symtab.str_size as u64,
            available: data.len() as u64,
        });
    }
    let string_table = StringTable::new(&data[str_start..str_end]);

    let nsyms = symtab.nsyms as usize;
    if nsyms > MAX_SYMBOLS {
        return Err(Error::Format(format!(
            "symbol table claims {nsyms} symbols, which exceeds the limit of {MAX_SYMBOLS}"
        )));
    }

    let endian = mach.endian();
    let sym_offset = symtab.sym_offset as usize;

    let symbols = match mach.bitness() {
        Bitness::Bits64 => parse_nlist64(data, endian, sym_offset, nsyms, &string_table)?,
        Bitness::Bits32 => parse_nlist32(data, endian, sym_offset, nsyms, &string_table)?,
    };

    Ok(SymbolTable::new(symbols, string_table))
}

fn parse_nlist64<'data>(
    data: &'data [u8],
    endian: crate::io::Endian,
    offset: usize,
    count: usize,
    string_table: &StringTable<'data>,
) -> Result<Vec<Symbol<'data>>> {
    let entry_size = size_of::<RawNlist64>();
    let max_cap = data.len().saturating_sub(offset) / entry_size;
    let mut symbols = Vec::with_capacity(count.min(max_cap));

    for i in 0..count {
        let raw: RawNlist64 = pod::read_pod(data, offset + i * entry_size)?;
        let n_strx = endian.interpret_u32(raw.n_strx);
        let n_desc = endian.interpret_u16(raw.n_desc);
        let n_value = endian.interpret_u64(raw.n_value);

        let name = string_table.get(n_strx)?;

        symbols.push(Symbol {
            name,
            sym_type: SymbolType::from_n_type(raw.n_type),
            external: raw.n_type & N_EXT != 0,
            private_external: raw.n_type & N_PEXT != 0,
            section_index: raw.n_sect,
            desc: n_desc,
            value: n_value,
            index: i,
        });
    }

    Ok(symbols)
}

fn parse_nlist32<'data>(
    data: &'data [u8],
    endian: crate::io::Endian,
    offset: usize,
    count: usize,
    string_table: &StringTable<'data>,
) -> Result<Vec<Symbol<'data>>> {
    let entry_size = size_of::<RawNlist32>();
    let max_cap = data.len().saturating_sub(offset) / entry_size;
    let mut symbols = Vec::with_capacity(count.min(max_cap));

    for i in 0..count {
        let raw: RawNlist32 = pod::read_pod(data, offset + i * entry_size)?;
        let n_strx = endian.interpret_u32(raw.n_strx);
        // Cast i16 to u16 to preserve bit pattern for bitmask interpretation
        let n_desc = endian.interpret_u16(raw.n_desc as u16);
        let n_value = endian.interpret_u32(raw.n_value) as u64;

        let name = string_table.get(n_strx)?;

        symbols.push(Symbol {
            name,
            sym_type: SymbolType::from_n_type(raw.n_type),
            external: raw.n_type & N_EXT != 0,
            private_external: raw.n_type & N_PEXT != 0,
            section_index: raw.n_sect,
            desc: n_desc,
            value: n_value,
            index: i,
        });
    }

    Ok(symbols)
}
