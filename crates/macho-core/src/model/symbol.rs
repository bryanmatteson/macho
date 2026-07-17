use crate::error::{Error, Result};
use crate::format::constants::*;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The SymbolType type.
pub enum SymbolType {
    /// The Undefined variant.
    Undefined,
    /// The Absolute variant.
    Absolute,
    /// The Section variant.
    Section,
    /// The PreboundUndefined variant.
    PreboundUndefined,
    /// The Indirect variant.
    Indirect,
    /// STAB debugging symbol. The inner value is the stab type code
    /// (the full `n_type` byte with `N_STAB` bits set). STAB symbols are
    /// not regular code/data symbols — `is_defined()` and `is_undefined()`
    /// both return false for them.
    Stab(u8),
    /// Unknown symbol type. The inner value is the masked N_TYPE bits only
    /// (not the full n_type byte).
    Unknown(u8),
}

impl SymbolType {
    /// Performs from_n_type.
    pub fn from_n_type(n_type: u8) -> Self {
        if n_type & N_STAB != 0 {
            return Self::Stab(n_type);
        }
        match n_type & N_TYPE {
            N_UNDF => Self::Undefined,
            N_ABS => Self::Absolute,
            N_SECT => Self::Section,
            N_PBUD => Self::PreboundUndefined,
            N_INDR => Self::Indirect,
            other => Self::Unknown(other),
        }
    }

    /// Performs name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Undefined => "undef",
            Self::Absolute => "abs",
            Self::Section => "sect",
            Self::PreboundUndefined => "pbud",
            Self::Indirect => "indr",
            Self::Stab(_) => "stab",
            Self::Unknown(_) => "unk",
        }
    }

    /// Performs is_stab.
    pub fn is_stab(&self) -> bool {
        matches!(self, Self::Stab(_))
    }
}

impl fmt::Display for SymbolType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Debug, Clone)]
/// The Symbol type.
pub struct Symbol<'data> {
    /// The name field.
    pub name: &'data str,
    /// The sym_type field.
    pub sym_type: SymbolType,
    /// The external field.
    pub external: bool,
    /// The private_external field.
    pub private_external: bool,
    /// The section_index field.
    pub section_index: u8,
    /// The desc field.
    pub desc: u16,
    /// The value field.
    pub value: u64,
    /// Original index in the symbol table.
    pub index: usize,
}

impl Symbol<'_> {
    /// Performs is_stab.
    pub fn is_stab(&self) -> bool {
        self.sym_type.is_stab()
    }

    /// Performs is_defined.
    pub fn is_defined(&self) -> bool {
        matches!(self.sym_type, SymbolType::Section | SymbolType::Absolute)
    }

    /// Performs is_undefined.
    pub fn is_undefined(&self) -> bool {
        matches!(self.sym_type, SymbolType::Undefined)
    }

    /// Performs is_weak_def.
    pub fn is_weak_def(&self) -> bool {
        self.desc & N_WEAK_DEF != 0
    }

    /// Performs is_weak_ref.
    pub fn is_weak_ref(&self) -> bool {
        self.desc & N_WEAK_REF != 0
    }

    /// Performs is_no_dead_strip.
    pub fn is_no_dead_strip(&self) -> bool {
        self.desc & N_NO_DEAD_STRIP != 0
    }

    /// Performs is_alt_entry.
    pub fn is_alt_entry(&self) -> bool {
        self.desc & N_ALT_ENTRY != 0
    }

    /// Extract the library ordinal from bits 8-15 of n_desc.
    pub fn library_ordinal(&self) -> u8 {
        ((self.desc >> 8) & 0xFF) as u8
    }
}

impl fmt::Display for Symbol<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x} {} {}", self.value, self.sym_type, self.name)
    }
}

/// A view into the raw string table bytes, supporting index-based lookup.
#[derive(Clone)]
pub struct StringTable<'data> {
    data: &'data [u8],
}

impl<'data> StringTable<'data> {
    /// Performs new.
    pub fn new(data: &'data [u8]) -> Self {
        Self { data }
    }

    /// Performs get.
    pub fn get(&self, index: u32) -> Result<&'data str> {
        let start = index as usize;
        if start >= self.data.len() {
            return Err(Error::bounds(start as u64, 1, self.data.len() as u64));
        }
        let slice = &self.data[start..];
        let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
        std::str::from_utf8(&slice[..end]).map_err(|e| {
            Error::format(format!(
                "invalid UTF-8 in string table at index {index}: {e}"
            ))
        })
    }

    /// Performs bytes.
    pub fn bytes(&self) -> &'data [u8] {
        self.data
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for StringTable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("StringTable")
            .field("len", &self.data.len())
            .finish()
    }
}

/// A parsed symbol table extracted from LC_SYMTAB.
pub struct SymbolTable<'data> {
    symbols: Vec<Symbol<'data>>,
    string_table: StringTable<'data>,
}

impl<'data> SymbolTable<'data> {
    pub(crate) fn new(symbols: Vec<Symbol<'data>>, string_table: StringTable<'data>) -> Self {
        Self {
            symbols,
            string_table,
        }
    }

    /// Performs symbols.
    pub fn symbols(&self) -> &[Symbol<'data>] {
        &self.symbols
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Performs get.
    pub fn get(&self, index: usize) -> Option<&Symbol<'data>> {
        self.symbols.get(index)
    }

    /// Performs string_table.
    pub fn string_table(&self) -> &StringTable<'data> {
        &self.string_table
    }

    /// Performs find_by_name.
    pub fn find_by_name(&self, name: &str) -> Option<&Symbol<'data>> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /// Performs defined.
    pub fn defined(&self) -> impl Iterator<Item = &Symbol<'data>> {
        self.symbols.iter().filter(|s| s.is_defined())
    }

    /// Performs undefined.
    pub fn undefined(&self) -> impl Iterator<Item = &Symbol<'data>> {
        self.symbols.iter().filter(|s| s.is_undefined())
    }

    /// Performs stabs.
    pub fn stabs(&self) -> impl Iterator<Item = &Symbol<'data>> {
        self.symbols.iter().filter(|s| s.is_stab())
    }

    /// Performs external.
    pub fn external(&self) -> impl Iterator<Item = &Symbol<'data>> {
        self.symbols.iter().filter(|s| s.external)
    }
}

impl fmt::Debug for SymbolTable<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SymbolTable")
            .field("num_symbols", &self.symbols.len())
            .field("string_table", &self.string_table)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_table_get() {
        let data = b"\0hello\0world\0";
        let st = StringTable::new(data);
        assert_eq!(st.get(0).unwrap(), "");
        assert_eq!(st.get(1).unwrap(), "hello");
        assert_eq!(st.get(7).unwrap(), "world");
    }

    #[test]
    fn string_table_out_of_bounds() {
        let data = b"\0hello\0";
        let st = StringTable::new(data);
        assert!(st.get(100).is_err());
    }

    #[test]
    fn symbol_type_classification() {
        assert_eq!(SymbolType::from_n_type(0x0f), SymbolType::Section);
        assert_eq!(SymbolType::from_n_type(0x01), SymbolType::Undefined);
        assert_eq!(SymbolType::from_n_type(0x03), SymbolType::Absolute);
    }

    #[test]
    fn stab_type_classification() {
        // N_FUN = 0x24 has N_STAB bits set (0x20 & 0xe0 != 0)
        let st = SymbolType::from_n_type(0x24);
        assert!(st.is_stab());
        assert_eq!(st, SymbolType::Stab(0x24));
        assert_eq!(st.name(), "stab");
    }

    #[test]
    fn symbol_helpers() {
        let sym = Symbol {
            name: "_test",
            sym_type: SymbolType::Section,
            external: true,
            private_external: false,
            section_index: 1,
            desc: N_WEAK_DEF,
            value: 0x1000,
            index: 0,
        };
        assert!(sym.is_defined());
        assert!(!sym.is_undefined());
        assert!(!sym.is_stab());
        assert!(sym.is_weak_def());
        assert!(!sym.is_weak_ref());
        assert_eq!(sym.library_ordinal(), 0);
    }
}
