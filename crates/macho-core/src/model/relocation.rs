use std::fmt;

/// A decoded relocation entry, either standard or scattered.
#[derive(Debug, Clone, Copy)]
pub enum Relocation {
    Standard(StandardRelocation),
    Scattered(ScatteredRelocation),
}

impl Relocation {
    pub fn address(&self) -> u32 {
        match self {
            Self::Standard(r) => r.address,
            Self::Scattered(r) => r.address,
        }
    }

    pub fn reloc_type(&self) -> u8 {
        match self {
            Self::Standard(r) => r.reloc_type,
            Self::Scattered(r) => r.reloc_type,
        }
    }

    pub fn length(&self) -> u8 {
        match self {
            Self::Standard(r) => r.length,
            Self::Scattered(r) => r.length,
        }
    }

    pub fn pc_relative(&self) -> bool {
        match self {
            Self::Standard(r) => r.pc_relative,
            Self::Scattered(r) => r.pc_relative,
        }
    }

    pub fn is_scattered(&self) -> bool {
        matches!(self, Self::Scattered(_))
    }
}

impl fmt::Display for Relocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard(r) => write!(
                f,
                "addr={:#x} type={} len={} pcrel={} extern={} sym={}",
                r.address, r.reloc_type, r.length, r.pc_relative, r.is_extern, r.symbol_num
            ),
            Self::Scattered(r) => write!(
                f,
                "SCATTERED addr={:#x} type={} len={} pcrel={} value={:#x}",
                r.address, r.reloc_type, r.length, r.pc_relative, r.value
            ),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct StandardRelocation {
    pub address: u32,
    /// Symbol table index (if extern) or section ordinal (if not extern). 24 bits.
    pub symbol_num: u32,
    pub pc_relative: bool,
    /// Log2 of the relocation size: 0=byte, 1=word, 2=long, 3=quad.
    pub length: u8,
    pub is_extern: bool,
    /// Architecture-specific relocation type. 4 bits.
    pub reloc_type: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct ScatteredRelocation {
    /// Architecture-specific relocation type. 4 bits.
    pub reloc_type: u8,
    /// Log2 of the relocation size.
    pub length: u8,
    pub pc_relative: bool,
    /// Offset within the section. 24 bits.
    pub address: u32,
    /// The value the relocation refers to (address of the symbol).
    pub value: i32,
}
