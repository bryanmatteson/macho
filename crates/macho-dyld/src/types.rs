use std::fmt;

use crate::format::constants::*;

/// A resolved fixup at a specific file location.
#[derive(Debug, Clone)]
pub struct Fixup {
    /// The segment_index field.
    pub segment_index: usize,
    /// The segment_offset field.
    pub segment_offset: u64,
    /// The kind field.
    pub kind: FixupKind,
}

#[derive(Debug, Clone)]
/// The FixupKind type.
#[non_exhaustive]
pub enum FixupKind {
    /// The Rebase variant.
    Rebase {
        /// The u64 field.
        target: u64,
    },
    /// The Bind variant.
    Bind {
        /// The u32 field.
        import_index: u32,
        /// The i64 field.
        addend: i64,
    },
    /// The AuthRebase variant.
    AuthRebase {
        /// The u64 field.
        target: u64,
        /// The u16 field.
        diversity: u16,
        /// The u8 field.
        key: u8,
        /// The bool field.
        addr_div: bool,
    },
    /// The AuthBind variant.
    AuthBind {
        /// The u32 field.
        import_index: u32,
        /// The u16 field.
        diversity: u16,
        /// The u8 field.
        key: u8,
        /// The bool field.
        addr_div: bool,
    },
}

/// An import referenced by chained fixups.
#[derive(Debug, Clone)]
pub struct ChainedImport<'data> {
    /// The name field.
    pub name: &'data str,
    /// The lib_ordinal field.
    pub lib_ordinal: i32,
    /// The weak field.
    pub weak: bool,
    /// The addend field.
    pub addend: i64,
}

/// An exported symbol from the exports trie.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The name field.
    pub name: String,
    /// The flags field.
    pub flags: u32,
    /// The kind field.
    pub kind: ExportKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The ExportKind type.
#[non_exhaustive]
pub enum ExportKind {
    /// The Regular variant.
    Regular {
        /// The u64 field.
        address: u64,
    },
    /// The ThreadLocal variant.
    ThreadLocal {
        /// The u64 field.
        address: u64,
    },
    /// The Absolute variant.
    Absolute {
        /// The u64 field.
        address: u64,
    },
    /// The Reexport variant.
    Reexport {
        /// The u64 field.
        ordinal: u64,
        /// The item field.
        name: Option<String>,
    },
    /// The StubAndResolver variant.
    StubAndResolver {
        /// The u64 field.
        stub_offset: u64,
        /// The u64 field.
        resolver_offset: u64,
    },
}

impl Export {
    /// Performs address.
    pub fn address(&self) -> Option<u64> {
        match &self.kind {
            ExportKind::Regular { address }
            | ExportKind::ThreadLocal { address }
            | ExportKind::Absolute { address } => Some(*address),
            _ => None,
        }
    }

    /// Performs is_weak.
    pub fn is_weak(&self) -> bool {
        self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0
    }

    /// Performs is_reexport.
    pub fn is_reexport(&self) -> bool {
        self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT != 0
    }
}

impl fmt::Display for Export {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            ExportKind::Regular { address } => write!(f, "{:#018x} {}", address, self.name),
            ExportKind::ThreadLocal { address } => {
                write!(f, "{:#018x} [tlv] {}", address, self.name)
            }
            ExportKind::Absolute { address } => write!(f, "{:#018x} [abs] {}", address, self.name),
            ExportKind::Reexport { ordinal, name } => {
                write!(f, "[reexport ord={ordinal}] {}", self.name)?;
                if let Some(n) = name {
                    write!(f, " -> {n}")?;
                }
                Ok(())
            }
            ExportKind::StubAndResolver {
                stub_offset,
                resolver_offset,
            } => {
                write!(
                    f,
                    "[stub={stub_offset:#x} resolver={resolver_offset:#x}] {}",
                    self.name
                )
            }
        }
    }
}

/// A legacy rebase entry from LC_DYLD_INFO.
#[derive(Debug, Clone)]
pub struct RebaseEntry {
    /// The segment_index field.
    pub segment_index: usize,
    /// The segment_offset field.
    pub segment_offset: u64,
    /// The rebase_type field.
    pub rebase_type: u8,
}

/// A legacy bind entry from LC_DYLD_INFO.
#[derive(Debug, Clone)]
pub struct BindEntry<'data> {
    /// The segment_index field.
    pub segment_index: usize,
    /// The segment_offset field.
    pub segment_offset: u64,
    /// The bind_type field.
    pub bind_type: u8,
    /// The symbol_name field.
    pub symbol_name: &'data str,
    /// The lib_ordinal field.
    pub lib_ordinal: i64,
    /// The addend field.
    pub addend: i64,
    /// The weak field.
    pub weak: bool,
    /// The lazy field.
    pub lazy: bool,
}

impl fmt::Display for BindEntry<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "seg[{}]+{:#x} {} ordinal={} addend={}",
            self.segment_index,
            self.segment_offset,
            self.symbol_name,
            self.lib_ordinal,
            self.addend
        )
    }
}
