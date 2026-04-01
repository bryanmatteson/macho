use std::fmt;

use crate::format::constants::*;

/// A resolved fixup at a specific file location.
#[derive(Debug, Clone)]
pub struct Fixup {
    pub segment_index: usize,
    pub segment_offset: u64,
    pub kind: FixupKind,
}

#[derive(Debug, Clone)]
pub enum FixupKind {
    Rebase {
        target: u64,
    },
    Bind {
        import_index: u32,
        addend: i64,
    },
    AuthRebase {
        target: u64,
        diversity: u16,
        key: u8,
        addr_div: bool,
    },
    AuthBind {
        import_index: u32,
        diversity: u16,
        key: u8,
        addr_div: bool,
    },
}

/// An import referenced by chained fixups.
#[derive(Debug, Clone)]
pub struct ChainedImport<'data> {
    pub name: &'data str,
    pub lib_ordinal: i32,
    pub weak: bool,
    pub addend: i64,
}

/// An exported symbol from the exports trie.
#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub flags: u32,
    pub kind: ExportKind,
}

#[derive(Debug, Clone)]
pub enum ExportKind {
    Regular {
        address: u64,
    },
    ThreadLocal {
        address: u64,
    },
    Absolute {
        address: u64,
    },
    Reexport {
        ordinal: u64,
        name: Option<String>,
    },
    StubAndResolver {
        stub_offset: u64,
        resolver_offset: u64,
    },
}

impl Export {
    pub fn address(&self) -> Option<u64> {
        match &self.kind {
            ExportKind::Regular { address }
            | ExportKind::ThreadLocal { address }
            | ExportKind::Absolute { address } => Some(*address),
            _ => None,
        }
    }

    pub fn is_weak(&self) -> bool {
        self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION != 0
    }

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
    pub segment_index: usize,
    pub segment_offset: u64,
    pub rebase_type: u8,
}

/// A legacy bind entry from LC_DYLD_INFO.
#[derive(Debug, Clone)]
pub struct BindEntry<'data> {
    pub segment_index: usize,
    pub segment_offset: u64,
    pub bind_type: u8,
    pub symbol_name: &'data str,
    pub lib_ordinal: i64,
    pub addend: i64,
    pub weak: bool,
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
