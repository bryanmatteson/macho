// SPDX-License-Identifier: MIT
// Mach-O specific patching operations and models.

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::ops::Range;

// ---------------------------------------------------------------------------
// MachoPatcher
// ---------------------------------------------------------------------------

const X86_64_REL32_JUMP_LEN: usize = 5;
const X86_64_ABSOLUTE_JUMP_LEN: usize = 14;
const ARM64_DIRECT_BRANCH_LEN: usize = 4;
const ARM64_ABSOLUTE_JUMP_LEN: usize = 16;
const ARM64E_MATERIALIZED_JUMP_LEN: usize = 20;
const ARM64_LDR_X16_LITERAL_8: [u8; 4] = [0x50, 0x00, 0x00, 0x58];
const ARM64_BR_X16: [u8; 4] = [0x00, 0x02, 0x1F, 0xD6];

/// Architecture variants supported by patch planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum PatchArch {
    /// The Arm64 variant.
    Arm64,
    /// The Arm64e variant.
    Arm64e,
    /// The X86_64 variant.
    X86_64,
    /// The I386 variant.
    I386,
}

impl fmt::Display for PatchArch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arm64 => write!(f, "arm64"),
            Self::Arm64e => write!(f, "arm64e"),
            Self::X86_64 => write!(f, "x86_64"),
            Self::I386 => write!(f, "i386"),
        }
    }
}

/// A single symbol entry tracked for patch lookup.
#[derive(Debug, Clone)]
pub struct PatchSymbolEntry {
    /// The address field.
    pub address: u64,
    /// The size field.
    pub size: u64,
    /// The section field.
    pub section: Option<usize>,
    /// The is_external field.
    pub is_external: bool,
}

/// Symbol table with by-name and by-address lookup.
#[derive(Debug, Clone, Default)]
pub struct PatchSymbolTable {
    by_name: HashMap<String, PatchSymbolEntry>,
    by_address: BTreeMap<u64, String>,
}

impl PatchSymbolTable {
    /// Performs new.
    pub fn new() -> Self {
        Self::default()
    }

    /// Performs insert.
    pub fn insert(&mut self, name: String, entry: PatchSymbolEntry) {
        if entry.address != 0 {
            self.by_address.insert(entry.address, name.clone());
        }
        self.by_name.insert(name, entry);
    }

    /// Performs by_name.
    pub fn by_name(&self, name: &str) -> Option<&PatchSymbolEntry> {
        self.by_name.get(name)
    }

    /// Performs by_address.
    pub fn by_address(&self, addr: u64) -> Option<(&u64, &String)> {
        self.by_address.range(..=addr).next_back()
    }

    /// Performs at_address.
    pub fn at_address(&self, addr: u64) -> Option<&String> {
        self.by_address.get(&addr)
    }

    /// Performs len.
    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    /// Performs is_empty.
    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    /// Performs iter.
    pub fn iter(&self) -> impl Iterator<Item = (&String, &PatchSymbolEntry)> {
        self.by_name.iter()
    }

    /// Performs symbols_with_prefix.
    pub fn symbols_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a PatchSymbolEntry)> + 'a {
        self.by_name
            .iter()
            .filter(move |(name, _)| name.starts_with(prefix))
    }

    /// Performs symbols_matching.
    pub fn symbols_matching<'a, F>(
        &'a self,
        mut predicate: F,
    ) -> impl Iterator<Item = (&'a String, &'a PatchSymbolEntry)> + 'a
    where
        F: FnMut(&str, &PatchSymbolEntry) -> bool + 'a,
    {
        self.by_name
            .iter()
            .filter(move |(name, entry)| predicate(name, entry))
    }

    /// Performs vtable_symbols.
    pub fn vtable_symbols<'a>(
        &'a self,
        type_name: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a PatchSymbolEntry)> + 'a {
        let prefix = vtable_mangled_prefix(type_name);
        self.symbols_matching(move |name, _| name.starts_with(&prefix))
    }
}

/// A section within a segment.
#[derive(Debug, Clone)]
pub struct PatchSectionInfo {
    /// The name field.
    pub name: String,
    /// The segment_name field.
    pub segment_name: String,
    /// The addr field.
    pub addr: u64,
    /// The size field.
    pub size: u64,
    /// The offset field.
    pub offset: u32,
    /// The section_type field.
    pub section_type: Option<String>,
}

/// A segment in the binary.
#[derive(Debug, Clone)]
pub struct PatchSegmentInfo {
    /// The name field.
    pub name: String,
    /// The vmaddr field.
    pub vmaddr: u64,
    /// The vmsize field.
    pub vmsize: u64,
    /// The fileoff field.
    pub fileoff: u64,
    /// The filesize field.
    pub filesize: u64,
    /// The sections field.
    pub sections: Vec<PatchSectionInfo>,
}

/// Machine-code encoding selected for a function-entry branch patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum HookJumpEncoding {
    /// x86_64 `jmp rel32`.
    X86_64Relative,
    /// x86_64 `jmp qword ptr [rip + 0]; .quad target`.
    X86_64Absolute,
    /// arm64/arm64e `b <imm26>`.
    Arm64BranchImmediate,
    /// arm64/arm64e `ldr x16, #8; br x16; .quad target`.
    Arm64AbsoluteLiteral,
    /// arm64e `movz`/`movk` address materialization followed by `br x16`.
    ///
    /// Unlike the literal form, this does not introduce an unauthenticated
    /// pointer field into executable bytes.
    Arm64eMaterializedAddress,
}

impl HookJumpEncoding {
    /// Return the exact number of bytes emitted for this jump encoding.
    pub fn len(self) -> usize {
        match self {
            Self::X86_64Relative => X86_64_REL32_JUMP_LEN,
            Self::X86_64Absolute => X86_64_ABSOLUTE_JUMP_LEN,
            Self::Arm64BranchImmediate => ARM64_DIRECT_BRANCH_LEN,
            Self::Arm64AbsoluteLiteral => ARM64_ABSOLUTE_JUMP_LEN,
            Self::Arm64eMaterializedAddress => ARM64E_MATERIALIZED_JUMP_LEN,
        }
    }

    /// Return `true` when the encoding occupies zero bytes.
    pub fn is_empty(self) -> bool {
        self.len() == 0
    }
}

/// A resolved jump encoding for an executable hook patch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookJump {
    /// The arch field.
    pub arch: PatchArch,
    /// The source_va field.
    pub source_va: u64,
    /// The destination_va field.
    pub destination_va: u64,
    /// The encoding field.
    pub encoding: HookJumpEncoding,
    /// The bytes field.
    pub bytes: Vec<u8>,
}

impl HookJump {
    /// Return the number of bytes to write for this jump.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return `true` when the jump encodes no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A concrete patch plan for rewriting a function entry to branch elsewhere.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntryPatchPlan {
    /// The arch field.
    pub arch: PatchArch,
    /// The entry_va field.
    pub entry_va: u64,
    /// The entry_offset field.
    pub entry_offset: usize,
    /// The destination_va field.
    pub destination_va: u64,
    /// The overwrite_len field.
    pub overwrite_len: usize,
    /// The original_bytes field.
    pub original_bytes: Vec<u8>,
    /// The jump field.
    pub jump: HookJump,
    /// The patch_bytes field.
    pub patch_bytes: Vec<u8>,
}

impl FunctionEntryPatchPlan {
    /// Return the virtual address execution should resume at after the stolen bytes.
    pub fn resume_va(&self) -> u64 {
        self.entry_va + self.overwrite_len as u64
    }
}

/// A trampoline buffer that replays stolen bytes and jumps back to the function body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrampolinePlan {
    /// The arch field.
    pub arch: PatchArch,
    /// The trampoline_va field.
    pub trampoline_va: u64,
    /// The relocated_bytes field.
    pub relocated_bytes: Vec<u8>,
    /// The resume_va field.
    pub resume_va: u64,
    /// The jump_back field.
    pub jump_back: HookJump,
    /// The bytes field.
    pub bytes: Vec<u8>,
}

/// A complete function-entry hook plan: entry detour plus trampoline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntryHookPlan {
    /// The entry field.
    pub entry: FunctionEntryPatchPlan,
    /// The trampoline field.
    pub trampoline: TrampolinePlan,
}
