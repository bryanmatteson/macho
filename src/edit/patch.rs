// SPDX-License-Identifier: MIT
//! Mach-O specific patching operations.
//!
//! Provides a `MachoPatcher` that operates on an in-memory copy of a Mach-O
//! binary, offering virtual address to file offset translation, symbol-based
//! offset lookup, byte pattern searching, atomic read/write operations that
//! return the original bytes for rollback, and architecture-aware executable
//! hook patch planning for function-entry detours.

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
const ARM64_NOP: [u8; 4] = [0x1F, 0x20, 0x03, 0xD5];
const ARM64_LDR_X16_LITERAL_8: [u8; 4] = [0x50, 0x00, 0x00, 0x58];
const ARM64_BR_X16: [u8; 4] = [0x00, 0x02, 0x1F, 0xD6];

/// Architecture variants supported by patch planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PatchArch {
    Arm64,
    Arm64e,
    X86_64,
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
    pub address: u64,
    pub size: u64,
    pub section: Option<usize>,
    pub is_external: bool,
}

/// Symbol table with by-name and by-address lookup.
#[derive(Debug, Clone, Default)]
pub struct PatchSymbolTable {
    by_name: HashMap<String, PatchSymbolEntry>,
    by_address: BTreeMap<u64, String>,
}

impl PatchSymbolTable {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: String, entry: PatchSymbolEntry) {
        if entry.address != 0 {
            self.by_address.insert(entry.address, name.clone());
        }
        self.by_name.insert(name, entry);
    }

    pub fn by_name(&self, name: &str) -> Option<&PatchSymbolEntry> {
        self.by_name.get(name)
    }

    pub fn by_address(&self, addr: u64) -> Option<(&u64, &String)> {
        self.by_address.range(..=addr).next_back()
    }

    pub fn at_address(&self, addr: u64) -> Option<&String> {
        self.by_address.get(&addr)
    }

    pub fn len(&self) -> usize {
        self.by_name.len()
    }

    pub fn is_empty(&self) -> bool {
        self.by_name.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &PatchSymbolEntry)> {
        self.by_name.iter()
    }

    pub fn symbols_with_prefix<'a>(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = (&'a String, &'a PatchSymbolEntry)> + 'a {
        self.by_name
            .iter()
            .filter(move |(name, _)| name.starts_with(prefix))
    }

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
    pub name: String,
    pub segment_name: String,
    pub addr: u64,
    pub size: u64,
    pub offset: u32,
    pub section_type: Option<String>,
}

/// A segment in the binary.
#[derive(Debug, Clone)]
pub struct PatchSegmentInfo {
    pub name: String,
    pub vmaddr: u64,
    pub vmsize: u64,
    pub fileoff: u64,
    pub filesize: u64,
    pub sections: Vec<PatchSectionInfo>,
}

/// Machine-code encoding selected for a function-entry branch patch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HookJumpEncoding {
    /// x86_64 `jmp rel32`.
    X86_64Relative,
    /// x86_64 `jmp qword ptr [rip + 0]; .quad target`.
    X86_64Absolute,
    /// arm64/arm64e `b <imm26>`.
    Arm64BranchImmediate,
    /// arm64/arm64e `ldr x16, #8; br x16; .quad target`.
    Arm64AbsoluteLiteral,
}

impl HookJumpEncoding {
    /// Return the exact number of bytes emitted for this jump encoding.
    pub fn len(self) -> usize {
        match self {
            Self::X86_64Relative => X86_64_REL32_JUMP_LEN,
            Self::X86_64Absolute => X86_64_ABSOLUTE_JUMP_LEN,
            Self::Arm64BranchImmediate => ARM64_DIRECT_BRANCH_LEN,
            Self::Arm64AbsoluteLiteral => ARM64_ABSOLUTE_JUMP_LEN,
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
    pub arch: PatchArch,
    pub source_va: u64,
    pub destination_va: u64,
    pub encoding: HookJumpEncoding,
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
    pub arch: PatchArch,
    pub entry_va: u64,
    pub entry_offset: usize,
    pub destination_va: u64,
    pub overwrite_len: usize,
    pub original_bytes: Vec<u8>,
    pub jump: HookJump,
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
    pub arch: PatchArch,
    pub trampoline_va: u64,
    pub relocated_bytes: Vec<u8>,
    pub resume_va: u64,
    pub jump_back: HookJump,
    pub bytes: Vec<u8>,
}

/// A complete function-entry hook plan: entry detour plus trampoline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FunctionEntryHookPlan {
    pub entry: FunctionEntryPatchPlan,
    pub trampoline: TrampolinePlan,
}

/// Operates on a mutable in-memory copy of a Mach-O binary.
///
/// All mutations go through `write_bytes`, which returns the original content
/// so that callers can feed it into the rollback store.
#[derive(Debug)]
pub struct MachoPatcher {
    data: Vec<u8>,
    symbols: PatchSymbolTable,
    segments: Vec<PatchSegmentInfo>,
}

impl MachoPatcher {
    /// Create a new patcher from an image's data, symbols, and segments.
    pub fn new(data: Vec<u8>, symbols: PatchSymbolTable, segments: Vec<PatchSegmentInfo>) -> Self {
        Self {
            data,
            symbols,
            segments,
        }
    }

    /// Return a reference to the underlying byte buffer.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Consume the patcher and return the (potentially modified) byte buffer.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Return a reference to the symbol table.
    pub fn symbols(&self) -> &PatchSymbolTable {
        &self.symbols
    }

    /// Return a reference to the segment list.
    pub fn segments(&self) -> &[PatchSegmentInfo] {
        &self.segments
    }

    // -- Address translation ------------------------------------------------

    /// Translate a virtual address to a file offset.
    ///
    /// Walks segments to find one whose `[vmaddr, vmaddr+vmsize)` range
    /// contains `va`, then computes `fileoff + (va - vmaddr)`.
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        for seg in &self.segments {
            let Some(seg_end) = seg.vmaddr.checked_add(seg.vmsize) else {
                continue;
            };
            if va >= seg.vmaddr && va < seg_end {
                let delta = va - seg.vmaddr;
                // Ensure the offset falls within the file-backed portion.
                if delta < seg.filesize {
                    let Some(fileoff) = seg.fileoff.checked_add(delta) else {
                        continue;
                    };
                    return usize::try_from(fileoff).ok();
                }
            }
        }
        None
    }

    /// Translate a relative virtual address (offset from image base) to a
    /// file offset. The image base is taken from the first `__TEXT` segment
    /// (or the first segment if no `__TEXT` exists).
    pub fn rva_to_offset(&self, rva: u64) -> Option<usize> {
        let base = self.image_base();
        self.va_to_offset(base + rva)
    }

    /// Return the image base address (vmaddr of the first __TEXT segment, or
    /// the first segment).
    pub fn image_base(&self) -> u64 {
        self.segments
            .iter()
            .find(|s| s.name == "__TEXT")
            .or_else(|| self.segments.first())
            .map(|s| s.vmaddr)
            .unwrap_or(0)
    }

    /// Look up a symbol by name and return its file offset.
    pub fn symbol_offset(&self, name: &str) -> Option<usize> {
        let entry = self.symbols.by_name(name)?;
        self.va_to_offset(entry.address)
    }

    fn va_range_to_offset(&self, va: u64, len: usize) -> Option<usize> {
        let len = u64::try_from(len).ok()?;

        for seg in &self.segments {
            let Some(seg_end) = seg.vmaddr.checked_add(seg.vmsize) else {
                continue;
            };
            if va < seg.vmaddr || va >= seg_end {
                continue;
            }

            let delta = va - seg.vmaddr;
            let range_end = delta.checked_add(len)?;
            if range_end > seg.filesize {
                return None;
            }

            let fileoff = seg.fileoff.checked_add(delta)?;
            return usize::try_from(fileoff).ok();
        }

        None
    }

    // -- Executable hook planning ------------------------------------------

    /// Encode a jump suitable for function-entry patching.
    ///
    /// Supported encodings:
    /// - `x86_64`: prefers a 5-byte `jmp rel32`; falls back to a 14-byte
    ///   RIP-indirect absolute jump (`jmp qword ptr [rip + 0]; .quad target`)
    ///   when the target is out of `rel32` range.
    /// - `arm64` / `arm64e`: prefers a 4-byte `b <imm26>` when the target is
    ///   within +/-128 MiB; falls back to a 16-byte literal veneer
    ///   (`ldr x16, #8; br x16; .quad target`) otherwise.
    ///
    /// Failure modes:
    /// - `i386` is rejected as unsupported.
    /// - `arm64` / `arm64e` require both `source_va` and `destination_va` to be
    ///   4-byte aligned.
    /// - The arm64 direct branch form is rejected when the delta is not a
    ///   multiple of 4 or exceeds the signed `imm26` range, in which case the
    ///   absolute literal veneer is used instead.
    /// - `arm64e` uses the same bytes as `arm64`; callers must supply raw code
    ///   virtual addresses, not PAC-signed function pointers.
    pub fn encode_hook_jump(
        arch: PatchArch,
        source_va: u64,
        destination_va: u64,
    ) -> Result<HookJump, String> {
        ensure_hook_arch_supported(arch)?;

        match arch {
            PatchArch::X86_64 => encode_x86_64_hook_jump(source_va, destination_va),
            PatchArch::Arm64 | PatchArch::Arm64e => {
                encode_arm64_hook_jump(arch, source_va, destination_va)
            }
            PatchArch::I386 => {
                Err("executable hook patching is not supported for i386".to_string())
            }
        }
    }

    /// Validate bytes intended to be moved into a trampoline buffer.
    ///
    /// Support differences:
    /// - `x86_64`: a conservative decoder rejects relative control-flow,
    ///   RIP-relative addressing, and unsupported complex instructions because
    ///   the trampoline copies bytes verbatim and performs no relocation fixups.
    /// - `arm64` / `arm64e`: bytes must be a whole-number sequence of 4-byte
    ///   instructions and are rejected when they contain common PC-relative or
    ///   control-flow instructions that would need relocation rewriting.
    ///
    /// Failure modes:
    /// - unsupported architectures are rejected.
    /// - `arm64` / `arm64e` reject byte lengths that are not multiples of 4.
    /// - `arm64` / `arm64e` reject instructions such as `b`, `bl`, `b.cond`,
    ///   `cbz/cbnz`, `tbz/tbnz`, `adr`, `adrp`, literal loads, and
    ///   register-based or authenticated branch instructions.
    pub fn validate_trampoline_instructions(arch: PatchArch, bytes: &[u8]) -> Result<(), String> {
        ensure_hook_arch_supported(arch)?;

        match arch {
            PatchArch::X86_64 => validate_x86_64_trampoline_bytes(bytes),
            PatchArch::Arm64 | PatchArch::Arm64e => validate_arm64_trampoline_bytes(arch, bytes),
            PatchArch::I386 => {
                Err("executable hook patching is not supported for i386".to_string())
            }
        }
    }

    /// Build a trampoline buffer that replays `relocated_bytes` and jumps to
    /// `resume_va`.
    ///
    /// This emits bytes only; it does not allocate storage or write them into
    /// any image. Callers are responsible for choosing a trampoline location
    /// and mapping it through the appropriate image patcher.
    pub fn build_trampoline(
        arch: PatchArch,
        trampoline_va: u64,
        relocated_bytes: &[u8],
        resume_va: u64,
    ) -> Result<TrampolinePlan, String> {
        ensure_hook_arch_supported(arch)?;
        validate_patch_alignment(arch, trampoline_va, relocated_bytes.len())?;
        Self::validate_trampoline_instructions(arch, relocated_bytes)?;

        let jump_source_va = trampoline_va
            .checked_add(relocated_bytes.len() as u64)
            .ok_or_else(|| format!("trampoline at {trampoline_va:#x} overflows address space"))?;
        let jump_back = Self::encode_hook_jump(arch, jump_source_va, resume_va)?;

        let mut bytes = Vec::with_capacity(relocated_bytes.len() + jump_back.len());
        bytes.extend_from_slice(relocated_bytes);
        bytes.extend_from_slice(&jump_back.bytes);

        Ok(TrampolinePlan {
            arch,
            trampoline_va,
            relocated_bytes: relocated_bytes.to_vec(),
            resume_va,
            jump_back,
            bytes,
        })
    }

    /// Return a conservative upper bound for a relocated trampoline buffer.
    ///
    /// This is primarily useful for live-image hook installers that need to
    /// reserve executable memory before the relocated trampoline bytes are
    /// materialized.
    pub fn estimate_relocated_trampoline_capacity(arch: PatchArch, original_len: usize) -> usize {
        match arch {
            PatchArch::X86_64 => original_len.saturating_mul(4).saturating_add(32),
            PatchArch::Arm64 | PatchArch::Arm64e => {
                (original_len / 4).saturating_mul(20).saturating_add(16)
            }
            PatchArch::I386 => 0,
        }
    }

    /// Relocate stolen instructions so they can execute from `trampoline_va`.
    ///
    /// Unlike [`Self::validate_trampoline_instructions`], this performs
    /// architecture-specific instruction rewriting for common PC-relative
    /// encodings used in function prologues.
    pub fn relocate_stolen_bytes(
        arch: PatchArch,
        source_va: u64,
        trampoline_va: u64,
        bytes: &[u8],
    ) -> Result<Vec<u8>, String> {
        ensure_hook_arch_supported(arch)?;

        match arch {
            PatchArch::X86_64 => relocate_x86_64_stolen_bytes(source_va, trampoline_va, bytes),
            PatchArch::Arm64 | PatchArch::Arm64e => {
                relocate_arm64_stolen_bytes(arch, source_va, trampoline_va, bytes)
            }
            PatchArch::I386 => {
                Err("executable hook patching is not supported for i386".to_string())
            }
        }
    }

    /// Build a trampoline from original stolen bytes, relocating them from the
    /// function entry at `source_va` into the trampoline at `trampoline_va`.
    pub fn build_relocated_trampoline(
        arch: PatchArch,
        source_va: u64,
        trampoline_va: u64,
        original_bytes: &[u8],
        resume_va: u64,
    ) -> Result<TrampolinePlan, String> {
        let relocated_bytes =
            Self::relocate_stolen_bytes(arch, source_va, trampoline_va, original_bytes)?;
        ensure_hook_arch_supported(arch)?;
        validate_patch_alignment(arch, trampoline_va, original_bytes.len())?;

        let jump_source_va = trampoline_va
            .checked_add(relocated_bytes.len() as u64)
            .ok_or_else(|| format!("trampoline at {trampoline_va:#x} overflows address space"))?;
        let jump_back = Self::encode_hook_jump(arch, jump_source_va, resume_va)?;

        let mut bytes = Vec::with_capacity(relocated_bytes.len() + jump_back.len());
        bytes.extend_from_slice(&relocated_bytes);
        bytes.extend_from_slice(&jump_back.bytes);

        Ok(TrampolinePlan {
            arch,
            trampoline_va,
            relocated_bytes,
            resume_va,
            jump_back,
            bytes,
        })
    }

    /// Plan a function-entry patch that overwrites `overwrite_len` bytes at
    /// `entry_va` with a branch to `destination_va`, padding any remainder with
    /// architecture-appropriate NOPs.
    ///
    /// Failure modes:
    /// - `entry_va` must map into this image and the full overwrite window must
    ///   be readable.
    /// - `overwrite_len` must be large enough for the selected jump encoding.
    /// - `arm64` / `arm64e` require `entry_va` and `overwrite_len` to be 4-byte
    ///   aligned.
    pub fn plan_function_entry_patch(
        &self,
        arch: PatchArch,
        entry_va: u64,
        destination_va: u64,
        overwrite_len: usize,
    ) -> Result<FunctionEntryPatchPlan, String> {
        ensure_hook_arch_supported(arch)?;
        if overwrite_len == 0 {
            return Err(
                "function-entry hook planning requires a non-zero patch length".to_string(),
            );
        }
        validate_patch_alignment(arch, entry_va, overwrite_len)?;

        let entry_offset = self.va_range_to_offset(entry_va, overwrite_len).ok_or_else(|| {
            format!(
                "function entry patch window [{:#x}, {:#x}) is not fully mappable in this image",
                entry_va,
                entry_va.saturating_add(overwrite_len as u64),
            )
        })?;
        let original_bytes = self
            .read_bytes(entry_offset, overwrite_len)
            .ok_or_else(|| {
                format!(
                    "cannot read {overwrite_len} bytes for function entry patch at {entry_va:#x}"
                )
            })?
            .to_vec();

        let jump = Self::encode_hook_jump(arch, entry_va, destination_va)?;
        if overwrite_len < jump.len() {
            return Err(format!(
                "function entry patch at {entry_va:#x} needs {} bytes for {:?}, but overwrite_len is {}",
                jump.len(),
                jump.encoding,
                overwrite_len,
            ));
        }

        let mut patch_bytes = Vec::with_capacity(overwrite_len);
        patch_bytes.extend_from_slice(&jump.bytes);
        let padding_len = overwrite_len - jump.len();
        if padding_len > 0 {
            patch_bytes.extend_from_slice(&nop_bytes_for_arch(arch, padding_len)?);
        }

        Ok(FunctionEntryPatchPlan {
            arch,
            entry_va,
            entry_offset,
            destination_va,
            overwrite_len,
            original_bytes,
            jump,
            patch_bytes,
        })
    }

    /// Plan a complete function-entry hook: an entry detour to `hook_va` plus
    /// a trampoline at `trampoline_va` containing the stolen bytes and a jump
    /// back to the original function body.
    ///
    /// This is intended for local integration in `apply.rs`: the returned plan
    /// is pure data, so callers can decide whether and where to materialize the
    /// trampoline bytes.
    pub fn plan_function_entry_hook(
        &self,
        arch: PatchArch,
        entry_va: u64,
        hook_va: u64,
        trampoline_va: u64,
        overwrite_len: usize,
    ) -> Result<FunctionEntryHookPlan, String> {
        let entry = self.plan_function_entry_patch(arch, entry_va, hook_va, overwrite_len)?;
        let trampoline = Self::build_relocated_trampoline(
            arch,
            entry.entry_va,
            trampoline_va,
            &entry.original_bytes,
            entry.resume_va(),
        )?;

        Ok(FunctionEntryHookPlan { entry, trampoline })
    }

    // -- Read / Write -------------------------------------------------------

    /// Read a byte slice from the buffer.
    pub fn read_bytes(&self, offset: usize, len: usize) -> Option<&[u8]> {
        let end = offset.checked_add(len)?;
        if end <= self.data.len() {
            Some(&self.data[offset..end])
        } else {
            None
        }
    }

    /// Write bytes at `offset`, returning the original bytes that were
    /// overwritten. Returns an error if the write would exceed the buffer.
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<Vec<u8>, String> {
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            format!(
                "write at offset {:#x} with length {} overflows the address space",
                offset,
                bytes.len(),
            )
        })?;
        if end > self.data.len() {
            return Err(format!(
                "write at offset {:#x} with length {} exceeds image size {}",
                offset,
                bytes.len(),
                self.data.len(),
            ));
        }

        let original = self.data[offset..end].to_vec();
        self.data[offset..end].copy_from_slice(bytes);
        Ok(original)
    }

    /// Write a single byte at `offset`, returning the original byte.
    pub fn write_byte(&mut self, offset: usize, byte: u8) -> Result<u8, String> {
        if offset >= self.data.len() {
            return Err(format!(
                "write at offset {:#x} exceeds image size {}",
                offset,
                self.data.len(),
            ));
        }
        let original = self.data[offset];
        self.data[offset] = byte;
        Ok(original)
    }

    // -- Pattern search -----------------------------------------------------

    /// Find all offsets where `pattern` matches, with `mask` applied.
    ///
    /// For each candidate offset in `scope`, the match succeeds when for every
    /// byte index `i`: `(data[off+i] & mask[i]) == (pattern[i] & mask[i])`.
    ///
    /// `pattern` and `mask` must be the same length. A mask byte of `0xFF`
    /// means exact match; `0x00` means wildcard (match any).
    pub fn find_bytes(&self, pattern: &[u8], mask: &[u8], scope: Range<usize>) -> Vec<usize> {
        assert_eq!(
            pattern.len(),
            mask.len(),
            "pattern and mask must have the same length"
        );

        let pat_len = pattern.len();
        if pat_len == 0 || scope.start + pat_len > self.data.len() {
            return Vec::new();
        }

        let end = scope.end.min(self.data.len());
        if scope.start + pat_len > end {
            return Vec::new();
        }

        let mut results = Vec::new();
        let search_end = end - pat_len + 1;

        for off in scope.start..search_end {
            let mut matched = true;
            for i in 0..pat_len {
                if (self.data[off + i] & mask[i]) != (pattern[i] & mask[i]) {
                    matched = false;
                    break;
                }
            }
            if matched {
                results.push(off);
            }
        }

        results
    }

    /// Search for exact byte sequences (no mask, all bytes must match).
    pub fn find_exact(&self, needle: &[u8], scope: Range<usize>) -> Vec<usize> {
        let mask = vec![0xFF; needle.len()];
        self.find_bytes(needle, &mask, scope)
    }

    /// Find null-terminated C strings matching `needle` in the binary.
    ///
    /// Returns a vec of `(offset, allocated_size)` tuples. The allocated size
    /// is the number of bytes from the start of the string to the next null
    /// byte (inclusive). This is useful for in-place string replacement with
    /// null padding.
    pub fn find_cstring(&self, needle: &str) -> Vec<(usize, usize)> {
        let needle_bytes = needle.as_bytes();
        if needle_bytes.is_empty() {
            return Vec::new();
        }

        let mut results = Vec::new();
        let data = &self.data;
        let data_len = data.len();

        // Search for the needle bytes followed by a null terminator.
        let mut pos = 0;
        while pos + needle_bytes.len() < data_len {
            if let Some(found) = find_subsequence(&data[pos..], needle_bytes) {
                let abs_offset = pos + found;
                // Verify null terminator follows.
                let after = abs_offset + needle_bytes.len();
                if after < data_len && data[after] == 0 {
                    // Measure the full allocation: scan forward from the start
                    // to find contiguous null bytes (the padded region).
                    let mut end = after + 1;
                    while end < data_len && data[end] == 0 {
                        end += 1;
                    }
                    let alloc_size = end - abs_offset;
                    results.push((abs_offset, alloc_size));
                }
                pos = abs_offset + 1;
            } else {
                break;
            }
        }

        results
    }

    /// Find null-terminated C strings within a specific file region.
    ///
    /// This scopes the search to a byte range (e.g., from a `StringRegion`),
    /// avoiding matches in code or unrelated data sections.
    ///
    /// Returns `(offset, allocated_size)` tuples, same as `find_cstring`.
    pub fn find_cstring_in_region(
        &self,
        needle: &str,
        region_offset: usize,
        region_size: usize,
    ) -> Vec<(usize, usize)> {
        let needle_bytes = needle.as_bytes();
        if needle_bytes.is_empty() || region_size == 0 {
            return Vec::new();
        }

        let data = &self.data;
        let region_end = region_offset.saturating_add(region_size).min(data.len());
        let mut results = Vec::new();
        let mut pos = region_offset;

        while pos + needle_bytes.len() < region_end {
            if let Some(found) = find_subsequence(&data[pos..region_end], needle_bytes) {
                let abs_offset = pos + found;
                let after = abs_offset + needle_bytes.len();
                if after < data.len() && data[after] == 0 {
                    let mut end = after + 1;
                    while end < data.len() && data[end] == 0 {
                        end += 1;
                    }
                    let alloc_size = end - abs_offset;
                    results.push((abs_offset, alloc_size));
                }
                pos = abs_offset + 1;
            } else {
                break;
            }
        }

        results
    }

    // -- NOP fill -----------------------------------------------------------

    /// Fill `count` bytes at `offset` with NOP instructions.
    ///
    /// For arm64, uses the 4-byte NOP encoding `0xD503201F`. For x86_64,
    /// uses single-byte `0x90` NOPs.
    pub fn nop_fill(
        &mut self,
        offset: usize,
        count: usize,
        arm64: bool,
    ) -> Result<Vec<u8>, String> {
        if arm64 {
            self.write_bytes(offset, &nop_bytes_for_arch(PatchArch::Arm64, count)?)
        } else {
            self.write_bytes(offset, &nop_bytes_for_arch(PatchArch::X86_64, count)?)
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the first occurrence of `needle` in `haystack`.
fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

pub fn vtable_mangled_prefix(type_name: &str) -> String {
    format!("__ZTV{}{}", type_name.len(), type_name)
}

pub fn nop_bytes_for_arch(arch: PatchArch, count: usize) -> Result<Vec<u8>, String> {
    match arch {
        PatchArch::X86_64 => Ok(vec![0x90; count]),
        PatchArch::Arm64 | PatchArch::Arm64e => {
            if count % 4 != 0 {
                return Err(format!(
                    "{arch} NOP padding requires a count divisible by 4, got {count}"
                ));
            }
            let mut bytes = Vec::with_capacity(count);
            for _ in 0..(count / 4) {
                bytes.extend_from_slice(&ARM64_NOP);
            }
            Ok(bytes)
        }
        PatchArch::I386 => Err("NOP padding is not supported for i386 hook patches".to_string()),
    }
}

fn ensure_hook_arch_supported(arch: PatchArch) -> Result<(), String> {
    match arch {
        PatchArch::X86_64 | PatchArch::Arm64 | PatchArch::Arm64e => Ok(()),
        PatchArch::I386 => Err("executable hook patching is not supported for i386".to_string()),
    }
}

fn validate_patch_alignment(arch: PatchArch, address: u64, len: usize) -> Result<(), String> {
    match arch {
        PatchArch::X86_64 => Ok(()),
        PatchArch::Arm64 | PatchArch::Arm64e => {
            if address % 4 != 0 {
                return Err(format!(
                    "{arch} function-entry patch address must be 4-byte aligned, got {address:#x}"
                ));
            }
            if len % 4 != 0 {
                return Err(format!(
                    "{arch} function-entry patch length must be divisible by 4, got {len}"
                ));
            }
            Ok(())
        }
        PatchArch::I386 => Err("executable hook patching is not supported for i386".to_string()),
    }
}

fn encode_x86_64_hook_jump(source_va: u64, destination_va: u64) -> Result<HookJump, String> {
    let relative_delta = i128::from(destination_va)
        - i128::from(
            source_va
                .checked_add(X86_64_REL32_JUMP_LEN as u64)
                .ok_or_else(|| format!("x86_64 jump source {source_va:#x} overflows"))?,
        );

    if (i32::MIN as i128..=i32::MAX as i128).contains(&relative_delta) {
        let displacement = i32::try_from(relative_delta).map_err(|_| {
            format!(
                "x86_64 relative jump delta out of range: source={source_va:#x} destination={destination_va:#x}"
            )
        })?;
        let mut bytes = Vec::with_capacity(X86_64_REL32_JUMP_LEN);
        bytes.push(0xE9);
        bytes.extend_from_slice(&displacement.to_le_bytes());
        return Ok(HookJump {
            arch: PatchArch::X86_64,
            source_va,
            destination_va,
            encoding: HookJumpEncoding::X86_64Relative,
            bytes,
        });
    }

    let mut bytes = Vec::with_capacity(X86_64_ABSOLUTE_JUMP_LEN);
    bytes.extend_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
    bytes.extend_from_slice(&destination_va.to_le_bytes());

    Ok(HookJump {
        arch: PatchArch::X86_64,
        source_va,
        destination_va,
        encoding: HookJumpEncoding::X86_64Absolute,
        bytes,
    })
}

fn encode_arm64_hook_jump(
    arch: PatchArch,
    source_va: u64,
    destination_va: u64,
) -> Result<HookJump, String> {
    if source_va % 4 != 0 {
        return Err(format!(
            "{arch} jump source must be 4-byte aligned, got {source_va:#x}"
        ));
    }
    if destination_va % 4 != 0 {
        return Err(format!(
            "{arch} jump destination must be 4-byte aligned, got {destination_va:#x}"
        ));
    }

    let delta = i128::from(destination_va) - i128::from(source_va);
    if delta % 4 == 0 {
        let scaled = delta / 4;
        if (-(1_i128 << 25)..=(1_i128 << 25) - 1).contains(&scaled) {
            let imm26 = (i32::try_from(scaled)
                .map_err(|_| "arm64 jump delta out of range".to_string())?
                as u32)
                & 0x03FF_FFFF;
            let insn = 0x1400_0000u32 | imm26;
            return Ok(HookJump {
                arch,
                source_va,
                destination_va,
                encoding: HookJumpEncoding::Arm64BranchImmediate,
                bytes: insn.to_le_bytes().to_vec(),
            });
        }
    }

    let mut bytes = Vec::with_capacity(ARM64_ABSOLUTE_JUMP_LEN);
    bytes.extend_from_slice(&ARM64_LDR_X16_LITERAL_8);
    bytes.extend_from_slice(&ARM64_BR_X16);
    bytes.extend_from_slice(&destination_va.to_le_bytes());

    Ok(HookJump {
        arch,
        source_va,
        destination_va,
        encoding: HookJumpEncoding::Arm64AbsoluteLiteral,
        bytes,
    })
}

fn relocate_x86_64_stolen_bytes(
    source_va: u64,
    trampoline_va: u64,
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    let mut src_off = 0usize;
    let mut relocated = Vec::with_capacity(bytes.len() + 16);
    while src_off < bytes.len() {
        let insn = &bytes[src_off..];
        let src_insn_va = source_va + src_off as u64;
        let dst_insn_va = trampoline_va + relocated.len() as u64;
        let rewritten =
            relocate_x86_64_instruction(insn, src_insn_va, dst_insn_va).map_err(|reason| {
                format!(
                    "x86_64 trampoline relocation rejected instruction at byte offset {:#x}: {}",
                    src_off, reason
                )
            })?;
        let len = x86_64_instruction_len(insn, src_insn_va)
            .map_err(|reason| {
                format!(
                    "x86_64 trampoline relocation rejected instruction at byte offset {:#x}: {}",
                    src_off, reason
                )
            })?
            .0;
        src_off += len;
        relocated.extend_from_slice(&rewritten);
    }
    Ok(relocated)
}

fn relocate_x86_64_instruction(
    bytes: &[u8],
    src_va: u64,
    dst_va: u64,
) -> Result<Vec<u8>, &'static str> {
    let mut idx = 0usize;
    let mut rex_w = false;
    let mut address_override = false;
    while let Some(&byte) = bytes.get(idx) {
        match byte {
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 => {
                idx += 1;
            }
            0x67 => {
                address_override = true;
                idx += 1;
            }
            0x40..=0x4F => {
                rex_w |= byte & 0x08 != 0;
                idx += 1;
            }
            _ => break,
        }
    }
    if address_override {
        return Err("address-size override is not supported");
    }

    let opcode_offset = idx;
    let opcode = *bytes.get(idx).ok_or("truncated instruction")?;
    idx += 1;

    match opcode {
        0xE8 => {
            let end = checked_advance(idx, 4, bytes)?;
            let disp = i32::from_le_bytes(
                bytes[idx..end]
                    .try_into()
                    .map_err(|_| "truncated instruction")?,
            );
            let target = add_signed_u64(src_va + end as u64, disp as i64)?;
            let new_disp = rel32(target, dst_va + end as u64)?;
            let mut out = bytes[..opcode_offset].to_vec();
            out.push(0xE8);
            out.extend_from_slice(&new_disp.to_le_bytes());
            return Ok(out);
        }
        0xE9 => {
            let end = checked_advance(idx, 4, bytes)?;
            let disp = i32::from_le_bytes(
                bytes[idx..end]
                    .try_into()
                    .map_err(|_| "truncated instruction")?,
            );
            let target = add_signed_u64(src_va + end as u64, disp as i64)?;
            return Ok(
                MachoPatcher::encode_hook_jump(PatchArch::X86_64, dst_va, target)
                    .map_err(|_| "relative jump encoding failed")?
                    .bytes,
            );
        }
        0xEB => {
            let end = checked_advance(idx, 1, bytes)?;
            let disp = bytes[idx] as i8;
            let target = add_signed_u64(src_va + end as u64, disp as i64)?;
            return Ok(
                MachoPatcher::encode_hook_jump(PatchArch::X86_64, dst_va, target)
                    .map_err(|_| "relative jump encoding failed")?
                    .bytes,
            );
        }
        0x70..=0x7F => {
            let end = checked_advance(idx, 1, bytes)?;
            let disp = bytes[idx] as i8;
            let target = add_signed_u64(src_va + end as u64, disp as i64)?;
            let cc = opcode & 0x0F;
            let new_disp = rel32(target, dst_va + bytes[..opcode_offset].len() as u64 + 6)?;
            let mut out = bytes[..opcode_offset].to_vec();
            out.push(0x0F);
            out.push(0x80 | cc);
            out.extend_from_slice(&new_disp.to_le_bytes());
            return Ok(out);
        }
        0x0F => {
            let second = *bytes.get(idx).ok_or("truncated two-byte opcode")?;
            idx += 1;
            if (0x80..=0x8F).contains(&second) {
                let end = checked_advance(idx, 4, bytes)?;
                let disp = i32::from_le_bytes(
                    bytes[idx..end]
                        .try_into()
                        .map_err(|_| "truncated instruction")?,
                );
                let target = add_signed_u64(src_va + end as u64, disp as i64)?;
                let new_disp = rel32(target, dst_va + bytes[..opcode_offset].len() as u64 + 6)?;
                let mut out = bytes[..opcode_offset].to_vec();
                out.push(0x0F);
                out.push(second);
                out.extend_from_slice(&new_disp.to_le_bytes());
                return Ok(out);
            }
        }
        0xE0..=0xE3 => return Err("loop branch"),
        _ => {}
    }

    let len = x86_64_instruction_len(bytes, src_va)?.0;
    let mut out = bytes[..len].to_vec();
    if let Some((disp_offset, disp_len)) = find_x86_64_rip_relative_disp(bytes)? {
        if disp_len != 4 {
            return Err("unexpected RIP-relative displacement size");
        }
        let end = disp_offset + disp_len;
        let disp = i32::from_le_bytes(
            out[disp_offset..end]
                .try_into()
                .map_err(|_| "truncated instruction")?,
        );
        let target = add_signed_u64(src_va + len as u64, disp as i64)?;
        let new_disp = rel32(target, dst_va + len as u64)?;
        out[disp_offset..end].copy_from_slice(&new_disp.to_le_bytes());
    } else if opcode == 0xB8 && rex_w {
    }
    Ok(out)
}

fn find_x86_64_rip_relative_disp(bytes: &[u8]) -> Result<Option<(usize, usize)>, &'static str> {
    let mut idx = 0usize;
    while let Some(&byte) = bytes.get(idx) {
        match byte {
            0xF0
            | 0xF2
            | 0xF3
            | 0x2E
            | 0x36
            | 0x3E
            | 0x26
            | 0x64
            | 0x65
            | 0x66
            | 0x67
            | 0x40..=0x4F => idx += 1,
            _ => break,
        }
    }
    let opcode = *bytes.get(idx).ok_or("truncated instruction")?;
    idx += 1;
    if opcode == 0x0F {
        let second = *bytes.get(idx).ok_or("truncated two-byte opcode")?;
        idx += 1;
        match second {
            0x1F | 0xAF | 0xB6 | 0xB7 | 0xBE | 0xBF => {}
            _ => return Ok(None),
        }
    }
    let modrm_offset = idx;
    let modrm = *bytes.get(modrm_offset).ok_or("truncated ModRM")?;
    let mode = modrm >> 6;
    let rm = modrm & 0x07;
    idx += 1;
    if mode == 0b11 {
        return Ok(None);
    }
    if rm == 0b100 {
        let sib = *bytes.get(idx).ok_or("truncated SIB")?;
        idx += 1;
        let base = sib & 0x07;
        if mode == 0b00 && base == 0b101 {
            return Ok(Some((idx, 4)));
        }
    }
    if mode == 0b00 && rm == 0b101 {
        return Ok(Some((idx, 4)));
    }
    Ok(None)
}

fn relocate_arm64_stolen_bytes(
    arch: PatchArch,
    source_va: u64,
    trampoline_va: u64,
    bytes: &[u8],
) -> Result<Vec<u8>, String> {
    if bytes.len() % 4 != 0 {
        return Err(format!(
            "{arch} trampoline bytes must be a whole number of instructions, got {} bytes",
            bytes.len()
        ));
    }
    let mut relocated = Vec::with_capacity(bytes.len() + 32);
    for (index, chunk) in bytes.chunks_exact(4).enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(chunk);
        let insn = u32::from_le_bytes(buf);
        let src_insn_va = source_va + (index * 4) as u64;
        let dst_insn_va = trampoline_va + relocated.len() as u64;
        let rewritten = relocate_arm64_instruction(insn, src_insn_va, dst_insn_va).map_err(
            |reason| {
                format!(
                    "{arch} trampoline relocation rejected instruction at byte offset {:#x}: {} ({:#010x})",
                    index * 4,
                    reason,
                    insn
                )
            },
        )?;
        relocated.extend_from_slice(&rewritten);
    }
    Ok(relocated)
}

fn relocate_arm64_instruction(
    insn: u32,
    src_va: u64,
    dst_va: u64,
) -> Result<Vec<u8>, &'static str> {
    if insn & 0x7C00_0000 == 0x1400_0000 {
        let target = add_signed_u64(src_va, sign_extend(((insn & 0x03FF_FFFF) as u64) << 2, 28))?;
        let link = (insn & 0x8000_0000) != 0;
        if let Some(encoded) = encode_arm64_branch_immediate(link, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_absolute_jump_sequence(target, link));
    }
    if insn & 0xFF00_0010 == 0x5400_0000 {
        let cond = (insn & 0xF) as u8;
        let imm = ((insn >> 5) & 0x7FFFF) as u64;
        let target = add_signed_u64(src_va, sign_extend(imm << 2, 21))?;
        if let Some(encoded) = encode_arm64_cond_branch(cond, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_conditional_absolute_jump_sequence(
            cond, dst_va, target,
        ));
    }
    if insn & 0x7E00_0000 == 0x3400_0000 {
        let imm = ((insn >> 5) & 0x7FFFF) as u64;
        let target = add_signed_u64(src_va, sign_extend(imm << 2, 21))?;
        if let Some(encoded) = encode_arm64_cbz(insn, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_cbz_absolute_jump_sequence(insn, dst_va, target));
    }
    if insn & 0x7E00_0000 == 0x3600_0000 {
        let imm = ((insn >> 5) & 0x3FFF) as u64;
        let target = add_signed_u64(src_va, sign_extend(imm << 2, 16))?;
        if let Some(encoded) = encode_arm64_tbz(insn, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_tbz_absolute_jump_sequence(insn, dst_va, target));
    }
    if insn & 0x9F00_0000 == 0x1000_0000 {
        let target = decode_adr_target(insn, src_va);
        if let Some(encoded) = encode_adr(insn, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_load_address_sequence(insn & 0x1F, target));
    }
    if insn & 0x9F00_0000 == 0x9000_0000 {
        let target = decode_adrp_target(insn, src_va);
        if let Some(encoded) = encode_adrp(insn, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_load_address_sequence(insn & 0x1F, target));
    }
    if let Some(target) = decode_arm64_integer_ldr_literal_target(insn, src_va) {
        if let Some(encoded) = encode_arm64_integer_ldr_literal(insn, dst_va, target) {
            return Ok(encoded.to_le_bytes().to_vec());
        }
        return Ok(arm64_integer_literal_load_sequence(insn, target));
    }
    if insn & 0xFE00_0000 == 0xD600_0000 || insn & 0xFE00_0000 == 0xD700_0000 {
        return Err("register or authenticated branch");
    }
    Ok(insn.to_le_bytes().to_vec())
}

fn add_signed_u64(base: u64, delta: i64) -> Result<u64, &'static str> {
    base.checked_add_signed(delta).ok_or("address overflow")
}

fn rel32(target: u64, next_ip: u64) -> Result<i32, &'static str> {
    let delta = i128::from(target) - i128::from(next_ip);
    if !(i32::MIN as i128..=i32::MAX as i128).contains(&delta) {
        return Err("relative target out of range");
    }
    Ok(delta as i32)
}

fn sign_extend(value: u64, bits: u8) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

fn encode_arm64_branch_immediate(link: bool, source_va: u64, target_va: u64) -> Option<u32> {
    let delta = i128::from(target_va) - i128::from(source_va);
    if delta % 4 != 0 {
        return None;
    }
    let scaled = delta / 4;
    if !((-(1_i128 << 25))..=((1_i128 << 25) - 1)).contains(&scaled) {
        return None;
    }
    let base = if link { 0x9400_0000 } else { 0x1400_0000 };
    Some(base | ((scaled as i32 as u32) & 0x03FF_FFFF))
}

fn encode_arm64_cond_branch(cond: u8, source_va: u64, target_va: u64) -> Option<u32> {
    let delta = i128::from(target_va) - i128::from(source_va);
    if delta % 4 != 0 {
        return None;
    }
    let scaled = delta / 4;
    if !((-(1_i128 << 18))..=((1_i128 << 18) - 1)).contains(&scaled) {
        return None;
    }
    Some(0x5400_0000 | (((scaled as i32 as u32) & 0x7FFFF) << 5) | (cond as u32))
}

fn encode_arm64_cbz(insn: u32, source_va: u64, target_va: u64) -> Option<u32> {
    let delta = i128::from(target_va) - i128::from(source_va);
    if delta % 4 != 0 {
        return None;
    }
    let scaled = delta / 4;
    if !((-(1_i128 << 18))..=((1_i128 << 18) - 1)).contains(&scaled) {
        return None;
    }
    Some((insn & !0x00FF_FFE0) | (((scaled as i32 as u32) & 0x7FFFF) << 5))
}

fn encode_arm64_tbz(insn: u32, source_va: u64, target_va: u64) -> Option<u32> {
    let delta = i128::from(target_va) - i128::from(source_va);
    if delta % 4 != 0 {
        return None;
    }
    let scaled = delta / 4;
    if !((-(1_i128 << 13))..=((1_i128 << 13) - 1)).contains(&scaled) {
        return None;
    }
    Some((insn & !0x0007_FFE0) | (((scaled as i32 as u32) & 0x3FFF) << 5))
}

fn decode_adr_target(insn: u32, source_va: u64) -> u64 {
    let immlo = ((insn >> 29) & 0x3) as u64;
    let immhi = ((insn >> 5) & 0x7FFFF) as u64;
    let imm = (immhi << 2) | immlo;
    source_va.wrapping_add_signed(sign_extend(imm, 21))
}

fn decode_adrp_target(insn: u32, source_va: u64) -> u64 {
    let immlo = ((insn >> 29) & 0x3) as u64;
    let immhi = ((insn >> 5) & 0x7FFFF) as u64;
    let imm = (immhi << 2) | immlo;
    (source_va & !0xFFF).wrapping_add_signed(sign_extend(imm, 21) << 12)
}

fn encode_adr(insn: u32, source_va: u64, target_va: u64) -> Option<u32> {
    let delta = i128::from(target_va) - i128::from(source_va);
    if !((-(1_i128 << 20))..=((1_i128 << 20) - 1)).contains(&delta) {
        return None;
    }
    let imm = delta as i64 as u64;
    let immlo = (imm & 0x3) as u32;
    let immhi = ((imm >> 2) & 0x7FFFF) as u32;
    Some((insn & !0x60FF_FFE0) | (immlo << 29) | (immhi << 5))
}

fn encode_adrp(insn: u32, source_va: u64, target_va: u64) -> Option<u32> {
    let src_page = source_va & !0xFFF;
    let target_page = target_va & !0xFFF;
    let delta = (i128::from(target_page) - i128::from(src_page)) >> 12;
    if !((-(1_i128 << 20))..=((1_i128 << 20) - 1)).contains(&delta) {
        return None;
    }
    let imm = delta as i64 as u64;
    let immlo = (imm & 0x3) as u32;
    let immhi = ((imm >> 2) & 0x7FFFF) as u32;
    Some((insn & !0x60FF_FFE0) | (immlo << 29) | (immhi << 5))
}

fn decode_arm64_integer_ldr_literal_target(insn: u32, source_va: u64) -> Option<u64> {
    let top = insn & 0xFF00_0000;
    if top != 0x1800_0000 && top != 0x5800_0000 {
        return None;
    }
    let imm = ((insn >> 5) & 0x7FFFF) as u64;
    Some(source_va.wrapping_add_signed(sign_extend(imm << 2, 21)))
}

fn encode_arm64_integer_ldr_literal(insn: u32, source_va: u64, target_va: u64) -> Option<u32> {
    let delta = i128::from(target_va) - i128::from(source_va);
    if delta % 4 != 0 {
        return None;
    }
    let scaled = delta / 4;
    if !((-(1_i128 << 18))..=((1_i128 << 18) - 1)).contains(&scaled) {
        return None;
    }
    Some((insn & !0x00FF_FFE0) | (((scaled as i32 as u32) & 0x7FFFF) << 5))
}

fn arm64_absolute_jump_sequence(target_va: u64, link: bool) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&0x5800_0050u32.to_le_bytes());
    bytes.extend_from_slice(&(if link { 0xD63F_0200u32 } else { 0xD61F_0200u32 }).to_le_bytes());
    bytes.extend_from_slice(&target_va.to_le_bytes());
    bytes
}

fn arm64_conditional_absolute_jump_sequence(cond: u8, dst_va: u64, target_va: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    let skip = encode_arm64_cond_branch(cond ^ 1, dst_va, dst_va + 20).expect("local skip encodes");
    bytes.extend_from_slice(&skip.to_le_bytes());
    bytes.extend_from_slice(&arm64_absolute_jump_sequence(target_va, false));
    bytes
}

fn arm64_cbz_absolute_jump_sequence(insn: u32, dst_va: u64, target_va: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    let skip =
        encode_arm64_cbz(insn ^ 0x0100_0000, dst_va, dst_va + 20).expect("local skip encodes");
    bytes.extend_from_slice(&skip.to_le_bytes());
    bytes.extend_from_slice(&arm64_absolute_jump_sequence(target_va, false));
    bytes
}

fn arm64_tbz_absolute_jump_sequence(insn: u32, dst_va: u64, target_va: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(20);
    let skip =
        encode_arm64_tbz(insn ^ 0x0100_0000, dst_va, dst_va + 20).expect("local skip encodes");
    bytes.extend_from_slice(&skip.to_le_bytes());
    bytes.extend_from_slice(&arm64_absolute_jump_sequence(target_va, false));
    bytes
}

fn arm64_load_address_sequence(register: u32, target_va: u64) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(16);
    bytes.extend_from_slice(&(0x5800_0040u32 | register).to_le_bytes());
    bytes.extend_from_slice(&0x1400_0003u32.to_le_bytes());
    bytes.extend_from_slice(&target_va.to_le_bytes());
    bytes
}

fn arm64_integer_literal_load_sequence(insn: u32, target_va: u64) -> Vec<u8> {
    let register = insn & 0x1F;
    let is_64 = (insn & 0x4000_0000) != 0;
    let mut bytes = Vec::with_capacity(20);
    bytes.extend_from_slice(&0x5800_0070u32.to_le_bytes());
    let load_reg = if is_64 {
        0xF940_0000u32 | (16 << 5) | register
    } else {
        0xB940_0000u32 | (16 << 5) | register
    };
    bytes.extend_from_slice(&load_reg.to_le_bytes());
    bytes.extend_from_slice(&0x1400_0002u32.to_le_bytes());
    bytes.extend_from_slice(&target_va.to_le_bytes());
    bytes
}

fn validate_x86_64_trampoline_bytes(bytes: &[u8]) -> Result<(), String> {
    let mut offset = 0;
    while offset < bytes.len() {
        let (len, is_branch, uses_rip_relative) = x86_64_instruction_len(&bytes[offset..], 0)
            .map_err(|reason| {
                format!(
                    "x86_64 trampoline relocation rejected instruction at byte offset {:#x}: {}",
                    offset, reason
                )
            })?;
        if uses_rip_relative {
            return Err(format!(
                "x86_64 trampoline relocation rejected instruction at byte offset {:#x}: RIP-relative addressing",
                offset
            ));
        }
        if is_branch {
            let reason = if bytes
                .get(offset)
                .is_some_and(|opcode| matches!(opcode, 0xE8))
            {
                "relative call"
            } else if bytes
                .get(offset)
                .is_some_and(|opcode| matches!(opcode, 0xE9 | 0xEB))
            {
                "relative jump"
            } else if bytes
                .get(offset)
                .is_some_and(|opcode| matches!(opcode, 0x70..=0x7F | 0xE0..=0xE3))
            {
                "conditional branch"
            } else {
                "control-flow instruction"
            };
            return Err(format!(
                "x86_64 trampoline relocation rejected instruction at byte offset {:#x}: {}",
                offset, reason
            ));
        }
        offset += len;
    }

    Ok(())
}

fn x86_64_instruction_len(
    bytes: &[u8],
    _insn_va: u64,
) -> Result<(usize, bool, bool), &'static str> {
    let mut idx = 0;
    let mut rex_w = false;
    let mut operand_override = false;
    let mut address_size_override = false;

    while let Some(&byte) = bytes.get(idx) {
        match byte {
            0xF0 | 0xF2 | 0xF3 | 0x2E | 0x36 | 0x3E | 0x26 | 0x64 | 0x65 | 0x66 => {
                operand_override |= byte == 0x66;
                idx += 1;
            }
            0x67 => {
                address_size_override = true;
                idx += 1;
            }
            0x40..=0x4F => {
                rex_w |= byte & 0x08 != 0;
                idx += 1;
            }
            _ => break,
        }
    }

    if address_size_override {
        return Err("address-size override is not supported");
    }

    let opcode = *bytes.get(idx).ok_or("truncated instruction")?;
    idx += 1;

    let mut is_branch = false;
    let mut uses_rip_relative = false;

    match opcode {
        0x70..=0x7F => {
            is_branch = true;
            return Ok((
                checked_advance(idx, 1, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xE8 => {
            is_branch = true;
            return Ok((
                checked_advance(idx, 4, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xE9 | 0xEB => {
            is_branch = true;
            let len = if opcode == 0xEB { 1 } else { 4 };
            return Ok((
                checked_advance(idx, len, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xE0..=0xE3 => {
            is_branch = true;
            return Ok((
                checked_advance(idx, 1, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xC2 => {
            return Ok((
                checked_advance(idx, 2, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xC3 | 0xCA | 0xCB | 0x50..=0x5F | 0x90..=0x97 | 0x98..=0x99 | 0x9C..=0x9F => {
            return Ok((idx, is_branch, uses_rip_relative));
        }
        0x68 => {
            return Ok((
                checked_advance(idx, 4, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0x6A => {
            return Ok((
                checked_advance(idx, 1, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xA0..=0xA3 => {
            let len = if address_size_override { 4 } else { 8 };
            return Ok((
                checked_advance(idx, len, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xA8 => {
            return Ok((
                checked_advance(idx, 1, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xA9 => {
            let len = if operand_override { 2 } else { 4 };
            return Ok((
                checked_advance(idx, len, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xB0..=0xB7 => {
            return Ok((
                checked_advance(idx, 1, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0xB8..=0xBF => {
            let imm_len = if rex_w {
                8
            } else if operand_override {
                2
            } else {
                4
            };
            return Ok((
                checked_advance(idx, imm_len, bytes)?,
                is_branch,
                uses_rip_relative,
            ));
        }
        0x0F => {
            let second = *bytes.get(idx).ok_or("truncated two-byte opcode")?;
            idx += 1;

            if (0x80..=0x8F).contains(&second) {
                is_branch = true;
                return Ok((
                    checked_advance(idx, 4, bytes)?,
                    is_branch,
                    uses_rip_relative,
                ));
            }
            if second == 0x1E && bytes.get(idx) == Some(&0xFA) {
                return Ok((idx + 1, is_branch, uses_rip_relative));
            }

            let modrm = match second {
                0x1F | 0xAF | 0xB6 | 0xB7 | 0xBE | 0xBF => parse_x86_64_modrm(bytes, idx)?,
                _ => return Err("unsupported two-byte opcode"),
            };

            uses_rip_relative = modrm.rip_relative;
            return Ok((idx + modrm.len, is_branch, uses_rip_relative));
        }
        _ => {}
    }

    let (modrm_needed, imm_len, group5_control_flow) = match opcode {
        0x01 | 0x03 | 0x09 | 0x0B | 0x11 | 0x13 | 0x19 | 0x1B | 0x21 | 0x23 | 0x29 | 0x2B
        | 0x31 | 0x33 | 0x39 | 0x3B | 0x63 | 0x84 | 0x85 | 0x86 | 0x87 | 0x88 | 0x89 | 0x8A
        | 0x8B | 0x8D | 0x8F | 0xD0 | 0xD1 | 0xD2 | 0xD3 | 0xFE => (true, None, false),
        0x69 => (true, Some(4usize), false),
        0x6B => (true, Some(1usize), false),
        0x80 | 0x82 | 0x83 | 0xC0 | 0xC1 | 0xC6 => (true, Some(1usize), false),
        0x81 | 0xC7 => (true, Some(4usize), false),
        0xF6 => (true, None, false),
        0xF7 => (true, None, false),
        0xFF => (true, None, true),
        _ => return Err("unsupported opcode"),
    };

    if !modrm_needed {
        return Ok((idx, is_branch, uses_rip_relative));
    }

    let modrm = parse_x86_64_modrm(bytes, idx)?;
    uses_rip_relative = modrm.rip_relative;
    if group5_control_flow && matches!(modrm.reg, 2..=5) {
        is_branch = true;
    }

    let mut end = idx + modrm.len;
    match opcode {
        0xF6 if modrm.reg == 0 => end = checked_advance(end, 1, bytes)?,
        0xF7 if modrm.reg == 0 => end = checked_advance(end, 4, bytes)?,
        _ => {
            if let Some(imm_len) = imm_len {
                end = checked_advance(end, imm_len, bytes)?;
            }
        }
    }

    Ok((end, is_branch, uses_rip_relative))
}

#[derive(Debug, Clone, Copy)]
struct X86_64ModRm {
    len: usize,
    reg: u8,
    rip_relative: bool,
}

fn parse_x86_64_modrm(bytes: &[u8], modrm_offset: usize) -> Result<X86_64ModRm, &'static str> {
    let modrm = *bytes.get(modrm_offset).ok_or("truncated ModRM")?;
    let mode = modrm >> 6;
    let reg = (modrm >> 3) & 0x07;
    let rm = modrm & 0x07;

    let mut len = 1;
    let rip_relative = mode != 0b11 && rm == 0b101;

    if mode != 0b11 && rm == 0b100 {
        let sib = *bytes.get(modrm_offset + len).ok_or("truncated SIB")?;
        len += 1;
        let base = sib & 0x07;
        if mode == 0b00 && base == 0b101 {
            len = checked_advance(modrm_offset, len + 4, bytes)? - modrm_offset;
            return Ok(X86_64ModRm {
                len,
                reg,
                rip_relative,
            });
        }
    }

    let disp_len = match mode {
        0b00 if rm == 0b101 => 4,
        0b01 => 1,
        0b10 => 4,
        _ => 0,
    };
    len = checked_advance(modrm_offset, len + disp_len, bytes)? - modrm_offset;

    Ok(X86_64ModRm {
        len,
        reg,
        rip_relative,
    })
}

fn checked_advance(current: usize, advance: usize, bytes: &[u8]) -> Result<usize, &'static str> {
    let end = current
        .checked_add(advance)
        .ok_or("instruction length overflow")?;
    if end <= bytes.len() {
        Ok(end)
    } else {
        Err("truncated instruction")
    }
}

fn validate_arm64_trampoline_bytes(arch: PatchArch, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() % 4 != 0 {
        return Err(format!(
            "{arch} trampoline bytes must be a whole number of instructions, got {} bytes",
            bytes.len()
        ));
    }

    for (insn_index, insn_bytes) in bytes.chunks_exact(4).enumerate() {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(insn_bytes);
        let insn = u32::from_le_bytes(buf);
        if let Some(reason) = classify_arm64_relocated_instruction(insn) {
            return Err(format!(
                "{arch} trampoline relocation rejected instruction at byte offset {:#x}: {} ({:#010x})",
                insn_index * 4,
                reason,
                insn,
            ));
        }
    }

    Ok(())
}

fn classify_arm64_relocated_instruction(insn: u32) -> Option<&'static str> {
    if insn & 0x7C00_0000 == 0x1400_0000 {
        return Some("branch immediate");
    }
    if insn & 0xFF00_0010 == 0x5400_0000 {
        return Some("conditional branch");
    }
    if insn & 0x7E00_0000 == 0x3400_0000 {
        return Some("compare-and-branch");
    }
    if insn & 0x7E00_0000 == 0x3600_0000 {
        return Some("test-and-branch");
    }
    if insn & 0x9F00_0000 == 0x1000_0000 {
        return Some("ADR");
    }
    if insn & 0x9F00_0000 == 0x9000_0000 {
        return Some("ADRP");
    }
    if insn & 0x3B00_0000 == 0x1800_0000 {
        return Some("literal load");
    }
    if insn & 0xFE00_0000 == 0xD600_0000 || insn & 0xFF00_0000 == 0xD700_0000 {
        return Some("register or authenticated branch");
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_patcher() -> MachoPatcher {
        let data = vec![0u8; 0x2000];

        let mut symbols = PatchSymbolTable::new();
        symbols.insert(
            "_main".to_string(),
            PatchSymbolEntry {
                address: 0x100100,
                size: 0,
                section: Some(0),
                is_external: true,
            },
        );
        symbols.insert(
            "_helper".to_string(),
            PatchSymbolEntry {
                address: 0x101010,
                size: 0,
                section: Some(1),
                is_external: false,
            },
        );

        let segments = vec![
            PatchSegmentInfo {
                name: "__TEXT".to_string(),
                vmaddr: 0x100000,
                vmsize: 0x1000,
                fileoff: 0,
                filesize: 0x1000,
                sections: vec![PatchSectionInfo {
                    name: "__text".to_string(),
                    segment_name: "__TEXT".to_string(),
                    addr: 0x100000,
                    size: 0x1000,
                    offset: 0,
                    section_type: None,
                }],
            },
            PatchSegmentInfo {
                name: "__DATA".to_string(),
                vmaddr: 0x101000,
                vmsize: 0x1000,
                fileoff: 0x1000,
                filesize: 0x1000,
                sections: vec![PatchSectionInfo {
                    name: "__data".to_string(),
                    segment_name: "__DATA".to_string(),
                    addr: 0x101000,
                    size: 0x1000,
                    offset: 0x1000,
                    section_type: None,
                }],
            },
        ];

        MachoPatcher::new(data, symbols, segments)
    }

    #[test]
    fn va_to_offset_text_segment() {
        let p = make_test_patcher();
        // VA 0x100100 is in __TEXT: fileoff=0 + (0x100100 - 0x100000) = 0x100
        assert_eq!(p.va_to_offset(0x100100), Some(0x100));
    }

    #[test]
    fn va_to_offset_data_segment() {
        let p = make_test_patcher();
        // VA 0x101010 is in __DATA: fileoff=0x1000 + (0x101010 - 0x101000) = 0x1010
        assert_eq!(p.va_to_offset(0x101010), Some(0x1010));
    }

    #[test]
    fn va_to_offset_out_of_range() {
        let p = make_test_patcher();
        assert_eq!(p.va_to_offset(0x200000), None);
    }

    #[test]
    fn va_to_offset_at_segment_boundary() {
        let p = make_test_patcher();
        // Start of __TEXT
        assert_eq!(p.va_to_offset(0x100000), Some(0));
        // Start of __DATA
        assert_eq!(p.va_to_offset(0x101000), Some(0x1000));
    }

    #[test]
    fn va_to_offset_end_exclusive() {
        let p = make_test_patcher();
        // One past end of __TEXT vmrange => falls into __DATA? No: 0x101000
        // is the start of __DATA vmaddr, so it should map there.
        assert_eq!(p.va_to_offset(0x101000), Some(0x1000));
        // Beyond __DATA
        assert_eq!(p.va_to_offset(0x102000), None);
    }

    #[test]
    fn rva_to_offset() {
        let p = make_test_patcher();
        // Image base is __TEXT vmaddr = 0x100000.
        // RVA 0x100 => VA 0x100100 => file offset 0x100.
        assert_eq!(p.rva_to_offset(0x100), Some(0x100));
        // RVA 0x1010 => VA 0x101010 => file offset 0x1010.
        assert_eq!(p.rva_to_offset(0x1010), Some(0x1010));
    }

    #[test]
    fn image_base() {
        let p = make_test_patcher();
        assert_eq!(p.image_base(), 0x100000);
    }

    #[test]
    fn symbol_offset_lookup() {
        let p = make_test_patcher();
        assert_eq!(p.symbol_offset("_main"), Some(0x100));
        assert_eq!(p.symbol_offset("_helper"), Some(0x1010));
        assert_eq!(p.symbol_offset("_missing"), None);
    }

    #[test]
    fn read_write_bytes() {
        let mut p = make_test_patcher();

        // Write some bytes at offset 0x100.
        let patch = [0xDE, 0xAD, 0xBE, 0xEF];
        let original = p.write_bytes(0x100, &patch).unwrap();
        assert_eq!(original, [0x00, 0x00, 0x00, 0x00]);

        // Read them back.
        let readback = p.read_bytes(0x100, 4).unwrap();
        assert_eq!(readback, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn write_bytes_returns_original() {
        let mut p = make_test_patcher();

        // First write
        let patch1 = [0x01, 0x02, 0x03];
        let orig1 = p.write_bytes(0x10, &patch1).unwrap();
        assert_eq!(orig1, [0x00, 0x00, 0x00]);

        // Second write at same location
        let patch2 = [0xAA, 0xBB, 0xCC];
        let orig2 = p.write_bytes(0x10, &patch2).unwrap();
        assert_eq!(orig2, [0x01, 0x02, 0x03]);
    }

    #[test]
    fn write_bytes_out_of_bounds() {
        let mut p = make_test_patcher();
        let big = vec![0xFF; 0x3000]; // larger than 0x2000 buffer
        assert!(p.write_bytes(0, &big).is_err());
    }

    #[test]
    fn find_bytes_exact() {
        let mut p = make_test_patcher();
        // Plant a pattern.
        p.data[0x200] = 0xCA;
        p.data[0x201] = 0xFE;
        p.data[0x202] = 0xBA;
        p.data[0x203] = 0xBE;

        let pattern = [0xCA, 0xFE, 0xBA, 0xBE];
        let mask = [0xFF, 0xFF, 0xFF, 0xFF];
        let results = p.find_bytes(&pattern, &mask, 0..0x1000);
        assert_eq!(results, vec![0x200]);
    }

    #[test]
    fn find_bytes_with_wildcard() {
        let mut p = make_test_patcher();
        // Plant patterns.
        p.data[0x100] = 0xCA;
        p.data[0x101] = 0x11;
        p.data[0x102] = 0xBA;

        p.data[0x300] = 0xCA;
        p.data[0x301] = 0x99;
        p.data[0x302] = 0xBA;

        let pattern = [0xCA, 0x00, 0xBA]; // middle byte is wildcard
        let mask = [0xFF, 0x00, 0xFF];
        let results = p.find_bytes(&pattern, &mask, 0..0x1000);
        assert!(results.contains(&0x100));
        assert!(results.contains(&0x300));
    }

    #[test]
    fn find_bytes_no_match() {
        let p = make_test_patcher();
        let pattern = [0xDE, 0xAD];
        let mask = [0xFF, 0xFF];
        let results = p.find_bytes(&pattern, &mask, 0..0x2000);
        assert!(results.is_empty());
    }

    #[test]
    fn find_exact_helper() {
        let mut p = make_test_patcher();
        p.data[0x50] = 0xAB;
        p.data[0x51] = 0xCD;
        let results = p.find_exact(&[0xAB, 0xCD], 0..0x1000);
        assert_eq!(results, vec![0x50]);
    }

    #[test]
    fn find_cstring_basic() {
        let mut p = make_test_patcher();
        let s = b"hello";
        let offset = 0x500;
        p.data[offset..offset + s.len()].copy_from_slice(s);
        p.data[offset + s.len()] = 0; // null terminator
        // Add some padding nulls
        p.data[offset + s.len() + 1] = 0;
        p.data[offset + s.len() + 2] = 0;
        // Place a non-null byte to bound the allocation scan.
        p.data[offset + s.len() + 3] = 0x42;

        let results = p.find_cstring("hello");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, offset);
        // allocated size = "hello" (5) + null (1) + 2 padding nulls (2) = 8
        assert_eq!(results[0].1, 8);
    }

    #[test]
    fn find_cstring_no_match() {
        let p = make_test_patcher();
        let results = p.find_cstring("nonexistent");
        assert!(results.is_empty());
    }

    #[test]
    fn encode_hook_jump_x86_64_relative() {
        let jump = MachoPatcher::encode_hook_jump(PatchArch::X86_64, 0x1000, 0x1100).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::X86_64Relative);
        assert_eq!(jump.bytes, vec![0xE9, 0xFB, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn encode_hook_jump_x86_64_absolute_fallback() {
        let jump =
            MachoPatcher::encode_hook_jump(PatchArch::X86_64, 0x1000, 0x1_0000_0000).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::X86_64Absolute);
        assert_eq!(
            jump.bytes,
            vec![
                0xFF, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
            ]
        );
    }

    #[test]
    fn encode_hook_jump_arm64_direct_branch() {
        let jump = MachoPatcher::encode_hook_jump(PatchArch::Arm64, 0x1000, 0x1040).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::Arm64BranchImmediate);
        assert_eq!(jump.bytes, vec![0x10, 0x00, 0x00, 0x14]);
    }

    #[test]
    fn encode_hook_jump_arm64e_absolute_literal() {
        let jump =
            MachoPatcher::encode_hook_jump(PatchArch::Arm64e, 0x1000, 0x9000_0000_0000).unwrap();
        assert_eq!(jump.encoding, HookJumpEncoding::Arm64AbsoluteLiteral);
        assert_eq!(
            jump.bytes,
            vec![
                0x50, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1F, 0xD6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x90,
                0x00, 0x00,
            ]
        );
    }

    #[test]
    fn build_trampoline_x86_64_appends_jump_back() {
        let trampoline = MachoPatcher::build_trampoline(
            PatchArch::X86_64,
            0x2000,
            &[0x55, 0x48, 0x89, 0xE5],
            0x3000,
        )
        .unwrap();

        assert_eq!(
            trampoline.jump_back.encoding,
            HookJumpEncoding::X86_64Relative
        );
        assert_eq!(
            trampoline.bytes,
            vec![0x55, 0x48, 0x89, 0xE5, 0xE9, 0xF7, 0x0F, 0x00, 0x00]
        );
    }

    #[test]
    fn build_trampoline_arm64_appends_jump_back() {
        let relocated = [
            0xFD, 0x7B, 0xBF, 0xA9, // stp x29, x30, [sp, #-16]!
            0xFD, 0x03, 0x00, 0x91, // mov x29, sp
        ];
        let trampoline =
            MachoPatcher::build_trampoline(PatchArch::Arm64, 0x2000, &relocated, 0x2048).unwrap();

        assert_eq!(
            trampoline.jump_back.encoding,
            HookJumpEncoding::Arm64BranchImmediate
        );
        assert_eq!(
            trampoline.bytes,
            vec![
                0xFD, 0x7B, 0xBF, 0xA9, 0xFD, 0x03, 0x00, 0x91, 0x10, 0x00, 0x00, 0x14,
            ]
        );
    }

    #[test]
    fn build_trampoline_x86_64_allows_empty_relocated_bytes() {
        let trampoline =
            MachoPatcher::build_trampoline(PatchArch::X86_64, 0x2000, &[], 0x3000).unwrap();

        assert_eq!(trampoline.relocated_bytes, Vec::<u8>::new());
        assert_eq!(
            trampoline.jump_back.encoding,
            HookJumpEncoding::X86_64Relative
        );
        assert_eq!(trampoline.bytes, vec![0xE9, 0xFB, 0x0F, 0x00, 0x00]);
    }

    #[test]
    fn validate_trampoline_instructions_x86_64_rejects_rip_relative_lea() {
        let err = MachoPatcher::validate_trampoline_instructions(
            PatchArch::X86_64,
            &[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00], // lea rax, [rip]
        )
        .unwrap_err();

        assert!(err.contains("RIP-relative"));
    }

    #[test]
    fn plan_function_entry_hook_x86_64_relocates_relative_control_flow_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x105].copy_from_slice(&[0xE8, 0x01, 0x00, 0x00, 0x00]); // call +1

        let plan = p
            .plan_function_entry_hook(PatchArch::X86_64, 0x100100, 0x100200, 0x100300, 5)
            .unwrap();

        let disp = i32::from_le_bytes(plan.trampoline.relocated_bytes[1..5].try_into().unwrap());
        let target = (plan.trampoline.trampoline_va + 5).wrapping_add_signed(disp as i64);
        assert_eq!(target, 0x100106);
    }

    #[test]
    fn plan_function_entry_hook_x86_64_relocates_rip_relative_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x107].copy_from_slice(&[0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00]);

        let plan = p
            .plan_function_entry_hook(PatchArch::X86_64, 0x100100, 0x100200, 0x100300, 7)
            .unwrap();

        let disp = i32::from_le_bytes(plan.trampoline.relocated_bytes[3..7].try_into().unwrap());
        let target = (plan.trampoline.trampoline_va + 7).wrapping_add_signed(disp as i64);
        assert_eq!(target, 0x100107);
    }

    #[test]
    fn build_relocated_trampoline_arm64_rewrites_branch_immediate() {
        let source = 0x1400_0002u32.to_le_bytes();
        let trampoline = MachoPatcher::build_relocated_trampoline(
            PatchArch::Arm64,
            0x1000,
            0x2000,
            &source,
            0x1004,
        )
        .unwrap();

        let first = u32::from_le_bytes(trampoline.relocated_bytes[..4].try_into().unwrap());
        assert_ne!(first, 0x1400_0002);
    }

    #[test]
    fn plan_function_entry_patch_x86_64_pads_with_nops() {
        let mut p = make_test_patcher();
        let original = [0x55, 0x48, 0x89, 0xE5, 0x41, 0x57, 0x41, 0x56];
        p.data[0x100..0x108].copy_from_slice(&original);

        let plan = p
            .plan_function_entry_patch(PatchArch::X86_64, 0x100100, 0x100200, original.len())
            .unwrap();

        assert_eq!(plan.entry_offset, 0x100);
        assert_eq!(plan.original_bytes, original);
        assert_eq!(plan.jump.encoding, HookJumpEncoding::X86_64Relative);
        assert_eq!(
            plan.patch_bytes,
            vec![0xE9, 0xFB, 0x00, 0x00, 0x00, 0x90, 0x90, 0x90]
        );
        assert_eq!(plan.resume_va(), 0x100108);
    }

    #[test]
    fn plan_function_entry_patch_x86_64_far_target_requires_larger_window() {
        let p = make_test_patcher();
        let err = p
            .plan_function_entry_patch(PatchArch::X86_64, 0x100100, 0x1_0000_0000, 5)
            .unwrap_err();
        assert!(err.contains("needs 14 bytes"));
    }

    #[test]
    fn plan_function_entry_patch_arm64_rejects_unaligned_overwrite_len() {
        let p = make_test_patcher();
        let err = p
            .plan_function_entry_patch(PatchArch::Arm64, 0x100100, 0x100200, 6)
            .unwrap_err();
        assert!(err.contains("divisible by 4"));
    }

    #[test]
    fn plan_function_entry_hook_arm64_relocates_pc_relative_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x104].copy_from_slice(&[0x10, 0x00, 0x00, 0x14]); // b +0x40

        let plan = p
            .plan_function_entry_hook(PatchArch::Arm64, 0x100100, 0x100200, 0x100300, 4)
            .unwrap();

        let first = u32::from_le_bytes(plan.trampoline.relocated_bytes[..4].try_into().unwrap());
        assert_ne!(first, 0x1400_0010);
    }

    #[test]
    fn plan_function_entry_hook_arm64_rejects_register_branch_stolen_bytes() {
        let mut p = make_test_patcher();
        p.data[0x100..0x104].copy_from_slice(&[0x00, 0x02, 0x1F, 0xD6]); // br x16

        let err = p
            .plan_function_entry_hook(PatchArch::Arm64e, 0x100100, 0x100200, 0x100300, 4)
            .unwrap_err();

        assert!(err.contains("register or authenticated branch"));
    }

    #[test]
    fn plan_function_entry_patch_rejects_va_window_crossing_segment_gap() {
        let p = make_test_patcher();
        let err = p
            .plan_function_entry_patch(PatchArch::X86_64, 0x100ffc, 8, 8)
            .unwrap_err();

        assert!(err.contains("not fully mappable"));
    }

    #[test]
    fn nop_fill_x86() {
        let mut p = make_test_patcher();
        let original = p.nop_fill(0x100, 5, false).unwrap();
        assert_eq!(original, vec![0x00; 5]);
        assert_eq!(
            p.read_bytes(0x100, 5).unwrap(),
            &[0x90, 0x90, 0x90, 0x90, 0x90]
        );
    }

    #[test]
    fn nop_fill_arm64() {
        let mut p = make_test_patcher();
        let original = p.nop_fill(0x100, 8, true).unwrap();
        assert_eq!(original, vec![0x00; 8]);
        let nop_arm64 = [0x1F, 0x20, 0x03, 0xD5, 0x1F, 0x20, 0x03, 0xD5];
        assert_eq!(p.read_bytes(0x100, 8).unwrap(), &nop_arm64);
    }

    #[test]
    fn nop_fill_arm64_unaligned() {
        let mut p = make_test_patcher();
        let result = p.nop_fill(0x100, 5, true);
        assert!(result.is_err());
    }
}
