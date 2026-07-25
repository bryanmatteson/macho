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

    /// Translate a file offset to a virtual address.
    ///
    /// Walks segments to find one whose `[fileoff, fileoff+filesize)` range
    /// contains `offset`, then computes `vmaddr + (offset - fileoff)`.
    pub fn offset_to_va(&self, offset: usize) -> Option<u64> {
        let offset = offset as u64;
        for seg in &self.segments {
            let Some(seg_end) = seg.fileoff.checked_add(seg.filesize) else {
                continue;
            };
            if offset >= seg.fileoff && offset < seg_end {
                let delta = offset - seg.fileoff;
                return seg.vmaddr.checked_add(delta);
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
    ) -> Result<HookJump> {
        ensure_hook_arch_supported(arch)?;

        match arch {
            PatchArch::X86_64 => encode_x86_64_hook_jump(source_va, destination_va),
            PatchArch::Arm64 | PatchArch::Arm64e => {
                encode_arm64_hook_jump(arch, source_va, destination_va)
            }
            PatchArch::I386 => Err(Error::invalid(
                "executable hook patching is not supported for i386",
            )),
        }
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
    ) -> Result<FunctionEntryPatchPlan> {
        ensure_hook_arch_supported(arch)?;
        if overwrite_len == 0 {
            return Err(Error::invalid(
                "function-entry hook planning requires a non-zero patch length",
            ));
        }
        validate_patch_alignment(arch, entry_va, overwrite_len)?;

        let entry_offset = self.va_range_to_offset(entry_va, overwrite_len).ok_or_else(|| {
            Error::invalid(format!(
                "function entry patch window [{:#x}, {:#x}) is not fully mappable in this image",
                entry_va,
                entry_va.saturating_add(overwrite_len as u64),
            ))
        })?;
        let original_bytes = self
            .read_bytes(entry_offset, overwrite_len)
            .ok_or_else(|| {
                Error::invalid(format!(
                    "cannot read {overwrite_len} bytes for function entry patch at {entry_va:#x}"
                ))
            })?
            .to_vec();

        let jump = Self::encode_hook_jump(arch, entry_va, destination_va)?;
        if overwrite_len < jump.len() {
            return Err(Error::invalid(format!(
                "function entry patch at {entry_va:#x} needs {} bytes for {:?}, but overwrite_len is {}",
                jump.len(),
                jump.encoding,
                overwrite_len,
            )));
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
    /// Returns pure plan data. Callers materialize trampoline bytes where they
    /// choose.
    pub fn plan_function_entry_hook(
        &self,
        arch: PatchArch,
        entry_va: u64,
        hook_va: u64,
        trampoline_va: u64,
        overwrite_len: usize,
    ) -> Result<FunctionEntryHookPlan> {
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
    pub fn write_bytes(&mut self, offset: usize, bytes: &[u8]) -> Result<Vec<u8>> {
        let end = offset.checked_add(bytes.len()).ok_or_else(|| {
            Error::invalid(format!(
                "write at offset {:#x} with length {} overflows the address space",
                offset,
                bytes.len(),
            ))
        })?;
        if end > self.data.len() {
            return Err(Error::bounds(
                offset as u64,
                bytes.len() as u64,
                self.data.len() as u64,
            ));
        }

        let original = self.data[offset..end].to_vec();
        self.data[offset..end].copy_from_slice(bytes);
        Ok(original)
    }

    /// Write a single byte at `offset`, returning the original byte.
    pub fn write_byte(&mut self, offset: usize, byte: u8) -> Result<u8> {
        if offset >= self.data.len() {
            return Err(Error::bounds(
                offset as u64,
                1,
                self.data.len() as u64,
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
    ) -> Result<Vec<u8>> {
        if arm64 {
            self.write_bytes(offset, &nop_bytes_for_arch(PatchArch::Arm64, count)?)
        } else {
            self.write_bytes(offset, &nop_bytes_for_arch(PatchArch::X86_64, count)?)
        }
    }
}
