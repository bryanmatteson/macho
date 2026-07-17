impl MachoPatcher {
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
    pub fn validate_trampoline_instructions(arch: PatchArch, bytes: &[u8]) -> Result<()> {
        ensure_hook_arch_supported(arch)?;
        validate_trampoline_bytes_unified(arch, bytes)
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
    ) -> Result<TrampolinePlan> {
        ensure_hook_arch_supported(arch)?;
        validate_patch_alignment(arch, trampoline_va, relocated_bytes.len())?;
        Self::validate_trampoline_instructions(arch, relocated_bytes)?;

        let jump_source_va = trampoline_va
            .checked_add(relocated_bytes.len() as u64)
            .ok_or_else(|| {
                Error::invalid(format!(
                    "trampoline at {trampoline_va:#x} overflows address space"
                ))
            })?;
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
    ) -> Result<Vec<u8>> {
        ensure_hook_arch_supported(arch)?;

        relocate_stolen_bytes_unified(arch, source_va, trampoline_va, bytes)
    }

    /// Build a trampoline from original stolen bytes, relocating them from the
    /// function entry at `source_va` into the trampoline at `trampoline_va`.
    pub fn build_relocated_trampoline(
        arch: PatchArch,
        source_va: u64,
        trampoline_va: u64,
        original_bytes: &[u8],
        resume_va: u64,
    ) -> Result<TrampolinePlan> {
        let relocated_bytes =
            Self::relocate_stolen_bytes(arch, source_va, trampoline_va, original_bytes)?;
        ensure_hook_arch_supported(arch)?;
        validate_patch_alignment(arch, trampoline_va, original_bytes.len())?;

        let jump_source_va = trampoline_va
            .checked_add(relocated_bytes.len() as u64)
            .ok_or_else(|| {
                Error::invalid(format!(
                    "trampoline at {trampoline_va:#x} overflows address space"
                ))
            })?;
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
}
