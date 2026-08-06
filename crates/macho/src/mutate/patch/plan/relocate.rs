fn relocate_stolen_bytes_unified(
    arch: PatchArch,
    source_va: u64,
    trampoline_va: u64,
    bytes: &[u8],
) -> Result<Vec<u8>> {
    let insn_arch = patch_arch_to_insn_arch(arch)?;

    if insn_arch.is_arm64() && bytes.len() % 4 != 0 {
        return Err(Error::invalid(format!(
            "{arch} trampoline bytes must be a whole number of instructions, got {} bytes",
            bytes.len()
        )));
    }

    let mut src_off = 0usize;
    let mut relocated = Vec::with_capacity(bytes.len() + 32);

    while src_off < bytes.len() {
        let insn_bytes = &bytes[src_off..];
        let src_insn_va = source_va + src_off as u64;
        let dst_insn_va = trampoline_va + relocated.len() as u64;

        let insn = crate::insn::decode_one(insn_bytes, src_insn_va, insn_arch).map_err(|source| {
            let mut error = Error::from(source);
            error.location = Some(crate::core::OffsetSpan {
                offset: src_off as u64,
                len: insn_bytes.len() as u64,
            });
            error
        })?;

        // Reject register/indirect branches -- they cannot be safely relocated.
        match &insn.kind {
            crate::insn::InsnKind::Branch(b) | crate::insn::InsnKind::Call(b) => {
                if matches!(
                    b.target,
                    crate::insn::BranchTarget::Register | crate::insn::BranchTarget::Indirect
                ) {
                    return Err(Error::invalid(format!(
                        "{arch} trampoline relocation rejected instruction at byte offset {:#x}: \
                         register or authenticated branch",
                        src_off
                    )));
                }
            }
            _ => {}
        }

        let rewritten = crate::insn::relocate_insn(
            &insn_bytes[..insn.len],
            src_insn_va,
            dst_insn_va,
            insn_arch,
        )
        .map_err(|source| {
            let mut error = Error::from(source);
            error.location = Some(crate::core::OffsetSpan {
                offset: src_off as u64,
                len: insn.len as u64,
            });
            error
        })?;

        src_off += insn.len;
        relocated.extend_from_slice(&rewritten);
    }

    Ok(relocated)
}
