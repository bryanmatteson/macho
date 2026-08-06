fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// Performs vtable_mangled_prefix.
pub fn vtable_mangled_prefix(type_name: &str) -> String {
    format!("__ZTV{}{}", type_name.len(), type_name)
}

/// Performs nop_bytes_for_arch.
pub fn nop_bytes_for_arch(arch: PatchArch, count: usize) -> Result<Vec<u8>> {
    let insn_arch = patch_arch_to_insn_arch(arch).map_err(|_| {
        Error::invalid("NOP padding is not supported for i386 hook patches")
    })?;
    crate::insn::encode_nop(insn_arch, count).map_err(Into::into)
}
