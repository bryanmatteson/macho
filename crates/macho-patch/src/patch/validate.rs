fn ensure_hook_arch_supported(arch: PatchArch) -> Result<()> {
    match arch {
        PatchArch::X86_64 | PatchArch::Arm64 | PatchArch::Arm64e => Ok(()),
        PatchArch::I386 => Err(Error::invalid(
            "executable hook patching is not supported for i386",
        )),
    }
}

fn validate_patch_alignment(arch: PatchArch, address: u64, len: usize) -> Result<()> {
    match arch {
        PatchArch::X86_64 => Ok(()),
        PatchArch::Arm64 | PatchArch::Arm64e => {
            if address % 4 != 0 {
                return Err(Error::invalid(format!(
                    "{arch} function-entry patch address must be 4-byte aligned, got {address:#x}"
                )));
            }
            if len % 4 != 0 {
                return Err(Error::invalid(format!(
                    "{arch} function-entry patch length must be divisible by 4, got {len}"
                )));
            }
            Ok(())
        }
        PatchArch::I386 => Err(Error::invalid(
            "executable hook patching is not supported for i386",
        )),
    }
}

fn patch_arch_to_insn_arch(arch: PatchArch) -> Result<macho_insn::Arch> {
    match arch {
        PatchArch::X86_64 => Ok(macho_insn::Arch::X86_64),
        PatchArch::Arm64 => Ok(macho_insn::Arch::Arm64),
        PatchArch::Arm64e => Ok(macho_insn::Arch::Arm64e),
        PatchArch::I386 => Err(Error::invalid("i386 is not supported")),
    }
}

fn validate_trampoline_bytes_unified(arch: PatchArch, bytes: &[u8]) -> Result<()> {
    let insn_arch = patch_arch_to_insn_arch(arch)?;

    if insn_arch.is_arm64() && bytes.len() % 4 != 0 {
        return Err(Error::invalid(format!(
            "{arch} trampoline bytes must be a whole number of instructions, got {} bytes",
            bytes.len()
        )));
    }

    let mut offset = 0;
    while offset < bytes.len() {
        let insn_bytes = &bytes[offset..];
        let insn = macho_insn::decode_one(insn_bytes, 0, insn_arch).map_err(|source| {
            let mut error = Error::from(source);
            error.location = Some(macho_core::OffsetSpan {
                offset: offset as u64,
                len: insn_bytes.len() as u64,
            });
            error
        })?;

        match insn.kind {
            macho_insn::InsnKind::Branch(_) => {
                return Err(Error::invalid(format!(
                    "{arch} trampoline relocation rejected instruction at byte offset {:#x}: branch",
                    offset
                )));
            }
            macho_insn::InsnKind::Call(_) => {
                return Err(Error::invalid(format!(
                    "{arch} trampoline relocation rejected instruction at byte offset {:#x}: call",
                    offset
                )));
            }
            macho_insn::InsnKind::CondBranch(_) => {
                return Err(Error::invalid(format!(
                    "{arch} trampoline relocation rejected instruction at byte offset {:#x}: conditional branch",
                    offset
                )));
            }
            macho_insn::InsnKind::PcRelative(_) => {
                return Err(Error::invalid(format!(
                    "{arch} trampoline relocation rejected instruction at byte offset {:#x}: RIP-relative addressing",
                    offset
                )));
            }
            macho_insn::InsnKind::Return
            | macho_insn::InsnKind::Nop
            | macho_insn::InsnKind::Other => {}
            _ => {
                return Err(Error::invalid(format!(
                    "{arch} trampoline relocation rejected an unsupported instruction at byte offset {offset:#x}"
                )));
            }
        }

        offset += insn.len;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
