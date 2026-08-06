use super::spec::{OperationDetail, encode_hex};
use crate::cli::model::macho_file::MachoFile;
use crate::format::constants::{CPU_TYPE_ARM64, CPU_TYPE_X86, CPU_TYPE_X86_64, VmProtection};
use crate::patch::{
    FunctionEntryPatchPlan, HookJumpEncoding, MachoPatcher, PatchArch, PatchSegmentInfo,
    PatchSymbolTable,
};
use anyhow::Result;

pub(super) fn plan_detour(
    macho: &MachoFile<'_>,
    entry_va: u64,
    destination_va: u64,
    overwrite_len: usize,
) -> Result<(FunctionEntryPatchPlan, usize)> {
    let arch = patch_arch(macho)?;
    if !executable_file_range(macho, entry_va, overwrite_len) {
        anyhow::bail!(
            "function-entry window [{entry_va:#x}, {:#x}) is not wholly file-backed in one executable segment",
            entry_va.saturating_add(overwrite_len as u64)
        );
    }
    if !executable_file_range(macho, destination_va, 1) {
        anyhow::bail!(
            "detour destination {destination_va:#x} is not file-backed in an executable segment"
        );
    }

    let segments = macho
        .segments()
        .iter()
        .map(|segment| PatchSegmentInfo {
            name: segment.name().to_string(),
            vmaddr: segment.vm_addr().0,
            vmsize: segment.vm_size(),
            fileoff: segment.file_offset().0,
            filesize: segment.file_size(),
            sections: Vec::new(),
        })
        .collect();
    let patcher = MachoPatcher::new(macho.bytes().to_vec(), PatchSymbolTable::new(), segments);
    let entry_offset = patcher.va_to_offset(entry_va).ok_or_else(|| {
        anyhow::anyhow!("function entry {entry_va:#x} does not map to a file offset")
    })?;
    let entry_end = entry_offset
        .checked_add(overwrite_len)
        .ok_or_else(|| anyhow::anyhow!("function-entry file window overflows usize"))?;
    let window = patcher
        .data()
        .get(entry_offset..entry_end)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "function-entry window at {entry_va:#x} (file offset {entry_offset:#x}) is outside the image"
            )
        })?;
    let instruction_count = validate_instruction_window(arch, entry_va, entry_offset, window)?;
    let plan = patcher
        .plan_function_entry_patch(arch, entry_va, destination_va, overwrite_len)
        .map_err(anyhow::Error::from)?;
    Ok((plan, instruction_count))
}

fn validate_instruction_window(
    arch: PatchArch,
    entry_va: u64,
    entry_offset: usize,
    window: &[u8],
) -> Result<usize> {
    let insn_arch = match arch {
        PatchArch::X86_64 => crate::insn::Arch::X86_64,
        PatchArch::Arm64 => crate::insn::Arch::Arm64,
        PatchArch::Arm64e => crate::insn::Arch::Arm64e,
        _ => anyhow::bail!("strict instruction validation is unsupported for {arch}"),
    };
    let mut offset = 0usize;
    let mut count = 0usize;
    while offset < window.len() {
        let va = entry_va
            .checked_add(offset as u64)
            .ok_or_else(|| anyhow::anyhow!("function-entry VA window overflows u64"))?;
        let file_offset = entry_offset + offset;
        let instruction = crate::insn::decode_one(&window[offset..], va, insn_arch).map_err(
            |error| {
                anyhow::anyhow!(
                    "function-entry overwrite is not a complete instruction sequence: decode failed at VA {va:#x} (file offset {file_offset:#x}, window byte +{offset:#x}): {error}"
                )
            },
        )?;
        if instruction.len == 0 || instruction.len > window.len() - offset {
            anyhow::bail!(
                "function-entry overwrite is not a complete instruction sequence: instruction at VA {va:#x} (file offset {file_offset:#x}) extends beyond the overwrite window"
            );
        }
        offset += instruction.len;
        count += 1;
    }
    Ok(count)
}

fn executable_file_range(macho: &MachoFile<'_>, va: u64, len: usize) -> bool {
    let Ok(len) = u64::try_from(len) else {
        return false;
    };
    if len == 0 {
        return false;
    }
    macho.segments().iter().any(|segment| {
        if !segment.init_prot().contains(VmProtection::EXECUTE) {
            return false;
        }
        let start = segment.vm_addr().0;
        let Some(delta) = va.checked_sub(start) else {
            return false;
        };
        let Some(end) = delta.checked_add(len) else {
            return false;
        };
        end <= segment.file_size()
    })
}

fn patch_arch(macho: &MachoFile<'_>) -> Result<PatchArch> {
    let header = macho.header();
    match header.cpu_type().0 {
        CPU_TYPE_X86_64 => Ok(PatchArch::X86_64),
        CPU_TYPE_ARM64 if header.arch_spec().is_arm64e() => Ok(PatchArch::Arm64e),
        CPU_TYPE_ARM64 => Ok(PatchArch::Arm64),
        CPU_TYPE_X86 => anyhow::bail!("executable patching is unsupported for i386"),
        cpu => anyhow::bail!(
            "executable patching is unsupported for architecture {} (CPU type {cpu:#x})",
            header.arch_spec().name()
        ),
    }
}

pub(super) fn detour_detail(
    plan: &FunctionEntryPatchPlan,
    instruction_count: usize,
) -> OperationDetail {
    OperationDetail::Detour {
        arch: plan.arch.to_string(),
        entry_va: plan.entry_va,
        entry_offset: plan.entry_offset,
        destination_va: plan.destination_va,
        overwrite_len: plan.overwrite_len,
        instruction_count,
        encoding: match plan.jump.encoding {
            HookJumpEncoding::X86_64Relative => "x86_64_relative",
            HookJumpEncoding::X86_64Absolute => "x86_64_absolute",
            HookJumpEncoding::Arm64BranchImmediate => "arm64_branch_immediate",
            HookJumpEncoding::Arm64AbsoluteLiteral => "arm64_absolute_literal",
            _ => "unknown",
        },
        original_bytes: encode_hex(&plan.original_bytes),
        replacement_bytes: encode_hex(&plan.patch_bytes),
    }
}
