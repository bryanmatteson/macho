fn encode_arm64_hook_jump(
    arch: PatchArch,
    source_va: u64,
    destination_va: u64,
) -> Result<HookJump> {
    if source_va % 4 != 0 {
        return Err(Error::invalid(format!(
            "{arch} jump source must be 4-byte aligned, got {source_va:#x}"
        )));
    }
    if destination_va % 4 != 0 {
        return Err(Error::invalid(format!(
            "{arch} jump destination must be 4-byte aligned, got {destination_va:#x}"
        )));
    }

    let delta = i128::from(destination_va) - i128::from(source_va);
    if delta % 4 == 0 {
        let scaled = delta / 4;
        if (-(1_i128 << 25)..=(1_i128 << 25) - 1).contains(&scaled) {
            let imm26 = (i32::try_from(scaled)
                .map_err(|_| Error::invalid("arm64 jump delta out of range"))?
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

    if arch == PatchArch::Arm64e {
        let mut bytes = Vec::with_capacity(ARM64E_MATERIALIZED_JUMP_LEN);
        for halfword in 0..4_u32 {
            let immediate = ((destination_va >> (halfword * 16)) & 0xffff) as u32;
            let base = if halfword == 0 {
                0xD280_0000_u32 // MOVZ Xd, #imm16
            } else {
                0xF280_0000_u32 // MOVK Xd, #imm16, LSL #shift
            };
            let instruction = base | (halfword << 21) | (immediate << 5) | 16;
            bytes.extend_from_slice(&instruction.to_le_bytes());
        }
        bytes.extend_from_slice(&ARM64_BR_X16);
        return Ok(HookJump {
            arch,
            source_va,
            destination_va,
            encoding: HookJumpEncoding::Arm64eMaterializedAddress,
            bytes,
        });
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

fn is_arm64_bti_landing_pad(bytes: &[u8]) -> bool {
    let Some(word) = bytes
        .get(..4)
        .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
        .map(u32::from_le_bytes)
    else {
        return false;
    };
    matches!(word, 0xD503_241F | 0xD503_245F | 0xD503_249F | 0xD503_24DF)
}
