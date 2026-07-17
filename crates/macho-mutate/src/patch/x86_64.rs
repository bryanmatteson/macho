fn encode_x86_64_hook_jump(source_va: u64, destination_va: u64) -> Result<HookJump> {
    let relative_delta = i128::from(destination_va)
        - i128::from(
            source_va
                .checked_add(X86_64_REL32_JUMP_LEN as u64)
                .ok_or_else(|| {
                    Error::invalid(format!("x86_64 jump source {source_va:#x} overflows"))
                })?,
        );

    if (i32::MIN as i128..=i32::MAX as i128).contains(&relative_delta) {
        let displacement = i32::try_from(relative_delta).map_err(|_| {
            Error::invalid(format!(
                "x86_64 relative jump delta out of range: source={source_va:#x} destination={destination_va:#x}"
            ))
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
