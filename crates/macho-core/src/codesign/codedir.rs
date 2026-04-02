use crate::error::{Error, Result};
use crate::codesign::superblob::{read_be_u32, read_be_u64};
use crate::codesign::types::{CSMAGIC_CODEDIRECTORY, CodeDirectory, HashType};

/// Parse a CodeDirectory blob.
pub fn parse_code_directory<'data>(data: &'data [u8]) -> Result<CodeDirectory<'data>> {
    if data.len() < 44 {
        return Err(Error::Format("CodeDirectory blob too small".into()));
    }

    let magic = read_be_u32(data, 0);
    if magic != CSMAGIC_CODEDIRECTORY {
        return Err(Error::Format(format!(
            "expected CodeDirectory magic 0xFADE0C02, got {magic:#010x}"
        )));
    }

    let _length = read_be_u32(data, 4);
    let version = read_be_u32(data, 8);
    let flags = read_be_u32(data, 12);
    let _hash_offset = read_be_u32(data, 16) as usize;
    let ident_offset = read_be_u32(data, 20) as usize;
    let n_special_slots = read_be_u32(data, 24);
    let n_code_slots = read_be_u32(data, 28);
    let code_limit = read_be_u32(data, 32);
    let hash_size = data.get(36).copied().unwrap_or(0);
    let hash_type_raw = data.get(37).copied().unwrap_or(0);
    let _platform = data.get(38).copied().unwrap_or(0);
    let page_size = data.get(39).copied().unwrap_or(0);

    let hash_type = HashType::from_u8(hash_type_raw);

    // Read identifier string
    let identifier = if ident_offset > 0 && ident_offset < data.len() {
        read_cstring(data, ident_offset)
    } else {
        None
    };

    // Read team ID (version >= 0x20200)
    let team_id = if version >= 0x20200 && data.len() >= 52 {
        let team_offset = read_be_u32(data, 48) as usize;
        if team_offset > 0 && team_offset < data.len() {
            read_cstring(data, team_offset)
        } else {
            None
        }
    } else {
        None
    };

    // Read exec segment info (version >= 0x20400)
    // Layout: ... spare3(4)@52, codeLimit64(8)@56, execSegBase(8)@64,
    //         execSegLimit(8)@72, execSegFlags(8)@80
    let (exec_seg_base, exec_seg_limit, exec_seg_flags) = if version >= 0x20400 && data.len() >= 88
    {
        (
            Some(read_be_u64(data, 64)),
            Some(read_be_u64(data, 72)),
            Some(read_be_u64(data, 80)),
        )
    } else {
        (None, None, None)
    };

    Ok(CodeDirectory {
        version,
        flags,
        hash_type,
        hash_size,
        page_size,
        n_code_slots,
        n_special_slots,
        code_limit,
        identifier,
        team_id,
        exec_seg_base,
        exec_seg_limit,
        exec_seg_flags,
    })
}

fn read_cstring(data: &[u8], offset: usize) -> Option<&str> {
    let slice = data.get(offset..)?;
    let end = slice.iter().position(|&b| b == 0).unwrap_or(slice.len());
    std::str::from_utf8(&slice[..end]).ok()
}
