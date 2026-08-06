use crate::metadata::codesign::error::{Error, Result};
use crate::metadata::codesign::types::{BlobType, CSMAGIC_EMBEDDED_SIGNATURE, SignatureBlob};

/// Parse a SuperBlob from raw code signature data.
///
/// All values in the code signature are big-endian regardless of the
/// Mach-O file's endianness. Truncated or structurally invalid superblobs
/// produce a typed `Error` rather than being silently dropped — callers can
/// choose to degrade if they want, but this parser never invents a zero.
pub fn parse_super_blob(data: &[u8]) -> Result<Vec<SignatureBlob<'_>>> {
    if data.len() < 12 {
        return Err(Error::format(
            "code signature too small for SuperBlob header",
        ));
    }

    let magic = read_be_u32(data, 0)?;
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(Error::format(format!(
            "expected SuperBlob magic 0xFADE0CC0, got {magic:#010x}"
        )));
    }

    let length = read_be_u32(data, 4)? as usize;
    let count = read_be_u32(data, 8)? as usize;

    if length > data.len() {
        return Err(Error::format(format!(
            "SuperBlob length {length} exceeds data size {}",
            data.len()
        )));
    }

    if count > 100 {
        return Err(Error::format(format!(
            "SuperBlob claims {count} blobs, which is unreasonably large"
        )));
    }

    let mut blobs = Vec::with_capacity(count);
    let index_start = 12usize;
    let index_size = count
        .checked_mul(8)
        .ok_or_else(|| Error::format("SuperBlob index size overflows"))?;
    let index_end = index_start
        .checked_add(index_size)
        .ok_or_else(|| Error::format("SuperBlob index extent overflows"))?;
    if index_end > data.len() {
        return Err(Error::format(format!(
            "SuperBlob claims {count} blobs but data is only {} bytes",
            data.len()
        )));
    }

    for i in 0..count {
        let idx_offset = index_start + i * 8;
        let blob_type_raw = read_be_u32(data, idx_offset)?;
        let blob_offset = read_be_u32(data, idx_offset + 4)? as usize;

        // A blob needs its own 8-byte magic+length header.
        let hdr_end = blob_offset
            .checked_add(8)
            .ok_or_else(|| Error::format("SuperBlob sub-blob header overflows"))?;
        if hdr_end > data.len() {
            return Err(Error::format(format!(
                "SuperBlob sub-blob at offset {blob_offset} extends past data"
            )));
        }

        let blob_magic = read_be_u32(data, blob_offset)?;
        let blob_length = read_be_u32(data, blob_offset + 4)? as usize;
        let blob_end = blob_offset.saturating_add(blob_length).min(data.len());
        let blob_data = &data[blob_offset..blob_end];

        blobs.push(SignatureBlob {
            blob_type: BlobType::from_slot(blob_type_raw),
            magic: blob_magic,
            offset: blob_offset as u32,
            size: blob_length as u32,
            data: blob_data,
        });
    }

    Ok(blobs)
}

/// Read a big-endian `u32` at `offset`. Fails when the slice does not cover
/// the required 4 bytes instead of silently returning 0 — the previous
/// behavior was unobservable from the caller and could propagate wrong
/// values through signature parsing.
pub(crate) fn read_be_u32(data: &[u8], offset: usize) -> Result<u32> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| Error::bounds(offset as u64, 4, data.len() as u64))?;
    if end > data.len() {
        return Err(Error::bounds(offset as u64, 4, data.len() as u64));
    }
    let bytes: [u8; 4] = data[offset..end]
        .try_into()
        .expect("slice length guaranteed by bounds check");
    Ok(u32::from_be_bytes(bytes))
}

/// Read a big-endian `u64` at `offset`. See [`read_be_u32`].
pub(crate) fn read_be_u64(data: &[u8], offset: usize) -> Result<u64> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| Error::bounds(offset as u64, 8, data.len() as u64))?;
    if end > data.len() {
        return Err(Error::bounds(offset as u64, 8, data.len() as u64));
    }
    let bytes: [u8; 8] = data[offset..end]
        .try_into()
        .expect("slice length guaranteed by bounds check");
    Ok(u64::from_be_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_be_u32_rejects_truncated() {
        let data = [0u8; 3];
        assert!(read_be_u32(&data, 0).is_err());
    }

    #[test]
    fn read_be_u32_rejects_offset_overflow() {
        let data = [0u8; 8];
        assert!(read_be_u32(&data, usize::MAX).is_err());
    }

    #[test]
    fn read_be_u32_reads_correctly() {
        let data = [0xDE, 0xAD, 0xBE, 0xEF];
        assert_eq!(read_be_u32(&data, 0).unwrap(), 0xDEADBEEF);
    }

    #[test]
    fn parse_super_blob_rejects_truncated_header() {
        let data = [0u8; 4];
        assert!(parse_super_blob(&data).is_err());
    }

    #[test]
    fn parse_super_blob_rejects_truncated_index() {
        // Claim 2 blobs but provide no index bytes.
        let mut data = Vec::new();
        data.extend_from_slice(&CSMAGIC_EMBEDDED_SIGNATURE.to_be_bytes());
        data.extend_from_slice(&12u32.to_be_bytes());
        data.extend_from_slice(&2u32.to_be_bytes());
        assert!(parse_super_blob(&data).is_err());
    }
}
