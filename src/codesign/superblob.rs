use crate::codesign::types::{BlobType, CSMAGIC_EMBEDDED_SIGNATURE, SignatureBlob};
use crate::error::{Error, Result};

/// Parse a SuperBlob from raw code signature data.
///
/// All values in the code signature are big-endian regardless of the
/// Mach-O file's endianness.
pub fn parse_super_blob(data: &[u8]) -> Result<Vec<SignatureBlob<'_>>> {
    if data.len() < 12 {
        return Err(Error::Format(
            "code signature too small for SuperBlob header".into(),
        ));
    }

    let magic = read_be_u32(data, 0);
    if magic != CSMAGIC_EMBEDDED_SIGNATURE {
        return Err(Error::Format(format!(
            "expected SuperBlob magic 0xFADE0CC0, got {magic:#010x}"
        )));
    }

    let length = read_be_u32(data, 4) as usize;
    let count = read_be_u32(data, 8) as usize;

    if length > data.len() {
        return Err(Error::Format(format!(
            "SuperBlob length {length} exceeds data size {}",
            data.len()
        )));
    }

    if count > 100 {
        return Err(Error::Format(format!(
            "SuperBlob claims {count} blobs, which is unreasonably large"
        )));
    }

    let mut blobs = Vec::with_capacity(count);
    let index_start = 12;

    for i in 0..count {
        let idx_offset = index_start + i * 8;
        if idx_offset + 8 > data.len() {
            break;
        }

        let blob_type_raw = read_be_u32(data, idx_offset);
        let blob_offset = read_be_u32(data, idx_offset + 4) as usize;

        if blob_offset + 8 > data.len() {
            continue;
        }

        let blob_magic = read_be_u32(data, blob_offset);
        let blob_length = read_be_u32(data, blob_offset + 4) as usize;
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

pub(crate) fn read_be_u32(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap())
}

pub(crate) fn read_be_u64(data: &[u8], offset: usize) -> u64 {
    if offset + 8 > data.len() {
        return 0;
    }
    u64::from_be_bytes(data[offset..offset + 8].try_into().unwrap())
}
