use crate::codesign::superblob::read_be_u32;
use crate::codesign::types::{
    BlobType, CS_REQUIREMENT_TYPE_DESIGNATED, CSMAGIC_REQUIREMENT, CSMAGIC_REQUIREMENTS,
    SignatureBlob,
};
use crate::error::{Error, Result};

const REQUIREMENTS_HEADER_SIZE: usize = 12;
const REQUIREMENT_INDEX_SIZE: usize = 8;
const GENERIC_BLOB_HEADER_SIZE: usize = 8;
const MAX_REQUIREMENT_COUNT: usize = 16;

/// Locate the designated requirement inside the requirements set.
///
/// The returned bytes are the complete canonical `CSMAGIC_REQUIREMENT` blob,
/// including its eight-byte magic and length header. A missing requirements
/// slot or a requirements set without a designated entry returns `None`;
/// malformed or duplicate structures are rejected.
pub fn extract_designated_requirement<'data>(
    blobs: &[SignatureBlob<'data>],
) -> Result<Option<&'data [u8]>> {
    let mut requirement_slots = blobs
        .iter()
        .filter(|blob| blob.blob_type == BlobType::Requirements);
    let Some(requirements) = requirement_slots.next() else {
        return Ok(None);
    };
    if requirement_slots.next().is_some() {
        return Err(Error::format(
            "code signature contains duplicate requirements slots",
        ));
    }

    parse_designated_requirement(requirements.data)
}

fn parse_designated_requirement(data: &[u8]) -> Result<Option<&[u8]>> {
    if data.len() < REQUIREMENTS_HEADER_SIZE {
        return Err(Error::format(
            "requirements blob is too small for its header",
        ));
    }
    let magic = read_be_u32(data, 0)?;
    if magic != CSMAGIC_REQUIREMENTS {
        return Err(Error::format(format!(
            "expected requirements magic {CSMAGIC_REQUIREMENTS:#010x}, got {magic:#010x}"
        )));
    }

    let declared_length = read_be_u32(data, 4)? as usize;
    if declared_length < REQUIREMENTS_HEADER_SIZE || declared_length > data.len() {
        return Err(Error::format(format!(
            "requirements length {declared_length} is outside the available {} bytes",
            data.len()
        )));
    }

    let count = read_be_u32(data, 8)? as usize;
    if count > MAX_REQUIREMENT_COUNT {
        return Err(Error::format(format!(
            "requirements blob claims {count} entries, exceeding the supported maximum of {MAX_REQUIREMENT_COUNT}"
        )));
    }
    let index_bytes = count
        .checked_mul(REQUIREMENT_INDEX_SIZE)
        .ok_or_else(|| Error::format("requirements index size overflows"))?;
    let index_end = REQUIREMENTS_HEADER_SIZE
        .checked_add(index_bytes)
        .ok_or_else(|| Error::format("requirements index extent overflows"))?;
    if index_end > declared_length {
        return Err(Error::format(
            "requirements index extends beyond the declared blob length",
        ));
    }

    let mut designated = None;
    for index in 0..count {
        let entry = REQUIREMENTS_HEADER_SIZE + index * REQUIREMENT_INDEX_SIZE;
        let requirement_type = read_be_u32(data, entry)?;
        if requirement_type != CS_REQUIREMENT_TYPE_DESIGNATED {
            continue;
        }
        if designated.is_some() {
            return Err(Error::format(
                "requirements blob contains duplicate designated requirements",
            ));
        }

        let offset = read_be_u32(data, entry + 4)? as usize;
        let header_end = offset
            .checked_add(GENERIC_BLOB_HEADER_SIZE)
            .ok_or_else(|| Error::format("designated requirement header overflows"))?;
        if offset < index_end || header_end > declared_length {
            return Err(Error::format(
                "designated requirement offset is outside the requirements blob",
            ));
        }
        let requirement_magic = read_be_u32(data, offset)?;
        if requirement_magic != CSMAGIC_REQUIREMENT {
            return Err(Error::format(format!(
                "expected designated requirement magic {CSMAGIC_REQUIREMENT:#010x}, got {requirement_magic:#010x}"
            )));
        }
        let requirement_length = read_be_u32(data, offset + 4)? as usize;
        if requirement_length < GENERIC_BLOB_HEADER_SIZE {
            return Err(Error::format(
                "designated requirement length is smaller than its header",
            ));
        }
        let end = offset
            .checked_add(requirement_length)
            .ok_or_else(|| Error::format("designated requirement extent overflows"))?;
        if end > declared_length {
            return Err(Error::format(
                "designated requirement extends beyond the requirements blob",
            ));
        }
        designated = Some(&data[offset..end]);
    }

    Ok(designated)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn requirements_blob(entries: &[(u32, &[u8])]) -> Vec<u8> {
        let header_len = REQUIREMENTS_HEADER_SIZE + entries.len() * REQUIREMENT_INDEX_SIZE;
        let total_len = header_len + entries.iter().map(|(_, blob)| blob.len()).sum::<usize>();
        let mut data = Vec::with_capacity(total_len);
        data.extend_from_slice(&CSMAGIC_REQUIREMENTS.to_be_bytes());
        data.extend_from_slice(&(total_len as u32).to_be_bytes());
        data.extend_from_slice(&(entries.len() as u32).to_be_bytes());

        let mut offset = header_len;
        for (requirement_type, blob) in entries {
            data.extend_from_slice(&requirement_type.to_be_bytes());
            data.extend_from_slice(&(offset as u32).to_be_bytes());
            offset += blob.len();
        }
        for (_, blob) in entries {
            data.extend_from_slice(blob);
        }
        data
    }

    fn requirement(payload: &[u8]) -> Vec<u8> {
        let length = GENERIC_BLOB_HEADER_SIZE + payload.len();
        [
            CSMAGIC_REQUIREMENT.to_be_bytes().as_slice(),
            (length as u32).to_be_bytes().as_slice(),
            payload,
        ]
        .concat()
    }

    #[test]
    fn returns_the_complete_designated_requirement_blob() {
        let designated = requirement(&[0, 0, 0, 1]);
        let library = requirement(&[0, 0, 0, 2]);
        let data = requirements_blob(&[
            (4, library.as_slice()),
            (CS_REQUIREMENT_TYPE_DESIGNATED, designated.as_slice()),
        ]);

        assert_eq!(
            parse_designated_requirement(&data).unwrap(),
            Some(designated.as_slice())
        );
    }

    #[test]
    fn missing_designated_requirement_is_none() {
        let library = requirement(&[0, 0, 0, 2]);
        let data = requirements_blob(&[(4, library.as_slice())]);
        assert_eq!(parse_designated_requirement(&data).unwrap(), None);
    }

    #[test]
    fn rejects_duplicate_and_out_of_bounds_designated_requirements() {
        let designated = requirement(&[0, 0, 0, 1]);
        let duplicate = requirements_blob(&[
            (CS_REQUIREMENT_TYPE_DESIGNATED, designated.as_slice()),
            (CS_REQUIREMENT_TYPE_DESIGNATED, designated.as_slice()),
        ]);
        assert!(parse_designated_requirement(&duplicate).is_err());

        let mut out_of_bounds =
            requirements_blob(&[(CS_REQUIREMENT_TYPE_DESIGNATED, designated.as_slice())]);
        out_of_bounds[16..20].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(parse_designated_requirement(&out_of_bounds).is_err());
    }
}
