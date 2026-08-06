//! Fast instruction identity and physical encoding backed by mkasm-generated tables.

use super::{Arch, DecodeError, EncodeError};

/// Architecture-neutral identity returned by the generated decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodingIdentity {
    /// Architecture mnemonic, such as `NOP` or `MOV`.
    pub mnemonic: &'static str,
    /// Stable architecture-corpus encoding identifier.
    pub encoding_id: &'static str,
    /// Stable x86 form identifier, when decoding x86-64.
    pub form_id: Option<&'static str>,
    /// ARM instruction class, when decoding ARM64.
    pub class: Option<&'static str>,
    /// Canonical ARM encoding for an alias, when present.
    pub alias_of: Option<&'static str>,
    /// Encoded instruction length in bytes.
    pub length: usize,
    /// Number of other corpus encodings that also matched.
    pub alternatives: usize,
    /// Generated x86 form-table index, usable with [`encode_x86_form`].
    pub form_index: Option<u32>,
}

/// Physical x86 encoder fields generated from opcodesDB.
pub use mkasm_x86_64::EncodeFields as X86EncodeFields;

/// A non-allocating x86 encoding result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EncodedX86 {
    bytes: [u8; 15],
    len: usize,
}

impl EncodedX86 {
    /// Returns the encoded instruction bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Returns the encoded instruction length.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the result contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Identify the architecture encoding at the start of `bytes` using generated tables.
///
/// This is the fast, allocation-free layer. Use [`super::decode_one`] when operand,
/// control-flow, register-access, or memory-access semantics are also required.
pub fn identify_encoding(bytes: &[u8], arch: Arch) -> Result<EncodingIdentity, DecodeError> {
    match arch {
        Arch::X86_64 => identify_x86(bytes),
        Arch::Arm64 | Arch::Arm64e => identify_arm64(bytes),
    }
}

/// Encode an ARM64 instruction whose corpus encoding has no variable fields.
pub fn encode_arm64_fixed(encoding_id: &str) -> Result<[u8; 4], EncodeError> {
    mkasm_aarch64::encode_fixed(encoding_id)
        .map(u32::to_le_bytes)
        .map_err(|error| EncodeError {
            message: error.to_string(),
        })
}

/// Encode an ARM64 instruction by assigning its physical bit fields.
pub fn encode_arm64_fields(
    encoding_id: &str,
    fields: &[(&str, u64)],
) -> Result<[u8; 4], EncodeError> {
    mkasm_aarch64::encode_with_fields(encoding_id, fields)
        .map(u32::to_le_bytes)
        .map_err(|error| EncodeError {
            message: error.to_string(),
        })
}

/// Encode a generated x86 form into an inline 15-byte buffer.
///
/// `form_index` is obtained from [`EncodingIdentity::form_index`]. The field set
/// defaults to 64-bit mode and describes physical prefix, ModR/M, SIB,
/// displacement, immediate, and register bits.
pub fn encode_x86_form(
    form_index: u32,
    fields: X86EncodeFields,
) -> Result<EncodedX86, EncodeError> {
    let mut bytes = [0u8; 15];
    let len = mkasm_x86_64::encode(form_index as usize, fields, &mut bytes).map_err(|error| {
        EncodeError {
            message: format!("{error:?}"),
        }
    })?;
    Ok(EncodedX86 { bytes, len })
}

fn identify_arm64(bytes: &[u8]) -> Result<EncodingIdentity, DecodeError> {
    let word = bytes.get(..4).ok_or_else(|| DecodeError {
        message: "truncated ARM64 instruction".to_string(),
    })?;
    let decoded =
        mkasm_aarch64::decode(u32::from_le_bytes(word.try_into().unwrap())).map_err(|error| {
            DecodeError {
                message: error.to_string(),
            }
        })?;
    Ok(EncodingIdentity {
        mnemonic: decoded.mnemonic,
        encoding_id: decoded.encoding_id,
        form_id: None,
        class: Some(decoded.class),
        alias_of: (!decoded.alias_of.is_empty()).then_some(decoded.alias_of),
        length: 4,
        alternatives: decoded.ambiguous.len(),
        form_index: None,
    })
}

fn identify_x86(bytes: &[u8]) -> Result<EncodingIdentity, DecodeError> {
    let decoded =
        mkasm_x86_64::decode(bytes, mkasm_x86_64::Mode::Mode64).map_err(|error| DecodeError {
            message: format!("{error:?}"),
        })?;
    let encoding = decoded.encoding();
    Ok(EncodingIdentity {
        mnemonic: encoding.mnemonic,
        encoding_id: encoding.id,
        form_id: Some(encoding.form_id),
        class: None,
        alias_of: None,
        length: decoded.length as usize,
        alternatives: decoded.alternatives as usize,
        form_index: Some(decoded.form_index),
    })
}
