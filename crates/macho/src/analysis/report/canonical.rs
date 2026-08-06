//! Canonical JSON encoding used for report identities and digests.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A value cannot be encoded by the canonical integer-only profile.
#[derive(Debug, thiserror::Error)]
pub enum CanonicalJsonError {
    /// Serialization failed.
    #[error("serialize canonical JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    /// The profile rejects floating-point numbers.
    #[error("canonical report JSON does not permit floating-point numbers")]
    FloatingPoint,
}

/// Serializes `value` as compact UTF-8 JSON with recursively sorted keys.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalJsonError> {
    let value = serde_json::to_value(value)?;
    reject_floats(&value)?;
    Ok(serde_json::to_vec(&value)?)
}

/// Computes a lowercase SHA-256 digest without per-byte formatting allocation.
pub fn sha256_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn reject_floats(value: &Value) -> Result<(), CanonicalJsonError> {
    match value {
        Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            Err(CanonicalJsonError::FloatingPoint)
        }
        Value::Array(values) => values.iter().try_for_each(reject_floats),
        Value::Object(values) => values.values().try_for_each(reject_floats),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn object_keys_are_canonical_and_floats_are_rejected() {
        assert_eq!(
            canonical_json(&json!({"z": 1, "a": {"b": 2, "a": 1}})).unwrap(),
            br#"{"a":{"a":1,"b":2},"z":1}"#
        );
        assert!(matches!(
            canonical_json(&json!({"value": 1.5})),
            Err(CanonicalJsonError::FloatingPoint)
        ));
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
