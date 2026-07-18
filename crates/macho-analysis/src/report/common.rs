//! Common validated report values.

#![allow(missing_docs)]

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Validation failure for a common wire value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WireValueError {
    #[error("expected exactly 64 lowercase hexadecimal characters")]
    Digest,
    #[error("expected an uppercase canonical UUID")]
    Uuid,
    #[error("collection must not be empty")]
    Empty,
    #[error("collection must contain at least two distinct values")]
    AtLeastTwo,
    #[error("invalid {kind}: {detail}")]
    Text {
        kind: &'static str,
        detail: &'static str,
    },
    #[error("address range end must be greater than its start")]
    AddressRange,
    #[error("expected a lowercase even-length hexadecimal byte string")]
    Bytes,
}

/// A canonical lowercase hexadecimal byte string.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct HexBytes(String);

impl HexBytes {
    pub fn from_bytes(bytes: &[u8]) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut value = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            value.push(HEX[(byte >> 4) as usize] as char);
            value.push(HEX[(byte & 0x0f) as usize] as char);
        }
        Self(value)
    }

    pub fn new(value: impl Into<String>) -> Result<Self, WireValueError> {
        let value = value.into();
        if value.len() % 2 == 0
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            Ok(Self(value))
        } else {
            Err(WireValueError::Bytes)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

macro_rules! digest_type {
    ($name:ident) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, WireValueError> {
                let value = value.into();
                if value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                {
                    Ok(Self(value))
                } else {
                    Err(WireValueError::Digest)
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

digest_type!(ObservationId);
digest_type!(EntityId);
digest_type!(FactId);
digest_type!(EvidenceId);
digest_type!(DiagnosticId);
digest_type!(RecoveryGapId);
digest_type!(RequestDigest);
digest_type!(ObjCEntityId);
digest_type!(ObjCMemberId);
digest_type!(ObjCObservationId);
digest_type!(ObjCEvidenceId);
digest_type!(ObjCDiagnosticId);
digest_type!(SwiftEntityId);
digest_type!(SwiftObservationId);
digest_type!(SwiftEvidenceId);
digest_type!(SwiftDiagnosticId);
digest_type!(SwiftGapId);
digest_type!(HypothesisId);
digest_type!(ContentHash);

macro_rules! exact_version {
    ($name:ident, $expected:literal) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(u32);

        impl $name {
            pub const CURRENT: Self = Self($expected);
            pub const fn get(self) -> u32 {
                self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = u32::deserialize(deserializer)?;
                if value == $expected {
                    Ok(Self(value))
                } else {
                    Err(serde::de::Error::custom(format!(
                        "unsupported schema version {value}; expected {}",
                        $expected
                    )))
                }
            }
        }
    };
}

exact_version!(RecoverySchemaVersion, 1);
exact_version!(ObjCReportVersion, 1);
exact_version!(SwiftReportVersion, 1);
exact_version!(HypothesisBundleVersion, 1);
exact_version!(ModelResponseVersion, 1);
exact_version!(HypothesisReportVersion, 1);
exact_version!(SnapshotSchemaVersion, 3);

/// A validated non-empty order-bearing collection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    pub fn new(values: Vec<T>) -> Result<Self, WireValueError> {
        if values.is_empty() {
            Err(WireValueError::Empty)
        } else {
            Ok(Self(values))
        }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    pub fn as_mut_slice(&mut self) -> &mut [T] {
        &mut self.0
    }

    pub fn push(&mut self, value: T) {
        self.0.push(value);
    }

    pub fn into_vec(self) -> Vec<T> {
        self.0
    }
}

impl<T: Serialize> Serialize for NonEmpty<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for NonEmpty<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Vec::<T>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// A validated collection with at least two distinct values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AtLeastTwo<T>(Vec<T>);

impl<T: PartialEq> AtLeastTwo<T> {
    pub fn new(values: Vec<T>) -> Result<Self, WireValueError> {
        let distinct = values
            .iter()
            .enumerate()
            .all(|(index, value)| !values[..index].contains(value));
        if values.len() < 2 || !distinct {
            Err(WireValueError::AtLeastTwo)
        } else {
            Ok(Self(values))
        }
    }

    pub fn as_slice(&self) -> &[T] {
        &self.0
    }
}

impl<T: Serialize> Serialize for AtLeastTwo<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl<'de, T: Deserialize<'de> + PartialEq> Deserialize<'de> for AtLeastTwo<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(Vec::<T>::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainerKind {
    Thin,
    Fat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityStability {
    CrossBuild,
    SliceOnly,
    Ambiguous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceStrength {
    Exact,
    Correlated,
    Inferred,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Architecture {
    pub cpu_type: i32,
    pub cpu_subtype: i32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CanonicalUuid(String);

impl CanonicalUuid {
    pub fn new(value: impl Into<String>) -> Result<Self, WireValueError> {
        let value = value.into();
        let valid = value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte),
            });
        valid.then_some(Self(value)).ok_or(WireValueError::Uuid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageIdentity {
    pub content_sha256: ContentHash,
    pub byte_len: u64,
    pub container: ContainerKind,
    pub slice_index: u32,
    pub architecture: Architecture,
    pub uuid: Option<CanonicalUuid>,
}

pub type ImageInputIdentity = ImageIdentity;

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportSliceIdentity {
    pub image: ImageIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportContainerIdentity {
    pub content_sha256: ContentHash,
    pub byte_len: u64,
    pub container: ContainerKind,
    pub slice_count: u32,
}

macro_rules! text_type {
    ($name:ident, $kind:literal, $max:literal, $predicate:expr) => {
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, WireValueError> {
                let value = value.into();
                if !value.is_empty() && value.len() <= $max && ($predicate)(&value) {
                    Ok(Self(value))
                } else {
                    Err(WireValueError::Text {
                        kind: $kind,
                        detail: "value violates length or character constraints",
                    })
                }
            }
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

text_type!(
    LogicalInputLabel,
    "logical input label",
    128,
    |value: &str| { !value.contains(['/', '\0']) }
);
text_type!(MachName, "Mach name", 16, |value: &str| !value
    .contains('\0'));
text_type!(Identifier, "identifier", 255, |value: &str| {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|first| first == '_' || first.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
});
text_type!(ValidatedGlob, "glob", 1024, |value: &str| {
    !value.contains(['/', '\\', '\0'])
});

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SectionIdentity {
    pub segment: MachName,
    pub section: MachName,
    pub ordinal: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AddressRange {
    pub start: u64,
    pub end_exclusive: u64,
}

impl AddressRange {
    pub fn new(start: u64, end_exclusive: u64) -> Result<Self, WireValueError> {
        (end_exclusive > start)
            .then_some(Self {
                start,
                end_exclusive,
            })
            .ok_or(WireValueError::AddressRange)
    }
}

impl<'de> Deserialize<'de> for AddressRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            start: u64,
            end_exclusive: u64,
        }
        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.start, wire.end_exclusive).map_err(serde::de::Error::custom)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityLocation {
    pub address: Option<u64>,
    pub section: Option<SectionIdentity>,
    pub range: Option<AddressRange>,
}
