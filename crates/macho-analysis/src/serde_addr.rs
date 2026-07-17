use serde::{Deserialize, Deserializer, Serializer};

use crate::model::addr::{ThinFileOffset, Va};

pub fn va<S>(value: &Va, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(value.0)
}

pub fn va_from<'de, D>(deserializer: D) -> Result<Va, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(deserializer).map(Va)
}

pub fn thin_file_offset<S>(value: &ThinFileOffset, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_u64(value.0)
}

pub fn thin_file_offset_from<'de, D>(deserializer: D) -> Result<ThinFileOffset, D::Error>
where
    D: Deserializer<'de>,
{
    u64::deserialize(deserializer).map(ThinFileOffset)
}
