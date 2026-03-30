use crate::constants::*;
use crate::error::{Error, Result};
use crate::model::header::{CpuSubtype, CpuType};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatMagic {
    Fat32,
    Fat64,
}

impl FatMagic {
    /// Construct from a big-endian-interpreted magic value.
    ///
    /// Fat headers are always big-endian on disk. The parser reads the raw
    /// bytes with `Endian::Big`, so this function always receives the canonical
    /// values `FAT_MAGIC` or `FAT_MAGIC_64`.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            FAT_MAGIC => Ok(Self::Fat32),
            FAT_MAGIC_64 => Ok(Self::Fat64),
            _ => Err(Error::Format(format!("unrecognized fat magic: {v:#010x}"))),
        }
    }

    pub fn is_64bit(self) -> bool {
        matches!(self, Self::Fat64)
    }
}

#[derive(Debug, Clone)]
pub struct FatHeader {
    pub magic: FatMagic,
    pub nfat_arch: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ArchSpec {
    pub cpu_type: CpuType,
    pub cpu_subtype: CpuSubtype,
}

impl ArchSpec {
    pub fn is_x86_64(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_X86_64
    }

    pub fn is_arm64(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_ARM64 && self.cpu_subtype.masked() != CPU_SUBTYPE_ARM64E
    }

    pub fn is_arm64e(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_ARM64 && self.cpu_subtype.masked() == CPU_SUBTYPE_ARM64E
    }

    pub fn name(&self) -> String {
        if self.is_arm64e() {
            "arm64e".to_string()
        } else {
            self.cpu_type.name().to_string()
        }
    }
}

impl fmt::Debug for ArchSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ArchSpec({})", self.name())
    }
}

impl fmt::Display for ArchSpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}
