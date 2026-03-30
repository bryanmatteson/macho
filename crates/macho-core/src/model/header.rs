use crate::constants::*;
use crate::error::{Error, Result};
use crate::io::endian::Endian;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bitness {
    Bits32,
    Bits64,
}

impl Bitness {
    pub fn header_size(self) -> usize {
        match self {
            Bitness::Bits32 => 28,
            Bitness::Bits64 => 32,
        }
    }
}

impl fmt::Display for Bitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bitness::Bits32 => write!(f, "32-bit"),
            Bitness::Bits64 => write!(f, "64-bit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MagicNumber {
    MachO32,
    MachO64,
    MachO32Swapped,
    MachO64Swapped,
}

impl MagicNumber {
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            MH_MAGIC => Ok(Self::MachO32),
            MH_MAGIC_64 => Ok(Self::MachO64),
            MH_CIGAM => Ok(Self::MachO32Swapped),
            MH_CIGAM_64 => Ok(Self::MachO64Swapped),
            _ => Err(Error::Format(format!(
                "unrecognized Mach-O magic: {v:#010x}"
            ))),
        }
    }

    pub fn endian(self) -> Endian {
        match self {
            Self::MachO32 | Self::MachO64 => {
                // Native byte order magic means the file matches the host.
                // On LE hosts (all modern Apple), non-swapped = Little.
                // On BE hosts, non-swapped = Big.
                if cfg!(target_endian = "little") {
                    Endian::Little
                } else {
                    Endian::Big
                }
            }
            Self::MachO32Swapped | Self::MachO64Swapped => {
                if cfg!(target_endian = "little") {
                    Endian::Big
                } else {
                    Endian::Little
                }
            }
        }
    }

    pub fn bitness(self) -> Bitness {
        match self {
            Self::MachO32 | Self::MachO32Swapped => Bitness::Bits32,
            Self::MachO64 | Self::MachO64Swapped => Bitness::Bits64,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpuType(pub i32);

impl CpuType {
    pub fn name(self) -> &'static str {
        match self.0 {
            CPU_TYPE_X86 => "x86",
            CPU_TYPE_X86_64 => "x86_64",
            CPU_TYPE_ARM => "arm",
            CPU_TYPE_ARM64 => "arm64",
            CPU_TYPE_ARM64_32 => "arm64_32",
            CPU_TYPE_POWERPC => "ppc",
            CPU_TYPE_POWERPC64 => "ppc64",
            _ => "unknown",
        }
    }

    pub fn is_64bit(self) -> bool {
        (self.0 & CPU_ARCH_ABI64) != 0
    }
}

impl fmt::Debug for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CpuType({}, {})", self.name(), self.0)
    }
}

impl fmt::Display for CpuType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CpuSubtype(pub i32);

impl CpuSubtype {
    /// Returns the subtype with capability bits stripped (high byte masked off).
    pub fn masked(self) -> i32 {
        self.0 & CPU_SUBTYPE_MASK
    }

    pub fn name(self, cpu_type: CpuType) -> &'static str {
        let masked = self.masked();
        match (cpu_type.0, masked) {
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_ALL) => "all",
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64_V8) => "v8",
            (CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E) => "arm64e",
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_ALL) => "all",
            (CPU_TYPE_X86_64, CPU_SUBTYPE_X86_64_H) => "haswell",
            (_, CPU_SUBTYPE_ALL) => "all",
            _ => "unknown",
        }
    }
}

impl fmt::Debug for CpuSubtype {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CpuSubtype({:#x})", self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    Object,
    Execute,
    Fvmlib,
    Core,
    Preload,
    Dylib,
    Dylinker,
    Bundle,
    DylibStub,
    Dsym,
    KextBundle,
    Fileset,
    GpuExecute,
    GpuDylib,
    Unknown(u32),
}

impl FileType {
    pub fn from_u32(v: u32) -> Self {
        match v {
            MH_OBJECT => Self::Object,
            MH_EXECUTE => Self::Execute,
            MH_FVMLIB => Self::Fvmlib,
            MH_CORE => Self::Core,
            MH_PRELOAD => Self::Preload,
            MH_DYLIB => Self::Dylib,
            MH_DYLINKER => Self::Dylinker,
            MH_BUNDLE => Self::Bundle,
            MH_DYLIB_STUB => Self::DylibStub,
            MH_DSYM => Self::Dsym,
            MH_KEXT_BUNDLE => Self::KextBundle,
            MH_FILESET => Self::Fileset,
            MH_GPU_EXECUTE => Self::GpuExecute,
            MH_GPU_DYLIB => Self::GpuDylib,
            _ => Self::Unknown(v),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Object => "MH_OBJECT",
            Self::Execute => "MH_EXECUTE",
            Self::Fvmlib => "MH_FVMLIB",
            Self::Core => "MH_CORE",
            Self::Preload => "MH_PRELOAD",
            Self::Dylib => "MH_DYLIB",
            Self::Dylinker => "MH_DYLINKER",
            Self::Bundle => "MH_BUNDLE",
            Self::DylibStub => "MH_DYLIB_STUB",
            Self::Dsym => "MH_DSYM",
            Self::KextBundle => "MH_KEXT_BUNDLE",
            Self::Fileset => "MH_FILESET",
            Self::GpuExecute => "MH_GPU_EXECUTE",
            Self::GpuDylib => "MH_GPU_DYLIB",
            Self::Unknown(_) => "MH_UNKNOWN",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MachHeader {
    pub magic: MagicNumber,
    pub cpu_type: CpuType,
    pub cpu_subtype: CpuSubtype,
    pub file_type: FileType,
    pub ncmds: u32,
    pub sizeofcmds: u32,
    pub flags: MachHeaderFlags,
    pub reserved: u32,
}
