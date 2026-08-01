use crate::error::{Error, Result};
use crate::format::constants::*;
use crate::format::io::endian::Endian;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The Bitness type.
pub enum Bitness {
    /// The Bits32 variant.
    Bits32,
    /// The Bits64 variant.
    Bits64,
}

impl Bitness {
    /// Performs header_size.
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
/// The MagicNumber type.
pub enum MagicNumber {
    /// The MachO32 variant.
    MachO32,
    /// The MachO64 variant.
    MachO64,
    /// The MachO32Swapped variant.
    MachO32Swapped,
    /// The MachO64Swapped variant.
    MachO64Swapped,
}

impl MagicNumber {
    /// Performs from_u32.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            MH_MAGIC => Ok(Self::MachO32),
            MH_MAGIC_64 => Ok(Self::MachO64),
            MH_CIGAM => Ok(Self::MachO32Swapped),
            MH_CIGAM_64 => Ok(Self::MachO64Swapped),
            _ => Err(Error::format(format!(
                "unrecognized Mach-O magic: {v:#010x}"
            ))),
        }
    }

    /// Performs endian.
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

    /// Performs bitness.
    pub fn bitness(self) -> Bitness {
        match self {
            Self::MachO32 | Self::MachO32Swapped => Bitness::Bits32,
            Self::MachO64 | Self::MachO64Swapped => Bitness::Bits64,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The FatMagic type.
pub enum FatMagic {
    /// The Fat32 variant.
    Fat32,
    /// The Fat64 variant.
    Fat64,
}

impl FatMagic {
    /// Performs from_u32.
    pub fn from_u32(v: u32) -> Result<Self> {
        match v {
            FAT_MAGIC => Ok(Self::Fat32),
            FAT_MAGIC_64 => Ok(Self::Fat64),
            _ => Err(Error::format(format!("unrecognized fat magic: {v:#010x}"))),
        }
    }

    /// Performs is_64bit.
    pub fn is_64bit(self) -> bool {
        matches!(self, Self::Fat64)
    }
}

#[derive(Debug, Clone)]
/// The FatHeader type.
pub struct FatHeader {
    magic: FatMagic,
    nfat_arch: u32,
}

impl FatHeader {
    pub(crate) const fn new(magic: FatMagic, nfat_arch: u32) -> Self {
        Self { magic, nfat_arch }
    }

    /// Fat container encoding width.
    pub const fn magic(&self) -> FatMagic {
        self.magic
    }

    /// Number of architecture entries declared by the validated table.
    pub const fn architecture_count(&self) -> u32 {
        self.nfat_arch
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// The CpuType type.
pub struct CpuType(pub i32);

impl CpuType {
    /// Performs name.
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

    /// Performs is_64bit.
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
/// The CpuSubtype type.
pub struct CpuSubtype(pub i32);

impl CpuSubtype {
    /// Returns the subtype with capability bits stripped (high byte masked off).
    pub fn masked(self) -> i32 {
        self.0 & CPU_SUBTYPE_MASK
    }

    /// Performs name.
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

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
/// The ArchSpec type.
pub struct ArchSpec {
    /// The cpu_type field.
    pub cpu_type: CpuType,
    /// The cpu_subtype field.
    pub cpu_subtype: CpuSubtype,
}

impl ArchSpec {
    /// Returns whether a user-facing architecture selector names this slice.
    ///
    /// A CPU-family name selects every subtype in that family, while a known
    /// qualified slice name selects only that subtype. For example, `arm64`
    /// matches both plain arm64 and arm64e slices, whereas `arm64e` matches
    /// only arm64e. Names are matched case-insensitively to preserve the CLI's
    /// established behavior. Unknown subtype names retain the family spelling
    /// and require an exact raw tuple where unambiguous identity matters.
    pub fn matches_selector(&self, selector: &str) -> bool {
        self.cpu_type.name().eq_ignore_ascii_case(selector)
            || self.name().eq_ignore_ascii_case(selector)
    }

    /// Performs is_x86_64.
    pub fn is_x86_64(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_X86_64
    }

    /// Whether this is the Haswell-qualified x86-64 slice known as `x86_64h`.
    pub fn is_x86_64h(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_X86_64 && self.cpu_subtype.masked() == CPU_SUBTYPE_X86_64_H
    }

    /// Performs is_arm64.
    pub fn is_arm64(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_ARM64 && self.cpu_subtype.masked() != CPU_SUBTYPE_ARM64E
    }

    /// Performs is_arm64e.
    pub fn is_arm64e(&self) -> bool {
        self.cpu_type.0 == CPU_TYPE_ARM64 && self.cpu_subtype.masked() == CPU_SUBTYPE_ARM64E
    }

    /// Performs name.
    pub fn name(&self) -> String {
        if self.is_arm64e() {
            "arm64e".to_string()
        } else if self.is_x86_64h() {
            "x86_64h".to_string()
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The FileType type.
pub enum FileType {
    /// The Object variant.
    Object,
    /// The Execute variant.
    Execute,
    /// The Fvmlib variant.
    Fvmlib,
    /// The Core variant.
    Core,
    /// The Preload variant.
    Preload,
    /// The Dylib variant.
    Dylib,
    /// The Dylinker variant.
    Dylinker,
    /// The Bundle variant.
    Bundle,
    /// The DylibStub variant.
    DylibStub,
    /// The Dsym variant.
    Dsym,
    /// The KextBundle variant.
    KextBundle,
    /// The Fileset variant.
    Fileset,
    /// The GpuExecute variant.
    GpuExecute,
    /// The GpuDylib variant.
    GpuDylib,
    /// The Unknown variant.
    Unknown(u32),
}

impl FileType {
    /// Performs from_u32.
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

    /// Performs name.
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
/// The MachoHeader type.
pub struct MachoHeader {
    pub(crate) magic: MagicNumber,
    pub(crate) cpu_type: CpuType,
    pub(crate) cpu_subtype: CpuSubtype,
    pub(crate) file_type: FileType,
    pub(crate) ncmds: u32,
    pub(crate) sizeofcmds: u32,
    pub(crate) flags: MachoHeaderFlags,
    pub(crate) reserved: u32,
}

impl MachoHeader {
    /// Parsed Mach-O magic and byte-order encoding.
    pub const fn magic(&self) -> MagicNumber {
        self.magic
    }
    /// Declared CPU family.
    pub const fn cpu_type(&self) -> CpuType {
        self.cpu_type
    }
    /// Declared CPU subtype.
    pub const fn cpu_subtype(&self) -> CpuSubtype {
        self.cpu_subtype
    }
    /// Qualified architecture identity for this Mach-O slice.
    pub const fn arch_spec(&self) -> ArchSpec {
        ArchSpec {
            cpu_type: self.cpu_type,
            cpu_subtype: self.cpu_subtype,
        }
    }
    /// Declared Mach-O file type.
    pub const fn file_type(&self) -> FileType {
        self.file_type
    }
    /// Number of validated load commands.
    pub const fn load_command_count(&self) -> u32 {
        self.ncmds
    }
    /// Declared load-command byte size.
    pub const fn load_commands_size(&self) -> u32 {
        self.sizeofcmds
    }
    /// Validated header flags.
    pub const fn flags(&self) -> MachoHeaderFlags {
        self.flags
    }
    /// Reserved 64-bit header word.
    pub const fn reserved(&self) -> u32 {
        self.reserved
    }
}
