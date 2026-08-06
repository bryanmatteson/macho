use crate::core::format::constants::*;
use crate::core::model::addr::ThinFileOffset;
use std::fmt;

#[derive(Debug, Clone)]
/// The ParsedLoadCommand type.
pub struct ParsedLoadCommand {
    pub(crate) kind: LoadCommand,
    pub(crate) file_offset: ThinFileOffset,
    pub(crate) raw_size: u32,
}

impl ParsedLoadCommand {
    /// Parsed command payload.
    pub fn kind(&self) -> &LoadCommand {
        &self.kind
    }
    /// Slice-relative byte offset of the command header.
    pub const fn file_offset(&self) -> ThinFileOffset {
        self.file_offset
    }
    /// Validated command size in bytes.
    pub const fn raw_size(&self) -> u32 {
        self.raw_size
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The LoadCommand type.
pub enum LoadCommand {
    /// The Segment32 variant.
    Segment32(SegmentCommandData),
    /// The Segment64 variant.
    Segment64(SegmentCommandData),
    /// The Symtab variant.
    Symtab(SymtabData),
    /// The Dysymtab variant.
    Dysymtab(DysymtabData),
    /// The DyldInfo variant.
    DyldInfo(DyldInfoData),
    /// The DyldInfoOnly variant.
    DyldInfoOnly(DyldInfoData),
    /// The DyldExportsTrie variant.
    DyldExportsTrie(LinkeditData),
    /// The DyldChainedFixups variant.
    DyldChainedFixups(LinkeditData),
    /// The Main variant.
    Main(EntryPointData),
    /// The Uuid variant.
    Uuid(UuidData),
    /// The BuildVersion variant.
    BuildVersion(BuildVersionData),
    /// The SourceVersion variant.
    SourceVersion(SourceVersionData),
    /// The VersionMinMacOS variant.
    VersionMinMacOS(VersionMinData),
    /// The VersionMinIOS variant.
    VersionMinIOS(VersionMinData),
    /// The VersionMinTvOS variant.
    VersionMinTvOS(VersionMinData),
    /// The VersionMinWatchOS variant.
    VersionMinWatchOS(VersionMinData),
    /// The IdDylib variant.
    IdDylib(DylibData),
    /// The LoadDylib variant.
    LoadDylib(DylibData),
    /// The LoadWeakDylib variant.
    LoadWeakDylib(DylibData),
    /// The ReexportDylib variant.
    ReexportDylib(DylibData),
    /// The LazyLoadDylib variant.
    LazyLoadDylib(DylibData),
    /// The LoadUpwardDylib variant.
    LoadUpwardDylib(DylibData),
    /// The Rpath variant.
    Rpath(StringData),
    /// The TargetTriple variant.
    TargetTriple(StringData),
    /// The IdDylinker variant.
    IdDylinker(StringData),
    /// The LoadDylinker variant.
    LoadDylinker(StringData),
    /// The DyldEnvironment variant.
    DyldEnvironment(StringData),
    /// The SubFramework variant.
    SubFramework(StringData),
    /// The SubUmbrella variant.
    SubUmbrella(StringData),
    /// The SubClient variant.
    SubClient(StringData),
    /// The SubLibrary variant.
    SubLibrary(StringData),
    /// The CodeSignature variant.
    CodeSignature(LinkeditData),
    /// The SegmentSplitInfo variant.
    SegmentSplitInfo(LinkeditData),
    /// The FunctionStarts variant.
    FunctionStarts(LinkeditData),
    /// The DataInCode variant.
    DataInCode(LinkeditData),
    /// The DylibCodeSignDrs variant.
    DylibCodeSignDrs(LinkeditData),
    /// The LinkerOptimizationHint variant.
    LinkerOptimizationHint(LinkeditData),
    /// The AtomInfo variant.
    AtomInfo(LinkeditData),
    /// The FunctionVariants variant.
    FunctionVariants(LinkeditData),
    /// The FunctionVariantFixups variant.
    FunctionVariantFixups(LinkeditData),
    /// The EncryptionInfo variant.
    EncryptionInfo(EncryptionInfoData),
    /// The EncryptionInfo64 variant.
    EncryptionInfo64(EncryptionInfoData),
    /// The LinkerOption variant.
    LinkerOption(LinkerOptionData),
    /// The Note variant.
    Note(NoteData),
    /// The FilesetEntry variant.
    FilesetEntry(FilesetEntryData),
    /// The PrebindCksum variant.
    PrebindCksum(PrebindCksumData),
    /// The TwolevelHints variant.
    TwolevelHints(TwolevelHintsData),
    /// The Routines variant.
    Routines(RoutinesData),
    /// The Routines64 variant.
    Routines64(RoutinesData),
    /// The Thread variant.
    Thread(RawData),
    /// The UnixThread variant.
    UnixThread(RawData),
    /// The PreboundDylib variant.
    PreboundDylib(RawData),
    /// The Ident variant.
    Ident(RawData),
    /// The Unknown variant.
    Unknown(UnknownLoadCommand),
}

impl LoadCommand {
    /// Performs name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Segment32(_) => "LC_SEGMENT",
            Self::Segment64(_) => "LC_SEGMENT_64",
            Self::Symtab(_) => "LC_SYMTAB",
            Self::Dysymtab(_) => "LC_DYSYMTAB",
            Self::DyldInfo(_) => "LC_DYLD_INFO",
            Self::DyldInfoOnly(_) => "LC_DYLD_INFO_ONLY",
            Self::DyldExportsTrie(_) => "LC_DYLD_EXPORTS_TRIE",
            Self::DyldChainedFixups(_) => "LC_DYLD_CHAINED_FIXUPS",
            Self::Main(_) => "LC_MAIN",
            Self::Uuid(_) => "LC_UUID",
            Self::BuildVersion(_) => "LC_BUILD_VERSION",
            Self::SourceVersion(_) => "LC_SOURCE_VERSION",
            Self::VersionMinMacOS(_) => "LC_VERSION_MIN_MACOSX",
            Self::VersionMinIOS(_) => "LC_VERSION_MIN_IPHONEOS",
            Self::VersionMinTvOS(_) => "LC_VERSION_MIN_TVOS",
            Self::VersionMinWatchOS(_) => "LC_VERSION_MIN_WATCHOS",
            Self::IdDylib(_) => "LC_ID_DYLIB",
            Self::LoadDylib(_) => "LC_LOAD_DYLIB",
            Self::LoadWeakDylib(_) => "LC_LOAD_WEAK_DYLIB",
            Self::ReexportDylib(_) => "LC_REEXPORT_DYLIB",
            Self::LazyLoadDylib(_) => "LC_LAZY_LOAD_DYLIB",
            Self::LoadUpwardDylib(_) => "LC_LOAD_UPWARD_DYLIB",
            Self::Rpath(_) => "LC_RPATH",
            Self::TargetTriple(_) => "LC_TARGET_TRIPLE",
            Self::IdDylinker(_) => "LC_ID_DYLINKER",
            Self::LoadDylinker(_) => "LC_LOAD_DYLINKER",
            Self::DyldEnvironment(_) => "LC_DYLD_ENVIRONMENT",
            Self::SubFramework(_) => "LC_SUB_FRAMEWORK",
            Self::SubUmbrella(_) => "LC_SUB_UMBRELLA",
            Self::SubClient(_) => "LC_SUB_CLIENT",
            Self::SubLibrary(_) => "LC_SUB_LIBRARY",
            Self::CodeSignature(_) => "LC_CODE_SIGNATURE",
            Self::SegmentSplitInfo(_) => "LC_SEGMENT_SPLIT_INFO",
            Self::FunctionStarts(_) => "LC_FUNCTION_STARTS",
            Self::DataInCode(_) => "LC_DATA_IN_CODE",
            Self::DylibCodeSignDrs(_) => "LC_DYLIB_CODE_SIGN_DRS",
            Self::LinkerOptimizationHint(_) => "LC_LINKER_OPTIMIZATION_HINT",
            Self::AtomInfo(_) => "LC_ATOM_INFO",
            Self::FunctionVariants(_) => "LC_FUNCTION_VARIANTS",
            Self::FunctionVariantFixups(_) => "LC_FUNCTION_VARIANT_FIXUPS",
            Self::EncryptionInfo(_) => "LC_ENCRYPTION_INFO",
            Self::EncryptionInfo64(_) => "LC_ENCRYPTION_INFO_64",
            Self::LinkerOption(_) => "LC_LINKER_OPTION",
            Self::Note(_) => "LC_NOTE",
            Self::FilesetEntry(_) => "LC_FILESET_ENTRY",
            Self::PrebindCksum(_) => "LC_PREBIND_CKSUM",
            Self::TwolevelHints(_) => "LC_TWOLEVEL_HINTS",
            Self::Routines(_) => "LC_ROUTINES",
            Self::Routines64(_) => "LC_ROUTINES_64",
            Self::Thread(_) => "LC_THREAD",
            Self::UnixThread(_) => "LC_UNIXTHREAD",
            Self::PreboundDylib(_) => "LC_PREBOUND_DYLIB",
            Self::Ident(_) => "LC_IDENT",
            Self::Unknown(_) => "LC_UNKNOWN",
        }
    }

    /// Performs summary.
    pub fn summary(&self) -> String {
        match self {
            Self::Segment32(d) | Self::Segment64(d) => {
                format!("segment_index={}", d.segment_index)
            }
            Self::Uuid(d) => format_uuid(&d.uuid),
            Self::BuildVersion(d) => {
                format!("{} {}", d.platform.name(), d.minos)
            }
            Self::Main(d) => format!("entry_offset={:#x}", d.entry_offset),
            Self::SourceVersion(d) => format!("{}", d.version),
            Self::LoadDylib(d)
            | Self::LoadWeakDylib(d)
            | Self::ReexportDylib(d)
            | Self::LazyLoadDylib(d)
            | Self::LoadUpwardDylib(d)
            | Self::IdDylib(d) => d.name.clone(),
            Self::Rpath(d)
            | Self::TargetTriple(d)
            | Self::LoadDylinker(d)
            | Self::IdDylinker(d)
            | Self::DyldEnvironment(d)
            | Self::SubFramework(d)
            | Self::SubUmbrella(d)
            | Self::SubClient(d)
            | Self::SubLibrary(d) => d.value.clone(),
            Self::Symtab(d) => format!("nsyms={}", d.nsyms),
            Self::CodeSignature(d)
            | Self::FunctionStarts(d)
            | Self::DataInCode(d)
            | Self::DyldExportsTrie(d)
            | Self::DyldChainedFixups(d)
            | Self::SegmentSplitInfo(d)
            | Self::DylibCodeSignDrs(d)
            | Self::LinkerOptimizationHint(d)
            | Self::AtomInfo(d)
            | Self::FunctionVariants(d)
            | Self::FunctionVariantFixups(d) => {
                format!("off={:#x} size={:#x}", d.data_offset, d.data_size)
            }
            Self::VersionMinMacOS(d)
            | Self::VersionMinIOS(d)
            | Self::VersionMinTvOS(d)
            | Self::VersionMinWatchOS(d) => {
                format!("{}", d.version)
            }
            Self::EncryptionInfo(d) | Self::EncryptionInfo64(d) => {
                format!(
                    "cryptoff={:#x} cryptsize={:#x} cryptid={}",
                    d.crypt_offset, d.crypt_size, d.crypt_id
                )
            }
            Self::DyldInfo(d) | Self::DyldInfoOnly(d) => {
                format!(
                    "rebase={:#x}+{:#x} bind={:#x}+{:#x} export={:#x}+{:#x}",
                    d.rebase_off,
                    d.rebase_size,
                    d.bind_off,
                    d.bind_size,
                    d.export_off,
                    d.export_size
                )
            }
            Self::FilesetEntry(d) => d.entry_id.clone(),
            Self::Note(d) => d.data_owner.clone(),
            _ => String::new(),
        }
    }

    /// Performs as_uuid.
    pub fn as_uuid(&self) -> Option<&UuidData> {
        match self {
            Self::Uuid(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_build_version.
    pub fn as_build_version(&self) -> Option<&BuildVersionData> {
        match self {
            Self::BuildVersion(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_symtab.
    pub fn as_symtab(&self) -> Option<&SymtabData> {
        match self {
            Self::Symtab(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_dysymtab.
    pub fn as_dysymtab(&self) -> Option<&DysymtabData> {
        match self {
            Self::Dysymtab(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_main.
    pub fn as_main(&self) -> Option<&EntryPointData> {
        match self {
            Self::Main(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_dylib.
    pub fn as_dylib(&self) -> Option<&DylibData> {
        match self {
            Self::LoadDylib(d)
            | Self::LoadWeakDylib(d)
            | Self::ReexportDylib(d)
            | Self::LazyLoadDylib(d)
            | Self::LoadUpwardDylib(d)
            | Self::IdDylib(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_rpath.
    pub fn as_rpath(&self) -> Option<&str> {
        match self {
            Self::Rpath(d) => Some(&d.value),
            _ => None,
        }
    }

    /// Performs as_segment.
    pub fn as_segment(&self) -> Option<&SegmentCommandData> {
        match self {
            Self::Segment32(d) | Self::Segment64(d) => Some(d),
            _ => None,
        }
    }

    /// Performs as_linkedit_data.
    pub fn as_linkedit_data(&self) -> Option<&LinkeditData> {
        match self {
            Self::CodeSignature(d)
            | Self::FunctionStarts(d)
            | Self::DataInCode(d)
            | Self::DyldExportsTrie(d)
            | Self::DyldChainedFixups(d)
            | Self::SegmentSplitInfo(d)
            | Self::DylibCodeSignDrs(d)
            | Self::LinkerOptimizationHint(d)
            | Self::AtomInfo(d)
            | Self::FunctionVariants(d)
            | Self::FunctionVariantFixups(d) => Some(d),
            _ => None,
        }
    }
}

/// Performs format_uuid.
pub fn format_uuid(uuid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0],
        uuid[1],
        uuid[2],
        uuid[3],
        uuid[4],
        uuid[5],
        uuid[6],
        uuid[7],
        uuid[8],
        uuid[9],
        uuid[10],
        uuid[11],
        uuid[12],
        uuid[13],
        uuid[14],
        uuid[15],
    )
}

// Data structs for each load command variant

#[derive(Debug, Clone, PartialEq, Eq)]
/// The SegmentCommandData type.
pub struct SegmentCommandData {
    /// The segment_index field.
    pub segment_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The SymtabData type.
pub struct SymtabData {
    /// The sym_offset field.
    pub sym_offset: u32,
    /// The nsyms field.
    pub nsyms: u32,
    /// The str_offset field.
    pub str_offset: u32,
    /// The str_size field.
    pub str_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The DysymtabData type.
pub struct DysymtabData {
    /// The ilocalsym field.
    pub ilocalsym: u32,
    /// The nlocalsym field.
    pub nlocalsym: u32,
    /// The iextdefsym field.
    pub iextdefsym: u32,
    /// The nextdefsym field.
    pub nextdefsym: u32,
    /// The iundefsym field.
    pub iundefsym: u32,
    /// The nundefsym field.
    pub nundefsym: u32,
    /// The tocoff field.
    pub tocoff: u32,
    /// The ntoc field.
    pub ntoc: u32,
    /// The modtaboff field.
    pub modtaboff: u32,
    /// The nmodtab field.
    pub nmodtab: u32,
    /// The extrefsymoff field.
    pub extrefsymoff: u32,
    /// The nextrefsyms field.
    pub nextrefsyms: u32,
    /// The indirectsymoff field.
    pub indirectsymoff: u32,
    /// The nindirectsyms field.
    pub nindirectsyms: u32,
    /// The extreloff field.
    pub extreloff: u32,
    /// The nextrel field.
    pub nextrel: u32,
    /// The locreloff field.
    pub locreloff: u32,
    /// The nlocrel field.
    pub nlocrel: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The DyldInfoData type.
pub struct DyldInfoData {
    /// The rebase_off field.
    pub rebase_off: u32,
    /// The rebase_size field.
    pub rebase_size: u32,
    /// The bind_off field.
    pub bind_off: u32,
    /// The bind_size field.
    pub bind_size: u32,
    /// The weak_bind_off field.
    pub weak_bind_off: u32,
    /// The weak_bind_size field.
    pub weak_bind_size: u32,
    /// The lazy_bind_off field.
    pub lazy_bind_off: u32,
    /// The lazy_bind_size field.
    pub lazy_bind_size: u32,
    /// The export_off field.
    pub export_off: u32,
    /// The export_size field.
    pub export_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The LinkeditData type.
pub struct LinkeditData {
    /// The data_offset field.
    pub data_offset: u32,
    /// The data_size field.
    pub data_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The EntryPointData type.
pub struct EntryPointData {
    /// The entry_offset field.
    pub entry_offset: u64,
    /// The stack_size field.
    pub stack_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The UuidData type.
pub struct UuidData {
    /// The uuid field.
    pub uuid: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The BuildVersionData type.
pub struct BuildVersionData {
    /// The platform field.
    pub platform: Platform,
    /// The minos field.
    pub minos: PackedVersion,
    /// The sdk field.
    pub sdk: PackedVersion,
    /// The tools field.
    pub tools: Vec<BuildToolVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The BuildToolVersion type.
pub struct BuildToolVersion {
    /// The tool field.
    pub tool: Tool,
    /// The version field.
    pub version: PackedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The SourceVersionData type.
pub struct SourceVersionData {
    /// The version field.
    pub version: SourceVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The VersionMinData type.
pub struct VersionMinData {
    /// The version field.
    pub version: PackedVersion,
    /// The sdk field.
    pub sdk: PackedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The DylibData type.
pub struct DylibData {
    /// The name field.
    pub name: String,
    /// The timestamp field.
    pub timestamp: u32,
    /// The current_version field.
    pub current_version: PackedVersion,
    /// The compatibility_version field.
    pub compatibility_version: PackedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The StringData type.
pub struct StringData {
    /// The value field.
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The EncryptionInfoData type.
pub struct EncryptionInfoData {
    /// The crypt_offset field.
    pub crypt_offset: u32,
    /// The crypt_size field.
    pub crypt_size: u32,
    /// The crypt_id field.
    pub crypt_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The LinkerOptionData type.
pub struct LinkerOptionData {
    /// The strings field.
    pub strings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The NoteData type.
pub struct NoteData {
    /// The data_owner field.
    pub data_owner: String,
    /// The offset field.
    pub offset: u64,
    /// The size field.
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The FilesetEntryData type.
pub struct FilesetEntryData {
    /// The vm_addr field.
    pub vm_addr: u64,
    /// The file_offset field.
    pub file_offset: u64,
    /// The entry_id field.
    pub entry_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The PrebindCksumData type.
pub struct PrebindCksumData {
    /// The cksum field.
    pub cksum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The TwolevelHintsData type.
pub struct TwolevelHintsData {
    /// The offset field.
    pub offset: u32,
    /// The nhints field.
    pub nhints: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The RoutinesData type.
pub struct RoutinesData {
    /// The init_address field.
    pub init_address: u64,
    /// The init_module field.
    pub init_module: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The RawData type.
pub struct RawData {
    /// The data field.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// The UnknownLoadCommand type.
pub struct UnknownLoadCommand {
    /// The cmd field.
    pub cmd: u32,
    /// The data field.
    pub data: Vec<u8>,
}

// Version and platform types

#[derive(Clone, Copy, PartialEq, Eq)]
/// The PackedVersion type.
pub struct PackedVersion(pub u32);

impl PackedVersion {
    /// Performs major.
    pub fn major(self) -> u32 {
        self.0 >> 16
    }

    /// Performs minor.
    pub fn minor(self) -> u32 {
        (self.0 >> 8) & 0xFF
    }

    /// Performs patch.
    pub fn patch(self) -> u32 {
        self.0 & 0xFF
    }
}

impl fmt::Debug for PackedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for PackedVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major(), self.minor(), self.patch())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// The SourceVersion type.
pub struct SourceVersion(pub u64);

impl SourceVersion {
    /// Performs a.
    pub fn a(self) -> u64 {
        (self.0 >> 40) & 0xFFFFFF
    }
    /// Performs b.
    pub fn b(self) -> u64 {
        (self.0 >> 30) & 0x3FF
    }
    /// Performs c.
    pub fn c(self) -> u64 {
        (self.0 >> 20) & 0x3FF
    }
    /// Performs d.
    pub fn d(self) -> u64 {
        (self.0 >> 10) & 0x3FF
    }
    /// Performs e.
    pub fn e(self) -> u64 {
        self.0 & 0x3FF
    }
}

impl fmt::Debug for SourceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

impl fmt::Display for SourceVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}.{}.{}.{}.{}",
            self.a(),
            self.b(),
            self.c(),
            self.d(),
            self.e()
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// The Platform type.
pub struct Platform(pub u32);

impl Platform {
    /// Performs name.
    pub fn name(self) -> &'static str {
        match self.0 {
            PLATFORM_MACOS => "macOS",
            PLATFORM_IOS => "iOS",
            PLATFORM_TVOS => "tvOS",
            PLATFORM_WATCHOS => "watchOS",
            PLATFORM_BRIDGEOS => "bridgeOS",
            PLATFORM_MACCATALYST => "Mac Catalyst",
            PLATFORM_IOSSIMULATOR => "iOS Simulator",
            PLATFORM_TVOSSIMULATOR => "tvOS Simulator",
            PLATFORM_WATCHOSSIMULATOR => "watchOS Simulator",
            PLATFORM_DRIVERKIT => "DriverKit",
            PLATFORM_VISIONOS => "visionOS",
            PLATFORM_VISIONOSSIMULATOR => "visionOS Simulator",
            PLATFORM_FIRMWARE => "Firmware",
            PLATFORM_SEPOS => "sepOS",
            _ => "unknown",
        }
    }
}

impl fmt::Debug for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Platform({})", self.name())
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
/// The Tool type.
pub struct Tool(pub u32);

impl Tool {
    /// Performs name.
    pub fn name(self) -> &'static str {
        match self.0 {
            TOOL_CLANG => "clang",
            TOOL_SWIFT => "swift",
            TOOL_LD => "ld",
            TOOL_LLD => "lld",
            TOOL_METAL => "metal",
            TOOL_AIRLLD => "airlld",
            TOOL_AIRNT => "airnt",
            TOOL_AIRNT_PLUGIN => "airnt_plugin",
            TOOL_AIRPACK => "airpack",
            TOOL_GPUARCHIVER => "gpuarchiver",
            TOOL_METAL_FRAMEWORK => "metal_framework",
            _ => "unknown",
        }
    }
}

impl fmt::Debug for Tool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Tool({})", self.name())
    }
}
