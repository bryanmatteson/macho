use crate::format::constants::*;
use crate::model::addr::ThinFileOffset;
use std::fmt;

#[derive(Debug, Clone)]
pub struct ParsedLoadCommand {
    pub kind: LoadCommand,
    pub file_offset: ThinFileOffset,
    pub raw_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoadCommand {
    Segment32(SegmentCommandData),
    Segment64(SegmentCommandData),
    Symtab(SymtabData),
    Dysymtab(DysymtabData),
    DyldInfo(DyldInfoData),
    DyldInfoOnly(DyldInfoData),
    DyldExportsTrie(LinkeditData),
    DyldChainedFixups(LinkeditData),
    Main(EntryPointData),
    Uuid(UuidData),
    BuildVersion(BuildVersionData),
    SourceVersion(SourceVersionData),
    VersionMinMacOS(VersionMinData),
    VersionMinIOS(VersionMinData),
    VersionMinTvOS(VersionMinData),
    VersionMinWatchOS(VersionMinData),
    IdDylib(DylibData),
    LoadDylib(DylibData),
    LoadWeakDylib(DylibData),
    ReexportDylib(DylibData),
    LazyLoadDylib(DylibData),
    LoadUpwardDylib(DylibData),
    Rpath(StringData),
    TargetTriple(StringData),
    IdDylinker(StringData),
    LoadDylinker(StringData),
    DyldEnvironment(StringData),
    SubFramework(StringData),
    SubUmbrella(StringData),
    SubClient(StringData),
    SubLibrary(StringData),
    CodeSignature(LinkeditData),
    SegmentSplitInfo(LinkeditData),
    FunctionStarts(LinkeditData),
    DataInCode(LinkeditData),
    DylibCodeSignDrs(LinkeditData),
    LinkerOptimizationHint(LinkeditData),
    AtomInfo(LinkeditData),
    FunctionVariants(LinkeditData),
    FunctionVariantFixups(LinkeditData),
    EncryptionInfo(EncryptionInfoData),
    EncryptionInfo64(EncryptionInfoData),
    LinkerOption(LinkerOptionData),
    Note(NoteData),
    FilesetEntry(FilesetEntryData),
    PrebindCksum(PrebindCksumData),
    TwolevelHints(TwolevelHintsData),
    Routines(RoutinesData),
    Routines64(RoutinesData),
    Thread(RawData),
    UnixThread(RawData),
    PreboundDylib(RawData),
    Ident(RawData),
    Unknown(UnknownLoadCommand),
}

impl LoadCommand {
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

    pub fn as_uuid(&self) -> Option<&UuidData> {
        match self {
            Self::Uuid(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_build_version(&self) -> Option<&BuildVersionData> {
        match self {
            Self::BuildVersion(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_symtab(&self) -> Option<&SymtabData> {
        match self {
            Self::Symtab(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_dysymtab(&self) -> Option<&DysymtabData> {
        match self {
            Self::Dysymtab(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_main(&self) -> Option<&EntryPointData> {
        match self {
            Self::Main(d) => Some(d),
            _ => None,
        }
    }

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

    pub fn as_rpath(&self) -> Option<&str> {
        match self {
            Self::Rpath(d) => Some(&d.value),
            _ => None,
        }
    }

    pub fn as_segment(&self) -> Option<&SegmentCommandData> {
        match self {
            Self::Segment32(d) | Self::Segment64(d) => Some(d),
            _ => None,
        }
    }

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
pub struct SegmentCommandData {
    pub segment_index: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SymtabData {
    pub sym_offset: u32,
    pub nsyms: u32,
    pub str_offset: u32,
    pub str_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DysymtabData {
    pub ilocalsym: u32,
    pub nlocalsym: u32,
    pub iextdefsym: u32,
    pub nextdefsym: u32,
    pub iundefsym: u32,
    pub nundefsym: u32,
    pub tocoff: u32,
    pub ntoc: u32,
    pub modtaboff: u32,
    pub nmodtab: u32,
    pub extrefsymoff: u32,
    pub nextrefsyms: u32,
    pub indirectsymoff: u32,
    pub nindirectsyms: u32,
    pub extreloff: u32,
    pub nextrel: u32,
    pub locreloff: u32,
    pub nlocrel: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DyldInfoData {
    pub rebase_off: u32,
    pub rebase_size: u32,
    pub bind_off: u32,
    pub bind_size: u32,
    pub weak_bind_off: u32,
    pub weak_bind_size: u32,
    pub lazy_bind_off: u32,
    pub lazy_bind_size: u32,
    pub export_off: u32,
    pub export_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkeditData {
    pub data_offset: u32,
    pub data_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryPointData {
    pub entry_offset: u64,
    pub stack_size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UuidData {
    pub uuid: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildVersionData {
    pub platform: Platform,
    pub minos: PackedVersion,
    pub sdk: PackedVersion,
    pub tools: Vec<BuildToolVersion>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BuildToolVersion {
    pub tool: Tool,
    pub version: PackedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceVersionData {
    pub version: SourceVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionMinData {
    pub version: PackedVersion,
    pub sdk: PackedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DylibData {
    pub name: String,
    pub timestamp: u32,
    pub current_version: PackedVersion,
    pub compatibility_version: PackedVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringData {
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptionInfoData {
    pub crypt_offset: u32,
    pub crypt_size: u32,
    pub crypt_id: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkerOptionData {
    pub strings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteData {
    pub data_owner: String,
    pub offset: u64,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesetEntryData {
    pub vm_addr: u64,
    pub file_offset: u64,
    pub entry_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrebindCksumData {
    pub cksum: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TwolevelHintsData {
    pub offset: u32,
    pub nhints: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutinesData {
    pub init_address: u64,
    pub init_module: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawData {
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownLoadCommand {
    pub cmd: u32,
    pub data: Vec<u8>,
}

// Version and platform types

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PackedVersion(pub u32);

impl PackedVersion {
    pub fn major(self) -> u32 {
        self.0 >> 16
    }

    pub fn minor(self) -> u32 {
        (self.0 >> 8) & 0xFF
    }

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
pub struct SourceVersion(pub u64);

impl SourceVersion {
    pub fn a(self) -> u64 {
        (self.0 >> 40) & 0xFFFFFF
    }
    pub fn b(self) -> u64 {
        (self.0 >> 30) & 0x3FF
    }
    pub fn c(self) -> u64 {
        (self.0 >> 20) & 0x3FF
    }
    pub fn d(self) -> u64 {
        (self.0 >> 10) & 0x3FF
    }
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
pub struct Platform(pub u32);

impl Platform {
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
pub struct Tool(pub u32);

impl Tool {
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
