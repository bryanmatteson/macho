// Mach-O magic numbers
/// The MH_MAGIC constant.
pub const MH_MAGIC: u32 = 0xfeed_face;
/// The MH_CIGAM constant.
pub const MH_CIGAM: u32 = 0xcefa_edfe;
/// The MH_MAGIC_64 constant.
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
/// The MH_CIGAM_64 constant.
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

// Fat binary magic numbers (always big-endian on disk)
/// The FAT_MAGIC constant.
pub const FAT_MAGIC: u32 = 0xcafe_babe;
/// The FAT_CIGAM constant.
pub const FAT_CIGAM: u32 = 0xbeba_feca;
/// The FAT_MAGIC_64 constant.
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
/// The FAT_CIGAM_64 constant.
pub const FAT_CIGAM_64: u32 = 0xbfba_feca;

// File types
/// The MH_OBJECT constant.
pub const MH_OBJECT: u32 = 0x1;
/// The MH_EXECUTE constant.
pub const MH_EXECUTE: u32 = 0x2;
/// The MH_FVMLIB constant.
pub const MH_FVMLIB: u32 = 0x3;
/// The MH_CORE constant.
pub const MH_CORE: u32 = 0x4;
/// The MH_PRELOAD constant.
pub const MH_PRELOAD: u32 = 0x5;
/// The MH_DYLIB constant.
pub const MH_DYLIB: u32 = 0x6;
/// The MH_DYLINKER constant.
pub const MH_DYLINKER: u32 = 0x7;
/// The MH_BUNDLE constant.
pub const MH_BUNDLE: u32 = 0x8;
/// The MH_DYLIB_STUB constant.
pub const MH_DYLIB_STUB: u32 = 0x9;
/// The MH_DSYM constant.
pub const MH_DSYM: u32 = 0xa;
/// The MH_KEXT_BUNDLE constant.
pub const MH_KEXT_BUNDLE: u32 = 0xb;
/// The MH_FILESET constant.
pub const MH_FILESET: u32 = 0xc;
/// The MH_GPU_EXECUTE constant.
pub const MH_GPU_EXECUTE: u32 = 0xd;
/// The MH_GPU_DYLIB constant.
pub const MH_GPU_DYLIB: u32 = 0xe;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// The MachoHeaderFlags flag value.
    pub struct MachoHeaderFlags: u32 {
        /// The NOUNDEFS flag value.
        const NOUNDEFS                      = 0x0000_0001;
        /// The INCRLINK flag value.
        const INCRLINK                      = 0x0000_0002;
        /// The DYLDLINK flag value.
        const DYLDLINK                      = 0x0000_0004;
        /// The BINDATLOAD flag value.
        const BINDATLOAD                    = 0x0000_0008;
        /// The PREBOUND flag value.
        const PREBOUND                      = 0x0000_0010;
        /// The SPLIT_SEGS flag value.
        const SPLIT_SEGS                    = 0x0000_0020;
        /// The LAZY_INIT flag value.
        const LAZY_INIT                     = 0x0000_0040;
        /// The TWOLEVEL flag value.
        const TWOLEVEL                      = 0x0000_0080;
        /// The FORCE_FLAT flag value.
        const FORCE_FLAT                    = 0x0000_0100;
        /// The NOMULTIDEFS flag value.
        const NOMULTIDEFS                   = 0x0000_0200;
        /// The NOFIXPREBINDING flag value.
        const NOFIXPREBINDING               = 0x0000_0400;
        /// The PREBINDABLE flag value.
        const PREBINDABLE                   = 0x0000_0800;
        /// The ALLMODSBOUND flag value.
        const ALLMODSBOUND                  = 0x0000_1000;
        /// The SUBSECTIONS_VIA_SYMBOLS flag value.
        const SUBSECTIONS_VIA_SYMBOLS       = 0x0000_2000;
        /// The CANONICAL flag value.
        const CANONICAL                     = 0x0000_4000;
        /// The WEAK_DEFINES flag value.
        const WEAK_DEFINES                  = 0x0000_8000;
        /// The BINDS_TO_WEAK flag value.
        const BINDS_TO_WEAK                 = 0x0001_0000;
        /// The ALLOW_STACK_EXECUTION flag value.
        const ALLOW_STACK_EXECUTION         = 0x0002_0000;
        /// The ROOT_SAFE flag value.
        const ROOT_SAFE                     = 0x0004_0000;
        /// The SETUID_SAFE flag value.
        const SETUID_SAFE                   = 0x0008_0000;
        /// The NO_REEXPORTED_DYLIBS flag value.
        const NO_REEXPORTED_DYLIBS          = 0x0010_0000;
        /// The PIE flag value.
        const PIE                           = 0x0020_0000;
        /// The DEAD_STRIPPABLE_DYLIB flag value.
        const DEAD_STRIPPABLE_DYLIB         = 0x0040_0000;
        /// The HAS_TLV_DESCRIPTORS flag value.
        const HAS_TLV_DESCRIPTORS           = 0x0080_0000;
        /// The NO_HEAP_EXECUTION flag value.
        const NO_HEAP_EXECUTION             = 0x0100_0000;
        /// The APP_EXTENSION_SAFE flag value.
        const APP_EXTENSION_SAFE            = 0x0200_0000;
        /// The NLIST_OUTOFSYNC_WITH_DYLDINFO flag value.
        const NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x0400_0000;
        /// The SIM_SUPPORT flag value.
        const SIM_SUPPORT                   = 0x0800_0000;
        /// The IMPLICIT_PAGEZERO flag value.
        const IMPLICIT_PAGEZERO             = 0x1000_0000;
        /// The DYLIB_IN_CACHE flag value.
        const DYLIB_IN_CACHE                = 0x8000_0000;
    }
}

// Load command constants
/// The LC_REQ_DYLD constant.
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

/// The LC_SEGMENT constant.
pub const LC_SEGMENT: u32 = 0x1;
/// The LC_SYMTAB constant.
pub const LC_SYMTAB: u32 = 0x2;
/// The LC_SYMSEG constant.
pub const LC_SYMSEG: u32 = 0x3;
/// The LC_THREAD constant.
pub const LC_THREAD: u32 = 0x4;
/// The LC_UNIXTHREAD constant.
pub const LC_UNIXTHREAD: u32 = 0x5;
/// The LC_LOADFVMLIB constant.
pub const LC_LOADFVMLIB: u32 = 0x6;
/// The LC_IDFVMLIB constant.
pub const LC_IDFVMLIB: u32 = 0x7;
/// The LC_IDENT constant.
pub const LC_IDENT: u32 = 0x8;
/// The LC_FVMFILE constant.
pub const LC_FVMFILE: u32 = 0x9;
/// The LC_PREPAGE constant.
pub const LC_PREPAGE: u32 = 0xa;
/// The LC_DYSYMTAB constant.
pub const LC_DYSYMTAB: u32 = 0xb;
/// The LC_LOAD_DYLIB constant.
pub const LC_LOAD_DYLIB: u32 = 0xc;
/// The LC_ID_DYLIB constant.
pub const LC_ID_DYLIB: u32 = 0xd;
/// The LC_LOAD_DYLINKER constant.
pub const LC_LOAD_DYLINKER: u32 = 0xe;
/// The LC_ID_DYLINKER constant.
pub const LC_ID_DYLINKER: u32 = 0xf;
/// The LC_PREBOUND_DYLIB constant.
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
/// The LC_ROUTINES constant.
pub const LC_ROUTINES: u32 = 0x11;
/// The LC_SUB_FRAMEWORK constant.
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
/// The LC_SUB_UMBRELLA constant.
pub const LC_SUB_UMBRELLA: u32 = 0x13;
/// The LC_SUB_CLIENT constant.
pub const LC_SUB_CLIENT: u32 = 0x14;
/// The LC_SUB_LIBRARY constant.
pub const LC_SUB_LIBRARY: u32 = 0x15;
/// The LC_TWOLEVEL_HINTS constant.
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
/// The LC_PREBIND_CKSUM constant.
pub const LC_PREBIND_CKSUM: u32 = 0x17;
/// The LC_LOAD_WEAK_DYLIB constant.
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
/// The LC_SEGMENT_64 constant.
pub const LC_SEGMENT_64: u32 = 0x19;
/// The LC_ROUTINES_64 constant.
pub const LC_ROUTINES_64: u32 = 0x1a;
/// The LC_UUID constant.
pub const LC_UUID: u32 = 0x1b;
/// The LC_RPATH constant.
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
/// The LC_CODE_SIGNATURE constant.
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
/// The LC_SEGMENT_SPLIT_INFO constant.
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
/// The LC_REEXPORT_DYLIB constant.
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
/// The LC_LAZY_LOAD_DYLIB constant.
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// The LC_ENCRYPTION_INFO constant.
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
/// The LC_DYLD_INFO constant.
pub const LC_DYLD_INFO: u32 = 0x22;
/// The LC_DYLD_INFO_ONLY constant.
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
/// The LC_LOAD_UPWARD_DYLIB constant.
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
/// The LC_VERSION_MIN_MACOSX constant.
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// The LC_VERSION_MIN_IPHONEOS constant.
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
/// The LC_FUNCTION_STARTS constant.
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// The LC_DYLD_ENVIRONMENT constant.
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
/// The LC_MAIN constant.
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
/// The LC_DATA_IN_CODE constant.
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// The LC_SOURCE_VERSION constant.
pub const LC_SOURCE_VERSION: u32 = 0x2a;
/// The LC_DYLIB_CODE_SIGN_DRS constant.
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
/// The LC_ENCRYPTION_INFO_64 constant.
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
/// The LC_LINKER_OPTION constant.
pub const LC_LINKER_OPTION: u32 = 0x2d;
/// The LC_LINKER_OPTIMIZATION_HINT constant.
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
/// The LC_VERSION_MIN_TVOS constant.
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
/// The LC_VERSION_MIN_WATCHOS constant.
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// The LC_NOTE constant.
pub const LC_NOTE: u32 = 0x31;
/// The LC_BUILD_VERSION constant.
pub const LC_BUILD_VERSION: u32 = 0x32;
/// The LC_DYLD_EXPORTS_TRIE constant.
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
/// The LC_DYLD_CHAINED_FIXUPS constant.
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
/// The LC_FILESET_ENTRY constant.
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
/// The LC_ATOM_INFO constant.
pub const LC_ATOM_INFO: u32 = 0x36;
/// The LC_FUNCTION_VARIANTS constant.
pub const LC_FUNCTION_VARIANTS: u32 = 0x37;
/// The LC_FUNCTION_VARIANT_FIXUPS constant.
pub const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
/// The LC_TARGET_TRIPLE constant.
pub const LC_TARGET_TRIPLE: u32 = 0x39;

// Section type mask and values
/// The SECTION_TYPE_MASK constant.
pub const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
/// The SECTION_ATTRIBUTES_MASK constant.
pub const SECTION_ATTRIBUTES_MASK: u32 = 0xffff_ff00;

/// The S_REGULAR constant.
pub const S_REGULAR: u8 = 0x0;
/// The S_ZEROFILL constant.
pub const S_ZEROFILL: u8 = 0x1;
/// The S_CSTRING_LITERALS constant.
pub const S_CSTRING_LITERALS: u8 = 0x2;
/// The S_4BYTE_LITERALS constant.
pub const S_4BYTE_LITERALS: u8 = 0x3;
/// The S_8BYTE_LITERALS constant.
pub const S_8BYTE_LITERALS: u8 = 0x4;
/// The S_LITERAL_POINTERS constant.
pub const S_LITERAL_POINTERS: u8 = 0x5;
/// The S_NON_LAZY_SYMBOL_POINTERS constant.
pub const S_NON_LAZY_SYMBOL_POINTERS: u8 = 0x6;
/// The S_LAZY_SYMBOL_POINTERS constant.
pub const S_LAZY_SYMBOL_POINTERS: u8 = 0x7;
/// The S_SYMBOL_STUBS constant.
pub const S_SYMBOL_STUBS: u8 = 0x8;
/// The S_MOD_INIT_FUNC_POINTERS constant.
pub const S_MOD_INIT_FUNC_POINTERS: u8 = 0x9;
/// The S_MOD_TERM_FUNC_POINTERS constant.
pub const S_MOD_TERM_FUNC_POINTERS: u8 = 0xa;
/// The S_COALESCED constant.
pub const S_COALESCED: u8 = 0xb;
/// The S_GB_ZEROFILL constant.
pub const S_GB_ZEROFILL: u8 = 0xc;
/// The S_INTERPOSING constant.
pub const S_INTERPOSING: u8 = 0xd;
/// The S_16BYTE_LITERALS constant.
pub const S_16BYTE_LITERALS: u8 = 0xe;
/// The S_DTRACE_DOF constant.
pub const S_DTRACE_DOF: u8 = 0xf;
/// The S_LAZY_DYLIB_SYMBOL_POINTERS constant.
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u8 = 0x10;
/// The S_THREAD_LOCAL_REGULAR constant.
pub const S_THREAD_LOCAL_REGULAR: u8 = 0x11;
/// The S_THREAD_LOCAL_ZEROFILL constant.
pub const S_THREAD_LOCAL_ZEROFILL: u8 = 0x12;
/// The S_THREAD_LOCAL_VARIABLES constant.
pub const S_THREAD_LOCAL_VARIABLES: u8 = 0x13;
/// The S_THREAD_LOCAL_VARIABLE_POINTERS constant.
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u8 = 0x14;
/// The S_THREAD_LOCAL_INIT_FUNCTION_POINTERS constant.
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u8 = 0x15;
/// The S_INIT_FUNC_OFFSETS constant.
pub const S_INIT_FUNC_OFFSETS: u8 = 0x16;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// The SectionAttributes flag value.
    pub struct SectionAttributes: u32 {
        /// The PURE_INSTRUCTIONS flag value.
        const PURE_INSTRUCTIONS   = 0x8000_0000;
        /// The NO_TOC flag value.
        const NO_TOC              = 0x4000_0000;
        /// The STRIP_STATIC_SYMS flag value.
        const STRIP_STATIC_SYMS   = 0x2000_0000;
        /// The NO_DEAD_STRIP flag value.
        const NO_DEAD_STRIP       = 0x1000_0000;
        /// The LIVE_SUPPORT flag value.
        const LIVE_SUPPORT        = 0x0800_0000;
        /// The SELF_MODIFYING_CODE flag value.
        const SELF_MODIFYING_CODE = 0x0400_0000;
        /// The DEBUG flag value.
        const DEBUG               = 0x0200_0000;
        /// The SOME_INSTRUCTIONS flag value.
        const SOME_INSTRUCTIONS   = 0x0000_0400;
        /// The EXT_RELOC flag value.
        const EXT_RELOC           = 0x0000_0200;
        /// The LOC_RELOC flag value.
        const LOC_RELOC           = 0x0000_0100;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// The SegmentFlags flag value.
    pub struct SegmentFlags: u32 {
        /// The HIGHVM flag value.
        const HIGHVM              = 0x1;
        /// The FVMLIB flag value.
        const FVMLIB              = 0x2;
        /// The NORELOC flag value.
        const NORELOC             = 0x4;
        /// The PROTECTED_VERSION_1 flag value.
        const PROTECTED_VERSION_1 = 0x8;
        /// The READ_ONLY flag value.
        const READ_ONLY           = 0x10;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    /// The VmProtection flag value.
    pub struct VmProtection: i32 {
        /// The READ flag value.
        const READ    = 0x1;
        /// The WRITE flag value.
        const WRITE   = 0x2;
        /// The EXECUTE flag value.
        const EXECUTE = 0x4;
    }
}

impl VmProtection {
    /// Performs rwx_string.
    pub fn rwx_string(self) -> String {
        let r = if self.contains(Self::READ) { 'r' } else { '-' };
        let w = if self.contains(Self::WRITE) { 'w' } else { '-' };
        let x = if self.contains(Self::EXECUTE) {
            'x'
        } else {
            '-'
        };
        format!("{r}{w}{x}")
    }
}

impl std::fmt::Display for VmProtection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.rwx_string())
    }
}

// CPU type constants
/// The CPU_ARCH_ABI64 constant.
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000;
/// The CPU_ARCH_ABI64_32 constant.
pub const CPU_ARCH_ABI64_32: i32 = 0x0200_0000;

/// The CPU_TYPE_ANY constant.
pub const CPU_TYPE_ANY: i32 = -1;
/// The CPU_TYPE_X86 constant.
pub const CPU_TYPE_X86: i32 = 7;
/// The CPU_TYPE_X86_64 constant.
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
/// The CPU_TYPE_ARM constant.
pub const CPU_TYPE_ARM: i32 = 12;
/// The CPU_TYPE_ARM64 constant.
pub const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
/// The CPU_TYPE_ARM64_32 constant.
pub const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
/// The CPU_TYPE_POWERPC constant.
pub const CPU_TYPE_POWERPC: i32 = 18;
/// The CPU_TYPE_POWERPC64 constant.
pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;

// CPU subtype mask: strips capability bits (high byte) from cpusubtype
/// The CPU_SUBTYPE_MASK constant.
pub const CPU_SUBTYPE_MASK: i32 = 0x00FF_FFFF;

// CPU subtype constants
/// The CPU_SUBTYPE_ALL constant.
pub const CPU_SUBTYPE_ALL: i32 = 0;
/// The CPU_SUBTYPE_X86_64_ALL constant.
pub const CPU_SUBTYPE_X86_64_ALL: i32 = 3;
/// The CPU_SUBTYPE_X86_64_H constant.
pub const CPU_SUBTYPE_X86_64_H: i32 = 8;
/// The CPU_SUBTYPE_ARM64_ALL constant.
pub const CPU_SUBTYPE_ARM64_ALL: i32 = 0;
/// The CPU_SUBTYPE_ARM64_V8 constant.
pub const CPU_SUBTYPE_ARM64_V8: i32 = 1;
/// The CPU_SUBTYPE_ARM64E constant.
pub const CPU_SUBTYPE_ARM64E: i32 = 2;
/// The CPU_SUBTYPE_ARM64_32_ALL constant.
pub const CPU_SUBTYPE_ARM64_32_ALL: i32 = 0;

// Platform constants
/// The PLATFORM_UNKNOWN constant.
pub const PLATFORM_UNKNOWN: u32 = 0;
/// The PLATFORM_ANY constant.
pub const PLATFORM_ANY: u32 = 0xFFFF_FFFF;
/// The PLATFORM_MACOS constant.
pub const PLATFORM_MACOS: u32 = 1;
/// The PLATFORM_IOS constant.
pub const PLATFORM_IOS: u32 = 2;
/// The PLATFORM_TVOS constant.
pub const PLATFORM_TVOS: u32 = 3;
/// The PLATFORM_WATCHOS constant.
pub const PLATFORM_WATCHOS: u32 = 4;
/// The PLATFORM_BRIDGEOS constant.
pub const PLATFORM_BRIDGEOS: u32 = 5;
/// The PLATFORM_MACCATALYST constant.
pub const PLATFORM_MACCATALYST: u32 = 6;
/// The PLATFORM_IOSSIMULATOR constant.
pub const PLATFORM_IOSSIMULATOR: u32 = 7;
/// The PLATFORM_TVOSSIMULATOR constant.
pub const PLATFORM_TVOSSIMULATOR: u32 = 8;
/// The PLATFORM_WATCHOSSIMULATOR constant.
pub const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
/// The PLATFORM_DRIVERKIT constant.
pub const PLATFORM_DRIVERKIT: u32 = 10;
/// The PLATFORM_VISIONOS constant.
pub const PLATFORM_VISIONOS: u32 = 11;
/// The PLATFORM_VISIONOSSIMULATOR constant.
pub const PLATFORM_VISIONOSSIMULATOR: u32 = 12;
/// The PLATFORM_FIRMWARE constant.
pub const PLATFORM_FIRMWARE: u32 = 13;
/// The PLATFORM_SEPOS constant.
pub const PLATFORM_SEPOS: u32 = 14;

// Tool constants
/// The TOOL_CLANG constant.
pub const TOOL_CLANG: u32 = 1;
/// The TOOL_SWIFT constant.
pub const TOOL_SWIFT: u32 = 2;
/// The TOOL_LD constant.
pub const TOOL_LD: u32 = 3;
/// The TOOL_LLD constant.
pub const TOOL_LLD: u32 = 4;
/// The TOOL_METAL constant.
pub const TOOL_METAL: u32 = 1024;
/// The TOOL_AIRLLD constant.
pub const TOOL_AIRLLD: u32 = 1025;
/// The TOOL_AIRNT constant.
pub const TOOL_AIRNT: u32 = 1026;
/// The TOOL_AIRNT_PLUGIN constant.
pub const TOOL_AIRNT_PLUGIN: u32 = 1027;
/// The TOOL_AIRPACK constant.
pub const TOOL_AIRPACK: u32 = 1028;
/// The TOOL_GPUARCHIVER constant.
pub const TOOL_GPUARCHIVER: u32 = 1031;
/// The TOOL_METAL_FRAMEWORK constant.
pub const TOOL_METAL_FRAMEWORK: u32 = 1032;

// Dylib use marker (for detecting dylib_use_command vs dylib_command)
/// The DYLIB_USE_MARKER constant.
pub const DYLIB_USE_MARKER: u32 = 0x1a74_1800;

// Symbol table n_type masks
/// The N_STAB constant.
pub const N_STAB: u8 = 0xe0;
/// The N_PEXT constant.
pub const N_PEXT: u8 = 0x10;
/// The N_TYPE constant.
pub const N_TYPE: u8 = 0x0e;
/// The N_EXT constant.
pub const N_EXT: u8 = 0x01;

// Symbol type values (after masking with N_TYPE)
/// The N_UNDF constant.
pub const N_UNDF: u8 = 0x0;
/// The N_ABS constant.
pub const N_ABS: u8 = 0x2;
/// The N_SECT constant.
pub const N_SECT: u8 = 0xe;
/// The N_PBUD constant.
pub const N_PBUD: u8 = 0xc;
/// The N_INDR constant.
pub const N_INDR: u8 = 0xa;

// Section ordinals
/// The NO_SECT constant.
pub const NO_SECT: u8 = 0;

// n_desc flags
/// The N_ARM_THUMB_DEF constant.
pub const N_ARM_THUMB_DEF: u16 = 0x0008;
/// The REFERENCED_DYNAMICALLY constant.
pub const REFERENCED_DYNAMICALLY: u16 = 0x0010;
/// The N_NO_DEAD_STRIP constant.
pub const N_NO_DEAD_STRIP: u16 = 0x0020;
/// The N_WEAK_REF constant.
pub const N_WEAK_REF: u16 = 0x0040;
/// The N_WEAK_DEF constant.
pub const N_WEAK_DEF: u16 = 0x0080;
/// The N_SYMBOL_RESOLVER constant.
pub const N_SYMBOL_RESOLVER: u16 = 0x0100;
/// The N_ALT_ENTRY constant.
pub const N_ALT_ENTRY: u16 = 0x0200;
/// The N_COLD_FUNC constant.
pub const N_COLD_FUNC: u16 = 0x0400;

// Library ordinal helpers (extracted from bits 8-15 of n_desc)
/// The SELF_LIBRARY_ORDINAL constant.
pub const SELF_LIBRARY_ORDINAL: u8 = 0x0;
/// The MAX_LIBRARY_ORDINAL constant.
pub const MAX_LIBRARY_ORDINAL: u8 = 0xfd;
/// The DYNAMIC_LOOKUP_ORDINAL constant.
pub const DYNAMIC_LOOKUP_ORDINAL: u8 = 0xfe;
/// The EXECUTABLE_ORDINAL constant.
pub const EXECUTABLE_ORDINAL: u8 = 0xff;

// Reference type mask (bits 0-2 of n_desc for undefined symbols)
/// The REFERENCE_TYPE constant.
pub const REFERENCE_TYPE: u16 = 0x7;

// Relocation constants
/// The R_SCATTERED constant.
pub const R_SCATTERED: u32 = 0x8000_0000;
/// The R_ABS constant.
pub const R_ABS: u8 = 0;

// Generic relocation types
/// The GENERIC_RELOC_VANILLA constant.
pub const GENERIC_RELOC_VANILLA: u8 = 0;
/// The GENERIC_RELOC_PAIR constant.
pub const GENERIC_RELOC_PAIR: u8 = 1;
/// The GENERIC_RELOC_SECTDIFF constant.
pub const GENERIC_RELOC_SECTDIFF: u8 = 2;
/// The GENERIC_RELOC_PB_LA_PTR constant.
pub const GENERIC_RELOC_PB_LA_PTR: u8 = 3;
/// The GENERIC_RELOC_LOCAL_SECTDIFF constant.
pub const GENERIC_RELOC_LOCAL_SECTDIFF: u8 = 4;
/// The GENERIC_RELOC_TLV constant.
pub const GENERIC_RELOC_TLV: u8 = 5;

// ARM64 relocation types
/// The ARM64_RELOC_UNSIGNED constant.
pub const ARM64_RELOC_UNSIGNED: u8 = 0;
/// The ARM64_RELOC_SUBTRACTOR constant.
pub const ARM64_RELOC_SUBTRACTOR: u8 = 1;
/// The ARM64_RELOC_BRANCH26 constant.
pub const ARM64_RELOC_BRANCH26: u8 = 2;
/// The ARM64_RELOC_PAGE21 constant.
pub const ARM64_RELOC_PAGE21: u8 = 3;
/// The ARM64_RELOC_PAGEOFF12 constant.
pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
/// The ARM64_RELOC_GOT_LOAD_PAGE21 constant.
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
/// The ARM64_RELOC_GOT_LOAD_PAGEOFF12 constant.
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
/// The ARM64_RELOC_POINTER_TO_GOT constant.
pub const ARM64_RELOC_POINTER_TO_GOT: u8 = 7;
/// The ARM64_RELOC_TLVP_LOAD_PAGE21 constant.
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u8 = 8;
/// The ARM64_RELOC_TLVP_LOAD_PAGEOFF12 constant.
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u8 = 9;
/// The ARM64_RELOC_ADDEND constant.
pub const ARM64_RELOC_ADDEND: u8 = 10;
/// The ARM64_RELOC_AUTHENTICATED_POINTER constant.
pub const ARM64_RELOC_AUTHENTICATED_POINTER: u8 = 11;

// X86_64 relocation types
/// The X86_64_RELOC_UNSIGNED constant.
pub const X86_64_RELOC_UNSIGNED: u8 = 0;
/// The X86_64_RELOC_SIGNED constant.
pub const X86_64_RELOC_SIGNED: u8 = 1;
/// The X86_64_RELOC_BRANCH constant.
pub const X86_64_RELOC_BRANCH: u8 = 2;
/// The X86_64_RELOC_GOT_LOAD constant.
pub const X86_64_RELOC_GOT_LOAD: u8 = 3;
/// The X86_64_RELOC_GOT constant.
pub const X86_64_RELOC_GOT: u8 = 4;
/// The X86_64_RELOC_SUBTRACTOR constant.
pub const X86_64_RELOC_SUBTRACTOR: u8 = 5;
/// The X86_64_RELOC_SIGNED_1 constant.
pub const X86_64_RELOC_SIGNED_1: u8 = 6;
/// The X86_64_RELOC_SIGNED_2 constant.
pub const X86_64_RELOC_SIGNED_2: u8 = 7;
/// The X86_64_RELOC_SIGNED_4 constant.
pub const X86_64_RELOC_SIGNED_4: u8 = 8;
/// The X86_64_RELOC_TLV constant.
pub const X86_64_RELOC_TLV: u8 = 9;

// Chained fixup pointer formats
/// The DYLD_CHAINED_PTR_ARM64E constant.
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
/// The DYLD_CHAINED_PTR_64 constant.
pub const DYLD_CHAINED_PTR_64: u16 = 2;
/// The DYLD_CHAINED_PTR_32 constant.
pub const DYLD_CHAINED_PTR_32: u16 = 3;
/// The DYLD_CHAINED_PTR_32_CACHE constant.
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
/// The DYLD_CHAINED_PTR_32_FIRMWARE constant.
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
/// The DYLD_CHAINED_PTR_64_OFFSET constant.
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
/// The DYLD_CHAINED_PTR_ARM64E_KERNEL constant.
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
/// The DYLD_CHAINED_PTR_64_KERNEL_CACHE constant.
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
/// The DYLD_CHAINED_PTR_ARM64E_USERLAND constant.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
/// The DYLD_CHAINED_PTR_ARM64E_FIRMWARE constant.
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
/// The DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE constant.
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
/// The DYLD_CHAINED_PTR_ARM64E_USERLAND24 constant.
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

// Chained fixup page start sentinels
/// The DYLD_CHAINED_PTR_START_NONE constant.
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
/// The DYLD_CHAINED_PTR_START_MULTI constant.
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

// Chained fixup import formats
/// The DYLD_CHAINED_IMPORT constant.
pub const DYLD_CHAINED_IMPORT: u32 = 1;
/// The DYLD_CHAINED_IMPORT_ADDEND constant.
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
/// The DYLD_CHAINED_IMPORT_ADDEND64 constant.
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

// Export symbol flags
/// The EXPORT_SYMBOL_FLAGS_KIND_MASK constant.
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u32 = 0x03;
/// The EXPORT_SYMBOL_FLAGS_KIND_REGULAR constant.
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u32 = 0x00;
/// The EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL constant.
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u32 = 0x01;
/// The EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE constant.
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u32 = 0x02;
/// The EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION constant.
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u32 = 0x04;
/// The EXPORT_SYMBOL_FLAGS_REEXPORT constant.
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u32 = 0x08;
/// The EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER constant.
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u32 = 0x10;
/// The EXPORT_SYMBOL_FLAGS_STATIC_RESOLVER constant.
pub const EXPORT_SYMBOL_FLAGS_STATIC_RESOLVER: u32 = 0x20;

// Rebase opcodes (high nibble = opcode, low nibble = immediate)
/// The REBASE_OPCODE_MASK constant.
pub const REBASE_OPCODE_MASK: u8 = 0xF0;
/// The REBASE_IMMEDIATE_MASK constant.
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
/// The REBASE_OPCODE_DONE constant.
pub const REBASE_OPCODE_DONE: u8 = 0x00;
/// The REBASE_OPCODE_SET_TYPE_IMM constant.
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
/// The REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB constant.
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
/// The REBASE_OPCODE_ADD_ADDR_ULEB constant.
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
/// The REBASE_OPCODE_ADD_ADDR_IMM_SCALED constant.
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
/// The REBASE_OPCODE_DO_REBASE_IMM_TIMES constant.
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
/// The REBASE_OPCODE_DO_REBASE_ULEB_TIMES constant.
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
/// The REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB constant.
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
/// The REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING constant.
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING: u8 = 0x80;

/// The REBASE_TYPE_POINTER constant.
pub const REBASE_TYPE_POINTER: u8 = 1;
/// The REBASE_TYPE_TEXT_ABSOLUTE32 constant.
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
/// The REBASE_TYPE_TEXT_PCREL32 constant.
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

// Bind opcodes
/// The BIND_OPCODE_MASK constant.
pub const BIND_OPCODE_MASK: u8 = 0xF0;
/// The BIND_IMMEDIATE_MASK constant.
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
/// The BIND_OPCODE_DONE constant.
pub const BIND_OPCODE_DONE: u8 = 0x00;
/// The BIND_OPCODE_SET_DYLIB_ORDINAL_IMM constant.
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
/// The BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB constant.
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
/// The BIND_OPCODE_SET_DYLIB_SPECIAL_IMM constant.
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
/// The BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM constant.
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
/// The BIND_OPCODE_SET_TYPE_IMM constant.
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
/// The BIND_OPCODE_SET_ADDEND_SLEB constant.
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
/// The BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB constant.
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
/// The BIND_OPCODE_ADD_ADDR_ULEB constant.
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
/// The BIND_OPCODE_DO_BIND constant.
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
/// The BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB constant.
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
/// The BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED constant.
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
/// The BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB constant.
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
/// The BIND_OPCODE_THREADED constant.
pub const BIND_OPCODE_THREADED: u8 = 0xD0;

/// The BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE constant.
pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE: u8 = 0x00;
/// The BIND_SUBOPCODE_THREADED_APPLY constant.
pub const BIND_SUBOPCODE_THREADED_APPLY: u8 = 0x01;

/// The BIND_TYPE_POINTER constant.
pub const BIND_TYPE_POINTER: u8 = 1;
/// The BIND_TYPE_TEXT_ABSOLUTE32 constant.
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
/// The BIND_TYPE_TEXT_PCREL32 constant.
pub const BIND_TYPE_TEXT_PCREL32: u8 = 3;

/// The BIND_SPECIAL_DYLIB_SELF constant.
pub const BIND_SPECIAL_DYLIB_SELF: i8 = 0;
/// The BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE constant.
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i8 = -1;
/// The BIND_SPECIAL_DYLIB_FLAT_LOOKUP constant.
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i8 = -2;
/// The BIND_SPECIAL_DYLIB_WEAK_LOOKUP constant.
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i8 = -3;
