// Mach-O magic numbers
pub const MH_MAGIC: u32 = 0xfeed_face;
pub const MH_CIGAM: u32 = 0xcefa_edfe;
pub const MH_MAGIC_64: u32 = 0xfeed_facf;
pub const MH_CIGAM_64: u32 = 0xcffa_edfe;

// Fat binary magic numbers (always big-endian on disk)
pub const FAT_MAGIC: u32 = 0xcafe_babe;
pub const FAT_CIGAM: u32 = 0xbeba_feca;
pub const FAT_MAGIC_64: u32 = 0xcafe_babf;
pub const FAT_CIGAM_64: u32 = 0xbfba_feca;

// File types
pub const MH_OBJECT: u32 = 0x1;
pub const MH_EXECUTE: u32 = 0x2;
pub const MH_FVMLIB: u32 = 0x3;
pub const MH_CORE: u32 = 0x4;
pub const MH_PRELOAD: u32 = 0x5;
pub const MH_DYLIB: u32 = 0x6;
pub const MH_DYLINKER: u32 = 0x7;
pub const MH_BUNDLE: u32 = 0x8;
pub const MH_DYLIB_STUB: u32 = 0x9;
pub const MH_DSYM: u32 = 0xa;
pub const MH_KEXT_BUNDLE: u32 = 0xb;
pub const MH_FILESET: u32 = 0xc;
pub const MH_GPU_EXECUTE: u32 = 0xd;
pub const MH_GPU_DYLIB: u32 = 0xe;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachoHeaderFlags: u32 {
        const NOUNDEFS                      = 0x0000_0001;
        const INCRLINK                      = 0x0000_0002;
        const DYLDLINK                      = 0x0000_0004;
        const BINDATLOAD                    = 0x0000_0008;
        const PREBOUND                      = 0x0000_0010;
        const SPLIT_SEGS                    = 0x0000_0020;
        const LAZY_INIT                     = 0x0000_0040;
        const TWOLEVEL                      = 0x0000_0080;
        const FORCE_FLAT                    = 0x0000_0100;
        const NOMULTIDEFS                   = 0x0000_0200;
        const NOFIXPREBINDING               = 0x0000_0400;
        const PREBINDABLE                   = 0x0000_0800;
        const ALLMODSBOUND                  = 0x0000_1000;
        const SUBSECTIONS_VIA_SYMBOLS       = 0x0000_2000;
        const CANONICAL                     = 0x0000_4000;
        const WEAK_DEFINES                  = 0x0000_8000;
        const BINDS_TO_WEAK                 = 0x0001_0000;
        const ALLOW_STACK_EXECUTION         = 0x0002_0000;
        const ROOT_SAFE                     = 0x0004_0000;
        const SETUID_SAFE                   = 0x0008_0000;
        const NO_REEXPORTED_DYLIBS          = 0x0010_0000;
        const PIE                           = 0x0020_0000;
        const DEAD_STRIPPABLE_DYLIB         = 0x0040_0000;
        const HAS_TLV_DESCRIPTORS           = 0x0080_0000;
        const NO_HEAP_EXECUTION             = 0x0100_0000;
        const APP_EXTENSION_SAFE            = 0x0200_0000;
        const NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x0400_0000;
        const SIM_SUPPORT                   = 0x0800_0000;
        const IMPLICIT_PAGEZERO             = 0x1000_0000;
        const DYLIB_IN_CACHE                = 0x8000_0000;
    }
}

// Load command constants
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

pub const LC_SEGMENT: u32 = 0x1;
pub const LC_SYMTAB: u32 = 0x2;
pub const LC_SYMSEG: u32 = 0x3;
pub const LC_THREAD: u32 = 0x4;
pub const LC_UNIXTHREAD: u32 = 0x5;
pub const LC_LOADFVMLIB: u32 = 0x6;
pub const LC_IDFVMLIB: u32 = 0x7;
pub const LC_IDENT: u32 = 0x8;
pub const LC_FVMFILE: u32 = 0x9;
pub const LC_PREPAGE: u32 = 0xa;
pub const LC_DYSYMTAB: u32 = 0xb;
pub const LC_LOAD_DYLIB: u32 = 0xc;
pub const LC_ID_DYLIB: u32 = 0xd;
pub const LC_LOAD_DYLINKER: u32 = 0xe;
pub const LC_ID_DYLINKER: u32 = 0xf;
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
pub const LC_ROUTINES: u32 = 0x11;
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
pub const LC_SUB_UMBRELLA: u32 = 0x13;
pub const LC_SUB_CLIENT: u32 = 0x14;
pub const LC_SUB_LIBRARY: u32 = 0x15;
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
pub const LC_PREBIND_CKSUM: u32 = 0x17;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
pub const LC_SEGMENT_64: u32 = 0x19;
pub const LC_ROUTINES_64: u32 = 0x1a;
pub const LC_UUID: u32 = 0x1b;
pub const LC_RPATH: u32 = 0x1c | LC_REQ_DYLD;
pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1e;
pub const LC_REEXPORT_DYLIB: u32 = 0x1f | LC_REQ_DYLD;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_DYLD_INFO: u32 = 0x22;
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
pub const LC_FUNCTION_STARTS: u32 = 0x26;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
pub const LC_DATA_IN_CODE: u32 = 0x29;
pub const LC_SOURCE_VERSION: u32 = 0x2a;
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2b;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;
pub const LC_LINKER_OPTION: u32 = 0x2d;
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2e;
pub const LC_VERSION_MIN_TVOS: u32 = 0x2f;
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
pub const LC_NOTE: u32 = 0x31;
pub const LC_BUILD_VERSION: u32 = 0x32;
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
pub const LC_ATOM_INFO: u32 = 0x36;
pub const LC_FUNCTION_VARIANTS: u32 = 0x37;
pub const LC_FUNCTION_VARIANT_FIXUPS: u32 = 0x38;
pub const LC_TARGET_TRIPLE: u32 = 0x39;

// Section type mask and values
pub const SECTION_TYPE_MASK: u32 = 0x0000_00ff;
pub const SECTION_ATTRIBUTES_MASK: u32 = 0xffff_ff00;

pub const S_REGULAR: u8 = 0x0;
pub const S_ZEROFILL: u8 = 0x1;
pub const S_CSTRING_LITERALS: u8 = 0x2;
pub const S_4BYTE_LITERALS: u8 = 0x3;
pub const S_8BYTE_LITERALS: u8 = 0x4;
pub const S_LITERAL_POINTERS: u8 = 0x5;
pub const S_NON_LAZY_SYMBOL_POINTERS: u8 = 0x6;
pub const S_LAZY_SYMBOL_POINTERS: u8 = 0x7;
pub const S_SYMBOL_STUBS: u8 = 0x8;
pub const S_MOD_INIT_FUNC_POINTERS: u8 = 0x9;
pub const S_MOD_TERM_FUNC_POINTERS: u8 = 0xa;
pub const S_COALESCED: u8 = 0xb;
pub const S_GB_ZEROFILL: u8 = 0xc;
pub const S_INTERPOSING: u8 = 0xd;
pub const S_16BYTE_LITERALS: u8 = 0xe;
pub const S_DTRACE_DOF: u8 = 0xf;
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u8 = 0x10;
pub const S_THREAD_LOCAL_REGULAR: u8 = 0x11;
pub const S_THREAD_LOCAL_ZEROFILL: u8 = 0x12;
pub const S_THREAD_LOCAL_VARIABLES: u8 = 0x13;
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u8 = 0x14;
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u8 = 0x15;
pub const S_INIT_FUNC_OFFSETS: u8 = 0x16;

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SectionAttributes: u32 {
        const PURE_INSTRUCTIONS   = 0x8000_0000;
        const NO_TOC              = 0x4000_0000;
        const STRIP_STATIC_SYMS   = 0x2000_0000;
        const NO_DEAD_STRIP       = 0x1000_0000;
        const LIVE_SUPPORT        = 0x0800_0000;
        const SELF_MODIFYING_CODE = 0x0400_0000;
        const DEBUG               = 0x0200_0000;
        const SOME_INSTRUCTIONS   = 0x0000_0400;
        const EXT_RELOC           = 0x0000_0200;
        const LOC_RELOC           = 0x0000_0100;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SegmentFlags: u32 {
        const HIGHVM              = 0x1;
        const FVMLIB              = 0x2;
        const NORELOC             = 0x4;
        const PROTECTED_VERSION_1 = 0x8;
        const READ_ONLY           = 0x10;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct VmProtection: i32 {
        const READ    = 0x1;
        const WRITE   = 0x2;
        const EXECUTE = 0x4;
    }
}

impl VmProtection {
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
pub const CPU_ARCH_ABI64: i32 = 0x0100_0000;
pub const CPU_ARCH_ABI64_32: i32 = 0x0200_0000;

pub const CPU_TYPE_ANY: i32 = -1;
pub const CPU_TYPE_X86: i32 = 7;
pub const CPU_TYPE_X86_64: i32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM: i32 = 12;
pub const CPU_TYPE_ARM64: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;
pub const CPU_TYPE_ARM64_32: i32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32;
pub const CPU_TYPE_POWERPC: i32 = 18;
pub const CPU_TYPE_POWERPC64: i32 = CPU_TYPE_POWERPC | CPU_ARCH_ABI64;

// CPU subtype mask: strips capability bits (high byte) from cpusubtype
pub const CPU_SUBTYPE_MASK: i32 = 0x00FF_FFFF;

// CPU subtype constants
pub const CPU_SUBTYPE_ALL: i32 = 0;
pub const CPU_SUBTYPE_X86_64_ALL: i32 = 3;
pub const CPU_SUBTYPE_X86_64_H: i32 = 8;
pub const CPU_SUBTYPE_ARM64_ALL: i32 = 0;
pub const CPU_SUBTYPE_ARM64_V8: i32 = 1;
pub const CPU_SUBTYPE_ARM64E: i32 = 2;
pub const CPU_SUBTYPE_ARM64_32_ALL: i32 = 0;

// Platform constants
pub const PLATFORM_UNKNOWN: u32 = 0;
pub const PLATFORM_ANY: u32 = 0xFFFF_FFFF;
pub const PLATFORM_MACOS: u32 = 1;
pub const PLATFORM_IOS: u32 = 2;
pub const PLATFORM_TVOS: u32 = 3;
pub const PLATFORM_WATCHOS: u32 = 4;
pub const PLATFORM_BRIDGEOS: u32 = 5;
pub const PLATFORM_MACCATALYST: u32 = 6;
pub const PLATFORM_IOSSIMULATOR: u32 = 7;
pub const PLATFORM_TVOSSIMULATOR: u32 = 8;
pub const PLATFORM_WATCHOSSIMULATOR: u32 = 9;
pub const PLATFORM_DRIVERKIT: u32 = 10;
pub const PLATFORM_VISIONOS: u32 = 11;
pub const PLATFORM_VISIONOSSIMULATOR: u32 = 12;
pub const PLATFORM_FIRMWARE: u32 = 13;
pub const PLATFORM_SEPOS: u32 = 14;

// Tool constants
pub const TOOL_CLANG: u32 = 1;
pub const TOOL_SWIFT: u32 = 2;
pub const TOOL_LD: u32 = 3;
pub const TOOL_LLD: u32 = 4;
pub const TOOL_METAL: u32 = 1024;
pub const TOOL_AIRLLD: u32 = 1025;
pub const TOOL_AIRNT: u32 = 1026;
pub const TOOL_AIRNT_PLUGIN: u32 = 1027;
pub const TOOL_AIRPACK: u32 = 1028;
pub const TOOL_GPUARCHIVER: u32 = 1031;
pub const TOOL_METAL_FRAMEWORK: u32 = 1032;

// Dylib use marker (for detecting dylib_use_command vs dylib_command)
pub const DYLIB_USE_MARKER: u32 = 0x1a74_1800;

// Symbol table n_type masks
pub const N_STAB: u8 = 0xe0;
pub const N_PEXT: u8 = 0x10;
pub const N_TYPE: u8 = 0x0e;
pub const N_EXT: u8 = 0x01;

// Symbol type values (after masking with N_TYPE)
pub const N_UNDF: u8 = 0x0;
pub const N_ABS: u8 = 0x2;
pub const N_SECT: u8 = 0xe;
pub const N_PBUD: u8 = 0xc;
pub const N_INDR: u8 = 0xa;

// Section ordinals
pub const NO_SECT: u8 = 0;

// n_desc flags
pub const N_ARM_THUMB_DEF: u16 = 0x0008;
pub const REFERENCED_DYNAMICALLY: u16 = 0x0010;
pub const N_NO_DEAD_STRIP: u16 = 0x0020;
pub const N_WEAK_REF: u16 = 0x0040;
pub const N_WEAK_DEF: u16 = 0x0080;
pub const N_SYMBOL_RESOLVER: u16 = 0x0100;
pub const N_ALT_ENTRY: u16 = 0x0200;
pub const N_COLD_FUNC: u16 = 0x0400;

// Library ordinal helpers (extracted from bits 8-15 of n_desc)
pub const SELF_LIBRARY_ORDINAL: u8 = 0x0;
pub const MAX_LIBRARY_ORDINAL: u8 = 0xfd;
pub const DYNAMIC_LOOKUP_ORDINAL: u8 = 0xfe;
pub const EXECUTABLE_ORDINAL: u8 = 0xff;

// Reference type mask (bits 0-2 of n_desc for undefined symbols)
pub const REFERENCE_TYPE: u16 = 0x7;

// Relocation constants
pub const R_SCATTERED: u32 = 0x8000_0000;
pub const R_ABS: u8 = 0;

// Generic relocation types
pub const GENERIC_RELOC_VANILLA: u8 = 0;
pub const GENERIC_RELOC_PAIR: u8 = 1;
pub const GENERIC_RELOC_SECTDIFF: u8 = 2;
pub const GENERIC_RELOC_PB_LA_PTR: u8 = 3;
pub const GENERIC_RELOC_LOCAL_SECTDIFF: u8 = 4;
pub const GENERIC_RELOC_TLV: u8 = 5;

// ARM64 relocation types
pub const ARM64_RELOC_UNSIGNED: u8 = 0;
pub const ARM64_RELOC_SUBTRACTOR: u8 = 1;
pub const ARM64_RELOC_BRANCH26: u8 = 2;
pub const ARM64_RELOC_PAGE21: u8 = 3;
pub const ARM64_RELOC_PAGEOFF12: u8 = 4;
pub const ARM64_RELOC_GOT_LOAD_PAGE21: u8 = 5;
pub const ARM64_RELOC_GOT_LOAD_PAGEOFF12: u8 = 6;
pub const ARM64_RELOC_POINTER_TO_GOT: u8 = 7;
pub const ARM64_RELOC_TLVP_LOAD_PAGE21: u8 = 8;
pub const ARM64_RELOC_TLVP_LOAD_PAGEOFF12: u8 = 9;
pub const ARM64_RELOC_ADDEND: u8 = 10;
pub const ARM64_RELOC_AUTHENTICATED_POINTER: u8 = 11;

// X86_64 relocation types
pub const X86_64_RELOC_UNSIGNED: u8 = 0;
pub const X86_64_RELOC_SIGNED: u8 = 1;
pub const X86_64_RELOC_BRANCH: u8 = 2;
pub const X86_64_RELOC_GOT_LOAD: u8 = 3;
pub const X86_64_RELOC_GOT: u8 = 4;
pub const X86_64_RELOC_SUBTRACTOR: u8 = 5;
pub const X86_64_RELOC_SIGNED_1: u8 = 6;
pub const X86_64_RELOC_SIGNED_2: u8 = 7;
pub const X86_64_RELOC_SIGNED_4: u8 = 8;
pub const X86_64_RELOC_TLV: u8 = 9;

// Chained fixup pointer formats
pub const DYLD_CHAINED_PTR_ARM64E: u16 = 1;
pub const DYLD_CHAINED_PTR_64: u16 = 2;
pub const DYLD_CHAINED_PTR_32: u16 = 3;
pub const DYLD_CHAINED_PTR_32_CACHE: u16 = 4;
pub const DYLD_CHAINED_PTR_32_FIRMWARE: u16 = 5;
pub const DYLD_CHAINED_PTR_64_OFFSET: u16 = 6;
pub const DYLD_CHAINED_PTR_ARM64E_KERNEL: u16 = 7;
pub const DYLD_CHAINED_PTR_64_KERNEL_CACHE: u16 = 8;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND: u16 = 9;
pub const DYLD_CHAINED_PTR_ARM64E_FIRMWARE: u16 = 10;
pub const DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE: u16 = 11;
pub const DYLD_CHAINED_PTR_ARM64E_USERLAND24: u16 = 12;

// Chained fixup page start sentinels
pub const DYLD_CHAINED_PTR_START_NONE: u16 = 0xFFFF;
pub const DYLD_CHAINED_PTR_START_MULTI: u16 = 0x8000;

// Chained fixup import formats
pub const DYLD_CHAINED_IMPORT: u32 = 1;
pub const DYLD_CHAINED_IMPORT_ADDEND: u32 = 2;
pub const DYLD_CHAINED_IMPORT_ADDEND64: u32 = 3;

// Export symbol flags
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u32 = 0x03;
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u32 = 0x00;
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u32 = 0x01;
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u32 = 0x02;
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u32 = 0x04;
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u32 = 0x08;
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u32 = 0x10;
pub const EXPORT_SYMBOL_FLAGS_STATIC_RESOLVER: u32 = 0x20;

// Rebase opcodes (high nibble = opcode, low nibble = immediate)
pub const REBASE_OPCODE_MASK: u8 = 0xF0;
pub const REBASE_IMMEDIATE_MASK: u8 = 0x0F;
pub const REBASE_OPCODE_DONE: u8 = 0x00;
pub const REBASE_OPCODE_SET_TYPE_IMM: u8 = 0x10;
pub const REBASE_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x20;
pub const REBASE_OPCODE_ADD_ADDR_ULEB: u8 = 0x30;
pub const REBASE_OPCODE_ADD_ADDR_IMM_SCALED: u8 = 0x40;
pub const REBASE_OPCODE_DO_REBASE_IMM_TIMES: u8 = 0x50;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES: u8 = 0x60;
pub const REBASE_OPCODE_DO_REBASE_ADD_ADDR_ULEB: u8 = 0x70;
pub const REBASE_OPCODE_DO_REBASE_ULEB_TIMES_SKIPPING: u8 = 0x80;

pub const REBASE_TYPE_POINTER: u8 = 1;
pub const REBASE_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const REBASE_TYPE_TEXT_PCREL32: u8 = 3;

// Bind opcodes
pub const BIND_OPCODE_MASK: u8 = 0xF0;
pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
pub const BIND_OPCODE_DONE: u8 = 0x00;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
pub const BIND_OPCODE_THREADED: u8 = 0xD0;

pub const BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE: u8 = 0x00;
pub const BIND_SUBOPCODE_THREADED_APPLY: u8 = 0x01;

pub const BIND_TYPE_POINTER: u8 = 1;
pub const BIND_TYPE_TEXT_ABSOLUTE32: u8 = 2;
pub const BIND_TYPE_TEXT_PCREL32: u8 = 3;

pub const BIND_SPECIAL_DYLIB_SELF: i8 = 0;
pub const BIND_SPECIAL_DYLIB_MAIN_EXECUTABLE: i8 = -1;
pub const BIND_SPECIAL_DYLIB_FLAT_LOOKUP: i8 = -2;
pub const BIND_SPECIAL_DYLIB_WEAK_LOOKUP: i8 = -3;
