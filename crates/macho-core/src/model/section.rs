use crate::format::constants::*;
use crate::model::addr::ThinFileOffset;
use crate::model::addr::Va;
use crate::model::names::{SectionName, SegmentName};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// The SectionType type.
pub enum SectionType {
    /// The Regular variant.
    Regular,
    /// The ZeroFill variant.
    ZeroFill,
    /// The CStringLiterals variant.
    CStringLiterals,
    /// The FourByteLiterals variant.
    FourByteLiterals,
    /// The EightByteLiterals variant.
    EightByteLiterals,
    /// The LiteralPointers variant.
    LiteralPointers,
    /// The NonLazySymbolPointers variant.
    NonLazySymbolPointers,
    /// The LazySymbolPointers variant.
    LazySymbolPointers,
    /// The SymbolStubs variant.
    SymbolStubs,
    /// The ModInitFuncPointers variant.
    ModInitFuncPointers,
    /// The ModTermFuncPointers variant.
    ModTermFuncPointers,
    /// The Coalesced variant.
    Coalesced,
    /// The GbZeroFill variant.
    GbZeroFill,
    /// The Interposing variant.
    Interposing,
    /// The SixteenByteLiterals variant.
    SixteenByteLiterals,
    /// The DTraceDof variant.
    DTraceDof,
    /// The LazyDylibSymbolPointers variant.
    LazyDylibSymbolPointers,
    /// The ThreadLocalRegular variant.
    ThreadLocalRegular,
    /// The ThreadLocalZeroFill variant.
    ThreadLocalZeroFill,
    /// The ThreadLocalVariables variant.
    ThreadLocalVariables,
    /// The ThreadLocalVariablePointers variant.
    ThreadLocalVariablePointers,
    /// The ThreadLocalInitFunctionPointers variant.
    ThreadLocalInitFunctionPointers,
    /// The InitFuncOffsets variant.
    InitFuncOffsets,
    /// The Unknown variant.
    Unknown(u8),
}

impl SectionType {
    /// Performs from_flags.
    pub fn from_flags(flags: u32) -> Self {
        let ty = (flags & SECTION_TYPE_MASK) as u8;
        match ty {
            S_REGULAR => Self::Regular,
            S_ZEROFILL => Self::ZeroFill,
            S_CSTRING_LITERALS => Self::CStringLiterals,
            S_4BYTE_LITERALS => Self::FourByteLiterals,
            S_8BYTE_LITERALS => Self::EightByteLiterals,
            S_LITERAL_POINTERS => Self::LiteralPointers,
            S_NON_LAZY_SYMBOL_POINTERS => Self::NonLazySymbolPointers,
            S_LAZY_SYMBOL_POINTERS => Self::LazySymbolPointers,
            S_SYMBOL_STUBS => Self::SymbolStubs,
            S_MOD_INIT_FUNC_POINTERS => Self::ModInitFuncPointers,
            S_MOD_TERM_FUNC_POINTERS => Self::ModTermFuncPointers,
            S_COALESCED => Self::Coalesced,
            S_GB_ZEROFILL => Self::GbZeroFill,
            S_INTERPOSING => Self::Interposing,
            S_16BYTE_LITERALS => Self::SixteenByteLiterals,
            S_DTRACE_DOF => Self::DTraceDof,
            S_LAZY_DYLIB_SYMBOL_POINTERS => Self::LazyDylibSymbolPointers,
            S_THREAD_LOCAL_REGULAR => Self::ThreadLocalRegular,
            S_THREAD_LOCAL_ZEROFILL => Self::ThreadLocalZeroFill,
            S_THREAD_LOCAL_VARIABLES => Self::ThreadLocalVariables,
            S_THREAD_LOCAL_VARIABLE_POINTERS => Self::ThreadLocalVariablePointers,
            S_THREAD_LOCAL_INIT_FUNCTION_POINTERS => Self::ThreadLocalInitFunctionPointers,
            S_INIT_FUNC_OFFSETS => Self::InitFuncOffsets,
            other => Self::Unknown(other),
        }
    }

    /// Performs name.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Regular => "S_REGULAR",
            Self::ZeroFill => "S_ZEROFILL",
            Self::CStringLiterals => "S_CSTRING_LITERALS",
            Self::FourByteLiterals => "S_4BYTE_LITERALS",
            Self::EightByteLiterals => "S_8BYTE_LITERALS",
            Self::LiteralPointers => "S_LITERAL_POINTERS",
            Self::NonLazySymbolPointers => "S_NON_LAZY_SYMBOL_POINTERS",
            Self::LazySymbolPointers => "S_LAZY_SYMBOL_POINTERS",
            Self::SymbolStubs => "S_SYMBOL_STUBS",
            Self::ModInitFuncPointers => "S_MOD_INIT_FUNC_POINTERS",
            Self::ModTermFuncPointers => "S_MOD_TERM_FUNC_POINTERS",
            Self::Coalesced => "S_COALESCED",
            Self::GbZeroFill => "S_GB_ZEROFILL",
            Self::Interposing => "S_INTERPOSING",
            Self::SixteenByteLiterals => "S_16BYTE_LITERALS",
            Self::DTraceDof => "S_DTRACE_DOF",
            Self::LazyDylibSymbolPointers => "S_LAZY_DYLIB_SYMBOL_POINTERS",
            Self::ThreadLocalRegular => "S_THREAD_LOCAL_REGULAR",
            Self::ThreadLocalZeroFill => "S_THREAD_LOCAL_ZEROFILL",
            Self::ThreadLocalVariables => "S_THREAD_LOCAL_VARIABLES",
            Self::ThreadLocalVariablePointers => "S_THREAD_LOCAL_VARIABLE_POINTERS",
            Self::ThreadLocalInitFunctionPointers => "S_THREAD_LOCAL_INIT_FUNCTION_POINTERS",
            Self::InitFuncOffsets => "S_INIT_FUNC_OFFSETS",
            Self::Unknown(_) => "S_UNKNOWN",
        }
    }

    /// Performs is_zerofill.
    pub fn is_zerofill(&self) -> bool {
        matches!(
            self,
            Self::ZeroFill | Self::GbZeroFill | Self::ThreadLocalZeroFill
        )
    }
}

#[derive(Debug, Clone)]
/// The Section type.
pub struct Section {
    pub(crate) segment_name: SegmentName,
    pub(crate) section_name: SectionName,
    pub(crate) addr: Va,
    pub(crate) size: u64,
    pub(crate) offset: ThinFileOffset,
    pub(crate) align: u32,
    pub(crate) reloff: ThinFileOffset,
    pub(crate) nreloc: u32,
    pub(crate) section_type: SectionType,
    pub(crate) attributes: SectionAttributes,
    pub(crate) reserved1: u32,
    pub(crate) reserved2: u32,
    pub(crate) reserved3: u32,
}

impl Section {
    /// Fixed-width containing segment name.
    pub const fn segment_name(&self) -> &SegmentName {
        &self.segment_name
    }
    /// Fixed-width section name.
    pub const fn section_name(&self) -> &SectionName {
        &self.section_name
    }
    /// Section virtual start address.
    pub const fn addr(&self) -> Va {
        self.addr
    }
    /// Section virtual size in bytes.
    pub const fn size(&self) -> u64 {
        self.size
    }
    /// Slice-relative file offset.
    pub const fn offset(&self) -> ThinFileOffset {
        self.offset
    }
    /// Base-two alignment exponent.
    pub const fn align(&self) -> u32 {
        self.align
    }
    /// Slice-relative relocation-table offset.
    pub const fn relocation_offset(&self) -> ThinFileOffset {
        self.reloff
    }
    /// Number of relocation records.
    pub const fn relocation_count(&self) -> u32 {
        self.nreloc
    }
    /// Decoded section type.
    pub const fn section_type(&self) -> SectionType {
        self.section_type
    }
    /// Parsed section attributes.
    pub const fn attributes(&self) -> SectionAttributes {
        self.attributes
    }
    /// First type-specific reserved word.
    pub const fn reserved1(&self) -> u32 {
        self.reserved1
    }
    /// Second type-specific reserved word.
    pub const fn reserved2(&self) -> u32 {
        self.reserved2
    }
    /// Third type-specific reserved word.
    pub const fn reserved3(&self) -> u32 {
        self.reserved3
    }
}
