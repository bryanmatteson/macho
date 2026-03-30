use crate::addr::ThinFileOffset;
use crate::addr::Va;
use crate::constants::*;
use crate::model::names::{SectionName, SegmentName};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SectionType {
    Regular,
    ZeroFill,
    CStringLiterals,
    FourByteLiterals,
    EightByteLiterals,
    LiteralPointers,
    NonLazySymbolPointers,
    LazySymbolPointers,
    SymbolStubs,
    ModInitFuncPointers,
    ModTermFuncPointers,
    Coalesced,
    GbZeroFill,
    Interposing,
    SixteenByteLiterals,
    DTraceDof,
    LazyDylibSymbolPointers,
    ThreadLocalRegular,
    ThreadLocalZeroFill,
    ThreadLocalVariables,
    ThreadLocalVariablePointers,
    ThreadLocalInitFunctionPointers,
    InitFuncOffsets,
    Unknown(u8),
}

impl SectionType {
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

    pub fn is_zerofill(&self) -> bool {
        matches!(
            self,
            Self::ZeroFill | Self::GbZeroFill | Self::ThreadLocalZeroFill
        )
    }
}

#[derive(Debug, Clone)]
pub struct Section {
    pub segment_name: SegmentName,
    pub section_name: SectionName,
    pub addr: Va,
    pub size: u64,
    pub offset: ThinFileOffset,
    pub align: u32,
    pub reloff: ThinFileOffset,
    pub nreloc: u32,
    pub section_type: SectionType,
    pub attributes: SectionAttributes,
    pub reserved1: u32,
    pub reserved2: u32,
    pub reserved3: u32,
}
