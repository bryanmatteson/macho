//! Types for the DWARF function and global-variable indexes.

use std::fmt;

/// Information about a function extracted from DWARF debug info.
#[derive(Debug, Clone)]
pub struct DwarfFunctionInfo {
    /// Offset of the containing compilation unit in `.debug_info`.
    pub unit_offset: u64,
    /// Offset of the subprogram DIE relative to its compilation unit.
    pub die_offset: u64,
    /// The `DW_AT_name` of the subprogram (source-level name).
    pub name: Option<String>,
    /// The `DW_AT_linkage_name` (mangled symbol name).
    pub linkage_name: Option<String>,
    /// The `DW_AT_low_pc` (entry point virtual address).
    pub address: Option<u64>,
    /// The function byte size (from `DW_AT_high_pc` or `DW_AT_ranges`).
    pub size: Option<u64>,
    /// Return type.
    pub return_type: DwarfType,
    /// Formal parameters (excludes implicit `this` unless `is_artificial` is set).
    pub parameters: Vec<DwarfParameter>,
    /// Whether the function accepts variadic arguments (`DW_TAG_unspecified_parameters`).
    pub is_variadic: bool,
    /// Calling convention.
    pub calling_convention: CallingConvention,
}

/// Information about a global variable extracted from DWARF debug info.
#[derive(Debug, Clone)]
pub struct DwarfVariableInfo {
    /// Offset of the containing compilation unit in `.debug_info`.
    pub unit_offset: u64,
    /// Offset of the variable DIE relative to its compilation unit.
    pub die_offset: u64,
    /// The `DW_AT_name` source spelling.
    pub name: Option<String>,
    /// The `DW_AT_linkage_name` symbol spelling.
    pub linkage_name: Option<String>,
    /// The source type when its DIE reference can be resolved.
    pub ty: DwarfType,
}

/// A formal parameter from DWARF.
#[derive(Debug, Clone)]
pub struct DwarfParameter {
    /// Parameter name from `DW_AT_name`.
    pub name: Option<String>,
    /// Parameter type.
    pub ty: DwarfType,
    /// Whether this is a compiler-generated parameter (e.g., implicit `this`).
    pub is_artificial: bool,
}

/// A type representation sufficient for ABI comparison.
///
/// This intentionally does NOT recurse into struct/union fields — for ABI
/// compatibility checking, we need shape (pointer depth, size, name identity)
/// but not internal layout.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DwarfType {
    /// No return type or `void`.
    Void,
    /// Base type (int, char, float, bool, etc.).
    Base {
        /// The String field.
        name: String,
        /// The u64 field.
        byte_size: u64,
        /// The BaseTypeEncoding field.
        encoding: BaseTypeEncoding,
    },
    /// Pointer type.
    Pointer {
        /// The item field.
        pointee: Box<DwarfType>,
        /// The u64 field.
        byte_size: u64,
    },
    /// C++ reference (&).
    Reference {
        #[doc = "The referent field."]
        referent: Box<DwarfType>,
    },
    /// C++ rvalue reference (&&).
    RvalueReference {
        #[doc = "The referent field."]
        referent: Box<DwarfType>,
    },
    /// `const` qualifier.
    Const(Box<DwarfType>),
    /// `volatile` qualifier.
    Volatile(Box<DwarfType>),
    /// `restrict` qualifier.
    Restrict(Box<DwarfType>),
    /// `typedef` (preserves the source name).
    Typedef {
        /// The String field.
        name: String,
        /// The item field.
        underlying: Box<DwarfType>,
    },
    /// Struct / class (name + size only, no fields).
    Structure {
        /// The item field.
        name: Option<String>,
        /// The item field.
        byte_size: Option<u64>,
    },
    /// Union.
    Union {
        /// The item field.
        name: Option<String>,
        /// The item field.
        byte_size: Option<u64>,
    },
    /// Enum.
    Enumeration {
        /// The item field.
        name: Option<String>,
        /// The item field.
        byte_size: Option<u64>,
    },
    /// Array.
    Array {
        /// The item field.
        element: Box<DwarfType>,
        /// The item field.
        count: Option<u64>,
    },
    /// Function pointer / subroutine type.
    Subroutine {
        /// The item field.
        return_type: Box<DwarfType>,
        /// The item field.
        params: Vec<DwarfType>,
    },
    /// Type could not be resolved (missing DIE reference, cycle, etc.).
    Unresolved,
}

/// Base type encoding (maps to `DW_ATE_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BaseTypeEncoding {
    /// The Signed variant.
    Signed,
    /// The Unsigned variant.
    Unsigned,
    /// The Float variant.
    Float,
    /// The Boolean variant.
    Boolean,
    /// The Address variant.
    Address,
    /// The Char variant.
    Char,
    /// The SignedChar variant.
    SignedChar,
    /// The UnsignedChar variant.
    UnsignedChar,
    /// The Other variant.
    Other(u8),
}

impl BaseTypeEncoding {
    /// Performs from_dwarf.
    pub fn from_dwarf(val: u8) -> Self {
        match val {
            0x05 => Self::Signed,
            0x07 => Self::Unsigned,
            0x04 => Self::Float,
            0x02 => Self::Boolean,
            0x01 => Self::Address,
            0x08 => Self::UnsignedChar,
            0x06 => Self::SignedChar,
            0x0B => Self::Char, // DW_ATE_UTF
            other => Self::Other(other),
        }
    }
}

/// Calling convention (maps to `DW_CC_*` values).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallingConvention {
    /// Normal C calling convention (`DW_CC_normal` or absent).
    #[default]
    Normal,
    /// Other / explicitly specified.
    Other(u8),
}

impl fmt::Display for DwarfType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Void => write!(f, "void"),
            Self::Base { name, .. } => write!(f, "{name}"),
            Self::Pointer { pointee, .. } => write!(f, "{pointee}*"),
            Self::Reference { referent } => write!(f, "{referent}&"),
            Self::RvalueReference { referent } => write!(f, "{referent}&&"),
            Self::Const(inner) => write!(f, "const {inner}"),
            Self::Volatile(inner) => write!(f, "volatile {inner}"),
            Self::Restrict(inner) => write!(f, "{inner} restrict"),
            Self::Typedef { name, .. } => write!(f, "{name}"),
            Self::Structure { name, .. } => {
                write!(f, "struct {}", name.as_deref().unwrap_or("<anon>"))
            }
            Self::Union { name, .. } => {
                write!(f, "union {}", name.as_deref().unwrap_or("<anon>"))
            }
            Self::Enumeration { name, .. } => {
                write!(f, "enum {}", name.as_deref().unwrap_or("<anon>"))
            }
            Self::Array { element, count } => {
                if let Some(n) = count {
                    write!(f, "{element}[{n}]")
                } else {
                    write!(f, "{element}[]")
                }
            }
            Self::Subroutine {
                return_type,
                params,
            } => {
                write!(f, "{return_type}(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{p}")?;
                }
                write!(f, ")")
            }
            Self::Unresolved => write!(f, "<unresolved>"),
        }
    }
}
