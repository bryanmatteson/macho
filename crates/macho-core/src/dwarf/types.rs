//! Types for the DWARF function index.

use std::fmt;

/// Information about a function extracted from DWARF debug info.
#[derive(Debug, Clone)]
pub struct DwarfFunctionInfo {
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
pub enum DwarfType {
    /// No return type or `void`.
    Void,
    /// Base type (int, char, float, bool, etc.).
    Base {
        name: String,
        byte_size: u64,
        encoding: BaseTypeEncoding,
    },
    /// Pointer type.
    Pointer {
        pointee: Box<DwarfType>,
        byte_size: u64,
    },
    /// C++ reference (&).
    Reference {
        referent: Box<DwarfType>,
    },
    /// C++ rvalue reference (&&).
    RvalueReference {
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
        name: String,
        underlying: Box<DwarfType>,
    },
    /// Struct / class (name + size only, no fields).
    Structure {
        name: Option<String>,
        byte_size: Option<u64>,
    },
    /// Union.
    Union {
        name: Option<String>,
        byte_size: Option<u64>,
    },
    /// Enum.
    Enumeration {
        name: Option<String>,
        byte_size: Option<u64>,
    },
    /// Array.
    Array {
        element: Box<DwarfType>,
        count: Option<u64>,
    },
    /// Function pointer / subroutine type.
    Subroutine {
        return_type: Box<DwarfType>,
        params: Vec<DwarfType>,
    },
    /// Type could not be resolved (missing DIE reference, cycle, etc.).
    Unresolved,
}

/// Base type encoding (maps to `DW_ATE_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseTypeEncoding {
    Signed,
    Unsigned,
    Float,
    Boolean,
    Address,
    Char,
    SignedChar,
    UnsignedChar,
    Other(u8),
}

impl BaseTypeEncoding {
    pub fn from_dwarf(val: u8) -> Self {
        match val {
            0x05 => Self::Signed,
            0x07 => Self::Unsigned,
            0x04 => Self::Float,
            0x02 => Self::Boolean,
            0x01 => Self::Address,
            0x08 => Self::UnsignedChar,
            0x06 => Self::SignedChar,
            0x0B => Self::Char,      // DW_ATE_UTF
            other => Self::Other(other),
        }
    }
}

/// Calling convention (maps to `DW_CC_*` values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallingConvention {
    /// Normal C calling convention (`DW_CC_normal` or absent).
    Normal,
    /// Other / explicitly specified.
    Other(u8),
}

impl Default for CallingConvention {
    fn default() -> Self {
        Self::Normal
    }
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
            Self::Subroutine { return_type, params } => {
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
