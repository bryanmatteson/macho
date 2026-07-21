#![deny(missing_docs)]
//! C++ RTTI, vtable, and architecture-aware ABI inference.
//!
//! Depend on this crate directly for C++ structure recovery without the `macho`
//! façade: build a [`VtableIndex`] or [`build_typeinfo_index`] from a
//! [`macho_core::MachoFile`].

pub use macho_core::{format, model};
pub use macho_dyld as dyld;
pub use macho_dyld::resolve;
pub use macho_symbols as symbols;

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{CppError, CppErrorKind, Result};

pub mod abi;
mod abi_types;
/// The typeinfo module.
pub mod typeinfo;
/// The types module.
pub mod types;
/// The vtable module.
pub mod vtable;

pub use abi_types::{ArgumentTypeHint, CppBodyAnalysis, CppBodyKind, CppReturnChannel};
pub use typeinfo::build_typeinfo_index;
pub use types::{
    CppBaseClass, CppConfidence, CppEvidence, CppEvidenceKind, CppTypeInfoKind, CppTypeInfoNode,
};
pub use vtable::{SlotTarget, VtableEntry, VtableIndex, VtableSlot};
