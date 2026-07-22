#![deny(missing_docs)]
//! C++ RTTI, vtable, and architecture-aware ABI inference.
//!
//! Depend on this crate directly for C++ structure recovery without the `macho`
//! façade: build a [`VtableIndex`] or [`build_typeinfo_index`] from a
//! [`macho_core::MachoFile`] or a borrowed byte source.

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
#[cfg(feature = "itanium-rtti")]
mod strict_rtti;
/// The typeinfo module.
pub mod typeinfo;
/// The types module.
pub mod types;
/// The vtable module.
pub mod vtable;

pub use abi_types::{ArgumentTypeHint, CppBodyAnalysis, CppBodyKind, CppReturnChannel};
#[cfg(feature = "itanium-rtti")]
pub use strict_rtti::{
    ItaniumBaseRecord, ItaniumPointeeRecord, ItaniumTypeInfoFamily, ItaniumTypeInfoRecord,
    StrictPointerAuthentication, StrictPointerEncoding, StrictPointerObservation,
    StrictPointerTarget, StrictRttiBatch, StrictRttiConservation, StrictRttiGap, StrictRttiGapCode,
    StrictRttiLimits, StrictRttiObservation, StrictRttiObservationKind, StrictRttiOutcome,
    StrictRttiRecord, decode_strict_rtti, decode_strict_rtti_from_source,
};
pub use typeinfo::{build_typeinfo_index, build_typeinfo_index_from_source};
pub use types::{
    CppBaseClass, CppConfidence, CppEvidence, CppEvidenceKind, CppTypeInfoKind, CppTypeInfoNode,
};
pub use vtable::{SlotTarget, VtableEntry, VtableIndex, VtableSlot};

use crate::model::macho_file::MachoFile;

fn parse_source<'data, S>(source: &'data S) -> Result<MachoFile<'data>>
where
    S: AsRef<[u8]> + ?Sized,
{
    match macho_core::parse(source.as_ref())? {
        macho_core::model::container::MachoContainer::Thin(macho) => Ok(macho),
        macho_core::model::container::MachoContainer::Fat(_) => Err(Error::unsupported(
            "borrowed source contains a universal Mach-O; select an architecture explicitly",
        )),
    }
}
