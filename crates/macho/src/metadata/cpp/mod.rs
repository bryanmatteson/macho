#![deny(missing_docs)]
//! C++ RTTI, vtable, and architecture-aware ABI inference.
//!
//! Depend on this crate directly for C++ structure recovery without the `macho`
//! façade: build a [`crate::metadata::cpp::VtableIndex`] or
//! [`crate::metadata::cpp::build_typeinfo_index`] from a
//! [`crate::core::MachoFile`] or a borrowed byte source.

pub use crate::core::{format, model};

/// The error module.
pub mod error;
#[cfg(feature = "fixups")]
pub(crate) use error::Error;
pub use error::{CppError, CppErrorKind, Result};

#[cfg(feature = "abi")]
pub mod abi;
mod abi_types;
#[cfg(feature = "itanium-rtti")]
mod strict_rtti;
#[cfg(feature = "itanium-rtti")]
mod strict_vtable;
#[cfg(feature = "fixups")]
/// The typeinfo module.
pub mod typeinfo;
/// The types module.
pub mod types;
#[cfg(feature = "fixups")]
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
#[cfg(feature = "itanium-rtti")]
pub use strict_vtable::{
    ItaniumThunkAdjustment, ItaniumVtableAddressPointRecord, ItaniumVtableAddressPointSource,
    ItaniumVtableAmbiguousWordRecord, ItaniumVtableExtentSource, ItaniumVtableGroupRecord,
    ItaniumVtableOffsetRecord, ItaniumVtableOffsetRole, ItaniumVtableSlotRecord,
    ItaniumVtableSlotRole, ItaniumVtableSymbolKind, ItaniumVttEntryRecord, ItaniumVttRecord,
    StrictVtableBatch, StrictVtableLimits, StrictVtableRecord, decode_strict_vtables,
    decode_strict_vtables_from_source,
};
#[cfg(feature = "fixups")]
pub use typeinfo::{build_typeinfo_index, build_typeinfo_index_from_source};
pub use types::{
    CppBaseClass, CppConfidence, CppEvidence, CppEvidenceKind, CppTypeInfoKind, CppTypeInfoNode,
};
#[cfg(feature = "fixups")]
pub use vtable::{SlotTarget, VtableEntry, VtableIndex, VtableSlot};

#[cfg(feature = "fixups")]
use crate::metadata::cpp::model::macho_file::MachoFile;

#[cfg(feature = "fixups")]
fn parse_source<'data, S>(source: &'data S) -> Result<MachoFile<'data>>
where
    S: AsRef<[u8]> + ?Sized,
{
    match crate::core::parse(source.as_ref())? {
        crate::core::model::container::MachoContainer::Thin(macho) => Ok(macho),
        crate::core::model::container::MachoContainer::Fat(_) => Err(Error::unsupported(
            "borrowed source contains a universal Mach-O; select an architecture explicitly",
        )),
    }
}
