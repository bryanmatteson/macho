//! Pointer and fixup resolution.

mod evidence;
/// The fixups module.
pub mod fixups;
/// The pointers module.
pub mod pointers;

pub use evidence::{
    PointerAuthentication, PointerEncoding, PointerObservation, PointerResolver, PointerTarget,
};
pub use pointers::{ResolutionContext, ResolvedTarget};
