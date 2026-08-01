//! Pointer and fixup resolution.

mod evidence;
/// The fixups module.
pub mod fixups;
/// The pointers module.
pub mod pointers;

pub use evidence::{
    DyldPointer, InventoryPointerTarget, LegacyBindOccurrence, LegacyBindStream,
    PointerAuthentication, PointerEncoding, PointerInventory, PointerInventoryContinuation,
    PointerObservation, PointerResolver, PointerTarget,
};
pub use pointers::{ResolutionContext, ResolvedTarget};
