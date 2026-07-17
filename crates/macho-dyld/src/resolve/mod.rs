//! Pointer and fixup resolution.

/// The fixups module.
pub mod fixups;
/// The pointers module.
pub mod pointers;

pub use pointers::{ResolutionContext, ResolvedTarget};
