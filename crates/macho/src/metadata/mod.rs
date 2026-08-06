#![deny(missing_docs)]
#![allow(clippy::collapsible_if, clippy::manual_is_multiple_of)]
//! Feature-gated Mach-O metadata decoding and symbol interpretation.

#[cfg(feature = "analysis")]
pub use crate::analysis::image;
#[cfg(feature = "evidence")]
pub use crate::evidence;

/// Code-signature metadata.
#[cfg(feature = "codesign")]
pub mod codesign;
/// C++ ABI, RTTI, and vtable metadata.
#[cfg(feature = "cpp")]
pub mod cpp;
/// Process-free language demangling.
#[cfg(feature = "demangle")]
pub mod demangle;
/// DWARF metadata and traversal.
#[cfg(feature = "dwarf")]
pub mod dwarf;
/// Dyld binding, fixup, export, and function-start metadata.
#[cfg(feature = "dyld")]
pub mod dyld;
/// Objective-C runtime metadata.
#[cfg(feature = "objc")]
pub mod objc;
/// Swift ABI metadata.
#[cfg(feature = "swift")]
pub mod swift;
/// Mach-O symbol and indirect-symbol metadata.
#[cfg(feature = "symbols")]
pub mod symbols;
