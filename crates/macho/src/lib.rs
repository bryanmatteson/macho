#![deny(missing_docs)]
//! Feature-gated Mach-O parsing, metadata, analysis, mutation, and delivery.

/// Byte-safe structural Mach-O parsing and validation.
pub mod core;

/// The core parsing error surface.
pub mod error {
    pub use crate::core::{ParseError, ParseErrorKind, ParseResult};
}

pub use core::ext;
pub use core::format;
pub use core::model;
pub use core::{ParseError, ParseErrorKind, ParseResult, parse, parse_with_options};

/// Architecture-aware instruction decoding, encoding, and relocation.
#[cfg(feature = "insn")]
pub mod insn;

/// Feature-gated Mach-O metadata decoding and symbol interpretation.
pub mod metadata;

#[cfg(feature = "codesign")]
pub use metadata::codesign;
#[cfg(feature = "cpp")]
pub use metadata::cpp;
#[cfg(feature = "dwarf")]
pub use metadata::dwarf;
#[cfg(feature = "dyld")]
pub use metadata::dyld;
#[cfg(feature = "objc")]
pub use metadata::objc;
#[cfg(feature = "swift")]
pub use metadata::swift;
#[cfg(feature = "symbols")]
pub use metadata::symbols as symbol_metadata;

/// Dyld shared-cache parsing and extraction.
#[cfg(feature = "dyld-cache")]
pub mod dyld_cache;

/// Selective analysis, snapshots, diffing, auditing, and reconstruction.
#[cfg(feature = "analysis")]
pub mod analysis;

#[cfg(feature = "header-infer")]
pub use analysis::header_infer;
#[cfg(feature = "analysis")]
pub use analysis::header_syntax;

/// In-memory structural mutation, signing, and patch planning.
#[cfg(feature = "structural")]
pub mod mutate;

#[cfg(feature = "patch")]
pub use mutate::patch;

/// Cross-language evidence collection.
#[cfg(feature = "evidence")]
pub mod evidence;

/// Verified mutation workflow composition.
#[cfg(feature = "workflow")]
pub mod workflow;

/// Testable command-line grammar and delivery implementation.
#[cfg(feature = "cli")]
pub mod cli;

/// Dyld target resolution helpers.
#[cfg(feature = "dyld")]
pub mod resolve {
    #[cfg(feature = "analysis")]
    pub use crate::analysis::paths;
    pub use crate::metadata::dyld::resolve::{ResolutionContext, ResolvedTarget, fixups};
}

/// Symbol table and demangling helpers.
#[cfg(feature = "symbols")]
pub mod symbols {
    pub use crate::metadata::symbols::{demangle, table};
}
