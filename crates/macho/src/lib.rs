#![deny(missing_docs)]
//! Feature-gated façade for the Mach-O workspace.

/// The error module.
pub mod error {
    pub use macho_core::{ParseError, ParseErrorKind, ParseResult};
}

pub use macho_core as core;
pub use macho_core::ext;
pub use macho_core::format;
pub use macho_core::model;
pub use macho_core::{ParseError, ParseErrorKind, ParseResult, parse, parse_with_options};

#[cfg(feature = "analysis")]
pub use macho_analysis as analysis;
#[cfg(feature = "metadata")]
pub use macho_codesign as codesign;
#[cfg(feature = "metadata")]
pub use macho_cpp as cpp;
#[cfg(feature = "metadata")]
pub use macho_dwarf as dwarf;
#[cfg(feature = "metadata")]
pub use macho_dyld as dyld;
#[cfg(feature = "dyld-cache")]
pub use macho_dyld_cache as dyld_cache;
#[cfg(feature = "header-infer")]
pub use macho_header_infer as header_infer;
#[cfg(feature = "mutation")]
pub use macho_insn as insn;
#[cfg(feature = "mutation")]
pub use macho_mutate as mutate;
#[cfg(feature = "metadata")]
pub use macho_objc as objc;
#[cfg(feature = "metadata")]
pub use macho_swift as swift;
#[cfg(feature = "metadata")]
pub use macho_symbols as symbol_metadata;
#[cfg(feature = "workflow")]
pub use macho_workflow as workflow;

#[cfg(feature = "metadata")]
/// The metadata module.
pub mod metadata {
    #[cfg(feature = "analysis")]
    pub use macho_analysis::image;
    pub use macho_codesign as codesign;
    pub use macho_dyld as dyld;
    pub use macho_objc as objc;
    pub use macho_swift as swift;
}

#[cfg(feature = "metadata")]
/// The resolve module.
pub mod resolve {
    #[cfg(feature = "analysis")]
    pub use macho_analysis::paths;
    pub use macho_dyld::resolve::{ResolutionContext, ResolvedTarget, fixups};
}

#[cfg(feature = "metadata")]
/// The symbols module.
pub mod symbols {
    pub use macho_symbols::{demangle, exports, imports, table};
}
