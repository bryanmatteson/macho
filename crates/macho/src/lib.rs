extern crate self as macho;

pub mod error {
    pub use macho_core::{Error, Result};
}

pub use macho_analysis as analysis;
pub use macho_core as core;
pub use macho_core::ext;
pub use macho_core::format;
pub use macho_core::model;
pub use macho_core::{Error, Result, parse};
pub use macho_mutate as mutate;

pub mod metadata {
    pub use macho_core::codesign;
    pub use macho_core::dyld;
    pub use macho_core::image;
    pub use macho_core::objc;
    pub use macho_core::swift;
}

pub mod resolve {
    pub use macho_core::resolve::{ResolutionContext, ResolvedTarget, fixups, paths};
}

pub mod symbols {
    pub use macho_core::symbols::{demangle, exports, imports, table};
}

pub mod api;
pub mod commands;
pub mod inputs;
