pub mod error {
    pub use macho_core::{Error, Result};
}

pub mod ext {
    pub use macho_core::ext::MachoExt;
}

pub use macho_core::{Error, Result};
pub use macho_core::{format, model};
pub use macho_metadata::metadata;

pub mod audit;
pub mod container;
pub mod deps;
pub mod diff;
pub mod snapshot;
pub mod strings;
pub mod xref;

pub mod resolve {
    pub use macho_core::resolve::{ResolutionContext, ResolvedTarget};
    pub use macho_metadata::resolve::{fixups, paths};
}

pub mod symbols {
    pub use macho_core::symbols::{demangle, table};
    pub use macho_metadata::symbols::{exports, imports};
}

pub mod analysis {
    pub use crate::audit;
    pub use crate::container;
    pub use crate::deps;
    pub use crate::diff;
    pub use crate::snapshot;
    pub use crate::strings;
    pub use crate::xref;
}
