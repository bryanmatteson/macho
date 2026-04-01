pub mod error {
    pub use macho_core::{Error, Result};
}

pub mod ext {
    pub use macho_core::ext::MachoExt;
}

pub use macho_core::{Error, Result};
pub use macho_core::{format, model};

pub mod codesign;
pub mod dyld;
pub mod image;
pub mod objc;
pub mod resolve;
pub mod swift;
pub mod symbols;

pub mod metadata {
    pub use crate::codesign;
    pub use crate::dyld;
    pub use crate::image;
    pub use crate::objc;
    pub use crate::swift;
}
