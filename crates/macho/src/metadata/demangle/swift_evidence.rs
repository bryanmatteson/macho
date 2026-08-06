//! Owned, process-free Swift mangling evidence.
//!
//! This module is the public boundary around the third-party Swift parser.
//! Parser nodes and parser-owned types never cross the boundary: callers
//! receive only owned Mach-O evidence values and decide independently how to
//! project them into product-specific semantic identities.

mod convert;
mod decode;
mod model;

pub use decode::{
    decode_swift_dynamic_replacement, decode_swift_mangling, decode_swift_objc_callable,
};
pub use model::*;
