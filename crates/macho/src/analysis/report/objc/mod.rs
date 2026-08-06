//! Canonical Objective-C runtime recovery.

mod build;
mod encoding;
mod graph;
mod header;
mod identity;
mod types;
mod validate;

pub use build::{recover_objc_container, recover_objc_surface};
pub use header::project_objc_headers;
pub use types::*;
