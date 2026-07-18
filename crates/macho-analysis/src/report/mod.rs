//! Canonical, validated language-recovery wire vocabulary.

mod canonical;
mod common;
/// Versioned disassembly report schema.
pub mod disassembly;
mod header;
mod header_correlation;
mod objc;
mod recovery;
mod recovery_execute;
mod registry;
mod swift;
mod symbol_recovery;

pub use canonical::{CanonicalJsonError, canonical_json, sha256_hex};
pub use common::*;
pub use header::*;
pub use header_correlation::{HeaderCorrelationInput, execute_header_correlation};
pub use objc::*;
pub use recovery::*;
pub use recovery_execute::{execute_recovery_abi, execute_recovery_sources};
pub use registry::{
    DOMAIN_IDS, HEADER_VALIDATION_CODES, RECOVERY_DIAGNOSTIC_CODES, RECOVERY_ENTITY_KINDS,
    RECOVERY_ENTITY_ROLES, RECOVERY_FIELDS,
};
pub use swift::*;
pub use symbol_recovery::{recover_symbol_container, recover_symbol_surface};
