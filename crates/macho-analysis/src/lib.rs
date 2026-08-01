#![deny(missing_docs)]
//! Selective Mach-O analysis, snapshots, diffing, auditing, and reconstruction.

// Internal re-exports (not part of public API)
pub(crate) use macho_core as core;
pub(crate) use macho_core::ext;
pub(crate) use macho_core::{format, model};
pub(crate) use macho_dwarf as dwarf;
pub(crate) use macho_symbols as symbols;

pub use macho_codesign as codesign;
pub use macho_cpp as cpp;
pub use macho_dyld as dyld;
pub use macho_objc as objc;
pub use macho_swift as swift;

mod serde_addr;

/// The error module.
pub mod error;
pub(crate) use error::Error;
pub use error::{AnalysisDomain, AnalysisError, AnalysisErrorKind, Result};

// Analysis modules
pub mod abi;
pub mod analyzer;
/// The audit module.
pub mod audit;
/// The container module.
pub mod container;
/// The deps module.
pub mod deps;
/// The diff module.
pub mod diff;
/// Bounded, architecture-aware Mach-O disassembly.
pub mod disassembly;
/// The image module.
pub mod image;
/// The paths module.
pub mod paths;
pub mod planner;
/// The reconstruct module.
pub mod reconstruct;
/// Canonical language-recovery wire reports and schema registry.
pub mod report;
/// The snapshot module.
pub mod snapshot;
/// The strings module.
pub mod strings;
/// The vtables module.
pub mod vtables;
/// The xref module.
pub mod xref;

pub use analyzer::{
    AnalysisDocument, AnalysisFailure, AnalysisIssue, Analyzer, ContainerIdentity, DomainPayload,
    DomainReportKey, DomainState, SliceIdentity, SliceSnapshot, SnapshotDocument,
    UnsupportedReason, domain_reports,
};
pub use planner::{
    AnalysisLimits, AnalysisPlan, AuditPlan, AuditRuleSpec, ContainerPlan, DiffPlan,
};
