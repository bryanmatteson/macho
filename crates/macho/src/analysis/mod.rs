#![deny(missing_docs)]
#![allow(
    unreachable_patterns,
    clippy::collapsible_if,
    clippy::manual_is_multiple_of
)] // Keep conservative fallbacks for evolving public enums.
//! Selective Mach-O analysis, snapshots, diffing, auditing, and reconstruction.

// Internal re-exports (not part of public API)
pub(crate) use crate::core;
pub(crate) use crate::core::ext;
pub(crate) use crate::core::{format, model};
pub(crate) use crate::metadata::dwarf;
pub(crate) use crate::metadata::symbols;

pub use crate::metadata::codesign;
pub use crate::metadata::cpp;
pub use crate::metadata::dyld;
pub use crate::metadata::objc;
pub use crate::metadata::swift;

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
/// Bounded inter-procedural direct-call recovery over function identities.
pub mod call_graph;
/// The container module.
pub mod container;
/// Bounded control-flow recovery over recovered function identities.
pub mod control_flow;
/// Dependency declarations, static image universes, and runtime frontiers.
pub mod dependency_index;
/// The deps module.
pub mod deps;
/// The diff module.
pub mod diff;
/// Bounded, architecture-aware Mach-O disassembly.
pub mod disassembly;
/// Bounded DWARF traversal and source-address inventory.
pub mod dwarf_index;
/// Function-bound exception and unwind metadata inventory.
pub mod exception_index;
/// Conserved executable-section byte classification.
pub mod executable_bytes;
/// Bounded evidence-bearing function recovery.
pub mod functions;
/// Offline, bounded, evidence-accountable header hypothesis exchange.
pub mod header_infer;
/// Process-free parsing, validation, and rendering for recovered headers.
pub mod header_syntax;
/// The image module.
pub mod image;
/// Indexed image layout and address translation.
pub mod image_layout;
pub mod indirect_calls;
/// Bounded strict Objective-C runtime inventory.
pub mod objc_index;
/// The paths module.
pub mod paths;
pub mod planner;
/// Format-level pointer, fixup, bind, and relocation inventory.
pub mod pointer_index;
/// Unified Macho-owned program recovery over one exact image.
pub mod program;
/// The reconstruct module.
pub mod reconstruct;
/// Stable identities, questions, guidance, and provenance for steerable recovery.
pub mod recovery;
/// Canonical language-recovery wire reports and schema registry.
pub mod report;
/// Symbol-backed and ABI-structural image-bound Itanium RTTI recovery.
pub mod rtti;
/// Global data objects, function signatures, stack frames, and local variables.
pub mod semantic_index;
/// The snapshot module.
pub mod snapshot;
/// Image-bound string inventory and address queries.
pub mod string_index;
/// The strings module.
pub mod strings;
/// Bounded strict Swift ABI inventory.
pub mod swift_index;
/// Image-bound nlist, export, and import symbol inventory.
pub mod symbol_inventory;
/// Bounded inter-procedural branch, tail-call, and thunk recovery.
pub mod transfers;
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
