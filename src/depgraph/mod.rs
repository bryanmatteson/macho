pub mod compat;
pub mod graph;

pub use compat::{CompatCategory, CompatFinding, CompatReport, CompatSeverity};
pub use graph::{
    DepGraph, GraphIssue, ImportProvider, IssueSeverity, NormalizedDylib, ReexportInfo,
    ResolvedExport, ResolvedImport,
};
// Re-export DylibLinkKind from its canonical home in inspect::
pub use crate::inspect::DylibLinkKind;
