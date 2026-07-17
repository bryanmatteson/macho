/// The compat module.
pub mod compat;
/// The graph module.
pub mod graph;

pub use crate::image::DylibLinkKind;
pub use compat::{CompatCategory, CompatFinding, CompatReport, CompatSeverity};
pub use graph::{
    DepGraph, GraphIssue, ImportProvider, IssueSeverity, NormalizedDylib, ReexportInfo,
    ResolvedExport, ResolvedImport,
};
