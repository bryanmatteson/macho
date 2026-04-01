pub mod compat;
pub mod graph;

pub use crate::metadata::image::DylibLinkKind;
pub use compat::{CompatCategory, CompatFinding, CompatReport, CompatSeverity};
pub use graph::{
    DepGraph, GraphIssue, ImportProvider, IssueSeverity, NormalizedDylib, ReexportInfo,
    ResolvedExport, ResolvedImport,
};
